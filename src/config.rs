//! Config: TOML file → env override (HTWICKET_, `__` nesting) → CLI. See htwicket.example.toml + docs/configuration.md.
//! CEL exprs are compiled at load time — invalid expr is a startup failure, never a request-time one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "d_listen")]
    pub listen: String,
    #[serde(default = "d_base_path")]
    pub base_path: String,
    pub htpasswd_file: PathBuf,
    /// Defaults to `.htwicket.toml` next to htpasswd_file.
    pub sidecar_file: Option<PathBuf>,
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
    /// Auto-generated + persisted to `{state_dir}/jwt_secret` when unset.
    pub jwt_secret: Option<String>,
    /// Drops the Secure cookie flag (plain-http demo). Logs a loud startup warning.
    #[serde(default)]
    pub insecure_cookies: bool,
    /// Accept `Authorization: Basic` on /auth (backwards compat for scripted clients).
    #[serde(default)]
    pub basic_auth_passthrough: bool,
    /// Rehash legacy entries to bcrypt on successful login (plaintext in hand).
    #[serde(default)]
    pub upgrade_hash_on_login: bool,
    #[serde(default = "d_min_password_len")]
    pub min_password_len: usize,
    /// JWT exp; sliding re-mint past half-life.
    #[serde(default = "d_session_idle_hours")]
    pub session_idle_hours: u32,
    /// Absolute cap via orig_iat claim.
    #[serde(default = "d_session_max_days")]
    pub session_max_days: u32,
    pub superadmins: Superadmins,
    /// App-specific user attribute schema; htwicket core is app-agnostic.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldSpec>,
    /// /auth 200-response headers, CEL over {username, fields.*}. X-Remote-User-Id is always sent.
    #[serde(default)]
    pub headers: BTreeMap<String, ExprSpec>,
    /// Extra JWT claims, baked at login (headers are the fresh/authoritative channel).
    #[serde(default, rename = "jwt-claims")]
    pub jwt_claims: BTreeMap<String, ExprSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Superadmins {
    /// CEL: who may access /admin (admins of htwicket itself, not of the proxied app).
    pub expr: String,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Bool,
    String,
    Email,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    #[serde(rename = "type")]
    pub type_: FieldType,
    /// TOML value matching type_; applied before any CEL eval so exprs are total.
    pub default: Option<toml::Value>,
    #[serde(default)]
    pub required: bool,
    /// Shown (read-only) to the user on their own /account. `user_editable_expr` evaluating
    /// true for a user implies visibility for that user (you can edit only what you can see).
    #[serde(default)]
    pub user_visible: bool,
    /// CEL (bool) over {username, fields.*}: may THIS user edit the field on /account?
    /// Default "false" (admin-only). e.g. "true" (anyone), or "fields.is_admin".
    #[serde(default = "d_false_expr")]
    pub user_editable_expr: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExprSpec {
    #[serde(rename = "type")]
    pub type_: FieldType,
    pub expr: String,
}

/// Per-key CLI overrides — the topmost layer, for the scalar top-level keys only. The tables
/// (`[superadmins]`, `[fields.*]`, ...) are structured config, not deploy-time knobs: file/env
/// only. `jwt_secret` is deliberately absent too — argv is visible in `ps`, use
/// `HTWICKET_JWT_SECRET`. Bool flags: presence = true, `--flag=false` to force off.
#[derive(clap::Args, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Overrides {
    /// Bind address
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// URL prefix all routes are served under
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,
    /// Password file
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub htpasswd_file: Option<PathBuf>,
    /// Fields file (default: .htwicket.toml next to htpasswd file)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sidecar_file: Option<PathBuf>,
    /// Holds the auto-generated jwt_secret
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<PathBuf>,
    /// Drop the cookie Secure flag (plain-http demo only)
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_cookies: Option<bool>,
    /// Accept Authorization: Basic on /auth
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth_passthrough: Option<bool>,
    /// Rehash legacy entries to bcrypt on successful login
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_hash_on_login: Option<bool>,
    /// Minimum password length
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_password_len: Option<usize>,
    /// JWT idle expiry; sliding re-mint past half-life
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_idle_hours: Option<u32>,
    /// Absolute session cap
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_max_days: Option<u32>,
}

pub fn load(path: &Path, cli: &Overrides) -> anyhow::Result<Config> {
    let cfg: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("HTWICKET_").split("__"))
        .merge(Serialized::defaults(cli))
        .extract()?;
    validate(&cfg)?;
    // CEL exprs are compiled by `serve` (crate::web), not here: the offline `user` subcommands
    // must keep working for lockout recovery even when a header/claim expr is broken.
    Ok(cfg)
}

/// Static config invariants — fail startup loudly rather than surprise at request time.
fn validate(cfg: &Config) -> anyhow::Result<()> {
    if !cfg.base_path.starts_with('/') {
        anyhow::bail!("base_path must start with '/' (got {:?})", cfg.base_path);
    }
    for (name, spec) in &cfg.fields {
        // Field names are referenced as `fields.<name>` in CEL, so they must be CEL identifiers.
        if !is_ident(name) {
            anyhow::bail!("field name `{name}` must be a CEL identifier ([A-Za-z_][A-Za-z0-9_]*)");
        }
        if spec.type_ == FieldType::Bool && spec.required {
            anyhow::bail!("field `{name}`: `required` applies only to non-bool fields");
        }
        if let Some(default) = &spec.default {
            let ok = match spec.type_ {
                FieldType::Bool => default.is_bool(),
                FieldType::String | FieldType::Email => default.is_str(),
            };
            if !ok {
                anyhow::bail!(
                    "field `{name}`: default does not match type {:?}",
                    spec.type_
                );
            }
        }
    }
    Ok(())
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test supplies a complete config body (top-level keys must precede any [table]).
    fn parse(body: &str) -> Config {
        toml::from_str(body).unwrap()
    }
    const REQUIRED: &str = "htpasswd_file = \"/tmp/.htpasswd\"\n";
    const SUPERADMINS: &str = "[superadmins]\nexpr = \"false\"\n";

    #[test]
    fn valid_config_passes() {
        let cfg = parse(&format!(
            "{REQUIRED}{SUPERADMINS}[fields.is_admin]\ntype = \"bool\"\ndefault = false\n"
        ));
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn bool_field_cannot_be_required() {
        let cfg = parse(&format!(
            "{REQUIRED}{SUPERADMINS}[fields.is_admin]\ntype = \"bool\"\nrequired = true\n"
        ));
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn default_must_match_type() {
        let cfg = parse(&format!(
            "{REQUIRED}{SUPERADMINS}[fields.is_admin]\ntype = \"bool\"\ndefault = \"yes\"\n"
        ));
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn field_name_must_be_cel_identifier() {
        let cfg = parse(&format!(
            "{REQUIRED}{SUPERADMINS}[fields.\"x-y\"]\ntype = \"string\"\n"
        ));
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn layering_file_env_cli() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "htwicket.toml",
                r#"
                    listen = "file"
                    base_path = "/file"
                    htpasswd_file = "/file/.htpasswd"
                    sidecar_file = "/file/.sidecar"
                    state_dir = "/file/state"
                    insecure_cookies = false
                    basic_auth_passthrough = false
                    upgrade_hash_on_login = false
                    min_password_len = 1
                    session_idle_hours = 1
                    session_max_days = 1
                    [superadmins]
                    expr = "false"
                "#,
            )?;
            jail.set_env("HTWICKET_LISTEN", "env");
            jail.set_env("HTWICKET_BASE_PATH", "/env");
            let cli = Overrides {
                listen: Some("cli".into()),
                htpasswd_file: Some("/cli/.htpasswd".into()),
                sidecar_file: Some("/cli/.sidecar".into()),
                state_dir: Some("/cli/state".into()),
                insecure_cookies: Some(true),
                basic_auth_passthrough: Some(true),
                upgrade_hash_on_login: Some(true),
                min_password_len: Some(3),
                session_idle_hours: Some(3),
                session_max_days: Some(3),
                ..Overrides::default()
            };
            let cfg = load(Path::new("htwicket.toml"), &cli)
                .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.listen, "cli"); // CLI beats env beats file
            assert_eq!(cfg.base_path, "/env"); // env beats file (no CLI override given)
            assert_eq!(cfg.htpasswd_file, PathBuf::from("/cli/.htpasswd"));
            assert_eq!(cfg.sidecar_file, Some(PathBuf::from("/cli/.sidecar")));
            assert_eq!(cfg.state_dir, PathBuf::from("/cli/state"));
            assert!(cfg.insecure_cookies);
            assert!(cfg.basic_auth_passthrough);
            assert!(cfg.upgrade_hash_on_login);
            assert_eq!(cfg.min_password_len, 3);
            assert_eq!(cfg.session_idle_hours, 3);
            assert_eq!(cfg.session_max_days, 3);
            Ok(())
        });
    }

    #[test]
    fn unset_keys_keep_defaults() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "htwicket.toml",
                "htpasswd_file = \"/tmp/.htpasswd\"\n[superadmins]\nexpr = \"false\"\n",
            )?;
            let cfg = load(Path::new("htwicket.toml"), &Overrides::default())
                .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.listen, d_listen());
            assert_eq!(cfg.session_max_days, d_session_max_days());
            assert!(!cfg.insecure_cookies);
            Ok(())
        });
    }

    #[test]
    fn base_path_must_be_absolute() {
        let cfg = parse(&format!(
            "base_path = \"htwicket\"\n{REQUIRED}{SUPERADMINS}"
        ));
        assert!(validate(&cfg).is_err());
    }
}

fn d_listen() -> String {
    "127.0.0.1:52155".into()
}
fn d_base_path() -> String {
    "/htwicket".into()
}
fn d_state_dir() -> PathBuf {
    "/var/lib/htwicket".into()
}
fn d_min_password_len() -> usize {
    8
}
fn d_session_idle_hours() -> u32 {
    12
}
fn d_session_max_days() -> u32 {
    7
}
fn d_false_expr() -> String {
    "false".into()
}
