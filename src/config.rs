//! Config: TOML file → env override (HTWICKET_, `__` nesting) → CLI. See htwicket.example.toml + docs/configuration.md.
//! CEL exprs are compiled at load time — invalid expr is a startup failure, never a request-time one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
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
    /// Raise the log level from INFO to DEBUG: per-request + file-I/O traces (never secrets).
    #[serde(default)]
    pub debug: bool,
    /// Drops the Secure cookie flag (plain-http demo). Logs a loud startup warning.
    #[serde(default)]
    pub insecure_cookies: bool,
    /// Accept `Authorization: Basic` on /auth (backwards compat for scripted clients).
    #[serde(default)]
    pub basic_auth_passthrough: bool,
    /// Rehash entries not in `password_hash` on successful login (plaintext in hand).
    #[serde(default)]
    pub upgrade_hash_on_login: bool,
    /// Algorithm for newly written hashes. bcrypt keeps `.htpasswd` readable by nginx
    /// `auth_basic`; argon2id is stronger but forfeits that escape hatch. Verification reads both
    /// (plus all legacy formats) regardless.
    #[serde(default = "d_password_hash")]
    pub password_hash: PasswordAlgo,
    #[serde(default = "d_min_password_len")]
    pub min_password_len: usize,
    /// JWT exp; sliding re-mint past half-life.
    #[serde(default = "d_session_idle_hours")]
    pub session_idle_hours: u32,
    /// Absolute cap via orig_iat claim.
    #[serde(default = "d_session_max_days")]
    pub session_max_days: u32,
    /// Honor the browser's Accept-Language header (matched against compiled catalogs) before
    /// falling back to default_lang.
    #[serde(default = "d_http_accept_language")]
    pub http_accept_language: bool,
    /// CEL (string) over {username, fields.*}: fallback UI locale when Accept-Language yields no
    /// catalog match (or http_accept_language is off). Empty username/fields on pre-login pages.
    #[serde(default = "d_default_lang")]
    pub default_lang: String,
    /// Raw (unescaped) HTML rendered above the form on every page — a logo, custom title, colors.
    /// Whitelabel branding; trusted operator input, intentionally not escaped.
    #[serde(default)]
    pub app_title_html: Option<String>,
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

/// Hash algorithm for newly written passwords (see the `password_hash` config field).
#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum PasswordAlgo {
    Bcrypt,
    Argon2id,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Bool,
    String,
    Email,
}

impl FieldType {
    /// Does `v` carry this type? (bool for Bool, string for String/Email.)
    pub fn matches(self, v: &toml::Value) -> bool {
        match self {
            FieldType::Bool => v.is_bool(),
            FieldType::String | FieldType::Email => v.is_str(),
        }
    }
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
    /// Sort key for field's position in management views. If unset, user field name for sorting.
    #[serde(default)]
    pub sort_key: Option<String>,
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
    /// Raise the log level to DEBUG (per-request + file-I/O traces)
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<bool>,
    /// Drop the cookie Secure flag (plain-http demo only)
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_cookies: Option<bool>,
    /// Accept Authorization: Basic on /auth
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth_passthrough: Option<bool>,
    /// Rehash entries not in password_hash on successful login
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_hash_on_login: Option<bool>,
    /// Algorithm for newly written hashes (bcrypt keeps nginx auth_basic compat; argon2id is stronger)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<PasswordAlgo>,
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
    /// Honor the browser Accept-Language header before default_lang
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_accept_language: Option<bool>,
    /// Fallback locale CEL expr (over {username, fields.*}) when Accept-Language has no match
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_lang: Option<String>,
    /// Raw HTML shown above the form on every page (branding/whitelabel)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_title_html: Option<String>,
}

impl Config {
    /// Schema fields in display order for /admin and /account: sorted by each field's `sort_key`
    /// (falling back to its name when unset), ties broken by name. `cfg.fields` is a name-sorted
    /// BTreeMap, so with no `sort_key` set this is just the current alphabetical order.
    pub fn ordered_fields(&self) -> Vec<(&String, &FieldSpec)> {
        let mut v: Vec<_> = self.fields.iter().collect();
        v.sort_by(|(a_name, a), (b_name, b)| {
            let a_key = a.sort_key.as_deref().unwrap_or(a_name);
            let b_key = b.sort_key.as_deref().unwrap_or(b_name);
            a_key.cmp(b_key).then_with(|| a_name.cmp(b_name))
        });
        v
    }
}

pub fn load(path: &Path, cli: &Overrides) -> anyhow::Result<Config> {
    // `jwt_secret_file` is read by us below (not a Config field), so keep it out of the figment —
    // `deny_unknown_fields` would otherwise reject the env var.
    let mut cfg: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(
            Env::prefixed("HTWICKET_")
                .split("__")
                .ignore(&["jwt_secret_file"]),
        )
        .merge(Serialized::defaults(cli))
        .extract()?;
    // Docker-style secret indirection: when jwt_secret isn't set directly (file/env/CLI), allow
    // pointing at a mounted secret file via HTWICKET_JWT_SECRET_FILE. A direct value wins.
    if cfg.jwt_secret.is_none()
        && let Ok(file) = std::env::var("HTWICKET_JWT_SECRET_FILE")
    {
        let secret = std::fs::read_to_string(&file)
            .with_context(|| format!("reading HTWICKET_JWT_SECRET_FILE `{file}`"))?;
        cfg.jwt_secret = Some(secret.trim_end_matches(['\r', '\n']).to_string());
    }
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
        if let Some(default) = &spec.default
            && !spec.type_.matches(default)
        {
            anyhow::bail!(
                "field `{name}`: default does not match type {:?}",
                spec.type_
            );
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
    fn ordered_fields_defaults_to_name_order() {
        let cfg = parse(&format!(
            "{REQUIRED}{SUPERADMINS}[fields.zebra]\ntype = \"string\"\n[fields.alpha]\ntype = \"string\"\n"
        ));
        let order: Vec<&str> = cfg
            .ordered_fields()
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(order, ["alpha", "zebra"]); // no sort_key → field-name order
    }

    #[test]
    fn ordered_fields_uses_sort_key_then_name() {
        // Declaration order is irrelevant; sort_key drives position, unset falls back to name.
        let cfg = parse(&format!(
            "{REQUIRED}{SUPERADMINS}\
             [fields.bbb]\ntype = \"string\"\nsort_key = \"1\"\n\
             [fields.aaa]\ntype = \"string\"\n\
             [fields.ccc]\ntype = \"string\"\nsort_key = \"2\"\n"
        ));
        let order: Vec<&str> = cfg
            .ordered_fields()
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        // String sort: "1"(bbb) < "2"(ccc) < "aaa" (aaa's unset key = its name).
        assert_eq!(order, ["bbb", "ccc", "aaa"]);
    }

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
                    password_hash = "argon2id"
                    [superadmins]
                    expr = "false"
                "#,
            )?;
            jail.set_env("HTWICKET_LISTEN", "env");
            jail.set_env("HTWICKET_BASE_PATH", "/env");
            jail.set_env("HTWICKET_PASSWORD_HASH", "bcrypt");
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
                password_hash: Some(PasswordAlgo::Argon2id),
                http_accept_language: Some(false),
                debug: Some(true),
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
            assert_eq!(cfg.password_hash, PasswordAlgo::Argon2id); // CLI beats env beats file
            assert!(!cfg.http_accept_language); // CLI override of the true default
            assert!(cfg.debug); // CLI flag turns DEBUG tracing on
            Ok(())
        });
    }

    #[test]
    fn jwt_secret_file_fills_unset_secret() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "htwicket.toml",
                "htpasswd_file = \"/tmp/.htpasswd\"\n[superadmins]\nexpr = \"false\"\n",
            )?;
            // Trailing newline (as `echo secret > file` writes) is trimmed.
            jail.create_file("secret", "supersecretvalue\n")?;
            jail.set_env("HTWICKET_JWT_SECRET_FILE", "secret"); // resolved against the jail cwd
            let cfg = load(Path::new("htwicket.toml"), &Overrides::default())
                .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.jwt_secret.as_deref(), Some("supersecretvalue"));
            Ok(())
        });
    }

    #[test]
    fn direct_jwt_secret_wins_over_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "htwicket.toml",
                "htpasswd_file = \"/tmp/.htpasswd\"\n[superadmins]\nexpr = \"false\"\n",
            )?;
            jail.create_file("secret", "from-file\n")?;
            jail.set_env("HTWICKET_JWT_SECRET_FILE", "secret");
            jail.set_env("HTWICKET_JWT_SECRET", "from-env");
            let cfg = load(Path::new("htwicket.toml"), &Overrides::default())
                .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.jwt_secret.as_deref(), Some("from-env"));
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
            assert!(!cfg.debug); // defaults off (INFO)
            assert!(cfg.http_accept_language); // defaults on
            assert_eq!(cfg.default_lang, d_default_lang());
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
fn d_password_hash() -> PasswordAlgo {
    PasswordAlgo::Bcrypt
}
fn d_session_idle_hours() -> u32 {
    12
}
fn d_session_max_days() -> u32 {
    7
}
fn d_http_accept_language() -> bool {
    true
}
fn d_default_lang() -> String {
    "'en'".into()
}
fn d_false_expr() -> String {
    "false".into()
}
