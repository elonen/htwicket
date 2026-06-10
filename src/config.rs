//! Config: TOML file → env override (HTWICKET_, `__` nesting) → CLI. See PLAN.md for full example.
//! CEL exprs are compiled at load time — invalid expr is a startup failure, never a request-time one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;

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
    #[serde(default = "d_session_hours")]
    pub session_hours: u32,
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
    /// Editable by the user themself on /account (default: admin-only).
    #[serde(default)]
    pub user_editable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExprSpec {
    #[serde(rename = "type")]
    pub type_: FieldType,
    pub expr: String,
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let cfg: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed("HTWICKET_").split("__"))
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
            anyhow::bail!(
                "field name `{name}` must be a CEL identifier ([A-Za-z_][A-Za-z0-9_]*)"
            );
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
                anyhow::bail!("field `{name}`: default does not match type {:?}", spec.type_);
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
    fn base_path_must_be_absolute() {
        let cfg = parse(&format!("base_path = \"htwicket\"\n{REQUIRED}{SUPERADMINS}"));
        assert!(validate(&cfg).is_err());
    }
}

fn d_listen() -> String { "127.0.0.1:8088".into() }
fn d_base_path() -> String { "/htwicket".into() }
fn d_state_dir() -> PathBuf { "/var/lib/htwicket".into() }
fn d_min_password_len() -> usize { 8 }
fn d_session_hours() -> u32 { 12 }
fn d_session_max_days() -> u32 { 7 }
