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

#[derive(Deserialize, Clone, Copy, PartialEq)]
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
    // TODO: validate (field defaults match types, required only on non-bools, username-safe
    // field names) and compile all CEL exprs (crate::cel) — fail startup on any error.
    Ok(cfg)
}

fn d_listen() -> String { "127.0.0.1:8088".into() }
fn d_base_path() -> String { "/htwicket".into() }
fn d_state_dir() -> PathBuf { "/var/lib/htwicket".into() }
fn d_min_password_len() -> usize { 8 }
fn d_session_hours() -> u32 { 12 }
fn d_session_max_days() -> u32 { 7 }
