//! In-memory user DB backed by .htpasswd (canonical passwords) + .htwicket.toml sidecar (fields).
//! Reload on mtime change (one stat() per request). Writes: flock on shared `.lock` file
//! (server + CLI), write-temp + atomic rename. Unknown sidecar fields: warn + preserve, never delete.

use std::collections::BTreeMap;

pub struct UserDb {
    pub users: BTreeMap<String, User>,
    // TODO: htpasswd/sidecar paths + last-seen mtimes for reload_if_changed()
}

pub struct User {
    /// Raw hash field from .htpasswd (DES/$apr1$/$1$/$5$/$6$/$2y$). None = sidecar-only user (no password).
    pub hash: Option<String>,
    /// pwd_fp = first 16 hex of SHA-256(hash field); rotates on every password write (bcrypt re-salts).
    pub pwd_fp: Option<String>,
    /// Schema-declared fields with config defaults pre-applied (CEL exprs are total over these).
    pub fields: BTreeMap<String, toml::Value>,
}

impl UserDb {
    pub fn load(_cfg: &crate::config::Config) -> anyhow::Result<Self> {
        todo!("parse .htpasswd lines + sidecar TOML, apply field defaults, validate schema")
    }

    pub fn reload_if_changed(&mut self) -> anyhow::Result<bool> {
        todo!("stat both files, reload on mtime change; also clears authn verify-cache")
    }

    /// Username: 1-64 chars, [A-Za-z0-9@._-] (no ':' — htpasswd format).
    pub fn valid_username(_name: &str) -> bool {
        todo!()
    }

    pub fn write_password(&mut self, _user: &str, _bcrypt_hash: &str) -> anyhow::Result<()> {
        todo!("flock, rewrite htpasswd atomically (temp+rename)")
    }

    pub fn write_fields(&mut self, _user: &str, _fields: &BTreeMap<String, toml::Value>) -> anyhow::Result<()> {
        todo!("flock, rewrite sidecar atomically, preserving unknown fields")
    }
}
