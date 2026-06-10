//! In-memory user DB backed by .htpasswd (canonical passwords) + .htwicket.toml sidecar (fields).
//! Reload on mtime change (one stat() per request). Writes: flock on shared `.lock` file
//! (server + CLI), write-temp + atomic rename. Unknown sidecar fields: warn + preserve, never delete.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Config, FieldType};

pub struct UserDb {
    pub users: BTreeMap<String, User>,
    cfg: Arc<Config>,
    htpasswd_path: PathBuf,
    sidecar_path: PathBuf,
    lock_path: PathBuf,
    /// Raw sidecar tables (incl. fields outside the schema) — preserved verbatim on write.
    sidecar: Sidecar,
    htpasswd_mtime: Option<SystemTime>,
    sidecar_mtime: Option<SystemTime>,
}

pub struct User {
    /// Raw hash field from .htpasswd (DES/$apr1$/$1$/$5$/$6$/$2y$). None = sidecar-only user (no password).
    pub hash: Option<String>,
    /// pwd_fp = first 16 hex of SHA-256(hash field); rotates on every password write (bcrypt re-salts).
    pub pwd_fp: Option<String>,
    /// Schema-declared fields with config defaults pre-applied (CEL exprs are total over these).
    pub fields: BTreeMap<String, toml::Value>,
}

/// On-disk sidecar shape: `[users."<name>"]` table per user, holding all fields (known + unknown).
#[derive(Default, Serialize, Deserialize)]
struct Sidecar {
    #[serde(default)]
    users: BTreeMap<String, toml::Table>,
}

impl UserDb {
    pub fn load(cfg: Arc<Config>) -> anyhow::Result<Self> {
        let htpasswd_path = cfg.htpasswd_file.clone();
        let sidecar_path = cfg
            .sidecar_file
            .clone()
            .unwrap_or_else(|| htpasswd_path.with_file_name(".htwicket.toml"));
        // One shared lock for both files (server + CLI), sibling to the htpasswd file so
        // it falls under nginx/Apache's stock `/\.ht` deny globs like the data files do.
        let lock_path = htpasswd_path.with_file_name(".htwicket.lock");

        let mut db = UserDb {
            users: BTreeMap::new(),
            cfg,
            htpasswd_path,
            sidecar_path,
            lock_path,
            sidecar: Sidecar::default(),
            htpasswd_mtime: None,
            sidecar_mtime: None,
        };
        db.reload()?;
        Ok(db)
    }

    /// Re-read both files if either's mtime changed since last load. Returns true on reload;
    /// the caller clears the authn verify-cache when it does.
    pub fn reload_if_changed(&mut self) -> anyhow::Result<bool> {
        if mtime(&self.htpasswd_path) == self.htpasswd_mtime
            && mtime(&self.sidecar_path) == self.sidecar_mtime
        {
            return Ok(false);
        }
        self.reload()?;
        Ok(true)
    }

    fn reload(&mut self) -> anyhow::Result<()> {
        let htpasswd_text = read_opt(&self.htpasswd_path)?.unwrap_or_default();
        let sidecar_text = read_opt(&self.sidecar_path)?.unwrap_or_default();
        let sidecar: Sidecar = toml::from_str(&sidecar_text)
            .with_context(|| format!("parsing sidecar {}", self.sidecar_path.display()))?;

        self.users = build_users(&self.cfg, &htpasswd_text, &sidecar);
        self.sidecar = sidecar;
        self.htpasswd_mtime = mtime(&self.htpasswd_path);
        self.sidecar_mtime = mtime(&self.sidecar_path);
        if self.users.is_empty() {
            tracing::warn!("no users found — run `htwicket user add <name>`");
        }
        Ok(())
    }

    /// Username: 1-64 chars, [A-Za-z0-9@._-] (no ':' — htpasswd format).
    pub fn valid_username(name: &str) -> bool {
        (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-'))
    }

    /// Schema problems for one user (type mismatch / missing required field). Empty = ok.
    /// Backs `user check`'s exit code 2.
    pub fn schema_errors(&self, name: &str) -> Vec<String> {
        let raw = self.sidecar.users.get(name);
        effective_fields(&self.cfg, raw.unwrap_or(&toml::Table::new())).1
    }

    pub fn write_password(&mut self, user: &str, bcrypt_hash: &str) -> anyhow::Result<()> {
        let mut lock = self.open_lock()?;
        let _guard = lock.write()?;
        let mut entries = parse_htpasswd(&read_opt(&self.htpasswd_path)?.unwrap_or_default());
        entries.insert(user.to_string(), bcrypt_hash.to_string());
        atomic_write(&self.htpasswd_path, &serialize_htpasswd(&entries))?;
        self.htpasswd_mtime = mtime(&self.htpasswd_path);

        let u = self.users.entry(user.to_string()).or_insert_with(|| User {
            hash: None,
            pwd_fp: None,
            fields: effective_fields(&self.cfg, &toml::Table::new()).0,
        });
        u.hash = Some(bcrypt_hash.to_string());
        u.pwd_fp = Some(pwd_fp(bcrypt_hash));
        Ok(())
    }

    /// Merge `fields` into the user's sidecar table, preserving any unknown fields already there.
    pub fn write_fields(
        &mut self,
        user: &str,
        fields: &BTreeMap<String, toml::Value>,
    ) -> anyhow::Result<()> {
        let mut lock = self.open_lock()?;
        let _guard = lock.write()?;
        let mut sidecar = read_sidecar(&self.sidecar_path)?;
        let table = sidecar.users.entry(user.to_string()).or_default();
        for (k, v) in fields {
            table.insert(k.clone(), v.clone());
        }
        atomic_write(&self.sidecar_path, &toml::to_string_pretty(&sidecar)?)?;
        self.sidecar_mtime = mtime(&self.sidecar_path);

        let effective = effective_fields(&self.cfg, &sidecar.users[user]).0;
        self.sidecar = sidecar;
        self.users.entry(user.to_string()).or_insert_with(|| User {
            hash: None,
            pwd_fp: None,
            fields: BTreeMap::new(),
        }).fields = effective;
        Ok(())
    }

    /// Remove the user from both files under one lock.
    pub fn delete_user(&mut self, user: &str) -> anyhow::Result<()> {
        let mut lock = self.open_lock()?;
        let _guard = lock.write()?;
        let mut entries = parse_htpasswd(&read_opt(&self.htpasswd_path)?.unwrap_or_default());
        if entries.remove(user).is_some() {
            atomic_write(&self.htpasswd_path, &serialize_htpasswd(&entries))?;
            self.htpasswd_mtime = mtime(&self.htpasswd_path);
        }
        let mut sidecar = read_sidecar(&self.sidecar_path)?;
        if sidecar.users.remove(user).is_some() {
            atomic_write(&self.sidecar_path, &toml::to_string_pretty(&sidecar)?)?;
            self.sidecar_mtime = mtime(&self.sidecar_path);
        }
        self.sidecar = sidecar;
        self.users.remove(user);
        Ok(())
    }

    /// Open (creating if needed) the shared lock file. Caller takes `.write()` for the duration
    /// of a read-modify-write; the lock is advisory and released when the guard drops. Opened
    /// lazily per write so read-only use (e.g. `user list`) never needs write access to the dir.
    fn open_lock(&self) -> anyhow::Result<fd_lock::RwLock<fs::File>> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("opening lock file {}", self.lock_path.display()))?;
        Ok(fd_lock::RwLock::new(file))
    }
}

fn build_users(cfg: &Config, htpasswd_text: &str, sidecar: &Sidecar) -> BTreeMap<String, User> {
    let hashes = parse_htpasswd(htpasswd_text);
    let mut names: Vec<&String> = hashes.keys().chain(sidecar.users.keys()).collect();
    names.sort();
    names.dedup();

    let empty = toml::Table::new();
    names
        .into_iter()
        .map(|name| {
            let hash = hashes.get(name).cloned();
            let raw = sidecar.users.get(name).unwrap_or(&empty);
            let (fields, errors) = effective_fields(cfg, raw);
            for e in &errors {
                tracing::warn!("user {name}: {e}");
            }
            let user = User {
                pwd_fp: hash.as_deref().map(pwd_fp),
                hash,
                fields,
            };
            (name.clone(), user)
        })
        .collect()
}

/// Resolve schema fields against a raw sidecar table: validated value or config default.
/// Returns the effective field map plus any schema problems (type mismatch, missing required).
fn effective_fields(
    cfg: &Config,
    raw: &toml::Table,
) -> (BTreeMap<String, toml::Value>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut errors = Vec::new();
    for (name, spec) in &cfg.fields {
        match raw.get(name) {
            Some(v) if type_ok(spec.type_, v) => {
                out.insert(name.clone(), v.clone());
            }
            Some(_) => errors.push(format!("field `{name}` is not a {:?}", spec.type_)),
            None => match &spec.default {
                Some(d) => {
                    out.insert(name.clone(), d.clone());
                }
                None if spec.required => errors.push(format!("required field `{name}` is missing")),
                None => {}
            },
        }
    }
    (out, errors)
}

fn type_ok(t: FieldType, v: &toml::Value) -> bool {
    match t {
        FieldType::Bool => v.is_bool(),
        FieldType::String | FieldType::Email => v.is_str(),
    }
}

/// Parse `user:hash` lines into a name→hash map. Blank lines and lines without a `:` are skipped.
fn parse_htpasswd(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() {
                return None;
            }
            let (user, hash) = line.split_once(':')?;
            Some((user.to_string(), hash.to_string()))
        })
        .collect()
}

fn serialize_htpasswd(entries: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (user, hash) in entries {
        out.push_str(user);
        out.push(':');
        out.push_str(hash);
        out.push('\n');
    }
    out
}

fn read_sidecar(path: &Path) -> anyhow::Result<Sidecar> {
    let text = read_opt(path)?.unwrap_or_default();
    Ok(toml::from_str(&text).with_context(|| format!("parsing sidecar {}", path.display()))?)
}

/// First 16 hex (8 bytes) of SHA-256 over the raw hash field.
fn pwd_fp(hash: &str) -> String {
    let digest = Sha256::digest(hash.as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn read_opt(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Write via a temp file in the same dir + atomic rename, preserving the existing file's
/// permissions (new files get 0600 — the data is password hashes).
fn atomic_write(path: &Path, contents: &str) -> anyhow::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mode = fs::metadata(path).map(|m| m.permissions().mode()).unwrap_or(0o600);
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    tmp.write_all(contents.as_bytes())?;
    tmp.flush()?;
    tmp.as_file().set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("persisting {}: {}", path.display(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cfg_with_fields(htpasswd: PathBuf) -> Arc<Config> {
        // Minimal config: one bool field (default false) + one required string, for schema tests.
        let toml = format!(
            r#"
            htpasswd_file = "{}"
            [superadmins]
            expr = "false"
            [fields.is_admin]
            type = "bool"
            default = false
            [fields.display_name]
            type = "string"
            "#,
            htpasswd.display()
        );
        Arc::new(toml::from_str(&toml).unwrap())
    }

    #[test]
    fn valid_username_rules() {
        assert!(UserDb::valid_username("alice"));
        assert!(UserDb::valid_username("a.b_c-d@example.com"));
        assert!(!UserDb::valid_username("")); // empty
        assert!(!UserDb::valid_username("has:colon"));
        assert!(!UserDb::valid_username("space bar"));
        assert!(!UserDb::valid_username(&"x".repeat(65)));
    }

    #[test]
    fn parse_and_defaults_and_pwd_fp() {
        let dir = tempfile::tempdir().unwrap();
        let htpasswd = dir.path().join(".htpasswd");
        fs::write(&htpasswd, "alice:$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope\n").unwrap();
        fs::write(
            dir.path().join(".htwicket.toml"),
            "[users.alice]\nis_admin = true\ndisplay_name = \"Alice\"\n",
        )
        .unwrap();

        let db = UserDb::load(cfg_with_fields(htpasswd)).unwrap();
        let alice = &db.users["alice"];
        assert_eq!(alice.fields["is_admin"], toml::Value::Boolean(true));
        assert_eq!(alice.fields["display_name"], toml::Value::String("Alice".into()));
        assert!(alice.hash.is_some());
        assert_eq!(alice.pwd_fp.as_ref().unwrap().len(), 16);
    }

    #[test]
    fn write_preserves_unknown_fields_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let htpasswd = dir.path().join(".htpasswd");
        let sidecar = dir.path().join(".htwicket.toml");
        fs::write(&htpasswd, "bob:$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope\n").unwrap();
        // App-foreign field htwicket knows nothing about — must survive a write.
        fs::write(&sidecar, "[users.bob]\nquota_mb = 500\n").unwrap();

        let mut db = UserDb::load(cfg_with_fields(htpasswd)).unwrap();
        let mut f = BTreeMap::new();
        f.insert("is_admin".to_string(), toml::Value::Boolean(true));
        db.write_fields("bob", &f).unwrap();

        let written = fs::read_to_string(&sidecar).unwrap();
        assert!(written.contains("quota_mb"), "unknown field dropped:\n{written}");
        assert!(written.contains("is_admin"));
        assert_eq!(db.users["bob"].fields["is_admin"], toml::Value::Boolean(true));
    }

    #[test]
    fn schema_errors_flags_type_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let htpasswd = dir.path().join(".htpasswd");
        fs::write(&htpasswd, "carol:$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope\n").unwrap();
        // is_admin declared bool but set to a string → schema error.
        fs::write(dir.path().join(".htwicket.toml"), "[users.carol]\nis_admin = \"yes\"\n").unwrap();

        let db = UserDb::load(cfg_with_fields(htpasswd)).unwrap();
        assert!(!db.schema_errors("carol").is_empty());
        assert!(db.schema_errors("alice").is_empty()); // unknown user: no fields, no errors
    }

    #[test]
    fn password_write_updates_file_and_fp() {
        let dir = tempfile::tempdir().unwrap();
        let htpasswd = dir.path().join(".htpasswd");
        let mut db = UserDb::load(cfg_with_fields(htpasswd.clone())).unwrap();

        let hash = crate::authn::hash_password("hunter2").unwrap();
        db.write_password("dave", &hash).unwrap();
        let file = fs::read_to_string(&htpasswd).unwrap();
        assert!(file.starts_with("dave:$2"));
        assert!(db.users["dave"].pwd_fp.is_some());

        db.delete_user("dave").unwrap();
        assert!(!db.users.contains_key("dave"));
        assert_eq!(fs::read_to_string(&htpasswd).unwrap(), "");
    }
}
