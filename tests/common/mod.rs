//! Shared harness for the end-to-end tests: spawns the real `htwicket serve` binary against
//! tempdir state files and drives it over HTTP with reqwest. Each `tests/<domain>.rs` pulls this
//! in via `mod common;` (the `common/` subdir keeps Cargo from treating it as its own test binary).
#![allow(dead_code)] // each test binary uses only a subset of these helpers

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

// bcrypt of the password "password" (cost 5) — lets tests seed .htpasswd without hashing.
pub const PW_HASH: &str = "$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope";
pub const PW: &str = "password";

pub struct Server {
    child: Child,
    pub base: String,
    pub config: PathBuf,
    pub dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Spawn a server with the given sidecar contents and a couple of seeded users (admin, bob),
/// both with password "password". `admin` is a superadmin (by username); `bob` is not.
pub fn spawn(sidecar: &str) -> Server {
    spawn_with(sidecar, "")
}

/// As `spawn`, but `extra` is spliced in among the scalar top-level keys (must precede any
/// `[table]`), letting a test set keys like `password_hash` / `upgrade_hash_on_login`.
pub fn spawn_with(sidecar: &str, extra: &str) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let htpasswd = dir.path().join(".htpasswd");
    std::fs::write(&htpasswd, format!("admin:{PW_HASH}\nbob:{PW_HASH}\n")).unwrap();
    std::fs::write(dir.path().join(".htwicket.toml"), sidecar).unwrap();

    let port = free_port();
    let config = dir.path().join("htwicket.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
base_path = "/htwicket"
htpasswd_file = "{htpasswd}"
state_dir = "{state}"
insecure_cookies = true
basic_auth_passthrough = true
{extra}
[superadmins]
expr = "username == 'admin' || fields.is_admin"
[fields.is_admin]
type = "bool"
default = false
[fields.display_name]
type = "string"
default = ""
user_editable_expr = "true"
[fields.can_upload]
type = "bool"
default = true
user_visible = true
[headers.X-Remote-User-Is-Admin]
type = "bool"
expr = "fields.is_admin"
[headers.X-Remote-User-Name]
type = "string"
expr = "fields.display_name != '' ? fields.display_name : username"
"#,
            htpasswd = htpasswd.display(),
            state = dir.path().join("state").display(),
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_htwicket"))
        .arg("-c")
        .arg(&config)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let base = format!("http://127.0.0.1:{port}/htwicket");
    wait_ready(&base);
    Server {
        child,
        base,
        config,
        dir,
    }
}

fn wait_ready(base: &str) {
    let client = reqwest::blocking::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if client
            .get(format!("{base}/healthz"))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not become ready");
}

pub fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

pub fn check_exit(config: &Path, user: &str) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_htwicket"))
        .arg("-c")
        .arg(config)
        .args(["user", "check", user])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code()
        .unwrap()
}

/// Every `<attr>="..."` value in rendered HTML (double-quoted, which all the templates use). The
/// form-contract tests use this to assert the page emits exactly the input `name=`s / button
/// `value=`s the POST handlers read back, so template/handler drift fails a test instead of only
/// breaking a real browser.
pub fn attr_values(html: &str, attr: &str) -> Vec<String> {
    let pat = format!("{attr}=\"");
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(&pat) {
        rest = &rest[i + pat.len()..];
        if let Some(end) = rest.find('"') {
            out.push(rest[..end].to_string());
            rest = &rest[end + 1..];
        }
    }
    out
}

/// The `value="..."` of each element carrying `name="action"` — the admin submit/delete/add
/// buttons `admin_submit` dispatches on. Relies on the template emitting `name` before `value` on
/// the button (as admin.html does).
pub fn action_values(html: &str) -> Vec<String> {
    const NAME: &str = r#"name="action""#;
    const VALUE: &str = r#"value=""#;
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(NAME) {
        rest = &rest[i + NAME.len()..];
        if let Some(v) = rest.find(VALUE) {
            let after = &rest[v + VALUE.len()..];
            if let Some(end) = after.find('"') {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
        }
    }
    out
}

/// Force a strictly-later mtime so the server's mtime-based reload fires regardless of the
/// filesystem's timestamp resolution.
pub fn bump_mtime(path: &Path) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();
}
