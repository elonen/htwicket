//! End-to-end tests: spawn the real `htwicket serve` binary against tempdir state files and
//! drive it over HTTP with reqwest. Covers the login flow, /auth header outputs, Basic
//! passthrough, lockout, the admin gate + CRUD, and `user check` exit codes (PLAN "Testing").

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// bcrypt of the password "password" (cost 5) — lets tests seed .htpasswd without hashing.
const PW_HASH: &str = "$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope";
const PW: &str = "password";

struct Server {
    child: Child,
    base: String,
    config: PathBuf,
    _dir: tempfile::TempDir,
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
fn spawn(sidecar: &str) -> Server {
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
[superadmins]
expr = "username == 'admin' || fields.is_admin"
[fields.is_admin]
type = "bool"
default = false
[fields.display_name]
type = "string"
default = ""
user_editable = true
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
        _dir: dir,
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

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn check_exit(config: &Path, user: &str) -> i32 {
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

#[test]
fn login_then_auth_emits_cel_headers() {
    let srv = spawn("[users.admin]\ndisplay_name = \"Administrator\"\nis_admin = true\n");
    let c = client();

    // No cookie => bare 401.
    let r = c.get(format!("{}/auth", srv.base)).send().unwrap();
    assert_eq!(r.status(), 401);

    // Login (303 + Set-Cookie), then /auth returns the CEL-derived identity headers.
    let r = c
        .post(format!("{}/login", srv.base))
        .form(&[
            ("username", "admin"),
            ("password", PW),
            ("rd", "/dashboard"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers().get("location").unwrap(), "/dashboard");

    let r = c.get(format!("{}/auth", srv.base)).send().unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("x-remote-user-id").unwrap(), "admin");
    assert_eq!(r.headers().get("x-remote-user-is-admin").unwrap(), "true");
    assert_eq!(
        r.headers().get("x-remote-user-name").unwrap(),
        "Administrator"
    );
}

#[test]
fn basic_passthrough() {
    let srv = spawn("");
    let c = reqwest::blocking::Client::new();
    let r = c
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("x-remote-user-id").unwrap(), "bob");

    let r = c
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some("wrong"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[test]
fn open_redirect_rejected() {
    let srv = spawn("");
    let c = client();
    let r = c
        .post(format!("{}/login", srv.base))
        .form(&[
            ("username", "admin"),
            ("password", PW),
            ("rd", "//evil.example"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers().get("location").unwrap(), "/"); // bad rd falls back to "/"
}

#[test]
fn lockout_after_repeated_failures() {
    let srv = spawn("");
    let c = client();
    for _ in 0..6 {
        let _ = c
            .post(format!("{}/login", srv.base))
            .form(&[("username", "bob"), ("password", "wrong")])
            .send()
            .unwrap();
    }
    // Even the correct password is now refused (rate-limit runs before verification).
    let r = c
        .post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    let body = r.text().unwrap();
    assert!(
        body.contains("Too many failed attempts"),
        "expected lockout message, got:\n{body}"
    );
}

#[test]
fn admin_gate_and_add_user() {
    let srv = spawn("");
    // bob is not a superadmin => 403 on /admin.
    let cb = client();
    cb.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    assert_eq!(
        cb.get(format!("{}/admin", srv.base))
            .send()
            .unwrap()
            .status(),
        403
    );

    // admin can open /admin and add a user.
    let ca = client();
    ca.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();
    assert_eq!(
        ca.get(format!("{}/admin", srv.base))
            .send()
            .unwrap()
            .status(),
        200
    );

    let r = ca
        .post(format!("{}/admin", srv.base))
        .form(&[
            ("action", "add"),
            ("username", "carol"),
            ("new_password", "carolpassword"),
            ("f_is_admin", "on"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().unwrap().contains("carol"));

    // The new user can now authenticate via Basic and is flagged admin by the CEL header.
    let r = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("carol", Some("carolpassword"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("x-remote-user-is-admin").unwrap(), "true");
}

#[test]
fn user_check_exit_codes() {
    // schema-broken sidecar for bob: is_admin is a string, not a bool.
    let srv = spawn("[users.bob]\nis_admin = \"nope\"\n");
    assert_eq!(check_exit(&srv.config, "admin"), 0); // password set, schema ok
    assert_eq!(check_exit(&srv.config, "ghost"), 1); // missing
    assert_eq!(check_exit(&srv.config, "bob"), 2); // schema failure
}

#[test]
fn password_change_invalidates_session() {
    // Changing bob's password rotates pwd_fp, so an old cookie must stop working at /auth.
    let srv = spawn("");
    let c = client();
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    assert_eq!(
        c.get(format!("{}/auth", srv.base)).send().unwrap().status(),
        200
    );

    // Rotate bob's password out-of-band via the CLI (server reloads on mtime change).
    let mut child = Command::new(env!("CARGO_BIN_EXE_htwicket"))
        .arg("-c")
        .arg(&srv.config)
        .args(["user", "passwd", "bob"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"brandnewpassword\n")
        .unwrap();
    assert!(child.wait().unwrap().success());

    assert_eq!(
        c.get(format!("{}/auth", srv.base)).send().unwrap().status(),
        401
    );
}
