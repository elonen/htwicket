//! End-to-end tests: spawn the real `htwicket serve` binary against tempdir state files and
//! drive it over HTTP with reqwest. Covers the login flow, /auth header outputs, Basic
//! passthrough, lockout, the admin gate + CRUD, and `user check` exit codes (docs/architecture.md).

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

// bcrypt of the password "password" (cost 5) — lets tests seed .htpasswd without hashing.
const PW_HASH: &str = "$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope";
const PW: &str = "password";

struct Server {
    child: Child,
    base: String,
    config: PathBuf,
    dir: tempfile::TempDir,
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
    spawn_with(sidecar, "")
}

/// As `spawn`, but `extra` is spliced in among the scalar top-level keys (must precede any
/// `[table]`), letting a test set keys like `password_hash` / `upgrade_hash_on_login`.
fn spawn_with(sidecar: &str, extra: &str) -> Server {
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

/// Force a strictly-later mtime so the server's mtime-based reload fires regardless of the
/// filesystem's timestamp resolution.
fn bump_mtime(path: &Path) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();
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
fn basic_lockout_after_repeated_failures() {
    // The Basic passthrough branch of /auth shares the login form's limiter: repeated wrong
    // passwords lock the user out, after which even the correct password is refused.
    let srv = spawn("");
    let c = reqwest::blocking::Client::new();
    for _ in 0..6 {
        let r = c
            .get(format!("{}/auth", srv.base))
            .basic_auth("bob", Some("wrong"))
            .send()
            .unwrap();
        assert_eq!(r.status(), 401);
    }
    // Correct password, but the lockout is in force ⇒ still 401 (verify is never reached).
    let r = c
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(r.status(), 401);
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

    // Add a user (password only — fields take their config defaults).
    let r = ca
        .post(format!("{}/admin", srv.base))
        .form(&[
            ("action", "add"),
            ("username", "carol"),
            ("new_password", "carolpassword"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().unwrap().contains("carol"));

    // The new user can now authenticate via Basic; is_admin defaults to false (not set at add).
    let r = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("carol", Some("carolpassword"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("x-remote-user-is-admin").unwrap(), "false");
}

#[test]
fn admin_batch_save_renames_and_edits() {
    let srv = spawn("");
    let ca = client();
    ca.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();

    // One batch save (whole table): rename bob -> bob2, grant is_admin, set a display name.
    // admin's row is sent too (browser submits every row); keep its can_upload on.
    let r = ca
        .post(format!("{}/admin", srv.base))
        .form(&[
            ("action", "save"),
            ("username[admin]", "admin"),
            ("f_can_upload[admin]", "on"),
            ("username[bob]", "bob2"),
            ("f_display_name[bob]", "Bob Renamed"),
            ("f_is_admin[bob]", "on"),
            ("f_can_upload[bob]", "on"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);

    let basic = reqwest::blocking::Client::new();
    // Old name is gone...
    let old = basic
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(old.status(), 401);
    // ...renamed user keeps the original password and carries the edited fields.
    let new = basic
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob2", Some(PW))
        .send()
        .unwrap();
    assert_eq!(new.status(), 200);
    assert_eq!(
        new.headers().get("x-remote-user-name").unwrap(),
        "Bob Renamed"
    );
    assert_eq!(new.headers().get("x-remote-user-is-admin").unwrap(), "true");
}

#[test]
fn admin_save_rejects_duplicate_username() {
    let srv = spawn("");
    let ca = client();
    ca.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();
    // Renaming bob onto the existing "admin" must be refused, and bob must survive.
    let r = ca
        .post(format!("{}/admin", srv.base))
        .form(&[("action", "save"), ("username[bob]", "admin")])
        .send()
        .unwrap();
    assert!(r.text().unwrap().contains("already exists"));
    let still = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(still.status(), 200);
}

#[test]
fn account_visibility_and_editability() {
    let srv = spawn("");
    let c = client();
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();

    // /account for bob: display_name is editable (input), can_upload is read-only (no input),
    // is_admin is neither visible nor editable (absent entirely).
    let page = c
        .get(format!("{}/account", srv.base))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        page.contains(r#"name="f_display_name""#),
        "editable field missing an input"
    );
    assert!(
        !page.contains(r#"name="f_can_upload""#),
        "read-only field should have no input"
    );
    assert!(
        page.contains("can upload"),
        "user_visible field should still be shown"
    );
    assert!(
        !page.contains("is admin"),
        "non-visible field leaked onto /account"
    );

    // bob tries to grant himself is_admin (not editable for him) while editing display_name.
    c.post(format!("{}/account", srv.base))
        .form(&[
            ("f_display_name", "Bobby"),
            ("f_is_admin", "on"),
            ("f_can_upload", "on"),
        ])
        .send()
        .unwrap();

    // Editable change took; the non-editable is_admin was ignored (still not a superadmin).
    let auth = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(auth.headers().get("x-remote-user-name").unwrap(), "Bobby");
    assert_eq!(
        auth.headers().get("x-remote-user-is-admin").unwrap(),
        "false"
    );
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

#[test]
fn login_migrates_hash_to_configured_algo() {
    // bob is seeded as bcrypt. With password_hash=argon2id + upgrade_hash_on_login, a successful
    // login (server holds the plaintext) must rewrite his .htpasswd line to argon2id; a user who
    // never logs in stays bcrypt.
    let srv = spawn_with(
        "",
        "password_hash = \"argon2id\"\nupgrade_hash_on_login = true",
    );
    let htpasswd = srv.dir.path().join(".htpasswd");

    let before = std::fs::read_to_string(&htpasswd).unwrap();
    assert!(
        before.lines().all(|l| l.contains(":$2")),
        "precondition: both users seeded bcrypt:\n{before}"
    );

    let c = client();
    let r = c
        .post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    assert_eq!(r.status(), 303); // rehash is written before the response returns

    let after = std::fs::read_to_string(&htpasswd).unwrap();
    assert!(
        after.lines().any(|l| l.starts_with("bob:$argon2id$")),
        "login did not migrate bob to argon2id:\n{after}"
    );
    assert!(
        after.lines().any(|l| l.starts_with("admin:$2")),
        "admin never logged in, should stay bcrypt:\n{after}"
    );

    // The migrated argon2id hash still authenticates with the same password.
    let auth = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(auth.status(), 200);
}

#[test]
fn sliding_remint_emits_fresh_cookie() {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

    let srv = spawn("");

    // Negative: a fresh login followed by an immediate /auth must NOT re-mint.
    let c = client();
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    let r = c.get(format!("{}/auth", srv.base)).send().unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers().get("set-cookie").is_none(),
        "a fresh session must not be re-minted"
    );

    // Positive: hand-mint a token whose iat is 7h old — past half of the default 12h idle window —
    // so /auth must slide it. session_idle_hours can't be tuned below 1h, so a live wait is
    // impossible; mint directly with the server's secret instead.
    let secret = std::fs::read(srv.dir.path().join("state").join("jwt_secret")).unwrap();
    let now = jsonwebtoken::get_current_timestamp();
    let orig_iat = now - 2 * 86400; // 2 days ago: distinct from iat, inside the 7-day absolute cap
    let claims = serde_json::json!({
        "sub": "bob",
        "iat": now - 7 * 3600,
        "exp": now + 5 * 3600, // iat + 12h idle, still in the future
        "iss": "htwicket",
        "orig_iat": orig_iat,
        "factors": ["pw"],
        // pwd_fp omitted: a token without it is accepted (skips the fingerprint check).
    });
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
    .unwrap();

    let r = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .header(reqwest::header::COOKIE, format!("htwicket_session={token}"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers().get("x-remote-user-id").unwrap(), "bob");
    let set = r
        .headers()
        .get("set-cookie")
        .expect("aged session should re-mint a Set-Cookie")
        .to_str()
        .unwrap();
    let fresh = set
        .split("htwicket_session=")
        .nth(1)
        .expect("Set-Cookie is for the session cookie")
        .split(';')
        .next()
        .unwrap();

    // The re-minted token carries a fresh iat but the *original* orig_iat (sliding, not re-login).
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&["htwicket"]);
    v.validate_aud = false;
    let data =
        jsonwebtoken::decode::<serde_json::Value>(fresh, &DecodingKey::from_secret(&secret), &v)
            .unwrap();
    assert_eq!(data.claims["orig_iat"].as_u64().unwrap(), orig_iat);
    assert!(
        data.claims["iat"].as_u64().unwrap() > now - 7 * 3600,
        "re-minted iat was not refreshed"
    );
}

#[test]
fn basic_cache_cleared_on_file_reload() {
    // A successful Basic verify is cached for 5 min. Rewriting the user's hash bumps the file's
    // mtime, which forces a reload that clears the cache — so the old password must stop working
    // immediately rather than riding the cache until TTL expiry.
    let srv = spawn("");
    let htpasswd = srv.dir.path().join(".htpasswd");
    let c = reqwest::blocking::Client::new();

    // Prime the cache with a good Basic auth.
    let r = c
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);

    // Rewrite bob's entry to a different password's hash, then bump mtime to guarantee a reload.
    let other = bcrypt::hash("a-different-password", 5).unwrap();
    std::fs::write(&htpasswd, format!("admin:{PW_HASH}\nbob:{other}\n")).unwrap();
    bump_mtime(&htpasswd);

    // The old password is no longer cached and no longer matches ⇒ immediate 401.
    let r = c
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(r.status(), 401);

    // Sanity: the new password authenticates against the reloaded file.
    let r = c
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some("a-different-password"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
}
