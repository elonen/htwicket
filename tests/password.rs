//! Password lifecycle: session revocation on password change (pwd_fp rotation) via both the
//! offline CLI and the /account self-service form, lazy hash migration on login, and Basic
//! verify-cache invalidation on file reload.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{PW, PW_HASH, bump_mtime, client, spawn, spawn_with};

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
fn account_password_change_revokes_old_sessions() {
    // The /account self-service form is the GUI path behind "Changing it signs you out of all
    // sessions": a successful change rotates pwd_fp, so the cookie minted under the old password
    // stops working at /auth. (Distinct from the CLI path above — same effect, different entry.)
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

    let r = c
        .post(format!("{}/account", srv.base))
        .form(&[("old_password", PW), ("new_password", "brandnewpassword")])
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.text().unwrap().contains("Password changed."),
        "account form should confirm the change"
    );

    // Old cookie is now stale (pwd_fp mismatch) → 401.
    assert_eq!(
        c.get(format!("{}/auth", srv.base)).send().unwrap().status(),
        401
    );
    // The new password authenticates.
    let basic = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some("brandnewpassword"))
        .send()
        .unwrap();
    assert_eq!(basic.status(), 200);
}

#[test]
fn account_password_change_validation_keeps_old_password() {
    // Wrong current password and too-short new password are each rejected with a message, and the
    // stored password is left untouched (the original still authenticates).
    let srv = spawn("");
    let c = client();
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();

    let wrong_old = c
        .post(format!("{}/account", srv.base))
        .form(&[
            ("old_password", "nope"),
            ("new_password", "brandnewpassword"),
        ])
        .send()
        .unwrap();
    assert!(
        wrong_old
            .text()
            .unwrap()
            .contains("Current password is incorrect."),
        "wrong current password should be rejected"
    );

    let too_short = c
        .post(format!("{}/account", srv.base))
        .form(&[("old_password", PW), ("new_password", "short")])
        .send()
        .unwrap();
    assert!(
        too_short
            .text()
            .unwrap()
            .contains("New password is too short."),
        "too-short new password should be rejected"
    );

    let basic = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(
        basic.status(),
        200,
        "password must be unchanged after rejections"
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
