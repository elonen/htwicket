//! Brute-force lockout on both the login form and the Basic passthrough branch of /auth (they
//! share one rate limiter).

mod common;

use common::{PW, client, spawn};

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
