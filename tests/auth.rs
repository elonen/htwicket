//! Login flow, /auth header outputs, Basic passthrough, the open-redirect guard, and sliding
//! session re-mint.

mod common;

use common::{PW, client, spawn};

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
