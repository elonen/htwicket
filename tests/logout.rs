//! Logout flow: the GET confirm page, cookie clearing on POST, and that the session is dead at
//! /auth afterwards — the GUI's "real logout" headline, otherwise only exercised by hand.

mod common;

use common::{PW, client, spawn};

#[test]
fn logout_confirms_then_clears_session() {
    let srv = spawn("");
    let c = client();

    // Logged out: GET /logout has nothing to confirm → redirect to login.
    let r = c.get(format!("{}/logout", srv.base)).send().unwrap();
    assert_eq!(r.status(), 303);
    assert!(
        r.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("/login"),
        "logged-out /logout should redirect to login"
    );

    // Log in, then the confirm page names the signed-in user.
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    let confirm = c.get(format!("{}/logout", srv.base)).send().unwrap();
    assert_eq!(confirm.status(), 200);
    assert!(
        confirm.text().unwrap().contains("bob"),
        "confirm page should name the signed-in user"
    );

    // Session is live before logout.
    assert_eq!(
        c.get(format!("{}/auth", srv.base)).send().unwrap().status(),
        200
    );

    // POST /logout clears the cookie (Max-Age=0) and redirects to login.
    let out = c.post(format!("{}/logout", srv.base)).send().unwrap();
    assert_eq!(out.status(), 303);
    assert!(
        out.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("/login"),
        "logout should redirect to login"
    );
    let set = out
        .headers()
        .get("set-cookie")
        .expect("logout must emit a cookie-clearing Set-Cookie")
        .to_str()
        .unwrap();
    assert!(
        set.contains("Max-Age=0"),
        "logout cookie should expire immediately: {set}"
    );

    // The client dropped the cleared cookie → /auth is back to 401.
    assert_eq!(
        c.get(format!("{}/auth", srv.base)).send().unwrap().status(),
        401
    );
}
