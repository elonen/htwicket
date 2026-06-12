//! The /admin superadmin gate and CRUD (add, batch save/rename/edit, duplicate rejection) plus
//! the per-field visibility/editability rules on /account.

mod common;

use common::{PW, client, spawn};

#[test]
fn admin_gate_and_add_user() {
    let srv = spawn("");
    // bob is not a superadmin => custom 403 page on /admin (not the bare browser 403).
    let cb = client();
    cb.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    let denied = cb.get(format!("{}/admin", srv.base)).send().unwrap();
    assert_eq!(denied.status(), 403);
    assert!(
        denied.text().unwrap().contains("Access denied"),
        "non-admin should get the custom 403 page"
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
fn add_user_can_set_profile_fields() {
    let srv = spawn("");
    let ca = client();
    ca.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();
    // Adding a user now accepts profile fields (`f_<name>`) in the same request, so an admin
    // configures the account at creation instead of add-then-edit.
    let r = ca
        .post(format!("{}/admin", srv.base))
        .form(&[
            ("action", "add"),
            ("username", "dave"),
            ("new_password", "davepassword"),
            ("f_display_name", "Dave"),
            ("f_is_admin", "on"),
        ])
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    // Persisted at creation: /auth headers reflect the fields immediately.
    let auth = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("dave", Some("davepassword"))
        .send()
        .unwrap();
    assert_eq!(auth.status(), 200);
    assert_eq!(auth.headers().get("x-remote-user-name").unwrap(), "Dave");
    assert_eq!(
        auth.headers().get("x-remote-user-is-admin").unwrap(),
        "true"
    );
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
fn account_admin_shortcut_only_for_superadmins() {
    let srv = spawn("");

    // admin (a superadmin) sees the /admin shortcut on their own account page.
    let ca = client();
    ca.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();
    let admin_page = ca
        .get(format!("{}/account", srv.base))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        admin_page.contains(r#"href="/htwicket/admin""#),
        "superadmin account page should link to /admin:\n{admin_page}"
    );

    // bob is not a superadmin => no shortcut.
    let cb = client();
    cb.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    let bob_page = cb
        .get(format!("{}/account", srv.base))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        !bob_page.contains(r#"href="/htwicket/admin""#),
        "non-superadmin account page must not link to /admin:\n{bob_page}"
    );
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
        page.contains("Can upload"),
        "user_visible field should still be shown"
    );
    assert!(
        !page.contains("Is admin"),
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
