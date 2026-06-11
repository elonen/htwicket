//! Form-contract guard against template/handler drift. The other suites fabricate the form fields
//! a browser would post; these assert the rendered HTML actually emits that same contract — the
//! input `name=`s and button `value=`s the POST handlers read back — so a renamed field or button
//! fails here instead of only in a real browser. The admin case then drives a real action with a
//! value scraped from the page, proving the handler still honors what the template renders.

mod common;

use std::collections::HashSet;

use common::{PW, action_values, attr_values, client, spawn};

#[test]
fn login_form_emits_expected_inputs() {
    let srv = spawn("");
    let html = reqwest::blocking::get(format!("{}/login", srv.base))
        .unwrap()
        .text()
        .unwrap();
    let names: HashSet<String> = attr_values(&html, "name").into_iter().collect();
    for expected in ["username", "password", "rd"] {
        assert!(
            names.contains(expected),
            "login form missing input name={expected:?}:\n{html}"
        );
    }
}

#[test]
fn admin_form_emits_handler_contract() {
    let srv = spawn("");
    let c = client();
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();
    let html = c
        .get(format!("{}/admin", srv.base))
        .send()
        .unwrap()
        .text()
        .unwrap();

    // Per-row rename/password + per-field inputs the batch save reads, and the add-user form.
    let names: HashSet<String> = attr_values(&html, "name").into_iter().collect();
    for expected in [
        "username[bob]",
        "password[bob]",
        "f_is_admin[bob]",
        "f_display_name[bob]",
        "f_can_upload[bob]",
        "username",     // add-user form
        "new_password", // add-user form
    ] {
        assert!(
            names.contains(expected),
            "admin form missing name={expected:?}:\n{html}"
        );
    }

    // The action buttons admin_submit dispatches on.
    let actions: HashSet<String> = action_values(&html).into_iter().collect();
    for expected in ["save", "add", "delete:admin", "delete:bob"] {
        assert!(
            actions.contains(expected),
            "admin missing action button value={expected:?}:\n{html}"
        );
    }

    // Drive a real delete with the value scraped from the page (not a hardcoded string): if the
    // template's delete value drifts, the scrape misses and this fails — and otherwise it covers
    // the delete path end to end (no other test does).
    let delete_bob = action_values(&html)
        .into_iter()
        .find(|a| a.starts_with("delete:") && a.ends_with("bob"))
        .expect("admin page should render a delete button for bob");
    let r = c
        .post(format!("{}/admin", srv.base))
        .form(&[("action", delete_bob.as_str())])
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    let gone = reqwest::blocking::Client::new()
        .get(format!("{}/auth", srv.base))
        .basic_auth("bob", Some(PW))
        .send()
        .unwrap();
    assert_eq!(
        gone.status(),
        401,
        "deleted user must no longer authenticate"
    );
}

#[test]
fn account_form_emits_password_inputs() {
    let srv = spawn("");
    let c = client();
    c.post(format!("{}/login", srv.base))
        .form(&[("username", "bob"), ("password", PW)])
        .send()
        .unwrap();
    let html = c
        .get(format!("{}/account", srv.base))
        .send()
        .unwrap()
        .text()
        .unwrap();
    // The self-service password-change inputs account_submit reads.
    let names: HashSet<String> = attr_values(&html, "name").into_iter().collect();
    for expected in ["old_password", "new_password"] {
        assert!(
            names.contains(expected),
            "account form missing name={expected:?}:\n{html}"
        );
    }
}
