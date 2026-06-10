//! Page chrome: the base-path landing page, whitelabel branding (`app_title_html` rendered raw +
//! the htwicket footer kept on /admin only), and the placeholder-only login form.

mod common;

use common::{PW, client, spawn, spawn_with};

#[test]
fn index_links_to_account_and_admin() {
    let srv = spawn("");
    // The landing page lives at the base-path root, with and without the trailing slash.
    for url in [format!("{}/", srv.base), srv.base.clone()] {
        let r = reqwest::blocking::get(&url).unwrap();
        assert_eq!(r.status(), 200, "index not served at {url}");
        let body = r.text().unwrap();
        assert!(
            body.contains(r#"href="/htwicket/account""#),
            "index missing account link at {url}:\n{body}"
        );
        assert!(
            body.contains(r#"href="/htwicket/admin""#),
            "index missing admin link at {url}:\n{body}"
        );
    }
}

#[test]
fn app_title_html_is_raw_everywhere_footer_admin_only() {
    let srv = spawn_with("", "app_title_html = \"<b id=brand>ACME</b>\"\n");

    // Login page: branding rendered unescaped; the htwicket footer is gone (whitelabel default).
    let login = reqwest::blocking::get(format!("{}/login", srv.base))
        .unwrap()
        .text()
        .unwrap();
    assert!(
        login.contains("<b id=brand>ACME</b>"),
        "app_title_html should render raw on login:\n{login}"
    );
    assert!(
        !login.contains(r#"class="foot""#),
        "footer should be hidden on login:\n{login}"
    );

    // Admin page: branding shows here too, and the footer is retained only on this view.
    let ca = client();
    ca.post(format!("{}/login", srv.base))
        .form(&[("username", "admin"), ("password", PW)])
        .send()
        .unwrap();
    let admin = ca
        .get(format!("{}/admin", srv.base))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        admin.contains("<b id=brand>ACME</b>"),
        "app_title_html missing on admin:\n{admin}"
    );
    assert!(
        admin.contains(r#"class="foot""#),
        "footer should remain on admin:\n{admin}"
    );
}

#[test]
fn login_form_uses_placeholders_and_has_no_heading() {
    let srv = spawn("");
    let body = reqwest::blocking::get(format!("{}/login", srv.base))
        .unwrap()
        .text()
        .unwrap();
    // The redundant <h1> heading is gone; the field labels moved into placeholders.
    assert!(
        !body.contains("<h1>"),
        "login should carry no heading:\n{body}"
    );
    assert!(
        body.contains(r#"placeholder="Username""#),
        "username label should be a placeholder:\n{body}"
    );
    assert!(
        body.contains(r#"placeholder="Password""#),
        "password label should be a placeholder:\n{body}"
    );
}
