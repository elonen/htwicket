//! Page chrome: the base-path landing page, whitelabel branding (`app_title_html` rendered raw +
//! the htwicket footer kept on /admin only), and the login form's labels + heading.

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
fn login_form_has_heading_and_real_labels() {
    let srv = spawn("");
    let body = reqwest::blocking::get(format!("{}/login", srv.base))
        .unwrap()
        .text()
        .unwrap();
    // Standard, accessible form: an h2 page heading (h1 is reserved for app_title_html branding)
    // and real <label>s for each field — not placeholder-as-label.
    assert!(
        body.contains(r#"<h2 class="page-title">Sign in</h2>"#),
        "login should carry a Sign in heading:\n{body}"
    );
    assert!(
        body.contains(r#"<label for="username">"#) && body.contains(r#"<label for="password">"#),
        "username and password should have visible labels:\n{body}"
    );
    assert!(
        !body.contains("placeholder="),
        "fields should use labels, not placeholders:\n{body}"
    );
}
