//! Askama view models. Rendering data is precomputed into plain fields/`FieldView`s so the
//! templates stay free of enum logic. `tr()` is the template-facing translation hook; it's an
//! English pass-through for now (per-request locale threading lands with the i18n catalogs).

use askama::Template;

/// Shared template helpers. askama resolves `{{ tr("...") }}` / `{{ css() }}` as method calls on
/// the view, so these live on a trait every view implements: `tr` threads the negotiated locale
/// into the i18n lookup, `css` inlines the embedded stylesheet, `version` stamps the footer.
trait Tr {
    fn lang(&self) -> &str;
    fn tr(&self, msgid: &str) -> String {
        crate::i18n::tr(self.lang(), msgid)
    }
    /// The whole stylesheet, embedded in the binary and inlined into <style> (use the `safe`
    /// filter — CSS contains `>` and `"`). One self-contained sheet, no runtime asset fetch.
    fn css(&self) -> &'static str {
        include_str!("htwicket.css")
    }
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}
impl Tr for LoginTemplate {
    fn lang(&self) -> &str {
        &self.lang
    }
}
impl Tr for LogoutTemplate {
    fn lang(&self) -> &str {
        &self.lang
    }
}
impl Tr for AccountTemplate {
    fn lang(&self) -> &str {
        &self.lang
    }
}
impl Tr for AdminTemplate {
    fn lang(&self) -> &str {
        &self.lang
    }
}

/// One schema field as shown in a form: a checkbox for bools, a text/email input otherwise,
/// or read-only text when the viewer may not edit it.
pub struct FieldView {
    pub name: String,
    pub label: String,
    pub is_bool: bool,
    pub input_type: &'static str, // "text" | "email"
    pub value: String,
    pub checked: bool,
    pub editable: bool,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub lang: String,
    pub insecure_cookies: bool,
    pub error: Option<String>,
    pub rd: String,
    /// Submitted username, preserved on a failed attempt (empty on first load).
    pub username: String,
}

#[derive(Template)]
#[template(path = "logout.html")]
pub struct LogoutTemplate {
    pub lang: String,
    pub insecure_cookies: bool,
    pub username: String,
}

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    pub lang: String,
    pub insecure_cookies: bool,
    pub username: String,
    pub fields: Vec<FieldView>,
    pub error: Option<String>,
    pub notice: Option<String>,
    /// cfg.min_password_len, for the client-side `minlength` hint (server still enforces).
    pub min_password_len: usize,
}

/// One row of the admin user table: username + every schema field as an editable `FieldView`.
pub struct UserRow {
    pub name: String,
    pub has_password: bool,
    pub fields: Vec<FieldView>,
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct AdminTemplate {
    pub lang: String,
    pub insecure_cookies: bool,
    pub users: Vec<UserRow>,
    pub error: Option<String>,
    pub notice: Option<String>,
    /// cfg.min_password_len, for the client-side `minlength` hint (server still enforces).
    pub min_password_len: usize,
}
