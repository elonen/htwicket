//! Askama view models. Rendering data is precomputed into plain fields/`FieldView`s so the
//! templates stay free of enum logic. `tr()` is the template-facing translation hook; it's an
//! English pass-through for now (per-request locale threading lands with the i18n catalogs).

use askama::Template;

/// Template-facing translation hook. askama resolves `{{ tr("...") }}` as `self.tr(...)`, so it
/// must be a method; a trait with a default impl lets every view share one English pass-through.
/// Per-request locale threading lands with the i18n catalogs (then this reads each view's `lang`).
trait Tr {
    fn tr(&self, msgid: &str) -> String {
        crate::i18n::tr(None, msgid)
    }
}
impl Tr for LoginTemplate {}
impl Tr for LogoutTemplate {}
impl Tr for AccountTemplate {}
impl Tr for AdminTemplate {}

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
    pub lang: &'static str,
    pub insecure_cookies: bool,
    pub error: Option<String>,
    pub rd: String,
}

#[derive(Template)]
#[template(path = "logout.html")]
pub struct LogoutTemplate {
    pub lang: &'static str,
    pub insecure_cookies: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    pub lang: &'static str,
    pub insecure_cookies: bool,
    pub username: String,
    pub fields: Vec<FieldView>,
    pub error: Option<String>,
    pub notice: Option<String>,
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
    pub lang: &'static str,
    pub insecure_cookies: bool,
    pub users: Vec<UserRow>,
    /// Blank field views for the "add user" form.
    pub add_fields: Vec<FieldView>,
    pub error: Option<String>,
    pub notice: Option<String>,
}
