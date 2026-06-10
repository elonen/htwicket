//! gettext-style i18n: po/<locale>.po compiled by build.rs into a static lookup (no runtime
//! files); msgid = the English source string; missing entry falls back to source.
//! Locale comes from Accept-Language (no per-user preference storage in v1).
//!
//! TODO: build.rs PO compilation; until then this is a pass-through so templates can
//! already use tr().

pub fn tr(_locale: Option<&str>, msgid: &str) -> String {
    msgid.to_string()
}

pub fn tr_fmt(locale: Option<&str>, msgid: &str, params: &[(&str, &str)]) -> String {
    let mut out = tr(locale, msgid);
    for (name, value) in params {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}
