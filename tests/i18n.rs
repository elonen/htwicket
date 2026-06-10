//! Locale negotiation: Accept-Language matching with English fallback, and the `default_lang`
//! override when `http_accept_language` is disabled.

mod common;

use common::{spawn, spawn_with};

#[test]
fn login_locale_follows_accept_language() {
    // Default config (http_accept_language=true, default_lang='en'): the browser's header picks
    // the locale when a catalog matches, else the page falls back to English.
    let srv = spawn("");
    let c = reqwest::blocking::Client::new();

    let fi = c
        .get(format!("{}/login", srv.base))
        .header(reqwest::header::ACCEPT_LANGUAGE, "fi-FI,fi;q=0.9")
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        fi.contains(r#"lang="fi""#),
        "expected Finnish <html lang>:\n{fi}"
    );
    assert!(
        fi.contains("Kirjaudu sisään"),
        "expected Finnish login copy"
    );

    // An unsupported language has no catalog → English fallback via default_lang.
    let en = c
        .get(format!("{}/login", srv.base))
        .header(reqwest::header::ACCEPT_LANGUAGE, "de-DE,de;q=0.9")
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        en.contains(r#"lang="en""#),
        "expected English <html lang>:\n{en}"
    );
}

#[test]
fn higher_priority_english_beats_lower_priority_catalog() {
    // A real browser header where English (source, no catalog) outranks Finnish must render
    // English — not fall through to the lower-q Finnish catalog.
    let srv = spawn("");
    let page = reqwest::blocking::Client::new()
        .get(format!("{}/login", srv.base))
        .header(
            reqwest::header::ACCEPT_LANGUAGE,
            "en-GB,en;q=0.9,fi;q=0.8,en-US;q=0.7",
        )
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(page.contains(r#"lang="en""#), "expected English:\n{page}");
    assert!(
        !page.contains("Kirjaudu sisään"),
        "should not render Finnish:\n{page}"
    );
}

#[test]
fn default_lang_used_when_accept_language_disabled() {
    // http_accept_language=false ignores the header entirely; default_lang ('fi') is the locale
    // even for an English-only browser.
    let srv = spawn_with(
        "",
        "http_accept_language = false\ndefault_lang = \"'fi'\"\n",
    );
    let c = reqwest::blocking::Client::new();

    let page = c
        .get(format!("{}/login", srv.base))
        .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        page.contains(r#"lang="fi""#),
        "Accept-Language should be ignored, default_lang ('fi') should win:\n{page}"
    );
    assert!(
        page.contains("Kirjaudu sisään"),
        "expected Finnish login copy"
    );
}
