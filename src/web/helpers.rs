//! Low-level request helpers shared across the handlers: cookie/Basic parsing, the Origin-vs-Host
//! CSRF guard, open-redirect validation, client-IP extraction, cookie minting, template rendering,
//! and locale negotiation.

use std::collections::BTreeMap;

use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine as _;

use crate::cel::{self, CelValue};
use crate::config::Config;
use crate::i18n::best_locale;
use crate::state::User;
use crate::token::{self, Claims};

use super::{AppError, AppState, Handler};

/// Check if the DB file has changed on disk since we last loaded it, and if so, reload.
pub(super) async fn ensure_db_fresh(state: &AppState) -> Result<(), AppError> {
    if state.db.read().await.changed_on_disk() {
        let mut w = state.db.write().await;
        if w.reload_if_changed()? {
            state.cache.clear();
        }
    }
    Ok(())
}

pub(super) fn get_and_validate_token_claims(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<Claims> {
    let token = cookie_value(headers, token::COOKIE_NAME)?;
    token::verify_jwt(&token, &state.keys, state.cfg.session_max_days)
}

/// Authenticated UI user behind the session cookie, applying the SAME revocation gate as `/auth`:
/// valid token + the user still exists + `pwd_fp` still matches (a rotated password evicts the
/// cookie everywhere, not only at `/auth`). Returns the claims; callers re-read the DB for what
/// they render. Run `ensure_db_fresh` first so the fingerprint compares against current state.
pub(super) async fn authed_claims(headers: &HeaderMap, state: &AppState) -> Option<Claims> {
    let claims = get_and_validate_token_claims(headers, state)?;
    let db = state.db.read().await;
    let user = db.users.get(&claims.sub)?;
    (claims.pwd_fp.is_none() || claims.pwd_fp == user.pwd_fp).then_some(claims)
}

/// Extract a cookie value by name, if present and well-formed.
pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie::Cookie::split_parse(raw)
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_string())
}

/// Parse HTTP Basic credentials, if present and well-formed.
pub(super) fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    // Auth scheme is case-insensitive (RFC 7235); accept any casing of `Basic`.
    let (scheme, b64) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Origin-vs-Host CSRF guard. Missing Origin is allowed (SameSite=Lax covers it; curl/older
/// clients send none); a present Origin must match the Host authority.
pub(super) fn csrf_origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    // Host/authority is case-insensitive (RFC 3986); compare without folding the attacker any slack.
    origin
        .split_once("://")
        .is_some_and(|(_, authority)| authority.eq_ignore_ascii_case(host))
}

/// Anti-open-redirect: only same-origin absolute paths pass, so anything that survives is safe to
/// hand straight to `Location`.
pub(super) fn valid_redirect(rd: &str) -> bool {
    rd.starts_with('/')                              // same-origin absolute path (no scheme/authority)
        && !rd.starts_with("//")                     // protocol-relative `//evil.com`
        && !rd.starts_with("/\\")                    // `/\evil.com` — browsers fold `\`→`/`, so == `//`
        && !rd.contains(|c: char| c.is_control()) // CR/LF & other control chars → `Location` injection
}

/// Best-effort client IP for rate-limit keying and logs. Takes the *rightmost* `X-Forwarded-For`
/// entry: that's the peer our trusted reverse proxy actually saw and appended, whereas any
/// client-supplied XFF values sit to its left — so this can't be spoofed to rotate the lockout key.
/// Not validated as an IP; it's only ever a bucket/log key, so a junk value just buckets separately.
pub(super) fn forwarded_for_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn redirect_to_login(state: &AppState, rd: &str) -> Response {
    Redirect::to(&format!("{}?rd={rd}", state.cfg.self_url("/login"))).into_response()
}

/// Session cookie header; an empty token clears the cookie (Max-Age=0).
pub(super) fn cookie_header(token: &str, cfg: &Config) -> Result<HeaderValue, AppError> {
    let max_age = if token.is_empty() {
        0
    } else {
        cfg.session_idle_hours as i64 * 3600
    };
    let c = cookie::Cookie::build((token::COOKIE_NAME, token))
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(max_age))
        .secure(!cfg.insecure_cookies)
        .build();
    Ok(HeaderValue::from_str(&c.to_string())?)
}

pub(super) fn render<T: askama::Template>(t: T) -> Handler {
    Ok(Html(t.render()?).into_response())
}

/// Negotiate the request locale: the browser's Accept-Language (matched against the compiled
/// catalogs) when `http_accept_language` is on and it matches; otherwise the `default_lang` CEL
/// fallback over {username, fields.*}, and "en" if that errors (e.g. `fields.*` on a pre-login
/// page) or yields a non-string.
pub(super) fn lang_of(
    state: &AppState,
    headers: &HeaderMap,
    user: Option<&User>,
    username: &str,
) -> String {
    if state.cfg.http_accept_language {
        let header = headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok());
        if let Some(loc) = best_locale(header) {
            return loc;
        }
    }
    let empty: BTreeMap<String, toml::Value> = BTreeMap::new();
    let fields = user.map(|u| &u.fields).unwrap_or(&empty);
    match cel::context(fields, username)
        .and_then(|ctx| cel::eval(&state.compiled.default_lang, &ctx))
    {
        Ok(CelValue::Str(s)) => s,
        _ => "en".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{csrf_origin_ok, valid_redirect};
    use axum::http::{HeaderMap, HeaderValue};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for &(k, v) in pairs {
            h.insert(k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn valid_rd_accepts_relative_rejects_external_and_control() {
        for ok in ["/", "/x", "/dashboard", "/a/b?q=1#frag"] {
            assert!(valid_redirect(ok), "should accept {ok:?}");
        }
        // empty, scheme, protocol-relative, backslash trick, and control chars are all open-redirect
        // or smuggling risks.
        for bad in ["", "https://evil", "//evil", "/\\evil", "/a\nb", "/a\0b"] {
            assert!(!valid_redirect(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn origin_ok_requires_matching_authority() {
        // No Origin at all is allowed — curl/older clients send none; SameSite=Lax covers it.
        assert!(csrf_origin_ok(&headers(&[("host", "auth.example")])));
        // A present Origin must match the Host authority.
        assert!(csrf_origin_ok(&headers(&[
            ("origin", "https://auth.example"),
            ("host", "auth.example"),
        ])));
        // A foreign Origin is the CSRF case → reject.
        assert!(!csrf_origin_ok(&headers(&[
            ("origin", "https://evil.example"),
            ("host", "auth.example"),
        ])));
        // A present Origin with no Host to compare against can't be validated → reject.
        assert!(!csrf_origin_ok(&headers(&[(
            "origin",
            "https://auth.example"
        )])));
    }
}
