//! Route handlers: the nginx `auth_request` target plus the login / logout / account / admin
//! pages and their POST actions. Each returns `Handler` (an internal failure becomes 500 + log).

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::authn::{self, Throttle};
use crate::cel;
use crate::i18n::tr;
use crate::session::{self, Claims};
use crate::state::UserDb;

use super::helpers::{
    basic_credentials, client_ip, cookie_header, current_claims, ensure_fresh, lang_of, origin_ok,
    redirect_to_login, render, valid_rd,
};
use super::templates::{AccountTemplate, LogoutTemplate};
use super::views::{
    account_field_views, auth_response_headers, collect_fields, eval_jwt_claims, field_editable,
    is_superadmin, render_admin, render_login,
};
use super::{AppError, AppState, Handler};

/// nginx auth_request target. Order: session cookie → Basic (if passthrough) → 401 (bare).
/// 200: X-Remote-User-Id + [headers.*] CEL outputs + sliding re-mint Set-Cookie.
pub(super) async fn auth(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    ensure_fresh(&state).await?;
    let db = state.db.read().await;

    // 1) Session cookie.
    if let Some(claims) = current_claims(&headers, &state)
        && let Some(user) = db.users.get(&claims.sub)
        && (claims.pwd_fp.is_none() || claims.pwd_fp == user.pwd_fp)
    {
        let mut out = auth_response_headers(&state, user, &claims.sub)?;
        let reminted = session::needs_remint(&claims, session::now(), state.cfg.session_idle_hours);
        if reminted {
            let next = session::remint(&claims, session::now(), state.cfg.session_idle_hours);
            let token = session::mint(&next, &state.keys)?;
            out.insert(header::SET_COOKIE, cookie_header(&token, &state.cfg)?);
        }
        tracing::debug!(user = %claims.sub, reminted, "auth ok via session cookie");
        return Ok((StatusCode::OK, out).into_response());
    }

    // 2) Basic passthrough (scripted clients). Never mints a cookie. Brute-force limited via the
    //    same RateLimiter as the login form, but only cache *misses* touch it: an authenticated
    //    client that polls /auth on every proxied request must never spend per-IP budget. See
    //    docs/security.md "Brute force".
    if state.cfg.basic_auth_passthrough
        && let Some((user, pass)) = basic_credentials(&headers)
        && let Some(u) = db.users.get(&user)
    {
        if state.cache.check(&user, &pass) {
            let out = auth_response_headers(&state, u, &user)?;
            tracing::debug!(user = %user, "auth ok via basic (verify cache hit)");
            return Ok((StatusCode::OK, out).into_response());
        }
        // Cache miss ⇒ a real bcrypt verify. Gate it on the limiter (a locked-out user is refused
        // even with the right password) and count only failures.
        let ip = client_ip(&headers);
        if state.limiter.check(&user, &ip).is_ok() {
            let hash = u.hash.clone();
            drop(db); // bcrypt takes ~100ms of CPU; don't hold the read lock across it
            let good = match hash {
                Some(h) => authn::verify_password_blocking(pass.clone(), h).await,
                None => false,
            };
            if !good {
                state.limiter.record_failure(&user, &ip);
                return Ok(StatusCode::UNAUTHORIZED.into_response());
            }
            state.limiter.record_success(&user, &ip);
            state.cache.store(&user, &pass);
            let db = state.db.read().await; // re-acquire: the user may have changed mid-verify
            if let Some(u) = db.users.get(&user) {
                let out = auth_response_headers(&state, u, &user)?;
                tracing::debug!(user = %user, "auth ok via basic (password verified)");
                return Ok((StatusCode::OK, out).into_response());
            }
        }
    }

    // 3) Bare 401 (nginx swallows subrequest body; browsers handled by error_page redirect).
    tracing::debug!(ip = %client_ip(&headers), "auth denied → 401");
    Ok(StatusCode::UNAUTHORIZED.into_response())
}

#[derive(Deserialize)]
pub(super) struct RdQuery {
    rd: Option<String>,
}

pub(super) async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RdQuery>,
) -> Handler {
    let rd = q.rd.unwrap_or_default();
    tracing::debug!(rd = %rd, "GET login page");
    render_login(
        &state,
        &lang_of(&state, &headers, None, ""),
        rd,
        None,
        String::new(),
    )
}

#[derive(Deserialize)]
pub(super) struct LoginForm {
    username: String,
    password: String,
    rd: Option<String>,
}

/// Verify (rate-limited), mint the session JWT (factors=["pw"], pwd_fp, jwt-claims), 303 to rd.
/// Optionally rehash an entry not in `password_hash` to it (upgrade_hash_on_login).
pub(super) async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Handler {
    if !origin_ok(&headers) {
        tracing::debug!(user = %form.username, "POST login rejected: Origin/Host mismatch");
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let lang = lang_of(&state, &headers, None, ""); // no authenticated user yet
    let rd = form.rd.unwrap_or_default();
    let ip = client_ip(&headers);
    tracing::debug!(user = %form.username, ip = %ip, "POST login attempt");
    if let Err(t) = state.limiter.check(&form.username, &ip) {
        let msg = match t {
            Throttle::Ip => tr(
                &lang,
                "Too many attempts from your network. Wait a minute and retry.",
            ),
            Throttle::User => tr(&lang, "Too many failed attempts. Try again shortly."),
        };
        return render_login(&state, &lang, rd, Some(msg), form.username.clone());
    }
    ensure_fresh(&state).await?;

    let hash = {
        let db = state.db.read().await;
        db.users.get(&form.username).and_then(|u| u.hash.clone())
    };
    let good = match &hash {
        Some(h) => authn::verify_password_blocking(form.password.clone(), h.clone()).await,
        None => false,
    };
    if !good {
        state.limiter.record_failure(&form.username, &ip);
        return render_login(
            &state,
            &lang,
            rd,
            Some(tr(&lang, "Invalid username or password.")),
            form.username.clone(),
        );
    }
    state.limiter.record_success(&form.username, &ip);

    // Opt-in: rehash an entry not in the configured algorithm now that we hold the plaintext.
    let hash = hash.unwrap();
    if state.cfg.upgrade_hash_on_login
        && authn::needs_rehash(&hash, state.cfg.password_hash)
        && let Ok(new_hash) =
            authn::hash_password_blocking(form.password.clone(), state.cfg.password_hash).await
    {
        let _ = state
            .db
            .write()
            .await
            .write_password(&form.username, &new_hash);
    }

    // Read fresh pwd_fp + bake jwt-claims after any rehash.
    let (pwd_fp, extra) = {
        let db = state.db.read().await;
        let user = db.users.get(&form.username);
        let fp = user.and_then(|u| u.pwd_fp.clone());
        let extra = eval_jwt_claims(&state, user, &form.username)?;
        (fp, extra)
    };
    let claims = session::new_session(
        &form.username,
        vec!["pw".into()],
        pwd_fp,
        extra,
        session::now(),
        state.cfg.session_idle_hours,
    );
    let token = session::mint(&claims, &state.keys)?;
    let target = if valid_rd(&rd) { rd } else { "/".to_string() };
    tracing::debug!(user = %form.username, target = %target, "login: session minted, redirecting");
    let mut resp = Redirect::to(&target).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie_header(&token, &state.cfg)?);
    Ok(resp)
}

pub(super) async fn logout_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    // Confirm page needs the current identity for "signed in as <user>". Not logged in => nothing
    // to confirm; send them to login.
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/"));
    };
    let db = state.db.read().await;
    let lang = lang_of(&state, &headers, db.users.get(&claims.sub), &claims.sub);
    drop(db);
    tracing::debug!(user = %claims.sub, "GET logout confirm page");
    render(LogoutTemplate {
        lang,
        insecure_cookies: state.cfg.insecure_cookies,
        username: claims.sub,
    })
}

/// Clears the cookie and redirects to the login page (GET shows the confirm form).
pub(super) async fn logout_submit(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    if !origin_ok(&headers) {
        tracing::debug!("POST logout rejected: Origin/Host mismatch");
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    tracing::debug!("POST logout: clearing session cookie");
    let mut resp = Redirect::to(&format!("{}/login", state.cfg.base_path)).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie_header("", &state.cfg)?);
    Ok(resp)
}

pub(super) async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/account"));
    };
    ensure_fresh(&state).await?;
    let db = state.db.read().await;
    let Some(user) = db.users.get(&claims.sub) else {
        return Ok(redirect_to_login(&state, "/account"));
    };
    tracing::debug!(user = %claims.sub, "GET account page");
    render(AccountTemplate {
        lang: lang_of(&state, &headers, Some(user), &claims.sub),
        insecure_cookies: state.cfg.insecure_cookies,
        username: claims.sub.clone(),
        fields: account_field_views(&state, user, &claims.sub),
        error: None,
        notice: None,
        min_password_len: state.cfg.min_password_len,
    })
}

/// Own password change (old pw required) + fields this user may edit (user_editable_expr).
pub(super) async fn account_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Handler {
    if !origin_ok(&headers) {
        tracing::debug!("POST account rejected: Origin/Host mismatch");
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/account"));
    };
    ensure_fresh(&state).await?;
    let user = claims.sub.clone();
    tracing::debug!(
        user = %user,
        password_change = form.get("new_password").is_some_and(|s| !s.is_empty()),
        "POST account self-service update"
    );
    let lang = {
        let db = state.db.read().await;
        lang_of(&state, &headers, db.users.get(&user), &user)
    };

    let mut error = None;
    let mut notice = None;

    // Password change (only if a new password was entered).
    if let Some(newpw) = form.get("new_password").filter(|s| !s.is_empty()) {
        let old = form.get("old_password").map(String::as_str).unwrap_or("");
        let current = {
            state
                .db
                .read()
                .await
                .users
                .get(&user)
                .and_then(|u| u.hash.clone())
        };
        let old_ok = match &current {
            Some(h) => authn::verify_password_blocking(old.to_string(), h.clone()).await,
            None => false,
        };
        if !old_ok {
            error = Some(tr(&lang, "Current password is incorrect."));
        } else if newpw.len() < state.cfg.min_password_len {
            error = Some(tr(&lang, "New password is too short."));
        } else {
            let hash =
                authn::hash_password_blocking(newpw.clone(), state.cfg.password_hash).await?;
            state.db.write().await.write_password(&user, &hash)?;
            notice = Some(tr(&lang, "Password changed."));
        }
    }

    // Editable fields — only those `user_editable_expr` grants this user (evaluated against
    // their current fields). Snapshot so we can drop the read lock before writing.
    if error.is_none() {
        let snapshot = state
            .db
            .read()
            .await
            .users
            .get(&user)
            .map(|u| u.fields.clone());
        if let Some(fields) = snapshot {
            let ctx = cel::context(&fields, &user).ok();
            let updates = collect_fields(
                &state.cfg,
                &form,
                |name| format!("f_{name}"),
                |name| {
                    ctx.as_ref()
                        .is_some_and(|ctx| field_editable(&state, name, ctx))
                },
            );
            if !updates.is_empty() {
                state.db.write().await.write_fields(&user, &updates)?;
                notice.get_or_insert_with(|| tr(&lang, "Saved."));
            }
        }
    }

    let db = state.db.read().await;
    let fields = db
        .users
        .get(&user)
        .map(|u| account_field_views(&state, u, &user))
        .unwrap_or_default();
    render(AccountTemplate {
        lang,
        insecure_cookies: state.cfg.insecure_cookies,
        username: user,
        fields,
        error,
        notice,
        min_password_len: state.cfg.min_password_len,
    })
}

pub(super) async fn admin_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    let claims = match require_superadmin(&state, &headers).await {
        Ok(claims) => claims,
        Err(resp) => return Ok(resp),
    };
    let lang = {
        let db = state.db.read().await;
        lang_of(&state, &headers, db.users.get(&claims.sub), &claims.sub)
    };
    tracing::debug!(admin = %claims.sub, "GET admin page");
    render_admin(&state, &lang, None, None).await
}

/// Shared /admin prologue: session claims (else login redirect), fresh DB, superadmin gate
/// (else 403). Ok carries the verified claims (for the locale context); Err the early-exit response.
async fn require_superadmin(state: &AppState, headers: &HeaderMap) -> Result<Claims, Response> {
    let Some(claims) = current_claims(headers, state) else {
        return Err(redirect_to_login(state, "/admin"));
    };
    ensure_fresh(state)
        .await
        .map_err(IntoResponse::into_response)?;
    let db = state.db.read().await;
    if !is_superadmin(state, db.users.get(&claims.sub), &claims.sub) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    Ok(claims)
}

/// Superadmins only. Actions: `save` (batch edit/rename + set passwords across all rows),
/// `delete:<user>` (per-row button), `add` (the separate add-user form).
pub(super) async fn admin_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Handler {
    if !origin_ok(&headers) {
        tracing::debug!("POST admin rejected: Origin/Host mismatch");
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let claims = match require_superadmin(&state, &headers).await {
        Ok(claims) => claims,
        Err(resp) => return Ok(resp),
    };

    let lang = {
        let db = state.db.read().await;
        lang_of(&state, &headers, db.users.get(&claims.sub), &claims.sub)
    };
    let action = form.get("action").map(String::as_str).unwrap_or("");
    tracing::debug!(admin = %claims.sub, action, "POST admin action");
    // Outer Err = internal failure (500 + log); inner Err = validation message for the page.
    let outcome = if action == "save" {
        save_all(&state, &lang, &form).await?
    } else if let Some(name) = action.strip_prefix("delete:") {
        delete_one(&state, &lang, name).await?
    } else if action == "add" {
        add_one(&state, &lang, &form).await?
    } else {
        Err(tr(&lang, "Unknown action."))
    };
    match outcome {
        Ok(notice) => render_admin(&state, &lang, None, Some(notice)).await,
        Err(msg) => render_admin(&state, &lang, Some(msg), None).await,
    }
}

struct SaveRow {
    old: String,
    new: String,
    password_hash: Option<String>,
    /// None = the submitted fields match the row's current effective fields (no-op, skip the write).
    fields: Option<BTreeMap<String, toml::Value>>,
}

/// Batch-apply the whole user table: per-user `username[old]` (rename), `password[old]` (blank =
/// keep), and `f_<field>[old]`. The batch is validated as a whole first (valid + unique usernames,
/// password length) so one bad row rejects the save rather than applying partially. Unchanged
/// rows are skipped so saving an untouched table writes nothing.
async fn save_all(
    state: &AppState,
    lang: &str,
    form: &HashMap<String, String>,
) -> Result<Result<String, String>, AppError> {
    let rows: Vec<(String, BTreeMap<String, toml::Value>)> = {
        let db = state.db.read().await;
        db.users
            .iter()
            .map(|(name, u)| (name.clone(), u.fields.clone()))
            .collect()
    };
    let current: HashSet<String> = rows.iter().map(|(name, _)| name.clone()).collect();

    let mut plan = Vec::new();
    let mut final_names = HashSet::new();
    for (old, current_fields) in &rows {
        let new = form
            .get(&format!("username[{old}]"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| old.clone());
        if !UserDb::valid_username(&new) {
            return Ok(Err(tr(lang, "Invalid username.")));
        }
        // Reject renaming onto any other current name (avoids swaps/chains) or a batch duplicate.
        if (&new != old && current.contains(&new)) || !final_names.insert(new.clone()) {
            return Ok(Err(tr(lang, "Username already exists.")));
        }
        let password = form
            .get(&format!("password[{old}]"))
            .filter(|s| !s.is_empty())
            .cloned();
        if let Some(p) = &password
            && p.len() < state.cfg.min_password_len
        {
            return Ok(Err(tr(lang, "Password is too short.")));
        }
        // Hash here, before the write lock is taken — bcrypt/argon2 are too slow to run under it.
        let password_hash = match password {
            Some(p) => Some(authn::hash_password_blocking(p, state.cfg.password_hash).await?),
            None => None,
        };
        let fields = collect_fields(&state.cfg, form, |n| format!("f_{n}[{old}]"), |_| true);
        plan.push(SaveRow {
            old: old.clone(),
            new,
            password_hash,
            fields: (&fields != current_fields).then_some(fields),
        });
    }

    let mut db = state.db.write().await;
    for row in plan {
        // Apply to the current (old) name, then rename — so the rename carries the fresh data.
        if let Some(fields) = &row.fields {
            db.write_fields(&row.old, fields)?;
        }
        if let Some(hash) = row.password_hash {
            db.write_password(&row.old, &hash)?;
        }
        if row.new != row.old {
            db.rename_user(&row.old, &row.new)?;
        }
    }
    Ok(Ok(tr(lang, "Saved.")))
}

async fn delete_one(
    state: &AppState,
    lang: &str,
    user: &str,
) -> Result<Result<String, String>, AppError> {
    state.db.write().await.delete_user(user)?;
    Ok(Ok(tr(lang, "User deleted.")))
}

/// The separate add-user form: `username` + `new_password`. Fields are left to their config
/// defaults (no sidecar entry written); the admin sets them afterward via the row editor + Save.
async fn add_one(
    state: &AppState,
    lang: &str,
    form: &HashMap<String, String>,
) -> Result<Result<String, String>, AppError> {
    let username = form.get("username").map(String::as_str).unwrap_or("");
    if !UserDb::valid_username(username) {
        return Ok(Err(tr(lang, "Invalid username.")));
    }
    if state
        .db
        .read()
        .await
        .users
        .get(username)
        .is_some_and(|u| u.hash.is_some())
    {
        return Ok(Err(tr(lang, "User already exists.")));
    }
    let Some(pw) = form.get("new_password").filter(|s| !s.is_empty()) else {
        return Ok(Err(tr(lang, "A password is required to add a user.")));
    };
    if pw.len() < state.cfg.min_password_len {
        return Ok(Err(tr(lang, "Password is too short.")));
    }
    let hash = authn::hash_password_blocking(pw.clone(), state.cfg.password_hash).await?;
    state.db.write().await.write_password(username, &hash)?;
    Ok(Ok(tr(lang, "User added.")))
}
