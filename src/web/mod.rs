//! HTTP layer. All routes under cfg.base_path so nginx proxy_pass needs no rewrite.
//! CSRF: SameSite=Lax + Origin-vs-Host check on every POST (no token machinery).
//! `rd` redirect targets must be relative, start with '/', and not '//' (open-redirect guard).

mod templates;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use base64::Engine as _;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::authn::{self, RateLimiter, Throttle, VerifyCache};
use crate::cel::{self, CelValue, CompiledExpr};
use crate::config::{Config, FieldSpec, FieldType};
use crate::i18n::{best_locale, tr};
use crate::session::{self, Claims};
use crate::state::{User, UserDb};
use templates::{
    AccountTemplate, AdminTemplate, FieldView, LoginTemplate, LogoutTemplate, UserRow,
};

/// CEL (Common Expression Language) programs + parsed header names, compiled once at startup (bad expr / header name = fail).
struct CompiledExpressions {
    headers: Vec<(HeaderName, CompiledExpr)>,
    jwt_claims: Vec<(String, CompiledExpr)>,
    superadmin: CompiledExpr,
    /// Per-field `user_editable_expr` (bool over {username, fields.*}) tells if given user may edit it.
    field_editable: BTreeMap<String, CompiledExpr>,
    /// `default_lang` (string over {username, fields.*}): the fallback UI locale.
    default_lang: CompiledExpr,
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    db: Arc<RwLock<UserDb>>,
    keys: Arc<session::Keys>,
    compiled: Arc<CompiledExpressions>,
    limiter: Arc<RateLimiter>,
    cache: Arc<VerifyCache>,
}

pub fn serve(cfg: Config) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let compiled = Arc::new(compile_all(&cfg)?); // startup failure on a bad expr / header name
    let keys = Arc::new(session::Keys::new(&session::load_or_create_secret(&cfg)?));
    let db = Arc::new(RwLock::new(UserDb::load(cfg.clone())?));
    if cfg.insecure_cookies {
        tracing::warn!(
            "insecure_cookies enabled — Secure flag dropped; use only on localhost or an encrypted tunnel"
        );
    }
    let state = AppState {
        cfg: cfg.clone(),
        db,
        keys,
        compiled,
        limiter: Arc::new(RateLimiter::new()),
        cache: Arc::new(VerifyCache::new()),
    };

    tokio::runtime::Runtime::new()?.block_on(async move {
        let app = router(&cfg.base_path, state);
        let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
        tracing::info!("listening on {}", cfg.listen);
        axum::serve(listener, app).await?;
        Ok(())
    })
}

fn compile_all(cfg: &Config) -> anyhow::Result<CompiledExpressions> {
    let superadmin =
        cel::compile(&cfg.superadmins.expr, FieldType::Bool).context("superadmins.expr")?;
    let mut headers = Vec::new();
    for (name, spec) in &cfg.headers {
        let hn = HeaderName::try_from(name).map_err(|_| anyhow!("invalid header name `{name}`"))?;
        let expr =
            cel::compile(&spec.expr, spec.type_).with_context(|| format!("headers.{name}"))?;
        headers.push((hn, expr));
    }
    let mut jwt_claims = Vec::new();
    for (name, spec) in &cfg.jwt_claims {
        let expr =
            cel::compile(&spec.expr, spec.type_).with_context(|| format!("jwt-claims.{name}"))?;
        jwt_claims.push((name.clone(), expr));
    }
    let mut field_editable = BTreeMap::new();
    for (name, spec) in &cfg.fields {
        let expr = cel::compile(&spec.user_editable_expr, FieldType::Bool)
            .with_context(|| format!("fields.{name}.user_editable_expr"))?;
        field_editable.insert(name.clone(), expr);
    }
    let default_lang =
        cel::compile(&cfg.default_lang, FieldType::String).context("default_lang")?;
    Ok(CompiledExpressions {
        headers,
        jwt_claims,
        superadmin,
        field_editable,
        default_lang,
    })
}

fn router(base_path: &str, state: AppState) -> Router {
    Router::new().nest(
        base_path,
        Router::new()
            .route("/auth", get(auth))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", get(logout_page).post(logout_submit))
            .route("/account", get(account_page).post(account_submit))
            .route("/admin", get(admin_page).post(admin_submit))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(state),
    )
}

// ---- Error glue: handlers return Result<Response, AppError>; AppError => 500 + log. ----

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("{:#}", self.0);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

type Handler = Result<Response, AppError>;

// ---- Handlers ----

/// nginx auth_request target. Order: session cookie → Basic (if passthrough) → 401 (bare).
/// 200: X-Remote-User-Id + [headers.*] CEL outputs + sliding re-mint Set-Cookie.
async fn auth(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    ensure_fresh(&state).await?;
    let db = state.db.read().await;

    // 1) Session cookie.
    if let Some(claims) = current_claims(&headers, &state)
        && let Some(user) = db.users.get(&claims.sub)
        && (claims.pwd_fp.is_none() || claims.pwd_fp == user.pwd_fp)
    {
        let mut out = auth_response_headers(&state, user, &claims.sub)?;
        if session::needs_remint(&claims, session::now(), state.cfg.session_idle_hours) {
            let next = session::remint(&claims, session::now(), state.cfg.session_idle_hours);
            let token = session::mint(&next, &state.keys)?;
            out.insert(header::SET_COOKIE, cookie_header(&token, &state.cfg)?);
        }
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
                return Ok((StatusCode::OK, out).into_response());
            }
        }
    }

    // 3) Bare 401 (nginx swallows subrequest body; browsers handled by error_page redirect).
    Ok(StatusCode::UNAUTHORIZED.into_response())
}

#[derive(Deserialize)]
struct RdQuery {
    rd: Option<String>,
}

async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RdQuery>,
) -> Handler {
    render_login(
        &state,
        &lang_of(&state, &headers, None, ""),
        q.rd.unwrap_or_default(),
        None,
        String::new(),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    rd: Option<String>,
}

/// Verify (rate-limited), mint the session JWT (factors=["pw"], pwd_fp, jwt-claims), 303 to rd.
/// Optionally rehash an entry not in `password_hash` to it (upgrade_hash_on_login).
async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let lang = lang_of(&state, &headers, None, ""); // no authenticated user yet
    let rd = form.rd.unwrap_or_default();
    let ip = client_ip(&headers);
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
    let mut resp = Redirect::to(&target).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie_header(&token, &state.cfg)?);
    Ok(resp)
}

async fn logout_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    // Confirm page needs the current identity for "signed in as <user>". Not logged in => nothing
    // to confirm; send them to login.
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/"));
    };
    let db = state.db.read().await;
    let lang = lang_of(&state, &headers, db.users.get(&claims.sub), &claims.sub);
    drop(db);
    render(LogoutTemplate {
        lang,
        insecure_cookies: state.cfg.insecure_cookies,
        username: claims.sub,
    })
}

/// Clears the cookie and redirects to the login page (GET shows the confirm form).
async fn logout_submit(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let mut resp = Redirect::to(&format!("{}/login", state.cfg.base_path)).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie_header("", &state.cfg)?);
    Ok(resp)
}

async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/account"));
    };
    ensure_fresh(&state).await?;
    let db = state.db.read().await;
    let Some(user) = db.users.get(&claims.sub) else {
        return Ok(redirect_to_login(&state, "/account"));
    };
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
async fn account_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/account"));
    };
    ensure_fresh(&state).await?;
    let user = claims.sub.clone();
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

async fn admin_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    let claims = match require_superadmin(&state, &headers).await {
        Ok(claims) => claims,
        Err(resp) => return Ok(resp),
    };
    let lang = {
        let db = state.db.read().await;
        lang_of(&state, &headers, db.users.get(&claims.sub), &claims.sub)
    };
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
async fn admin_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Handler {
    if !origin_ok(&headers) {
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

// ---- View building ----

async fn render_admin(
    state: &AppState,
    lang: &str,
    error: Option<String>,
    notice: Option<String>,
) -> Handler {
    let db = state.db.read().await;
    let users = db
        .users
        .iter()
        .map(|(name, u)| UserRow {
            name: name.clone(),
            has_password: u.hash.is_some(),
            fields: admin_field_views(&state.cfg, &u.fields),
        })
        .collect();
    render(AdminTemplate {
        lang: lang.to_string(),
        insecure_cookies: state.cfg.insecure_cookies,
        users,
        error,
        notice,
        min_password_len: state.cfg.min_password_len,
    })
}

fn render_login(
    state: &AppState,
    lang: &str,
    rd: String,
    error: Option<String>,
    username: String,
) -> Handler {
    render(LoginTemplate {
        lang: lang.to_string(),
        insecure_cookies: state.cfg.insecure_cookies,
        error,
        rd,
        username,
    })
}

fn make_field_view(
    name: &str,
    spec: &FieldSpec,
    value: Option<&toml::Value>,
    editable: bool,
) -> FieldView {
    FieldView {
        name: name.to_string(),
        label: name.replace('_', " "),
        is_bool: spec.type_ == FieldType::Bool,
        input_type: if spec.type_ == FieldType::Email {
            "email"
        } else {
            "text"
        },
        value: match value {
            Some(toml::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        },
        checked: value.and_then(toml::Value::as_bool).unwrap_or(false),
        editable,
    }
}

/// Admin sees and may edit every schema field.
fn admin_field_views(cfg: &Config, values: &BTreeMap<String, toml::Value>) -> Vec<FieldView> {
    cfg.fields
        .iter()
        .map(|(name, spec)| make_field_view(name, spec, values.get(name), true))
        .collect()
}

/// /account view: only fields visible to this user (user_visible, or editable-for-them).
/// Editability is the per-user `user_editable_expr` (fail closed on eval error).
fn account_field_views(state: &AppState, user: &User, username: &str) -> Vec<FieldView> {
    let ctx = cel::context(&user.fields, username).ok();
    state
        .cfg
        .fields
        .iter()
        .filter_map(|(name, spec)| {
            let editable = ctx
                .as_ref()
                .is_some_and(|ctx| field_editable(state, name, ctx));
            (spec.user_visible || editable)
                .then(|| make_field_view(name, spec, user.fields.get(name), editable))
        })
        .collect()
}

/// May the user behind `ctx` edit `field` right now? Evaluates the field's user_editable_expr;
/// any miss or eval error is treated as not-editable (fail closed).
fn field_editable(state: &AppState, field: &str, ctx: &cel::Context) -> bool {
    state
        .compiled
        .field_editable
        .get(field)
        .is_some_and(|expr| cel::eval_bool(expr, ctx))
}

/// Read submitted values for the schema fields passing `accept`; `key` maps a field name to its
/// form key (`f_<name>` on /account, `f_<name>[<row>]` in the admin table). Bools: present = true.
fn collect_fields(
    cfg: &Config,
    form: &HashMap<String, String>,
    key: impl Fn(&str) -> String,
    accept: impl Fn(&str) -> bool,
) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for (name, spec) in &cfg.fields {
        if !accept(name) {
            continue;
        }
        let key = key(name);
        let value = match spec.type_ {
            FieldType::Bool => toml::Value::Boolean(form.contains_key(&key)),
            _ => toml::Value::String(form.get(&key).cloned().unwrap_or_default()),
        };
        out.insert(name.clone(), value);
    }
    out
}

/// X-Remote-User-Id (always) + each [headers.*] CEL output. A CEL/eval error bubbles to 500.
fn auth_response_headers(
    state: &AppState,
    user: &User,
    username: &str,
) -> Result<HeaderMap, AppError> {
    let mut out = HeaderMap::new();
    out.insert(
        HeaderName::from_static("x-remote-user-id"),
        HeaderValue::from_str(username)?,
    );
    if state.compiled.headers.is_empty() {
        return Ok(out); // skip the context build on the hot path when no headers are configured
    }
    let ctx = cel::context(&user.fields, username)?;
    for (name, expr) in &state.compiled.headers {
        let value = match cel::eval(expr, &ctx)? {
            CelValue::Bool(b) => b.to_string(),
            CelValue::Str(s) => s,
        };
        out.insert(name.clone(), HeaderValue::from_str(&value)?);
    }
    Ok(out)
}

fn eval_jwt_claims(
    state: &AppState,
    user: Option<&User>,
    username: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, AppError> {
    let mut map = serde_json::Map::new();
    let Some(user) = user else { return Ok(map) };
    let ctx = cel::context(&user.fields, username)?;
    for (name, expr) in &state.compiled.jwt_claims {
        let value = match cel::eval(expr, &ctx)? {
            CelValue::Bool(b) => serde_json::Value::Bool(b),
            CelValue::Str(s) => serde_json::Value::String(s),
        };
        map.insert(name.clone(), value);
    }
    Ok(map)
}

fn is_superadmin(state: &AppState, user: Option<&User>, username: &str) -> bool {
    let Some(user) = user else { return false };
    cel::context(&user.fields, username)
        .map(|ctx| cel::eval_bool(&state.compiled.superadmin, &ctx))
        .unwrap_or(false)
}

// ---- Request helpers ----

async fn ensure_fresh(state: &AppState) -> Result<(), AppError> {
    if state.db.read().await.changed_on_disk() {
        let mut w = state.db.write().await;
        if w.reload_if_changed()? {
            state.cache.clear();
        }
    }
    Ok(())
}

fn current_claims(headers: &HeaderMap, state: &AppState) -> Option<Claims> {
    let token = cookie_value(headers, session::COOKIE_NAME)?;
    session::verify(&token, &state.keys, state.cfg.session_max_days)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{name}=");
    raw.split(';')
        .find_map(|part| part.trim().strip_prefix(&prefix))
        .map(str::to_string)
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Origin-vs-Host CSRF guard. Missing Origin is allowed (SameSite=Lax covers it; curl/older
/// clients send none); a present Origin must match the Host authority.
fn origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin
        .split_once("://")
        .is_some_and(|(_, authority)| authority == host)
}

fn valid_rd(rd: &str) -> bool {
    rd.starts_with('/')
        && !rd.starts_with("//")
        && !rd.starts_with("/\\")
        && !rd.contains(|c: char| c.is_control())
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn redirect_to_login(state: &AppState, rd: &str) -> Response {
    Redirect::to(&format!("{}/login?rd={}", state.cfg.base_path, rd)).into_response()
}

/// Session cookie header; an empty token clears the cookie (Max-Age=0).
fn cookie_header(token: &str, cfg: &Config) -> Result<HeaderValue, AppError> {
    let secure = if cfg.insecure_cookies { "" } else { "; Secure" };
    let max_age = if token.is_empty() {
        0
    } else {
        cfg.session_idle_hours as u64 * 3600
    };
    let s = format!(
        "{}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure}",
        session::COOKIE_NAME
    );
    Ok(HeaderValue::from_str(&s)?)
}

fn render<T: askama::Template>(t: T) -> Handler {
    Ok(Html(t.render()?).into_response())
}

/// Negotiate the request locale: the browser's Accept-Language (matched against the compiled
/// catalogs) when `http_accept_language` is on and it matches; otherwise the `default_lang` CEL
/// fallback over {username, fields.*}, and "en" if that errors (e.g. `fields.*` on a pre-login
/// page) or yields a non-string.
fn lang_of(state: &AppState, headers: &HeaderMap, user: Option<&User>, username: &str) -> String {
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
    use super::valid_rd;

    #[test]
    fn valid_rd_accepts_relative_rejects_external_and_control() {
        for ok in ["/", "/x", "/dashboard", "/a/b?q=1#frag"] {
            assert!(valid_rd(ok), "should accept {ok:?}");
        }
        // empty, scheme, protocol-relative, backslash trick, and control chars are all open-redirect
        // or smuggling risks.
        for bad in ["", "https://evil", "//evil", "/\\evil", "/a\nb", "/a\0b"] {
            assert!(!valid_rd(bad), "should reject {bad:?}");
        }
    }
}
