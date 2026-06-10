//! HTTP layer. All routes under cfg.base_path so nginx proxy_pass needs no rewrite.
//! CSRF: SameSite=Lax + Origin-vs-Host check on every POST (no token machinery).
//! `rd` redirect targets must be relative, start with '/', and not '//' (open-redirect guard).

mod templates;

use std::collections::{BTreeMap, HashMap};
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

use crate::cel::{self, CompiledExpr};
use crate::config::{Config, FieldType};
use crate::session::{self, Claims};
use crate::state::{User, UserDb};
use templates::{
    AccountTemplate, AdminTemplate, FieldView, LoginTemplate, LogoutTemplate, UserRow,
};

const LANG: &str = "en"; // per-request locale arrives with the i18n catalogs (step 8)

/// CEL programs + parsed header names, compiled once at startup (bad expr / header name = fail).
struct Compiled {
    headers: Vec<(HeaderName, CompiledExpr)>,
    jwt_claims: Vec<(String, CompiledExpr)>,
    superadmin: CompiledExpr,
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    db: Arc<RwLock<UserDb>>,
    secret: Arc<Vec<u8>>,
    compiled: Arc<Compiled>,
    limiter: Arc<crate::authn::RateLimiter>,
    cache: Arc<crate::authn::VerifyCache>,
}

pub fn serve(cfg: Config) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let compiled = Arc::new(compile_all(&cfg)?); // startup failure on a bad expr / header name
    let secret = Arc::new(session::load_or_create_secret(&cfg)?);
    let db = Arc::new(RwLock::new(UserDb::load(cfg.clone())?));
    if cfg.insecure_cookies {
        tracing::warn!(
            "insecure_cookies enabled — Secure flag dropped; use only on localhost or an encrypted tunnel"
        );
    }
    let state = AppState {
        cfg: cfg.clone(),
        db,
        secret,
        compiled,
        limiter: Arc::new(crate::authn::RateLimiter::new()),
        cache: Arc::new(crate::authn::VerifyCache::new()),
    };

    tokio::runtime::Runtime::new()?.block_on(async move {
        let app = router(&cfg.base_path, state);
        let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
        tracing::info!("listening on {}", cfg.listen);
        axum::serve(listener, app).await?;
        Ok(())
    })
}

fn compile_all(cfg: &Config) -> anyhow::Result<Compiled> {
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
    Ok(Compiled {
        headers,
        jwt_claims,
        superadmin,
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
    let db = state.db.read().await; // read-only path: no writes here, safe to hold across sync work

    // 1) Session cookie.
    if let Some(claims) = current_claims(&headers, &state)
        && let Some(user) = db.users.get(&claims.sub)
        && (claims.pwd_fp.is_none() || claims.pwd_fp == user.pwd_fp)
    {
        let mut out = auth_response_headers(&state, user, &claims.sub)?;
        if session::needs_remint(&claims, session::now(), state.cfg.session_hours) {
            let next = session::remint(&claims, session::now(), state.cfg.session_hours);
            let token = session::mint(&next, &state.secret)?;
            out.insert(header::SET_COOKIE, cookie_header(&token, &state.cfg)?);
        }
        return Ok((StatusCode::OK, out).into_response());
    }

    // 2) Basic passthrough (scripted clients). Never mints a cookie.
    if state.cfg.basic_auth_passthrough
        && let Some((user, pass)) = basic_credentials(&headers)
        && let Some(u) = db.users.get(&user)
    {
        let ok = state.cache.check(&user, &pass)
            || u.hash.as_deref().is_some_and(|h| {
                let v = crate::authn::verify_password(&pass, h);
                if v {
                    state.cache.store(&user, &pass);
                }
                v
            });
        if ok {
            let out = auth_response_headers(&state, u, &user)?;
            return Ok((StatusCode::OK, out).into_response());
        }
    }

    // 3) Bare 401 (nginx swallows subrequest body; browsers handled by error_page redirect).
    Ok(StatusCode::UNAUTHORIZED.into_response())
}

#[derive(Deserialize)]
struct RdQuery {
    rd: Option<String>,
}

async fn login_page(State(state): State<AppState>, Query(q): Query<RdQuery>) -> Handler {
    render_login(&state, q.rd.unwrap_or_default(), None)
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    rd: Option<String>,
}

/// Verify (rate-limited), mint the session JWT (factors=["pw"], pwd_fp, jwt-claims), 303 to rd.
/// Optionally rehash a legacy entry to bcrypt (upgrade_hash_on_login).
async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let rd = form.rd.unwrap_or_default();
    let ip = client_ip(&headers);
    if let Err(msg) = state.limiter.check(&form.username, &ip) {
        return render_login(&state, rd, Some(msg));
    }
    ensure_fresh(&state).await?;

    let hash = {
        let db = state.db.read().await;
        db.users.get(&form.username).and_then(|u| u.hash.clone())
    };
    let good = hash
        .as_deref()
        .is_some_and(|h| crate::authn::verify_password(&form.password, h));
    if !good {
        state.limiter.record_failure(&form.username, &ip);
        return render_login(&state, rd, Some(tr("Invalid username or password.")));
    }
    state.limiter.record_success(&form.username, &ip);

    // Opt-in: rehash a non-bcrypt entry now that we hold the plaintext.
    let hash = hash.unwrap();
    if state.cfg.upgrade_hash_on_login
        && !hash.starts_with("$2")
        && let Ok(new_hash) = crate::authn::hash_password(&form.password)
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
        state.cfg.session_hours,
    );
    let token = session::mint(&claims, &state.secret)?;
    let target = if valid_rd(&rd) { rd } else { "/".to_string() };
    let mut resp = Redirect::to(&target).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie_header(&token, &state.cfg)?);
    Ok(resp)
}

async fn logout_page(State(state): State<AppState>) -> Handler {
    render(LogoutTemplate {
        lang: LANG,
        insecure_cookies: state.cfg.insecure_cookies,
    })
}

/// Clears the cookie and redirects to the login page (GET shows the confirm form).
async fn logout_submit(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let mut resp = Redirect::to(&format!("{}/login", state.cfg.base_path)).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_cookie_header(&state.cfg)?);
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
        lang: LANG,
        insecure_cookies: state.cfg.insecure_cookies,
        username: claims.sub.clone(),
        fields: field_views(&state.cfg, &user.fields, false),
        error: None,
        notice: None,
    })
}

/// Own password change (old pw required) + user_editable fields.
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
        let old_ok = current
            .as_deref()
            .is_some_and(|h| crate::authn::verify_password(old, h));
        if !old_ok {
            error = Some(tr("Current password is incorrect."));
        } else if newpw.len() < state.cfg.min_password_len {
            error = Some(tr("New password is too short."));
        } else {
            let hash = crate::authn::hash_password(newpw)?;
            state.db.write().await.write_password(&user, &hash)?;
            notice = Some(tr("Password changed."));
        }
    }

    // Editable fields.
    if error.is_none() {
        let updates = collect_fields(&state.cfg, &form, false);
        if !updates.is_empty() {
            state.db.write().await.write_fields(&user, &updates)?;
            notice.get_or_insert_with(|| tr("Saved."));
        }
    }

    let db = state.db.read().await;
    let fields = db
        .users
        .get(&user)
        .map(|u| field_views(&state.cfg, &u.fields, false))
        .unwrap_or_default();
    render(AccountTemplate {
        lang: LANG,
        insecure_cookies: state.cfg.insecure_cookies,
        username: user,
        fields,
        error,
        notice,
    })
}

async fn admin_page(State(state): State<AppState>, headers: HeaderMap) -> Handler {
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/admin"));
    };
    ensure_fresh(&state).await?;
    {
        let db = state.db.read().await;
        if !is_superadmin(&state, db.users.get(&claims.sub), &claims.sub) {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
    }
    render_admin(&state, None, None).await
}

/// Superadmins only: add/delete user, set password, edit all fields.
async fn admin_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let Some(claims) = current_claims(&headers, &state) else {
        return Ok(redirect_to_login(&state, "/admin"));
    };
    ensure_fresh(&state).await?;
    {
        let db = state.db.read().await;
        if !is_superadmin(&state, db.users.get(&claims.sub), &claims.sub) {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
    }

    let action = form.get("action").map(String::as_str).unwrap_or("");
    let username = form.get("username").cloned().unwrap_or_default();
    let new_password = form.get("new_password").filter(|s| !s.is_empty());

    let outcome = apply_admin_action(&state, action, &username, new_password, &form).await;
    match outcome {
        Ok(notice) => render_admin(&state, None, Some(notice)).await,
        Err(msg) => render_admin(&state, Some(msg), None).await,
    }
}

/// Returns Ok(notice) / Err(user-facing message). Real (unexpected) IO errors bubble as AppError
/// only from render_admin; expected validation failures are Err(String) shown in the page.
async fn apply_admin_action(
    state: &AppState,
    action: &str,
    username: &str,
    new_password: Option<&String>,
    form: &HashMap<String, String>,
) -> Result<String, String> {
    match action {
        "delete" => {
            state
                .db
                .write()
                .await
                .delete_user(username)
                .map_err(|e| e.to_string())?;
            Ok(tr("User deleted."))
        }
        "add" | "save" => {
            if !UserDb::valid_username(username) {
                return Err(tr("Invalid username."));
            }
            if action == "add" {
                let exists = state
                    .db
                    .read()
                    .await
                    .users
                    .get(username)
                    .is_some_and(|u| u.hash.is_some());
                if exists {
                    return Err(tr("User already exists."));
                }
            }
            if let Some(pw) = new_password {
                if pw.len() < state.cfg.min_password_len {
                    return Err(tr("Password is too short."));
                }
                let hash = crate::authn::hash_password(pw).map_err(|e| e.to_string())?;
                state
                    .db
                    .write()
                    .await
                    .write_password(username, &hash)
                    .map_err(|e| e.to_string())?;
            } else if action == "add" {
                return Err(tr("A password is required to add a user."));
            }
            let updates = collect_fields(&state.cfg, form, true);
            if !updates.is_empty() {
                state
                    .db
                    .write()
                    .await
                    .write_fields(username, &updates)
                    .map_err(|e| e.to_string())?;
            }
            Ok(if action == "add" {
                tr("User added.")
            } else {
                tr("Saved.")
            })
        }
        _ => Err(tr("Unknown action.")),
    }
}

// ---- View building ----

async fn render_admin(state: &AppState, error: Option<String>, notice: Option<String>) -> Handler {
    let db = state.db.read().await;
    let users = db
        .users
        .iter()
        .map(|(name, u)| UserRow {
            name: name.clone(),
            has_password: u.hash.is_some(),
            fields: field_views(&state.cfg, &u.fields, true),
        })
        .collect();
    render(AdminTemplate {
        lang: LANG,
        insecure_cookies: state.cfg.insecure_cookies,
        users,
        add_fields: field_views(&state.cfg, &BTreeMap::new(), true),
        error,
        notice,
    })
}

fn render_login(state: &AppState, rd: String, error: Option<String>) -> Handler {
    render(LoginTemplate {
        lang: LANG,
        insecure_cookies: state.cfg.insecure_cookies,
        error,
        rd,
    })
}

/// Build form `FieldView`s. `all_editable` (admin) makes every field editable; otherwise only
/// `user_editable` ones are, the rest shown read-only.
fn field_views(
    cfg: &Config,
    values: &BTreeMap<String, toml::Value>,
    all_editable: bool,
) -> Vec<FieldView> {
    cfg.fields
        .iter()
        .map(|(name, spec)| {
            let v = values.get(name);
            FieldView {
                name: name.clone(),
                label: name.replace('_', " "),
                is_bool: spec.type_ == FieldType::Bool,
                input_type: if spec.type_ == FieldType::Email {
                    "email"
                } else {
                    "text"
                },
                value: match v {
                    Some(toml::Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                },
                checked: v.and_then(toml::Value::as_bool).unwrap_or(false),
                editable: all_editable || spec.user_editable,
            }
        })
        .collect()
}

/// Read submitted form values for editable schema fields (`f_<name>`). Bools: present = true.
fn collect_fields(
    cfg: &Config,
    form: &HashMap<String, String>,
    all_editable: bool,
) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for (name, spec) in &cfg.fields {
        if !all_editable && !spec.user_editable {
            continue;
        }
        let key = format!("f_{name}");
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
    for (name, expr) in &state.compiled.headers {
        let value = match cel::eval(expr, user, username)? {
            toml::Value::Boolean(b) => b.to_string(),
            toml::Value::String(s) => s,
            other => other.to_string(),
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
    for (name, expr) in &state.compiled.jwt_claims {
        let value = match cel::eval(expr, user, username)? {
            toml::Value::Boolean(b) => serde_json::Value::Bool(b),
            toml::Value::String(s) => serde_json::Value::String(s),
            other => serde_json::Value::String(other.to_string()),
        };
        map.insert(name.clone(), value);
    }
    Ok(map)
}

fn is_superadmin(state: &AppState, user: Option<&User>, username: &str) -> bool {
    let Some(user) = user else { return false };
    matches!(
        cel::eval(&state.compiled.superadmin, user, username),
        Ok(toml::Value::Boolean(true))
    )
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
    session::verify(&token, &state.secret, state.cfg.session_max_days)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{name}=")))
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

fn cookie_header(token: &str, cfg: &Config) -> Result<HeaderValue, AppError> {
    let secure = if cfg.insecure_cookies { "" } else { "; Secure" };
    let max_age = cfg.session_hours as u64 * 3600;
    let s = format!(
        "{}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure}",
        session::COOKIE_NAME
    );
    Ok(HeaderValue::from_str(&s)?)
}

fn clear_cookie_header(cfg: &Config) -> Result<HeaderValue, AppError> {
    let secure = if cfg.insecure_cookies { "" } else { "; Secure" };
    let s = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}",
        session::COOKIE_NAME
    );
    Ok(HeaderValue::from_str(&s)?)
}

fn render<T: askama::Template>(t: T) -> Handler {
    Ok(Html(t.render()?).into_response())
}

fn tr(msgid: &str) -> String {
    crate::i18n::tr(None, msgid)
}
