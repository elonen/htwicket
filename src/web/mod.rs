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

use crate::cel::{self, CompiledExpr};
use crate::config::{Config, FieldType};
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
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    db: Arc<RwLock<UserDb>>,
    secret: Arc<Vec<u8>>,
    compiled: Arc<CompiledExpressions>,
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
    Ok(CompiledExpressions {
        headers,
        jwt_claims,
        superadmin,
        field_editable,
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
        if session::needs_remint(&claims, session::now(), state.cfg.session_idle_hours) {
            let next = session::remint(&claims, session::now(), state.cfg.session_idle_hours);
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

async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RdQuery>,
) -> Handler {
    render_login(
        &state,
        &lang_of(&headers),
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
/// Optionally rehash a legacy entry to bcrypt (upgrade_hash_on_login).
async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Handler {
    if !origin_ok(&headers) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let lang = lang_of(&headers);
    let rd = form.rd.unwrap_or_default();
    let ip = client_ip(&headers);
    if let Err(msg) = state.limiter.check(&form.username, &ip) {
        return render_login(&state, &lang, rd, Some(msg), form.username.clone());
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
        return render_login(
            &state,
            &lang,
            rd,
            Some(tr(&lang, "Invalid username or password.")),
            form.username.clone(),
        );
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
        state.cfg.session_idle_hours,
    );
    let token = session::mint(&claims, &state.secret)?;
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
    render(LogoutTemplate {
        lang: lang_of(&headers),
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
        lang: lang_of(&headers),
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
    let lang = lang_of(&headers);
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
            error = Some(tr(&lang, "Current password is incorrect."));
        } else if newpw.len() < state.cfg.min_password_len {
            error = Some(tr(&lang, "New password is too short."));
        } else {
            let hash = crate::authn::hash_password(newpw)?;
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
            let snap = User {
                hash: None,
                pwd_fp: None,
                fields,
            };
            let updates = collect_fields(&state.cfg, &form, |name| {
                field_editable(&state, name, &snap, &user)
            });
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
    render_admin(&state, &lang_of(&headers), None, None).await
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

    let lang = lang_of(&headers);
    let action = form.get("action").map(String::as_str).unwrap_or("");
    let outcome = if action == "save" {
        save_all(&state, &lang, &form).await
    } else if let Some(name) = action.strip_prefix("delete:") {
        delete_one(&state, &lang, name).await
    } else if action == "add" {
        add_one(&state, &lang, &form).await
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
    password: Option<String>,
    fields: BTreeMap<String, toml::Value>,
}

/// Batch-apply the whole user table: per-user `username[old]` (rename), `password[old]` (blank =
/// keep), and `f_<field>[old]`. The batch is validated as a whole first (valid + unique usernames,
/// password length) so one bad row rejects the save rather than applying partially.
async fn save_all(
    state: &AppState,
    lang: &str,
    form: &HashMap<String, String>,
) -> Result<String, String> {
    let names: Vec<String> = { state.db.read().await.users.keys().cloned().collect() };
    let current: HashSet<String> = names.iter().cloned().collect();

    let mut plan = Vec::new();
    let mut final_names = HashSet::new();
    for old in &names {
        let new = form
            .get(&format!("username[{old}]"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| old.clone());
        if !UserDb::valid_username(&new) {
            return Err(tr(lang, "Invalid username."));
        }
        // Reject renaming onto any other current name (avoids swaps/chains) or a batch duplicate.
        if (&new != old && current.contains(&new)) || !final_names.insert(new.clone()) {
            return Err(tr(lang, "Username already exists."));
        }
        let password = form
            .get(&format!("password[{old}]"))
            .filter(|s| !s.is_empty())
            .cloned();
        if let Some(p) = &password
            && p.len() < state.cfg.min_password_len
        {
            return Err(tr(lang, "Password is too short."));
        }
        let fields = collect_row_fields(&state.cfg, form, old);
        plan.push(SaveRow {
            old: old.clone(),
            new,
            password,
            fields,
        });
    }

    let mut db = state.db.write().await;
    for row in plan {
        // Apply to the current (old) name, then rename — so the rename carries the fresh data.
        db.write_fields(&row.old, &row.fields)
            .map_err(|e| e.to_string())?;
        if let Some(p) = row.password {
            let hash = crate::authn::hash_password(&p).map_err(|e| e.to_string())?;
            db.write_password(&row.old, &hash)
                .map_err(|e| e.to_string())?;
        }
        if row.new != row.old {
            db.rename_user(&row.old, &row.new)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(tr(lang, "Saved."))
}

async fn delete_one(state: &AppState, lang: &str, user: &str) -> Result<String, String> {
    state
        .db
        .write()
        .await
        .delete_user(user)
        .map_err(|e| e.to_string())?;
    Ok(tr(lang, "User deleted."))
}

/// The separate add-user form: `username` + `new_password`. Fields are left to their config
/// defaults (no sidecar entry written); the admin sets them afterward via the row editor + Save.
async fn add_one(
    state: &AppState,
    lang: &str,
    form: &HashMap<String, String>,
) -> Result<String, String> {
    let username = form.get("username").map(String::as_str).unwrap_or("");
    if !UserDb::valid_username(username) {
        return Err(tr(lang, "Invalid username."));
    }
    if state
        .db
        .read()
        .await
        .users
        .get(username)
        .is_some_and(|u| u.hash.is_some())
    {
        return Err(tr(lang, "User already exists."));
    }
    let Some(pw) = form.get("new_password").filter(|s| !s.is_empty()) else {
        return Err(tr(lang, "A password is required to add a user."));
    };
    if pw.len() < state.cfg.min_password_len {
        return Err(tr(lang, "Password is too short."));
    }
    let hash = crate::authn::hash_password(pw).map_err(|e| e.to_string())?;
    state
        .db
        .write()
        .await
        .write_password(username, &hash)
        .map_err(|e| e.to_string())?;
    Ok(tr(lang, "User added."))
}

/// Read `f_<field>[<old>]` values for every schema field (admin edits all). Bools: present = true.
fn collect_row_fields(
    cfg: &Config,
    form: &HashMap<String, String>,
    old: &str,
) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for (name, spec) in &cfg.fields {
        let key = format!("f_{name}[{old}]");
        let value = match spec.type_ {
            FieldType::Bool => toml::Value::Boolean(form.contains_key(&key)),
            _ => toml::Value::String(form.get(&key).cloned().unwrap_or_default()),
        };
        out.insert(name.clone(), value);
    }
    out
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
    spec: &crate::config::FieldSpec,
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
    state
        .cfg
        .fields
        .iter()
        .filter_map(|(name, spec)| {
            let editable = field_editable(state, name, user, username);
            (spec.user_visible || editable)
                .then(|| make_field_view(name, spec, user.fields.get(name), editable))
        })
        .collect()
}

/// May `username` edit `field` right now? Evaluates the field's user_editable_expr; any miss or
/// eval error is treated as not-editable (fail closed).
fn field_editable(state: &AppState, field: &str, user: &User, username: &str) -> bool {
    state
        .compiled
        .field_editable
        .get(field)
        .is_some_and(|expr| {
            matches!(
                cel::eval(expr, user, username),
                Ok(toml::Value::Boolean(true))
            )
        })
}

/// Read submitted `f_<name>` values for the given schema fields. Bools: present = true.
fn collect_fields(
    cfg: &Config,
    form: &HashMap<String, String>,
    accept: impl Fn(&str) -> bool,
) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for (name, spec) in &cfg.fields {
        if !accept(name) {
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
    let max_age = cfg.session_idle_hours as u64 * 3600;
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

fn tr(lang: &str, msgid: &str) -> String {
    crate::i18n::tr(lang, msgid)
}

/// Negotiate the request locale from Accept-Language against the compiled catalogs (else "en").
fn lang_of(headers: &HeaderMap) -> String {
    crate::i18n::best_locale(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}
