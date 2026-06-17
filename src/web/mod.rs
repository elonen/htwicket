//! HTTP layer. All routes under cfg.base_path so nginx proxy_pass needs no rewrite.
//! CSRF: SameSite=Lax + Origin-vs-Host check on every POST (no token machinery).
//! `rd` redirect targets must be relative, start with '/', and not '//' (open-redirect guard).
//!
//! Submodules: `handlers` (route handlers), `views` (template view models + CEL evaluation),
//! `helpers` (request parsing, cookies, locale), `templates` (Askama view structs).

mod handlers;
mod helpers;
mod templates;
mod views;

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use axum::Router;
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::RwLock;

use crate::auth::{RateLimiter, VerifyCache};
use crate::cel::{self, CompiledExpr};
use crate::config::{Config, FieldType};
use crate::state::UserDb;
use crate::token;

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
    keys: Arc<token::Keys>,
    compiled: Arc<CompiledExpressions>,
    limiter: Arc<RateLimiter>,
    cache: Arc<VerifyCache>,
}

pub fn serve(cfg: Config) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let compiled = Arc::new(compile_all(&cfg)?); // startup failure on a bad expr / header name
    let keys = Arc::new(token::Keys::new(&token::load_or_create_secret(&cfg)?));
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
        // Reserved: `x-remote-user-id` is the canonical identity htwicket always emits, and
        // `set-cookie` would let a configured header forge sessions — neither may be overridden.
        if matches!(hn.as_str(), "x-remote-user-id" | "set-cookie") {
            return Err(anyhow!(
                "reserved header name `{name}` cannot be configured"
            ));
        }
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
    use handlers::{
        account_page, account_submit, admin_page, admin_submit, auth, index_page, login_page,
        login_submit, logout_page, logout_submit,
    };
    let inner = Router::new()
        // axum's nested "/" matches the base path WITHOUT a trailing slash (`/htwicket`). The slash
        // variant (`/htwicket/`) is served by the explicit outer route below — both render the index
        // directly, with no redirect (a redirect would ping-pong against a directory-style reverse
        // proxy that re-adds the trailing slash → ERR_TOO_MANY_REDIRECTS).
        .route("/", get(index_page))
        .route("/auth", get(auth))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout_page).post(logout_submit))
        .route("/account", get(account_page).post(account_submit))
        .route("/admin", get(admin_page).post(admin_submit))
        .route("/healthz", get(|| async { "ok" }));
    Router::new()
        .route(&format!("{base_path}/"), get(index_page))
        .nest(base_path, inner)
        .with_state(state)
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
