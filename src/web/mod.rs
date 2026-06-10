//! HTTP layer. All routes under cfg.base_path so nginx proxy_pass needs no rewrite.
//! CSRF: SameSite=Lax + Origin-vs-Host check on every POST (no token machinery).
//! `rd` redirect targets must be relative, start with '/', and not '//' (open-redirect guard).

use axum::routing::get;
use axum::Router;

use crate::config::Config;

pub fn serve(cfg: Config) -> anyhow::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async {
        let app = router(&cfg);
        let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
        tracing::info!("listening on {}", cfg.listen);
        axum::serve(listener, app).await?;
        Ok(())
    })
}

fn router(cfg: &Config) -> Router {
    Router::new()
        .nest(
            &cfg.base_path,
            Router::new()
                .route("/auth", get(auth))
                .route("/login", get(login_page).post(login_submit))
                .route("/logout", get(logout_page).post(logout_submit))
                .route("/account", get(account_page).post(account_submit))
                .route("/admin", get(admin_page).post(admin_submit))
                .route("/healthz", get(|| async { "ok" })),
        )
        // TODO: shared state (Config, UserDb behind RwLock + reload_if_changed, jwt secret,
        // RateLimiter, VerifyCache, compiled CEL)
}

/// nginx auth_request target. Order: session cookie → Basic (if passthrough) → 401 (bare).
/// 200: X-Remote-User-Id + [headers.*] CEL outputs + sliding re-mint Set-Cookie.
/// Checks pwd_fp claim against current state when present.
async fn auth() -> &'static str {
    todo!()
}

async fn login_page() -> &'static str {
    todo!("askama login template; carries rd")
}

/// Verify (RateLimiter first), mint JWT (factors=[\"pw\"], pwd_fp, jwt-claims), 303 to validated rd.
/// Optionally rehash legacy entry to bcrypt (upgrade_hash_on_login).
async fn login_submit() -> &'static str {
    todo!()
}

/// GET shows a confirm page with a POST button (safe as a plain link target from app menus).
async fn logout_page() -> &'static str {
    todo!()
}

async fn logout_submit() -> &'static str {
    todo!("clear cookie, redirect to login")
}

/// Own password change (old pw required) + user_editable fields.
async fn account_page() -> &'static str {
    todo!()
}

async fn account_submit() -> &'static str {
    todo!()
}

/// Superadmins only ([superadmins].expr): user table, add/delete, set password, edit all fields.
async fn admin_page() -> &'static str {
    todo!()
}

async fn admin_submit() -> &'static str {
    todo!()
}
