//! Session JWT in cookie `htwicket_session`: HttpOnly, SameSite=Lax, Path=/,
//! Secure unless insecure_cookies. HS256 pinned — token-header alg is ignored.
//! Stateless; the only revocation is pwd_fp mismatch (password change rotates it).

use serde::{Deserialize, Serialize};

pub const COOKIE_NAME: &str = "htwicket_session";

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub iss: String, // "htwicket"
    /// First login time; survives sliding re-mints; enforces session_max_days.
    pub orig_iat: u64,
    /// ["pw"] for now; future methods (totp, oidc) append. Basic-auth requests never mint cookies.
    pub factors: Vec<String>,
    /// First 16 hex of SHA-256(.htpasswd hash field). Present => must match at /auth, else 401.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pwd_fp: Option<String>,
    /// [jwt-claims.*] config exprs, baked at login (stale until re-login; headers are authoritative).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub fn mint(_claims: Claims, _secret: &[u8]) -> anyhow::Result<String> {
    todo!("jsonwebtoken::encode, HS256")
}

/// Validates signature + exp + iss, pins HS256, then checks orig_iat against session_max_days.
pub fn verify(_token: &str, _secret: &[u8]) -> Option<Claims> {
    todo!()
}

/// Sliding renewal: re-mint (same orig_iat) when more than half of session_hours has elapsed.
/// /auth sets the new cookie; nginx propagates it via auth_request_set + add_header (see PLAN.md).
pub fn needs_remint(_claims: &Claims) -> bool {
    todo!()
}

/// Load jwt_secret from config, else read/create {state_dir}/jwt_secret (random, 0600).
pub fn load_or_create_secret(_cfg: &crate::config::Config) -> anyhow::Result<Vec<u8>> {
    todo!()
}
