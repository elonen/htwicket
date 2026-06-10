//! Session JWT in cookie `htwicket_session`: HttpOnly, SameSite=Lax, Path=/,
//! Secure unless insecure_cookies. HS256 pinned — token-header alg is ignored.
//! Stateless; the only revocation is pwd_fp mismatch (password change rotates it).

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

pub const COOKIE_NAME: &str = "htwicket_session";
const ISSUER: &str = "htwicket";

/// HS256 keys + validation derived from the secret once at startup — building
/// EncodingKey/DecodingKey/Validation per request is pure constant work.
pub struct Keys {
    enc: EncodingKey,
    dec: DecodingKey,
    validation: Validation,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[ISSUER]);
        validation.validate_aud = false; // htwicket tokens carry no audience
        Keys {
            enc: EncodingKey::from_secret(secret),
            dec: DecodingKey::from_secret(secret),
            validation,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

/// Current Unix time in seconds.
pub fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}

/// Fresh login: iat = orig_iat = now, exp = now + session_idle_hours.
pub fn new_session(
    sub: &str,
    factors: Vec<String>,
    pwd_fp: Option<String>,
    extra: serde_json::Map<String, serde_json::Value>,
    now: u64,
    session_idle_hours: u32,
) -> Claims {
    Claims {
        sub: sub.to_string(),
        iat: now,
        exp: now + session_idle_hours as u64 * 3600,
        iss: ISSUER.to_string(),
        orig_iat: now,
        factors,
        pwd_fp,
        extra,
    }
}

/// Sliding re-mint: new iat/exp, everything else (orig_iat, factors, pwd_fp, baked claims) preserved.
/// Not a re-login — jwt-claims stay as baked at login (headers are the fresh channel).
pub fn remint(prev: &Claims, now: u64, session_idle_hours: u32) -> Claims {
    Claims {
        iat: now,
        exp: now + session_idle_hours as u64 * 3600,
        ..prev.clone()
    }
}

pub fn mint(claims: &Claims, keys: &Keys) -> anyhow::Result<String> {
    Ok(encode(&Header::new(Algorithm::HS256), claims, &keys.enc)?)
}

/// Validate signature + exp + iss, pinning HS256 (token-header alg cannot downgrade us), then
/// enforce the absolute cap: orig_iat + session_max_days. Any failure => None (no session).
pub fn verify(token: &str, keys: &Keys, session_max_days: u32) -> Option<Claims> {
    let data = decode::<Claims>(token, &keys.dec, &keys.validation).ok()?;
    let claims = data.claims;
    if claims.orig_iat + session_max_days as u64 * 86400 < now() {
        return None;
    }
    Some(claims)
}

/// Sliding renewal: re-mint once more than half of session_idle_hours has elapsed since iat.
pub fn needs_remint(claims: &Claims, now: u64, session_idle_hours: u32) -> bool {
    now.saturating_sub(claims.iat) > (session_idle_hours as u64 * 3600) / 2
}

/// Load jwt_secret from config, else read/create {state_dir}/jwt_secret (32 random bytes, 0600).
pub fn load_or_create_secret(cfg: &crate::config::Config) -> anyhow::Result<Vec<u8>> {
    if let Some(secret) = &cfg.jwt_secret {
        return Ok(secret.as_bytes().to_vec());
    }
    let path = cfg.state_dir.join("jwt_secret");
    match fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&cfg.state_dir)
                .with_context(|| format!("creating state dir {}", cfg.state_dir.display()))?;
            let secret = random_bytes(32)?;
            fs::write(&path, &secret).with_context(|| format!("writing {}", path.display()))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            tracing::info!("generated new jwt_secret at {}", path.display());
            Ok(secret)
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

pub(crate) fn random_bytes(n: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key";

    fn keys() -> Keys {
        Keys::new(SECRET)
    }

    fn claims(now: u64) -> Claims {
        new_session(
            "alice",
            vec!["pw".into()],
            Some("deadbeefdeadbeef".into()),
            Default::default(),
            now,
            12,
        )
    }

    #[test]
    fn mint_verify_roundtrip() {
        let c = claims(now());
        let token = mint(&c, &keys()).unwrap();
        let got = verify(&token, &keys(), 7).unwrap();
        assert_eq!(got.sub, "alice");
        assert_eq!(got.orig_iat, c.orig_iat);
        assert_eq!(got.pwd_fp.as_deref(), Some("deadbeefdeadbeef"));
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = mint(&claims(now()), &keys()).unwrap();
        assert!(verify(&token, &Keys::new(b"other-secret"), 7).is_none());
    }

    #[test]
    fn expired_token_rejected() {
        let mut c = claims(now());
        c.iat = now() - 7200;
        c.exp = now() - 3600; // well past the 60s default leeway
        let token = mint(&c, &keys()).unwrap();
        assert!(verify(&token, &keys(), 7).is_none());
    }

    #[test]
    fn absolute_cap_rejects_old_origin() {
        let mut c = claims(now());
        c.orig_iat = now() - 100 * 86400; // 100 days ago, but exp still fresh
        let token = mint(&c, &keys()).unwrap();
        assert!(verify(&token, &keys(), 7).is_none());
        assert!(verify(&token, &keys(), 365).is_some());
    }

    #[test]
    fn wrong_issuer_rejected() {
        let mut c = claims(now());
        c.iss = "evil".into();
        let token = mint(&c, &keys()).unwrap();
        assert!(verify(&token, &keys(), 7).is_none());
    }

    #[test]
    fn other_algorithm_rejected() {
        // Pinning means a token signed with a different alg must not verify, even with our secret.
        let token = encode(
            &Header::new(Algorithm::HS512),
            &claims(now()),
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert!(verify(&token, &keys(), 7).is_none());
    }

    #[test]
    fn remint_threshold_and_preserves_origin() {
        let start = 1_000_000u64;
        let c = claims(start);
        assert!(!needs_remint(&c, start + 60, 12)); // fresh
        assert!(needs_remint(&c, start + 7 * 3600, 12)); // past half of 12h
        let r = remint(&c, start + 7 * 3600, 12);
        assert_eq!(r.orig_iat, c.orig_iat);
        assert!(r.iat > c.iat && r.exp > c.exp);
    }
}
