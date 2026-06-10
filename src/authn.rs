//! Password verification (legacy formats in, bcrypt out), Basic-passthrough verify cache,
//! and login brute-force limiting. See docs/security.md.

/// Verify a password against any supported .htpasswd hash.
///
/// Format coverage is split between two crates so we never hit htpasswd-verify's
/// bcrypt `.unwrap()` panic or its DES-only fallthrough for `$1$`/`$5$`/`$6$`:
///   - `$apr1$` (Apache MD5) and `{SHA}` (Apache base64 SHA1) → htpasswd-verify
///   - everything else (DES crypt, `$1$`, `$2a$`/`$2b$`/`$2y$`, `$5$`, `$6$`) →
///     `pwhash::unix::verify`, which dispatches by prefix.
///
/// Unknown/garbage hashes verify as `false`, never panic. See the hash-matrix test.
pub fn verify_password(password: &str, hash: &str) -> bool {
    if let Some(rest) = hash.strip_prefix("$apr1$") {
        // htpasswd-verify indexes the salt at bytes [6..14] unchecked (it assumes the
        // canonical `$apr1$<8-char salt>$<hash>` htpasswd/openssl emit). Gate on that
        // exact shape so a short or multi-byte salt can't trip an out-of-bounds slice.
        let well_formed = rest.as_bytes().get(8) == Some(&b'$')
            && rest.as_bytes()[..8].iter().all(u8::is_ascii_graphic);
        well_formed && htpasswd_verify::md5::verify_apr1_hash(hash, password).unwrap_or(false)
    } else if hash.starts_with("{SHA}") {
        htpasswd_verify::Hash::parse(hash).check(password)
    } else {
        pwhash::unix::verify(password, hash)
    }
}

/// New hashes are always bcrypt — keeps the file verifiable by plain nginx auth_basic (escape hatch).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(bcrypt::hash(password, bcrypt::DEFAULT_COST)?)
}

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const VERIFY_TTL: Duration = Duration::from_secs(300);
const FAILS_BEFORE_LOCK: u32 = 5;
const LOCK_CAP_SECS: u64 = 300;
const IP_WINDOW: Duration = Duration::from_secs(60);
const IP_MAX_PER_WINDOW: u32 = 30;

/// TTL cache (5 min) of successful Basic verifications keyed by SHA-256(user:pass).
/// bcrypt per request is unaffordable; only active with basic_auth_passthrough. Cleared on file reload.
#[derive(Default)]
pub struct VerifyCache {
    entries: Mutex<HashMap<String, Instant>>, // key -> expiry
}

impl VerifyCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(user: &str, pass: &str) -> String {
        let mut h = Sha256::new();
        h.update(user.as_bytes());
        h.update(b":");
        h.update(pass.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// True if this exact (user, pass) verified successfully within the TTL.
    pub fn check(&self, user: &str, pass: &str) -> bool {
        let key = Self::key(user, pass);
        let mut entries = self.entries.lock().unwrap();
        match entries.get(&key) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                entries.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn store(&self, user: &str, pass: &str) {
        self.entries
            .lock()
            .unwrap()
            .insert(Self::key(user, pass), Instant::now() + VERIFY_TTL);
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

struct UserFails {
    failures: u32,
    locked_until: Option<Instant>,
}

struct IpWindow {
    start: Instant,
    count: u32,
}

/// In-memory login throttle: per-username exponential backoff after 5 failures (2^n s, cap 5 min)
/// plus a coarse per-IP cap (30/min). Client IP = last X-Forwarded-For entry (peer is nginx).
/// Logs success/failure/lockout at INFO with username + IP.
#[derive(Default)]
pub struct RateLimiter {
    users: Mutex<HashMap<String, UserFails>>,
    ips: Mutex<HashMap<String, IpWindow>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Call before verifying a login. Err(reason) means the attempt is refused (locked/throttled);
    /// the reason is a user-facing message. Consumes one per-IP token on success.
    pub fn check(&self, username: &str, ip: &str) -> Result<(), String> {
        let now = Instant::now();
        {
            let mut ips = self.ips.lock().unwrap();
            let w = ips.entry(ip.to_string()).or_insert(IpWindow {
                start: now,
                count: 0,
            });
            if now.duration_since(w.start) > IP_WINDOW {
                *w = IpWindow {
                    start: now,
                    count: 0,
                };
            }
            if w.count >= IP_MAX_PER_WINDOW {
                return Err("Too many attempts from your network. Wait a minute and retry.".into());
            }
            w.count += 1;
        }
        let users = self.users.lock().unwrap();
        if let Some(st) = users.get(username)
            && st.locked_until.is_some_and(|until| until > now)
        {
            return Err("Too many failed attempts. Try again shortly.".into());
        }
        Ok(())
    }

    pub fn record_failure(&self, username: &str, ip: &str) {
        let mut users = self.users.lock().unwrap();
        let st = users.entry(username.to_string()).or_insert(UserFails {
            failures: 0,
            locked_until: None,
        });
        st.failures += 1;
        if st.failures >= FAILS_BEFORE_LOCK {
            let exp = (st.failures - FAILS_BEFORE_LOCK).min(9); // avoid shift overflow
            let secs = (1u64 << exp).min(LOCK_CAP_SECS);
            st.locked_until = Some(Instant::now() + Duration::from_secs(secs));
            tracing::info!(user = username, ip = ip, lock_secs = secs, "login lockout");
        } else {
            tracing::info!(
                user = username,
                ip = ip,
                failures = st.failures,
                "login failure"
            );
        }
    }

    pub fn record_success(&self, username: &str, ip: &str) {
        self.users.lock().unwrap().remove(username);
        tracing::info!(user = username, ip = ip, "login success");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // All vectors below encode the password "password" (DES/$apr1$/{SHA} reuse the
    // htpasswd-verify upstream test vectors; the modular ones are openssl-generated
    // with fixed salts so they stay stable).
    const PW: &str = "password";
    const VECTORS: &[(&str, &str)] = &[
        ("des", "bGVh02xkuGli2"),
        ("apr1", "$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0"),
        ("md5_1", "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0"),
        (
            "sha256_5",
            "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/",
        ),
        (
            "sha512_6",
            "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1",
        ),
        (
            "bcrypt_2y",
            "$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope",
        ),
        (
            "bcrypt_2a",
            "$2a$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope",
        ),
        ("sha1", "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="),
    ];

    #[test]
    fn hash_matrix_accepts_correct_and_rejects_wrong() {
        for (name, hash) in VECTORS {
            assert!(
                verify_password(PW, hash),
                "{name}: correct password rejected"
            );
            assert!(
                !verify_password("wrong", hash),
                "{name}: wrong password accepted"
            );
        }
    }

    #[test]
    fn garbage_hashes_do_not_panic() {
        for h in [
            "",
            "x",
            "$2y$broken",
            "$apr1$short",
            "{SHA}!!!",
            "$9$unknown$x",
        ] {
            assert!(!verify_password(PW, h), "garbage hash {h:?} verified true");
        }
    }

    #[test]
    fn bcrypt_roundtrip() {
        let h = hash_password(PW).unwrap();
        assert!(h.starts_with("$2"), "wrote non-bcrypt hash: {h}");
        assert!(verify_password(PW, &h));
        assert!(!verify_password("nope", &h));
    }
}
