//! TTL cache of successful Basic-auth verifications, keyed by SHA-256(user:pass). Only active with
//! basic_auth_passthrough; cleared on file reload. See docs/security.md.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const VERIFY_TTL: Duration = Duration::from_secs(300);

/// TTL cache (5 min) of successful Basic verifications keyed by SHA-256(user:pass).
/// bcrypt per request is unaffordable; only active with basic_auth_passthrough. Cleared on file reload.
#[derive(Default)]
pub struct VerifyCache {
    entries: Mutex<HashMap<[u8; 32], Instant>>, // digest -> expiry
}

impl VerifyCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(user: &str, pass: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(user.as_bytes());
        h.update(b":");
        h.update(pass.as_bytes());
        h.finalize().into()
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
