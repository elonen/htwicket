//! In-memory login brute-force throttle: per-username exponential backoff + a coarse per-IP cap.
//! See docs/security.md.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const FAILS_BEFORE_LOCK: u32 = 5;
const LOCK_CAP_SECS: u64 = 300;
const IP_WINDOW: Duration = Duration::from_secs(60);
const IP_MAX_PER_WINDOW: u32 = 30;

struct UserFails {
    failures: u32,
    locked_until: Option<Instant>,
    last_failure: Instant,
}

struct IpWindow {
    start: Instant,
    count: u32,
}

/// Why an attempt was refused. The web layer maps these to translated user-facing text.
#[derive(Clone, Copy, Debug)]
pub enum Throttle {
    /// Per-IP request cap hit.
    Ip,
    /// Per-username lockout in force.
    User,
}

/// Sweep threshold: both maps are attacker-growable (sprayed usernames, spoofed X-Forwarded-For),
/// so once one passes this size, `check` drops entries whose window/lockout has lapsed.
const SWEEP_AT: usize = 1024;
/// A failure streak with no lockout in force is forgotten after this long.
const FAILS_STALE: Duration = Duration::from_secs(3600);

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

    /// Call before verifying a login. Err means the attempt is refused (locked/throttled).
    /// Consumes one per-IP token on success.
    pub fn check(&self, username: &str, ip: &str) -> Result<(), Throttle> {
        let now = Instant::now();
        {
            let mut ips = self.ips.lock().unwrap();
            if ips.len() >= SWEEP_AT {
                ips.retain(|_, w| now.duration_since(w.start) <= IP_WINDOW);
            }
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
                return Err(Throttle::Ip);
            }
            w.count += 1;
        }
        let mut users = self.users.lock().unwrap();
        if users.len() >= SWEEP_AT {
            users.retain(|_, st| {
                st.locked_until.is_some_and(|until| until > now)
                    || now.duration_since(st.last_failure) < FAILS_STALE
            });
        }
        if let Some(st) = users.get(username)
            && st.locked_until.is_some_and(|until| until > now)
        {
            return Err(Throttle::User);
        }
        Ok(())
    }

    pub fn record_failure(&self, username: &str, ip: &str) {
        let mut users = self.users.lock().unwrap();
        let st = users.entry(username.to_string()).or_insert(UserFails {
            failures: 0,
            locked_until: None,
            last_failure: Instant::now(),
        });
        st.failures += 1;
        st.last_failure = Instant::now();
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
