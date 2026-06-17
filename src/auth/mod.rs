//! Authentication, split by concern: password verify/hash (`password`), the Basic-passthrough
//! verify cache (`cache`), and the login brute-force throttle (`ratelimit`). See docs/security.md.

mod cache;
mod password;
mod ratelimit;

pub use cache::VerifyCache;
pub use password::{hash_password, hash_password_blocking, needs_rehash, verify_password_blocking};
pub use ratelimit::{RateLimiter, Throttle};
