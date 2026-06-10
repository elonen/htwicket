//! Password verification (legacy formats in, bcrypt out), Basic-passthrough verify cache,
//! and login brute-force limiting. See PLAN.md "Security decisions".

/// Verify a password against any supported .htpasswd hash.
///
/// Format coverage is split between two crates so we never hit htpasswd-verify's
/// bcrypt `.unwrap()` panic or its DES-only fallthrough for `$1$`/`$5$`/`$6$`:
///   - `$apr1$` (Apache MD5) and `{SHA}` (Apache base64 SHA1) → htpasswd-verify
///   - everything else (DES crypt, `$1$`, `$2a$`/`$2b$`/`$2y$`, `$5$`, `$6$`) →
///     `pwhash::unix::verify`, which dispatches by prefix.
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

/// TTL cache (5 min) of successful Basic verifications keyed by SHA-256(user:pass).
/// bcrypt per request is unaffordable; only active with basic_auth_passthrough. Cleared on file reload.
pub struct VerifyCache;

/// In-memory: per-username exponential backoff after 5 failures (2^n s, cap 5 min)
/// + coarse per-IP cap (30/min). Client IP = last X-Forwarded-For entry (direct peer is nginx).
/// Logs success/failure/lockout at INFO with username + IP.
pub struct RateLimiter;

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
        ("sha256_5", "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/"),
        (
            "sha512_6",
            "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1",
        ),
        ("bcrypt_2y", "$2y$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope"),
        ("bcrypt_2a", "$2a$05$Ftpcc093Aifqr/esFXS5XexMgXGY7SDuA7tGgcXFV8/LAyo5/yope"),
        ("sha1", "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="),
    ];

    #[test]
    fn hash_matrix_accepts_correct_and_rejects_wrong() {
        for (name, hash) in VECTORS {
            assert!(verify_password(PW, hash), "{name}: correct password rejected");
            assert!(!verify_password("wrong", hash), "{name}: wrong password accepted");
        }
    }

    #[test]
    fn garbage_hashes_do_not_panic() {
        for h in ["", "x", "$2y$broken", "$apr1$short", "{SHA}!!!", "$9$unknown$x"] {
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
