# Security model

htwicket trusts exactly one peer — nginx — and faces no traffic directly. The session mechanics it
references here live in [auth-flow.md](auth-flow.md).

## Sessions & tokens

- **HS256, pinned.** The token-header `alg` is ignored on verify, so a token can't downgrade or
  switch the algorithm. `iss` is checked too.
- **`jwt_secret`** auto-generates as 32 random bytes (`/dev/urandom`) persisted `0600` under
  `state_dir` if you don't set one. Set it explicitly only to share sessions across instances.
- **Revocation = password change.** Stateless by design; the only kill switch is the `pwd_fp`
  fingerprint check — changing a password invalidates every outstanding session for that user. Full
  mechanics: [auth-flow.md](auth-flow.md#revocation--password-change).
- **Cookie flags** — `HttpOnly; SameSite=Lax; Path=/`, plus `Secure` unless `insecure_cookies`.

## CSRF

No token machinery. Two layers: `SameSite=Lax` on the session cookie, and an **Origin-vs-Host check
on every POST** — a present `Origin` must match `Host`, else `403`. A missing `Origin` is allowed
(SameSite covers it; `curl`/older clients send none).

## Brute force

In-memory, per-process (`src/authn.rs`):

- **Per-username**: exponential backoff after 5 failures — `2^n` seconds, capped at 5 min. Cleared
  on a successful login.
- **Per-IP**: coarse cap of 30 attempts/min. Client IP = **last** `X-Forwarded-For` entry (the
  direct peer is always nginx — so nginx **must** set XFF; see [deployment.md](deployment.md)).
- Login success/failure/lockout is logged at `INFO` with username + IP (audit trail).

## Passwords at rest

- Writes are **bcrypt only** (default cost), keeping `.htpasswd` verifiable by plain nginx
  `auth_basic` as an escape hatch.
- Legacy hashes (DES, `$apr1$`, `{SHA}`, `$1$`, `$5$`/`$6$`) verify but are never written; opt-in
  `upgrade_hash_on_login` rehashes them to bcrypt the moment a user logs in.
- Unknown/garbage hashes verify `false` — never panic (covered by the hash-matrix test).
- Basic-passthrough caches successful verifies for 5 min keyed by SHA-256(`user:pass`), cleared on
  file reload (bcrypt-per-request would be unaffordable).

## Input validation

- **Usernames**: 1–64 chars, `[A-Za-z0-9@._-]` — no `:` (htpasswd format), no separators.
- **Redirects (`rd`)**: must be a relative path starting `/`, not `//` or `/\`, no control chars —
  blocks open-redirects. Bad/missing → `/`.
- **CEL**: compiled at startup (typo = startup failure); runtime eval error or type mismatch is a
  `500` + log, **fail closed**.

## `insecure_cookies`

Drops the `Secure` flag and shows a persistent warning banner — passwords/sessions then ride plain
HTTP. Legitimate only on localhost or an encrypted tunnel. **Not** needed behind TLS-terminating
nginx (the browser judges `Secure` by its own https scheme). See [deployment.md](deployment.md).

## No web bootstrap

A zero-user install logs a warning and stays locked — there is no setup page (no unauthenticated
surface). The first user is created with the CLI ([deployment.md](deployment.md#managing-users-cli)).
