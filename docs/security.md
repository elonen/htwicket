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

No token machinery - use a modern browser for best CSRF safety. Two layers: `SameSite=Lax` on the session cookie, and an **Origin-vs-Host check
on every POST** — a present `Origin` must match `Host`, else `403`. A missing `Origin` is allowed
(SameSite covers it; `curl`/older clients send none).

## Brute force

In-memory, per-process (`src/auth/ratelimit.rs`):

- **Per-username**: exponential backoff after 5 failures — `2^n` seconds, capped at 5 min. Cleared
  on a successful login.
- **Per-IP**: coarse cap of 30 attempts/min. Client IP = **last** `X-Forwarded-For` entry (the
  direct peer is always nginx — so nginx **must** set XFF; see [deployment.md](deployment.md)).
- Success/failure/lockout is logged at `INFO` with username + IP (audit trail).

Both password-verification surfaces are limited: the **login form** and the **Basic passthrough**
branch of `/auth` (`basic_auth_passthrough`). They **share** the same per-username and per-IP state,
with two deliberate consequences:

- On `/auth`, only a cache **miss** consults the limiter — a request served from the Basic-verify
  cache (below) spends no budget. Without this an authenticated scripted client, which hits `/auth`
  on *every* proxied request, would trip the per-IP cap within seconds. So only genuine bcrypt
  verifications count, and only failed ones lock the account.
- Because the state is shared, a stale script repeatedly sending a **wrong** Basic password (e.g. a
  cron job left running after a password change) locks the user out of the **web login form** too —
  the same per-username backoff applies to both. This is intended (it is one account, one backoff),
  but worth knowing when diagnosing a sudden lockout.

One asymmetry from the cache: a Basic password that verified *before* a lockout stays accepted from
the cache until its 5-min TTL expires or the file is reloaded, even while the form is locked.

## Passwords at rest

- Writes use the **`password_hash`** algorithm (`src/config.rs`). Default **bcrypt** (default cost),
  which keeps `.htpasswd` verifiable by plain nginx `auth_basic` as an escape hatch.
- **`argon2id`** is opt-in: stronger, memory-hard (`Argon2::default()` — v19, m=19 MiB, t=2, p=1),
  but argon2 lines are **not** readable by nginx `auth_basic`, so that escape hatch is forfeited
  (`basic_auth_passthrough` is unaffected — htwicket verifies there, not nginx).
- Verification reads everything either way: DES, `$apr1$`, `{SHA}`, `$1$`, `$5$`/`$6$`, bcrypt, and
  argon2. Opt-in `upgrade_hash_on_login` rehashes any entry **not already in `password_hash`** —
  legacy *and* the other strong algorithm — to it the moment a user logs in.
- Unknown/garbage hashes verify `false`.
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
reverse proxy (the browser judges `Secure` by its own https scheme). See [deployment.md](deployment.md).

## No web bootstrap

A zero-user install logs a warning and stays locked — there is no setup page (no unauthenticated
surface). The first user is created with the CLI ([deployment.md](deployment.md#managing-users-cli)).
