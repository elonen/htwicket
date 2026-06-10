# Auth flow

How a request gets authenticated, and how the session lives and dies. Nginx is the only direct
peer; htwicket never faces the internet itself. For the nginx config see
[deployment.md](deployment.md); for the attacker's-eye view see [security.md](security.md).

## The big picture

```
browser ──► nginx (TLS) ──► protected location
                              │  auth_request subrequest
                              ▼
                          htwicket GET /auth ──► 200 + X-Remote-User-* headers ──► backend
                                            └──► 401 ──► nginx error_page ──► 302 /login?rd=…
```

Mginx fires an internal `auth_request` to `/auth` for every hit on a protected location. **200** =
let the request through, copying htwicket's `X-Remote-User-*` headers to the backend. **401** =
nginx redirects the browser to the login form, remembering the original URL in `rd` (redirect after login).

## Per-request: `GET /auth`

The handler tries each credential source in order and stops at the first that works
(`src/web/mod.rs::auth`):

1. **Session cookie** `htwicket_session` — verify the JWT (below); confirm the user still exists
   and the password fingerprint still matches. On success emit headers and maybe re-mint the cookie.
2. **`Authorization: Basic`** — only if `basic_auth_passthrough = true`. Verify against `.htpasswd`
   (via a cache). Never mints a cookie. For scripted/legacy clients.
3. **Bare `401`** —  no body (nginx discards a subrequest body anyway).

<details>
<summary>200-response headers</summary>

- `X-Remote-User-Id: <username>` — always, not configurable.
- one header per `[headers.*]` config entry, value = its CEL expression over `{username, fields.*}`.
- `Set-Cookie` — only when a sliding re-mint happened (see below).

A CEL eval error here is a `500` (fail closed), never a silent grant. Header schema + CEL:
[configuration.md](configuration.md).
</details>

<details>
<summary>Reload freshness</summary>

Before reading users, `/auth` `stat()`s `.htpasswd` + the sidecar and reloads them if the mtime
changed (one stat, read-lock fast path). So CLI edits and admin-UI saves take effect within one
request — no restart or cache to bust. Details: [configuration.md](configuration.md#state-files).
</details>

## Logging in: `POST /login`

1. Origin-vs-Host CSRF check (see [security.md](security.md)).
2. Rate-limit gate (per-username backoff + per-IP cap). Refused → re-render form with a message.
3. Verify the password against the stored hash (any legacy format in, see
   [configuration.md](configuration.md#state-files)).
4. On success: optionally rehash an entry not in `password_hash` to it (`upgrade_hash_on_login`), bake
   `[jwt-claims.*]`, **mint** the session JWT, `Set-Cookie`, `303` to `rd`.

`rd` is validated as a relative path (starts `/`, not `//`, no control chars) — bad/missing `rd`
falls back to `/`. Wrong password → record failure, re-render with the username preserved.

## The session JWT

Cookie `htwicket_session`: `HttpOnly; SameSite=Lax; Path=/; Max-Age=<idle>` plus `Secure` unless
`insecure_cookies` is configured (for localhost / HTTP testing).
Signed **HS256, pinned** — the token header's `alg` is ignored, so a token can't
downgrade the verifier. Stateless: htwicket keeps no server-side session list.

<details>
<summary>JWT Claims</summary>

| claim | meaning |
|---|---|
| `sub` | username |
| `iat` / `exp` | issued-at / idle expiry (`iat + session_idle_hours`) |
| `orig_iat` | first login; survives re-mints; enforces the absolute cap |
| `iss` | `"htwicket"` (checked on verify) |
| `factors` | `["pw"]` today; future methods (totp, oidc) append |
| `pwd_fp` | password fingerprint — first 16 hex of SHA-256(`.htpasswd` hash) |
| *(extra)* | each `[jwt-claims.*]`, baked at login |

`src/session.rs`.
</details>

### Lifecycle

- **Idle expiry** — `exp = iat + session_idle_hours`. Past it, the cookie is dead.
- **Sliding re-mint** — at `/auth`, once more than *half* of `session_idle_hours` has elapsed,
  htwicket re-mints (fresh `iat`/`exp`, everything else preserved) and returns a new `Set-Cookie`.
  An active session never expires from idle; nginx must propagate that header (deployment.md).
  A re-mint is *not* a re-login: baked `[jwt-claims.*]` stay as they were — headers are the fresh
  channel.
- **Absolute cap** — `orig_iat + session_max_days`. Hit it and the session ends regardless of
  activity; only a real re-login (new `orig_iat`) resets it.

### Revocation = password change (or re-salt)

The only revocation mechanism, by design (stateless sessions). `pwd_fp` is a fingerprint of the
stored password hash. At `/auth` the token's `pwd_fp` must equal the user's current one. Changing a
password re-salts bcrypt → the hash changes → `pwd_fp` rotates → **every** outstanding session for
that user fails the next `/auth` and is forced back to login. (Tokens minted without a `pwd_fp` skip
the check — a forward-compat escape hatch.)

## Logging out: `/logout`

`GET /logout` shows a confirm page (so a prefetched link can't log you out); `POST /logout`
(CSRF-checked) clears the cookie (`Max-Age=0`) and redirects to `/login`. Since sessions are
stateless this only drops the cookie on *this* browser — other sessions live until idle/cap/password
change.

## Basic passthrough (scripted clients)

With `basic_auth_passthrough = true`, `/auth` also accepts `Authorization: Basic`. bcrypt-per-request
is too slow, so a successful verify is cached for 5 min keyed by SHA-256(`user:pass`); the cache is
cleared on every file reload. No cookie is ever minted for a Basic request. Browsers hitting a
challenge-response flow will break on the `401→login` redirect — see the caveat in
[deployment.md](deployment.md).
