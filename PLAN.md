# htwicket — design plan

Small auth gateway + user manager for nginx `auth_request`. Replaces htadmin-style PHP .htpasswd
GUIs in self-hosted/demo deployments. Backwards compatible with existing `.htpasswd` files
(verifies DES crypt / `$apr1$` / `$1$` / SHA / bcrypt), writes bcrypt only. App-agnostic:
fields/headers/claims are config-declared, nothing app-specific in core.

Name: "ht" nods to htpasswd lineage without locking out future OIDC.
License: MIT OR Apache-2.0. Sibling project of ldap_authz_proxy.

## Stack

- axum + tokio + tower-http — HTTP
- figment + clap — config: TOML file → env override → CLI args
- askama — server-rendered templates, plain HTML forms, embedded classless CSS (pico.css). No JS build.
- jsonwebtoken — session cookie = JWT, HS256 **pinned** (token-header alg ignored)
- cel-interpreter (clarkmcc/cel-rust) — header/claim/superadmin expressions
- htpasswd-verify (DES, $apr1$, SHA1, bcrypt) + pwhash ($1$, $5$, $6$) + bcrypt (writing) — verify exact coverage with the hash-matrix unit test.
- gettext-style i18n: `po/<locale>.po` compiled by build.rs into a static lookup (no runtime files); msgid = English source; locale from `Accept-Language`. English-only catalog at launch is fine; machinery in from day one.
- tracing — logs to stdout (journald/docker)

Single static binary (musl), all assets embedded.

## State files

- `.htpasswd` — canonical passwords, `user:hash` lines. Existing files work unmodified.
- `.htwicket.toml` — sidecar, same dir by default. Per-user tables with schema-declared fields.
  Leading-`.ht` name falls under stock nginx/Apache `location ~ /\.ht` deny globs.
  Unknown fields found in sidecar: warn + preserve, never delete.
- Both: parsed into memory; reload on mtime change (one `stat()` per request). Writes: flock on
  shared `.lock` file (server + CLI), write-temp + atomic rename.
- `{state_dir}/jwt_secret` — auto-generated signing key if not set in config. Default state_dir
  `/var/lib/htwicket`.
- htadmin's `.htmeta` is **ignored**. No import.

## Config (`/etc/htwicket.toml`, env prefix `HTWICKET_`, `__` for nesting)

```toml
listen = "127.0.0.1:8088"
base_path = "/htwicket"            # all routes served under this; proxy_pass needs no rewrite
htpasswd_file = "/var/www/.htpasswd"
# sidecar_file defaults to .htwicket.toml next to htpasswd_file
# state_dir = "/var/lib/htwicket"
# jwt_secret = "..."               # else auto-generated + persisted
insecure_cookies = false           # true drops Secure flag (plain-http demo); loud startup warning
                                   # + persistent warning banner on all GUI pages while enabled.
                                   # Legit only for localhost or encrypted overlays (VPN/Tailscale);
                                   # NOT needed behind TLS-terminating nginx (Secure is judged by the
                                   # browser's scheme, not htwicket's listener) — document loudly.
basic_auth_passthrough = false     # demo sets true (backwards compat for scripted clients)
# upgrade_hash_on_login = false    # opt-in: rehash legacy entries to bcrypt at login (plaintext in hand)
min_password_len = 8
session_hours = 12                 # JWT exp; sliding re-mint past half-life
session_max_days = 7               # absolute cap via orig_iat

[superadmins]                      # admins of htwicket itself (GUI /admin access)
expr = "username == 'admin' || fields.is_admin"   # CEL; OR'd over nothing else — this is the whole gate

[fields.is_admin]                  # example app schema (core knows none of it)
type = "bool"                      # bool | string | email
default = false
# required = false                 # non-bools only
# user_editable = false            # shown editable on /account

[fields.display_name]
type = "string"
user_editable = true

[fields.can_upload]
type = "bool"
default = true

[headers.X-Remote-User-Is-Admin]   # /auth 200-response headers, picked up via auth_request_set
type = "bool"
expr = "fields.is_admin"           # CEL over {username, fields.*} with defaults pre-applied

[headers.X-Remote-User-Name]
type = "string"
expr = "fields.display_name != '' ? fields.display_name : username"

[jwt-claims.can_upload]            # optional extra claims, baked at login (stale until re-login — headers are authoritative)
type = "bool"
expr = "fields.can_upload"
```

CEL: compiled at config load (bad expr = startup failure). Result type-checked against `type`.
Runtime eval error → 500 + log, fail closed. `X-Remote-User-Id: <username>` always sent, not configurable.

## HTTP endpoints (all under base_path)

- `GET /auth` — nginx auth_request target. Order: session cookie → Basic header (if passthrough) → 401.
  200: identity/CEL headers + sliding re-mint (`Set-Cookie` when >half of session_hours elapsed).
  401: bare (nginx swallows subrequest headers anyway; browsers handled by error_page redirect).
- `GET|POST /login` — form → JWT cookie → 303 to `rd` (validated: relative, starts `/`, no `//`).
- `GET|POST /logout` — GET shows confirm page w/ POST button (safe link target); POST clears cookie.
- `GET|POST /account` — own password change (old pw required) + `user_editable` fields.
- `GET|POST /admin` — superadmins only: user table, add/delete user, set password, edit all fields. No pagination.
- `GET /healthz` — unauthenticated 200.

## Session JWT

- Cookie `htwicket_session`; HttpOnly, SameSite=Lax, Secure unless `insecure_cookies`, Path=/.
- Claims: `sub`, `iat`, `exp`, `iss="htwicket"`, `orig_iat` (first login; survives re-mints; enforces session_max_days),
  `factors` (`["pw"]` for now), `pwd_fp`, plus `[jwt-claims.*]`.
- `pwd_fp` = first 16 hex of SHA-256(hash field from .htpasswd). Present ⇒ must match current in-memory
  value at /auth, else 401. Password change re-salts bcrypt → fp rotates → all sessions die. The only
  revocation mechanism (stateless by design).
- Basic-auth requests never mint cookies.

## Security decisions

- CSRF: SameSite=Lax + Origin-vs-Host check on every POST. No token machinery.
- Brute force: in-memory; per-username exponential backoff after 5 failures (2^n s, cap 5 min) +
  coarse per-IP cap (30 attempts/min). Client IP = last X-Forwarded-For entry (direct peer is always nginx).
- Basic passthrough perf: bcrypt per request is unaffordable → TTL cache (5 min) of successful
  verifications keyed by SHA-256(user:pass); cleared on file reload. Only active with passthrough on.
- Username: 1–64 chars, `[A-Za-z0-9@._-]` (no `:` — htpasswd format).
- Auth audit: tracing INFO on login success/failure/lockout with username + IP.
- Zero users at startup: warn "no users — run `htwicket user add`". No web bootstrap (no setup-page surface).

## CLI (clap subcommands)

- `htwicket serve` (default)
- `htwicket user add <name>` — password from stdin/tty prompt; `--random` generates + prints
- `htwicket user passwd <name>` — stdin/tty; `--random`
- `htwicket user del <name>`
- `htwicket user list`
- `htwicket user check <name>` — exit 0 ok+password set, 1 missing, 2 sidecar fields fail schema.
  Docker entrypoints: `user check admin || user passwd admin --random`.

All file ops honor the flock; work offline against the files (lockout recovery story).

## nginx wiring (documented example in README)

```nginx
location = /htwicket/auth {
    internal;
    proxy_pass http://127.0.0.1:8088/htwicket/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # Authorization + Cookie inherited by subrequest automatically
}
location / {
    auth_request /htwicket/auth;
    auth_request_set $uid $upstream_http_x_remote_user_id;
    auth_request_set $adm $upstream_http_x_remote_user_is_admin;
    auth_request_set $sc  $upstream_http_set_cookie;     # sliding re-mint propagation
    proxy_set_header X-Remote-User-Id $uid;
    proxy_set_header X-Remote-User-Is-Admin $adm;
    add_header Set-Cookie $sc;                           # nginx omits header when var empty
    error_page 401 = @login;
    proxy_pass http://backend;
}
location @login { return 302 /htwicket/login?rd=$request_uri; }
location /htwicket/ { proxy_pass http://127.0.0.1:8088; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; }
```

Caveat to document: 401→login redirect means challenge-response Basic clients break; preemptive
(`curl -u`, most libs) work. API-only locations can override error_page to plain 401.

## Repo layout / packaging

```
src/            main.rs, config.rs, state.rs (files+reload), authn.rs (verify+cache+ratelimit),
                session.rs (JWT), cel.rs, web/ (handlers), cli.rs, i18n.rs
templates/      askama: login, logout, account, admin, base
po/             gettext catalogs; build.rs compiles to static lookup
Dockerfile      scratch/distroless, musl binary
debian/         .deb: systemd unit (runs as www-data), /etc/htwicket.toml conffile
Makefile, CI    GitHub Actions: test, clippy, musl build, deb, docker push (mirror ldap_authz_proxy setup)
```

## Testing

- Unit: hash-verify matrix (DES, $apr1$, $1$, $5$/$6$, $2y$), CEL eval + type checks, config layering,
  sidecar schema validation, rd validation, pwd_fp rotation.
- Integration: spawn binary against tempdir files; reqwest: login flow, /auth header outputs, Basic
  passthrough + cache, sliding re-mint, lockout, admin CRUD, user check exit codes.
- Full nginx e2e belongs to downstream deployments' tests, not here.

## Non-goals (v1)

- TOTP / passkeys / OIDC — seam documented: any future method is just another route that mints the same
  session JWT; `factors` claim + sidecar carry per-user secrets later. OIDC-only deployments would need
  API tokens to replace Basic passthrough (same verify path, different store) — not now.
- Email / SMTP / password-reset mail.
- Multi-domain SSO / forward-auth across hosts. Subpath-on-same-vhost only.
- Server-side session store / revocation beyond pwd_fp.
- Unix socket listener, i18n catalogs beyond en, pagination.
