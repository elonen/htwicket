# Architecture

A single Rust binary. Templates, the one stylesheet, and the compiled translation catalogs are all
**embedded** — no runtime asset files, no database, no JS build. State is two plain files
([configuration.md](configuration.md#state-files)).

## Stack

| concern | crate |
|---|---|
| HTTP | `axum` + `tokio` |
| config (TOML → env) | `figment` + `clap` |
| templates / styling | `askama` (server-rendered HTML, one inlined CSS, no JS) |
| session cookie | `jsonwebtoken` — JWT, HS256 **pinned** (`rust_crypto`, no C deps) |
| CEL expressions | `cel-interpreter` |
| password verify (legacy in) | `htpasswd-verify` (`$apr1$`, `{SHA}`) + `pwhash` (DES, `$1$/$5$/$6$`) |
| password write (bcrypt out) | `bcrypt` |
| i18n | gettext `po/*.po`, compiled by `build.rs` into a static table |
| logging | `tracing` → stdout (journald/docker) |

## Module map (`src/`)

| file | responsibility |
|---|---|
| `main.rs` | tracing init → `cli::run` |
| `cli.rs` | clap: `serve` (default) + offline `user` subcommands |
| `config.rs` | load + layer + validate `Config` |
| `state.rs` | in-memory `UserDb` over `.htpasswd` + sidecar; reload, `flock`, atomic writes |
| `authn.rs` | password verify, Basic-verify cache, brute-force limiter |
| `session.rs` | JWT mint / verify / re-mint; `jwt_secret` load-or-create |
| `cel.rs` | compile + eval + type-check CEL |
| `i18n.rs` | locale negotiation + catalog lookup |
| `web/mod.rs` | axum router + all HTTP handlers |
| `web/templates.rs` | askama view models |
| `templates/*.html`, `web/htwicket.css` | the embedded UI |

`build.rs` compiles `po/*.po` into `OUT_DIR/i18n_catalog.rs` (see [translating.md](translating.md)).

## Testing

`make test-and-check` (test + clippy `-D warnings` + `fmt --check`).

- **Unit** — hash-verify matrix (every legacy format + garbage), CEL eval/type-checks, config
  layering + validation, sidecar schema, `rd` validation, session mint/verify/re-mint/cap.
- **Integration** (`tests/integration.rs`) — spawns the real binary against tempdir files and drives
  it over HTTP: login → `/auth` headers, Basic passthrough, lockout (form + Basic), sliding re-mint
  `Set-Cookie`, Basic verify-cache cleared on reload, admin CRUD + batch rename, account
  visibility/editability, password-change session invalidation, `user check` exit codes.

Full nginx end-to-end is left to downstream deployments.

## Non-goals & extension seams

Deliberately out of scope (v1): TOTP/passkeys/OIDC, password-reset email, multi-domain/forward-auth
SSO (subpath-on-same-vhost only), a server-side session store or revocation beyond `pwd_fp`, unix
socket listener, and admin-UI pagination.

The design leaves room, though: any future auth method is just another route that mints the **same**
session JWT — the `factors` claim records which methods were used, and per-user secrets can live in
the sidecar. An OIDC-only deployment would swap Basic passthrough for API tokens on the same verify
path. None of it is built yet.
