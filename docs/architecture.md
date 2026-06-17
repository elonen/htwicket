# Architecture

A single Rust binary. Templates, the one stylesheet, and the compiled translation catalogs are all
**embedded** — no runtime asset files, no database, no JS build. State is two plain files
([configuration.md](configuration.md#state-files)).

## Stack

| concern | crate |
|---|---|
| HTTP | `axum` + `tokio` |
| config (TOML → env → CLI) | `figment` + `clap` |
| templates / styling | `askama` (server-rendered HTML, one inlined CSS, no JS) |
| session cookie | `jsonwebtoken` — JWT, HS256 **pinned** (`rust_crypto`, no C deps) |
| CEL expressions | `cel-interpreter` |
| password verify (legacy in) | `htpasswd-verify` (`$apr1$`, `{SHA}`) + `pwhash` (DES, `$1$/$5$/$6$`) + `argon2` |
| password write (configurable out) | `bcrypt` (default) or `argon2` (`password_hash` config) |
| i18n | gettext `po/*.po`, compiled by `build.rs` into a static table |
| logging | `tracing` → stdout (journald/docker); INFO, or DEBUG when `debug = true` |

The design leaves room for things like TOTP and alternative auth methods like OIDC: they'd be just another route that
mints the same session JWT. Not implemented for now though.

## Module map (`src/`)

| file | responsibility |
|---|---|
| `main.rs` | entry: load config, init tracing (`debug` → DEBUG), dispatch `serve`/`user`/`healthz` |
| `cli/mod.rs` | clap `Cli`/`Command`: `serve` (default), offline `user`, `healthz` |
| `cli/user.rs` | offline `user` subcommands (add/passwd/del/list/check) |
| `cli/healthz.rs` | `healthz` subcommand — probe a running server's `/healthz` for container `HEALTHCHECK` |
| `config.rs` | load + layer + validate `Config` |
| `state.rs` | in-memory `UserDb` over `.htpasswd` + sidecar; reload, `flock`, atomic writes |
| `auth/password.rs` | password verify + hash (legacy in, `password_hash` out) |
| `auth/cache.rs` | Basic-passthrough verify cache |
| `auth/ratelimit.rs` | brute-force limiter (per-username backoff + per-IP cap) |
| `token.rs` | JWT mint / verify / re-mint; `jwt_secret` load-or-create |
| `cel.rs` | compile + eval + type-check CEL |
| `i18n.rs` | locale negotiation + catalog lookup |
| `web/mod.rs` | axum router; compiles every CEL expr at startup |
| `web/handlers.rs` | route handlers — `/auth`, login, logout, account, admin |
| `web/views.rs` | view models + CEL evaluation (header/claim/superadmin/editable) |
| `web/helpers.rs` | request parsing, cookies, locale negotiation, `rd` validation |
| `web/templates.rs` | askama view structs |
| `templates/*.html`, `web/htwicket.css` | the embedded UI |

`build.rs` compiles `po/*.po` into `OUT_DIR/i18n_catalog.rs` (see [translating.md](translating.md)).

## Testing

`make test-and-check` (test + clippy `-D warnings` + `fmt --check`).

- **Unit** — hash-verify matrix (every legacy format + garbage), CEL eval/type-checks, config
  layering + validation, sidecar schema, `rd` validation, session mint/verify/re-mint/cap.
- **Integration** (`tests/*.rs`, one suite per feature) — spawn the real binary against tempdir
  files and drive it over HTTP: login → `/auth` headers, Basic passthrough, open-redirect/CSRF
  guards, sliding re-mint `Set-Cookie` (`auth.rs`); lockout on form + Basic (`rate_limit.rs`);
  password-change session invalidation + lazy hash migration + Basic verify-cache reload
  (`password.rs`); admin CRUD + batch rename + account visibility/editability (`admin.rs`); logout
  (`logout.rs`); locale negotiation + `default_lang` (`i18n.rs`); `user check` exit codes + bootstrap
  flags (`cli.rs`); page chrome + `app_title_html` branding (`ui.rs`); and a form-contract guard
  against template/handler drift (`form_contract.rs`).

Full nginx end-to-end is left to downstream deployments.
