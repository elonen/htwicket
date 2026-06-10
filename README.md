# htwicket

Small auth gateway + user manager for nginx `auth_request`. A modern replacement for
htadmin-style `.htpasswd` GUIs:

- **Backwards compatible**: verifies existing `.htpasswd` files as-is (DES crypt, `$apr1$`,
  `$1$`, `$5$`/`$6$`, bcrypt). Writes bcrypt only, so the file stays usable with plain
  nginx `auth_basic` as an escape hatch.
- **Modern sessions**: login form + JWT cookie (real logout, sliding expiry, sessions die on
  password change). Optional `Authorization: Basic` passthrough for scripted clients.
- **App-agnostic user attributes**: declare fields in config (`is_admin`, `can_upload`, ...),
  manage them as checkboxes/inputs in the built-in admin UI, expose them to your app as
  headers/JWT claims via [CEL](https://cel.dev) expressions.
- Single static binary; config from TOML + env vars; offline CLI for user management and
  lockout recovery.

Status: **design phase** — see [PLAN.md](PLAN.md) for the full architecture.

## Quick shape

```
browser ──► nginx ──auth_request──► htwicket /auth ──► 200 + X-Remote-User-* headers
                │                        (cookie or Basic, CEL-derived headers)
                └──► your app (trusts headers from nginx)
htwicket /login /logout /account /admin — login form, self-service, user management UI
.htpasswd (passwords) + .htwicket.toml (fields) — plain files, also editable via CLI
```

nginx wiring example: see PLAN.md. Example config: [htwicket.example.toml](htwicket.example.toml).

## License

MIT OR Apache-2.0, at your option. Contributions must be compatible with both.
