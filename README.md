# htwicket - migrate from old .htaccess to something a slightly more modern

Small auth gateway + user manager for nginx `auth_request`.
Provides a web GUI for editing `.htpasswd`, upgrading its hashes to bcrypt,
and providing custom user data backend apps.

- **Backwards compatible**: verifies existing `.htpasswd` files as-is (DES crypt, `$apr1$`,
  `$1$`, `$5$`/`$6$`, bcrypt). Writes bcrypt only, so the file stays usable with plain
  nginx `auth_basic` as an escape hatch.
- **Modern sessions**: login form + JWT cookie (real logout, sliding expiry, sessions die on
  password change). Optional `Authorization: Basic` passthrough for scripted clients.
- **App-agnostic user attributes**: declare fields in config (`is_admin`, `can_upload`, ...),
  manage them as checkboxes/inputs in the built-in admin UI, expose them to your app as
  headers/JWT claims via [CEL expressions](https://cel.dev).
- **Self-contained**: one binary, all templates/CSS/translations embedded; config from TOML +
  env vars; offline CLI for user management and lockout recovery; no JS, no runtime assets, no DB.

## Quick shape

```
browser ──► nginx ──auth_request──► htwicket /auth ──► 200 + X-Remote-User-* headers
                │                        (cookie or Basic, CEL-derived headers)
                └──► your app (trusts headers from nginx)

htwicket /login /logout /account /admin — login form, self-service, user management UI

.htpasswd (passwords) + .htwicket.toml (fields) — plain files, also editable via admin CLI
```

## Quick start

```sh
sudo $EDITOR /etc/htwicket.toml        # edit htpasswd_file, superadmins, fields…
sudo htwicket user add admin           # prompts for a password
sudo systemctl enable --now htwicket   # or: htwicket serve
```

Then point nginx at it — see [docs/deployment.md](docs/deployment.md). Annotated config:
[htwicket.example.toml](htwicket.example.toml).

## Documentation

- [auth-flow.md](docs/auth-flow.md) — how a request is authenticated, step by step; the session JWT lifecycle.
- [configuration.md](docs/configuration.md) — config layering, the field/header/claim schema + CEL, state files.
- [deployment.md](docs/deployment.md) — nginx wiring, the `.deb`/systemd install, the CLI, lockout recovery.
- [security.md](docs/security.md) — threat model and the security decisions behind it.
- [architecture.md](docs/architecture.md) — stack, module map, testing, non-goals & extension seams.
- [translating.md](docs/translating.md) — translate the UI (gettext workflow).

## License
MIT OR Apache-2.0, at your option. Contributions must be compatible with both.
(c) 2026 by Jarno Elonen <elonen@iki.fi>
