# Configuration

The annotated [htwicket.example.toml](../htwicket.example.toml) is canonical reference — copy it
to `/etc/htwicket.toml` and edit. This page explains the layering and the schema/CEL semantics
behind it.

## Layering

`Config` is assembled (`src/config.rs`) as **TOML file → env override → built-in defaults**:

- File: `--config <path>` (default `/etc/htwicket.toml`).
- Env: `HTWICKET_` prefix, `__` for nesting — e.g. `HTWICKET_LISTEN`,
  `HTWICKET_SUPERADMINS__EXPR`, `HTWICKET_SESSION_IDLE_HOURS`.

Everything is validated at startup — an unknown key, a bad `base_path`, a malformed CEL expression,
or a default that doesn't match its field type is a **loud startup failure**, never a request-time
surprise. (CEL is compiled by `serve` only, so the offline `user` CLI keeps working even with a
broken header/claim expr — the lockout-recovery path.)

## Core keys

Defaults in parentheses. See the example for inline guidance.

| key | meaning |
|---|---|
| `listen` (`127.0.0.1:8088`) | bind address |
| `base_path` (`/htwicket`) | all routes served under this; nginx `proxy_pass` needs no rewrite |
| `htpasswd_file` *(required)* | the password file |
| `sidecar_file` | fields file (default: `.htwicket.toml` next to `htpasswd_file`) |
| `state_dir` (`/var/lib/htwicket`) | holds the auto-generated `jwt_secret` |
| `jwt_secret` | HS256 key; auto-generated + persisted under `state_dir` if unset |
| `insecure_cookies` (`false`) | drop the cookie `Secure` flag — plain-http demo only; see [security.md](security.md) |
| `basic_auth_passthrough` (`false`) | accept `Authorization: Basic` on `/auth` ([auth-flow.md](auth-flow.md)) |
| `upgrade_hash_on_login` (`false`) | rehash a legacy entry to bcrypt on successful login |
| `min_password_len` (`8`) | enforced by the UI + CLI |
| `session_idle_hours` (`12`) | JWT idle expiry; sliding re-mint past half-life |
| `session_max_days` (`7`) | absolute session cap |

## Fields, headers, claims

htwicket core knows no app-specific attribute. You declare them; CEL turns them into outputs.

**`[fields.<name>]`** — a per-user attribute stored in the sidecar. `<name>` must be a CEL
identifier (`[A-Za-z_][A-Za-z0-9_]*`).

| key | meaning |
|---|---|
| `type` | `bool` \| `string` \| `email` |
| `default` | value when the user has none (must match `type`) |
| `required` | non-bool only; flags a missing value in `user check` / admin UI |
| `user_visible` (`false`) | show it (read-only) on the user's own `/account` |
| `user_editable_expr` (`"false"`) | CEL bool: may *this* user edit it? Editable ⇒ visible |

**`[headers.<name>]`** and **`[jwt-claims.<name>]`** — `{ type, expr }`. Each `expr` is CEL.
Headers are emitted on every `/auth` 200 (live); claims are baked once at login (stale until
re-login — so headers are authoritative). `X-Remote-User-Id` is always sent and isn't configurable.

**`[superadmins].expr`** — CEL bool deciding who may open `/admin`.

### CEL semantics

Expressions (cel-interpreter) evaluate over a context of `username` (string) and `fields.*`
(every declared field, with `default`/zero pre-applied so exprs are *total* — a typo'd field name
errors rather than silently missing). The result is type-checked against the declared `type`.
Compiled once at startup (bad expr = startup failure); a runtime eval error is a `500` + log —
**fail closed**, never silently grant. Examples:

```toml
[superadmins]
expr = "username == 'admin' || fields.is_admin"

[headers.X-Remote-User-Name]
type = "string"
expr = "fields.display_name != '' ? fields.display_name : username"
```

## State files

Three plain files live beside each other (all under nginx/Apache's stock `location ~ /\.ht` deny
glob, so they're never web-served). Managed by `src/state.rs`.

- **`.htpasswd`** — canonical passwords, one `user:hash` line each. Existing files work unmodified.
  Verifies DES crypt, `$apr1$`, `{SHA}`, `$1$`, `$5$`/`$6$`, and bcrypt (`$2a/2b/2y`); **writes
  bcrypt only**, so the file stays usable with plain nginx `auth_basic`.
- **`.htwicket.toml`** (sidecar) — `[users."<name>"]` table per user holding the declared fields.
  Fields htwicket doesn't know are **warned about but preserved verbatim**, never dropped.
- **`.htwicket.lock`** — advisory `flock`, shared by server *and* CLI.

A user may exist in either file alone: password-only (no fields) or sidecar-only (fields, no
password — can't log in until given one).

<details>
<summary>Concurrency &amp; reload</summary>

- **Reads**: in-memory; reloaded when either file's mtime changes (one `stat()` per request, on the
  read-lock fast path). CLI edits / admin saves apply within one request.
- **Writes**: take the `flock`, write a temp file in the same dir, `fsync`, atomic `rename`.
  Existing permissions are preserved; new files are `0600` (they hold password hashes). The same
  path is used by the server and the offline CLI, so they never corrupt each other.
</details>
