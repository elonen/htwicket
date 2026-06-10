# Deployment

## nginx wiring

Htwicket sits behind nginx, which terminates TLS and is htwicket's only direct peer. Serve htwicket
under the same `base_path` it's configured with, so `proxy_pass` needs no URL rewriting. The auth
flow itself is explained in [auth-flow.md](auth-flow.md).

```nginx
# htwicket's own pages (login, account, admin, …)
location /htwicket/ {
    proxy_pass http://127.0.0.1:52155;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

# the internal auth_request target
location = /htwicket/auth {
    internal;
    proxy_pass http://127.0.0.1:52155/htwicket/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # Authorization + Cookie are inherited by the subrequest automatically.
}

# your protected app
location / {
    auth_request /htwicket/auth;
    auth_request_set $uid $upstream_http_x_remote_user_id;
    auth_request_set $adm $upstream_http_x_remote_user_is_admin;
    auth_request_set $sc  $upstream_http_set_cookie;   # propagate the sliding re-mint
    proxy_set_header X-Remote-User-Id $uid;
    proxy_set_header X-Remote-User-Is-Admin $adm;
    add_header Set-Cookie $sc;                          # nginx omits it when $sc is empty
    error_page 401 = @login;
    proxy_pass http://backend;
}
location @login { return 302 /htwicket/login?rd=$request_uri; }
```

- One `auth_request_set` + `proxy_set_header` pair **per `[headers.*]`** you want forwarded;
  `X-Remote-User-Id` is always present.
- The `$sc` / `add_header Set-Cookie` line is what makes sliding sessions reach the browser. Drop it
  and active sessions still expire at `session_idle_hours`.
- `X-Forwarded-For` must be set: htwicket reads its **last** entry as the client IP for rate-limiting
  (the direct peer is always nginx). See [security.md](security.md).

> **Caveat — Basic clients.** The `401 → 302 /login` redirect breaks challenge-response Basic auth
> (the browser never gets its `WWW-Authenticate`). Preemptive clients (`curl -u`, most libraries,
> `basic_auth_passthrough = true`) are fine. For API-only locations, override `error_page` to return
> a plain `401` instead of redirecting.

## Install (.deb / systemd)

`make debian-docker` cross-builds `.deb`s (trixie + bookworm, amd64 + arm64); CI attaches them to
`v*` releases. The package installs:

- `/usr/bin/htwicket`
- `/etc/htwicket.toml` — a conffile, seeded from the example. **Edit before starting.**
- a systemd unit running as `www-data`, with `StateDirectory=htwicket` → `/var/lib/htwicket` (`0700`,
  holds the auto-generated `jwt_secret`).

The unit is installed **disabled and not started** — htwicket needs a configured file and at least
one user first:

```sh
sudo $EDITOR /etc/htwicket.toml
sudo htwicket user add admin
sudo systemctl enable --now htwicket
```

`GET /healthz` returns an unauthenticated `200` for load-balancer probes.

## Managing users (CLI)

All `user` subcommands work **offline** against the files, under the same `flock` as the server — so
they're safe to run on a live deployment and are the lockout-recovery path (they don't need the CEL
exprs to compile, so a broken `[headers.*]` can't lock you out of fixing it).

| command | does |
|---|---|
| `htwicket user add <name>` | add user; password from tty/stdin, or `--random` (prints it) |
| `htwicket user passwd <name>` | set password; tty/stdin, or `--random` |
| `htwicket user del <name>` | remove from both files |
| `htwicket user list` | list usernames |
| `htwicket user check <name>` | exit `0` ok+password set, `1` missing, `2` sidecar fields fail schema |

```sh
echo "$PW" | htwicket user passwd alice          # piped (no tty)
htwicket user check admin || htwicket user passwd admin --random   # docker entrypoint idiom
```

Day-to-day user/field management also happens in the web `/admin` UI (superadmins only); the CLI is
for bootstrapping, automation, and recovery.

## `insecure_cookies`

Setting `insecure_cookies = true` drops the cookie `Secure` flag and shows a persistent warning
banner on every page. You almost never need it: behind a TLS-terminating nginx, the browser judges
`Secure` by *its* scheme (https), not htwicket's plain-http listener — so leave it `false`. It's
legitimate only for localhost or an encrypted overlay (VPN/Tailscale) served over plain http. See
[security.md](security.md).
