# htwicket demo

Throwaway test container: htwicket behind nginx (`auth_request`) guarding a PHP page that
dumps the forwarded `X-Remote-User-*` headers and the decoded session-JWT claims.

```sh
make demo                                            # from repo root, or:
docker build -f demo/Dockerfile -t htwicket-demo .   # context is the repo root
docker run --rm -p 8080:80 htwicket-demo
```

Open <http://localhost:8080/> → redirected to login. Users: `admin/admin`, `alice/alice`,
and `bob`, whose password is generated and printed to the console at startup.
Basic-auth path: `curl -u admin:admin http://localhost:8080/`.

Plain-http demo, **not** production: config is the verbatim `htwicket.example.toml`, with
`insecure_cookies` / `basic_auth_passthrough` / `min_password_len` overridden via `HTWICKET_*`
env in `Dockerfile.demo` (add more `-e HTWICKET_…` to experiment).

Files: `nginx-default.conf` (proxy + auth_request wiring), `app/index.php` (the backend),
`entrypoint.sh` (seed users, start htwicket + php + nginx).
