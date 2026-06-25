# HTWicket demo

Throwaway Compose playground: HTWicket — as the production scratch/distroless image
(`Dockerfile.runtime`, including its `healthz` HEALTHCHECK, which gates nginx startup) —
behind stock nginx (`auth_request`) guarding a PHP page that dumps the forwarded
`X-Remote-User-*` headers and the decoded session-JWT claims.

```sh
make demo    # from repo root: build, seed users, docker compose up
```

Open <http://localhost:8080/> → redirected to login. Users: `admin/admin`, `alice/alice`,
and `bob`, whose password is generated and printed at seed time.
Basic-auth path: `curl -u admin:admin http://localhost:8080/`.

Plain-http demo, **not** production: config is the verbatim `htwicket.example.toml`
mounted read-only, with `insecure_cookies` / `basic_auth_passthrough` / listen + state
paths overridden via `HTWICKET_*` env in `compose.yml` (add more there to experiment).

Services (`compose.yml`): `htwicket` (the runtime image + a `data` volume for
.htpasswd/state), `nginx` (stock image, `nginx-default.conf` mounted), and `app` (stock
php, `app/index.php`). User seeding happens in the Makefile by piping passwords into
`htwicket user add` via `docker compose run` — the distroless image has no shell.

Reset a password in the running demo (exec the binary directly — no shell in the image):
`docker compose -f demo/compose.yml exec htwicket /usr/bin/htwicket user passwd bob --random`.
Other `user` subcommands work the same way (see [docs/deployment.md](../docs/deployment.md)).

Reset seeded users/state: `docker compose -f demo/compose.yml down -v`.
