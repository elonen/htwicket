# demo/Dockerfile — self-contained playground for htwicket.
#
# Build context is the REPO ROOT (it compiles the crate), so build from there:
#
#   docker build -f demo/Dockerfile -t htwicket-demo .   # or: make demo
#   docker run --rm -p 8080:80 htwicket-demo
#   open http://localhost:8080/        # redirected to login; sign in as admin / admin
#
# Runs the daemon behind nginx (auth_request) protecting a tiny PHP page that dumps the
# headers nginx forwarded *and* the decoded session-JWT claims — so you can watch the
# [headers.*] and JWT channels light up as you log in. Supporting files live in demo/;
# the config is the shipped htwicket.example.toml verbatim (demo-only knobs are env vars
# below, so there is no second TOML to drift).
#
# Plain-http demo only (insecure_cookies, basic_auth_passthrough). NOT a production layout.

# ---- build the binary (pure Rust, no native deps; same toolchain as Dockerfile.deb) ----
FROM rust:1-slim-trixie AS builder
WORKDIR /app
COPY . /app
RUN cargo build --release

# ---- runtime: nginx + php + htwicket on trixie-slim ----
FROM debian:trixie-slim

RUN apt-get -qy update \
 && apt-get -qy install --no-install-recommends nginx-light php-cli curl \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

COPY --from=builder /app/target/release/htwicket /usr/bin/htwicket
COPY htwicket.example.toml      /etc/htwicket.toml
COPY demo/nginx-default.conf    /etc/nginx/conf.d/default.conf
COPY demo/app/                  /var/www/app/
COPY demo/entrypoint.sh         /usr/local/bin/demo-entrypoint.sh
RUN chmod +x /usr/local/bin/demo-entrypoint.sh

# Demo-only overrides on top of the verbatim example config (env beats file in the
# config layering). insecure_cookies is required over plain http; the rest are demo
# conveniences — debug on for visible per-request traces. Override or add HTWICKET_*
# at `docker run -e ...` to experiment.
ENV HTWICKET_INSECURE_COOKIES=true \
    HTWICKET_BASIC_AUTH_PASSTHROUGH=true \
    HTWICKET_MIN_PASSWORD_LEN=4 \
    HTWICKET_DEBUG=true

EXPOSE 80
CMD ["/usr/local/bin/demo-entrypoint.sh"]
