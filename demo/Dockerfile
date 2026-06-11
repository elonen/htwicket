# syntax=docker/dockerfile:1
# demo/Dockerfile — self-contained playground for htwicket.
#
# Build context is the REPO ROOT (it compiles the crate), so build from there:
#
#   docker build -f demo/Dockerfile -t htwicket-demo .   # or: make demo
#   docker run --rm -p 8080:80 htwicket-demo
#   open http://localhost:8080/        # redirected to login; sign in as admin / admin
#
# Plain-http demo only (insecure_cookies, basic_auth_passthrough). NOT a production layout.

FROM rust:1-slim-trixie AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock build.rs ./
COPY po ./po
COPY templates ./templates
COPY src ./src

RUN --mount=type=cache,id=htwicket-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=htwicket-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=htwicket-demo-target,target=/app/target \
    cargo build --release && cp target/release/htwicket /usr/bin/htwicket


# ---- runtime: nginx + php + htwicket on trixie-slim ----
FROM debian:trixie-slim

RUN apt-get -qy update \
 && apt-get -qy install --no-install-recommends nginx-light php-cli curl \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

COPY --from=builder /usr/bin/htwicket /usr/bin/htwicket
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
    HTWICKET_DEBUG=true \
    HTWICKET_APP_TITLE_HTML="<h1>Example App</h1>"

EXPOSE 80
CMD ["/usr/local/bin/demo-entrypoint.sh"]
