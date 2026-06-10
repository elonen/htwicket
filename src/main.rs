//! htwicket — small auth gateway + user manager for nginx `auth_request`.
//! Design: docs/architecture.md. Backwards compatible with .htpasswd; writes bcrypt (default) or
//! argon2id (`password_hash`).

mod authn;
mod cel;
mod cli;
mod config;
mod i18n;
mod session;
mod state;
mod web;

fn main() -> anyhow::Result<()> {
    // tracing is initialized inside cli::run, once the `debug` config knob is known.
    cli::run()
}
