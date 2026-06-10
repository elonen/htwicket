//! htwicket — small auth gateway + user manager for nginx `auth_request`.
//! Design: docs/architecture.md. Backwards compatible with .htpasswd; writes bcrypt only.

mod authn;
mod cel;
mod cli;
mod config;
mod i18n;
mod session;
mod state;
mod web;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    cli::run()
}
