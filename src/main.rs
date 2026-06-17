//! htwicket — small auth gateway + user manager for nginx `auth_request`.
//! Design: docs/architecture.md. Backwards compatible with .htpasswd; writes bcrypt (default) or
//! argon2id (`password_hash`).

mod auth;
mod cel;
mod cli;
mod config;
mod i18n;
mod state;
mod token;
mod web;

use clap::Parser;
use cli::{Cli, Command};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = config::load(&cli.config, &cli.overrides)?;
    init_tracing(cfg.debug);
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => web::serve(cfg),
        Command::User { action } => cli::user::run(cfg, action),
        Command::Healthz => cli::healthz::run(&cfg),
    }
}

/// stdout subscriber; INFO by default, DEBUG when `debug = true` (config/env/`--debug`) for
/// per-request and file-I/O traces.
fn init_tracing(debug: bool) {
    let level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_flags_distinguish_unset_true_false() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let cli = Cli::parse_from(["htwicket", "--insecure-cookies", "serve"]);
        assert_eq!(cli.overrides.insecure_cookies, Some(true));
        let cli = Cli::parse_from(["htwicket", "--insecure-cookies=false"]);
        assert_eq!(cli.overrides.insecure_cookies, Some(false));
        let cli = Cli::parse_from(["htwicket"]);
        assert_eq!(cli.overrides.insecure_cookies, None);
    }
}
