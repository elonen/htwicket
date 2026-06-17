pub mod healthz;
pub mod user;

use crate::config;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Modernized .htaccess with user management web UI & CLI"
)]
pub struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "/etc/htwicket.toml")]
    pub config: std::path::PathBuf,
    /// Per-key overrides on top of file + env (docs/configuration.md#layering)
    #[command(flatten)]
    pub overrides: config::Overrides,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the HTTP server (default)
    Serve,
    /// Manage users in .htpasswd + .htwicket.toml
    User {
        #[command(subcommand)]
        action: user::UserAction,
    },
    /// Probe a running server's health endpoint; exit 0 if healthy, 1 otherwise (container HEALTHCHECK)
    Healthz,
}
