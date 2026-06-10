//! CLI entry: `serve` (default) + offline `user` subcommands (lockout recovery story).
//! All user ops honor the shared flock and work directly on the files.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Auth gateway + .htpasswd user manager for nginx auth_request")]
pub struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "/etc/htwicket.toml")]
    pub config: std::path::PathBuf,
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
        action: UserAction,
    },
}

#[derive(Subcommand)]
pub enum UserAction {
    /// Add user; password from stdin/tty prompt, or --random (generates + prints)
    Add { name: String, #[arg(long)] random: bool },
    /// Set password; stdin/tty prompt, or --random
    Passwd { name: String, #[arg(long)] random: bool },
    Del { name: String },
    List,
    /// Exit 0 = exists + password set, 1 = missing, 2 = sidecar fields fail schema
    Check { name: String },
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = crate::config::load(&cli.config)?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => crate::web::serve(cfg),
        Command::User { action: _ } => todo!("user CRUD against state files under flock"),
    }
}
