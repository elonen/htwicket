//! CLI entry: `serve` (default) + offline `user` subcommands (lockout recovery story).
//! All user ops honor the shared flock and work directly on the files.

use std::sync::Arc;

use anyhow::bail;
use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::state::UserDb;

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
    pub overrides: crate::config::Overrides,
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
    Add {
        name: String,
        #[arg(long)]
        random: bool,
    },
    /// Set password; stdin/tty prompt, or --random
    Passwd {
        name: String,
        #[arg(long)]
        random: bool,
    },
    Del {
        name: String,
    },
    List,
    /// Exit 0 = exists + password set, 1 = missing, 2 = sidecar fields fail schema
    Check {
        name: String,
    },
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = crate::config::load(&cli.config, &cli.overrides)?;
    init_tracing(cfg.debug);
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => crate::web::serve(cfg),
        Command::User { action } => run_user(cfg, action),
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

/// Offline user management against the state files (under the shared flock). Works even when
/// header/claim CEL is broken — the recovery path — since CEL is only compiled by `serve`.
fn run_user(cfg: Config, action: UserAction) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let mut db = UserDb::load(cfg.clone())?;
    match action {
        UserAction::Add { name, random } => {
            require_valid(&name)?;
            if db.users.get(&name).is_some_and(|u| u.hash.is_some()) {
                bail!("user `{name}` already exists (use `user passwd` to change the password)");
            }
            let hash = crate::authn::hash_password(
                &read_password(random, cfg.min_password_len)?,
                cfg.password_hash,
            )?;
            db.write_password(&name, &hash)?;
            println!("added user `{name}`");
        }
        UserAction::Passwd { name, random } => {
            require_valid(&name)?;
            let hash = crate::authn::hash_password(
                &read_password(random, cfg.min_password_len)?,
                cfg.password_hash,
            )?;
            db.write_password(&name, &hash)?;
            println!("set password for `{name}`");
        }
        UserAction::Del { name } => {
            if !db.users.contains_key(&name) {
                bail!("no such user `{name}`");
            }
            db.delete_user(&name)?;
            println!("deleted user `{name}`");
        }
        UserAction::List => {
            for name in db.users.keys() {
                println!("{name}");
            }
        }
        UserAction::Check { name } => {
            // 0 = exists + password set + schema ok; 1 = missing/no password; 2 = schema fails.
            let code = match db.users.get(&name) {
                Some(u) if u.hash.is_some() => {
                    let errors = db.schema_errors(&name);
                    if errors.is_empty() {
                        0
                    } else {
                        for e in errors {
                            eprintln!("{name}: {e}");
                        }
                        2
                    }
                }
                _ => 1,
            };
            std::process::exit(code);
        }
    }
    Ok(())
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

fn require_valid(name: &str) -> anyhow::Result<()> {
    if !UserDb::valid_username(name) {
        bail!("invalid username `{name}` (1-64 chars, [A-Za-z0-9@._-])");
    }
    Ok(())
}

/// `--random`: generate a strong password, print it, and use it. Otherwise prompt without echo
/// (also reads a piped line, e.g. `echo pw | htwicket user passwd alice`).
fn read_password(random: bool, min_len: usize) -> anyhow::Result<String> {
    if random {
        let pw: String = crate::session::random_bytes(16)?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("generated password: {pw}");
        return Ok(pw);
    }
    use std::io::IsTerminal;
    let pw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("new password: ")? // hidden echo
    } else {
        // Piped, e.g. `echo pw | htwicket user passwd alice` (docker entrypoint).
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    if pw.len() < min_len {
        bail!("password too short (minimum {min_len} characters)");
    }
    Ok(pw)
}
