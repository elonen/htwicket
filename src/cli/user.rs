use std::sync::Arc;

use anyhow::{Context as _, bail};
use clap::Subcommand;

use crate::config::Config;
use crate::state::UserDb;

#[derive(Subcommand)]
pub enum UserAction {
    /// Add user; password from stdin/tty, --random (generates + prints), or --password-env VAR
    Add {
        name: String,
        #[arg(long)]
        random: bool,
        /// Read the password from this env var (non-interactive; keeps it off argv/`ps`)
        #[arg(long, value_name = "VAR", conflicts_with = "random")]
        password_env: Option<String>,
        /// No-op (exit 0) if the user already exists — idempotent bootstrap for containers
        #[arg(long)]
        if_missing: bool,
    },
    /// Set password; stdin/tty, --random, or --password-env VAR
    Passwd {
        name: String,
        #[arg(long)]
        random: bool,
        /// Read the password from this env var (non-interactive; keeps it off argv/`ps`)
        #[arg(long, value_name = "VAR", conflicts_with = "random")]
        password_env: Option<String>,
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

/// Offline user management against the state files (under the shared flock). Works even when
/// header/claim CEL is broken — the recovery path — since CEL is only compiled by `serve`.
pub fn run(cfg: Config, action: UserAction) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let mut db = UserDb::load(cfg.clone())?;
    match action {
        UserAction::Add {
            name,
            random,
            password_env,
            if_missing,
        } => {
            require_valid(&name)?;
            if db.users.get(&name).is_some_and(|u| u.hash.is_some()) {
                if if_missing {
                    println!("user `{name}` already exists — leaving unchanged");
                    return Ok(());
                }
                bail!("user `{name}` already exists (use `user passwd` to change the password)");
            }
            let hash = crate::auth::hash_password(
                &read_password(random, password_env.as_deref(), cfg.min_password_len)?,
                cfg.password_hash,
            )?;
            db.write_password(&name, &hash)?;
            println!("added user `{name}`");
        }
        UserAction::Passwd {
            name,
            random,
            password_env,
        } => {
            require_valid(&name)?;
            let hash = crate::auth::hash_password(
                &read_password(random, password_env.as_deref(), cfg.min_password_len)?,
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

fn require_valid(name: &str) -> anyhow::Result<()> {
    if !UserDb::valid_username(name) {
        bail!("invalid username `{name}` (1-64 chars, [A-Za-z0-9@._-])");
    }
    Ok(())
}

/// `--random`: generate a strong password, print it, and use it. `--password-env VAR`: read it
/// verbatim from the environment (non-interactive, off argv — for one-shot container bootstrap).
/// Otherwise prompt without echo (also reads a piped line, e.g. `echo pw | htwicket user passwd alice`).
fn read_password(
    random: bool,
    password_env: Option<&str>,
    min_len: usize,
) -> anyhow::Result<String> {
    if random {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw)?;
        let pw: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        println!("generated password: {pw}");
        return Ok(pw);
    }
    use std::io::IsTerminal;
    let pw = if let Some(var) = password_env {
        std::env::var(var).with_context(|| format!("reading password from ${var}"))?
    } else if std::io::stdin().is_terminal() {
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
