use std::sync::Arc;

use anyhow::bail;
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
        /// Read the password from this env var (non-interactive; keeps it off argv/`ps`). A
        /// non-empty value takes precedence over --random; if unset/empty, add --random to fall
        /// back to a generated password (otherwise it's an error).
        #[arg(long, value_name = "VAR")]
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
        /// Read the password from this env var (non-interactive; keeps it off argv/`ps`). A
        /// non-empty value takes precedence over --random; if unset/empty, add --random to fall
        /// back to a generated password (otherwise it's an error).
        #[arg(long, value_name = "VAR")]
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

/// Generate a strong random password, print it (so a bootstrap operator can recover it from the
/// logs), and return it. Shared by `--random` and the `--password-env` + `--random` unset/empty
/// fallback.
fn generate_random_password() -> anyhow::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)?;
    let pw: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    println!("generated password: {pw}");
    Ok(pw)
}

/// `--random`: generate a strong password, print it, and use it. `--password-env VAR`: read it
/// verbatim from the environment (non-interactive, off argv — for one-shot container bootstrap). A
/// non-empty VAR wins even over `--random`; an unset/empty VAR is an error unless `--random` is also
/// given, in which case it falls back to a generated password (so an unconfigured bootstrap still
/// works). Otherwise prompt without echo (also reads a piped line, e.g. `echo pw | htwicket user passwd alice`).
fn read_password(
    random: bool,
    password_env: Option<&str>,
    min_len: usize,
) -> anyhow::Result<String> {
    use std::io::IsTerminal;
    let pw = if let Some(var) = password_env {
        // A non-empty value wins (even over --random). Unset (Err) or empty falls back to a
        // generated password only when --random is also given; otherwise it's a hard error.
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => v,
            _ if random => return generate_random_password(),
            _ => bail!(
                "env var ${var} is unset or empty; set it, or also pass --random to generate one"
            ),
        }
    } else if random {
        return generate_random_password();
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

#[cfg(test)]
mod tests {
    use super::*;

    // `generate_random_password` yields 16 bytes as hex.
    const RANDOM_LEN: usize = 32;

    #[test]
    fn password_env_set_is_used_verbatim() {
        // Unique var name: std::env is process-global and tests run in parallel.
        let var = "HTWICKET_TEST_PW_SET";
        unsafe { std::env::set_var(var, "correcthorse") };
        assert_eq!(read_password(false, Some(var), 8).unwrap(), "correcthorse");
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn password_env_set_overrides_random() {
        // A non-empty value wins even when --random is also passed.
        let var = "HTWICKET_TEST_PW_OVERRIDE";
        unsafe { std::env::set_var(var, "correcthorse") };
        assert_eq!(read_password(true, Some(var), 8).unwrap(), "correcthorse");
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn password_env_unset_without_random_errors() {
        // A name we never set → var() is Err → hard error without --random.
        let var = "HTWICKET_TEST_PW_UNSET";
        assert!(read_password(false, Some(var), 8).is_err());
    }

    #[test]
    fn password_env_empty_without_random_errors() {
        let var = "HTWICKET_TEST_PW_EMPTY";
        unsafe { std::env::set_var(var, "") };
        assert!(read_password(false, Some(var), 8).is_err());
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn password_env_unset_with_random_falls_back() {
        // --random alongside --password-env → generated fallback when the var is unset.
        let var = "HTWICKET_TEST_PW_UNSET_RANDOM";
        let pw = read_password(true, Some(var), 8).unwrap();
        assert_eq!(pw.len(), RANDOM_LEN);
    }

    #[test]
    fn password_env_empty_with_random_falls_back() {
        // Compose passes an unconfigured password as "" → generated fallback with --random.
        let var = "HTWICKET_TEST_PW_EMPTY_RANDOM";
        unsafe { std::env::set_var(var, "") };
        let pw = read_password(true, Some(var), 8).unwrap();
        assert_eq!(pw.len(), RANDOM_LEN);
        unsafe { std::env::remove_var(var) };
    }
}
