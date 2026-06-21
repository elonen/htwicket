//! The `user` CLI subcommands: `check` exit codes, and `add`'s container-bootstrap flags.

mod common;

use std::process::{Command, Stdio};

use common::{check_exit, spawn};

#[test]
fn user_check_exit_codes() {
    // schema-broken sidecar for bob: is_admin is a string, not a bool.
    let srv = spawn("[users.bob]\nis_admin = \"nope\"\n");
    assert_eq!(check_exit(&srv.config, "admin"), 0); // password set, schema ok
    assert_eq!(check_exit(&srv.config, "ghost"), 1); // missing
    assert_eq!(check_exit(&srv.config, "bob"), 2); // schema failure
}

#[test]
fn user_add_if_missing_and_password_env() {
    let srv = spawn(""); // seeds admin + bob

    // Run `user add ...` with PW set in the environment; returns the exit code.
    let add = |args: &[&str], pw: &str| -> i32 {
        Command::new(env!("CARGO_BIN_EXE_htwicket"))
            .arg("-c")
            .arg(&srv.config)
            .arg("user")
            .args(args)
            .env("PW", pw)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code()
            .unwrap()
    };

    // --if-missing on an existing user is a no-op (exit 0), password untouched.
    assert_eq!(
        add(
            &["add", "admin", "--if-missing", "--password-env", "PW"],
            "ignored"
        ),
        0
    );
    assert_eq!(check_exit(&srv.config, "admin"), 0);

    // --password-env creates a new user non-interactively, then is idempotent under --if-missing.
    assert_eq!(check_exit(&srv.config, "carol"), 1); // not there yet
    assert_eq!(
        add(&["add", "carol", "--password-env", "PW"], "carolpass"),
        0
    );
    assert_eq!(check_exit(&srv.config, "carol"), 0);
    assert_eq!(
        add(
            &["add", "carol", "--if-missing", "--password-env", "PW"],
            "carolpass"
        ),
        0
    );

    // A too-short env password is rejected (default min length 8) and no user is created.
    assert_ne!(add(&["add", "dave", "--password-env", "PW"], "short"), 0);
    assert_eq!(check_exit(&srv.config, "dave"), 1);

    // --password-env with an empty/unconfigured var is a hard error on its own...
    assert_ne!(add(&["add", "erin", "--password-env", "PW"], ""), 0);
    assert_eq!(check_exit(&srv.config, "erin"), 1);
    // ...but adding --random falls back to a generated password (clap allows both flags together).
    assert_eq!(
        add(&["add", "erin", "--password-env", "PW", "--random"], ""),
        0
    );
    assert_eq!(check_exit(&srv.config, "erin"), 0);
}
