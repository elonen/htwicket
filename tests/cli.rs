//! The `user check` CLI subcommand and its exit codes.

mod common;

use common::{check_exit, spawn};

#[test]
fn user_check_exit_codes() {
    // schema-broken sidecar for bob: is_admin is a string, not a bool.
    let srv = spawn("[users.bob]\nis_admin = \"nope\"\n");
    assert_eq!(check_exit(&srv.config, "admin"), 0); // password set, schema ok
    assert_eq!(check_exit(&srv.config, "ghost"), 1); // missing
    assert_eq!(check_exit(&srv.config, "bob"), 2); // schema failure
}
