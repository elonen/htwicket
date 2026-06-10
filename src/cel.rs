//! CEL expressions (cel-interpreter) for [headers.*], [jwt-claims.*] and [superadmins].expr.
//! Compiled once at config load (bad expr = startup failure). Eval context: `username` (string)
//! and `fields.*` (defaults pre-applied, so exprs are total). Result is type-checked against the
//! declared type; a runtime eval error is 500 + log — fail closed, never silently grant.

use anyhow::{anyhow, bail};
use cel_interpreter::{Context, Program, Value};

use crate::config::FieldType;
use crate::state::User;

pub struct CompiledExpr {
    pub program: Program,
    pub type_: FieldType,
    /// Kept for error messages — the evaluator's own errors don't echo the source.
    source: String,
}

pub fn compile(expr: &str, type_: FieldType) -> anyhow::Result<CompiledExpr> {
    // cel-interpreter's ANTLR-generated parser panics on some malformed input (e.g. a trailing
    // operator) instead of returning ParseErrors. Catch it so a config typo becomes a clean
    // startup error rather than an internal-panic trace. Compile runs only at startup over
    // admin-controlled config, so the cost is irrelevant.
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Program::compile(expr)));
    let program = match parsed {
        Ok(Ok(program)) => program,
        Ok(Err(e)) => bail!("invalid CEL expression `{expr}`: {e}"),
        Err(_) => bail!("invalid CEL expression `{expr}` (parser rejected it)"),
    };
    Ok(CompiledExpr { program, type_, source: expr.to_string() })
}

/// Evaluate over {username, fields.*} and coerce the result to the declared type.
/// Errors (eval failure or type mismatch) are returned for the caller to log + fail closed.
pub fn eval(expr: &CompiledExpr, user: &User, username: &str) -> anyhow::Result<toml::Value> {
    let mut ctx = Context::default();
    ctx.add_variable("username", username).map_err(|e| anyhow!("cel context: {e}"))?;
    ctx.add_variable("fields", &user.fields).map_err(|e| anyhow!("cel context: {e}"))?;
    let value = expr
        .program
        .execute(&ctx)
        .map_err(|e| anyhow!("evaluating `{}`: {e}", expr.source))?;
    coerce(value, expr.type_, &expr.source)
}

/// Map a CEL result to a toml::Value of the declared type. `bool` serializes to the strings
/// "true"/"false" when later emitted as a header; that's the caller's concern, not ours.
fn coerce(value: Value, type_: FieldType, source: &str) -> anyhow::Result<toml::Value> {
    match (type_, value) {
        (FieldType::Bool, Value::Bool(b)) => Ok(toml::Value::Boolean(b)),
        (FieldType::String | FieldType::Email, Value::String(s)) => {
            Ok(toml::Value::String(s.to_string()))
        }
        (t, v) => bail!("`{source}` was expected to yield {t:?} but produced {v:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(fields: &[(&str, toml::Value)]) -> User {
        User {
            hash: None,
            pwd_fp: None,
            fields: fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        }
    }

    #[test]
    fn superadmin_expr_is_bool() {
        let e = compile("username == 'admin' || fields.is_admin", FieldType::Bool).unwrap();
        let u = user(&[("is_admin", toml::Value::Boolean(false))]);
        assert_eq!(eval(&e, &u, "admin").unwrap(), toml::Value::Boolean(true));
        assert_eq!(eval(&e, &u, "bob").unwrap(), toml::Value::Boolean(false));

        let admin = user(&[("is_admin", toml::Value::Boolean(true))]);
        assert_eq!(eval(&e, &admin, "bob").unwrap(), toml::Value::Boolean(true));
    }

    #[test]
    fn string_ternary_expr() {
        let e = compile(
            "fields.display_name != '' ? fields.display_name : username",
            FieldType::String,
        )
        .unwrap();
        let named = user(&[("display_name", toml::Value::String("Alice".into()))]);
        assert_eq!(eval(&e, &named, "alice").unwrap(), toml::Value::String("Alice".into()));
        let blank = user(&[("display_name", toml::Value::String(String::new()))]);
        assert_eq!(eval(&e, &blank, "bob").unwrap(), toml::Value::String("bob".into()));
    }

    #[test]
    fn type_mismatch_is_error() {
        // Declared Bool but the expression yields a string → fail closed.
        let e = compile("username", FieldType::Bool).unwrap();
        assert!(eval(&e, &user(&[]), "alice").is_err());
    }

    #[test]
    fn invalid_syntax_fails_to_compile() {
        assert!(compile("fields. ||", FieldType::Bool).is_err());
    }

    #[test]
    fn missing_field_reference_errors_at_eval() {
        // `fields` has defaults pre-applied in production, so a missing key only happens on
        // misconfiguration; it must error (fail closed), not silently grant.
        let e = compile("fields.nonexistent", FieldType::Bool).unwrap();
        assert!(eval(&e, &user(&[]), "alice").is_err());
    }
}
