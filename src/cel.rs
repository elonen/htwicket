//! CEL expressions (cel-interpreter) for [headers.*], [jwt-claims.*] and [superadmins].expr.
//! Compiled once at config load (bad expr = startup failure). Eval context: `username` (string)
//! and `fields.*` (defaults pre-applied, so exprs are total). Result is type-checked against the
//! declared type; a runtime eval error is 500 + log — fail closed, never silently grant.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail};
pub use cel_interpreter::Context;
use cel_interpreter::{Program, Value};

use crate::config::FieldType;

pub struct CompiledExpr {
    pub program: Program,
    pub type_: FieldType,
    /// Kept for error messages — the evaluator's own errors don't echo the source.
    source: String,
}

/// An eval result, already coerced to the declared type. `bool` serializes to the strings
/// "true"/"false" when later emitted as a header; that's the caller's concern, not ours.
#[derive(PartialEq, Debug)]
pub enum CelValue {
    Bool(bool),
    Str(String),
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
    Ok(CompiledExpr {
        program,
        type_,
        source: expr.to_string(),
    })
}

/// Eval context over {username, fields.*}. Build once and reuse across exprs —
/// `Context::default()` re-registers the whole CEL stdlib each call, so a fresh context
/// per expression is measurable on the /auth hot path.
pub fn context(
    fields: &BTreeMap<String, toml::Value>,
    username: &str,
) -> anyhow::Result<Context<'static>> {
    let mut ctx = Context::default();
    ctx.add_variable("username", username)
        .map_err(|e| anyhow!("cel context: {e}"))?;
    ctx.add_variable("fields", fields)
        .map_err(|e| anyhow!("cel context: {e}"))?;
    Ok(ctx)
}

/// Evaluate and coerce the result to the declared type. Errors (eval failure or type mismatch)
/// are returned for the caller to log + fail closed.
pub fn eval(expr: &CompiledExpr, ctx: &Context) -> anyhow::Result<CelValue> {
    let value = expr
        .program
        .execute(ctx)
        .map_err(|e| anyhow!("evaluating `{}`: {e}", expr.source))?;
    match (expr.type_, value) {
        (FieldType::Bool, Value::Bool(b)) => Ok(CelValue::Bool(b)),
        (FieldType::String | FieldType::Email, Value::String(s)) => {
            Ok(CelValue::Str(s.to_string()))
        }
        (t, v) => bail!(
            "`{}` was expected to yield {t:?} but produced {v:?}",
            expr.source
        ),
    }
}

/// Bool eval that fails closed: any eval error, or a non-true result, is `false`.
pub fn eval_bool(expr: &CompiledExpr, ctx: &Context) -> bool {
    matches!(eval(expr, ctx), Ok(CelValue::Bool(true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, toml::Value)]) -> BTreeMap<String, toml::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn run(
        e: &CompiledExpr,
        f: &BTreeMap<String, toml::Value>,
        name: &str,
    ) -> anyhow::Result<CelValue> {
        eval(e, &context(f, name)?)
    }

    #[test]
    fn superadmin_expr_is_bool() {
        let e = compile("username == 'admin' || fields.is_admin", FieldType::Bool).unwrap();
        let f = fields(&[("is_admin", toml::Value::Boolean(false))]);
        assert_eq!(run(&e, &f, "admin").unwrap(), CelValue::Bool(true));
        assert_eq!(run(&e, &f, "bob").unwrap(), CelValue::Bool(false));

        let admin = fields(&[("is_admin", toml::Value::Boolean(true))]);
        assert_eq!(run(&e, &admin, "bob").unwrap(), CelValue::Bool(true));
    }

    #[test]
    fn string_ternary_expr() {
        let e = compile(
            "fields.display_name != '' ? fields.display_name : username",
            FieldType::String,
        )
        .unwrap();
        let named = fields(&[("display_name", toml::Value::String("Alice".into()))]);
        assert_eq!(
            run(&e, &named, "alice").unwrap(),
            CelValue::Str("Alice".into())
        );
        let blank = fields(&[("display_name", toml::Value::String(String::new()))]);
        assert_eq!(run(&e, &blank, "bob").unwrap(), CelValue::Str("bob".into()));
    }

    #[test]
    fn type_mismatch_is_error() {
        // Declared Bool but the expression yields a string → fail closed.
        let e = compile("username", FieldType::Bool).unwrap();
        assert!(run(&e, &fields(&[]), "alice").is_err());
        assert!(!eval_bool(&e, &context(&fields(&[]), "alice").unwrap()));
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
        assert!(run(&e, &fields(&[]), "alice").is_err());
    }
}
