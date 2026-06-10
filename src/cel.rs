//! CEL expressions (cel-interpreter) for [headers.*], [jwt-claims.*] and [superadmins].expr.
//! Compiled once at config load (bad expr = startup failure). Eval context: `username` (string)
//! and `fields.*` (defaults pre-applied, so exprs are total). Result is type-checked against the
//! declared type; a runtime eval error is 500 + log — fail closed, never silently grant.

use crate::config::FieldType;

pub struct CompiledExpr {
    pub program: cel_interpreter::Program,
    pub type_: FieldType,
}

pub fn compile(_expr: &str, _type_: FieldType) -> anyhow::Result<CompiledExpr> {
    todo!()
}

pub fn eval(_expr: &CompiledExpr, _user: &crate::state::User, _username: &str) -> anyhow::Result<toml::Value> {
    todo!("build context, eval, check result type; bool serializes to \"true\"/\"false\" in headers")
}
