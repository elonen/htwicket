//! View building: turn DB state into template view models, evaluate the per-request CEL programs
//! (header outputs, JWT claims, superadmin gate, per-field editability), and read submitted form
//! fields back into the schema.

use std::collections::{BTreeMap, HashMap};

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use crate::cel::{self, CelValue};
use crate::config::{Config, FieldSpec, FieldType};
use crate::state::User;

use super::helpers::render;
use super::templates::{AdminTemplate, FieldView, LoginTemplate, UserRow};
use super::{AppError, AppState, Handler};

pub(super) async fn render_admin(
    state: &AppState,
    lang: &str,
    error: Option<String>,
    notice: Option<String>,
) -> Handler {
    let db = state.db.read().await;
    let users = db
        .users
        .iter()
        .map(|(name, u)| UserRow {
            name: name.clone(),
            has_password: u.hash.is_some(),
            fields: admin_field_views(&state.cfg, &u.fields),
        })
        .collect();
    render(AdminTemplate {
        lang: lang.to_string(),
        insecure_cookies: state.cfg.insecure_cookies,
        app_title_html: state.cfg.app_title_html.clone(),
        base_path: state.cfg.base_path.clone(),
        users,
        error,
        notice,
        min_password_len: state.cfg.min_password_len,
    })
}

pub(super) fn render_login(
    state: &AppState,
    lang: &str,
    rd: String,
    error: Option<String>,
    username: String,
) -> Handler {
    render(LoginTemplate {
        lang: lang.to_string(),
        insecure_cookies: state.cfg.insecure_cookies,
        app_title_html: state.cfg.app_title_html.clone(),
        base_path: state.cfg.base_path.clone(),
        error,
        rd,
        username,
    })
}

fn make_field_view(
    name: &str,
    spec: &FieldSpec,
    value: Option<&toml::Value>,
    editable: bool,
) -> FieldView {
    FieldView {
        name: name.to_string(),
        label: name.replace('_', " "),
        is_bool: spec.type_ == FieldType::Bool,
        input_type: if spec.type_ == FieldType::Email {
            "email"
        } else {
            "text"
        },
        value: match value {
            Some(toml::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        },
        checked: value.and_then(toml::Value::as_bool).unwrap_or(false),
        editable,
    }
}

/// Admin sees and may edit every schema field.
fn admin_field_views(cfg: &Config, values: &BTreeMap<String, toml::Value>) -> Vec<FieldView> {
    cfg.fields
        .iter()
        .map(|(name, spec)| make_field_view(name, spec, values.get(name), true))
        .collect()
}

/// /account view: only fields visible to this user (user_visible, or editable-for-them).
/// Editability is the per-user `user_editable_expr` (fail closed on eval error).
pub(super) fn account_field_views(state: &AppState, user: &User, username: &str) -> Vec<FieldView> {
    let ctx = cel::context(&user.fields, username).ok();
    state
        .cfg
        .fields
        .iter()
        .filter_map(|(name, spec)| {
            let editable = ctx
                .as_ref()
                .is_some_and(|ctx| field_editable(state, name, ctx));
            (spec.user_visible || editable)
                .then(|| make_field_view(name, spec, user.fields.get(name), editable))
        })
        .collect()
}

/// May the user behind `ctx` edit `field` right now? Evaluates the field's user_editable_expr;
/// any miss or eval error is treated as not-editable (fail closed).
pub(super) fn field_editable(state: &AppState, field: &str, ctx: &cel::Context) -> bool {
    state
        .compiled
        .field_editable
        .get(field)
        .is_some_and(|expr| cel::eval_bool(expr, ctx))
}

/// Read submitted values for the schema fields passing `accept`; `key` maps a field name to its
/// form key (`f_<name>` on /account, `f_<name>[<row>]` in the admin table). Bools: present = true.
pub(super) fn collect_fields(
    cfg: &Config,
    form: &HashMap<String, String>,
    key: impl Fn(&str) -> String,
    accept: impl Fn(&str) -> bool,
) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for (name, spec) in &cfg.fields {
        if !accept(name) {
            continue;
        }
        let key = key(name);
        let value = match spec.type_ {
            FieldType::Bool => toml::Value::Boolean(form.contains_key(&key)),
            _ => toml::Value::String(form.get(&key).cloned().unwrap_or_default()),
        };
        out.insert(name.clone(), value);
    }
    out
}

/// X-Remote-User-Id (always) + each [headers.*] CEL output. A CEL/eval error bubbles to 500.
pub(super) fn auth_response_headers(
    state: &AppState,
    user: &User,
    username: &str,
) -> Result<HeaderMap, AppError> {
    let mut out = HeaderMap::new();
    out.insert(
        HeaderName::from_static("x-remote-user-id"),
        HeaderValue::from_str(username)?,
    );
    if state.compiled.headers.is_empty() {
        return Ok(out); // skip the context build on the hot path when no headers are configured
    }
    let ctx = cel::context(&user.fields, username)?;
    for (name, expr) in &state.compiled.headers {
        let value = match cel::eval(expr, &ctx)? {
            CelValue::Bool(b) => b.to_string(),
            CelValue::Str(s) => s,
        };
        out.insert(name.clone(), HeaderValue::from_str(&value)?);
    }
    Ok(out)
}

pub(super) fn eval_jwt_claims(
    state: &AppState,
    user: Option<&User>,
    username: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, AppError> {
    let mut map = serde_json::Map::new();
    let Some(user) = user else { return Ok(map) };
    let ctx = cel::context(&user.fields, username)?;
    for (name, expr) in &state.compiled.jwt_claims {
        let value = match cel::eval(expr, &ctx)? {
            CelValue::Bool(b) => serde_json::Value::Bool(b),
            CelValue::Str(s) => serde_json::Value::String(s),
        };
        map.insert(name.clone(), value);
    }
    Ok(map)
}

pub(super) fn is_superadmin(state: &AppState, user: Option<&User>, username: &str) -> bool {
    let Some(user) = user else { return false };
    cel::context(&user.fields, username)
        .map(|ctx| cel::eval_bool(&state.compiled.superadmin, &ctx))
        .unwrap_or(false)
}
