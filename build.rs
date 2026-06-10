//! Compile `po/<locale>.po` gettext catalogs into a static Rust table baked into the binary
//! (no runtime catalog files). msgid = English source string; the runtime looks entries up and
//! falls back to the source on a miss (see src/i18n.rs). With no .po files the table is empty
//! and everything renders in English — the machinery is present, the catalog optional.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=po");

    let mut code = String::from("pub static CATALOGS: &[(&str, &[(&str, &str)])] = &[\n");
    if let Ok(entries) = fs::read_dir("po") {
        let mut po_files: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "po"))
            .collect();
        po_files.sort();
        for path in po_files {
            println!("cargo:rerun-if-changed={}", path.display());
            let locale = path.file_stem().unwrap().to_string_lossy().to_string();
            let content = fs::read_to_string(&path).unwrap();
            code.push_str(&format!("    ({locale:?}, &[\n"));
            for (msgid, msgstr) in parse_po(&content) {
                if !msgid.is_empty() && !msgstr.is_empty() {
                    code.push_str(&format!("        ({msgid:?}, {msgstr:?}),\n"));
                }
            }
            code.push_str("    ]),\n");
        }
    }
    code.push_str("];\n");

    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("i18n_catalog.rs");
    fs::write(&out, code).unwrap();
}

/// Minimal .po reader: msgid/msgstr pairs, adjacent "string" continuation lines, `#` comments.
/// Each entry begins with `msgid`; the header (empty msgid) is dropped downstream.
fn parse_po(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut id = String::new();
    let mut msg = String::new();
    let mut in_msgstr = false;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("msgid ") {
            if !id.is_empty() {
                out.push((std::mem::take(&mut id), std::mem::take(&mut msg)));
            } else {
                msg.clear();
            }
            id = unquote(rest);
            in_msgstr = false;
        } else if let Some(rest) = line.strip_prefix("msgstr ") {
            msg = unquote(rest);
            in_msgstr = true;
        } else if line.starts_with('"') {
            if in_msgstr {
                msg.push_str(&unquote(line));
            } else {
                id.push_str(&unquote(line));
            }
        }
    }
    if !id.is_empty() {
        out.push((id, msg));
    }
    out
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    let inner = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(s);
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}
