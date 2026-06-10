# Translating htwicket

The UI uses gettext-style catalogs. **English is the source language** — the `msgid` *is* the
English string, so there is no `en` catalog and any missing translation falls back to the English
source. The viewer's language comes from the `Accept-Language` header (primary subtag: `fi`, `de`, …).

Translations live in `po/<locale>.po`. `build.rs` compiles them straight into the binary, so a plain
`cargo build` is the whole "compile" step — no catalog files ship or load at runtime:

```
edit po/fi.po  →  cargo build  →  done (fi baked into the binary)
```

The targets below need the gettext CLI tools (`xgettext`, `msginit`, `msgmerge`, `msgfmt`).

## Add a language

```
make i18n-init LOCALE=fi   # create po/fi.po from the current strings
# fill in the msgstr "" lines in po/fi.po
cargo build                # bake it in
```

## Update after the code changes

When UI strings are added, changed, or removed, refresh the catalogs:

```
make i18n-update    # re-extract, then msgmerge into every po/*.po
```

`msgmerge` keeps existing translations, adds new untranslated entries, and flags changed ones
`#, fuzzy` for review.

## Targets

| target | what it does |
|---|---|
| `make i18n-extract` | rebuild `po/htwicket.pot` (the string template) from source |
| `make i18n-update` | merge the template into every `po/<loc>.po` |
| `make i18n-init LOCALE=xx` | start a new translation |
| `make i18n-stats` | per-locale coverage (e.g. `po/fi.po: 18 translated, 9 untranslated`) |
| `make i18n` | extract + update |

## Notes

- `po/htwicket.pot` is generated (gitignored); the `po/<loc>.po` files are the source of truth.
- Keep `msgid`s ASCII and whole sentences — no concatenation, no markup inside the string.
  Translations carry the Unicode.
- Strings are `tr("…")` in templates and `tr(lang, "…")` in Rust; both are extracted automatically.
