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

## Counts and translator notes

- A count is one string with a `{count}` placeholder, looked up via `tr_count("{count} users", n)`;
  the number is substituted after translation. There is a **single** plural form (no separate n=1
  string), so translate it to read naturally for any count — e.g. Finnish uses the partitive
  `"{count} käyttäjää"`, never the nominative plural `"{count} käyttäjät"`.
- Leave guidance for translators as a `#.` **TRANSLATORS:** comment directly above the entry in the
  `.po` (see `"{count} users"` in `po/fi.po`). These comments are preserved and ignored at compile.
  `xgettext` only auto-extracts `TRANSLATORS:` comments from Rust source (C-style `//`), **not** from
  Askama `{# … #}` template comments — so for a template string, add the note in the `.po` by hand.
