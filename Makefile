SHELL := /bin/bash
.PHONY: build test check test-and-check clean demo \
        i18n i18n-extract i18n-update i18n-init i18n-stats \
        debian-local debian-docker debian-docker-one

# ---- Cargo (host) ----

build:
	cargo build --release

test:
	cargo test

check:
	cargo clippy -- -D warnings
	cargo fmt --check

test-and-check: test check

clean:
	cargo clean
	rm -rf dist_deb

# ---- Demo container ------------------------------------------------------
#
# Build + run the throwaway demo: htwicket behind nginx guarding a PHP page that
# echoes the forwarded headers + decoded JWT. Browse http://localhost:8080/
# (admin/admin, alice/alice, bob/<printed>). Ctrl-C to stop. See demo/README.md.

demo:
	DOCKER_BUILDKIT=1 docker build -f demo/Dockerfile -t htwicket-demo .
	docker run --rm -p 8080:80 htwicket-demo

# ---- Internationalization (gettext) --------------------------------------
#
# English is the source language (= the msgid); there is no en.po and a missing
# translation falls back to the English source. Translatable strings are `tr("...")`
# in templates and `tr(lang, "...")` in Rust. build.rs compiles po/*.po straight into
# the binary, so a plain `cargo build` is the whole "compile" step — there is none here.
#
#   make i18n-extract         # rebuild po/htwicket.pot from the sources
#   make i18n-update          # merge the .pot into every existing po/<loc>.po
#   make i18n-init LOCALE=fi  # start a new translation: po/fi.po
#   make i18n-stats           # translation coverage per locale
#   make i18n                 # extract + update
#
# Needs the gettext CLI tools (xgettext/msgmerge/msginit/msgfmt).

POT := po/htwicket.pot
# Single xgettext pass over Rust + templates. C mode finds `tr(...)` in both; tr:1 picks the
# template msgid (1st arg) and tr:2 the Rust msgid (2nd arg, after the locale) — non-string
# args are ignored.
I18N_SOURCES := $(shell find src -name '*.rs') $(wildcard templates/*.html)

i18n: i18n-extract i18n-update

i18n-extract: $(POT)

$(POT): $(I18N_SOURCES)
	@# C mode misreads apostrophes/quotes in Rust+HTML comments as "unterminated string/character"
	@# warnings — harmless (extraction is correct). Drop just those lines, keep every other
	@# warning, and preserve xgettext's exit code.
	@xgettext --language=C --from-code=UTF-8 --sort-by-file \
		--keyword=tr:1 --keyword=tr:2 \
		--package-name=htwicket --copyright-holder="htwicket authors" \
		-o $@ $(I18N_SOURCES) 2>$@.err; rc=$$?; \
		grep -vE 'warning: unterminated (string literal|character constant)' $@.err >&2 || true; \
		rm -f $@.err; exit $$rc
	@# msgids are ASCII, so xgettext leaves charset=CHARSET; pin it to UTF-8 so msginit-derived
	@# .po files (and accented msgstr) are UTF-8. Temp+mv keeps it portable (BSD/GNU sed differ).
	@sed 's/charset=CHARSET/charset=UTF-8/' $@ > $@.tmp && mv $@.tmp $@
	@echo "$@: $$(($$(grep -c '^msgid ' $@) - 1)) strings"

i18n-update: $(POT)
	@shopt -s nullglob; pos=(po/*.po); \
	if [ $${#pos[@]} -eq 0 ]; then \
		echo "no po/*.po yet — start one with: make i18n-init LOCALE=<xx>"; \
	else \
		for po in "$${pos[@]}"; do echo "msgmerge $$po"; \
			msgmerge --update --backup=none --quiet "$$po" $(POT); done; \
	fi

i18n-init: $(POT)
	@test -n "$(LOCALE)" || { echo "usage: make i18n-init LOCALE=fi"; exit 1; }
	@test ! -e po/$(LOCALE).po || { echo "po/$(LOCALE).po already exists"; exit 1; }
	msginit --no-translator --locale=$(LOCALE) --input=$(POT) --output-file=po/$(LOCALE).po
	@echo "created po/$(LOCALE).po — translate the msgstr lines, then \`cargo build\` bakes it in"

i18n-stats:
	@shopt -s nullglob; pos=(po/*.po); \
	if [ $${#pos[@]} -eq 0 ]; then echo "(no translations yet)"; \
	else for po in "$${pos[@]}"; do printf "%s: " "$$po"; \
		msgfmt --statistics "$$po" -o /dev/null; done; fi

# ---- Debian packaging ----------------------------------------------------
#
# `debian-local`  builds a .deb for the host (or container) architecture.
# `debian-docker` cross-builds .debs for every Debian release × architecture
#                 inside rust:slim containers (amd64/arm64 via QEMU emulation).
#
# Adapted from the clapshot multi-arch scheme, collapsed to a single crate.

UID := $(shell id -u)
GID := $(shell id -g)

# Native arch unless cross-building (TARGET_ARCH=amd64|arm64 → emulated platform).
ifeq ($(TARGET_ARCH),)
  ARCH = $(shell uname -m)
  PLATFORM_STR =
else
  ARCH = $(TARGET_ARCH)
  PLATFORM_STR = --platform linux/$(TARGET_ARCH)
endif

DEBIAN_VER ?= trixie
DOCKER_IMG_NAME = htwicket_$(DEBIAN_VER)_$(ARCH)

# What a .deb is built from — rebuild the stamp when any of these change.
RUST_DEPS = $(shell find src templates po Cargo.toml Cargo.lock build.rs -type f 2>/dev/null)
DEB_DEPS  = $(shell find debian -type f 2>/dev/null) \
            README.md LICENSE-MIT LICENSE-APACHE htwicket.example.toml

# Persistent Docker named volumes so repeated/emulated builds don't re-download
# and recompile every crate. registry/git are platform-independent and shared;
# the target dir is keyed per release+arch so objects from different targets
# never mix. (rust:slim makes /usr/local/cargo world-writable.)
CARGO_CACHE_MOUNTS = \
	--mount type=volume,source=htwicket-cargo-registry,target=/usr/local/cargo/registry \
	--mount type=volume,source=htwicket-cargo-git,target=/usr/local/cargo/git \
	--mount type=volume,source=htwicket-target-$(DEBIAN_VER)-$(ARCH),target=/app/target

debian-local: dist_deb/built.$(ARCH).stamp

dist_deb/built.$(ARCH).stamp: $(RUST_DEPS) $(DEB_DEPS)
	@command -v cargo-deb >/dev/null 2>&1 || cargo install cargo-deb
	cargo deb
	mkdir -p dist_deb
	find target/debian/ -maxdepth 1 -type f -name '*.deb' -exec cp {} dist_deb/ \;
	touch $@

# Cross-build every release × arch into dist_deb. trixie is the baseline;
# bookworm (oldstable) is kept for back-compat. Releases whose base image isn't
# pullable are skipped (e.g. a next-stable codename before it ships); a failure
# prints which target was building.
debian-docker:
	@echo "Building htwicket .deb packages for multiple Debian releases × architectures..."
	rm -rf dist_deb && mkdir -p dist_deb
	set -e; \
	trap 'echo "" >&2; echo "######## debian-docker FAILED while building: $$CURRENT ########" >&2' ERR; \
	for debver in trixie bookworm; do \
		echo ""; \
		echo "=== Checking base image availability for Debian $$debver ==="; \
		if docker build --platform linux/amd64 -q - <<< "FROM rust:1-slim-$$debver" >/dev/null 2>&1; then \
			for plat in arm64 amd64; do \
				echo "--- Building htwicket for $$debver/$$plat ---"; \
				CURRENT="$$debver/$$plat"; \
				DEBIAN_VER=$$debver TARGET_ARCH=$$plat $(MAKE) --no-print-directory debian-docker-one; \
			done; \
		else \
			echo "=== Skipping $$debver (base image not available) ==="; \
		fi; \
	done
	rm -f dist_deb/*dbgsym* 2>/dev/null || true
	@echo ""
	@echo "=== Built packages ==="
	ls -l dist_deb/

# One release/arch: build the image, run cargo-deb inside it (as root, into the
# cached target volume), copy the .deb out and chown it back to the host user.
debian-docker-one:
	mkdir -p dist_deb
	DOCKER_BUILDKIT=1 docker build $(PLATFORM_STR) -t $(DOCKER_IMG_NAME):latest \
		--build-arg DEBIAN_VER=$(DEBIAN_VER) -f Dockerfile.deb .
	docker run --rm $(PLATFORM_STR) \
		--mount type=bind,source="$$(pwd)/dist_deb",target=/deb \
		$(CARGO_CACHE_MOUNTS) --user root $(DOCKER_IMG_NAME):latest \
		bash -c "cd /app && make debian-local && cp dist_deb/*.deb /deb/ && chown -R $(UID):$(GID) /deb"
	@# Tag freshly-built .debs with the Debian codename, inserting it just before
	@# the arch suffix. Already-tagged debs (another release) keep their codename.
	@for f in dist_deb/*.deb; do \
		newname=$$(echo "$$f" | sed -E 's/(_[0-9][0-9.]*-?[0-9]*)_(amd64|arm64|all)\.deb$$/\1_$(DEBIAN_VER)_\2.deb/'); \
		if [ "$$f" != "$$newname" ]; then mv "$$f" "$$newname"; fi; \
	done
