#!/bin/sh
# Seed demo users, then run htwicket + the PHP app + nginx together (plain http).
# Config is /etc/htwicket.toml (the shipped example); demo-only knobs come from the
# HTWICKET_* env vars set in Dockerfile.demo.
set -e
CFG=/etc/htwicket.toml

mkdir -p /var/www/app /var/lib/htwicket

# Seed demo users (idempotent). admin is a superadmin via the [superadmins] expr.
# bob gets a generated password, printed to the console (`user add --random`).
htwicket --config "$CFG" user check admin >/dev/null 2>&1 || echo admin | htwicket --config "$CFG" user add admin
htwicket --config "$CFG" user check alice >/dev/null 2>&1 || echo alice | htwicket --config "$CFG" user add alice
htwicket --config "$CFG" user check bob   >/dev/null 2>&1 || htwicket --config "$CFG" user add bob --random

htwicket --config "$CFG" serve &
php -S 127.0.0.1:8000 -t /var/www/app >/dev/null 2>&1 &

# Wait for htwicket to answer before nginx starts proxying auth subrequests to it.
for _ in $(seq 1 50); do
    curl -fsS http://127.0.0.1:52155/htwicket/healthz >/dev/null 2>&1 && break
    sleep 0.2
done

echo "Open http://localhost:8080/ in browser  (users: admin/admin, alice/alice, bob/<password above>)"
exec nginx -g 'daemon off;'
