#!/bin/bash

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${SCRIPT_DIR}/.venv/bin/python3"
JSON_DIR="${JSON_DIR:-/caddy_json_export}"
CADDYFILE_PATH="${CADDYFILE_PATH:-/etc/caddy/Caddyfile}"

echo "==> Generating wireguard_webadmin.json..."
"$PYTHON" "${SCRIPT_DIR}/export_wireguard_webadmin_config.py"

echo "==> Processing config files..."
"$PYTHON" "${SCRIPT_DIR}/process_config.py"

echo "==> Starting Caddy..."
caddy run --config "$CADDYFILE_PATH" --adapter caddyfile &
CADDY_PID=$!

sleep 2

echo "==> Watching ${JSON_DIR} for config changes..."
while true; do
    inotifywait -qq -e close_write,moved_to,create "${JSON_DIR}/" --include '.*\.json$' 2>/dev/null || true
    sleep 1

    echo "==> Config change detected, reprocessing..."
    "$PYTHON" "${SCRIPT_DIR}/process_config.py"

    echo "==> Reloading Caddy..."
    caddy reload --config "$CADDYFILE_PATH" --adapter caddyfile 2>/dev/null || echo "Warning: Caddy reload failed, will retry on next change."
done
