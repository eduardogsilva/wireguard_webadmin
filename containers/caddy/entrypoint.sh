#!/bin/bash

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="python3"
JSON_DIR="${JSON_DIR:-/caddy_json_export}"
CADDYFILE_PATH="${CADDYFILE_PATH:-/etc/caddy/Caddyfile}"
CADDY_PID=""

echo "==> Generating wireguard_webadmin.json..."
"$PYTHON" "${SCRIPT_DIR}/export_wireguard_webadmin_config.py"

generate_caddyfile() {
    "$PYTHON" "${SCRIPT_DIR}/process_config.py"
    # Validation output is not printed because provider errors may include credentials
    if ! caddy validate --config "$CADDYFILE_PATH" --adapter caddyfile >/dev/null 2>&1; then
        echo "Warning: generated Caddyfile is invalid, regenerating with DNS challenge disabled. Check the DNS credentials."
        DISABLE_DNS_CHALLENGE=1 "$PYTHON" "${SCRIPT_DIR}/process_config.py"
    fi
}

sync_tls_state() {
    "$PYTHON" "${SCRIPT_DIR}/process_config.py" --sync-tls-state
}

start_caddy() {
    caddy run --config "$CADDYFILE_PATH" --adapter caddyfile &
    CADDY_PID=$!
}

stop_caddy() {
    kill "$CADDY_PID" 2>/dev/null || true
    for attempt in $(seq 1 10); do
        kill -0 "$CADDY_PID" 2>/dev/null || break
        sleep 1
    done
    kill -9 "$CADDY_PID" 2>/dev/null || true
    wait "$CADDY_PID" 2>/dev/null || true
}

echo "==> Processing config files..."
generate_caddyfile
sync_tls_state >/dev/null

echo "==> Starting Caddy..."
start_caddy

sleep 2

echo "==> Watching ${JSON_DIR} for config changes..."
while true; do
    inotifywait -qq -e close_write,moved_to,create "${JSON_DIR}/" --include '.*\.json$' 2>/dev/null || true
    sleep 1

    echo "==> Config change detected, reprocessing..."
    generate_caddyfile

    if [ "$(sync_tls_state)" = "restart" ]; then
        # A reload keeps previously issued certificates cached in memory
        echo "==> Certificate settings changed, restarting Caddy..."
        stop_caddy
        start_caddy
    else
        echo "==> Reloading Caddy..."
        caddy reload --config "$CADDYFILE_PATH" --adapter caddyfile 2>/dev/null || echo "Warning: Caddy reload failed, will retry on next change."
    fi
done
