#!/bin/bash

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="python3"
JSON_DIR="${JSON_DIR:-/caddy_json_export}"
CADDYFILE_PATH="${CADDYFILE_PATH:-/etc/caddy/Caddyfile}"
CADDY_PID=""
CLUSTER_NODE="${CLUSTER_NODE:-false}"

# The WireGuard WebAdmin interface is only published by the primary server
if [ "$CLUSTER_NODE" != "true" ]; then
    echo "==> Generating wireguard_webadmin.json..."
    "$PYTHON" "${SCRIPT_DIR}/export_wireguard_webadmin_config.py"
fi

generate_caddyfile() {
    "$PYTHON" "${SCRIPT_DIR}/process_config.py" >/dev/null
    # Validation output is not printed because provider errors may include credentials
    if ! caddy validate --config "$CADDYFILE_PATH" --adapter caddyfile >/dev/null 2>&1; then
        echo "Warning: generated Caddyfile is invalid, regenerating with DNS challenge disabled. Check the DNS credentials."
        DISABLE_DNS_CHALLENGE=1 "$PYTHON" "${SCRIPT_DIR}/process_config.py" >/dev/null
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
# Nothing is cached yet, so hosts left on a fallback certificate get a new ACME attempt
"$PYTHON" "${SCRIPT_DIR}/process_config.py" --reset-fallback-certificates

echo "==> Starting Caddy..."
start_caddy

if [ "$CLUSTER_NODE" != "true" ]; then
    # Certificates used by cluster workers are exported as soon as they are issued or renewed
    (
        while true; do
            sleep 60
            "$PYTHON" "${SCRIPT_DIR}/process_config.py" --export-certificates || true
        done
    ) &
fi

sleep 2

caddyfile_checksum() {
    sha256sum "$CADDYFILE_PATH" 2>/dev/null | cut -d ' ' -f 1
}

APPLIED_CADDYFILE="$(caddyfile_checksum)"

echo "==> Watching ${JSON_DIR} for config changes..."
while true; do
    # The timeout also picks up changes written before the watch started or missed while reloading
    inotifywait -qq -t 60 -e close_write,moved_to,create "${JSON_DIR}/" --include '.*\.json$' 2>/dev/null || true
    sleep 1

    # The container that owns this network namespace was restarted: exit so Docker restarts Caddy and it
    # joins the new namespace (otherwise it keeps serving from a namespace without published ports)
    if [ -f "${JSON_DIR}/.netns_owner" ] && [ "$(cat "${JSON_DIR}/.netns_owner")" != "$(readlink /proc/self/ns/net)" ]; then
        echo "Network namespace owner changed, restarting..."
        stop_caddy
        exit 1
    fi

    generate_caddyfile

    if ! kill -0 "$CADDY_PID" 2>/dev/null; then
        echo "==> Caddy is not running, starting it again..."
        sync_tls_state >/dev/null
        start_caddy
        APPLIED_CADDYFILE="$(caddyfile_checksum)"
    elif [ "$(sync_tls_state)" = "restart" ]; then
        # A reload keeps previously issued certificates cached in memory
        echo "==> Certificate settings changed, restarting Caddy..."
        stop_caddy
        start_caddy
        APPLIED_CADDYFILE="$(caddyfile_checksum)"
    elif [ "$(caddyfile_checksum)" != "$APPLIED_CADDYFILE" ]; then
        echo "==> Config change detected, reloading Caddy..."
        if caddy reload --config "$CADDYFILE_PATH" --adapter caddyfile 2>/dev/null; then
            APPLIED_CADDYFILE="$(caddyfile_checksum)"
        else
            echo "Warning: Caddy reload failed, will retry on next change."
        fi
    fi
done
