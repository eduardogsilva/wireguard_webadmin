#!/bin/sh

set -eu

CONFIG_PATH="/config/configuration.yml"
MAX_WAIT=120
WAIT_INTERVAL=2

echo "==> Waiting for Authelia configuration file..."
elapsed=0
while [ ! -f "$CONFIG_PATH" ]; do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "Error: Timed out waiting for ${CONFIG_PATH} after ${MAX_WAIT}s"
        exit 1
    fi
    sleep "$WAIT_INTERVAL"
    elapsed=$((elapsed + WAIT_INTERVAL))
done
echo "==> Configuration file found: ${CONFIG_PATH}"

echo "==> Starting Authelia..."
authelia --config "$CONFIG_PATH" &
AUTHELIA_PID=$!

sleep 3

echo "==> Watching ${CONFIG_PATH} for changes..."
while true; do
    inotifywait -qq -e close_write,moved_to "${CONFIG_PATH}" 2>/dev/null || true
    sleep 2

    echo "==> Configuration change detected, restarting Authelia..."
    kill "$AUTHELIA_PID" 2>/dev/null || true
    wait "$AUTHELIA_PID" 2>/dev/null || true

    authelia --config "$CONFIG_PATH" &
    AUTHELIA_PID=$!
    echo "==> Authelia restarted with PID ${AUTHELIA_PID}"
done
