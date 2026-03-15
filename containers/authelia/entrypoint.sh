#!/bin/sh

set -eu

CONFIG_PATH="/config/configuration.yml"
WAIT_INTERVAL=5

echo "==> Waiting for Authelia configuration file..."
while [ ! -f "$CONFIG_PATH" ]; do
    sleep "$WAIT_INTERVAL"
done
echo "==> Configuration file found: ${CONFIG_PATH}"

echo "==> Starting Authelia..."
authelia --config "$CONFIG_PATH" &
AUTHELIA_PID=$!

sleep 3

echo "==> Watching ${CONFIG_PATH} for changes..."

# Function to safely get hash in minimal environments
get_hash() {
    md5sum "$CONFIG_PATH" 2>/dev/null | awk '{print $1}' || echo "error"
}

LAST_HASH=$(get_hash)

while true; do
    sleep 3
    CURRENT_HASH=$(get_hash)

    if [ "$LAST_HASH" != "$CURRENT_HASH" ]; then
        echo "==> Configuration change detected, restarting Authelia..."
        LAST_HASH="$CURRENT_HASH"
        
        kill "$AUTHELIA_PID" 2>/dev/null || true
        wait "$AUTHELIA_PID" 2>/dev/null || true

        authelia --config "$CONFIG_PATH" &
        AUTHELIA_PID=$!
        echo "==> Authelia restarted with PID ${AUTHELIA_PID}"
    fi
done
