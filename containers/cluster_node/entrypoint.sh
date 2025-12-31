#!/bin/bash
set -e

# Set Timezone
if [ -n "$TZ" ]; then
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
fi

# Check required variables
if [ -z "$MASTER_SERVER_ADDRESS" ]; then
    echo "ERROR: MASTER_SERVER_ADDRESS is not set."
    exit 1
fi

if [ -z "$TOKEN" ]; then
    echo "ERROR: TOKEN is not set."
    exit 1
fi

# Check MASTER_SERVER_ADDRESS for HTTPS
if [[ "$MASTER_SERVER_ADDRESS" != https://* ]]; then
    if [[ "$MASTER_SERVER_ADDRESS" == http://192.168.* ]]; then
        echo "Warning: Using HTTP only for development."
    else
        echo "ERROR: MASTER_SERVER_ADDRESS must start with https://. Received: $MASTER_SERVER_ADDRESS"
        exit 1
    fi
fi

exec "$@"
