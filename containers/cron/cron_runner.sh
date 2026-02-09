#!/bin/bash
set -e

[ -z "$1" ] && exit 1

ENDPOINT="$1"
CRON_KEY="$(cat /app_secrets/cron_key)"
URL="http://wireguard-webadmin:8000/api/cron/${ENDPOINT}/?cron_key=${CRON_KEY}"

BODY="$(/usr/bin/curl -sS "$URL" 2>&1 || true)"
echo "[$(date -Is)] ${ENDPOINT} -> ${BODY}"
