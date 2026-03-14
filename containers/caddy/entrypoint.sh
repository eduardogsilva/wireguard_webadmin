#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${SCRIPT_DIR}/.venv/bin/python3"

"$PYTHON" "${SCRIPT_DIR}/export_wireguard_webadmin_config.py"

exec "$@"
