#!/bin/bash

set -e

if [ -z "$SERVER_ADDRESS" ]; then
    echo "SERVER_ADDRESS environment variable is not set. Exiting."
    exit 1
fi

DEBUG_VALUE="False"
if [[ "${DEBUG_MODE,,}" == "true" ]]; then
    DEBUG_VALUE="True"
fi

cat > /app/wireguard_webadmin/production_settings.py <<EOL
DEBUG = $DEBUG_VALUE
ALLOWED_HOSTS = ['$SERVER_ADDRESS']
CSRF_TRUSTED_ORIGINS = ['https://$SERVER_ADDRESS']
SECRET_KEY = '$(openssl rand -base64 32)'
EOL

exec "$@"
