#!/bin/bash

set -e

if [[ "$COMPOSE_VERSION" != "02r" ]]; then
    echo "ERROR: Please upgrade your docker compose file. Exiting."
    exit 1
fi

if [ -z "$SERVER_ADDRESS" ]; then
    echo "SERVER_ADDRESS environment variable is not set. Exiting."
    exit 1
fi

DEBUG_VALUE="False"
if [[ "${DEBUG_MODE,,}" == "true" ]]; then
    DEBUG_VALUE="True"
fi

if [ ! -f /app_secrets/rrdtool_key ]; then
    cat /proc/sys/kernel/random/uuid > /app_secrets/rrdtool_key
fi

cat > /app/wireguard_webadmin/production_settings.py <<EOL
DEBUG = $DEBUG_VALUE
ALLOWED_HOSTS = ['wireguard-webadmin', '$SERVER_ADDRESS']
CSRF_TRUSTED_ORIGINS = ['http://wireguard-webadmin', 'https://$SERVER_ADDRESS']
SECRET_KEY = '$(openssl rand -base64 32)'
EOL

sed -i "/^    path('admin\/', admin.site.urls),/s/^    /    # /" /app/wireguard_webadmin/urls.py

exec "$@"
