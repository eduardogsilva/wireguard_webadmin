#!/bin/bash

set -e

if [[ "$COMPOSE_VERSION" != "03r" ]]; then
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

SERVER_HOSTNAME=$(echo $SERVER_ADDRESS | cut -d ':' -f 1)
EXTRA_ALLOWED_HOSTS_STRING=""
CSRF_EXTRA_TRUSTED_ORIGINS=""
if [ -n "$EXTRA_ALLOWED_HOSTS" ]; then
    IFS=',' read -ra ADDR <<< "$EXTRA_ALLOWED_HOSTS"
    for i in "${ADDR[@]}"; do
        EXTRA_ALLOWED_HOSTS_STRING+=", '$(echo $i | cut -d ':' -f 1)'"
        CSRF_EXTRA_TRUSTED_ORIGINS+=", 'https://$i'"
    done
fi

cat > /app/wireguard_webadmin/production_settings.py <<EOL
DEBUG = $DEBUG_VALUE
ALLOWED_HOSTS = ['wireguard-webadmin', '${SERVER_HOSTNAME}'${EXTRA_ALLOWED_HOSTS_STRING}]
CSRF_TRUSTED_ORIGINS = ['http://wireguard-webadmin', 'https://$SERVER_ADDRESS'${CSRF_EXTRA_TRUSTED_ORIGINS}]
SECRET_KEY = '$(openssl rand -base64 32)'
EOL

if [ -n "$TZ" ]; then
    echo "TIME_ZONE = '$TZ'" >> /app/wireguard_webadmin/production_settings.py
fi


sed -i "/^    path('admin\/', admin.site.urls),/s/^    /    # /" /app/wireguard_webadmin/urls.py

exec "$@"
