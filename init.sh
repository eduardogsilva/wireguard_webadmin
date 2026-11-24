#!/bin/bash
set -e

# Containers sharing this network namespace (Caddy) restart themselves when it changes
if [ -d /caddy_json_export ]; then
    readlink /proc/self/ns/net > /caddy_json_export/.netns_owner
fi

# Lets wait for the DNS container to start
sleep 5

# Django startup
python manage.py migrate --noinput
python manage.py collectstatic --noinput

# Export WireGuard, firewall and Caddy configs before bringing up interfaces
python manage.py export_configs

# Starts each WireGuard configuration file found in /etc/wireguard, unless the cluster settings disable WireGuard
# on the primary server
shopt -s nullglob
config_files=(/etc/wireguard/*.conf)
if [ ${#config_files[@]} -gt 0 ]; then
    if python manage.py primary_wireguard_enabled; then
        for f in "${config_files[@]}"; do
            wg-quick up "$(basename "${f}" .conf)"
        done
    else
        echo "WireGuard is disabled on the primary server, interfaces not started."
    fi
fi
if [[ "${DEV_MODE,,}" == "true" ]]; then
    echo ""
    echo ""
    echo "================================================================"
    echo "= WARNING: DEV_MODE is enabled. Do not use this in production! ="
    echo "================================================================"
    echo ""
    echo ""
    echo "DEV_MODE=true -> Starting Django runserver"
    exec python manage.py runserver 0.0.0.0:8000
else
    echo "Starting Gunicorn"
    exec gunicorn wireguard_webadmin.wsgi:application --bind 0.0.0.0:8000 --workers 2 --threads 2 --timeout 60 --log-level info --capture-output --access-logfile - --error-logfile -
fi