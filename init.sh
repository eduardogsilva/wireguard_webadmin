#!/bin/bash
set -e

# Lets wait for the DNS container to start
sleep 5

# Starts each WireGuard configuration file found in /etc/wireguard
shopt -s nullglob
config_files=(/etc/wireguard/*.conf)
if [ ${#config_files[@]} -gt 0 ]; then
    for f in "${config_files[@]}"; do
        wg-quick up "$(basename "${f}" .conf)"
    done
fi

# Django startup
python manage.py migrate --noinput
python manage.py collectstatic --noinput
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