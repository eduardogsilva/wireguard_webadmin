#!/bin/bash
set -e

WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL=${WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL:-60}

case "$WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL" in
    30|60|150|300)
        ;;
    *)
        echo "Error: Invalid WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL value: $WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL. Allowed values are 30, 60, 150, 300."
        exit 1
        ;;
esac

echo "Starting cron with WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL=$WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL"

# Create cron tasks
cat <<EOF > /etc/cron.d/cron_tasks
*/15 * * * * root sleep 20 ; /usr/bin/curl -s http://wireguard-webadmin:8000/api/cron_check_updates/ >> /var/log/cron.log 2>&1
*/10 * * * * root sleep 15 ; /usr/bin/curl -s http://wireguard-webadmin:8000/api/cron_update_peer_latest_handshake/ >> /var/log/cron.log 2>&1
* * * * * root sleep 10 ; /usr/bin/curl -s http://wireguard-webadmin:8000/api/cron_peer_scheduler/ >> /var/log/cron.log 2>&1
* * * * * root sleep 30 ; /usr/bin/curl -s http://wireguard-webadmin:8000/api/cron_calculate_peer_schedules/ >> /var/log/cron.log 2>&1
EOF

CMD="/usr/bin/curl -s http://wireguard-webadmin:8000/api/cron_refresh_wireguard_status_cache/ >> /var/log/cron.log 2>&1"

if [ "$WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL" -eq 30 ]; then
    echo "* * * * * root $CMD" >> /etc/cron.d/cron_tasks
    echo "* * * * * root sleep 30; $CMD" >> /etc/cron.d/cron_tasks
elif [ "$WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL" -eq 60 ]; then
    echo "* * * * * root $CMD" >> /etc/cron.d/cron_tasks
elif [ "$WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL" -eq 150 ]; then
    echo "*/5 * * * * root $CMD" >> /etc/cron.d/cron_tasks
    echo "*/5 * * * * root sleep 150; $CMD" >> /etc/cron.d/cron_tasks
elif [ "$WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL" -eq 300 ]; then
    echo "*/5 * * * * root $CMD" >> /etc/cron.d/cron_tasks
fi

# Permissions
chmod 0644 /etc/cron.d/cron_tasks
# crontab /etc/cron.d/cron_tasks

# Touch log file
touch /var/log/cron.log

# Execute cron
exec cron -f
