#!/bin/bash
CONFIG_FILE="/etc/dnsmasq/wireguard_webadmin_dns.conf"
DEFAULT_CONFIG_CONTENT="
no-dhcp-interface=
server=1.1.1.1
server=1.0.0.1

listen-address=0.0.0.0
bind-interfaces
"

create_default_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Config file not found, creating a new one..."
        echo "$DEFAULT_CONFIG_CONTENT" > "$CONFIG_FILE"
    fi
}

start_dnsmasq() {
    dnsmasq -C "$CONFIG_FILE" &
    while inotifywait -e modify "$CONFIG_FILE"; do
        echo "Configuration changed, reloading dnsmasq..."
        pkill dnsmasq
        sleep 5
        dnsmasq -C "$CONFIG_FILE" &
    done
}


handle_sigint() {
    echo "SIGINT received. Stopping inotifywait and dnsmasq..."
    pkill inotifywait
    pkill dnsmasq
    exit 0
}

trap handle_sigint SIGINT

create_default_config
start_dnsmasq
