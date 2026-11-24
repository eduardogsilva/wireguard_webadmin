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

# Written by cluster nodes, where this container shares the network namespace of the node. When the node
# container is restarted it gets a new namespace, so this container must restart to join it again.
NETNS_OWNER_FILE="/etc/dnsmasq/.netns_owner"

watch_network_namespace() {
    while sleep 30; do
        if [ -f "$NETNS_OWNER_FILE" ] && [ "$(cat "$NETNS_OWNER_FILE")" != "$(readlink /proc/self/ns/net)" ]; then
            echo "Network namespace of the cluster node changed, restarting..."
            kill -TERM 1
            pkill inotifywait
            return
        fi
    done
}

trap handle_sigint SIGINT
trap 'pkill dnsmasq; exit 1' SIGTERM

create_default_config
watch_network_namespace &
start_dnsmasq
