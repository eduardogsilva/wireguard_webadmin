#!/bin/bash
echo '--- Ping the DNS container...'
ping -c 4 wireguard-webadmin-dns
echo ''
echo ''
echo '--- Checking firewall rules...'
iptables -t nat -L WGWADM_PREROUTING -nv |grep -e pkts -e dpt:53

output=$(iptables -t nat -L WGWADM_PREROUTING -nv | grep -e dpt:53)
if [[ -z "$output" ]]; then
  echo ''
  echo '=== ERROR: No firewall rules redirecting the DNS service were found.'
else
  if [[ "$output" == *"127.0.0.250"* ]]; then
    echo ''
    echo '=== ERROR: The firewall script failed to resolve the DNS service name.'
    echo '=== The IP 127.0.0.250 is a fallback address.'
  fi
fi
echo ''
echo ''
echo '--- Testing the DNS resolution...'
echo 'Resolving google.com...'
dig @wireguard-webadmin-dns google.com +short
echo ''
echo ''
echo '--- Testing getent hosts...'
getent hosts wireguard-webadmin-dns
DNS_IP=$(getent hosts wireguard-webadmin-dns | awk '{ print $1 }')
if [ -z "$DNS_IP" ]; then
    DNS_IP="127.0.0.250"
fi
echo "DNS IP: $DNS_IP"