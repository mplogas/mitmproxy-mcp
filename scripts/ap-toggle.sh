#!/usr/bin/env bash
# AP toggle script for MITM interception.
# Starts/stops hostapd + dnsmasq and applies/removes iptables NAT rules.
#
# Prerequisites (one-time manual setup, see README):
#   - /etc/hostapd/hostapd.conf configured
#   - /etc/dnsmasq.d/mitm.conf configured
#   - Static IP for wlan0 configured
#   - IP forwarding enabled: net.ipv4.ip_forward=1
#
# Usage: ap-toggle.sh start|stop

set -euo pipefail

WLAN_IF="${MITM_WLAN_IF:-wlan0}"
PROXY_PORT="${MITM_PROXY_PORT:-8080}"

iptables_rules() {
    local action="$1"  # -A or -D
    # NAT: masquerade outbound traffic from wlan0 clients
    sudo iptables -t nat "$action" POSTROUTING -o eth0 -j MASQUERADE
    # Redirect HTTP/HTTPS/MQTT-TLS through mitmproxy
    sudo iptables -t nat "$action" PREROUTING -i "$WLAN_IF" -p tcp --dport 80 -j REDIRECT --to-port "$PROXY_PORT"
    sudo iptables -t nat "$action" PREROUTING -i "$WLAN_IF" -p tcp --dport 443 -j REDIRECT --to-port "$PROXY_PORT"
    sudo iptables -t nat "$action" PREROUTING -i "$WLAN_IF" -p tcp --dport 8883 -j REDIRECT --to-port "$PROXY_PORT"
}

start_ap() {
    echo "Starting AP on $WLAN_IF..."
    # Stop NetworkManager management of wlan0 to avoid conflicts
    sudo nmcli device set "$WLAN_IF" managed no 2>/dev/null || true
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    iptables_rules -A
    echo "AP started. SSID and config from /etc/hostapd/hostapd.conf"
}

stop_ap() {
    echo "Stopping AP on $WLAN_IF..."
    iptables_rules -D 2>/dev/null || true
    sudo systemctl stop hostapd 2>/dev/null || true
    sudo systemctl stop dnsmasq 2>/dev/null || true
    # Restore NetworkManager management
    sudo nmcli device set "$WLAN_IF" managed yes 2>/dev/null || true
    echo "AP stopped."
}

case "${1:-}" in
    start)  start_ap ;;
    stop)   stop_ap ;;
    *)      echo "Usage: $0 start|stop" >&2; exit 1 ;;
esac
