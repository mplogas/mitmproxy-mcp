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
NM_AP_CONN="${MITM_NM_CONN:-mitm-ap}"

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

    # Unmask services in case setup hasn't run or a system update re-masked them
    sudo systemctl unmask hostapd dnsmasq 2>/dev/null || true

    # Disconnect any active WiFi connection on wlan0 and assign static IP
    # via the NM connection created by ap-setup.sh
    sudo nmcli device disconnect "$WLAN_IF" 2>/dev/null || true
    sudo nmcli device set "$WLAN_IF" managed no 2>/dev/null || true

    # Assign the static AP gateway address directly. The NM connection
    # cannot be activated while hostapd also manages the interface, so
    # we set the address with ip-addr instead.
    sudo ip addr flush dev "$WLAN_IF" 2>/dev/null || true
    # Read the gateway from the NM connection if it exists, otherwise default
    AP_GW=$(nmcli -g ipv4.addresses connection show "$NM_AP_CONN" 2>/dev/null || echo "192.168.4.1/24")
    sudo ip addr add "$AP_GW" dev "$WLAN_IF" 2>/dev/null || true
    sudo ip link set "$WLAN_IF" up

    # hostapd may fail on the first attempt if NM hasn't fully released
    # wlan0 yet. systemd auto-restarts it, so give it a moment.
    sudo systemctl start hostapd || sleep 2
    sudo systemctl is-active --quiet hostapd || {
        echo "Waiting for hostapd to start..."
        sleep 3
        sudo systemctl is-active --quiet hostapd || {
            echo "Error: hostapd failed to start" >&2
            exit 1
        }
    }
    # Verify wlan0 is actually in AP mode (NM can race and re-grab the interface)
    for i in 1 2 3 4 5; do
        if iw dev "$WLAN_IF" info 2>/dev/null | grep -q "type AP"; then
            break
        fi
        echo "Waiting for AP mode on $WLAN_IF (attempt $i)..."
        sleep 2
    done
    if ! iw dev "$WLAN_IF" info 2>/dev/null | grep -q "type AP"; then
        echo "Error: $WLAN_IF not in AP mode after starting hostapd" >&2
        exit 1
    fi

    sudo systemctl start dnsmasq
    iptables_rules -A
    echo "AP started. SSID and config from /etc/hostapd/hostapd.conf"
}

stop_ap() {
    echo "Stopping AP on $WLAN_IF..."
    iptables_rules -D 2>/dev/null || true
    sudo systemctl stop hostapd 2>/dev/null || true
    sudo systemctl stop dnsmasq 2>/dev/null || true

    # Remove the static AP address and restore NetworkManager management.
    # NM will reconnect wlan0 to the previously configured WiFi network.
    sudo ip addr flush dev "$WLAN_IF" 2>/dev/null || true
    sudo nmcli device set "$WLAN_IF" managed yes 2>/dev/null || true
    echo "AP stopped. NetworkManager will reconnect wlan0."
}

case "${1:-}" in
    start)  start_ap ;;
    stop)   stop_ap ;;
    *)      echo "Usage: $0 start|stop" >&2; exit 1 ;;
esac
