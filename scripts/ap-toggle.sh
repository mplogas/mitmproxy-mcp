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
IW="$(command -v iw 2>/dev/null || echo /usr/sbin/iw)"

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

    # Clean slate: stop hostapd if running, then fully release the interface
    sudo systemctl stop hostapd 2>/dev/null || true
    sudo systemctl stop dnsmasq 2>/dev/null || true
    sudo nmcli device disconnect "$WLAN_IF" 2>/dev/null || true
    sudo nmcli device set "$WLAN_IF" managed no 2>/dev/null || true

    # Wait for NM to actually release the interface. Without this,
    # hostapd races with NM and fails to take over the radio.
    for i in 1 2 3 4 5; do
        if ! $IW dev "$WLAN_IF" info 2>/dev/null | grep -q "type managed"; then
            break
        fi
        # NM may still hold wlan0 in managed/connected state; poke it again
        sudo nmcli device disconnect "$WLAN_IF" 2>/dev/null || true
        echo "Waiting for NM to release $WLAN_IF (attempt $i)..."
        sleep 1
    done

    # Assign the static AP gateway address
    sudo ip addr flush dev "$WLAN_IF" 2>/dev/null || true
    AP_GW=$(nmcli -g ipv4.addresses connection show "$NM_AP_CONN" 2>/dev/null || echo "192.168.4.1/24")
    sudo ip addr add "$AP_GW" dev "$WLAN_IF" 2>/dev/null || true
    sudo ip link set "$WLAN_IF" up

    # Start hostapd and verify it took over the radio.
    # First attempt may fail if NM hasn't fully released the interface;
    # the retry loop handles this.
    sudo systemctl start hostapd 2>/dev/null || true
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if $IW dev "$WLAN_IF" info 2>/dev/null | grep -q "type AP"; then
            break
        fi
        if [ "$i" -eq 1 ]; then
            echo "Waiting for AP mode on $WLAN_IF..."
        fi
        # If hostapd died, restart it
        if ! sudo systemctl is-active --quiet hostapd; then
            echo "  hostapd not running, restarting (attempt $i)..."
            sudo systemctl start hostapd 2>/dev/null || true
        fi
        sleep 1
    done
    if ! $IW dev "$WLAN_IF" info 2>/dev/null | grep -q "type AP"; then
        echo "Error: $WLAN_IF not in AP mode after 10 attempts" >&2
        sudo journalctl -u hostapd --no-pager -n 5 >&2
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
