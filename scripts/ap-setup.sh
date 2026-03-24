#!/usr/bin/env bash
# One-time WiFi AP setup for MITM interception.
# Idempotent: safe to run multiple times. Overwrites configs with current values.
#
# Usage: ap-setup.sh [options]
#   --ssid NAME         AP network name (default: pidev-mitm)
#   --passphrase PASS   WPA2 passphrase, min 8 chars (default: pidev-mitm-key)
#   --channel N         WiFi channel (default: 7)
#   --subnet PREFIX     /24 subnet for AP clients (default: 192.168.4)
#   --interface IF      WiFi interface (default: wlan0)
#   --dry-run           Show what would be done without changing anything
#
# What it does:
#   1. Installs hostapd + dnsmasq + tshark (if missing)
#   2. Writes /etc/hostapd/hostapd.conf
#   3. Writes /etc/dnsmasq.d/mitm.conf
#   4. Creates a NetworkManager static connection for the AP interface
#   5. Enables IP forwarding in sysctl
#   6. Disables (but unmasks) hostapd + dnsmasq from auto-starting
#   7. Adds current user to wireshark group for unprivileged packet capture
#
# After running: use ap-toggle.sh start/stop to bring the AP up per engagement.

set -euo pipefail

# -- Defaults (override via flags) ------------------------------------------

SSID="pidev-mitm"
PASSPHRASE="pidev-mitm-key"
CHANNEL=7
SUBNET="192.168.4"
IFACE="wlan0"
DRY_RUN=false

# -- Parse args --------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssid)       SSID="$2"; shift 2 ;;
        --passphrase) PASSPHRASE="$2"; shift 2 ;;
        --channel)    CHANNEL="$2"; shift 2 ;;
        --subnet)     SUBNET="$2"; shift 2 ;;
        --interface)  IFACE="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=true; shift ;;
        -h|--help)
            head -16 "$0" | tail -15
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# -- Validation --------------------------------------------------------------

if [[ ${#PASSPHRASE} -lt 8 ]]; then
    echo "Error: passphrase must be at least 8 characters" >&2
    exit 1
fi

GATEWAY="${SUBNET}.1"
DHCP_START="${SUBNET}.10"
DHCP_END="${SUBNET}.50"
NM_CONN="mitm-ap"

# -- Helpers ------------------------------------------------------------------

run() {
    echo "  > $*"
    if [[ "$DRY_RUN" == "false" ]]; then
        "$@"
    fi
}

write_file() {
    local path="$1"
    local content="$2"
    echo "  Writing $path"
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "$content" | sudo tee "$path" > /dev/null
    else
        echo "$content" | sed 's/^/    /'
    fi
}

# -- 1. Install packages (idempotent) ----------------------------------------

echo "[1/7] Checking packages..."
for pkg in hostapd dnsmasq tshark; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "  $pkg already installed"
    else
        # tshark asks about non-root capture; pre-answer yes
        if [[ "$pkg" == "tshark" ]]; then
            echo "  Installing $pkg (enabling non-root capture)..."
            if [[ "$DRY_RUN" == "false" ]]; then
                echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
            fi
        fi
        run sudo apt-get install -y "$pkg"
    fi
done

# -- 2. hostapd config -------------------------------------------------------

echo "[2/7] Writing hostapd config..."
write_file /etc/hostapd/hostapd.conf "\
interface=${IFACE}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase=${PASSPHRASE}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP"

# Point hostapd to the config (some distros need this)
if [[ -f /etc/default/hostapd ]]; then
    if ! grep -q "^DAEMON_CONF=" /etc/default/hostapd 2>/dev/null; then
        write_file /etc/default/hostapd 'DAEMON_CONF="/etc/hostapd/hostapd.conf"'
    fi
fi

# -- 3. dnsmasq config -------------------------------------------------------

echo "[3/7] Writing dnsmasq config..."
write_file /etc/dnsmasq.d/mitm.conf "\
interface=${IFACE}
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,24h
# Do not read /etc/resolv.conf -- serve upstream DNS directly
no-resolv
server=8.8.8.8
server=1.1.1.1"

# -- 4. NetworkManager static IP for AP interface ----------------------------

echo "[4/7] Configuring NetworkManager connection '${NM_CONN}'..."
if nmcli -t -f NAME connection show | grep -qx "${NM_CONN}"; then
    echo "  Connection '${NM_CONN}' exists, updating..."
    run sudo nmcli connection modify "${NM_CONN}" \
        ipv4.addresses "${GATEWAY}/24" \
        ipv4.method manual \
        connection.autoconnect no
else
    echo "  Creating connection '${NM_CONN}'..."
    run sudo nmcli connection add \
        type wifi \
        con-name "${NM_CONN}" \
        ifname "${IFACE}" \
        ssid "${SSID}" \
        ipv4.addresses "${GATEWAY}/24" \
        ipv4.method manual \
        connection.autoconnect no
fi

# -- 5. IP forwarding --------------------------------------------------------

echo "[5/7] Enabling IP forwarding..."
if grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "  Already enabled"
else
    if grep -q "^#net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "  Uncommenting existing line"
        run sudo sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    else
        echo "  Appending to sysctl.conf"
        if [[ "$DRY_RUN" == "false" ]]; then
            echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf > /dev/null
        fi
    fi
    run sudo sysctl -p
fi

# -- 6. Disable auto-start (ap-toggle.sh manages these) ----------------------

echo "[6/7] Configuring hostapd and dnsmasq services..."
# Unmask first -- Debian/Bookworm may mask hostapd on install, which
# prevents systemctl start from working at all.
run sudo systemctl unmask hostapd 2>/dev/null || true
run sudo systemctl unmask dnsmasq 2>/dev/null || true
# Disable auto-start. ap-toggle.sh starts/stops them per engagement.
run sudo systemctl disable hostapd 2>/dev/null || true
run sudo systemctl disable dnsmasq 2>/dev/null || true
run sudo systemctl stop hostapd 2>/dev/null || true
run sudo systemctl stop dnsmasq 2>/dev/null || true

# -- 7. Wireshark group for unprivileged tshark capture ----------------------

echo "[7/7] Adding $(whoami) to wireshark group..."
if id -nG "$(whoami)" | grep -qw wireshark; then
    echo "  Already in wireshark group"
else
    run sudo usermod -aG wireshark "$(whoami)"
    echo "  Added. A new shell or re-login is required for this to take effect."
fi

# -- Done ---------------------------------------------------------------------

echo ""
echo "AP setup complete."
echo "  SSID:      ${SSID}"
echo "  Interface: ${IFACE}"
echo "  Gateway:   ${GATEWAY}"
echo "  DHCP:      ${DHCP_START} - ${DHCP_END}"
echo "  Channel:   ${CHANNEL}"
echo ""
echo "Use ap-toggle.sh start/stop to bring the AP up per engagement."
echo "The AP will NOT start automatically on boot."
