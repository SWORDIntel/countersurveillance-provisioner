#!/usr/bin/env bash
# setup-spoke.sh - Configure WireGuard spoke link to ChronoSink Hub
# Usage: ./setup-spoke.sh <spoke_ip: e.g. 10.200.0.2> <hub_endpoint: e.g. 192.168.1.100 or oci.public.ip> <hub_public_key>

set -euo pipefail

SPOKE_IP="${1:-}"
HUB_ENDPOINT="${2:-}"
HUB_PUBKEY="${3:-}"

if [[ -z "$SPOKE_IP" || -z "$HUB_ENDPOINT" || -z "$HUB_PUBKEY" ]]; then
    echo "Usage: $0 <spoke_wg_ip: e.g. 10.200.0.2> <hub_endpoint: IP or FQDN> <hub_public_key>"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root (or via sudo)."
    exit 1
fi

echo "[*] Checking WireGuard installation..."
if ! command -v wg &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq wireguard wireguard-tools
fi

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

KEY_FILE="/etc/wireguard/spoke_private.key"
PUB_FILE="/etc/wireguard/spoke_public.key"

if [[ ! -f "$KEY_FILE" ]]; then
    echo "[*] Generating Spoke WireGuard keypair..."
    wg genkey | tee "$KEY_FILE" | wg pubkey > "$PUB_FILE"
    chmod 600 "$KEY_FILE" "$PUB_FILE"
fi

PRIV_KEY=$(cat "$KEY_FILE")
PUB_KEY=$(cat "$PUB_FILE")

CONF_FILE="/etc/wireguard/wg-honeypot.conf"
cat > "$CONF_FILE" <<EOF
[Interface]
Address = ${SPOKE_IP}/24
PrivateKey = ${PRIV_KEY}

[Peer]
PublicKey = ${HUB_PUBKEY}
Endpoint = ${HUB_ENDPOINT}:51820
AllowedIPs = 10.200.0.1/32
PersistentKeepalive = 25
EOF

chmod 600 "$CONF_FILE"

echo "[*] Starting wg-quick@wg-honeypot..."
systemctl enable --now wg-quick@wg-honeypot

echo ""
echo "[✓] WireGuard Spoke active on ${SPOKE_IP} -> Hub ${HUB_ENDPOINT}"
echo "[*] Public Key for this Spoke (add to Hub config):"
echo "    ${PUB_KEY}"
