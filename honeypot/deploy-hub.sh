#!/usr/bin/env bash
# deploy-hub.sh - Automated installer for ChronoSink Deception Hub & WireGuard Endpoint
# Usage: sudo ./deploy-hub.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root (or via sudo)."
    exit 1
fi

echo "=========================================================="
echo "  Deploying ChronoSink Deception Engine & WireGuard Hub  "
echo "=========================================================="

echo "[1/5] Installing core dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip wireguard wireguard-tools nftables curl

echo "[2/5] Installing ChronoSink Go Daemon to /opt/chronosink/..."
mkdir -p /opt/chronosink /var/log/chronosink /etc/chronosink
ARCH=$(uname -m)
BIN_SRC="${SCRIPT_DIR}/bin/chronosink-linux-amd64"
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    BIN_SRC="${SCRIPT_DIR}/bin/chronosink-linux-arm64"
fi

if [[ -f "$BIN_SRC" ]]; then
    cp "$BIN_SRC" /opt/chronosink/chronosink
    chmod 755 /opt/chronosink/chronosink
elif [[ -f "${SCRIPT_DIR}/chronosink.py" ]]; then
    # Fallback to python script if binary not present
    cp "${SCRIPT_DIR}/chronosink.py" /opt/chronosink/chronosink.py
    chmod 755 /opt/chronosink/chronosink.py
fi

cp "${SCRIPT_DIR}/chronosink.service" /etc/systemd/system/chronosink.service
systemctl daemon-reload
systemctl enable --now chronosink.service

echo "[3/5] Installing Hub NFTables Deception Mangle Table..."
mkdir -p /etc/nftables.d
cp "${SCRIPT_DIR}/configs/hub-nftables.nft" /etc/nftables.d/chronosink_mangle.nft

# Include in main nftables config if not already present
if ! grep -q "chronosink_mangle.nft" /etc/nftables.conf 2>/dev/null; then
    echo 'include "/etc/nftables.d/chronosink_mangle.nft"' >> /etc/nftables.conf
fi
nft -f /etc/nftables.d/chronosink_mangle.nft

echo "[4/5] Setting up WireGuard Hub keys and interface..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

HUB_KEY="/etc/wireguard/hub_private.key"
HUB_PUB="/etc/wireguard/hub_public.key"

if [[ ! -f "$HUB_KEY" ]]; then
    echo "[*] Generating new Hub WireGuard keypair..."
    wg genkey | tee "$HUB_KEY" | wg pubkey > "$HUB_PUB"
    chmod 600 "$HUB_KEY" "$HUB_PUB"
fi

HUB_PRIV=$(cat "$HUB_KEY")
HUB_PUBLIC=$(cat "$HUB_PUB")

HUB_CONF="/etc/wireguard/wg-hub.conf"
if [[ ! -f "$HUB_CONF" ]]; then
    cat > "$HUB_CONF" <<EOF
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = ${HUB_PRIV}

# Policy routing to preserve real scanner source IP for replies
PostUp = ip rule add iif %i table 200; ip route add default dev %i table 200; sysctl -w net.ipv4.ip_forward=1
PostDown = ip rule del iif %i table 200; ip route del default dev %i table 200

# Spoke: T320 (192.168.1.95)
# [Peer]
# PublicKey = <T320_SPOKE_PUBKEY>
# AllowedIPs = 10.200.0.2/32

# Spoke: 730xd (192.168.1.90)
# [Peer]
# PublicKey = <730XD_SPOKE_PUBKEY>
# AllowedIPs = 10.200.0.3/32

# Spoke: T420 (192.168.1.91)
# [Peer]
# PublicKey = <T420_SPOKE_PUBKEY>
# AllowedIPs = 10.200.0.4/32
EOF
    chmod 600 "$HUB_CONF"
fi

systemctl enable --now wg-quick@wg-hub || true

echo "[5/5] Verifying ChronoSink status..."
systemctl is-active --quiet chronosink.service && echo "[✓] chronosink.service is running." || echo "[!] chronosink failed to start."

echo ""
echo "=========================================================="
echo "  Deployment Complete!                                   "
echo "=========================================================="
echo "Hub WireGuard Public Key:"
echo "  ${HUB_PUBLIC}"
echo ""
echo "Next Steps:"
echo "1. On each spoke (T320, 730xd, T420), run:"
echo "   sudo ./wireguard/setup-spoke.sh <spoke_wg_ip> <hub_endpoint> '${HUB_PUBLIC}'"
echo "2. Add each spoke's public key as a [Peer] block in /etc/wireguard/wg-hub.conf"
echo "   and reload: sudo wg syncconf wg-hub <(wg-quick strip wg-hub)"
echo "3. Monitor incoming deception telemetry:"
echo "   tail -f /var/log/chronosink/probes.jsonl"
