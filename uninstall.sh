#!/usr/bin/env bash
# uninstall.sh — Safe Counter-Surveillance & ChronoSink Teardown
# Preserves all host tables (Proxmox PVE, Docker, Podman). Removes ONLY provisioner assets.
set -euo pipefail

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

echo -e "${Y}[*] Stopping and disabling provisioner services...${NC}"
sudo systemctl stop countersurveillance-block.service chronosink.service countersurveillance-refresh.timer countersurveillance-refresh.service 2>/dev/null || true
sudo systemctl disable countersurveillance-block.service chronosink.service countersurveillance-refresh.timer countersurveillance-refresh.service 2>/dev/null || true

echo -e "${Y}[*] Removing ONLY table inet countersurveillance (preserving host tables)...${NC}"
sudo nft delete table inet countersurveillance 2>/dev/null || true

echo -e "${Y}[*] Archiving configuration files...${NC}"
if [ -f /etc/nftables.d/countersurveillance.nft ]; then
    sudo mv /etc/nftables.d/countersurveillance.nft "/etc/nftables.d/countersurveillance.nft.uninstalled.$(date +%Y%m%d%H%M%S)"
fi

sudo rm -f /etc/systemd/system/countersurveillance-block.service \
           /etc/systemd/system/chronosink.service \
           /etc/systemd/system/countersurveillance-refresh.service \
           /etc/systemd/system/countersurveillance-refresh.timer
sudo systemctl daemon-reload

echo -e "${G}[+] Provisioner teardown complete. Host firewall tables remain untouched.${NC}"
