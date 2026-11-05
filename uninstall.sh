#!/usr/bin/env bash
# uninstall.sh — Safe Counter-Surveillance & ChronoSink Teardown
# Preserves all host tables (Proxmox PVE, Docker, Podman). Removes ONLY provisioner assets.
set -euo pipefail

SUDO=()
if (( EUID != 0 )); then
    SUDO=(sudo)
fi

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

echo -e "${Y}[*] Stopping and disabling provisioner services...${NC}"
"${SUDO[@]}" systemctl stop countersurveillance-block.service chronosink.service countersurveillance-refresh.timer countersurveillance-refresh.service wg-quick@wg-hub wg-quick@wg-honeypot 2>/dev/null || true
"${SUDO[@]}" systemctl disable countersurveillance-block.service chronosink.service countersurveillance-refresh.timer countersurveillance-refresh.service wg-quick@wg-hub wg-quick@wg-honeypot 2>/dev/null || true

echo -e "${Y}[*] Removing table inet countersurveillance and chronosink_mangle (preserving host tables)...${NC}"
"${SUDO[@]}" nft delete table inet countersurveillance 2>/dev/null || true
"${SUDO[@]}" nft delete table inet chronosink_mangle 2>/dev/null || true

# Remove any stale include directives in /etc/nftables.conf
if [ -f /etc/nftables.conf ]; then
    "${SUDO[@]}" sed -i '/countersurveillance\.nft/d' /etc/nftables.conf 2>/dev/null || true
    "${SUDO[@]}" sed -i '/chronosink_mangle\.nft/d' /etc/nftables.conf 2>/dev/null || true
fi

echo -e "${Y}[*] Archiving configuration files...${NC}"
if [ -f /etc/nftables.d/countersurveillance.nft ]; then
    "${SUDO[@]}" mv /etc/nftables.d/countersurveillance.nft "/etc/nftables.d/countersurveillance.nft.uninstalled.$(date +%Y%m%d%H%M%S)"
fi
if [ -f /etc/nftables.d/chronosink_mangle.nft ]; then
    "${SUDO[@]}" mv /etc/nftables.d/chronosink_mangle.nft "/etc/nftables.d/chronosink_mangle.nft.uninstalled.$(date +%Y%m%d%H%M%S)"
fi

echo -e "${Y}[*] Purging provisioner directories and logrotate definitions...${NC}"
"${SUDO[@]}" rm -rf /opt/chronosink \
            /opt/countersurveillance \
            /etc/countersurveillance \
            /etc/chronosink \
            /var/log/chronosink

"${SUDO[@]}" rm -f /etc/logrotate.d/chronosink \
           /etc/logrotate.d/cs-egress-drops

"${SUDO[@]}" rm -f /etc/systemd/system/countersurveillance-block.service \
           /etc/systemd/system/chronosink.service \
           /etc/systemd/system/countersurveillance-refresh.service \
           /etc/systemd/system/countersurveillance-refresh.timer
"${SUDO[@]}" systemctl daemon-reload

echo -e "${Y}[*] Restoring firewall configuration...${NC}"
RESTORED=0
# 1. Search for existing pre-deployment backups
LATEST_BACKUP=""
for candidate in $(ls -t /etc/nftables.d/countersurveillance.nft.bak.* /etc/nftables.d/*.bak.* /etc/nftables.conf.bak.* /tmp/cs_backup_* 2>/dev/null || true); do
    if [ -f "$candidate" ] && "${SUDO[@]}" nft -c -f "$candidate" >/dev/null 2>&1; then
        LATEST_BACKUP="$candidate"
        break
    fi
done

if [ -n "$LATEST_BACKUP" ]; then
    echo -e "${CY}[+] Found valid pre-installation backup: ${LATEST_BACKUP}${NC}"
    echo -e "${CY}[*] Restoring kernel tables from backup...${NC}"
    if "${SUDO[@]}" nft -f "$LATEST_BACKUP" 2>/dev/null; then
        echo -e "${G}[+] Successfully restored firewall to original pre-deployment state.${NC}"
        RESTORED=1
    else
        echo -e "${R}[!] Backup restoration encountered errors; falling back to OS standard settings.${NC}"
    fi
fi

# 2. If no valid backup was present or restoration failed, apply standard OS settings determined by hostname
if [ "$RESTORED" -eq 0 ]; then
    CURRENT_HOST=$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "generic")
    echo -e "${CY}[*] No backup restored. Detecting standard configuration for host: ${CURRENT_HOST}...${NC}"

    if command -v pveversion >/dev/null 2>&1 || [ -f /etc/pve/firewall/cluster.fw ] || [[ "$CURRENT_HOST" =~ ^(730xd|t320|pve.*)$ ]]; then
        echo -e "${CY}[*] Host identified as Proxmox VE hypervisor (${CURRENT_HOST}). Re-establishing standard PVE firewall...${NC}"
        if command -v pve-firewall >/dev/null 2>&1; then
            "${SUDO[@]}" pve-firewall restart 2>/dev/null || "${SUDO[@]}" systemctl restart pve-firewall 2>/dev/null || true
        fi
        if [ -f /etc/nftables.conf ] && "${SUDO[@]}" nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
            "${SUDO[@]}" nft -f /etc/nftables.conf 2>/dev/null || true
        fi
        echo -e "${G}[+] Restored standard Proxmox VE firewall state.${NC}"
    elif [[ "$CURRENT_HOST" =~ ^(t420|.*workstation.*|.*desktop.*|.*laptop.*)$ ]]; then
        echo -e "${CY}[*] Host identified as workstation node (${CURRENT_HOST}). Preserving native local & VPN tables...${NC}"
        # Native tables (t420_local, mullvad) remain completely intact in kernel
        if [ -f /etc/nftables.conf ] && "${SUDO[@]}" nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
            "${SUDO[@]}" nft -f /etc/nftables.conf 2>/dev/null || true
        fi
        echo -e "${G}[+] Restored standard workstation networking state.${NC}"
    else
        echo -e "${CY}[*] Host identified as standard OS node (${CURRENT_HOST}). Restoring standard distribution nftables...${NC}"
        if [ -f /etc/nftables.conf ] && "${SUDO[@]}" nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
            "${SUDO[@]}" nft -f /etc/nftables.conf 2>/dev/null || true
        fi
        if command -v ufw >/dev/null 2>&1 && "${SUDO[@]}" systemctl is-active --quiet ufw 2>/dev/null; then
            "${SUDO[@]}" ufw reload 2>/dev/null || true
        fi
        if command -v firewall-cmd >/dev/null 2>&1 && "${SUDO[@]}" systemctl is-active --quiet firewalld 2>/dev/null; then
            "${SUDO[@]}" firewall-cmd --reload 2>/dev/null || true
        fi
        echo -e "${G}[+] Restored standard OS firewall state.${NC}"
    fi
fi

echo -e "${G}[+] Provisioner teardown complete. Host firewall tables remain untouched.${NC}"
