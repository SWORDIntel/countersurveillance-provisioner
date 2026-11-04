#!/usr/bin/env bash
# install.sh — Clean-Slate Turnkey Installer for Counter-Surveillance Suite
# Overwrites and undoes any existing configs/tables first before performing deployment.
# Can be run locally or targeted across all needed machines / cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-filter}"

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

usage() {
    echo -e "${CY}=== Counter-Surveillance Clean-Slate Installer ===${NC}"
    echo -e "${CY}Usage:${NC}"
    echo "  $0 [filter]                    # Clean-slate reset & deploy packet filter (default)"
    echo "  $0 install-refresh             # Clean-slate install suite to /opt + refresh timer"
    echo "  $0 local-daemon                # Clean-slate deploy ChronoSink daemon locally"
    echo "  $0 local-container             # Clean-slate deploy ChronoSink in local container"
    echo "  $0 spoke-tunnel <sink_ip>      # Clean-slate deploy WireGuard spoke tunnel to sink"
    echo "  $0 hub                         # Clean-slate provision central ChronoSink hub"
    echo "  $0 remote <user@host> [cmd]    # Clean-slate provision remote node via SSH"
    echo "  $0 cluster                     # Clean-slate provision all cluster nodes (local + remotes)"
    echo "  $0 --help                      # Show this help menu"
    exit 0
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "help" ]]; then
    usage
fi

clean_slate_reset() {
    echo -e "${Y}[*] Undoing and resetting any existing counter-surveillance configs...${NC}"

    # 1. Stop provisioner services
    sudo systemctl stop countersurveillance-block.service chronosink.service countersurveillance-refresh.timer countersurveillance-refresh.service 2>/dev/null || true

    # 2. Flush and delete any existing countersurveillance table
    if sudo nft list table inet countersurveillance >/dev/null 2>&1; then
        echo "[*] Deleting existing table inet countersurveillance..."
        sudo nft delete table inet countersurveillance 2>/dev/null || true
    fi

    # 3. Clean up stale backup or temporary artifacts (preserving active rollback files)
    sudo rm -f /etc/nftables.d/countersurveillance.nft.bak.* /etc/nftables.d/countersurveillance.nft.uninstalled.* 2>/dev/null || true
    sudo rm -f /tmp/cs_temp_* 2>/dev/null || true

    # 4. Remove stale installed ruleset so fresh config is guaranteed to overwrite
    sudo rm -f /etc/nftables.d/countersurveillance.nft 2>/dev/null || true
    sudo mkdir -p /etc/nftables.d /etc/countersurveillance

    echo -e "${G}[+] Clean-slate reset complete.${NC}"
}

echo -e "${CY}=== Counter-Surveillance Clean-Slate Installer ===${NC}"

# If deploying to a remote host only, do not reset the local machine's firewall
if [[ "$ACTION" != "remote" ]]; then
    clean_slate_reset
fi

echo -e "${CY}[*] Proceeding with deployment: ${ACTION}...${NC}\n"
exec "${SCRIPT_DIR}/deploy.sh" "$@"
