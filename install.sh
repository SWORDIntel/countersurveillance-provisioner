#!/usr/bin/env bash
# install.sh — Clean-Slate Turnkey Installer for Counter-Surveillance Suite
# Overwrites and undoes any existing configs/tables first before performing deployment.
# Deploys a complete standalone counter-surveillance node on any machine.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-auto}"

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

usage() {
    echo -e "${CY}=== Counter-Surveillance Clean-Slate Installer ===${NC}"
    echo -e "${CY}Usage:${NC}"
    echo "  $0 [auto|all]                  # Complete turnkey standalone deployment (default)"
    echo "  $0 filter                      # Clean-slate reset & deploy packet filter only"
    echo "  $0 local-daemon                # Clean-slate deploy ChronoSink daemon + filter"
    echo "  $0 install-refresh             # Clean-slate install suite to /opt + refresh timer"
    echo "  $0 remote <user@host> [cmd]    # Clean-slate provision remote node via SSH"
    echo "  $0 uninstall                   # Safe teardown of countersurveillance table and services"
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

# If deploying to a remote host only, do not reset the local machine's firewall.
# For local sub-commands that are not auto/all, perform clean_slate_reset here
# (auto/all performs Step 1 clean_slate_reset inside deploy.sh deploy_standalone).
if [[ "$ACTION" != "remote" && "$ACTION" != "auto" && "$ACTION" != "all" ]]; then
    clean_slate_reset
fi

echo -e "${CY}[*] Proceeding with deployment: ${ACTION}...${NC}\n"

if [[ $# -gt 0 ]]; then
    shift
fi
exec "${SCRIPT_DIR}/deploy.sh" "$ACTION" "$@"
