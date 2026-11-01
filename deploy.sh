#!/usr/bin/env bash
# deploy.sh — Turnkey Counter-Surveillance & ChronoSink Provisioner
# Hardened with Atomic Rollback Watchdog and Distributed Local Deception
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_NFT="${SCRIPT_DIR}/configs/countersurveillance.nft"
SERVICE_FILE="${SCRIPT_DIR}/configs/countersurveillance-block.service"
VERIFY_SCRIPT="${SCRIPT_DIR}/verify.sh"
ENV_FILE="${SCRIPT_DIR}/provisioner.env"

# Source environment configuration if present
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
elif [[ -f "${SCRIPT_DIR}/provisioner.env.example" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/provisioner.env.example"
fi

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

usage() {
    echo -e "${CY}Usage:${NC}"
    echo "  $0 filter                      # Deploy packet filter & anti-recon rules (with rollback watchdog)"
    echo "  $0 install-refresh             # Install suite to /opt + daily egress whitelist refresh timer"
    echo "  $0 local-daemon                # Deploy Go ChronoSink daemon locally on this PC"
    echo "  $0 local-container             # Deploy ChronoSink inside local Docker/Podman container"
    echo "  $0 spoke-tunnel <sink_ip> [pubkey] # Connect to remote sink hub over WireGuard"
    echo "  $0 hub                         # Provision this PC as central ChronoSink Hub"
    echo "  $0 remote <user@host> [cmd]    # Provision remote node via SSH with atomic rollback watchdog"
    echo "  $0 cluster                     # Provision full cluster (t420, 730xd, t320)"
    exit 1
}

deploy_filter() {
    echo -e "\n${CY}=== Deploying In-Kernel Packet Filter (with Watchdog) ===${NC}"
    python3 "${SCRIPT_DIR}/tools/update_blacklist.py"

    echo "[*] Preflight syntax validation..."
    sudo nft -c -f "${CONFIG_NFT}"

    sudo mkdir -p /etc/nftables.d
    BACKUP_FILE="/etc/nftables.d/countersurveillance.nft.bak.$(date +%Y%m%d%H%M%S)"

    # Backup existing table if active.
    # The dump must start with a table reset: replaying a bare dump onto a live
    # table only appends rules, it does not restore the previous state.
    if sudo nft list table inet countersurveillance >/dev/null 2>&1; then
        echo "[*] Backing up existing table to ${BACKUP_FILE}..."
        {
            printf 'table inet countersurveillance\ndelete table inet countersurveillance\n'
            sudo nft list table inet countersurveillance
        } | sudo tee "${BACKUP_FILE}" >/dev/null
    fi

    # Arm Rollback Watchdog (reverts in 25s if verification fails)
    WATCHDOG_PID=""
    if [ -f "${BACKUP_FILE}" ]; then
        (sleep 25 && sudo nft -f "${BACKUP_FILE}" 2>/dev/null && echo -e "\n${R}[!] Rollback Watchdog fired due to verification timeout!${NC}") &
        WATCHDOG_PID=$!
    fi

    echo "[*] Installing ruleset and restarting service..."
    sudo cp "${CONFIG_NFT}" /etc/nftables.d/countersurveillance.nft
    sudo cp "${SERVICE_FILE}" /etc/systemd/system/countersurveillance-block.service

    sudo systemctl daemon-reload
    sudo systemctl enable countersurveillance-block.service
    sudo systemctl restart countersurveillance-block.service

    echo "[*] Running post-deployment verification..."
    if bash "${VERIFY_SCRIPT}"; then
        if [ -n "$WATCHDOG_PID" ]; then
            kill "$WATCHDOG_PID" 2>/dev/null || true
        fi
        # Record the node's egress mode so the refresh timer redeploys with the
        # same policy instead of silently downgrading a strict node to accept.
        sudo mkdir -p /etc/countersurveillance
        {
            if [ "${STRICT_EGRESS:-0}" = "1" ]; then echo 'STRICT_EGRESS=1'; else echo 'STRICT_EGRESS=0'; fi
            if [ "${STRICT_ALLOW_WEB:-0}" = "1" ]; then echo 'STRICT_ALLOW_WEB=1'; else echo 'STRICT_ALLOW_WEB=0'; fi
            if [ "${STRICT_LOG_DROPS:-1}" = "1" ]; then echo 'STRICT_LOG_DROPS=1'; else echo 'STRICT_LOG_DROPS=0'; fi
        } | sudo tee /etc/countersurveillance/egress.mode >/dev/null
        echo -e "${G}[+] Deployment verified. Rollback watchdog disarmed.${NC}"
        echo "[+] Egress mode recorded: $(sudo cat /etc/countersurveillance/egress.mode)"
    else
        echo -e "${R}[-] Verification failed! Reverting ruleset immediately...${NC}"
        if [ -f "${BACKUP_FILE}" ]; then
            sudo nft -f "${BACKUP_FILE}"
        fi
        if [ -n "$WATCHDOG_PID" ]; then
            kill "$WATCHDOG_PID" 2>/dev/null || true
        fi
        exit 1
    fi
}

deploy_refresh_units() {
    echo -e "\n${CY}=== Installing Egress Whitelist Refresh Timer ===${NC}"
    INSTALL_DIR="/opt/countersurveillance"

    sudo mkdir -p "${INSTALL_DIR}"
    sudo rsync -a --delete \
        --exclude '.git' --exclude 'honeypot/bin' \
        "${SCRIPT_DIR}/" "${INSTALL_DIR}/"

    sudo mkdir -p /etc/countersurveillance
    if [ ! -f /etc/countersurveillance/egress.mode ]; then
        # Derive the mode from the ruleset actually installed, so a node already
        # running strict is never silently downgraded to accept by the refresh.
        if sudo grep -qE 'hook (output|forward).*policy drop' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
            {
                echo 'STRICT_EGRESS=1'
                if sudo grep -qE 'tcp dport \{ 22, 80, 443 \}' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
                    echo 'STRICT_ALLOW_WEB=1'
                else
                    echo 'STRICT_ALLOW_WEB=0'
                fi
                # New generator names per-direction prefixes (cs-audit-out /
                # cs-strict-fwd, ...); the old monolithic 'cs-egress-drop' is
                # gone. Match any cs- log rule so strict nodes keep logging.
                if sudo grep -qE 'log prefix "cs-' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
                    echo 'STRICT_LOG_DROPS=1'
                else
                    echo 'STRICT_LOG_DROPS=0'
                fi
            } | sudo tee /etc/countersurveillance/egress.mode >/dev/null
            echo "[*] Detected strict egress in the installed ruleset; recording STRICT_EGRESS=1."
        else
            printf 'STRICT_EGRESS=0\nSTRICT_ALLOW_WEB=0\n' | sudo tee /etc/countersurveillance/egress.mode >/dev/null
            echo "[*] Installed ruleset uses accept policy; recording STRICT_EGRESS=0."
        fi
    fi

    sudo install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-refresh.service" /etc/systemd/system/
    sudo install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-refresh.timer" /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now countersurveillance-refresh.timer

    echo -e "${G}[+] Refresh timer installed (mode: $(sudo cat /etc/countersurveillance/egress.mode))${NC}"
    systemctl list-timers countersurveillance-refresh.timer --no-pager || true
}

deploy_local_daemon() {
    echo -e "\n${CY}=== Deploying ChronoSink Go Daemon on Local PC ===${NC}"

    sudo mkdir -p /opt/chronosink /var/log/chronosink /etc/chronosink /opt/qihse-data/events
    sudo chmod 777 /opt/qihse-data/events 2>/dev/null || true
    ARCH=$(uname -m)
    BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink-linux-amd64"
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
        BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink-linux-arm64"
    fi

    echo "[*] Installing binary (${ARCH}) to /opt/chronosink/chronosink..."
    sudo cp "${BIN_SOURCE}" /opt/chronosink/chronosink
    sudo chmod 755 /opt/chronosink/chronosink

    cat <<EOF | sudo tee /etc/chronosink/chronosink.env > /dev/null
CITADEL_HOST=${CITADEL_HOST:-192.168.1.91}
CITADEL_PORT=${CITADEL_PORT:-17872}
QIHSE_EVENTS_FILE=${QIHSE_EVENTS_FILE:-/opt/qihse-data/events/countersurveillance_alerts.jsonl}
EOF

    sudo cp "${SCRIPT_DIR}/honeypot/chronosink.service" /etc/systemd/system/chronosink.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now chronosink.service

    deploy_filter
    echo -e "${G}[+] Distributed local ChronoSink active and piping evidence to QIHSE & Citadel!${NC}"
}

deploy_local_container() {
    echo -e "\n${CY}=== Deploying ChronoSink Local OCI Container ===${NC}"
    CONTAINER_ENGINE=""
    if command -v docker &>/dev/null; then
        CONTAINER_ENGINE="docker"
    elif command -v podman &>/dev/null; then
        CONTAINER_ENGINE="podman"
    else
        echo -e "${R}[-] Neither docker nor podman found on this machine.${NC}"
        exit 1
    fi

    echo "[*] Building ChronoSink container image via ${CONTAINER_ENGINE}..."
    ${CONTAINER_ENGINE} build -t chronosink:latest -f "${SCRIPT_DIR}/honeypot/Dockerfile" "${SCRIPT_DIR}/honeypot"

    echo "[*] Starting ChronoSink container on host network..."
    ${CONTAINER_ENGINE} rm -f chronosink 2>/dev/null || true
    ${CONTAINER_ENGINE} run -d --name chronosink \
        --restart unless-stopped \
        --net host \
        -v /opt/qihse-data/events:/opt/qihse-data/events \
        -v /var/log/chronosink:/var/log/chronosink \
        -e CITADEL_HOST="${CITADEL_HOST:-192.168.1.91}" \
        -e CITADEL_PORT="${CITADEL_PORT:-17872}" \
        -e QIHSE_EVENTS_FILE="${QIHSE_EVENTS_FILE:-/opt/qihse-data/events/countersurveillance_alerts.jsonl}" \
        chronosink:latest

    deploy_filter
    echo -e "${G}[+] Local ChronoSink container running and telemetry linked to QIHSE!${NC}"
}

deploy_spoke_tunnel() {
    local TARGET_SINK="${1:-${SINK_ENDPOINT}}"
    local PUBKEY="${2:-${SINK_WG_PUBKEY:-}}"
    local LOCAL_IP="${3:-${LOCAL_WG_IP:-10.200.0.2}}"

    echo -e "\n${CY}=== Establishing WireGuard Tunnel to Sink: ${TARGET_SINK} ===${NC}"
    if [[ -z "$PUBKEY" ]]; then
        echo -e "${Y}[!] Sink WireGuard public key not provided. Run deploy-hub.sh on the sink host first.${NC}"
        read -r -p "Enter Sink WireGuard Public Key: " PUBKEY
    fi

    sudo bash "${SCRIPT_DIR}/wireguard/setup-spoke.sh" "${LOCAL_IP}" "${TARGET_SINK}" "${PUBKEY}"
    deploy_filter
    echo -e "${G}[+] WireGuard tunnel established. Trapped scanner probes will route to ${TARGET_SINK}!${NC}"
}

deploy_remote() {
    local TARGET="$1"
    local SUB_CMD="${2:-filter}"
    echo -e "\n${CY}=== Provisioning Remote Node: ${TARGET} (Action: ${SUB_CMD}) ===${NC}"

    python3 "${SCRIPT_DIR}/tools/update_blacklist.py"
    echo "[*] Transferring provisioner suite to ${TARGET}..."
    ssh "${TARGET}" "mkdir -p /tmp/cs-provisioner"
    scp -rq "${SCRIPT_DIR}/"* "${TARGET}:/tmp/cs-provisioner/"

    echo "[*] Executing ${SUB_CMD} on ${TARGET} with Remote Rollback Watchdog..."
    ssh "${TARGET}" bash -s << EOF
set -euo pipefail
cd /tmp/cs-provisioner
chmod +x deploy.sh verify.sh uninstall.sh tools/*.sh tools/*.py honeypot/bin/* 2>/dev/null || true

echo "[*] Remote preflight syntax validation..."
sudo -n nft -c -f configs/countersurveillance.nft

# Backup existing table (delete-prefixed so replay restores rather than merges)
BACKUP_FILE="/tmp/cs_remote_rollback.nft"
if sudo -n nft list table inet countersurveillance >/dev/null 2>&1; then
    {
        printf 'table inet countersurveillance\ndelete table inet countersurveillance\n'
        sudo -n nft list table inet countersurveillance
    } | sudo -n tee "\${BACKUP_FILE}" >/dev/null
fi

# Arm 30-second Watchdog
WATCHDOG_PID=""
if [ -f "\${BACKUP_FILE}" ]; then
    (sleep 30 && sudo -n nft -f "\${BACKUP_FILE}" 2>/dev/null && echo "[!] Remote watchdog restored previous firewall state.") >/dev/null 2>&1 &
    WATCHDOG_PID=\$!
fi

# Execute deployment command. SSH does not forward the operator's env, and
# the generator's unexported defaults differ from deploy.sh's record step, so
# re-apply the node's recorded egress mode explicitly (defaults: permissive
# accept with drop logging, matching deploy.sh's STRICT_LOG_DROPS default).
if [ -f /etc/countersurveillance/egress.mode ]; then
    # shellcheck source=/dev/null
    . /etc/countersurveillance/egress.mode
    export STRICT_EGRESS STRICT_ALLOW_WEB STRICT_LOG_DROPS
fi
sudo -n env STRICT_EGRESS="\${STRICT_EGRESS:-0}" \
    STRICT_ALLOW_WEB="\${STRICT_ALLOW_WEB:-0}" \
    STRICT_LOG_DROPS="\${STRICT_LOG_DROPS:-1}" \
    ./deploy.sh ${SUB_CMD}

# Disarm watchdog on success
if [ -n "\${WATCHDOG_PID}" ]; then
    kill "\${WATCHDOG_PID}" 2>/dev/null || true
    sudo -n rm -f "\${BACKUP_FILE}"
    echo "[✓] Remote deployment successful. Watchdog disarmed."
fi

rm -rf /tmp/cs-provisioner
EOF

    echo -e "${G}[+] Remote node ${TARGET} successfully provisioned and verified!${NC}"
}

if [ $# -lt 1 ]; then
    usage
fi

case "$1" in
    filter)
        deploy_filter
        ;;
    install-refresh)
        deploy_refresh_units
        ;;
    local|local-daemon)
        deploy_local_daemon
        ;;
    local-container)
        deploy_local_container
        ;;
    spoke-tunnel)
        deploy_spoke_tunnel "${2:-}" "${3:-}" "${4:-}"
        ;;
    hub)
        sudo bash "${SCRIPT_DIR}/honeypot/deploy-hub.sh"
        ;;
    remote)
        if [ $# -lt 2 ]; then
            usage
        fi
        deploy_remote "$2" "${3:-filter}"
        ;;
    cluster)
        echo -e "${CY}[*] Starting cluster-wide counter-surveillance deployment...${NC}"
        deploy_filter
        deploy_remote "john@192.168.1.90" filter
        deploy_remote "john@192.168.1.95" filter
        echo -e "\n${G}[+] All cluster nodes successfully provisioned!${NC}"
        ;;
    *)
        usage
        ;;
esac
