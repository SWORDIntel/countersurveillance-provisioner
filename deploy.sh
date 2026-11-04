#!/usr/bin/env bash
# deploy.sh — Turnkey Counter-Surveillance & ChronoSink Provisioner
# Hardened with Atomic Rollback Watchdog and Standalone Autonomous Deception
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
    echo -e "${CY}=== Counter-Surveillance & ChronoSink Turnkey Provisioner ===${NC}"
    echo -e "${CY}Usage:${NC}"
    echo "  $0 [auto|all]                  # Fully automatic standalone deployment (Steps 1-5, default)"
    echo "  $0 filter                      # Deploy packet filter & anti-recon rules only"
    echo "  $0 local-daemon                # Deploy ChronoSink Go daemon + filter"
    echo "  $0 install-refresh             # Install suite to /opt + daily egress whitelist refresh timer"
    echo "  $0 remote <user@host> [cmd]    # Provision remote node via SSH (default cmd: auto)"
    echo "  $0 uninstall                   # Safe teardown of countersurveillance table and services"
    echo "  $0 --help                      # Show this help menu"
    exit 0
}

clean_slate_reset() {
    echo -e "\n${Y}[*] Step 1: Clean-slate undo/reset of existing counter-surveillance configs...${NC}"

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

ensure_event_dirs() {
    sudo mkdir -p /opt/chronosink /var/log/chronosink /etc/chronosink /opt/qihse-data/events
    sudo chmod 1777 /opt/qihse-data/events 2>/dev/null || true
    sudo chmod 1777 /var/log/chronosink 2>/dev/null || true
}

install_logrotate() {
    echo "[*] Installing logrotate definitions..."
    sudo mkdir -p /etc/logrotate.d

    cat <<'EOF' | sudo tee /etc/logrotate.d/chronosink >/dev/null
/var/log/chronosink/*.jsonl /opt/qihse-data/events/*.jsonl {
    rotate 7
    size 50M
    compress
    copytruncate
    missingok
    notifempty
}
EOF
    sudo chmod 0644 /etc/logrotate.d/chronosink

    cat <<'EOF' | sudo tee /etc/logrotate.d/cs-egress-drops >/dev/null
/var/log/cs-egress-drops.log {
    rotate 14
    size 100M
    compress
    copytruncate
    missingok
    notifempty
}
EOF
    sudo chmod 0644 /etc/logrotate.d/cs-egress-drops
}

deploy_chronosink_daemon() {
    echo -e "\n${CY}=== Step 2: Deploying ChronoSink Go Daemon on Local Host ===${NC}"

    ensure_event_dirs
    install_logrotate
    ARCH=$(uname -m)
    BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink-linux-amd64"
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
        BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink-linux-arm64"
    fi

    if [ ! -f "${BIN_SOURCE}" ] && [ -f "${SCRIPT_DIR}/honeypot/bin/chronosink" ]; then
        BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink"
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
    sudo systemctl restart chronosink.service

    echo -e "${G}[+] ChronoSink Go daemon deployed and active.${NC}"
}

deploy_filter() {
    echo -e "\n${CY}=== Step 3: Deploying In-Kernel Packet Filter (with Watchdog) ===${NC}"
    ensure_event_dirs
    install_logrotate
    python3 "${SCRIPT_DIR}/tools/update_blacklist.py"

    echo "[*] Preflight syntax validation..."
    sudo nft -c -f "${CONFIG_NFT}"

    sudo mkdir -p /etc/nftables.d
    BACKUP_FILE="/etc/nftables.d/countersurveillance.nft.bak.$(date +%Y%m%d%H%M%S)"

    # Backup existing table if active, or initialize clean rollback target.
    # The dump must start with a table reset: replaying a bare dump onto a live
    # table only appends rules, it does not restore the previous state.
    if sudo nft list table inet countersurveillance >/dev/null 2>&1; then
        echo "[*] Backing up existing table to ${BACKUP_FILE}..."
        {
            printf 'table inet countersurveillance\ndelete table inet countersurveillance\n'
            sudo nft list table inet countersurveillance
        } | sudo tee "${BACKUP_FILE}" >/dev/null
    else
        echo "[*] Initializing rollback target for clean deletion..."
        printf 'table inet countersurveillance\ndelete table inet countersurveillance\n' | sudo tee "${BACKUP_FILE}" >/dev/null
    fi

    # Arm Rollback Watchdog (detached, immune to SIGHUP, disarm file flag)
    WATCHDOG_DISARM="/tmp/cs_watchdog_disarm.$$"
    rm -f "$WATCHDOG_DISARM"
    (
        trap '' HUP
        sleep 60
        if [ ! -f "$WATCHDOG_DISARM" ]; then
            sudo nft -f "$BACKUP_FILE" 2>/dev/null || true
            logger -t cs-watchdog "Rollback watchdog fired after timeout"
        fi
        rm -f "$WATCHDOG_DISARM" "$BACKUP_FILE"
    ) </dev/null >/dev/null 2>&1 &
    WATCHDOG_PID=$!

    echo "[*] Installing ruleset and restarting service..."
    sudo cp "${CONFIG_NFT}" /etc/nftables.d/countersurveillance.nft
    sudo cp "${SERVICE_FILE}" /etc/systemd/system/countersurveillance-block.service

    sudo systemctl daemon-reload
    sudo systemctl enable countersurveillance-block.service
    sudo systemctl restart countersurveillance-block.service

    echo "[*] Running post-deployment verification..."
    if bash "${VERIFY_SCRIPT}"; then
        touch "$WATCHDOG_DISARM"
        kill "$WATCHDOG_PID" 2>/dev/null || true
        sudo rm -f "$BACKUP_FILE" "$WATCHDOG_DISARM" 2>/dev/null || true

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
        touch "$WATCHDOG_DISARM"
        kill "$WATCHDOG_PID" 2>/dev/null || true
        if [ -f "${BACKUP_FILE}" ]; then
            sudo nft -f "${BACKUP_FILE}" 2>/dev/null || true
            sudo rm -f "${BACKUP_FILE}" 2>/dev/null || true
        fi
        sudo rm -f "$WATCHDOG_DISARM" 2>/dev/null || true
        exit 1
    fi
}

deploy_refresh_units() {
    echo -e "\n${CY}=== Step 4: Installing Daily Egress Whitelist Refresh Timer ===${NC}"
    INSTALL_DIR="/opt/countersurveillance"

    sudo mkdir -p "${INSTALL_DIR}"
    if command -v rsync &>/dev/null; then
        sudo rsync -a --delete \
            --exclude '.git' --exclude 'honeypot/bin' \
            "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
    else
        sudo cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/"
        sudo rm -rf "${INSTALL_DIR}/.git" "${INSTALL_DIR}/honeypot/bin"
    fi

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

deploy_standalone() {
    echo -e "\n${CY}================================================================${NC}"
    echo -e "${CY}   Turnkey Standalone Counter-Surveillance Node Deployment       ${NC}"
    echo -e "${CY}================================================================${NC}"

    # Step 1: Clean-slate undo/reset any prior configs
    clean_slate_reset

    # Step 2: Deploy ChronoSink Go daemon
    deploy_chronosink_daemon

    # Step 3: Deploy in-kernel packet filter
    deploy_filter

    # Step 4: Deploy daily refresh timer
    deploy_refresh_units

    # Step 5: Run verify.sh diagnostics and report full success
    echo -e "\n${CY}=== Step 5: Full Node Diagnostics & Verification ===${NC}"
    bash "${VERIFY_SCRIPT}"

    echo -e "\n${G}[✓] Standalone counter-surveillance node fully deployed, verified, and operational!${NC}"
}

deploy_local_daemon() {
    deploy_chronosink_daemon
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

deploy_remote() {
    local TARGET="$1"
    local SUB_CMD="${2:-auto}"
    echo -e "\n${CY}=== Provisioning Remote Node: ${TARGET} (Action: ${SUB_CMD}) ===${NC}"

    python3 "${SCRIPT_DIR}/tools/update_blacklist.py"
    echo "[*] Transferring provisioner suite to ${TARGET}..."
    ssh "${TARGET}" "mkdir -p /tmp/cs-provisioner"
    scp -rq "${SCRIPT_DIR}/"* "${TARGET}:/tmp/cs-provisioner/"

    echo "[*] Executing ${SUB_CMD} on ${TARGET} with Remote Rollback Watchdog..."
    ssh "${TARGET}" bash -s << EOF
set -euo pipefail
cd /tmp/cs-provisioner
chmod +x install.sh deploy.sh verify.sh uninstall.sh tools/*.sh tools/*.py honeypot/bin/* 2>/dev/null || true

echo "[*] Remote preflight syntax validation..."
sudo -n nft -c -f configs/countersurveillance.nft

# Backup existing table or initialize clean rollback target
BACKUP_FILE="/tmp/cs_remote_rollback.nft"
if sudo -n nft list table inet countersurveillance >/dev/null 2>&1; then
    {
        printf 'table inet countersurveillance\ndelete table inet countersurveillance\n'
        sudo -n nft list table inet countersurveillance
    } | sudo -n tee "\${BACKUP_FILE}" >/dev/null
else
    printf 'table inet countersurveillance\ndelete table inet countersurveillance\n' | sudo -n tee "\${BACKUP_FILE}" >/dev/null
fi

# Arm Rollback Watchdog (detached, immune to SIGHUP, disarm file flag)
WATCHDOG_DISARM="/tmp/cs_watchdog_disarm.\$\$"
rm -f "\${WATCHDOG_DISARM}"
(
    trap '' HUP
    sleep 60
    if [ ! -f "\${WATCHDOG_DISARM}" ]; then
        sudo -n nft -f "\${BACKUP_FILE}" 2>/dev/null || true
        logger -t cs-watchdog "Rollback watchdog fired after timeout"
    fi
    rm -f "\${WATCHDOG_DISARM}" "\${BACKUP_FILE}"
) </dev/null >/dev/null 2>&1 &
WATCHDOG_PID=\$!

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
    ./install.sh ${SUB_CMD}

# Disarm watchdog on success
touch "\${WATCHDOG_DISARM}"
kill "\${WATCHDOG_PID}" 2>/dev/null || true
sudo -n rm -f "\${BACKUP_FILE}" "\${WATCHDOG_DISARM}" 2>/dev/null || true
echo "[✓] Remote deployment successful. Watchdog disarmed."

rm -rf /tmp/cs-provisioner
EOF

    echo -e "${G}[+] Remote node ${TARGET} successfully provisioned and verified!${NC}"
}

ACTION="${1:-auto}"

case "$ACTION" in
    ""|auto|all)
        deploy_standalone
        ;;
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
    remote)
        if [ $# -lt 2 ]; then
            echo -e "${R}[-] Missing remote host argument.${NC}"
            usage
            exit 1
        fi
        deploy_remote "$2" "${3:-auto}"
        ;;
    uninstall)
        sudo bash "${SCRIPT_DIR}/uninstall.sh"
        ;;
    cluster|hub|spoke-tunnel)
        echo -e "${R}[-] Legacy command '$ACTION' has been retired.${NC}"
        echo -e "${Y}[*] Autonomous standalone architecture is now standard: every machine has its own local ChronoSink deception sink and filter.${NC}"
        echo -e "${Y}[*] Run '$0' or './install.sh' with no arguments to deploy a complete standalone node.${NC}"
        exit 1
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo -e "${R}[-] Unknown action: $1${NC}"
        usage
        exit 1
        ;;
esac
