#!/usr/bin/env bash
# deploy.sh — Turnkey Counter-Surveillance & ChronoSink Provisioner
# Hardened with Atomic Rollback Watchdog and Standalone Autonomous Deception
set -euo pipefail

SUDO=()
if (( EUID != 0 )); then
    SUDO=(sudo)
fi

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
    "${SUDO[@]}" systemctl stop countersurveillance-block.service chronosink.service countersurveillance-refresh.timer countersurveillance-refresh.service 2>/dev/null || true

    # 2. Flush and delete any existing countersurveillance table
    if "${SUDO[@]}" nft list table inet countersurveillance >/dev/null 2>&1; then
        echo "[*] Deleting existing table inet countersurveillance..."
        "${SUDO[@]}" nft delete table inet countersurveillance 2>/dev/null || true
    fi

    # 3. Clean up stale backup or temporary artifacts (preserving active rollback files)
    "${SUDO[@]}" rm -f /etc/nftables.d/countersurveillance.nft.bak.* /etc/nftables.d/countersurveillance.nft.uninstalled.* 2>/dev/null || true
    "${SUDO[@]}" rm -f /tmp/cs_temp_* 2>/dev/null || true

    # 4. Remove stale installed ruleset so fresh config is guaranteed to overwrite
    "${SUDO[@]}" rm -f /etc/nftables.d/countersurveillance.nft 2>/dev/null || true
    "${SUDO[@]}" mkdir -p /etc/nftables.d /etc/countersurveillance

    echo -e "${G}[+] Clean-slate reset complete.${NC}"
}

ensure_event_dirs() {
    "${SUDO[@]}" mkdir -p /opt/chronosink /var/log/chronosink /etc/chronosink /opt/qihse-data/events
    "${SUDO[@]}" chmod 1777 /opt/qihse-data/events 2>/dev/null || true
    "${SUDO[@]}" chmod 1777 /var/log/chronosink 2>/dev/null || true
}

install_logrotate() {
    echo "[*] Installing logrotate definitions..."
    "${SUDO[@]}" mkdir -p /etc/logrotate.d

    # Install from configs/ rather than an inline copy. The two drifted, and only
    # the inline one ever reached a host -- so a fix applied to the committed
    # file changed nothing on any machine.
    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/cs-egress-drops.logrotate" /etc/logrotate.d/cs-egress-drops

    # The ChronoSink drop-in belongs only on a host that runs the daemon: its `su`
    # names an account a policy-only node does not have, and logrotate treats an
    # unknown user in a drop-in as a parse error and skips every file in it.
    if "${SUDO[@]}" test -x /opt/chronosink/chronosink; then
        "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/chronosink.logrotate" /etc/logrotate.d/chronosink
    else
        "${SUDO[@]}" rm -f /etc/logrotate.d/chronosink
    fi
}

port_80_should_stay_free() {
    if [[ "${CHRONOSINK_ALLOW_PORT_80:-0}" =~ ^(1|true|yes|on)$ ]]; then
        return 1
    fi
    if [[ "${CHRONOSINK_DISABLE_PORT_80:-0}" =~ ^(1|true|yes|on)$ ]]; then
        return 0
    fi
    local svc
    for svc in caddy nginx apache2 httpd haproxy traefik; do
        if "${SUDO[@]}" systemctl is-active --quiet "${svc}.service" 2>/dev/null || \
           "${SUDO[@]}" systemctl is-enabled --quiet "${svc}.service" 2>/dev/null; then
            return 0
        fi
    done
    if [ -d /etc/letsencrypt/live ] || command -v certbot &>/dev/null; then
        return 0
    fi
    if ss -Htlpn 'sport = :80' 2>/dev/null | grep -vq 'chronosink'; then
        return 0
    fi
    return 1
}

resolve_chronosink_env() {
    local raw_ports="${CHRONOSINK_RAW_PORTS:-9445,23,445,5555,8291}"
    local http_ports="${CHRONOSINK_HTTP_PORTS:-}"
    local disable_80="${CHRONOSINK_DISABLE_PORT_80:-0}"
    local acme_webroot="${CHRONOSINK_ACME_WEBROOT:-/var/www/acme-challenge}"

    if port_80_should_stay_free; then
        disable_80="1"
        if [ -z "${http_ports}" ]; then
            http_ports="9080,8080,8443"
        else
            http_ports=$(printf '%s' "${http_ports}" | tr ',' '\n' | awk '$1 != "" && $1 != "80"' | paste -sd ',' -)
        fi
        echo "[*] Leaving port 80 free for web/TLS & Let's Encrypt HTTP-01 (ChronoSink HTTP ports: ${http_ports})."
    elif [ -z "${http_ports}" ]; then
        http_ports="9080,8080,8443,80"
    fi

    RESOLVED_CHRONOSINK_HTTP_PORTS="${http_ports}"
    RESOLVED_CHRONOSINK_RAW_PORTS="${raw_ports}"
    RESOLVED_CHRONOSINK_DISABLE_80="${disable_80}"
    RESOLVED_CHRONOSINK_ACME_WEBROOT="${acme_webroot}"
}

deploy_chronosink_daemon() {
    echo -e "\n${CY}=== Step 2: Deploying ChronoSink Go Daemon on Local Host ===${NC}"

    ensure_event_dirs
    install_logrotate
    resolve_chronosink_env
    ARCH=$(uname -m)
    BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink-linux-amd64"
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
        BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink-linux-arm64"
    fi

    if [ ! -f "${BIN_SOURCE}" ] && [ -f "${SCRIPT_DIR}/honeypot/bin/chronosink" ]; then
        BIN_SOURCE="${SCRIPT_DIR}/honeypot/bin/chronosink"
    fi

    echo "[*] Installing binary (${ARCH}) to /opt/chronosink/chronosink..."
    "${SUDO[@]}" install -m 0755 "${BIN_SOURCE}" /opt/chronosink/chronosink.new
    "${SUDO[@]}" mv -f /opt/chronosink/chronosink.new /opt/chronosink/chronosink

    cat <<EOF | "${SUDO[@]}" tee /etc/chronosink/chronosink.env > /dev/null
CITADEL_HOST=${CITADEL_HOST:-192.168.1.91}
CITADEL_PORT=${CITADEL_PORT:-17872}
QIHSE_EVENTS_FILE=${QIHSE_EVENTS_FILE:-/opt/qihse-data/events/countersurveillance_alerts.jsonl}
CHRONOSINK_HTTP_PORTS=${RESOLVED_CHRONOSINK_HTTP_PORTS}
CHRONOSINK_RAW_PORTS=${RESOLVED_CHRONOSINK_RAW_PORTS}
CHRONOSINK_DISABLE_PORT_80=${RESOLVED_CHRONOSINK_DISABLE_80}
CHRONOSINK_ACME_WEBROOT=${RESOLVED_CHRONOSINK_ACME_WEBROOT}
EOF
    if [ -n "${CHRONOSINK_ACME_PROXY:-}" ]; then
        printf 'CHRONOSINK_ACME_PROXY=%s\n' "${CHRONOSINK_ACME_PROXY}" | "${SUDO[@]}" tee -a /etc/chronosink/chronosink.env > /dev/null
    fi

    # The daemon must own its evidence log, so it needs a stable account: a
    # DynamicUser UID changes every start and can never own a persistent file.
    # Stop the unit first -- while it runs, nss-systemd resolves this name to a
    # transient UID and useradd refuses the name as taken.
    "${SUDO[@]}" systemctl stop chronosink.service 2>/dev/null || true
    if ! grep -q '^chronosink:' /etc/passwd; then
        "${SUDO[@]}" useradd --system --user-group --no-create-home \
            --shell /usr/sbin/nologin --comment "ChronoSink deception daemon" chronosink
    fi
    "${SUDO[@]}" install -d -m 0750 -o chronosink -g chronosink /var/log/chronosink
    if [ -f /var/log/chronosink/probes.jsonl ]; then
        "${SUDO[@]}" chown chronosink:chronosink /var/log/chronosink/probes.jsonl
        "${SUDO[@]}" chmod 0640 /var/log/chronosink/probes.jsonl
    fi
    # install_logrotate ran before the binary existed, so it withheld this
    # drop-in. Install it now that both the daemon and its account are present.
    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/chronosink.logrotate" /etc/logrotate.d/chronosink

    "${SUDO[@]}" cp "${SCRIPT_DIR}/honeypot/chronosink.service" /etc/systemd/system/chronosink.service
    "${SUDO[@]}" systemctl daemon-reload
    "${SUDO[@]}" systemctl enable --now chronosink.service
    "${SUDO[@]}" systemctl restart chronosink.service

    echo -e "${G}[+] ChronoSink Go daemon deployed and active.${NC}"
}

EGRESS_MODE_FILE="/etc/countersurveillance/egress.mode"

# Record the node's egress mode. All three keys are always written: a mode file
# that omits one lets the next reader fall back to a different default, which is
# how an audit-logging node came to render a ruleset with no audit rules.
record_egress_mode() {
    "${SUDO[@]}" mkdir -p /etc/countersurveillance
    {
        if [ "${STRICT_EGRESS:-0}" = "1" ]; then echo 'STRICT_EGRESS=1'; else echo 'STRICT_EGRESS=0'; fi
        if [ "${STRICT_ALLOW_WEB:-0}" = "1" ]; then echo 'STRICT_ALLOW_WEB=1'; else echo 'STRICT_ALLOW_WEB=0'; fi
        if [ "${STRICT_LOG_DROPS:-1}" = "1" ]; then echo 'STRICT_LOG_DROPS=1'; else echo 'STRICT_LOG_DROPS=0'; fi
    } | "${SUDO[@]}" tee "$EGRESS_MODE_FILE" >/dev/null
}

# Re-apply the recorded mode before rendering, so a re-deploy reproduces the
# policy actually in force. A refresh run carries no STRICT_* environment, and
# rendering the defaults there would silently downgrade a strict node and drop
# audit logging. An explicitly exported variable still wins.
load_egress_mode() {
    "${SUDO[@]}" test -f "$EGRESS_MODE_FILE" || return 0
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            STRICT_EGRESS|STRICT_ALLOW_WEB|STRICT_LOG_DROPS)
                if [ -z "${!key+x}" ]; then export "$key=$value"; fi
                ;;
        esac
    done < <("${SUDO[@]}" cat "$EGRESS_MODE_FILE")
}

# Render the ruleset. With a committed egress pin, every host renders the same
# whitelist; CS_REFRESH_EGRESS=1 re-resolves and re-pins deliberately.
refresh_egress() {
    load_egress_mode
    local pin="${CS_EGRESS_PIN:-${SCRIPT_DIR}/configs/egress.pinned.json}"
    if [ "${CS_REFRESH_EGRESS:-0}" = "1" ]; then
        echo "[*] Re-resolving egress whitelist (CS_REFRESH_EGRESS=1) and re-pinning..."
        python3 "${SCRIPT_DIR}/tools/update_blacklist.py" --emit-pin "$pin"
    elif [ -f "$pin" ]; then
        echo "[*] Egress whitelist from pin: ${pin}"
        echo "    (hosts converge on this list; CS_REFRESH_EGRESS=1 to re-resolve)"
        python3 "${SCRIPT_DIR}/tools/update_blacklist.py" --use-pin "$pin"
    else
        echo "[!] No egress pin at ${pin}; resolving DNS (per-host whitelist)."
        echo "    Pin once with: CS_REFRESH_EGRESS=1 $0 filter"
        python3 "${SCRIPT_DIR}/tools/update_blacklist.py"
    fi
}

deploy_filter() {
    echo -e "\n${CY}=== Step 3: Deploying In-Kernel Packet Filter (with Watchdog) ===${NC}"
    ensure_event_dirs
    install_logrotate
    refresh_egress

    echo "[*] Preflight syntax validation..."
    "${SUDO[@]}" nft -c -f "${CONFIG_NFT}"

    "${SUDO[@]}" mkdir -p /etc/nftables.d
    BACKUP_FILE="/etc/nftables.d/countersurveillance.nft.bak.$(date +%Y%m%d%H%M%S)"
    # On-disk ruleset backup must exist before the watchdog is forked: the
    # subshell inherits variables at fork time, so a later assignment would not
    # be visible to it and the file restore would be skipped.
    RULESET_FILE="/etc/nftables.d/countersurveillance.nft"
    RULESET_FILE_BACKUP="${RULESET_FILE}.pre-deploy.$(date +%Y%m%d%H%M%S)"
    if [ -f "$RULESET_FILE" ]; then
        "${SUDO[@]}" cp -a "$RULESET_FILE" "$RULESET_FILE_BACKUP" 2>/dev/null || true
    fi

    # Backup existing table if active, or initialize clean rollback target.
    # The dump must start with a table reset: replaying a bare dump onto a live
    # table only appends rules, it does not restore the previous state.
    if "${SUDO[@]}" nft list table inet countersurveillance >/dev/null 2>&1; then
        echo "[*] Backing up existing table to ${BACKUP_FILE}..."
        {
            printf 'table inet countersurveillance\ndelete table inet countersurveillance\n'
            "${SUDO[@]}" nft list table inet countersurveillance
        } | "${SUDO[@]}" tee "${BACKUP_FILE}" >/dev/null
    else
        echo "[*] Initializing rollback target for clean deletion..."
        printf 'table inet countersurveillance\ndelete table inet countersurveillance\n' | "${SUDO[@]}" tee "${BACKUP_FILE}" >/dev/null
    fi

    # Arm Rollback Watchdog (detached, immune to SIGHUP, disarm file flag)
    # 60s was too short: verification on a busy node can exceed it, and a fired
    # watchdog silently restores the previous ruleset *after* a green run, so the
    # deploy looks successful while the old policy is live. Default 600s.
    WATCHDOG_SECS="${CS_WATCHDOG_SECS:-600}"
    WATCHDOG_DISARM="/tmp/cs_watchdog_disarm.$$"
    rm -f "$WATCHDOG_DISARM"
    (
        trap '' HUP
        sleep "$WATCHDOG_SECS"
        if [ ! -f "$WATCHDOG_DISARM" ]; then
            # Restore both the on-disk ruleset and the live table: restoring
            # only the table leaves a broken file for the next boot.
            if [ -f "${RULESET_FILE_BACKUP:-}" ]; then
                "${SUDO[@]}" cp -a "$RULESET_FILE_BACKUP" "$RULESET_FILE" 2>/dev/null || true
            fi
            "${SUDO[@]}" nft -f "$BACKUP_FILE" 2>/dev/null || true
            logger -t cs-watchdog -p daemon.alert \
                "Rollback watchdog fired after ${WATCHDOG_SECS}s; previous ruleset restored"
        fi
        rm -f "$WATCHDOG_DISARM" "$BACKUP_FILE"
    ) </dev/null >/dev/null 2>&1 &
    WATCHDOG_PID=$!

    echo "[*] Installing ruleset and restarting service..."
    "${SUDO[@]}" cp "${CONFIG_NFT}" "$RULESET_FILE"
    # Integrity assertion: the file that actually landed must be the file that was
    # validated. A silent rewrite (stale watchdog, concurrent refresh, editor) is
    # otherwise invisible once the table reports healthy.
    SHA_WANT=$(sha256sum "${CONFIG_NFT}" | cut -d' ' -f1)
    SHA_GOT=$("${SUDO[@]}" sha256sum "$RULESET_FILE" | cut -d' ' -f1)
    if [ "$SHA_WANT" != "$SHA_GOT" ]; then
        echo -e "${R}[-] Installed ruleset hash mismatch${NC}"
        echo "    expected ${SHA_WANT}"
        echo "    installed ${SHA_GOT}"
        logger -t cs-deploy -p daemon.alert \
            "ruleset hash mismatch after install (expected ${SHA_WANT}, got ${SHA_GOT}); aborting"
        exit 1
    fi
    echo "[+] Ruleset installed and hash-verified (sha256 ${SHA_WANT:0:16}…)"
    # Perimeter guard: atomic apply + verification + loud alerting. Installed
    # before the unit is (re)started, since the unit now execs it.
    "${SUDO[@]}" install -m 0755 "${SCRIPT_DIR}/tools/nft_guard.py" /usr/local/sbin/nft-guard.py
    "${SUDO[@]}" cp "${SERVICE_FILE}" /etc/systemd/system/countersurveillance-block.service
    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-alert.service" /etc/systemd/system/
    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-health.service" /etc/systemd/system/
    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-health.timer" /etc/systemd/system/

    "${SUDO[@]}" systemctl daemon-reload
    "${SUDO[@]}" systemctl enable countersurveillance-block.service
    "${SUDO[@]}" systemctl restart countersurveillance-block.service
    # The timer is what notices a table that did not come back after a reboot or
    # was flushed by a competing tool. Installing the unit without enabling it
    # leaves the health check permanently inert.
    "${SUDO[@]}" systemctl enable --now countersurveillance-health.timer

    echo "[*] Running post-deployment verification..."
    POST_VERIFY_OK=0
    if bash "${VERIFY_SCRIPT}"; then
        # Re-assert integrity: a fired watchdog or a concurrent refresh can rewrite
        # the ruleset while verification runs, leaving a green run over old policy.
        SHA_NOW=$("${SUDO[@]}" sha256sum "$RULESET_FILE" | cut -d' ' -f1)
        if [ "$SHA_NOW" = "$SHA_WANT" ]; then
            POST_VERIFY_OK=1
        else
            echo -e "${R}[-] Ruleset changed during deployment${NC}"
            echo "    expected ${SHA_WANT}"
            echo "    now      ${SHA_NOW}"
            logger -t cs-deploy -p daemon.alert \
                "ruleset hash changed during deploy (${SHA_WANT:0:16} -> ${SHA_NOW:0:16})"
        fi
    fi
    if [ "$POST_VERIFY_OK" = "1" ]; then
        touch "$WATCHDOG_DISARM"
        kill "$WATCHDOG_PID" 2>/dev/null || true
        "${SUDO[@]}" rm -f "$BACKUP_FILE" "$WATCHDOG_DISARM" 2>/dev/null || true

        # Record the node's egress mode so the refresh timer redeploys with the
        # same policy instead of silently downgrading a strict node to accept.
        record_egress_mode
        echo -e "${G}[+] Deployment verified. Rollback watchdog disarmed.${NC}"
        echo "[+] Egress mode recorded: $("${SUDO[@]}" cat /etc/countersurveillance/egress.mode)"
    else
        echo -e "${R}[-] Verification failed! Reverting ruleset immediately...${NC}"
        touch "$WATCHDOG_DISARM"
        kill "$WATCHDOG_PID" 2>/dev/null || true
        # Restore the on-disk ruleset as well as the live table.
        if [ -f "${RULESET_FILE_BACKUP:-}" ]; then
            "${SUDO[@]}" cp -a "$RULESET_FILE_BACKUP" "$RULESET_FILE" 2>/dev/null || true
        fi
        if [ -f "${BACKUP_FILE}" ]; then
            "${SUDO[@]}" nft -f "${BACKUP_FILE}" 2>/dev/null || true
            "${SUDO[@]}" rm -f "${BACKUP_FILE}" 2>/dev/null || true
        fi
        "${SUDO[@]}" rm -f "$WATCHDOG_DISARM" 2>/dev/null || true
        exit 1
    fi
}

deploy_refresh_units() {
    echo -e "\n${CY}=== Step 4: Installing Daily Egress Whitelist Refresh Timer ===${NC}"
    INSTALL_DIR="/opt/countersurveillance"

    "${SUDO[@]}" mkdir -p "${INSTALL_DIR}"
    if command -v rsync &>/dev/null; then
        "${SUDO[@]}" rsync -a --delete \
            --exclude '.git' --exclude 'honeypot/bin' \
            "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
    else
        "${SUDO[@]}" cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/"
        "${SUDO[@]}" rm -rf "${INSTALL_DIR}/.git" "${INSTALL_DIR}/honeypot/bin"
    fi

    "${SUDO[@]}" mkdir -p /etc/countersurveillance
    if [ ! -f /etc/countersurveillance/egress.mode ]; then
        # Derive the mode from the ruleset actually installed, so a node already
        # running strict is never silently downgraded to accept by the refresh.
        if "${SUDO[@]}" grep -qE 'hook (output|forward).*policy drop' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
            {
                echo 'STRICT_EGRESS=1'
                if "${SUDO[@]}" grep -qE 'tcp dport \{ 22, 80, 443 \}' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
                    echo 'STRICT_ALLOW_WEB=1'
                else
                    echo 'STRICT_ALLOW_WEB=0'
                fi
                if "${SUDO[@]}" grep -qE 'log prefix "cs-audit' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
                    echo 'STRICT_LOG_DROPS=1'
                else
                    echo 'STRICT_LOG_DROPS=0'
                fi
            } | "${SUDO[@]}" tee /etc/countersurveillance/egress.mode >/dev/null
            echo "[*] Detected strict egress in the installed ruleset; recording STRICT_EGRESS=1."
        else
            # Derive logging from the audit rules actually present, and always
            # write all three keys so no reader has to guess a default.
            {
                echo 'STRICT_EGRESS=0'
                echo 'STRICT_ALLOW_WEB=0'
                if "${SUDO[@]}" grep -qE 'log prefix "cs-audit' /etc/nftables.d/countersurveillance.nft 2>/dev/null; then
                    echo 'STRICT_LOG_DROPS=1'
                else
                    echo 'STRICT_LOG_DROPS=0'
                fi
            } | "${SUDO[@]}" tee /etc/countersurveillance/egress.mode >/dev/null
            echo "[*] Installed ruleset uses accept policy; recording STRICT_EGRESS=0."
        fi
    fi

    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-refresh.service" /etc/systemd/system/
    "${SUDO[@]}" install -m 0644 "${SCRIPT_DIR}/configs/countersurveillance-refresh.timer" /etc/systemd/system/
    "${SUDO[@]}" systemctl daemon-reload
    "${SUDO[@]}" systemctl enable --now countersurveillance-refresh.timer
    # Health timer: detects a perimeter that vanished after boot and alerts.
    "${SUDO[@]}" systemctl enable --now countersurveillance-health.timer

    echo -e "${G}[+] Refresh timer installed (mode: $("${SUDO[@]}" cat /etc/countersurveillance/egress.mode))${NC}"
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

    resolve_chronosink_env
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
        -e CHRONOSINK_HTTP_PORTS="${RESOLVED_CHRONOSINK_HTTP_PORTS}" \
        -e CHRONOSINK_RAW_PORTS="${RESOLVED_CHRONOSINK_RAW_PORTS}" \
        -e CHRONOSINK_DISABLE_PORT_80="${RESOLVED_CHRONOSINK_DISABLE_80}" \
        -e CHRONOSINK_ACME_WEBROOT="${RESOLVED_CHRONOSINK_ACME_WEBROOT}" \
        chronosink:latest

    deploy_filter
    echo -e "${G}[+] Local ChronoSink container running and telemetry linked to QIHSE!${NC}"
}

deploy_remote() {
    local TARGET="$1"
    local SUB_CMD="${2:-auto}"
    echo -e "\n${CY}=== Provisioning Remote Node: ${TARGET} (Action: ${SUB_CMD}) ===${NC}"

    refresh_egress
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
    # Same fuse as the node-side deploy: verification must not outlive it, or a
    # fired watchdog silently restores the old table after a green run.
    sleep "\${CS_WATCHDOG_SECS:-600}"
    if [ ! -f "\${WATCHDOG_DISARM}" ]; then
        sudo -n nft -f "\${BACKUP_FILE}" 2>/dev/null || true
        logger -t cs-watchdog -p daemon.alert \
            "Remote rollback watchdog fired after \${CS_WATCHDOG_SECS:-600}s"
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
        "${SUDO[@]}" bash "${SCRIPT_DIR}/uninstall.sh"
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
