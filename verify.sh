#!/usr/bin/env bash
# verify.sh — Counter-Surveillance Post-Deployment Verification Runner
set -euo pipefail

SUDO=()
SUDO_N=()
if (( EUID != 0 )); then
    SUDO=(sudo)
    SUDO_N=("${SUDO[@]}" -n)
fi

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

echo -e "${CY}=====================================================${NC}"
echo -e "${CY}   Counter-Surveillance Verification & Diagnostics   ${NC}"
echo -e "${CY}=====================================================${NC}"

# 1. Systemd Service Status
echo -n "[*] Checking firewall systemd service... "
if systemctl is-active --quiet countersurveillance-block.service; then
    echo -e "${G}ACTIVE${NC}"
else
    echo -e "${R}FAILED${NC} (Service not active)"
    exit 1
fi

# 2. Kernel Table Status
echo -n "[*] Checking nftables table in kernel... "
if "${SUDO[@]}" nft list table inet countersurveillance >/dev/null 2>&1; then
    echo -e "${G}LOADED${NC}"
else
    echo -e "${R}FAILED${NC} (Table 'countersurveillance' not in kernel)"
    exit 1
fi

# 3. DNS Egress Verification (actual A-record queries, not ICMP reachability)
echo -n "[*] Testing IPv4 DNS resolution (8.8.8.8, 1.1.1.1, 9.9.9.9)... "
DNS_OK=0
for resolver in 8.8.8.8 1.1.1.1 9.9.9.9; do
    if dig +short +time=2 +tries=1 "@${resolver}" example.com A 2>/dev/null \
        | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        DNS_OK=$((DNS_OK + 1))
    fi
done
# Fallback check against system resolver if upstream leak-protection VPN is active
if [ "${DNS_OK}" -eq 0 ] && dig +short +time=2 +tries=1 example.com A 2>/dev/null | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    DNS_OK=1
fi
if [ "${DNS_OK}" -ge 1 ]; then
    echo -e "${G}PASS${NC}"
else
    echo -e "${R}FAIL${NC} (A record returned by ${DNS_OK}/3 resolvers)"
    exit 1
fi

echo -n "[*] Testing IPv4 ICMP egress (8.8.8.8, 1.1.1.1)... "
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    echo -e "${G}PASS${NC}"
else
    echo -e "${R}FAIL${NC}"
    exit 1
fi

# 4. IPv6 Egress Verification
echo -n "[*] Testing IPv6 Connectivity (2606:4700:4700::1111)... "
if ping -6 -c 1 -W 2 2606:4700:4700::1111 >/dev/null 2>&1; then
    echo -e "${G}PASS${NC}"
else
    echo -e "${Y}SKIP / NO GLOBAL IPV6 ROUTE${NC}"
fi

# 5. Critical Repositories & API Egress
echo -n "[*] Testing GitHub Core Access (https://github.com)... "
if curl -I -s -m 5 https://github.com | grep -qE "HTTP/[123] (200|301|302)"; then
    echo -e "${G}PASS${NC}"
else
    echo -e "${R}FAIL${NC}"
    exit 1
fi

echo -n "[*] Testing PyPI Index Access (https://pypi.org)... "
if curl -I -s -m 5 https://pypi.org | grep -qE "HTTP/[123] (200|301|302)"; then
    echo -e "${G}PASS${NC}"
else
    echo -e "${R}FAIL${NC}"
    exit 1
fi

# 6. Scope separation: scanner/jail sets are INGRESS-only. The 2026-11-01
# provenance audit removed scanner networks from output/forward entirely, so
# the old "ping a Censys IP and watch it drop" test now asserts the WRONG
# behavior (an outbound drop would mean the blunt-instrument list is back).
echo -n "[*] Testing ingress/outbound scope separation... "
RULESET=$("${SUDO[@]}" nft list table inet countersurveillance 2>/dev/null || true)
fail_scope() { echo -e "${R}FAIL${NC} ($1)"; exit 1; }

if [ -z "$RULESET" ]; then fail_scope "countersurveillance table missing"; fi

for chain in output forward; do
    CHAIN_TXT=$(printf '%s\n' "$RULESET" | sed -n "/chain $chain {/,/^\t}/p")
    if printf '%s\n' "$CHAIN_TXT" | grep -qE '@(blocked_v[46]|dynamic_scanners_v[46])'; then
        fail_scope "$chain references ingress-only scanner set"
    fi
done
for setname in blocked_v4 blocked_v6 dynamic_scanners_v4 dynamic_scanners_v6; do
    if ! printf '%s\n' "$RULESET" | grep -qE "set $setname"; then
        fail_scope "ingress set $setname missing from table"
    fi
done
# The inbound references must exist where they belong.
INPUT_TXT=$(printf '%s\n' "$RULESET" | sed -n "/chain input {/,/^\t}/p")
printf '%s\n' "$INPUT_TXT" | grep -q '@blocked_v4' || fail_scope "input does not reference @blocked_v4"
echo -e "${G}PASS${NC} (scanner sets ingress-only; outbound endpoint sets present)"

# 7. ChronoSink Local Deception Status (if installed)
if systemctl is-active --quiet chronosink.service 2>/dev/null; then
    echo -n "[*] Testing ChronoSink Local Deception Engine (port 9080)... "
    if curl -s -m 3 http://127.0.0.1:9080/probe-check | grep -q "Directory traversal rejected"; then
        echo -e "${G}PASS${NC} (Responding with temporal deception)"
    else
        echo -e "${Y}ONLINE${NC}"
    fi
fi

# 8. Tunnel daemon health (guards STRICT_EGRESS rollouts: a default-deny output
# chain that loses the mesh VPN is a regression the other checks cannot see).
if systemctl is-active --quiet tailscaled 2>/dev/null; then
    echo -n "[*] Testing Tailscale mesh state... "
    if tailscale status --json 2>/dev/null | grep -q '"BackendState": *"Running"'; then
        echo -e "${G}PASS${NC}"
    else
        echo -e "${R}FAIL${NC} (tailscaled not Running)"
        exit 1
    fi
fi

if command -v wg >/dev/null 2>&1 && [ -n "$("${SUDO_N[@]}" wg show interfaces 2>/dev/null)" ]; then
    echo -n "[*] Testing WireGuard handshakes... "
    if "${SUDO_N[@]}" wg show all latest-handshakes 2>/dev/null | awk '$2 > 0 {found=1} END {exit !found}'; then
        echo -e "${G}PASS${NC}"
    else
        echo -e "${Y}WARN${NC} (no recent handshake)"
    fi
fi

# 9. Refresh Timer Status (if installed)
if systemctl is-active --quiet countersurveillance-refresh.timer 2>/dev/null; then
    echo -n "[*] Checking egress refresh timer... "
    echo -e "${G}ACTIVE${NC}"
fi

# 10. Jump Desktop Allowances & Signaling Verification
echo -n "[*] Testing Jump Desktop allowances (Fluid 5273, P2P 35384-45385, signaling)... "
JD_INPUT=$(printf '%s\n' "$RULESET" | sed -n "/chain input {/,/^\t}/p")
if printf '%s\n' "$JD_INPUT" | grep -q 'dport 5273' && printf '%s\n' "$JD_INPUT" | grep -q '35384-45385'; then
    if curl -s -m 4 --head https://api.jumpdesktop.com >/dev/null 2>&1 || curl -s -m 4 --head https://neuron.jumpdesktop.com >/dev/null 2>&1; then
        echo -e "${G}PASS${NC} (Rules active & cloud signaling reachable)"
    else
        echo -e "${G}PASS${NC} (In-kernel Fluid and P2P rules verified)"
    fi
else
    fail_scope "Jump Desktop port allowances (5273 / 35384-45385) missing from input chain"
fi

echo -e "\n${G}[+] All counter-surveillance verification checks completed successfully!${NC}"
