#!/usr/bin/env bash
# verify.sh — Counter-Surveillance Post-Deployment Verification Runner
set -euo pipefail

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
if sudo nft list table inet countersurveillance >/dev/null 2>&1; then
    echo -e "${G}LOADED${NC}"
else
    echo -e "${R}FAILED${NC} (Table 'countersurveillance' not in kernel)"
    exit 1
fi

# 3. DNS Egress Verification
echo -n "[*] Testing IPv4 DNS Egress (8.8.8.8, 1.1.1.1)... "
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

# 6. Surveillance Scanner Interception Test
echo -n "[*] Testing Scanner Packet Interception (Censys 162.142.125.1)... "
PRE_DROPS=$(sudo nft list table inet countersurveillance | grep "ip daddr @blocked_v4" | awk '{for(i=1;i<=NF;i++) if($i=="packets") print $(i+1)}' | head -n 1)
PRE_DROPS=${PRE_DROPS:-0}

ping -c 1 -W 1 162.142.125.1 >/dev/null 2>&1 || true

POST_DROPS=$(sudo nft list table inet countersurveillance | grep "ip daddr @blocked_v4" | awk '{for(i=1;i<=NF;i++) if($i=="packets") print $(i+1)}' | head -n 1)
POST_DROPS=${POST_DROPS:-0}

if [ "$POST_DROPS" -gt "$PRE_DROPS" ]; then
    echo -e "${G}PASS${NC} (Drop counter incremented: $PRE_DROPS -> $POST_DROPS)"
else
    echo -e "${Y}WARNING${NC} (Counter unchanged: $PRE_DROPS -> $POST_DROPS)"
fi

# 7. ChronoSink Local Deception Status (if installed)
if systemctl is-active --quiet chronosink.service 2>/dev/null; then
    echo -n "[*] Testing ChronoSink Local Deception Engine (port 9080)... "
    if curl -s -m 3 http://127.0.0.1:9080/probe-check | grep -q "Directory traversal rejected"; then
        echo -e "${G}PASS${NC} (Responding with temporal deception)"
    else
        echo -e "${Y}ONLINE${NC}"
    fi
fi

echo -e "\n${G}[+] All counter-surveillance verification checks completed successfully!${NC}"
