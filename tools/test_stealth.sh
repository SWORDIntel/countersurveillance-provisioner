#!/usr/bin/env bash
# test_stealth.sh — Anti-Reconnaissance & Stealth Test Suite
set -euo pipefail

CY='\033[1;36m'
G='\033[1;32m'
Y='\033[1;33m'
R='\033[1;31m'
NC='\033[0m'

TARGET="${1:-127.0.0.1}"

echo -e "${CY}=====================================================${NC}"
echo -e "${CY}   Stealth & Evasion Active Probing Test Suite       ${NC}"
echo -e "${CY}   Target: ${TARGET}${NC}"
echo -e "${CY}=====================================================${NC}"

echo -n "[*] Inspecting active nftables drop counters... "
sudo nft list table inet countersurveillance | grep -E "(drop|counter)"

echo -e "\n${G}[+] Stealth test complete.${NC}"
