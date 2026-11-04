#!/usr/bin/env python3
"""
update_blacklist.py — Threat Intelligence Collapser & Dual-Stack nftables Generator

Implements:
  1. Strict separation of Inbound Management Trust vs. Outbound Developer Egress.
  2. Full IPv4 and IPv6 parity (including @dynamic_scanners_v6).
  3. Pre-flight overlap detection to prevent self-blackholing.
  4. Local ChronoSink redirection hooks.
"""

import ipaddress
import json
import os
import socket
import sys
import tempfile
from datetime import date
from urllib.parse import urlsplit

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_PATH = os.path.join(BASE_DIR, "data", "scanner_subnets.json")
DOMAINS_PATH = os.path.join(BASE_DIR, "data", "egress_domains.json")
OUTBOUND_PATH = os.path.join(BASE_DIR, "data", "outbound_blocks.json")
OUTPUT_NFT = os.path.join(BASE_DIR, "configs", "countersurveillance.nft")

# Refuse to emit a ruleset if the domain list resolves too thinly: under
# STRICT_EGRESS an incomplete whitelist is a self-inflicted egress outage.
MIN_RESOLVE_RATIO = 0.8

# 1. Authorised Management Sources (RFC1918, Loopback, Carrier CGNAT/Tailscale)
TRUSTED_MGMT_V4 = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",    # CGNAT / Tailscale
    "169.254.0.0/16",   # Link-local
    # Operator SSH tunnel & proxy endpoints
    "89.169.111.62/32",
    "144.126.248.239/32",
]

TRUSTED_MGMT_V6 = [
    "::1/128",          # Loopback
    "fe80::/10",        # Link-local
    "fc00::/7",         # Unique Local Address (ULA)
]

# 2. Essential Outbound Developer Egress (DNS, Repos, CDNs)
ESSENTIAL_EGRESS_V4 = [
    # Core Public DNS Resolvers
    "1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32",
    "9.9.9.9/32", "149.112.112.112/32", "208.67.222.222/32", "208.67.220.220/32",
    # GitHub Core Infrastructure & Fastly/Azure CDN
    "140.82.112.0/20", "185.199.108.0/22", "192.30.252.0/22",
    "20.201.0.0/16", "20.205.0.0/16",
    # Fastly CDN (PyPI / pythonhosted.org / Debian / Rust cargo)
    "151.101.0.0/16", "199.232.0.0/16",
    # Ubuntu / Canonical Repositories
    "91.189.88.0/21", "185.125.188.0/22",
    # parrot-sabot protected engagement egress: Rayobyte proxy exit and the
    # dedicated parrot0 bridge subnet used by engagement containers
    "144.126.248.239/32", "172.18.0.0/16",
    # Operator SSH tunnel endpoint (local port forward to the proxy host)
    "89.169.111.62/32",
    # Chrony upstream time sources (time1/time2.panq.nl, leontp2.office.panq.nl)
    # Required only under STRICT_EGRESS; harmless while the policy is accept.
    "185.51.192.61/32", "185.51.192.62/32", "45.138.55.61/32"
]

ESSENTIAL_EGRESS_V6 = [
    # Core Public DNS Resolvers
    "2001:4860:4860::8888/128", "2001:4860:4860::8844/128",
    "2606:4700:4700::1111/128", "2606:4700:4700::1001/128",
    "2620:fe::fe/128", "2620:fe::9/128"
]

# Strict egress enforcement (opt-in, per node, staged rollout).
# When enabled the output and forward chains default-deny instead of
# default-accept, so @essential_egress and @trusted_mgmt become a real
# whitelist. The input chain is unaffected: management isolation is enforced
# by its explicit rules, and flipping it to drop would not add protection.
STRICT_EGRESS = os.environ.get("STRICT_EGRESS", "0") == "1"

# Workstation profile: also allow plain web egress, so a daily-driver host keeps
# working while every non-web, non-whitelisted destination stays denied.
STRICT_ALLOW_WEB = os.environ.get("STRICT_ALLOW_WEB", "0") == "1"

# Log what the strict policy actually drops (rate limited), so the egress
# profile can be observed instead of guessed.
STRICT_LOG_DROPS = os.environ.get("STRICT_LOG_DROPS", "1" if STRICT_EGRESS else "0") == "1"

# Daemons whose own traffic is trusted regardless of destination under strict
# mode: mesh VPN, Tor, the WireGuard VPN daemon, and BitTorrent (peer ports are
# dynamic — the 24h window logged 671 dst/port combos on uid 121 alone, so no
# destination allowlist can describe Transmission). Emitted only when the unit
# exists on the generating host.
TRUSTED_EGRESS_UNITS = [
    "tailscaled.service", "i2pd.service", "mullvad-daemon.service",
    "transmission-daemon.service",
]

# Existence probes run at generation time on the generating host; tests inject
# a fake by patching SYS_PROBE.
SYS_PROBE = os.path.exists


def strict_allowances(allow_web, probe=None):
    """Allowances shared by the strict and audit (shadow) output/forward chains.

    Every entry is evidence-gated by the 24-hour window analysis
    (data/window_analysis_2026-11-01.md) plus the fresh audit baseline: ports
    whose servers churn (NTP pools, resolver upstreams, SMTP relays, STUN) and
    kernel WireGuard transports, which own no cgroup and would otherwise sever
    the tunnels the cgroupv2 rules cannot see. Returns (output, forward) line
    lists; the caller appends the counter/log tail, so anything added here is
    exempt from the would-be-drop audit by construction.
    """
    probe = probe or SYS_PROBE
    web = []
    if allow_web:
        web = ['        tcp dport { 22, 80, 443 } counter accept',
               '        udp dport 443 counter accept']
    common = [
        # Pool NTP rotation defeats a static time-server allowlist.
        '        udp dport 123 counter accept',
        # Resolver upstreams churn with DHCP/learned configuration.
        '        udp dport 53 counter accept',
        '        tcp dport 53 counter accept',
        # SMTP: postfix MX delivery and MUA submission to rotating endpoints.
        '        tcp dport 25 counter accept',
        # STUN/TURN for voice/video (observed local and spoke-forwarded).
        '        udp dport 3478 counter accept',
        '        tcp dport 3478 counter accept',
        # XMPP push (Google FCM).
        '        tcp dport 5228 counter accept',
        # Kernel WireGuard transports create their UDP socket outside any
        # cgroup, so the unit rules below never match them; the relay/peer
        # listen ports are the only matchable signature (51820/51821 hubs,
        # 41641 Tailscale, 1025 observed spoke peer). Without this, strict
        # mode severs hc-backup/hc-mgmt/Tailscale handshakes.
        '        udp dport { 1025, 41641, 51820, 51821 } counter accept',
        # Jump Desktop Connect: Fluid (TCP/UDP 5273), P2P direct (UDP 35384-45385), RDP (UDP 3389)
        '        tcp dport 5273 counter accept',
        '        udp dport { 3389, 5273, 35384-45385 } counter accept',
        # DHCP client renewal and lab dnsmasq replies must survive drop policy.
        '        udp sport 68 udp dport 67 accept',
        '        udp sport 67 udp dport 68 accept',
        '        udp sport 546 udp dport 547 accept',
        # NDP neighbour-advertisement unicast replies and PMTUDv6 die when
        # dropped; the ICMPv6 control plane is infrastructure, not egress.
        '        meta l4proto ipv6-icmp accept',
    ]
    if probe("/sys/class/net/he-ipv6"):
        # HE tunnelbroker: local and forwarded inner IPv6 rides he-ipv6.
        common.append('        oifname "he-ipv6" accept')
    output_lines = ['        oifname "tailscale0" accept', '        oifname "wg*" accept'] + web + common
    forward_lines = list(output_lines)
    for unit in TRUSTED_EGRESS_UNITS:
        path = f"system.slice/{unit}"
        if probe(f"/sys/fs/cgroup/{path}"):
            level = path.count("/") + 1
            output_lines.append(f'        socket cgroupv2 level {level} "{path}" accept')
    if probe("/sys/class/net/he-ipv6"):
        # The sit driver's outer protocol-41 packets are locally generated
        # (output only); forwarded tunnel traffic is inner v6 via he-ipv6.
        output_lines.append('        ip protocol 41 accept')
    if probe("/sys/class/net/parrot0"):
        # Engagement-container transit: the parrot_sabot_egress table (higher
        # priority) owns the proxy pinning; this only must not fight it.
        forward_lines.append('        iifname "parrot0" accept')
    return output_lines, forward_lines


def resolve_domains(names, family):
    """Resolve hostnames to concrete addresses for the egress whitelist."""
    found, failed = [], []
    for name in names:
        try:
            infos = socket.getaddrinfo(name, None, family)
        except (socket.gaierror, UnicodeError) as exc:
            failed.append((name, exc))
            continue
        for info in infos:
            found.append(info[4][0])
    return sorted(set(found)), failed


def load_egress_domains():
    if not os.path.exists(DOMAINS_PATH):
        return [], []
    with open(DOMAINS_PATH) as f:
        data = json.load(f)
    return list(data.get("required", [])), list(data.get("optional", []))


def collapse_and_clean(net_strings, ip_cls):
    nets = [ip_cls(s.strip()) for s in net_strings if s.strip()]
    collapsed = list(ipaddress.collapse_addresses(nets))
    return [str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n) for n in collapsed]


def indent_elements(items):
    return ",\n".join(f"            {item}" for item in items)


def load_scoped_targets(path, scope, today=None):
    """Only reviewed, unexpired records can enter an enforcement set."""
    today = today or date.today()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    expected_version = 3 if scope == "ingress" else 1
    if data.get("schema_version") != expected_version or data.get("scope") != scope:
        raise ValueError(f"{path}: expected schema {expected_version}, scope {scope}")
    targets = data.get("targets")
    if not isinstance(targets, dict):
        raise ValueError(f"{path}: targets must be an object")
    addresses = {4: [], 6: []}
    for key, target in targets.items():
        if not isinstance(target, dict):
            raise ValueError(f"{key}: target must be an object")
        nets = []
        for family in (4, 6):
            values = target.get(f"ipv{family}", [])
            if not isinstance(values, list):
                raise ValueError(f"{key}: ipv{family} must be a list")
            for value in values:
                net = ipaddress.ip_network(value)
                if net.version != family:
                    raise ValueError(f"{key}: wrong address family: {value}")
                nets.append(net)
        if not nets:
            continue
        sources = target.get("sources", [])
        if not isinstance(sources, list) or not sources or any(
            not isinstance(s, str) or urlsplit(s).scheme != "https"
            or not urlsplit(s).hostname or urlsplit(s).username for s in sources
        ):
            raise ValueError(f"{key}: nonempty HTTPS provenance is required")
        reviewed = date.fromisoformat(target["reviewed_at"])
        expires = date.fromisoformat(target["expires_at"])
        if reviewed > today or expires <= reviewed:
            raise ValueError(f"{key}: invalid review/expiry interval")
        if scope == "ingress":
            for net in nets:
                if not net.network_address.is_global or net.is_multicast or net.is_reserved or net.is_loopback or net.is_link_local:
                    raise ValueError(f"{key}: non-global/private network rejected: {net}")
        if scope == "outbound":
            if (target.get("category") not in {"tracking", "spyware_c2"}
                    or target.get("dedicated") is not True
                    or not isinstance(target.get("evidence"), str)
                    or not target["evidence"].strip()):
                raise ValueError(f"{key}: dedicated tracking/C2 endpoint evidence required")
            for net in nets:
                if net.prefixlen != net.max_prefixlen or not net.network_address.is_global:
                    raise ValueError(f"{key}: outbound IP blocks must be exact public endpoints: {net}")
        if expires <= today:
            print(f"[!] Expired {scope} entry omitted: {key} ({expires})", file=sys.stderr)
            continue
        for net in nets:
            addresses[net.version].append(str(net))
    return addresses[4], addresses[6]


def validate_overlaps(blocked, protected, label):
    for value in blocked:
        net = ipaddress.ip_network(value)
        for allowed in protected:
            other = ipaddress.ip_network(allowed)
            if net.version == other.version and net.overlaps(other):
                raise ValueError(f"{label} {net} overlaps protected infrastructure {other}")


def main():
    raw_blocked_v4, raw_blocked_v6 = load_scoped_targets(JSON_PATH, "ingress")
    outbound_v4, outbound_v6 = load_scoped_targets(OUTBOUND_PATH, "outbound")

    trusted_v4_clean = collapse_and_clean(TRUSTED_MGMT_V4, ipaddress.ip_network)
    trusted_v6_clean = collapse_and_clean(TRUSTED_MGMT_V6, ipaddress.ip_network)

    # Merge DNS-resolved host addresses into the static egress whitelist so
    # vendor CDN moves do not break strict egress.
    required, optional = load_egress_domains()
    resolved_v4, failed_v4 = resolve_domains(required + optional, socket.AF_INET)
    resolved_v6, failed_v6 = resolve_domains(required + optional, socket.AF_INET6)
    required_failed = [n for n, _ in failed_v4 if n in required]
    for name in required_failed:
        print(f"[!] WARNING: required egress domain did not resolve: {name}", file=sys.stderr)
    total_required = len(required)
    if total_required and (total_required - len(required_failed)) / total_required < MIN_RESOLVE_RATIO:
        print(
            f"[!] SAFETY ERROR: only {total_required - len(required_failed)}/{total_required} "
            "required egress domains resolved; refusing to emit a thin whitelist.",
            file=sys.stderr,
        )
        sys.exit(3)

    egress_v4_source = ESSENTIAL_EGRESS_V4 + [f"{ip}/32" for ip in resolved_v4]
    egress_v6_source = ESSENTIAL_EGRESS_V6 + [f"{ip}/128" for ip in resolved_v6]

    egress_v4_clean = collapse_and_clean(egress_v4_source, ipaddress.ip_network)
    egress_v6_clean = collapse_and_clean(egress_v6_source, ipaddress.ip_network)
    blocked_v4_clean = collapse_and_clean(raw_blocked_v4, ipaddress.ip_network)
    blocked_v6_clean = collapse_and_clean(raw_blocked_v6, ipaddress.ip_network)
    outbound_v4_clean = collapse_and_clean(outbound_v4, ipaddress.ip_network)
    outbound_v6_clean = collapse_and_clean(outbound_v6, ipaddress.ip_network)

    # Ingress lists must not jail management or essential egress; outbound blocks
    # must not shadow essential infrastructure, even when its addresses are on shared hosting.
    protected_infrastructure = (
        TRUSTED_MGMT_V4 + TRUSTED_MGMT_V6 + egress_v4_source + egress_v6_source
    )
    validate_overlaps(blocked_v4_clean + blocked_v6_clean,
                      protected_infrastructure, "Ingress scanner")
    validate_overlaps(outbound_v4_clean + outbound_v6_clean,
                      protected_infrastructure, "Outbound endpoint")

    print(f"[+] Management Whitelist: {len(trusted_v4_clean)} v4, {len(trusted_v6_clean)} v6")
    print(f"[+] Essential Egress:     {len(egress_v4_clean)} v4, {len(egress_v6_clean)} v6 "
          f"({len(resolved_v4)} v4/{len(resolved_v6)} v6 from {len(required) + len(optional)} domains)")
    print(f"[+] Ingress Scanners:     {len(blocked_v4_clean)} v4, {len(blocked_v6_clean)} v6")
    print(f"[+] Outbound Endpoints:   {len(outbound_v4_clean)} v4, {len(outbound_v6_clean)} v6")
    print(f"[+] Output/Forward Policy: {'DROP (strict)' if STRICT_EGRESS else 'ACCEPT (whitelist advisory)'}")

    egress_policy = "drop" if STRICT_EGRESS else "accept"

    # Shadow and enforced profiles share their allowances; only OUTPUT has a
    # local socket and can use cgroup ownership. Neither grants proxy bypass.
    allowance_lines, forward_allowance_lines = [], []
    if STRICT_EGRESS or STRICT_LOG_DROPS:
        allowance_lines, forward_allowance_lines = strict_allowances(STRICT_ALLOW_WEB)
    if STRICT_LOG_DROPS:
        kind = "strict" if STRICT_EGRESS else "audit"
        # Count all matches, sample only the log. A limit must never gate a
        # drop verdict, nor follow the log it is meant to limit.
        allowance_lines += ['        counter',
                            f'        limit rate 600/minute burst 50 packets log prefix "cs-{kind}-out " group 1']
        forward_allowance_lines += ['        counter',
                                    f'        limit rate 600/minute burst 50 packets log prefix "cs-{kind}-fwd " group 1']
    allowance_block = "\n".join(allowance_lines)
    forward_allowance_block = "\n".join(forward_allowance_lines)

    # nft rejects `elements = {  }` on an empty set; declare it bare instead.
    def outbound_set(name, family, items):
        if not items:
            return f"    set {name} {{\n        type ipv{family}_addr\n        flags interval\n    }}"
        return (f"    set {name} {{\n        type ipv{family}_addr\n"
                f"        flags interval\n        elements = {{ {', '.join(items)} }}\n    }}")
    outbound_set_v4 = outbound_set("outbound_block_v4", 4, outbound_v4_clean)
    outbound_set_v6 = outbound_set("outbound_block_v6", 6, outbound_v6_clean)

    nft_template = f"""# Counter-Surveillance & Anti-Reconnaissance Packet Filter
# Generated by update_blacklist.py
# Output/Forward policy: {egress_policy}{"  # STRICT_EGRESS=1" if STRICT_EGRESS else ""}
# DO NOT EDIT DIRECTLY: Update data/scanner_subnets.json and re-run tools/update_blacklist.py.

# Idempotent Atomic Table Reset
table inet countersurveillance
delete table inet countersurveillance

table inet countersurveillance {{
    # --------------------------------------------------------------------------
    # 1. Trusted Management Ingress (RFC1918, Loopback, Tailscale, Link-Local)
    # --------------------------------------------------------------------------
    set trusted_mgmt_v4 {{
        type ipv4_addr
        flags interval
        elements = {{
{indent_elements(trusted_v4_clean)}
        }}
    }}

    set trusted_mgmt_v6 {{
        type ipv6_addr
        flags interval
        elements = {{
{indent_elements(trusted_v6_clean)}
        }}
    }}

    # --------------------------------------------------------------------------
    # 2. Essential Outbound Developer Egress (DNS, GitHub, PyPI, Repositories)
    # --------------------------------------------------------------------------
    set essential_egress_v4 {{
        type ipv4_addr
        flags interval
        elements = {{
{indent_elements(egress_v4_clean)}
        }}
    }}

    set essential_egress_v6 {{
        type ipv6_addr
        flags interval
        elements = {{
{indent_elements(egress_v6_clean)}
        }}
    }}

    # --------------------------------------------------------------------------
    # 3. Source-verified INGRESS scanner networks (not tracking destinations)
    # --------------------------------------------------------------------------
    set blocked_v4 {{
        type ipv4_addr
        flags interval
        elements = {{
{indent_elements(blocked_v4_clean)}
        }}
    }}

    set blocked_v6 {{
        type ipv6_addr
        flags interval
        elements = {{
{indent_elements(blocked_v6_clean)}
        }}
    }}

    # Independently reviewed dedicated outbound tracking / spyware endpoints.
    # Empty sets mean no such attribution has been established by this audit.
{outbound_set_v4}
{outbound_set_v6}

    chain ingress_scanner_drop {{
        limit rate 600/minute burst 50 packets log prefix "cs-in-scan " group 1
        counter drop
    }}
    chain ingress_jail_drop {{
        limit rate 600/minute burst 50 packets log prefix "cs-in-jail " group 1
        counter drop
    }}
    chain outbound_drop {{
        limit rate 600/minute burst 50 packets log prefix "cs-out-block " group 1
        counter drop
    }}
    chain forward_drop {{
        limit rate 600/minute burst 50 packets log prefix "cs-fwd-block " group 1
        counter drop
    }}

    # --------------------------------------------------------------------------
    # 4. Dynamic Auto-Trapped Scanners (24-hour INGRESS-only Jails)
    # --------------------------------------------------------------------------
    set dynamic_scanners_v4 {{
        type ipv4_addr
        size 32768
        flags dynamic,timeout
        timeout 24h
    }}

    set dynamic_scanners_v6 {{
        type ipv6_addr
        size 32768
        flags dynamic,timeout
        timeout 24h
    }}

    # --------------------------------------------------------------------------
    # PREROUTING: Local ChronoSink Deception Redirect
    # --------------------------------------------------------------------------
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;

        # Decoys belong to this host, never a VM/container transit destination.
        iifname "lo" accept
        fib daddr type != local return

        # Steer trapped scanner IPs hitting web decoys -> local ChronoSink HTTP
        ip saddr @dynamic_scanners_v4 tcp dport {{ 80, 8080, 8443 }} redirect to :9080
        ip6 saddr @dynamic_scanners_v6 tcp dport {{ 80, 8080, 8443 }} redirect to :9080

        # Steer trapped scanner IPs hitting raw decoys -> local ChronoSink Tarpit
        ip saddr @dynamic_scanners_v4 tcp dport {{ 23, 445, 5555, 8291 }} redirect to :9445
        ip6 saddr @dynamic_scanners_v6 tcp dport {{ 23, 445, 5555, 8291 }} redirect to :9445
    }}

    # --------------------------------------------------------------------------
    # INPUT: Perimeter Protection & Management Isolation
    # --------------------------------------------------------------------------
    chain input {{
        type filter hook input priority -5; policy accept;

        # Loopback traffic is trusted unconditionally
        iifname "lo" accept

        # A. Anti-Reconnaissance: Drop abnormal/manipulated TCP flags
        ct state invalid counter drop
        tcp flags & (fin|syn) == (fin|syn) counter drop
        tcp flags & (syn|rst) == (syn|rst) counter drop
        tcp flags ! fin,syn,rst,psh,ack,urg counter drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) counter drop

        # B. Conntrack: Established/related sessions bypass further checks
        ct state established,related accept

        # C. Auto-Jailed Scanner Suppression
        ip saddr @dynamic_scanners_v4 tcp dport {{ 9080, 9445 }} counter accept
        ip6 saddr @dynamic_scanners_v6 tcp dport {{ 9080, 9445 }} counter accept
        ip saddr @dynamic_scanners_v4 jump ingress_jail_drop
        ip6 saddr @dynamic_scanners_v6 jump ingress_jail_drop

        # D. Known OSINT Scanner Blocklist
        ip saddr @blocked_v4 jump ingress_scanner_drop
        ip6 saddr @blocked_v6 jump ingress_scanner_drop

        # E. Decoy Port Traps: Auto-jail external probes into dynamic sets
        # Excludes loopback, management, tunnels, and local bridges from self-jailing
        iifname != {{ "lo", "tailscale0", "wg*", "docker0", "parrot0", "hc-mgmt", "hc-backup" }} ip saddr != @trusted_mgmt_v4 ip saddr != @essential_egress_v4 tcp dport {{ 23, 445, 5555, 8291 }} add @dynamic_scanners_v4 {{ ip saddr }} counter drop
        iifname != {{ "lo", "tailscale0", "wg*", "docker0", "parrot0", "hc-mgmt", "hc-backup" }} ip6 saddr != @trusted_mgmt_v6 ip6 saddr != @essential_egress_v6 tcp dport {{ 23, 445, 5555, 8291 }} add @dynamic_scanners_v6 {{ ip6 saddr }} counter drop

        # Trusted interface bypass for management, tunnels & cluster mesh
        iifname {{ "tailscale0", "wg*", "hc-mgmt", "hc-backup" }} accept

        # Jump Desktop Connect: Direct P2P & Fluid Connect
        tcp dport 5273 counter accept
        udp dport {{ 5273, 35384-45385 }} counter accept

        # F. Management Perimeter Stealth:
        # Strictly require source to be in @trusted_mgmt for sensitive daemons:
        # SSH (22), NFS (111, 2049), Spice (3128), RDP (3389), VNC (5900),
        # Corosync (UDP 5404-5405), Agent RPC (7778, 7781), Proxmox Web (8006).
        # Proxmox management and cluster traffic stays strictly LAN-only.
        ip saddr != @trusted_mgmt_v4 tcp dport {{ 22, 111, 2049, 3128, 3389, 5900, 7778, 7781, 8006 }} counter drop
        ip6 saddr != @trusted_mgmt_v6 tcp dport {{ 22, 111, 2049, 3128, 3389, 5900, 7778, 7781, 8006 }} counter drop
        ip saddr != @trusted_mgmt_v4 udp dport {{ 3389, 5404, 5405 }} counter drop
        ip6 saddr != @trusted_mgmt_v6 udp dport {{ 3389, 5404, 5405 }} counter drop

        # G. ICMP Sweep Normalization: Rate-limit echo requests to 5/s
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip protocol icmp icmp type echo-request counter drop
        meta l4proto ipv6-icmp icmpv6 type echo-request limit rate 5/second accept
        meta l4proto ipv6-icmp icmpv6 type echo-request counter drop
    }}

    # --------------------------------------------------------------------------
    # OUTPUT: Egress Protection
    # --------------------------------------------------------------------------
    chain output {{
        type filter hook output priority -5; policy {egress_policy};

        # Loopback traffic is trusted unconditionally
        oifname "lo" accept

        # A reviewed outbound endpoint is independent of ingress scan history.
        ip daddr @outbound_block_v4 jump outbound_drop
        ip6 daddr @outbound_block_v6 jump outbound_drop
        ct state established,related accept

        # Whitelist critical developer & management egress
        ip daddr @essential_egress_v4 accept
        ip6 daddr @essential_egress_v6 accept
        ip daddr @trusted_mgmt_v4 accept
        ip6 daddr @trusted_mgmt_v6 accept

        # Link-local multicast is LAN discovery (mDNS/LLMNR/SSDP), not egress
        ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} accept
        ip6 daddr ff00::/8 accept

        # Scanner sets and honeypot jails have NO outbound authority.
{allowance_block}
    }}

    # --------------------------------------------------------------------------
    # FORWARD: Transit Protection (Containers / VMs / Bridges)
    # --------------------------------------------------------------------------
    chain forward {{
        type filter hook forward priority -5; policy {egress_policy};
        ip daddr @outbound_block_v4 jump forward_drop
        ip6 daddr @outbound_block_v6 jump forward_drop
        ct state established,related accept

        # Inter-node LAN, Proxmox cluster transit, and VM bridges
        ip saddr @trusted_mgmt_v4 ip daddr @trusted_mgmt_v4 accept
        ip6 saddr @trusted_mgmt_v6 ip6 daddr @trusted_mgmt_v6 accept
        iifname "vmbr*" oifname "vmbr*" accept
        iifname {{ "tailscale0", "wg*" }} accept
        oifname {{ "tailscale0", "wg*" }} accept

        # Enforce that Proxmox cluster traffic stays strictly on local bridges / LAN
        iifname != "vmbr*" oifname "vmbr*" tcp dport {{ 3128, 8006 }} drop
        oifname != "vmbr*" tcp dport {{ 3128, 8006 }} drop
        iifname != "vmbr*" oifname "vmbr*" udp dport {{ 5404, 5405 }} drop
        oifname != "vmbr*" udp dport {{ 5404, 5405 }} drop

        # Jump Desktop Connect Transit & Bridging
        tcp dport 5273 accept
        tcp sport 5273 accept
        udp dport {{ 5273, 35384-45385 }} accept
        udp sport {{ 5273, 35384-45385 }} accept

        ip daddr @essential_egress_v4 accept
        ip6 daddr @essential_egress_v6 accept
        ip daddr @trusted_mgmt_v4 accept
        ip6 daddr @trusted_mgmt_v6 accept

        # Link-local multicast is LAN discovery (mDNS/LLMNR/SSDP), not egress
        ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} accept
        ip6 daddr ff00::/8 accept

{forward_allowance_block}
    }}
}}
"""
    # A resolver/schema/write failure must leave the last generated file intact.
    fd, temporary = tempfile.mkstemp(prefix=".countersurveillance-", dir=os.path.dirname(OUTPUT_NFT))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(nft_template)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, OUTPUT_NFT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    print(f"[+] Output written to: {OUTPUT_NFT}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"[!] SAFETY ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
