# Counter-Surveillance & Anti-Reconnaissance Provisioner

Production-grade, automated provisioning suite for deploying high-precision, dual-stack packet filtering, scanner deception, honeypot auto-trapping, and anti-reconnaissance controls across Linux nodes.

---

## Architecture Overview

```
                                [ INCOMING / OUTGOING PACKET ]
                                               │
                 ┌─────────────────────────────┴─────────────────────────────┐
                 ▼                                                           ▼
           [ INBOUND ]                                                 [ OUTBOUND ]
                 │                                                           │
 1. Anti-Reconnaissance Filter                                   1. State Conntrack
    • Drop invalid TCP states                                       • ct state established,related accept
    • Drop NULL, Xmas, SYN-FIN, SYN-RST scans                                │
                 │                                               2. Essential Egress Whitelist
 2. State Conntrack                                                 • Allow @essential_egress_v4 / v6
    • ct state established,related accept                           • Allow @trusted_mgmt_v4 / v6
                 │                                                           │
 3. Auto-Jailed Scanner Suppression                              3. Scanner & Jail Blackhole
    • Drop @dynamic_scanners_v4 / v6                                • Drop @blocked_v4 / v6
                 │                                                  • Drop @dynamic_scanners_v4 / v6
 4. Blocklist Evaluation
    • Drop @blocked_v4 / v6 (Censys, Shodan, Stretchoid)
                 │
 5. Perimeter Stealth (Strict Interface & Port Isolation)
    • Non-LAN sources hitting management ports (22, 111,
      2049, 3128, 3389, 5900, 7778, 7781, 8006) -> DROP
                 │
 6. Decoy Trap Ports (23, 445, 5555, 8291, 80, 8080)
    • Stateful jailing: add @dynamic_scanners_v4/v6 (24h timeout)
    • In-kernel redirection: redirect to :9080 (HTTP) or :9445 (Raw)
                 │
                 ▼
 7. ICMP Sweep Normalization
    • Rate-limit echo requests to 5/s, drop bursts
```

---

### Core Architectural Principles

1. **Autonomous Standalone Architecture ("Every Machine Has Its Own Sink")**:
   - Rather than fragile Layer 3 transparent routing across WireGuard, the lightweight ChronoSink Go daemon (<8 MB RAM, 5.6 MB binary) runs **locally on each node**.
   - Trapped probes are redirected locally via in-kernel `nftables redirect to :port`, preserving the attacker's genuine Layer 3 `source_ip` without proxy encapsulation or asymmetric routing traps.
   - Evidence is logged locally to `/opt/qihse-data/events/countersurveillance_alerts.jsonl` and optionally dispatched via UDP to Citadel Shield / telemetry endpoints.
   - Every node is completely autonomous and standalone: no cluster hubs, spoke tunnels, or cross-node synchronizations are required. Running `./install.sh` with zero arguments provisions the entire stack cleanly.

2. **Strict Ingress Trust vs. Outbound Egress Separation**:
   - `@trusted_mgmt_v4` & `@trusted_mgmt_v6`: Authorised management subnets (RFC1918, Loopback, Tailscale, Link-Local) strictly enforced on management daemons.
   - `@essential_egress_v4` & `@essential_egress_v6`: Developer outbound services (DNS, GitHub, PyPI, distro repos), evaluated strictly in `output` and `forward`.

3. **Dual-Stack In-Kernel Parity**:
   - Full IPv4 and IPv6 parity across static blocks, anti-reconnaissance TCP flags, ICMP sweep rate limits, and dynamic auto-jailing sets (`@dynamic_scanners_v6`).

4. **Transactional Deployment with Rollback Watchdogs**:
   - Remote deployments via `deploy.sh remote` arm a 30-second kernel rollback watchdog (`(sleep 30 && nft -f backup) &`).
   - If verification fails or connectivity drops, the watchdog automatically restores the prior firewall state, preventing remote hypervisor lockouts.

5. **Jump Desktop Remote Management & Fluid Protocol Compatibility**:
   - Explicitly permits Jump Desktop Connect and Fluid protocol traffic across all operating modes:
     - Inbound Fluid listener: `tcp dport 5273` and `udp dport 5273` counter accept
     - Inbound Direct P2P media streams: `udp dport 35384-45385` and `udp sport 35384-45385` counter accept
     - Outbound / Forward transit: Unrestricted bidirectional P2P UDP and Fluid TCP/UDP communication
     - Cloud Signaling & Discovery: Core authentication and rendezvous endpoints (`neuron.jumpdesktop.com`, `api.jumpdesktop.com`, `turn.jumpdesktop.com`, `jumpdesktop.com`) pre-resolved and whitelisted in `@essential_egress_v4/v6`.

---

## Directory Structure

```
countersurveillance-provisioner/
├── README.md                      # Architecture, usage, and threat model
├── ROADMAP.md                     # Implementation milestones & progress
├── install.sh                     # Clean-slate turnkey installer (undoes/overwrites prior configs first)
├── deploy.sh                      # Turnkey runner with atomic rollback watchdog
├── verify.sh                      # Post-deployment validation test suite
├── uninstall.sh                   # Safe rollback (preserves Proxmox/Docker tables)
├── provisioner.env.example        # Central configuration template
├── configs/
│   ├── countersurveillance.nft    # Compiled dual-stack nftables ruleset
│   └── countersurveillance-block.service # Systemd oneshot management unit
├── data/
│   └── scanner_subnets.json       # Structured scanner target database
├── tools/
│   ├── update_blacklist.py        # Threat intel parser & CIDR collapser
│   └── test_stealth.sh            # Evasion and drop inspection helper
├── honeypot/                      # ChronoSink Deception Engine
│   ├── Dockerfile                 # Minimal multi-stage container (<15MB)
│   ├── chronosink.service         # Hardened systemd service (sandboxed, memory-capped)
│   ├── deploy-hub.sh              # Standalone hub deployment script
│   ├── bin/
│   │   ├── chronosink             # Static AMD64 Go executable (5.6 MB)
│   │   ├── chronosink-linux-amd64 # AMD64 binary
│   │   └── chronosink-linux-arm64 # ARM64 binary (OCI Ampere / AArch64)
│   ├── go/
│   │   ├── go.mod                 # Go module definition
│   │   └── main.go                # Hardened deception daemon & evidence emitter
│   └── configs/
│       ├── hub-nftables.nft       # Hub TTL 128 mangling
│       └── hub-wireguard.conf.template # Hub WireGuard overlay configuration
└── wireguard/                     # Cluster Spoke Interconnects (Optional Overlay)
    ├── setup-spoke.sh             # Spoke configuration helper
    └── spoke/
        └── wg0-honeypot.conf.template # Spoke WireGuard configuration template
```

---

## ChronoSink Evidence Telemetry Schema

Every probe captured by ChronoSink is logged to `/var/log/chronosink/probes.jsonl` using a structured schema:

```json
{
  "schema_version": 1,
  "event_id": "9aabf18b14f19403fc26daf1",
  "sensor_id": "node-01",
  "timestamp_utc": "2026-10-30T15:11:04Z",
  "source_ip": "198.51.100.25",
  "source_port": 35930,
  "destination_port": 9080,
  "protocol": "tcp",
  "persona": "apache-1.3.27-2003",
  "action": "deceive",
  "classification": "scanner-probe",
  "confidence": 0.90,
  "payload_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "rule_id": "decoy-http",
  "connection_id": "80f6238b8e3ad5d8",
  "details": {
    "host": "198.51.100.25:80",
    "method": "GET",
    "uri": "/.env",
    "user_agent": "Mozilla/5.0 (compatible; CensysInspect/1.1)"
  }
}
```

---

## Usage

The scripts check the effective user ID once and set a `SUDO` command prefix for privileged
operations. Run them directly as root without `sudo`; non-root users use `sudo` for privileged
commands. Remote deployments still require the SSH account on the target to have working `sudo`.

### 0. Turnkey Standalone Installation (100% Automatic, Zero Arguments)
```bash
./install.sh
```
Or directly:
```bash
./deploy.sh
```
Running `./install.sh` or `./deploy.sh` with no arguments automatically provisions a complete, autonomous standalone counter-surveillance node on the machine ("every machine has its own sink, no cluster needed"):
1. **Clean-Slate Reset**: Stops services, clears existing `table inet countersurveillance`, cleans stale backups and temporary files.
2. **ChronoSink Go Deception Daemon**: Detects architecture (`amd64` or `arm64`), installs `/opt/chronosink/chronosink`, configures Citadel/QIHSE endpoints, and enables/starts `chronosink.service`.
3. **In-Kernel Packet Filter**: Updates threat intel blacklist, validates syntax (`nft -c -f`), installs `/etc/nftables.d/countersurveillance.nft`, enables and restarts `countersurveillance-block.service` under rollback watchdog protection.
4. **Daily Egress Whitelist Refresh Timer**: Installs the suite to `/opt/countersurveillance` and activates `countersurveillance-refresh.timer`.
5. **Full Diagnostics & Verification**: Runs `verify.sh` to confirm service health, kernel table presence, DNS/ICMP/API egress, ingress/egress scope separation, and ChronoSink temporal deception.

Sub-commands for targeted tasks:
```bash
./install.sh filter                         # Clean reset & deploy packet filter only
./install.sh local-daemon                   # Clean reset & deploy ChronoSink daemon + filter
./install.sh install-refresh                # Clean reset & install refresh timer only
./install.sh remote user@remote-host       # Clean reset & provision remote node via SSH (default: auto)
./install.sh uninstall                      # Safe teardown of countersurveillance table and services
```

### 1. Deploy In-Kernel Filter Only (Local Node)
```bash
./deploy.sh filter
```
Compiles ruleset, checks syntax, arms rollback timer, and verifies egress. The node's egress mode is recorded to `/etc/countersurveillance/egress.mode` on success, so later refreshes reuse it.

### 2. Deploy Deception Daemon + Filter (Local Node)
```bash
./deploy.sh local-daemon
```
Installs the sandboxed ChronoSink Go binary under systemd, applies local redirect rules, and pipes alerts to Citadel Shield / QIHSE.

### 3. Deploy Remotely via SSH (with Watchdog Protection)
```bash
./deploy.sh remote user@remote-host         # Runs full standalone auto deployment
./deploy.sh remote user@remote-host filter  # Runs filter-only deployment
```
*Note: The remote watchdog restores the previous firewall state automatically if connectivity fails.*

The remote deploy re-applies the **node's recorded mode**: the shipped heredoc sources `/etc/countersurveillance/egress.mode` on the target host, so `filter` over SSH never downgrades a node even when the dispatch host has different `STRICT_*` variables in its environment.

### 4. Run Verification Suite
```bash
./verify.sh
```

### 5. Safe Teardown / Rollback
```bash
./uninstall.sh
```
*Guaranteed to remove only `table inet countersurveillance`, preserving all Proxmox, Docker, and host routing tables.*

### 6. Strict Egress Enforcement (Opt-In, Per Node)
```bash
sudo STRICT_EGRESS=1 ./deploy.sh filter     # default-deny output + forward
```
In strict mode `@essential_egress_*` and `@trusted_mgmt_*` become an enforced whitelist instead of an advisory shortcut: the `output` and `forward` chains default-deny. The `input` chain is unchanged — its management isolation is already explicit, and flipping it to drop adds no protection.

Destination addresses are resolved at generation time from `data/egress_domains.json` and merged into the egress sets, so a vendor CDN move (GitHub fronting changes regularly) cannot silently break egress. If fewer than 80 % of required domains resolve, generation aborts with exit 3 and the live table is left untouched.

Roll back a node to the previous ruleset:
```bash
sudo nft -f "$(ls -t /etc/nftables.d/countersurveillance.nft.bak.* | head -1)"
```
Workstation profile — keeps a daily-driver host usable while still denying all non-web egress:

```bash
sudo STRICT_EGRESS=1 STRICT_ALLOW_WEB=1 ./deploy.sh filter
```
The allowance set is generated per node by `strict_allowances()` (`tools/update_blacklist.py`) and is **shared verbatim between strict enforcement and shadow-audit mode** (`STRICT_LOG_DROPS=1` with `STRICT_EGRESS=0`), so `cs-audit-*` events are exactly the class strict mode would drop. It existence-probes each host (interfaces under `/sys/class/net`, units under `/sys/fs/cgroup/system.slice`) and emits only what is present:

- `oifname "lo"` and `ct state established,related`
- the resolved `@essential_egress_*` destination sets
- `tailscale0` / `wg*` interfaces
- web egress with `STRICT_ALLOW_WEB=1`: `tcp dport { 22, 80, 443 }` + `udp dport 443` (QUIC)
- NTP (123), DNS (53 tcp+udp), SMTP (25), STUN (3478), GCM/FCM push (5228)
- kernel-WireGuard transports `udp dport { 1025, 41641, 51820, 51821 }` — kernel-owned WG sockets are never attributable via `socket cgroupv2`, so the transport ports are the stable contract
- BitTorrent: `udp sport 6881` plus a `transmission-daemon.service` cgroup allow (its dynamic destination/port pairs cannot be destination-described)
- `meta l4proto ipv6-icmp` and ICMP/ICMPv6 echo-request rate-limited to 5/s
- `socket cgroupv2` unit allows for the `tailscaled`, `i2pd`, `mullvad-daemon` and `transmission-daemon` units that exist on the node
- Hurricane Electric tunnel: `oifname "he-ipv6"` in output and forward, `ip protocol 41` in output only
- forward-only `iifname "parrot0"` for Parrot engagement containers

`socket cgroupv2` attribution is emitted **only in `output`** by design: it attributes the locally-owned socket, which does not exist for forwarded VM/LAN traffic (that is covered by the port allows instead). Allowances are emitted *after* the `@outbound_block_*` verdict jumps, so an evidenced blocking decision stays dropped even on an allowed port; the `counter` + `log` audit tail comes last, so it records only traffic no allowance accepted.

Deployment status: nodes can run permissive audit mode (`STRICT_EGRESS=0 STRICT_ALLOW_WEB=1 STRICT_LOG_DROPS=1`) with shadow logging live; the strict flip is gated on a clean 24 h `tools/egress_review.sh` sign-off.

### 7. Daily Egress Whitelist Refresh
```bash
sudo ./deploy.sh install-refresh
```
Installs the suite to `/opt/countersurveillance` and a `countersurveillance-refresh.timer` that regenerates and redeploys the ruleset each day in the node's recorded mode. Every run preflights, arms the rollback watchdog, and auto-reverts on verification failure, so a bad DNS day leaves the live table alone. `/etc/countersurveillance/egress.mode` is mandatory for the unit: if it is missing the unit fails loudly rather than downgrading a strict node to accept.

A post-refresh survival check (`tools/refresh_survival_check.sh`, exit 0/1/2) verifies each node after the morning window: refresh unit verified and the recorded mode re-applied, `/etc/countersurveillance/egress.mode` unchanged, zero fresh legacy `cs-egress-drop` lines, and ulogd2 + the stream alive. Exit 2 means the refresh has not run yet — rerun after ~05:00 GMT. Nodes can run it via the `configs/user/cs-refresh-check.timer` user timer (Mondays 05:30, `Persistent=true`); failures are journalled via `OnFailure=cs-refresh-check-fail.service` → `systemd-cat -t cs-refresh-check`, with no desktop popup.
