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

1. **Distributed Deception, Centralized Evidence**:
   - Rather than fragile Layer 3 transparent routing across WireGuard, the lightweight ChronoSink Go daemon (<8 MB RAM, 5.6 MB binary) runs **locally on each node**.
   - Trapped probes are redirected locally via in-kernel `nftables redirect to :port`, preserving the attacker's genuine Layer 3 `source_ip` without proxy encapsulation or asymmetric routing traps.
   - Evidence is dispatched centrally to `/opt/qihse-data/events/countersurveillance_alerts.jsonl` and Citadel Shield (`192.168.1.91:17872`).

2. **Strict Ingress Trust vs. Outbound Egress Separation**:
   - `@trusted_mgmt_v4` & `@trusted_mgmt_v6`: Authorised management subnets (RFC1918, Loopback, Tailscale, Link-Local) strictly enforced on management daemons.
   - `@essential_egress_v4` & `@essential_egress_v6`: Developer outbound services (DNS, GitHub, PyPI, distro repos), evaluated strictly in `output` and `forward`.

3. **Dual-Stack In-Kernel Parity**:
   - Full IPv4 and IPv6 parity across static blocks, anti-reconnaissance TCP flags, ICMP sweep rate limits, and dynamic auto-jailing sets (`@dynamic_scanners_v6`).

4. **Transactional Deployment with Rollback Watchdogs**:
   - Remote deployments via `deploy.sh remote` arm a 30-second kernel rollback watchdog (`(sleep 30 && nft -f backup) &`).
   - If verification fails or connectivity drops, the watchdog automatically restores the prior firewall state, preventing remote hypervisor lockouts.

---

## Directory Structure

```
countersurveillance-provisioner/
├── README.md                      # Architecture, usage, and threat model
├── ROADMAP.md                     # Implementation milestones & progress
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
  "sensor_id": "t420",
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

### 1. Deploy In-Kernel Filter (Local Node)
```bash
./deploy.sh filter
```
Compiles ruleset, checks syntax, arms rollback timer, and verifies egress.

### 2. Deploy Full Deception Stack (Local Node)
```bash
./deploy.sh local-daemon
```
Installs the sandboxed ChronoSink Go binary under systemd, applies local redirect rules, and pipes alerts to Citadel Shield / QIHSE.

### 3. Deploy Remotely via SSH (with Watchdog Protection)
```bash
./deploy.sh remote john@192.168.1.95 local-daemon   # T320
./deploy.sh remote john@192.168.1.90 local-daemon   # 730xd
```
*Note: The remote watchdog restores the previous firewall state automatically if connectivity fails.*

### 4. Run Verification Suite
```bash
./verify.sh
```

### 5. Safe Teardown / Rollback
```bash
./uninstall.sh
```
*Guaranteed to remove only `table inet countersurveillance`, preserving all Proxmox, Docker, and host routing tables.*
