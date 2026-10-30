# Counter-Surveillance & Deception Provisioner Roadmap

- [x] **Phase 1: Dual-Stack In-Kernel Packet Filtering & Policy Separation**
  - [x] Strict separation of Ingress Management Trust (`@trusted_mgmt`) from Outbound Egress (`@essential_egress`)
  - [x] Full IPv4 and IPv6 parity, including dual-stack dynamic jailing (`@dynamic_scanners_v6`, 24h timeout)
  - [x] Discard TCP reconnaissance scans (NULL, Xmas, SYN-FIN, SYN-RST)
  - [x] Rate-limit ICMP/ICMPv6 sweeps to 5 req/s

- [x] **Phase 2: Dynamic Honeypot Jailing & Perimeter Stealth**
  - [x] Auto-jail hostile IPs hitting decoy lure ports (23, 445, 5555, 8291)
  - [x] Strictly isolate management ports (SSH, Proxmox, XRDP, VNC, Agent RPC) to authenticated management sources
  - [x] Isolate table scope to prevent interference with Proxmox (`pve-firewall`) or container bridges

- [x] **Phase 3: Transactional Deployment & Rollback Watchdogs**
  - [x] Implement 30-second atomic rollback watchdog in `deploy.sh` (prevent remote hypervisor lockouts)
  - [x] Implement `verify.sh` automated post-provision diagnostic runner
  - [x] Implement non-destructive `uninstall.sh` (removes only `table inet countersurveillance`)

- [x] **Phase 4: ChronoSink Go Engine & Hardening**
  - [x] Native static Go binary (5.6MB AMD64, 5.3MB ARM64, <8MB RAM)
  - [x] Concurrency ceiling (256 connections) and request payload capping (4 KB)
  - [x] Standardized investigation evidence schema with SHA-256 payload hashing
  - [x] Hardened systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges=yes`, `MemoryMax=64M`)
  - [x] Bounded harmless deception default with retro temporal headers (`Date: Oct 2003`)

- [x] **Phase 5: Distributed Local Deception & Telemetry Pipeline**
  - [x] Local kernel redirection (`redirect to :9080/:9445`), guaranteeing 100% genuine attacker IP preservation
  - [x] Direct append to authoritative QIHSE event store (`/opt/qihse-data/events/countersurveillance_alerts.jsonl`)
  - [x] Non-blocking UDP dispatch to Citadel Shield (`192.168.1.91:17872`) triggering real-time KEYSTONE trigram indexing

- [ ] **Phase 6: Fleet Rollout**
  - [ ] Deploy hardened local-daemon to `730xd` (192.168.1.90) via `deploy.sh remote`
  - [ ] Deploy hardened local-daemon to `T320` (192.168.1.95) via `deploy.sh remote`
