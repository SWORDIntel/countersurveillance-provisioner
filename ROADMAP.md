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

- [x] **Phase 6: Fleet Rollout**
  - [x] Deploy hardened local-daemon to hypervisor node via `deploy.sh remote`
  - [x] Deploy hardened local-daemon to secondary server node via `deploy.sh remote`

- [x] **Phase 7: Evidence-Gated Egress Policy**
  - [x] Provenance audit of the original 60-CIDR scanner list against primary sources (`data/list_audit.json`); ingress scanner sets scoped input-only
  - [x] Outbound blocking split into its own evidence-gated store (`data/outbound_blocks.json`: exact /32//128, HTTPS provenance, overlap validation)
  - [x] NFLOG→ulogd2 drop telemetry with live fleet-wide aggregation (`cs-egress-stream` → `~/.local/state/cs-egress/all.log`)
  - [x] Evidence-gated strict allowance set from the 24-hour would-be-drop review — QUIC/NTP/DNS/SMTP/STUN/push/WG-transports/BT/he-ipv6/parrot0, shared verbatim between strict and shadow-audit modes

- [x] **Phase 8: Fluid Remote Management & Clean-Slate Turnkey Deployment**
  - [x] Add Jump Desktop Connect support: Fluid protocol (TCP/UDP 5273), direct P2P (UDP 35384–45385), and cloud signaling domains (`neuron/api/turn.jumpdesktop.com`)
  - [x] Strictly confine Proxmox management (8006, 3128) and Corosync (UDP 5404–5405) traffic to authenticated `@trusted_mgmt` and local bridges
  - [x] Implement clean-slate `install.sh` that resets prior rules and guarantees complete overwrite of existing configurations across all nodes
  - [x] Resilient cluster deployment handling offline/maintenance nodes cleanly without aborting execution

- [x] **Phase 9: Standalone Autonomous Architecture & Turnkey Zero-Flag Deployment**
  - [x] Deprecate and retire legacy hub-and-spoke cluster options (`cluster`, `hub`, `spoke-tunnel`) in favor of self-contained autonomous nodes ("every machine has its own sink, no cluster needed")
  - [x] Fix argument forwarding bug in `install.sh` when invoked without arguments
  - [x] Implement 5-step fully automatic standalone deployment pipeline in `install.sh` and `deploy.sh` (`clean_slate_reset` -> ChronoSink daemon -> in-kernel filter -> daily refresh timer -> full diagnostics)
  - [x] Support sub-commands (`filter`, `local-daemon`, `install-refresh`, `remote`, `uninstall`) across `install.sh` and `deploy.sh`
  - [x] Update documentation and operational runbooks for zero-flag turnkey node provisioning

- [x] **Phase 10: Hardened Watchdogs, Systemd Sandboxing & Recovery Mechanisms**
  - [x] Detached watchdog immune to SIGHUP with disarm file flag preventing race conditions in `deploy.sh`
  - [x] Initialized rollback target on clean-slate and fresh installs guaranteeing clean table deletion on failure
  - [x] Logrotate configurations for ChronoSink JSONL alerts and kernel egress drop logs
  - [x] Sticky bit (1777) permissions on `/opt/qihse-data/events` for unprivileged ChronoSink append
  - [x] Systemd sandboxing hardening (`DynamicUser=yes`, `ProtectKernelModules=true`, `MemoryDenyWriteExecute=true`, `RestrictRealtime=true`, `RestrictNamespaces=true`)
  - [x] Non-fatal WireGuard handshake verification in `verify.sh` avoiding false rollback triggers
  - [x] Full purge teardown in `uninstall.sh` (mangled tables, WireGuard units, and directory artifacts)
  - [x] Pre-deployment backup restoration or hostname-detected standard OS firewall restoration in `uninstall.sh`
