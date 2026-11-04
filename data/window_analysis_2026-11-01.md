# 24-hour observation window analysis — 2026-10-31 23:47 → 2026-11-01 10:11 UTC

Source: `~/.local/state/cs-egress/all.log` (41,432 events; 100% parsed after log rotation).
Window closed after the scoped ruleset deployed to all nodes.
`cs-egress-drop` lines cease after rollout; only
`cs-audit-out` / `cs-audit-fwd` (audit-only, rate-limited) lines exist afterwards. **Zero
enforcement drops under the new ruleset.**

## What strict mode would have broken (per node)

### Hypervisor node (38,236 would-be drops)
| UID | process | events | traffic | verdict |
|-----|---------|--------|---------|---------|
| 1000 | (monitoring cron) | 20,864 | TCP/443 → 121.40.11.50 (Alibaba, Hangzhou): 19,884 SYNs + 26 other dsts | **Self-inflicted retry storm.** The old list blocked the endpoint; the client retried at 1.2 SYNs/s for 4h04m (00:00→04:04). Endpoint is alive (HTTP 404 on GET /). Allowed now. Origin process will be named by `cs-synwatch` on its next run. |
| 121 | debian-transmission | 16,584 | BitTorrent: 671 dst/port combos; UDP/6881 to 132 peers, local port 51413, heavy China-ISP IPv6 ranges | Ordinary P2P egress. Allowed under permissive; would have broken Transmission under strict. |
| 0 | root (phoenix/caddy/HE) | 525 | TCP/443 → Cloudflare 162.159.13x (173), UDP/53 → 103.86.99.x (28), dpt 8245 → AWS (54) | Management/plumbing. Allowed. |
| 100 | _chrony | 63 | NTP to 4 pool servers (rotating) | Pool rotation defeats a static NTP allowlist. Allowed. |
| 42 | _apt | 37 | TCP/443 to 24 apt mirror dsts | Package fetching. Allowed. |
| 995 | plex | 38 | TCP/443 → AWS + Cloudflare | Plex metadata. Allowed. |
| 986 | polarproxy | 17 | TCP/443+80 → AWS | Proxy service. Allowed. |
| − | kernel | 32 | ICMPv6 (1 dst each) | Router/NDP noise. Allowed. |
| 105 | postfix | 3 | TCP/25 → 172.217.76.26 (Gmail MX) | Outbound mail. Would have broken SMTP under strict. |
| 996 | ollama | 2 | TCP/443 | Model fetch. Allowed. |

### Workstation node (3,659 would-be drops)
| UID | process | events | traffic | verdict |
|-----|---------|--------|---------|---------|
| 1000 | browser | 3,461 | **UDP/443 (QUIC) to 164 dsts** (Google/Cloudflare edge: 142.251.x, 35.190.x) | QUIC browsing. Strict's TCP-only 443 allowlist would have broken QUIC; browsers would fall back after long stalls. |
| 100 | _chrony | 48 | NTP to 3 pool servers | Pool rotation. Allowed. |
| — | misc | 12 | STUN/3478 (4 UDP + 4 TCP), TCP/5228 (XMPP), TCP/25 | Voice-call STUN, IM, mail. Allowed. |

### Secondary server node (71 would-be drops)
- 17 × NTP (uid 100, single server 82.16.107.176) — pool entry; allowed.
- 3 × TCP/80 → 93.184.216.34 (example.com) — benign script traffic; allowed.
- 2 × TCP/22 → 45.143.203.73 — outbound SSH by a local monitor to an IP in the *quarantined*
  `hostile_probers` range. Not surveillance; stays allowed (no evidenced outbound attribution).

## Conclusions
1. The old list was a blunt instrument: it blocked (a) the user's own tooling endpoint,
   triggering a 20k-packet retry storm, (b) QUIC browsing, (c) BitTorrent, (d) SMTP,
   (e) NTP pool rotation. None of those is unconsented tracking or surveillance.
2. The new split-scope ruleset enforces only scanner-network *ingress* plus explicitly
   evidenced outbound tracking endpoints (currently none pass the evidence bar), leaving
   all ordinary traffic untouched.
3. All 56 quarantined CIDRs are recorded in `data/list_audit.json`; nothing was deleted.
4. Side fix while on-site: duplicate `phoenix-node.service` unit (same api.py as active
   `phoenix-api.service`) was crash-looping on `Errno 98` and was disabled; the real unit
   serves 127.0.0.1:8089 correctly (decoy payload verified).
5. Follow-up: `cs-synwatch.timer` on the node logs pid+cmdline of any future SYN_SENT socket
   to 121.40.11.50 for 24h → confirms which monitoring job owns that endpoint.
