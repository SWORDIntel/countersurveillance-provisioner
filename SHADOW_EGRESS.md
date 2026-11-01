# 730xd egress shadow (strict-mode readiness)

> **SUPERSEDED (2026-11-01).** The standalone `inet cs_shadow` table described
> below has been replaced by **shadow-audit mode** in the main
> `inet countersurveillance` table: `STRICT_LOG_DROPS=1 STRICT_EGRESS=0
> ./deploy.sh filter` emits the same allowance set strict mode would use and
> logs every would-be drop as `cs-audit-out` / `cs-audit-fwd` via
> NFLOG→ulogd2 (see README §6 and `~/.local/state/cs-egress/all.log`).
> Verified absent on all three nodes via `nft list tables`; retained as the
> historical design record.

`table inet cs_shadow` on 730xd logs every **new forwarded flow** that
`STRICT_EGRESS=1` would blackhole, then accepts it. Nothing is dropped.

## Check what strict would block

```bash
ssh john@192.168.1.90 'sudo journalctl -k --since -24h | grep cs-shadow | grep -oE "DST=[0-9a-f.:]+" | cut -d= -f2 | sort | uniq -c | sort -rn'
```

## Reports (journal, no popup)

Hourly user timer writes a `cs-shadow-report` journal line listing only
destinations not seen before — `logger -t cs-shadow-report`, with no desktop
popup (operator request 2026-11-01; it previously raised a no-timeout toast).

```bash
systemctl --user status cs-shadow-report.timer
systemctl --user start cs-shadow-report.service   # fire now
cat ~/.local/state/cs-shadow/seen.txt             # everything seen so far
```

## Flip 730xd to strict (after whitelisting)

```bash
cd ~/Documents/countersurveillance-provisioner
sudo STRICT_EGRESS=1 ./deploy.sh filter
```

## Remove the shadow

```bash
ssh john@192.168.1.90 'sudo nft delete table inet cs_shadow'
```
