# 730xd egress shadow (strict-mode readiness)

`table inet cs_shadow` on 730xd logs every **new forwarded flow** that
`STRICT_EGRESS=1` would blackhole, then accepts it. Nothing is dropped.

## Check what strict would block

```bash
ssh john@192.168.1.90 'sudo journalctl -k --since -24h | grep cs-shadow | grep -oE "DST=[0-9a-f.:]+" | cut -d= -f2 | sort | uniq -c | sort -rn'
```

## Toasts

Hourly user timer pops a **no-timeout** notification listing only destinations
not seen before.

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
