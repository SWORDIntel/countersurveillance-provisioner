#!/usr/bin/env bash
# egress_review.sh — aggregate "would be dropped under strict" across the fleet.
# Works because the strict profile is still evaluated in accept mode: every
# packet that reaches the log rule would have been dropped with STRICT_EGRESS=1.
set -euo pipefail
SINCE="${1:--24h}"

collect() {
    local node="$1" target="$2"
    local raw
    if [ "$target" = "local" ]; then
        raw="$(sudo -n journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep 'cs-egress-drop' || true)"
    else
        raw="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$target" \
            "sudo -n journalctl -k --since '$SINCE' --no-pager 2>/dev/null | grep 'cs-egress-drop'" 2>/dev/null || true)"
    fi
    local n
    n="$(printf '%s' "$raw" | grep -c 'cs-egress-drop' || true)"
    printf '\n### %s — %s events\n' "$node" "$n"
    [ "${n:-0}" -eq 0 ] && return 0
    printf '%s\n' "$raw" \
        | grep -oE 'DST=[0-9a-f.]+ .*PROTO=[A-Z]+ SPT=[0-9]+ DPT=[0-9]+' \
        | sed 's/LEN=[0-9]* //;s/TOS=[^ ]* //;s/PREC=[^ ]* //;s/TTL=[0-9]* //;s/ID=[0-9]* //;s/DF //;s/WINDOW=[0-9]* //;s/RES=[^ ]* //;s/URGP=[0-9]* //' \
        | sort | uniq -c | sort -rn | head -15
}

echo "Would-be drops under STRICT_EGRESS (window: ${SINCE})"
collect t420 local
collect t320 john@192.168.1.95
collect 730xd john@192.168.1.90
