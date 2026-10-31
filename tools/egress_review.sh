#!/usr/bin/env bash
# egress_review.sh — aggregate "would be dropped under strict" from the single
# combined NFLOG file collected by egress_collect.sh.
set -euo pipefail
COMBINED="${CS_AGG_DIR:-$HOME/.local/state/cs-egress}/all.log"
WINDOW="${1:-all}"

[ -s "$COMBINED" ] || { echo "no data yet: $COMBINED"; exit 0; }

echo "Would-be drops under STRICT_EGRESS (source: $COMBINED, window: $WINDOW)"
echo

for node in t420 t320 730xd; do
    events="$(awk -v n="$node" '$1 == n' "$COMBINED" | wc -l)"
    printf '### %s — %s events\n' "$node" "$events"
    [ "$events" -eq 0 ] && { echo; continue; }
    awk -v n="$node" '$1 == n' "$COMBINED" \
        | grep -oE 'DST=[0-9a-f.]+ .*PROTO=[A-Z]+ SPT=[0-9]+ DPT=[0-9]+|UID=[0-9]+' \
        | sed 's/LEN=[0-9]* //;s/TOS=[^ ]* //;s/PREC=[^ ]* //;s/TTL=[0-9]* //;s/ID=[0-9]* //;s/DF[^ ]* //;s/WINDOW=[0-9]* //;s/RES=[^ ]* //;s/URGP=[0-9]* //' \
        | sort | uniq -c | sort -rn | head -10
    echo
done

echo "By process owner (UID) / direction:"
awk '{ for (i=1;i<=NF;i++) if ($i ~ /^UID=/) u=$i } { print $1, u }' "$COMBINED" \
    | sort | uniq -c | sort -rn | head -10
