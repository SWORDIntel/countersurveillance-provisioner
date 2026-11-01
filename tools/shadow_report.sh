#!/usr/bin/env bash
# shadow_report.sh — pop a persistent toast listing destinations the strict
# egress policy would blackhole on 730xd (from the inet cs_shadow counter log).
set -euo pipefail

HOST="${SHADOW_HOST:-john@192.168.1.90}"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/cs-shadow"
SEEN="$STATE/seen.txt"
mkdir -p "$STATE"
touch "$SEEN"
sort -u -o "$SEEN" "$SEEN"

CUR="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" \
    'sudo -n journalctl -k --since "-24h" --no-pager 2>/dev/null | grep "cs-shadow" | grep -oE "DST=[0-9a-f.:]+" | cut -d= -f2' \
    | grep -E '^[0-9a-f.:]+$' | sort -u)" || exit 0

[ -z "$CUR" ] && exit 0

NEW="$(comm -13 "$SEEN" <(printf '%s\n' "$CUR"))"
[ -z "$NEW" ] && exit 0

printf '%s\n' "$CUR" | sort -u -o "$SEEN"
COUNT="$(printf '%s\n' "$NEW" | wc -l)"
SAMPLE="$(printf '%s\n' "$NEW" | head -6 | tr '\n' ' ')"

# Operator request (2026-11-01): record to the journal, no desktop popup.
# The shadow destination list itself (${SEEN}) is still updated above.
logger -t cs-shadow-report \
    "730xd egress shadow: ${COUNT} new destination(s): ${SAMPLE} — would be blocked under STRICT_EGRESS; full list: ${SEEN}"
