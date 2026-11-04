#!/usr/bin/env bash
# egress_collect.sh — pull per-node NFLOG drop files onto this PC and rebuild
# one combined file. Uses the headless linux agent where the build supports
# download, and falls back to scp for older agents.
set -euo pipefail

DEST="${CS_AGG_DIR:-$HOME/.local/state/cs-egress}"
mkdir -p "$DEST"
COMBINED="$DEST/all.log"
: > "$COMBINED.tmp"

pull() {  # $1=node  $2=target-or-local  $3=agent-target
    local node="$1" target="$2" agent="$3" out="$DEST/$1.log"
    if [ "$target" = "local" ]; then
        cp -f /var/log/cs-egress-drops.log "$out" 2>/dev/null || : > "$out"
    elif ! linuxagent --target "$agent" download /var/log/cs-egress-drops.log --local="$out" >/dev/null 2>&1; then
        scp -q -o BatchMode=yes -o ConnectTimeout=8 "$target:/var/log/cs-egress-drops.log" "$out" 2>/dev/null || : > "$out"
    fi
    [ -s "$out" ] || return 0
    sed "s/^/$node /" "$out" >> "$COMBINED.tmp"
}

pull "$(hostname)" local "$(hostname)"
if [ -n "${REMOTE_NODES:-}" ]; then
    for entry in $REMOTE_NODES; do
        # Format: node_name=user@host
        name="${entry%%=*}"
        target="${entry#*=}"
        pull "$name" "$target" "$name"
    done
fi

if [ -s "$COMBINED.tmp" ]; then
    sort -k2,3 "$COMBINED.tmp" > "$COMBINED"
else
    : > "$COMBINED"
fi
rm -f "$COMBINED.tmp"
printf 'combined: %s lines -> %s\n' "$(wc -l < "$COMBINED")" "$COMBINED"
