#!/usr/bin/env bash
# egress_stream.sh — stream NFLOG drop events from every node into one local
# file, live. Remotes expose /var/log/cs-egress-drops.log world-readable, so
# no sudo is needed on the far side.
set -uo pipefail

OUT="${CS_AGG_DIR:-$HOME/.local/state/cs-egress}/all.log"
mkdir -p "$(dirname "$OUT")"
touch "$OUT"

stream_local() {
    while :; do
        tail -F -n 0 /var/log/cs-egress-drops.log 2>/dev/null \
            | sed -u 's/^/t420 /' >> "$OUT"
        sleep 5
    done
}

stream_remote() {
    local node="$1" host="$2"
    while :; do
        ssh -o BatchMode=yes -o ConnectTimeout=8 \
            -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
            "$host" 'tail -F -n 0 /var/log/cs-egress-drops.log' 2>/dev/null \
            | sed -u "s/^/$node /" >> "$OUT"
        sleep 5
    done
}

stream_local &
stream_remote t320 john@192.168.1.95 &
stream_remote 730xd john@192.168.1.90 &

wait
