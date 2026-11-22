#!/usr/bin/env bash
# repin.sh — deliberate egress re-pin, run on one node at a time.
#
# Nothing here reaches across the network: each node renders, reviews, verifies
# and deploys locally. Convergence comes from every node consuming the same
# committed pin, so the sequence is: re-pin on one node, commit, pull elsewhere,
# then run --status (or `--deploy`) on each node.
#
#   tools/repin.sh                    # review: render a candidate, show the diff, write nothing
#   tools/repin.sh --status           # is this node running the committed pin?
#   tools/repin.sh --write            # accept the candidate (previous kept as .prev)
#   tools/repin.sh --write --deploy   # ...and apply it to this node
#   tools/repin.sh --write --commit   # ...and commit the reviewed pin
#   tools/repin.sh --strict           # use the strict drift gate during --write
#
# Review a re-pin like a firewall change: every address in the pin is one this
# node may egress to.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="${SCRIPT_DIR}/configs/egress.pinned.json"
TOOL="${SCRIPT_DIR}/tools/update_blacklist.py"
RULESET="${CS_RULESET_PATH:-/etc/nftables.d/countersurveillance.nft}"

WRITE=0
COMMIT=0
DEPLOY=0
STATUS=0
STRICT=0
MAX_RATIO="0.25"

usage() {
    sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --status) STATUS=1; shift ;;
        --write)  WRITE=1; shift ;;
        --commit) COMMIT=1; shift ;;
        --deploy) DEPLOY=1; shift ;;
        --strict) STRICT=1; shift ;;
        --max-drift-ratio) MAX_RATIO="${2:?--max-drift-ratio needs a value}"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

if [ ! -f "$PIN" ]; then
    echo "[!] No committed pin at ${PIN}" >&2
    echo "    Create one first: tools/repin.sh --write" >&2
    exit 1
fi

# --- --status: is the live ruleset exactly what the committed pin renders? ----
if [ "$STATUS" -eq 1 ]; then
    if [ ! -f "$RULESET" ]; then
        echo "[!] No installed ruleset at ${RULESET}" >&2
        exit 1
    fi
    RENDERED="$(mktemp -t egress-render.XXXXXX.nft)"
    trap 'rm -f "$RENDERED"' EXIT
    if ! "$TOOL" --use-pin "$PIN" --output "$RENDERED" >/dev/null 2>&1; then
        echo "[!] Failed to render the pin; the pin may be invalid" >&2
        exit 1
    fi
    live_sum="$(sha256sum "$RULESET" | cut -d' ' -f1)"
    pin_sum="$(sha256sum "$RENDERED" | cut -d' ' -f1)"
    if [ "$live_sum" = "$pin_sum" ]; then
        echo "[+] CONVERGED: ${RULESET} matches the committed pin (${pin_sum:0:16}…)"
        exit 0
    fi
    echo "[-] DIVERGED: this node is not running the committed pin" >&2
    echo "    live: ${live_sum:0:16}…  pin: ${pin_sum:0:16}…" >&2
    echo "    Apply it with: tools/repin.sh --write --deploy   (or ./deploy.sh filter)" >&2
    exit 1
fi

# --- review: render a candidate pin and show what would change ---------------
CANDIDATE="$(mktemp -t egress-pin-candidate.XXXXXX.json)"
RENDER_TMP="${CANDIDATE}.nft"
trap 'rm -f "$CANDIDATE" "$RENDER_TMP"' EXIT

echo "[*] Rendering candidate pin on $(hostname)..."
# --output keeps the tracked config untouched: a review must not dirty the tree.
"$TOOL" --emit-pin "$CANDIDATE" --output "$RENDER_TMP" >/dev/null

if [ ! -s "$CANDIDATE" ]; then
    echo "[!] Candidate pin is empty; refusing to continue" >&2
    exit 1
fi

echo "[*] Review (committed pin -> candidate):"
"$TOOL" --diff-pin "$PIN" "$CANDIDATE" || true

if [ "$WRITE" -eq 0 ]; then
    echo
    echo "[i] Dry review only. Nothing written."
    echo "    Next: --write to accept, then --deploy (this node) and --commit."
    exit 0
fi

cp -a "$PIN" "${PIN}.prev"
echo "[*] Previous pin kept at ${PIN}.prev"
install -m 0644 "$CANDIDATE" "$PIN"
echo "[+] Pin installed: ${PIN}"

if [ "$STRICT" -eq 1 ]; then
    echo "[*] Strict drift gate (max ratio ${MAX_RATIO})..."
    if ! "$TOOL" --check-pin "$PIN" --strict-drift --max-drift-ratio "$MAX_RATIO"; then
        echo "[!] Strict gate failed; the pin is written but not deployed." >&2
        exit 1
    fi
else
    "$TOOL" --check-pin "$PIN" >/dev/null || true
fi

if [ "$DEPLOY" -eq 1 ]; then
    echo "[*] Deploying to this node..."
    ( cd "$SCRIPT_DIR" && ./deploy.sh filter )
fi

if [ "$COMMIT" -eq 1 ]; then
    if ! git -C "$SCRIPT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        echo "[!] ${SCRIPT_DIR} is not a git repository; skipping commit" >&2
        exit 1
    fi
    git -C "$SCRIPT_DIR" add configs/egress.pinned.json
    if git -C "$SCRIPT_DIR" diff --cached --quiet; then
        echo "[i] Pin unchanged; nothing to commit."
    else
        git -C "$SCRIPT_DIR" commit -q -m "Re-pin reviewed egress whitelist

Rendered with tools/update_blacklist.py --emit-pin on $(hostname).
Review this pin like a firewall change: every address here is one the node may
egress to."
        echo "[+] Committed: $(git -C "$SCRIPT_DIR" log --oneline -1)"
    fi
fi

if [ "$DEPLOY" -eq 0 ] && [ "$COMMIT" -eq 0 ]; then
    echo
    echo "[i] Pin written only. Apply it with --deploy, commit it with --commit,"
    echo "    then pull on the other nodes and run --status there."
fi
