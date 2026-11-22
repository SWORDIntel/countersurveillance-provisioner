#!/usr/bin/env bash
# repin.sh — deliberate egress re-pin workflow.
#
#   1. render a candidate pin (optionally on a canonical dual-stack node)
#   2. show exactly which addresses changed (review step)
#   3. optionally install it, commit it and deploy the reviewed list
#
# Nothing is written to the repo unless --write is given, and nothing is
# committed or deployed unless asked, so a plain run is a safe dry review.
#
#   tools/repin.sh                       # render candidate, show diff, write nothing
#   tools/repin.sh --write               # accept the candidate pin (still no commit)
#   tools/repin.sh --write --commit      # ...and commit the reviewed pin
#   tools/repin.sh --write --commit --deploy        # ...and deploy this host
#   tools/repin.sh --host t320 --write --commit     # pin from a dual-stack node
#   tools/repin.sh --strict              # fail the drift gate above --max-drift-ratio
#   tools/repin.sh --host t320 --remote-tool /root/cs-src/tools/update_blacklist.py
#                                        # pin from a specific checkout on that host
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="${SCRIPT_DIR}/configs/egress.pinned.json"
TOOL="${SCRIPT_DIR}/tools/update_blacklist.py"
CANONICAL_HOST=""
REMOTE_TOOL="/opt/countersurveillance/tools/update_blacklist.py"
WRITE=0
COMMIT=0
DEPLOY=0
DEPLOY_HOSTS=""
STRICT=0
MAX_RATIO="0.25"

usage() {
    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host)   CANONICAL_HOST="${2:?--host needs a value}"; shift 2 ;;
        --remote-tool) REMOTE_TOOL="${2:?--remote-tool needs a value}"; shift 2 ;;
        --write)  WRITE=1; shift ;;
        --commit) COMMIT=1; shift ;;
        --deploy) DEPLOY=1; shift ;;
        --hosts)  DEPLOY_HOSTS="${2:?--hosts needs a value}"; shift 2 ;;
        --strict) STRICT=1; shift ;;
        --max-drift-ratio) MAX_RATIO="${2:?--max-drift-ratio needs a value}"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

CANDIDATE="$(mktemp -t egress-pin-candidate.XXXXXX.json)"
trap 'rm -f "$CANDIDATE"' EXIT

if [ -n "$CANONICAL_HOST" ]; then
    echo "[*] Rendering candidate pin on ${CANONICAL_HOST}..."
    if ! ssh "$CANONICAL_HOST" "test -x ${REMOTE_TOOL}"; then
        echo "[!] ${REMOTE_TOOL} not found on ${CANONICAL_HOST}; deploy there first" >&2
        echo "    (or pass --remote-tool <path to update_blacklist.py>)" >&2
        exit 1
    fi
    REMOTE_TMP="/tmp/egress-pin-candidate.$$.json"
    ssh "$CANONICAL_HOST" "python3 ${REMOTE_TOOL} --emit-pin ${REMOTE_TMP} --output ${REMOTE_TMP}.nft >/dev/null && cat ${REMOTE_TMP}" > "$CANDIDATE"
    ssh "$CANONICAL_HOST" "rm -f ${REMOTE_TMP} ${REMOTE_TMP}.nft" || true
else
    echo "[*] Rendering candidate pin on this host..."
    # Render the ruleset to a temp path: a review must not dirty the tracked config.
    "$TOOL" --emit-pin "$CANDIDATE" --output "${CANDIDATE}.nft" >/dev/null
    rm -f "${CANDIDATE}.nft"
fi

if [ ! -s "$CANDIDATE" ]; then
    echo "[!] Candidate pin is empty; refusing to continue" >&2
    exit 1
fi

echo "[*] Review (committed pin -> candidate):"
if [ -f "$PIN" ]; then
    "$TOOL" --diff-pin "$PIN" "$CANDIDATE" || true
else
    echo "    (no committed pin yet; this becomes the initial reviewed list)"
    python3 - "$CANDIDATE" <<'PY'
import json, sys
pin = json.load(open(sys.argv[1]))
total = sum(len(v) for v in pin["v4"].values()) + sum(len(v) for v in pin["v6"].values())
print(f"    {len(pin['v4'])} v4 / {len(pin['v6'])} v6 domains, {total} addresses")
PY
fi

if [ "$WRITE" -eq 0 ]; then
    echo
    echo "[i] Dry review only. Re-run with --write to install this pin,"
    echo "    then --commit and --deploy once you have reviewed the addresses."
    exit 0
fi

if [ -f "$PIN" ]; then
    cp -a "$PIN" "${PIN}.prev"
    echo "[*] Previous pin kept at ${PIN}.prev"
fi
install -m 0644 "$CANDIDATE" "$PIN"
echo "[+] Pin installed: ${PIN}"

if [ "$STRICT" -eq 1 ]; then
    echo "[*] Strict drift gate (max ratio ${MAX_RATIO})..."
    set +e
    "$TOOL" --check-pin "$PIN" --strict-drift --max-drift-ratio "$MAX_RATIO"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "[!] Strict gate failed; the pin is installed but not deployed." >&2
        exit "$rc"
    fi
else
    "$TOOL" --check-pin "$PIN" >/dev/null || true
fi

if [ "$COMMIT" -eq 1 ]; then
    if git -C "$SCRIPT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$SCRIPT_DIR" add configs/egress.pinned.json
        git -C "$SCRIPT_DIR" commit -q -m "Re-pin reviewed egress whitelist

Rendered with tools/update_blacklist.py --emit-pin${CANONICAL_HOST:+ on ${CANONICAL_HOST}}.
Review this pin like a firewall change: every address here is one the node may
egress to." || echo "[i] Nothing to commit (pin unchanged)"
        echo "[+] Comprehensive commit: $(git -C "$SCRIPT_DIR" log --oneline -1)"
    else
        echo "[!] ${SCRIPT_DIR} is not a git repository; skipping commit" >&2
    fi
fi

if [ "$DEPLOY" -eq 1 ]; then
    echo "[*] Deploying to this host..."
    ( cd "$SCRIPT_DIR" && ./deploy.sh filter )
fi

if [ -n "$DEPLOY_HOSTS" ]; then
    for host in $DEPLOY_HOSTS; do
        echo "[*] Deploying to ${host}..."
        tar czf - -C "$SCRIPT_DIR" --exclude=.git --exclude=__pycache__ --exclude=.pytest_cache . 2>/dev/null \
            | ssh "$host" 'rm -rf /root/cs-src && mkdir -p /root/cs-src && tar xzf - -C /root/cs-src && cd /root/cs-src && chmod +x *.sh tools/*.sh tools/*.py && ./deploy.sh filter'
    done
fi

echo "[+] Re-pin workflow complete."
