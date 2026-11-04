#!/usr/bin/env bash
#
# refresh_survival_check.sh — post-refresh sanity check for the fleet.
#
# The daily countersurveillance-refresh.timer fires on each node in the
# ~04:30–05:00 GMT window and re-runs `deploy.sh filter` from /opt with the
# recorded mode. This script verifies, per node, that this morning's refresh:
#
#   1. ran and verified        ("[+] Deployment verified. Rollback watchdog
#                               disarmed." in the refresh unit journal)
#   2. re-applied the recorded mode ("Egress mode recorded: ..." matches
#      /etc/countersurveillance/egress.mode)
#   3. left /etc/countersurveillance/egress.mode exactly as expected
#   4. emitted NO legacy "cs-egress-drop" lines dated today
#      (post-allowance generator only emits cs-audit-*, cs-in-scan,
#      cs-in-jail, cs-out-block, cs-fwd-block — a fresh legacy line means an
#      old ruleset was loaded; this is the 2026-11-01 04:27 failure signature)
#   5. ulogd2 (drop-telemetry sink) is active
#
# On the aggregator it additionally requires the user-level
# cs-egress-stream.service active, so ~/.local/state/cs-egress/all.log keeps
# aggregating events.
#
# Usage:
#   tools/refresh_survival_check.sh
#
# Exit codes: 0 = all green, 1 = one or more checks failed,
#             2 = refresh has not run yet today (rerun after ~05:00 GMT).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EXPECTED_MODE="STRICT_EGRESS=0
STRICT_ALLOW_WEB=1
STRICT_LOG_DROPS=1"

AGGREGATOR_HOST=""                 # empty = local
declare -A NODES=(
  ["local"]=""
)
if [ -n "${SURVIVAL_CHECK_NODES:-}" ]; then
  for pair in $SURVIVAL_CHECK_NODES; do
    lbl="${pair%%=*}"
    tgt="${pair#*=}"
    NODES["$lbl"]="$tgt"
  done
fi

# The per-node probe is ONE string so nested quoting survives ssh intact.
NODE_PROBE='
echo "HOST=$(hostname)"
echo "MODE_BEGIN"
sudo -n cat /etc/countersurveillance/egress.mode 2>/dev/null
echo "MODE_END"
echo "JOUR_BEGIN"
sudo -n journalctl -u countersurveillance-refresh.service --since "04:00" --no-pager 2>/dev/null \
  | grep -iE "deployment verified|egress mode recorded|STRICT_ALLOW_WEB=|STRICT_LOG_DROPS=|fail|watchdog" || true
echo "JOUR_END"
D="$(date "+%b %e")"
echo "LEGACY_TODAY=$(sudo -n grep -F -e "$D" /var/log/cs-egress-drops.log 2>/dev/null | grep -cF "cs-egress-drop" || true)"
echo "AUDIT_TODAY=$(sudo -n grep -F -e "$D" /var/log/cs-egress-drops.log 2>/dev/null | grep -cE "cs-audit-(out|fwd)" || true)"
echo "ULOGD=$(systemctl is-active ulogd2 2>/dev/null)"
'

FAILURES=0
SKIPPED=0

section() { printf '\n== %s ==\n' "$1"; }

run_probe() {
  local host="$1"
  if [ -n "$host" ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" "$NODE_PROBE" 2>/dev/null
  else
    bash -c "$NODE_PROBE"
  fi
}

extract_block() { # output, begin-marker, end-marker
  sed -n "/^$2\$/,/^$3\$/p" <<<"$1" | sed '1d;$d'
}

check_node() {
  local label="$1" host="$2" out host_seen mode jour legacy audit ulogd mode_ok rc=0

  section "$label"
  out="$(run_probe "$host")" || { echo "FAIL: probe unreachable ($host)"; return 1; }

  host_seen="$(sed -n 's/^HOST=//p' <<<"$out")"
  if [ "$host_seen" != "$label" ]; then
    echo "FAIL: hostname mismatch (expected $label, got '${host_seen:-<empty>}') — possible route hijack"
    rc=1
  fi

  mode="$(extract_block "$out" MODE_BEGIN MODE_END)"
  if [ "$mode" = "$EXPECTED_MODE" ]; then
    echo "PASS: mode file $mode" | tr '\n' ' '; echo
  else
    echo "FAIL: mode file is '$(echo "$mode" | tr '\n' ' ')' expected '$(echo "$EXPECTED_MODE" | tr '\n' ' ')'"; rc=1
  fi

  jour="$(extract_block "$out" JOUR_BEGIN JOUR_END)"
  if [ -z "$jour" ]; then
    echo "SKIP: refresh has not run yet today (journal empty since 04:00)"
    return 2
  fi
  if grep -q "Deployment verified" <<<"$jour"; then
    echo "PASS: refresh verified (watchdog disarmed)"
  else
    echo "FAIL: no 'Deployment verified' in today's refresh journal"; rc=1
  fi
  # deploy.sh:90 echoes the 3-line mode file after one prefix, so journald
  # splits the continuation values onto their own journal lines.
  local se saw sld bad
  se="$(sed -n 's/^STRICT_EGRESS=//p' <<<"$mode")"
  saw="$(sed -n 's/^STRICT_ALLOW_WEB=//p' <<<"$mode")"
  sld="$(sed -n 's/^STRICT_LOG_DROPS=//p' <<<"$mode")"
  if [ -n "$se$saw$sld" ] \
     && grep -q "Egress mode recorded: STRICT_EGRESS=$se" <<<"$jour" \
     && grep -q "STRICT_ALLOW_WEB=$saw" <<<"$jour" \
     && grep -q "STRICT_LOG_DROPS=$sld" <<<"$jour"; then
    echo "PASS: refresh re-applied recorded mode ($se/$saw/$sld)"
  else
    echo "FAIL: refresh journal does not confirm recorded mode"; rc=1
  fi
  bad="$(grep -iE "verification failed|watchdog fired|restored previous firewall|reverting" <<<"$jour" || true)"
  if [ -n "$bad" ]; then
    echo "FAIL: refresh journal contains failure lines:"; sed 's/^/       /' <<<"$bad"
    rc=1
  fi

  legacy="$(sed -n 's/^LEGACY_TODAY=//p' <<<"$out")"
  if [ "$legacy" = "0" ]; then
    echo "PASS: no legacy cs-egress-drop lines today"
  else
    echo "FAIL: $legacy legacy cs-egress-drop lines today (old ruleset resurfaced?)"; rc=1
  fi

  audit="$(sed -n 's/^AUDIT_TODAY=//p' <<<"$out")"
  echo "INFO: ${audit:-0} cs-audit-* lines today (0 is fine — allowances absorb would-be drops)"

  ulogd="$(sed -n 's/^ULOGD=//p' <<<"$out")"
  if [ "$ulogd" = "active" ]; then
    echo "PASS: ulogd2 active"
  else
    echo "FAIL: ulogd2 is '${ulogd:-<unknown>}' (drop telemetry sink down)"; rc=1
  fi

  return "$rc"
}

for label in "${!NODES[@]}"; do
  check_node "$label" "${NODES[$label]}"
  rc=$?
  if [ "$rc" -eq 1 ]; then FAILURES=$((FAILURES + 1)); fi
  if [ "$rc" -eq 2 ]; then SKIPPED=$((SKIPPED + 1)); fi
done

section "local aggregator stream"
if systemctl --user is-active cs-egress-stream.service >/dev/null 2>&1; then
  echo "PASS: cs-egress-stream.service active"
else
  echo "FAIL: cs-egress-stream.service not active — all.log is stale"
  FAILURES=$((FAILURES + 1))
fi
if [ -f "$HOME/.local/state/cs-egress/all.log" ]; then
  echo "INFO: all.log lines today: $(grep -F -e "$(date '+%b %e')" "$HOME/.local/state/cs-egress/all.log" | wc -l)"
else
  echo "FAIL: $HOME/.local/state/cs-egress/all.log missing"
  FAILURES=$((FAILURES + 1))
fi

section "summary"
if [ "$SKIPPED" -gt 0 ]; then
  echo "RESULT: SKIP — refresh not yet run on $SKIPPED node(s); rerun after ~05:00 GMT"
  exit 2
fi
if [ "$FAILURES" -gt 0 ]; then
  echo "RESULT: FAIL — $FAILURES node(s) failed checks"
  exit 1
fi
echo "RESULT: PASS — all nodes refreshed in recorded mode, telemetry intact"
