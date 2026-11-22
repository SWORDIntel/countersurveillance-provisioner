#!/usr/bin/env python3
"""Perimeter guard for the countersurveillance nftables ruleset.

A failed `nft -f` leaves the host with *no* countersurveillance table at all,
and until this guard existed nothing noticed: the unit simply went failed and
the perimeter stayed absent (observed on 730xd for six days, 2026-11-16..22).

Modes:
  --preflight   validate the installed ruleset, no changes
  --apply       validate, load atomically, verify, roll back on failure
  --health      verify the live table; re-apply and alert when it is absent
  --alert-only  emit the failure alert (systemd OnFailure handler)

Every failure path emits a loud alert (journal priority alert, /dev/kmsg, wall
to logged-in users, optional webhook, and the QIHSE JSONL event file) and exits
non-zero so systemd records the unit as failed rather than silently inactive.

Stdlib only, no network access except an explicitly configured webhook.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NFT = os.getenv("CS_NFT_BIN", "/usr/sbin/nft")
RULESET = "/etc/nftables.d/countersurveillance.nft"
TABLE = "inet countersurveillance"
STATE_DIR = os.getenv("CS_STATE_DIR", "/run/countersurveillance")
STATE_FILE = os.path.join(STATE_DIR, "perimeter.state.json")
EVENTS_FILE = os.getenv(
    "QIHSE_EVENTS_FILE", "/opt/qihse-data/events/countersurveillance_alerts.jsonl"
)
WEBHOOK = os.getenv("CS_ALERT_WEBHOOK", "")
# A live ruleset always has filter chains; anything less means a partial load.
MIN_CHAINS = 2


def _run(argv, timeout=30):
    """Run a command, returning (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "missing binary: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss: %s" % (timeout, " ".join(argv))


def _write_state(**fields):
    try:
        Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
        state = {}
        try:
            state = json.loads(Path(STATE_FILE).read_text())
        except Exception:
            pass
        state.update(fields)
        state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tmp = STATE_FILE + ".tmp"
        Path(tmp).write_text(json.dumps(state, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def _read_state():
    try:
        return json.loads(Path(STATE_FILE).read_text())
    except Exception:
        return {}


def alert(reason, detail="", severity="alert"):
    """Emit the perimeter alarm through every available local channel."""
    host = socket.gethostname()
    message = "COUNTERSURVEILLANCE PERIMETER DOWN on %s: %s" % (host, reason)
    if detail:
        message += " | " + detail.replace("\n", " ")[:600]

    # 1. journal, at alert priority so it survives default filtering
    if shutil.which("logger"):
        _run(["logger", "-t", "cs-perimeter", "-p", "daemon.%s" % severity, message])

    # 2. kernel log: visible in dmesg/console even with journald degraded
    detail_tag = "ruleset=" + RULESET
    try:
        with open("/dev/kmsg", "w") as kmsg:
            kmsg.write("cs-perimeter: %s %s\n" % (message, detail_tag))
    except Exception:
        pass

    # 3. broadcast to logged-in operators
    if shutil.which("wall"):
        try:
            subprocess.run(["wall"], input=message + "\n", text=True, timeout=5)
        except Exception:
            pass

    # 4. durable JSONL event (repo convention, consumed by Citadel Shield)
    try:
        Path(EVENTS_FILE).parent.mkdir(parents=True, exist_ok=True)
        event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "cs-perimeter-guard",
            "host": host,
            "severity": severity,
            "reason": reason,
            "detail": detail[:2000],
            "ruleset": RULESET,
        }
        with open(EVENTS_FILE, "a") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    except Exception:
        pass

    # 5. optional out-of-band webhook
    if WEBHOOK:
        try:
            import urllib.request

            payload = json.dumps({"text": message}).encode()
            request = urllib.request.Request(
                WEBHOOK, data=payload, headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(request, timeout=10).read()
        except Exception as exc:
            _run(["logger", "-t", "cs-perimeter", "-p", "daemon.err",
                  "webhook delivery failed: %s" % exc])

    _write_state(last_alert_reason=reason, last_alert_at=time.time())
    print("ALERT: " + message, file=sys.stderr)
    return message


def preflight(ruleset=RULESET):
    """Syntax/feature validation without changing state."""
    if not Path(ruleset).is_file():
        return False, "ruleset missing: %s" % ruleset
    rc, _, err = _run([NFT, "-c", "-f", ruleset])
    if rc != 0:
        return False, err.strip() or ("nft -c exited %d" % rc)
    return True, ""


def table_present(table=TABLE):
    rc, _, _ = _run([NFT, "list", "table"] + table.split())
    return rc == 0


def table_stats(table=TABLE):
    """Return (chain_count, rule_count) for the live table."""
    rc, out, _ = _run([NFT, "list", "table"] + table.split())
    if rc != 0:
        return 0, 0
    chains = sum(1 for line in out.splitlines() if line.strip().startswith("chain "))
    rules = sum(
        1
        for line in out.splitlines()
        if line.strip()
        and not line.strip().startswith(("chain ", "table ", "}", "set ", "counter ", "elements", "type ", "flags ", "comment "))
        and line.rstrip().endswith(("accept", "drop", "return", "queue", "reject", "log", "counter"))
    )
    return chains, rules


def snapshot(table=TABLE, path=None):
    """Dump the live table to a replayable rollback file (table reset first)."""
    path = path or os.path.join(STATE_DIR, "rollback.nft")
    try:
        Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
        rc, out, err = _run([NFT, "list", "table"] + table.split())
        with open(path, "w") as handle:
            handle.write("table %s\ndelete table %s\n" % (table, table))
            if rc == 0:
                handle.write(out)
        os.chmod(path, 0o600)
        return path if rc == 0 else None
    except Exception:
        return None


def verify(table=TABLE, min_chains=MIN_CHAINS):
    chains, rules = table_stats(table)
    if chains < min_chains:
        return False, "table %s has %d chain(s), expected >= %d" % (
            table,
            chains,
            min_chains,
        )
    if rules < 1:
        return False, "table %s loaded but contains no rules" % table
    return True, "chains=%d rules=%d" % (chains, rules)


def apply(ruleset=RULESET, table=TABLE):
    ok, detail = preflight(ruleset)
    if not ok:
        alert("preflight failed", detail)
        return 1
    rollback = snapshot(table)
    rc, _, err = _run([NFT, "-f", ruleset])
    if rc != 0:
        alert("ruleset load failed", err.strip() or ("nft -f exited %d" % rc))
        return 1
    ok, detail = verify(table)
    if not ok:
        alert("post-load verification failed", detail)
        if rollback:
            rrc, _, rerr = _run([NFT, "-f", rollback])
            if rrc == 0:
                _write_state(rolled_back=True, rollback_at=time.time())
            else:
                alert("rollback failed", rerr.strip())
        return 1
    _write_state(
        last_apply_ok=True,
        last_apply_at=time.time(),
        applied_ruleset=str(ruleset),
        live=detail,
        rolled_back=False,
    )
    print("perimeter applied: %s" % detail)
    return 0


def health(ruleset=RULESET, table=TABLE):
    """Detect a vanished perimeter and heal it; loud on every absence."""
    if table_present(table):
        ok, detail = verify(table)
        if ok:
            _write_state(healthy=True, checked_at=time.time(), live=detail)
            print("perimeter healthy: %s" % detail)
            return 0
        alert("perimeter table present but incomplete", detail)
        return apply(ruleset, table)
    alert(
        "perimeter table absent",
        "no %s table loaded; reapplying %s" % (table, ruleset),
    )
    return apply(ruleset, table)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--health", action="store_true")
    mode.add_argument("--alert-only", action="store_true")
    parser.add_argument("--ruleset", default=RULESET)
    parser.add_argument("--table", default=TABLE)
    parser.add_argument("--detail", default="")
    args = parser.parse_args(argv)

    if args.preflight:
        ok, detail = preflight(args.ruleset)
        if not ok:
            alert("preflight failed", detail)
            return 1
        print("preflight ok")
        return 0
    if args.apply:
        return apply(args.ruleset, args.table)
    if args.health:
        return health(args.ruleset, args.table)
    state = _read_state()
    detail = args.detail or "unit failed; last apply %s" % (
        state.get("last_apply_at", "unknown")
    )
    alert("countersurveillance-block.service failed", detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
