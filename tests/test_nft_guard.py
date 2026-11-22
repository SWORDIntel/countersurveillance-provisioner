"""Offline tests for the perimeter guard; no nft, no network, no root."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guard", ROOT / "tools/nft_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

LIVE_TABLE = """table inet countersurveillance {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related counter accept
\t\ttcp dport 22 counter accept
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy drop;
\t\tct state established counter accept
\t}
}
"""


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.events = base / "events.jsonl"
        self.state_dir = base / "state"
        self.ruleset = base / "countersurveillance.nft"
        self.ruleset.write_text("table inet countersurveillance { }\n")
        self._patches = [
            patch.object(guard, "EVENTS_FILE", str(self.events)),
            patch.object(guard, "STATE_DIR", str(self.state_dir)),
            patch.object(guard, "STATE_FILE", str(self.state_dir / "perimeter.state.json")),
            patch.object(guard, "WEBHOOK", ""),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self.tmp.cleanup)
        for p in self._patches:
            self.addCleanup(p.stop)

    def events_written(self):
        if not self.events.exists():
            return []
        return [json.loads(line) for line in self.events.read_text().splitlines() if line]

    # -- preflight ---------------------------------------------------------
    def test_preflight_failure_alerts_and_exits_nonzero(self):
        def fake_run(argv, timeout=30):
            return 1, "", "Error: cgroupv2 path fails: No such file or directory"

        with patch.object(guard, "_run", fake_run):
            rc = guard.main(["--preflight", "--ruleset", str(self.ruleset)])
        self.assertEqual(rc, 1)
        events = self.events_written()
        self.assertTrue(events, "a failed preflight must emit an alert event")
        self.assertEqual(events[-1]["source"], "cs-perimeter-guard")
        self.assertIn("cgroupv2", events[-1]["detail"])

    def test_preflight_missing_ruleset_alerts(self):
        with patch.object(guard, "_run", lambda *a, **k: (0, "", "")):
            rc = guard.main(["--preflight", "--ruleset", "/nonexistent/file.nft"])
        self.assertEqual(rc, 1)
        self.assertTrue(self.events_written())

    # -- apply -------------------------------------------------------------
    def test_apply_success_records_state(self):
        calls = []

        def fake_run(argv, timeout=30):
            calls.append(argv)
            if "list" in argv:
                return 0, LIVE_TABLE, ""
            return 0, "", ""

        with patch.object(guard, "_run", fake_run):
            rc = guard.main(["--apply", "--ruleset", str(self.ruleset)])
        self.assertEqual(rc, 0)
        state = json.loads((self.state_dir / "perimeter.state.json").read_text())
        self.assertTrue(state["last_apply_ok"])
        self.assertIn("chains=", state["live"])
        self.assertFalse(self.events_written(), "success must not alert")

    def test_apply_load_failure_alerts_without_rollback_when_empty(self):
        def fake_run(argv, timeout=30):
            if "-c" in argv:
                return 0, "", ""
            if "list" in argv:  # no prior table -> nothing to snapshot
                return 1, "", "No such file or directory"
            return 1, "", "Error: syntax error, unexpected newline"

        with patch.object(guard, "_run", fake_run):
            rc = guard.main(["--apply", "--ruleset", str(self.ruleset)])
        self.assertEqual(rc, 1)
        events = self.events_written()
        self.assertTrue(any("ruleset load failed" in e["reason"] for e in events))

    def test_verification_failure_triggers_rollback_and_alert(self):
        loaded = {"n": 0}

        def fake_run(argv, timeout=30):
            if "-c" in argv:
                return 0, "", ""
            if "list" in argv:
                # 1st: snapshot of live table; 2nd: post-load verify (bad)
                loaded["n"] += 1
                if loaded["n"] == 1:
                    return 0, LIVE_TABLE, ""
                return 0, "table inet countersurveillance {\n}\n", ""
            if "delete" in argv[1] if len(argv) > 1 else False:
                return 0, "", ""
            return 0, "", ""

        with patch.object(guard, "_run", fake_run):
            rc = guard.main(["--apply", "--ruleset", str(self.ruleset)])
        self.assertEqual(rc, 1)
        reasons = [e["reason"] for e in self.events_written()]
        self.assertTrue(any("verification failed" in r for r in reasons), reasons)

    # -- health ------------------------------------------------------------
    def test_health_alerts_and_reapplies_when_table_missing(self):
        applied = {"n": 0}

        def fake_run(argv, timeout=30):
            if "-c" in argv:
                return 0, "", ""
            if "list" in argv:
                # absent during health check, healthy after re-apply
                if applied["n"] == 0:
                    return 1, "", "No such file or directory"
                return 0, LIVE_TABLE, ""
            if "-f" in argv:
                applied["n"] += 1
                return 0, "", ""
            return 0, "", ""

        with patch.object(guard, "_run", fake_run):
            rc = guard.main(["--health", "--ruleset", str(self.ruleset)])
        self.assertEqual(rc, 0, "health must heal the perimeter and report success")
        reasons = [e["reason"] for e in self.events_written()]
        self.assertTrue(any("perimeter table absent" in r for r in reasons), reasons)

    def test_health_quiet_when_perimeter_intact(self):
        with patch.object(guard, "_run", lambda argv, timeout=30: (0, LIVE_TABLE, "")):
            rc = guard.main(["--health", "--ruleset", str(self.ruleset)])
        self.assertEqual(rc, 0)
        self.assertFalse(self.events_written(), "a healthy perimeter must stay quiet")

    # -- alert-only --------------------------------------------------------
    def test_alert_only_emits_event(self):
        rc = guard.main(["--alert-only", "--detail", "unit failed"])
        self.assertEqual(rc, 0)
        events = self.events_written()
        self.assertTrue(events)
        self.assertIn("unit failed", events[-1]["detail"])


if __name__ == "__main__":
    unittest.main()
