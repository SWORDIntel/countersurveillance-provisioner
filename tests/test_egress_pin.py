"""Offline tests for the reviewed egress pin; no DNS, no nft, no root."""
import importlib.util
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "ubl", ROOT / "tools" / "update_blacklist.py"
)
ubl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ubl)


class PinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "egress.pinned.json"
        self.v4 = {"a.example": ["192.0.2.1"], "b.example": ["192.0.2.2"]}
        self.v6 = {"a.example": ["2001:db8::1"]}

    def write(self, **kwargs):
        with patch.dict("os.environ", {"SOURCE_DATE_EPOCH_ISO": "2026-01-01T00:00:00Z"}):
            ubl.write_pin(
                str(self.path),
                kwargs.get("required", ["a.example"]),
                kwargs.get("optional", ["b.example"]),
                self.v4,
                self.v6,
                "deadbeef",
            )

    def test_write_is_deterministic_for_same_inputs(self):
        self.write()
        first = self.path.read_bytes()
        self.write()
        self.assertEqual(first, self.path.read_bytes())

    def test_round_trip_preserves_attribution(self):
        self.write()
        pin = ubl.load_pin(str(self.path))
        self.assertEqual(pin["schema"], 1)
        self.assertEqual(pin["v4"], self.v4)
        self.assertEqual(pin["v6"], self.v6)
        self.assertEqual(pin["ruleset_sha256"], "deadbeef")

    def test_rejects_unknown_schema(self):
        self.path.write_text(json.dumps({"schema": 99, "v4": {}, "v6": {}}))
        with self.assertRaises(ValueError):
            ubl.load_pin(str(self.path))

    def test_resolve_from_pin_returns_pinned_addresses(self):
        self.write()
        pin = ubl.load_pin(str(self.path))
        v4, v6 = ubl.resolve_from_pin(pin, ["a.example"], ["b.example"])
        self.assertEqual(v4["a.example"], ["192.0.2.1"])
        self.assertEqual(v4["b.example"], ["192.0.2.2"])
        self.assertEqual(v6["a.example"], ["2001:db8::1"])

    def test_resolve_from_pin_rejects_uncovered_required_domain(self):
        self.write(required=["a.example"])
        pin = ubl.load_pin(str(self.path))
        with self.assertRaises(ValueError) as ctx:
            ubl.resolve_from_pin(pin, ["a.example", "missing.example"], [])
        self.assertIn("missing.example", str(ctx.exception))

    def test_drift_detects_added_and_removed_addresses(self):
        self.write()
        pin = ubl.load_pin(str(self.path))
        live = {
            socket.AF_INET: {"a.example": ["192.0.2.9"], "b.example": ["192.0.2.2"]},
            socket.AF_INET6: {"a.example": ["2001:db8::1"]},
        }

        def fake_resolve(names, family):
            return dict(live[family]), []

        with patch.object(ubl, "resolve_map", fake_resolve):
            drift = ubl.check_pin_drift(pin, ["a.example"], ["b.example"])
        joined = "\n".join(drift)
        self.assertIn("+192.0.2.9", joined)
        self.assertIn("-192.0.2.1", joined)
        self.assertNotIn("b.example", joined, "unchanged domains must not report drift")

    def test_pin_diff_reports_added_and_removed(self):
        old = {"v4": {"a": ["192.0.2.1", "192.0.2.2"]}, "v6": {}}
        new = {"v4": {"a": ["192.0.2.2", "192.0.2.9"]}, "v6": {}}
        lines, added, removed = ubl.pin_diff(old, new)
        self.assertEqual((added, removed), (1, 1))
        self.assertEqual(len(lines), 1)
        self.assertIn("+192.0.2.9", lines[0])
        self.assertIn("-192.0.2.1", lines[0])

    def test_pin_diff_ignores_unchanged_and_new_domains(self):
        old = {"v4": {"a": ["192.0.2.1"]}, "v6": {}}
        new = {"v4": {"a": ["192.0.2.1"], "b": ["192.0.2.5"]}, "v6": {}}
        lines, added, removed = ubl.pin_diff(old, new)
        self.assertEqual((added, removed), (1, 0))
        self.assertIn("b", lines[0])

    def test_pin_diff_identical_pins_are_silent(self):
        pin = {"v4": {"a": ["192.0.2.1"]}, "v6": {"a": ["2001:db8::1"]}}
        lines, added, removed = ubl.pin_diff(pin, pin)
        self.assertEqual(lines, [])
        self.assertEqual((added, removed), (0, 0))


if __name__ == "__main__":
    unittest.main()
