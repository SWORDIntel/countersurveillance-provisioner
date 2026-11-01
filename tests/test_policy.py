"""Offline policy/schema regression tests; no public network access."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("policy", ROOT / "tools/update_blacklist.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def record(v4=None, v6=None, **extra):
    return {"name": "Synthetic fixture, never deployed", "ipv4": v4 or [], "ipv6": v6 or [],
            "sources": ["https://example.com/policy-test"], "reviewed_at": "2020-01-01",
            "expires_at": "2099-01-01", **extra}


def manifest(scope, targets=None):
    return {"schema_version": 3 if scope == "ingress" else 1,
            "scope": scope, "targets": targets or {}}


def render(directory, ingress=None, outbound=None, strict=False, web=False, logging=True,
           resolver=None):
    directory = Path(directory)
    for name, obj in (("ingress.json", ingress or manifest("ingress")),
                      ("outbound.json", outbound or manifest("outbound")),
                      ("domains.json", {"required": ["example.com"], "optional": []})):
        (directory / name).write_text(json.dumps(obj))
    overrides = dict(JSON_PATH=str(directory / "ingress.json"),
                     OUTBOUND_PATH=str(directory / "outbound.json"),
                     DOMAINS_PATH=str(directory / "domains.json"),
                     OUTPUT_NFT=str(directory / "rules.nft"),
                     STRICT_EGRESS=strict, STRICT_ALLOW_WEB=web,
                     STRICT_LOG_DROPS=logging, TRUSTED_EGRESS_UNITS=[])
    resolver = resolver or (lambda names, family: (["93.184.216.35"] if family == socket.AF_INET else [], []))
    with patch.multiple(policy, **overrides), patch.object(policy, "resolve_domains", resolver), contextlib.redirect_stdout(io.StringIO()):
        policy.main()
    return (directory / "rules.nft").read_text()


def chain(text, name):
    start = text.index("    chain " + name + " {")
    return text[start:text.index("\n    }", start)]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def load(self, obj, scope="ingress"):
        path = self.directory / "test.json"
        path.write_text(json.dumps(obj))
        return policy.load_scoped_targets(path, scope)

    def test_source_scopes_never_cross_into_output_or_transit(self):
        ingress = manifest("ingress", {"fixture": record(["162.142.125.0/24"], ["2620:96:e000:b0cc:e::/80"])})
        text = render(self.directory, ingress)
        for name in ("output", "forward"):
            contents = chain(text, name)
            self.assertNotIn("@blocked_", contents)
            self.assertNotIn("@dynamic_scanners_", contents)
            self.assertIn("@outbound_block_v4", contents)
            self.assertIn("@outbound_block_v6", contents)
            self.assertIn("policy accept", contents)
        self.assertIn("@blocked_v4", chain(text, "input"))
        self.assertIn("@dynamic_scanners_v6", chain(text, "input"))
        self.assertIn("fib daddr type != local return", chain(text, "prerouting"))

    def test_all_policy_profiles(self):
        for strict in (False, True):
            for web in (False, True):
                for logging in (False, True):
                    with self.subTest(strict=strict, web=web, logging=logging):
                        text = render(self.directory, strict=strict, web=web, logging=logging)
                        for name, suffix in (("output", "out"), ("forward", "fwd")):
                            contents = chain(text, name)
                            self.assertIn("policy " + ("drop" if strict else "accept"), contents)
                            self.assertEqual("udp dport 443" in contents, web and (strict or logging))
                            self.assertEqual(f"cs-{'strict' if strict else 'audit'}-{suffix} " in contents, logging)
                            self.assertNotIn("level info", contents)

    def test_log_limiter_precedes_log_and_cannot_gate_verdict(self):
        text = render(self.directory)
        for name in ("ingress_scanner_drop", "ingress_jail_drop", "outbound_drop", "forward_drop"):
            contents = chain(text, name)
            self.assertLess(contents.index("limit rate"), contents.index("log prefix"))
            self.assertIn('group 1\n        counter drop', contents)
        for line in text.splitlines():
            if "log prefix" in line:
                self.assertIn("group 1", line)
                self.assertLess(line.index("limit rate"), line.index("log prefix"))

    def test_outbound_denies_precede_conntrack_and_web_exemptions(self):
        text = render(self.directory, web=True)
        for name in ("output", "forward"):
            contents = chain(text, name)
            self.assertLess(contents.index("@outbound_block_v4"), contents.index("ct state established"))
            self.assertLess(contents.index("@outbound_block_v6"), contents.index("tcp dport"))

    def test_empty_outbound_is_valid_not_a_scanner_fallback(self):
        self.assertEqual(self.load(manifest("outbound"), "outbound"), ([], []))

    def test_wrong_or_legacy_scope_rejected(self):
        for obj in ({"targets": {}}, manifest("outbound"), {**manifest("ingress"), "schema_version": 2}):
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                self.load(obj)

    def test_ingress_requires_review_provenance_and_family(self):
        base = record(["162.142.125.0/24"])
        variants = [{**base, "sources": []}, {**base, "sources": ["http://example.com"]},
                    {**base, "reviewed_at": "2200-01-01"}, {**base, "expires_at": "2019-01-01"},
                    {**base, "ipv4": ["2620:96:e000::/48"]}, {**base, "ipv4": "162.142.125.0/24"}]
        for value in variants:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                self.load(manifest("ingress", {"x": value}))

    def test_outbound_requires_exact_public_dedicated_endpoint_and_evidence(self):
        base = record(["93.184.216.34/32"], ["2001:4860:1111::dead/128"],
                      category="tracking", dedicated=True, evidence="Synthetic fixture")
        self.assertEqual(len(self.load(manifest("outbound", {"x": base}), "outbound")[0]), 1)
        variants = [{**base, "dedicated": False}, {**base, "category": "scanner"},
                    {**base, "evidence": ""}, {**base, "ipv4": ["93.184.216.0/24"]},
                    {**base, "ipv4": ["192.168.1.90/32"]}, {**base, "ipv6": ["fc00::1/128"]}]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load(manifest("outbound", {"x": value}), "outbound")

    def test_expired_entries_removed_not_kept_or_reclassified(self):
        for scope in ("ingress", "outbound"):
            value = record(["93.184.216.34/32"], expires_at="2021-01-01",
                           category="tracking", dedicated=True, evidence="Synthetic fixture")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(self.load(manifest(scope, {"x": value}), scope), ([], []))
            self.assertIn("Expired", err.getvalue())

    def test_protected_infrastructure_dual_stack(self):
        for block, allow in (("192.168.1.0/24", "192.168.0.0/16"),
                             ("2001:4860:4860::8888/128", "2001:4860:4860::8888/128")):
            with self.subTest(block=block), self.assertRaises(ValueError):
                policy.validate_overlaps([block], [allow], "fixture")
        policy.validate_overlaps(["93.184.216.34/32"], ["fc00::/7"], "fixture")

    def test_dns_failure_keeps_last_file(self):
        old = self.directory / "rules.nft"
        old.write_text("last known good")
        def failed(names, family):
            return [], [(name, socket.gaierror("fixture")) for name in names]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            render(self.directory, resolver=failed)
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(old.read_text(), "last known good")

    def test_invalid_manifest_keeps_last_file(self):
        old = self.directory / "rules.nft"
        old.write_text("last known good")
        with self.assertRaises(ValueError):
            render(self.directory, outbound={"schema_version": 99, "scope": "outbound", "targets": {}})
        self.assertEqual(old.read_text(), "last known good")

    def test_strict_allowances_match_window_evidence(self):
        out, fwd = policy.strict_allowances(True, probe=lambda p: False)
        for lines, chain_name in ((out, "output"), (fwd, "forward")):
            joined = "\n".join(lines)
            for needle in ("tcp dport { 22, 80, 443 }", "udp dport 443",
                           "udp dport 123", "udp dport 53", "tcp dport 53",
                           "tcp dport 25", "udp dport 3478", "tcp dport 3478",
                           "tcp dport 5228",
                           "udp dport { 1025, 41641, 51820, 51821 }",
                           "udp sport 68 udp dport 67",
                           "meta l4proto ipv6-icmp"):
                self.assertIn(needle, joined, f"{chain_name}: {needle}")
            self.assertNotIn("he-ipv6", joined, chain_name)
        self.assertNotIn("parrot0", "\n".join(fwd))
        self.assertNotIn("cgroupv2", "\n".join(out))

    def test_strict_allowance_probes_emit_node_specific_rules(self):
        out, fwd = policy.strict_allowances(False, probe=lambda p: True)
        self.assertIn('oifname "he-ipv6" accept', "\n".join(out))
        self.assertIn('oifname "he-ipv6" accept', "\n".join(fwd))
        self.assertIn("ip protocol 41 accept", "\n".join(out))
        self.assertNotIn("ip protocol 41", "\n".join(fwd))
        self.assertIn('iifname "parrot0" accept', "\n".join(fwd))
        self.assertNotIn("parrot0", "\n".join(out))
        # transmission-daemon.service sits directly under system.slice.
        self.assertIn('socket cgroupv2 level 2 "system.slice/transmission-daemon.service"', "\n".join(out))

    def test_allowances_precede_shadow_log_tail_after_outbound_blocks(self):
        text = render(self.directory, strict=False, web=True, logging=True)
        for name in ("output", "forward"):
            contents = chain(text, name)
            self.assertLess(contents.index("@outbound_block_v4"), contents.index("udp dport 123"))
            self.assertLess(contents.index("udp dport 123"), contents.index("log prefix"))
            self.assertLess(contents.index("meta l4proto ipv6-icmp"), contents.index("log prefix"))

    def test_collapse_does_not_change_coverage(self):
        self.assertEqual(policy.collapse_and_clean(["162.142.125.0/25", "162.142.125.128/25"], policy.ipaddress.ip_network), ["162.142.125.0/24"])


if __name__ == "__main__":
    unittest.main()
