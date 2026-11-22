"""Static safeguards for deploy.sh; no root, no nft, no network.

These code-review tests pin the two mistakes that produced a false-green
deploy on 2026-11-22: a rollout watchdog that fired *during* verification and
silently restored the previous ruleset, and no integrity check on the file
that actually landed.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = (ROOT / "deploy.sh").read_text()


class DeploySafeguardTests(unittest.TestCase):
    def test_watchdog_default_is_long_enough(self):
        self.assertIn(
            'WATCHDOG_SECS="${CS_WATCHDOG_SECS:-600}"',
            DEPLOY,
            "watchdog must default to 600s so verification cannot outlive it",
        )
        self.assertIn('sleep "$WATCHDOG_SECS"', DEPLOY)
        # The remote-SSH path carries its own copy; it must use the same fuse.
        self.assertIn('sleep "\\${CS_WATCHDOG_SECS:-600}"', DEPLOY)
        self.assertNotIn("sleep 60\n", DEPLOY, "the old 60s fuse must not return")

    def test_file_backup_is_assigned_before_the_watchdog_forks(self):
        backup_at = DEPLOY.index('RULESET_FILE_BACKUP="${RULESET_FILE}.pre-deploy')
        fork_at = DEPLOY.index("WATCHDOG_PID=$!")
        self.assertLess(
            backup_at,
            fork_at,
            "a subshell inherits variables at fork time; assigning the backup "
            "path after the fork leaves the rollback unable to restore the file",
        )

    def test_installed_ruleset_is_hash_verified(self):
        self.assertIn("SHA_WANT=$(sha256sum", DEPLOY)
        self.assertIn('SHA_GOT=$("${SUDO[@]}" sha256sum', DEPLOY)
        self.assertIn('if [ "$SHA_WANT" != "$SHA_GOT" ]', DEPLOY)

    def test_hash_is_rechecked_after_verification(self):
        verify_at = DEPLOY.index('if bash "${VERIFY_SCRIPT}"; then')
        recheck_at = DEPLOY.index("SHA_NOW=")
        self.assertGreater(
            recheck_at,
            verify_at,
            "the ruleset must be re-hashed after verification, since a fired "
            "watchdog or concurrent refresh can rewrite it mid-run",
        )
        self.assertIn('if [ "$POST_VERIFY_OK" = "1" ]', DEPLOY)

    def test_rollback_restores_the_file_not_only_the_table(self):
        # Watchdog path and explicit failure path both restore the on-disk ruleset.
        self.assertGreaterEqual(
            DEPLOY.count('cp -a "$RULESET_FILE_BACKUP" "$RULESET_FILE"'), 2
        )

    def test_watchdog_alerts_at_alert_priority(self):
        self.assertIn("logger -t cs-watchdog -p daemon.alert", DEPLOY)

    def test_guard_is_installed_before_the_unit_restarts(self):
        install_at = DEPLOY.index("nft_guard.py\" /usr/local/sbin/nft-guard.py")
        restart_at = DEPLOY.index("systemctl restart countersurveillance-block.service")
        self.assertLess(install_at, restart_at)

    def test_egress_pin_is_consumed_unless_refresh_requested(self):
        self.assertIn("refresh_egress()", DEPLOY)
        self.assertIn('--use-pin "$pin"', DEPLOY)
        self.assertIn('--emit-pin "$pin"', DEPLOY)
        self.assertIn('CS_REFRESH_EGRESS', DEPLOY)
        # Both the local and remote paths must go through the shared helper.
        self.assertEqual(DEPLOY.count("refresh_egress\n"), 2)

    def test_repin_driver_is_dry_by_default(self):
        script = (ROOT / "tools" / "repin.sh").read_text()
        self.assertIn("WRITE=0", script)
        self.assertIn("COMMIT=0", script)
        self.assertIn("DEPLOY=0", script)
        # Candidate rendering must not mutate the tracked ruleset.
        self.assertIn('--output "${CANDIDATE}.nft"', script)
        self.assertIn("--diff-pin", script)


if __name__ == "__main__":
    unittest.main()
