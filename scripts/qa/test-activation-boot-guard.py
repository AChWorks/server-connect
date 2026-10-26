#!/usr/bin/env python3
"""Hermetic checks for cause-specific QA boot recovery refusal receipts."""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("activation-boot-guard.py")
SPEC = importlib.util.spec_from_file_location("sc_activation_boot_qa", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class BootRefusalTests(unittest.TestCase):
    def check_scope(self, rows, expected_code, expected_marker):
        seen = []

        def ip_fixture(*args):
            seen.append(args)
            return rows.get(args, [])

        stderr = io.StringIO()
        with mock.patch.object(guard, "ip_rows", side_effect=ip_fixture):
            with mock.patch.object(guard, "main", side_effect=guard.require_empty_guest_owned_scope):
                with contextlib.redirect_stderr(stderr):
                    code = guard.run()
        self.assertEqual(code, expected_code)
        if expected_marker:
            self.assertIn(expected_marker, stderr.getvalue())
        else:
            self.assertEqual(stderr.getvalue(), "")
        return seen

    def test_foreign_link_only(self):
        seen = self.check_scope(
            {("link", "show"): [{"ifname": "lo"}, {"ifname": "scqafx0"}]},
            41, "QA_BOOT_REFUSAL_CODE=FOREIGN_LINK",
        )
        self.assertNotIn(("-4", "route", "show", "table", "all"), seen)

    def test_foreign_route_only_with_clean_links(self):
        seen = self.check_scope(
            {
                ("link", "show"): [{"ifname": "lo"}],
                ("-4", "route", "show", "table", "all"): [
                    {"dst": "8.8.8.0/24", "dev": "lo", "table": 20120}
                ],
            },
            42, "QA_BOOT_REFUSAL_CODE=FOREIGN_ROUTE",
        )
        self.assertIn(("-4", "route", "show", "table", "all"), seen)

    def test_foreign_rule_only(self):
        self.check_scope(
            {
                ("link", "show"): [{"ifname": "lo"}],
                ("-4", "rule", "show"): [{"priority": 30001, "table": 20120}],
            },
            43, "QA_BOOT_REFUSAL_CODE=FOREIGN_RULE",
        )

    def test_native_inspection_failure_is_not_conflict(self):
        stderr = io.StringIO()
        with mock.patch.object(
            guard, "ip_rows", side_effect=subprocess.CalledProcessError(1, ["/usr/bin/ip"])
        ):
            with mock.patch.object(guard, "main", side_effect=guard.require_empty_guest_owned_scope):
                with contextlib.redirect_stderr(stderr):
                    code = guard.run()
        self.assertEqual(code, 24)
        self.assertIn("QA_BOOT_FAIL_CLOSED_OTHER", stderr.getvalue())
        self.assertNotIn("QA_BOOT_REFUSAL_CODE", stderr.getvalue())

    def test_native_inspection_timeout_is_not_conflict(self):
        stderr = io.StringIO()
        with mock.patch.object(
            guard, "ip_rows", side_effect=subprocess.TimeoutExpired(["/usr/bin/ip"], 5)
        ):
            with mock.patch.object(guard, "main", side_effect=guard.require_empty_guest_owned_scope):
                with contextlib.redirect_stderr(stderr):
                    code = guard.run()
        self.assertEqual(code, 24)
        self.assertNotIn("QA_BOOT_REFUSAL_CODE", stderr.getvalue())

    def test_missing_or_invalid_invocation_is_not_conflict(self):
        for value in ("", "not-a-systemd-invocation"):
            with self.subTest(invocation=value):
                stderr = io.StringIO()
                with mock.patch.object(guard.os, "getuid", return_value=0):
                    with mock.patch.object(sys, "argv", [str(SCRIPT), "recover"]):
                        with mock.patch.dict(os.environ, {"INVOCATION_ID": value}):
                            with contextlib.redirect_stderr(stderr):
                                code = guard.run()
                self.assertEqual(code, 24)
                self.assertIn("QA_BOOT_FAIL_CLOSED_OTHER", stderr.getvalue())
                self.assertNotIn("QA_BOOT_REFUSAL_CODE", stderr.getvalue())

    def test_invalid_journal_is_not_conflict(self):
        stderr = io.StringIO()
        with mock.patch.object(guard, "main", side_effect=ValueError("invalid journal")):
            with contextlib.redirect_stderr(stderr):
                code = guard.run()
        self.assertEqual(code, 24)
        self.assertNotIn("QA_BOOT_REFUSAL_CODE", stderr.getvalue())

    def test_clean_observation_succeeds(self):
        seen = self.check_scope(
            {
                ("link", "show"): [{"ifname": "lo"}],
                ("-4", "rule", "show"): [{"priority": 0}, {"priority": 32766}],
                ("-6", "rule", "show"): [{"priority": 0}, {"priority": 32766}],
            },
            0, "",
        )
        self.assertIn(("-6", "route", "show", "table", "all"), seen)


if __name__ == "__main__":
    unittest.main(verbosity=2)
