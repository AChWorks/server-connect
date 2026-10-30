#!/usr/bin/env python3
"""Fixture ownership and bookkeeping regressions; no native activity."""

import argparse
import contextlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch


path = Path(__file__).with_name("supervised-product-tun.py")
spec = importlib.util.spec_from_file_location("supervised_fixture", path)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

METADATA = {"metainfo": {"version": "1.1.3", "json_schema_version": 1}}
TABLE = {"table": {"family": "inet", "name": "scqasupforeign", "handle": 42}}
RECEIPT = json.dumps({"nftables": [METADATA, TABLE, {"chain": {
    "family": "inet", "table": "scqasupforeign", "name": "unrelated", "handle": 43,
}}]})


class FakeNFT:
    """Model committed state separately from the command's reported outcome."""

    def __init__(self):
        self.table = None
        self.creation = "success"
        self.snapshot_error = False
        self.inventory_error = False
        self.inventory_text = None
        self.inventories = 0
        self.creations = 0
        self.deletions = 0

    def run(self, argv, *, input, capture_output, text, timeout):
        assert capture_output and text and 0 < timeout <= 20
        code, output, error = 0, "", ""
        if argv == ["nft", "-j", "list", "tables"]:
            self.inventories += 1
            if self.inventory_error:
                code, error = 1, "inventory unavailable"
            elif self.inventory_text is not None:
                output = self.inventory_text
            else:
                output = json.dumps({"nftables": [METADATA] + ([TABLE] if self.table is not None else [])})
        elif argv in (["nft", "-j", "list", "table", "inet", "scqasupforeign"],
                      ["nft", "-j", "-a", "list", "table", "inet", "scqasupforeign"]):
            if self.table is None or ("-a" in argv and self.snapshot_error):
                code, error = 1, "table read failed"
            else:
                output = self.table
        elif argv == ["nft", "-f", "-"]:
            self.creations += 1
            if self.creation != "rejected":
                self.table = RECEIPT
            if self.creation == "timeout_after_commit":
                raise subprocess.TimeoutExpired(argv, timeout)
            if self.creation in ("rejected", "error_after_commit"):
                code, error = 1, "creation did not return success"
        elif argv == ["nft", "delete", "table", "inet", "scqasupforeign"]:
            self.deletions += 1
            self.table = None
        else:
            raise AssertionError("unexpected command in ordinary regression: " + repr(argv))
        return subprocess.CompletedProcess(argv, code, stdout=output, stderr=error)


class ForeignCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeNFT()
        self.fixture = self.new_fixture()
        self.runner = patch.object(driver.subprocess, "run", side_effect=self.fake.run)
        self.runner.start()
        self.addCleanup(self.runner.stop)
        self.journal = patch.object(driver, "JOURNAL", Mock(exists=Mock(return_value=False)))
        self.journal.start()
        self.addCleanup(self.journal.stop)

    @staticmethod
    def new_fixture():
        return driver.Fixture(argparse.Namespace(profile="a" * 16, upstream_pid=2, ipv6=False))

    def test_rejected_creation_cleanup_proves_absence_without_delete(self):
        self.fake.creation = "rejected"
        with self.assertRaises(AssertionError):
            self.fixture.add_foreign()
        self.assertTrue(self.fixture.foreign)
        self.assertIsNone(self.fixture.foreign_snapshot)
        self.fixture.cleanup()
        self.assertFalse(self.fixture.foreign)
        self.assertIsNone(self.fake.table)
        self.assertEqual(self.fake.inventories, 2)
        self.assertEqual(self.fake.deletions, 0)

    def test_ambiguous_creation_retains_unreceipted_table(self):
        for creation, snapshot_error in (("error_after_commit", False),
                                         ("timeout_after_commit", False), ("success", True)):
            with self.subTest(creation=creation, snapshot_error=snapshot_error):
                self.fixture = self.new_fixture()
                self.fake.table = None
                self.fake.creation = creation
                self.fake.snapshot_error = snapshot_error
                with self.assertRaises((AssertionError, subprocess.TimeoutExpired)):
                    self.fixture.add_foreign()
                self.assertIsNone(self.fixture.foreign_snapshot)
                with self.assertRaisesRegex(AssertionError, "unreceipted.*retained"):
                    self.fixture.cleanup()
                self.assertTrue(self.fixture.foreign)
                self.assertEqual(self.fake.table, RECEIPT)
                self.assertEqual(self.fake.deletions, 0)

    def test_unreadable_or_malformed_inventory_never_proves_absence(self):
        self.fixture.foreign = True
        bad_documents = ("not JSON", "{}", "[]", '{"nftables":{}}', '{"nftables":[]}',
                         json.dumps({"nftables": [{"table": {"family": "inet", "name": "unrelated", "handle": 99}}]}),
                         '{"nftables":[null]}', '{"nftables":[{"table":{}}]}',
                         '{"nftables":[{"chain":{}}]}',
                         '{"nftables":[{"metainfo":{"json_schema_version":2}}]}',
                         json.dumps({"nftables": [TABLE, TABLE]}))
        for document in (None, *bad_documents):
            with self.subTest(document=document):
                self.fake.inventory_error = document is None
                self.fake.inventory_text = document
                with self.assertRaises((AssertionError, ValueError)):
                    self.fixture.cleanup()
                self.assertTrue(self.fixture.foreign)
                self.assertEqual(self.fake.deletions, 0)

    def test_existing_table_is_never_adopted(self):
        self.fake.table = RECEIPT
        with self.assertRaisesRegex(AssertionError, "already exists"):
            self.fixture.add_foreign()
        self.fixture.cleanup()
        self.assertFalse(self.fixture.foreign)
        self.assertEqual(self.fake.table, RECEIPT)
        self.assertEqual((self.fake.creations, self.fake.deletions), (0, 0))

    def test_exact_receipt_allows_cleanup(self):
        self.fixture.add_foreign()
        self.assertEqual(self.fixture.foreign_snapshot, RECEIPT)
        self.fixture.cleanup()
        self.assertFalse(self.fixture.foreign)
        self.assertIsNone(self.fixture.foreign_snapshot)
        self.assertIsNone(self.fake.table)
        self.assertEqual(self.fake.deletions, 1)

    def test_changed_receipt_retains_table(self):
        self.fixture.add_foreign()
        changed = RECEIPT.replace('"handle": 42', '"handle": 44')
        self.assertNotEqual(changed, RECEIPT)
        self.fake.table = changed
        with self.assertRaisesRegex(AssertionError, "receipt changed"):
            self.fixture.cleanup()
        self.assertTrue(self.fixture.foreign)
        self.assertEqual(self.fixture.foreign_snapshot, RECEIPT)
        self.assertEqual(self.fake.table, changed)
        self.assertEqual(self.fake.deletions, 0)


class FakeExecutor:
    def __init__(self, unit):
        self.unit = unit
        self.device, self.inode, self.content = 7, 41, b"original installed executor"
        self.original_identity = (self.device, self.inode, self.content)
        self.regular, self.symlink = True, False
        self.resets = []
        self.properties = {
            "ActiveState": "failed", "Result": "signal", "LoadState": "loaded",
            "MainPID": "0", "ControlPID": "0", "Job": "", "DropInPaths": "",
            "FragmentPath": str(self),
        }

    def __str__(self):
        return "/etc/systemd/system/" + self.unit

    def __truediv__(self, unit):
        assert unit == self.unit
        return self

    def is_file(self):
        return self.regular

    def is_symlink(self):
        return self.symlink

    def stat(self):
        return argparse.Namespace(st_dev=self.device, st_ino=self.inode)

    def read_bytes(self):
        return self.content

    def show(self, unit, prop):
        assert unit == self.unit
        return self.properties[prop]

    def command(self, argv):
        assert argv == ["systemctl", "reset-failed", self.unit]
        self.resets.append(argv)
        self.properties.update(ActiveState="inactive", Result="success")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


class ExecutorBookkeepingTests(unittest.TestCase):
    def exercise(self, fake):
        fixture = ForeignCleanupTests.new_fixture()
        # Run the actual bounded wait with a synthetic clock; no sleeping,
        # filesystem changes, service manager, or native commands are used.
        with patch.object(driver, "UNITS", fake), \
                patch.object(fixture, "show", side_effect=fake.show), \
                patch.object(fixture, "command", side_effect=fake.command), \
                patch.object(driver.time, "monotonic", side_effect=itertools.count()), \
                patch.object(driver.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            fixture.reset_failed_executor(fake.unit, fake.original_identity, "failed")

    def test_inactive_or_collected_executor_needs_no_reset(self):
        for unit in (driver.HEALTH, driver.RECOVERY):
            for collected in (False, True):
                with self.subTest(unit=unit, collected=collected):
                    fake = FakeExecutor(unit)
                    fake.properties.update(ActiveState="inactive", Result="success")
                    if collected:
                        fake.properties.update(LoadState="not-found", FragmentPath="")
                    self.exercise(fake)
                    self.assertEqual(fake.resets, [])

    def test_authentic_idle_failed_executor_resets_only_exact_role(self):
        for unit in (driver.HEALTH, driver.RECOVERY):
            with self.subTest(unit=unit):
                fake = FakeExecutor(unit)
                self.exercise(fake)
                self.assertEqual(fake.resets, [["systemctl", "reset-failed", unit]])
                self.assertEqual(fake.properties["ActiveState"], "inactive")
                self.assertEqual(fake.properties["Result"], "success")

    def test_foreign_or_replaced_failed_executor_is_rejected(self):
        mutations = (("device", 8), ("inode", 42), ("content", b"replacement"),
                     ("regular", False), ("symlink", True), ("LoadState", "masked"),
                     ("FragmentPath", "/run/systemd/system/foreign.service"),
                     ("DropInPaths", "/etc/systemd/system/foreign.conf"))
        for unit in (driver.HEALTH, driver.RECOVERY):
            for field, value in mutations:
                with self.subTest(unit=unit, changed=field):
                    fake = FakeExecutor(unit)
                    if field in fake.properties:
                        fake.properties[field] = value
                    else:
                        setattr(fake, field, value)
                    with self.assertRaises(AssertionError):
                        self.exercise(fake)
                    self.assertEqual(fake.resets, [])

    def test_busy_executor_is_rejected_without_reset(self):
        for unit in (driver.HEALTH, driver.RECOVERY):
            for field, value in (("ActiveState", "activating"), ("MainPID", "17"),
                                 ("ControlPID", "18"), ("Job", "19")):
                with self.subTest(unit=unit, busy=field):
                    fake = FakeExecutor(unit)
                    fake.properties[field] = value
                    with self.assertRaisesRegex(AssertionError, "timed out.*idle executor"):
                        self.exercise(fake)
                    self.assertEqual(fake.resets, [])


class FailureReportingTests(unittest.TestCase):
    def run_main(self, original):
        fixture = Mock(started=time.monotonic())
        fixture.start.side_effect = original
        cleanup_error = AssertionError("unreceipted table retained")
        fixture.cleanup.side_effect = cleanup_error
        output = io.StringIO()
        argv = ["supervised-fixture", "--profile", "a" * 16, "--upstream-pid", "2", "--ipv6"]
        with patch.object(driver, "Fixture", return_value=fixture), patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(output):
            with self.assertRaises(type(original or cleanup_error)) as raised:
                driver.main()
        self.assertIs(raised.exception, original or cleanup_error)
        fixture.cleanup.assert_called_once_with()
        self.assertIn("SUPERVISED_TUN_FAILURE_CLEANUP_UNRESOLVED=AssertionError: unreceipted table retained", output.getvalue())
        return fixture

    def test_cleanup_failure_does_not_replace_acceptance_failure(self):
        fixture = self.run_main(RuntimeError("acceptance witness failed"))
        fixture.diagnostics.assert_called_once_with()

    def test_cleanup_failure_after_success_still_fails_run(self):
        self.run_main(None)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("SUPERVISED_FIXTURE_CREATION_CLEANUP_BOUNDARIES=PASS")
    print("SUPERVISED_FIXTURE_EXACT_FAILED_EXECUTOR_BOOKKEEPING=PASS")
