#!/usr/bin/env python3
"""Fixture ownership and bookkeeping regressions; no native activity."""

import argparse
import contextlib
import copy
import importlib.util
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback
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


class FakeHealthProcess:
    ARGV = b"/opt/server-connect/current/bin/server-connect\0--json\0smart-tun-trial-health\0"

    def __init__(self, modes):
        self.modes = modes
        self.mode = modes[0]
        self.pid = 41
        self.descriptor = None
        self.opened, self.closed = [], []
        self.dispatch_attempts, self.delivered = [], []
        self.bound_pids = {}
        self.elapsed, self.available_after = 0, None
        self.probe_due_ms = 0
        self.delivery_times = []
        self.output = io.StringIO()
        self.completed_signal = None
        self.stop_state = "T"
        self.operation = "a" * 32
        self.journal_data = {"operation_id": self.operation, "phase": "trial_pending", "revision": 1,
                             "supervised": {"confirmed": True, "state": "healthy", "attempts": 0, "failures": 0,
                                            "recovery_deadline_uptime_ms": 0, "rounds": 3,
                                            "last_probe_uptime_ms": 1000, "lease_deadline_uptime_ms": 30000,
                                            "evidence": {"probe_count": 7, "elapsed_ms": 10}}}
        self.journal_reads, self.journal_hook_at = 0, 1
        self.journal_hook = None

    def journal(self):
        self.journal_reads += 1
        current = copy.deepcopy(self.journal_data)
        current["supervised"]["next_probe_uptime_ms"] = self.probe_due_ms
        if self.journal_hook is not None and self.journal_reads >= self.journal_hook_at:
            current = self.journal_hook(current)
        self.last_journal_return = current
        return current

    def show(self, unit, prop):
        assert (unit, prop) == (driver.HEALTH, "MainPID")
        if (self.descriptor is None and self.available_after is not None and
                self.elapsed != 5 and self.elapsed < self.available_after):
            return "0"
        if self.descriptor is not None:
            self.unit_reads += 1
            if self.mode == "pid_churn" or (self.mode == "pid_change_at_dispatch" and self.unit_reads == 2):
                self.pid += 1
        return str(self.pid)

    def open(self, pid):
        assert pid == self.pid and self.descriptor is None
        self.mode = self.modes[min(len(self.opened), len(self.modes) - 1)]
        if self.available_after is not None and self.elapsed >= self.available_after:
            self.mode = "correct"
        self.descriptor = 100 + len(self.opened)
        self.bound_pids[self.descriptor] = pid
        self.opened.append(self.descriptor)
        self.image_reads = self.argv_reads = self.unit_reads = 0
        self.completed_signal = None
        return self.descriptor

    def command(self, argv, *, timeout):
        assert argv[:3] == ["systemctl", "show", driver.HEALTH] and timeout == 3
        fields = argv[4::2]
        main_pid = self.show(driver.HEALTH, "MainPID")
        pid = self.bound_pids[self.descriptor] if self.completed_signal is not None else self.pid
        values = {"MainPID": main_pid, "InvocationID": f"{pid:032x}", "ExecMainPID": str(pid),
                  "ExecMainCode": "0", "ExecMainStatus": "0", "ActiveState": "activating",
                  "Result": "success", "ExecMainStartTimestampMonotonic": str(1000 + pid)}
        if self.completed_signal == driver.signal.SIGKILL:
            values.update(MainPID="0", ExecMainCode="2", ExecMainStatus="9", ActiveState="failed", Result="signal")
            if self.mode == "kill_ordinary_exit":
                values.update(ExecMainCode="1", ExecMainStatus="0", ActiveState="inactive", Result="success")
            if self.mode == "kill_other_signal":
                values["ExecMainStatus"] = "15"
            if self.mode == "kill_no_receipt":
                values.update(ExecMainCode="0", ExecMainStatus="0")
        if self.completed_signal is not None:
            if self.mode in ("kill_wrong_invocation", "stop_wrong_invocation"):
                values["InvocationID"] = "f" * 32
            if self.mode in ("kill_wrong_pid", "stop_wrong_pid"):
                values["ExecMainPID"] = str(pid + 1)
            if self.mode == "kill_wrong_start":
                values["ExecMainStartTimestampMonotonic"] = str(1001 + pid)
            if self.mode == "stop_disappears":
                values["MainPID"] = "0"
        assert set(fields) == set(values)
        return subprocess.CompletedProcess(argv, 0, stdout="\n".join(key + "=" + values[key] for key in fields) + "\n", stderr="")

    def stat(self, path):
        if path == "/opt/server-connect/current/bin/server-connect":
            return argparse.Namespace(st_dev=7, st_ino=41)
        assert path == f"/proc/{self.bound_pids[self.descriptor]}/exe"
        if self.mode == "disappears":
            raise ProcessLookupError("early short invocation has already exited")
        self.image_reads += 1
        changed = ((self.mode == "exec_change" and self.image_reads >= 3) or
                   (self.mode == "exec_change_during_argv" and self.image_reads >= 2) or
                   (self.mode == "stop_wrong_image" and self.completed_signal is not None))
        inode = 9 if self.mode in ("starting", "foreign") or changed else 41
        return argparse.Namespace(st_dev=7, st_ino=inode)

    def path(self, path):
        if path == "/proc/uptime":
            return argparse.Namespace(read_text=lambda: str(self.elapsed) + " 0\n")
        if path == f"/proc/{self.bound_pids[self.descriptor]}/stat":
            return argparse.Namespace(read_bytes=self.process_stat)
        assert path == f"/proc/{self.bound_pids[self.descriptor]}/cmdline"
        return argparse.Namespace(read_bytes=self.argv)

    def process_stat(self):
        if self.mode == "disappears":
            raise ProcessLookupError("early short invocation has already exited")
        pid = self.bound_pids[self.descriptor]
        generation, state = 2000 + pid, "S"
        if self.completed_signal == driver.signal.SIGSTOP:
            state = "S" if self.mode == "stop_unobserved" else self.stop_state
            if self.mode == "stop_wrong_generation":
                generation += 1
        fields = [state] + ["0"] * 19
        fields[19] = str(generation)
        return (str(pid) + " (server-connect) " + " ".join(fields) + "\n").encode()

    def argv(self):
        self.argv_reads += 1
        if self.mode == "wrong_argv" or (self.mode == "argv_change" and self.argv_reads >= 2):
            return self.ARGV + b"unexpected-extra-argument\0"
        return self.ARGV

    def send(self, descriptor, requested_signal):
        assert descriptor == self.descriptor
        self.dispatch_attempts.append((descriptor, requested_signal))
        if self.mode == "exit_at_dispatch":
            # The unit acquires a replacement, but the opened fd still refers
            # to the exited process. Never fall back to signalling a PID.
            self.pid += 1
            raise ProcessLookupError("pidfd target exited before dispatch")
        self.delivered.append((descriptor, requested_signal))
        self.delivery_times.append(self.elapsed)
        self.completed_signal = requested_signal

    def close(self, descriptor):
        assert descriptor == self.descriptor
        self.closed.append(descriptor)
        self.descriptor = None


class ExecutorSignalTests(unittest.TestCase):
    def exercise(self, fake, requested_signal):
        fixture = ForeignCleanupTests.new_fixture()
        fixture.op = fake.operation
        fake_os = argparse.Namespace(pidfd_open=fake.open, stat=fake.stat, close=fake.close, CLD_KILLED=2)
        fake_signal = argparse.Namespace(SIGKILL=driver.signal.SIGKILL, SIGSTOP=driver.signal.SIGSTOP,
                                         pidfd_send_signal=fake.send)
        ticks = itertools.count()

        def monotonic():
            fake.elapsed = next(ticks)
            return fake.elapsed

        with patch.object(driver, "os", fake_os), patch.object(driver, "signal", fake_signal), \
                patch.object(driver, "Path", side_effect=fake.path), \
                patch.object(fixture, "show", side_effect=fake.show), \
                patch.object(fixture, "command", side_effect=fake.command), \
                patch.object(fixture, "journal", side_effect=fake.journal), \
                patch.object(driver.time, "monotonic", side_effect=monotonic), \
                patch.object(driver.time, "sleep"), contextlib.redirect_stdout(fake.output):
            try:
                return fixture.wait_for_health_executor(requested_signal)
            finally:
                fake.health_signal_snapshot = getattr(fixture, "health_signal_snapshot", None)
                self.assertEqual(fake.closed, fake.opened, "a process descriptor leaked")

    def test_transitional_image_waits_for_correct_exec_before_signal(self):
        for requested_signal in (driver.signal.SIGKILL, driver.signal.SIGSTOP):
            with self.subTest(signal=requested_signal):
                fake = FakeHealthProcess(["starting", "correct"])
                self.assertTrue(self.exercise(fake, requested_signal))
                self.assertEqual(len(fake.opened), 2)
                self.assertEqual(fake.delivered, [(fake.opened[1], requested_signal)])

    def test_disappeared_early_tick_allows_authenticated_executor_after_eight_seconds(self):
        for due, descriptors in ((0, 2), (6000, 1)):
            with self.subTest(due=due):
                fake = FakeHealthProcess(["disappears", "correct"])
                fake.available_after = 10
                fake.probe_due_ms = due
                self.assertTrue(self.exercise(fake, driver.signal.SIGSTOP))
                self.assertEqual(len(fake.opened), descriptors)
                self.assertEqual(fake.delivered, [(fake.opened[-1], driver.signal.SIGSTOP)])
                self.assertEqual(fake.delivery_times, [10])
                self.assertGreater(fake.delivery_times[0], 8)
                self.assertLess(fake.delivery_times[0], 15)
                self.assertIn("SUPERVISED_TUN_EXECUTOR_FAULT_RECEIPT=", fake.output.getvalue())
                self.assertNotIn("AUTH_TIMEOUT", fake.output.getvalue())

    def test_persistent_foreign_image_or_extra_argv_times_out_without_signal(self):
        for mode in ("foreign", "wrong_argv"):
            with self.subTest(mode=mode):
                fake = FakeHealthProcess([mode])
                with self.assertRaisesRegex(AssertionError, "timed out.*authenticated health executor"):
                    self.exercise(fake, driver.signal.SIGKILL)
                self.assertEqual(fake.elapsed, 15)
                self.assertGreater(len(fake.opened), 1)
                self.assertEqual(fake.dispatch_attempts, [])
                output = fake.output.getvalue()
                prefix = "SUPERVISED_TUN_EXECUTOR_AUTH_TIMEOUT="
                self.assertTrue(output.startswith(prefix))
                observation = json.loads(output[len(prefix):])
                self.assertEqual(set(observation), {"pid", "readiness"})
                self.assertEqual(observation["pid"], 41)
                self.assertEqual(observation["readiness"],
                                 "executable_mismatch" if mode == "foreign" else "argv_mismatch")
                self.assertNotIn("unexpected-extra-argument", output)
                self.assertLess(len(output), 256)

    def test_unit_pid_churn_never_signals_the_old_executor(self):
        fake = FakeHealthProcess(["pid_churn"])
        with self.assertRaisesRegex(AssertionError, "timed out.*authenticated health executor"):
            self.exercise(fake, driver.signal.SIGSTOP)
        self.assertGreater(len(set(fake.bound_pids.values())), 1)
        self.assertEqual(fake.dispatch_attempts, [])

    def test_dispatch_recheck_rejects_changed_image_argv_or_unit_pid(self):
        for mode in ("exec_change", "exec_change_during_argv", "argv_change", "pid_change_at_dispatch"):
            with self.subTest(mode=mode):
                fake = FakeHealthProcess([mode])
                with self.assertRaisesRegex(AssertionError, "timed out.*authenticated health executor"):
                    self.exercise(fake, driver.signal.SIGKILL)
                self.assertEqual(fake.dispatch_attempts, [])

    def test_exit_at_dispatch_never_signals_the_replacement(self):
        fake = FakeHealthProcess(["exit_at_dispatch"])
        with self.assertRaisesRegex(AssertionError, "timed out.*authenticated health executor"):
            self.exercise(fake, driver.signal.SIGKILL)
        self.assertGreater(len(set(fake.bound_pids.values())), 1)
        self.assertEqual(fake.dispatch_attempts, [(fd, driver.signal.SIGKILL) for fd in fake.opened])
        self.assertEqual(fake.delivered, [])

    def test_sigstop_requires_observed_same_generation_stopped_state(self):
        for state in ("T", "t"):
            with self.subTest(state=state):
                fake = FakeHealthProcess(["correct"])
                fake.stop_state = state
                self.assertTrue(self.exercise(fake, driver.signal.SIGSTOP))
                self.assertIn("outcome:" + state, fake.output.getvalue())
        for mode in ("stop_unobserved", "stop_disappears", "stop_wrong_generation",
                     "stop_wrong_invocation", "stop_wrong_pid", "stop_wrong_image"):
            with self.subTest(mode=mode):
                fake = FakeHealthProcess([mode])
                with self.assertRaises(AssertionError):
                    self.exercise(fake, driver.signal.SIGSTOP)
                self.assertEqual(len(fake.dispatch_attempts), 1, "an unproven dispatch was retried")
                self.assertNotIn("EXECUTOR_FAULT_RECEIPT", fake.output.getvalue())

    def test_sigkill_requires_exact_attributable_signal_death(self):
        fake = FakeHealthProcess(["correct"])
        self.assertTrue(self.exercise(fake, driver.signal.SIGKILL))
        self.assertIn("signal:9 outcome:killed", fake.output.getvalue())
        for mode in ("kill_ordinary_exit", "kill_other_signal", "kill_no_receipt", "kill_wrong_invocation",
                     "kill_wrong_pid", "kill_wrong_start"):
            with self.subTest(mode=mode):
                fake = FakeHealthProcess([mode])
                with self.assertRaises(AssertionError):
                    self.exercise(fake, driver.signal.SIGKILL)
                self.assertEqual(len(fake.dispatch_attempts), 1, "an unproven dispatch was retried")
                self.assertNotIn("EXECUTOR_FAULT_RECEIPT", fake.output.getvalue())

    def check_invalid_operation_context(self, late):
        changes = ((None, None, None), ("operation", "operation_id", "c" * 32),
                   ("operation", "phase", "trial_cleanup_pending"), ("operation", "revision", 2),
                   ("operation", "revision", True), ("operation", "revision", 1.0),
                   ("supervised", "confirmed", False), ("supervised", "confirmed", 1),
                   ("supervised", "state", "reconnecting"), ("supervised", "attempts", 1),
                   ("supervised", "attempts", False), ("supervised", "failures", 1),
                   ("supervised", "failures", False), ("supervised", "recovery_deadline_uptime_ms", 1),
                   ("supervised", "recovery_deadline_uptime_ms", False))
        for requested_signal in (driver.signal.SIGKILL, driver.signal.SIGSTOP):
            for section, field, value in changes:
                with self.subTest(signal=requested_signal, late=late, section=section, field=field, value=value):
                    fake = FakeHealthProcess(["correct"])
                    fake.journal_hook_at = 2 if late else 1

                    def changed(current):
                        if section is None:
                            return None
                        target = current if section == "operation" else current["supervised"]
                        target[field] = value
                        return current

                    fake.journal_hook = changed
                    with self.assertRaisesRegex(AssertionError, "executor fault (is not bound|requires)"):
                        self.exercise(fake, requested_signal)
                    self.assertEqual(fake.journal_reads, fake.journal_hook_at)
                    self.assertEqual(len(fake.opened), 1 if late else 0)
                    self.assertEqual(fake.dispatch_attempts, [])
                    self.assertEqual(fake.delivered, [])
                    self.assertNotIn("EXECUTOR_FAULT_RECEIPT", fake.output.getvalue())

    def test_initial_context_requires_original_confirmed_healthy_operation(self):
        self.check_invalid_operation_context(late=False)

    def test_final_context_change_prevents_fault_dispatch(self):
        self.check_invalid_operation_context(late=True)

    def test_retained_snapshot_copies_final_pre_dispatch_health_evidence(self):
        for requested_signal in (driver.signal.SIGKILL, driver.signal.SIGSTOP):
            with self.subTest(signal=requested_signal):
                fake = FakeHealthProcess(["correct"])
                fake.journal_hook_at = 2

                def updated(current):
                    current["supervised"].update(rounds=4, last_probe_uptime_ms=2000)
                    current["supervised"]["evidence"]["elapsed_ms"] = 11
                    return current

                fake.journal_hook = updated
                self.assertTrue(self.exercise(fake, requested_signal))
                expected = copy.deepcopy(fake.last_journal_return["supervised"])
                self.assertEqual(expected["rounds"], 4)
                self.assertEqual(fake.health_signal_snapshot, expected)
                fake.last_journal_return["supervised"]["evidence"]["elapsed_ms"] = 999
                fake.last_journal_return["supervised"]["rounds"] = 99
                self.assertEqual(fake.health_signal_snapshot, expected, "fault snapshot retained mutable journal data")


class ConfirmationDeathTests(unittest.TestCase):
    def fixture(self):
        fixture = ForeignCleanupTests.new_fixture()
        fixture.op, fixture.challenge = "b" * 32, "c" * 64
        return fixture

    def request(self, boundary="before-confirm-publish"):
        fixture = self.fixture()
        return {"operation_id": fixture.op, "revision": 1, "boundary": boundary,
                "argv": [driver.SC, "--json", "smart-tun-trial-confirm", "--operation-id", fixture.op,
                         "--revision", "1", "--challenge", fixture.challenge, "--qa-kill-at", boundary]}

    def receipt(self, request):
        return {"kind": "scqa-confirm-death-v1", "operation_id": request["operation_id"],
                "revision": 1, "boundary": request["boundary"], "child_returncode": -9}

    def wrapper(self, request, returncode=-9, error=None):
        raw = request if isinstance(request, bytes) else json.dumps(request).encode()
        input_stream = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        output, errors = io.StringIO(), io.StringIO()
        child = subprocess.CompletedProcess([], returncode, stdout="forged child receipt", stderr="secret child error")
        with patch.object(sys, "stdin", input_stream), \
                patch.object(driver.subprocess, "run", return_value=child, side_effect=error) as run, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit) as exited:
                exec(compile(driver.CONFIRM_DEATH_WRAPPER, "<remote-confirm-death-wrapper>", "exec"), {})
        self.assertEqual(errors.getvalue(), "")
        return exited.exception.code, output.getvalue(), run

    def test_actual_remote_wrapper_accepts_only_child_sigkill(self):
        for boundary in ("before-confirm-publish", "after-confirm-publish"):
            request = self.request(boundary)
            for code in (-9, 0, 1, 137, 255, -15):
                with self.subTest(boundary=boundary, code=code):
                    exit_code, output, run = self.wrapper(request, code)
                    run.assert_called_once_with(request["argv"], stdin=subprocess.DEVNULL,
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                timeout=20, check=False)
                    if code == -9:
                        self.assertEqual(exit_code, 0)
                        self.assertEqual(json.loads(output), self.receipt(request))
                    else:
                        self.assertNotEqual(exit_code, 0)
                        self.assertEqual(output, "")
                    self.assertNotIn(request["argv"][8], output)
                    self.assertNotIn("forged child receipt", output)

    def test_wrapper_timeout_or_spawn_failure_never_earns_death_receipt(self):
        request = self.request()
        for error in (subprocess.TimeoutExpired(request["argv"], 20, output=b"secret", stderr=b"secret"),
                      OSError("secret launch details")):
            with self.subTest(error=type(error).__name__):
                code, output, _run = self.wrapper(request, error=error)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, "")

    def test_wrapper_rejects_misdirected_or_oversized_input_before_launch(self):
        wrong = self.request()
        wrong["argv"][0] = "/bin/false"
        mismatch = self.request()
        mismatch["operation_id"] = "a" * 32
        for request in (wrong, mismatch, b"not JSON", b"x" * 4097):
            with self.subTest(request_type=type(request).__name__):
                code, output, run = self.wrapper(request)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, "")
                run.assert_not_called()

    def test_caller_uses_fresh_ssh_constant_command_and_stdin_payload(self):
        for boundary in ("before-confirm-publish", "after-confirm-publish"):
            fixture = self.fixture()
            output = io.StringIO()
            reply = json.dumps(self.receipt(self.request(boundary)))
            with patch.object(fixture, "command", return_value=subprocess.CompletedProcess([], 0, reply, "")) as command, \
                    contextlib.redirect_stdout(output):
                fixture.confirm_publication_death(boundary)
            argv = command.call_args.args[0]
            self.assertIn("ControlMaster=no", argv)
            self.assertIn("ControlPath=none", argv)
            self.assertEqual(driver.shlex.split(argv[-1]), ["/usr/bin/python3", "-I", "-B", "-c", driver.CONFIRM_DEATH_WRAPPER])
            self.assertNotIn(fixture.challenge, " ".join(argv))
            self.assertEqual(json.loads(command.call_args.kwargs["data"]), self.request(boundary))
            self.assertIn("SUPERVISED_TUN_CONFIRM_DEATH_RECEIPT=", output.getvalue())
            self.assertNotIn(fixture.challenge, output.getvalue())

    def test_caller_rejects_failed_transport_or_malformed_mismatched_receipt(self):
        fixture = self.fixture()
        receipt = self.receipt(self.request())
        candidates = [(code, json.dumps(receipt)) for code in (1, 137, 255, -9)]
        candidates += [(0, raw) for raw in ("", "not JSON " + fixture.challenge, "x" * 2049, "[]")]
        for key, value in (("kind", "foreign"), ("operation_id", "a" * 32), ("revision", 2), ("revision", True),
                           ("boundary", "after-confirm-publish"), ("child_returncode", 0),
                           ("child_returncode", 1), ("child_returncode", 137), ("child_returncode", -15), ("extra", 1)):
            candidates.append((0, json.dumps({**receipt, key: value})))
        candidates.append((0, json.dumps(receipt)[:-1] + ',"revision":1}'))
        for code, payload in candidates:
            with self.subTest(code=code, payload_size=len(payload)):
                output = io.StringIO()
                with patch.object(fixture, "command", return_value=subprocess.CompletedProcess([], code, payload, fixture.challenge)), \
                        contextlib.redirect_stdout(output), self.assertRaises(AssertionError) as raised:
                    fixture.confirm_publication_death("before-confirm-publish")
                self.assertNotIn(fixture.challenge, str(raised.exception))
                self.assertEqual(output.getvalue(), "")

    def test_ordinary_confirmation_failure_cannot_pass_via_natural_expiry(self):
        fixture = self.fixture()
        with patch.object(fixture, "apply"), \
                patch.object(fixture, "command", return_value=subprocess.CompletedProcess([], 1, "", "")), \
                patch.object(fixture, "health", return_value={"confirmed": False}) as health, \
                patch.object(fixture, "independent_off") as off, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(AssertionError):
                fixture.publication_failures()
        health.assert_not_called()
        off.assert_not_called()

    def test_command_timeout_redacts_challenge_and_captured_output(self):
        fixture = self.fixture()
        argv = fixture.ssh_arguments() + [driver.SC, "--json", "smart-tun-trial-confirm", "--challenge", fixture.challenge]
        original = subprocess.TimeoutExpired(argv, 30, output=fixture.challenge, stderr=fixture.challenge)
        with patch.object(driver.subprocess, "run", side_effect=original):
            try:
                fixture.command(argv, timeout=30)
            except subprocess.TimeoutExpired as error:
                rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
                self.assertNotIn(fixture.challenge, rendered)
                self.assertIn("<challenge>", rendered)
                self.assertIsNone(error.output)
                self.assertIsNone(error.stderr)
                self.assertTrue(error.__suppress_context__)
            else:
                self.fail("timeout was not propagated with its original exception type")


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


class FakeTimer:
    """One owned cleanup operation; all observations and commands are synthetic."""

    FAILURE = {"ok": False, "error": {"code": "guard_unavailable", "message": "health timer disarm not verified"}}

    class Path:
        def __init__(self, fake, name):
            self.fake, self.name = fake, str(name)

        def __truediv__(self, suffix):
            return type(self)(self.fake, self.name + "/" + suffix)

        def exists(self):
            return self.name in self.fake.existing_paths

        def is_symlink(self):
            return self.name in self.fake.symlink_paths

    def __init__(self):
        self.operation = "a" * 32
        self.original_boot = "a1234567-89ab-cdef-0123-456789abcdef"
        self.boot = self.original_boot
        self.baseline = ["original routes", "original rules and handles"]
        self.saved_before = {"profile": "original profile", "policy": "original policy", "selection": "direct"}
        self.native_state, self.saved_state = copy.deepcopy(self.baseline), dict(self.saved_before)
        self.files, roles = {}, []
        for index, unit in enumerate((driver.HEALTH, driver.TIMER)):
            body = ("original installed " + unit + "\n").encode()
            digest = driver.hashlib.sha256(body).hexdigest()
            self.files[unit] = ((7, 40 + index, body), (8, 50 + index, (digest + "\n").encode()))
            roles.append({"unit_dev": 7, "unit_ino": 40 + index, "digest_dev": 8,
                          "digest_ino": 50 + index, "sha256": digest})
        self.originals = copy.deepcopy(self.files)
        self.journal_data = {"operation_id": self.operation, "boot_id": self.original_boot,
                             "phase": "trial_cleanup_pending", "revision": 4, "supervised": {"roles": roles}}
        idle = {"ActiveState": "inactive", "Result": "success", "MainPID": "0", "ControlPID": "0",
                "Job": "", "ControlGroup": ""}
        self.properties = {driver.CORE: dict(idle), driver.RECOVERY: dict(idle)}
        self.properties[driver.RECOVERY].update(ActiveState="failed", Result="exit-code", ExecMainPID="73",
                                                ExecMainCode="1", ExecMainStatus="1", InvocationID="b" * 32)
        for unit in (driver.HEALTH, driver.TIMER):
            self.properties[unit] = {"Id": unit, "LoadState": "loaded", "FragmentPath": str(driver.UNITS / unit),
                                     "DropInPaths": "", "Transient": "no", "UnitFileState": "static", **idle}
        self.properties[driver.TIMER].update(UnitFileState="disabled", ActiveState="failed", Result="resources",
                                             Unit=driver.HEALTH)
        self.initial_counts = {("health-0-tcp", 11): 2, ("health-0-udp", 12): 3, ("health-0-dns", 13): 4}
        self.fresh_counts = {key: value + 1 for key, value in self.initial_counts.items()}
        self.existing_paths, self.symlink_paths = set(), set()
        self.commands, self.resets, self.events = [], [], []
        self.after_show, self.after_reset = {}, None
        self.wire_error = None
        self.output = io.StringIO()

    def path(self, name):
        return self.Path(self, name)

    def journal(self):
        self.events.append("journal")
        return copy.deepcopy(self.journal_data)

    def role_files(self, unit):
        return copy.deepcopy(self.files[unit])

    def replace_file(self, unit, artifact, component, value):
        files = list(self.files[unit])
        fields = list(files[artifact])
        fields[component] = value
        files[artifact] = tuple(fields)
        self.files[unit] = tuple(files)

    def wires(self, mode):
        assert mode == "direct"
        self.events.append("direct")
        if self.wire_error is not None:
            raise self.wire_error

    def counters(self):
        self.events.append("counters")
        return dict(self.fresh_counts)

    def command(self, argv, *, check=True, timeout=20, data=None):
        self.commands.append(list(argv))
        assert check and data is None and 0 < timeout <= 20
        if argv == ["systemctl", "reset-failed", driver.TIMER]:
            self.events.append("reset")
            self.resets.append(list(argv))
            self.properties[driver.TIMER].update(ActiveState="inactive", Result="success")
            if self.after_reset is not None:
                self.after_reset(self)
            output = ""
        else:
            # Any start/enable, recovery reset, or other mutation fails closed.
            assert argv[:2] == ["systemctl", "show"] and argv[2] in self.properties, argv
            assert argv[3::2] == ["-p"] * len(argv[4::2]) and len(argv) % 2 == 1, argv
            unit, fields = argv[2], argv[4::2]
            self.events.append("observe:" + unit)
            output = "".join(field + "=" + self.properties[unit][field] + "\n" for field in fields)
            hook = self.after_show.pop(unit, None)
            if hook is not None:
                hook(self)
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")


class TimerReconciliationTests(unittest.TestCase):
    def exercise(self, fake, kind="masked", failure=FakeTimer.FAILURE):
        fixture = ForeignCleanupTests.new_fixture()
        fixture.op, fixture.fixture_boot_id = fake.operation, fake.original_boot
        fixture.baseline, fixture.saved_before = copy.deepcopy(fake.baseline), dict(fake.saved_before)
        fixture.health_role_originals = copy.deepcopy(fake.originals)
        fixture.direct_counts = dict(fake.initial_counts)
        with patch.object(driver, "Path", side_effect=fake.path), \
                patch.object(fixture, "journal", side_effect=fake.journal), \
                patch.object(fixture, "current_boot_id", side_effect=lambda: fake.boot), \
                patch.object(fixture, "native", side_effect=lambda: copy.deepcopy(fake.native_state)), \
                patch.object(fixture, "saved", side_effect=lambda: dict(fake.saved_state)), \
                patch.object(fixture, "health_role_files", side_effect=fake.role_files), \
                patch.object(fixture, "wires", side_effect=fake.wires), \
                patch.object(fixture, "counters", side_effect=fake.counters), \
                patch.object(fixture, "command", side_effect=fake.command), \
                patch.object(driver.subprocess, "run", side_effect=AssertionError("unexpected real process")), \
                patch.object(driver.subprocess, "Popen", side_effect=AssertionError("unexpected real process")), \
                patch.object(driver.time, "monotonic", side_effect=itertools.count()), \
                patch.object(driver.time, "sleep"), contextlib.redirect_stdout(fake.output):
            result = fixture.reconcile_failed_health_timer(kind, failure)
        self.assertEqual(fixture.direct_counts, fake.fresh_counts)
        return result

    def assert_refused(self, fake, **kwargs):
        with self.assertRaises(AssertionError):
            self.exercise(fake, **kwargs)
        self.assertEqual(fake.resets, [], "an unproven timer was reset before the refusal")
        self.assert_mutations(fake, [])

    def assert_mutations(self, fake, expected):
        mutations = [argv for argv in fake.commands if argv[:2] != ["systemctl", "show"]]
        self.assertEqual(mutations, expected, "unexpected bookkeeping mutation was attempted")

    def test_exact_failed_timer_resets_only_after_direct_and_recovery_evidence(self):
        for kind in ("masked", "missing"):
            for finalized in (False, True):
                with self.subTest(kind=kind, finalized=finalized):
                    fake = FakeTimer()
                    if finalized:
                        fake.after_reset = lambda state: setattr(state, "journal_data", None)
                    self.assertTrue(self.exercise(fake, kind))
                    self.assertEqual(fake.resets, [["systemctl", "reset-failed", driver.TIMER]])
                    self.assert_mutations(fake, fake.resets)
                    self.assertLess(fake.events.index("direct"), fake.events.index("counters"))
                    self.assertLess(fake.events.index("counters"), fake.events.index("observe:" + driver.RECOVERY))
                    self.assertLess(fake.events.index("observe:" + driver.RECOVERY), fake.events.index("reset"))
                    prefix = "SUPERVISED_TUN_" + kind.upper() + "_OPERATOR_TIMER_RECONCILIATION="
                    lines = fake.output.getvalue().splitlines()
                    self.assertEqual(len(lines), 1)
                    self.assertTrue(lines[0].startswith(prefix))
                    receipt = json.loads(lines[0][len(prefix):])
                    self.assertEqual((receipt["operation_id"], receipt["phase"], receipt["revision"]),
                                     (fake.operation, "trial_cleanup_pending", 4))
                    self.assertIs(receipt["direct_verified"], True)
                    self.assertEqual(receipt["timer"], {"ActiveState": "failed", "Result": "resources",
                                                        "UnitFileState": "disabled", "Unit": driver.HEALTH, "Job": ""})
                    self.assertEqual(receipt["recovery"], fake.properties[driver.RECOVERY])

    def test_already_successful_timer_requires_evidence_but_no_reset(self):
        for kind in ("masked", "missing"):
            with self.subTest(kind=kind):
                fake = FakeTimer()
                fake.properties[driver.TIMER].update(ActiveState="inactive", Result="success")
                fake.properties[driver.RECOVERY].update(ActiveState="inactive", Result="success")
                self.assertFalse(self.exercise(fake, kind))
                self.assertEqual(fake.resets, [])
                self.assert_mutations(fake, [])
                self.assertIn("direct", fake.events)
                self.assertIn("observe:" + driver.RECOVERY, fake.events)

    def test_existing_recovery_invocation_can_drain_without_being_reset(self):
        fake = FakeTimer()
        idle = dict(fake.properties[driver.RECOVERY])
        fake.properties[driver.RECOVERY].update(ActiveState="active", MainPID="73",
                                                ControlGroup="/system.slice/recovery")
        fake.after_show[driver.RECOVERY] = lambda state: state.properties[driver.RECOVERY].update(idle)
        self.assertTrue(self.exercise(fake))
        self.assertEqual(fake.events.count("observe:" + driver.RECOVERY), 2)
        self.assertEqual(fake.resets, [["systemctl", "reset-failed", driver.TIMER]])
        self.assert_mutations(fake, fake.resets)
        self.assertLess(max(index for index, event in enumerate(fake.events)
                            if event == "observe:" + driver.RECOVERY), fake.events.index("reset"))

    def test_only_exact_timer_disarm_error_and_unit_fault_kind_are_admitted(self):
        bad_errors = (None, {}, {"ok": True, "error": FakeTimer.FAILURE["error"]},
                      {"ok": False, "error": {"code": "guard_unavailable", "message": "other failure"}},
                      {"ok": False, "error": {"code": "permission_denied", "message": "health timer disarm not verified"}},
                      {"ok": False, "error": {**FakeTimer.FAILURE["error"], "unexpected": True}})
        for failure in bad_errors:
            with self.subTest(failure=failure):
                fake = FakeTimer()
                self.assert_refused(fake, failure=failure)
                self.assertEqual(fake.events, [])
        fake = FakeTimer()
        self.assert_refused(fake, kind="failed")
        self.assertEqual(fake.events, [])

    def test_cleanup_operation_boot_phase_and_revision_are_bound(self):
        mutations = (
            lambda state: setattr(state, "journal_data", None),
            lambda state: state.journal_data.update(operation_id="c" * 32),
            lambda state: state.journal_data.update(boot_id="different boot"),
            lambda state: setattr(state, "boot", "rebooted"),
            lambda state: state.journal_data.update(phase="trial_active"),
            lambda state: state.journal_data.update(revision=3),
            lambda state: state.journal_data.update(revision=4.0),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(change=index):
                fake = FakeTimer()
                mutate(fake)
                self.assert_refused(fake)
                self.assertNotIn("direct", fake.events)

    def test_native_off_and_saved_state_are_required(self):
        mutations = (
            lambda state: state.existing_paths.add("/sys/class/net/sctunqa0"),
            lambda state: state.existing_paths.add("/var/lib/server-connect/smart-tun-trial.json"),
            lambda state: state.native_state.append("remaining native rule"),
            lambda state: state.saved_state.update(selection="changed"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(change=index):
                fake = FakeTimer()
                mutate(fake)
                self.assert_refused(fake)

    def test_replaced_unit_or_digest_file_is_never_adopted(self):
        for unit in (driver.HEALTH, driver.TIMER):
            for artifact in (0, 1):
                for component, value in ((0, 99), (1, 99), (2, b"replacement\n")):
                    with self.subTest(unit=unit, artifact=artifact, component=component):
                        fake = FakeTimer()
                        fake.replace_file(unit, artifact, component, value)
                        self.assert_refused(fake)

    def test_role_receipt_and_digest_must_authenticate_original_files(self):
        for index in (0, 1):
            for field in ("unit_dev", "unit_ino", "digest_dev", "digest_ino", "sha256"):
                with self.subTest(role=index, field=field):
                    fake = FakeTimer()
                    fake.journal_data["supervised"]["roles"][index][field] = "0" * 64 if field == "sha256" else 99
                    self.assert_refused(fake)
        fake = FakeTimer()
        fake.replace_file(driver.TIMER, 1, 2, b"0" * 64 + b"\n")
        fake.originals = copy.deepcopy(fake.files)
        self.assert_refused(fake)

    def test_runtime_overrides_including_dangling_symlinks_are_rejected(self):
        for unit in (driver.HEALTH, driver.TIMER):
            for path in ("/run/systemd/system/" + unit, "/run/systemd/system/" + unit + ".d",
                         "/run/systemd/transient/" + unit):
                for symlink in (False, True):
                    with self.subTest(path=path, symlink=symlink):
                        fake = FakeTimer()
                        (fake.symlink_paths if symlink else fake.existing_paths).add(path)
                        self.assert_refused(fake)

    def test_loaded_health_roles_require_exact_runtime_ownership(self):
        for unit in (driver.HEALTH, driver.TIMER):
            for field, value in (("Id", "foreign.service"), ("LoadState", "masked"),
                                 ("FragmentPath", "/run/systemd/system/foreign.service"),
                                 ("DropInPaths", "/etc/systemd/system/foreign.conf"), ("Transient", "yes")):
                with self.subTest(unit=unit, field=field):
                    fake = FakeTimer()
                    fake.properties[unit][field] = value
                    self.assert_refused(fake)

    def test_role_replacement_during_runtime_observation_is_rejected(self):
        for unit in (driver.HEALTH, driver.TIMER):
            with self.subTest(unit=unit):
                fake = FakeTimer()
                fake.after_show[unit] = lambda state: state.replace_file(unit, 0, 1, 99)
                self.assert_refused(fake)

    def test_enabled_busy_active_or_wrong_target_timer_is_rejected(self):
        mutations = ({"UnitFileState": "enabled"}, {"ActiveState": "active"}, {"Job": "41"},
                     {"Unit": driver.RECOVERY}, {"ActiveState": "inactive", "Result": "exit-code"},
                     {"ActiveState": "failed", "Result": "success"}, {"Result": ""})
        for change in mutations:
            with self.subTest(change=change):
                fake = FakeTimer()
                fake.properties[driver.TIMER].update(change)
                self.assert_refused(fake)

    def test_core_health_and_recovery_must_be_quiescent_with_released_cgroups(self):
        changes = (("ActiveState", "active"), ("MainPID", "73"), ("ControlPID", "74"),
                   ("Job", "41"), ("ControlGroup", "/system.slice/residual"))
        for unit in (driver.CORE, driver.HEALTH, driver.RECOVERY):
            for field, value in changes:
                with self.subTest(unit=unit, field=field):
                    fake = FakeTimer()
                    fake.properties[unit][field] = value
                    self.assert_refused(fake)
        for unit in (driver.CORE, driver.HEALTH):
            with self.subTest(unit=unit, field="Result"):
                fake = FakeTimer()
                fake.properties[unit]["Result"] = "exit-code"
                self.assert_refused(fake)
        fake = FakeTimer()
        fake.properties[driver.HEALTH]["UnitFileState"] = "enabled"
        self.assert_refused(fake)

    def test_every_direct_counter_must_freshly_advance_with_same_identity(self):
        for failure in ("wire", "stale", "one_stale", "replaced_counter"):
            with self.subTest(failure=failure):
                fake = FakeTimer()
                if failure == "wire":
                    fake.wire_error = AssertionError("no exact Direct response")
                elif failure == "stale":
                    fake.fresh_counts = dict(fake.initial_counts)
                elif failure == "one_stale":
                    key = next(iter(fake.initial_counts))
                    fake.fresh_counts[key] = fake.initial_counts[key]
                else:
                    key, value = fake.fresh_counts.popitem()
                    fake.fresh_counts[(key[0], 999)] = value
                self.assert_refused(fake)

    def test_last_context_check_catches_changes_after_recovery_diagnostics(self):
        mutations = (
            lambda state: state.replace_file(driver.TIMER, 0, 1, 99),
            lambda state: state.journal_data.update(operation_id="c" * 32),
            lambda state: state.journal_data.update(phase="trial_active"),
            lambda state: setattr(state, "journal_data", None),
            lambda state: setattr(state, "boot", "rebooted"),
            lambda state: state.native_state.append("new native rule"),
            lambda state: state.properties[driver.TIMER].update(UnitFileState="enabled"),
            lambda state: state.properties[driver.TIMER].update(ActiveState="active"),
            lambda state: state.properties[driver.HEALTH].update(ControlGroup="/system.slice/residual"),
            lambda state: state.properties[driver.CORE].update(Result="exit-code"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(change=index):
                fake = FakeTimer()
                fake.after_show[driver.RECOVERY] = mutate
                self.assert_refused(fake)
                self.assertIn("observe:" + driver.RECOVERY, fake.events)

    def test_reset_must_be_followed_by_exact_roles_native_off_and_inactive_timer(self):
        mutations = (
            lambda state: state.replace_file(driver.HEALTH, 1, 1, 99),
            lambda state: state.native_state.append("new native rule"),
            lambda state: state.journal_data.update(operation_id="c" * 32),
            lambda state: state.properties[driver.TIMER].update(ActiveState="failed", Result="resources"),
            lambda state: state.properties[driver.TIMER].update(Result="exit-code"),
            lambda state: state.properties[driver.TIMER].update(UnitFileState="enabled"),
            lambda state: state.properties[driver.TIMER].update(Unit=driver.RECOVERY),
            lambda state: state.properties[driver.TIMER].update(Job="41"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(change=index):
                fake = FakeTimer()
                fake.after_reset = mutate
                with self.assertRaises(AssertionError):
                    self.exercise(fake)
                self.assertEqual(fake.resets, [["systemctl", "reset-failed", driver.TIMER]])
                self.assert_mutations(fake, fake.resets)
        fake = FakeTimer()
        def finalized_with_native_residue(state):
            state.journal_data = None
            state.native_state.append("native residue after finalization")
        fake.after_reset = finalized_with_native_residue
        with self.assertRaises(AssertionError):
            self.exercise(fake)
        self.assertEqual(len(fake.resets), 1)
        self.assert_mutations(fake, fake.resets)


class FakeFinalReceipt:
    SUPERVISOR_REASONS = {"supervisor_unavailable", "supervisor_lease_expired"}

    def __init__(self, reason="supervisor_unavailable"):
        self.operation = "a" * 32
        self.boot = "a1234567-89ab-cdef-0123-456789abcdef"
        evidence = {"underlay_healthy": True, "vpn_healthy": True, "ipv4_tcp": True, "ipv4_udp": True,
                    "ipv4_dns": True, "ipv6_tcp": False, "ipv6_udp": False, "ipv6_dns": False,
                    "failed_targets": 0, "probe_count": 7, "elapsed_ms": 10, "reason": "healthy"}
        self.snapshot = {"confirmed": True, "state": "healthy", "attempts": 0, "failures": 0,
                         "recovery_deadline_uptime_ms": 0, "rounds": 3, "last_probe_uptime_ms": 50000,
                         "lease_deadline_uptime_ms": 60000, "evidence": evidence}
        self.value = {"operation_id": self.operation, "phase": "trial_cleared", "recovery_verified": True,
                      "experiment_only": True, "activation_ready": False, "management_confirmed": True,
                      "health_reason": reason, "reconnect_attempts": 0, "health_failures": 0,
                      "recovery_deadline_uptime_ms": 0, "health_round": 3, "health_last_uptime_ms": 50000,
                      "health_evidence": copy.deepcopy(evidence)}
        self.unit = driver.RECOVERY
        self.transform_rows = None
        self.commands = []
        self.output = io.StringIO()

    def path(self, name):
        assert name == "/proc/sys/kernel/random/boot_id"
        return argparse.Namespace(read_text=lambda: self.boot + "\n")

    def rows(self):
        # A real CLI JSON object spans multiple journal records. Reverse the
        # delivered rows so the production parser must reconstruct timestamp
        # order within this one attributable invocation, stream, and PID.
        document = json.dumps({"ok": True, "data": self.value}, indent=2)
        rows = [{"_SYSTEMD_UNIT": self.unit, "_SYSTEMD_INVOCATION_ID": "b" * 32,
                 "_STREAM_ID": "c" * 32, "_PID": "73", "_BOOT_ID": self.boot.replace("-", ""),
                 "_TRANSPORT": "stdout", "__MONOTONIC_TIMESTAMP": str(100000 + number), "MESSAGE": line}
                for number, line in enumerate(document.splitlines())]
        if self.transform_rows is not None:
            rows = self.transform_rows(rows)
        return list(reversed(rows))

    def command(self, argv, *, timeout):
        assert timeout == 3
        self.commands.append(list(argv))
        if argv == ["journalctl", "--sync"]:
            output = ""
        else:
            assert argv == ["journalctl", "-b", "--no-pager", "-n", "513", "-o", "json",
                            "-u", driver.RECOVERY, "-u", driver.HEALTH], argv
            output = "".join(json.dumps(row) + "\n" for row in self.rows())
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")


class FinalReceiptTests(unittest.TestCase):
    def exercise(self, fake, reason=FakeFinalReceipt.SUPERVISOR_REASONS, attempts=0, *, supervisor=True,
                 off_uptime_ms=60000):
        fixture = ForeignCleanupTests.new_fixture()
        fixture.op = fake.operation
        options = {"supervisor_snapshot": copy.deepcopy(fake.snapshot), "off_uptime_ms": off_uptime_ms} if supervisor else {}
        with patch.object(driver, "Path", side_effect=fake.path), \
                patch.object(fixture, "command", side_effect=fake.command), \
                patch.object(driver.subprocess, "run", side_effect=AssertionError("unexpected real process")), \
                patch.object(driver.subprocess, "Popen", side_effect=AssertionError("unexpected real process")), \
                patch.object(driver.time, "monotonic", side_effect=itertools.count()), \
                patch.object(driver.time, "sleep"), contextlib.redirect_stdout(fake.output):
            fixture.final_receipt(reason, attempts, **options)

    def assert_rejected(self, fake, **options):
        with self.assertRaises(AssertionError):
            self.exercise(fake, **options)
        self.assertNotIn("SUPERVISED_TUN_FINAL_RECEIPT=", fake.output.getvalue())

    def test_both_supervisor_causes_accept_only_matching_retained_health(self):
        for reason in sorted(FakeFinalReceipt.SUPERVISOR_REASONS):
            for unit in (driver.HEALTH, driver.RECOVERY):
                with self.subTest(reason=reason, unit=unit):
                    fake = FakeFinalReceipt(reason)
                    fake.unit = unit
                    # Product JSON omits optional zero fields; absence still
                    # means zero, while explicit noninteger values do not.
                    if unit == driver.HEALTH:
                        for field in ("reconnect_attempts", "health_failures", "recovery_deadline_uptime_ms"):
                            del fake.value[field]
                    self.exercise(fake)
                    output = fake.output.getvalue()
                    self.assertIn("unit:" + unit, output)
                    self.assertIn("reason:" + reason + " attempts:0", output)
                    self.assertIn("round:3 last_probe_ms:50000 lease_deadline_ms:60000 off_observed_ms:60000", output)
                    self.assertEqual(len(fake.commands), 2)

    def test_normal_single_reason_exhaustion_remains_exact(self):
        fake = FakeFinalReceipt("reconnect_exhausted")
        fake.value.update(reconnect_attempts=2, health_failures=2, recovery_deadline_uptime_ms=70000)
        self.exercise(fake, reason="reconnect_exhausted", attempts=2, supervisor=False)
        self.assertIn("reason:reconnect_exhausted attempts:2", fake.output.getvalue())
        self.assertNotIn("lease_deadline_ms:", fake.output.getvalue())
        for observed in ("supervisor_unavailable", "supervisor_lease_expired", "protected_underlay_failed"):
            with self.subTest(observed=observed):
                fake = FakeFinalReceipt(observed)
                fake.value["reconnect_attempts"] = 2
                self.assert_rejected(fake, reason="reconnect_exhausted", attempts=2, supervisor=False)

    def test_dead_timer_uses_one_exact_reason_without_frozen_probe_round(self):
        fake = FakeFinalReceipt()
        fake.value.update(health_round=4, health_last_uptime_ms=55000)
        fake.value["health_evidence"]["elapsed_ms"] = 20
        self.exercise(fake, reason="supervisor_unavailable", supervisor=False)
        self.assertIn("reason:supervisor_unavailable attempts:0", fake.output.getvalue())
        fake = FakeFinalReceipt("supervisor_lease_expired")
        self.assert_rejected(fake, reason="supervisor_unavailable", supervisor=False)

    def test_reason_sets_require_exact_supervisor_pair_and_snapshot(self):
        for reasons in ({"supervisor_unavailable"}, {"supervisor_unavailable", "reconnect_exhausted"},
                        FakeFinalReceipt.SUPERVISOR_REASONS | {"protected_underlay_failed"}):
            with self.subTest(reasons=reasons):
                fake = FakeFinalReceipt()
                self.assert_rejected(fake, reason=reasons)
                self.assertEqual(fake.commands, [])
        fake = FakeFinalReceipt()
        self.assert_rejected(fake, supervisor=False)
        self.assertEqual(fake.commands, [])

    def test_supervisor_receipt_rejects_path_causes_or_any_recovery_progress(self):
        for reason in ("reconnect_exhausted", "protected_underlay_failed", "vpn_path_mismatch"):
            with self.subTest(reason=reason):
                self.assert_rejected(FakeFinalReceipt(reason))
        for supervisor in (True, False):
            for field in ("reconnect_attempts", "health_failures", "recovery_deadline_uptime_ms"):
                for value in (1, False, 0.0):
                    with self.subTest(supervisor=supervisor, field=field, value=value):
                        fake = FakeFinalReceipt()
                        fake.value[field] = value
                        options = {} if supervisor else {"reason": "supervisor_unavailable", "supervisor": False}
                        self.assert_rejected(fake, **options)
        fake = FakeFinalReceipt()
        fake.value["reconnect_attempts"] = 1
        self.assert_rejected(fake, attempts=1)

    def test_supervisor_receipt_rejects_later_round_timestamp_or_evidence(self):
        for field, value in (("health_round", 4), ("health_last_uptime_ms", 50001),
                             ("health_evidence", {"probe_count": 7, "elapsed_ms": 10})):
            with self.subTest(field=field):
                fake = FakeFinalReceipt()
                fake.value[field] = value
                self.assert_rejected(fake)
        fake = FakeFinalReceipt()
        fake.value["health_evidence"]["elapsed_ms"] = 11
        self.assert_rejected(fake)

    def test_lease_cause_requires_observed_off_at_or_after_original_deadline(self):
        for observed in (59999, None, 60000.0, True):
            with self.subTest(off_uptime_ms=observed):
                self.assert_rejected(FakeFinalReceipt("supervisor_lease_expired"), off_uptime_ms=observed)
        for deadline in (0, -1, 60000.0, True):
            with self.subTest(deadline=deadline):
                fake = FakeFinalReceipt("supervisor_lease_expired")
                fake.snapshot["lease_deadline_uptime_ms"] = deadline
                self.assert_rejected(fake)
        self.exercise(FakeFinalReceipt("supervisor_lease_expired"), off_uptime_ms=60001)

    def test_receipt_requires_one_authenticated_unambiguous_invocation(self):
        for fault in ("wrong_boot", "wrong_unit", "wrong_pid", "split_invocation", "ambiguous_invocation"):
            with self.subTest(fault=fault):
                fake = FakeFinalReceipt()

                def transform(rows):
                    if fault == "ambiguous_invocation":
                        other = copy.deepcopy(rows)
                        for row in other:
                            row["_SYSTEMD_INVOCATION_ID"] = "d" * 32
                        return rows + other
                    if fault == "split_invocation":
                        rows[len(rows) // 2]["_SYSTEMD_INVOCATION_ID"] = "d" * 32
                    else:
                        field, value = {"wrong_boot": ("_BOOT_ID", "d" * 32),
                                        "wrong_unit": ("_SYSTEMD_UNIT", "foreign.service"),
                                        "wrong_pid": ("_PID", "1")}[fault]
                        for row in rows:
                            row[field] = value
                    return rows

                fake.transform_rows = transform
                self.assert_rejected(fake)

    def test_off_timestamp_is_captured_before_executor_drain_and_direct_checks(self):
        fixture = ForeignCleanupTests.new_fixture()
        events, existence, pids = [], iter((True, False)), iter(("73", "0"))
        uptime = ["42.125 0\n"]

        def journal_exists():
            exists = next(existence)
            events.append("present" if exists else "absent")
            return exists

        def read_uptime():
            events.append("uptime")
            return uptime[0]

        def path(name):
            self.assertEqual(name, "/proc/uptime")
            return argparse.Namespace(read_text=read_uptime)

        def show(unit, prop):
            self.assertEqual((unit, prop), (driver.HEALTH, "MainPID"))
            events.append("drain")
            uptime[0] = "90.000 0\n"
            return next(pids)

        with patch.object(driver, "JOURNAL", argparse.Namespace(exists=journal_exists)), \
                patch.object(driver, "Path", side_effect=path), patch.object(fixture, "show", side_effect=show), \
                patch.object(fixture, "inactive", side_effect=lambda: events.append("off_and_direct")), \
                patch.object(fixture, "command", side_effect=AssertionError("unexpected command")), \
                patch.object(driver.time, "monotonic", side_effect=itertools.count()), patch.object(driver.time, "sleep"):
            observed = fixture.independent_off()
        self.assertEqual(observed, 42125)
        self.assertEqual(events, ["present", "absent", "uptime", "drain", "drain", "off_and_direct"])


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("SUPERVISED_FIXTURE_CREATION_CLEANUP_BOUNDARIES=PASS")
    print("SUPERVISED_FIXTURE_EXACT_FAILED_EXECUTOR_BOOKKEEPING=PASS")
    print("SUPERVISED_FIXTURE_AUTHENTIC_EXECUTOR_SIGNAL=PASS")
    print("SUPERVISED_FIXTURE_REMOTE_CONFIRM_SIGKILL_RECEIPT=PASS")
    print("SUPERVISED_FIXTURE_EXACT_FAILED_TIMER_RECONCILIATION=PASS")
    print("SUPERVISED_FIXTURE_EXECUTOR_FAULT_CAUSAL_CONTEXT=PASS")
    print("SUPERVISED_FIXTURE_SUPERVISOR_OFF_CAUSAL_RECEIPTS=PASS")
