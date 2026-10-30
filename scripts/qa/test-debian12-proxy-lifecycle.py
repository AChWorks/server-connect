#!/usr/bin/env python3
"""Ordinary, unprivileged regression checks; never construct or run FieldRun.

Run with: PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-debian12-proxy-lifecycle.py
Evidence/admission predicates and a private current-user temporary-tree deletion
primitive are exercised. No subprocess, systemd, network, installed product path
or privileged lifecycle action is invoked by this suite.
"""

import copy
import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "field_lifecycle", Path(__file__).with_name("host-debian12-proxy-lifecycle.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def manifest():
    return {
        "schema": 1, "target_id": "ira-124", "source_revision": "a" * 40,
        "source_tree": "b" * 40,
        "boot_id": "c4633c6c-00ff-4abc-8000-f6c43fd73333", "run_name": "run-01",
        "artifacts": {
            label: {"file": label + ".tar.gz", "bytes": 1024, "sha256": "c" * 64}
            for label in ("base", "update", "invalid_unit")},
    }


def live_core():
    return {"pid": 2301, "invocation": "d" * 32, "start_ticks": "739182",
            "systemd_start": "7391820000", "exe_sha256": "e" * 64}


def absent_unit():
    return {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead",
            "Transient": "no", "FragmentPath": "", "DropInPaths": "",
            "Job": "", "UnitFileState": ""}


def members():
    result = []
    for name in ("server-connect", "server-connect/bin",
                 "server-connect/THIRD-PARTY-LICENSES"):
        item = tarfile.TarInfo(name + "/")
        item.type = tarfile.DIRTYPE
        result.append(item)
    for name in sorted(driver.BUNDLE_FILES):
        item = tarfile.TarInfo("server-connect/" + name)
        item.size = 1
        result.append(item)
    return result


PROFILE_ID = "a" * 16


def make_private_state(root, label=b"original"):
    root.mkdir(mode=0o700)
    (root / "profiles").mkdir(mode=0o700)
    contents = {
        ".lock": b"", "state.json": b'{"desired":"direct"}\n',
        "proxy-auth": label + b"-auth", driver.OWNER_FILE: label + b"-owner",
        "profiles/" + PROFILE_ID + ".json": label + b"-profile",
    }
    for relative, data in contents.items():
        path = root / relative
        path.write_bytes(data)
        path.chmod(0o600)
    return contents


def private_inventory(root):
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        profile_fd = os.open("profiles", os.O_RDONLY | os.O_DIRECTORY, dir_fd=root_fd)
        try:
            return driver.private_state_inventory_at(root_fd, profile_fd, PROFILE_ID)
        finally:
            os.close(profile_fd)
    finally:
        os.close(root_fd)


class TrafficEvidenceTests(unittest.TestCase):
    def test_success_requires_exact_nonce_and_independent_origin_delivery(self):
        body = b"server-connect-field:/proof/unique-nonce"
        self.assertTrue(driver.delivery_passed(0, body, body, 10, 11))
        for rc, actual, before, after in (
                (0, b"unrelated success", 10, 11), (1, body, 10, 11),
                (0, body, 10, 10), (0, body, 10, 12), (False, body, 10, 11)):
            with self.subTest(rc=rc, actual=actual, before=before, after=after):
                self.assertFalse(driver.delivery_passed(rc, actual, body, before, after))

    def test_failed_curl_that_reached_origin_is_a_leak(self):
        core = live_core()
        self.assertTrue(driver.outage_passed(7, b"", 3, 3, core, dict(core)))
        for rc, body, after in ((7, b"", 4), (0, b"", 3),
                                (7, b"partial body", 3), (-15, b"", 3)):
            with self.subTest(rc=rc, body=body, after=after):
                self.assertFalse(driver.outage_passed(rc, body, 3, after, core, core))

    def test_client_must_be_the_same_proven_live_generation_during_outage(self):
        before = live_core()
        for key in before:
            after = dict(before)
            del after[key]
            with self.subTest(missing=key):
                self.assertFalse(driver.outage_passed(7, b"", 0, 0, before, after))
        for key, value in (("pid", 2302), ("invocation", "f" * 32),
                           ("start_ticks", "739183"), ("systemd_start", "7391830000")):
            after = dict(before, **{key: value})
            with self.subTest(restarted=key):
                self.assertFalse(driver.outage_passed(7, b"", 0, 0, before, after))
        for key, value in (("pid", 0), ("pid", True), ("invocation", "0" * 32),
                           ("start_ticks", "0"), ("systemd_start", "0"),
                           ("exe_sha256", "unpinned")):
            incomplete = dict(before, **{key: value})
            with self.subTest(invalid=key, value=value):
                self.assertFalse(driver.outage_passed(7, b"", 0, 0,
                                                     incomplete, incomplete))


class InputAdmissionTests(unittest.TestCase):
    def test_opposite_target_requires_the_actual_mismatch_refusal(self):
        report = {
            "ok": False, "data": {"target": "", "verified": False},
            "error": {"code": "installer_target_mismatch",
                      "message": "bundle target does not match the actual supported host"},
        }
        self.assertTrue(driver.opposite_target_refused(1, report))
        for code in (0, 2, -15, True):
            self.assertFalse(driver.opposite_target_refused(code, report))
        for key, value in (("ok", True), ("data", {"target": "", "verified": True}),
                           ("error", {"code": "invalid_arguments", "message": "unavailable"})):
            with self.subTest(key=key):
                self.assertFalse(driver.opposite_target_refused(1, dict(report, **{key: value})))

    def test_exact_manifest_and_optional_machine_pin(self):
        value = manifest()
        driver.validate_manifest(value)
        value["machine_id_sha256"] = "d" * 64
        driver.validate_manifest(value)

    def test_incomplete_or_wrong_host_manifest_is_refused(self):
        for key, value in (("schema", True), ("target_id", "ira-125"),
                           ("source_revision", "short"), ("source_tree", 12),
                           ("boot_id", None), ("boot_id", "invalid"),
                           ("run_name", "../previous"), ("machine_id_sha256", 8)):
            candidate = manifest()
            candidate[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(driver.CheckFailure):
                    driver.validate_manifest(candidate)
        for key in manifest():
            candidate = manifest()
            del candidate[key]
            with self.subTest(missing=key), self.assertRaises(driver.CheckFailure):
                driver.validate_manifest(candidate)

    def test_artifacts_are_complete_local_bounded_and_pinned(self):
        for key, value in (("file", "../base.tar.gz"), ("file", "/root/base.tar.gz"),
                           ("bytes", True), ("bytes", 0), ("bytes", 104857601),
                           ("sha256", "unknown"), ("sha256", None)):
            candidate = manifest()
            candidate["artifacts"]["base"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(driver.CheckFailure):
                driver.validate_manifest(candidate)
        candidate = manifest()
        del candidate["artifacts"]["invalid_unit"]
        with self.assertRaises(driver.CheckFailure):
            driver.validate_manifest(candidate)
        candidate = manifest()
        candidate["artifacts"]["update"]["file"] = candidate["artifacts"]["base"]["file"]
        with self.assertRaises(driver.CheckFailure):
            driver.validate_manifest(candidate)

    def test_bundle_requires_exact_regular_payload(self):
        driver.validate_members(members())
        cases = []
        candidate = members()
        candidate[-1].name = "server-connect/../outside"
        cases.append(candidate)
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            candidate = members()
            candidate[-1].type = kind
            candidate[-1].linkname = "/etc/passwd"
            cases.append(candidate)
        candidate = members()
        candidate.append(copy.copy(candidate[-1]))
        cases.append(candidate)
        candidate = members()
        candidate[-1].name = "server-connect/unexpected"
        cases.append(candidate)
        candidate = members()
        candidate[-1].size = 134217729
        cases.append(candidate)
        cases.append(members()[:-1])
        for index, candidate in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(driver.CheckFailure):
                driver.validate_members(candidate)


class CleanupEvidenceTests(unittest.TestCase):
    def test_exact_current_user_temporary_state_can_be_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / driver.STATE.name
            make_private_state(root)
            expected = private_inventory(root)
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                driver.delete_exact_private_state(parent_fd, PROFILE_ID, expected)
            finally:
                os.close(parent_fd)
            self.assertFalse(root.exists())

    def test_directory_replacement_between_path_check_and_open_is_preserved(self):
        for replaced in ("root", "profiles"):
            with self.subTest(replaced=replaced), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / driver.STATE.name
                original = make_private_state(root)
                expected = private_inventory(root)
                # These are the valid pathname observations immediately before
                # cleanup opens the directories. The injected swap follows them.
                self.assertTrue(driver.private_directory_matches(root.stat(), expected["."]))
                self.assertTrue(driver.private_directory_matches(
                    (root / "profiles").stat(), expected["profiles"]))
                parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                real_open = os.open
                swapped = False
                replacement_contents = None

                def swap_on_open(path, flags, *args, **kwargs):
                    nonlocal swapped, replacement_contents
                    trigger = driver.STATE.name if replaced == "root" else "profiles"
                    if not swapped and path == trigger:
                        old = root if replaced == "root" else root / "profiles"
                        old.rename(parent / "retained-original")
                        if replaced == "root":
                            replacement_contents = make_private_state(root, b"foreign")
                        else:
                            old.mkdir(mode=0o700)
                            foreign = old / (PROFILE_ID + ".json")
                            foreign.write_bytes(b"foreign-profile")
                            foreign.chmod(0o600)
                            replacement_contents = dict(original)
                            replacement_contents["profiles/" + PROFILE_ID + ".json"] = b"foreign-profile"
                        swapped = True
                    return real_open(path, flags, *args, **kwargs)

                try:
                    with mock.patch.object(driver.os, "open", side_effect=swap_on_open):
                        expected_error = "Opened " + (
                            "state root" if replaced == "root" else "profiles") + " identity"
                        with self.assertRaisesRegex(driver.CheckFailure, expected_error):
                            driver.delete_exact_private_state(parent_fd, PROFILE_ID, expected)
                finally:
                    os.close(parent_fd)
                self.assertTrue(swapped)
                for relative, data in replacement_contents.items():
                    self.assertEqual((root / relative).read_bytes(), data)
                retained = parent / "retained-original"
                if replaced == "root":
                    for relative, data in original.items():
                        self.assertEqual((retained / relative).read_bytes(), data)
                else:
                    self.assertEqual((retained / (PROFILE_ID + ".json")).read_bytes(),
                                     original["profiles/" + PROFILE_ID + ".json"])

    def test_baseline_normalization_keeps_route_or_lifetime_state_changes(self):
        before = {"gateway": "192.0.2.1", "expires": 120,
                  "address": {"local": "192.0.2.2", "valid_life_time": 3600}}
        aged = copy.deepcopy(before)
        aged["expires"] = 60
        aged["address"]["valid_life_time"] = 3540
        self.assertEqual(driver.normalize_network(before), driver.normalize_network(aged))
        for key, value in (("gateway", "192.0.2.9"), ("expires", 0),
                           ("expires", -1), ("expires", 4294967295)):
            with self.subTest(key=key, value=value):
                self.assertNotEqual(driver.normalize_network(before),
                                    driver.normalize_network(dict(before, **{key: value})))

    def test_success_cannot_hide_failed_lifecycle_or_uncertain_cleanup(self):
        complete = {
            "lifecycle_completed": True, "exact_test_state_purged": True,
            "all_private_children_stopped": True, "no_outage_origin_delivery": True,
            "task_listeners_absent": True, "product_resources_absent": True,
            "recorded_host_views_unchanged": True, "mutation_outcome_known": True,
            "changed_host_components": [], "cleanup_errors": [],
        }
        self.assertTrue(driver.final_passed(complete))
        for key, value in complete.items():
            missing = dict(complete)
            del missing[key]
            with self.subTest(missing=key):
                self.assertFalse(driver.final_passed(missing))
            if value is True:
                with self.subTest(false=key):
                    self.assertFalse(driver.final_passed(dict(complete, **{key: False})))
        for fields in ({"failure": {}}, {"cleanup_errors": ["unknown state owner"]},
                       {"changed_host_components": ["routes4"]}):
            with self.subTest(fields=fields):
                self.assertFalse(driver.final_passed(dict(complete, **fields)))

    def test_absent_timer_and_absent_service_have_different_observation_fields(self):
        timer = absent_unit()
        self.assertTrue(driver.unit_absent("example.timer", timer))
        self.assertFalse(driver.unit_absent("example.service", timer))
        service = dict(timer, MainPID="0", ControlPID="0")
        self.assertTrue(driver.unit_absent("example.service", service))
        for field, value in (("MainPID", "8"), ("ControlPID", "8"),
                             ("LoadState", "loaded"), ("Job", "17"),
                             ("DropInPaths", "/etc/systemd/system/conflict.conf")):
            with self.subTest(field=field):
                self.assertFalse(driver.unit_absent(
                    "example.service", dict(service, **{field: value})))
        del timer["FragmentPath"]
        self.assertFalse(driver.unit_absent("example.timer", timer))

    def test_cleanup_preserves_foreign_files_replacements_and_changed_ownership(self):
        expected = {
            ".": {"kind": "directory", "uid": 0, "gid": 0, "mode": 0o700,
                  "device": 8, "inode": 100},
            "owned.json": {"kind": "file", "uid": 0, "gid": 0, "mode": 0o600,
                           "device": 8, "inode": 101, "bytes": 2, "sha256": "f" * 64},
        }
        self.assertTrue(driver.purge_inventory_matches(copy.deepcopy(expected), expected))
        changed = copy.deepcopy(expected)
        changed["foreign"] = dict(expected["owned.json"])
        self.assertFalse(driver.purge_inventory_matches(changed, expected))
        for field, value in (("inode", 102), ("sha256", "a" * 64),
                             ("uid", 1000), ("gid", 1000), ("mode", 0o644),
                             ("kind", "symlink")):
            changed = copy.deepcopy(expected)
            changed["owned.json"][field] = value
            with self.subTest(field=field):
                self.assertFalse(driver.purge_inventory_matches(changed, expected))
                if field in {"uid", "gid", "mode", "kind"}:
                    self.assertFalse(driver.purge_inventory_matches(changed, changed))
        self.assertFalse(driver.purge_inventory_matches({}, {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
