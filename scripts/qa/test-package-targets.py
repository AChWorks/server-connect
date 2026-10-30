#!/usr/bin/env python3
"""Ordinary package argument and installer preflight-order regressions.

The builder sees only an intentionally invalid core archive, so these tests
never build or unpack a candidate. The installer harness executes its actual
verify_payload function against private inert executables and real checksums;
file ownership checks are replaced with unprivileged fixture checks. This is
not native platform, installed-host, ABI or publisher-authenticity evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "scripts" / "package.sh"
INSTALLER = ROOT / "bundle" / "install.sh"
PAYLOAD_FILES = (
    "bin/server-connect",
    "bin/sing-box",
    "bin/libcronet.so",
    "server-connect.service",
    "server-connect-activation-recover.service",
    "server-connect-activation-recover.timer",
    "server-connect-smart-tun.service",
    "server-connect-smart-health.service",
    "server-connect-smart-health.timer",
    "install.sh",
    "THIRD-PARTY-LICENSES/sing-box-LICENSE",
    "manifest.json",
)


class PackageArgumentTests(unittest.TestCase):
    def invoke(self, *targets):
        with tempfile.TemporaryDirectory(prefix="sc-package-args-") as scratch:
            core = Path(scratch) / "invalid-core.tar.gz"
            core.write_bytes(b"INERT NON-ARCHIVE FIXTURE\n")
            return subprocess.run(
                ["/bin/sh", str(PACKAGE), str(core), *targets],
                capture_output=True, text=True, timeout=5,
            )

    def test_only_explicit_supported_targets_reach_pinned_core_check(self):
        # Reaching this distinct refusal proves default/explicit target
        # admission without bypassing the production core-integrity gate.
        for args in ((), ("debian-12-amd64",), ("debian-13-amd64",)):
            with self.subTest(target=args or "default"):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Pinned upstream core archive digest mismatch", result.stderr)
                self.assertNotIn("Unsupported package target", result.stderr)

    def test_unsupported_and_empty_targets_fail_before_core_processing(self):
        for target in ("", "debian-11-amd64", "debian-14-amd64", "debian-12-arm64", "ubuntu-24.04-amd64"):
            with self.subTest(target=target):
                result = self.invoke(target)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("Unsupported package target", result.stderr)
                self.assertNotIn("Pinned upstream core archive digest mismatch", result.stderr)

    def test_extra_target_arguments_are_not_silently_ignored(self):
        result = self.invoke("debian-12-amd64", "debian-13-amd64")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Usage: scripts/package.sh", result.stderr)
        self.assertNotIn("Pinned upstream core archive digest mismatch", result.stderr)


class InstallerTargetOrderingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sc-installer-target-order-")
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory / "bundle"
        self.bundle.mkdir()
        self.calls = self.directory / "executed-checks"
        for name in PAYLOAD_FILES:
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"INERT QA ONLY\n")
        (self.bundle / "manifest.json").write_text(json.dumps({"target": "debian-12-amd64"}) + "\n")
        # These are deliberately inert test executables, not substitutes for
        # ROOT's real Go target-parser tests or exact installed candidate QA.
        (self.bundle / "bin/server-connect").write_text(r"""#!/bin/sh
set -eu
printf '%s\n' "$1" >> "$SC_QA_CALLS"
case "$1" in
 installer-check-target)
  [ "$#" -eq 3 ] && [ "$2" = --manifest ] && [ "$3" = "$SC_QA_MANIFEST" ] || exit 91
  exit "$SC_QA_TARGET_EXIT"
  ;;
 version)
  [ "$#" -eq 2 ] && [ "$2" = --json ] || exit 92
  printf '%s\n' '{"ok":true,"data":{"sing_box":"1.14.3"}}'
  ;;
 *) exit 93 ;;
esac
""")
        (self.bundle / "bin/sing-box").write_text(r"""#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = version ] || exit 94
printf '%s\n' core-version >> "$SC_QA_CALLS"
printf '%s\n' 'sing-box version 1.14.3'
""")
        for name in ("bin/server-connect", "bin/sing-box"):
            (self.bundle / name).chmod(0o700)
        self.write_checksums()
        body = INSTALLER.read_text()
        begin = body.index("verify_payload() {\n")
        end = body.index("\n}\n", begin) + len("\n}\n")
        self.function = body[begin:end]

    def tearDown(self):
        self.temporary.cleanup()

    def write_checksums(self):
        (self.bundle / "checksums.sha256").write_text("".join(
            hashlib.sha256((self.bundle / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in PAYLOAD_FILES
        ))

    def invoke(self, target_exit):
        environment = os.environ.copy()
        environment.update({
            "SC_QA_BUNDLE": str(self.bundle),
            "SC_QA_CALLS": str(self.calls),
            "SC_QA_MANIFEST": str(self.bundle / "manifest.json"),
            "SC_QA_TARGET_EXIT": str(target_exit),
        })
        # Only this read-only preflight function is extracted. No entrypoint,
        # lifecycle code, systemd operation or installed path can be invoked.
        harness = r"""set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
SOURCE_DIR=$SC_QA_BUNDLE
say() { printf 'Server Connect: %s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
check_root_file() { [ -f "$1" ] && [ ! -L "$1" ] || die 'fixture file missing'; }
check_root_dir() { [ -d "$1" ] && [ ! -L "$1" ] || die 'fixture directory missing'; }
""" + self.function + "\nverify_payload\n"
        result = subprocess.run(
            ["/bin/sh", "-s"], input=harness, env=environment,
            capture_output=True, text=True, timeout=5,
        )
        calls = self.calls.read_text().splitlines() if self.calls.exists() else []
        return result, calls

    def test_checksum_failure_prevents_any_candidate_execution(self):
        with (self.bundle / "manifest.json").open("a") as changed:
            changed.write("CORRUPTED AFTER CHECKSUM\n")
        result, calls = self.invoke(0)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("bundle checksum mismatch; no changes applied", result.stderr)
        self.assertEqual(calls, [])

    def test_target_refusal_stops_later_executable_checks(self):
        result, calls = self.invoke(19)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Server Connect: ERROR: bundle target does not match this supported host", result.stderr)
        self.assertEqual(calls, ["installer-check-target"])

    def test_accepted_target_precedes_manager_and_core_version_checks(self):
        result, calls = self.invoke(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["installer-check-target", "version", "core-version"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
