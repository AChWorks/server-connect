#!/usr/bin/env python3
"""Rootless execution of the actual installer release staging and audit path.

No systemd, root-owned installation, network, live service or product state
is touched. Installed Debian12/13 guest tests separately prove real lifecycle.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INSTALLER = (Path(__file__).resolve().parents[2] / "bundle/install.sh").read_text()
def extract(start: str, stop: str) -> str:
    assert INSTALLER.count(start) == 1, start
    tail = INSTALLER.partition(start)[2]
    assert stop in tail
    return start + tail.partition(stop)[0] + stop

FUNCTIONS = (
    extract("release_payload_files() {\n", "\n}\n")
    + "\n"
    + extract("verify_release_payload() (\n", "\n)\n")
    + "\n"
    + extract("check_owned() {\n", "\n}\n")
)
STAGING = extract(
    " stage=$(mktemp -d \"$PREFIX/releases/.stage.XXXXXXXX\") || die 'cannot stage release'\n",
    " stage=''\n",
)
assert 'verify_release_payload "$stage"' in STAGING
assert 'install -m 0644 "$SOURCE_DIR/checksums.sha256"' in STAGING
RELEASE_ASSIGNMENT = [line for line in INSTALLER.splitlines()
                      if line.startswith('release_name="0.1.0-dev-')]
assert len(RELEASE_ASSIGNMENT) == 1
assert 'sha256sum "$SOURCE_DIR/checksums.sha256" | cut -c 1-16' in RELEASE_ASSIGNMENT[0]
assert 'release_created=yes' in STAGING

FILES = (
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
PROLOG = """set -eu
check_root_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
check_root_dir() { [ -d "$1" ] && [ ! -L "$1" ]; }
check_dir() { check_root_dir "$1"; }
die() { printf 'QA_REFUSED:%s\\n' "$*" >&2; exit 21; }
"""
# Mock root-ownership has no authority: the above checks exercise only
# regular file/path and digest behavior in a private disposable directory.


class ReleasePayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sc-release-payload-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.prefix = self.root / "target"
        (self.prefix / "releases").mkdir(parents=True)
        for name in FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("fixture-for-" + name + "\n").encode())
        self.checksums()

    def checksums(self):
        (self.source / "checksums.sha256").write_text(
            "".join(hashlib.sha256((self.source / name).read_bytes()).hexdigest()
                    + "  " + name + "\n" for name in FILES))

    def shell(self, command: str, *, expected=0):
        env = dict(os.environ, QA_SOURCE=str(self.source),
                   QA_PREFIX=str(self.prefix))
        script = (PROLOG + FUNCTIONS +
                  'SOURCE_DIR=$QA_SOURCE\nPREFIX=$QA_PREFIX\n'
                  'STATE=$QA_PREFIX/absent-state\n'
                  'UNIT=$QA_PREFIX/absent-unit\n'
                  'COMMAND=$QA_PREFIX/absent-command\n' + command)
        result = subprocess.run(["/bin/sh", "-s"], input=script,
                                text=True, capture_output=True,
                                env=env, timeout=10)
        if expected:
            self.assertNotEqual(result.returncode, 0,
                                f"unsafe payload accepted\n{result.stdout}\n{result.stderr}")
        else:
            self.assertEqual(result.returncode, 0,
                             f"rc={result.returncode}\n{result.stdout}\n{result.stderr}")
        return result

    def publish(self):
        suffix = hashlib.sha256(
            (self.source / "checksums.sha256").read_bytes()).hexdigest()[:16]
        name = "0.1.0-dev-" + suffix
        result = self.shell(
            RELEASE_ASSIGNMENT[0] + '\n'
            + 'release="$PREFIX/releases/$release_name"\n'
            'stage=""\nrelease_created=no\n'
            + STAGING + '\nprintf "%s\\n" "$release"\n')
        self.assertEqual(result.stdout.strip(), str(self.prefix / "releases" / name))
        return self.prefix / "releases" / name

    def audit(self, path, expected=0):
        return self.shell('verify_release_payload "' + str(path) + '"\n',
                          expected=expected)

    def test_complete_bundle_retained_and_bit_identical(self):
        release = self.publish()
        self.audit(release)
        for name in (*FILES, "checksums.sha256"):
            with self.subTest(name=name):
                self.assertEqual((release / name).read_bytes(),
                                 (self.source / name).read_bytes())
        self.assertEqual((release / ".owner").read_text(),
                         "AChWorks/server-connect\n")
        self.assertEqual((release / "install.sh").stat().st_mode & 0o777, 0o755)

    def test_manifest_change_changes_release_name_even_with_same_binaries(self):
        first = self.publish()
        (self.source / "manifest.json").write_text("distinct manifest, same manager and core\n")
        self.checksums()
        second = self.publish()
        self.assertNotEqual(first, second)
        self.audit(first)
        self.audit(second)

    def test_mutation_and_symlink_are_refused(self):
        release = self.publish()
        (release / "manifest.json").write_text("modified without new digest\n")
        self.audit(release, expected=21)
        (release / "manifest.json").write_bytes((self.source / "manifest.json").read_bytes())
        self.audit(release)
        (release / "bin/sing-box").unlink()
        (release / "bin/sing-box").symlink_to(self.source / "bin/sing-box")
        self.audit(release, expected=21)

    def test_omitted_duplicate_escape_and_ordered_checksums_fail_closed(self):
        release = self.publish()
        checksums = release / "checksums.sha256"
        original = checksums.read_text().splitlines(keepends=True)
        for changed in (
            original[:-1],  # sha256sum -c alone accepts missing manifest
            original + original[-1:],
            original[:-1] + [original[-1].replace("manifest.json", "../manifest.json")],
            original[::-1],
        ):
            checksums.write_text("".join(changed))
            self.audit(release, expected=21)
        checksums.write_text("".join(original))
        self.audit(release)

    def owned_current(self, release, expected=0):
        (self.prefix / ".owner").write_text("AChWorks/server-connect\n")
        current = self.prefix / "current"
        if current.is_symlink():
            current.unlink()
        current.symlink_to("releases/" + release.name)
        return self.shell("check_owned\n", expected=expected)

    def test_current_release_audit_and_tamper_refusal_before_lifecycle(self):
        release = self.publish()
        self.owned_current(release)
        (release / "manifest.json").write_text("changed after publication\n")
        self.owned_current(release, expected=21)
        (release / "manifest.json").write_bytes((self.source / "manifest.json").read_bytes())
        self.owned_current(release)
        renamed = self.prefix / "releases" / ("0.1.0-dev-" + "f" * 16)
        release.rename(renamed)
        self.owned_current(renamed, expected=21)

    def test_legacy_release_remains_accepted_but_partial_metadata_refused(self):
        release = self.prefix / "releases" / ("0.1.0-dev-" + "a" * 16)
        (release / "bin").mkdir(parents=True)
        (release / "THIRD-PARTY-LICENSES").mkdir()
        for name in ("bin/server-connect", "bin/sing-box", "bin/libcronet.so",
                     "THIRD-PARTY-LICENSES/sing-box-LICENSE"):
            (release / name).write_bytes((self.source / name).read_bytes())
        (release / ".owner").write_text("AChWorks/server-connect\n")
        self.owned_current(release)
        (release / "manifest.json").write_bytes((self.source / "manifest.json").read_bytes())
        self.owned_current(release, expected=21)

    def test_current_symlink_escape_is_rejected(self):
        (self.prefix / ".owner").write_text("AChWorks/server-connect\n")
        (self.prefix / "current").symlink_to("releases/..")
        self.shell("check_owned\n", expected=21)

    def test_installed_service_template_tampering_is_detected(self):
        release = self.publish()
        self.owned_current(release)
        (release / "server-connect-smart-health.service").write_bytes(
            b"changed managed service template\n")
        self.owned_current(release, expected=21)
        self.audit(release, expected=21)


if __name__ == "__main__":
    unittest.main(verbosity=2)
