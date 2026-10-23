#!/usr/bin/env python3
"""Bounded local regression tests for the privileged online bootstrap.

No installation, privileged network mutation, external fetch or real release
artifact is involved. The server serves synthetic archives on loopback only.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "bootstrap-online.sh"
INSTALLER = ROOT / "bundle" / "install.sh"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def archive(path: Path, *, abnormal: str | None = None) -> str:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as output:
        folder = tarfile.TarInfo("server-connect/")
        folder.type = tarfile.DIRTYPE
        folder.mode = 0o755
        output.addfile(folder)

        body = b"#!/bin/sh\nexit 93\n"  # This must NEVER run in --verify-only.
        entry = tarfile.TarInfo("server-connect/install.sh")
        entry.mode = 0o755
        entry.size = len(body)
        output.addfile(entry, io.BytesIO(body))
        if abnormal == "duplicate":
            output.addfile(entry, io.BytesIO(body))
        if abnormal == "traversal":
            entry = tarfile.TarInfo("server-connect/../../escape")
            entry.size = len(body)
            output.addfile(entry, io.BytesIO(body))
        if abnormal == "symlink":
            entry = tarfile.TarInfo("server-connect/link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            output.addfile(entry)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BootstrapEnvironmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="sc-bootstrap-qa-")
        cls.directory = Path(cls.temporary.name)
        cls.digests = {}
        for name, abnormal in [
            ("valid.tar.gz", None),
            ("duplicate.tar.gz", "duplicate"),
            ("traversal.tar.gz", "traversal"),
            ("symlink.tar.gz", "symlink"),
        ]:
            cls.digests[name] = archive(cls.directory / name, abnormal=abnormal)
        handler = partial(QuietHandler, directory=str(cls.directory))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def bootstrap(self, filename="valid.tar.gz", *, changes=None, digest=None):
        environment = os.environ.copy()
        if changes:
            environment.update(changes)
        return subprocess.run(
            [
                "/bin/sh", str(BOOTSTRAP),
                "--archive-url",
                f"http://127.0.0.1:{self.server.server_port}/{filename}",
                "--sha256", digest or self.digests[filename], "--verify-only",
            ],
            env=environment, capture_output=True, text=True, timeout=25,
        )

    def test_valid_local_archive(self):
        result = self.bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_inherited_tar_options_are_ignored(self):
        result = self.bootstrap(changes={"TAR_OPTIONS": "--help", "GZIP": "--bad-option"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_curl_config_is_not_loaded(self):
        directory = self.directory / "curl-home"
        directory.mkdir(exist_ok=True)
        (directory / ".curlrc").write_text("--not-a-valid-curl-option\n")
        result = self.bootstrap(changes={"CURL_HOME": str(directory)})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_inherited_executable_path_is_ignored(self):
        shadow = self.directory / "shadow"
        shadow.mkdir(exist_ok=True)
        fake_tar = shadow / "tar"
        fake_tar.write_text("#!/bin/sh\nexit 94\n")
        fake_tar.chmod(0o755)
        result = self.bootstrap(changes={"PATH": str(shadow) + ":" + os.environ.get("PATH", "")})
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned staging test requires CI root")
    def test_root_does_not_trust_tmpdir(self):
        result = self.bootstrap(changes={"TMPDIR": str(self.directory / "no-such-directory")})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_archive_policy_rejects_unsafe_members(self):
        for filename in ("duplicate.tar.gz", "traversal.tar.gz", "symlink.tar.gz"):
            with self.subTest(filename=filename):
                result = self.bootstrap(filename)
                self.assertNotEqual(result.returncode, 0, "Unsafe archive was accepted")

    def test_independent_digest_required(self):
        result = self.bootstrap(digest="0" * 64)
        self.assertNotEqual(result.returncode, 0)

    def test_offline_installer_ignores_inherited_path(self):
        shadow = self.directory / "shadow-installer"
        shadow.mkdir(exist_ok=True)
        marker = self.directory / "untrusted-id-executed"
        fake_id = shadow / "id"
        fake_id.write_text('#!/bin/sh\nprintf "called\\n" > "$SC_QA_SENTINEL"\nprintf "0\\n"\n')
        fake_id.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = str(shadow) + ":" + environment.get("PATH", "")
        environment["SC_QA_SENTINEL"] = str(marker)
        # This is an intentionally incomplete bundle. Preflight MUST fail and
        # must never run a caller-provided executable or install anything.
        result = subprocess.run(
            ["/bin/sh", str(INSTALLER), "--verify-only"],
            env=environment, capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists(), result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
