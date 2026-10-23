#!/usr/bin/env python3
"""Disposable, loopback-only security regressions for the development bootstrap.

No real installer is allowed to run in these fixtures; synthetic release
binaries are inert and every HTTP invocation passes --verify-only.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "bootstrap-online.sh"
INSTALLER = ROOT / "bundle" / "install.sh"
FILE_NAMES = [
    "server-connect/install.sh",
    "server-connect/server-connect.service",
    "server-connect/manifest.json",
    "server-connect/checksums.sha256",
    "server-connect/bin/server-connect",
    "server-connect/bin/sing-box",
    "server-connect/bin/libcronet.so",
    "server-connect/THIRD-PARTY-LICENSES/sing-box-LICENSE",
]


def archive(path: Path, *, abnormal: str | None = None) -> str:
    if abnormal == "expanded":
        info = tarfile.TarInfo("server-connect/bin/sing-box")
        info.mode = 0o755
        info.size = 4294967297
        with gzip.open(path, "wb") as output:
            # A declared oversized entry is rejected before reading payload.
            output.write(info.tobuf(format=tarfile.GNU_FORMAT))
            output.write(b"\0" * 1024)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    format_type = tarfile.PAX_FORMAT if abnormal == "pax_metadata" else tarfile.GNU_FORMAT
    with tarfile.open(path, "w:gz", format=format_type) as output:
        for directory in [
            "server-connect/",
            "server-connect/bin/",
            "server-connect/THIRD-PARTY-LICENSES/",
        ]:
            entry = tarfile.TarInfo(directory)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            output.addfile(entry)
        for name in FILE_NAMES:
            body = b"INERT QA ONLY\n"
            if name == "server-connect/install.sh":
                body = b"#!/bin/sh\nexit 93\n"  # Never executed by --verify-only.
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name.endswith("/install.sh") else 0o644
            entry.size = len(body)
            if abnormal == "pax_metadata" and name.endswith("/install.sh"):
                entry.pax_headers = {"comment": "x" * 3_000_000}
            output.addfile(entry, io.BytesIO(body))
        if abnormal == "duplicate":
            entry = tarfile.TarInfo("server-connect/install.sh")
            entry.size = 1
            output.addfile(entry, io.BytesIO(b"x"))
        if abnormal == "traversal":
            entry = tarfile.TarInfo("server-connect/../../escape")
            entry.size = 1
            output.addfile(entry, io.BytesIO(b"x"))
        if abnormal == "symlink":
            entry = tarfile.TarInfo("server-connect/link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            output.addfile(entry)
        if abnormal == "hardlink":
            entry = tarfile.TarInfo("server-connect/link")
            entry.type = tarfile.LNKTYPE
            entry.linkname = "server-connect/install.sh"
            output.addfile(entry)
        if abnormal == "members":
            for i in range(10001):
                entry = tarfile.TarInfo(f"server-connect/extra-{i:05d}")
                entry.size = 1
                output.addfile(entry, io.BytesIO(b"x"))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LocalHTTPHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/declared-too-large":
            self.send_response(200)
            self.send_header("Content-Length", "4096")
            self.end_headers()
            return
        if self.path == "/truncated":
            self.send_response(200)
            self.send_header("Content-Length", "4096")
            self.end_headers()
            self.wfile.write(b"x" * 100)
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/chunked-too-large":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for _ in range(4):
                    payload = b"x" * 600
                    self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        return super().do_GET()


class BootstrapSecurityTest(unittest.TestCase):
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
            ("hardlink.tar.gz", "hardlink"),
            ("expanded.tar.gz", "expanded"),
            ("members.tar.gz", "members"),
            ("pax_metadata.tar.gz", "pax_metadata"),
        ]:
            cls.digests[name] = archive(cls.directory / name, abnormal=abnormal)
        handler = partial(LocalHTTPHandler, directory=str(cls.directory))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def bootstrap(self, filename="valid.tar.gz", *, changes=None, digest=None, extra=(), interpreter="/bin/sh", clean_entry=False):
        environment = os.environ.copy()
        if changes:
            environment.update(changes)
        argv = [
            interpreter, str(BOOTSTRAP), "--archive-url",
            f"http://127.0.0.1:{self.server.server_port}/{filename}",
            "--sha256", digest or self.digests.get(filename, "0" * 64),
            "--verify-only", *extra,
        ]
        if clean_entry:
            argv = [
                "/usr/bin/env", "-i", "HOME=/root",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", *argv,
            ]
        return subprocess.run(
            argv, env=environment, capture_output=True, text=True, timeout=30,
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

    @unittest.skipUnless(os.geteuid() == 0, "privileged staging fixture requires CI root")
    def test_root_does_not_trust_tmpdir(self):
        result = self.bootstrap(changes={"TMPDIR": str(self.directory / "no-such-directory")})
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "trusted root-entry fixture requires CI root")
    def test_clean_entry_discards_bash_startup(self):
        marker = self.directory / "bad-startup"
        startup = self.directory / "untrusted-bash-env"
        startup.write_text(f"printf unsafe > '{marker}'\n")
        result = self.bootstrap(changes={"BASH_ENV": str(startup), "PYTHONPATH": "/invalid"},
                                interpreter="/bin/bash", clean_entry=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), "inherited Bash startup code executed")

    @unittest.skipUnless(
        os.geteuid() == 0 and os.environ.get("SC_QA_SUDO_ENTRY") == "1",
        "real sudo entry fixture is only enabled in disposable Debian CI",
    )
    def test_trusted_sudo_entry_removes_bash_and_loader_environment(self):
        # Start as unprivileged nobody. A non-existent preload path is a
        # harmless marker; propagation to privileged helpers produces a
        # visible loader warning instead of running untrusted library code.
        marker = self.directory / "privileged-bash-startup-was-read"
        startup = self.directory / "hostile-bash-env"
        startup.write_text(f"printf unsafe > '{marker}'\n")
        env = os.environ.copy()
        env["BASH_ENV"] = str(startup)
        env["LD_PRELOAD"] = "/not-a-valid-sc-qa-loader.so"
        env["LD_AUDIT"] = "/not-a-valid-sc-qa-audit.so"
        env["PATH"] = "/not-a-valid-shadow-bin:" + env.get("PATH", "")
        argv = [
            "/usr/bin/sudo", "-n", "--", "/usr/bin/env", "-i",
            "HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
            "/bin/bash", str(BOOTSTRAP),
            "--archive-url", f"http://127.0.0.1:{self.server.server_port}/valid.tar.gz",
            "--sha256", self.digests["valid.tar.gz"], "--verify-only",
        ]

        def demote():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)

        result = subprocess.run(
            argv, env=env, preexec_fn=demote,
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), "untrusted BASH_ENV was executed as root")
        self.assertNotIn("ld.so", result.stderr, "loader configuration reached a privileged helper")
        self.assertIn("Installation was not attempted", result.stdout)

    def test_rejects_unsafe_members_and_parser_resource_abuse(self):
        for filename in (
            "duplicate.tar.gz", "traversal.tar.gz", "symlink.tar.gz",
            "hardlink.tar.gz", "expanded.tar.gz", "members.tar.gz",
            "pax_metadata.tar.gz",
        ):
            with self.subTest(filename=filename):
                result = self.bootstrap(filename)
                self.assertNotEqual(result.returncode, 0, "Unsafe archive was accepted")

    def test_independent_digest_required(self):
        result = self.bootstrap(digest="0" * 64)
        self.assertNotEqual(result.returncode, 0)

    def test_transfer_ceiling_applies_to_declared_and_chunked_lengths(self):
        # The fixture uses the same curl max-filesize path, but with a
        # smaller operator-specified ceiling; never transfers 1 GiB in CI.
        for filename in ("declared-too-large", "chunked-too-large"):
            with self.subTest(filename=filename):
                result = self.bootstrap(filename, extra=("--max-download-bytes", "1024"))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("transfer ceiling", result.stderr)

    def test_transfer_truncation_is_rejected(self):
        result = self.bootstrap("truncated")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Online acquisition failed", result.stderr)

    def test_cannot_raise_global_transfer_ceiling(self):
        for size in ("0", "1073741825", "-1", "not-a-number", "9999999999999999999999"):
            result = self.bootstrap(extra=("--max-download-bytes", size))
            self.assertNotEqual(result.returncode, 0)

    def test_failure_cleans_disposable_staging(self):
        if os.geteuid() == 0:
            parent = Path("/root")
            pattern = ".server-connect-bootstrap.*"
            before = set(parent.glob(pattern))
            result = self.bootstrap("chunked-too-large", extra=("--max-download-bytes", "1024"))
            after = set(parent.glob(pattern))
        else:
            parent = self.directory / "restricted-tmp"
            parent.mkdir(mode=0o700, exist_ok=True)
            before = set(parent.iterdir())
            result = self.bootstrap("chunked-too-large", changes={"TMPDIR": str(parent)},
                                    extra=("--max-download-bytes", "1024"))
            after = set(parent.iterdir())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, after, "temporary acquisition staging leaked")

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
        result = subprocess.run(
            ["/bin/sh", str(INSTALLER), "--verify-only"],
            env=environment, capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists(), result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned ancestry verification requires CI root")
    def test_offline_source_trust_chain(self):
        # No complete bundle or systemd service exists in this disposable
        # unit fixture: rejection must occur BEFORE installed service I/O.
        with tempfile.TemporaryDirectory(prefix="sc-unsafe-") as bad:
            staged = Path(bad) / "root-owned" / "bundle"
            staged.mkdir(parents=True, mode=0o700)
            installer = staged / "install.sh"
            shutil.copyfile(INSTALLER, installer)
            installer.chmod(0o700)
            result = subprocess.run(
                ["/bin/sh", str(installer), "--verify-only"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe writable directory", result.stderr)
        with tempfile.TemporaryDirectory(prefix=".server-connect-qa-", dir="/root") as good:
            staged = Path(good) / "bundle"
            staged.mkdir(mode=0o700)
            installer = staged / "install.sh"
            shutil.copyfile(INSTALLER, installer)
            installer.chmod(0o700)
            alias = Path(good) / "alias"
            alias.symlink_to(staged, target_is_directory=True)
            result = subprocess.run(
                ["/bin/sh", str(alias / "install.sh"), "--verify-only"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe or missing directory", result.stderr)
            result = subprocess.run(
                ["/bin/sh", str(installer), "--verify-only"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotIn("unsafe or missing directory", result.stderr)
            self.assertNotIn("untrusted installer source path", result.stderr)
            # A non-root process cannot rename a component under /root.
            probe = subprocess.run(
                ["/usr/bin/python3", "-c",
                 "import os,sys; os.rename(sys.argv[1], sys.argv[2])",
                 str(staged), str(Path(good) / "renamed")],
                preexec_fn=lambda: os.setuid(65534),
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(probe.returncode, 0)
            self.assertTrue(staged.is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
