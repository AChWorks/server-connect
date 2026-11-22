#!/usr/bin/env python3
"""Disposable, loopback-only security regressions for the development bootstrap.

No real installer is allowed to run in these fixtures; synthetic release
binaries are inert and every HTTP invocation passes --verify-only.
"""
from __future__ import annotations

import base64
import errno
import signal
import contextlib
import gzip
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "bootstrap-online.sh"
INSTALLER = ROOT / "bundle" / "install.sh"
FILE_NAMES = [
    "server-connect/install.sh",
    "server-connect/release-auth.py",
    "server-connect/LICENSE",
    "server-connect/server-connect.service",
    "server-connect/server-connect-activation-recover.service",
    "server-connect/server-connect-activation-recover.timer",
    "server-connect/server-connect-native-tun.service",
    "server-connect/server-connect-smart-health.service",
    "server-connect/server-connect-smart-health.timer",
    "server-connect/manifest.json",
    "server-connect/checksums.sha256",
    "server-connect/bin/server-connect",
    "server-connect/bin/sing-box",
    "server-connect/bin/libcronet.so",
    "server-connect/THIRD-PARTY-LICENSES/sing-box-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/publicsuffix-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/publicsuffix-list.dat",
    "server-connect/THIRD-PARTY-LICENSES/chocolate4u-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json",
    "server-connect/THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt",
    "server-connect/THIRD-PARTY-LICENSES/dbip-iran-prefixes.json",
]


class ZeroSource:
    """Stream compressible bytes without allocating a large buffer."""
    def __init__(self, total: int):
        self.remaining = total

    def read(self, n=-1) -> bytes:
        count = min(self.remaining, 65536 if n < 0 else n)
        self.remaining -= count
        return b"\x00" * count


def archive(path: Path, *, abnormal: str | None = None,
            contents: dict[str, bytes] | None = None,
            executable_members: tuple[str, ...] = ()) -> str:
    if abnormal == "compressed_oversized":
        # Actual ~192 MiB expansion, tiny gzip. Budget gate must reject the
        # member before creating any extracted data on the host filesystem.
        with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as output:
            member = tarfile.TarInfo("server-connect/bin/sing-box")
            member.size = 201326593
            output.addfile(member, ZeroSource(member.size))
        return hashlib.sha256(path.read_bytes()).hexdigest()
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
            missing_unit = {
                "missing_project_license": "LICENSE",
                "missing_recovery_timer": "server-connect-activation-recover.timer",
                "missing_native_unit": "server-connect-native-tun.service",
                "missing_health_service": "server-connect-smart-health.service",
                "missing_health_timer": "server-connect-smart-health.timer",
                "missing_psl_license": "publicsuffix-LICENSE",
                "missing_psl_source": "publicsuffix-list.dat",
                "missing_chocolate_license": "chocolate4u-LICENSE",
                "missing_chocolate_source": "chocolate4u-geoip-ir.json",
                "missing_dbip_attribution": "dbip-ATTRIBUTION.txt",
                "missing_dbip_source": "dbip-iran-prefixes.json",
            }.get(abnormal)
            if missing_unit and name.endswith("/" + missing_unit):
                continue
            body = b"INERT QA ONLY\n"
            if name == "server-connect/install.sh":
                body = b"#!/bin/sh\nexit 93\n"  # Never executed by --verify-only.
            if contents is not None:
                body = contents.get(name, body)
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name.endswith("/install.sh") or name in executable_members else 0o644
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
        if self.path in ("/redirect-external-http", "/redirect-external-https", "/redirect-loopback"):
            self.send_response(302)
            target = {
                "/redirect-external-http": "http://outside.invalid/should-not-fetch?token=PRIVATE_QA",
                "/redirect-external-https": "https://outside.invalid/should-not-fetch?token=PRIVATE_QA",
                "/redirect-loopback": f"http://127.0.0.1:{self.server.server_port}/redirect-sentinel",
            }[self.path]
            self.send_header("Location", target)
            self.end_headers()
            return
        if self.path == "/redirect-sentinel":
            self.server.redirect_followed = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"invalid")
            return
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



class BootstrapBeforeAPTTests(unittest.TestCase):
    """The actual no-Python POSIX acquisition preflight gates any APT call."""

    @classmethod
    def setUpClass(cls):
        source = BOOTSTRAP.read_text()
        a = source.index("bootstrap_preflight_source_url() {\n")
        b = source.index("\n}\n", a) + len("\n}\n")
        cls.preflight = source[a:b]
        a = source.index("bootstrap_parse_acquisition_mode() {\n")
        b = source.index("\n}\n", a) + len("\n}\n")
        cls.preflight += "\n" + source[a:b]
        a = source.index("# Admission BEFORE any package transaction.")
        b = source.index("\nset --\n", a)
        cls.admission = source[a:b].replace(
            '$(/usr/bin/uname -m)', '"$SC_QA_ARCH"'
        )

    def attempt(self, source_url, *, arch="x86_64", os_version="13",
                local_qa="no", source_kind="", target="", python_absent=False):
        with tempfile.TemporaryDirectory(prefix="sc-early-apt-") as tmp:
            marker = Path(tmp) / "APT_WOULD_HAVE_RUN"
            # The native tools were verified immediately before this block.
            # Mock only CPU and OS identity to exercise unsupported-host paths
            # on the same runner as positive Debian12/13 tests.
            program = (
                "set -eu\n"
                f"SC_QA_ARCH={shlex.quote(arch)}\n"
                f"SC_QA_OS={shlex.quote(os_version)}\n"
                f"url={shlex.quote(source_url)}\n"
                f'local_qa={shlex.quote(local_qa)}\n'
                f'source_kind={shlex.quote(source_kind)}\n'
                f'target={shlex.quote(target)}\n'
                + ('command() { if [ "$1" = -v ] && [ "$2" = python3 ]; then return 1; fi; type "$2" >/dev/null 2>&1; }\n'
                   if python_absent else '')
                + 'bootstrap_read_os_version() { case "$SC_QA_OS" in 12|13) echo "$SC_QA_OS" ;; *) return 1 ;; esac; }\n'
                + self.preflight + "\n"
                + self.admission + "\n"
                + f'printf APT_WOULD_RUN > {shlex.quote(str(marker))}\n'
            )
            completed = subprocess.run(
                ["/bin/sh", "-c", program],
                capture_output=True, text=True, timeout=6,
            )
            return completed, marker.exists()

    def test_unsupported_os_arch_and_url_reject_before_apt(self):
        scenarios = [
            ("https://mirror.example/server-connect/release-index.json", "aarch64", "13", "no", ""),
            ("https://mirror.example/server-connect/release-index.json", "x86_64", "11", "no", ""),
            ("https://mirror.example@foreign.example/index", "x86_64", "13", "no", ""),
            ("https://mirror.example:bad/index", "x86_64", "13", "no", ""),
            ("https://mirror.example:0/index", "x86_64", "13", "no", ""),
            ("https://mirror.example/#fragment", "x86_64", "13", "no", ""),
            ("http://outside.invalid/index", "x86_64", "13", "yes", ""),
            ("https://[bad-addr]/index", "x86_64", "13", "no", ""),
            ("https://[0:0:0:0:0:0:0]/index", "x86_64", "13", "no", ""),
        ]
        for url, arch, os_version, local, kind in scenarios:
            with self.subTest(url=url, arch=arch, os_version=os_version):
                result, apt = self.attempt(url, arch=arch, os_version=os_version,
                                           local_qa=local, source_kind=kind)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(apt, "invalid host/source crossed APT boundary")

    def test_supported_debian12_debian13_and_qa_loopback_admit(self):
        for version in ("12", "13"):
            for url, local, kind in [
                ("https://mirror.example/server-connect/release-index.json", "no", "mirror"),
                ("http://127.0.0.1:19179/bundle.tar.gz", "yes", ""),
            ]:
                with self.subTest(version=version, url=url):
                    result, apt = self.attempt(url, os_version=version, local_qa=local,
                                               source_kind=kind)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(apt, "valid supported host blocked before optional APT")

    def test_python_absent_oversize_urls_rejected_before_any_apt(self):
        # Distinguish URL and hostname limits from downstream DNS/curl errors:
        # the same valid short authority must still be admitted for both OSes.
        for version in ("12", "13"):
            valid = "https://mirror.example/server-connect/release-index.json"
            allowed, apt = self.attempt(valid, os_version=version, source_kind="mirror", python_absent=True)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            self.assertTrue(apt)
            for invalid in (
                "https://mirror.example/" + "a" * 4075,
                "https://" + "a" * 254 + ".example/bundle",
                "https://mirror.example/" + "a" * 4096 + "#ignored",
            ):
                with self.subTest(version=version, size=len(invalid)):
                    result, apt = self.attempt(invalid, os_version=version,
                                               source_kind="mirror", python_absent=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(apt, "rejected URL reached APT without Python")
        # UTF-8 in the pathname also violates the Python parser's ASCII-only
        # contract and must be refused before installing missing prerequisites.
        result, apt = self.attempt("https://mirror.example/" + chr(233),
                                   source_kind="mirror", python_absent=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(apt)

    def test_target_selection_must_match_host_before_apt(self):
        result, apt = self.attempt(
            "https://mirror.example/release-index.json",
            os_version="13", source_kind="mirror", target="debian-12-amd64",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(apt)



class BootstrapIdentityParserTest(unittest.TestCase):
    """Execute only the actual pure parser; never read or replace host identity."""

    @classmethod
    def setUpClass(cls):
        body = BOOTSTRAP.read_text()
        start = body.index("bootstrap_parse_os_identity() (\n")
        end = body.index("\n)\n", start) + len("\n)\n")
        cls.parser = "set -eu\n" + body[start:end] + "\nbootstrap_parse_os_identity\n"

    def parse(self, identity):
        raw = identity.encode() if isinstance(identity, str) else identity
        return subprocess.run(
            ["/bin/sh", "-c", self.parser], input=raw,
            capture_output=True, timeout=5,
        )

    def test_canonical_supported_identity_is_literal(self):
        for version in ("12", "13"):
            for quote in ("", "'", '"'):
                with self.subTest(version=version, quote=quote):
                    raw = (
                        "# canonical native identity\n"
                        "PRETTY_NAME=\"Debian GNU/Linux\"\n"
                        f"ID={quote}debian{quote}\n"
                        f"VERSION_ID={quote}{version}{quote}\n"
                    )
                    result = self.parse(raw)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, (version + "\n").encode())
        result = self.parse(" \t# comment\n\tVERSION_ID='12' \t\n  ID=debian\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"12\n")

    def test_missing_unsupported_and_ambiguous_identity_is_rejected(self):
        cases = (
            "", "ID=debian\n", "VERSION_ID=12\n",
            "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=12\n",
            "ID=debian\nVERSION_ID=11\n", "ID=debian\nVERSION_ID=14\n",
            "ID=debian\nVERSION_ID=12.0\n",
            "ID=debian\nID=debian\nVERSION_ID=12\n",
            "ID=debian\nVERSION_ID=12\nVERSION_ID=13\n",
            "ID=debian\nid=debian\nVERSION_ID=12\n",
            "Id=debian\nVERSION_ID=12\n", "ID=debian\nversion_id=12\n",
            "ID=debian\nVersion_ID=12\n",
            "ID =debian\nVERSION_ID=12\n", "export ID=debian\nVERSION_ID=12\n",
            "ID=debian\nVERSION_ID= 12\n", "ID=\"debian\nVERSION_ID=12\n",
            "ID=de\\bian\nVERSION_ID=12\n", "ID='de'bian\nVERSION_ID=12\n",
            "ID=debian;true\nVERSION_ID=12\n", "ID=debian\nVERSION_ID=12 # comment\n",
            "ID=debian\nVERSION_ID=12\nnot-an-assignment\n",
            "ID=debian\nVERSION_ID=12\n1INVALID=value\n",
            b"ID=de\x00bian\nVERSION_ID=12\n",
            b"ID=debian\nVERSION_ID=12\n\x01", b"ID=debian\nVERSION_ID=12\n\xff",
        )
        for raw in cases:
            with self.subTest(identity=raw):
                result = self.parse(raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_byte_limit_includes_trailing_newlines(self):
        prefix = b"ID=debian\nVERSION_ID=12\n#"
        boundary = prefix + b"x" * (16384 - len(prefix))
        result = self.parse(boundary)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"12\n")
        for raw in (boundary + b"x", prefix + b"\n" * (16385 - len(prefix))):
            result = self.parse(raw)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_shell_like_identity_and_description_never_execute(self):
        with tempfile.TemporaryDirectory(prefix="sc-os-identity-witness-") as scratch:
            marker = Path(scratch) / "metadata-was-executed"
            quoted = shlex.quote(str(marker))
            cases = (
                (f"ID=$(: > {quoted}; printf debian)\nVERSION_ID=12\n", False),
                (f"ID=debian\nVERSION_ID=`: > {quoted}; printf 12`\n", False),
                (f"ID=debian\nVERSION_ID=12; : > {quoted}\n", False),
                (f"ID=debian\nVERSION_ID=13\nPRETTY_NAME=\"$(: > {quoted})\"\n", True),
                (f"ID=debian\nVERSION_ID=13\nUNKNOWN=`: > {quoted}`\n", True),
            )
            for raw, allowed in cases:
                with self.subTest(identity=raw, allowed=allowed):
                    self.assertFalse(marker.exists())
                    result = self.parse(raw)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)
                    self.assertEqual(result.stdout, b"13\n" if allowed else b"")
                    self.assertFalse(marker.exists(), "OS metadata executed as shell code")


class BootstrapSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="sc-bootstrap-qa-")
        cls.directory = Path(cls.temporary.name)
        cls.digests = {}
        for name, abnormal in [
            ("valid.tar.gz", None),
            ("missing_project_license.tar.gz", "missing_project_license"),
            ("missing_recovery_timer.tar.gz", "missing_recovery_timer"),
            ("missing_native_unit.tar.gz", "missing_native_unit"),
            ("missing_health_service.tar.gz", "missing_health_service"),
            ("missing_health_timer.tar.gz", "missing_health_timer"),
            ("missing_chocolate_license.tar.gz", "missing_chocolate_license"),
            ("missing_chocolate_source.tar.gz", "missing_chocolate_source"),
            ("missing_dbip_attribution.tar.gz", "missing_dbip_attribution"),
            ("missing_dbip_source.tar.gz", "missing_dbip_source"),
            ("duplicate.tar.gz", "duplicate"),
            ("traversal.tar.gz", "traversal"),
            ("symlink.tar.gz", "symlink"),
            ("hardlink.tar.gz", "hardlink"),
            ("expanded.tar.gz", "expanded"),
            ("members.tar.gz", "members"),
            ("pax_metadata.tar.gz", "pax_metadata"),
            ("compressed_oversized.tar.gz", "compressed_oversized"),
        ]:
            cls.digests[name] = archive(cls.directory / name, abnormal=abnormal)
        handler = partial(LocalHTTPHandler, directory=str(cls.directory))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.server.redirect_followed = False
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def bootstrap(self, filename="valid.tar.gz", *, changes=None, digest=None, extra=(), interpreter="/bin/sh", clean_entry=False, url=None):
        environment = os.environ.copy()
        if changes:
            environment.update(changes)
        argv = [
            interpreter, str(BOOTSTRAP), "--local-qa", "--archive-url",
            url or f"http://127.0.0.1:{self.server.server_port}/{filename}",
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

    def test_verify_only_does_not_admit_targets_or_execute_payloads(self):
        # Target admission belongs to the shared installer. These archives
        # prove only acquisition/layout verification, including when their
        # target metadata is unsupported; no fixture payload may execute.
        executable_names = (
            "server-connect/install.sh",
            "server-connect/bin/server-connect",
            "server-connect/bin/sing-box",
        )
        for target in ("debian-12-amd64", "debian-13-amd64", "unsupported-qa-target"):
            with self.subTest(target=target):
                contents = {
                    "server-connect/manifest.json": json.dumps(
                        {"schema": 1, "target": target},
                    ).encode(),
                }
                markers = []
                for name in executable_names:
                    marker = self.directory / f"verify-{target}-{Path(name).name}.executed"
                    self.assertFalse(marker.exists())
                    markers.append(marker)
                    contents[name] = (
                        "#!/bin/sh\n"
                        f": > {shlex.quote(str(marker))}\n"
                        "exit 93\n"
                    ).encode()
                filename = f"verify-{target}.tar.gz"
                digest = archive(
                    self.directory / filename, contents=contents,
                    executable_members=executable_names,
                )
                result = self.bootstrap(filename, digest=digest)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Installation was not attempted.", result.stdout)
                for marker in markers:
                    self.assertFalse(marker.exists(), "verify-only executed a release payload")

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
            "--local-qa", "--archive-url", f"http://127.0.0.1:{self.server.server_port}/valid.tar.gz",
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
            "missing_project_license.tar.gz", "missing_recovery_timer.tar.gz", "missing_native_unit.tar.gz",
            "missing_health_service.tar.gz",
            "missing_health_timer.tar.gz", "missing_chocolate_license.tar.gz",
            "missing_chocolate_source.tar.gz", "missing_dbip_attribution.tar.gz",
            "missing_dbip_source.tar.gz", "duplicate.tar.gz", "traversal.tar.gz", "symlink.tar.gz",
            "hardlink.tar.gz", "expanded.tar.gz", "members.tar.gz",
            "pax_metadata.tar.gz", "compressed_oversized.tar.gz",
        ):
            with self.subTest(filename=filename):
                result = self.bootstrap(filename)
                self.assertNotEqual(result.returncode, 0, "Unsafe archive was accepted")

    def test_real_compressed_bomb_rejected_without_extracting(self):
        sample = self.directory / "compressed_oversized.tar.gz"
        self.assertLess(sample.stat().st_size, 1_500_000)
        result = self.bootstrap("compressed_oversized.tar.gz")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Online archive rejected", result.stderr)

    def test_url_authority_parser_has_strict_https_and_loopback_modes(self):
        # Execute the exact embedded URL validator without network requests.
        body = BOOTSTRAP.read_text()
        code = body.split("<<'PYURL'\n", 1)[1].split("\nPYURL", 1)[0]
        cases = (
            ("https://trusted.example/release?token=QA_PRIVATE", True, "https"),
            ("https://trusted.example:443/release", True, "https"),
            ("http://127.0.0.1:8080/a", True, "http_loopback"),
            ("http://localhost:8080/a", True, "http_localhost:8080"),
            ("http://localhost:8080@external.invalid/a", False, ""),
            ("http://127.0.0.1:8080@external.invalid/a", False, ""),
            ("http://localhost:99999/a", False, ""),
            ("http://localhost:bad/a", False, ""),
            ("http://127.0.0.2:8080/a", False, ""),
            ("http://127.1:8080/a", False, ""),
            ("http://external.invalid:8080/a", False, ""),
            ("http://localhost:8080@localhost:8181/a", False, ""),
            ("http://localhost:8080/a#fragment", False, ""),
            ("https://user:secret@trusted.example/a", False, ""),
            ("https://trusted.example/a#fragment", False, ""),
            ("https://trusted.example/unsafe\r\nHost: outside.invalid", False, ""),
            ("https://trusted.example\\@outside.invalid/a", False, ""),
            ("ftp://trusted.example/release", False, ""),
        )
        for address, allowed, mode in cases:
            with self.subTest(url=address.split("?")[0]):
                result = subprocess.run(
                    ["/usr/bin/python3", "-I", "-S", "-", address],
                    input=code, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                if allowed:
                    self.assertEqual(result.stdout.strip(), mode)
                else:
                    self.assertEqual(result.stdout, "")
                self.assertNotIn("QA_PRIVATE", result.stdout + result.stderr)

    def test_http_loopback_redirects_do_not_escape(self):
        self.server.redirect_followed = False
        for endpoint in ("redirect-external-http", "redirect-external-https", "redirect-loopback"):
            with self.subTest(redirect=endpoint):
                result = self.bootstrap(endpoint)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Online acquisition failed", result.stderr)
                self.assertNotIn("PRIVATE_QA", result.stderr)
                self.assertFalse(self.server.redirect_followed, "redirect was followed")
        result = self.bootstrap(url=f"http://localhost:{self.server.server_port}/valid.tar.gz")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.server.redirect_followed)

    def test_http_loopback_userinfo_does_not_trigger_request(self):
        for authority in (
            f"localhost:{self.server.server_port}@external.invalid",
            f"127.0.0.1:{self.server.server_port}@external.invalid",
        ):
            result = self.bootstrap(url=f"http://{authority}/archive?token=PRIVATE_QA")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unsupported URL", result.stderr)
            self.assertNotIn("PRIVATE_QA", result.stdout + result.stderr)

    def test_capacity_limited_private_tmpfs_fails_before_download(self):
        # A dedicated tiny tmpfs has genuine kernel-enforced FS capacity;
        # no mock statvfs or large disk write is involved.
        scratch = Path("/dev/shm")
        if not scratch.is_dir() or not os.access(scratch, os.W_OK):
            self.skipTest("no writable tmpfs available")
        stat = os.statvfs(scratch)
        if stat.f_blocks * stat.f_frsize > 268435456:
            self.skipTest("available tmpfs is not capacity limited")
        with tempfile.TemporaryDirectory(prefix="sc-capacity-qa-", dir=scratch) as directory:
            Path(directory).chmod(0o777 if os.geteuid() == 0 else 0o700)
            environment = os.environ.copy()
            environment["TMPDIR"] = directory
            argv = [
                "/bin/sh", str(BOOTSTRAP), "--local-qa", "--archive-url",
                f"http://127.0.0.1:{self.server.server_port}/valid.tar.gz",
                "--sha256", self.digests["valid.tar.gz"], "--verify-only",
            ]

            def demote():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)

            result = subprocess.run(
                argv, env=environment,
                preexec_fn=demote if os.geteuid() == 0 else None,
                capture_output=True, text=True, timeout=20,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Insufficient reserved staging capacity", result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [], "staging was not cleaned")

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
        for size in ("0", "100663297", "1073741825", "-1", "not-a-number", "9999999999999999999999"):
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
            ["/bin/sh", str(INSTALLER), "--verify-only", "--local-qa"],
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
                ["/bin/sh", str(installer), "--verify-only", "--local-qa"],
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
                ["/bin/sh", str(alias / "install.sh"), "--verify-only", "--local-qa"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe or missing directory", result.stderr)
            result = subprocess.run(
                ["/bin/sh", str(installer), "--verify-only", "--local-qa"],
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


class SignedReleaseTest(unittest.TestCase):
    """Real ephemeral signatures; inert archives; no installed product mutation."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix=".sc-signed-qa-", dir="/root" if os.geteuid() == 0 else None,
        )
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        trusted_tools = cls.directory / "trusted-tools"
        trusted_tools.mkdir(mode=0o700)
        cls.bootstrap = trusted_tools / "bootstrap-online.sh"
        cls.auth = trusted_tools / "release-auth.py"
        shutil.copyfile(BOOTSTRAP, cls.bootstrap)
        shutil.copyfile(ROOT / "scripts" / "release-auth.py", cls.auth)
        cls.private = cls.directory / "qa-private.pem"
        cls.public = cls.directory / "qa-public.pem"
        cls.wrong_private = cls.directory / "wrong-private.pem"
        cls.wrong_public = cls.directory / "wrong-public.pem"
        for private, public in ((cls.private, cls.public), (cls.wrong_private, cls.wrong_public)):
            subprocess.run(
                ["/usr/bin/openssl", "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(private)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
            )
            private.chmod(0o600)
            subprocess.run(
                ["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
            )
        handler = partial(LocalHTTPHandler, directory=str(cls.directory))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # TLS trust and publisher-signature trust are independent ephemeral QA
        # identities; neither is installed in the host's trust store.
        cls.ca = cls.directory / "tls-ca.pem"
        tls_key, tls_cert = cls.directory / "tls-key.pem", cls.directory / "tls-cert.pem"
        csr, extensions = cls.directory / "tls.csr", cls.directory / "tls.ext"
        extensions.write_text(
            "subjectAltName=DNS:localhost\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        for command in (
            ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Server Connect ephemeral QA CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(cls.directory / "tls-ca-key.pem"), "-out", str(cls.ca)],
            ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", str(tls_key), "-out", str(csr)],
            ["x509", "-req", "-in", str(csr), "-CA", str(cls.ca),
             "-CAkey", str(cls.directory / "tls-ca-key.pem"), "-set_serial", "1",
             "-days", "1", "-extfile", str(extensions), "-out", str(tls_cert)],
        ):
            subprocess.run(["/usr/bin/openssl", *command], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)

        class HTTPSHandler(LocalHTTPHandler):
            def handle(self):
                self.http_started = False
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError):
                    # Certificate refusal can close TLS before any HTTP request.
                    if self.http_started:
                        raise

            def do_GET(self):
                self.http_started = True
                self.server.requests.append((self.path, self.connection.version()))
                if self.path.endswith("/bootstrap-online.sh"):
                    response = getattr(self.server, "bootstrap_response", "")
                    if response == "redirect":
                        self.send_response(302)
                        self.send_header("Location", "https://outside.invalid/foreign-bootstrap")
                        self.end_headers()
                        return
                    if response.startswith("redirect-complete-"):
                        status = int(response.rsplit("-", 1)[-1])
                        body = self.server.bootstrap_response_body
                        self.send_response(status)
                        self.send_header("Location", "https://outside.invalid/foreign-bootstrap")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    if response == "truncated":
                        self.send_response(200)
                        self.send_header("Content-Length", "1000000")
                        self.end_headers()
                        self.wfile.write(b"#!/bin/sh\necho partial\n")
                        self.wfile.flush()
                        self.close_connection = True
                        return
                if self.path == "/https-downgrade":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{cls.server.server_port}/redirect-sentinel")
                    self.end_headers()
                    return
                super().do_GET()

        cls.https_servers = []
        for _ in range(2):  # Official-origin and operator-mirror transport fixtures.
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(HTTPSHandler, directory=str(cls.directory)))
            server.requests = []
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.https_servers.append((server, thread))

    @classmethod
    def tearDownClass(cls):
        for server, thread in cls.https_servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.directory))
        self.marker = self.case / "PAYLOAD_EXECUTED"
        self.payload = {
            name: b"INERT QA ONLY\n" for name in FILE_NAMES
        }
        for name in ("install.sh", "bin/server-connect", "bin/sing-box"):
            self.payload["server-connect/" + name] = (
                "#!/bin/sh\n: > " + shlex.quote(str(self.marker)) + "\nexit 93\n"
            ).encode()
        self.payload["server-connect/release-auth.py"] = self.auth.read_bytes()
        self.manifest = {
            "schema": 1, "manager": "0.1.0-dev", "core": "sing-box 1.14.3",
            "core_archive_sha256": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
            "source_revision": "4865cd123fbfafeb5acb9bc70105cbf1ae8d7279",
            "source_state": "clean", "target": "debian-13-amd64",
            "redistribution": "not authorized; local QA only",
        }
        self.fixture()

    def tearDown(self):
        self.assertFalse(self.marker.exists(), "acquisition executed an archive payload")
        shutil.rmtree(self.case)

    def sign_raw(self):
        subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(self.private),
             "-out", str(self.signature), str(self.metadata)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )

    def fixture(self, abnormal=None, manifest_override=None):
        # Follow the installer's canonical payload order, independently of
        # archive member order, and bind every actual fixture byte.
        ordered = (
            "bin/server-connect", "bin/sing-box", "bin/libcronet.so",
            "server-connect.service", "server-connect-activation-recover.service",
            "server-connect-activation-recover.timer",
            "server-connect-native-tun.service",
            "server-connect-smart-health.service", "server-connect-smart-health.timer",
            "install.sh", "release-auth.py", "LICENSE", "THIRD-PARTY-LICENSES/sing-box-LICENSE",
            "THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE",
            "THIRD-PARTY-LICENSES/publicsuffix-LICENSE",
            "THIRD-PARTY-LICENSES/publicsuffix-list.dat",
            "THIRD-PARTY-LICENSES/chocolate4u-LICENSE",
            "THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json",
            "THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt",
            "THIRD-PARTY-LICENSES/dbip-iran-prefixes.json", "manifest.json",
        )
        self.payload["server-connect/manifest.json"] = json.dumps(
            manifest_override or self.manifest, separators=(",", ":"),
        ).encode() + b"\n"
        self.payload["server-connect/checksums.sha256"] = "".join(
            hashlib.sha256(self.payload["server-connect/" + name]).hexdigest()
            + "  " + name + "\n" for name in ordered
        ).encode()
        self.bundle = self.case / "bundle.tar.gz"
        digest = archive(self.bundle, abnormal=abnormal, contents=self.payload)
        self.identity = {
            "schema": 1, "purpose": "server-connect-release",
            "version": "0.1.0-dev", "target": "debian-13-amd64",
            "archive_sha256": digest,
            "checksums_sha256": hashlib.sha256(self.payload["server-connect/checksums.sha256"]).hexdigest(),
            "manifest_sha256": hashlib.sha256(self.payload["server-connect/manifest.json"]).hexdigest(),
            "source_revision": self.manifest["source_revision"], "source_state": "clean",
            "core": self.manifest["core"], "core_archive_sha256": self.manifest["core_archive_sha256"],
        }
        self.metadata = Path(str(self.bundle) + ".release.json")
        self.signature = Path(str(self.bundle) + ".sig")
        self.metadata.write_text(json.dumps(self.identity, separators=(",", ":")) + "\n")
        self.sign_raw()

    def arguments(self, online=False, public=None, version="0.1.0-dev", target="debian-13-amd64"):
        source = (
            ["--local-qa", "--archive-url",
             f"http://127.0.0.1:{self.server.server_port}/{self.case.name}/bundle.tar.gz"]
            if online else ["--archive-file", str(self.bundle)]
        )
        return [
            "/bin/sh", str(self.bootstrap), *source, "--publisher-key", str(public or self.public),
            "--version", version, "--target", target, "--verify-only",
        ]

    def run_bootstrap(self, **kwargs):
        return subprocess.run(self.arguments(**kwargs), capture_output=True, text=True, timeout=30)

    def test_authenticated_online_and_offline_use_identical_bytes(self):
        for online in (False, True):
            result = self.run_bootstrap(online=online)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Publisher signature and pinned release identity verified", result.stdout)
            self.assertIn("LOCAL QA ONLY", result.stdout)
            self.assertIn("Installation was not attempted.", result.stdout)

    def run_https(self, origin=0, host="localhost", trusted=True, path=None, **kwargs):
        server = self.https_servers[origin][0]
        url = f"https://{host}:{server.server_port}" + (path or f"/{self.case.name}/bundle.tar.gz")
        argv = self.arguments(**kwargs)
        argv[2:4] = ["--archive-url", url]
        argv.insert(1, "-x")  # Observe the real extraction command without a production hook.
        self.assertNotIn("--local-qa", argv)
        env = os.environ.copy()
        for name in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            env.pop(name, None)
        if trusted:
            env["CURL_CA_BUNDLE"] = str(self.ca)
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)

    def assert_https_refused_before_extraction(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("timeout -s TERM -k 3s 150s python3 -I -S -", result.stderr)
        self.assertNotIn("Publisher signature and pinned release identity verified", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_signed_https_origins_and_offline_bind_identical_immutable_bytes(self):
        expected = self.identity["archive_sha256"]
        offline = self.run_bootstrap()
        self.assertEqual(offline.returncode, 0, offline.stderr)
        for origin, (server, _) in enumerate(self.https_servers):
            with self.subTest(origin=origin):
                server.requests.clear()
                result = self.run_https(origin=origin)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Publisher signature and pinned release identity verified", result.stdout)
                self.assertIn("Installation was not attempted.", result.stdout)
                self.assertIn("timeout -s TERM -k 3s 150s python3 -I -S -", result.stderr)
                expected_paths = [f"/{self.case.name}/bundle.tar.gz" + suffix
                                  for suffix in ("", ".release.json", ".sig")]
                self.assertEqual([path for path, _ in server.requests], expected_paths)
                self.assertTrue(all(version in ("TLSv1.2", "TLSv1.3") for _, version in server.requests))
                self.assertEqual(hashlib.sha256(self.bundle.read_bytes()).hexdigest(), expected)

    def test_signed_https_rejects_untrusted_ca_hostname_and_http_downgrade(self):
        server = self.https_servers[0][0]
        for options in ({"trusted": False}, {"host": "127.0.0.1"}):
            with self.subTest(options=options):
                server.requests.clear()
                self.assert_https_refused_before_extraction(
                    self.run_https(**options), "Online acquisition failed")
                self.assertEqual(server.requests, [], "untrusted TLS reached HTTP request handling")
        self.server.redirect_followed = False
        server.requests.clear()
        self.assert_https_refused_before_extraction(
            self.run_https(path="/https-downgrade"), "Online acquisition failed")
        self.assertEqual([path for path, _ in server.requests], ["/https-downgrade"])
        self.assertFalse(self.server.redirect_followed, "HTTPS redirected to plaintext HTTP")

    def test_signed_https_rejects_wrong_publisher_and_tampering_before_extraction(self):
        self.assert_https_refused_before_extraction(
            self.run_https(public=self.wrong_public), "publisher signature or key validation failed")
        self.bundle.write_bytes(self.bundle.read_bytes() + b"tampered")
        self.assert_https_refused_before_extraction(
            self.run_https(origin=1), "signed archive digest mismatch")

    def test_official_default_rejects_digest_only_and_http_without_qa(self):
        for source in (["--archive-file", str(self.bundle)],
                       ["--archive-url", "https://127.0.0.1:19/unreachable"]):
            result = subprocess.run(
                ["/bin/sh", str(self.bootstrap), *source, "--sha256", self.identity["archive_sha256"],
                 "--verify-only"], capture_output=True, text=True, timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Normal installation does not take detached signatures or independent digests", result.stderr)
        argv = self.arguments(online=True)
        argv.remove("--local-qa")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP requires explicit --local-qa", result.stderr)

    def test_wrong_missing_key_target_version_and_mixed_mode_are_refused(self):
        for changes in ({"public": self.wrong_public},
                        {"public": self.case / "missing.pem"},
                        {"version": "0.1.1"}, {"target": "debian-12-amd64"},
                        {"target": "debian-13-arm64"}):
            with self.subTest(changes=changes):
                result = self.run_bootstrap(**changes)
                self.assertNotEqual(result.returncode, 0)
        result = subprocess.run(
            self.arguments() + ["--sha256", self.identity["archive_sha256"]],
            capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_tampered_archive_metadata_and_truncated_signature_are_refused(self):
        originals = {
            self.bundle: self.bundle.read_bytes(), self.metadata: self.metadata.read_bytes(),
            self.signature: self.signature.read_bytes(),
        }
        for path, changed in (
            (self.bundle, originals[self.bundle] + b"tampered"),
            (self.metadata, originals[self.metadata].replace(b'"clean"', b'"dirty"')),
            (self.signature, originals[self.signature][:12]),
        ):
            with self.subTest(input=path.name):
                path.write_bytes(changed)
                result = self.run_bootstrap()
                self.assertNotEqual(result.returncode, 0)
                path.write_bytes(originals[path])

    def test_even_valid_signatures_do_not_admit_ambiguous_or_wrong_identity(self):
        original = self.metadata.read_bytes()
        variants = [
            original.replace(b'"schema":1', b'"schema":1,"schema":1'),
            original.replace(b'"purpose":"server-connect-release"', b'"purpose":"other-product"'),
            original.replace(b'"source_state":"clean"', b'"source_state":"dirty"'),
            original.replace(b'"source_revision":"4865cd123fbfafeb5acb9bc70105cbf1ae8d7279"', b'"source_revision":"HEAD"'),
            original[:-2] + b',"extra":1}\n',
            original.replace(b'"schema":1', b'"schema":true'),
            original + b"\x00", b" " * 16385,
        ]
        for raw in variants:
            with self.subTest(metadata=raw[:70]):
                self.metadata.write_bytes(raw)
                self.sign_raw()
                self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.metadata.write_bytes(original)
        self.sign_raw()

    def test_signed_manifest_cannot_disagree_with_version_target_source_or_core(self):
        for field, value in (("manager", "9.9.9"), ("target", "debian-12-amd64"),
                             ("source_revision", "0" * 40), ("core", "sing-box 0.0.0")):
            with self.subTest(field=field):
                self.fixture(manifest_override=dict(self.manifest, **{field: value}))
                self.assertNotEqual(self.run_bootstrap().returncode, 0)

    def test_signed_archive_missing_first_party_license_is_refused(self):
        self.fixture(abnormal="missing_project_license")
        for online in (False, True):
            result = self.run_bootstrap(online=online)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Archive preflight failed", result.stderr)
            self.assertFalse(self.marker.exists())

    def test_signed_archive_missing_attributed_country_source_or_license_is_refused(self):
        for missing in ("missing_chocolate_license", "missing_chocolate_source"):
            with self.subTest(missing=missing):
                self.fixture(abnormal=missing)
                for online in (False, True):
                    result = self.run_bootstrap(online=online)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Archive preflight failed", result.stderr)
                    self.assertFalse(self.marker.exists())

    def test_signed_archive_missing_dbip_attribution_or_modified_data_is_refused(self):
        for missing in ("missing_dbip_attribution", "missing_dbip_source"):
            with self.subTest(missing=missing):
                self.fixture(abnormal=missing)
                for online in (False, True):
                    result = self.run_bootstrap(online=online)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Archive preflight failed", result.stderr)
                    self.assertFalse(self.marker.exists())

    def test_signed_archive_missing_psl_materials_refused_before_execution(self):
        # An otherwise valid signed archive cannot waive either the MPL-2.0
        # notice or the exact data source before extraction/privileged use.
        for missing in ("missing_psl_license", "missing_psl_source"):
            with self.subTest(missing=missing):
                self.fixture(abnormal=missing)
                for online in (False, True):
                    result = self.run_bootstrap(online=online)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Archive preflight failed", result.stderr)
                    self.assertNotIn("Installation was not attempted.", result.stdout)
                    self.assertFalse(self.marker.exists())

    def test_valid_signature_cannot_authorize_traversal_links_or_gzip_truncation(self):
        for abnormal in ("traversal", "symlink", "hardlink", "duplicate"):
            with self.subTest(archive=abnormal):
                self.fixture(abnormal=abnormal)
                for online in (False, True):
                    result = self.run_bootstrap(online=online)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Archive preflight failed", result.stderr)
        self.fixture()
        self.bundle.write_bytes(self.bundle.read_bytes()[:-8])  # Drop gzip CRC/length.
        self.identity["archive_sha256"] = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.metadata.write_text(json.dumps(self.identity) + "\n")
        self.sign_raw()
        self.assertNotEqual(self.run_bootstrap().returncode, 0)

    def test_shared_installer_authentication_precedes_any_candidate_executable(self):
        # Execute only the actual read-only installer gate, with ownership
        # helpers replaced for this unprivileged fixture. No entrypoint,
        # installed path or systemd lifecycle operation is available.
        bundle = self.case / "extracted"
        for name, data in self.payload.items():
            destination = bundle / name.removeprefix("server-connect/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        for name in ("bin/server-connect", "bin/sing-box"):
            (bundle / name).chmod(0o700)
        body = INSTALLER.read_text()
        functions = []
        for start, end in (("release_payload_files() {\n", "\n}\n"),
                           ("verify_release_payload() (\n", "\n)\n"),
                           ("bundle_release_version() {\n", "\n}\n"),
                           ("verify_payload() {\n", "\n}\n")):
            position = body.index(start)
            finish = body.index(end, position) + len(end)
            functions.append(body[position:finish])
        harness = (
            "set -eu\n"
            "check_root_file() { [ -f \"$1\" ] && [ ! -L \"$1\" ]; }\n"
            "check_root_dir() { [ -d \"$1\" ] && [ ! -L \"$1\" ]; }\n"
            "say() { printf '%s\\n' \"$*\"; }\n"
            "die() { say \"$*\" >&2; exit 1; }\n"
            "need() { command -v \"$1\" >/dev/null; }\n"
            "local_qa=no\nretained_auth=no\n" +
            "\n".join(f"{name}={shlex.quote(str(value))}" for name, value in (
                ("SOURCE_DIR", bundle), ("metadata_file", self.metadata),
                ("signature_file", self.signature), ("publisher_key", self.wrong_public),
                ("pinned_version", "0.1.0-dev"), ("pinned_target", "debian-13-amd64"),
            )) + "\n" + "\n".join(functions) + "\nverify_payload\n"
        )
        result = subprocess.run(
            ["/bin/sh", "-s"], input=harness, text=True,
            capture_output=True, timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publisher authentication failed before candidate execution", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_missing_signed_sidecars_and_symlinked_trust_anchor_are_refused(self):
        alias = self.case / "alias-key.pem"
        alias.symlink_to(self.public)
        self.assertNotEqual(self.run_bootstrap(public=alias).returncode, 0)
        saved = self.signature.read_bytes()
        self.signature.unlink()
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.signature.write_bytes(saved)

    @unittest.skipUnless(os.geteuid() == 0, "real root-owned import ancestry requires CI root")
    def test_signed_guest_imports_preserve_bytes_and_protect_root_trust(self):
        self.check_signed_guest_import_protection(foreign_owner=False)

    @unittest.skipUnless(os.geteuid() == 0, "foreign-owner imports require real CI root")
    def test_signed_guest_imports_reject_foreign_owner_with_protected_modes(self):
        self.check_signed_guest_import_protection(foreign_owner=True)

    def check_signed_guest_import_protection(self, *, foreign_owner):
        trust = self.case / "qa-release-trust"
        trust.mkdir(mode=0o700)
        originals = {"bootstrap-online.sh": self.bootstrap.read_bytes(),
                     "release-auth.py": self.auth.read_bytes(),
                     "release.json": self.metadata.read_bytes(),
                     "archive.tar.gz": self.bundle.read_bytes()}
        # Hosted Docker imports were UID/GID 1001 even when modes were safe.
        # Keep ownership and writable-mode failures as independent cases.
        imported_modes = {"bootstrap-online.sh": 0o755, "release-auth.py": 0o644,
                          "release.json": 0o600, "archive.tar.gz": 0o600}
        for name, mode in imported_modes.items():
            path = self.bundle if name == "archive.tar.gz" else trust / name
            if path != self.bundle:
                path.write_bytes(originals[name])
            path.chmod(mode if foreign_owner else 0o666)
            if foreign_owner:
                os.chown(path, 1001, 1001)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid,
                              path.stat().st_mode & 0o777),
                             (1001, 1001, mode) if foreign_owner else (0, 0, 0o666))
        original_archive_stat = self.bundle.stat()
        signature = trust / "fixture.sig"
        argv = [
            "/usr/bin/python3", "-I", "-S", str(self.auth), "sign-local-qa",
            "--metadata", str(trust / "release.json"), "--signature", str(signature),
            "--signing-key", str(self.private), "--version", "0.1.0-dev",
            "--target", "debian-13-amd64", "--archive", str(self.bundle),
        ]
        rejected = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("protected root-owned ancestry", rejected.stderr)
        self.assertFalse(signature.exists())

        fixture = (ROOT / "scripts/qa/test-installed-host.sh").read_text()
        self.assertEqual(fixture.count("<<'QAPROTECT'\n"), 1)
        prepare = fixture.split("<<'QAPROTECT'\n", 1)[1].split("\nQAPROTECT\n", 1)[0]
        prepare = prepare.replace("/root/qa-release-trust", str(trust)).replace(
            "/root/sc-qa-bundle.tar.gz", str(self.bundle))
        staged = subprocess.run(
            ["/bin/sh", "-s"], input=prepare, capture_output=True, text=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, timeout=10,
        )
        self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
        if foreign_owner:
            self.assertEqual(staged.stdout.count("uid=1001 gid=1001"), 4)
        else:
            self.assertEqual(staged.stdout.count("mode=666"), 4)
        self.assertIn("SIGNED_QA_IMPORTED_INPUTS_PROTECTED=PASS", staged.stdout)
        for name, raw in originals.items():
            path = trust / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid,
                              path.stat().st_mode & 0o777, path.stat().st_nlink),
                             (0, 0, 0o600, 1))
        self.assertEqual(self.bundle.read_bytes(), originals["archive.tar.gz"])
        self.assertEqual((self.bundle.stat().st_uid, self.bundle.stat().st_gid,
                          self.bundle.stat().st_mode),
                         (original_archive_stat.st_uid, original_archive_stat.st_gid,
                          original_archive_stat.st_mode),
                         "fixture must not change the original external archive ownership or mode")
        argv[-1] = str(trust / "archive.tar.gz")
        signed = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertIn("LOCAL QA signature created", signed.stdout)
        subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(self.public),
             "-signature", str(signature), str(trust / "release.json")],
            capture_output=True, check=True, timeout=10,
        )

        # Protected leaf copies never authorize an unsafe ancestor.
        original_signature = signature.read_bytes()
        trust.chmod(0o777)
        refused = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("protected root-owned ancestry", refused.stderr)
        self.assertEqual(signature.read_bytes(), original_signature)
        trust.chmod(0o700)

    def test_local_qa_signing_uses_explicit_key_and_never_overwrites_signature(self):
        output = self.case / "new.sig"
        argv = [
            "/usr/bin/python3", "-I", "-S", str(self.auth), "sign-local-qa",
            "--metadata", str(self.metadata), "--signature", str(output),
            "--signing-key", str(self.private), "--version", "0.1.0-dev",
            "--target", "debian-13-amd64", "--archive", str(self.bundle),
        ]
        first = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(first.returncode, 0, first.stderr)
        signed = output.read_bytes()
        second = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(output.read_bytes(), signed)
        self.assertIn("LOCAL QA", first.stdout)

    def receipt_runtime(self):
        if not hasattr(self, "_receipt_runtime"):
            spec = importlib.util.spec_from_file_location("sc_auth_receipt_fixture", self.auth)
            runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runtime)
            # Only the namespace constant changes for this unprivileged
            # fixture. Production has no environment/CLI prefix override.
            runtime.INSTALLED_RELEASES = self.case / "managed" / "releases"
            runtime.INSTALLED_RELEASES.mkdir(parents=True)
            self._receipt_runtime = runtime
        return self._receipt_runtime

    def receipt_action(self, action, bundle, *, public=None):
        runtime = self.receipt_runtime()
        argv = [str(self.auth), action, "--bundle", str(bundle)]
        if action == "install-receipt":
            argv += [
                "--metadata", str(self.metadata), "--signature", str(self.signature),
                "--publisher-key", str(public or self.public),
                "--version", "0.1.0-dev", "--target", "debian-13-amd64",
            ]
        output = io.StringIO()
        previous_mask = os.umask(0o077)
        try:
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                runtime.main()
        finally:
            os.umask(previous_mask)
        return output.getvalue()

    def receipt_stage(self, suffix="abcdefgh"):
        runtime = self.receipt_runtime()
        stage = runtime.INSTALLED_RELEASES / (".stage." + suffix)
        stage.mkdir(mode=0o700)
        for name, data in self.payload.items():
            destination = stage / name.removeprefix("server-connect/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        (stage / ".owner").write_bytes(b"AChWorks/server-connect\n")
        return stage

    def receipt_publish(self, suffix="abcdefgh"):
        stage = self.receipt_stage(suffix)
        self.receipt_action("install-receipt", stage)
        final = stage.parent / ("0.1.0-dev-" + self.identity["checksums_sha256"][:16])
        stage.rename(final)
        self.receipt_action("verify-installed", final)
        return final

    def test_receipt_retains_only_public_trust_material_after_acquisition_cleanup(self):
        key_copy = self.case / "independent-public.pem"
        key_copy.write_bytes(self.public.read_bytes())
        stage = self.receipt_stage()
        self.receipt_action("install-receipt", stage, public=key_copy)
        final = stage.parent / ("0.1.0-dev-" + self.identity["checksums_sha256"][:16])
        stage.rename(final)
        receipt = final / "authentication.json"
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt.stat().st_nlink, 1)
        stored = json.loads(receipt.read_bytes())
        self.assertEqual(stored["release_checksums_sha256"], self.identity["checksums_sha256"])
        self.assertIn(b"BEGIN PUBLIC KEY", base64.b64decode(stored["publisher_key_b64"]))
        self.assertNotIn(b"PRIVATE KEY", receipt.read_bytes())
        self.metadata.unlink()
        self.signature.unlink()
        key_copy.unlink()
        result = self.receipt_action("verify-installed", final)
        self.assertIn("verified offline", result)

    def test_receipt_update_preserves_previous_release_and_refuses_cross_release_copy(self):
        previous = self.receipt_publish()
        retained = (previous / "authentication.json").read_bytes()
        self.manifest["source_revision"] = "b" * 40
        self.fixture()
        current = self.receipt_publish("ijklmnop")
        self.assertNotEqual(current, previous)
        self.receipt_action("verify-installed", previous)
        self.receipt_action("verify-installed", current)
        self.assertEqual((previous / "authentication.json").read_bytes(), retained)
        actual = (current / "authentication.json").read_bytes()
        (current / "authentication.json").write_bytes(retained)
        with self.assertRaises(ValueError):
            self.receipt_action("verify-installed", current)
        (current / "authentication.json").write_bytes(actual)

    def test_receipt_tamper_missing_ambiguous_and_unowned_namespace_fail_closed(self):
        release = self.receipt_publish()
        path = release / "authentication.json"
        original = path.read_bytes()
        values = json.loads(original)
        changes = (
            {"publisher_spki_sha256": "0" * 64},
            {"release_checksums_sha256": "0" * 64},
            {"signature_b64": base64.b64encode(b"wrong-signature").decode()},
            {"metadata_b64": base64.b64encode(b'{"schema":1}').decode()},
            {"publisher_key_b64": base64.b64encode(self.wrong_public.read_bytes()).decode()},
            {"owner": "foreign-project"},
        )
        for change in changes:
            with self.subTest(change=tuple(change)):
                path.write_text(json.dumps(dict(values, **change)))
                with self.assertRaises((ValueError, OSError)):
                    self.receipt_action("verify-installed", release)
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.receipt_action("verify-installed", release)
        path.chmod(0o600)
        alias = self.case / "foreign-hardlink"
        os.link(path, alias)
        with self.assertRaises(ValueError):
            self.receipt_action("verify-installed", release)
        alias.unlink()
        (release / "local-qa.sha256").write_text(self.identity["checksums_sha256"] + "\n")
        with self.assertRaises(ValueError):
            self.receipt_action("verify-installed", release)
        (release / "local-qa.sha256").unlink()
        path.unlink()
        with self.assertRaises(OSError):
            self.receipt_action("verify-installed", release)
        path.write_bytes(original)
        path.chmod(0o600)
        outside = self.case / release.name
        shutil.copytree(release, outside)
        with self.assertRaises(ValueError):
            self.receipt_action("verify-installed", outside)

    def test_receipt_creation_is_idempotent_and_never_overwrites_foreign_or_unsigned_state(self):
        stage = self.receipt_stage()
        self.receipt_action("install-receipt", stage)
        receipt = stage / "authentication.json"
        original = receipt.read_bytes()
        inode = receipt.stat().st_ino
        self.receipt_action("install-receipt", stage)
        self.assertEqual(receipt.stat().st_ino, inode)
        self.assertEqual(receipt.read_bytes(), original)
        receipt.write_bytes(original + b"\n")
        with self.assertRaises(ValueError):
            self.receipt_action("install-receipt", stage)
        self.assertEqual(receipt.read_bytes(), original + b"\n")
        receipt.unlink()
        (stage / "local-qa.sha256").write_text(self.identity["checksums_sha256"] + "\n")
        with self.assertRaises(ValueError):
            self.receipt_action("install-receipt", stage)
        self.assertFalse(receipt.exists())

    def test_receipt_failed_publication_and_fsync_never_become_success_claims(self):
        runtime = self.receipt_runtime()
        stage = self.receipt_stage()
        receipt = stage / "authentication.json"
        with mock.patch.object(runtime, "link_anonymous_receipt", side_effect=OSError("injected publish failure")):
            with self.assertRaises(OSError):
                self.receipt_action("install-receipt", stage)
        self.assertFalse(receipt.exists())
        self.assertEqual(list(stage.glob(".authentication.*")), [])
        original_fsync = os.fsync
        count = 0

        def fail_directory_fsync(fd):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("injected directory fsync failure")
            return original_fsync(fd)

        with mock.patch.object(runtime.os, "fsync", side_effect=fail_directory_fsync):
            with self.assertRaises(OSError):
                self.receipt_action("install-receipt", stage)
        # Complete readable bytes do not establish acknowledged durability.
        # The installer must keep this unpromoted stage until rollback.
        self.assertTrue(receipt.is_file())
        self.assertEqual(list(stage.glob(".authentication.*")), [])
        with mock.patch.object(runtime.os, "fsync", side_effect=OSError("still unavailable")):
            with self.assertRaises(OSError):
                self.receipt_action("install-receipt", stage)
        self.receipt_action("install-receipt", stage)
        self.receipt_action("verify-installed", stage)

    def test_real_sigkill_inside_anonymous_signed_receipt_publication(self):
        # Test the actual Signed receipt helper in a separate OS process;
        # SIGKILL bypasses Python finally and can never be mistaken for a
        # caught exception or a successful write. No signed auth bytes may be
        # published before linkat; after linkat only one inode/name exists.
        script = """
import importlib.util, os, signal, sys
helper, when, bundle, metadata, signature, key = sys.argv[1:]
spec = importlib.util.spec_from_file_location("real_signed_receipt_sigkill", helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.INSTALLED_RELEASES = __import__("pathlib").Path(bundle).parent
original = module.link_anonymous_receipt
def interrupt(fd, directory):
    if when == "before":
        os.kill(os.getpid(), signal.SIGKILL)
    original(fd, directory)
    os.kill(os.getpid(), signal.SIGKILL)
module.link_anonymous_receipt = interrupt
sys.argv = [helper, "install-receipt", "--bundle", bundle, "--metadata", metadata,
            "--signature", signature, "--publisher-key", key,
            "--version", "0.1.0-dev", "--target", "debian-13-amd64"]
module.main()
"""
        for when in ("before", "after"):
            with self.subTest(interruption=when):
                stage = self.receipt_stage("sigbefor" if when=="before" else "sigafter")
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-c", script, str(self.auth),
                     when, str(stage), str(self.metadata),
                     str(self.signature), str(self.public)],
                    capture_output=True, text=True, timeout=25)
                self.assertEqual(child.returncode, -signal.SIGKILL,
                                 child.stdout + child.stderr)
                receipt = stage / "authentication.json"
                self.assertEqual(list(stage.glob(".authentication.*")), [])
                if when == "before":
                    self.assertFalse(receipt.exists(), "anonymous prep became visible")
                    self.receipt_action("install-receipt", stage)
                else:
                    self.assertTrue(receipt.is_file(), "atomic link was not published")
                    self.assertEqual(receipt.stat().st_nlink, 1)
                    self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
                self.receipt_action("verify-installed", stage)
                self.receipt_action("install-receipt", stage)
                self.assertEqual(receipt.stat().st_nlink, 1)
                self.assertEqual(list(stage.glob(".authentication.*")), [])

    def test_anonymous_signed_receipt_rejects_filesystem_without_support(self):
        runtime = self.receipt_runtime()
        stage = self.receipt_stage("notsuprt")
        original_open = runtime.os.open

        def reject_anonymous(path, flags, *args, **kwargs):
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError(errno.EOPNOTSUPP, "anonymous temp unsupported")
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(runtime.os, "open", side_effect=reject_anonymous):
            with self.assertRaisesRegex(ValueError, "anonymous installed authentication staging unavailable"):
                self.receipt_action("install-receipt", stage)
        self.assertFalse((stage / "authentication.json").exists())
        self.assertEqual(list(stage.glob(".authentication.*")), [])

    def signed_first_recovery_fixture(self, *, published=True):
        # Execute the actual installer first-transaction scanner using the
        # original real Signed crypto and inode-bound rootless directory
        # layout. Only the hardcoded /opt and systemd path are substituted
        # inside this disposable fixture; no installed host is modified.
        runtime = self.receipt_runtime()
        stage = self.receipt_stage("authsign")
        if published:
            self.receipt_action("install-receipt", stage)
        release_name="0.1.0-dev-"+self.identity["checksums_sha256"][:16]
        release=stage.parent/release_name
        stage.rename(release)
        prefix=runtime.INSTALLED_RELEASES.parent
        (prefix/".owner").write_text("AChWorks/server-connect\n")
        (prefix/"current").symlink_to("releases/"+release_name)
        private=self.case/"first-private"
        private.mkdir(mode=0o700)
        outer=self.case/".server-connect-release.authsign"
        first=self.case/".server-connect-initial.ABCDE123"
        canonical=subprocess.run(["/usr/bin/openssl","pkey","-pubin",
                                  "-in",str(self.public),"-pubout"],
                                  check=True,capture_output=True,timeout=15).stdout
        binding="signed:"+":".join(hashlib.sha256(v).hexdigest()
               for v in (self.metadata.read_bytes(),self.signature.read_bytes(),canonical))
        (private/".first-install-intent").write_text(
            f"{first}\n{prefix.stat().st_dev}:{prefix.stat().st_ino}\n{binding}\n")
        (private/".first-release-intent").write_text(
            f"{outer}\n{release.stat().st_dev}:{release.stat().st_ino}\n{release_name}\n{binding}\n")
        for intent in private.iterdir():intent.chmod(0o600)
        source=self.case/"signed-source"
        source.mkdir()
        for name,raw in self.payload.items():
            path=source/name.removeprefix("server-connect/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
        helper=source/"release-auth.py"
        written=helper.read_text()
        assert 'INSTALLED_RELEASES = Path("/opt/server-connect/releases")' in written
        helper.write_text(written.replace(
            'INSTALLED_RELEASES = Path("/opt/server-connect/releases")',
            f'INSTALLED_RELEASES = Path({str(runtime.INSTALLED_RELEASES)!r})'))
        unitdir=self.case/"units";unitdir.mkdir()
        source_code=INSTALLER.read_text()
        begin=source_code.index("FIRST_INSTALL_INTENT=$STATE/.first-install-intent\n")
        end=source_code.index(
            "# Inspect the *effective* systemd identity before ANY stop/disable/enable or",
            begin)
        functions=source_code[begin:end]
        functions=functions.replace("/opt",str(self.case))
        functions=functions.replace(
            '/etc/systemd/system "$COMMAND" "$release_name"',
            f'{unitdir} "$COMMAND" "$release_name"')
        prolog=(
            "set -eu\n"
            f'PREFIX={shlex.quote(str(prefix))}\n'
            f'STATE={shlex.quote(str(private))}\n'
            f'SOURCE_DIR={shlex.quote(str(source))}\n'
            f'COMMAND={shlex.quote(str(self.case/"absent-bin"))}\n'
            f'release_name={shlex.quote(release_name)}\n'
            f'metadata_file={shlex.quote(str(self.metadata))}\n'
            f'signature_file={shlex.quote(str(self.signature))}\n'
            f'publisher_key={shlex.quote(str(self.public))}\n'
            'trust_kind=signed\n'
            'say() { printf "%s\n" "$*"; }\n'
            'die() { printf "REFUSED:%s\n" "$*" >&2; exit 21; }\n'
            +functions+"\n"
        )
        def reconcile(action,trust="signed",public=None,signature=None):
            args=prolog.replace('trust_kind=signed\n','trust_kind='+trust+'\n')
            if public is not None:
                args=args.replace('publisher_key='+shlex.quote(str(self.public))+'\n',
                                  'publisher_key='+shlex.quote(str(public))+'\n')
            if signature is not None:
                args=args.replace('signature_file='+shlex.quote(str(self.signature))+'\n',
                                  'signature_file='+shlex.quote(str(signature))+'\n')
            return subprocess.run(["/bin/sh","-c",args+
                "first_install_reconcile_transaction "+action+"\n"],
                capture_output=True,text=True,timeout=40)
        return reconcile,release,private

    def test_signed_first_recovery_requires_exact_receipt_and_selected_authority(self):
        reconcile,release,private=self.signed_first_recovery_fixture()
        valid=reconcile("inspect")
        self.assertEqual(valid.returncode,0,valid.stderr)
        with self.subTest("downgrade"):
            refused=reconcile("inspect",trust="unsigned")
            self.assertNotEqual(refused.returncode,0)
            self.assertTrue(release.exists())
        with self.subTest("wrong publisher"):
            refused=reconcile("inspect",public=self.wrong_public)
            self.assertNotEqual(refused.returncode,0)
            self.assertTrue(release.exists())
        original=self.signature.read_bytes()
        self.signature.write_bytes(original+b"foreign")
        with self.subTest("changed signer input"):
            refused=reconcile("recover")
            self.assertNotEqual(refused.returncode,0)
            self.assertTrue(release.exists())
        self.signature.write_bytes(original)
        auth=release/"authentication.json"
        real=auth.read_bytes()
        auth.write_bytes(real.replace(b'"owner":"AChWorks/server-connect"',
                                          b'"owner":"foreign-project"'))
        with self.subTest("conflicting final receipt"):
            refused=reconcile("recover")
            self.assertNotEqual(refused.returncode,0)
            self.assertTrue(auth.exists())
        auth.write_bytes(real)
        shadow=release/".authentication.foreign"
        os.link(auth,shadow)
        with self.subTest("foreign hardlink"):
            refused=reconcile("recover")
            self.assertNotEqual(refused.returncode,0)
            self.assertTrue(shadow.exists())
            self.assertEqual(auth.stat().st_nlink,2)
        shadow.unlink()
        self.assertEqual(reconcile("inspect").returncode,0)
        completed=reconcile("recover")
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertFalse(release.exists())
        self.assertFalse((private/".first-release-intent").exists())
        self.assertFalse((private/".first-install-intent").exists())

    def test_signed_prelink_first_install_never_downgrades_implicitly(self):
        reconcile, release, private = self.signed_first_recovery_fixture(published=False)
        receipt = private / ".first-release-intent"
        source_identity = receipt.read_bytes()
        self.assertFalse((release / "authentication.json").exists())
        self.assertEqual(reconcile("inspect").returncode, 0)
        for kind in ("unsigned", "local-qa"):
            with self.subTest(trust=kind):
                rejected = reconcile("inspect", trust=kind)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("original", rejected.stderr)
                self.assertEqual(receipt.read_bytes(), source_identity)
                self.assertTrue(release.exists(), "partial Signed release was adopted")
                self.assertFalse((release / "integrity.sha256").exists())
        # A second, cryptographically valid independent publisher cannot
        # silently replace the original operator-selected signer even when
        # payload bytes and signed release metadata are identical.
        new_private = self.case / "alternate-signing-private.pem"
        new_public = self.case / "alternate-signing-public.pem"
        new_signature = self.case / "alternate-release.sig"
        subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(new_private)],
                       check=True, capture_output=True, timeout=30)
        subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(new_private),
                        "-pubout", "-out", str(new_public)],
                       check=True, capture_output=True, timeout=15)
        subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-sign",
                        str(new_private), "-out", str(new_signature),
                        str(self.metadata)],
                       check=True, capture_output=True, timeout=15)
        valid = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256",
                                "-verify", str(new_public), "-signature",
                                str(new_signature), str(self.metadata)],
                               capture_output=True, text=True, timeout=15)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        other = reconcile("inspect", public=new_public, signature=new_signature)
        self.assertNotEqual(other.returncode, 0)
        self.assertIn("original", other.stderr)
        self.assertEqual(receipt.read_bytes(), source_identity)
        # One explicit, owned, *cleanup-only* action may abandon the
        # incomplete Signed operation when the operator no longer has its key.
        self.assertEqual(reconcile("inspect-abandon", trust="unsigned").returncode, 0)
        self.assertTrue(release.exists(), "inspection must not mutate")
        self.assertEqual(reconcile("abandon", trust="unsigned").returncode, 0)
        self.assertFalse(release.exists())
        self.assertFalse(private.joinpath(".first-install-intent").exists())
        self.assertFalse(receipt.exists())

    def test_signed_prelink_abandon_preserves_foreign_and_swapped_inodes(self):
        reconcile, release, private = self.signed_first_recovery_fixture(published=False)
        foreign = release / "unowned-resource"
        foreign.write_bytes(b"preserve foreign")
        denied = reconcile("abandon", trust="unsigned")
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(foreign.read_bytes(), b"preserve foreign")
        self.assertTrue(private.joinpath(".first-release-intent").exists())
        foreign.unlink()
        displaced = self.case / "original-signed-release"
        release.rename(displaced)
        release.mkdir()
        denied = reconcile("abandon", trust="unsigned")
        self.assertNotEqual(denied.returncode, 0)
        self.assertTrue(release.exists())
        self.assertTrue(displaced.exists())
        self.assertTrue(private.joinpath(".first-release-intent").exists())

    def test_signed_published_explicit_abandon_checks_original_receipt_digest(self):
        reconcile, release, private = self.signed_first_recovery_fixture(published=True)
        claim = private / ".first-release-intent"
        raw = claim.read_bytes()
        # Embedded Signed material cannot be replaced even if the operator
        # explicitly chooses only to abandon an interrupted stage.
        claim.write_bytes(raw.replace(b"signed:", b"signed:0", 1))
        self.assertNotEqual(reconcile("abandon", trust="unsigned").returncode, 0)
        self.assertTrue(release.exists())
        claim.write_bytes(raw)
        self.assertEqual(reconcile("inspect-abandon", trust="unsigned").returncode, 0)
        self.assertEqual(reconcile("abandon", trust="unsigned").returncode, 0)
        self.assertFalse(release.exists())

    def test_signed_prefix_claim_alone_preserves_original_trust(self):
        reconcile, release, private = self.signed_first_recovery_fixture(published=False)
        current=release.parent.parent / "current"
        current.unlink()
        shutil.rmtree(release)
        stage=private / ".first-release-intent"
        stage.unlink()
        self.assertEqual(reconcile("inspect", trust="signed").returncode, 0)
        self.assertNotEqual(reconcile("inspect", trust="unsigned").returncode, 0)
        self.assertEqual(reconcile("abandon", trust="unsigned").returncode, 0)
        self.assertFalse(private.joinpath(".first-install-intent").exists())

    def installer_receipt_harness(self, command, *, source=None):
        body = INSTALLER.read_text()
        functions = []
        for start, end in (
            ("release_payload_files() {\n", "\n}\n"),
            ("verify_release_payload() (\n", "\n)\n"),
            ("release_trust_file() (\n", "\n)\n"),
            ("verify_release_trust() (\n", "\n)\n"),
            ("verify_installed_release() (\n", "\n)\n"),
            ("bundle_release_version() {\n", "\n}\n"),
            ("verify_payload() {\n", "\n}\n"),
            ("rollback_candidate() {\n", "\n}\n"),
        ):
            position = body.index(start)
            finish = body.index(end, position) + len(end)
            functions.append(body[position:finish])
        # The native installer fragments run unchanged apart from ownership
        # helpers and this bridge's private namespace constant. Crypto,
        # immutable identity checks, actual file deletion, modes and inode
        # comparisons all execute; no service/lifecycle entrypoint is run.
        bridge = r"""
import importlib.util, os, sys
from pathlib import Path
assert sys.argv[1:3] == ["-I", "-S"]
helper = sys.argv[3]
spec = importlib.util.spec_from_file_location("sc_auth_receipt_shell_fixture", helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.INSTALLED_RELEASES = Path(os.environ["SC_QA_RELEASES"])
sys.argv = [helper] + sys.argv[4:]
try:
    module.main()
except (ValueError, OSError):
    sys.exit(1)
"""
        prefix = self.receipt_runtime().INSTALLED_RELEASES.parent
        environment = dict(os.environ, SC_QA_RELEASES=str(prefix / "releases"),
                           SC_QA_AUTH_BRIDGE=bridge)
        prolog = (
            "set -eu\n"
            "check_root_file() { [ -f \"$1\" ] && [ ! -L \"$1\" ]; }\n"
            "check_root_dir() { [ -d \"$1\" ] && [ ! -L \"$1\" ]; }\n"
            "check_dir() { check_root_dir \"$1\"; }\n"
            "say() { printf '%s\\n' \"$*\"; }\n"
            "die() { say \"$*\" >&2; exit 1; }\n"
            "need() { command -v \"$1\" >/dev/null; }\n"
            "python3() { if [ \"$1\" = -I ] && [ \"$2\" = -S ] && { [ \"$3\" = - ] || [ \"$3\" = -c ]; }; then /usr/bin/python3 \"$@\"; else /usr/bin/python3 -B -I -S -c \"$SC_QA_AUTH_BRIDGE\" \"$@\"; fi; }\n"
            "remove_backup() { :; }\n"
            "PREFIX=" + shlex.quote(str(prefix)) + "\n"
            "SOURCE_DIR=" + shlex.quote(str(source or self.case / "source")) + "\n"
            "local_qa=no\nretained_auth=yes\n"
        )
        return subprocess.run(
            ["/bin/sh", "-s"], input=prolog + "\n".join(functions) + "\n" + command,
            env=environment, text=True, capture_output=True, timeout=30,
        )

    def rollback_fixture(self, release):
        source = self.case / "source"
        source.mkdir()
        for name, data in self.payload.items():
            path = source / name.removeprefix("server-connect/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        command = (
            "release=" + shlex.quote(str(release)) + "\n"
            "release_name=" + shlex.quote(release.name) + "\n"
            "release_stage_identity=$(stat -c '%d:%i' \"$release\")\n"
            "rollback_needed=no\nstage=''\nrelease_created=yes\nprefix_created=no\n"
            "rollback_candidate\nprintf 'ROLLBACK_FAILED=%s\\n' \"$failed\"\n"
        )
        return self.installer_receipt_harness(command, source=source)

    def test_actual_rollback_removes_only_new_signed_receipt_and_preserves_previous(self):
        previous = self.receipt_publish()
        previous_receipt = (previous / "authentication.json").read_bytes()
        self.manifest["source_revision"] = "b" * 40
        self.fixture()
        current = self.receipt_publish("ijklmnop")
        result = self.rollback_fixture(current)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ROLLBACK_FAILED=no", result.stdout)
        self.assertFalse(current.exists(), "owned failed publication was not removed")
        self.assertEqual((previous / "authentication.json").read_bytes(), previous_receipt)
        self.receipt_action("verify-installed", previous)

    def test_actual_rollback_preserves_all_files_when_signed_receipt_is_uncertain(self):
        release = self.receipt_publish()
        receipt = release / "authentication.json"
        receipt.write_bytes(receipt.read_bytes() + b"corrupt")
        before = {str(path.relative_to(release)): path.read_bytes()
                  for path in release.rglob("*") if path.is_file()}
        result = self.rollback_fixture(release)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ROLLBACK_FAILED=yes", result.stdout)
        self.assertIn("RECOVERY_REQUIRED", result.stdout)
        self.assertEqual(before, {str(path.relative_to(release)): path.read_bytes()
                                 for path in release.rglob("*") if path.is_file()})

    def test_actual_uninstall_cleanup_removes_valid_signed_receipts_after_preflight(self):
        previous = self.receipt_publish()
        self.manifest["source_revision"] = "b" * 40
        self.fixture()
        current = self.receipt_publish("ijklmnop")
        retained_profile = self.case / "operator-profile"
        retained_profile.write_bytes(b"private operator state preserved\n")
        body = INSTALLER.read_text()
        start = body.index(' if [ -d "$PREFIX/releases" ] && [ ! -L "$PREFIX/releases" ]; then\n')
        end = body.index('\n fi\n', start) + len('\n fi\n')
        cleanup = body[start:end]
        command = (
            'for release in "$PREFIX"/releases/*; do\n'
            ' verify_installed_release "$release" || exit 1\n'
            'done\n' + cleanup + "\n"
        )
        # An invalid retained key/signature blocks the actual preflight
        # before this deletion section can touch either release.
        receipt = current / "authentication.json"
        original = receipt.read_bytes()
        receipt.write_bytes(original + b"corrupt")
        rejected = self.installer_receipt_harness(command)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertTrue(previous.is_dir())
        self.assertTrue(current.is_dir())
        receipt.write_bytes(original)
        completed = self.installer_receipt_harness(command)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(previous.exists())
        self.assertFalse(current.exists())
        self.assertEqual(retained_profile.read_bytes(), b"private operator state preserved\n")

    def test_retained_installer_preflight_works_without_original_sidecars_or_key(self):
        # The actual payload gate may execute these bounded inert binaries
        # only after validating the retained trust. No systemd command exists.
        self.payload["server-connect/bin/server-connect"] = (
            b'#!/bin/sh\ncase "$1" in\n'
            b'installer-check-target) exit 0;;\n'
            b'version) printf \'%s\\n\' \'{"ok":true,"data":{"manager":"0.1.0-dev","sing_box":"1.14.3"}}\';;\n'
            b'*) exit 97;;\nesac\n'
        )
        self.payload["server-connect/bin/sing-box"] = (
            b'#!/bin/sh\nprintf "%s\\n" "sing-box version 1.14.3"\n'
        )
        self.fixture()
        release = self.receipt_publish()
        for name in ("bin/server-connect", "bin/sing-box"):
            (release / name).chmod(0o700)
        self.metadata.unlink()
        self.signature.unlink()
        result = self.installer_receipt_harness("verify_payload\n", source=release)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("retained publisher authentication verified offline", result.stdout)

    @unittest.skipUnless(os.uname().machine == "x86_64", "Linux amd64 syscall witness")
    def test_offline_succeeds_with_all_network_syscalls_fatal(self):
        # A fresh process installs a Linux seccomp filter inherited by every
        # child. Any attempted socket or network transfer is fatal (SIGSYS),
        # including curl/DNS/HTTP/APT, so successful verification cannot use it.
        # This affects only the test subprocess, never the host network.
        launcher = r"""
import ctypes, os, sys
class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
items = [(0x20,0,0,4), (0x15,1,0,0xc000003e), (0x06,0,0,0x80000000),
         (0x20,0,0,0)]
for call in (41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,288,299,307):
    items.extend([(0x15,0,1,call), (0x06,0,0,0x80000000)])
items.append((0x06,0,0,0x7fff0000))
filters = (Filter * len(items))(*(Filter(*entry) for entry in items))
program = Program(len(items), filters)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program)):
    sys.exit(97)
os.execv(sys.argv[1], sys.argv[1:])
"""
        # First prove the independent witness really kills a socket attempt.
        probe = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-c", launcher,
             "/usr/bin/python3", "-I", "-S", "-c", "import socket; socket.socket()"],
            capture_output=True, timeout=10,
        )
        self.assertEqual(probe.returncode, -31, "seccomp network witness did not enforce SIGSYS")
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-c", launcher, *self.arguments()],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Publisher signature and pinned release identity verified", result.stdout)

    def unsigned_bootstrap(self, *extra, url=None, mirror_base=None, ca=True):
        if mirror_base is not None:
            source = ['--mirror-base', mirror_base]
        elif url is not None:
            source = ['--archive-url', url]
        else:
            source = ['--archive-file', str(self.bundle)]
        env = os.environ.copy()
        if ca:
            env['CURL_CA_BUNDLE'] = str(self.ca)
        else:
            env.pop('CURL_CA_BUNDLE', None)
        return subprocess.run(['/bin/sh', str(self.bootstrap), *source, '--verify-only', *extra],
                              capture_output=True, text=True, timeout=30, env=env)

    def test_keyless_offline_archive_and_metadata_integrity(self):
        result = self.unsigned_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Installation was not attempted', result.stdout)
        self.assertIn('not publisher authentication', result.stderr)
        before = self.bundle.read_bytes()
        self.bundle.write_bytes(before + b'tampered')
        rejected = self.unsigned_bootstrap()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('archive integrity mismatch', rejected.stderr)
        self.bundle.write_bytes(before)
        before_meta = self.metadata.read_bytes()
        self.metadata.write_bytes(before_meta.replace(b'"source_state":"clean"', b'"source_state":"dirty"'))
        rejected = self.unsigned_bootstrap()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('nothing installed', rejected.stderr)
        self.metadata.write_bytes(before_meta)
        self.metadata.unlink()
        rejected = self.unsigned_bootstrap()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('Local release identity unavailable', rejected.stderr)


    def documented_entrypoint(self, channel, *, trusted=True):
        import re
        docs = (ROOT / "docs" / "OFFLINE-DISTRIBUTION.md").read_text()
        if channel == "mirror":
            section = docs.split("**Operator-hosted HTTPS mirror", 1)[1].split("**Completely offline", 1)[0]
            server = self.https_servers[1][0]
        else:
            section = docs.split("**Official GitHub release channel", 1)[1].split("**Operator-hosted HTTPS mirror", 1)[0]
            server = self.https_servers[0][0]
        command = re.search(r"```sh\n(.*?)\n```", section, re.S).group(1)
        command = command.replace("sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin ", "")
        command = command.replace(
            "/root/.server-connect-entry.XXXXXXXX",
            str(self.case / ".server-connect-entry.XXXXXXXX"),
        )
        base = f"https://localhost:{server.server_port}/{self.case.name}/"
        if channel == "mirror":
            command = command.replace("https://mirror.example/server-connect/", base)
        else:
            command = command.replace(
                "https://github.com/AChWorks/server-connect/releases/latest/download/bootstrap-online.sh",
                base + "bootstrap-online.sh",
            )
        env = os.environ.copy()
        if trusted:
            env["CURL_CA_BUNDLE"] = str(self.ca)
        else:
            env.pop("CURL_CA_BUNDLE", None)
        return subprocess.run(["/bin/sh", "-eu", "-c", command],
                              capture_output=True, text=True, timeout=17, env=env)

    def test_documented_bootstrap_download_stages_full_bytes_before_execution(self):
        for channel, index in (("official", 0), ("mirror", 1)):
            with self.subTest(channel=channel):
                server = self.https_servers[index][0]
                source = self.case / "bootstrap-online.sh"
                executed = self.case / "BOOTSTRAP_ENTRY_RAN"
                source.write_text("#!/bin/sh\nprintf 'ok' > "+shlex.quote(str(executed))+"\n# SERVER_CONNECT_BOOTSTRAP_END\n")
                try:
                    server.bootstrap_response = ""
                    server.requests.clear()
                    good = self.documented_entrypoint(channel)
                    self.assertEqual(good.returncode, 0, good.stderr)
                    self.assertEqual(executed.read_text(), "ok")
                    self.assertEqual([path for path, _ in server.requests],
                                     [f"/{self.case.name}/bootstrap-online.sh"])
                    self.assertFalse(list(self.case.glob(".server-connect-entry.*")))
                    executed.unlink()
                    # TLS failure, redirect, truncated transfer, complete-but-
                    # unfinished source: none may execute the fetched script.
                    server.requests.clear()
                    rejected = self.documented_entrypoint(channel, trusted=False)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(executed.exists())
                    self.assertEqual(server.requests, [])
                    # A redirect with an executable and *complete* shell
                    # body must be refused even if curl exits successfully.
                    if channel == "mirror":
                        server.bootstrap_response_body = source.read_bytes()
                        for code in (302, 307, 308):
                            server.requests.clear()
                            server.bootstrap_response = f"redirect-complete-{code}"
                            rejected = self.documented_entrypoint(channel)
                            self.assertNotEqual(rejected.returncode, 0)
                            self.assertIn(f"HTTP status {code} refused", rejected.stderr)
                            self.assertFalse(executed.exists(), "3xx body executed")
                            self.assertEqual([p for p, _ in server.requests],
                                             [f"/{self.case.name}/bootstrap-online.sh"])
                            self.assertFalse(list(self.case.glob(".server-connect-entry.*")))
                    server.bootstrap_response = "truncated"
                    rejected = self.documented_entrypoint(channel)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(executed.exists())
                    self.assertFalse(list(self.case.glob(".server-connect-entry.*")))
                    server.bootstrap_response = "redirect"
                    rejected = self.documented_entrypoint(channel)
                    if channel == "mirror":
                        self.assertNotEqual(rejected.returncode, 0)
                        self.assertNotIn("foreign-bootstrap", rejected.stdout)
                    # Official supports redirects; the untrusted foreign host
                    # is deliberately unreachable, so this fixture also fails.
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(executed.exists())
                    server.bootstrap_response = ""
                    source.write_text("#!/bin/sh\nprintf bad > "+shlex.quote(str(executed))+"\n")
                    rejected = self.documented_entrypoint(channel)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("Incomplete bootstrap", rejected.stderr)
                    self.assertFalse(executed.exists())
                finally:
                    server.bootstrap_response = ""
                    source.unlink(missing_ok=True)
                    executed.unlink(missing_ok=True)

    def test_keyless_https_requires_real_tls_and_no_signature(self):
        server = self.https_servers[0][0]
        server.requests.clear()
        url = f'https://localhost:{server.server_port}/{self.case.name}/bundle.tar.gz'
        success = self.unsigned_bootstrap(url=url)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual([p for p, _ in server.requests], [
            f'/{self.case.name}/bundle.tar.gz', f'/{self.case.name}/bundle.tar.gz.release.json',
        ])
        server.requests.clear()
        untrusted = self.unsigned_bootstrap(url=url, ca=False)
        self.assertNotEqual(untrusted.returncode, 0)
        self.assertEqual(server.requests, [])
        self.assertNotIn('Installation was not attempted', untrusted.stdout)

    def test_keyless_mirror_index_resolves_debian_and_rejects_tamper(self):
        if not Path('/etc/os-release').read_text().count('VERSION_ID="13"'):
            self.skipTest('fixture has Debian 13 target; Debian 12 is exercised in installed-host CI')
        server = self.https_servers[1][0]
        base = f'https://localhost:{server.server_port}/{self.case.name}/'
        index = self.case / 'release-index.json'
        index_data = {'schema': 1, 'version': '0.1.0-dev', 'artifacts': {
            target: {'archive': 'bundle.tar.gz', 'sha256': self.identity['archive_sha256']}
            for target in ('debian-12-amd64', 'debian-13-amd64')
        }}
        index.write_text(json.dumps(index_data) + '\n')
        server.requests.clear()
        success = self.unsigned_bootstrap(mirror_base=base)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual([p for p, _ in server.requests], [
            f'/{self.case.name}/release-index.json', f'/{self.case.name}/bundle.tar.gz',
            f'/{self.case.name}/bundle.tar.gz.release.json',
        ])
        server.requests.clear()
        index_data['artifacts']['debian-13-amd64']['sha256'] = '0' * 64
        index.write_text(json.dumps(index_data) + '\n')
        refused = self.unsigned_bootstrap(mirror_base=base)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('index and release identity disagree', refused.stderr)
        self.assertFalse(self.marker.exists())
        for value in ('../foreign.tar.gz', 'https://github.com/other.tar.gz', '/absolute.tar.gz'):
            with self.subTest(unsafe_archive=value):
                index_data['artifacts']['debian-13-amd64']['archive'] = value
                index.write_text(json.dumps(index_data) + '\n')
                server.requests.clear()
                refused = self.unsigned_bootstrap(mirror_base=base)
                self.assertNotEqual(refused.returncode, 0)
                self.assertEqual([p for p, _ in server.requests], [f'/{self.case.name}/release-index.json'])
        index.write_text('{"schema":1,"schema":1}')
        refused = self.unsigned_bootstrap(mirror_base=base)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('Release index validation failed', refused.stderr)

    def test_keyless_negative_archive_layout_even_if_index_and_digest_match(self):
        self.fixture(abnormal='traversal')
        rejected = self.unsigned_bootstrap()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('Archive preflight failed', rejected.stderr)



if __name__ == "__main__":
    unittest.main(verbosity=2)
