#!/usr/bin/env python3
"""Negative controls for the actual disconnected TUN native-app QA helper."""

import importlib.util
from pathlib import Path
import urllib.error
import urllib.request
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name("tun-native-apps.py")
spec = importlib.util.spec_from_file_location("tun_native_apps", MODULE)
apps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apps)


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scqa-app-witness-")
        self.addCleanup(self.temp.cleanup)
        witness = Path(self.temp.name) / "witness"
        self.patch = patch.object(apps, "WITNESS", witness)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write(self, *records):
        apps.WITNESS.write_text("\n".join(records) + ("\n" if records else ""), encoding="ascii")

    def test_valid_independent_sources(self):
        self.write(
            "8.8.8.8\t/apt/dists/qa/Release",
            "8.8.8.8\t/git/fixture.git/info/refs",
            "8.8.8.8\t/git/fixture.git/git-upload-pack",
        )
        apps.check_witness(
            "8.8.8.8",
            ["/apt/dists/qa/Release", "/git/fixture.git/info/refs",
             "/git/fixture.git/git-upload-pack"],
        )

    def test_wrong_source_or_missing_app_fails(self):
        cases = [
            ("10.254.72.1\t/apt/dists/qa/Release",
             "8.8.8.8\t/git/fixture.git/info/refs",
             "8.8.8.8\t/git/fixture.git/git-upload-pack"),
            ("8.8.8.8\t/apt/dists/qa/Release",),
            ("8.8.8.8\t/git/fixture.git/info/refs",),
            ("8.8.8.8\t/apt/dists/qa/Release",
             "8.8.8.8\t/git/fixture.git/info/refs"),
            (),
        ]
        for records in cases:
            with self.subTest(records=records):
                self.write(*records)
                with self.assertRaises(RuntimeError):
                    apps.check_witness(
                        "8.8.8.8",
                        ["/apt/dists/qa/Release", "/git/fixture.git/info/refs",
                         "/git/fixture.git/git-upload-pack"],
                    )

    def test_wordpress_nonce_and_independent_path_witness(self):
        nonce = "0123456789abcdef"
        self.write(f"10.254.72.1\t/wp/nonce?value={nonce}")
        apps.wp_witness("10.254.72.1", nonce)
        self.write(f"8.8.8.8\t/wp/nonce?value={nonce}")
        apps.wp_witness("8.8.8.8", nonce)
        for records, expected in (
            ((f"10.254.72.1\t/wp/nonce?value={nonce}",), "8.8.8.8"),
            (("8.8.8.8\t/wp/nonce?value=stale1234567890",), "8.8.8.8"),
            ((f"8.8.8.8\t/wp/nonce?value={nonce}", "8.8.8.8\t/apt/"), "8.8.8.8"),
            ((), "8.8.8.8"),
        ):
            with self.subTest(records=records):
                self.write(*records)
                with self.assertRaises(RuntimeError):
                    apps.wp_witness(expected, nonce)
        self.write()
        apps.wp_witness("none", nonce)
        self.write(f"10.254.72.1\t/wp/nonce?value={nonce}")
        with self.assertRaises(RuntimeError):
            apps.wp_witness("none", nonce)

    def test_outage_requires_empty_independent_origin_witness(self):
        self.write()
        apps.check_witness("", [])
        self.write("10.254.72.1\t/git/fixture.git/info/refs")
        with self.assertRaises(RuntimeError):
            apps.check_witness("", [])

    def test_outage_cannot_pass_from_unrelated_client_errors(self):
        # Emulate the expected exit codes but with wrong error causality.
        # The helper must require evidence of both real origin attempts.
        with tempfile.TemporaryDirectory(prefix="scqa-app-status-") as temp:
            with patch.object(apps, "ROOT", Path(temp)):
                self.write()
                with patch.object(apps, "run", side_effect=[
                    type("Run", (), {"returncode": 100, "stderr": b"E: unknown package error"})(),
                    type("Run", (), {"returncode": 100, "stderr": b"E: No packages found"})(),
                    type("Run", (), {"returncode": 128, "stderr": b"fatal: invalid repository"})(),
                ]):
                    with self.assertRaisesRegex(RuntimeError, "not an origin acquisition failure"):
                        apps.exercise("outage")


class FixtureTests(unittest.TestCase):
    def test_disconnected_git_identity_never_needs_host_resolver(self):
        # The strace-proven source of the selected-path stall was Git's
        # fallback hostname DNS during identity generation after pack fetch.
        # Verify a process-local QA identity works without changing ~/.gitconfig.
        for kind in ("GIT_COMMITTER_IDENT", "GIT_AUTHOR_IDENT"):
            with self.subTest(kind=kind):
                ident = apps.checked(["/usr/bin/git", "var", kind]).decode("ascii")
                self.assertIn("Disposable TUN QA <qa@invalid.test>", ident)
                self.assertNotIn("@localhost", ident)

    def test_isolated_index_and_real_local_git_objects(self):
        with tempfile.TemporaryDirectory(prefix="scqa-app-fixture-") as temp:
            root = Path(temp) / "native"
            with patch.object(apps, "ROOT", root), \
                 patch.object(apps, "PUBLIC", root / "public"), \
                 patch.object(apps, "WITNESS", root / "witness"):
                apps.prepare()
                self.assertIn(
                    b"Package: sc-qa-tun-route-proof",
                    (root / "public/apt/dists/qa/main/binary-amd64/Packages").read_bytes(),
                )
                self.assertTrue((root / "public/git/fixture.git/HEAD").is_file())
                # No static info/refs means the guest must prove real smart
                # Git HTTP upload-pack, not silently revert to dumb HTTP.
                self.assertFalse((root / "public/git/fixture.git/info/refs").exists())
                self.assertIn("8.8.8.8:19187", (root / "sources.list").read_text())
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    apps.prepare()

    def test_prepare_preserves_foreign_path_and_cleans_own_partial_fixture(self):
        with tempfile.TemporaryDirectory(prefix="scqa-app-ownership-") as temp:
            root = Path(temp) / "native"
            with patch.object(apps, "ROOT", root), patch.object(apps, "PUBLIC", root / "public"), \
                 patch.object(apps, "WITNESS", root / "witness"):
                root.mkdir()
                foreign = root / "foreign-data"
                foreign.write_text("must not be removed")
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    apps.prepare()
                self.assertEqual(foreign.read_text(), "must not be removed")
                foreign.unlink()
                root.rmdir()
                # Force failure after the atomic directory creation. No
                # partially created QA fixture must survive a failed setup.
                with patch.object(apps, "checked", side_effect=RuntimeError("injected setup fault")):
                    with self.assertRaisesRegex(RuntimeError, "injected setup fault"):
                        apps.prepare()
                self.assertFalse(root.exists())

    def test_genuine_http_wordpress_origin_records_real_source_and_nonce(self):
        with tempfile.TemporaryDirectory(prefix="scqa-wp-origin-") as temp:
            witness = Path(temp) / "witness"
            with patch.object(apps, "WITNESS", witness):
                witness.touch()
                server = apps.ThreadingHTTPServer(("127.0.0.1", 0), apps.OriginHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                base = f"http://127.0.0.1:{server.server_port}"
                nonce = "0123456789abcdef"
                try:
                    with urllib.request.urlopen(f"{base}/wp/nonce?value={nonce}", timeout=3) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(),
                            f"SC_QA_WP_NONCE:{nonce};SOURCE=127.0.0.1".encode())
                    self.assertEqual(witness.read_text(),
                        f"127.0.0.1\t/wp/nonce?value={nonce}\n")
                    for invalid in ("0", "not-a-hex-string", "0123456789abcdef012345"):
                        with self.assertRaises(urllib.error.HTTPError) as context:
                            urllib.request.urlopen(f"{base}/wp/nonce?value={invalid}", timeout=3)
                        self.assertEqual(context.exception.code, 400)
                    self.assertEqual(witness.read_text(),
                        f"127.0.0.1\t/wp/nonce?value={nonce}\n")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_genuine_loopback_smart_http_clone(self):
        # No privileged namespace or production socket. Exercise the actual
        # CGI-backed smart HTTP fixture and verify a real cloned commit.
        with tempfile.TemporaryDirectory(prefix="scqa-smart-git-") as temp:
            root = Path(temp) / "native"
            with patch.object(apps, "ROOT", root), \
                 patch.object(apps, "PUBLIC", root / "public"), \
                 patch.object(apps, "WITNESS", root / "witness"):
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
                listener.close()
                with patch.object(apps, "ORIGIN", f"http://127.0.0.1:{port}"):
                    apps.prepare()
                    server = apps.ThreadingHTTPServer(("127.0.0.1", port), apps.OriginHandler)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        result = apps.run(
                            ["/usr/bin/git", "clone", "-q",
                             f"{apps.ORIGIN}/git/fixture.git",
                             str(root / "smart-clone")],
                            timeout=7,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr[-1500:])
                        actual = apps.checked(
                            ["/usr/bin/git", "-C", str(root / "smart-clone"),
                             "rev-parse", "HEAD"]
                        ).decode().strip()
                        expected = (root / "expected-git-sha").read_text().strip()
                        self.assertEqual(actual, expected)
                        entries = (root / "witness").read_text()
                        self.assertIn("/git/fixture.git/info/refs", entries)
                        self.assertIn("/git/fixture.git/git-upload-pack", entries)
                        self.assertNotIn("/git/fixture.git/objects/", entries)
                    finally:
                        server.shutdown()
                        server.server_close()
                        thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
