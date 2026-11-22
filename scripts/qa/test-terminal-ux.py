#!/usr/bin/env python3
"""Nonprivileged PTY and bootstrap finalization tests; no install, APT or network."""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (ROOT / "scripts/bootstrap-online.sh").read_text()


def run_pty(argv, input_text, *, width=40, height=24, term="xterm-256color", no_color=False):
    env = os.environ.copy()
    env["TERM"] = term
    env["COLUMNS"] = str(width)
    if no_color:
        env["NO_COLOR"] = "1"
    else:
        env.pop("NO_COLOR", None)
    child, master = pty.fork()
    if child == 0:
        os.execvpe(argv[0], argv, env)
    output = bytearray()
    try:
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
        os.write(master, input_text.encode())
        deadline = time.monotonic() + 10
        status = None
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                    if not chunk:
                        break
                    output += chunk
                except OSError as e:
                    if e.errno != errno.EIO:
                        raise
                    break
            waited, result = os.waitpid(child, os.WNOHANG)
            if waited:
                # A child can exit while its final output is still readable.
                # Reaping it is final; waiting again on the next iteration
                # raises ChildProcessError instead of finishing this test.
                status = result
                break
        if status is None:
            # EIO on the PTY master means the slave was closed, but the
            # process can still be exiting; allow its exit status to settle.
            for _ in range(40):
                try:
                    waited, result = os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    waited, result = child, 0
                if waited:
                    status = result
                    break
                time.sleep(0.025)
        if status is None:
            raise AssertionError("PTY operation did not finish; refusing a hanging menu")
        return output.decode(errors="replace"), os.waitstatus_to_exitcode(status)
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
        os.close(master)


class TerminalUXTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="sc-pty-ux-")
        cls.binary = str(Path(cls.build.name) / "server-connect")
        build = subprocess.run(["go", "build", "-buildvcs=false", "-trimpath",
                                "-ldflags=-s -w -X main.managerVersion=0.1.0",
                                "-o", cls.binary, "./cmd/server-connect"], cwd=ROOT,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=90)
        if build.returncode:
            raise AssertionError("disposable PTY test CLI build failed: " + build.stderr.strip())

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_screen_and_no_overflow_at_supported_terminal_widths(self):
        for width in (30, 40, 80, 120):
            for section, keys in (("main", "q\n"), ("advanced", "a\nq\n")):
                with self.subTest(width=width, section=section):
                    state = Path(self.build.name) / "never-initialized"
                    raw, code = run_pty([self.binary, "--state-dir", str(state), "menu"], keys,
                                        width=width)
                    self.assertEqual(code, 0)
                    self.assertIn("\x1b[?1049h", raw)
                    self.assertIn("\x1b[?1049l", raw)
                    frames = raw.split("\x1b[2J\x1b[H")
                    self.assertGreaterEqual(len(frames), 2)
                    frame = frames[1] if section == "main" else frames[-1]
                    visible = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", frame).replace("\r", "")
                    visible = visible.partition("Choice:")[0]
                    rows = visible.splitlines()
                    self.assertLessEqual(len(rows), 23, (width, section, len(rows)))
                    self.assertLessEqual(max((len(row) for row in rows), default=0), width)
                    if section == "advanced":
                        self.assertIn("Underlay DNS", visible)
                    else:
                        self.assertIn("Connection", visible)
                    self.assertFalse(state.exists(), "drawing a menu created state")

    def test_interrupt_and_terminate_restore_terminal(self):
        # Interrupting the menu must never strand an SSH terminal on its
        # alternate screen. It must preserve the original signal exit status.
        for termination in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=termination):
                state = Path(self.build.name) / "absent-interrupt"
                child, master = pty.fork()
                if child == 0:
                    env = os.environ.copy()
                    env["TERM"] = "xterm-256color"
                    os.execvpe(self.binary, [self.binary, "--state-dir", str(state), "menu"], env)
                data = bytearray()
                status = None
                try:
                    deadline = time.monotonic() + 6
                    while b"Choice:" not in data and time.monotonic() < deadline:
                        ready, _, _ = select.select([master], [], [], 0.1)
                        if ready:
                            try:
                                data += os.read(master, 65536)
                            except OSError as exc:
                                if exc.errno != errno.EIO:
                                    raise
                                break
                    self.assertIn(b"Choice:", data)
                    os.kill(child, termination)
                    while time.monotonic() < deadline:
                        ready, _, _ = select.select([master], [], [], 0.1)
                        if ready:
                            try:
                                data += os.read(master, 65536)
                            except OSError as exc:
                                if exc.errno != errno.EIO:
                                    raise
                        waited, result = os.waitpid(child, os.WNOHANG)
                        if waited:
                            status = result
                            break
                    self.assertIsNotNone(status, "menu did not exit after terminal signal")
                    self.assertEqual(os.waitstatus_to_exitcode(status), -termination)
                    self.assertIn(b"\x1b[?1049h", data)
                    self.assertIn(b"\x1b[?1049l", data)
                    self.assertFalse(state.exists())
                finally:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child, 0)
                    except ChildProcessError:
                        pass
                    os.close(master)

    def test_no_color_and_dumb_terminal_never_force_color(self):
        state = str(Path(self.build.name) / "absent")
        for term, no_color in (("dumb", False), ("xterm-256color", True)):
            with self.subTest(term=term, no_color=no_color):
                raw, code = run_pty([self.binary, "--state-dir", state, "menu"], "q\n",
                                    term=term, no_color=no_color)
                self.assertEqual(code, 0)
                self.assertNotIn("\x1b[1;36m", raw)
                if term == "dumb":
                    self.assertNotIn("\x1b[", raw)
                else:
                    self.assertIn("\x1b[?1049h", raw)

    def test_human_status_mode_native_and_profile_pages_keep_json_separate(self):
        names = {"1": "Connection status", "18": "Available modes",
                 "22": "Native guard and recovery", "2": "Saved profiles"}
        with tempfile.TemporaryDirectory(prefix="sc-ux-human-pages-") as private:
            state = str(Path(private) / "state")
            for choice, label in names.items():
                with self.subTest(choice=choice):
                    raw, exit_code = run_pty([self.binary, "--state-dir", state, "menu"],
                                             choice + "\n\nq\n", width=80)
                    self.assertEqual(exit_code, 0)
                    self.assertIn(label, raw)
                    self.assertNotIn('"observed_mode":', raw)
                    self.assertNotIn('"general_host_activation":', raw)
                    self.assertIn("Press Enter to return", raw)
            # CLI JSON remains structured and independently inspectable.
            result = subprocess.run([self.binary, "--state-dir", state, "--json", "mode-overview"],
                                    text=True, capture_output=True, timeout=6)
            self.assertIn('"general_host_activation":false', result.stdout)
            self.assertNotIn("\x1b[", result.stdout)

    def test_errors_use_red_only_on_suitable_terminals_and_offer_next_step(self):
        with tempfile.TemporaryDirectory(prefix="sc-ux-error-") as private:
            args = [self.binary, "--state-dir", str(Path(private) / "state"),
                    "import", "--file", str(Path(private) / "nonexistent")]
            for term, no_color, expects_red in (("xterm-256color", False, True),
                                                ("dumb", False, False),
                                                ("xterm-256color", True, False)):
                with self.subTest(term=term, no_color=no_color):
                    out, code = run_pty(args, "", term=term, no_color=no_color)
                    self.assertNotEqual(code, 0)
                    self.assertIn("Error [file_not_found]", out)
                    self.assertIn("State:", out)
                    self.assertIn("Next:", out)
                    self.assertEqual("\x1b[1;31m" in out, expects_red)

    def test_cancellation_requires_no_privileged_operation_and_shows_feedback(self):
        state = Path(self.build.name) / "absent-cancel"
        raw, code = run_pty([self.binary, "--state-dir", str(state), "menu"],
                            "8\ncancel\n\nq\n")
        self.assertEqual(code, 0)
        self.assertIn("Canceled: no action started", raw)
        self.assertIn("Press Enter to return to the menu", raw)
        self.assertFalse(state.exists())


class BootstrapUXTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a = BOOTSTRAP.index("bootstrap_finish_with_menu() {\n")
        b = BOOTSTRAP.index("\n}\n", a) + len("\n}\n")
        cls.finalizer = BOOTSTRAP[a:b]
        a = BOOTSTRAP.index("\nset --\nif [ -n \"$url\" ]; then")
        b = BOOTSTRAP.index("\nif [ \"$#\" -gt 0 ]; then", a)
        cls.prerequisites = BOOTSTRAP[a:b]
        a = BOOTSTRAP.index('\nif [ "$#" -gt 0 ]; then', b)
        b = BOOTSTRAP.index('\nif [ -n "$url" ]; then\n command -v curl', a)
        cls.apt_transaction = BOOTSTRAP[a:b]

    def test_only_missing_installed_capabilities_are_selected(self):
        cases = (
            ("online", "no", "", []),
            ("online", "no", "curl", ["curl"]),
            ("local", "no", "curl", []),
            ("local", "no", "nft ip", ["nftables", "iproute2"]),
            ("online", "no", "curl python3 nft ip", ["curl", "python3", "nftables", "iproute2"]),
            ("local", "no", "curl python3 nft ip", ["python3", "nftables", "iproute2"]),
            ("local", "yes", "curl python3 nft ip", ["python3"]),
        )
        for source, verify_only, missing, expected in cases:
            with self.subTest(source=source, verify_only=verify_only, missing=missing):
                url = 'http://127.0.0.1:1/' if source == 'online' else ''
                program = ("set -eu\n" + "SC_MISSING=' " + missing + " '\n" +
                           'url=' + repr(url) + "\nverify_only=" + verify_only +
                           "\nauthenticated=integrity\n" +
                           "command() { [ \"$1\" = -v ] || return 1; " +
                           "case \"$SC_MISSING\" in *\" $2 \"*) return 1;; *) return 0;; esac; }\n" +
                           self.prerequisites + "\nprintf 'ARG:%s\\n' \"$@\"\n")
                result = subprocess.run(["/bin/sh", "-c", program], text=True,
                                        capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = [] if result.stdout.strip() == "ARG:" else [x[4:] for x in result.stdout.splitlines()]
                self.assertEqual(actual, expected)

    def test_configured_apt_failure_gives_operator_action_and_no_install(self):
        # Exercise the exact native prerequisite APT transaction with only its
        # absolute apt command replaced by a recording function. No actual APT.
        transaction = self.apt_transaction.replace('DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get',
                                                     'DEBIAN_FRONTEND=noninteractive qa_apt')
        for stage, expect_calls in (("success", 2), ("update", 1), ("install", 2),
                                    ("verify_only", 0), ("apt_missing", 0)):
            with self.subTest(stage=stage):
                with tempfile.TemporaryDirectory(prefix='sc-apt-mirror-') as temp:
                    marker = Path(temp) / 'apt-calls'
                    code = ("set -eu\n"
                            + 'verify_only=' + ('yes' if stage == 'verify_only' else 'no') + '\n'
                            + "set -- python3 nftables iproute2\n"
                            + "bootstrap_read_os_version() { printf '13\\n'; }\n"
                            + "qa_apt() { printf '%s\\n' \"$*\" >> " + repr(str(marker)) + "; "
                            + "case '" + stage + "' in "
                            + "update) case \"$*\" in *' update') return 23;; esac;; "
                            + "install) case \"$*\" in *' install -y --no-remove --no-install-recommends python3 nftables iproute2') return 24;; esac;; "
                            + "esac; return 0; }\n")
                    step = transaction
                    if stage == 'apt_missing':
                        step = step.replace('[ -x /usr/bin/apt-get ] ||', 'false ||')
                    result = subprocess.run(['/bin/sh', '-c', code + step], text=True,
                                            capture_output=True, timeout=5)
                    calls = marker.read_text().splitlines() if marker.exists() else []
                    self.assertEqual(len(calls), expect_calls, (result.stdout, result.stderr))
                    if stage == 'success':
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(calls[0].endswith('update'))
                        self.assertTrue(calls[1].endswith('install -y --no-remove --no-install-recommends python3 nftables iproute2'))
                    else:
                        self.assertNotEqual(result.returncode, 0, (stage, result.stderr))
                        if stage == 'update':
                            self.assertIn('Cannot refresh existing Debian APT sources', result.stderr)
                        elif stage == 'install':
                            self.assertIn('APT could not install missing packages', result.stderr)
                        elif stage == 'verify_only':
                            self.assertIn('--verify-only never installs packages', result.stderr)
                        elif stage == 'apt_missing':
                            self.assertIn('Native Debian APT is unavailable', result.stderr)
                        self.assertIn('python3 nftables iproute2', result.stderr)

    def test_documented_outer_https_fetch_installs_only_missing_tools(self):
        docs = (ROOT / "docs/OFFLINE-DISTRIBUTION.md").read_text()
        first = docs.index('  fetch_missing=""\n')
        last = docs.index('  bootstrap=$(mktemp ', first)
        fragment = docs[first:last]
        self.assertIn('/usr/bin/apt-get', fragment)
        # Replace only the package-manager invocation with a recording fake.
        # This checks the exact documented pre-fetch branch without any APT or
        # network effect on the runner or user's host.
        fragment = fragment.replace('/usr/bin/apt-get -o', 'mock_apt -o')
        for absent_curl, absent_ca, bad_cpu, packages in (
            (False, False, False, []),
            (True, False, False, ['curl']),
            (False, True, False, ['ca-certificates']),
            (True, True, False, ['curl', 'ca-certificates']),
            (True, False, True, []),
        ):
            with self.subTest(absent_curl=absent_curl, absent_ca=absent_ca, bad_cpu=bad_cpu):
                with tempfile.TemporaryDirectory(prefix='sc-outer-deps-') as temp:
                    marker = Path(temp) / 'apt-operations'
                    fixture = fragment
                    if absent_ca:
                        fixture = fixture.replace('/etc/ssl/certs/ca-certificates.crt',
                                                  str(Path(temp) / 'missing-ca'))
                    if bad_cpu:
                        fixture = fixture.replace('$(/usr/bin/uname -m)', '$(printf aarch64)')
                    entry = 'set -eu\n'
                    if absent_curl:
                        entry += 'command() { if [ "$1" = -v ] && [ "$2" = curl ]; then return 1; fi; type "$2" >/dev/null 2>&1; }\n'
                    entry += ('mock_apt() { printf "%s\n" "$*" >> "' + str(marker) + '"; }\n'
                              + fixture + '\n')
                    result = subprocess.run(['/bin/sh', '-c', entry], text=True,
                                            capture_output=True, timeout=5)
                    if bad_cpu:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(marker.exists(), 'unsupported CPU ran host APT')
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if not packages:
                        self.assertFalse(marker.exists(), 'existing packages caused APT update')
                        continue
                    lines = marker.read_text().splitlines()
                    self.assertEqual(len(lines), 2)
                    self.assertTrue(lines[0].endswith('update'))
                    self.assertIn('install -y --no-remove --no-install-recommends ', lines[1])
                    self.assertEqual(lines[1].split('--no-install-recommends ', 1)[1].split(), packages)

    def test_post_install_opens_only_in_pty_and_can_be_disabled(self):
        with tempfile.TemporaryDirectory(prefix="sc-ux-post-install-") as base:
            marker = Path(base) / "entered"
            fake = Path(base) / "server-connect"
            fake.write_text("#!/bin/sh\n[ \"$1\" = menu ] || exit 19\n"
                            + "printf entered > '" + str(marker) + "'\n"
                            + "read answer\n[ \"$answer\" = q ]\n")
            fake.chmod(0o700)
            helper = self.finalizer.replace("/opt/server-connect/current/bin/server-connect", str(fake))
            for auto_menu, term, is_pty, should_open in (("yes", "xterm", True, True),
                                                        ("no", "xterm", True, False),
                                                        ("yes", "dumb", True, False),
                                                        ("yes", "xterm", False, False)):
                with self.subTest(auto_menu=auto_menu, term=term, is_pty=is_pty):
                    marker.unlink(missing_ok=True)
                    script = "set -eu\nauto_menu=" + auto_menu + "\n" + helper + "\nbootstrap_finish_with_menu\n"
                    if is_pty:
                        out, code = run_pty(["/bin/sh", "-c", script], "q\n", term=term)
                    else:
                        result = subprocess.run(["/bin/sh", "-c", script], text=True,
                                                capture_output=True, timeout=5,
                                                env={**os.environ, "TERM": term})
                        out, code = result.stdout + result.stderr, result.returncode
                    self.assertEqual(code, 0, out)
                    self.assertEqual(marker.exists(), should_open)
                    self.assertIn("Opening Server Connect" if should_open else "Open the menu with", out)


if __name__ == "__main__":
    unittest.main()
