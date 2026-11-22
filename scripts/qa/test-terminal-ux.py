#!/usr/bin/env python3
"""Nonprivileged PTY and bootstrap finalization tests; no install, APT or network."""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import pty
import re
import shlex
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
        docs = (ROOT / "docs/OFFLINE-DISTRIBUTION.md").read_text()
        blocks = re.findall(r"```sh\n(.*?)\n```", docs, re.S)
        cls.prefetch_blocks = []
        for command in blocks[:2]:
            start = command.index("  # Pre-bootstrap curl/CA acquisition:")
            end = command.index("  bootstrap=$(mktemp ", start)
            cls.prefetch_blocks.append(command[start:end])
        assert len(cls.prefetch_blocks) == 2
        assert cls.prefetch_blocks[0] == cls.prefetch_blocks[1], (
            "Official and Mirror must have identical prefetch trust/APT handling")

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

    def run_prefetch_fixture(self, block, *, missing_curl=False, missing_ca=False,
                             symlink=False, relative_link=False, unsafe_link=False, unsafe_mode=False,
                             unsafe_owner=False, invalid_os=False, unsupported_arch=False,
                             apt_stage="success", apt_available=True):
        with tempfile.TemporaryDirectory(prefix="sc-outer-fetch-") as temp:
            root = Path(temp)
            (root / "etc").mkdir()
            (root / "usr" / "lib").mkdir(parents=True)
            etc_os, usr_os = root / "etc" / "os-release", root / "usr" / "lib" / "os-release"
            os_text = ("ID=ubuntu\nVERSION_ID=13\n" if invalid_os
                       else "ID=debian\nVERSION_ID=\"13\"\n")
            usr_os.write_text(os_text)
            if symlink:
                if unsafe_link:
                    alien = root / "foreign-os-release"
                    alien.write_text(os_text)
                    etc_os.symlink_to(alien)
                else:
                    etc_os.symlink_to("../usr/lib/os-release" if relative_link else usr_os)
            else:
                etc_os.write_text(os_text)
            if unsafe_mode:
                (usr_os if symlink else etc_os).chmod(0o666)
            marker = root / "apt.log"
            fragment = (block.replace("/etc/os-release", str(etc_os))
                              .replace("/usr/lib/os-release", str(usr_os))
                              .replace(".." + str(usr_os), "../usr/lib/os-release")
                              .replace("/usr/bin/stat", "fixture_stat")
                              .replace("/usr/bin/apt-get", "fixture_apt"))
            # Fixture root ownership can be modeled without root or writing
            # system metadata. Preserve actual mode and inode checks.
            spoof_uid = "no" if unsafe_owner else "yes"
            entry = ("set -eu\n"
                     + "SC_TMP=" + shlex.quote(temp) + "\n"
                     + "SC_MARKER=" + shlex.quote(str(marker)) + "\n"
                     + "SC_SPOOF_UID=" + spoof_uid + "\n"
                     + "fixture_stat() {\n"
                     + "  if [ \"$1\" = -c ] && [ \"$2\" = %u ] && [ \"${4#\"$SC_TMP\"}\" != \"$4\" ] && [ \"$SC_SPOOF_UID\" = yes ]; then\n"
                     + "    printf '0\\n'; return 0\n"
                     + "  fi\n"
                     + "  /usr/bin/stat \"$@\"\n"
                     + "}\n"
                     + "fixture_apt() {\n"
                     + "  printf '%s\\n' \"$*\" >> \"$SC_MARKER\"\n"
                     + "  case \"$*\" in\n"
                     + "    *' update') [ \"$SC_APT_STAGE\" = update ] && { echo 'SIMULATED APT UPDATE ERROR' >&2; return 91; };;\n"
                     + "    *' install -y --no-remove --no-install-recommends '*) [ \"$SC_APT_STAGE\" = install ] && { echo 'SIMULATED APT INSTALL ERROR' >&2; return 92; };;\n"
                     + "  esac\n"
                     + "  return 0\n"
                     + "}\n"
                     + "SC_APT_STAGE=" + apt_stage + "\n")
            if missing_curl:
                entry += ("command() { [ \"$1\" = -v ] || return 1; "
                          "[ \"$2\" != curl ] && type \"$2\" >/dev/null 2>&1; }\n")
            if missing_ca:
                fragment = fragment.replace("/etc/ssl/certs/ca-certificates.crt", str(root / "absent-ca"))
            if unsupported_arch:
                fragment = fragment.replace("$(/usr/bin/uname -m)", "$(printf aarch64)")
            if not apt_available:
                fragment = fragment.replace("[ -x fixture_apt ]", "false")
            else:
                fragment = fragment.replace("[ -x fixture_apt ]", "true")
            result = subprocess.run(["/bin/sh", "-c", entry + fragment],
                                    text=True, capture_output=True, timeout=5)
            return result, marker.read_text().splitlines() if marker.exists() else []

    def test_documented_outer_https_fetch_installs_only_missing_tools(self):
        for channel, fragment in enumerate(self.prefetch_blocks):
            for miss_curl, miss_ca, packages in (
                (False, False, []), (True, False, ["curl"]),
                (False, True, ["ca-certificates"]),
                (True, True, ["curl", "ca-certificates"]),
            ):
                with self.subTest(channel=channel, miss_curl=miss_curl, miss_ca=miss_ca):
                    result, calls = self.run_prefetch_fixture(fragment, missing_curl=miss_curl,
                                                              missing_ca=miss_ca)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(calls), 2 if packages else 0)
                    if packages:
                        self.assertTrue(calls[0].endswith("update"))
                        self.assertEqual(calls[1].split("--no-install-recommends ", 1)[1].split(), packages)

    def test_documented_prefetch_valid_os_paths_and_negative_trust_before_apt(self):
        for channel, fragment in enumerate(self.prefetch_blocks):
            for setup in ({}, {"symlink": True}, {"symlink": True, "relative_link": True},
                          {"unsafe_link": True, "symlink": True},
                          {"unsafe_mode": True}, {"unsafe_mode": True, "symlink": True},
                          {"unsafe_owner": True}, {"invalid_os": True},
                          {"unsupported_arch": True}):
                with self.subTest(channel=channel, setup=setup):
                    result, calls = self.run_prefetch_fixture(fragment, missing_curl=True, **setup)
                    should_pass = setup in ({}, {"symlink": True},
                                            {"symlink": True, "relative_link": True})
                    self.assertEqual(result.returncode == 0, should_pass, result.stderr)
                    self.assertEqual(len(calls), 2 if should_pass else 0)
                    if not should_pass:
                        self.assertIn("No APT or Server Connect bootstrap executed", result.stderr)

    def test_documented_prefetch_apt_failures_are_actionable(self):
        for channel, fragment in enumerate(self.prefetch_blocks):
            for stage, expected_calls, expected_error in (
                ("success", 2, ""), ("update", 1, "APT index update failed"),
                ("install", 2, "APT installation failed"),
                ("missing", 0, "Native APT is unavailable"),
            ):
                with self.subTest(channel=channel, stage=stage):
                    result, calls = self.run_prefetch_fixture(fragment, missing_curl=True,
                                                              missing_ca=True, apt_stage=stage,
                                                              apt_available=stage != "missing")
                    self.assertEqual(len(calls), expected_calls, result.stderr)
                    if stage != "success":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(expected_error, result.stderr)
                        self.assertIn("curl ca-certificates", result.stderr)
                        self.assertIn("Server Connect bootstrap was not executed", result.stderr)
                        self.assertIn("trusted Debian mirror", result.stderr)
                        if stage in ("update", "install"):
                            self.assertIn("SIMULATED APT", result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_menu_failure_after_install_does_not_fail_bootstrap(self):
        with tempfile.TemporaryDirectory(prefix="sc-menu-failure-") as base:
            fake = Path(base) / "server-connect"
            fake.write_text("#!/bin/sh\nexit 19\n")
            fake.chmod(0o700)
            helper = self.finalizer.replace("/opt/server-connect/current/bin/server-connect", str(fake))
            raw, code = run_pty(["/bin/sh", "-c", "set -eu\nauto_menu=yes\n" +
                                 helper + "\nbootstrap_finish_with_menu\n"], "", term="xterm")
            self.assertEqual(code, 0)
            self.assertIn("Installation completed. Opening Server Connect", raw)
            self.assertIn("Open the menu with: sudo server-connect", raw)

    def test_tty_stdout_without_controlling_tty_preserves_success(self):
        # A PTY slave bound to stdout is not necessarily a controlling TTY.
        # Under set -e an unguarded /dev/tty redirect used to report a
        # *completed* install as failed. Test the actual documented shape.
        with tempfile.TemporaryDirectory(prefix="sc-no-controlling-tty-") as base:
            marker = Path(base) / "menu-ran"
            fake = Path(base) / "server-connect"
            fake.write_text("#!/bin/sh\nprintf triggered > " + repr(str(marker)) + "\n")
            fake.chmod(0o700)
            helper = self.finalizer.replace("/opt/server-connect/current/bin/server-connect", str(fake))
            shell = "set -eu\nauto_menu=yes\n" + helper + "\nbootstrap_finish_with_menu\n"
            master, slave = pty.openpty()
            try:
                # start_new_session detaches the child from our controlling
                # terminal, but preserves a TTY on its stdout fd.
                result = subprocess.run(["/bin/sh", "-c", shell], stdin=subprocess.DEVNULL,
                                        stdout=slave, stderr=subprocess.PIPE,
                                        start_new_session=True,
                                        text=True, timeout=5,
                                        env={**os.environ, "TERM": "xterm-256color"})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Open the menu with: sudo server-connect", result.stderr)
                self.assertFalse(marker.exists(), "menu started with no controlling TTY")
            finally:
                os.close(slave)
                os.close(master)

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
