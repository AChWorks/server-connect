#!/usr/bin/env python3
"""Executable rootless checks for the actual isolated NOTRACK QA evidence.

Only AST-extracted socket/parser fragments and trusted Python startup probes
execute here. No unshare, ip, nft, sysctl, real socket or field-script entrypoint
is invoked. Synthetic incomplete evidence must never become a native PASS.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
QA = ROOT / "scripts" / "qa"
HELPERS = (
    "field-notrack-drain-transition.sh",
    "field-notrack-inherited-mark.sh",
    "field-notrack-session-preservation.sh",
)


def python_blocks(name):
    source = (QA / name).read_text()
    blocks = []
    for match in re.finditer(r"(?m)^([^\n]*python3[^\n]*)<<'PY'\n", source):
        end = re.search(r"(?m)^PY$", source[match.end():])
        if end is None:
            raise AssertionError("unterminated QA Python heredoc")
        body = source[match.end():match.end() + end.start()]
        blocks.append((match.group(1).strip(), body))
    return blocks


def negative_fragments(name):
    fragments = []
    for _, body in python_blocks(name):
        tree = ast.parse(body)
        for parent in ast.walk(tree):
            for _, items in ast.iter_fields(parent):
                if not isinstance(items, list):
                    continue
                for index, node in enumerate(items[:-1]):
                    if not isinstance(node, ast.Try) or not isinstance(items[index + 1], ast.Assert):
                        continue
                    calls = [part for part in ast.walk(node)
                             if isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute)
                             and part.func.attr == "recv"]
                    if len(calls) == 1:
                        fragment = ast.fix_missing_locations(
                            ast.Module(body=[node, items[index + 1]], type_ignores=[]))
                        fragments.append(compile(fragment, name, "exec"))
    return fragments


class ReceiveWitness:
    def __init__(self, payload):
        self.payload = payload

    def recv(self, size):
        if self.payload is None:
            raise socket.timeout("independent receiver timeout")
        return self.payload[:size]


class FakeSocket:
    def __init__(self, fixture, role):
        self.fixture, self.role = fixture, role
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        self.closed = True

    def settimeout(self, value):
        pass

    def bind(self, address):
        pass

    def listen(self, size):
        pass

    def connect(self, address):
        pass

    def accept(self):
        return FakeSocket(self.fixture, "accepted"), ("127.0.0.1", 40001)

    def getsockopt(self, *unused):
        return self.fixture.mark

    def sendall(self, payload):
        pass

    def recv(self, size):
        return (b"hi" if self.role == "accepted" else self.fixture.reply)[:size]


class SocketFixture:
    def __init__(self, mark, reply):
        self.mark, self.reply = mark, reply
        self.created = 0

    def socket(self, *unused):
        role = "server" if self.created == 0 else "client"
        self.created += 1
        return FakeSocket(self, role)


def diag_message(kind=20, flags=2, payload=None, sequence=1, pid=777):
    if payload is None:
        row = bytearray(80)
        row[0], row[1] = socket.AF_INET, 1
        struct.pack_into("!HH", row, 4, 28993, 40001)
        struct.pack_into("=II", row, 44, 101, 202)
        struct.pack_into("=I", row, 68, 1234)
        struct.pack_into("=HHI", row, 72, 8, 15, 0x00540000)
        payload = bytes(row)
    result = struct.pack("=IHHII", 16 + len(payload), kind, flags, sequence, pid) + payload
    return result + b"\0" * ((-len(result)) % 4)


def diag_done(flags=2, error=0):
    return diag_message(kind=3, flags=flags, payload=struct.pack("=i", error))


class DiagnosticSocket:
    def __init__(self, datagrams):
        self.datagrams = list(datagrams)
        self.closed = False

    def settimeout(self, value):
        pass

    def bind(self, address):
        pass

    def getsockname(self):
        return (777, 0)

    def sendto(self, request, destination):
        if len(request) != 72 or destination != (0, 0):
            raise AssertionError("unexpected diagnostic request")

    def recvmsg(self, size):
        if not self.datagrams:
            raise socket.timeout("incomplete diagnostic dump")
        data, flags, peer = self.datagrams.pop(0)
        return data, [], flags, peer

    def close(self):
        self.closed = True


class NotrackEvidenceTests(unittest.TestCase):
    def test_any_observed_negative_payload_or_eof_is_rejected(self):
        total = 0
        for name in ("field-notrack-drain-transition.sh", "field-notrack-session-preservation.sh"):
            fragments = negative_fragments(name)
            self.assertEqual(len(fragments), 3 if "drain" in name else 1)
            for index, fragment in enumerate(fragments):
                for payload in (b"c", b"X", b"", b"outbound-prefix"):
                    with self.subTest(helper=name, negative=index, payload=payload):
                        peer = ReceiveWitness(payload)
                        namespace = {
                            "socket": socket, "client": peer, "remote_accepted": peer,
                            "bad_client": peer, "other_client": peer,
                            "packets": lambda _: 1, "count": lambda _: 1, "chain": "fixture",
                        }
                        with self.assertRaises(AssertionError):
                            exec(fragment, namespace)
                total += 1
        self.assertEqual(total, 4)

    def test_actual_negative_timeout_remains_accepted(self):
        for name in ("field-notrack-drain-transition.sh", "field-notrack-session-preservation.sh"):
            for fragment in negative_fragments(name):
                peer = ReceiveWitness(None)
                exec(fragment, {
                    "socket": socket, "client": peer, "remote_accepted": peer,
                    "bad_client": peer, "other_client": peer,
                    "packets": lambda _: 1, "count": lambda _: 1, "chain": "fixture",
                })

    def inherited_exchange(self, index, reply):
        header, body = python_blocks("field-notrack-inherited-mark.sh")[index]
        args = shlex.split(header)
        arguments = args[args.index("-") + 1:]
        self.assertEqual(len(arguments), 2)
        fixture = SocketFixture(int(arguments[1]), reply)
        output = io.StringIO()
        with mock.patch.object(socket, "socket", fixture.socket), \
                mock.patch.object(sys, "argv", ["-"] + arguments), \
                mock.patch.object(threading, "excepthook", lambda _: None), \
                contextlib.redirect_stdout(output):
            exec(compile(body, "inherited-exchange", "exec"), {"__name__": "fixture"})
        return output.getvalue()

    def test_client_reply_failure_reaches_the_main_test(self):
        self.assertEqual(len(python_blocks("field-notrack-inherited-mark.sh")), 2)
        for index in (0, 1):
            with self.subTest(exchange=index):
                with self.assertRaises(AssertionError):
                    self.inherited_exchange(index, b"NO")

    def test_client_positive_exchange_still_reaches_pass(self):
        for index in (0, 1):
            self.assertIn("=PASS", self.inherited_exchange(index, b"ok"))

    def inspect_dump(self, datagrams):
        body = python_blocks("field-notrack-drain-transition.sh")[0][1]
        tree = ast.parse(body)
        functions = [node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == "kernel_socket_marks"]
        self.assertEqual(len(functions), 1)
        diagnostic = DiagnosticSocket(datagrams)
        fake_socket = types.SimpleNamespace(
            socket=lambda *unused: diagnostic, AF_NETLINK=socket.AF_NETLINK,
            SOCK_RAW=socket.SOCK_RAW, AF_INET=socket.AF_INET, IPPROTO_TCP=socket.IPPROTO_TCP,
            MSG_TRUNC=socket.MSG_TRUNC,
        )
        namespace = {"socket": fake_socket, "struct": struct}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "inet-diag-fragment", "exec"), namespace)
        try:
            return namespace["kernel_socket_marks"]()
        finally:
            self.assertTrue(diagnostic.closed, "diagnostic descriptor leaked")

    def test_complete_kernel_dump_keeps_cookie_inode_and_mark(self):
        result = self.inspect_dump([(diag_message() + diag_done(), 0, (0, 0))])
        self.assertEqual(result, {40001: (1234, (202 << 32) | 101, 0x00540000)})
        self.assertEqual(self.inspect_dump([(diag_done(), 0, (0, 0))]), {})

    def test_interrupted_data_or_done_dump_is_refused(self):
        for packets in (
            [(diag_message(flags=2 | 0x10), 0, (0, 0)), (diag_done(), 0, (0, 0))],
            [(diag_message(), 0, (0, 0)), (diag_done(flags=2 | 0x10), 0, (0, 0))],
        ):
            with self.subTest(interrupted=packets[0][0][:16]):
                with self.assertRaises(AssertionError):
                    self.inspect_dump(packets)

    def test_done_cannot_hide_later_errors_or_records(self):
        for suffix in (diag_message(kind=4, payload=b""), diag_message(), b"truncated"):
            with self.subTest(suffix=suffix[:16]):
                with self.assertRaises(AssertionError):
                    self.inspect_dump([(diag_message() + diag_done() + suffix, 0, (0, 0))])

    def test_existing_incomplete_malformed_and_foreign_dump_refusals_remain(self):
        cases = (
            [(diag_message(), socket.MSG_TRUNC, (0, 0))],
            [(diag_message(sequence=2) + diag_done(), 0, (0, 0))],
            [(diag_message() + diag_done(), 0, (5, 0))],
            [(diag_message() + diag_message() + diag_done(), 0, (0, 0))],
            [(diag_message() + diag_done(error=-4), 0, (0, 0))],
            [(diag_message(kind=4, payload=b""), 0, (0, 0))],
            [(b"truncated", 0, (0, 0))],
            [(diag_message(), 0, (0, 0))],
        )
        for index, packets in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises((AssertionError, socket.timeout)):
                    self.inspect_dump(packets)

    def test_namespace_observation_failure_never_admits_mutation(self):
        source = (QA / "field-notrack-inherited-mark.sh").read_text()
        inner = source.split("unshare -n /bin/bash <<'GUEST'\n", 1)[1]
        gate = inner.split("ip link set lo up\n", 1)[0]
        fake_readlink = """
readlink() {
    if [[ "$1" == /proc/1/ns/net ]]; then
        printf '%s\\n' "$TEST_PARENT_NS"
        return "$TEST_PARENT_FAILURE"
    fi
    if [[ "$1" == /proc/self/ns/net ]]; then
        printf '%s\\n' "$TEST_SELF_NS"
        return "$TEST_SELF_FAILURE"
    fi
    return 99
}
"""
        for parent, current, parent_failure, current_failure, admitted in (
            ("net:[123]", "net:[124]", 0, 0, True),
            ("net:[123]", "net:[123]", 0, 0, False),
            ("", "net:[124]", 1, 0, False),
            ("net:[123]", "", 0, 1, False),
            ("net:[123]", "net:[124]", 1, 0, False),
            ("net:[123]", "net:[124]", 0, 1, False),
            ("unknown", "net:[124]", 0, 0, False),
            ("net:[123]", "unknown", 0, 0, False),
        ):
            with self.subTest(parent=parent, current=current,
                              parent_failure=parent_failure, current_failure=current_failure):
                result = subprocess.run(
                    ["/bin/bash", "--noprofile", "--norc", "-c",
                     fake_readlink + gate + "\necho NAMESPACE_ADMITTED\n"],
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                         "TEST_PARENT_NS": parent, "TEST_SELF_NS": current,
                         "TEST_PARENT_FAILURE": str(parent_failure),
                         "TEST_SELF_FAILURE": str(current_failure)},
                    text=True, capture_output=True, timeout=5,
                )
                self.assertEqual(result.returncode == 0, admitted, result.stderr)
                self.assertEqual("NAMESPACE_ADMITTED" in result.stdout, admitted)

    def test_python_entrypoints_ignore_optimization_and_startup_modules(self):
        with tempfile.TemporaryDirectory(prefix="sc-notrack-startup-") as directory:
            temporary = Path(directory)
            marker = temporary / "UNTRUSTED_STARTUP"
            attack = temporary / "attack"
            attack.mkdir()
            attack_code = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n"
            (attack / "sitecustomize.py").write_text(attack_code)
            user_site = temporary / "userbase" / "lib" / (
                f"python{sys.version_info.major}.{sys.version_info.minor}") / "site-packages"
            user_site.mkdir(parents=True)
            (user_site / "usercustomize.py").write_text(attack_code)
            for name in HELPERS:
                source = (QA / name).read_text()
                headers = [header for header, _ in python_blocks(name)]
                # Include the inherited helper's final pipe-to-python witness.
                headers += [line.split(" -c ", 1)[0] + " -c" for line in source.splitlines()
                            if re.search(r"\|\s+(?:/usr/bin/)?python3\b.* -c ", line)]
                self.assertEqual(len(headers), 3 if "inherited" in name else 1)
                for index, header in enumerate(headers):
                    with self.subTest(helper=name, entry=index):
                        words = shlex.split(header)
                        python_index = next(i for i, word in enumerate(words)
                                            if Path(word).name == "python3")
                        flags = []
                        for word in words[python_index + 1:]:
                            if word in ("-", "-c"):
                                break
                            flags.append(word)
                        environment = dict(
                            os.environ, PYTHONOPTIMIZE="1", PYTHONPATH=str(attack),
                            PYTHONUSERBASE=str(temporary / "userbase"), HOME=str(temporary),
                        )
                        for line in source.splitlines():
                            if line.startswith("unset "):
                                for variable in shlex.split(line)[1:]:
                                    environment.pop(variable, None)
                        marker.unlink(missing_ok=True)
                        result = subprocess.run(
                            ["/usr/bin/python3", *flags, "-c",
                             "import sys; print(sys.flags.optimize, sys.flags.isolated, sys.flags.no_site)"],
                            env=environment, capture_output=True, text=True, timeout=5,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), "0 1 1")
                        self.assertFalse(marker.exists(), "untrusted Python startup code ran")


if __name__ == "__main__":
    unittest.main(verbosity=2)
