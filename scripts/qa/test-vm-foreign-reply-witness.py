#!/usr/bin/env python3
"""Unprivileged negative and protocol regressions for vm-foreign-reply-witness.

The real named VETH/SSH/HTTP/route exercise is a separate authorized VM test.
No kernel namespaces, firewall, routes, privileged ports or SSH daemon are
changed by this unit test.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import os
import time
from types import SimpleNamespace
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch


MODULE = Path(__file__).with_name("vm-foreign-reply-witness.py")
spec = importlib.util.spec_from_file_location("vm_foreign_reply_witness", MODULE)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class VMForeignReplyWitnessTests(unittest.TestCase):
    def proc_row(self, source=w.PEER_IP, dest=w.ROOT_IP, port=19123,
                 inode=4442, state="01"):
        ip = lambda raw: socket.inet_aton(raw)[::-1].hex().upper()
        return ("   0: "+ip(source)+":AA11 "+ip(dest)+":"+f"{port:04X}"+
                " "+state+" 00000000:00000000 00:00000000 00000000 1000 0 "+str(inode)+" 1 000000 100 0 0 10 0")

    def proc_text(self, *rows):
        return "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + "\n".join(rows)

    def test_exact_client_ssh_fd_identity_and_refusals(self):
        valid = self.proc_row()
        self.assertEqual(w.find_ssh_inode(self.proc_text(valid), {4442}, 19123), 4442)
        negatives = [
            (self.proc_text(valid), {4443}, 19123),
            (self.proc_text(self.proc_row(source="198.51.100.8")), {4442}, 19123),
            (self.proc_text(self.proc_row(dest="198.51.100.8")), {4442}, 19123),
            (self.proc_text(self.proc_row(port=1234)), {4442}, 19123),
            (self.proc_text(self.proc_row(state="02")), {4442}, 19123),
            (self.proc_text(self.proc_row(inode=4442), self.proc_row(inode=4443)), {4442, 4443}, 19123),
            (self.proc_text("malformed"), {4442}, 19123),
            (self.proc_text(), {4442}, 19123),
        ]
        for text, fds, port in negatives:
            with self.subTest(text=text[-70:], fds=fds):
                with self.assertRaises(w.WitnessError):
                    w.find_ssh_inode(text, fds, port)

    def test_persistent_transport_real_process_nonce_and_interruption(self):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", w.REMOTE_LOOP],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
        try:
            with patch.object(w, "ssh_socket_inode", return_value=4442) as inode:
                self.assertEqual(w.original_ssh_round(process, 19123, None), 4442)
                self.assertEqual(w.original_ssh_round(process, 19123, 4442), 4442)
                self.assertEqual(inode.call_count, 4)
                with self.assertRaisesRegex(w.WitnessError, "original_ssh_socket_changed"):
                    w.original_ssh_round(process, 19123, 4443)
            with patch.object(w, "ssh_socket_inode", return_value=4442):
                real_line = w.bounded_line
                with patch.object(w, "bounded_line", side_effect=lambda fd: real_line(fd)+"_tampered"):
                    with self.assertRaisesRegex(w.WitnessError, "original_ssh_nonce_mismatch"):
                        w.original_ssh_round(process, 19123, 4442)
                with patch.object(w, "ssh_socket_inode", side_effect=[4442, 4552]):
                    with self.assertRaisesRegex(w.WitnessError, "original_ssh_transport_changed"):
                        w.original_ssh_round(process, 19123, 4442)
            process.terminate()
            process.wait(timeout=2)
            with patch.object(w, "ssh_socket_inode", return_value=4442):
                with self.assertRaisesRegex(w.WitnessError, "original_ssh_exited"):
                    w.original_ssh_round(process, 19123, 4442)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe:
                    pipe.close()

    def test_initial_ssh_socket_race_waits_only_for_real_first_connection(self):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", w.REMOTE_LOOP],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
        try:
            missing = w.WitnessError("ssh_transport_identity_missing")
            with (patch.object(w, "ssh_socket_inode", side_effect=[missing, missing, 4442, 4442]) as probe,
                  patch.object(w.time, "sleep") as delay):
                self.assertEqual(w.original_ssh_round(process, 19123, None), 4442)
                self.assertEqual(probe.call_count, 4)
                self.assertEqual(delay.call_count, 2)
            # Once a baseline transport is known, a missing socket must
            # immediately fail rather than wait and accidentally accept a new one.
            with patch.object(w, "ssh_socket_inode", side_effect=missing) as probe:
                with self.assertRaisesRegex(w.WitnessError, "ssh_transport_identity_missing"):
                    w.original_ssh_round(process, 19123, 4442)
                self.assertEqual(probe.call_count, 1)
            with patch.object(w, "ssh_socket_inode", side_effect=w.WitnessError("ssh_transport_identity_ambiguous")) as probe:
                with self.assertRaisesRegex(w.WitnessError, "ssh_transport_identity_ambiguous"):
                    w.original_ssh_round(process, 19123, None)
                self.assertEqual(probe.call_count, 1)
            with (patch.object(w, "ssh_socket_inode", side_effect=missing),
                  patch.object(w.time, "monotonic", side_effect=[10.0, 16.5]),
                  patch.object(w.time, "sleep")):
                with self.assertRaisesRegex(w.WitnessError, "original_ssh_connection_timeout"):
                    w.original_ssh_round(process, 19123, None)
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe: pipe.close()

    def test_replayed_or_malformed_remote_command_is_rejected(self):
        good = secrets.token_hex(16)
        ok = subprocess.run([sys.executable, "-u", "-c", w.REMOTE_LOOP],
                            input=(good+"\n").encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(ok.stdout, ("SCQA_SSH1 "+good+"\n").encode())
        bad = subprocess.run([sys.executable, "-u", "-c", w.REMOTE_LOOP],
                             input=b"not-a-nonce\n", stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(bad.returncode, 7)
        self.assertEqual(bad.stdout, b"")

    def test_http_origin_rejects_wrong_source_and_nonce(self):
        def request(source, path):
            h = w.Origin.__new__(w.Origin)
            h.client_address = (source, 30001)
            h.path = path
            h.wfile = io.BytesIO()
            h.send_response = MagicMock()
            h.send_header = MagicMock()
            h.end_headers = MagicMock()
            h.send_error = MagicMock()
            h.do_GET()
            return h
        nonce = secrets.token_hex(16)
        valid = request(w.PEER_IP, "/witness/"+nonce)
        valid.send_response.assert_called_once_with(200)
        self.assertEqual(valid.wfile.getvalue(), ("SCQA_HTTP1 "+nonce+" "+w.PEER_IP+"\n").encode())
        self.assertIn(("Cache-Control", "no-store"), [c.args for c in valid.send_header.call_args_list])
        for source, path in [
            ("198.51.100.9", "/witness/"+nonce),
            (w.PEER_IP, "/witness/not-hex"),
            (w.PEER_IP, "/witness/"+nonce+"extra"),
            (w.PEER_IP, "/not-witness/"+nonce),
            (w.PEER_IP, "/witness/"+nonce+"?a=b"),
        ]:
            with self.subTest(source=source, path=path):
                rejected = request(source, path)
                rejected.send_error.assert_called_once()
                rejected.send_response.assert_not_called()
                self.assertEqual(rejected.wfile.getvalue(), b"")

    def test_http_client_binds_peers_preserves_socket_and_refuses_false_success(self):
        def simulate(remote=w.ROOT_IP, local=w.PEER_IP, remote_port=19124, status=200, store="no-store",
                     false_body=False, new_socket=False, close_socket=False, version=11,
                     will_close=False):
            holder = {}
            class FakeSocket:
                def __init__(self):
                    self.real = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                def fileno(self): return self.real.fileno()
                def getpeername(self): return (remote, remote_port)
                def getsockname(self): return (local, 30001)
                def close(self): self.real.close()
            class Response:
                def __init__(self, uri):
                    self.uri = uri
                    self.status, self.version, self.will_close = status, version, will_close
                def getheader(self, key):
                    return store if key == "Cache-Control" else None
                def read(self, _):
                    token = self.uri.removeprefix("/witness/")
                    if false_body:
                        token = "a"*32 if token != "a"*32 else "b"*32
                    return ("SCQA_HTTP1 "+token+" "+w.PEER_IP+"\n").encode()
            class Connection:
                def __init__(self, _host, port, **_kwargs):
                    self.port = port
                    self.sock = FakeSocket()
                    holder["instance"] = self
                    self.old = None
                def connect(self): pass
                def request(self, method, path, headers):
                    self.method, self.path, self.headers = method, path, headers
                def getresponse(self):
                    if new_socket:
                        self.old = self.sock
                        self.sock = FakeSocket()
                    elif close_socket:
                        self.old = self.sock
                        self.sock = None
                    return Response(self.path)
                def close(self):
                    self.closed = True
                    if self.old is not None:
                        self.old.close()
                    if self.sock is not None:
                        self.sock.close()
            success = (remote == w.ROOT_IP and local == w.PEER_IP and remote_port == 19124 and status == 200 and
                       store == "no-store" and not false_body and not new_socket and
                       not close_socket and version == 11 and not will_close)
            with patch.object(w.http.client, "HTTPConnection", Connection):
                if success:
                    identity = w.http_round(19124)
                    self.assertGreater(identity[0], 0)
                    self.assertEqual(identity[1:], (30001, 19124))
                    self.assertEqual(holder["instance"].method, "GET")
                    self.assertEqual(holder["instance"].headers["Cache-Control"], "no-cache")
                else:
                    with self.assertRaises(w.WitnessError):
                        w.http_round(19124)
                self.assertTrue(holder["instance"].closed)
        simulate()
        simulate(remote="198.51.100.99")
        simulate(remote_port=19011)
        simulate(local="198.51.100.99")
        simulate(status=302)
        simulate(store="public")
        simulate(false_body=True)
        simulate(version=10)
        simulate(will_close=True)
        simulate(new_socket=True)
        simulate(close_socket=True)

    def test_original_http_rejects_closed_or_replaced_socket(self):
        class Socket:
            def __init__(self):
                self.real = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            def fileno(self): return self.real.fileno()
            def getpeername(self): return (w.ROOT_IP, 19124)
            def getsockname(self): return (w.PEER_IP, 30001)
            def close(self): self.real.close()
        class Connection:
            def __init__(self): self.sock, self.port = Socket(), 19124
            def request(self, _method, path, headers): self.path = path
            def getresponse(self):
                class R:
                    status, version, will_close = 200, 11, False
                    def getheader(self, key): return "no-store" if key == "Cache-Control" else None
                    def read(self, _):
                        return ("SCQA_HTTP1 "+self.path+" "+w.PEER_IP+"\n").encode()
                r=R()
                r.path = self.path.removeprefix("/witness/")
                return r
        c=Connection()
        try:
            initial = w.verified_http_socket(c)
            self.assertEqual(w.http_request(c, initial), initial)
            with self.assertRaisesRegex(w.WitnessError, "existing_http_socket_changed"):
                w.http_request(c, (initial[0]+1, initial[1], initial[2]))
            c.sock.close()
            c.sock = None
            with self.assertRaisesRegex(w.WitnessError, "existing_http_socket_closed"):
                w.http_request(c, initial)
        finally:
            if c.sock is not None:
                c.sock.close()

    def test_actual_unprivileged_loopback_http_keepalive_and_concurrent_fresh(self):
        # This is NOT a field test; replace TEST-NET addresses only inside the
        # unit-process reference, without creating an interface or namespace.
        with patch.object(w, "ROOT_IP", "127.0.0.1"), patch.object(w, "PEER_IP", "127.0.0.1"):
            server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            connection = w.http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            try:
                connection.connect()
                identity = w.verified_http_socket(connection)
                self.assertEqual(w.http_request(connection, identity), identity)
                self.assertEqual(w.http_request(connection, identity), identity)
                fresh = w.http_round(server.server_port)
                self.assertNotEqual(fresh, identity)
                self.assertEqual(w.http_request(connection, identity), identity)
                connection.close()
                with self.assertRaisesRegex(w.WitnessError, "existing_http_socket_closed"):
                    w.http_request(connection, identity)
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_full_staged_client_roundtrip_over_same_real_http_socket(self):
        # Exercise the real multi-phase client control flow with a real
        # concurrent HTTP server and a live local process for SSH stdin/out.
        # OpenSSH authentication/kernel topology are intentionally separate
        # privileged-guest acceptance obligations.
        with patch.object(w, "ROOT_IP", "127.0.0.1"), patch.object(w, "PEER_IP", "127.0.0.1"):
            server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                output = io.StringIO()
                ssh_port = 19123 if server.server_port != 19123 else 19122
                with tempfile.TemporaryDirectory() as temp:
                    key, known = Path(temp)/"key", Path(temp)/"known_hosts"
                    key.write_text("synthetic-key")
                    known.write_text("[127.0.0.1]:19123 ssh-ed25519 synthetic-public-key\n")
                    key.chmod(0o600)
                    known.chmod(0o600)
                    with (patch.object(w, "ssh_command", return_value=[sys.executable, "-u", "-c", w.REMOTE_LOOP]) as ssh,
                          patch.object(w, "ssh_socket_inode", return_value=4442) as identity,
                          patch.object(w, "new_ssh_round") as fresh,
                          patch.object(w, "next_phase", side_effect=["pending", "confirmed", "off"]) as transition,
                          contextlib.redirect_stdout(output)):
                        w.client(key, known, ssh_port, server.server_port)
                self.assertEqual(ssh.call_count, 1)
                frozen_key = ssh.call_args.args[0]
                self.assertNotEqual(frozen_key, key)
                self.assertFalse(frozen_key.exists(), "cleanup removes the frozen SSH key")
                self.assertEqual(identity.call_count, 8)
                self.assertEqual(fresh.call_count, 4)
                self.assertEqual(transition.call_count, 3)
                observed = output.getvalue().splitlines()
                self.assertEqual(len(observed), 5)
                stages = [json.loads(line) for line in observed[:-1]]
                self.assertEqual([s["stage"] for s in stages],
                                 ["baseline", "pending", "confirmed", "off"])
                for stage in stages:
                    self.assertEqual(stage["http_existing"], "pass")
                    self.assertEqual(stage["http_fresh"], "pass")
                    self.assertEqual(stage["ssh_existing"], "pass")
                    self.assertEqual(stage["ssh_fresh"], "pass")
                    self.assertEqual(stage["product_phase"], "not_observed")
                self.assertTrue(observed[-1].startswith("VM_INGRESS_WITNESS=PASS (NOT "))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_stage_order_is_bounded_and_no_phase_skips(self):
        allowed = {("baseline", "pending"), ("pending", "confirmed"),
                   ("pending", "off"), ("confirmed", "degraded"),
                   ("confirmed", "off"), ("degraded", "off")}
        for p in ("baseline", "pending", "confirmed", "degraded", "off", "x"):
            for n in ("baseline", "pending", "confirmed", "degraded", "off", "x"):
                self.assertEqual(w.phase_allowed(p, n), (p,n) in allowed)
        def operator_input(data, *, close=False, seconds=0.06):
            read_fd, write_fd = os.pipe()
            try:
                if data:
                    os.write(write_fd, data)
                if close:
                    os.close(write_fd)
                    write_fd = -1
                with os.fdopen(read_fd, "r") as input_stream:
                    with (patch.object(w.sys, "stdin", input_stream),
                          contextlib.redirect_stdout(io.StringIO())):
                        return w.next_phase("baseline", seconds=seconds)
            finally:
                if write_fd >= 0:
                    os.close(write_fd)
        self.assertEqual(operator_input(b"pending\n"), "pending")
        self.assertEqual(operator_input(b"pending\r\n"), "pending")
        for payload, close, reason in [
            (b"", False, "operator_phase_timeout"),
            (b"pending", False, "operator_phase_timeout"),
            (b"pending", True, "operator_phase_unexpected_eof"),
            (b"", True, "operator_phase_unexpected_eof"),
            (b"off\n", False, "operator_phase_out_of_order"),
            (b"p"*25, False, "operator_phase_label_too_long"),
            (b"pen\xffding\n", False, "operator_phase_invalid_encoding"),
            (b"pending\n", False, None),
        ]:
            if reason is None:
                continue
            with self.subTest(payload=payload, close=close):
                began = time.monotonic()
                with self.assertRaisesRegex(w.WitnessError, reason):
                    operator_input(payload, close=close)
                self.assertLess(time.monotonic() - began, 1.5,
                                "partial operator input escaped the deadline")

    def test_pinned_ssh_host_no_proxy_and_safe_key_permissions(self):
        args = w.ssh_command(Path("/tmp/qa-key"), Path("/tmp/qa-known"), 19123, "print('ok')")
        self.assertEqual(args[0], "/usr/bin/ssh")
        self.assertEqual(args[args.index("-b")+1], w.PEER_IP)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ControlMaster=no", args)
        self.assertIn("ProxyCommand=none", args)
        self.assertIn("ProxyJump=none", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("IdentityAgent=none", args)
        self.assertIn("PreferredAuthentications=publickey", args)
        self.assertIn("GlobalKnownHostsFile=/dev/null", args)
        self.assertNotIn("-A", args)
        self.assertEqual(args[-2], "scqa@"+w.ROOT_IP)
        with tempfile.TemporaryDirectory() as d:
            key, known = Path(d)/"key", Path(d)/"known"
            key.write_text("synthetic")
            known.write_text("synthetic")
            key.chmod(0o600)
            w.require_key_files(key, known)
            key.chmod(0o644)
            with self.assertRaises(w.WitnessError):
                w.require_key_files(key, known)
            key.chmod(0o600)
            key.unlink()
            key.symlink_to(known)
            with self.assertRaises(w.WitnessError):
                w.require_key_files(key, known)

    def test_vm_root_and_peer_namespace_admission_refuses_third_namespace(self):
        # Mock only the attested metadata and namespace *identity*, never call
        # unshare/setns or change any host network namespace in source CI.
        root = (4, 401)
        peer = (4, 402)
        third = (4, 403)
        def validate(here, in_peer, named=peer):
            def fake_stat(path):
                value = ({"/run/netns/scqa-foreign": named,
                          "/proc/1/ns/net": root,
                          "/proc/self/ns/net": here})[path]
                return SimpleNamespace(st_dev=value[0], st_ino=value[1])
            def read_text(path, *_a, **_k):
                if str(path) == "/etc/os-release":
                    return 'ID=debian\nVERSION_ID="13"\n'
                if str(path) == "/sys/class/dmi/id/sys_vendor":
                    return "QEMU"
                raise AssertionError("Unexpected identity source")
            with (patch.object(w.os, "stat", side_effect=fake_stat),
                  patch.object(w.os, "uname", return_value=SimpleNamespace(nodename="sc-qa-vm-us01")),
                  patch.object(w.Path, "read_text", read_text),
                  patch.object(w.Path, "exists", return_value=False)):
                w.require_guest(in_peer)
        validate(root, False)
        validate(peer, True)
        for current, peer_mode, reason in (
            (third, False, "not_vm_root_network_namespace"),
            (third, True, "incorrect_named_network_namespace"),
            (root, True, "incorrect_named_network_namespace"),
            (peer, False, "not_vm_root_network_namespace"),
        ):
            with self.subTest(current=current, peer_mode=peer_mode):
                with self.assertRaisesRegex(w.WitnessError, reason):
                    validate(current, peer_mode)
        with self.assertRaisesRegex(w.WitnessError,
                                    "root_and_peer_network_namespace_collide"):
            validate(root, False, named=root)

    def test_known_hosts_pin_ownership_permissions_and_mutation_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            key, host = Path(d)/"key", Path(d)/"known_hosts"
            key.write_text("test-private")
            key.chmod(0o600)
            first = "[198.51.100.1]:19123 ssh-ed25519 FIRSTKEY\n"
            second = "[198.51.100.1]:19123 ssh-ed25519 CHANGEDKEY\n"
            host.write_text(first)
            host.chmod(0o600)
            w.require_key_files(key, host)
            with w.pinned_host_file(host) as (snapshot, identity):
                self.assertEqual(snapshot.read_text(), first)
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)
                w.assert_pinned_hosts(host, snapshot, identity)
                host.write_text(second)
                with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_changed"):
                    w.assert_pinned_hosts(host, snapshot, identity)
                self.assertEqual(snapshot.read_text(), first)
            host.write_text(first)
            with w.pinned_host_file(host) as (snapshot, identity):
                # Replacing the inode with IDENTICAL bytes must still fail.
                changed = Path(d)/"other"
                changed.write_text(first)
                changed.chmod(0o600)
                os.replace(changed, host)
                with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_changed"):
                    w.assert_pinned_hosts(host, snapshot, identity)
            with w.pinned_host_file(host) as (snapshot, identity):
                host.rename(Path(d)/"old-host")
                host.symlink_to(Path(d)/"old-host")
                with self.assertRaises(w.WitnessError):
                    w.assert_pinned_hosts(host, snapshot, identity)
            host.unlink()
            (Path(d)/"old-host").rename(host)
            with w.pinned_host_file(host) as (snapshot, identity):
                # The private OpenSSH file is also pinned to its own inode.
                replacement = Path(d)/"snapshot-replacement"
                replacement.write_text(first)
                replacement.chmod(0o400)
                os.replace(replacement, snapshot)
                with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_changed"):
                    w.assert_pinned_hosts(host, snapshot, identity)
            with w.pinned_host_file(host) as (snapshot, identity):
                snapshot.chmod(0o600)
                snapshot.write_text(second)
                with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_changed"):
                    w.assert_pinned_hosts(host, snapshot, identity)
            for mode in (0o666, 0o620):
                host.chmod(mode)
                with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_ownership_or_permissions_unsafe"):
                    w.require_key_files(key, host)
            host.chmod(0o600)
            # Nonregular or pipe-backed trust files must be refused without
            # blocking on an absent FIFO writer.
            fifo = Path(d)/"named-pipe"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(w.WitnessError,
                                        "ssh_host_pin_ownership_or_permissions_unsafe"):
                w.require_key_files(key, fifo)
            native_fstat = os.fstat
            def foreign_owner(fd):
                st = native_fstat(fd)
                return SimpleNamespace(st_mode=st.st_mode, st_uid=987654)
            with patch.object(w.os, "fstat", side_effect=foreign_owner):
                with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_ownership_or_permissions_unsafe"):
                    w.read_trusted_known_hosts(host)

    def test_changed_host_pin_during_fresh_ssh_refuses_stage_and_reaps_original(self):
        # A successful SSH subprocess is not sufficient if the source trust
        # file changed during that connection. The witness must fail closed.
        with (patch.object(w, "ROOT_IP", "127.0.0.1"),
              patch.object(w, "PEER_IP", "127.0.0.1"),
              tempfile.TemporaryDirectory() as d):
            key, host = Path(d)/"key", Path(d)/"known_hosts"
            key.write_text("test-private")
            key.chmod(0o600)
            host.write_text("[127.0.0.1]:19123 ssh-ed25519 first-key\n")
            host.chmod(0o600)
            server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            children = []
            real_popen = subprocess.Popen
            def tracked_popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                return child
            def changed_during_auth(_key, _frozen_pin, _port):
                host.write_text("[127.0.0.1]:19123 ssh-ed25519 changed-key\n")
            try:
                with (patch.object(w, "ssh_command", return_value=[sys.executable, "-u", "-c", w.REMOTE_LOOP]),
                      patch.object(w, "ssh_socket_inode", return_value=4442),
                      patch.object(w, "new_ssh_round", side_effect=changed_during_auth),
                      patch.object(w.subprocess, "Popen", side_effect=tracked_popen),
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    with self.assertRaisesRegex(w.WitnessError, "ssh_host_pin_changed"):
                        w.client(key, host, 19123, server.server_port)
                self.assertNotIn("VM_INGRESS_WITNESS=PASS", output.getvalue())
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                self.assertTrue(children[0].stdin.closed)
                self.assertTrue(children[0].stdout.closed)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_private_key_freeze_confidentiality_and_source_identity(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d)/"private_key"
            key.write_bytes(b"test-private")
            key.chmod(0o600)
            with w.pinned_private_key_file(key) as (snapshot, identity):
                self.assertNotEqual(key, snapshot)
                self.assertEqual(snapshot.read_bytes(), key.read_bytes())
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o700)
                w.assert_pinned_private_key(key, snapshot, identity)
                key.write_bytes(b"another-key")
                with self.assertRaisesRegex(w.WitnessError, "ssh_private_key_changed"):
                    w.assert_pinned_private_key(key, snapshot, identity)
                self.assertEqual(snapshot.read_bytes(), b"test-private")
            self.assertFalse(snapshot.exists(), "the private snapshot must not persist")

            key.write_bytes(b"test-private")
            key.chmod(0o600)
            with w.pinned_private_key_file(key) as (snapshot, identity):
                same_bytes = Path(d)/"same"
                same_bytes.write_bytes(key.read_bytes())
                same_bytes.chmod(0o600)
                os.replace(same_bytes, key)
                with self.assertRaisesRegex(w.WitnessError, "ssh_private_key_changed"):
                    w.assert_pinned_private_key(key, snapshot, identity)
            with w.pinned_private_key_file(key) as (snapshot, identity):
                replacement = Path(d)/"swap_snapshot"
                replacement.write_bytes(key.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, snapshot)
                with self.assertRaisesRegex(w.WitnessError, "ssh_private_key_changed"):
                    w.assert_pinned_private_key(key, snapshot, identity)
            with w.pinned_private_key_file(key) as (snapshot, identity):
                snapshot.write_bytes(b"corrupted")
                with self.assertRaises(w.WitnessError):
                    w.assert_pinned_private_key(key, snapshot, identity)
            for mode in (0o644, 0o640, 0o622):
                with self.subTest(mode=mode):
                    key.chmod(mode)
                    with self.assertRaisesRegex(w.WitnessError,
                                                "ssh_private_key_ownership_or_permissions_unsafe"):
                        w.read_trusted_private_key(key)
            key.chmod(0o600)
            native_fstat = os.fstat

            def impersonated_owner(fd):
                st = native_fstat(fd)
                return SimpleNamespace(st_mode=st.st_mode, st_uid=987654)

            with patch.object(w.os, "fstat", side_effect=impersonated_owner):
                with self.assertRaisesRegex(w.WitnessError,
                                            "ssh_private_key_ownership_or_permissions_unsafe"):
                    w.read_trusted_private_key(key)
            key.unlink()
            key.symlink_to(Path(d)/"target")
            with self.assertRaisesRegex(w.WitnessError, "ssh_identity_file_invalid"):
                w.read_trusted_private_key(key)
            key.unlink()
            fifo = Path(d)/"fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(w.WitnessError,
                                        "ssh_private_key_ownership_or_permissions_unsafe"):
                w.read_trusted_private_key(fifo)
            key.write_bytes(b"")
            key.chmod(0o600)
            with self.assertRaisesRegex(w.WitnessError,
                                        "ssh_private_key_ownership_or_permissions_unsafe"):
                w.read_trusted_private_key(key)

    def test_private_key_swap_during_fresh_auth_fails_and_reaps_original(self):
        # A different SSH identity can also authenticate on the fixture.
        # Never credit its success to the baseline key or leave the original
        # transport open after source-key drift, even for identical bytes.
        for swap_kind in ("in_place", "same_bytes_new_inode"):
            with (self.subTest(swap_kind=swap_kind),
                  patch.object(w, "ROOT_IP", "127.0.0.1"),
                  patch.object(w, "PEER_IP", "127.0.0.1"),
                  tempfile.TemporaryDirectory() as d):
                key, known = Path(d)/"key", Path(d)/"known_hosts"
                key.write_text("test-private")
                key.chmod(0o600)
                known.write_text("[127.0.0.1]:19123 ssh-ed25519 first-key\n")
                known.chmod(0o600)
                server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
                server.daemon_threads = True
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                children = []
                real_popen = subprocess.Popen

                def tracked_popen(*args, **kwargs):
                    child = real_popen(*args, **kwargs)
                    children.append(child)
                    return child

                def changed_during_auth(snapshot_key, _known, _port):
                    # Every SSH invocation must consume the pinned private
                    # snapshot, not the mutable original source path.
                    self.assertNotEqual(snapshot_key, key)
                    self.assertEqual(snapshot_key.read_text(), "test-private")
                    if swap_kind == "in_place":
                        key.write_text("second-private")
                    else:
                        replacement = Path(d)/"replacement"
                        replacement.write_text("test-private")
                        replacement.chmod(0o600)
                        os.replace(replacement, key)

                try:
                    with (patch.object(w, "ssh_command",
                                       return_value=[sys.executable, "-u", "-c", w.REMOTE_LOOP]),
                          patch.object(w, "ssh_socket_inode", return_value=4442),
                          patch.object(w, "new_ssh_round", side_effect=changed_during_auth),
                          patch.object(w.subprocess, "Popen", side_effect=tracked_popen),
                          contextlib.redirect_stdout(io.StringIO()) as output):
                        with self.assertRaisesRegex(w.WitnessError, "ssh_private_key_changed"):
                            w.client(key, known, 19123, server.server_port)
                    self.assertNotIn("VM_INGRESS_WITNESS=PASS", output.getvalue())
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll())
                    self.assertTrue(children[0].stdin.closed)
                    self.assertTrue(children[0].stdout.closed)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())

    def test_final_fresh_http_drift_fails_without_terminal_pass(self):
        # The final stage must not be reported successful if identity changes
        # while its last fresh HTTP request is in flight. Use live loopback HTTP,
        # a real persistent SSH-like subprocess and only mock SSH authentication.
        mutations = (
            ("key_content", "ssh_private_key_changed"),
            ("key_identical_new_inode", "ssh_private_key_changed"),
            ("key_snapshot_replacement", "ssh_private_key_changed"),
            ("known_hosts_content", "ssh_host_pin_changed"),
            ("known_hosts_snapshot", "ssh_host_pin_changed"),
        )
        for mutation, expected_reason in mutations:
            with (self.subTest(mutation=mutation),
                  patch.object(w, "ROOT_IP", "127.0.0.1"),
                  patch.object(w, "PEER_IP", "127.0.0.1"),
                  tempfile.TemporaryDirectory() as d):
                key, known = Path(d)/"key", Path(d)/"known_hosts"
                key.write_text("qa-identity-A")
                key.chmod(0o600)
                known.write_text("[127.0.0.1]:19123 ssh-ed25519 QA-PIN-A\\n")
                known.chmod(0o600)
                server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
                server.daemon_threads = True
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                originals, frozen = [], []
                native_popen = subprocess.Popen
                native_http_round = w.http_round
                http_round_count = [0]

                def track_original(*args, **kwargs):
                    child = native_popen(*args, **kwargs)
                    originals.append(child)
                    return child

                def fresh_ssh(frozen_key, host_snapshot, _port):
                    frozen[:] = [frozen_key, host_snapshot]

                def mutate_after_fresh_http(port):
                    answer = native_http_round(port)
                    http_round_count[0] += 1
                    if http_round_count[0] == 4:  # final off-stage round
                        frozen_key, host_snapshot = frozen
                        if mutation == "key_content":
                            key.write_text("qa-identity-B")
                        elif mutation == "key_identical_new_inode":
                            replacement = Path(d)/"new-key"
                            replacement.write_bytes(key.read_bytes())
                            replacement.chmod(0o600)
                            os.replace(replacement, key)
                        elif mutation == "key_snapshot_replacement":
                            replacement = Path(d)/"new-frozen-key"
                            replacement.write_bytes(frozen_key.read_bytes())
                            replacement.chmod(0o600)
                            os.replace(replacement, frozen_key)
                        elif mutation == "known_hosts_content":
                            known.write_text("[127.0.0.1]:19123 ssh-ed25519 QA-PIN-B\\n")
                        else:
                            host_snapshot.chmod(0o600)
                            host_snapshot.write_text("[127.0.0.1]:19123 ssh-ed25519 QA-PIN-B\\n")
                    return answer

                out, err = io.StringIO(), io.StringIO()
                try:
                    with (patch.object(w, "require_guest"),
                          patch.object(w.sys, "argv",
                                       ["witness", "client", "--private-key", str(key),
                                        "--known-hosts", str(known), "--ssh-port", "19123",
                                        "--http-port", str(server.server_port)]),
                          patch.object(w, "ssh_command",
                                       return_value=[sys.executable, "-u", "-c", w.REMOTE_LOOP]),
                          patch.object(w, "ssh_socket_inode", return_value=4442),
                          patch.object(w, "new_ssh_round", side_effect=fresh_ssh),
                          patch.object(w, "next_phase", side_effect=["pending", "confirmed", "off"]),
                          patch.object(w, "http_round", side_effect=mutate_after_fresh_http),
                          patch.object(w.subprocess, "Popen", side_effect=track_original),
                          contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)):
                        code = w.main()
                    self.assertEqual(http_round_count[0], 4)
                    self.assertEqual(code, 1)
                    self.assertIn("VM_INGRESS_WITNESS=FAIL reason=" + expected_reason,
                                  err.getvalue())
                    self.assertNotIn("VM_INGRESS_WITNESS=PASS", out.getvalue())
                    self.assertEqual(len(originals), 1)
                    self.assertIsNotNone(originals[0].poll(), "original SSH must be reaped")
                    self.assertTrue(originals[0].stdin.closed)
                    self.assertTrue(originals[0].stdout.closed)
                    self.assertEqual(len(frozen), 2)
                    self.assertFalse(frozen[0].exists(), "frozen private identity must be removed")
                    self.assertFalse(frozen[1].exists(), "frozen host pin must be removed")
                    self.assertNotIn("qa-identity-A", err.getvalue())
                    self.assertNotIn(str(key), err.getvalue())
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())

    def test_final_ssh_http_cleanup_failure_suppresses_terminal_pass(self):
        # The HTTP cleanup exception occurs after all stage observations.
        # A terminal PASS cannot precede the successful teardown boundary.
        with (patch.object(w, "ROOT_IP", "127.0.0.1"),
              patch.object(w, "PEER_IP", "127.0.0.1"),
              tempfile.TemporaryDirectory() as d):
            key, known = Path(d)/"key", Path(d)/"known_hosts"
            key.write_text("qa-secret-identity")
            key.chmod(0o600)
            known.write_text("[127.0.0.1]:19123 ssh-ed25519 QA-PIN\\n")
            known.chmod(0o600)
            server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            originals, frozen, persistent = [], [], []
            native_popen = subprocess.Popen
            native_http_round = w.http_round
            native_verify = w.verified_http_socket
            native_close = w.http.client.HTTPConnection.close
            final_round_complete = [False]
            count = [0]

            def track_original(*args, **kwargs):
                child = native_popen(*args, **kwargs)
                originals.append(child)
                return child

            def fresh_ssh(frozen_key, known_snapshot, _port):
                frozen[:] = [frozen_key, known_snapshot]

            def observe_persistent(connection):
                if not persistent:
                    persistent.append(connection)
                return native_verify(connection)

            def final_http(port):
                result = native_http_round(port)
                count[0] += 1
                if count[0] == 4:
                    final_round_complete[0] = True
                return result

            def fail_persistent_close(connection):
                native_close(connection)
                if final_round_complete[0] and persistent and connection is persistent[0]:
                    raise OSError("qa-secret-identity-must-not-leak")
            out, err = io.StringIO(), io.StringIO()
            try:
                with (patch.object(w, "require_guest"),
                      patch.object(w.sys, "argv",
                                   ["witness", "client", "--private-key", str(key),
                                    "--known-hosts", str(known), "--ssh-port", "19123",
                                    "--http-port", str(server.server_port)]),
                      patch.object(w, "ssh_command",
                                   return_value=[sys.executable, "-u", "-c", w.REMOTE_LOOP]),
                      patch.object(w, "ssh_socket_inode", return_value=4442),
                      patch.object(w, "new_ssh_round", side_effect=fresh_ssh),
                      patch.object(w, "next_phase", side_effect=["pending", "confirmed", "off"]),
                      patch.object(w, "http_round", side_effect=final_http),
                      patch.object(w, "verified_http_socket", side_effect=observe_persistent),
                      patch.object(w.http.client.HTTPConnection, "close",
                                   autospec=True, side_effect=fail_persistent_close),
                      patch.object(w.subprocess, "Popen", side_effect=track_original),
                      contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)):
                    code = w.main()
                self.assertEqual(count[0], 4)
                self.assertTrue(final_round_complete[0])
                self.assertEqual(code, 1)
                self.assertIn("VM_INGRESS_WITNESS=FAIL reason=qa_listener_or_socket_unavailable",
                              err.getvalue())
                self.assertNotIn("VM_INGRESS_WITNESS=PASS", out.getvalue())
                self.assertNotIn("qa-secret-identity", err.getvalue())
                self.assertNotIn(str(key), err.getvalue())
                self.assertEqual(len(originals), 1)
                self.assertIsNotNone(originals[0].poll())
                self.assertTrue(originals[0].stdin.closed)
                self.assertTrue(originals[0].stdout.closed)
                self.assertEqual(len(frozen), 2)
                self.assertFalse(frozen[0].exists())
                self.assertFalse(frozen[1].exists())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_partial_stage_input_forces_client_cleanup(self):
        # Full client control flow, real HTTP/1.1 and a real persistent
        # subprocess; only SSH transport and fresh auth are simulated.
        with (patch.object(w, "ROOT_IP", "127.0.0.1"),
              patch.object(w, "PEER_IP", "127.0.0.1"),
              tempfile.TemporaryDirectory() as d):
            key, known = Path(d)/"key", Path(d)/"known"
            key.write_text("synthetic")
            known.write_text("[127.0.0.1]:19123 ssh-ed25519 synthetic\n")
            key.chmod(0o600)
            known.chmod(0o600)
            server = w.ThreadingHTTPServer(("127.0.0.1", 0), w.Origin)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            read_fd, write_fd = os.pipe()
            subprocesses = []
            real_popen = subprocess.Popen
            real_next_phase = w.next_phase
            def tracked_popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                subprocesses.append(child)
                return child
            try:
                os.write(write_fd, b"pen")  # no newline; writer remains open
                with os.fdopen(read_fd, "r") as input_stream:
                    with (patch.object(w.sys, "stdin", input_stream),
                          patch.object(w, "ssh_command", return_value=[sys.executable, "-u", "-c", w.REMOTE_LOOP]),
                          patch.object(w, "ssh_socket_inode", return_value=4442),
                          patch.object(w, "new_ssh_round"),
                          patch.object(w.subprocess, "Popen", side_effect=tracked_popen),
                          patch.object(w, "next_phase", side_effect=lambda prev: real_next_phase(prev, seconds=0.12)),
                          contextlib.redirect_stdout(io.StringIO())):
                        began = time.monotonic()
                        with self.assertRaisesRegex(w.WitnessError, "operator_phase_timeout"):
                            w.client(key, known, 19123, server.server_port)
                        self.assertLess(time.monotonic() - began, 5)
                self.assertEqual(len(subprocesses), 1)
                self.assertIsNotNone(subprocesses[0].poll())
                self.assertTrue(subprocesses[0].stdin.closed)
                self.assertTrue(subprocesses[0].stdout.closed)
            finally:
                os.close(write_fd)
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_not_on_exact_guest_refuses_without_changes(self):
        result = subprocess.run([sys.executable, "-B", str(MODULE), "origin", "--http-port", "19124"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"VM_INGRESS_WITNESS=FAIL", result.stderr)
        self.assertNotIn(b"VM_INGRESS_HTTP_ORIGIN=READY", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
