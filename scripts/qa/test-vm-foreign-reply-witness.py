#!/usr/bin/env python3
"""Unprivileged negative and protocol regressions for vm-foreign-reply-witness.

The real named VETH/SSH/HTTP/route exercise is a separate authorized VM test.
No kernel namespaces, firewall, routes, privileged ports or SSH daemon are
changed by this unit test.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import os
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

    def test_stage_order_is_bounded_and_no_phase_skips(self):
        allowed = {("baseline", "pending"), ("pending", "confirmed"),
                   ("pending", "off"), ("confirmed", "degraded"),
                   ("confirmed", "off"), ("degraded", "off")}
        for p in ("baseline", "pending", "confirmed", "degraded", "off", "x"):
            for n in ("baseline", "pending", "confirmed", "degraded", "off", "x"):
                self.assertEqual(w.phase_allowed(p, n), (p,n) in allowed)
        with contextlib.redirect_stdout(io.StringIO()):
            with patch.object(w.select, "select", return_value=([],[],[])):
                with self.assertRaisesRegex(w.WitnessError, "operator_phase_timeout"):
                    w.next_phase("baseline")
            with patch.object(w.select, "select", return_value=([1],[],[])):
                with patch.object(sys, "stdin", io.StringIO("off\n")):
                    with self.assertRaisesRegex(w.WitnessError, "operator_phase_out_of_order"):
                        w.next_phase("baseline")

    def test_pinned_ssh_host_no_proxy_and_safe_key_permissions(self):
        args = w.ssh_command(Path("/tmp/qa-key"), Path("/tmp/qa-known"), 19123, "print('ok')")
        self.assertEqual(args[0], "/usr/bin/ssh")
        self.assertEqual(args[args.index("-b")+1], w.PEER_IP)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ControlMaster=no", args)
        self.assertIn("ProxyCommand=none", args)
        self.assertIn("ProxyJump=none", args)
        self.assertIn("BatchMode=yes", args)
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

    def test_not_on_exact_guest_refuses_without_changes(self):
        result = subprocess.run([sys.executable, "-B", str(MODULE), "origin", "--http-port", "19124"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"VM_INGRESS_WITNESS=FAIL", result.stderr)
        self.assertNotIn(b"VM_INGRESS_HTTP_ORIGIN=READY", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
