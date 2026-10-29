#!/usr/bin/env python3
"""Negative controls for real synthetic large-payload TUN wire witnesses."""
import importlib.util
from pathlib import Path
import socket
import threading
import errno
import io
from unittest.mock import patch
import unittest

module_path = Path(__file__).with_name("tun-payload-wire.py")
spec = importlib.util.spec_from_file_location("tun_payload", module_path)
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


class PayloadWitnessTests(unittest.TestCase):
    def test_full_length_and_source_integrity(self):
        token = b"0123456789abcdef"
        for source in ("10.254.72.1", "8.8.8.8"):
            for count in (payload.TCP_BYTES, payload.UDP_BYTES):
                with self.subTest(source=source, count=count):
                    request = payload.packet(token, count)
                    reply = payload.response(request, source, count)
                    payload.verify_response(reply, token, source, count)
                    for bad in (reply[:-1], reply + b"tail", reply[:len(payload.MAGIC) + 16] + b"ffffffffffffffff" + reply[len(payload.MAGIC) + 32:],
                                reply[:len(payload.MAGIC)] + b"X" + reply[len(payload.MAGIC) + 1:]):
                        with self.assertRaises(ValueError):
                            payload.verify_response(bad, token, source, count)
                    other = "8.8.8.8" if source == "10.254.72.1" else "10.254.72.1"
                    with self.assertRaises(ValueError):
                        payload.verify_response(reply, token, other, count)

    def test_reject_truncated_corrupt_and_wrong_source_requests(self):
        token = b"0123456789abcdef"
        request = payload.packet(token, payload.UDP_BYTES)
        for bad in (request[:-1], request + b"extra", request[:payload.HEADER_SIZE - 1],
                    request[:payload.HEADER_SIZE] + b"X" + request[payload.HEADER_SIZE + 1:]):
            with self.subTest(bad=bad[:30]):
                with self.assertRaises(ValueError):
                    payload.unpack_request(bad, payload.UDP_BYTES)
        with self.assertRaises(ValueError):
            payload.response(request, "203.0.113.1", payload.UDP_BYTES)
        with self.assertRaises(ValueError):
            payload.unpack_request(request, payload.TCP_BYTES)

    def test_outage_never_accepts_a_reply_or_unrelated_local_error(self):
        with patch.object(payload, "request_tcp", return_value=b"unexpected payload reply"):
            with self.assertRaisesRegex(ValueError, "despite upstream loss"):
                payload.client("tcp", "8.8.8.8", "none", "no-reply")
        with patch.object(payload, "request_tcp", side_effect=OSError(errno.EACCES, "denied")):
            with self.assertRaises(OSError):
                payload.client("tcp", "8.8.8.8", "none", "no-reply")
        with patch.object(payload, "request_udp", return_value=b"unexpected UDP reply"):
            with self.assertRaisesRegex(ValueError, "despite upstream loss"):
                payload.client("udp", "8.8.8.8", "none", "no-reply")
        with patch.object(payload, "request_udp", side_effect=OSError(errno.ENETUNREACH, "offline")), \
             patch("sys.stdout", io.StringIO()) as output:
            payload.client("udp", "8.8.8.8", "none", "no-reply")
            self.assertIn("UDP_NO_REPLY=PASS", output.getvalue())
        with patch.object(payload, "request_tcp", side_effect=socket.timeout("offline")):
            with self.assertRaises(socket.timeout):
                payload.client("tcp", "8.8.8.8", "8.8.8.8", "reply")

    def test_reject_invalid_expectations_before_networking(self):
        for args in (("tcp", "10.0.0.1", "none", "no-reply"),
                     ("udp", "8.8.8.8", "8.8.8.8", "no-reply"),
                     ("tcp", "8.8.8.8", "none", "reply"),
                     ("dns", "8.8.8.8", "none", "no-reply")):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    payload.client(*args)

    def test_real_loopback_tcp_and_udp_byte_round_trip(self):
        # Unprivileged: actual TCP and UDP sockets, but no routing/TUN claim.
        original_tcp, original_udp = payload.TCP_PORT, payload.UDP_PORT
        with payload.TCPServer(("127.0.0.1", 0), payload.TCPHandler) as tcp, \
             payload.UDPServer(("127.0.0.1", 0), payload.UDPHandler) as udp:
            payload.TCP_PORT, payload.UDP_PORT = tcp.server_address[1], udp.server_address[1]
            threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (tcp, udp)]
            for t in threads:
                t.start()
            try:
                token = b"0123456789abcdef"
                payload.verify_response(payload.request_tcp("127.0.0.1", token),
                                        token, "127.0.0.1", payload.TCP_BYTES)
                payload.verify_response(payload.request_udp("127.0.0.1", token),
                                        token, "127.0.0.1", payload.UDP_BYTES)
            finally:
                for s in (tcp, udp):
                    s.shutdown()
                for t in threads:
                    t.join(timeout=3)
                payload.TCP_PORT, payload.UDP_PORT = original_tcp, original_udp


if __name__ == "__main__":
    unittest.main()
