#!/usr/bin/env python3
"""No-network positive and negative checks of real field UDP packet grammar."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("field_udp_dns_wire", Path(__file__).with_name("field-udp-dns-wire.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FieldDNSWireTests(unittest.TestCase):
    def test_unique_dns_requests_have_bounded_expected_shape(self):
        ident, question, data = mod.query_packet(0)
        self.assertEqual(len(data), 12 + len(question))
        self.assertEqual(struct.unpack("!HHHHHH", data[:12]), (ident, 256, 1, 0, 0, 0))
        for size in (512, 1000, 1200, 1232, 1300):
            ident, question, data = mod.query_packet(size)
            self.assertEqual(len(data), size)
            self.assertEqual(struct.unpack("!HHHHHH", data[:12]), (ident, 256, 1, 0, 0, 1))
            self.assertTrue(data.endswith(bytes(size - (12 + len(question) + 15))))

    def test_rejects_false_dns_response(self):
        ident, question, _ = mod.query_packet()
        def answer(flags=0x8183, transaction=None, body=None, count=1):
            return struct.pack("!HHHHHH", ident if transaction is None else transaction, flags, count, 0, 0, 0) + (question if body is None else body)
        self.assertEqual(mod.response_rcode(answer(), ident, question), 3)
        self.assertEqual(mod.response_rcode(answer(flags=0x8180), ident, question), 0)
        for raw in (
            b"", b"short", answer(transaction=ident ^ 1), answer(flags=0x0183),
            answer(flags=0x8383), answer(flags=0x8182), answer(count=0),
            answer(body=b"wrong"), answer() + bytes(4096),
        ):
            with self.subTest(sample=raw[:16]), self.assertRaises(mod.EvidenceError):
                mod.response_rcode(raw, ident, question)

    def test_exact_veth_dns_frame_matching_and_false_positive_refusals(self):
        import socket
        ident, question, request = mod.query_packet(512)
        resolver = "1.1.1.1"
        ip_header = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0])
        ip_header += socket.inet_aton("172.31.249.2") + socket.inet_aton(resolver)
        udp = struct.pack("!HHHH", 41230, 53, 8 + len(request), 0)
        ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
        frame = ethernet + ip_header + udp + request
        self.assertTrue(mod.exact_dns_veth_frame(frame, resolver, request))
        for badframe, target, query in (
            (frame, "9.9.9.9", request),
            (frame, resolver, request + b"X"),
            (frame[:-3], resolver, request),
            (frame[:12] + b"\x86\xdd" + frame[14:], resolver, request),
            (frame[:14 + 9] + b"\x06" + frame[14 + 10:], resolver, request),
            (frame[:14 + 6] + b"\x00\x01" + frame[14 + 8:], resolver, request),
            (frame[:14 + 20 + 2] + b"\x00\x50" + frame[14 + 20 + 4:], resolver, request),
        ):
            with self.subTest(bad=badframe[:14]):
                self.assertFalse(mod.exact_dns_veth_frame(badframe, target, query))

    def test_invalid_packet_sizes(self):
        for size in (1, 42, 1351, 99999):
            with self.assertRaises(mod.EvidenceError):
                mod.query_packet(size)


if __name__ == "__main__":
    unittest.main()
