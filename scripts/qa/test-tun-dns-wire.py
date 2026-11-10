#!/usr/bin/env python3
"""Pure packet-contract tests; no privileged sockets or external DNS."""

import importlib.util
import errno
import io
import socket
from unittest.mock import MagicMock, patch
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CLIENT = module("scqa_dns_client", "tun-dns-client.py")
PEER = module("scqa_dns_peer", "tun-dns-peer.py")


class DNSWireContract(unittest.TestCase):
    def test_two_distinct_sender_paths(self):
        packet = CLIENT.question("unique-phase-01")
        self.assertEqual(PEER.question_end(packet), len(packet))
        for source, expected in (("10.254.72.1", "192.0.2.11"), ("8.8.8.8", "192.0.2.22")):
            reply = PEER.response_for(packet, source)
            self.assertEqual(CLIENT.answer_ipv4(reply, packet), expected)
        self.assertIsNone(PEER.response_for(packet, "203.0.113.7"))

    def test_dual_stack_responder_source_and_selected_dns_detour(self):
        packet = CLIENT.question("native-ipv6-wire")
        for source, expected in (("fd73:1::1", "192.0.2.11"),
                                 ("2606:4700:5::10", "192.0.2.22"),
                                 ("1.1.1.1", "192.0.2.33"),
                                 ("5.22.0.11", "192.0.2.22")):
            with self.subTest(source=source):
                self.assertEqual(CLIENT.answer_ipv4(PEER.response_for(packet, source), packet), expected)
        self.assertIsNone(PEER.response_for(packet, "fd73:1::999"))

    def test_core_reencoded_dns_answer_uncompressed_owner_is_valid(self):
        packet = CLIENT.question("unmatched-v6-udp")
        compressed = PEER.response_for(packet, "1.1.1.1")
        # Actual Core hijack-dns can replace the 2-byte compression pointer
        # with the full QNAME, preserving the exact question and A payload.
        raw_owner = packet[12:-4]
        uncompressed = compressed[:len(packet)] + raw_owner + compressed[len(packet) + 2:]
        self.assertEqual(len(uncompressed), 102)
        self.assertEqual(CLIENT.answer_ipv4(uncompressed, packet), "192.0.2.33")
        self.assertEqual(CLIENT.answer_ipv4(compressed, packet), "192.0.2.33")
        # An unrelated owner, extra bytes, wrong type or wrong question must
        # still fail. TTL itself is valid metadata and not a path identity.
        for bad in (
            uncompressed[:len(packet)] + b"X" + uncompressed[len(packet) + 1:],
            uncompressed + b"\0",
            uncompressed[:-1],
            uncompressed[:len(packet) + len(raw_owner)] + b"\x00\x1c" + uncompressed[len(packet) + len(raw_owner) + 2:],
            uncompressed[:12] + b"X" + uncompressed[13:],
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                CLIENT.answer_ipv4(bad, packet)

    def test_native_dual_stack_udp_uses_real_ipv6_socket_and_peer_tuple(self):
        destination = "2606:4700:5::10"
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recvfrom.return_value = (b"real-reply", (destination, 53, 0, 0))
        with patch.object(CLIENT.socket, "socket", return_value=sock) as create:
            self.assertEqual(CLIENT.wire_query(destination, "udp", b"dns-query"), b"real-reply")
        create.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.sendto.assert_called_once_with(b"dns-query", (destination, 53))
        sock.recvfrom.return_value = (b"reply-from-wrong-ip", ("2606:4700:8::8", 53, 0, 0))
        with patch.object(CLIENT.socket, "socket", return_value=sock):
            with self.assertRaisesRegex(ValueError, "another endpoint"):
                CLIENT.wire_query(destination, "udp", b"dns-query")

    def test_native_outage_rejects_success_and_forged_dns_failures(self):
        packet = CLIENT.question("native-outage")
        failure = packet[:2] + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + packet[12:]
        args = ["2606:4700:8::8", "none", "native-outage", "udp", "no-success"]
        with patch.object(CLIENT, "wire_query", return_value=failure), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            CLIENT.main(args)
            self.assertEqual(out.getvalue(), "REAL_TUN_DNS_NO_SUCCESS=PASS\n")
        bad = (
            PEER.response_for(packet, "2606:4700:8::8"),
            failure[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + failure[12:],
            failure[:-1], failure + b"X", failure[:-1] + b"X",
            b"XX" + failure[2:],
            failure[:2] + struct.pack("!HHHHH", 0x8182, 2, 0, 0, 0) + failure[12:],
        )
        for response in bad:
            with self.subTest(response=response), patch.object(CLIENT, "wire_query", return_value=response):
                with self.assertRaises(ValueError):
                    CLIENT.main(args)
        with patch.object(CLIENT, "wire_query", side_effect=OSError(errno.ENETUNREACH, "offline")), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            CLIENT.main(args)
            self.assertIn("NO_RESPONSE=PASS", out.getvalue())
        for destination in ("fe80::1", "fd73:1::3", "::1"):
            with self.assertRaises(ValueError):
                CLIENT.main([destination, "none", "negative", "udp", "no-success"])

    def test_phase_is_necessary_and_non_cacheable(self):
        one = CLIENT.question("phase-a")
        two = CLIENT.question("phase-b")
        self.assertNotEqual(one, two)
        with self.assertRaises(ValueError):
            CLIENT.answer_ipv4(PEER.response_for(one, "8.8.8.8"), two)
        for bad in ("", "UpperCase", "x" * 29, "bad.name", "leading_", "-bad"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                CLIENT.question(bad)

    def test_rejects_ambiguous_question_or_reply(self):
        packet = CLIENT.question("strict-query")
        good = PEER.response_for(packet, "8.8.8.8")
        malformed = [
            packet[:2] + b"\0\0" + packet[4:],  # no RD
            packet[:4] + b"\0\x02" + packet[6:],  # two questions
            packet[:12] + b"\xc0\x0c" + packet[14:],  # compressed query
            packet[:-4] + b"\0\x1c\0\x01",  # AAAA instead of A
            packet + b"trailer",
        ]
        for item in malformed:
            with self.subTest(question=item), self.assertRaises(ValueError):
                PEER.question_end(item)
        for reply in (
            good[:-1],
            good + b"\0",
            good[:2] + struct.pack("!H", 0x8183) + good[4:],
            good[:len(packet)] + b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 0, 4) + good[-4:],
        ):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                CLIENT.answer_ipv4(reply, packet)


if __name__ == "__main__":
    unittest.main()
