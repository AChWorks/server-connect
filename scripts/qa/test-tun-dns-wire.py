#!/usr/bin/env python3
"""Pure packet-contract tests; no privileged sockets or external DNS."""

import importlib.util
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
