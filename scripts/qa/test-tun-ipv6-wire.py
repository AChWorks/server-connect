#!/usr/bin/env python3
"""Unprivileged strict-negative IPv6 TUN wire classifier tests."""
import importlib.util
from pathlib import Path
import errno
import io
import socket
import unittest
from unittest.mock import patch

p = Path(__file__).with_name("tun-ipv6-wire.py")
spec = importlib.util.spec_from_file_location("tun_ipv6_wire", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class IPv6WireTests(unittest.TestCase):
    def test_exact_request_source_and_response(self):
        token = b"0123456789abcdef"
        for size in (m.TCP_BYTES, m.UDP_BYTES):
            sample = m.request(token, size)
            for source in ("fd73:1::1", "2001:db8:5::10", "2001:db8:8::8"):
                with self.subTest(size=size, source=source):
                    result = m.response(sample, source, size)
                    m.verify(result, token, source, size)
                    for bad in (result[:-1], result + b"x", result.replace(m.MAGIC, b"bad"),
                                result[:-1] + bytes([result[-1] ^ 1])):
                        with self.assertRaises(ValueError):
                            m.verify(bad, token, source, size)
                    with self.assertRaises(ValueError):
                        m.verify(result, b"abcdabcdabcdabcd", source, size)
                    with self.assertRaises(ValueError):
                        m.verify(result, token, "2001:db8:8::9", size)

    def test_invalid_and_corrupted_frames(self):
        token = b"0123456789abcdef"
        original = m.request(token, m.UDP_BYTES)
        for bad in (original[:-1], original + b"extra", original[:m.HEADER],
                    original[:m.HEADER] + b"X" + original[m.HEADER + 1:]):
            with self.assertRaises(ValueError):
                m.response(bad, "fd73:1::1", m.UDP_BYTES)
        with self.assertRaises(OSError):
            m.response(original, "bad::source::ip", m.UDP_BYTES)

    def test_outage_and_invalid_expectation(self):
        with patch.object(m, "tcp_probe", return_value=b"invalid"):
            with self.assertRaisesRegex(ValueError, "unexpectedly reached"):
                m.probe("tcp", "2001:db8:8::8", "none", "no-reply")
        with patch.object(m, "tcp_probe", side_effect=OSError(errno.EBADF, "invalid socket")):
            with self.assertRaises(OSError):
                m.probe("tcp", "2001:db8:8::8", "none", "no-reply")
        with patch.object(m, "udp_probe", side_effect=OSError(errno.ENETUNREACH, "offline")), \
                patch("sys.stdout", io.StringIO()) as out:
            m.probe("udp", "2001:db8:8::8", "none", "no-reply")
            self.assertIn("NO_REPLY=PASS", out.getvalue())
        for args in (("tcp", "fd73:1::2", "none", "no-reply"),
                     ("udp", "2001:db8:8::8", "fd73:1::1", "no-reply"),
                     ("tcp", "2001:db8:8::8", "none", "reply"),
                     ("dns", "2001:db8:8::8", "none", "no-reply")):
            with self.assertRaises(ValueError):
                m.probe(*args)

    def test_native_denial_is_negative_only(self):
        for transport in ("tcp", "udp"):
            for code in (errno.EPERM, errno.EACCES):
                with self.subTest(transport=transport, errno=code), \
                        patch.object(m, transport + "_probe", side_effect=OSError(code, "native denial")), \
                        patch("sys.stdout", io.StringIO()) as out:
                    m.probe(transport, "2001:db8:8::8", "none", "no-reply")
                    self.assertIn("NO_REPLY=PASS", out.getvalue())
                    with self.assertRaises(OSError):
                        m.probe(transport, "2001:db8:8::8", "2001:db8:8::8", "reply")

    def test_udp_origin_bindings_cannot_fall_back_to_wildcard(self):
        self.assertEqual(set(m.UDP_BIND_ADDRESSES), {
            "2001:db8:5::10", "2001:db8:5::11",
            "2001:db8:8::8", "2001:db8:8::9",
        })
        self.assertNotIn("::", m.UDP_BIND_ADDRESSES)

    def test_address_is_binary_canonicalized(self):
        token = b"0123456789abcdef"
        answer = m.response(m.request(token, m.UDP_BYTES), "2001:db8:5:0:0:0:0:10", m.UDP_BYTES)
        m.verify(answer, token, "2001:db8:5::10", m.UDP_BYTES)


if __name__ == "__main__":
    unittest.main()
