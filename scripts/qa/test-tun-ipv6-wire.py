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
            for source in ("fd73:1::1", "2606:4700:5::10", "2606:4700:8::8"):
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
                        m.verify(result, token, "2606:4700:8::9", size)

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
        with patch.object(m, "tcp_probe", return_value=b"invalid"), patch("sys.stderr", io.StringIO()):
            with self.assertRaisesRegex(ValueError, "unexpectedly reached"):
                m.probe("tcp", "2606:4700:8::8", "none", "no-reply")
        with patch.object(m, "tcp_probe", side_effect=OSError(errno.EBADF, "invalid socket")):
            with self.assertRaises(OSError):
                m.probe("tcp", "2606:4700:8::8", "none", "no-reply")
        with patch.object(m, "udp_probe", side_effect=OSError(errno.ENETUNREACH, "offline")), \
                patch("sys.stdout", io.StringIO()) as out:
            m.probe("udp", "2606:4700:8::8", "none", "no-reply")
            self.assertIn("NO_REPLY=PASS", out.getvalue())
        for args in (("tcp", "fd73:1::2", "none", "no-reply"),
                     ("udp", "2606:4700:8::8", "fd73:1::1", "no-reply"),
                     ("tcp", "2606:4700:8::8", "none", "reply"),
                     ("dns", "2606:4700:8::8", "none", "no-reply")):
            with self.assertRaises(ValueError):
                m.probe(*args)

    def test_unexpected_response_requires_exact_authenticated_frame(self):
        token = b"0123456789abcdef"
        destination = "2606:4700:8::8"
        for size in (m.TCP_BYTES, m.UDP_BYTES):
            for source, expected in (
                ("fd73:1::1", "authenticated-direct-underlay-source"),
                (destination, "authenticated-peer-vpn-source"),
                ("2606:4700:999::123", "authenticated-other-ipv6-source"),
            ):
                with self.subTest(size=size, source=source):
                    reply = m.response(m.request(token, size), source, size)
                    self.assertEqual(m.unexpected_response_kind(reply, token, destination, size), expected)
                    corrupt = (
                        reply[:-1], reply + b"extra", b"UNTRUSTED_SECRET", None,
                        b"X" + reply[1:], reply[:-1] + bytes([reply[-1] ^ 1]),
                        m.response(m.request(b"abcdef0123456789", size), source, size),
                    )
                    for bad in corrupt:
                        self.assertEqual(m.unexpected_response_kind(bad, token, destination, size),
                                         "unverified-response")

    def test_unexpected_response_never_passes_or_exposes_response_data(self):
        token = b"0123456789abcdef"
        destination = "2606:4700:8::8"
        original = "VPN-required IPv6 connection unexpectedly reached peer"
        for transport, size in (("tcp", m.TCP_BYTES), ("udp", m.UDP_BYTES)):
            frames = [(m.response(m.request(token, size), source, size), expected) for source, expected in (
                ("fd73:1::1", "authenticated-direct-underlay-source"),
                (destination, "authenticated-peer-vpn-source"),
                ("2606:4700:999::123", "authenticated-other-ipv6-source"),
            )]
            valid = frames[0][0]
            frames += [(value, "unverified-response") for value in (
                valid[:-1], b"UNTRUSTED_SECRET", b"X" + valid[1:],
                valid[:-1] + bytes([valid[-1] ^ 1]),
                m.response(m.request(b"abcdef0123456789", size), "fd73:1::1", size),
            )]
            for frame, expected in frames:
                with self.subTest(transport=transport, expected=expected), \
                        patch.object(m.secrets, "token_hex", return_value=token.decode("ascii")), \
                        patch.object(m, transport + "_probe", return_value=frame) as probe, \
                        patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
                    with self.assertRaisesRegex(ValueError, "^" + original + "$"):
                        m.probe(transport, destination, "none", "no-reply")
                    probe.assert_called_once_with(destination, token)
                    self.assertEqual(out.getvalue(), "")
                    self.assertEqual(err.getvalue(),
                                     f"REAL_TUN_IPV6_UNEXPECTED_RESPONSE transport={transport} classification={expected}\n")
                    for redacted in (token.decode("ascii"), "UNTRUSTED_SECRET", "2606:4700:999::123"):
                        self.assertNotIn(redacted, err.getvalue())

    def test_native_denial_is_negative_only(self):
        for transport in ("tcp", "udp"):
            for code in (errno.EPERM, errno.EACCES):
                with self.subTest(transport=transport, errno=code), \
                        patch.object(m, transport + "_probe", side_effect=OSError(code, "native denial")), \
                        patch("sys.stdout", io.StringIO()) as out:
                    m.probe(transport, "2606:4700:8::8", "none", "no-reply")
                    self.assertIn("NO_REPLY=PASS", out.getvalue())
                    with self.assertRaises(OSError):
                        m.probe(transport, "2606:4700:8::8", "2606:4700:8::8", "reply")

    def test_udp_origin_bindings_cannot_fall_back_to_wildcard(self):
        self.assertEqual(set(m.UDP_BIND_ADDRESSES), {
            "2606:4700:5::10", "2606:4700:5::11",
            "2606:4700:8::8", "2606:4700:8::9",
        })
        self.assertNotIn("::", m.UDP_BIND_ADDRESSES)

    def test_address_is_binary_canonicalized(self):
        token = b"0123456789abcdef"
        answer = m.response(m.request(token, m.UDP_BYTES), "2606:4700:5:0:0:0:0:10", m.UDP_BYTES)
        m.verify(answer, token, "2606:4700:5::10", m.UDP_BYTES)


if __name__ == "__main__":
    unittest.main()
