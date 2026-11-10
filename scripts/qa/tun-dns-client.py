#!/usr/bin/env python3
"""Proxy-unaware DNS wire probe for the disconnected real-TUN QA guest."""

import errno
import ipaddress
import re
import socket
import struct
import sys

TIMEOUT = 2.0
QUERY_ID = 0x5A71
QTYPE_A_IN = b"\x00\x01\x00\x01"
ALLOWED_FAILURE = {
    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED,
    errno.ETIMEDOUT, errno.ECONNRESET, errno.EPIPE,
}


def question(phase):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,27}", phase):
        raise ValueError("invalid DNS probe phase")
    labels = (phase, "scqa", "example", "test")
    name = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0"
    header = struct.pack("!HHHHHH", QUERY_ID, 0x0100, 1, 0, 0, 0)
    return header + name + QTYPE_A_IN


def answer_ipv4(response, query):
    if len(response) < len(query) + 16 or response[:2] != query[:2]:
        raise ValueError("unexpected DNS response length or transaction ID")
    if response[2:12] != struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0):
        raise ValueError("unexpected DNS response flags/counts")
    if response[12:len(query)] != query[12:]:
        raise ValueError("DNS answer question mismatch")

    # The fixture's authoritative DNS server uses an RFC 1035 compression
    # pointer. The official Core parses and re-serializes hijacked replies,
    # which may instead write the SAME owner as an uncompressed wire name.
    # Both are valid; never accept an unrelated owner or a loose DNS suffix.
    owner_start = len(query)
    if response[owner_start:owner_start + 2] == b"\xc0\x0c":
        record_start = owner_start + 2
    elif response[owner_start:owner_start + len(query[12:-4])] == query[12:-4]:
        record_start = owner_start + len(query[12:-4])
    else:
        raise ValueError("DNS answer owner does not match exact question")
    if len(response) != record_start + 14:
        raise ValueError("unexpected DNS response length or transaction ID")
    rr_type, rr_class, _ttl, size = struct.unpack("!HHIH", response[record_start:record_start + 10])
    if (rr_type, rr_class, size) != (1, 1, 4):
        raise ValueError("unexpected DNS answer type or metadata")
    return str(ipaddress.IPv4Address(response[record_start + 10:]))


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("incomplete DNS TCP response")
        data += chunk
    return data


def wire_query(destination, transport, query):
    family = socket.AF_INET6 if ipaddress.ip_address(destination).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        if transport == "tcp":
            sock.connect((destination, 53))
            sock.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", read_exact(sock, 2))[0]
            if length > 512:
                raise ValueError("oversized DNS TCP answer")
            return read_exact(sock, length)
        sock.sendto(query, (destination, 53))
        response, source = sock.recvfrom(512)
        if ipaddress.ip_address(source[0]) != ipaddress.ip_address(destination) or source[1] != 53:
            raise ValueError("DNS reply came from another endpoint")
        return response


def main(args):
    if len(args) != 5:
        raise ValueError("usage: DEST EXPECTED_IP|none PHASE udp|tcp reply|no-reply|no-success")
    destination, expected, phase, transport, mode = args
    if transport not in ("udp", "tcp") or mode not in ("reply", "no-reply", "no-success"):
        raise ValueError("invalid DNS probe mode")
    address = ipaddress.ip_address(destination)
    # Only these two fixed on-link IPv4/IPv6 DNS peers are accepted inside
    # the disconnected guest. Reject every other private/link-local target.
    if not address.is_global and destination not in ("fd73:1::2", "10.254.72.2"):
        raise ValueError("DNS target must be a public fixture or an exact private QA peer")
    if mode == "reply":
        ipaddress.IPv4Address(expected)
    elif expected != "none":
        raise ValueError("negative DNS mode requires none")
    request = question(phase)
    try:
        response = wire_query(destination, transport, request)
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        # On a failed selected path, Core can close a DNS-over-TCP stream
        # before sending its length-prefixed response. The precise EOF from
        # read_exact() is a valid no-success outcome, but an arbitrary
        # ConnectionError or a UDP framing error must remain a test failure.
        expected_timeout = isinstance(exc, (socket.timeout, TimeoutError))
        expected_tcp_eof = (transport == "tcp" and type(exc) is ConnectionError and
                            str(exc) == "incomplete DNS TCP response")
        expected_errno = isinstance(exc, OSError) and exc.errno in ALLOWED_FAILURE
        if mode not in ("no-reply", "no-success") or not (
                expected_timeout or expected_tcp_eof or expected_errno):
            raise
        print("REAL_TUN_DNS_NO_RESPONSE=PASS")
        return
    if mode == "no-reply":
        raise ValueError("VPN-required DNS unexpectedly returned a response")
    if mode == "no-success":
        # A local failure (SERVFAIL/REFUSED) is not a successful resolver
        # reply, but an independently observed native Direct leak still fails
        # in the caller's peer-side packet counters.
        if len(response) == len(request) and response[:2] == request[:2] and response[12:] == request[12:]:
            flags, qd, an, ns, ar = struct.unpack("!HHHHH", response[2:12])
            if flags in (0x8182, 0x8185) and qd == 1 and an == 0 and ns == 0 and ar == 0:
                print("REAL_TUN_DNS_NO_SUCCESS=PASS")
                return
        raise ValueError("VPN-required DNS unexpectedly returned a successful or invalid response")
    try:
        actual = answer_ipv4(response, request)
    except ValueError:
        # Only DNS header metadata from this disconnected synthetic fixture;
        # never print its query name, wire payload or returned address.
        if len(response) >= 12:
            flags, qd, an, ns, ar = struct.unpack("!HHHHH", response[2:12])
            print(f"REAL_TUN_DNS_REPLY_METADATA flags=0x{flags:04x} rcode={flags & 15} "
                  f"questions={qd} answers={an} authority={ns} additional={ar} "
                  f"wire_bytes={len(response)}", file=sys.stderr)
        raise
    if actual != expected:
        source = {"192.0.2.11": "native-underlay-direct", "192.0.2.22": "vpn-original-destination",
                  "192.0.2.33": "vpn-detoured-resolver"}.get(actual, "unrecognized-answer-source")
        print("REAL_TUN_DNS_SOURCE_CLASSIFICATION=" + source, file=sys.stderr)
        raise ValueError("DNS wire answer proves wrong source path")
    print("REAL_TUN_DNS_WIRE_REPLY=PASS")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, ConnectionError) as exc:
        known = {
            "unexpected DNS response length or transaction ID": "wire-length-or-id",
            "unexpected DNS response flags/counts": "wire-flags-or-rcode",
            "DNS answer question mismatch": "wire-question",
            "unexpected DNS answer type or metadata": "wire-answer-metadata",
            "DNS wire answer proves wrong source path": "path-source",
            "DNS reply came from another endpoint": "socket-peer",
            "VPN-required DNS unexpectedly returned a successful or invalid response": "outage-success",
        }
        reason = known.get(str(exc), "unexpected")
        print(f"REAL_TUN_DNS_WIRE=FAIL ({type(exc).__name__}, reason={reason})", file=sys.stderr)
        raise SystemExit(1)
