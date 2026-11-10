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
    if len(response) != len(query) + 16 or response[:2] != query[:2]:
        raise ValueError("unexpected DNS response length or transaction ID")
    if response[2:12] != struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0):
        raise ValueError("unexpected DNS response flags/counts")
    if response[12:len(query)] != query[12:]:
        raise ValueError("DNS answer question mismatch")
    if response[len(query):len(query) + 12] != b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4):
        raise ValueError("unexpected DNS answer type or metadata")
    return str(ipaddress.IPv4Address(response[-4:]))


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
    # Only the controlled, disconnected guest needs a private IPv6 DNS
    # positive control. Never accept unrelated private or link-local probes.
    if not address.is_global and destination != "fd73:1::2":
        raise ValueError("DNS target must be a controlled public fixture or the QA IPv6 peer")
    if mode == "reply":
        ipaddress.IPv4Address(expected)
    elif expected != "none":
        raise ValueError("negative DNS mode requires none")
    request = question(phase)
    try:
        response = wire_query(destination, transport, request)
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        if mode not in ("no-reply", "no-success") or (isinstance(exc, OSError) and
            not isinstance(exc, (socket.timeout, TimeoutError)) and exc.errno not in ALLOWED_FAILURE):
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
    actual = answer_ipv4(response, request)
    if actual != expected:
        raise ValueError("DNS wire answer proves wrong source path")
    print("REAL_TUN_DNS_WIRE_REPLY=PASS")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, ConnectionError) as exc:
        print("REAL_TUN_DNS_WIRE=FAIL (" + type(exc).__name__ + ")", file=sys.stderr)
        raise SystemExit(1)
