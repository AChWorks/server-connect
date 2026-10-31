#!/usr/bin/env python3
"""Disconnected guest-only IPv6 TCP/UDP source and data-plane witnesses.

No resolver, per-process routing, application proxy, field IPv6, or product
Apply is involved. Both source address and token/bodies originate in the peer.
"""
import errno
import hashlib
import secrets
import socket
import socketserver
import struct
import sys
import threading
from contextlib import ExitStack

MAGIC = b"SCQA-V6-WIRE"
TCP_BYTES = 128 * 1024
UDP_BYTES = 900
TCP_PORT = 19192
UDP_PORT = 19193
# Explicitly bind one independent UDP socket per loopback destination.
# Linux wildcard UDP replies may otherwise select the primary interface
# address, giving a false source identity on a genuine IPv6 Direct request.
UDP_BIND_ADDRESSES = ("2606:4700:5::10", "2606:4700:5::11",
                      "2606:4700:8::8", "2606:4700:8::9")
ALLOWED = {
    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED,
    errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT,
    # Native OUTPUT containment can reject before transmission. These are
    # accepted only by negative probes; positive paths must still succeed.
    errno.EPERM, errno.EACCES
}
HEADER = len(MAGIC) + 16 + 4


def data(token, size):
    if len(token) != 16 or any(c not in b"0123456789abcdef" for c in token):
        raise ValueError("noncanonical QA token")
    return hashlib.shake_256(token).digest(size)


def request(token, size):
    return MAGIC + token + struct.pack("!I", size) + data(token, size)


def response(request_bytes, observed_source, size):
    if len(request_bytes) != HEADER + size or not request_bytes.startswith(MAGIC):
        raise ValueError("wrong request frame/size")
    token = request_bytes[len(MAGIC):len(MAGIC) + 16]
    length = struct.unpack("!I", request_bytes[HEADER - 4:HEADER])[0]
    if length != size or request_bytes[HEADER:] != data(token, size):
        raise ValueError("corrupt request body/token")
    # No source is supplied by the request. Only the peer socket provides it.
    address = socket.inet_pton(socket.AF_INET6, observed_source)
    return MAGIC + address + token + data(token, size)


def verify(reply, token, expected_source, size):
    expected = MAGIC + socket.inet_pton(socket.AF_INET6, expected_source) + token + data(token, size)
    if reply != expected:
        raise ValueError("wrong IPv6 source, nonce, size, or exact response bytes")


def unexpected_response_kind(reply, token, destination, size):
    # Authenticate the already received frame before classifying its source.
    # Only fixed labels leave this function; arbitrary response bytes, source
    # text and the nonce are never diagnostic output or a reason to pass QA.
    try:
        if not isinstance(reply, bytes) or len(reply) != len(MAGIC) + 32 + size:
            return "unverified-response"
        source = socket.inet_ntop(socket.AF_INET6, reply[len(MAGIC):len(MAGIC) + 16])
        verify(reply, token, source, size)
    except (OSError, ValueError, TypeError):
        return "unverified-response"
    if source == "fd73:1::1":
        return "authenticated-direct-underlay-source"
    if source == destination:
        return "authenticated-peer-vpn-source"
    return "authenticated-other-ipv6-source"


def recv_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(min(65536, count - len(result)))
        if not part:
            raise ConnectionError("truncated IPv6 TCP transfer")
        result.extend(part)
    return bytes(result)


class TCP6(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            header = recv_exact(self.request, HEADER)
            if not header.startswith(MAGIC):
                return
            size = struct.unpack("!I", header[-4:])[0]
            if size != TCP_BYTES:
                return
            payload = header + recv_exact(self.request, size)
            self.request.sendall(response(payload, self.client_address[0], TCP_BYTES))
        except (OSError, ValueError, ConnectionError):
            return


class UDP6(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        try:
            sock.sendto(response(payload, self.client_address[0], UDP_BYTES), self.client_address)
        except (OSError, ValueError):
            return


def serve():
    with ExitStack() as stack:
        tcp = stack.enter_context(TCP6(("::", TCP_PORT), TCPHandler))
        # Same destination, same reply source for native Direct and VLESS
        # regardless of which source/interface Linux would pick for ::.
        udp_servers = [
            stack.enter_context(UDP6((address, UDP_PORT), UDPHandler))
            for address in UDP_BIND_ADDRESSES
        ]
        servers = [tcp, *udp_servers]
        threads = [threading.Thread(target=x.serve_forever, daemon=True) for x in servers]
        for thread in threads:
            thread.start()
        threads[0].join()


def tcp_probe(destination, token):
    with socket.create_connection((destination, TCP_PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(request(token, TCP_BYTES))
        return recv_exact(sock, len(MAGIC) + 16 + 16 + TCP_BYTES)


def udp_probe(destination, token):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(request(token, UDP_BYTES), (destination, UDP_PORT))
        reply, source = sock.recvfrom(1500)
        if source[0] != destination:
            raise ValueError("UDP reply came from a different IPv6 destination")
        return reply


def probe(transport, destination, expected_source, mode):
    if transport not in ("tcp", "udp") or mode not in ("reply", "no-reply"):
        raise ValueError("invalid IPv6 QA mode")
    if destination not in UDP_BIND_ADDRESSES:
        raise ValueError("not a controlled synthetic IPv6 fixture")
    if mode == "reply":
        if expected_source not in ("fd73:1::1", *UDP_BIND_ADDRESSES):
            raise ValueError("invalid IPv6 positive source expectation")
    elif expected_source != "none":
        raise ValueError("negative IPv6 expectation requires no source")
    token = secrets.token_hex(8).encode("ascii")
    try:
        value = tcp_probe(destination, token) if transport == "tcp" else udp_probe(destination, token)
    except (OSError, ConnectionError) as exc:
        if mode != "no-reply":
            raise
        if isinstance(exc, OSError) and not isinstance(exc, TimeoutError) and exc.errno not in ALLOWED:
            raise
        print(f"REAL_TUN_IPV6_{transport.upper()}_NO_REPLY=PASS (upstream unavailable)", flush=True)
        return
    if mode == "no-reply":
        kind = unexpected_response_kind(value, token, destination,
                                        TCP_BYTES if transport == "tcp" else UDP_BYTES)
        print(f"REAL_TUN_IPV6_UNEXPECTED_RESPONSE transport={transport} classification={kind}",
              file=sys.stderr, flush=True)
        raise ValueError("VPN-required IPv6 connection unexpectedly reached peer")
    verify(value, token, expected_source, TCP_BYTES if transport == "tcp" else UDP_BYTES)
    print(f"REAL_TUN_IPV6_{transport.upper()}=PASS (source={expected_source})", flush=True)


def main(args):
    if args == ["serve"]:
        serve()
    elif len(args) == 4:
        probe(*args)
    else:
        raise ValueError("usage: serve | tcp|udp DEST EXPECTED_SOURCE reply|no-reply")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, ConnectionError) as exc:
        print(f"REAL_TUN_IPV6=FAIL ({type(exc).__name__}: {exc})", file=sys.stderr)
        sys.exit(1)
