#!/usr/bin/env python3
"""Real large-payload TCP/UDP path witness in a disconnected Linux TUN guest.

No proxy, DNS or fake VPN success. A peer server returns the actual TCP/UDP
source and echoes deterministic, nonce-bound bytes in both directions.
This is not full ICMP PMTUD, IPv6 or physical-host throughput acceptance.
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

MAGIC = b"SCQA-PAYLOAD-v1"
TCP_BYTES = 512 * 1024
UDP_BYTES = 1300
TCP_PORT = 19188
UDP_PORT = 19189
TCP_TIMEOUT = 7.0
UDP_TIMEOUT = 3.0
HEADER_SIZE = len(MAGIC) + 16 + 4
ALLOW_FAILURE = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED,
                 errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT}
MAX_REPLY = TCP_BYTES + len(MAGIC) + 16 + 16


def body(token, count):
    if len(token) != 16 or any(c not in b"0123456789abcdef" for c in token):
        raise ValueError("noncanonical payload token")
    return hashlib.shake_256(token).digest(count)


def packet(token, count):
    return MAGIC + token + struct.pack("!I", count) + body(token, count)


def unpack_request(message, expected_size):
    if len(message) != HEADER_SIZE + expected_size or not message.startswith(MAGIC):
        raise ValueError("invalid request framing or size")
    token = message[len(MAGIC):len(MAGIC) + 16]
    size = struct.unpack("!I", message[len(MAGIC) + 16:HEADER_SIZE])[0]
    if size != expected_size or message[HEADER_SIZE:] != body(token, size):
        raise ValueError("incomplete or mutated request payload")
    return token


def response(message, source, expected_size):
    token = unpack_request(message, expected_size)
    address = source.encode("ascii")
    if address not in (b"10.254.72.1", b"8.8.8.8", b"127.0.0.1"):
        raise ValueError("unexpected synthetic source")
    return MAGIC + address.ljust(16, b"\0") + token + body(token, expected_size)


def verify_response(data, token, expected_source, size):
    expected = MAGIC + expected_source.encode("ascii").ljust(16, b"\0") + token + body(token, size)
    if data != expected:
        raise ValueError("source, nonce, size or echoed payload differs")


def recv_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(min(count - len(result), 65536))
        if not part:
            raise ConnectionError("incomplete TCP payload")
        result.extend(part)
    return bytes(result)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(TCP_TIMEOUT)
        try:
            header = recv_exact(conn, HEADER_SIZE)
            if not header.startswith(MAGIC):
                return
            size = struct.unpack("!I", header[-4:])[0]
            if size != TCP_BYTES:
                return
            received = header + recv_exact(conn, size)
            reply = response(received, self.client_address[0], TCP_BYTES)
            conn.sendall(reply)
        except (ValueError, ConnectionError, OSError):
            return


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request, sock = self.request
        try:
            reply = response(request, self.client_address[0], UDP_BYTES)
            sock.sendto(reply, self.client_address)
        except (ValueError, OSError):
            return


def server():
    with ExitStack() as stack:
        tcp = stack.enter_context(TCPServer(("0.0.0.0", TCP_PORT), TCPHandler))
        udp = stack.enter_context(UDPServer(("0.0.0.0", UDP_PORT), UDPHandler))
        threads = [threading.Thread(target=x.serve_forever, daemon=True) for x in (tcp, udp)]
        for thread in threads:
            thread.start()
        threads[0].join()


def request_tcp(destination, token):
    with socket.create_connection((destination, TCP_PORT), timeout=TCP_TIMEOUT) as sock:
        sock.settimeout(TCP_TIMEOUT)
        sock.sendall(packet(token, TCP_BYTES))
        return recv_exact(sock, len(MAGIC) + 16 + 16 + TCP_BYTES)


def request_udp(destination, token):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(UDP_TIMEOUT)
        sock.sendto(packet(token, UDP_BYTES), (destination, UDP_PORT))
        return sock.recvfrom(MAX_REPLY)[0]


def expect_df_rejection(destination):
    # Linux-specific IP_MTU_DISCOVER=10, IP_PMTUDISC_DO=2. In the guest the
    # genuine TUN reports MTU 1400: a 1390-byte UDP body + 28-byte IPv4/UDP
    # headers MUST fail locally, rather than silently fragment/bypass policy.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IP, 10, 2)
        sock.connect((destination, UDP_PORT))
        try:
            sock.send(b"x" * 1390)
        except OSError as exc:
            if exc.errno == errno.EMSGSIZE:
                print("REAL_TUN_PAYLOAD_DF_LIMIT=PASS (oversized DF datagram rejected locally)", flush=True)
                return
            raise
    raise ValueError("oversized DF datagram was accepted instead of EMSGSIZE")


def client(proto, destination, expected_source, mode):
    if proto not in ("tcp", "udp") or mode not in ("reply", "no-reply"):
        raise ValueError("invalid payload mode")
    if destination not in ("5.22.0.10", "8.8.8.8"):
        raise ValueError("invalid QA-only destination")
    if mode == "reply":
        if expected_source not in ("10.254.72.1", "8.8.8.8"):
            raise ValueError("invalid expected source")
    elif expected_source != "none":
        raise ValueError("negative test cannot expect a source")
    token = secrets.token_hex(8).encode("ascii")
    size = TCP_BYTES if proto == "tcp" else UDP_BYTES
    try:
        data = request_tcp(destination, token) if proto == "tcp" else request_udp(destination, token)
    except (OSError, TimeoutError, ConnectionError) as exc:
        if mode != "no-reply":
            raise
        if isinstance(exc, OSError) and not isinstance(exc, TimeoutError) and exc.errno not in ALLOW_FAILURE:
            raise
        print(f"REAL_TUN_PAYLOAD_{proto.upper()}_NO_REPLY=PASS (upstream unavailable)", flush=True)
        return
    if mode == "no-reply":
        raise ValueError("VPN-required payload received a reply despite upstream loss")
    verify_response(data, token, expected_source, size)
    print(f"REAL_TUN_PAYLOAD_{proto.upper()}=PASS (source={expected_source}, bytes={size})", flush=True)


def main(args):
    if args == ["serve"]:
        server()
    elif len(args) == 2 and args[0] == "df" and args[1] == "8.8.8.8":
        expect_df_rejection(args[1])
    elif len(args) == 4:
        client(*args)
    else:
        raise ValueError("usage: serve | df 8.8.8.8 | tcp|udp DEST SOURCE reply|no-reply")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, ConnectionError) as exc:
        print("REAL_TUN_PAYLOAD=FAIL (" + type(exc).__name__ + ": " + str(exc) + ")", file=sys.stderr)
        sys.exit(1)
