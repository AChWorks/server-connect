#!/usr/bin/env python3
"""Disposable guest-only authoritative DNS wire endpoint (UDP and TCP)."""

import ipaddress
from contextlib import ExitStack
import socketserver
import struct
import threading

SUFFIX = (b"scqa", b"example", b"test")
ANSWER_BY_SOURCE = {
    "10.254.72.1": ipaddress.IPv4Address("192.0.2.11").packed,
    "8.8.8.8": ipaddress.IPv4Address("192.0.2.22").packed,
}


def question_end(message):
    if len(message) < 20 or len(message) > 512:
        raise ValueError("invalid DNS message length")
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", message[:12])
    if flags != 0x0100 or qd != 1 or (an, ns, ar) != (0, 0, 0):
        raise ValueError("only one standard A question is allowed")
    offset = 12
    labels = []
    while True:
        if offset >= len(message):
            raise ValueError("truncated DNS question")
        length = message[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(message):
            raise ValueError("invalid or compressed DNS label")
        labels.append(message[offset:offset + length])
        offset += length
    if len(labels) != 4 or tuple(labels[1:]) != SUFFIX:
        raise ValueError("unexpected DNS query name")
    if not labels[0] or len(labels[0]) > 28:
        raise ValueError("invalid unique DNS probe label")
    if offset + 4 != len(message) or message[offset:] != b"\x00\x01\x00\x01":
        raise ValueError("only an uncompressed IN/A question is supported")
    return offset + 4


def response_for(message, source):
    end = question_end(message)
    if source not in ANSWER_BY_SOURCE:
        return None
    # 0x8180: response, recursion desired/available, no error. The answer's
    # IPv4 value is path-specific and has zero TTL to avoid cache acceptance.
    header = message[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4)
    return header + message[12:end] + answer + ANSWER_BY_SOURCE[source]


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        try:
            reply = response_for(query, self.client_address[0])
        except ValueError:
            return
        if reply is not None:
            sock.sendto(reply, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("incomplete framed DNS request")
        data += chunk
    return data


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            count = struct.unpack("!H", read_exact(self.request, 2))[0]
            if count > 512:
                return
            reply = response_for(read_exact(self.request, count), self.client_address[0])
            if reply is not None:
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except (ValueError, ConnectionError, TimeoutError, OSError):
            return


def main():
    # A wildcard-bound UDP socket can reply using the VETH's primary source
    # even when its query arrived at a synthetic public IP. Bind each
    # authoritative endpoint explicitly so the reply source is genuine.
    with ExitStack() as stack:
        servers = [
            stack.enter_context(kind((address, 53), handler))
            for address in ("5.22.0.10", "8.8.8.8")
            for kind, handler in ((UDPServer, UDPHandler), (TCPServer, TCPHandler))
        ]
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in servers
        ]
        for thread in threads:
            thread.start()
        try:
            threads[0].join()
        finally:
            for server in servers:
                server.shutdown()
            for thread in threads:
                thread.join(timeout=3)


if __name__ == "__main__":
    main()
