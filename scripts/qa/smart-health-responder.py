#!/usr/bin/env python3
"""Bounded, peer-observed health witnesses for the disconnected guest fixture.

The control file maps ``protocol@address`` to a fixed fault mode. An absent
entry means a normal reply. TLS fixture keys are intentionally public QA
material and are supplied separately from the normal installation archive. Updates
are observed for every request, so the fixture can fail one independent
target or one protocol without restarting the VPN core or the underlay.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import stat
import struct
import threading
import time


NONCE_REQUEST = re.compile(rb"SCHEALTH1 ([0-9a-f]{32})\n\Z")
DNS_LABEL = re.compile(rb"[0-9a-f]{28}\Z")
PUBLIC_ADDRESSES = (
    "8.8.8.8", "198.51.100.42", "2001:db8:8::8", "2001:db8:5::10",
)
PORTS = {"tcp": 19220, "udp": 19221, "dns": 19222, "https": 19224}
MAX_CLIENTS = 64
MAX_REQUEST = 256
CLIENT_TIMEOUT = 1.0
HTTPS_NAME = "scqa-health.example.test"
HTTPS_HEADER_LIMIT = 4096
HTTPS_BODY_LIMIT = 256
MAX_TLS_CLIENTS = 16
TLS_TIMEOUT = 1.0
TLS_CERTIFICATES = {"normal": "qa-server.pem", "wrong-name": "qa-wrong-name.pem",
                    "wrong-trust": "qa-wrong-trust.pem", "expired": "qa-expired.pem",
                    "client-auth-only": "qa-client-auth-only.pem"}
MODES = frozenset(("normal", "drop", "bad-nonce", "direct", "status503", "redirect",
                   "malformed", "truncated", "oversized", *TLS_CERTIFICATES))


def fixture_file(path):
    """Read one bounded regular fixture, refusing symlinks and replacements."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 16384:
            raise ValueError("invalid TLS fixture file")
        body = os.read(descriptor, 16385)
        after, named = os.fstat(descriptor), os.lstat(path)
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns")
        if len(body) != before.st_size or any(getattr(before, key) != getattr(after, key) or
                getattr(after, key) != getattr(named, key) for key in fields):
            raise ValueError("TLS fixture file changed during observation")
        return tuple(getattr(before, key) for key in fields), body
    finally:
        os.close(descriptor)


def tls_contexts(bundle):
    contexts = {}
    key = bundle / "qa-server-key.pem"
    key_snapshot = fixture_file(key)
    for mode, filename in TLS_CERTIFICATES.items():
        certificate = bundle / filename
        before = fixture_file(certificate)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        if fixture_file(certificate) != before or fixture_file(key) != key_snapshot:
            raise ValueError("TLS fixture changed while loading")
        contexts[mode] = context
    return contexts


def https_nonce(data):
    if len(data) > HTTPS_HEADER_LIMIT or not data.endswith(b"\r\n\r\n"):
        return None
    lines = data[:-4].split(b"\r\n")
    match = re.fullmatch(rb"GET /health/([0-9a-f]{32}) HTTP/1\.1", lines[0])
    if not match:
        return None
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            return None
        name = name.lower()
        if name in headers or any(byte < 32 or byte > 126 for byte in value):
            return None
        headers[name] = value.strip()
    if headers.get(b"host") not in (HTTPS_NAME.encode(), (HTTPS_NAME + ":19224").encode()):
        return None
    if b"transfer-encoding" in headers or headers.get(b"content-length", b"0") != b"0":
        return None
    return match[1]


def https_response(nonce, peer, mode):
    if mode == "drop":
        return None
    echoed = nonce
    if mode == "bad-nonce":
        echoed = (b"0" if nonce[:1] != b"0" else b"1") + nonce[1:]
    source = "10.254.72.1" if mode == "direct" else normalized(peer)
    body = b"SCHEALTH1 " + echoed + b" " + source.encode("ascii") + b"\n"
    status, headers = b"200 OK", b""
    if mode == "status503":
        status = b"503 Service Unavailable"
    elif mode == "redirect":
        status, headers = b"302 Found", b"Location: https://scqa-health.example.test/other\r\n"
    elif mode == "malformed":
        return b"HTTP/1.1 200 OK\r\nInvalid header\r\n\r\n" + body
    elif mode == "oversized":
        body = b"x" * (HTTPS_BODY_LIMIT + 1)
    length = len(body)
    if mode == "truncated":
        body = body[:-1]
    return (b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(length).encode() +
            b"\r\nConnection: close\r\n" + headers + b"\r\n" + body)


class TLSWorkers:
    """A capped per-connection deadline; shared selector work never handshakes."""

    def __init__(self, contexts, event, maximum=MAX_TLS_CLIENTS, timeout=TLS_TIMEOUT):
        self.contexts, self.event = contexts, event
        self.maximum, self.timeout = maximum, timeout
        self.lock = threading.Lock()
        self.active = {}
        self.stopping = False

    def start(self, connection, peer, destination, mode):
        try:
            worker = threading.Thread(target=self.run, args=(connection, peer, destination, mode), daemon=True)
        except BaseException:
            connection.close()
            raise
        with self.lock:
            if self.stopping or len(self.active) >= self.maximum:
                connection.close()
                return False
            # Record the socket before thread creation can fail or cleanup run.
            self.active[worker] = connection
            try:
                worker.start()
            except BaseException:
                self.active.pop(worker)
                connection.close()
                raise
        return True

    def run(self, connection, peer, destination, mode):
        worker = threading.current_thread()
        deadline = time.monotonic() + self.timeout
        nonce = None
        result = "tls-handshake-failed"
        try:
            # Wrapping without handshake is local. Serialize socket transfer
            # with shutdown so cleanup cannot lose the detached raw descriptor.
            with self.lock:
                if self.stopping:
                    return
                context = self.contexts.get(mode, self.contexts["normal"])
                connection = context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
                self.active[worker] = connection
            self.deadline(connection, deadline)
            connection.do_handshake()
            result = "request-failed"
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) <= HTTPS_HEADER_LIMIT:
                self.deadline(connection, deadline)
                part = connection.recv(HTTPS_HEADER_LIMIT + 1 - len(data))
                if not part:
                    break
                data.extend(part)
            nonce = https_nonce(bytes(data))
            if nonce is None:
                result = "rejected"
                return
            reply = https_response(nonce, peer, mode)
            if reply is None:
                result = "disabled"
                return
            self.deadline(connection, deadline)
            connection.sendall(reply)
            result = "replied"
        except (OSError, ValueError):
            pass
        finally:
            connection.close()
            try:
                self.event("https", destination, peer, result, nonce=nonce, mode=mode)
            finally:
                with self.lock:
                    self.active.pop(worker, None)

    @staticmethod
    def deadline(connection, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TLS worker deadline")
        connection.settimeout(remaining)

    def close(self):
        with self.lock:
            self.stopping = True
            workers = list(self.active)
            for connection in self.active.values():
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        deadline = time.monotonic() + self.timeout + 0.5
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            raise RuntimeError("TLS workers did not finish bounded cleanup")


def normalized(address):
    return str(ipaddress.ip_address(address))


def dns_response(data, peer, destination, direct=False):
    """Answer only this fixture's exact nonce-bearing IN/A question."""
    if len(data) < 17:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    if (flags, qd, an, ns, ar) != (0x0100, 1, 0, 0, 0):
        return None
    labels = []
    offset = 12
    while offset < len(data):
        size = data[offset]
        offset += 1
        if not size:
            break
        if size > 63 or offset + size > len(data):
            return None
        labels.append(data[offset:offset + size])
        offset += size
    else:
        return None
    if (len(labels) != 4 or not DNS_LABEL.fullmatch(labels[0]) or
            labels[1:] != [b"scqa", b"example", b"test"] or
            data[offset:] != struct.pack("!HH", 1, 1)):
        return None
    selected = not direct and normalized(peer) == normalized(destination)
    address = "192.0.2.22" if selected else "192.0.2.11"
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4)
    return (struct.pack("!6H", ident, 0x8180, 1, 1, 0, 0) +
            data[12:] + answer + socket.inet_aton(address))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--tls-bundle", required=True, type=Path)
    args = parser.parse_args()
    contexts = tls_contexts(args.tls_bundle)
    selector = selectors.DefaultSelector()
    stopping = False
    clients = {}
    event_lock = threading.Lock()

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def event(protocol, destination, peer, result, *, nonce=None, mode=None):
        record = {"monotonic_ns": time.monotonic_ns(), "protocol": protocol,
                  "destination": destination, "peer": normalized(peer),
                  "result": result}
        if nonce is not None:
            record["nonce"] = nonce.decode("ascii")
        if mode is not None:
            record["mode"] = mode
        with event_lock:
            with open(args.events, "a", encoding="utf-8") as out:
                out.write(json.dumps(record, separators=(",", ":")) + "\n")

    tls_workers = TLSWorkers(contexts, event)

    def behavior(protocol, destination):
        try:
            with open(args.control, "rb") as source:
                raw = source.read(4097)
            if len(raw) > 4096:
                return "drop"
            config = json.loads(raw)
            if not isinstance(config, dict):
                return "drop"
            value = config.get(protocol + "@" + destination, "normal")
            return value if isinstance(value, str) and value in MODES else "drop"
        except (OSError, ValueError):
            return "drop"

    def response(protocol, destination, peer, data):
        mode = behavior(protocol, destination)
        if mode == "drop":
            event(protocol, destination, peer, "disabled")
            return None
        if protocol == "dns":
            reply = dns_response(data, peer, destination, mode == "direct")
            if reply and mode == "bad-nonce":
                reply = bytes([reply[0] ^ 1]) + reply[1:]
        else:
            match = NONCE_REQUEST.fullmatch(data)
            if not match:
                reply = None
            else:
                nonce = match[1]
                if mode == "bad-nonce":
                    nonce = (b"0" if nonce[:1] != b"0" else b"1") + nonce[1:]
                reported_peer = "10.254.72.1" if mode == "direct" else normalized(peer)
                reply = b"SCHEALTH1 " + nonce + b" " + reported_peer.encode("ascii") + b"\n"
        event(protocol, destination, peer, "replied" if reply else "rejected")
        return reply

    def close_client(client):
        clients.pop(client, None)
        selector.unregister(client)
        client.close()

    try:
        addresses = ["10.254.72.2", "8.8.8.8", "198.51.100.42"]
        if args.ipv6:
            addresses.extend(PUBLIC_ADDRESSES[2:])
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            protocols = ("tcp",) if address == "10.254.72.2" else PORTS
            for protocol in protocols:
                socktype = socket.SOCK_STREAM if protocol in ("tcp", "https") else socket.SOCK_DGRAM
                server = socket.socket(family, socktype)
                try:
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if family == socket.AF_INET6:
                        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    server.bind((address, PORTS[protocol]))
                    server.setblocking(False)
                    if socktype == socket.SOCK_STREAM:
                        server.listen(16)
                    selector.register(server, selectors.EVENT_READ,
                                      ("listener", protocol, address))
                except BaseException:
                    server.close()
                    raise
        with open(args.ready, "x", encoding="ascii") as ready:
            ready.write(str(os.getpid()) + "\n")
        while not stopping:
            for key, _mask in selector.select(0.1):
                sock = key.fileobj
                kind, protocol, destination = key.data
                if kind == "listener" and protocol in ("tcp", "https"):
                    try:
                        client, peer = sock.accept()
                    except (BlockingIOError, ConnectionAbortedError):
                        continue
                    if protocol == "https":
                        tls_workers.start(client, peer[0], destination, behavior(protocol, destination))
                        continue
                    if len(clients) >= MAX_CLIENTS:
                        client.close()
                        continue
                    client.setblocking(False)
                    clients[client] = [time.monotonic() + CLIENT_TIMEOUT, bytearray(), peer[0]]
                    selector.register(client, selectors.EVENT_READ,
                                      ("client", protocol, destination))
                elif kind == "listener":
                    try:
                        data, peer = sock.recvfrom(MAX_REQUEST + 1)
                    except (BlockingIOError, ConnectionResetError):
                        continue
                    reply = response(protocol, destination, peer[0], data)
                    if reply:
                        try:
                            sock.sendto(reply, peer)
                        except OSError:
                            event(protocol, destination, peer[0], "reply-send-failed")
                else:
                    state = clients[sock]
                    try:
                        data = sock.recv(MAX_REQUEST + 1)
                    except BlockingIOError:
                        continue
                    except OSError:
                        close_client(sock)
                        continue
                    state[1].extend(data)
                    if not data or len(state[1]) > MAX_REQUEST:
                        close_client(sock)
                    elif b"\n" in state[1]:
                        reply = response(protocol, destination, state[2], bytes(state[1]))
                        if reply:
                            try:
                                sock.sendall(reply)
                            except (BlockingIOError, BrokenPipeError, ConnectionResetError):
                                pass
                        close_client(sock)
            now = time.monotonic()
            for client, state in list(clients.items()):
                if now >= state[0]:
                    close_client(client)
    finally:
        try:
            tls_workers.close()
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            selector.close()


if __name__ == "__main__":
    main()
