#!/usr/bin/env python3
"""Bounded, peer-observed health witnesses for the disconnected guest fixture.

The control file is an object mapping ``protocol@address`` to ``drop``,
``bad-nonce`` or ``direct``.  An absent entry means a normal reply.  Updates
are observed for every request, so the fixture can fail one independent
target or one protocol without restarting the VPN core or the underlay.
"""

import argparse
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import struct
import time


NONCE_REQUEST = re.compile(rb"SCHEALTH1 ([0-9a-f]{32})\n\Z")
DNS_LABEL = re.compile(rb"[0-9a-f]{28}\Z")
PUBLIC_ADDRESSES = (
    "8.8.8.8", "198.51.100.42", "2001:db8:8::8", "2001:db8:5::10",
)
PORTS = {"tcp": 19220, "udp": 19221, "dns": 19222}
MAX_CLIENTS = 64
MAX_REQUEST = 256
CLIENT_TIMEOUT = 1.0


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
    args = parser.parse_args()
    selector = selectors.DefaultSelector()
    stopping = False
    clients = {}

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def event(protocol, destination, peer, result):
        record = {"monotonic_ns": time.monotonic_ns(), "protocol": protocol,
                  "destination": destination, "peer": normalized(peer),
                  "result": result}
        with open(args.events, "a", encoding="utf-8") as out:
            out.write(json.dumps(record, separators=(",", ":")) + "\n")

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
            return value if value in ("normal", "drop", "bad-nonce", "direct") else "drop"
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
                socktype = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
                server = socket.socket(family, socktype)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                server.bind((address, PORTS[protocol]))
                server.setblocking(False)
                if protocol == "tcp":
                    server.listen(16)
                selector.register(server, selectors.EVENT_READ,
                                  ("listener", protocol, address))
        with open(args.ready, "x", encoding="ascii") as ready:
            ready.write(str(os.getpid()) + "\n")
        while not stopping:
            for key, _mask in selector.select(0.1):
                sock = key.fileobj
                kind, protocol, destination = key.data
                if kind == "listener" and protocol == "tcp":
                    try:
                        client, peer = sock.accept()
                    except (BlockingIOError, ConnectionAbortedError):
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
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()


if __name__ == "__main__":
    main()
