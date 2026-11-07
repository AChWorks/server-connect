#!/usr/bin/env python3
"""Bounded HTTPS source witness for explicitly authorized disposable field QA.

This is an independent observer, not a Server Connect activation mechanism.
Use ephemeral TLS keys and trust their public CA only inside the disposable
client. Two independently hosted instances can witness real Direct/VPN exits.
No authentication material, arbitrary headers or request bodies are logged.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import threading
import time

REQUEST = re.compile(rb"GET /trace\?sc_health=([0-9a-f]{32}) HTTP/1\.1\Z")
MAX_HEADER = 4096
MAX_CLIENTS = 8
DEADLINE = 4.0


def parse_request(data, name, port):
    if len(data) > MAX_HEADER or not data.endswith(b"\r\n\r\n"):
        raise ValueError("invalid request framing")
    lines = data[:-4].split(b"\r\n")
    match = REQUEST.fullmatch(lines[0])
    if match is None:
        raise ValueError("unexpected request target")
    headers = {}
    for line in lines[1:]:
        key, separator, value = line.partition(b":")
        key = key.lower()
        if not separator or key in headers or not re.fullmatch(rb"[a-z0-9-]+", key):
            raise ValueError("ambiguous request headers")
        if any(byte < 32 or byte > 126 for byte in value):
            raise ValueError("invalid header byte")
        headers[key] = value.strip()
    expected = {name.encode("ascii"), f"{name}:{port}".encode("ascii")}
    if headers.get(b"host") not in expected or b"transfer-encoding" in headers or headers.get(b"content-length", b"0") != b"0":
        raise ValueError("unexpected request authority or body")
    return match[1].decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--name", required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=6600)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.listen)
    if address.version != 4 or not 1024 <= args.port <= 65535 or not 1 <= args.seconds <= 7200:
        parser.error("explicit IPv4, unprivileged port and bounded lifetime required")
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", args.name):
        parser.error("canonical TLS name required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(args.cert, args.key)
    descriptor = os.open(args.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    log = os.fdopen(descriptor, "w", encoding="utf-8")
    lock = threading.Lock()
    stopping = threading.Event()
    slots = threading.BoundedSemaphore(MAX_CLIENTS)
    workers = set()
    count = 0

    def event(kind, **fields):
        nonlocal count
        with lock:
            count += 1
            log.write(json.dumps({"event": kind, "sequence": count, "unix_ns": time.time_ns(),
                                  "monotonic_ns": time.monotonic_ns(), **fields},
                                 sort_keys=True, separators=(",", ":")) + "\n")
            log.flush()
            os.fsync(log.fileno())
            if count >= 50000:
                stopping.set()

    def handle(raw, peer):
        secure = None
        nonce = None
        try:
            raw.settimeout(DEADLINE)
            started = time.monotonic()
            secure = context.wrap_socket(raw, server_side=True)
            data = bytearray()
            while not data.endswith(b"\r\n\r\n"):
                remaining = DEADLINE - (time.monotonic() - started)
                if remaining <= 0 or len(data) >= MAX_HEADER:
                    raise ValueError("request bound exceeded")
                secure.settimeout(remaining)
                block = secure.recv(1)
                if not block:
                    raise ValueError("incomplete request")
                data.extend(block)
            nonce = parse_request(bytes(data), args.name, args.port)
            source = str(ipaddress.ip_address(peer[0]))
            event("request", nonce=nonce, source=source, source_port=peer[1], witness=args.name)
            body = f"ip={source}\nvisit_scheme=https\nsc_health={nonce}\nts={time.time():.3f}\n".encode("ascii")
            response = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                        "Cache-Control: no-store\r\nConnection: close\r\n\r\n").encode("ascii") + body
            remaining = DEADLINE - (time.monotonic() - started)
            if remaining <= 0:
                raise ValueError("response deadline exceeded")
            secure.settimeout(remaining)
            secure.sendall(response)
            event("response", nonce=nonce, source=source, witness=args.name)
        except (OSError, ValueError):
            # Keep failures useful without publishing attacker-supplied data.
            event("rejected", nonce=nonce, source=peer[0])
        finally:
            if secure is not None:
                secure.close()
            raw.close()
            with lock:
                workers.discard(threading.current_thread())
            slots.release()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((args.listen, args.port))
        listener.listen(MAX_CLIENTS)
        listener.settimeout(0.5)
        event("ready", address=args.listen, port=args.port, witness=args.name,
              certificate_sha256=hashlib.sha256(args.cert.read_bytes()).hexdigest())
        print(json.dumps({"ready": True, "address": args.listen, "port": args.port, "witness": args.name}), flush=True)
        expires = time.monotonic() + args.seconds
        while not stopping.is_set() and time.monotonic() < expires:
            try:
                connection, peer = listener.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                connection.close()
                continue
            worker = threading.Thread(target=handle, args=(connection, peer), daemon=True)
            with lock:
                workers.add(worker)
            try:
                worker.start()
            except BaseException:
                with lock:
                    workers.discard(worker)
                connection.close()
                slots.release()
                raise
    finally:
        stopping.set()
        listener.close()
        with lock:
            active = list(workers)
        for worker in active:
            worker.join(DEADLINE + 1)
        event("stopped")
        log.close()


if __name__ == "__main__":
    main()
