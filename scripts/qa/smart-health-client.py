#!/usr/bin/env python3
"""Independent single-request traffic check for the guest health endpoints."""

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import struct
import sys
import time


PORTS = {"tcp": 19220, "udp": 19221, "dns": 19222, "https": 19224}
HTTPS_NAME = "scqa-health.example.test"
HTTPS_HEADER_LIMIT = 4096
HTTPS_BODY_LIMIT = 256


def authenticated_context(bundle):
    # Supplying the one public root explicitly keeps ambient trust stores and
    # caller environment out of this independent fixture check.
    path = bundle / "qa-root.pem"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 16384:
            raise ValueError("invalid public QA trust file")
        data = os.read(descriptor, 16385)
        after, named = os.fstat(descriptor), os.lstat(path)
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns")
        if len(data) != before.st_size or any(getattr(before, key) != getattr(after, key) or
                getattr(after, key) != getattr(named, key) for key in fields):
            raise ValueError("public QA trust file changed during observation")
    finally:
        os.close(descriptor)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=data.decode("ascii"))
    return context


def https_request(nonce):
    return ("GET /health/" + nonce + " HTTP/1.1\r\nHost: " + HTTPS_NAME +
            "\r\nConnection: close\r\n\r\n").encode("ascii")


def require_https_reply(data, request, expected):
    header, separator, body = data.partition(b"\r\n\r\n")
    if not separator or len(header) + 4 > HTTPS_HEADER_LIMIT:
        raise ValueError("HTTPS response header is missing or oversized")
    lines = header.split(b"\r\n")
    if re.fullmatch(rb"HTTP/1\.1 200 [\x20-\x7e]*", lines[0]) is None:
        raise ValueError("HTTPS response is not HTTP/1.1 status 200")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise ValueError("malformed HTTPS response header")
        name, value = name.lower(), value.strip()
        if name in headers or any(byte < 32 or byte > 126 for byte in value):
            raise ValueError("duplicate or invalid HTTPS response header")
        headers[name] = value
    length = headers.get(b"content-length", b"")
    if (re.fullmatch(rb"0|[1-9][0-9]*", length) is None or
            len(length) > 3 or int(length) > HTTPS_BODY_LIMIT or
            b"transfer-encoding" in headers or b"content-encoding" in headers):
        raise ValueError("unbounded or encoded HTTPS response")
    if len(body) != int(length):
        raise ValueError("truncated or trailing HTTPS response body")
    require_reply("https", body, request, expected)


def deadline(client, expires):
    remaining = expires - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("health request deadline")
    client.settimeout(remaining)


def dns_query(nonce, identifier):
    labels = [nonce.encode("ascii"), b"scqa", b"example", b"test"]
    question = b"".join(bytes([len(label)]) + label for label in labels)
    question += b"\0" + struct.pack("!HH", 1, 1)
    return struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + question


def require_reply(protocol, data, request, expected):
    if protocol == "dns":
        ident = struct.unpack("!H", request[:2])[0]
        answer = (struct.pack("!6H", ident, 0x8180, 1, 1, 0, 0) + request[12:] +
                  b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) +
                  socket.inet_aton(expected))
        if data != answer:
            raise ValueError("DNS response did not exactly bind nonce, transaction, question and selected source")
    elif data != request.rstrip(b"\n") + b" " + expected.encode("ascii") + b"\n":
        raise ValueError("health reply did not exactly bind request nonce and observed source")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol", choices=PORTS)
    parser.add_argument("destination")
    parser.add_argument("mode", choices=("direct", "vpn", "blocked"))
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--tls-bundle", type=Path)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.destination)
    if args.timeout <= 0 or args.timeout > 5:
        parser.error("timeout must be in (0, 5]")
    if args.protocol == "https" and args.tls_bundle is None:
        parser.error("HTTPS requires the explicit public QA trust bundle")
    context = authenticated_context(args.tls_bundle) if args.protocol == "https" else None
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    nonce = secrets.token_hex(14 if args.protocol == "dns" else 16)
    request = (dns_query(nonce, secrets.randbelow(65536)) if args.protocol == "dns"
               else ("SCHEALTH1 " + nonce + "\n").encode("ascii"))
    socktype = socket.SOCK_STREAM if args.protocol in ("tcp", "https") else socket.SOCK_DGRAM
    reply = None
    unavailable = None
    tls_authenticated = False
    expires = time.monotonic() + args.timeout
    with socket.socket(family, socktype) as client:
        try:
            deadline(client, expires)
            client.connect((str(address), PORTS[args.protocol]))
            if context is not None:
                # Connect to the literal target, then authenticate the fixed
                # name. No resolver, proxy, custom time or disabled check.
                client = context.wrap_socket(client, server_hostname=HTTPS_NAME, do_handshake_on_connect=False)
                deadline(client, expires)
                client.do_handshake()
                tls_authenticated = True
            deadline(client, expires)
            client.sendall(https_request(nonce) if context is not None else request)
            if args.protocol in ("tcp", "https"):
                received = bytearray()
                limit = HTTPS_HEADER_LIMIT + HTTPS_BODY_LIMIT + 1 if context is not None else 256
                while len(received) < limit:
                    deadline(client, expires)
                    data = client.recv(limit - len(received))
                    if not data:
                        break
                    received.extend(data)
                    # A later timeout/reset cannot turn delivered bytes into
                    # evidence that the selected path was blocked.
                    reply = bytes(received)
                if received:
                    reply = bytes(received)
                else:
                    unavailable = "eof"
            else:
                deadline(client, expires)
                reply = client.recv(512)
        except ssl.SSLError:
            # An unauthenticated TLS response is a failed control, never a
            # successful VPN check or proof that all response traffic stopped.
            raise ValueError("HTTPS certificate or handshake validation failed") from None
        except (TimeoutError, ConnectionRefusedError, ConnectionResetError) as exc:
            unavailable = type(exc).__name__
        except OSError as exc:
            if exc.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                 errno.ETIMEDOUT, errno.EPIPE):
                raise
            unavailable = errno.errorcode.get(exc.errno, "socket-error")
        finally:
            client.close()
    if args.mode == "blocked":
        if reply is not None or unavailable is None or tls_authenticated:
            raise ValueError("blocked path unexpectedly delivered a response")
        result = {"protocol": args.protocol, "destination": str(address),
                  "outcome": "blocked", "reason": unavailable}
    else:
        if reply is None or unavailable is not None:
            raise ValueError("expected path unavailable: " + str(unavailable))
        if args.protocol == "dns":
            expected = "192.0.2.22" if args.mode == "vpn" else "192.0.2.11"
        elif args.mode == "vpn":
            expected = str(address)
        else:
            expected = "fd73:1::1" if address.version == 6 else "10.254.72.1"
        if context is not None:
            require_https_reply(reply, request, expected)
        else:
            require_reply(args.protocol, reply, request, expected)
        result = {"protocol": args.protocol, "destination": str(address),
                  "outcome": args.mode, "observed_source": expected}
        if context is not None:
            result.update(tls_authenticated=True, server_name=HTTPS_NAME, nonce=nonce)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("SMART_HEALTH_WIRE=FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
