#!/usr/bin/env python3
"""Independent single-request traffic check for the guest health endpoints."""

import argparse
import errno
import ipaddress
import json
import secrets
import socket
import struct
import sys


PORTS = {"tcp": 19220, "udp": 19221, "dns": 19222}


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
    args = parser.parse_args()
    address = ipaddress.ip_address(args.destination)
    if args.timeout <= 0 or args.timeout > 5:
        parser.error("timeout must be in (0, 5]")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    nonce = secrets.token_hex(14 if args.protocol == "dns" else 16)
    request = (dns_query(nonce, secrets.randbelow(65536)) if args.protocol == "dns"
               else ("SCHEALTH1 " + nonce + "\n").encode("ascii"))
    socktype = socket.SOCK_STREAM if args.protocol == "tcp" else socket.SOCK_DGRAM
    reply = None
    unavailable = None
    with socket.socket(family, socktype) as client:
        client.settimeout(args.timeout)
        try:
            client.connect((str(address), PORTS[args.protocol]))
            client.sendall(request)
            if args.protocol == "tcp":
                received = bytearray()
                while len(received) < 256:
                    data = client.recv(256 - len(received))
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
                reply = client.recv(512)
        except (TimeoutError, ConnectionRefusedError, ConnectionResetError) as exc:
            unavailable = type(exc).__name__
        except OSError as exc:
            if exc.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                 errno.ETIMEDOUT, errno.EPIPE):
                raise
            unavailable = errno.errorcode.get(exc.errno, "socket-error")
    if args.mode == "blocked":
        if reply is not None or unavailable is None:
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
        require_reply(args.protocol, reply, request, expected)
        result = {"protocol": args.protocol, "destination": str(address),
                  "outcome": args.mode, "observed_source": expected}
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("SMART_HEALTH_WIRE=FAIL: " + str(exc), file=sys.stderr)
        sys.exit(1)
