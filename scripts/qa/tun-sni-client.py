#!/usr/bin/env python3
"""Disposable guest: real TLS ClientHello/SNI path proof, never certificate trust.

The peer presents an ephemeral self-signed test certificate. TLS verification
is disabled only to isolate packet routing from public PKI and DNS. These
tests do not authenticate an operator domain or a real VPN endpoint.
"""

import http.client
import socket
import ssl
import sys

if len(sys.argv) != 5:
    raise SystemExit("usage: tun-sni-client HOST|- IP EXPECTED_SOURCE|- reply|no-reply")

host, destination, expected_source, mode = sys.argv[1:]
if mode not in ("reply", "no-reply"):
    raise SystemExit("invalid TLS QA mode")
if mode == "reply" and expected_source == "-":
    raise SystemExit("positive TLS proof requires an expected source")
if mode == "no-reply" and expected_source != "-":
    raise SystemExit("negative TLS proof cannot claim a source")

# The '-' fixture deliberately omits SNI, proving name matching is optional
# rather than blindly applied to every connection to a domestic IP address.
sni = None if host == "-" else host
http_host = "no-sni.qa.invalid" if host == "-" else host
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    with socket.create_connection((destination, 19181), timeout=2) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            tls.settimeout(2)
            tls.sendall(
                ("GET /sni-proof HTTP/1.1\r\nHost: " + http_host +
                 "\r\nConnection: close\r\n\r\n").encode("ascii")
            )
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read()
            status = response.status
except (OSError, http.client.HTTPException) as exc:
    if mode != "no-reply":
        raise SystemExit("TLS positive path failed: " + str(exc)) from exc
    print("REAL_TUN_TLS_NO_RESPONSE=PASS")
    sys.exit(0)

if mode == "no-reply":
    raise SystemExit("TLS VPN-required request unexpectedly received a response")
if status != 200 or body != ("SOURCE=" + expected_source).encode("ascii"):
    raise SystemExit(
        "TLS source/path mismatch: status=" + str(status) + " body=" + repr(body)
    )
print("REAL_TUN_TLS_SOURCE_PATH=PASS")
