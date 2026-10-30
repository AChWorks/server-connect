#!/usr/bin/env python3
"""Protocol false-positive regressions; no networking or privileges."""

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import struct
from unittest.mock import patch


def load(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


client = load("smart-health-client")
server = load("smart-health-responder")
nonce = "a" * 28
query = client.dns_query(nonce, 0x1234)
vpn = server.dns_response(query, "8.8.8.8", "8.8.8.8")
direct = server.dns_response(query, "10.254.72.1", "8.8.8.8")
client.require_reply("dns", vpn, query, "192.0.2.22")
client.require_reply("dns", direct, query, "192.0.2.11")


def rejected(protocol, reply, request, expected):
    try:
        client.require_reply(protocol, reply, request, expected)
    except ValueError:
        return
    raise AssertionError("wire false positive accepted")


rejected("dns", direct, query, "192.0.2.22")
rejected("dns", vpn + b"trailing", query, "192.0.2.22")
rejected("dns", vpn, client.dns_query("b" * 28, 0x1234), "192.0.2.22")
rejected("dns", vpn, client.dns_query(nonce, 0x1235), "192.0.2.22")
for invalid in (
    query[:-1], query + b"extra", query[:2] + b"\x81\x80" + query[4:],
    query[:4] + struct.pack("!H", 2) + query[6:],
    query[:-2] + struct.pack("!H", 3),
    client.dns_query("x" * 28, 0x1234),
):
    assert server.dns_response(invalid, "8.8.8.8", "8.8.8.8") is None
request = b"SCHEALTH1 " + b"a" * 32 + b"\n"
reply = request[:-1] + b" 8.8.8.8\n"
for protocol in ("tcp", "udp"):
    client.require_reply(protocol, reply, request, "8.8.8.8")
    rejected(protocol, request[:-1] + b" 10.254.72.1\n", request, "8.8.8.8")
    rejected(protocol, reply, request.replace(b"a", b"b"), "8.8.8.8")
    rejected(protocol, reply + b"extra", request, "8.8.8.8")


class ScriptedTCP:
    """Deliver bytes before a later socket failure, without any networking."""

    def __init__(self, payload, ending):
        self.payload = payload
        self.ending = ending
        self.request = None
        self.reads = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        pass

    def connect(self, _address):
        pass

    def sendall(self, data):
        self.request = data

    def recv(self, _limit):
        self.reads += 1
        if self.reads == 1:
            if self.payload == "exact":
                return self.request[:-1] + b" 8.8.8.8\n"
            return self.payload
        if isinstance(self.ending, Exception):
            raise self.ending
        return self.ending


def tcp_case(mode, payload, ending, accepted):
    output = io.StringIO()
    fake = ScriptedTCP(payload, ending)
    with patch.object(client.socket, "socket", return_value=fake), \
            patch.object(client.sys, "argv", ["health-client", "tcp", "8.8.8.8", mode]), \
            contextlib.redirect_stdout(output):
        try:
            client.main()
        except ValueError:
            assert not accepted, "valid TCP control was rejected"
            assert not output.getvalue(), "failed probe emitted a successful receipt"
            return
    assert accepted, "delivered TCP bytes were incorrectly accepted as a blocked path"
    assert json.loads(output.getvalue())["outcome"] == mode


for payload in (b"S", "exact"):
    for ending in (TimeoutError("after payload"), ConnectionResetError("after payload"), b""):
        tcp_case("blocked", payload, ending, False)
for ending in (TimeoutError("after exact frame"), ConnectionResetError("after exact frame")):
    tcp_case("vpn", "exact", ending, False)
tcp_case("vpn", "exact", b"", True)
tcp_case("blocked", b"", b"", True)
print("SMART_HEALTH_WIRE_FALSE_POSITIVES_REJECTED=PASS")
print("SMART_HEALTH_PARTIAL_TCP_FAILURE_NOT_BLOCKED=PASS")
