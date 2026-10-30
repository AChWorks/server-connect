#!/usr/bin/env python3
"""Protocol regressions with bounded ordinary loopback TLS; no privileges."""

import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import threading
import time
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

    def close(self):
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

bundle = Path(__file__).resolve().parents[2] / "internal/sc/testdata/smart-health-tls"
contexts = server.tls_contexts(bundle)
trust = client.authenticated_context(bundle)
assert trust.check_hostname and trust.verify_mode == ssl.CERT_REQUIRED
assert len(trust.get_ca_certs()) == 1, "independent client used ambient trust roots"
https_nonce = "b" * 32
https_wire = client.https_request(https_nonce)
assert server.https_nonce(https_wire) == https_nonce.encode()
for malformed in (https_wire + b"body", https_wire.replace(b"GET", b"POST", 1),
                  https_wire.replace(b"/health/", b"/other/"),
                  https_wire.replace(b"Host: ", b"Host: wrong-"),
                  https_wire.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
                  https_wire.replace(b"\r\n\r\n", b"\r\nHost: scqa-health.example.test\r\n\r\n"),
                  b"x" * 4097):
    assert server.https_nonce(malformed) is None


@contextlib.contextmanager
def tls_peer(mode="normal", *, maximum=16, timeout=0.5):
    events, errors = [], []
    workers = server.TLSWorkers(contexts, lambda *args, **kwargs: events.append((args, kwargs)),
                                maximum=maximum, timeout=timeout)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.05)
    stopping = threading.Event()

    def accept():
        try:
            while not stopping.is_set():
                try:
                    connection, observed = listener.accept()
                except TimeoutError:
                    continue
                workers.start(connection, observed[0], "127.0.0.1", mode)
        except BaseException as error:
            errors.append(error)

    accepting = threading.Thread(target=accept)
    accepting.start()
    try:
        yield listener.getsockname()[1], workers, events
    finally:
        stopping.set()
        accepting.join(1)
        listener.close()
        workers.close()
        assert not accepting.is_alive() and not workers.active, "TLS workers leaked after test"
        assert not errors, errors


def https_client_case(mode, accepted, *, requested="vpn"):
    with tls_peer(mode) as (port, _workers, events):
        output = io.StringIO()
        argv = ["health-client", "https", "127.0.0.1", requested,
                "--timeout", "1", "--tls-bundle", str(bundle)]
        with patch.dict(client.PORTS, https=port), patch.object(client.sys, "argv", argv), \
                contextlib.redirect_stdout(output):
            try:
                client.main()
            except ValueError:
                assert not accepted, "valid authenticated TLS control rejected"
                assert not output.getvalue(), "failed HTTPS emitted a successful receipt"
            else:
                assert accepted, "invalid HTTPS control accepted: " + mode
                value = json.loads(output.getvalue())
                assert value["tls_authenticated"] is True and value["server_name"] == client.HTTPS_NAME
                assert value["observed_source"] == "127.0.0.1"
    if accepted:
        assert len(events) == 1 and events[0][0] == ("https", "127.0.0.1", "127.0.0.1", "replied")
        assert events[0][1]["nonce"].decode() == value["nonce"]


https_client_case("normal", True)
for mode in ("wrong-name", "wrong-trust", "expired", "client-auth-only", "status503", "redirect",
             "malformed", "truncated", "oversized", "bad-nonce", "direct", "drop"):
    https_client_case(mode, False)
for mode in ("normal", "drop", "wrong-name", "wrong-trust"):
    https_client_case(mode, False, requested="blocked")

# Authenticated HTTP failures cannot gain acceptance through framing aliases.
valid = server.https_response(https_nonce.encode(), "127.0.0.1", "normal")
nonce_request = b"SCHEALTH1 " + https_nonce.encode() + b"\n"
client.require_https_reply(valid, nonce_request, "127.0.0.1")
for invalid in (valid + b"trailing", valid.replace(b"HTTP/1.1", b"HTTP/1.0", 1),
                valid.replace(b"Connection: close", b"Transfer-Encoding: chunked"),
                valid.replace(b"Connection: close", b"Content-Encoding: gzip"),
                valid.replace(b"Connection: close", b"Content-Length: 54"),
                b"HTTP/1.1 200 OK\r\nX: " + b"x" * 4096 + b"\r\n\r\n"):
    try:
        client.require_https_reply(invalid, nonce_request, "127.0.0.1")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed HTTPS framing accepted")

# A stalled handshake consumes only one bounded worker. A fresh authenticated
# exchange and unrelated DNS parsing still finish before its deadline.
with tls_peer(timeout=1) as (port, workers, _events):
    stalled = socket.create_connection(("127.0.0.1", port), timeout=1)
    try:
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", port), timeout=1) as raw:
            with trust.wrap_socket(raw, server_hostname=client.HTTPS_NAME) as secure:
                secure.sendall(https_wire)
                received = bytearray()
                while True:
                    part = secure.recv(4096)
                    if not part:
                        break
                    received.extend(part)
        client.require_https_reply(bytes(received), nonce_request, "127.0.0.1")
        assert server.dns_response(query, "8.8.8.8", "8.8.8.8") == vpn
        assert time.monotonic() - started < 0.8, "stalled TLS blocked a different worker"
    finally:
        stalled.close()

workers = server.TLSWorkers(contexts, lambda *_args, **_kwargs: None, maximum=1, timeout=0.2)
first, peer_socket = socket.socketpair()
assert workers.start(first, "127.0.0.1", "127.0.0.1", "normal")
second, second_peer = socket.socketpair()
assert not workers.start(second, "127.0.0.1", "127.0.0.1", "normal")
assert second.fileno() == -1, "rejected worker leaked its socket"
started = time.monotonic()
workers.close()
assert time.monotonic() - started < 0.7 and not workers.active
peer_socket.close()
second_peer.close()

for failure in ("constructor", "start"):
    workers = server.TLSWorkers(contexts, lambda *_args, **_kwargs: None)
    raw, other = socket.socketpair()
    target = patch.object(server.threading, "Thread", side_effect=RuntimeError("thread construction failed")) \
        if failure == "constructor" else patch.object(server.threading.Thread, "start", side_effect=RuntimeError("thread start failed"))
    with target:
        try:
            workers.start(raw, "127.0.0.1", "127.0.0.1", "normal")
        except RuntimeError:
            pass
        else:
            raise AssertionError("injected thread failure did not occur")
    assert raw.fileno() == -1 and not workers.active
    workers.close()
    other.close()

# Missing, symlinked and malformed trust/leaf files fail before readiness;
# reloading must never silently fall back to a cached or ambient certificate.
with tempfile.TemporaryDirectory() as directory:
    copied = Path(directory)
    for name in ("qa-root.pem", "qa-server-key.pem", *server.TLS_CERTIFICATES.values()):
        (copied / name).write_bytes((bundle / name).read_bytes())
    for filename, loader in (("qa-root.pem", client.authenticated_context), ("qa-server.pem", server.tls_contexts)):
        path = copied / filename
        original = path.read_bytes()
        for mode in ("missing", "symlink", "invalid"):
            path.unlink()
            if mode == "symlink":
                path.symlink_to(bundle / filename)
            elif mode == "invalid":
                path.write_bytes(b"invalid certificate\n")
            try:
                loader(copied)
            except (OSError, ValueError):
                pass
            else:
                raise AssertionError("invalid TLS fixture was accepted: " + mode)
            if path.exists() or path.is_symlink():
                path.unlink()
            path.write_bytes(original)
    load_chain = server.ssl.SSLContext.load_cert_chain

    def replaced_during_load(context, certificate, key):
        load_chain(context, certificate, key)
        replacement = copied / "replaced.pem"
        replacement.write_bytes(Path(certificate).read_bytes())
        replacement.replace(certificate)

    with patch.object(server.ssl.SSLContext, "load_cert_chain", new=replaced_during_load):
        try:
            server.tls_contexts(copied)
        except ValueError:
            pass
        else:
            raise AssertionError("identical bytes in a replaced TLS fixture were adopted during loading")

print("SMART_HEALTH_WIRE_FALSE_POSITIVES_REJECTED=PASS")
print("SMART_HEALTH_PARTIAL_TCP_FAILURE_NOT_BLOCKED=PASS")
print("SMART_HEALTH_AUTHENTICATED_HTTPS_FALSE_POSITIVES_REJECTED=PASS")
print("SMART_HEALTH_TLS_WORKERS_BOUNDED_AND_CLEANED=PASS")
print("SMART_HEALTH_TLS_FIXTURE_FAILURES_CLOSED=PASS")
