#!/usr/bin/env python3
"""Scoped UDP DNS field witness for the disposable Server Connect netns.

A connected UDP socket sends an unpredictable query. A simultaneous passive
AF_PACKET listener on the single QA VETH distinguishes that EXACT application
query from unrelated selected-upstream/bootstrap DNS. The peer and path must
be verified separately by the shell harness; this is not product Guard proof.
"""
import argparse
import ipaddress
import secrets
import socket
import struct
import sys
import threading
import time


class EvidenceError(Exception):
    pass


def query_packet(size=0):
    token = secrets.token_hex(8)
    labels = (("sc" + token).encode("ascii"), b"example", b"com")
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    ident = secrets.randbits(16)
    edns = b""
    if size:
        min_size = 12 + len(question) + 15
        if size < min_size or size > 1350:
            raise EvidenceError("invalid_dns_size")
        pad = size - min_size
        # EDNS(0) OPT, 1232-byte response buffer, RFC7830 padding.
        edns = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 4 + pad)
        edns += struct.pack("!HH", 12, pad) + bytes(pad)
    request = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, int(bool(size)))
    request += question + edns
    if size and len(request) != size:
        raise EvidenceError("dns_size_mismatch")
    return ident, question, request


def response_rcode(message, ident, question):
    if len(message) < 12 + len(question) or len(message) > 4096:
        raise EvidenceError("dns_response_size_invalid")
    rid, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", message[:12])
    if rid != ident:
        raise EvidenceError("dns_transaction_changed")
    if not (flags & 0x8000) or (flags & 0x0200) or (flags & 0x7800):
        raise EvidenceError("dns_response_flags_invalid")
    if qd != 1 or message[12:12 + len(question)] != question:
        raise EvidenceError("dns_question_mismatch")
    rcode = flags & 15
    if rcode not in (0, 3):
        raise EvidenceError("dns_response_rcode_unexpected")
    return rcode


def exact_dns_veth_frame(frame, resolver, request):
    """Only an actual Ethernet IPv4/UDP/53 packet containing OUR entire DNS
    payload to the specified public resolver can count as Direct escape."""
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return False
    start = 14
    if frame[start] >> 4 != 4:
        return False
    ihl = (frame[start] & 15) * 4
    if ihl < 20 or len(frame) < start + ihl + 8 + len(request):
        return False
    if frame[start + 9] != socket.IPPROTO_UDP or frame[start + 16:start + 20] != socket.inet_aton(resolver):
        return False
    fragment = struct.unpack("!H", frame[start + 6:start + 8])[0]
    if fragment & 0x1fff:
        return False
    udp = start + ihl
    dest_port = struct.unpack("!H", frame[udp + 2:udp + 4])[0]
    payload_length = struct.unpack("!H", frame[udp + 4:udp + 6])[0]
    return dest_port == 53 and payload_length >= 8 + len(request) and frame[udp + 8:udp + 8 + len(request)] == request


def open_veth_observer(name, resolver, request):
    if name != "scfqap":
        raise EvidenceError("unapproved_field_underlay_device")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((name, 0))
        sock.settimeout(0.1)
    except OSError as exc:
        try:
            sock.close()
        except (OSError, UnboundLocalError):
            pass
        raise EvidenceError("veth_packet_observer_unavailable") from exc
    done, ready = threading.Event(), threading.Event()
    result = {"matched": False, "read_error": False}

    def collect():
        ready.set()
        while not done.is_set():
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                result["read_error"] = True
                break
            if exact_dns_veth_frame(frame, resolver, request):
                result["matched"] = True
                break

    worker = threading.Thread(target=collect, name="sc-wire-veth-capture", daemon=True)
    worker.start()
    if not ready.wait(1):
        done.set()
        sock.close()
        worker.join(1)
        raise EvidenceError("veth_packet_observer_not_ready")
    return sock, worker, done, result


def run(resolver, size, timeout, expect_outage, underlay_device="", underlay_mode="none", port=53):
    if not isinstance(ipaddress.ip_address(resolver), ipaddress.IPv4Address):
        raise EvidenceError("resolver_requires_ipv4")
    ident, question, request = query_packet(size)
    observation = None
    if underlay_mode != "none":
        if port != 53:
            raise EvidenceError("observer_requires_dns_port_53")
        observation = open_veth_observer(underlay_device, resolver, request)
    answer, receive_error = None, None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((resolver, port))
            sent = sock.send(request)
            if sent != len(request):
                raise EvidenceError("udp_send_incomplete")
            try:
                answer = sock.recv(4097)
            except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                receive_error = exc
    finally:
        if observation is not None:
            cap, worker, done, result = observation
            # The exact outgoing packet can be queued before the response
            # arrives, so allow a small bounded drain before judging absence.
            time.sleep(0.15)
            done.set()
            worker.join(1)
            cap.close()
            if worker.is_alive() or result["read_error"]:
                raise EvidenceError("veth_packet_capture_incomplete")
            if underlay_mode == "direct" and not result["matched"]:
                raise EvidenceError("direct_underlay_positive_capture_missing")
            if underlay_mode == "vpn" and result["matched"]:
                raise EvidenceError("exact_application_dns_escaped_direct")
            print("DNS_EXACT_APPLICATION_UNDERLAY=" + ("PRESENT" if result["matched"] else "ABSENT"))
    if expect_outage:
        if answer is not None:
            raise EvidenceError("dns_response_during_selected_provider_outage")
        print("DNS_OUTAGE_UNAVAILABLE=PASS (no UDP response)")
        return
    if receive_error is not None:
        raise EvidenceError("dns_udp_unavailable:" + receive_error.__class__.__name__) from receive_error
    rcode = response_rcode(answer, ident, question)
    print(f"DNS_UDP_REPLY=PASS request_bytes={len(request)} response_bytes={len(answer)} rcode={rcode}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", required=True)
    parser.add_argument("--size", type=int, choices=(0, 512, 1000, 1200, 1232, 1300), default=0)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--expect-outage", action="store_true")
    parser.add_argument("--underlay-if", default="")
    parser.add_argument("--underlay-mode", choices=("none", "direct", "vpn"), default="none")
    args = parser.parse_args(argv)
    try:
        addr = ipaddress.ip_address(args.resolver)
        if not isinstance(addr, ipaddress.IPv4Address) or not addr.is_global:
            raise EvidenceError("resolver_not_global_ipv4")
        if not 0.5 <= args.timeout <= 8.0:
            raise EvidenceError("timeout_out_of_bounds")
        if (args.underlay_mode == "none") != (args.underlay_if == ""):
            raise EvidenceError("observer_arguments_incomplete")
        run(args.resolver, args.size, args.timeout, args.expect_outage,
            args.underlay_if, args.underlay_mode)
    except (EvidenceError, ValueError) as exc:
        print("DNS_UDP_EVIDENCE=FAIL:" + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
