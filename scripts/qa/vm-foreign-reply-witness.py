#!/usr/bin/env python3
"""Bounded real SSH/HTTP reply witness for the *exact* disconnected Debian 13 QEMU VM.

This probe neither applies a TUN nor changes host routes, DNS, firewall, SSH
configuration or product state. It MUST be correlated with separately captured
product-state, native-kernel and VPN-peer evidence; phase names come from the
operator, not from an independently authenticated activation observer.

Run 'origin' in the guest root namespace; run 'client' from scqa-foreign
via 'ip netns exec'. The operator must separately provision a test-only,
host-key-pinned SSH listener on 198.51.100.1 and an authorized scqa key.
The original SSH process/socket remains open across all stages; new SSH and
uncached HTTP are checked independently at each stage. No public IP claim.
"""

import argparse
import http.client
import json
import os
from pathlib import Path
import stat
import re
import secrets
import select
import shlex
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT_IP = "198.51.100.1"
PEER_IP = "198.51.100.2"
NAMESPACE = "scqa-foreign"
NONCE = re.compile(r"[0-9a-f]{32}\Z")
SSH_REPLY = "SCQA_SSH1 "
HTTP_REPLY = "SCQA_HTTP1 "
REMOTE_LOOP = (
    "import sys\n"
    "for line in sys.stdin:\n"
    " token=line.rstrip('\\n')\n"
    " if len(token)!=32 or any(c not in '0123456789abcdef' for c in token):\n"
    "  sys.exit(7)\n"
    " print('SCQA_SSH1 '+token,flush=True)\n"
)


class WitnessError(Exception):
    pass


def require_guest(in_peer):
    try:
        release = Path("/etc/os-release").read_text()
        vendor = Path("/sys/class/dmi/id/sys_vendor").read_text().strip()
        guest = os.uname().nodename == "sc-qa-vm-us01"
        debian = re.search(r'^ID=debian$', release, re.M) is not None
        version = re.search(r'^VERSION_ID="?13"?$', release, re.M) is not None
        ns = os.stat("/run/netns/" + NAMESPACE)
        here = os.stat("/proc/self/ns/net")
        same_ns = (ns.st_dev, ns.st_ino) == (here.st_dev, here.st_ino)
    except (OSError, ValueError) as exc:
        raise WitnessError("vm_identity_unavailable") from exc
    if not (guest and debian and version and vendor == "QEMU"):
        raise WitnessError("not_exact_debian13_qemu_guest")
    if same_ns != in_peer:
        raise WitnessError("incorrect_named_network_namespace")
    if Path("/.dockerenv").exists():
        raise WitnessError("docker_guest_not_admitted")


def require_key_files(private_key, known_hosts):
    for path in (private_key, known_hosts):
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise WitnessError("ssh_identity_file_invalid")
    if private_key.stat().st_mode & 0o077:
        raise WitnessError("private_ssh_key_permissions_unsafe")


def ssh_command(key, known_hosts, port, remote):
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-b", PEER_IP, "-i", str(key),
        "-p", str(port), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=4", "-o", "ConnectionAttempts=1",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none", "-o", "LogLevel=ERROR",
        "-o", "UserKnownHostsFile=" + str(known_hosts),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "scqa@" + ROOT_IP, "python3 -u -c " + shlex.quote(remote),
    ]


def bounded_line(fd, seconds=6):
    deadline = time.monotonic() + seconds
    line = bytearray()
    while len(line) < 128:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise WitnessError("reply_timeout")
        part = os.read(fd, 1)
        if not part:
            raise WitnessError("transport_closed")
        if part == b"\n":
            try:
                return line.decode("ascii")
            except UnicodeDecodeError as exc:
                raise WitnessError("non_ascii_reply") from exc
        line.extend(part)
    raise WitnessError("reply_too_large")


def ipv4_proc(hex_ip):
    if len(hex_ip) != 8:
        raise WitnessError("invalid_proc_ip")
    return socket.inet_ntoa(bytes.fromhex(hex_ip)[::-1])


def find_ssh_inode(proc_tcp, owned_inodes, port):
    """Match the same ESTABLISHED IPv4 socket to the actual client SSH FD."""
    matches = set()
    for line in proc_tcp.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 10 or cols[3] != "01":
            continue
        try:
            local_ip, local_port = cols[1].split(":")
            remote_ip, remote_port = cols[2].split(":")
            inode = int(cols[9])
            matches_port = int(remote_port, 16) == port
            matches_src = ipv4_proc(local_ip) == PEER_IP
            matches_dst = ipv4_proc(remote_ip) == ROOT_IP
            valid_local_port = int(local_port, 16) > 0
        except (ValueError, WitnessError):
            continue
        if matches_port and matches_src and matches_dst and valid_local_port and inode in owned_inodes:
            matches.add(inode)
    if not matches:
        raise WitnessError("ssh_transport_identity_missing")
    if len(matches) > 1:
        raise WitnessError("ssh_transport_identity_ambiguous")
    return next(iter(matches))


def ssh_socket_inode(pid, port):
    try:
        fds = Path("/proc") / str(pid) / "fd"
        owned = set()
        for fd in fds.iterdir():
            try:
                match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd))
            except OSError:
                continue
            if match:
                owned.add(int(match.group(1)))
        text = (Path("/proc") / str(pid) / "net/tcp").read_text()
    except OSError as exc:
        raise WitnessError("ssh_transport_identity_unavailable") from exc
    return find_ssh_inode(text, owned, port)


def wait_for_initial_ssh_socket(process, port, seconds=6):
    # Popen returns before the real OpenSSH TCP socket necessarily exists.
    # Retry only initial *absence*, never ambiguity, read failures or changes
    # to an already witnessed established transport.
    deadline = time.monotonic() + seconds
    while True:
        if process.poll() is not None:
            raise WitnessError("original_ssh_exited")
        try:
            return ssh_socket_inode(process.pid, port)
        except WitnessError as exc:
            if str(exc) != "ssh_transport_identity_missing":
                raise
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WitnessError("original_ssh_connection_timeout")
        time.sleep(min(0.05, remaining))


def original_ssh_round(process, port, original_inode):
    if process.poll() is not None:
        raise WitnessError("original_ssh_exited")
    before = (wait_for_initial_ssh_socket(process, port) if original_inode is None
              else ssh_socket_inode(process.pid, port))
    if original_inode is not None and before != original_inode:
        raise WitnessError("original_ssh_socket_changed")
    token = secrets.token_hex(16)
    try:
        os.write(process.stdin.fileno(), (token + "\n").encode("ascii"))
    except OSError as exc:
        raise WitnessError("original_ssh_write_failed") from exc
    reply = bounded_line(process.stdout.fileno())
    if reply != SSH_REPLY + token:
        raise WitnessError("original_ssh_nonce_mismatch")
    after = ssh_socket_inode(process.pid, port)
    if after != before or process.poll() is not None:
        raise WitnessError("original_ssh_transport_changed_during_round")
    return before


def new_ssh_round(key, known_hosts, port):
    token = secrets.token_hex(16)
    remote = "print(" + repr("SCQA_NEW1 " + token) + ")"
    try:
        result = subprocess.run(ssh_command(key, known_hosts, port, remote),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WitnessError("new_ssh_transport_failed") from exc
    if result.returncode != 0 or result.stdout != ("SCQA_NEW1 " + token + "\n").encode("ascii"):
        raise WitnessError("new_ssh_nonce_mismatch")


def verified_http_socket(connection):
    sock = connection.sock
    if sock is None:
        raise WitnessError("existing_http_socket_closed")
    try:
        peer, local = sock.getpeername(), sock.getsockname()
        result = os.fstat(sock.fileno())
    except OSError as exc:
        raise WitnessError("http_socket_identity_unavailable") from exc
    if (not stat.S_ISSOCK(result.st_mode) or peer != (ROOT_IP, connection.port) or
            local[0] != PEER_IP or local[1] < 1):
        raise WitnessError("http_socket_not_on_ingress_peer")
    return (result.st_ino, local[1], peer[1])


def http_request(connection, expected_identity=None):
    before = verified_http_socket(connection)
    if expected_identity is not None and before != expected_identity:
        raise WitnessError("existing_http_socket_changed")
    token = secrets.token_hex(16)
    try:
        connection.request("GET", "/witness/" + token,
                           headers={"Host": ROOT_IP, "Cache-Control": "no-cache"})
        response = connection.getresponse()
        body = response.read(129)
        if (response.status != 200 or response.version != 11 or response.will_close or
                response.getheader("Cache-Control") != "no-store" or
                body != (HTTP_REPLY + token + " " + PEER_IP + "\n").encode("ascii")):
            raise WitnessError("http_origin_nonce_or_source_mismatch")
    except (OSError, http.client.HTTPException) as exc:
        raise WitnessError("http_reply_failed") from exc
    after = verified_http_socket(connection)
    if before != after:
        raise WitnessError("http_socket_changed_during_round")
    return before


def http_round(port):
    connection = http.client.HTTPConnection(ROOT_IP, port, timeout=4)
    try:
        connection.connect()
        return http_request(connection)
    finally:
        connection.close()


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        token = self.path.removeprefix("/witness/")
        if not (self.path.startswith("/witness/") and NONCE.fullmatch(token) and
                self.client_address[0] == PEER_IP):
            self.send_error(403, "invalid disconnected QA source or nonce")
            return
        body = (HTTP_REPLY + token + " " + PEER_IP + "\n").encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return  # Avoid collecting per-stage nonces in shared HTTP logs.


def phase_allowed(previous, next_phase):
    return next_phase in {
        "baseline": {"pending"},
        "pending": {"confirmed", "off"},
        "confirmed": {"degraded", "off"},
        "degraded": {"off"},
    }.get(previous, set())


def next_phase(previous):
    print("VM_INGRESS_WAIT_AFTER=" + previous, flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], 120)
    if not ready:
        raise WitnessError("operator_phase_timeout")
    label = sys.stdin.readline().strip()
    if not phase_allowed(previous, label):
        raise WitnessError("operator_phase_out_of_order")
    return label


def client(key, known_hosts, ssh_port, http_port):
    if ssh_port == http_port or not (1024 <= ssh_port <= 65535 and 1024 <= http_port <= 65535):
        raise WitnessError("invalid_test_listener_ports")
    require_key_files(key, known_hosts)
    persistent_http = http.client.HTTPConnection(ROOT_IP, http_port, timeout=4)
    try:
        persistent_http.connect()
        # Verify the original peer route BEFORE the first guarded Apply.
        http_identity = verified_http_socket(persistent_http)
        try:
            original = subprocess.Popen(ssh_command(key, known_hosts, ssh_port, REMOTE_LOOP),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0)
        except OSError as exc:
            raise WitnessError("ssh_client_start_failed") from exc
        try:
            ssh_inode = None
            stage = "baseline"
            while True:
                ssh_inode = original_ssh_round(original, ssh_port, ssh_inode)
                # An existing HTTP keepalive must survive every phase without
                # HTTPConnection silently dialing a replacement socket.
                http_request(persistent_http, http_identity)
                new_ssh_round(key, known_hosts, ssh_port)
                new_http_identity = http_round(http_port)
                if new_http_identity == http_identity:
                    raise WitnessError("new_http_reused_original_socket")
                print(json.dumps({"stage": stage, "ssh_existing": "pass", "ssh_fresh": "pass",
                                  "http_existing": "pass", "http_fresh": "pass",
                                  "socket_inode_unchanged": True,
                                  "product_phase": "not_observed",
                                  "scope": "disconnected_qa_ingress_only"}, sort_keys=True), flush=True)
                if stage == "off":
                    print("VM_INGRESS_WITNESS=PASS (NOT independent Apply/Guard/peer-path proof)", flush=True)
                    return
                stage = next_phase(stage)
        finally:
            if original.poll() is None:
                original.terminate()
                try:
                    original.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    original.kill()
                    original.wait(timeout=2)
            for pipe in (original.stdin, original.stdout):
                if pipe is not None:
                    pipe.close()
    finally:
        persistent_http.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    origin = modes.add_parser("origin", help="run test-only HTTP origin in exact VM root namespace")
    origin.add_argument("--http-port", type=int, default=19124)
    probe = modes.add_parser("client", help="test persistent SSH, fresh SSH and uncached HTTP from exact peer namespace")
    probe.add_argument("--private-key", type=Path, required=True)
    probe.add_argument("--known-hosts", type=Path, required=True)
    probe.add_argument("--ssh-port", type=int, default=19123)
    probe.add_argument("--http-port", type=int, default=19124)
    args = parser.parse_args()
    try:
        if args.mode == "origin":
            require_guest(False)
            if not 1024 <= args.http_port <= 65535:
                raise WitnessError("invalid_http_port")
            server = ThreadingHTTPServer((ROOT_IP, args.http_port), Origin)
            server.daemon_threads = True
            print("VM_INGRESS_HTTP_ORIGIN=READY", flush=True)
            try:
                server.serve_forever(poll_interval=0.2)
            finally:
                server.server_close()
        else:
            require_guest(True)
            client(args.private_key, args.known_hosts, args.ssh_port, args.http_port)
    except (WitnessError, OSError) as exc:
        code = str(exc) if isinstance(exc, WitnessError) else "qa_listener_or_socket_unavailable"
        print("VM_INGRESS_WITNESS=FAIL reason=" + code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
