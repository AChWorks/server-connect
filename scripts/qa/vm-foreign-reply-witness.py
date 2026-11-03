#!/usr/bin/env python3
"""Bounded real SSH/HTTP reply witness for the *exact* disconnected Debian 13 QEMU VM.

This probe neither applies a TUN nor changes host routes, DNS, firewall, SSH
configuration or product state. It MUST be correlated with separately captured
product-state, native-kernel and VPN-peer evidence; phase names come from the
operator, not from an independently authenticated activation observer.

Run 'origin' in the guest root namespace; run 'client' from scqa-foreign
via 'ip netns exec'. The operator must separately provision a test-only,
host-key-pinned SSH listener on 198.51.100.1 and an authorized scqa key.
The original SSH process/socket remains open across all stages using the same
frozen private key as fresh SSH; source identity drift is fatal. New SSH and
uncached HTTP are checked independently at each stage. No public IP claim.
"""

import argparse
from contextlib import contextmanager
import hashlib
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
import tempfile
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
        root = os.stat("/proc/1/ns/net")
        current_id = (here.st_dev, here.st_ino)
        peer_id = (ns.st_dev, ns.st_ino)
        root_id = (root.st_dev, root.st_ino)
    except (OSError, ValueError) as exc:
        raise WitnessError("vm_identity_unavailable") from exc
    if not (guest and debian and version and vendor == "QEMU"):
        raise WitnessError("not_exact_debian13_qemu_guest")
    # Root and peer must be distinct. A third namespace is neither root
    # nor the named peer, even if it can bind the literal TEST-NET address.
    if root_id == peer_id:
        raise WitnessError("root_and_peer_network_namespace_collide")
    if in_peer:
        if current_id != peer_id:
            raise WitnessError("incorrect_named_network_namespace")
    elif current_id != root_id:
        raise WitnessError("not_vm_root_network_namespace")
    if Path("/.dockerenv").exists():
        raise WitnessError("docker_guest_not_admitted")


def _file_identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def read_trusted_known_hosts(path):
    """Read a locally owned pin without following a swapped final symlink."""
    if not path.is_absolute():
        raise WitnessError("ssh_host_pin_path_invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid()) or
                    before.st_mode & 0o022 or not 0 < before.st_size <= 65536):
                raise WitnessError("ssh_host_pin_ownership_or_permissions_unsafe")
            content = source.read(65537)
            after = os.fstat(source.fileno())
        current = path.lstat()
    except OSError as exc:
        raise WitnessError("ssh_host_pin_unavailable") from exc
    if (_file_identity(before) != _file_identity(after) or
            _file_identity(before) != _file_identity(current) or
            len(content) != before.st_size):
        raise WitnessError("ssh_host_pin_changed_during_read")
    return (_file_identity(before), hashlib.sha256(content).digest()), content


def read_trusted_private_key(path):
    """Read a bounded owner-only key without following its final symlink."""
    if not path.is_absolute():
        raise WitnessError("ssh_identity_file_invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or
                    before.st_uid not in (0, os.geteuid()) or
                    before.st_mode & 0o077 or not 0 < before.st_size <= 65536):
                raise WitnessError("ssh_private_key_ownership_or_permissions_unsafe")
            content = source.read(65537)
            after = os.fstat(source.fileno())
        current = path.lstat()
    except OSError as exc:
        raise WitnessError("ssh_identity_file_invalid") from exc
    if (_file_identity(before) != _file_identity(after) or
            _file_identity(before) != _file_identity(current) or
            len(content) != before.st_size):
        raise WitnessError("ssh_private_key_changed_during_read")
    return (_file_identity(before), hashlib.sha256(content).digest()), content


def require_key_files(private_key, known_hosts):
    read_trusted_private_key(private_key)
    read_trusted_known_hosts(known_hosts)


def assert_pinned_private_key(source, snapshot, identity):
    observed, data = read_trusted_private_key(source)
    frozen, bytes_on_disk = read_trusted_private_key(snapshot)
    source_identity, snapshot_identity = identity
    if observed != source_identity or frozen != snapshot_identity or data != bytes_on_disk:
        raise WitnessError("ssh_private_key_changed")


@contextmanager
def pinned_private_key_file(source):
    """Freeze the same authenticated SSH key for original and fresh sessions.

    The private copy lives only in an owner-only temporary directory and is
    removed after the original SSH process has been reaped.
    """
    identity, data = read_trusted_private_key(source)
    with tempfile.TemporaryDirectory(prefix="scqa-ssh-key-") as location:
        snapshot = Path(location) / "private_key"
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fchmod(target.fileno(), 0o600)
        snapshot_identity, snapshot_data = read_trusted_private_key(snapshot)
        if snapshot_data != data:
            raise WitnessError("ssh_private_key_snapshot_invalid")
        paired_identity = (identity, snapshot_identity)
        assert_pinned_private_key(source, snapshot, paired_identity)
        yield snapshot, paired_identity


def assert_pinned_hosts(source, snapshot, identity):
    observed, data = read_trusted_known_hosts(source)
    frozen, bytes_on_disk = read_trusted_known_hosts(snapshot)
    source_identity, snapshot_identity = identity
    if observed != source_identity or frozen != snapshot_identity or data != bytes_on_disk:
        raise WitnessError("ssh_host_pin_changed")


@contextmanager
def pinned_host_file(source):
    """OpenSSH receives a private immutable-byte copy, never the mutable source.

    The original path and snapshot are revalidated before and after every
    fresh connection. A source path swap cannot change OpenSSH's trust set.
    """
    identity, data = read_trusted_known_hosts(source)
    with tempfile.TemporaryDirectory(prefix="scqa-host-pin-") as location:
        snapshot = Path(location) / "known_hosts"
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fchmod(target.fileno(), 0o400)
        snapshot_identity, snapshot_data = read_trusted_known_hosts(snapshot)
        if snapshot_data != data:
            raise WitnessError("ssh_host_pin_snapshot_invalid")
        paired_identity = (identity, snapshot_identity)
        assert_pinned_hosts(source, snapshot, paired_identity)
        yield snapshot, paired_identity


def ssh_command(key, known_hosts, port, remote):
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-b", PEER_IP, "-i", str(key),
        "-p", str(port), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey",
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


def next_phase(previous, seconds=120):
    print("VM_INGRESS_WAIT_AFTER=" + previous, flush=True)
    deadline = time.monotonic() + seconds
    fd = sys.stdin.fileno()
    line = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise WitnessError("operator_phase_timeout")
        # Read one byte at a time: never let a buffered readline() escape the
        # deadline after partial pipe/TTY input. Labels are shorter than 24.
        part = os.read(fd, 1)
        if not part:
            raise WitnessError("operator_phase_unexpected_eof")
        if part == b"\n":
            break
        if len(line) >= 24:
            raise WitnessError("operator_phase_label_too_long")
        line.extend(part)
    try:
        label = line.decode("ascii").removesuffix("\r")
    except UnicodeDecodeError as exc:
        raise WitnessError("operator_phase_invalid_encoding") from exc
    if not phase_allowed(previous, label):
        raise WitnessError("operator_phase_out_of_order")
    return label


def client(key, known_hosts, ssh_port, http_port):
    if ssh_port == http_port or not (1024 <= ssh_port <= 65535 and 1024 <= http_port <= 65535):
        raise WitnessError("invalid_test_listener_ports")
    require_key_files(key, known_hosts)
    with (pinned_host_file(known_hosts) as (snapshot, identity),
          pinned_private_key_file(key) as (frozen_key, key_identity)):
        _client_with_trusted_pin(key, known_hosts, snapshot, identity,
                                 frozen_key, key_identity, ssh_port, http_port)
    # A successful final stage is not a successful witness until the original
    # SSH/HTTP resources and both private snapshots have been closed/removed.
    print("VM_INGRESS_WITNESS=PASS (NOT independent Apply/Guard/peer-path proof)", flush=True)


def _client_with_trusted_pin(key, known_hosts, snapshot, identity,
                             frozen_key, key_identity, ssh_port, http_port):
    persistent_http = http.client.HTTPConnection(ROOT_IP, http_port, timeout=4)
    try:
        persistent_http.connect()
        # Verify the original peer route BEFORE the first guarded Apply.
        http_identity = verified_http_socket(persistent_http)
        try:
            original = subprocess.Popen(ssh_command(frozen_key, snapshot, ssh_port, REMOTE_LOOP),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0)
        except OSError as exc:
            raise WitnessError("ssh_client_start_failed") from exc
        try:
            ssh_inode = None
            stage = "baseline"
            while True:
                assert_pinned_hosts(known_hosts, snapshot, identity)
                assert_pinned_private_key(key, frozen_key, key_identity)
                ssh_inode = original_ssh_round(original, ssh_port, ssh_inode)
                # An existing HTTP keepalive must survive every phase without
                # HTTPConnection silently dialing a replacement socket.
                http_request(persistent_http, http_identity)
                assert_pinned_hosts(known_hosts, snapshot, identity)
                assert_pinned_private_key(key, frozen_key, key_identity)
                new_ssh_round(frozen_key, snapshot, ssh_port)
                assert_pinned_hosts(known_hosts, snapshot, identity)
                assert_pinned_private_key(key, frozen_key, key_identity)
                new_http_identity = http_round(http_port)
                # Fresh HTTP is the last potentially blocking external round.
                # Identity drift during it must be rejected before stage output.
                assert_pinned_hosts(known_hosts, snapshot, identity)
                assert_pinned_private_key(key, frozen_key, key_identity)
                if new_http_identity == http_identity:
                    raise WitnessError("new_http_reused_original_socket")
                print(json.dumps({"stage": stage, "ssh_existing": "pass", "ssh_fresh": "pass",
                                  "http_existing": "pass", "http_fresh": "pass",
                                  "socket_inode_unchanged": True,
                                  "product_phase": "not_observed",
                                  "scope": "disconnected_qa_ingress_only"}, sort_keys=True), flush=True)
                if stage == "off":
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
