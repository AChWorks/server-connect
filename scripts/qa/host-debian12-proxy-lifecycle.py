#!/usr/bin/env python3
"""Explicitly authorized IRA-124 Debian 12 installed Proxy Only field evidence.

Run only after MASTER reviews this driver and pins the exact candidate inputs:
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    /usr/bin/python3 -I -B host-debian12-proxy-lifecycle.py \
    --manifest /root/server-connect-debian12-field-TASK/input/manifest.json \
    --manifest-sha256 SHA256

The schema-1 manifest has exactly these required keys:
  schema: 1; target_id: "ira-124"; source_revision: Git SHA; source_tree: Git SHA;
  boot_id: current kernel boot UUID; run_name: "run-01";
  artifacts: {base: {file, bytes, sha256}}; no other artifact keys are accepted.
An optional machine_id_sha256 pins SHA256(/etc/machine-id stripped of whitespace).
The base archive is the exact ordinary Debian12 bundle, supplied inside input/.
No download, compiler, APT or artifact modification occurs here. Distinct-byte
update and invalid-unit rollback fixtures remain disconnected-CI-only and are
NOT_RUN on this field target. Same-base reinstall is not version migration.

The exclusive run directory retains private evidence. Only a proven test-created
product state directory is purged, after real product uninstall and exact file
checks under its lifecycle lock. Uncertain ownership is retained for MASTER.
No TUN, namespace, route, firewall, resolver, Docker or SSH mutation is performed.
Loopback VLESS evidence does not establish an external VPN path or a release.
"""

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid


PREFIX = Path("/opt/server-connect")
STATE = Path("/var/lib/server-connect")
COMMAND = Path("/usr/local/bin/server-connect")
OWNER_FILE = ".field-qa-owner.json"
PROXY_PORT = 20807
UNITS = (
    "server-connect.service",
    "server-connect-activation-recover.service",
    "server-connect-activation-recover.timer",
    "server-connect-smart-tun.service",
    "server-connect-smart-health.service",
    "server-connect-smart-health.timer",
)
UNIT_PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths",
    "UnitFileState", "Transient", "Job",
)
SERVICE_PROPERTIES = ("MainPID", "ControlPID", "InvocationID",
                      "ExecMainStartTimestampMonotonic", "Result")
TIMER_PROPERTIES = ("Unit", "LastTriggerUSecMonotonic")
BUNDLE_FILES = {
    "bin/server-connect", "bin/sing-box", "bin/libcronet.so",
    "THIRD-PARTY-LICENSES/sing-box-LICENSE", "install.sh", "manifest.json",
    "checksums.sha256", *UNITS,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
CORE_ARCHIVE_SHA = "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"


class CheckFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def trusted_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o022, "Untrusted directory: " + str(path))


def trusted_ancestry(path):
    require(path.is_absolute() and path == Path(os.path.normpath(str(path))),
            "Absolute canonical path required")
    for parent in reversed((path, *path.parents)):
        trusted_directory(parent)


def trusted_file(path, limit=1024 * 1024):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o022 and info.st_size <= limit,
            "Untrusted or oversized file: " + str(path))
    return path.read_bytes()


def save_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def validate_manifest(value):
    required = {"schema", "target_id", "source_revision", "source_tree",
                "boot_id", "run_name", "artifacts"}
    require(isinstance(value, dict) and required <= value.keys() and
            not value.keys() - required - {"machine_id_sha256"},
            "Unsupported field manifest schema")
    require(type(value["schema"]) is int and value["schema"] == 1 and
            value["target_id"] == "ira-124", "Wrong explicit target or schema")
    require(all(isinstance(value[key], str) and HEX40.fullmatch(value[key])
                for key in ("source_revision", "source_tree")),
            "Invalid candidate identity")
    require(isinstance(value["boot_id"], str) and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]),
        "Invalid boot identity")
    require(isinstance(value["run_name"], str) and
            re.fullmatch(r"run-[0-9]{2,4}", value["run_name"]),
            "Exclusive numbered run name required")
    require("machine_id_sha256" not in value or
            (isinstance(value["machine_id_sha256"], str) and
             HEX64.fullmatch(value["machine_id_sha256"])), "Invalid machine pin")
    artifacts = value["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == {"base"},
            "Only the normal base artifact is admitted on this field target")
    for artifact in artifacts.values():
        require(isinstance(artifact, dict) and
                set(artifact) == {"file", "bytes", "sha256"},
                "Invalid artifact metadata")
        name = artifact["file"]
        require(isinstance(name, str) and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz", name),
                "Artifact basename required")
        require(type(artifact["bytes"]) is int and
                0 < artifact["bytes"] <= 100 * 1024 * 1024 and
                isinstance(artifact["sha256"], str) and
                HEX64.fullmatch(artifact["sha256"]), "Invalid artifact bounds")


def validate_members(members):
    require(0 < len(members) <= 32, "Unexpected archive member count")
    files, seen, total = set(), set(), 0
    allowed_dirs = {"server-connect", "server-connect/bin",
                    "server-connect/THIRD-PARTY-LICENSES"}
    for member in members:
        name = member.name.rstrip("/")
        path = PurePosixPath(name)
        require(name not in seen and not path.is_absolute() and
                ".." not in path.parts and str(path) == name,
                "Ambiguous or unsafe archive member")
        seen.add(name)
        require(member.isdir() or member.isfile(),
                "Archive links and special files are forbidden")
        if member.isdir():
            require(name in allowed_dirs, "Unexpected archive directory")
        else:
            require(member.name == name, "Noncanonical payload member")
            require(path.parts and path.parts[0] == "server-connect",
                    "Unexpected archive prefix")
            relative = str(PurePosixPath(*path.parts[1:]))
            require(relative in BUNDLE_FILES and type(member.size) is int and
                    0 < member.size <= 134217728,
                    "Unexpected or oversized payload member")
            files.add(relative)
            total += member.size
    require(files == BUNDLE_FILES and total <= 256 * 1024 * 1024,
            "Incomplete or oversized bundle")


def normalize_network(value):
    if isinstance(value, dict):
        return {
            key: ({"finite_countdown": True, "type": type(item).__name__}
                  if key in {"valid_life_time", "preferred_life_time", "expires"}
                  and type(item) in {int, float} and item > 0 and item != 4294967295
                  else normalize_network(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_network(item) for item in value]
    return value


def unit_absent(name, properties):
    # Timers have no service PID properties. A missing service PID observation
    # is never equivalent to an observed zero PID.
    return (
        isinstance(properties, dict) and name.endswith((".service", ".timer")) and
        properties.get("LoadState") == "not-found" and
        properties.get("ActiveState") == "inactive" and
        properties.get("SubState") == "dead" and
        (name.endswith(".timer") or
         (properties.get("MainPID") == "0" and
          properties.get("ControlPID") == "0")) and
        properties.get("Transient") == "no"
        and all(key in properties and not properties[key] for key in
                ("FragmentPath", "DropInPaths", "Job", "UnitFileState"))
    )


def unchanged_core(before, after):
    required = {"pid", "invocation", "start_ticks", "systemd_start", "exe_sha256"}
    return (isinstance(before, dict) and isinstance(after, dict) and
            set(before) == required and set(after) == required and
            type(before["pid"]) is int and before["pid"] > 1 and
            isinstance(before["invocation"], str) and
            re.fullmatch(r"[0-9a-f]{32}", before["invocation"]) is not None and
            before["invocation"] != "0" * 32 and
            all(isinstance(before[key], str) and
                re.fullmatch(r"[1-9][0-9]*", before[key]) is not None
                for key in ("start_ticks", "systemd_start")) and
            isinstance(before["exe_sha256"], str) and
            HEX64.fullmatch(before["exe_sha256"]) is not None and before == after)


def delivery_passed(exit_code, received, expected, events_before, events_after):
    return (type(exit_code) is int and exit_code == 0 and expected and
            received == expected and type(events_before) is int and
            events_before >= 0 and type(events_after) is int and
            events_after == events_before + 1)


def outage_passed(exit_code, received, origin_before, origin_after, before, after):
    return (type(exit_code) is int and exit_code > 0 and received == b"" and
            type(origin_before) is int and origin_before >= 0 and
            type(origin_after) is int and
            origin_after == origin_before and unchanged_core(before, after))


def purge_inventory_matches(inventory, expected):
    """Unknown files, replaced inodes or changed contents never earn deletion."""
    return (isinstance(inventory, dict) and isinstance(expected, dict) and
            bool(expected) and inventory == expected and all(
        isinstance(record, dict) and record.get("kind") in {"file", "directory"}
        and record.get("uid") == 0 and record.get("gid") == 0 and
        type(record.get("mode")) is int and not record["mode"] & 0o077
        for record in inventory.values())
    )


def private_stat_record(info, kind):
    return {"kind": kind, "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
            "device": info.st_dev, "inode": info.st_ino}


def private_directory_matches(info, expected):
    return (stat.S_ISDIR(info.st_mode) and expected.get("mode") == 0o700 and
            private_stat_record(info, "directory") == expected)


def private_file_receipt_at(parent_fd, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                not before.st_mode & 0o077 and before.st_size <= 1024 * 1024,
                "Unexpected private state file; preserve state")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        after = os.fstat(descriptor)
        record = private_stat_record(before, "file")
        require(record == private_stat_record(after, "file") and
                before.st_size == after.st_size == len(data) and
                before.st_mtime_ns == after.st_mtime_ns and
                before.st_ctime_ns == after.st_ctime_ns and after.st_nlink == 1,
                "Private state file changed while observed")
        return dict(record, bytes=len(data), sha256=sha(data))
    finally:
        os.close(descriptor)


def private_state_inventory_at(root_fd, profile_fd, profile_id):
    require(re.fullmatch(r"[0-9a-f]{16}", profile_id), "Invalid private profile identity")
    root_files = (".lock", "state.json", "proxy-auth", OWNER_FILE)
    require(set(os.listdir(root_fd)) == {"profiles", *root_files} and
            os.listdir(profile_fd) == [profile_id + ".json"],
            "Unknown content in opened private state directories")
    inventory = {
        ".": private_stat_record(os.fstat(root_fd), "directory"),
        "profiles": private_stat_record(os.fstat(profile_fd), "directory"),
    }
    for name in root_files:
        inventory[name] = private_file_receipt_at(root_fd, name)
    inventory["profiles/" + profile_id + ".json"] = private_file_receipt_at(
        profile_fd, profile_id + ".json")
    return inventory


def delete_exact_private_state(parent_fd, profile_id, expected):
    """Delete one fixed state layout after checking the actual opened objects.

    The production caller supplies the fixed STATE parent and an inventory
    already admitted as root-owned. Comparing the inventory's exact UID/GID
    here also permits an ordinary current-user temporary-tree regression;
    this primitive provides no production path, OS or ownership override.
    """
    require(re.fullmatch(r"[0-9a-f]{16}", profile_id), "Invalid private profile identity")
    require(set(expected) == {".", "profiles", ".lock", "state.json", "proxy-auth",
                              OWNER_FILE, "profiles/" + profile_id + ".json"},
            "Unexpected deletion inventory")
    with contextlib.ExitStack() as opened:
        root_fd = os.open(STATE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent_fd)
        opened.callback(os.close, root_fd)
        require(private_directory_matches(os.fstat(root_fd), expected["."]),
                "Opened state root identity/owner/mode changed; preserve state")
        profile_fd = os.open("profiles", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=root_fd)
        opened.callback(os.close, profile_fd)
        require(private_directory_matches(os.fstat(profile_fd), expected["profiles"]),
                "Opened profiles identity/owner/mode changed; preserve state")
        require(private_state_inventory_at(root_fd, profile_fd, profile_id) == expected,
                "Opened private state inventory changed; preserve state")

        def directory_binding(parent, name, receipt):
            require(private_directory_matches(
                os.stat(name, dir_fd=parent, follow_symlinks=False), receipt),
                "Private directory binding changed; preserve state")

        def unlink_file(parent, name, receipt):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            metadata = private_stat_record(info, "file")
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    metadata == {key: receipt[key] for key in metadata} and
                    info.st_size == receipt["bytes"],
                    "Private file binding changed; preserve state")
            os.unlink(name, dir_fd=parent)

        # No unlink precedes both fstat checks and the descriptor-based receipt.
        directory_binding(parent_fd, STATE.name, expected["."])
        directory_binding(root_fd, "profiles", expected["profiles"])
        unlink_file(profile_fd, profile_id + ".json",
                    expected["profiles/" + profile_id + ".json"])
        directory_binding(root_fd, "profiles", expected["profiles"])
        os.rmdir("profiles", dir_fd=root_fd)
        for name in ("proxy-auth", "state.json", OWNER_FILE, ".lock"):
            unlink_file(root_fd, name, expected[name])
        directory_binding(parent_fd, STATE.name, expected["."])
        require(not os.listdir(root_fd), "New private state content appeared")
        os.rmdir(STATE.name, dir_fd=parent_fd)


def opposite_target_refused(exit_code, report):
    return (type(exit_code) is int and exit_code == 1 and isinstance(report, dict)
            and report.get("ok") is False and report.get("error") == {
                "code": "installer_target_mismatch",
                "message": "bundle target does not match the actual supported host"}
            and report.get("data") == {"target": "", "verified": False})


def final_passed(result):
    required = ("lifecycle_completed", "exact_test_state_purged",
                "all_private_children_stopped", "no_outage_origin_delivery",
                "task_listeners_absent", "product_resources_absent",
                "recorded_host_views_unchanged", "mutation_outcome_known")
    return (all(result.get(key) is True for key in required) and
            result.get("cleanup_errors") == [] and
            result.get("changed_host_components") == [] and "failure" not in result)


class FieldRun:
    def __init__(self, manifest_path, manifest_sha):
        require(os.geteuid() == 0, "Explicit root execution required")
        require(HEX64.fullmatch(manifest_sha), "Manifest digest required")
        trusted_ancestry(manifest_path.parent)
        raw = trusted_file(manifest_path, 32768)
        require(sha(raw) == manifest_sha, "Field manifest digest mismatch")
        self.manifest = json.loads(raw)
        validate_manifest(self.manifest)
        require(manifest_path.parent.name == "input" and
                manifest_path.parent.parent.parent == Path("/root") and
                manifest_path.parent.parent.name.startswith(
                    "server-connect-debian12-field-"),
                "Dedicated root-owned field staging required")
        self.input_dir = manifest_path.parent
        self.run_dir = self.input_dir.parent / self.manifest["run_name"]
        require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() ==
                self.manifest["boot_id"], "Host rebooted or wrong host")
        if "machine_id_sha256" in self.manifest:
            require(sha(Path("/etc/machine-id").read_bytes().strip()) ==
                    self.manifest["machine_id_sha256"], "Wrong machine identity")
        os_release = dict(line.split("=", 1) for line in
                          Path("/etc/os-release").read_text().splitlines()
                          if "=" in line)
        require(os_release.get("ID", "").strip('"') == "debian" and
                os_release.get("VERSION_ID", "").strip('"') == "12" and
                os.uname().machine == "x86_64" and
                Path("/proc/1/comm").read_text().strip() == "systemd",
                "This field driver requires Debian12/amd64 with systemd PID1")
        os.umask(0o077)
        self.run_dir.mkdir(mode=0o700)
        self.deadline = time.monotonic() + 360
        self.cleanup_deadline = None
        self.command_index = 0
        self.secrets = []
        self.children = []
        self.child_logs = []
        self.origin = None
        self.origin_thread = None
        self.origin_events = []
        self.failed_paths = set()
        self.event_lock = threading.Lock()
        self.port_numbers = set()
        self.bundles = {}
        self.bundle_hashes = {}
        self.profile_id = None
        self.profile_sha = None
        self.auth_sha = None
        self.runtime_sha = None
        self.state_identity = None
        self.state_marker = None
        self.install_dispatched = False
        self.installer_unverified = False
        self.mutator_uncertain = False
        self.stop_signal = None
        self.baseline = None
        self.results = {
            "schema": 1, "target_id": self.manifest["target_id"],
            "source_revision": self.manifest["source_revision"],
            "source_tree": self.manifest["source_tree"],
            "manifest_sha256": manifest_sha, "started_at": now(),
            "artifact_inputs": self.manifest["artifacts"],
            "scope": "Debian12 ordinary-base install/reinstall and local Proxy Only "
                     "lifecycle; no external VPN, TUN, physical reboot or public release acceptance",
            "not_run_on_field": {
                "distinct_byte_update": "NOT_RUN; disconnected-CI-only",
                "invalid_unit_rollback": "NOT_RUN; disconnected-CI-only",
                "version_migration": "NOT_RUN",
            },
            "stages": [], "cleanup_errors": [],
        }
        save_new(self.run_dir / "owner.json", {
            "task": "server-connect-debian12-proxy-field-v1",
            "nonce": secrets.token_hex(24), "manifest_sha256": manifest_sha,
            "boot_id": self.manifest["boot_id"], "created_at": now(),
        })

    def redact(self, text):
        for secret in self.secrets:
            text = text.replace(secret, "[PRIVATE_TEST_CREDENTIAL]")
        return text

    def event(self, kind, **fields):
        event = {"time": now(), "kind": kind, **fields}
        with (self.run_dir / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(self.redact(json.dumps(event)) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def stage(self, name, **evidence):
        self.results["stages"].append({"name": name, "passed": True, **evidence})
        self.event("stage_pass", name=name, **evidence)
        print("FIELD_LIFECYCLE_STAGE=" + name, flush=True)

    def call(self, args, timeout=12, expected=0, input_bytes=None, mutation=False):
        require(self.cleanup_deadline is not None or self.stop_signal is None,
                "Interruption requested; begin bounded cleanup")
        deadline = self.cleanup_deadline or self.deadline
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Field command budget exhausted")
        timeout = min(timeout, remaining)
        self.command_index += 1
        label = "command-%04d" % self.command_index
        self.event("before_dispatch", command_id=label, argv=list(map(str, args)),
                   mutation=mutation)
        started = time.monotonic()
        process = subprocess.Popen(list(map(str, args)), env=ENV,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if mutation:
                self.mutator_uncertain = True
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=20 if mutation else 2)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=5)
        result = {
            "command_id": label, "argv": list(map(str, args)),
            "exit": process.returncode, "timed_out": timed_out,
            "seconds": round(time.monotonic() - started, 3),
            "stdout": self.redact(stdout.decode(errors="replace")),
            "stderr": self.redact(stderr.decode(errors="replace")),
        }
        save_new(self.run_dir / (label + ".json"), result)
        require(len(stdout) <= 1024 * 1024 and len(stderr) <= 1024 * 1024,
                label + " exceeded output bound")
        require(not timed_out, label + " timed out; mutation outcome retained")
        require(self.cleanup_deadline is not None or self.stop_signal is None,
                "Interruption requested after command; outcome recorded")
        if expected is not None:
            require(process.returncode == expected,
                    label + " unexpected exit " + str(process.returncode))
        return process.returncode, stdout, stderr

    def unit(self, name):
        extra = TIMER_PROPERTIES if name.endswith(".timer") else SERVICE_PROPERTIES
        requested = UNIT_PROPERTIES + extra
        rc, output, _ = self.call(
            ["systemctl", "show", "--all", "--no-pager", name,
             "--property=" + ",".join(requested)],
            expected=None, timeout=8)
        values = dict(line.split("=", 1) for line in
                      output.decode().splitlines() if "=" in line)
        required = UNIT_PROPERTIES
        if not name.endswith(".timer") or values.get("LoadState") != "not-found":
            required += extra
        require(set(required) <= values.keys() and
                (rc == 0 or (rc == 1 and unit_absent(name, values))),
                "Incomplete systemd observation: " + name)
        return values

    def observe_host(self):
        raw = {}
        for key, args in (
            ("addresses", ["ip", "-j", "addr", "show"]),
            ("routes4", ["ip", "-j", "-4", "route", "show", "table", "all"]),
            ("routes6", ["ip", "-j", "-6", "route", "show", "table", "all"]),
            ("rules4", ["ip", "-j", "-4", "rule", "show"]),
            ("rules6", ["ip", "-j", "-6", "rule", "show"]),
        ):
            raw[key] = json.loads(self.call(args, timeout=8)[1])
        normalized = {key: normalize_network(value) for key, value in raw.items()}
        for key, executable in (("iptables4", "iptables-save"),
                                ("iptables6", "ip6tables-save")):
            text = self.call([executable], timeout=8)[1].decode()
            raw[key] = text
            normalized[key] = "\n".join(
                re.sub(r"^(:\S+ \S+ )\[\d+:\d+\]$", r"\1[COUNTERS]", line)
                for line in text.splitlines() if not line.startswith("#"))
        resolver = Path("/etc/resolv.conf")
        info = resolver.lstat()
        raw["resolver"] = {
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "gid": info.st_gid, "type": stat.S_IFMT(info.st_mode),
            "inode": info.st_ino, "sha256": file_hash(resolver),
            "link": os.readlink(resolver) if resolver.is_symlink() else None,
        }
        raw["docker_containers"] = self.call(
            ["docker", "ps", "-a", "--no-trunc", "--format",
             "{{.ID}} {{.Image}}"], timeout=8)[1].decode().splitlines()
        raw["protected_services"] = {}
        for name in ("ssh.service", "docker.service", "containerd.service"):
            values = self.unit(name)
            raw["protected_services"][name] = {
                key: values[key] for key in
                ("ActiveState", "SubState", "MainPID", "InvocationID",
                 "FragmentPath", "DropInPaths", "Job")}
        raw["listeners"] = sorted(self.call(
            ["ss", "-H", "-lntup"], timeout=8)[1].decode().splitlines())
        for key in ("resolver", "docker_containers", "protected_services",
                    "listeners"):
            normalized[key] = raw[key]
        return {"observed_at": now(), "raw": raw, "normalized": normalized,
                "hashes": {key: fingerprint(value)
                           for key, value in normalized.items()}}

    def product_absent(self, include_state=True):
        paths = [PREFIX, COMMAND, Path("/run/credentials/server-connect.service"),
                 *(Path("/etc/systemd/system") / n for n in UNITS)]
        if include_state:
            paths.append(STATE)
        return (all(not path.exists() and not path.is_symlink() for path in paths)
                and all(unit_absent(name, self.unit(name)) for name in UNITS))

    def ssh_observation(self, label):
        output = self.call(["ss", "-H", "-tnp", "state", "established"],
                           timeout=8)[1].decode()
        tuples = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4 or '"sshd"' not in line:
                continue
            try:
                local, port = fields[2].rsplit(":", 1)
                peer, peer_port = fields[3].rsplit(":", 1)
                if port == "22":
                    tuples.append({
                        "local": str(ipaddress.ip_address(local.strip("[]"))),
                        "port": 22,
                        "peer": str(ipaddress.ip_address(peer.strip("[]"))),
                        "peer_port": int(peer_port)})
            except ValueError:
                continue
        save_new(self.run_dir / ("ssh-" + label + ".json"), {
            "observed_at": now(), "tuples": tuples,
            "meaning": "Socket observation only. MASTER separately verifies "
                       "fresh Gateway access before and after this Job.",
        })

    def prepare_bundle(self, label):
        metadata = self.manifest["artifacts"][label]
        archive = self.input_dir / metadata["file"]
        info = archive.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and info.st_size == metadata["bytes"] and
                file_hash(archive) == metadata["sha256"],
                "Artifact size, ownership or digest mismatch: " + label)
        destination = self.run_dir / label
        destination.mkdir(mode=0o700)
        with tarfile.open(archive, "r:gz") as bundle:
            members, expanded = [], 0
            for member in bundle:
                expanded += member.size
                require(len(members) < 32 and 0 <= member.size <= 134217728 and
                        expanded <= 256 * 1024 * 1024,
                        "Archive exceeds bounded member/payload admission")
                members.append(member)
            validate_members(members)
            for member in members:
                if not member.isfile():
                    continue
                relative = PurePosixPath(*PurePosixPath(member.name).parts[1:])
                target = destination / str(relative)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = bundle.extractfile(member)
                require(stream is not None, "Payload member unavailable")
                with target.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        require(chunk, "Truncated payload")
                        output.write(chunk)
                        remaining -= len(chunk)
                target.chmod(0o500 if str(relative) in
                             {"bin/server-connect", "bin/sing-box", "install.sh"}
                             else 0o400)
        checksums = {}
        for line in (destination / "checksums.sha256").read_text().splitlines():
            require(re.fullmatch(r"[0-9a-f]{64}  [A-Za-z0-9._/-]+", line),
                    "Malformed checksums")
            checksum, name = line.split("  ", 1)
            require(name not in checksums, "Duplicate checksum")
            checksums[name] = checksum
        require(set(checksums) == BUNDLE_FILES - {"checksums.sha256"} and all(
            file_hash(destination / name) == checksum
            for name, checksum in checksums.items()), "Payload checksum mismatch")
        package = json.loads((destination / "manifest.json").read_text())
        require(isinstance(package, dict) and type(package.get("schema")) is int
                and package["schema"] == 1 and
                package.get("source_revision") == self.manifest["source_revision"]
                and package.get("source_state") == "clean" and
                package.get("target") == "debian-12-amd64" and
                package.get("manager") == "0.1.0-dev" and
                package.get("core") == "sing-box 1.14.3" and
                package.get("core_archive_sha256") == CORE_ARCHIVE_SHA,
                "Wrong exact candidate or Debian12 artifact target")
        self.bundles[label] = destination
        self.bundle_hashes[label] = {
            name: file_hash(destination / name) for name in BUNDLE_FILES}
        self.event("artifact_verified", label=label, **metadata)

    def installer(self, action):
        self.install_dispatched = self.install_dispatched or action == "--offline"
        if action != "--verify-only":
            # Set before dispatch. A failed/unknown installer is not erased by
            # a later uninstall. Only an observed successful exit clears this.
            self.installer_unverified = True
        result = self.call(
            ["/bin/sh", self.bundles["base"] / "install.sh", action],
            timeout=70, expected=None, mutation=action != "--verify-only")
        if action != "--verify-only" and result[0] == 0:
            self.installer_unverified = False
        require(result[0] == 0, "Installer returned unexpected exit")
        return result

    def opposite_target_helper(self):
        require(self.product_absent(), "Product resources predate target helper check")
        source = self.bundles["base"] / "manifest.json"
        other = json.loads(trusted_file(source))
        require(other["target"] == "debian-12-amd64", "Wrong helper source target")
        other["target"] = "debian-13-amd64"
        destination = self.run_dir / "opposite-target-helper-manifest.json"
        save_new(destination, other)
        rc, output, _ = self.call(
            [self.bundles["base"] / "bin/server-connect", "--json",
             "installer-check-target", "--manifest", destination], expected=1)
        require(opposite_target_refused(rc, json.loads(output)),
                "Actual-host opposite-target helper refusal was not established")
        require(file_hash(source) == self.bundle_hashes["base"]["manifest.json"] and
                self.product_absent(), "Target helper altered supplied metadata/product resources")
        self.stage("actual-host-opposite-target-helper-refusal",
                   actual_target="debian-12-amd64", refused_target="debian-13-amd64",
                   scope="Target helper only; complete-installer opposite-target negative is CI evidence")

    def cli(self, arguments, expected=0, input_bytes=None):
        mutation = arguments[0] in {"import", "select", "connect", "disconnect"}
        rc, output, error = self.call(
            [COMMAND, "--json", *arguments], expected=expected,
            input_bytes=input_bytes, mutation=mutation, timeout=20)
        require(output, "Missing CLI JSON")
        value = json.loads(output)
        require(isinstance(value, dict) and
                value.get("ok") is (rc == 0), "Dishonest CLI result envelope")
        return value

    def assert_owned_install(self, label=None):
        require(trusted_file(PREFIX / ".owner").strip() ==
                b"AChWorks/server-connect", "Installed owner conflict")
        require(COMMAND.is_symlink() and os.readlink(COMMAND) ==
                "/opt/server-connect/current/bin/server-connect",
                "Installed command identity conflict")
        target = os.readlink(PREFIX / "current")
        require(re.fullmatch(r"releases/0\.1\.0-dev-[0-9a-f]{16}", target),
                "Unexpected installed release link")
        for directory in ("bin", "THIRD-PARTY-LICENSES"):
            trusted_ancestry(PREFIX / target / directory)
        require(trusted_file(PREFIX / target / ".owner") ==
                b"AChWorks/server-connect\n", "Installed release owner conflict")
        manager_hash = file_hash(PREFIX / target / "bin/server-connect")
        matching = [key for key in self.bundles if
                    self.bundle_hashes[key]["bin/server-connect"] == manager_hash]
        require(len(matching) == 1 and (label is None or matching[0] == label),
                "Current release is not an exact supplied artifact")
        current = matching[0]
        for name in ("bin/server-connect", "bin/sing-box", "bin/libcronet.so",
                     "THIRD-PARTY-LICENSES/sing-box-LICENSE"):
            path = PREFIX / target / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                    not info.st_mode & 0o022 and info.st_size <= 134217728 and
                    file_hash(path) == self.bundle_hashes[current][name],
                    "Installed payload identity changed: " + name)
        for name in UNITS:
            path = Path("/etc/systemd/system") / name
            actual = sha(trusted_file(path))
            digest_path = PREFIX / ("unit.sha256" if name == UNITS[0]
                                    else name + ".sha256")
            require(actual == self.bundle_hashes[current][name] and
                    trusted_file(digest_path).decode().strip() == actual,
                    "Installed unit bytes/digest changed: " + name)
            props = self.unit(name)
            require(props["LoadState"] == "loaded" and
                    props["FragmentPath"] == str(path) and
                    not props["DropInPaths"] and props["Transient"] == "no",
                    "Loaded unit provenance changed: " + name)
        return current

    def inert_roles(self):
        for name in UNITS[1:]:
            props = self.unit(name)
            role_inert = (
                props["Unit"] == name.removesuffix(".timer") + ".service" and
                props["LastTriggerUSecMonotonic"] == "0"
                if name.endswith(".timer") else
                props["MainPID"] == "0" and props["ControlPID"] == "0" and
                props["ExecMainStartTimestampMonotonic"] == "0")
            require(props["ActiveState"] == "inactive" and
                    props["SubState"] in {"dead", "inactive"} and
                    role_inert and
                    not props["Job"] and props["UnitFileState"] ==
                    ("disabled" if name.endswith(".timer") else "static"),
                    "Experimental role is not inert: " + name)

    def state_identity_now(self):
        identities = {}
        for name in ("", "profiles", ".lock"):
            info = (STATE / name).lstat()
            require(info.st_uid == 0 and not info.st_mode & 0o077 and
                    (stat.S_ISREG(info.st_mode) if name == ".lock"
                     else stat.S_ISDIR(info.st_mode)), "Unsafe product state")
            identities[name] = [info.st_dev, info.st_ino]
        return identities

    def bind_created_state(self):
        self.state_identity = self.state_identity_now()
        self.state_marker = json.dumps({
            "schema": 1, "task": "server-connect-debian12-proxy-field-v1",
            "manifest_sha256": self.results["manifest_sha256"],
            "nonce": secrets.token_hex(24), "boot_id": self.manifest["boot_id"],
        }, sort_keys=True).encode()
        with (STATE / OWNER_FILE).open("xb") as stream:
            stream.write(self.state_marker)
            stream.flush()
            os.fsync(stream.fileno())
        save_new(self.run_dir / "state-owner-receipt.json", {
            "identities": self.state_identity,
            "marker_sha256": sha(self.state_marker), "bound_at": now(),
        })

    def selected_state(self, desired):
        require(self.state_identity_now() == self.state_identity,
                "Product state directory/lock was replaced")
        require(trusted_file(STATE / OWNER_FILE) == self.state_marker,
                "Test state marker changed")
        state = json.loads(trusted_file(STATE / "state.json"))
        require(state == {"version": 1, "selected": self.profile_id,
                          "desired": desired, "port": PROXY_PORT},
                "Selected profile/desired state changed")
        require(sha(trusted_file(STATE / "profiles" /
                                (self.profile_id + ".json"))) == self.profile_sha,
                "Saved private profile changed")
        if self.auth_sha is not None:
            require(sha(trusted_file(STATE / "proxy-auth")) == self.auth_sha,
                    "Saved proxy authentication changed")
        if desired == "proxy":
            require(self.runtime_sha is not None and
                    sha(trusted_file(STATE / "runtime.json")) == self.runtime_sha,
                    "Selected runtime configuration changed")
        else:
            require(not (STATE / "runtime.json").exists() and
                    not (STATE / "runtime.json").is_symlink(),
                    "Runtime credentials remain after Direct")
        return {"state_sha256": file_hash(STATE / "state.json"),
                "profile_sha256": self.profile_sha, "auth_sha256": self.auth_sha,
                "runtime_sha256": self.runtime_sha if desired == "proxy" else None}

    def active_core(self):
        self.assert_owned_install()
        self.inert_roles()
        report = self.cli(["status"])["data"]
        require(report.get("desired") == "proxy" and
                report.get("observed") == "active" and
                report.get("selected") == self.profile_id,
                "Installed Proxy Only state is not active")
        require(self.cli(["ready"])["data"].get("local_listener_ready") is True,
                "Authenticated local proxy is not ready")
        props = self.unit(UNITS[0])
        require(props["ActiveState"] == "active" and
                props["SubState"] == "running" and
                props["UnitFileState"] == "enabled" and not props["Job"] and
                props["ControlPID"] == "0" and
                re.fullmatch(r"[0-9a-f]{32}", props["InvocationID"]),
                "Proxy service is not a stable active invocation")
        pid = int(props["MainPID"])
        require(pid > 1, "Missing active proxy PID")
        proc = Path("/proc") / str(pid)
        start = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        executable_hash = file_hash(proc / "exe")
        require(executable_hash == self.bundle_hashes["base"]["bin/sing-box"],
                "Active PID is not the pinned core")
        evidence = {"pid": pid, "invocation": props["InvocationID"],
                    "start_ticks": start,
                    "systemd_start": props["ExecMainStartTimestampMonotonic"],
                    "exe_sha256": executable_hash}
        require(unchanged_core(evidence, evidence), "Incomplete live core identity")
        return evidence

    def direct_state(self):
        self.assert_owned_install()
        self.inert_roles()
        props = self.unit(UNITS[0])
        require(props["ActiveState"] == "inactive" and
                props["SubState"] == "dead" and
                props["MainPID"] == "0" and props["ControlPID"] == "0" and
                props["UnitFileState"] == "disabled" and not props["Job"],
                "Direct requires inactive and disabled owned proxy")
        return self.selected_state("direct")

    def private_upstream(self):
        identity = str(uuid.uuid4())
        self.secrets.append(identity)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.upstream_port = reservation.getsockname()[1]
        self.port_numbers.add(self.upstream_port)
        self.profile_uri = (
            "vless://" + identity + "@127.0.0.1:" + str(self.upstream_port) +
            "?type=tcp&security=none#Authorized-IRA124-Field-QA").encode()
        self.server_config = self.run_dir / "private-upstream.json"
        save_new(self.server_config, {
            "log": {"level": "warn"},
            "inbounds": [{"type": "vless", "tag": "field-local-vless",
                          "listen": "127.0.0.1",
                          "listen_port": self.upstream_port,
                          "users": [{"uuid": identity}]}],
            "outbounds": [{"type": "direct", "tag": "local-origin"}],
        })
        self.call([self.bundles["base"] / "bin/sing-box", "check",
                   "-c", self.server_config], timeout=10)
        run = self

        class Origin(http.server.BaseHTTPRequestHandler):
            timeout = 2

            def do_GET(self):
                if not re.fullmatch(r"/proof/[0-9a-f]{48}", self.path):
                    self.send_error(404)
                    return
                body = ("server-connect-field:" + self.path).encode()
                with run.event_lock:
                    run.origin_events.append({
                        "path": self.path, "peer": self.client_address[0],
                        "time": now()})
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.origin = http.server.HTTPServer(("127.0.0.1", 0), Origin)
        self.origin_port = self.origin.server_port
        self.port_numbers.add(self.origin_port)
        self.origin_thread = threading.Thread(
            target=self.origin.serve_forever,
            kwargs={"poll_interval": 0.1}, daemon=True)
        self.origin_thread.start()
        self.start_upstream()

    def start_upstream(self):
        index = len(self.children) + 1
        log = (self.run_dir / ("upstream-%d.private.log" % index)).open("xb")
        self.child_logs.append(log)
        process = subprocess.Popen(
            [str(self.bundles["base"] / "bin/sing-box"), "run",
             "-c", str(self.server_config)],
            env=ENV, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        self.children.append(process)
        self.upstream = process
        self.event("private_upstream_started", pid=process.pid,
                   generation=index, port=self.upstream_port)
        deadline = min(self.deadline, time.monotonic() + 5)
        while time.monotonic() < deadline:
            require(process.poll() is None, "Private upstream exited")
            listing = self.call(
                ["ss", "-H", "-lntp", "sport", "=", ":" + str(self.upstream_port)],
                timeout=3)[1].decode()
            if ("pid=" + str(process.pid) + ",") in listing and \
                    ("127.0.0.1:" + str(self.upstream_port)) in listing:
                return
            time.sleep(0.05)
        raise CheckFailure("Private upstream readiness timeout")

    @staticmethod
    def stop_child(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        require(process.poll() is not None, "Own child exit unverified")

    def request(self, selected, expected_success, label):
        path = "/proof/" + secrets.token_hex(24)
        if selected and not expected_success:
            self.failed_paths.add(path)
        url = "http://127.0.0.1:%d%s" % (self.origin_port, path)
        curl = ["/usr/bin/curl", "-q", "--silent", "--show-error", "--fail",
                "--connect-timeout", "2", "--max-time", "6",
                "--noproxy", "" if selected else "*", url]
        command = [COMMAND, "exec", "--", *curl] if selected else curl
        with self.event_lock:
            before = len(self.origin_events)
        rc, output, _ = self.call(command, expected=None, timeout=10)
        with self.event_lock:
            after = len(self.origin_events)
            matching = [item for item in self.origin_events
                        if item["path"] == path]
        expected = ("server-connect-field:" + path).encode()
        evidence = {"label": label, "selected_proxy": selected, "exit": rc,
                    "body_matches_nonce": output == expected,
                    "origin_before": before, "origin_after": after,
                    "matching_origin_requests": len(matching)}
        self.event("traffic_witness", **evidence)
        if expected_success:
            require(delivery_passed(rc, output, expected, before, after) and
                    len(matching) == 1 and matching[0]["peer"] == "127.0.0.1",
                    "Positive nonce delivery was not established: " + label)
        return rc, output, before, after

    def outage(self, label):
        self.request(True, True, label + "-positive-control")
        before = self.active_core()
        self.stop_child(self.upstream)
        self.event("private_upstream_stopped", pid=self.upstream.pid,
                   exit=self.upstream.returncode)
        rc, output, count, after_count = self.request(
            True, False, label + "-selected-outage")
        after = self.active_core()
        # Include any delivery which arrived after curl exited but while the
        # independent live-core observations were being collected.
        with self.event_lock:
            after_count = len(self.origin_events)
        require(outage_passed(rc, output, count, after_count, before, after),
                "Outage lacks live-core/no-Direct-leak proof")
        self.request(False, True, label + "-direct-control")
        self.start_upstream()
        self.request(True, True, label + "-restored")
        self.stage(label, core=before, zero_origin_delivery_during_loss=True)

    def tree_receipt(self, root, include_identity=False):
        result = {}
        require(root.exists() and not root.is_symlink(), "Missing owned tree")
        for path in [root, *sorted(root.rglob("*"))]:
            info = path.lstat()
            name = "." if path == root else str(path.relative_to(root))
            item = {"uid": info.st_uid, "gid": info.st_gid,
                    "mode": stat.S_IMODE(info.st_mode)}
            if include_identity:
                item.update(device=info.st_dev, inode=info.st_ino)
            if stat.S_ISDIR(info.st_mode):
                item["kind"] = "directory"
            elif stat.S_ISREG(info.st_mode):
                item.update(kind="file", bytes=info.st_size, sha256=file_hash(path))
            elif stat.S_ISLNK(info.st_mode):
                item.update(kind="symlink", target=os.readlink(path))
            else:
                raise CheckFailure("Unexpected resource type in owned tree")
            result[name] = item
        return result

    def purge_created_state(self):
        require(self.state_identity is not None and self.profile_id is not None,
                "No complete task state ownership receipt; preserve state")
        require(self.product_absent(include_state=False),
                "Product paths/units remain; preserve state")
        self.selected_state("direct")
        allowed = {".", "profiles", ".lock", "state.json", "proxy-auth",
                   OWNER_FILE, "profiles/" + self.profile_id + ".json"}
        expected = self.tree_receipt(STATE, include_identity=True)
        require(set(expected) == allowed and
                purge_inventory_matches(expected, expected),
                "Unknown private state content; preserve state")
        require(all([expected[name]["device"], expected[name]["inode"]] ==
                    self.state_identity[identity] for name, identity in
                    ((".", ""), ("profiles", "profiles"))),
                "Private directory receipt differs from original task ownership")
        require(expected["profiles/" + self.profile_id + ".json"]["sha256"] ==
                self.profile_sha and expected["proxy-auth"]["sha256"] ==
                self.auth_sha and expected[OWNER_FILE]["sha256"] ==
                sha(self.state_marker) and expected[".lock"]["bytes"] == 0,
                "Private state ownership changed")
        lock = os.open(STATE / ".lock", os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                    info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and
                    info.st_nlink == 1 and
                    [info.st_dev, info.st_ino] == self.state_identity[".lock"],
                    "State lock identity changed")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(self.state_identity_now() == self.state_identity and
                    self.product_absent(include_state=False) and
                    purge_inventory_matches(
                        self.tree_receipt(STATE, include_identity=True), expected),
                    "State changed before exact purge")
            self.event("before_exact_test_state_purge",
                       inventory_sha256=fingerprint(expected))
            trusted_ancestry(STATE.parent)
            parent_fd = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW)
            try:
                delete_exact_private_state(parent_fd, self.profile_id, expected)
            finally:
                os.close(parent_fd)
        finally:
            os.close(lock)
        require(not STATE.exists() and not STATE.is_symlink(),
                "Test state purge incomplete")
        self.results["exact_test_state_purged"] = True

    def execute(self):
        self.prepare_bundle("base")
        require(self.call(["systemctl", "--version"])[1].splitlines()[0].startswith(
            b"systemd 252 "), "Field compatibility requires observed systemd252")
        self.baseline = self.observe_host()
        save_new(self.run_dir / "baseline.json", self.baseline)
        require(not self.baseline["raw"]["docker_containers"],
                "This bounded IRA-124 admission requires the observed empty Docker baseline")
        require(self.product_absent(), "Existing product resources; refuse test")
        require(not self.call(
            ["ss", "-H", "-lntup", "sport", "=", ":" + str(PROXY_PORT)]
        )[1].strip(), "Product proxy port already belongs to another owner")
        self.port_numbers.add(PROXY_PORT)
        self.ssh_observation("before")
        self.stage("host-and-exact-artifacts-admitted")
        self.installer("--verify-only")
        require(self.product_absent(), "Verify-only changed product resources")
        self.opposite_target_helper()
        self.installer("--offline")
        self.assert_owned_install("base")
        self.inert_roles()
        props = self.unit(UNITS[0])
        require(props["ActiveState"] == "inactive" and
                props["SubState"] == "dead" and props["MainPID"] == "0" and
                props["ControlPID"] == "0" and not props["Job"] and
                props["UnitFileState"] == "disabled" and
                not (STATE / "runtime.json").exists() and
                not (STATE / "runtime.json").is_symlink() and
                not (STATE / "proxy-auth").exists() and
                not (STATE / "proxy-auth").is_symlink() and
                not list((STATE / "profiles").iterdir()) and
                json.loads(trusted_file(STATE / "state.json")) ==
                {"version": 1, "desired": "direct", "port": PROXY_PORT},
                "Initial install not inert")
        self.bind_created_state()
        self.stage("inactive-offline-install")
        self.private_upstream()
        imported = self.cli(["import", "--file", "-"],
                            input_bytes=self.profile_uri)["data"]
        self.profile_id = imported["id"]
        require(re.fullmatch(r"[0-9a-f]{16}", self.profile_id), "Invalid profile ID")
        self.profile_sha = file_hash(STATE / "profiles" / (self.profile_id + ".json"))
        self.cli(["select", self.profile_id])
        self.cli(["connect"])
        password = trusted_file(STATE / "proxy-auth", 1024)
        self.secrets.append(password.decode())
        self.auth_sha = sha(password)
        self.runtime_sha = sha(trusted_file(STATE / "runtime.json"))
        self.active_core()
        self.selected_state("proxy")
        self.request(False, True, "initial-direct-control")
        self.request(True, True, "installed-selected-path")
        self.stage("installed-local-vless-proxy")
        self.outage("live-core-upstream-loss")
        self.cli(["disconnect"])
        disconnected = self.direct_state()
        self.request(False, True, "direct-after-disconnect")
        failure = self.cli(["probe", "--via", "proxy", "--url",
                            "http://127.0.0.1:%d/" % self.origin_port], expected=1)
        require(failure.get("error", {}).get("code") == "proxy_unavailable" and
                failure.get("data", {}).get("result") == "unavailable",
                "Disconnected proxy did not fail closed")
        self.stage("disconnect-preserves-selected-profile", state=disconnected)
        before_reinstall = self.tree_receipt(PREFIX)
        self.installer("--offline")
        require(self.tree_receipt(PREFIX) == before_reinstall and
                self.direct_state() == disconnected, "Reinstall changed saved state")
        self.stage("same-artifact-reinstall")
        self.cli(["connect"])
        self.active_core()
        self.selected_state("proxy")
        self.request(True, True, "after-same-base-reinstall")
        self.stage("reconnect-after-same-base-reinstall")
        self.outage("post-reinstall-live-core-upstream-loss")
        self.cli(["disconnect"])
        final_saved = self.direct_state()
        self.installer("--uninstall")
        require(self.product_absent(include_state=False) and
                self.selected_state("direct") == final_saved,
                "Uninstall did not preserve saved state and remove owned product")
        self.stage("uninstall-preserves-private-profile")
        self.results["lifecycle_completed"] = True

    def cleanup(self):
        self.cleanup_deadline = time.monotonic() + 120
        if self.install_dispatched:
            try:
                require(not self.mutator_uncertain and not self.installer_unverified,
                        "Unverified mutator/installer outcome; preserve for reconciliation")
                if PREFIX.exists() or COMMAND.exists() or COMMAND.is_symlink():
                    self.assert_owned_install()
                    self.inert_roles()
                    self.cli(["disconnect"])
                    self.installer("--uninstall")
                if STATE.exists() or STATE.is_symlink():
                    self.purge_created_state()
            except BaseException as error:
                self.results["cleanup_errors"].append(
                    "Product/state cleanup uncertain: " + self.redact(str(error)))
        for child in reversed(self.children):
            try:
                self.stop_child(child)
            except BaseException as error:
                self.results["cleanup_errors"].append("Private child: " + str(error))
        if self.origin is not None:
            try:
                if self.origin_thread is not None and self.origin_thread.is_alive():
                    self.origin.shutdown()
                self.origin.server_close()
                if self.origin_thread is not None:
                    self.origin_thread.join(timeout=3)
                    require(not self.origin_thread.is_alive(), "Origin thread remains")
            except BaseException as error:
                self.results["cleanup_errors"].append("Private origin: " + str(error))
        for stream in self.child_logs:
            stream.close()
        self.results["all_private_children_stopped"] = all(
            child.poll() is not None for child in self.children)
        with self.event_lock:
            save_new(self.run_dir / "origin-events.json", self.origin_events)
            self.results["no_outage_origin_delivery"] = not any(
                event["path"] in self.failed_paths for event in self.origin_events)
        try:
            for port in self.port_numbers:
                require(not self.call(
                    ["ss", "-H", "-lntp", "sport", "=", ":" + str(port)],
                    timeout=5)[1].strip(), "Task listener remains: " + str(port))
            self.results["task_listeners_absent"] = True
            self.results["product_resources_absent"] = self.product_absent()
            if self.baseline is not None:
                after = self.observe_host()
                save_new(self.run_dir / "after.json", after)
                self.results["changed_host_components"] = [
                    key for key, value in self.baseline["hashes"].items()
                    if after["hashes"].get(key) != value]
                self.results["recorded_host_views_unchanged"] = not self.results[
                    "changed_host_components"]
                self.ssh_observation("after")
        except BaseException as error:
            self.results["cleanup_errors"].append(
                "Final observation incomplete: " + self.redact(str(error)))
        self.results["finished_at"] = now()
        if self.stop_signal is not None:
            self.results.setdefault("failure", {
                "type": "Interrupted", "message": "Signal received; bounded cleanup ran"})
            self.results["interrupted_signal"] = self.stop_signal
        self.results["mutation_outcome_known"] = not (
            self.mutator_uncertain or self.installer_unverified)
        self.results["passed"] = final_passed(self.results)
        self.results["limits"] = [
            "No external VPN, TUN, IPv6 path or physical reboot acceptance.",
            "Distinct-byte update and invalid-unit rollback are NOT_RUN on the field "
            "target; those fixtures remain disconnected-CI-only.",
            "Same-base reinstall does not establish version migration.",
            "iptables compatibility snapshots are not complete native nft inventory.",
            "Host observations are separate non-atomic snapshots.",
            "360-second command-admission budget plus bounded cleanup; process "
            "termination and observation failure are reported, not hidden.",
            "MASTER must separately verify fresh Gateway SSH access after the Job.",
        ]
        save_new(self.run_dir / "results.json", self.results)
        print("FIELD_LIFECYCLE_RESULT=" + json.dumps({
            key: self.results.get(key) for key in
            ("passed", "lifecycle_completed", "exact_test_state_purged",
             "all_private_children_stopped", "no_outage_origin_delivery",
             "task_listeners_absent",
             "product_resources_absent", "recorded_host_views_unchanged",
             "changed_host_components", "mutation_outcome_known",
             "cleanup_errors", "not_run_on_field")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    arguments = parser.parse_args()
    run = FieldRun(arguments.manifest, arguments.manifest_sha256)
    # Cooperatively stop at command boundaries. Interrupting an installer in
    # the middle of a mutation cannot establish a safe cleanup starting point.
    def request_stop(signum, _frame):
        run.stop_signal = signum

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, request_stop)
    try:
        run.execute()
    except BaseException as error:
        run.results["failure"] = {
            "type": type(error).__name__, "message": run.redact(str(error))}
        run.event("lifecycle_failure", **run.results["failure"])
    finally:
        run.cleanup()
    return 0 if run.results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
