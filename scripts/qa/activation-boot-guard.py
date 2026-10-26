#!/usr/bin/env python3
"""Disconnected Debian 13 QA ONLY: durable intent and independent boot observation.

This fixture is not installed, packaged, or called by Server Connect. It does
not arm a product guard and deliberately does not issue a network mutation.
Container restart recreates a network namespace, NOT a real host reboot.
"""
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path("/var/lib/sc-qa-boot-recovery")
JOURNAL = ROOT / "intent.json"
VERSION = "sc_qa_boot_v1"
HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def require_private_directory(create=False):
    if create and not ROOT.exists() and not ROOT.is_symlink():
        ROOT.mkdir(mode=0o700)
    info = ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("unsafe QA-only boot journal directory")
    return os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def exact_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate boot journal property")
        out[key] = value
    return out


def read_journal():
    fd = os.open(JOURNAL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("unsafe QA-only boot journal file")
        data = os.read(fd, 4097)
        if not data or len(data) > 4096:
            raise ValueError("invalid boot journal size")
        record = json.loads(data, object_pairs_hook=exact_pairs)
    finally:
        os.close(fd)
    if not isinstance(record, dict) or record.get("schema") != VERSION:
        raise ValueError("unsupported QA-only boot journal")
    phase = record.get("phase")
    expected = {"schema", "operation_id", "phase"}
    if phase == "recovered_noop_qa":
        expected.add("invocation")
    elif phase != "pending_qa_only":
        raise ValueError("unsupported QA-only boot journal phase")
    if set(record) != expected or not isinstance(record.get("operation_id"), str) or not HEX32.fullmatch(record["operation_id"]):
        raise ValueError("invalid QA-only boot journal identity or shape")
    if phase == "recovered_noop_qa":
        invocation = record.get("invocation")
        if not isinstance(invocation, str) or not HEX32.fullmatch(invocation):
            raise ValueError("invalid QA-only boot invocation identity")
    return record, data


def durable_write(record, directory_fd):
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    fd, name = tempfile.mkstemp(prefix=".intent-qa-", dir=ROOT)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as file:
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, JOURNAL)
        os.fsync(directory_fd)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def ip_rows(*args):
    result = subprocess.run(
        ["/usr/bin/ip", "-j", *args],
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        capture_output=True,
        timeout=5,
        check=True,
    )
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("oversized native guest kernel observation")
    rows = json.loads(result.stdout, object_pairs_hook=exact_pairs)
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("unexpected native guest kernel observation")
    return rows


def require_empty_guest_owned_scope():
    # This narrow *guest* predicate cannot prove generic Linux resource
    # ownership. A foreign object must block any optimistic success receipt.
    links = ip_rows("link", "show")
    names = [row.get("ifname") for row in links]
    if len(names) != 1 or names[0] != "lo":
        raise ValueError("foreign or staged link present after container restart")
    for family in ("-4", "-6"):
        for row in ip_rows(family, "route", "show", "table", "all"):
            table = row.get("table", "main")
            if str(table) == "20120":
                raise ValueError("foreign or staged route present after restart")
        for row in ip_rows(family, "rule", "show"):
            priority = row.get("priority")
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise ValueError("unsupported native guest RPDB priority")
            if 30000 <= priority <= 30999 or str(row.get("table")) == "20120":
                raise ValueError("foreign or staged RPDB rule after restart")


def main():
    if os.getuid() != 0 or len(sys.argv) < 2:
        raise ValueError("root QA-only action is required")
    action = sys.argv[1]
    if action == "arm":
        if len(sys.argv) != 3 or not HEX32.fullmatch(sys.argv[2]):
            raise ValueError("invalid QA-only arm operation")
        require_empty_guest_owned_scope()
        directory_fd = require_private_directory(create=True)
        try:
            if os.path.lexists(JOURNAL):
                previous, _ = read_journal()
                if previous["phase"] != "recovered_noop_qa" or previous["operation_id"] == sys.argv[2]:
                    raise ValueError("previous pending/corrupt/replayed boot journal")
            durable_write({"schema": VERSION, "operation_id": sys.argv[2], "phase": "pending_qa_only"}, directory_fd)
        finally:
            os.close(directory_fd)
        print("QA_BOOT_PENDING_DURABLE=PASS")
    elif action == "recover":
        if len(sys.argv) != 2:
            raise ValueError("invalid QA-only recover invocation")
        invocation = os.environ.get("INVOCATION_ID", "")
        if not HEX32.fullmatch(invocation):
            raise ValueError("not an authenticated systemd QA service invocation")
        directory_fd = require_private_directory()
        try:
            record, _ = read_journal()
            if record["phase"] != "pending_qa_only":
                raise ValueError("recovery is not pending; no replay")
            require_empty_guest_owned_scope()
            record["phase"] = "recovered_noop_qa"
            record["invocation"] = invocation
            durable_write(record, directory_fd)
        finally:
            os.close(directory_fd)
        print("QA_BOOT_JOURNAL_RECOVERED_NOOP=PASS (no network mutation)")
    elif action == "show":
        if len(sys.argv) != 2:
            raise ValueError("invalid QA-only show invocation")
        directory_fd = require_private_directory()
        try:
            record, _ = read_journal()
        finally:
            os.close(directory_fd)
        print(json.dumps(record, sort_keys=True))
    else:
        raise ValueError("unknown QA-only boot action")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"QA_BOOT_FAIL_CLOSED: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(24)
