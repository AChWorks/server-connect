#!/usr/bin/env python3
"""Read-only evidence checker for isolated native APT transport refusals.

Unlike the offline-install scanner, apt-get and apt-config must execute here.
No IPv4/IPv6/packet socket or unsupported transport helper may execute, and
every traced process/thread must have complete, non-timeout exit evidence.
Raw trace lines are never printed: method/config arguments may contain secrets.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys


class TraceFailure(ValueError):
    pass


DISABLED = ("ftp", "rsh", "ssh", "mirror+ftp")
DISABLED_PATH = "/usr/lib/apt/methods/false"


def require(condition: bool, label: str) -> None:
    if not condition:
        raise TraceFailure(label)


def check_payloads(payloads: dict[int, str]) -> None:
    require(0 < len(payloads) <= 256, "missing or excessive process evidence")
    parents: dict[int, int] = {}
    manager_pids: set[int] = set()
    acquisition_pids: set[int] = set()
    baseline_dumps = 0
    owned_dumps = 0
    exits: dict[int, int] = {}
    for pid, text in payloads.items():
        require(type(pid) is int and pid > 0, "invalid process identity")
        require(bool(text) and text.endswith("\n"), "empty or truncated process evidence")
        require(all(char in "\n\t" or 32 <= ord(char) <= 126 for char in text), "nontextual process evidence")
        # Inspect all text, including interrupted/resumed calls, before parsing.
        families = re.findall(r"\bAF_[A-Z0-9_]+\b", text)
        require(all(family in ("AF_UNIX", "AF_LOCAL", "AF_NETLINK") for family in families), "nonlocal network attempt")
        require(re.search(r"<(?:TCP|UDP|IP)(?:v6)?:", text) is None, "decoded Internet descriptor used")
        pending = ""
        finished = False
        for line in text.splitlines():
            require(not finished, "records after process completion")
            terminal = re.fullmatch(r"\+\+\+ exited with (0|100) \+\+\+", line)
            if terminal:
                if pending:
                    syscall = re.match(r"([a-z0-9_]+)\(", pending)
                    name = syscall.group(1) if syscall else "unknown"
                    # A trace of exit_group can be split at process death.
                    # A Go thread can also exit with a pending FUTEX wait;
                    # futex is synchronization, not network/exec/fork. Trace
                    # it by name in the scanner rather than accepting the
                    # unidentifiable ???( output of an unselected syscall.
                    # An actual exit receipt must still complete this trace.
                    # All pending network, exec and process-creation calls
                    # remain untrusted even if the process subsequently exits.
                    final_exit = re.fullmatch(r"exit_group\((0|100)\)?", pending)
                    benign_wait = name in ("wait4", "waitid", "futex")
                    require(benign_wait or (final_exit is not None and
                            int(final_exit.group(1)) == int(terminal.group(1))),
                            "incomplete syscall at process exit (" + name + ")")
                exits[pid] = int(terminal.group(1))
                finished = True
                continue
            if re.fullmatch(r"--- SIG[A-Z0-9]+ .* ---", line):
                continue
            if line.endswith(" <unfinished ...>"):
                require(not pending, "overlapping interrupted syscalls")
                pending = line.removesuffix(" <unfinished ...>")
                continue
            resumed = re.fullmatch(r"<\.\.\. ([a-z0-9_]+) resumed>(.*)", line)
            if resumed:
                require(bool(pending) and pending.startswith(resumed.group(1) + "("), "unmatched syscall resumption")
                line = pending + resumed.group(2)
                pending = ""
            require(re.fullmatch(r"[a-z0-9_]+\(.*\)\s+=\s+.+", line) is not None,
                    "unrecognized or incomplete syscall evidence")
            require(not line.startswith("execveat("), "unverifiable alternate execution")
            child = re.fullmatch(r"(?:clone|clone3|fork|vfork)\(.*\)\s+=\s+([1-9][0-9]*)", line)
            if child:
                child_pid = int(child.group(1))
                require(child_pid != pid and child_pid not in parents, "ambiguous descendant identity")
                parents[child_pid] = pid
            if line.startswith("execve("):
                execution = re.fullmatch(r'execve\("([^"\\]+)", \[(.*?)\], .*\)\s+=\s+(.+)', line)
                require(execution is not None, "unverifiable executable path or arguments")
                path, argv, result = execution.groups()
                require(path.rsplit("/", 1)[-1] not in (*DISABLED, "false"), "unsupported transport execution attempted")
                if result == "0":
                    if path == "/usr/local/bin/server-connect" and '"apt"' in argv:
                        manager_pids.add(pid)
                    if path == "/usr/bin/apt-config" and '"dump"' in argv:
                        denials = [f'"Dir::Bin::Methods::{method}={DISABLED_PATH}"' in argv for method in DISABLED]
                        if any(denials):
                            require(all(denials), "effective APT policy lost an owned denial")
                            owned_dumps += 1
                        else:
                            baseline_dumps += 1
                    if path == "/usr/bin/apt-get" and '"update"' in argv:
                        require('"/proc/self/fd/3"' in argv, "native APT lost its private configuration")
                        for method in DISABLED:
                            setting = f'"Dir::Bin::Methods::{method}={DISABLED_PATH}"'
                            require(setting in argv, "native APT lost an owned transport denial")
                        acquisition_pids.add(pid)
        require(finished, "missing process completion evidence")
    require(parents.keys() <= payloads.keys(), "missing descendant trace")
    roots = payloads.keys() - parents.keys()
    require(len(roots) == 1 and roots == manager_pids, "missing or ambiguous manager root")
    reached = set(roots)
    while True:
        descendants = {child for child, parent in parents.items() if parent in reached}
        expanded = reached | descendants
        if expanded == reached:
            break
        reached = expanded
    require(reached == payloads.keys(), "disconnected process evidence")
    require(len(acquisition_pids) == 1 and baseline_dumps >= 1 and owned_dumps >= 1,
            "native acquisition or two-stage policy evidence missing")
    require(all(exits[pid] == 100 for pid in roots | acquisition_pids), "native refusal exit not established")


def check_directory(directory: Path) -> None:
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o022 == 0,
            "unsafe trace directory")
    entries = list(directory.iterdir())
    require(0 < len(entries) <= 256, "missing or excessive trace files")
    payloads: dict[int, str] = {}
    total = 0
    for path in entries:
        name = re.fullmatch(r"trace\.([1-9][0-9]*)", path.name)
        require(name is not None, "unexpected trace file")
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_mode & 0o022 == 0,
                "unsafe trace file")
        require(0 < before.st_size <= 2 * 1024 * 1024, "empty or oversized trace file")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "trace identity changed")
            raw = source.read(2 * 1024 * 1024 + 1)
            after = os.fstat(source.fileno())
        current = path.lstat()
        require(len(raw) == before.st_size and (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
                and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), "trace changed while reading")
        total += len(raw)
        require(total <= 16 * 1024 * 1024, "excessive total trace evidence")
        payloads[int(name.group(1))] = raw.decode("ascii")
    check_payloads(payloads)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "invalid trace-check arguments")
        check_directory(Path(sys.argv[1]))
    except (OSError, UnicodeError, TraceFailure) as error:
        label = str(error) if isinstance(error, TraceFailure) else "unreadable process evidence"
        print("APT_DISABLED_TRANSPORT_TRACE=FAIL (" + label + ")", file=sys.stderr)
        sys.exit(1)
    print("APT_DISABLED_TRANSPORT_TRACE=PASS (complete process tree, owned denial, no transport helper or Internet attempt)")
