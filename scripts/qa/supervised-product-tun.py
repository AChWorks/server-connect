#!/usr/bin/env python3
"""Confirmed supervision acceptance in the existing disconnected guest only.

This never provisions a Docker container, changes a physical host, or treats
synthetic management/VPN proof as general-host production acceptance.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time


SC = "/usr/local/bin/server-connect"
PEER = "scqapeer"
JOURNAL = Path("/var/lib/server-connect/route-activation-journal.json")
HEALTH = "server-connect-smart-health.service"
TIMER = "server-connect-smart-health.timer"
RECOVERY = "server-connect-activation-recover.service"
RECOVERY_TIMER = "server-connect-activation-recover.timer"
CORE = "server-connect-smart-tun.service"
UNITS = Path("/etc/systemd/system")
ROOT = Path("/run/sc-qa-supervised")
PUBLIC4 = ("8.8.8.8", "198.51.100.42")
PUBLIC6 = ("2001:db8:8::8", "2001:db8:5::10")
PROTOCOLS = ("tcp", "udp", "dns", "https")
TLS_BUNDLE = Path("/root/qa-smart-health-tls")
TLS_FILES = ("qa-root.pem", "qa-server.pem", "qa-server-key.pem", "qa-wrong-name.pem",
             "qa-wrong-trust.pem", "qa-wrong-root.pem", "qa-expired.pem", "qa-client-auth-only.pem")
LEGACY_EVIDENCE_KEYS = frozenset(("underlay_healthy", "vpn_healthy", "ipv4_tcp", "ipv4_udp", "ipv4_dns",
                                "ipv6_tcp", "ipv6_udp", "ipv6_dns", "failed_targets", "probe_count",
                                "elapsed_ms", "reason"))
HTTPS_EVIDENCE_KEYS = LEGACY_EVIDENCE_KEYS | {"ipv4_https", "ipv6_https", "https_results"}


def exact_json(value):
    """Keep JSON number/boolean types distinct in complete fixture CAS proofs."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


CONFIRM_DEATH_WRAPPER = r'''
import json, re, signal, subprocess, sys

def main():
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            return 2
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"argv", "operation_id", "revision", "boundary"}:
            return 2
        operation, revision, boundary = request["operation_id"], request["revision"], request["boundary"]
        argv = request["argv"]
        if not isinstance(operation, str) or re.fullmatch("[0-9a-f]{32}", operation) is None:
            return 2
        if type(revision) is not int or revision != 1 or boundary not in ("before-confirm-publish", "after-confirm-publish"):
            return 2
        if not isinstance(argv, list) or len(argv) != 11 or not all(isinstance(item, str) for item in argv):
            return 2
        if re.fullmatch("[0-9a-f]{32,128}", argv[8]) is None:
            return 2
        expected = ["/usr/local/bin/server-connect", "--json", "smart-tun-trial-confirm",
                    "--operation-id", operation, "--revision", "1", "--challenge", argv[8],
                    "--qa-kill-at", boundary]
        if argv != expected:
            return 2
        child = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20, check=False)
        if child.returncode != -signal.SIGKILL:
            return 3
        receipt = {"kind": "scqa-confirm-death-v1", "operation_id": operation, "revision": revision,
                   "boundary": boundary, "child_returncode": child.returncode}
        sys.stdout.write(json.dumps(receipt, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        # A timeout may itself kill the child. It never earns a death receipt.
        # Do not expose input, argv, captured child output, or exception text.
        return 2

raise SystemExit(main())
'''


class Fixture:
    def __init__(self, args):
        self.args = args
        self.started = time.monotonic()
        self.processes = []
        self.streams = []
        self.saved_units = {}
        self.upstream_stopped = False
        self.foreign = False
        self.op = None
        self.challenge = None
        self.targets = PUBLIC4 + (PUBLIC6 if args.ipv6 else ())
        self.master = False
        self.cleaning = False
        self.root_created = False
        self.foreign_snapshot = None
        self.upstream_fd = None
        self.health_identity = None
        self.recovery_identity = None
        self.health_role_originals = {}
        self.fixture_boot_id = None
        self.health_fault_series = None
        self.tls_bundle = getattr(args, "tls_bundle", TLS_BUNDLE)
        self.tls_identity = None
        self.legacy_pause = None
        self.legacy_roles = {}
        self.applied_record = None

    def command(self, argv, *, check=True, timeout=20, data=None):
        elapsed = time.monotonic() - self.started
        if elapsed > 360 and not self.cleaning:
            raise AssertionError("supervised fixture exceeded its aggregate 360-second budget")
        safe = ["<challenge>" if i and argv[i - 1] == "--challenge" else value
                for i, value in enumerate(argv)]
        try:
            result = subprocess.run(argv, input=data, capture_output=True, text=True,
                                    timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise subprocess.TimeoutExpired(safe, error.timeout) from None
        if check and result.returncode:
            # Fixed QA commands and keys are not user credentials. Redact the
            # one-time confirmation argument; diagnostics retain exit/stderr.
            raise AssertionError(f"command failed ({result.returncode}): {safe}: {result.stderr[-2000:]}")
        return result

    def cli(self, *args, check=True, ssh=False, multiplex=False):
        argv = [SC, "--json", *map(str, args)]
        if ssh:
            argv = self.ssh_arguments(multiplex) + argv
        result = self.command(argv, check=False, timeout=30)
        try:
            value = json.loads(result.stdout)
        except ValueError:
            if check:
                raise AssertionError(f"product returned no JSON; exit={result.returncode}, stderr={result.stderr[-2000:]}")
            return result, None
        if check:
            assert result.returncode == 0 and value.get("ok") is True, value
            return value["data"]
        return result, value

    def show(self, unit, prop):
        return self.command(["systemctl", "show", unit, "-p", prop, "--value"]).stdout.strip()

    def journal(self):
        try:
            value = json.loads(JOURNAL.read_text())
        except FileNotFoundError:
            return None
        assert value["operation_id"] == self.op, "a different operation replaced the fixture"
        return value

    def health(self):
        value = self.journal()
        assert value is not None, "operation ended before expected health evidence"
        return value["supervised"]

    def wait(self, predicate, seconds, label):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(0.1)
        raise AssertionError("timed out waiting for " + label)

    def state(self):
        value = self.cli("smart-tun-trial-status")
        assert value["experiment_only"] and not value["activation_ready"], value
        assert not value["vpn_verified"], "synthetic operation must not claim general-host VPN verification"
        return value

    def native(self):
        def normalize(value):
            if isinstance(value, list):
                return [normalize(item) for item in value]
            if isinstance(value, dict):
                result = {key: normalize(item) for key, item in value.items()}
                counter = result.get("counter")
                if isinstance(counter, dict) and ("packets" in counter or "bytes" in counter):
                    assert all(type(counter.get(key)) is int and 0 <= counter[key] < 2**64
                               for key in ("packets", "bytes")), "malformed native packet counter"
                    counter["packets"] = counter["bytes"] = 0
                return result
            return value
        values = [json.loads(self.command(argv).stdout) for argv in (
            ["ip", "-N", "-j", "-4", "route", "show", "table", "all"],
            ["ip", "-N", "-j", "-4", "rule", "show"],
            ["ip", "-N", "-j", "-6", "route", "show", "table", "all"],
            ["ip", "-N", "-j", "-6", "rule", "show"],
            ["nft", "-n", "-j", "-a", "list", "ruleset"],
        )]
        for item in values[-1]["nftables"]:
            if "metainfo" not in item:
                assert len(item) == 1
                fields = next(iter(item.values()))
                assert type(fields.get("handle")) is int and fields["handle"] > 0
        values[-1] = normalize(values[-1])
        return [json.dumps(value, sort_keys=True, separators=(",", ":")) for value in values]

    def saved(self):
        import hashlib
        return {name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in (
                    ("profile", Path("/var/lib/server-connect/profiles") / (self.args.profile + ".json")),
                    ("policy", Path("/var/lib/server-connect/smart-tun-policy.json")),
                    ("selection", Path("/var/lib/server-connect/state.json")),
                )}

    def controls(self, mapping=None):
        staging = ROOT / "control.new"
        staging.write_text(json.dumps(mapping or {}))
        staging.replace(ROOT / "control.json")

    def ssh_arguments(self, multiplex=False):
        argv = ["ip", "netns", "exec", PEER, "ssh", "-F", "/dev/null",
                "-i", str(ROOT / "clientkey"), "-p", "19223", "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=3",
                "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(ROOT / "known_hosts"),
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                "-o", "ControlMaster=no", "-o", "ControlPath=" +
                (str(ROOT / "master.sock") if multiplex else "none"), "root@10.254.72.1"]
        return argv

    def background(self, argv, name):
        out = open(ROOT / (name + ".log"), "w")
        self.streams.append(out)
        process = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def current_boot_id(self):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def read_health_role_file(self, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
            assert 0 < before.st_size <= 65536, "invalid health role file size"
            body = os.read(descriptor, 65537)
            after, named = os.fstat(descriptor), os.lstat(path)
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
            assert all(getattr(before, field) == getattr(after, field) == getattr(named, field) for field in fields), \
                "health role file changed during observation"
            assert len(body) == before.st_size, "incomplete health role file"
            return before.st_dev, before.st_ino, body
        finally:
            os.close(descriptor)

    def health_role_files(self, name):
        return (self.read_health_role_file(UNITS / name),
                self.read_health_role_file(Path("/opt/server-connect") / (name + ".sha256")))

    def start(self):
        assert Path("/.dockerenv").is_file()
        assert Path("/proc/1/comm").read_text().strip() == "systemd"
        assert not JOURNAL.exists() and not ROOT.exists()
        assert self.tls_bundle.is_dir() and not self.tls_bundle.is_symlink()
        assert {path.name for path in self.tls_bundle.iterdir()} == set(TLS_FILES), "unexpected TLS fixture contents"
        self.tls_identity = {name: self.read_health_role_file(self.tls_bundle / name) for name in TLS_FILES}
        assert self.show(CORE, "ActiveState") == "inactive"
        assert self.show(HEALTH, "ActiveState") == "inactive"
        assert self.show(TIMER, "ActiveState") == "inactive"
        recovery_path = UNITS / RECOVERY
        recovery_stat = recovery_path.stat()
        self.recovery_identity = (recovery_stat.st_dev, recovery_stat.st_ino, recovery_path.read_bytes())
        self.health_role_originals = {name: self.health_role_files(name) for name in (HEALTH, TIMER)}
        self.legacy_roles = {name: self.health_role_files(name) for name in (TIMER, RECOVERY_TIMER, HEALTH, RECOVERY)}
        self.health_identity = self.health_role_originals[HEALTH][0]
        self.fixture_boot_id = self.current_boot_id()
        self.upstream_fd = os.pidfd_open(self.args.upstream_pid)
        upstream_argv = Path(f"/proc/{self.args.upstream_pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        assert upstream_argv == [b"/root/server-connect/bin/sing-box", b"run", b"-c", b"/run/sc-qa-tun-upstream.json"], upstream_argv
        ROOT.mkdir(mode=0o700)
        self.root_created = True
        self.baseline = self.native()
        self.controls()
        for name in ("hostkey", "clientkey"):
            self.command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ROOT / name)])
        shutil.copyfile(ROOT / "clientkey.pub", ROOT / "authorized_keys")
        (ROOT / "known_hosts").write_text("[10.254.72.1]:19223 " + (ROOT / "hostkey.pub").read_text())
        (ROOT / "sshd_config").write_text(
            "ListenAddress 10.254.72.1\nPort 19223\nHostKey " + str(ROOT / "hostkey") +
            "\nPidFile " + str(ROOT / "sshd.pid") + "\nAuthorizedKeysFile " + str(ROOT / "authorized_keys") +
            "\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "PubkeyAuthentication yes\nUsePAM yes\nAllowUsers root\nAllowTcpForwarding no\n"
            "AllowAgentForwarding no\nX11Forwarding no\nPermitTunnel no\nPrintMotd no\nLogLevel ERROR\n")
        self.command(["/usr/sbin/sshd", "-t", "-f", str(ROOT / "sshd_config")])
        self.background(["/usr/sbin/sshd", "-D", "-e", "-f", str(ROOT / "sshd_config")], "sshd")
        responder = ["ip", "netns", "exec", PEER, "/usr/bin/python3", "-I", "-B", "-u",
                     "/root/qa-smart-health-responder.py", "--control", str(ROOT / "control.json"),
                     "--events", str(ROOT / "events.jsonl"), "--ready", str(ROOT / "ready"),
                     "--tls-bundle", str(self.tls_bundle)]
        if self.args.ipv6:
            responder.append("--ipv6")
        self.background(responder, "responder")
        self.wait(lambda: (ROOT / "ready").is_file(), 3, "health responder")
        self.command(self.ssh_arguments() + ["true"])
        rules = ["table inet scqahealth {", "chain incoming { type filter hook input priority filter; policy accept;"]
        for number, address in enumerate(self.targets):
            family = "ip6" if ":" in address else "ip"
            for protocol in PROTOCOLS:
                transport = "tcp" if protocol in ("tcp", "https") else "udp"
                port = {"tcp": 19220, "udp": 19221, "dns": 19222, "https": 19224}[protocol]
                rules.append(f'iifname "scqapeer0" {family} daddr {address} {transport} dport {port} counter comment "health-{number}-{protocol}"')
        rules.extend(("}", "}"))
        self.command(["ip", "netns", "exec", PEER, "nft", "-f", "-"], data="\n".join(rules) + "\n")
        self.wires("direct")
        time.sleep(0.1)
        self.direct_counts = self.counters()
        assert all(value > 0 for value in self.direct_counts.values()), self.direct_counts
        self.marker("DIRECT_CONTROLS")
        self.marker("HTTPS_AUTHENTICATED_DIRECT_CONTROLS")

    def tls_unchanged(self):
        assert self.tls_identity is not None, "no original TLS fixture identity"
        assert self.tls_bundle.is_dir() and not self.tls_bundle.is_symlink()
        assert {path.name for path in self.tls_bundle.iterdir()} == set(TLS_FILES), "TLS fixture set changed"
        assert {name: self.read_health_role_file(self.tls_bundle / name) for name in TLS_FILES} == self.tls_identity, \
            "TLS fixture files were replaced or modified"

    def event_position(self):
        path = ROOT / "events.jsonl"
        return path.stat().st_size if path.exists() else 0

    def https_peer_evidence(self, position, modes=None):
        """Independent actual peer source; injected reply text is not path traffic."""
        modes = modes or {target: "normal" for target in self.targets}
        path = ROOT / "events.jsonl"
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            current = os.fstat(descriptor)
            assert stat.S_ISREG(current.st_mode) and current.st_size >= position, "peer event log replaced or truncated"
            os.lseek(descriptor, position, os.SEEK_SET)
            data = os.read(descriptor, 262145)
        finally:
            os.close(descriptor)
        assert len(data) <= 262144 and data.endswith(b"\n"), "incomplete or oversized peer evidence"
        rows = [json.loads(line) for line in data.splitlines()]
        witnessed, nonces = set(), set()
        for row in rows:
            if row.get("protocol") != "https":
                continue
            target = row.get("destination")
            assert target in self.targets and row.get("peer") == target, "HTTPS traffic used an unexpected actual source"
            if row.get("mode") != modes.get(target):
                continue
            if row["mode"] in ("wrong-name", "wrong-trust", "expired", "client-auth-only"):
                assert row.get("result") == "tls-handshake-failed" and "nonce" not in row, row
            else:
                assert row.get("result") == "replied" and re.fullmatch("[0-9a-f]{32}", row.get("nonce", "")), row
                assert row["nonce"] not in nonces, "HTTPS request nonce was reused"
                nonces.add(row["nonce"])
            witnessed.add(target)
        assert witnessed == set(modes), "missing per-target authenticated HTTPS peer observations"
        assert self.counters() == self.direct_counts, "HTTPS path silently escaped through Direct"

    def require_https_evidence(self, evidence, *, expected=None, healthy=None):
        assert isinstance(evidence, dict) and set(evidence) == HTTPS_EVIDENCE_KEYS, evidence
        assert type(evidence["probe_count"]) is int and evidence["probe_count"] == (17 if self.args.ipv6 else 9), evidence
        assert type(evidence["elapsed_ms"]) is int and 0 <= evidence["elapsed_ms"] <= 4500, evidence
        assert all(type(evidence[key]) is bool for key in ("vpn_healthy", "ipv4_https", "ipv6_https"))
        assert self.args.ipv6 or evidence["ipv6_https"] is False
        results = evidence["https_results"]
        assert isinstance(results, list) and len(results) == 4
        for index, result in enumerate(results):
            assert isinstance(result, dict) and set(result) == {"result", "status_code"}
            assert isinstance(result["result"], str) and type(result["status_code"]) is int
            if result["result"] in ("pass", "invalid_response", "path_mismatch"):
                assert result["status_code"] == 200, result
            elif result["result"] == "http_status":
                assert 100 <= result["status_code"] <= 599 and result["status_code"] != 200, result
            elif result["result"] in ("http_invalid_response", "http_oversized_response", "http_truncated_response", "canceled", "timeout"):
                assert result["status_code"] in (0, 200), result
            else:
                assert result["result"] in ("not_run", "transport_failed", "deadline_unavailable",
                    "nonce_unavailable", "tls_identity_failed", "tls_handshake_failed") and result["status_code"] == 0, result
            if index >= len(self.targets):
                assert result == {"result": "not_run", "status_code": 0}, result
        if expected is not None:
            for index, (result, code) in expected.items():
                assert results[index] == {"result": result, "status_code": code}, evidence
        if healthy is not None:
            assert evidence["vpn_healthy"] is healthy
            if healthy:
                assert evidence["ipv4_https"] and (not self.args.ipv6 or evidence["ipv6_https"]), evidence
        return evidence

    def ordinary_selected_evidence(self, evidence):
        assert evidence["underlay_healthy"], evidence
        for family in (4, 6) if self.args.ipv6 else (4,):
            assert all(evidence[f"ipv{family}_{protocol}"] for protocol in ("tcp", "udp", "dns")), evidence

    def https_fault_round(self, modes, expected, *, healthy, before_reconnect=False):
        previous = self.health()["rounds"]
        position = self.event_position()
        self.controls({"https@" + target: mode for target, mode in modes.items()})

        def measured():
            value = self.health()
            if value["rounds"] <= previous:
                return None
            results = value["evidence"]["https_results"]
            if all(results[index] == {"result": result, "status_code": code}
                   for index, (result, code) in expected.items()):
                return value
            return None

        value = self.wait(measured, 14, "installed cause-discriminating HTTPS round")
        self.require_https_evidence(value["evidence"], expected=expected, healthy=healthy)
        self.ordinary_selected_evidence(value["evidence"])
        if before_reconnect:
            assert value["state"] == "degraded" and value["failures"] == 1 and value["attempts"] == 0, value
        self.wires("vpn", ("tcp", "udp", "dns"))
        if before_reconnect:
            current = self.journal()
            assert current is not None and current["phase"] == "trial_pending" and current["supervised"]["attempts"] == 0, \
                "independent ordinary controls crossed an actual reconnect boundary"
        else:
            self.command(self.ssh_arguments() + ["true"], timeout=3)
        self.https_peer_evidence(position, {target: modes.get(target, "normal") for target in self.targets})
        print("SUPERVISED_TUN_HTTPS_DIAGNOSTIC=" + json.dumps({"operation_id": self.op,
              "modes": modes, "results": value["evidence"]["https_results"]}, separators=(",", ":")), flush=True)
        return value

    def https_diagnostics(self):
        # Four pairs reuse the initial real operation and its 5-second cadence.
        # A raised failure threshold permits observation; it grants no success.
        cases = (("wrong-name", "wrong-trust", "tls_identity_failed", 0, "tls_identity_failed", 0),
                 ("status503", "redirect", "http_status", 503, "http_status", 302),
                 ("malformed", "truncated", "http_invalid_response", 0, "http_truncated_response", 200),
                 ("oversized", "bad-nonce", "http_oversized_response", 200, "invalid_response", 200))
        for first, second, result0, status0, result1, status1 in cases:
            value = self.https_fault_round({PUBLIC4[0]: first, PUBLIC4[1]: second},
                {0: (result0, status0), 1: (result1, status1)}, healthy=False)
            assert value["state"] == "degraded" and value["attempts"] == 0, value
            assert not value["evidence"]["ipv4_https"]
        self.marker("HTTPS_TLS_HTTP_FAILURE_CLASSES")
        value = self.https_fault_round({PUBLIC4[0]: "wrong-name"},
            {0: ("tls_identity_failed", 0), 1: ("pass", 200)}, healthy=True)
        assert value["state"] == "healthy" and value["attempts"] == 0
        assert value["evidence"]["failed_targets"] == 1 and value["evidence"]["reason"] == "healthy_partial_targets"
        self.marker("HTTPS_ONE_DESTINATION_PARTIAL_TOLERANCE")

        # The peer really receives VPN traffic, but intentionally lies in its
        # reply. This tests critical response validation, not an observed leak.
        self.wires("vpn", ("tcp", "udp", "dns"))
        position = self.event_position()
        self.controls({"https@" + PUBLIC4[0]: "direct"})
        self.wait(lambda: not JOURNAL.exists(), 18, "wrong-source HTTPS critical owned Off")
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 5, "wrong-source health completion")
        self.https_peer_evidence(position, {PUBLIC4[0]: "direct", PUBLIC4[1]: "normal"})
        self.controls()
        self.inactive()
        receipt = self.final_receipt("vpn_path_mismatch", 0)
        self.require_https_evidence(receipt["health_evidence"], expected={0: ("path_mismatch", 200)}, healthy=False)
        self.ordinary_selected_evidence(receipt["health_evidence"])
        print("SUPERVISED_TUN_HTTPS_WRONG_SOURCE_INJECTION=reply text only; actual peer source remained selected", flush=True)
        self.marker("HTTPS_WRONG_SOURCE_CRITICAL_OFF")

    def https_exhaustion(self):
        print("SUPERVISED_TUN_CASE=https-only-reconnect-exhaustion", flush=True)
        self.apply(30, saved=True, health_failures=3, health_attempts=1)
        self.confirmed()
        self.command(self.ssh_arguments() + ["true"], timeout=3)
        value = self.https_fault_round({target: "status503" for target in self.targets},
            {index: ("http_status", 503) for index in range(len(self.targets))}, healthy=False, before_reconnect=True)
        self.wait(lambda: self.health()["attempts"] == 1, 18, "HTTPS-only bounded reconnect")
        assert value["evidence"]["reason"] == "vpn_ipv4_https_failed", value
        self.independent_off(25, restore_controls=True)
        receipt = self.final_receipt("reconnect_exhausted", 1)
        self.require_https_evidence(receipt["health_evidence"],
            expected={index: ("http_status", 503) for index in range(len(self.targets))}, healthy=False)
        self.ordinary_selected_evidence(receipt["health_evidence"])
        assert not receipt["health_evidence"]["ipv4_https"]
        self.marker("HTTPS_ONLY_RECONNECT_EXHAUSTION_AND_SAVED_STATE")

    def counters(self):
        raw = self.command(["ip", "netns", "exec", PEER, "nft", "-j", "-a", "list", "table", "inet", "scqahealth"]).stdout
        rules = [item["rule"] for item in json.loads(raw)["nftables"] if "rule" in item]
        result = {}
        for rule in rules:
            label = rule.get("comment")
            if label and label.startswith("health-"):
                counter = [entry["counter"] for entry in rule["expr"] if "counter" in entry]
                assert len(counter) == 1 and type(counter[0]["packets"]) is int
                result[(label, rule["handle"])] = counter[0]["packets"]
        assert len(result) == len(self.targets) * len(PROTOCOLS), result
        return result

    def wire(self, protocol, target, mode):
        argv = ["/usr/bin/python3", "-I", "-B", "/root/qa-smart-health-client.py",
                protocol, target, mode, "--timeout", "0.8"]
        if protocol == "https":
            argv += ["--tls-bundle", str(self.tls_bundle)]
        output = self.command(argv, timeout=2).stdout
        if protocol == "https" and mode != "blocked":
            result = json.loads(output)
            assert result["tls_authenticated"] is True and result["server_name"] == "scqa-health.example.test"
        return output

    def wires(self, mode, protocols=PROTOCOLS):
        # Concurrent fixed-size rounds keep negative protocol cases bounded.
        from concurrent.futures import ThreadPoolExecutor
        self.tls_unchanged()
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(self.wire, protocol, target, mode)
                       for target in self.targets for protocol in protocols]
            for future in futures:
                future.result()
        self.wire("tcp", "10.254.72.2", "direct")

    def apply(self, deadline=30, *, saved=False, **options):
        assert not JOURNAL.exists()
        saved_before = self.saved() if saved else None
        previous_op = self.op
        args = ["smart-tun-trial-apply"]
        if saved:
            args += ["--saved"]
        else:
            args += ["--tunnel-if", "sctunqa0", "--underlay-if", "scqaedge0",
                     "--tunnel-ipv4", "172.31.99.1/30", "--management-peer", "10.254.72.2",
                     "--domestic-cidr", "5.22.0.10/32", "--protected-cidr", "10.254.72.0/30"]
            if self.args.ipv6:
                args += ["--tunnel-ipv6", "fd73:99::1/64", "--domestic-ipv6-cidr", "2001:db8:5::/64",
                         "--ipv6-vpn-cidr", "2001:db8:5::10/128", "--ipv6-direct-cidr", "2001:db8:8::9/128"]
        args += ["--deadline-seconds", str(deadline), "--supervised", "--health-interval", "5",
                 "--health-grace", "0", "--health-failures", "1", "--health-attempts", "2",
                 "--health-recovery-seconds", "30"]
        for key, value in options.items():
            flag = "--" + key.replace("_", "-")
            if flag in args:
                args[args.index(flag) + 1] = str(value)
            else:
                args += [flag, str(value)]
        value = self.cli(*args)
        assert value["phase"] == "trial_pending" and value["revision"] == 1, value
        self.op, self.challenge = value["operation_id"], value["confirmation_challenge"]
        assert re.fullmatch("[0-9a-f]{32}", self.op)
        assert re.fullmatch("[0-9a-f]{32,128}", self.challenge)
        assert not value["management_confirmed"] and value["experiment_only"] and not value["activation_ready"], value
        self.saved_before = self.saved()
        self.applied_record = self.journal()
        if saved:
            assert self.saved_before == saved_before, "saved reapply changed saved input"
            assert previous_op is None or self.op != previous_op, "saved reapply reused an operation"
        self.wires("vpn")
        assert self.counters() == self.direct_counts, "health targets silently escaped through Direct"
        return value

    def confirm(self, **options):
        args = ["smart-tun-trial-confirm", "--operation-id", options.get("operation", self.op),
                "--revision", str(options.get("revision", 1)), "--challenge", options.get("challenge", self.challenge)]
        if options.get("kill"):
            args += ["--qa-kill-at", options["kill"]]
        return self.cli(*args, ssh=options.get("ssh", True), multiplex=options.get("multiplex", False),
                        check=options.get("check", True))

    def confirm_publication_death(self, boundary):
        assert boundary in ("before-confirm-publish", "after-confirm-publish")
        child_argv = [SC, "--json", "smart-tun-trial-confirm", "--operation-id", self.op,
                      "--revision", "1", "--challenge", self.challenge, "--qa-kill-at", boundary]
        request = {"argv": child_argv, "operation_id": self.op, "revision": 1, "boundary": boundary}
        remote = shlex.join(["/usr/bin/python3", "-I", "-B", "-c", CONFIRM_DEATH_WRAPPER])
        result = self.command(self.ssh_arguments() + [remote], check=False, timeout=30,
                              data=json.dumps(request, separators=(",", ":")))
        assert result.returncode == 0, "remote confirmation death witness failed (SSH exit " + str(result.returncode) + ")"
        assert len(result.stdout.encode()) <= 2048, "oversized remote confirmation death receipt"

        def unique_object(pairs):
            value = dict(pairs)
            if len(value) != len(pairs):
                raise ValueError("duplicate receipt field")
            return value

        try:
            receipt = json.loads(result.stdout, object_pairs_hook=unique_object)
        except ValueError:
            raise AssertionError("invalid remote confirmation death receipt JSON") from None
        expected = {"kind": "scqa-confirm-death-v1", "operation_id": self.op, "revision": 1,
                    "boundary": boundary, "child_returncode": -signal.SIGKILL}
        assert (isinstance(receipt, dict) and type(receipt.get("revision")) is int and
                type(receipt.get("child_returncode")) is int and receipt == expected), \
            "remote confirmation death receipt does not match the exact operation and boundary"
        print("SUPERVISED_TUN_CONFIRM_DEATH_RECEIPT=operation:" + self.op +
              " boundary:" + boundary + " signal:9", flush=True)

    def reject_confirmation(self, **options):
        result, value = self.confirm(check=False, **options)
        assert result.returncode != 0 and value and not value["ok"], value
        current = self.state()
        assert current["operation_id"] == self.op and current["revision"] == 1
        assert not current["management_confirmed"], current

    def confirmed(self):
        position = self.event_position()
        value = self.confirm()
        assert value["management_confirmed"] and value["supervision_state"] == "healthy", value
        assert value["experiment_only"] and not value["activation_ready"] and not value["vpn_verified"], value
        self.wait(lambda: self.health()["state"] == "healthy", 8, "confirmed healthy state")
        assert value["health_evidence_version"] == 2, value
        self.require_https_evidence(value["health_evidence"], healthy=True,
            expected={index: ("pass", 200) for index in range(len(self.targets))})
        self.https_peer_evidence(position)
        self.marker("HTTPS_AUTHENTICATED_SELECTED_PATH")

    def inactive(self):
        assert not JOURNAL.exists() and not Path("/var/lib/server-connect/smart-tun-trial.json").exists()
        assert not Path("/sys/class/net/sctunqa0").exists()
        assert self.show(CORE, "ActiveState") == "inactive"
        assert self.show(TIMER, "ActiveState") == "inactive"
        assert self.show(HEALTH, "MainPID") == "0"
        assert self.saved() == self.saved_before, "saved selection or policy changed"
        if self.foreign:
            assert self.foreign_bytes() == self.foreign_snapshot, "product altered the disjoint foreign owner"
            self.remove_foreign()
            self.marker("DISJOINT_FOREIGN_OWNER_PRESERVED")
        assert self.native() == self.baseline, "native baseline was not restored"
        value = self.cli("status")
        assert value["desired"] == "direct" and value["observed"] == "inactive", value
        self.verify_direct_delivery()
        self.marker("OFF_DIRECT_TCP_UDP_DNS")
        self.marker("OFF_DIRECT_AUTHENTICATED_HTTPS")

    def verify_direct_delivery(self):
        self.wires("direct")
        counts = self.counters()
        assert set(counts) == set(self.direct_counts), "Direct witness identity changed after Off"
        assert all(counts[key] > self.direct_counts[key] for key in counts), \
            "fresh Direct delivery did not advance every peer witness after Off"
        self.direct_counts = counts

    def disconnect(self):
        value = self.cli("smart-tun-trial-disconnect", "--operation-id", self.op, "--revision", "1")
        assert value["phase"] == "trial_cleared" and value["recovery_verified"], value
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 5, "health stop")
        self.inactive()

    def independent_off(self, seconds=35, *, restore_controls=False):
        # Deliberately never invoke status/recover while waiting: only the
        # installed independent roles can complete this transition.
        self.wait(lambda: not JOURNAL.exists(), seconds, "independent verified Off")
        off_uptime_ms = int(float(Path("/proc/uptime").read_text().split()[0]) * 1000)
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 22, "bounded health executor termination")
        if restore_controls:
            self.controls()
        self.inactive()
        return off_uptime_ms

    def final_receipt(self, reason, attempts, *, supervisor_snapshot=None, off_uptime_ms=None,
                      evidence_version=2, retained_legacy=None):
        """Select exact operation receipts from authenticated unit streams."""
        supervisor_reasons = {"supervisor_unavailable", "supervisor_lease_expired"}
        if isinstance(reason, str):
            reasons = {reason}
        else:
            assert reason == supervisor_reasons and supervisor_snapshot is not None, \
                "only an observed executor fault permits the explicit supervisor reason set"
            reasons = supervisor_reasons
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")

        def observed():
            self.command(["journalctl", "--sync"], timeout=3)
            output = self.command(["journalctl", "-b", "--no-pager", "-n", "513", "-o", "json",
                                   "-u", RECOVERY, "-u", HEALTH], timeout=3).stdout
            assert len(output.encode()) <= 1024 * 1024, "oversized bounded role evidence"
            streams = {}
            for line in output.splitlines():
                row = json.loads(line)
                unit, invocation, stream, pid = (row.get(name) for name in
                    ("_SYSTEMD_UNIT", "_SYSTEMD_INVOCATION_ID", "_STREAM_ID", "_PID"))
                if unit not in (RECOVERY, HEALTH) or row.get("_BOOT_ID") != boot or row.get("_TRANSPORT") != "stdout":
                    continue
                if not all(isinstance(value, str) and re.fullmatch("[0-9a-f]{32}", value)
                           for value in (invocation, stream)):
                    continue
                if not isinstance(pid, str) or not pid.isdigit() or int(pid) <= 1:
                    continue
                message = row.get("MESSAGE")
                if not isinstance(message, str) or len(message.encode()) > 16384:
                    continue
                timestamp = row.get("__MONOTONIC_TIMESTAMP")
                if not isinstance(timestamp, str) or not timestamp.isdigit():
                    continue
                streams.setdefault((unit, invocation, stream, pid), []).append((int(timestamp), message))
            matches = []
            for identity, rows in streams.items():
                # One immutable invocation/stream/PID owns the complete JSON
                # value; unrelated logs and relative cross-unit order cannot
                # create a successful final receipt for this exact operation.
                try:
                    value = json.loads("\n".join(message for _stamp, message in sorted(rows, key=lambda row: row[0])))
                except ValueError:
                    continue
                if not isinstance(value, dict):
                    continue
                if "ok" in value:
                    if value["ok"] is not True:
                        continue
                    value = value.get("data")
                if not isinstance(value, dict) or value.get("operation_id") != self.op or value.get("phase") != "trial_cleared":
                    continue
                assert value.get("recovery_verified") and value.get("experiment_only") and not value.get("activation_ready"), value
                actual_reason = value.get("health_reason")
                assert actual_reason in reasons and value.get("reconnect_attempts", 0) == attempts, value
                assert value.get("management_confirmed") and value.get("health_round", 0) > 0, value
                evidence = value["health_evidence"]
                assert type(value.get("health_evidence_version")) is int and value["health_evidence_version"] == evidence_version
                if evidence_version == 1:
                    assert retained_legacy is not None and set(evidence) == HTTPS_EVIDENCE_KEYS
                    assert exact_json({key: evidence[key] for key in LEGACY_EVIDENCE_KEYS}) == exact_json(retained_legacy["evidence"])
                    assert evidence["probe_count"] == (13 if self.args.ipv6 else 7)
                    assert evidence["ipv4_https"] is False and evidence["ipv6_https"] is False
                    assert exact_json(evidence["https_results"]) == exact_json([{"result": "not_run", "status_code": 0} for _ in range(4)])
                    assert type(value["health_round"]) is int and value["health_round"] == retained_legacy["rounds"]
                    assert type(value.get("health_last_uptime_ms")) is int and value["health_last_uptime_ms"] == retained_legacy["last_probe_uptime_ms"]
                else:
                    assert evidence_version == 2
                    self.require_https_evidence(evidence)
                assert 0 <= evidence["elapsed_ms"] <= 4500, evidence
                if actual_reason in supervisor_reasons:
                    assert attempts == 0 and all(type(value.get(key, 0)) is int and value.get(key, 0) == 0
                        for key in ("reconnect_attempts", "health_failures", "recovery_deadline_uptime_ms")), \
                        "supervisor Off was preceded by a path failure or recovery attempt"
                    if supervisor_snapshot is not None:
                        assert (value["health_round"] == supervisor_snapshot["rounds"] and
                                value.get("health_last_uptime_ms") == supervisor_snapshot["last_probe_uptime_ms"] and
                                evidence == supervisor_snapshot["evidence"]), \
                            "supervisor Off substituted a later health round for the observed fault"
                        if actual_reason == "supervisor_lease_expired":
                            deadline = supervisor_snapshot["lease_deadline_uptime_ms"]
                            assert (type(deadline) is int and deadline > 0 and type(off_uptime_ms) is int and
                                    off_uptime_ms >= deadline), \
                                "lease-expiry Off predates the captured boot-time lease deadline"
                matches.append((identity, actual_reason, value))
            assert len(matches) <= 1, "ambiguous final operation provenance"
            if matches:
                identity, actual_reason, value = matches[0]
                unit, invocation, _stream, _pid = identity
                timing = ""
                if supervisor_snapshot is not None:
                    timing = (f" round:{supervisor_snapshot['rounds']} last_probe_ms:{supervisor_snapshot['last_probe_uptime_ms']}"
                              f" lease_deadline_ms:{supervisor_snapshot['lease_deadline_uptime_ms']} off_observed_ms:{off_uptime_ms}")
                print(f"SUPERVISED_TUN_FINAL_RECEIPT=operation:{self.op} unit:{unit} invocation:{invocation} reason:{actual_reason} attempts:{attempts}" + timing, flush=True)
                return value
            return False

        return self.wait(observed, 5, "attributable final supervision receipt")

    def foreign_bytes(self):
        return self.command(["nft", "-j", "-a", "list", "table", "inet", "scqasupforeign"]).stdout

    def foreign_exists(self):
        # A failed table read does not establish absence. Require a successful,
        # structurally valid inventory before clearing unreceipted intent.
        value = json.loads(self.command(["nft", "-j", "list", "tables"]).stdout)
        assert isinstance(value, dict) and set(value) == {"nftables"}, "invalid nft table inventory"
        assert isinstance(value["nftables"], list), "invalid nft table inventory"
        tables = set()
        metadata_seen = False
        for row in value["nftables"]:
            assert isinstance(row, dict) and len(row) == 1, "invalid nft inventory entry"
            if "metainfo" in row:
                metadata = row["metainfo"]
                assert not metadata_seen and isinstance(metadata, dict), "invalid nft inventory metadata"
                assert type(metadata.get("json_schema_version")) is int and metadata["json_schema_version"] == 1, \
                    "unsupported nft inventory schema"
                metadata_seen = True
                continue
            assert "table" in row and isinstance(row["table"], dict), "unexpected nft inventory object"
            table = row["table"]
            assert table.get("family") in ("ip", "ip6", "inet", "arp", "bridge", "netdev"), \
                "invalid nft table family"
            assert isinstance(table.get("name"), str) and table["name"], "invalid nft table name"
            identity = (table["family"], table["name"])
            assert identity not in tables, "ambiguous nft table inventory"
            tables.add(identity)
        assert metadata_seen, "missing nft inventory metadata"
        return ("inet", "scqasupforeign") in tables

    def add_foreign(self):
        assert not self.foreign and self.foreign_snapshot is None, "foreign fixture intent remains unresolved"
        assert not self.foreign_exists(), "foreign fixture name already exists"
        # Record creation intent before issuing the native mutation, and keep
        # exact returned table bytes before any operation can remove it.
        self.foreign = True
        self.command(["nft", "-f", "-"], data=(
            "add table inet scqasupforeign\n"
            "add chain inet scqasupforeign unrelated\n"))
        self.foreign_snapshot = self.foreign_bytes()

    def remove_foreign(self):
        assert self.foreign, "no foreign fixture creation intent"
        if self.foreign_snapshot is None:
            assert not self.foreign_exists(), \
                "unreceipted foreign fixture table retained; cleanup cannot establish ownership"
            self.foreign = False
            return
        assert self.foreign_bytes() == self.foreign_snapshot, "foreign fixture receipt changed; table retained"
        self.command(["nft", "delete", "table", "inet", "scqasupforeign"])
        self.foreign = False
        self.foreign_snapshot = None

    def reject_installer_mutation(self):
        before = {str(path): path.read_bytes() for path in UNITS.glob("server-connect*.service")}
        before.update({str(path): path.read_bytes() for path in UNITS.glob("server-connect*.timer")})
        release = os.readlink("/opt/server-connect/current")
        for flags in (("--offline",), ("--uninstall",)):
            result = self.command(["/bin/sh", "/root/server-connect/install.sh", *flags], check=False)
            assert result.returncode, "installer accepted an active supervised operation"
            assert os.readlink("/opt/server-connect/current") == release
            assert all(Path(path).read_bytes() == data for path, data in before.items())
            assert self.health()["confirmed"] and self.state()["operation_id"] == self.op
        self.marker("ACTIVE_UPDATE_UNINSTALL_REFUSED")

    def pause_upstream(self):
        self.upstream_stopped = True
        signal.pidfd_send_signal(self.upstream_fd, signal.SIGSTOP)

    def resume_upstream(self):
        if self.upstream_stopped:
            signal.pidfd_send_signal(self.upstream_fd, signal.SIGCONT)
            self.upstream_stopped = False

    def marker(self, name):
        print("SUPERVISED_TUN_" + name + "=PASS", flush=True)

    def confirmations_and_health(self):
        if not self.args.ipv6:
            # An authenticated old transport must stay stale even if a new
            # channel/process is created after the challenge.
            master = self.ssh_arguments(True)
            master = ["ControlMaster=yes" if value == "ControlMaster=no" else value for value in master]
            master[-1:-1] = ["-f", "-N"]
            self.command(master)
            self.master = True
            self.apply(60, health_failures=10)
            self.reject_confirmation(operation="0" * 32)
            self.reject_confirmation(revision=2)
            self.reject_confirmation(challenge="0" * len(self.challenge))
            self.reject_confirmation(ssh=False)
            self.reject_confirmation(multiplex=True)
            # SSH_CONNECTION is attacker-controlled environment; no ancestor
            # transport can be manufactured by supplying its conventional text.
            result = self.command(["env", "SSH_CONNECTION=10.254.72.2 12345 10.254.72.1 19223", SC,
                                   "--json", "smart-tun-trial-confirm", "--operation-id", self.op,
                                   "--revision", "1", "--challenge", self.challenge], check=False)
            assert result.returncode and not json.loads(result.stdout)["ok"]
            self.confirmed()
            replay, reply = self.confirm(check=False)
            assert replay.returncode and reply and not reply["ok"], reply
            self.marker("FRESH_SSH_SINGLE_USE_AND_NEGATIVES")
            self.reject_installer_mutation()
            self.add_foreign()
            self.https_diagnostics()

        # Separate short-deadline operation proves confirmed continuation,
        # and keeps the large negative-confirmation budget out of this case.
        # The preceding IPv4 operation saved this policy. The IPv6 lane
        # starts before the pending dual-stack fixture, so it stays explicit.
        self.apply(12, saved=not self.args.ipv6)
        if not self.args.ipv6:
            self.marker("SAVED_REAPPLY")
        self.confirmed()
        deadline = self.health()["confirmation_deadline_uptime_ms"] if "confirmation_deadline_uptime_ms" in self.health() else self.state()["confirmation_deadline_uptime_ms"]
        while float(Path("/proc/uptime").read_text().split()[0]) * 1000 <= deadline + 1000:
            time.sleep(0.2)
        assert self.health()["confirmed"] and self.health()["state"] == "healthy"
        self.wires("vpn")
        assert self.counters() == self.direct_counts
        self.marker("CONFIRMED_BEYOND_ACTIVATION_DEADLINE")
        if self.args.ipv6:
            self.disconnect()
            self.marker("DUALSTACK_SELECTED_TCP_UDP_DNS")
            self.marker("DUALSTACK_AUTHENTICATED_HTTPS")
            return

        previous = self.health()["rounds"]
        self.controls({protocol + "@8.8.8.8": "drop" for protocol in PROTOCOLS})
        self.wait(lambda: self.health()["rounds"] > previous and
                  self.health()["evidence"]["failed_targets"] == 1, 15, "one-target measurement")
        assert self.health()["state"] == "healthy" and self.health()["attempts"] == 0
        assert self.health()["evidence"]["reason"] == "healthy_partial_targets"
        assert self.health()["evidence"]["failed_targets"] == 1
        self.controls()
        self.marker("ONE_TARGET_FALSE_ALARM_REJECTED")

        # DNS-only loss must count as a real selected-path incident although
        # genuine TCP and UDP selected paths continue to work.
        self.controls({"dns@" + address: "drop" for address in PUBLIC4})
        self.wait(lambda: self.health()["attempts"] >= 1, 18, "DNS-only reconnect")
        evidence = self.health()["evidence"]
        assert evidence["underlay_healthy"] and evidence["ipv4_tcp"] and evidence["ipv4_udp"]
        assert not evidence["ipv4_dns"] and not evidence["vpn_healthy"], evidence
        self.controls()
        self.wait(lambda: self.health()["state"] == "healthy", 15, "transient DNS recovery")
        assert self.health()["attempts"] == 1
        self.marker("DNS_FAILURE_AND_TRANSIENT_RECOVERY")

        # Actual upstream VLESS is stopped, not merely declared unhealthy.
        # The manager core and protected underlay remain independently live.
        self.pause_upstream()
        assert int(self.show(CORE, "MainPID")) > 1
        self.wires("blocked")
        assert self.counters() == self.direct_counts
        self.wait(lambda: self.health()["attempts"] >= 2, 18, "upstream reconnect")
        evidence = self.health()["evidence"]
        assert evidence["underlay_healthy"] and not evidence["vpn_healthy"], evidence
        self.resume_upstream()
        self.wait(lambda: self.health()["state"] == "healthy", 15, "selected-path recovery")
        assert self.health()["attempts"] == 2
        self.marker("LIVE_CORE_UPSTREAM_FAILURE_NO_DIRECT_LEAK")

        self.pause_upstream()
        self.independent_off(25)
        self.final_receipt("reconnect_exhausted", 2)
        self.resume_upstream()
        # Budget is operation-wide: returning healthy did not refill it.
        assert self.command(["systemctl", "is-active", "--quiet", TIMER], check=False).returncode
        time.sleep(1)
        self.inactive()
        self.marker("FINITE_EXHAUSTION_FLAPPING_AND_SAVED_STATE")

    def reset_failed_executor(self, unit, original_identity, kind):
        assert unit in (HEALTH, RECOVERY), "unsupported QA bookkeeping role"

        def idle_state():
            state = self.show(unit, "ActiveState")
            if (state in ("inactive", "failed") and self.show(unit, "MainPID") == "0" and
                    self.show(unit, "ControlPID") == "0" and self.show(unit, "Job") in ("", "0")):
                return state
            return None

        state = self.wait(idle_state, 5, "idle executor " + unit)
        # Healthy inactive units may be collected between observations. They
        # need no reset. Only an authentic idle failed role permits mutation.
        if state == "failed":
            path = UNITS / unit
            assert path.is_file() and not path.is_symlink(), "executor unit is missing or replaced"
            identity = path.stat()
            assert (identity.st_dev, identity.st_ino, path.read_bytes()) == original_identity, \
                "executor unit identity changed"
            assert self.show(unit, "LoadState") == "loaded", "executor unit is not loaded"
            assert self.show(unit, "FragmentPath") == str(path), "executor fragment changed"
            assert self.show(unit, "DropInPaths") == "", "executor has foreign drop-ins"
            assert idle_state() == "failed", "executor state changed before QA reset"
            print("SUPERVISED_TUN_" + kind.upper() + "_QA_BOOKKEEPING=reset exact idle " +
                  unit + " after verified Off and Direct delivery", flush=True)
            self.command(["systemctl", "reset-failed", unit])
        assert self.show(unit, "ActiveState") == "inactive" and self.show(unit, "Result") == "success"

    def wait_for_health_executor(self, requested_signal):
        label = "running authenticated health executor"
        self.health_signal_observation = {"pid": None, "readiness": "not_observed"}
        try:
            # Confirmation can put NextProbe just beyond the next timer tick.
            # Allow that short skipped invocation and one later five-second tick.
            return self.wait(lambda: self.signal_health_executor(requested_signal), 15, label)
        except AssertionError as error:
            if str(error) == "timed out waiting for " + label:
                print("SUPERVISED_TUN_EXECUTOR_AUTH_TIMEOUT=" +
                      json.dumps(self.health_signal_observation, separators=(",", ":")), flush=True)
            raise

    def unit_properties(self, unit, fields):
        argv = ["systemctl", "show", unit]
        for field in fields:
            argv += ["-p", field]
        raw = self.command(argv, timeout=3).stdout
        assert len(raw.encode()) <= 4096, "oversized health executor observation"
        values = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            assert separator and key in fields and key not in values, "invalid health executor observation"
            values[key] = value
        assert set(values) == set(fields), "incomplete health executor observation"
        return values

    def health_executor_observation(self):
        return self.unit_properties(HEALTH, ("MainPID", "InvocationID", "ExecMainPID", "ExecMainCode", "ExecMainStatus",
                                            "ExecMainStartTimestampMonotonic", "ActiveState", "Result"))

    def timer_reconciliation_context(self, expected=None, allow_finalized=False):
        current = self.journal()
        if current is None:
            assert allow_finalized and expected is not None, "timer reconciliation requires its cleanup journal"
            current = expected
        elif expected is not None:
            assert current == expected, "cleanup journal changed before timer reconciliation"
        assert (current["operation_id"] == self.op and current["boot_id"] == self.fixture_boot_id == self.current_boot_id() and
                current["phase"] == "trial_cleanup_pending" and type(current["revision"]) is int and current["revision"] == 4), \
            "timer reconciliation is not bound to the exact cleanup operation and boot"
        assert not Path("/sys/class/net/sctunqa0").exists(), "native TUN still exists"
        assert not Path("/var/lib/server-connect/smart-tun-trial.json").exists(), "trial credential remains"
        assert self.native() == self.baseline and self.saved() == self.saved_before, "native Off or saved state is not restored"
        core = self.unit_properties(CORE, ("ActiveState", "Result", "MainPID", "ControlPID", "ControlGroup", "Job"))
        assert (core["ActiveState"] == "inactive" and core["Result"] == "success" and core["MainPID"] == core["ControlPID"] == "0" and
                core["ControlGroup"] == "" and core["Job"] in ("", "0")), \
            "core is not quiescent during timer reconciliation"
        roles = current["supervised"]["roles"]
        assert isinstance(roles, list) and len(roles) == 2, "invalid supervision role identities"
        observed = {}
        fields = ("Id", "LoadState", "FragmentPath", "DropInPaths", "Transient", "UnitFileState", "ActiveState", "Result", "Job")
        for name, role in zip((HEALTH, TIMER), roles):
            files = self.health_role_files(name)
            assert files == self.health_role_originals[name], "health unit or digest was replaced"
            unit_file, digest_file = files
            digest = hashlib.sha256(unit_file[2]).hexdigest()
            identity = {"unit_dev": unit_file[0], "unit_ino": unit_file[1], "digest_dev": digest_file[0],
                        "digest_ino": digest_file[1], "sha256": digest}
            assert (role == identity and all(type(role[key]) is int for key in ("unit_dev", "unit_ino", "digest_dev", "digest_ino")) and
                    digest_file[2].decode("ascii").strip() == digest), "health role differs from the cleanup journal"
            for override in (Path("/run/systemd/system") / name, Path("/run/systemd/system") / (name + ".d"),
                             Path("/run/systemd/transient") / name):
                assert not override.exists() and not override.is_symlink(), "health role has a runtime override"
            properties = self.unit_properties(name, fields + (("MainPID", "ControlPID", "ControlGroup") if name == HEALTH else ("Unit",)))
            assert (properties["Id"] == name and properties["LoadState"] == "loaded" and
                    properties["FragmentPath"] == str(UNITS / name) and properties["DropInPaths"] == "" and
                    properties["Transient"] == "no"), "health role runtime ownership changed"
            assert self.health_role_files(name) == files, "health role changed during runtime inspection"
            observed[name] = properties
        service, timer = observed[HEALTH], observed[TIMER]
        assert (service["ActiveState"] == "inactive" and service["MainPID"] == service["ControlPID"] == "0" and
                service["ControlGroup"] == "" and service["Job"] in ("", "0") and service["UnitFileState"] == "static" and service["Result"] == "success"), \
            "health executor is not a quiescent successful original role"
        assert timer["Unit"] == HEALTH and timer["UnitFileState"] == "disabled" and timer["Job"] in ("", "0"), \
            "timer is enabled, busy, or targets another unit"
        return current, timer

    def reconcile_failed_health_timer(self, kind, failure):
        assert kind in ("masked", "missing"), "timer reconciliation is outside the unit-fault case"
        assert (isinstance(failure, dict) and failure.get("ok") is False and failure.get("error") ==
                {"code": "guard_unavailable", "message": "health timer disarm not verified"}), \
            "recovery failed for a reason other than the exact timer disarm blocker"
        journal, timer = self.timer_reconciliation_context()
        assert ((timer["ActiveState"] == "failed" and timer["Result"] not in ("", "success")) or
                (timer["ActiveState"] == "inactive" and timer["Result"] == "success")), \
            "timer is active or has an unexplained state"
        self.verify_direct_delivery()
        journal, timer = self.timer_reconciliation_context(journal)
        def quiescent_recovery():
            observed = self.unit_properties(RECOVERY, ("ActiveState", "Result", "MainPID", "ControlPID", "ControlGroup", "Job",
                                                       "ExecMainPID", "ExecMainCode", "ExecMainStatus", "InvocationID"))
            assert all(len(value) <= 128 for value in observed.values()), "oversized recovery bookkeeping observation"
            if (observed["ActiveState"] in ("inactive", "failed") and observed["MainPID"] == observed["ControlPID"] == "0" and
                    observed["ControlGroup"] == "" and observed["Job"] in ("", "0")):
                return observed
            return None

        recovery = self.wait(quiescent_recovery, 5, "quiescent recovery executor before timer bookkeeping")
        evidence = {"operation_id": self.op, "phase": journal["phase"], "revision": journal["revision"],
                    "timer": {key: timer[key] for key in ("ActiveState", "Result", "UnitFileState", "Unit", "Job")},
                    "recovery": recovery, "direct_verified": True}
        print("SUPERVISED_TUN_" + kind.upper() + "_OPERATOR_TIMER_RECONCILIATION=" +
              json.dumps(evidence, separators=(",", ":")), flush=True)
        journal, timer = self.timer_reconciliation_context(journal)
        if timer["ActiveState"] == "inactive":
            assert timer["Result"] == "success", "inactive timer has unexplained failure history"
            return False
        assert timer["ActiveState"] == "failed" and timer["Result"] not in ("", "success"), "timer failure changed"
        self.command(["systemctl", "reset-failed", TIMER])
        _journal, after = self.timer_reconciliation_context(journal, allow_finalized=True)
        assert after["ActiveState"] == "inactive" and after["Result"] == "success", "timer-only reset did not reconcile the exact role"
        return True

    def health_process_generation(self, pid):
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        closing = raw.rfind(b")")
        assert len(raw) <= 4096 and raw.startswith(f"{pid} (".encode()) and closing > 0, \
            "invalid health process generation"
        fields = raw[closing + 1:].split()
        assert len(fields) >= 20 and len(fields[0]) == 1 and fields[19].isdigit(), \
            "invalid health process stat fields"
        generation = int(fields[19])
        assert generation > 0, "missing health process generation"
        return generation, fields[0].decode("ascii")

    def signal_operation_context(self):
        current = self.journal()
        assert (current is not None and current["operation_id"] == self.op and
                current["phase"] == "trial_pending" and type(current["revision"]) is int and current["revision"] == 1), \
            "executor fault is not bound to the original pending operation"
        health = current["supervised"]
        assert (health["confirmed"] is True and health["state"] == "healthy" and
                type(health["attempts"]) is int and health["attempts"] == 0 and
                type(health["failures"]) is int and health["failures"] == 0 and
                type(health["recovery_deadline_uptime_ms"]) is int and health["recovery_deadline_uptime_ms"] == 0), \
            "executor fault requires a confirmed healthy operation before any failure or reconnect"
        self.health_signal_pending_operation = current
        return health

    def health_fault_context(self):
        series = self.health_fault_series
        if series is None:
            return self.signal_operation_context()
        current = self.journal()
        if current is None:
            series["stop_reason"] = "operation_absent"
            return None
        original = series["operation"]
        mutable = {"phase", "revision", "native", "supervised"}
        assert ({key: value for key, value in current.items() if key not in mutable} ==
                {key: value for key, value in original.items() if key not in mutable}), \
            "sustained executor fault lost the original operation identity"
        if current["phase"] != "trial_pending":
            terminal = {"trial_stop_requested": (2,), "trial_recovered": (2, 3),
                        "trial_cleanup_pending": (4,), "trial_cleared": (5,)}
            assert (type(current["revision"]) is int and
                    current["revision"] in terminal.get(current["phase"], ())), \
                "unexpected operation transition during sustained executor fault"
            series["stop_reason"] = "operation_cleanup"
            return None
        assert current == original, \
            "health publication, lease renewal, or retry occurred during sustained executor fault"
        now = int(float(Path("/proc/uptime").read_text().split()[0]) * 1000)
        if now >= series["lease_deadline_uptime_ms"]:
            series["stop_reason"] = "original_lease_due"
            return None
        if time.monotonic() >= series["monotonic_deadline"]:
            series["stop_reason"] = "absolute_polling_window_elapsed"
            return None
        return current["supervised"]

    def sustain_health_executor_fault(self, requested_signal):
        assert self.health_fault_series is None, "executor fault series already active"
        # One failed oneshot can be replaced by the still-enabled authentic
        # timer. Exercise sustained loss without altering either installed role.
        self.wait_for_health_executor(requested_signal)
        started = time.monotonic()
        original = json.loads(json.dumps(self.health_signal_operation_snapshot))
        health = original["supervised"]
        lease = health["lease_deadline_uptime_ms"]
        now = int(float(Path("/proc/uptime").read_text().split()[0]) * 1000)
        assert (type(lease) is int and lease > 0 and
                type(health["heartbeat_uptime_ms"]) is int and lease - health["heartbeat_uptime_ms"] == 35000), \
            "invalid original supervision lease for sustained fault"
        remaining = max(0, (lease - now) / 1000)
        assert remaining <= 35, "sustained fault would exceed the original health lease"
        first = dict(self.health_signal_identity)
        series = {"operation": original, "lease_deadline_uptime_ms": lease,
                  "monotonic_deadline": time.monotonic() + remaining,
                  "invocations": {first["invocation"]: first}, "stop_reason": None}
        self.health_fault_series = series
        try:
            # Every successor shares this one absolute deadline. A stopped
            # invocation is skipped until systemd retires it; it is not signalled
            # again. Stop before any same-operation cleanup or expired authority
            # can turn a health invocation into a recovery executor.
            while self.health_fault_context() is not None:
                self.signal_health_executor(requested_signal)
                if series["stop_reason"] is not None:
                    break
                time.sleep(0.1)
            evidence = {"operation_id": self.op, "signal": int(requested_signal),
                        "invocations": len(series["invocations"]),
                        "original_lease_deadline_uptime_ms": lease,
                        "observed_fault_window_seconds": round(time.monotonic() - started, 3),
                        "stop_reason": series["stop_reason"]}
            # This is the fault-injection receipt. Only the later attributable
            # final receipt establishes automatic supervision-loss Off and names
            # its actual HEALTH or RECOVERY emitter.
            print("SUPERVISED_TUN_SUSTAINED_EXECUTOR_FAULT=" + json.dumps(evidence, separators=(",", ":")), flush=True)
        finally:
            self.health_fault_series = None

    def signal_health_executor(self, requested_signal):
        assert requested_signal in (signal.SIGKILL, signal.SIGSTOP), "unsupported executor fault"
        health = self.health_fault_context()
        if health is None:
            return False
        due = health["next_probe_uptime_ms"]
        assert type(due) is int and due >= 0, "invalid next health probe time"
        if float(Path("/proc/uptime").read_text().split()[0]) * 1000 < due:
            self.health_signal_observation = {"pid": None, "readiness": "probe_not_due"}
            return False
        initial = self.health_executor_observation()
        pid = int(initial["MainPID"])
        self.health_signal_observation = {"pid": pid, "readiness": "awaiting_image"}
        if pid <= 1:
            self.health_signal_observation["readiness"] = "no_main_pid"
            return False
        invocation = initial["InvocationID"]
        started = initial["ExecMainStartTimestampMonotonic"]
        if (re.fullmatch("[0-9a-f]{32}", invocation) is None or not started.isdigit() or
                int(started) <= 0 or initial["ExecMainPID"] != str(pid)):
            self.health_signal_observation["readiness"] = "invocation_not_ready"
            return False
        series = self.health_fault_series
        if series is not None and invocation in series["invocations"]:
            previous = series["invocations"][invocation]
            assert previous["pid"] == pid and previous["start"] == started, \
                "a faulted health invocation changed process identity"
            self.health_signal_observation["readiness"] = "invocation_already_faulted"
            return False
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            self.health_signal_observation["readiness"] = "process_unavailable"
            return False
        dispatched = False
        try:
            generation, _state = self.health_process_generation(pid)
            expected = os.stat("/opt/server-connect/current/bin/server-connect")
            expected_argv = (b"/opt/server-connect/current/bin/server-connect\0"
                             b"--json\0smart-tun-trial-health\0")

            def authenticated_image():
                actual = os.stat(f"/proc/{pid}/exe")
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    self.health_signal_observation["readiness"] = "executable_mismatch"
                    return False
                argv = Path(f"/proc/{pid}/cmdline").read_bytes()
                after = os.stat(f"/proc/{pid}/exe")
                if argv != expected_argv:
                    self.health_signal_observation["readiness"] = "argv_mismatch"
                    return False
                if (after.st_dev, after.st_ino) != (expected.st_dev, expected.st_ino):
                    self.health_signal_observation["readiness"] = "executable_changed"
                    return False
                if self.health_process_generation(pid)[0] != generation:
                    self.health_signal_observation["readiness"] = "process_generation_changed"
                    return False
                self.health_signal_observation["readiness"] = "authenticated"
                return True

            def same_invocation(observed):
                return (observed["InvocationID"] == invocation and observed["ExecMainPID"] == str(pid) and
                        observed["ExecMainStartTimestampMonotonic"] == started)

            # systemd may publish MainPID while its child is still preparing
            # exec. An unmatched image/argv is not ready, never a signal target.
            # Retain the same pidfd and repeat both process and unit checks
            # immediately before dispatch. Exited/reused PIDs cannot retarget it.
            for _observation in range(2):
                if not authenticated_image():
                    return False
                observed = self.health_executor_observation()
                if observed["MainPID"] != str(pid) or not same_invocation(observed):
                    self.health_signal_observation["readiness"] = "unit_identity_changed"
                    return False
            operation_health = self.health_fault_context()
            if operation_health is None:
                return False
            if operation_health["next_probe_uptime_ms"] != due:
                self.health_signal_observation["readiness"] = "probe_deadline_changed"
                return False
            if series is not None:
                assert len(series["invocations"]) < 8, "sustained executor fault exceeded eight distinct invocations"
            # Capture before dispatch; only a proven outcome may establish the
            # immutable first snapshot used by the complete sustained series.
            operation = json.loads(json.dumps(self.health_signal_pending_operation if series is None else series["operation"]))
            signal.pidfd_send_signal(descriptor, requested_signal)
            dispatched = True
            self.health_signal_observation["readiness"] = "awaiting_signal_outcome"

            def observed_outcome():
                observed = self.health_executor_observation()
                assert same_invocation(observed), "health fault outcome belongs to a different invocation/PID/start"
                if requested_signal == signal.SIGSTOP:
                    assert observed["MainPID"] == str(pid), "stopped health PID disappeared or changed"
                    current_generation, state = self.health_process_generation(pid)
                    assert current_generation == generation, "stopped health process generation changed"
                    if state not in ("T", "t"):
                        return False
                    assert authenticated_image(), "stopped health image or argv changed"
                    again = self.health_executor_observation()
                    assert same_invocation(again) and again["MainPID"] == str(pid), \
                        "stopped health invocation changed during observation"
                    return state
                code, status = observed["ExecMainCode"], observed["ExecMainStatus"]
                if code == "0":
                    return False
                assert code == str(os.CLD_KILLED) and status == str(signal.SIGKILL), \
                    "health executor did not die from the requested SIGKILL"
                return "killed" if observed["MainPID"] == "0" else False

            outcome = self.wait(observed_outcome, 3, "exact health executor signal outcome")
            identity = {"pid": pid, "generation": generation, "invocation": invocation, "start": started}
            if series is None:
                self.health_signal_operation_snapshot = operation
                self.health_signal_snapshot = json.loads(json.dumps(operation["supervised"]))
            else:
                series["invocations"][invocation] = identity
            self.health_signal_identity = identity
            self.health_signal_observation["readiness"] = "outcome_verified"
            print(f"SUPERVISED_TUN_EXECUTOR_FAULT_RECEIPT=pid:{pid} generation:{generation} invocation:{invocation} start:{started} signal:{int(requested_signal)} outcome:{outcome}", flush=True)
            return True
        except (ProcessLookupError, FileNotFoundError):
            self.health_signal_observation["readiness"] = "process_unavailable"
            if dispatched:
                raise AssertionError("health executor disappeared after dispatch without an exact outcome") from None
            return False
        finally:
            os.close(descriptor)

    def executor_failure(self, kind):
        print("SUPERVISED_TUN_CASE=supervisor-" + kind, flush=True)
        self.apply(30)
        self.confirmed()
        if kind == "dead":
            self.command(["systemctl", "stop", TIMER])
        elif kind in ("failed", "hung"):
            self.pause_upstream()
            requested_signal = signal.SIGKILL if kind == "failed" else signal.SIGSTOP
            self.sustain_health_executor_fault(requested_signal)
        else:
            path = UNITS / HEALTH
            original = UNITS / (HEALTH + ".scqa-supervised-original")
            assert path.is_file() and not path.is_symlink() and not original.exists()
            identity = path.stat()
            self.saved_units[HEALTH] = (original, path.read_bytes(), identity.st_dev, identity.st_ino)
            self.command(["systemctl", "stop", HEALTH])
            path.rename(original)
            if kind == "masked":
                path.symlink_to("/dev/null")
            self.command(["systemctl", "daemon-reload"])
            assert self.show(HEALTH, "LoadState") == ("masked" if kind == "masked" else "not-found")
        if kind in ("dead", "failed", "hung"):
            off_uptime_ms = self.independent_off(30)
            if kind == "dead":
                self.final_receipt("supervisor_unavailable", 0)
            else:
                self.final_receipt({"supervisor_unavailable", "supervisor_lease_expired"}, 0,
                                   supervisor_snapshot=self.health_signal_snapshot, off_uptime_ms=off_uptime_ms)
        else:
            def terminal_or_uncertain():
                journal = self.journal()
                return (journal is None or journal["supervised"]["state"] == "uncertain" or
                        journal["phase"] == "trial_cleanup_pending")
            self.wait(terminal_or_uncertain, 15, kind + " executor containment")
            if JOURNAL.exists():
                assert self.show(CORE, "ActiveState") in ("inactive", "failed")
                if not Path("/sys/class/net/sctunqa0").exists() and self.native() == self.baseline:
                    self.wires("direct")
                    time.sleep(0.1)
                    counts = self.counters()
                    assert set(counts) == set(self.direct_counts)
                    assert all(counts[key] > self.direct_counts[key] for key in counts)
                    self.direct_counts = counts
                    print("SUPERVISED_TUN_" + kind.upper() + "_AUTOMATIC=NATIVE_OFF_FINALIZATION_UNCERTAIN", flush=True)
                else:
                    self.wires("blocked")
                    assert self.counters() == self.direct_counts
                    print("SUPERVISED_TUN_" + kind.upper() + "_AUTOMATIC=UNCERTAIN_CONTAINED", flush=True)
                self.restore_units()
                print("SUPERVISED_TUN_" + kind.upper() + "_OPERATOR_REMEDIATION=exact fixture unit restoration and product recovery", flush=True)
                result, receipt = self.cli("activation-trial-recover", check=False)
                if result.returncode:
                    self.reconcile_failed_health_timer(kind, receipt)
                    self.cli("activation-trial-recover")
                else:
                    assert receipt and receipt.get("ok") is True, "recovery returned an inconsistent success receipt"
                self.wait(lambda: not JOURNAL.exists(), 15, "post-remediation finalization")
            self.inactive()
        self.resume_upstream()
        self.restore_units()
        self.reset_failed_executor(HEALTH, self.health_identity, kind)
        # An authentic independent recovery invocation may have failed while
        # the fixture intentionally hid/masked the health unit. Restoring the
        # inode and finalizing Off does not reset that systemd history.
        self.reset_failed_executor(RECOVERY, self.recovery_identity, kind)
        self.marker("SUPERVISOR_" + kind.upper())

    def restore_units(self):
        changed = False
        for name, (original, content, device, inode) in list(self.saved_units.items()):
            path = UNITS / name
            if not original.exists():
                assert path.is_file() and not path.is_symlink()
                identity = path.stat()
                assert path.read_bytes() == content and (identity.st_dev, identity.st_ino) == (device, inode)
                del self.saved_units[name]
                continue
            identity = original.stat()
            assert original.read_bytes() == content and (identity.st_dev, identity.st_ino) == (device, inode)
            if path.is_symlink():
                assert os.readlink(path) == "/dev/null"
                path.unlink()
            else:
                assert not path.exists(), "unexpected owner at the health unit name"
            original.rename(path)
            identity = path.stat()
            assert (identity.st_dev, identity.st_ino) == (device, inode)
            del self.saved_units[name]
            changed = True
        if changed:
            self.command(["systemctl", "daemon-reload"])

    def publication_failures(self):
        print("SUPERVISED_TUN_CASE=publication-boundaries", flush=True)
        for boundary in ("before-confirm-publish", "after-confirm-publish"):
            self.apply(12)
            self.confirm_publication_death(boundary)
            if boundary == "before-confirm-publish":
                assert not self.health()["confirmed"]
                self.independent_off(25)
            else:
                assert self.health()["confirmed"]
                previous = self.health()["rounds"]
                self.wait(lambda: self.health()["rounds"] > previous, 12, "independent post-confirm health")
                assert self.health()["state"] == "healthy"
                self.disconnect()
        self.marker("CONFIRM_PUBLICATION_CONTROLLER_DEATH")
        self.apply(30)
        self.confirmed()
        for boundary in ("before-health-publish", "after-health-publish"):
            killed = False
            for _attempt in range(3):
                due = self.health()["next_probe_uptime_ms"]
                now = float(Path("/proc/uptime").read_text().split()[0]) * 1000
                time.sleep(max(0, (due - now) / 1000) + 0.02)
                result, _value = self.cli("smart-tun-trial-health", "--qa-kill-at", boundary, check=False)
                if result.returncode == -signal.SIGKILL:
                    killed = True
                    break
                assert result.returncode == 0, "health controller failed outside the requested boundary"
            assert killed, "requested health publication boundary was not exercised"
            previous = self.health()["rounds"]
            self.wait(lambda: self.health()["rounds"] > previous, 12, "independent post-controller health")
            assert self.health()["confirmed"] and self.health()["state"] == "healthy"
        self.legacy_recovery(False)
        self.marker("HEALTH_PUBLICATION_CONTROLLER_DEATH")

    @contextlib.contextmanager
    def legacy_operation_lock(self):
        """Pin the existing product lock for this one QA record injection."""
        parent = os.open(JOURNAL.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptor = None
        try:
            directory = os.fstat(parent)
            assert directory.st_uid == 0 and stat.S_IMODE(directory.st_mode) == 0o700
            descriptor = os.open(".lock", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            identity = os.fstat(descriptor)
            assert stat.S_ISREG(identity.st_mode) and identity.st_uid == 0 and identity.st_nlink == 1
            assert stat.S_IMODE(identity.st_mode) == 0o600
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    assert time.monotonic() < deadline, "legacy fixture product lock unavailable"
                    time.sleep(0.02)

            def unchanged():
                named = os.stat(JOURNAL.parent, follow_symlinks=False)
                current = os.stat(".lock", dir_fd=parent, follow_symlinks=False)
                assert (named.st_dev, named.st_ino, named.st_mode, named.st_uid) == \
                    (directory.st_dev, directory.st_ino, directory.st_mode, directory.st_uid), "state directory replaced"
                assert (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_nlink) == \
                    (identity.st_dev, identity.st_ino, identity.st_mode, identity.st_uid, identity.st_nlink), "product lock replaced"
                if self.legacy_pause is not None:
                    assert (identity.st_dev, identity.st_ino) == self.legacy_pause["lock"], "pause belongs to a different lock"

            unchanged()
            yield parent, (identity.st_dev, identity.st_ino)
            unchanged()
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def legacy_private_read(self, path, limit=262144):
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            assert stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= limit
            data = os.read(descriptor, limit + 1)
            after, named = os.fstat(descriptor), os.lstat(path)
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            assert len(data) == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(named, key)
                                                      for key in fields), "private legacy fixture state replaced"
            return data, (before.st_dev, before.st_ino)
        finally:
            os.close(descriptor)

    def legacy_read_journal(self):
        data, identity = self.legacy_private_read(JOURNAL, 131072)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                assert key not in result, "duplicate legacy journal key"
                result[key] = value
            return result

        value = json.loads(data, object_pairs_hook=unique)
        assert isinstance(value, dict) and value.get("operation_id") == self.op
        return value, data, identity

    def legacy_unit_proof(self, state):
        assert state in ("owned", "idle", "rearmed", "finalized")
        properties = ("Id", "LoadState", "FragmentPath", "DropInPaths", "Transient", "UnitFileState",
                      "ActiveState", "SubState", "Job")
        for name in (TIMER, RECOVERY_TIMER, HEALTH, RECOVERY):
            original = self.legacy_roles[name]
            assert self.health_role_files(name) == original, "legacy fixture role file or installer digest changed"
            assert hashlib.sha256(original[0][2]).hexdigest() == original[1][2].decode("ascii").strip()
            for directory in (Path("/run/systemd/system"),):
                assert not (directory / name).exists() and not (directory / name).is_symlink(), "runtime role replacement"
            timer = name.endswith(".timer")
            fields = self.unit_properties(name, properties + (("Unit",) if timer else
                ("MainPID", "ControlPID", "ControlGroup", "Result")))
            assert fields["Id"] == name and fields["LoadState"] == "loaded"
            assert fields["FragmentPath"] == str(UNITS / name) and fields["DropInPaths"] == "" and fields["Transient"] == "no"
            assert fields["UnitFileState"] == (("disabled" if state == "finalized" else "enabled") if timer else "static")
            if timer:
                assert fields["Unit"] == (HEALTH if name == TIMER else RECOVERY)
            if state in ("idle", "finalized"):
                assert fields["ActiveState"] == "inactive" and fields["SubState"] == "dead" and fields["Job"] in ("", "0")
                if not timer:
                    assert fields["MainPID"] == fields["ControlPID"] == "0" and fields["ControlGroup"] == ""
                    assert fields["Result"] == "success"
            elif state == "rearmed" and timer:
                assert fields["ActiveState"] == "active" and fields["SubState"] in ("waiting", "elapsed", "running")
                assert fields["Job"] in ("", "0")
            assert self.health_role_files(name) == original, "legacy role changed during native observation"

    def legacy_projection(self, record):
        assert self.applied_record is not None
        # Compare the complete genuine Apply-owned outer/native value. No
        # receipt, handle, ownership stage or operation identity is synthesized.
        assert exact_json({key: value for key, value in record.items() if key != "supervised"}) == \
            exact_json({key: value for key, value in self.applied_record.items() if key != "supervised"})
        assert record["version"] == 4 and record["intent_type"] == "smart_tun_native_supervised_trial_v1"
        assert record["operation_id"] == self.op and record["phase"] == "trial_pending" and record["revision"] == 1
        current = record["supervised"]
        assert current["version"] == 2 and current["confirmed"] is True and current["state"] == "healthy"
        assert current["attempts"] == current["failures"] == 0 and current["rounds"] > 0
        self.require_https_evidence(current["evidence"], healthy=True,
            expected={index: ("pass", 200) for index in range(len(self.targets))})
        self.ordinary_selected_evidence(current["evidence"])
        assert current["evidence"]["reason"] == "healthy" and current["evidence"]["failed_targets"] == 0
        projected = json.loads(json.dumps(record))
        old = projected["supervised"]
        old["version"] = 1
        for key in ("ipv4_https", "ipv6_https", "https_results"):
            del old["evidence"][key]
        old["evidence"]["probe_count"] = 13 if self.args.ipv6 else 7
        assert set(old["evidence"]) == LEGACY_EVIDENCE_KEYS and projected["native"] == record["native"]
        return projected

    def legacy_write_projection(self, parent, original, raw, identity, projected):
        staging = JOURNAL.name + ".scqa-legacy-" + self.op
        descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        created = os.fstat(descriptor)
        try:
            data = memoryview((json.dumps(projected, sort_keys=True, separators=(",", ":")) + "\n").encode())
            while data:
                written = os.write(descriptor, data)
                assert written > 0
                data = data[written:]
            os.fsync(descriptor)
            again, current_raw, current_identity = self.legacy_read_journal()
            assert (again, current_raw, current_identity) == (original, raw, identity), "legacy journal compare-and-swap failed"
            os.replace(staging, JOURNAL.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            after, _data, _identity = self.legacy_read_journal()
            assert exact_json(after) == exact_json(projected) and set(after["supervised"]["evidence"]) == LEGACY_EVIDENCE_KEYS
        finally:
            os.close(descriptor)
            try:
                current = os.stat(staging, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                assert (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino), "legacy staging file replaced"
                os.unlink(staging, dir_fd=parent)
                os.fsync(parent)

    def pause_and_project_legacy(self):
        assert self.legacy_pause is None
        with self.legacy_operation_lock() as (parent, lock_identity):
            original, raw, identity = self.legacy_read_journal()
            projected = self.legacy_projection(original)
            self.legacy_unit_proof("rearmed")
            path = ROOT / "legacy-pause.json"
            receipt = {"operation_id": self.op, "lock": lock_identity, "original": original, "projected": projected,
                       "roles": {name: {"device": identity[0][0], "inode": identity[0][1],
                                        "sha256": hashlib.sha256(identity[0][2]).hexdigest()}
                                 for name, identity in self.legacy_roles.items()}}
            body = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    output.write(body)
                    output.flush()
                    os.fsync(descriptor)
                directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                os.close(descriptor)
            actual, receipt_identity = self.legacy_private_read(path)
            assert actual == body
            # Durable pause ownership is recorded before the first stop, even
            # if a later stop, projection CAS or timer start fails.
            self.legacy_pause = {"lock": lock_identity, "original": original, "projected": projected,
                                 "stop": None, "receipt": body, "receipt_identity": receipt_identity, "rearmed": False}
            for name in (TIMER, RECOVERY_TIMER, HEALTH, RECOVERY):
                self.command(["systemctl", "stop", name], timeout=2)
            self.legacy_unit_proof("idle")
            assert self.legacy_read_journal() == (original, raw, identity), "journal changed while pausing exact roles"
            self.legacy_write_projection(parent, original, raw, identity, projected)
        status, envelope = self.cli("smart-tun-trial-status", check=False)
        assert status.returncode != 0 and envelope and envelope.get("ok") is False
        assert envelope.get("error", {}).get("code") == "trial_observation_uncertain", envelope
        inspected = envelope["data"]
        assert inspected["operation_id"] == self.op and inspected["health_reason"] == "legacy_reapply_required"
        assert inspected["supervision_state"] == "uncertain" and inspected["experiment_only"]
        assert type(inspected["health_evidence_version"]) is int and inspected["health_evidence_version"] == 1
        assert set(inspected["health_evidence"]) == HTTPS_EVIDENCE_KEYS
        assert exact_json({key: inspected["health_evidence"][key] for key in LEGACY_EVIDENCE_KEYS}) == exact_json(projected["supervised"]["evidence"])
        assert inspected["health_evidence"]["ipv4_https"] is False and inspected["health_evidence"]["ipv6_https"] is False
        assert exact_json(inspected["health_evidence"]["https_results"]) == exact_json([{"result": "not_run", "status_code": 0} for _ in range(4)])
        print("SUPERVISED_TUN_LEGACY_RECORD_INJECTION=exact Version1 schema projection; genuine original native ownership retained", flush=True)
        return json.loads(json.dumps(projected))

    def resume_legacy(self):
        pause = self.legacy_pause
        assert pause is not None
        with self.legacy_operation_lock():
            assert self.legacy_private_read(ROOT / "legacy-pause.json") == (pause["receipt"], pause["receipt_identity"])
            current, _raw, _identity = self.legacy_read_journal()
            assert exact_json(current) in tuple(exact_json(value) for value in (pause["original"], pause["projected"], pause["stop"])), \
                "legacy pause refuses a changed operation or ownership ledger"
            self.legacy_unit_proof("owned")
            # A failed stop may have left a queued job. Finish the exact
            # bounded drain under the lock before any rearm, without resetting
            # a failed role or treating an unacknowledged stop as quiescence.
            for name in (TIMER, RECOVERY_TIMER, HEALTH, RECOVERY):
                self.command(["systemctl", "stop", name], timeout=2)
            self.legacy_unit_proof("idle")
            assert exact_json(self.legacy_read_journal()[0]) == exact_json(current), "legacy journal changed while completing pause"
            # Both starts are bounded and idempotent only for the exact roles.
            # Keep the durable receipt through partial start and final recovery.
            pause["resumed_record"] = current
            for name in (RECOVERY_TIMER, TIMER):
                self.command(["systemctl", "start", name], timeout=2)
            self.legacy_unit_proof("rearmed")
            pause["rearmed"] = True

    def retire_legacy_pause(self, receipt):
        pause = self.legacy_pause
        assert pause is not None and isinstance(receipt, dict)
        assert receipt.get("operation_id") == self.op and receipt.get("phase") == "trial_cleared"
        assert receipt.get("recovery_verified") is True and receipt.get("experiment_only") is True
        # Final JSON can reach journald just before its emitting oneshot exits.
        # Drain outside the product lock; no executor waits on our held lock.
        self.wait(lambda: all(self.show(name, "ActiveState") == "inactive" and self.show(name, "MainPID") == "0"
                              for name in (HEALTH, RECOVERY)), 5, "legacy final executor drain")
        with self.legacy_operation_lock():
            assert not JOURNAL.exists() and not Path("/var/lib/server-connect/smart-tun-trial.json").exists()
            assert not Path("/sys/class/net/sctunqa0").exists() and self.native() == self.baseline
            self.legacy_unit_proof("finalized")
            path = ROOT / "legacy-pause.json"
            assert self.legacy_private_read(path) == (pause["receipt"], pause["receipt_identity"])
            path.unlink()
            directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self.legacy_pause = None

    def legacy_recovery(self, interrupted):
        if interrupted:
            self.apply(30, saved=True)
            self.confirmed()
        projected = self.pause_and_project_legacy()
        retained = projected["supervised"]
        reason = "legacy_reapply_required"
        # A killed old probe may still be closing its peer worker. With both
        # roles paused, allow that existing one-second connection deadline to
        # finish before attributing any later request to the new executor.
        time.sleep(1.1)
        position = self.event_position()
        if interrupted:
            stopped = json.loads(json.dumps(projected))
            stopped.update(phase="trial_stop_requested", revision=2)
            stopped["native"]["stop_reason"] = "off"
            stopped["supervised"].update(state="stopped", reason="operator_off",
                                         generation=retained["generation"] + 1)
            # Record the only authorized expected successor before the child
            # can die after its real durable stop write.
            self.legacy_pause["stop"] = stopped
            result, _receipt = self.cli("smart-tun-trial-disconnect", "--operation-id", self.op, "--revision", "1",
                                        "--qa-kill-at", "after-stop-request", check=False)
            assert result.returncode == -signal.SIGKILL, "legacy stop did not reach the exact durable boundary"
            with self.legacy_operation_lock():
                reread, _raw, _identity = self.legacy_read_journal()
                assert exact_json(reread) == exact_json(stopped) and reread["supervised"]["version"] == 1
                assert set(reread["supervised"]["evidence"]) == LEGACY_EVIDENCE_KEYS
            reason = "operator_off"
        self.resume_legacy()
        self.wait(lambda: not JOURNAL.exists(), 15, "independent Version1 owned recovery")
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 5, "legacy executor completion")
        assert self.event_position() == position, "legacy evidence incorrectly authorized a new probe round"
        receipt = self.final_receipt(reason, 0, evidence_version=1, retained_legacy=retained)
        self.inactive()
        self.retire_legacy_pause(receipt)
        self.marker("LEGACY_V1_INTERRUPTED_DURABLE_STOP" if interrupted else "LEGACY_V1_REAPPLY_REQUIRED_OWNED_OFF")

    def expired_confirmation(self):
        print("SUPERVISED_TUN_CASE=expired-confirmation", flush=True)
        self.apply(8)
        old_op, old_challenge = self.op, self.challenge
        self.independent_off(20)
        rejected, value = self.confirm(operation=old_op, challenge=old_challenge, check=False)
        assert rejected.returncode and value and not value["ok"]
        self.inactive()
        # This proves independent expiry to Off, then rejection of the stale operation.
        self.marker("EXPIRED_OFF_AND_REPLAY_REJECTED")

    def protected_underlay_failure(self):
        print("SUPERVISED_TUN_CASE=protected-underlay-loss", flush=True)
        self.apply(30)
        self.confirmed()
        original_core_pid = self.show(CORE, "MainPID")
        assert int(original_core_pid) > 1 and self.health()["attempts"] == 0
        self.controls({"tcp@10.254.72.2": "drop"})

        def stopped_without_retry():
            value = self.journal()
            if value is None:
                return True
            assert value["supervised"]["attempts"] == 0, "protected-path loss attempted reconnect"
            assert self.show(CORE, "MainPID") in ("0", original_core_pid), "protected-path loss restarted the core"
            return False

        self.wait(stopped_without_retry, 20, "protected underlay critical Off")
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 5, "critical health executor termination")
        self.controls()
        self.inactive()
        self.final_receipt("protected_underlay_failed", 0)
        self.marker("PROTECTED_UNDERLAY_IMMEDIATE_OFF_NO_RETRY")

    def cleanup(self):
        # Cleanup is explicit QA-operator remediation, never acceptance of
        # autonomous product rollback. Do not erase the original test failure.
        self.cleaning = True
        try:
            self.resume_upstream()
            if self.root_created:
                self.controls()
            if self.saved_units:
                self.restore_units()
            cleanup_receipt = None
            if self.legacy_pause is not None and not self.legacy_pause["rearmed"] and JOURNAL.exists():
                self.resume_legacy()
            if JOURNAL.exists():
                print("SUPERVISED_TUN_FAILURE_CLEANUP=explicit QA-operator exact-operation remediation", flush=True)
                value = json.loads(JOURNAL.read_text())
                assert self.op is not None and value["operation_id"] == self.op, \
                    "cleanup refuses to adopt an operation not bound by this fixture's Apply receipt"
                self.command(["systemctl", "stop", HEALTH], check=False, timeout=5)
                if value["phase"] == "trial_pending":
                    cleanup_receipt = self.cli("smart-tun-trial-disconnect", "--operation-id", self.op,
                                               "--revision", str(value["revision"]))
                else:
                    cleanup_receipt = self.cli("activation-trial-recover")
                self.wait(lambda: not JOURNAL.exists(), 15, "explicit failure cleanup")
            if self.legacy_pause is not None:
                if not cleanup_receipt or cleanup_receipt.get("phase") != "trial_cleared":
                    resumed = self.legacy_pause.get("resumed_record")
                    assert resumed is not None, "legacy cleanup has no exact resumed operation"
                    old = resumed["supervised"]
                    reason = "operator_off" if resumed["phase"] == "trial_stop_requested" else \
                        "legacy_reapply_required" if old["version"] == 1 else "supervisor_unavailable"
                    cleanup_receipt = self.final_receipt(reason, 0, evidence_version=old["version"],
                                                        retained_legacy=old if old["version"] == 1 else None)
                self.inactive()
                self.retire_legacy_pause(cleanup_receipt)
            if self.foreign:
                self.remove_foreign()
        finally:
            if self.master:
                argv = self.ssh_arguments(True)
                argv[-1:-1] = ["-O", "exit"]
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self.command(argv, check=False)
            for process in reversed(self.processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(3)
            for stream in self.streams:
                stream.close()
            if self.root_created and self.legacy_pause is None:
                for name in ("hostkey", "clientkey", "authorized_keys"):
                    with contextlib.suppress(FileNotFoundError):
                        (ROOT / name).unlink()
                assert ROOT.is_dir() and not ROOT.is_symlink()
                shutil.rmtree(ROOT)
            elif self.root_created:
                print("SUPERVISED_TUN_LEGACY_PAUSE_RETAINED=unresolved exact-operation pause receipt and diagnostics", flush=True)
            if self.upstream_fd is not None:
                os.close(self.upstream_fd)

    def diagnostics(self):
        """Bounded operation and role evidence, without challenge/credentials."""
        self.cleaning = True
        try:
            value = json.loads(JOURNAL.read_text()) if JOURNAL.exists() else None
            if value:
                safe = {key: value.get(key) for key in ("operation_id", "phase", "revision", "intent_type")}
                safe["supervision"] = {key: value.get("supervised", {}).get(key)
                                       for key in ("state", "reason", "confirmed", "rounds", "attempts", "failures", "evidence")}
                print("SUPERVISED_TUN_FAILURE_OPERATION=" + json.dumps(safe, separators=(",", ":")), flush=True)
            for unit in (HEALTH, TIMER, RECOVERY, CORE):
                result = self.command(["systemctl", "show", unit, "-p", "ActiveState", "-p", "LoadState",
                                       "-p", "Result", "-p", "MainPID", "-p", "ExecMainStatus"], check=False, timeout=3)
                print("SUPERVISED_TUN_FAILURE_ROLE=" + unit + " " + repr(result.stdout[-2000:]), flush=True)
            for name in ("sshd.log", "responder.log"):
                path = ROOT / name
                if path.exists():
                    with path.open("rb") as handle:
                        handle.seek(max(0, path.stat().st_size - 2000))
                        print("SUPERVISED_TUN_FAILURE_FIXTURE=" + name + " " + repr(handle.read().decode("utf-8", "replace")), flush=True)
        except Exception as error:
            print("SUPERVISED_TUN_FAILURE_DIAGNOSTIC_UNAVAILABLE=" + type(error).__name__, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--upstream-pid", required=True, type=int)
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--tls-bundle", type=Path, default=TLS_BUNDLE)
    args = parser.parse_args()
    assert re.fullmatch("[0-9a-f]{16}", args.profile) and args.upstream_pid > 1
    fixture = Fixture(args)
    original_failure = False
    try:
        fixture.start()
        fixture.confirmations_and_health()
        if not args.ipv6:
            fixture.https_exhaustion()
            fixture.expired_confirmation()
            fixture.protected_underlay_failure()
            for kind in ("dead", "failed", "hung", "masked", "missing"):
                fixture.executor_failure(kind)
            fixture.publication_failures()
            fixture.legacy_recovery(True)
        fixture.inactive()
        print("SUPERVISED_TUN_RESOURCE_BOUND_SECONDS=" + str(round(time.monotonic() - fixture.started, 2)), flush=True)
        fixture.marker("COMPLETE_EXPERIMENTAL_ONLY")
    except BaseException:
        original_failure = True
        fixture.diagnostics()
        raise
    finally:
        try:
            fixture.cleanup()
        except BaseException as error:
            print("SUPERVISED_TUN_FAILURE_CLEANUP_UNRESOLVED=" + type(error).__name__ +
                  ": " + str(error)[:2000], flush=True)
            if not original_failure:
                raise


if __name__ == "__main__":
    main()
