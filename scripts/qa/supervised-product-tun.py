#!/usr/bin/env python3
"""Confirmed supervision acceptance in the existing disconnected guest only.

This never provisions a Docker container, changes a physical host, or treats
synthetic management/VPN proof as general-host production acceptance.
"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time


SC = "/usr/local/bin/server-connect"
PEER = "scqapeer"
JOURNAL = Path("/var/lib/server-connect/route-activation-journal.json")
HEALTH = "server-connect-smart-health.service"
TIMER = "server-connect-smart-health.timer"
RECOVERY = "server-connect-activation-recover.service"
CORE = "server-connect-smart-tun.service"
UNITS = Path("/etc/systemd/system")
ROOT = Path("/run/sc-qa-supervised")
PUBLIC4 = ("8.8.8.8", "198.51.100.42")
PUBLIC6 = ("2001:db8:8::8", "2001:db8:5::10")
PROTOCOLS = ("tcp", "udp", "dns")


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

    def command(self, argv, *, check=True, timeout=20, data=None):
        elapsed = time.monotonic() - self.started
        if elapsed > 360 and not self.cleaning:
            raise AssertionError("supervised fixture exceeded its aggregate 360-second budget")
        result = subprocess.run(argv, input=data, capture_output=True, text=True,
                                timeout=timeout)
        if check and result.returncode:
            # Fixed QA commands and keys are not user credentials. Redact the
            # one-time confirmation argument; diagnostics retain exit/stderr.
            safe = ["<challenge>" if i and argv[i - 1] == "--challenge" else value
                    for i, value in enumerate(argv)]
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

    def start(self):
        assert Path("/.dockerenv").is_file()
        assert Path("/proc/1/comm").read_text().strip() == "systemd"
        assert not JOURNAL.exists() and not ROOT.exists()
        assert self.show(CORE, "ActiveState") == "inactive"
        assert self.show(HEALTH, "ActiveState") == "inactive"
        assert self.show(TIMER, "ActiveState") == "inactive"
        recovery_path = UNITS / RECOVERY
        recovery_stat = recovery_path.stat()
        self.recovery_identity = (recovery_stat.st_dev, recovery_stat.st_ino, recovery_path.read_bytes())
        health_path = UNITS / HEALTH
        health_stat = health_path.stat()
        self.health_identity = (health_stat.st_dev, health_stat.st_ino, health_path.read_bytes())
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
                     "--events", str(ROOT / "events.jsonl"), "--ready", str(ROOT / "ready")]
        if self.args.ipv6:
            responder.append("--ipv6")
        self.background(responder, "responder")
        self.wait(lambda: (ROOT / "ready").is_file(), 3, "health responder")
        self.command(self.ssh_arguments() + ["true"])
        rules = ["table inet scqahealth {", "chain incoming { type filter hook input priority filter; policy accept;"]
        for number, address in enumerate(self.targets):
            family = "ip6" if ":" in address else "ip"
            for protocol in PROTOCOLS:
                transport = "tcp" if protocol == "tcp" else "udp"
                port = {"tcp": 19220, "udp": 19221, "dns": 19222}[protocol]
                rules.append(f'iifname "scqapeer0" {family} daddr {address} {transport} dport {port} counter comment "health-{number}-{protocol}"')
        rules.extend(("}", "}"))
        self.command(["ip", "netns", "exec", PEER, "nft", "-f", "-"], data="\n".join(rules) + "\n")
        self.wires("direct")
        time.sleep(0.1)
        self.direct_counts = self.counters()
        assert all(value > 0 for value in self.direct_counts.values()), self.direct_counts
        self.marker("DIRECT_CONTROLS")

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
        return self.command(["/usr/bin/python3", "-I", "-B", "/root/qa-smart-health-client.py",
                             protocol, target, mode, "--timeout", "0.8"], timeout=2).stdout

    def wires(self, mode):
        # Concurrent fixed-size rounds keep negative protocol cases bounded.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(self.wire, protocol, target, mode)
                       for target in self.targets for protocol in PROTOCOLS]
            for future in futures:
                future.result()
        self.wire("tcp", "10.254.72.2", "direct")

    def apply(self, deadline=30, **options):
        assert not JOURNAL.exists()
        args = ["smart-tun-trial-apply", "--tunnel-if", "sctunqa0", "--underlay-if", "scqaedge0",
                "--tunnel-ipv4", "172.31.99.1/30", "--management-peer", "10.254.72.2",
                "--domestic-cidr", "5.22.0.10/32", "--protected-cidr", "10.254.72.0/30",
                "--deadline-seconds", str(deadline), "--supervised", "--health-interval", "5",
                "--health-grace", "0", "--health-failures", "1", "--health-attempts", "2",
                "--health-recovery-seconds", "30"]
        if self.args.ipv6:
            args += ["--tunnel-ipv6", "fd73:99::1/64", "--domestic-ipv6-cidr", "2001:db8:5::/64",
                     "--ipv6-vpn-cidr", "2001:db8:5::10/128", "--ipv6-direct-cidr", "2001:db8:8::9/128"]
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

    def reject_confirmation(self, **options):
        result, value = self.confirm(check=False, **options)
        assert result.returncode != 0 and value and not value["ok"], value
        current = self.state()
        assert current["operation_id"] == self.op and current["revision"] == 1
        assert not current["management_confirmed"], current

    def confirmed(self):
        value = self.confirm()
        assert value["management_confirmed"] and value["supervision_state"] == "healthy", value
        assert value["experiment_only"] and not value["activation_ready"] and not value["vpn_verified"], value
        self.wait(lambda: self.health()["state"] == "healthy", 8, "confirmed healthy state")

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
        self.wires("direct")
        counts = self.counters()
        assert set(counts) == set(self.direct_counts), "Direct witness identity changed after Off"
        assert all(counts[key] > self.direct_counts[key] for key in counts), \
            "fresh Direct delivery did not advance every peer witness after Off"
        self.direct_counts = counts
        self.marker("OFF_DIRECT_TCP_UDP_DNS")

    def disconnect(self):
        value = self.cli("smart-tun-trial-disconnect", "--operation-id", self.op, "--revision", "1")
        assert value["phase"] == "trial_cleared" and value["recovery_verified"], value
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 5, "health stop")
        self.inactive()

    def independent_off(self, seconds=35):
        # Deliberately never invoke status/recover while waiting: only the
        # installed independent roles can complete this transition.
        self.wait(lambda: not JOURNAL.exists(), seconds, "independent verified Off")
        self.wait(lambda: self.show(HEALTH, "MainPID") == "0", 22, "bounded health executor termination")
        self.inactive()

    def final_receipt(self, reason, attempts):
        """Select exact operation receipts from authenticated unit streams."""
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
                assert value.get("health_reason") == reason and value.get("reconnect_attempts", 0) == attempts, value
                assert value.get("management_confirmed") and value.get("health_round", 0) > 0, value
                evidence = value["health_evidence"]
                assert evidence["probe_count"] == (13 if self.args.ipv6 else 7)
                assert 0 <= evidence["elapsed_ms"] <= 4500, evidence
                matches.append(identity)
            assert len(matches) <= 1, "ambiguous final operation provenance"
            if matches:
                unit, invocation, _stream, _pid = matches[0]
                print(f"SUPERVISED_TUN_FINAL_RECEIPT=operation:{self.op} unit:{unit} invocation:{invocation} reason:{reason} attempts:{attempts}", flush=True)
                return True
            return False

        self.wait(observed, 5, "attributable final supervision receipt")

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
            self.apply(60)
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
            self.disconnect()

        # Separate short-deadline operation proves confirmed continuation,
        # and keeps the large negative-confirmation budget out of this case.
        self.apply(12)
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

    def executor_failure(self, kind):
        print("SUPERVISED_TUN_CASE=supervisor-" + kind, flush=True)
        self.apply(30)
        self.confirmed()
        if kind == "dead":
            self.command(["systemctl", "stop", TIMER])
        elif kind in ("failed", "hung"):
            self.pause_upstream()
            def signal_executor():
                pid = int(self.show(HEALTH, "MainPID"))
                if pid <= 1:
                    return False
                try:
                    descriptor = os.pidfd_open(pid)
                except ProcessLookupError:
                    return False
                try:
                    exe = os.stat(f"/proc/{pid}/exe")
                    expected = os.stat("/opt/server-connect/current/bin/server-connect")
                    assert (exe.st_dev, exe.st_ino) == (expected.st_dev, expected.st_ino)
                    assert b"smart-tun-trial-health\0" in Path(f"/proc/{pid}/cmdline").read_bytes()
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL if kind == "failed" else signal.SIGSTOP)
                    return True
                except (ProcessLookupError, FileNotFoundError):
                    return False
                finally:
                    os.close(descriptor)
            self.wait(signal_executor, 8, "running authenticated health executor")
            if kind == "failed":
                self.wait(lambda: self.show(HEALTH, "ActiveState") == "failed" or not JOURNAL.exists(), 3, "failed executor")
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
            self.independent_off(30)
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
                self.cli("activation-trial-recover")
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
            result, _reply = self.confirm(kill=boundary, check=False)
            assert result.returncode, "controller survived the requested publication boundary"
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
        self.disconnect()
        self.marker("HEALTH_PUBLICATION_CONTROLLER_DEATH")

    def expired_confirmation(self):
        print("SUPERVISED_TUN_CASE=expired-confirmation", flush=True)
        self.apply(8)
        old_op, old_challenge = self.op, self.challenge
        self.independent_off(20)
        rejected, value = self.confirm(operation=old_op, challenge=old_challenge, check=False)
        assert rejected.returncode and value and not value["ok"]
        self.inactive()
        self.marker("EXPIRED_CONFIRMATION")

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
            if JOURNAL.exists():
                print("SUPERVISED_TUN_FAILURE_CLEANUP=explicit QA-operator exact-operation remediation", flush=True)
                value = json.loads(JOURNAL.read_text())
                assert self.op is not None and value["operation_id"] == self.op, \
                    "cleanup refuses to adopt an operation not bound by this fixture's Apply receipt"
                self.command(["systemctl", "stop", HEALTH], check=False, timeout=5)
                if value["phase"] == "trial_pending":
                    self.cli("smart-tun-trial-disconnect", "--operation-id", self.op,
                             "--revision", str(value["revision"]))
                else:
                    self.cli("activation-trial-recover")
                self.wait(lambda: not JOURNAL.exists(), 15, "explicit failure cleanup")
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
            if self.root_created:
                for name in ("hostkey", "clientkey", "authorized_keys"):
                    with contextlib.suppress(FileNotFoundError):
                        (ROOT / name).unlink()
                assert ROOT.is_dir() and not ROOT.is_symlink()
                shutil.rmtree(ROOT)
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
    args = parser.parse_args()
    assert re.fullmatch("[0-9a-f]{16}", args.profile) and args.upstream_pid > 1
    fixture = Fixture(args)
    original_failure = False
    try:
        fixture.start()
        fixture.confirmations_and_health()
        if not args.ipv6:
            fixture.expired_confirmation()
            fixture.protected_underlay_failure()
            for kind in ("dead", "failed", "hung", "masked", "missing"):
                fixture.executor_failure(kind)
            fixture.publication_failures()
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
