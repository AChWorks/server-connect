#!/usr/bin/env python3
"""Real-packet Native shutdown boundary regression on an authorized disposable VM.

Host-wide Smart routing is changed by this test. A real independent guest console,
snapshot, separately observed management path and preexisting five-inventory
baseline are prerequisites. NEVER run against a production/customer host.
"""
import argparse
import bisect
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time

MANAGER = "/usr/local/bin/server-connect"
STATE = Path("/var/lib/server-connect")
COMMANDS = {
    "routes4.json": ["ip", "-j", "-4", "route", "show", "table", "all"],
    "routes6.json": ["ip", "-j", "-6", "route", "show", "table", "all"],
    "rules4.json": ["ip", "-j", "-4", "rule", "show"],
    "rules6.json": ["ip", "-j", "-6", "rule", "show"],
    "nft.json": ["nft", "-j", "list", "ruleset"],
}


def execute(*cmd, timeout=75):
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def manager(*args):
    response = execute(MANAGER, "--json", *args)
    try:
        doc = json.loads(response.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("manager JSON unavailable") from None
    if response.returncode or not doc.get("ok"):
        raise RuntimeError("manager command failed: " + json.dumps(doc.get("error", {})))
    return doc["data"]


def assert_original(baseline):
    for name, cmd in COMMANDS.items():
        if json.loads((baseline / name).read_text()) != json.loads(subprocess.check_output(cmd)):
            raise RuntimeError("kernel inventory drift: " + name)
    if execute("systemctl", "is-active", "ssh").stdout.strip() != "active":
        raise RuntimeError("management SSH stopped")
    if Path("/sys/class/net/sctun0").exists():
        raise RuntimeError("TUN remained after shutdown")


def state_sample():
    try:
        d = json.loads((STATE / "state.json").read_text())
        h = json.loads((STATE / "native-health.json").read_text())
        return {"at": time.time(), "desired": d.get("desired"),
                "phase": h.get("phase"), "reason": h.get("reason"),
                "tun": Path("/sys/class/net/sctun0").exists()}
    except (OSError, ValueError):
        return {"at": time.time(), "desired": "unknown", "phase": "unknown",
                "tun": Path("/sys/class/net/sctun0").exists()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--underlay-if", required=True)
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--foreign-exit-ip", required=True)
    parser.add_argument("--target-host", default="api.ipify.org")
    parser.add_argument("--authorized-disposable-vm-with-console", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.authorized_disposable_vm_with_console:
        parser.error("requires root and verified separate VM/console/snapshot authorization")
    if args.evidence_dir.exists():
        parser.error("refuses overwriting any previous evidence")
    source = json.loads(Path("/opt/server-connect/current/manifest.json").read_text())
    if source.get("redistribution") != "not authorized; local QA only":
        parser.error("only installed private QA candidates can be exercised")
    if manager("status")["desired"] != "direct":
        parser.error("must start in actual Direct")
    assert_original(args.baseline_dir)
    destination = socket.getaddrinfo(args.target_host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    os.mkdir(args.evidence_dir, mode=0o700)
    guard = "sc-qa-stop-" + str(os.getpid())
    armed = execute("systemd-run", "--quiet", "--collect", "--unit=" + guard,
                    "--on-active=165s", MANAGER, "--json", "disconnect")
    if armed.returncode or execute("systemctl", "is-active", guard + ".timer").stdout.strip() != "active":
        raise RuntimeError("independent failback timer was not armed")
    capture = None
    records = []
    snapshots = []
    stop = threading.Event()
    connected = False
    off_verified = False
    try:
        capture = subprocess.Popen(
            ["tcpdump", "-p", "-U", "-nn", "-tt", "-l", "-i", args.underlay_if,
             "tcp and dst host " + destination + " and dst port 443"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        def capture_worker():
            for line in capture.stdout:
                if "Flags [S]" in line:
                    try:
                        records.append({"at": float(line.split()[0]), "line": line.strip()[:180]})
                    except (ValueError, IndexError):
                        pass
        reader = threading.Thread(target=capture_worker, daemon=True)
        reader.start()
        time.sleep(.35)
        # The independent positive control proves the capture can see a
        # genuine Direct SYN; a zero-packet capture must not produce PASS.
        direct = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        direct.setblocking(False)
        try:
            direct.connect_ex((destination, 443))
        finally:
            direct.close()
        time.sleep(.45)
        if not records:
            raise RuntimeError("no Direct SYN positive control on Underlay")
        positive = len(records)

        def workload():
            while not stop.is_set():
                sample = state_sample()
                snapshots.append(sample)
                if sample["desired"] == "smart":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setblocking(False)
                    try:
                        s.connect_ex((destination, 443))
                    finally:
                        s.close()
                time.sleep(.025)
        worker = threading.Thread(target=workload, daemon=True)
        worker.start()
        started = time.monotonic()
        response = manager("connect-smart", "--underlay-if", args.underlay_if,
                           "--health-failures", "20")
        if response["observed"] != "active" or not Path("/sys/class/net/sctun0").exists():
            raise RuntimeError("native Core did not build a real selected TUN")
        connected = True
        probe = execute("curl", "--noproxy", "*", "-4", "-fsS",
                        "--connect-timeout", "7", "--max-time", "18",
                        "https://" + args.target_host, timeout=23)
        if probe.returncode or probe.stdout.strip() != args.foreign_exit_ip:
            raise RuntimeError("actual selected external egress not verified")
        time.sleep(.45)
        before_stop = time.time()
        off = manager("disconnect")
        after_stop = time.time()
        if manager("status")["desired"] != "direct":
            raise RuntimeError("Direct was not committed")
        if manager("status")["observed"] != "inactive":
            raise RuntimeError("native Core still active")
        off_verified = True
        time.sleep(.2)
        stop.set()
        worker.join(timeout=2)
        assert_original(args.baseline_dir)
        time.sleep(.25)
        if capture.poll() is None:
            capture.send_signal(signal.SIGINT)
        reader.join(timeout=4)
        times = [s["at"] for s in snapshots]
        first_smart = next((x["at"] for x in snapshots if x["desired"] == "smart"), None)
        last_smart = max((x["at"] for x in snapshots if x["desired"] == "smart"), default=None)
        if first_smart is None or last_smart is None or before_stop <= first_smart:
            raise RuntimeError("no effective Smart witness captured")
        smart_attempts = [x for x in snapshots if x["desired"] == "smart"]
        during_stop = [x for x in smart_attempts if before_stop <= x["at"] <= after_stop]
        if len(smart_attempts) < 25 or len(during_stop) < 5:
            raise RuntimeError("insufficient concurrent Smart/stop traffic witness")
        leaks = []
        for p in records[positive:]:
            if not first_smart <= p["at"] <= last_smart:
                continue
            i = bisect.bisect_right(times, p["at"]) - 1
            if i >= 0 and snapshots[i]["desired"] == "smart" and p["at"]-times[i] <= .065:
                leaks.append({**p, **{k: snapshots[i][k] for k in ["phase", "tun", "desired"]}})
        result = {
            "installed_source_sha": source.get("source_revision"), "selected_exit": probe.stdout.strip(),
            "target_ip": destination, "direct_positive_syns": positive,
            "smart_samples": len(smart_attempts), "stop_smart_samples": len(during_stop),
            "stop_seconds": round(after_stop-before_stop, 3),
            "leaked_direct_sns_while_smart": leaks,
            "recovery": off, "pass": not leaks}
        # Preserve the actual filtered tcpdump timestamps for subsequent
        # independent packet/phase inspection, not merely the PASS counter.
        (args.evidence_dir / "underlay-syn.log").write_text(
            "\n".join(x["line"] for x in records) + "\n")
        (args.evidence_dir / "stop-boundary.json").write_text(json.dumps(result, indent=2))
        (args.evidence_dir / "phasewatch.jsonl").write_text(
            "\n".join(json.dumps(x) for x in snapshots) + "\n")
        if leaks:
            raise RuntimeError("selected Direct SYN was observed while Smart remained desired")
        print("PASS_INSTALLED_VM_STOP_BOUNDARY: positive Direct control, real selected VPN, "
              "zero Direct SYN while Smart, exact Direct restoration", flush=True)
        print(json.dumps({k: v for k, v in result.items() if k != "recovery"}), flush=True)
    finally:
        stop.set()
        if capture:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            try:
                capture.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.communicate(timeout=2)
        if connected and not off_verified:
            try:
                manager("disconnect")
                off_verified = manager("status")["desired"] == "direct"
                if off_verified:
                    assert_original(args.baseline_dir)
            except Exception:
                pass
        if off_verified:
            execute("systemctl", "stop", guard + ".timer", timeout=12)
        else:
            print("UNCERTAIN: leaving independent failback timer armed", flush=True)


if __name__ == "__main__":
    main()
