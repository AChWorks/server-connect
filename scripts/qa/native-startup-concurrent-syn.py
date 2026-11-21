#!/usr/bin/env python3
"""Authorized disposable-VM-only field regression for the Native startup SYN race.

This makes host-wide network changes. A real VM console/snapshot and a separately
authorized nonproduction target are prerequisites; the acknowledgement below is
not evidence of those prerequisites. Never run this on production.
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import threading
import time
import pathlib

X = "/usr/local/bin/server-connect"
Q = {
    "routes4.json": ["ip", "-j", "-4", "route", "show", "table", "all"],
    "routes6.json": ["ip", "-j", "-6", "route", "show", "table", "all"],
    "rules4.json": ["ip", "-j", "-4", "rule", "show"],
    "rules6.json": ["ip", "-j", "-6", "rule", "show"],
    "nft.json": ["nft", "-j", "list", "ruleset"],
}

def run(*args, timeout=70):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def managed_status():
    p = run(X, "--json", "status", timeout=12)
    value = json.loads(p.stdout)
    if p.returncode or not value["ok"]:
        raise RuntimeError("manager status unavailable")
    return value["data"]

def verify_baseline(directory):
    for name, args in Q.items():
        original = json.loads((directory / name).read_text())
        current = json.loads(subprocess.check_output(args))
        if original != current:
            raise RuntimeError("VM baseline drift: " + name)
    if run("systemctl", "is-active", "ssh").stdout.strip() != "active":
        raise RuntimeError("SSH inactive")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--underlay-if", required=True)
    p.add_argument("--baseline-dir", type=pathlib.Path, required=True)
    p.add_argument("--target-host", default="api.ipify.org")
    p.add_argument("--foreign-exit-ip", required=True)
    p.add_argument("--authorized-disposable-vm-with-console", action="store_true")
    args = p.parse_args()
    if not args.authorized_disposable_vm_with_console or os.geteuid() != 0:
        p.error("requires explicitly authorized disposable VM, verified independent console/snapshot, and root")
    manifest = json.loads(pathlib.Path("/opt/server-connect/current/manifest.json").read_text())
    if manifest.get("redistribution") != "not authorized; local QA only":
        p.error("refuses non-QA published installation")
    if managed_status()["desired"] != "direct":
        p.error("requires Direct before activation")
    verify_baseline(args.baseline_dir)
    target = socket.getaddrinfo(args.target_host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    guard = "sc-qa-concurrent-" + str(os.getpid())
    arm = run("systemd-run", "--quiet", "--collect", "--unit=" + guard,
              "--on-active=175s", X, "--json", "disconnect")
    if arm.returncode or run("systemctl", "is-active", guard + ".timer").stdout.strip() != "active":
        raise RuntimeError("independent watchdog prearm failed")
    print("PASS_INDEPENDENT_VM_FAILBACK_ARMED", flush=True)
    capture = None
    stopped = threading.Event()
    witnessed = {"first_smart": None, "attempts": 0, "errors": {}}
    success = False
    try:
        capture = subprocess.Popen(
            ["tcpdump", "-U", "-l", "-nn", "-tt", "-i", args.underlay_if,
             "tcp and dst host " + target + " and dst port 443"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def emit():
            while not stopped.is_set() and witnessed["attempts"] < 100:
                try:
                    state = json.loads(pathlib.Path("/var/lib/server-connect/state.json").read_text())
                except (OSError, json.JSONDecodeError):
                    time.sleep(.008)
                    continue
                if state.get("desired") == "smart":
                    if witnessed["first_smart"] is None:
                        witnessed["first_smart"] = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    try:
                        result = sock.connect_ex((target, 443))
                    finally:
                        sock.close()
                    witnessed["errors"][result] = witnessed["errors"].get(result, 0) + 1
                    witnessed["attempts"] += 1
                    time.sleep(.02)
                else:
                    time.sleep(.008)
        worker = threading.Thread(target=emit, daemon=True)
        worker.start()
        time.sleep(.2)
        connected = run(X, "--json", "connect-smart", "--underlay-if",
                        args.underlay_if, "--health-failures", "20", timeout=90)
        try:
            reply = json.loads(connected.stdout)
        except json.JSONDecodeError:
            reply = {}
        if connected.returncode or not reply.get("ok") or reply.get("data", {}).get("observed") != "active":
            raise RuntimeError("native connection not ready: " + str(reply.get("error")))
        worker.join(timeout=3)
        if witnessed["first_smart"] is None or witnessed["attempts"] < 20:
            raise RuntimeError("no meaningful concurrent post-Smart client attempts")
        if not pathlib.Path("/sys/class/net/sctun0").exists():
            raise RuntimeError("CLI declared active without TUN device")
        foreign = run("curl", "--noproxy", "*", "-4", "-fsS", "--max-time", "18",
                      "https://" + args.target_host, timeout=22)
        if foreign.returncode or foreign.stdout.strip() != args.foreign_exit_ip:
            raise RuntimeError("selected foreign egress not independently proved")
        success = True
    finally:
        stopped.set()
        if capture:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            try:
                wire, _ = capture.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                capture.kill()
                wire, _ = capture.communicate(timeout=4)
            packets = []
            for line in wire.splitlines():
                if target in line and "Flags [S]" in line and ".443:" in line:
                    try:
                        stamp = float(line.split()[0])
                    except (ValueError, IndexError):
                        continue
                    if witnessed["first_smart"] and stamp >= witnessed["first_smart"]:
                        packets.append(line[:180])
            print("BOUNDARY_WITNESS", json.dumps({
                "attempts_after_requested_smart": witnessed["attempts"],
                "underlay_direct_syn_after_requested_smart": len(packets),
                "sample": packets[:2],
            }), flush=True)
            if packets:
                success = False
        off = run(X, "--json", "disconnect", timeout=65)
        try:
            off_ok = off.returncode == 0 and json.loads(off.stdout)["ok"]
            if off_ok and managed_status()["desired"] == "direct" and managed_status()["observed"] == "inactive":
                verify_baseline(args.baseline_dir)
                run("systemctl", "stop", guard + ".timer", timeout=12)
                print("PASS_EXACT_DIRECT_SSH_INVENTORY_WATCHDOG_CLEANUP", flush=True)
            else:
                success = False
                print("UNCERTAIN_DIRECT_KEEP_WATCHDOG_ARMED", flush=True)
        except Exception as exc:
            success = False
            print("UNCERTAIN_ROLLBACK_KEEP_WATCHDOG", type(exc).__name__, flush=True)
    if not success:
        raise RuntimeError("startup leak, failed egress, or incomplete recovery")
    print("PASS_NO_UNDERLAY_DIRECT_SYN_AFTER_REQUESTED_SMART", flush=True)

if __name__ == "__main__":
    main()
