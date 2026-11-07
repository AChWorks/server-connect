#!/usr/bin/env python3
"""Rootless execution of the actual embedded field recovery and EXIT finalizer.

Only kernel/service commands are substituted. Bash, flock, file identity tests,
receipt comparison, hashing and sync run normally in a private temporary tree.
The privileged field entrypoint is never executed.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

SOURCE = Path(__file__).with_name("field-root-selected-tun.sh").read_text()
MARKER = "cat > \"$work/recover.sh\" <<'RECOVER'\n"
assert SOURCE.count(MARKER) == 1
RECOVER = SOURCE.partition(MARKER)[2].partition("\nRECOVER\n")[0]
FINALIZER = "finalize() {\n" + SOURCE.partition("finalize() {\n")[2].partition("\ntrap finalize EXIT")[0]
assert RECOVER.startswith("#!/usr/bin/env bash\n") and "ROOT_HOST_NETWORK_RESTORED=PASS" in RECOVER
assert "FIELD_ROOT_OWNED_CLEANUP=PASS" in FINALIZER

OWNER = "scfhr_aabbccddeeff0011"
BOOT = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
BASE_ROUTES = "default via 192.0.2.1 dev qa-underlay\n"
BASE_RULES = "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"
RAW = "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n"
NAT = "-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n"
DIGEST = lambda data: hashlib.sha256(data.encode()).hexdigest()


def graph(*, capture=True, foreign=False, handle=17):
    rows = [{"metainfo": {"json_schema_version": 1}},
            {"table": {"family": "inet", "name": OWNER, "handle": handle}},
            {"chain": {"family": "inet", "table": OWNER, "name": "capture", "handle": 18}},
            {"chain": {"family": "inet", "table": OWNER, "name": "guard", "handle": 19}}]
    if capture:
        rows += [{"rule": {"family": "inet", "table": OWNER, "chain": "capture",
                           "handle": 20, "expr": [{"counter": {"packets": 1, "bytes": 64}}, {"return": None}]}},
                 {"rule": {"family": "inet", "table": OWNER, "chain": "capture",
                           "handle": 21, "expr": [{"counter": {"packets": 2, "bytes": 128}}]}}]
    rows += [{"rule": {"family": "inet", "table": OWNER, "chain": "guard",
                       "handle": 22, "expr": [{"counter": {"packets": 3, "bytes": 192}}, {"drop": None}]}}]
    if foreign:
        rows.append({"rule": {"family": "inet", "table": OWNER, "chain": "guard",
                               "handle": 99, "expr": [{"accept": None}]}})
    return {"nftables": rows}


def graph_digest(value):
    rows = copy.deepcopy(value["nftables"])
    for item in rows:
        for record in item.values():
            if isinstance(record, dict):
                record.pop("handle", None)
                for expression in record.get("expr", []):
                    if "counter" in expression:
                        expression["counter"] = {}
    return DIGEST(json.dumps(rows, sort_keys=True, separators=(",", ":")))


MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, sys, time
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state_path=pathlib.Path(os.environ["MOCK_STATE"])
d=json.loads(state_path.read_text())
d["calls"].append([name]+args)
def save():
    state_path.write_text(json.dumps(d))
def done(text="",rc=0):
    save()
    if text: print(text,end="")
    sys.exit(rc)
work=pathlib.Path(os.environ["MOCK_WORK"])
root=state_path.parent
owner="scfhr_aabbccddeeff0011"
if name=="nft":
    if d.get("inventory_failure") and args==["list","tables"]: done(rc=7)
    if args==["list","tables"]: done(("table inet "+owner+"\n") if d["table"] else "")
    if args==["list","table","inet",owner]:
        done(("table inet "+owner+" {\n}\n") if d["table"] else "",rc=0 if d["table"] else 1)
    if args==["-a","list","table","inet",owner]:
        done(("table inet "+owner+" {\n}\n") if d["table"] else "",rc=0 if d["table"] else 1)
    if args==["-j","-a","list","table","inet",owner]:
        if not d["table"]: done(rc=1)
        value=json.loads((root/("active.json" if d["capture"] else "retired.json")).read_text())
        value["nftables"][1]["table"]["handle"]=d.get("handle",17)
        if d.get("foreign"):
            value["nftables"].append({"rule":{"family":"inet","table":owner,"chain":"guard","handle":99,"expr":[{"accept":None}]}})
        done(json.dumps(value)+"\n")
    if args==["flush","chain","inet",owner,"capture"]:
        d["capture"]=False
        d["flushes"]+=1
        if d.get("flush_ack_fail_once"):
            d["flush_ack_fail_once"]=False
            done(rc=7)
        done()
    if args==["delete","table","inet",owner]:
        d["table"]=False
        d["deletes"]+=1
        if d.get("delete_ack_fail_once"):
            d["delete_ack_fail_once"]=False
            done(rc=7)
        done()
    done(rc=9)
if name=="systemctl":
    core="server-connect-field-root-core.service"
    timer="server-connect-field-root-recovery.timer"
    if args==["show",core,"-p","LoadState","--value"]: done("loaded\n")
    if args==["show",core,"-p","ExecStart","--value"]:
        done("/opt/server-connect/current/bin/sing-box run -c "+str(work/"config.json")+"\n")
    if args==["stop",core]:
        if d.get("pause_stop"):
            (root/"stop-entered").touch()
            save()
            deadline=time.monotonic()+8
            while not (root/"release-stop").exists():
                if time.monotonic()>deadline: done(rc=8)
                time.sleep(.02)
            d["pause_stop"]=False
        if d.get("stop_fail_once"):
            d["stop_fail_once"]=False
            done(rc=7)
        d["core"]=False
        tun=root/"sys/class/net/scfhrt0"
        if tun.exists(): tun.rmdir()
        done()
    if args==["is-active",core]: done("active\n" if d["core"] else "inactive\n",rc=0 if d["core"] else 3)
    if args==["stop",timer]:
        d["timer"]=False
        done()
    if args==["is-active",timer]: done("active\n" if d["timer"] else "inactive\n",rc=0 if d["timer"] else 3)
    if args==["is-active","ssh"]: done("active\n")
    done(rc=9)
if name=="ip":
    base_rules="0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"
    rule="10391: from all fwmark 0x530000/0xff0000 lookup 42441\n" if d["rule"] else ""
    routes=("default dev scfhrt0 scope link metric 10\n" if d["route"] else "")+("unreachable default metric 100\n" if d["fallback"] else "")
    if args==["-4","rule","show"]: done(base_rules+rule)
    if args==["-4","route","show","table","42441"]: done(routes)
    if args==["-4","route","show","table","all"]: done("default via 192.0.2.1 dev qa-underlay\n"+routes)
    if args==["-4","rule","del","priority","10391","fwmark","0x00530000/0x00ff0000","table","42441"]:
        d["rule"]=False
        done()
    if args==["-4","route","del","default","dev","scfhrt0","table","42441","metric","10"]:
        d["route"]=False
        done()
    if args==["-4","route","del","unreachable","default","table","42441","metric","100"]:
        d["fallback"]=False
        done()
    done(rc=9)
if name=="iptables":
    if args==["-t","raw","-S"]: done("-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n")
    if args==["-t","nat","-S"]: done("-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n")
    done(rc=9)
done(rc=9)
'''


class Fixture:
    def __init__(self, **flags):
        self.temp = tempfile.TemporaryDirectory(prefix="sc-field-root-recovery-")
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        tool = self.bin / "mock"
        tool.write_text(MOCK)
        tool.chmod(0o700)
        for name in ("nft", "ip", "iptables", "systemctl"):
            (self.bin / name).symlink_to(tool)
        for name, content in {
            "owner": OWNER + "\n", "boot": BOOT + "\n",
            "baseline": "\n".join(map(DIGEST, (BASE_ROUTES, BASE_RULES, RAW, NAT))) + "\n",
            "nft-handle": "17\n", "nft-receipt": graph_digest(graph()) + "\n",
            "nft-retired-receipt": graph_digest(graph(capture=False)) + "\n",
            "recovery.lock": "", "config.json": "{}\n",
        }.items():
            (self.work / name).write_text(content)
        (self.root / "sys/class/net/scfhrt0").mkdir(parents=True)
        (self.root / "active.json").write_text(json.dumps(graph()))
        (self.root / "retired.json").write_text(json.dumps(graph(capture=False)))
        self.state = self.root / "state.json"
        self.state.write_text(json.dumps(dict(table=True, capture=True, core=True,
                                              rule=True, route=True, fallback=True,
                                              timer=True, calls=[], flushes=0, deletes=0, **flags)))
        body = RECOVER
        for old, new in {
            "work=/root/server-connect-field-root-qa": "work=" + str(self.work),
            "/sys/class/net/": str(self.root / "sys/class/net") + "/",
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin":
                "export PATH=" + str(self.bin) + ":/usr/sbin:/usr/bin:/sbin:/bin",
        }.items():
            assert old in body
            body = body.replace(old, new)
        self.recovery = self.work / "recover.sh"
        self.recovery.write_text(body)
        self.env = dict(os.environ, MOCK_STATE=str(self.state), MOCK_WORK=str(self.work))
        self.env.pop("SC_FIELD_RECOVERY_LOCK_FD", None)
        self.env["PATH"] = str(self.bin) + ":/usr/sbin:/usr/bin:/sbin:/bin"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.temp.cleanup()

    def read(self):
        return json.loads(self.state.read_text())

    def change(self, **changes):
        state = self.read()
        state.update(changes)
        self.state.write_text(json.dumps(state))

    def run(self):
        return subprocess.run(["/usr/bin/bash", str(self.recovery)], env=self.env,
                              text=True, capture_output=True, timeout=15)

    def expect(self, result, success):
        assert (result.returncode == 0) == success, (result.returncode, result.stdout, result.stderr)
        assert ("ROOT_HOST_NETWORK_RESTORED=PASS" in result.stdout) == success, result.stdout

    def restored(self):
        state = self.read()
        assert not any(state[key] for key in ("table", "core", "rule", "route", "fallback")), state
        assert state["flushes"] == state["deletes"] == 1, state


with Fixture(stop_fail_once=True) as fixture:
    first = fixture.run()
    fixture.expect(first, False)
    assert "owned core stop failed" in first.stderr, first.stderr
    assert fixture.read()["table"] and not fixture.read()["capture"]
    second = fixture.run()
    fixture.expect(second, True)
    fixture.restored()
    fixture.expect(fixture.run(), True)
    fixture.restored()
print("FIELD_ROOT_RECOVERY_AFTER_FLUSH_FAILURE_AND_REPEAT=PASS")

for failure in ("flush_ack_fail_once", "delete_ack_fail_once"):
    with Fixture(**{failure: True}) as fixture:
        fixture.expect(fixture.run(), False)
        fixture.expect(fixture.run(), True)
        fixture.restored()
print("FIELD_ROOT_RECOVERY_AMBIGUOUS_FLUSH_AND_DELETE_RETRY=PASS")

with Fixture(stop_fail_once=True) as fixture:
    fixture.expect(fixture.run(), False)
    fixture.change(foreign=True)
    fixture.expect(fixture.run(), False)
    state = fixture.read()
    assert state["foreign"] and state["table"] and state["core"] and state["rule"]
    assert state["flushes"] == 1 and state["deletes"] == 0
print("FIELD_ROOT_RECOVERY_FOREIGN_CHILD_AFTER_PARTIAL_FAILURE_RETAINED=PASS")

for drift in ("no_retire_intent", "wrong_retire_intent", "different_handle", "inventory_failure"):
    with Fixture(stop_fail_once=True) as fixture:
        fixture.expect(fixture.run(), False)
        if drift == "no_retire_intent":
            (fixture.work / "capture-retire-intent").unlink()
        elif drift == "wrong_retire_intent":
            (fixture.work / "capture-retire-intent").write_text("other operation\n")
        elif drift == "different_handle":
            fixture.change(handle=18)
        else:
            fixture.change(inventory_failure=True)
        fixture.expect(fixture.run(), False)
        state = fixture.read()
        assert state["table"] and state["rule"] and state["flushes"] == 1 and state["deletes"] == 0
print("FIELD_ROOT_RECOVERY_UNRECEIPTED_OR_CHANGED_GRAPH_REFUSED=PASS")

with Fixture(pause_stop=True) as fixture:
    timer = subprocess.Popen(["/usr/bin/bash", str(fixture.recovery)], env=fixture.env,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finalizer = None
    try:
        deadline = time.monotonic() + 5
        while not (fixture.root / "stop-entered").exists():
            assert timer.poll() is None and time.monotonic() < deadline, "first recovery did not reach controlled pause"
            time.sleep(.02)
        # The actual kernel flock, not a mock or an in-memory test flag.
        locked = subprocess.run(["flock", "-n", str(fixture.work / "recovery.lock"), "true"])
        assert locked.returncode != 0, "recovery did not hold its lock through the kernel mutation"
        calls_before = fixture.read()["calls"]
        body = 'work="' + str(fixture.work) + '"\nwatch=server-connect-field-root-recovery\n' + FINALIZER + "\ntrue\nfinalize\n"
        finalizer = subprocess.Popen(["/usr/bin/bash", "-c", body], env=fixture.env,
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(.15)
        assert finalizer.poll() is None, "EXIT finalizer did not wait for the timer"
        assert fixture.read()["calls"] == calls_before, "second recovery inspected or mutated before owning the lock"
        (fixture.root / "release-stop").touch()
        timer_out, timer_err = timer.communicate(timeout=10)
        final_out, final_err = finalizer.communicate(timeout=10)
        assert timer.returncode == finalizer.returncode == 0, (timer_out, timer_err, final_out, final_err)
        assert "ROOT_HOST_NETWORK_RESTORED=PASS" in timer_out
        assert "FIELD_ROOT_OWNED_CLEANUP=PASS" in final_out
        fixture.restored()
        assert not fixture.work.exists(), "finalizer did not complete its exact private cleanup"
    finally:
        for process in (timer, finalizer):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
print("FIELD_ROOT_TIMER_AND_EXIT_ACTUAL_LOCK_SERIALIZATION=PASS")
