#!/usr/bin/env python3
"""Rootless failure injection against the embedded *actual* field cleanup body.

Every kernel/network command is replaced under an isolated temporary PATH;
absolute /root, /etc/netns, /var/run/netns, and /sys/class/net paths are
redirected to disposable temp fixtures. Never runs the privileged QA entrypoint.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).with_name("field-selected-tun-netns.sh").read_text()
PREFIX = "<<'CLEANUP'\n"
assert SOURCE.count(PREFIX) == 1
CLEANUP = SOURCE.partition(PREFIX)[2].partition("\nCLEANUP\n")[0]
assert CLEANUP.startswith("#!/usr/bin/env bash\n")
assert "QA_SCOPED_CLEANUP_VERIFIED=PASS" in CLEANUP

# Regress the exact real-host failure seen after successful independent
# cleanup: ip netns list returns an empty string, which is VALID, not UNKNOWN.
parser_marker = "valid_netns_listing() {\n"
assert SOURCE.count(parser_marker) == 1
parser_body = SOURCE.partition(parser_marker)[2].partition("\n}\n")[0]
parser_script = parser_marker + parser_body + "\n}\n"
for example in ("", "scf0123456789abcdef", "scf0123456789abcdef (id: 0)",
                "qa1 (id: 4)\nqa2"):
    result = subprocess.run(["/usr/bin/bash", "-c",
                             parser_script + '\nvalid_netns_listing "$1"', "qa", example])
    assert result.returncode == 0, ("valid namespace listing rejected", repr(example))
for example in ("broken namespace name", "qa (id: xyz)", "qa\nmalformed ?"):
    result = subprocess.run(["/usr/bin/bash", "-c",
                             parser_script + '\nvalid_netns_listing "$1"', "qa", example])
    assert result.returncode != 0, ("malformed namespace listing accepted", repr(example))
print("PARENT_EMPTY_AND_MALFORMED_NAMESPACE_LIST_VALIDATION=PASS")

MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state_path=pathlib.Path(os.environ["MOCK_STATE"])
d=json.loads(state_path.read_text())
def done(text="",rc=0):
    state_path.write_text(json.dumps(d))
    if text: print(text,end="")
    sys.exit(rc)
def rows(table,chain=None):
    base="-P FORWARD ACCEPT\n" if table=="filter" else "-P POSTROUTING ACCEPT\n"
    suffixes=(":forward-out",":forward-in") if table=="filter" else (":nat",)
    lines=[f'-A {"FORWARD" if table=="filter" else "POSTROUTING"} -m comment --comment "{tag}" -j ACCEPT\n'
           for tag in d["tags"] if tag.endswith(suffixes)]
    return base+"".join(lines)
if name=="ip":
    if args==["netns","list"]:
        d["netns_list_calls"]=d.get("netns_list_calls",0)+1
        if d.get("list_fail") or (d.get("post_list_fail") and d["netns_list_calls"]>1): done(rc=7)
        if d.get("list_malformed") or (d.get("post_list_malformed") and d["netns_list_calls"]>1):
            done("malformed name??\n")
        node=pathlib.Path(os.environ["MOCK_NS"])
        done((os.environ["MOCK_NS_NAME"]+" (id: 1)\n") if node.exists() else "")
    if args==["netns","pids",os.environ["MOCK_NS_NAME"]]:
        if d.get("pids_fail"): done(rc=7)
        done(str(d.get("live_pid"))+"\n" if d.get("live_pid") else "")
    if args==["netns","delete",os.environ["MOCK_NS_NAME"]]:
        if d.get("delete_fail"): done(rc=7)
        if not d.get("delete_no_effect"): pathlib.Path(os.environ["MOCK_NS"]).unlink()
        done()
    if args==["-4","route","show","table","all"]:
        done("DRIFTED\n" if d.get("route_drift") else "BASE_ROUTES\n")
    if args==["-4","rule","show"]: done("BASE_RULES\n")
    done(rc=9)
if name=="iptables":
    if "-t" not in args: done(rc=9)
    table=args[args.index("-t")+1]
    if table not in ("filter","nat"): done(rc=9)
    if "-S" in args:
        if d.get("iptables_list_fail"): done(rc=7)
        done(rows(table))
    if "-D" in args:
        tag=args[args.index("--comment")+1] if "--comment" in args else ""
        if d.get("delete_fail"): done(rc=7)
        if tag in d.get("delete_once",[]):
            d["delete_once"].remove(tag)
            done(rc=7)
        if tag not in d["tags"]: done(rc=1)
        d["tags"].remove(tag)
        done()
    done(rc=9)
if name=="iptables-save":
    if d.get("iptables_save_fail"): done(rc=7)
    done("*filter\n"+rows("filter")+"*nat\n"+rows("nat"))
if name=="systemctl":
    if args==["is-active","ssh"]: done("active\n")
    done(rc=9)
done(rc=9)
'''

RUN_ID = "aabbccddeeff0011"
NS = "scf" + RUN_ID
OWNER = "server-connect-field-netns-qa:" + RUN_ID
TAGS = [OWNER + suffix for suffix in (":forward-out", ":forward-in", ":nat")]
BOOT = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
HASH = lambda data: hashlib.sha256(data.encode()).hexdigest()
FILTER_BASE = "-P FORWARD ACCEPT\n"
NAT_BASE = "-P POSTROUTING ACCEPT\n"


def case(name, *, should_pass, with_ns=False, namespace_receipt=True, dns="absent",
         parent_collision=False, parent_owned=False, tags=True, flags=None,
         missing_ns_receipt=False, ns_inode_mismatch=False, repeat=1):
    flags = dict(flags or {})
    with tempfile.TemporaryDirectory(prefix="sc-field-qa-") as temp:
        root = Path(temp)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        tool = bin_dir / "mock"
        tool.write_text(MOCK)
        tool.chmod(0o700)
        for alias in ("ip", "iptables", "iptables-save", "systemctl"):
            (bin_dir / alias).symlink_to(tool)
        work = root / "private" / "work"
        work.mkdir(parents=True)
        (work / "run-id").write_text(RUN_ID + "\n")
        (work / "owner").write_text(f"host={os.uname().nodename} boot={BOOT} owner={OWNER}\n")
        (work / "underlay-interface").write_text("ens3\n")
        base_routes = HASH("BASE_ROUTES\n")
        base_rules = HASH("BASE_RULES\n")
        (work / "root-baseline").write_text(
            f"{base_routes} {base_rules} {HASH(FILTER_BASE)} {HASH(NAT_BASE)} {BOOT}\n"
        )
        (work / "resolv.conf").write_text("nameserver 1.1.1.1\n")
        node = root / "var" / "run" / "netns" / NS
        node.parent.mkdir(parents=True)
        if with_ns:
            node.touch()
            if namespace_receipt:
                stat = node.stat()
                (work / "namespace-id").write_text(
                    "1:2\n" if ns_inode_mismatch else f"{stat.st_dev}:{stat.st_ino}\n"
                )
            (work / "namespace-intent").touch()
        elif missing_ns_receipt:
            (work / "namespace-id").write_text("1:2\n")
        etc_parent = root / "etc" / "netns"
        if dns != "absent":
            dns_dir = etc_parent / NS
            dns_dir.mkdir(parents=True)
            if dns != "collision":
                stat = dns_dir.stat()
                (work / "created-resolver-dir").write_text(f"{stat.st_dev}:{stat.st_ino}\n")
                (work / "created-resolver-dir-intent").touch()
                if dns == "partial":
                    (dns_dir / ("resolv.conf.tmp." + RUN_ID)).write_text("half copy")
                elif dns == "complete":
                    (dns_dir / "resolv.conf").write_text("nameserver 1.1.1.1\n")
                elif dns == "foreign":
                    (dns_dir / "resolv.conf").write_text("nameserver 2.2.2.2\n")
        if parent_owned:
            etc_parent.mkdir(parents=True, exist_ok=True)
            parent_stat = etc_parent.stat()
            (work / "created-resolver-parent-intent").touch()
            (work / "created-resolver-parent").write_text(
                f"{parent_stat.st_dev}:{parent_stat.st_ino}\n"
            )
        if parent_collision:
            etc_parent.mkdir(parents=True, exist_ok=True)
            (work / "created-resolver-parent-intent").touch()
        state = root / "mock-state.json"
        state.write_text(json.dumps({"tags": TAGS.copy() if tags else [], **flags}))
        cleanup = CLEANUP
        replacements = {
            "work=/root/server-connect-field-netns-qa": "work=" + str(work),
            "/var/run/netns/": str(root / "var" / "run" / "netns") + "/",
            "/etc/netns": str(etc_parent),
            "/sys/class/net/": str(root / "sys" / "class" / "net") + "/",
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin":
                "export PATH=" + str(bin_dir) + ":/usr/sbin:/usr/bin:/sbin:/bin",
        }
        for original, replacement in replacements.items():
            assert original in cleanup, original
            cleanup = cleanup.replace(original, replacement)
        assert "work=" + str(work) in cleanup and str(node.parent) in cleanup and str(etc_parent) in cleanup
        env = dict(os.environ, MOCK_STATE=str(state), MOCK_NS=str(node), MOCK_NS_NAME=NS)
        for iteration in range(repeat):
            result = subprocess.run(["/usr/bin/bash", "-s"], input=cleanup,
                                    text=True, capture_output=True, env=env, timeout=15)
            if iteration < repeat - 1:
                assert result.returncode == 0, (name, iteration, result.stderr)
        state_after = json.loads(state.read_text())
        if should_pass:
            assert result.returncode == 0, (name, result.stdout, result.stderr)
            assert "QA_SCOPED_CLEANUP_VERIFIED=PASS" in result.stdout, name
            assert not state_after["tags"], (name, "root firewall rule remained")
            assert not node.exists(), (name, "namespace remained")
            assert not (etc_parent / NS).exists(), (name, "DNS fixture remained")
        else:
            assert result.returncode != 0, (name, result.stdout, result.stderr)
            assert "QA_SCOPED_CLEANUP_VERIFIED=PASS" not in result.stdout, name
            assert "RECOVERY_UNCERTAIN:" in result.stderr, (name, result.stderr)
            assert work.exists() and (work / "owner").exists(), (name, "recovery evidence destroyed")
            if dns == "collision":
                assert (etc_parent / NS).exists(), (name, "foreign DNS directory deleted")
            if with_ns and not namespace_receipt:
                assert node.exists(), (name, "foreign namespace deleted")
        print(name + "=PASS")


case("ROOT_CLEANUP_AND_IDEMPOTENCE", should_pass=True, tags=True, repeat=2)
case("ROOT_CLEANUP_NO_OWN_RULES", should_pass=True, tags=False)
case("XTABLES_BOUNDED_RETRY", should_pass=True,
     flags={"delete_once": [TAGS[0]]})
case("XTABLES_DELETE_FAILURE_FAILS_CLOSED", should_pass=False,
     flags={"delete_fail": True})
case("XTABLES_LIST_FAILURE_FAILS_CLOSED", should_pass=False,
     flags={"iptables_list_fail": True})
case("XTABLES_INDEPENDENT_LIST_FAILURE_FAILS_CLOSED", should_pass=False,
     flags={"iptables_save_fail": True})
case("NAMESPACE_LIST_FAILURE_FAILS_CLOSED", should_pass=False,
     flags={"list_fail": True})
case("NAMESPACE_MALFORMED_LIST_FAILS_CLOSED", should_pass=False,
     flags={"list_malformed": True})
case("NAMESPACE_PID_FAILURE_FAILS_CLOSED", should_pass=False,
     with_ns=True, flags={"pids_fail": True})
case("NAMESPACE_LIVE_UNOWNED_PROCESS_REFUSED", should_pass=False,
     with_ns=True, flags={"live_pid": os.getpid()})
case("NAMESPACE_DELETE_INTERRUPTED_REFUSED", should_pass=False,
     with_ns=True, flags={"delete_no_effect": True})
case("NAMESPACE_POSTDELETE_LIST_FAILURE_REFUSED", should_pass=False,
     with_ns=True, flags={"post_list_fail": True})
case("NAMESPACE_POSTDELETE_MALFORMED_LIST_REFUSED", should_pass=False,
     with_ns=True, flags={"post_list_malformed": True})
case("NAMESPACE_DELETE_ERROR_REFUSED", should_pass=False,
     with_ns=True, flags={"delete_fail": True})
case("NAMESPACE_CREATION_COLLISION_REFUSED", should_pass=False,
     with_ns=True, namespace_receipt=False)
case("NAMESPACE_UNRECEIPTED_DISAPPEARANCE_REFUSED", should_pass=False,
     missing_ns_receipt=True)
case("NAMESPACE_OWNED_CLEANUP", should_pass=True, with_ns=True, repeat=2)
case("NAMESPACE_INODE_COLLISION_REFUSED", should_pass=False,
     with_ns=True, ns_inode_mismatch=True)
case("DNS_CREATION_COLLISION_REFUSED", should_pass=False, dns="collision")
case("DNS_PARENT_CREATION_COLLISION_REFUSED", should_pass=False,
     parent_collision=True)
case("DNS_PARTIAL_TEMPORARY_REMOVED", should_pass=True, dns="partial")
case("DNS_OWNED_COMPLETE_REMOVED", should_pass=True, dns="complete")
case("DNS_OWNED_PARENT_REMOVED", should_pass=True, dns="partial",
     parent_owned=True, repeat=2)
case("DNS_CHANGED_FIXTURE_REFUSED", should_pass=False, dns="foreign")
case("ROOT_BASELINE_DRIFT_REFUSED", should_pass=False,
     flags={"route_drift": True})
print("FIELD_INDEPENDENT_RECOVERY_FAULT_MATRIX=PASS")
