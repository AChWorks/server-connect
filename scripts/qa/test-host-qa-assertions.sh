#!/usr/bin/env bash
# Hermetic fail-closed regression tests; no Docker, root, Internet or host changes.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
checker="$root/scripts/qa/host-qa-assertions.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/traces" "$scratch/fakebin"
trace_file="$scratch/traces/check.101"
safe_trace='execve("/usr/bin/env", ["env"], ["HOME=/root"]) = 0
socket(AF_UNIX, SOCK_STREAM, 0) = 3
exit_group(0) = ?'
printf '%s\n' "$safe_trace" >"$trace_file"

expect_trace_ok() {
  sh "$checker" trace "$scratch/traces" check >/dev/null ||
    { echo "Expected clean trace rejected: $1" >&2; exit 1; }
}
expect_trace_rejected() {
  local captured
  if captured=$(sh "$checker" trace "$scratch/traces" check 2>&1); then
    echo "Unsafe trace was accepted: $1" >&2
    exit 1
  fi
  [[ $captured == *'Host QA assertion failed:'* && $captured != *'=ZERO'* ]] ||
    { echo "Unsafe trace had no safe failure diagnostics: $1" >&2; exit 1; }
}

expect_trace_ok 'safe AF_UNIX operation'
printf '%s\n' "$safe_trace" 'socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 4' >"$trace_file"
expect_trace_rejected 'IPv6 socket attempt'
printf '%s\n' "$safe_trace" \
  'connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH' >"$trace_file"
expect_trace_rejected 'failed IPv4 connection attempt'
printf '%s\n' "$safe_trace" \
  'sendmsg(4<UDP:[127.0.0.1:1]>, {msg_name=NULL}, 0) = -1 EHOSTUNREACH' >"$trace_file"
expect_trace_rejected 'send on decoded UDP descriptor'
printf '%s\n' "$safe_trace" 'execve("/usr/bin/curl", ["curl"], []) = 0' >"$trace_file"
expect_trace_rejected 'forbidden execve'
printf '%s\n' "$safe_trace" \
  'execveat(AT_FDCWD, "/usr/bin/apt-get", ["apt-get"], [], 0) = 0' >"$trace_file"
expect_trace_rejected 'forbidden execveat'
printf '%s\n' "$safe_trace" \
  'execveat(3, "", ["unresolved"], [], AT_EMPTY_PATH) = 0' >"$trace_file"
expect_trace_rejected 'unresolved fd-only execveat'
printf '%s\n' "$safe_trace" >"$trace_file"
printf '\000' >>"$trace_file"
expect_trace_rejected 'binary or corrupted trace'
rm "$trace_file"
expect_trace_rejected 'missing process trace'
: >"$trace_file"
expect_trace_rejected 'all process traces empty'
printf '%s\n' "$safe_trace" >"$trace_file"
: >"$scratch/traces/check.102"
expect_trace_ok 'valid empty child trace alongside nonempty parent'
rm "$scratch/traces/check.102"
mkdir "$scratch/traces/check.102"
expect_trace_rejected 'non-regular child trace'
rmdir "$scratch/traces/check.102"
ln -s "$trace_file" "$scratch/traces/check.102"
expect_trace_rejected 'symlinked child trace'
rm "$scratch/traces/check.102"
chmod 000 "$trace_file"
if [[ $(id -u) -ne 0 ]]; then
  expect_trace_rejected 'unreadable trace'
fi
chmod 600 "$trace_file"
cat > "$scratch/fakebin/grep" <<'BAD_GREP'
#!/bin/sh
# A partial scanner failure must never be treated as no matches.
printf 'partial-scan\n'
exit 2
BAD_GREP
chmod +x "$scratch/fakebin/grep"
if captured=$(PATH="$scratch/fakebin:$PATH" sh "$checker" trace "$scratch/traces" check 2>&1); then
  echo 'grep I/O error was accepted as clean trace' >&2
  exit 1
fi
[[ $captured == *'grep exit 2'* && $captured != *'=ZERO'* ]] ||
  { echo 'grep I/O error did not retain scanner failure diagnostics' >&2; exit 1; }
expect_trace_ok 'clean trace after injected errors'

cat > "$scratch/fakebin/ip" <<'FAKE_IP'
#!/bin/sh
set -eu
if [ "$SC_QA_FAKE_IP_FAIL" = "$*" ]; then
  echo 'simulated ip query failure' >&2
  exit 88
fi
printf '%s %s\n' "$SC_QA_FAKE_IP_ALTER" "$*"
FAKE_IP
chmod +x "$scratch/fakebin/ip"
export PATH="$scratch/fakebin:$PATH" SC_QA_FAKE_IP_FAIL='none' SC_QA_FAKE_IP_ALTER=no
first=$(sh "$checker" network)
second=$(sh "$checker" network)
[[ $first == "$second" && $first =~ ^[0-9a-f]{64}$ ]] ||
  { echo 'stable complete five-component snapshot failed' >&2; exit 1; }
SC_QA_FAKE_IP_ALTER=yes
export SC_QA_FAKE_IP_ALTER
third=$(sh "$checker" network)
[[ $first != "$third" ]] ||
  { echo 'network change was not reflected by digest' >&2; exit 1; }
SC_QA_FAKE_IP_ALTER=no
export SC_QA_FAKE_IP_ALTER
for failed_query in \
  '-j -4 route show table all' \
  '-j -6 route show table all' \
  '-j -4 rule show' \
  '-j -6 rule show' \
  '-j link show'; do
  SC_QA_FAKE_IP_FAIL=$failed_query
  export SC_QA_FAKE_IP_FAIL
  if captured=$(sh "$checker" network 2>&1); then
    echo "Failed ip query produced a successful hash: $failed_query" >&2
    exit 1
  fi
  [[ $captured == *'snapshot query failed'* ]] ||
    { echo "Missing phase-specific failed ip diagnostic: $failed_query" >&2; exit 1; }
done
echo 'HOST_QA_ASSERTION_NEGATIVE_REGRESSIONS=PASS'

# Exercise the actual receipt checker with native-shaped journald rows.
# No systemd/root access: reject stale/wrong attribution and JSON fragments
# that would falsely manufacture independent completion from mixed streams.
python3 - "$checker" "$scratch" <<'PYRECOVERYFIXTURES'
import json
from pathlib import Path
import subprocess
import sys

checker, scratch = sys.argv[1:]
operation = "a" * 32
invocation = "b" * 32
receipt = {
    "operation_id": operation, "revision": 5, "phase": "trial_cleared",
    "experiment_only": True, "guard_scheduled": False,
    "activation_ready": False, "vpn_verified": False,
    "recovery_verified": True, "trial_rule_recovered": False,
}


def records(value, inv=invocation, stream="c" * 32, pid="101"):
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    return [{"__CURSOR": f"qa:{inv}:{stream}:{number}",
             "_SYSTEMD_UNIT": "server-connect-activation-recover.service",
             "_SYSTEMD_INVOCATION_ID": inv, "_TRANSPORT": "stdout",
             "_STREAM_ID": stream, "_PID": pid, "MESSAGE": line}
            for number, line in enumerate(text.splitlines())]


cases = 0


def check(label, rows, accepted=False, expected=operation):
    global cases
    path = Path(scratch) / "recovery.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = subprocess.run(["/bin/sh", checker, "recovery-receipt", str(path), expected],
                            text=True, capture_output=True)
    if accepted:
        assert result.returncode == 0 and result.stdout.strip() == invocation, (label, result)
    else:
        assert result.returncode != 0 and not result.stdout, (label, result)
        assert "Host QA assertion failed:" in result.stderr, (label, result)
    cases += 1


check("complete multiline receipt", records(receipt), True)
check("complete single-message receipt", records(json.dumps(receipt)), True)
pending = dict(receipt, phase="trial_pending", revision=1,
               guard_scheduled=True, recovery_verified=False)
check("earlier distinct pending invocation", records(pending, inv="d" * 32) + records(receipt), True)
for key, value in (("_SYSTEMD_UNIT", "other.service"), ("_TRANSPORT", "journal"),
                   ("_SYSTEMD_INVOCATION_ID", ""), ("_SYSTEMD_INVOCATION_ID", "0" * 32),
                   ("_STREAM_ID", ""), ("_PID", "1")):
    altered = records(receipt)
    for row in altered:
        row[key] = value
    check("untrusted identity " + key + value, altered)
altered = records(receipt)
for row in altered:
    row["SYSTEMD_INVOCATION_ID"] = row.pop("_SYSTEMD_INVOCATION_ID")
check("untrusted replacement invocation field", altered)
for key, value in (("_STREAM_ID", "e" * 32), ("_PID", "202"),
                   ("_SYSTEMD_INVOCATION_ID", "e" * 32)):
    altered = records(receipt)
    for row in altered[len(altered) // 2:]:
        row[key] = value
    check("stitched JSON across " + key, altered)
check("wrong operation", records(receipt), expected="f" * 32)
for key, value in (("revision", 4), ("phase", "trial_recovered"),
                   ("recovery_verified", False), ("guard_scheduled", True),
                   ("experiment_only", False), ("activation_ready", True),
                   ("vpn_verified", True), ("error", "failed"), ("ok", False)):
    check("failure-shaped receipt " + key, records(dict(receipt, **{key: value})))
check("incomplete JSON", records(receipt)[:-1])
check("duplicate journal entry", records(receipt) + records(receipt)[-1:])
check("duplicate successful invocations", records(receipt) + records(receipt, inv="e" * 32))
check("conflicting completed invocation", records(receipt) + records(dict(receipt, recovery_verified=False), inv="e" * 32))
check("conflicting stream within invocation", records(receipt) + records('{"error":"failed"}', stream="e" * 32))
duplicate_key = json.dumps(receipt).replace('"revision": 5', '"revision": 4, "revision": 5')
check("duplicate receipt field", records(duplicate_key))
check("empty journal", [])
print(f"HOST_QA_RECOVERY_RECEIPT_REGRESSIONS=PASS ({cases} attribution/completion cases)")
PYRECOVERYFIXTURES

# Exercise only the pure comparison from the installed helper. Do not source
# or execute its privileged fixture/journal/command paths in this regression.
python3 - "$root/scripts/qa/host-native-product-tun.sh" <<'PYNATIVEIFINDEXFIXTURES'
import ast,copy,json,sys
from pathlib import Path
source=Path(sys.argv[1]).read_text().split("<<'PYNATIVEGUARDGRAPH'\n",1)[1].split('\nPYNATIVEGUARDGRAPH\n',1)[0]
nodes=[node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef) and node.name=='nft_after_deleted_tun']
assert len(nodes)==1
namespace={'json':json}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<native nft observer>','exec'),namespace)
compare=namespace['nft_after_deleted_tun']
operation='a'*32;name='scnt_'+operation
link={'ifindex':22,'ifname':'sctunqa0','ifalias':'server-connect:'+operation}
remaining=[{'ifindex':1,'ifname':'lo'},{'ifindex':20,'ifname':'scqaedge0'}]
before={'nftables':[
    {'metainfo':{'version':'1.1.3','json_schema_version':1}},
    {'table':{'family':'inet','name':name,'handle':16}},
    {'chain':{'family':'inet','table':name,'name':'guard','handle':15}},
    {'rule':{'family':'inet','table':name,'chain':'guard','handle':28,
             'expr':[{'match':{'op':'==','left':{'meta':{'key':'oif'}},'right':'sctunqa0'}},{'return':None}]}},
    {'rule':{'family':'inet','table':name,'chain':'guard','handle':30,
             'expr':[{'match':{'op':'==','left':{'meta':{'key':'oifname'}},'right':'sctunqa0'}},
                     {'match':{'op':'==','left':{'meta':{'key':'oif'}},'right':'scqaedge0'}},
                     {'counter':{'packets':0,'bytes':0}}]}}]}
after=copy.deepcopy(before)
after['nftables'][3]['rule']['expr'][0]['match']['right']='22'
cases=0
def check(label,current,accepted=False,saved=before,inventory=remaining,original=link):
    global cases
    snapshots=copy.deepcopy((saved,current,original,inventory))
    try:result=compare(saved,current,original,inventory,operation)
    except AssertionError:result=False
    assert result is accepted,label
    assert snapshots==(saved,current,original,inventory),label+' mutated evidence'
    cases+=1
check('exact deleted index decimal string',after,True)
check('unchanged name after observed deletion',before)
for value in ('23','022',22,22.0,True):
    changed=copy.deepcopy(after);changed['nftables'][3]['rule']['expr'][0]['match']['right']=value
    check('wrong index representation '+repr(value),changed)
check('replacement under original name',after,inventory=remaining+[{'ifindex':23,'ifname':'sctunqa0'}])
check('original index reused under another name',after,inventory=remaining+[{'ifindex':22,'ifname':'foreign0'}])
check('original link remains',after,inventory=remaining+[link])
check('wrong authenticated alias',after,original=dict(link,ifalias='server-connect:'+'b'*32))
check('wrong authenticated index',after,original=dict(link,ifindex=23))
for field,value in (('handle',29),('unexpected',True)):
    changed=copy.deepcopy(after);changed['nftables'][3]['rule'][field]=value
    check('rule '+field+' changed',changed)
changed=copy.deepcopy(after);changed['nftables'][1]['table']['handle']=17
check('table handle changed',changed)
changed=copy.deepcopy(after);changed['nftables'][3]['rule']['expr'][0]['match']['unknown']='new'
check('unknown match field added',changed)
changed=copy.deepcopy(after);changed['nftables'][3]['rule']['expr'].reverse()
check('expression order changed',changed)
changed=copy.deepcopy(after);changed['nftables'][3:]=reversed(changed['nftables'][3:])
check('rule order changed',changed)
changed=copy.deepcopy(after);changed['nftables'][4]['rule']['expr'][0]['match']['right']='22'
check('oifname is not an index',changed)
changed=copy.deepcopy(after);changed['nftables'][4]['rule']['expr'][1]['match']['right']='20'
check('unrelated indexed interface changed',changed)
changed=copy.deepcopy(after);changed['nftables'][4]['rule']['expr'][2]['counter']['packets']=1
check('counter effect changed',changed)
changed=copy.deepcopy(after);changed['nftables'][4]['rule']['expr'][2]['counter']['packets']=False
check('JSON boolean is not numeric zero',changed)
saved=copy.deepcopy(before);changed=copy.deepcopy(after)
saved['nftables'][3]['rule']['expr'][0]['match']['unknown']='same'
changed['nftables'][3]['rule']['expr'][0]['match']['unknown']='same'
check('extra match fields do not gain normalization',changed,saved=saved)
saved=copy.deepcopy(before);changed=copy.deepcopy(after)
for value in (saved,changed):value['nftables'][3]['rule']['unknown']='retained'
check('unrelated unknown fields retained exactly',changed,True,saved=saved)
changed['nftables'][3]['rule']['unknown']='different'
check('different unknown field refused',changed,saved=saved)
saved=copy.deepcopy(before);changed=copy.deepcopy(after)
saved['nftables'].append(copy.deepcopy(saved['nftables'][3]));saved['nftables'][-1]['rule']['handle']=31
changed['nftables'].append(copy.deepcopy(changed['nftables'][3]));changed['nftables'][-1]['rule']['handle']=31
check('both enabled family rules keep exact indices',changed,True,saved=saved)
print(f'HOST_QA_NATIVE_DELETED_IFINDEX_REGRESSIONS=PASS ({cases} exact identity/graph cases)')
PYNATIVEIFINDEXFIXTURES
