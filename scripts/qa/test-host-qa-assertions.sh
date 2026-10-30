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

python3 - "$root/scripts/qa/host-native-product-tun.sh" <<'PYNATIVEPACKETFIXTURES'
import ast,copy,socket,struct,sys
from pathlib import Path
source=Path(sys.argv[1]).read_text()
def functions(marker,names,namespace):
    block=source.split("<<'"+marker+"'\n",1)[1].split('\n'+marker+'\n',1)[0]
    nodes=[x for x in ast.parse(block).body if isinstance(x,ast.FunctionDef) and x.name in names]
    assert {x.name for x in nodes}==set(names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<native packet observers>','exec'),namespace)
    return namespace
delta=functions('PYNATIVEAPPLYDIAG',('native_readiness_delta',),{})['native_readiness_delta']
before={'operation_id':'a'*32,'link_index':22,'nft_handle':16,'drop_handle':29,
        'tx_packets':10,'rx_packets':7,'guard_packets':0,'guard_bytes':0}
after=dict(before,tx_packets=14,rx_packets=9,guard_packets=2,guard_bytes=120)
assert delta(before,after)=={'tx_packets':4,'rx_packets':2,'guard_packets':2,'guard_bytes':120}
assert delta(before,before)==dict.fromkeys(('tx_packets','rx_packets','guard_packets','guard_bytes'),0)
cases=2
def reject_counter(value):
    global cases
    try:delta(before,value)
    except AssertionError:pass
    else:raise AssertionError('unsafe counter attribution accepted: '+repr(value))
    cases+=1
for key,value in (('operation_id','b'*32),('link_index',23),('nft_handle',17),('drop_handle',30),
                  ('tx_packets',9),('guard_packets',-1),('guard_bytes',True),('rx_packets',9.0),
                  ('nft_handle',True),('guard_packets',2**64)):
    reject_counter(dict(after,**{key:value}))
changed=dict(after);del changed['guard_bytes'];reject_counter(changed)
reject_counter(dict(after,unexpected=0));reject_counter(None)
loss_delta=functions('PYNATIVEAPPLYDIAG',('native_loss_delta',),{'native_readiness_delta':delta})['native_loss_delta']
peer={'namespace_dev':4,'namespace_ino':4026532000,'link_index':9,'underlay_index':8,
      'tcp_handle':3,'udp_handle':4,'tcp_packets':7,'tcp_bytes':700,'udp_packets':5,'udp_bytes':500}
loss_before={'native':before,'peer':peer}
loss_after={'native':after,'peer':dict(peer,tcp_packets=9,tcp_bytes=950)}
assert loss_delta(loss_before,loss_after)=={'native':delta(before,after),
       'peer':{'tcp_packets':2,'tcp_bytes':250,'udp_packets':0,'udp_bytes':0}}
assert all(value==0 for value in loss_delta(loss_before,loss_before)['peer'].values())
cases+=2
def reject_loss(value):
    global cases
    original=copy.deepcopy(value)
    try:loss_delta(loss_before,value)
    except (AssertionError,KeyError,TypeError):pass
    else:raise AssertionError('unsafe peer attribution accepted')
    assert value==original
    cases+=1
for key in ('namespace_dev','namespace_ino','link_index','underlay_index','tcp_handle','udp_handle'):
    changed=copy.deepcopy(loss_after);changed['peer'][key]+=1;reject_loss(changed)
for key,value in (('tcp_packets',6),('udp_bytes',-1),('tcp_handle',True),('udp_packets',5.0),('tcp_bytes',2**64)):
    changed=copy.deepcopy(loss_after);changed['peer'][key]=value;reject_loss(changed)
changed=copy.deepcopy(loss_after);changed['native']['operation_id']='b'*32;reject_loss(changed)
changed=copy.deepcopy(loss_after);changed['peer']['unknown']='secret';reject_loss(changed)
changed=copy.deepcopy(loss_after);del changed['peer']['tcp_handle'];reject_loss(changed)
reject_loss(dict(loss_after,unknown='secret'));reject_loss(None)
boot='11111111-2222-3333-4444-555555555555'
summary=functions('PYNATIVEAPPLYDIAG',('operation_summary',),
                  {'op':'a'*32,'read':lambda path,limit:boot if path.endswith('boot_id') else '100.25 90.0'})['operation_summary']
record={'operation_id':'a'*32,'version':4,'intent_type':'smart_tun_native_pending_trial_v1',
        'phase':'trial_pending','revision':1,'deadline_uptime_sec':160,'boot_id':boot,
        'profile_id':'REDACTED_SECRET','native':{'link_stage':'observed','nft':{'stage':'observed'}}}
for family in ('ipv4','ipv6'):
    record['native'][family]={key:{'stage':'observed','sha256':'REDACTED_SECRET'} for key in ('route','fallback','rule')}
safe=summary(record)
assert safe['operation_id']=='a'*32 and safe['uptime_sec']==100.25 and safe['deadline_uptime_sec']==160
assert 'REDACTED_SECRET' not in repr(safe) and set(safe)=={'operation_id','phase','revision','deadline_uptime_sec','uptime_sec','receipt_stages'}
for phase,revision in (('trial_pending',1),('trial_stop_requested',2),('trial_recovered',2),('trial_recovered',3),('trial_cleanup_pending',4)):
    assert summary(dict(record,phase=phase,revision=revision))['revision']==revision
for change in ({'operation_id':'b'*32},{'phase':'trial_cleared'},{'revision':2},{'revision':True},
               {'deadline_uptime_sec':0},{'deadline_uptime_sec':True},{'deadline_uptime_sec':2**63},
               {'boot_id':'different'}):
    try:summary(dict(record,**change))
    except AssertionError:pass
    else:raise AssertionError('unsafe operation summary accepted')
    cases+=1
changed=copy.deepcopy(record);changed['native']['ipv6']['fallback']['stage']='REDACTED_SECRET'
try:summary(changed)
except AssertionError:pass
else:raise AssertionError('unknown receipt stage exposed')
cases+=1
namespace=functions('PYNATIVEFORWARD',('checksum','transit_frame','forwarded_frame_matches'),{'socket':socket,'struct':struct})
build=namespace['transit_frame'];matches=namespace['forwarded_frame_matches']
host=bytes.fromhex('020000000001');peer=bytes.fromhex('020000000002');token=bytes(range(16));identity=0x1234
valid=build(host,peer,token,identity,36)
assert matches(valid,host,peer,token,identity)
assert valid[:6]==peer and valid[6:12]==host and valid[12:14]==b'\x08\x00'
ip=valid[14:34];udp=valid[34:]
assert ip[0]==0x45 and ip[8:10]==bytes((36,17)) and struct.unpack('!H',ip[2:4])[0]==len(valid)-14
assert ip[12:16]==socket.inet_aton('198.51.100.42') and ip[16:20]==socket.inet_aton('8.8.8.8')
assert struct.unpack('!HHH',udp[:6])==(19256,19257,len(udp))
assert udp[8:]==b'scqa-ipv4-transit:'+token
for checked in (ip,ip[12:20]+struct.pack('!BBH',0,17,len(udp))+udp):
    checked+=b'\0'*(len(checked)%2)
    total=sum(struct.unpack('!%dH'%(len(checked)//2),checked))
    while total>65535:total=(total&65535)+(total>>16)
    assert total==65535, 'generated IPv4/UDP checksum invalid'
frames=[build(peer,host,token,identity,37),build(host,peer,token,identity,37),
        valid[:-1],valid+b'\0',build(host,peer,b'x'*16,identity,36),build(host,peer,token,identity+1,36)]
for offset in (0,6,12,14,16,18,20,22,23,24,26,30,34,36,38,40,len(valid)-1):
    changed=bytearray(valid);changed[offset]^=1;frames.append(bytes(changed))
for frame in frames:assert not matches(frame,host,peer,token,identity), 'invalid transit frame accepted'
print(f'HOST_QA_NATIVE_PACKET_OBSERVER_REGRESSIONS=PASS ({cases} counter cases, {len(frames)+1} frame cases)')
PYNATIVEPACKETFIXTURES

# Pure admission/ownership predicates only; never acquire a lock or control a unit.
python3 - "$root/scripts/qa/host-native-product-tun.sh" <<'PYNATIVEPAUSEFIXTURES'
import ast,copy,hashlib,json,re,stat,sys
from pathlib import Path
from types import SimpleNamespace
source=Path(sys.argv[1]).read_text().split("<<'PYNATIVEPAUSE'\n",1)[1].split('\nPYNATIVEPAUSE\n',1)[0]
names={'pause_unit_valid','pause_unit_diagnostic','pause_journal_valid','pause_guard_context','canonical','private_file','pause_receipt_valid','pause_completion_binding'}
nodes=[x for x in ast.parse(source).body if isinstance(x,ast.FunctionDef) and x.name in names]
assert {x.name for x in nodes}==names
timer='server-connect-activation-recover.timer';executor='server-connect-activation-recover.service';core='server-connect-smart-tun.service'
operation='a'*32;boot='11111111-2222-3333-4444-555555555555';ns=SimpleNamespace(st_dev=4,st_ino=4026532000)
lock=SimpleNamespace(st_dev=8,st_ino=101)
namespace={'json':json,'re':re,'stat':stat,'hashlib':hashlib,'timer':timer,'executor':executor,'core':core,
           'units':(timer,executor,core),'operation':operation,'boot':boot,'ns':ns,'lock_identity':lambda:lock}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<native recovery pause predicates>','exec'),namespace)
unit=namespace['pause_unit_valid'];journal=namespace['pause_journal_valid'];receipt_valid=namespace['pause_receipt_valid'];canonical=namespace['canonical']
diagnostic=namespace['pause_unit_diagnostic'];completion_binding=namespace['pause_completion_binding'];guard_context=namespace['pause_guard_context']
cases=0
def check(label,call,valid=False):
    global cases
    try:call()
    except (AssertionError,KeyError,TypeError,ValueError):assert not valid,label
    else:assert valid,label
    cases+=1
timer_fields={'Id':timer,'LoadState':'loaded','FragmentPath':'/etc/systemd/system/'+timer,
              'DropInPaths':'','Transient':'no','UnitFileState':'enabled','ActiveState':'active',
              'SubState':'waiting','Job':'0','Unit':executor}
idle_timer=dict(timer_fields,ActiveState='inactive',SubState='dead')
executor_fields={'Id':executor,'LoadState':'loaded','FragmentPath':'/etc/systemd/system/'+executor,
                 'DropInPaths':'','Transient':'no','UnitFileState':'static','ActiveState':'inactive',
                 'SubState':'dead','Job':'0','MainPID':'0','ControlPID':'0','ControlGroup':'',
                 'Result':'success','ExecMainCode':'1','ExecMainStatus':'0'}
check('original active enabled timer',lambda:unit(timer_fields,timer,'active'),True)
check('triggered timer active/running',lambda:unit(dict(timer_fields,SubState='running'),timer,'active'),True)
check('active elapsed timer',lambda:unit(dict(timer_fields,SubState='elapsed'),timer,'active'),True)
check('idle timer',lambda:unit(idle_timer,timer,'idle'),True)
check('idle executor',lambda:unit(executor_fields,executor,'idle'),True)
check('initially paused is not owned rearm obligation',lambda:unit(idle_timer,timer,'active'))
for field,value in (('FragmentPath','/run/systemd/system/'+timer),('LoadState','masked'),
                    ('DropInPaths','/run/untrusted.conf'),('Transient','yes'),('UnitFileState','disabled'),
                    ('Job','42'),('Unit',core)):
    check('timer rejects '+field,lambda field=field,value=value:unit(dict(timer_fields,**{field:value}),timer,'active'))
for field,value in (('ActiveState','activating'),('ActiveState','failed'),('Job','42'),('MainPID','123'),('ControlPID','456')):
    check('executor not positively idle '+field,lambda field=field,value=value:unit(dict(executor_fields,**{field:value}),executor,'idle'))
check('empty job is idle',lambda:unit(dict(executor_fields,Job=''),executor,'idle'),True)
guard_failed=dict(executor_fields,ActiveState='failed',SubState='failed',Result='exit-code',ExecMainCode='1',ExecMainStatus='1')
check('guard executor has paired inactive/dead quiescence',lambda:unit(executor_fields,executor,'guard-quiescent'),True)
check('guard executor retains observed exit-code failure',lambda:unit(guard_failed,executor,'guard-quiescent'),True)
check('guard executor permits empty no-job value',lambda:unit(dict(guard_failed,Job=''),executor,'guard-quiescent'),True)
for field,value in (('ActiveState','inactive'),('SubState','dead'),('Result','success'),('Result','signal'),
                    ('ExecMainCode','2'),('ExecMainStatus','9'),('MainPID','123'),('ControlPID','456'),('Job','42'),
                    ('ControlGroup','/system.slice/untrusted.service'),('FragmentPath','/run/systemd/system/'+executor),
                    ('DropInPaths','/run/untrusted.conf'),('UnitFileState','enabled'),('Id',core),('Transient','yes')):
    check('guard quiescence rejects '+field+'='+value,
          lambda field=field,value=value:unit(dict(guard_failed,**{field:value}),executor,'guard-quiescent'))
missing_group=dict(guard_failed);del missing_group['ControlGroup']
check('guard quiescence requires observed empty cgroup',lambda:unit(missing_group,executor,'guard-quiescent'))
check('inactive guard executor also requires empty cgroup',lambda:unit(dict(executor_fields,ControlGroup='/nonempty'),executor,'guard-quiescent'))
check('failed executor remains invalid for ordinary idle',lambda:unit(guard_failed,executor,'idle'))
check('failed executor remains invalid for completed proof',lambda:unit(guard_failed,executor,'completed'))
check('guard state cannot authorize timer',lambda:unit(idle_timer,timer,'guard-quiescent'))
assert diagnostic(guard_failed,executor)['control_group']=='empty'
safe=diagnostic(dict(guard_failed,ControlGroup='/secret/UNTRUSTED'),executor)
assert safe['control_group']=='nonempty-or-unavailable-redacted' and 'UNTRUSTED' not in repr(safe)
assert diagnostic(missing_group,executor)['control_group']=='nonempty-or-unavailable-redacted'
cases+=3
core_failed=dict(executor_fields,Id=core,FragmentPath='/etc/systemd/system/'+core,
                 ActiveState='failed',SubState='failed',Result='signal',ExecMainCode='2',ExecMainStatus='9')
check('authenticated failed core killed by SIGKILL',lambda:unit(core_failed,core,'sigkill'),True)
check('SIGKILL witness permits empty no-job value',lambda:unit(dict(core_failed,Job=''),core,'sigkill'),True)
for field,value in (('ActiveState','inactive'),('SubState','dead'),('Result','exit-code'),
                    ('ExecMainCode','1'),('ExecMainStatus','15'),('MainPID','123'),('ControlPID','456'),('Job','42'),
                    ('FragmentPath','/run/systemd/system/'+core),('DropInPaths','/run/untrusted.conf'),
                    ('UnitFileState','enabled'),('Id',executor)):
    check('SIGKILL witness rejects '+field,lambda field=field,value=value:unit(dict(core_failed,**{field:value}),core,'sigkill'))
core_inactive=dict(core_failed,ActiveState='inactive',SubState='dead',Result='success',ExecMainCode='1',ExecMainStatus='0')
check('inactive cannot replace the failed-core precondition',lambda:unit(core_inactive,core,'sigkill'))
check('failed cannot replace completed inactive baseline',lambda:unit(core_failed,core,'completed'))
check('inactive core remains completed-state requirement',lambda:unit(core_inactive,core,'completed'),True)
assert diagnostic(core_failed,core)['ExecMainCode']=='2'
assert diagnostic(dict(core_failed,ExecMainCode='UNTRUSTED'),core)['ExecMainCode']=='other-redacted'
cases+=2
completed_timer=dict(idle_timer,UnitFileState='disabled')
completed_executor=dict(executor_fields,Result='success',ExecMainStatus='0')
check('completed timer is disarmed',lambda:unit(completed_timer,timer,'completed'),True)
check('completed executor is successful and idle',lambda:unit(completed_executor,executor,'completed'),True)
check('enabled timer is not completed',lambda:unit(idle_timer,timer,'completed'))
check('disarmed timer cannot authorize normal resume',lambda:unit(completed_timer,timer,'owned'))
for field,value in (('ActiveState','active'),('SubState','running'),('Job','42')):
    check('completed timer refuses '+field,lambda field=field,value=value:unit(dict(completed_timer,**{field:value}),timer,'completed'))
for field,value in (('Job','42'),('MainPID','123'),('ControlPID','456'),('Result','exit-code'),('ExecMainStatus','1')):
    check('completed executor refuses '+field,lambda field=field,value=value:unit(dict(completed_executor,**{field:value}),executor,'completed'))
safe=diagnostic(dict(timer_fields,SubState='running'),timer)
assert safe['SubState']=='running' and safe['fragment_scope']=='installed' and safe['executor_matches']
untrusted=dict(timer_fields,FragmentPath='/secret/UNTRUSTED',DropInPaths='UNTRUSTED',Id='UNTRUSTED',Unit='UNTRUSTED',
               ActiveState='UNTRUSTED',SubState='UNTRUSTED',Job='UNTRUSTED',ExecStart='UNTRUSTED')
safe=diagnostic(untrusted,timer)
assert 'UNTRUSTED' not in repr(safe) and safe['fragment_scope']=='other-redacted'
assert not safe['id_matches'] and not safe['executor_matches'] and safe['Job']=='other-redacted'
cases+=2
record={'version':4,'intent_type':'smart_tun_native_pending_trial_v1','operation_id':operation,
        'phase':'trial_pending','revision':1,'deadline_uptime_sec':160,'boot_id':boot,
        'tunnel_interface':'sctunqa0','underlay_interface':'scqaedge0','core_start_attempted':True,
        'native':{'version':1,'startup_verified':True,'namespace_dev':ns.st_dev,'namespace_ino':ns.st_ino,
                  'link_index':22,'underlay_index':8,'nft_handle':16,'nft_name':'scnt_'+operation,'stop_reason':'',
                  'ipv4':{'address':'172.31.99.1/30','table':42424},'ipv6':{'address':'fd73:99::1/64','table':42426}}}
check('original pending',lambda:journal(record,operation,'pending',100),True)
check('exact deadline rejected',lambda:journal(record,operation,'pending',160))
check('different operation',lambda:journal(record,'b'*32,'pending',100))
for field,value in (('revision',2),('revision',True),('deadline_uptime_sec',True),('core_start_attempted',False)):
    check('journal rejects '+field,lambda field=field,value=value:journal(dict(record,**{field:value}),operation,'pending',100))
guard=copy.deepcopy(record);guard.update(phase='trial_stop_requested',revision=2);guard['native']['stop_reason']='guard'
off=copy.deepcopy(guard);off['native']['stop_reason']='off'
check('guard stop',lambda:journal(guard,operation,'guard',200),True)
check('operator removed still exact guard stop',lambda:journal(guard,operation,'removed',200),True)
check('durable Off before after-stop-request kill',lambda:journal(off,operation,'off',100),True)
empty_reason=copy.deepcopy(off);empty_reason['native']['stop_reason']=''
check('Off boundary requires native off intent',lambda:journal(empty_reason,operation,'off',100))
check('guard cannot impersonate Off',lambda:journal(guard,operation,'off',100))
for field,value in (('startup_verified',False),('link_index',True),('nft_handle',0),('nft_name','foreign')):
    changed=copy.deepcopy(record);changed['native'][field]=value
    check('native identity rejects '+field,lambda changed=changed:journal(changed,operation,'pending',100))
info=SimpleNamespace(st_dev=9,st_ino=102,st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
receipt={'version':1,'operation_id':operation,'kind':'pending','boot_id':boot,'namespace_dev':ns.st_dev,'namespace_ino':ns.st_ino,
         'lock_dev':lock.st_dev,'lock_ino':lock.st_ino,'receipt_dev':info.st_dev,'receipt_ino':info.st_ino,
         'deadline_uptime_sec':160,'journal_sha256':'b'*64,'unit_sha256':{name:'c'*64 for name in (timer,executor,core)},
         'link_index':22,'underlay_index':8,'nft_handle':16}
check('exact private receipt',lambda:receipt_valid(receipt,info,canonical(receipt)),True)
guard_receipt=dict(receipt,kind='guard')
def guard_checkpoint(value,current,fields,core_fields=core_inactive):
    receipt_valid(value,info,canonical(value))
    scoped=guard_context(value,current,operation)
    unit(fields,executor,'guard-quiescent' if scoped else 'idle')
    if scoped:unit(core_fields,core,'idle')
check('same guard operation permits actual quiescent failed executor',lambda:guard_checkpoint(guard_receipt,guard,guard_failed),True)
check('same guard operation permits ordinary inactive executor',lambda:guard_checkpoint(guard_receipt,guard,executor_fields),True)
check('pending receipt does not authorize failed guard state',lambda:guard_checkpoint(receipt,guard,guard_failed))
check('pending operation keeps strict idle',lambda:guard_checkpoint(receipt,record,guard_failed))
check('Off phase keeps strict idle despite old guard receipt',lambda:guard_checkpoint(guard_receipt,off,guard_failed))
recovered_guard=copy.deepcopy(guard);recovered_guard['phase']='trial_recovered'
check('later guard recovery uses strict inactive executor',lambda:guard_checkpoint(guard_receipt,recovered_guard,executor_fields),True)
check('later guard recovery cannot reuse failed-state exception',lambda:guard_checkpoint(guard_receipt,recovered_guard,guard_failed))
cleanup_guard=copy.deepcopy(guard);cleanup_guard.update(phase='trial_cleanup_pending',revision=4)
check('later cleanup cannot reuse failed-state exception',lambda:guard_checkpoint(guard_receipt,cleanup_guard,guard_failed))
for field,value in (('operation_id','d'*32),('boot_id','different'),('revision',3),('deadline_uptime_sec',161)):
    changed=dict(guard,**{field:value})
    check('guard context rejects journal '+field,lambda changed=changed:guard_checkpoint(guard_receipt,changed,guard_failed))
for field,value in (('namespace_ino',ns.st_ino+1),('link_index',23),('underlay_index',9),('nft_handle',17),('stop_reason','off')):
    changed=copy.deepcopy(guard);changed['native'][field]=value
    check('guard context rejects native '+field,lambda changed=changed:guard_checkpoint(guard_receipt,changed,guard_failed))
for field,value in (('operation_id','d'*32),('kind','unknown'),('boot_id','different'),('lock_ino',lock.st_ino+1)):
    changed=dict(guard_receipt,**{field:value})
    check('guard context retains receipt provenance '+field,lambda changed=changed:guard_checkpoint(changed,guard,guard_failed))
check('guard context requires inactive core',lambda:guard_checkpoint(guard_receipt,guard,guard_failed,core_failed))
for field,value in (('operation_id','d'*32),('kind','unknown'),('boot_id','different'),('namespace_ino',ns.st_ino+1),
                    ('lock_ino',lock.st_ino+1),('receipt_ino',info.st_ino+1),('version',True),('deadline_uptime_sec',0),
                    ('journal_sha256','malformed')):
    changed=dict(receipt,**{field:value})
    check('receipt rejects '+field,lambda changed=changed:receipt_valid(changed,info,canonical(changed)))
for field,value in (('st_ino',info.st_ino+1),('st_mode',stat.S_IFREG|0o644),('st_uid',1000),('st_nlink',2)):
    changed=SimpleNamespace(**dict(vars(info),**{field:value}))
    check('receipt file identity '+field,lambda changed=changed:receipt_valid(receipt,changed,canonical(receipt)))
check('partial receipt bytes',lambda:receipt_valid(receipt,info,canonical(receipt)[:-2]))
check('extra raw data',lambda:receipt_valid(receipt,info,canonical(receipt)+b'secret'))
changed=dict(receipt,journal={'private':'must not be persisted'})
check('no copied product journal',lambda:receipt_valid(changed,info,canonical(changed)))
raw=canonical(receipt);invocation='d'*32
binding=json.dumps([info.st_dev,info.st_ino,hashlib.sha256(raw).hexdigest()],separators=(',',':'))
check('same pre-proof receipt binding',lambda:completion_binding(binding,receipt,info,raw,invocation),True)
for value in ('','0'*32,'not-an-invocation'):
    check('no terminal disposal without invocation identity',lambda value=value:completion_binding(binding,receipt,info,raw,value))
check('different operation is not terminal authority',lambda:completion_binding(binding,dict(receipt,operation_id='e'*32),info,raw,invocation))
check('guard-recovered receipt alone is not Off completion',lambda:completion_binding(binding,dict(receipt,kind='guard'),info,raw,invocation))
check('receipt bytes changed during proof',lambda:completion_binding(binding,receipt,info,raw+b' ',invocation))
replaced=SimpleNamespace(**dict(vars(info),st_ino=info.st_ino+1))
replacement=dict(receipt,receipt_ino=replaced.st_ino);replacement_raw=canonical(replacement)
check('self-consistent replacement still differs from original proof binding',lambda:completion_binding(binding,replacement,replaced,replacement_raw,invocation))
for value in ('[]',json.dumps([True,info.st_ino,hashlib.sha256(raw).hexdigest()]),json.dumps([info.st_dev,info.st_ino,'bad'])):
    check('malformed terminal binding',lambda value=value:completion_binding(value,receipt,info,raw,invocation))
print(f'HOST_QA_NATIVE_RECOVERY_PAUSE_REGRESSIONS=PASS ({cases} ownership/state cases)')
PYNATIVEPAUSEFIXTURES

# The recovery unit has plain-text errors and pretty JSON success receipts.
# Extract only pure parsing functions; never run its observer/service calls.
python3 - "$root/scripts/qa/host-native-product-tun.sh" <<'PYPENDINGINVOCATIONFIXTURES'
import ast,copy,json,re,sys
from pathlib import Path
source=Path(sys.argv[1]).read_text().split("<<'PYNATIVEPENDINGFAIL'\n",1)[1].split('\nPYNATIVEPENDINGFAIL\n',1)[0]
names={'hex32','strict_json','pending_invocation_summary'}
nodes=[x for x in ast.parse(source).body if isinstance(x,ast.FunctionDef) and x.name in names]
assert {x.name for x in nodes}==names
namespace={'json':json,'re':re}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pending invocation parser>','exec'),namespace)
parse=namespace['pending_invocation_summary']
operation='a'*32;invocation='b'*32;boot='c'*32;stream='d'*32
secret='CREDENTIAL_SHOULD_NOT_APPEAR'
receipt={'operation_id':operation,'revision':1,'phase':'trial_pending','experiment_only':True,
         'guard_scheduled':True,'activation_ready':False,'vpn_verified':False,'recovery_verified':False}
def records(value):
    text=value if isinstance(value,str) else json.dumps(value,indent=2)
    return [{'__CURSOR':'qa:'+str(index),'_SYSTEMD_UNIT':'server-connect-activation-recover.service',
             '_SYSTEMD_INVOCATION_ID':invocation,'_BOOT_ID':boot,'_TRANSPORT':'stdout',
             '_STREAM_ID':stream,'_PID':'4242','MESSAGE':line}
            for index,line in enumerate(text.splitlines())]
cases=0
def check(label,rows,expected=None):
    global cases
    original=copy.deepcopy(rows)
    try:value=parse(rows,invocation,boot,operation)
    except (AssertionError,KeyError,TypeError,ValueError):value=None
    if expected is None:assert value is None,label
    else:assert isinstance(value,dict) and value.get('kind')==expected,(label,value)
    assert rows==original,label+' mutated input'
    assert secret not in json.dumps(value),label+' leaked redacted data'
    assert value is None or 'code' not in value,label+' invented product error code'
    cases+=1
    return value
check('multiline receipt',records(receipt),'receipt')
check('single-line receipt',records(json.dumps(receipt)),'receipt')
check('absent prearm receipt',records({'phase':'absent','experiment_only':True}),'receipt')
for message in ('Error: guard trial schema invalid','Error: guard trial trailing data'):
    value=check('known static error',records(message),'known-static-error')
    assert value['message']==message
    check('near-match is not classified',records(message+' '+secret),'redacted')
    check('duplicate errors are not a single record',records(message+'\n'+message),'redacted')
check('unknown plain error',records('Error: '+secret),'redacted')
check('arbitrary text',records(secret),'redacted')
value=check('unknown receipt fields redacted',records(dict(receipt,credential=secret)),'receipt')
assert value['other_fields_redacted'] is True and 'credential' not in value
for key,value in (('_SYSTEMD_UNIT','other.service'),('_SYSTEMD_INVOCATION_ID','e'*32),('_BOOT_ID','e'*32),
                  ('_TRANSPORT','journal'),('_STREAM_ID','0'*32),('_PID','1'),('_PID','bad')):
    rows=records(receipt)
    for row in rows:row[key]=value
    check('invalid attribution '+key,rows)
rows=records(receipt)
for row in rows:row['SYSTEMD_INVOCATION_ID']=row.pop('_SYSTEMD_INVOCATION_ID')
check('untrusted replacement field',rows)
for key,value in (('_STREAM_ID','e'*32),('_PID','4243')):
    rows=records(receipt)
    for row in rows[len(rows)//2:]:row[key]=value
    check('mixed '+key,rows)
rows=records(receipt);rows[-1]['__CURSOR']=rows[0]['__CURSOR']
check('duplicate journal row',rows)
check('wrong receipt operation',records(dict(receipt,operation_id='e'*32)))
check('missing operation on pending receipt',records({k:v for k,v in receipt.items() if k!='operation_id'}))
for key,value in (('revision',True),('revision',6),('phase',secret),('guard_scheduled',1)):
    check('invalid safe field '+key,records(dict(receipt,**{key:value})))
check('JSON wrapper is not a unit receipt',records({'ok':False,'error':{'code':'arbitrary','message':secret}}))
check('incomplete JSON',records(receipt)[:-1],'redacted')
check('duplicate JSON key',records(json.dumps(receipt).replace('"revision": 1','"revision": 1, "revision": 2')),'redacted')
check('multiple JSON documents',records(json.dumps(receipt)+'\n'+json.dumps(receipt)),'redacted')
check('empty journal',[])
check('too many rows',records('\n'.join(['{}']*129)))
check('oversized message',records('x'*4097))
print(f'HOST_QA_PENDING_INVOCATION_REGRESSIONS=PASS ({cases} attribution/redaction cases)')
PYPENDINGINVOCATIONFIXTURES
