#!/bin/sh
# Sourced only by the disconnected Docker native fixture. This is a core
# feasibility witness, not product ownership, durable creation or admission.
owned_tun_index=
owned_replacement_index=
owned_tun_intent=no
owned_replacement_intent=no
owned_core_pid=
owned_core_start=
owned_nft_intent=no
owned_foreign_nft=
owned_rule_intents=
owned_rule_receipts=

owned_boundary_snapshot() {
  # Preserve semantic object identity. Last-queue close changes carrier and
  # linkdown flags; these are expected and must not masquerade as deletion.
  python3 - "$@" <<'PYOWNEDSNAPSHOT'
import json,subprocess,sys
from pathlib import Path
def query(*args):
    return json.loads(subprocess.check_output(args,text=True))
def nft_semantics(value):
    # Counter values may advance during valid foreign traffic. Keep the
    # complete object/handle/expression; normalize only validated uint64s.
    if isinstance(value,list):
        return [nft_semantics(item) for item in value]
    if isinstance(value,dict):
        result={key:nft_semantics(item) for key,item in value.items()}
        counter=result.get('counter')
        if isinstance(counter,dict) and ('packets' in counter or 'bytes' in counter):
            assert all(type(counter.get(key)) is int and 0<=counter[key]<2**64 for key in ('packets','bytes')), 'invalid native nft counter'
            counter['packets']=counter['bytes']=0
        return result
    return value
def routes(family):
    rows=query('ip','-N','-j',family,'route','show','table','all')
    for row in rows:
        if 'flags' in row:
            row['flags']=[flag for flag in row['flags'] if flag!='linkdown']
    return sorted(rows,key=lambda row:json.dumps(row,sort_keys=True))
links=[]
for name in sys.argv[1:]:
    row=query('ip','-N','-j','-d','link','show','dev',name)[0]
    addresses=query('ip','-N','-j','addr','show','dev',name)[0]['addr_info']
    for address in addresses:
        assert not any(address.get(flag) or flag in address.get('flags',[]) for flag in ('tentative','dadfailed')), 'unsettled address'
    flags=Path('/sys/class/net')/name/'tun_flags'
    links.append({'ifindex':row['ifindex'],'ifname':name,'mtu':row['mtu'],
                  'ifalias':row.get('ifalias'), 'kind':row.get('linkinfo',{}).get('info_kind'),
                  'flags':sorted(set(row['flags'])-{'LOWER_UP','RUNNING','NO-CARRIER'}),
                  'tun_flags':flags.read_text().strip() if flags.exists() else None,
                  'addresses':sorted((a['family'],a['local'],a['prefixlen'],a['scope']) for a in addresses)})
print(json.dumps({'links':links,'routes4':routes('-4'),'routes6':routes('-6'),
                 'rules4':query('ip','-N','-j','-4','rule','show'),
                 'rules6':query('ip','-N','-j','-6','rule','show'),
                 'nft':nft_semantics(query('nft','-j','list','ruleset'))},sort_keys=True,separators=(',',':')))
PYOWNEDSNAPSHOT
}

owned_require_snapshot() {
  owned_expected=$1
  owned_phase=$2
  shift 2
  owned_actual=$(owned_boundary_snapshot "$@") || {
    echo "OWNED_TUN_BOUNDARY=FAIL ($owned_phase native observation failed)" >&2; return 1;
  }
  test "$owned_actual" != "$owned_expected" || return 0
  python3 - "$owned_phase" "$owned_expected" "$owned_actual" <<'PYOWNEDDIFF'
import difflib,json,sys
before=json.dumps(json.loads(sys.argv[2]),sort_keys=True,indent=2).splitlines()
after=json.dumps(json.loads(sys.argv[3]),sort_keys=True,indent=2).splitlines()
diff=list(difflib.unified_diff(before,after,fromfile='expected',tofile='observed',lineterm=''))
print('OWNED_TUN_BOUNDARY=FAIL ('+sys.argv[1]+' semantic native mismatch)',file=sys.stderr)
text='\n'.join(diff[:120])
print(text[:16000],file=sys.stderr)
if len(diff)>120 or len(text)>16000:print('(native diff truncated)',file=sys.stderr)
PYOWNEDDIFF
  return 1
}

owned_wait_addresses() {
  for owned_try in $(seq 1 40); do
    owned_addresses_ready=yes
    for owned_link do
      owned_addresses=$(ip -6 addr show dev "$owned_link") || return 1
      if printf '%s\n' "$owned_addresses" | grep -Eq 'tentative|dadfailed'; then owned_addresses_ready=no; fi
    done
    test "$owned_addresses_ready" = no || return 0
    sleep 0.1
  done
  echo 'OWNED_TUN_BOUNDARY=FAIL (IPv6 address state did not settle)' >&2
  return 1
}

owned_core_identity() {
  python3 - "$owned_core_pid" "$owned_core_start" "$core" <<'PYOWNEDPID'
import os,sys
pid,start,core=sys.argv[1:]
assert pid.isdigit() and int(pid)>1
with open('/proc/'+pid+'/stat') as f:actual=f.read().rsplit(')',1)[1].split()[19]
assert actual==start and os.path.realpath('/proc/'+pid+'/exe')==os.path.realpath(core), 'core process identity changed'
PYOWNEDPID
}

owned_start_core() {
  # timeout remains the parent of the exact observed core PID and bounds
  # this QA process even if the controller ceases making progress.
  timeout --signal=TERM --kill-after=4s 90s "$core" run -c "$client_cfg" \
    >/run/sc-qa-owned-core.log 2>&1 &
  client_pid=$!
  owned_core_pid=
  for owned_try in $(seq 1 50); do
    if [ -r "/proc/$client_pid/task/$client_pid/children" ]; then
      set -- $(cat "/proc/$client_pid/task/$client_pid/children")
      if [ "$#" = 1 ] && [ "$(readlink -f "/proc/$1/exe")" = "$(readlink -f "$core")" ]; then
        owned_core_pid=$1
        owned_core_start=$(python3 - "$1" <<'PYOWNEDSTART'
import sys
with open('/proc/'+sys.argv[1]+'/stat') as f:print(f.read().rsplit(')',1)[1].split()[19])
PYOWNEDSTART
        )
        break
      fi
    fi
    sleep 0.1
  done
  test -n "$owned_core_pid" || { tail -40 /run/sc-qa-owned-core.log >&2; return 1; }
  owned_core_identity
  owned_ready=no
  for owned_try in $(seq 1 40); do
    if [ "$(cat /sys/class/net/sctunqa0/ifindex)" = "$owned_tun_index" ] &&
       [ "$(cat /sys/class/net/sctunqa0/carrier)" = 1 ] &&
       expect_source 8.8.8.8 8.8.8.8 && expect_source 5.22.0.10 10.254.72.1; then
      owned_ready=yes
      break
    fi
    owned_core_identity || { tail -40 /run/sc-qa-owned-core.log >&2; return 1; }
    sleep 0.1
  done
  test "$owned_ready" = yes || { tail -40 /run/sc-qa-owned-core.log >&2; return 1; }
}

owned_stop_core() {
  owned_core_identity
  kill -s "$1" "$owned_core_pid"
  owned_rc=0
  wait "$client_pid" || owned_rc=$?
  client_pid=
  owned_core_pid=
  test "$owned_rc" = "$2" || {
    echo "OWNED_TUN_CORE_STOP=FAIL (signal=$1 exit=$owned_rc expected=$2)" >&2
    tail -40 /run/sc-qa-owned-core.log >&2
    return 1
  }
}

owned_add_rule() {
  # Record the exact, preflight-absent QA intent before the single native
  # mutation. This is not a production transaction or a priority-only owner.
  owned_rule_intents="$*
$owned_rule_intents"
  owned_family=$1
  shift
  ip "$owned_family" rule add "$@"
  owned_rule_receipt=$(python3 - "$owned_family" "$2" <<'PYOWNEDRULERECEIPT'
import json,subprocess,sys
family,priority=sys.argv[1],int(sys.argv[2])
rows=json.loads(subprocess.check_output(['ip','-N','-j',family,'rule','show']))
rows=[row for row in rows if row.get('priority')==priority]
assert len(rows)==1, 'QA rule creation observation ambiguous'
print(json.dumps({'family':family,'priority':priority,'rows':rows},sort_keys=True))
PYOWNEDRULERECEIPT
  )
  owned_rule_receipts="$owned_rule_receipt
$owned_rule_receipts"
}

owned_boundary_cleanup() {
  owned_cleanup_failed=no
  if [ -n "$owned_core_pid" ]; then
    if owned_core_identity; then kill -KILL "$owned_core_pid" 2>/dev/null || :; else owned_cleanup_failed=yes; fi
  fi
  if [ -n "$client_pid" ]; then
    kill -TERM "$client_pid" 2>/dev/null || :
    wait "$client_pid" || :
    client_pid=
    owned_core_pid=
  fi
  # Intent precedes creation. A failed command may already have changed the
  # kernel; unresolved identity is retained and fails cleanup, never adopted
  # by name. Verified absence is sufficient when a command had no effect.
  if python3 - "$owned_replacement_intent" "$owned_replacement_index" "$owned_tun_intent" "$owned_tun_index" <<'PYOWNEDLINKCLEANUP'
import json,subprocess,sys
def links():return json.loads(subprocess.check_output(['ip','-N','-j','-d','link','show']))
failed=False
for intent,index,alias,kind in ((sys.argv[1],sys.argv[2],'scqa-foreign-replacement','dummy'),(sys.argv[3],sys.argv[4],'scqa-owned-boundary','tun')):
    if intent!='yes':continue
    try:
        current=links()
        if not index:
            assert not any(row['ifname']=='sctunqa0' for row in current), 'creation intent has unresolved link identity'
            continue
        rows=[row for row in current if row['ifindex']==int(index)]
        if not rows:continue
        assert len(rows)==1 and rows[0].get('ifalias')==alias and rows[0].get('linkinfo',{}).get('info_kind')==kind, 'observed link identity changed'
        subprocess.run(['ip','link','del','dev',rows[0]['ifname']],check=False)
        assert not any(row['ifindex']==int(index) for row in links()), 'link deletion not verified'
    except (AssertionError,ValueError,KeyError,subprocess.SubprocessError) as error:
        print('OWNED_TUN_BOUNDARY_CLEANUP=FAIL ('+alias+': '+str(error)+')',file=sys.stderr);failed=True
sys.exit(1 if failed else 0)
PYOWNEDLINKCLEANUP
  then
    owned_tun_index=; owned_replacement_index=
    owned_tun_intent=no; owned_replacement_intent=no
  else owned_cleanup_failed=yes; fi
  if python3 - "$owned_rule_intents" "$owned_rule_receipts" <<'PYOWNEDRULECLEANUP'
import json,subprocess,sys
receipts=[json.loads(line) for line in sys.argv[2].splitlines() if line]
failed=False
for line in sys.argv[1].splitlines():
    if not line:continue
    args=line.split();family,priority=args[0],int(args[2])
    def rows():return [row for row in json.loads(subprocess.check_output(['ip','-N','-j',family,'rule','show'])) if row.get('priority')==priority]
    try:
        current=rows()
        if not current:continue
        expected=[receipt['rows'] for receipt in receipts if receipt['family']==family and receipt['priority']==priority]
        assert len(expected)==1 and current==expected[0], 'rule creation identity unresolved or changed'
        subprocess.run(['ip',family,'rule','del',*args[1:]],check=False)
        assert not rows(), 'exact rule deletion not verified'
    except (AssertionError,ValueError,KeyError,subprocess.SubprocessError) as error:
        print('OWNED_TUN_BOUNDARY_CLEANUP=FAIL ('+family+' rule '+str(priority)+': '+str(error)+')',file=sys.stderr);failed=True
sys.exit(1 if failed else 0)
PYOWNEDRULECLEANUP
  then owned_rule_intents=; owned_rule_receipts=; else owned_cleanup_failed=yes; fi
  if [ "$owned_nft_intent" = yes ]; then
    if python3 - "$owned_foreign_nft" <<'PYOWNEDNFTCLEANUP'
import json,subprocess,sys
def tables():return json.loads(subprocess.check_output(['nft','-j','list','tables']))['nftables']
def present():return any(row.get('table',{}).get('family')=='inet' and row['table'].get('name')=='sing-box' for row in tables())
if present():
    assert sys.argv[1], 'nft creation intent has unresolved identity'
    current=json.loads(subprocess.check_output(['nft','-j','list','table','inet','sing-box']))
    assert current==json.loads(sys.argv[1]), 'foreign table identity changed'
    subprocess.run(['nft','delete','table','inet','sing-box'],check=False)
    assert not present(), 'nft table deletion not verified'
PYOWNEDNFTCLEANUP
    then owned_nft_intent=no; else owned_cleanup_failed=yes; fi
  fi
  rm -f /run/sc-qa-owned-core.log /run/sc-qa-owned-core-version || owned_cleanup_failed=yes
  test "$owned_cleanup_failed" = no
}

owned_tun_boundary_trial() {
  test "$ipv6_trial" = yes && test "$payload_trial" = yes
  test -f /.dockerenv && test "$(ps -p 1 -o comm=)" = systemd
  test ! -e /sys/class/net/sctunqa0 && test ! -e /sys/class/net/scqaowned0
  # Exact occupied destinations/tables/priorities reject before fixture
  # creation. Nothing in this probe permits adopting an existing owner.
  python3 - <<'PYOWNEDABSENCE'
import json,subprocess
for family in ('-4','-6'):
    rules=json.loads(subprocess.check_output(['ip','-N','-j',family,'rule','show']))
    assert not any(29800<=r.get('priority',-1)<=30020 for r in rules), 'QA rule range occupied'
    routes=json.loads(subprocess.check_output(['ip','-N','-j',family,'route','show','table','all']))
    assert not any(str(r.get('table')) in ('42740','42741') for r in routes), 'QA route table occupied'
tables=json.loads(subprocess.check_output(['nft','-j','list','tables']))['nftables']
assert not any(x.get('table',{}).get('family')=='inet' and x['table'].get('name')=='sing-box' for x in tables), 'foreign nft table already exists'
PYOWNEDABSENCE
  owned_baseline=$(owned_boundary_snapshot)
  "$core" version >/run/sc-qa-owned-core-version
  grep -Fx 'sing-box version 1.14.3' /run/sc-qa-owned-core-version >/dev/null
  grep -F 'with_gvisor' /run/sc-qa-owned-core-version >/dev/null
  cat /run/sc-qa-owned-core-version
  sha256sum "$core"

  /root/qa-tun-config-qa >"$client_cfg"
  python3 - "$client_cfg" <<'PYOWNEDCONFIG'
import json,sys
with open(sys.argv[1]) as f:config=json.load(f)
assert len(config['inbounds'])==1 and config['inbounds'][0]['type']=='tun'
# Deliberately replace, not merge, the automatic inbound. In particular a
# retained IPv6 address can create legacy special rules even auto_route=false.
config['inbounds']=[{'type':'tun','tag':'tun-in','interface_name':'sctunqa0',
    'address':[],'mtu':1400,'stack':'gvisor','auto_route':False,'auto_redirect':False,
    'dns_mode':'disabled','iproute2_table_index':42740,'iproute2_rule_index':30000,
    'auto_redirect_iproute2_fallback_rule_index':30020}]
config['route']['default_mark']=0x7420
with open(sys.argv[1],'w') as f:json.dump(config,f)
PYOWNEDCONFIG
  chmod 0600 "$client_cfg"
  "$core" check -c "$client_cfg"
  echo OWNED_TUN_ADDRESSLESS_GVISOR_CONFIG=PASS

  # Explicit gVisor at MTU1400 enables virtio/GSO in this pinned core;
  # precreate a matching persistent, no-PI, single-queue TUN.
  owned_tun_intent=yes
  ip tuntap add dev sctunqa0 mode tun vnet_hdr
  owned_tun_index=$(cat /sys/class/net/sctunqa0/ifindex)
  # Core attachment raises carrier and can trigger kernel link-local IPv6
  # generation later than the initial UP. Freeze address generation before
  # UP so the complete manager-owned address/dependency receipt is stable.
  ip link set dev sctunqa0 addrgenmode none
  ip link set dev sctunqa0 alias scqa-owned-boundary mtu 1400 up
  ip -4 addr add 172.31.99.1/30 dev sctunqa0
  ip -6 addr add fd73:99::1/64 dev sctunqa0 nodad
  # Separately owned payloads, deliberately absent from the core config.
  ip -4 addr add 172.31.98.9/32 dev sctunqa0
  ip -6 addr add fd73:98::9/128 dev sctunqa0 nodad
  ip -4 route add 198.18.40.0/24 dev sctunqa0 table 42741 proto 187 metric 42001
  ip -6 route add 2001:db8:40::/64 dev sctunqa0 table 42741 proto 187 metric 42001
  for owned_dest in 8.8.8.8/32 5.22.0.10/32; do
    ip -4 route add "$owned_dest" dev sctunqa0 src 172.31.99.1 table 42740 proto 186
  done
  for owned_dest in 2001:db8:8::8/128 2001:db8:5::10/128 2001:db8:5::11/128 2001:db8:8::9/128; do
    ip -6 route add "$owned_dest" dev sctunqa0 src fd73:99::1 table 42740 proto 186
  done
  # The mark exception is before capture and routes core Direct/VLESS
  # outbound sockets over the original main underlay, avoiding recursion.
  owned_add_rule -4 priority 29800 fwmark 0x7420 lookup main
  owned_add_rule -6 priority 29800 fwmark 0x7420 lookup main
  owned_add_rule -4 priority 29900 to 8.8.8.8/32 lookup 42740
  owned_add_rule -4 priority 29901 to 5.22.0.10/32 lookup 42740
  owned_add_rule -6 priority 29900 to 2001:db8:8::8/128 lookup 42740
  owned_add_rule -6 priority 29901 to 2001:db8:5::10/128 lookup 42740
  owned_add_rule -6 priority 29902 to 2001:db8:5::11/128 lookup 42740
  owned_add_rule -6 priority 29903 to 2001:db8:8::9/128 lookup 42740
  owned_add_rule -4 priority 30003 to 198.18.41.0/24 lookup 42741
  owned_add_rule -6 priority 30003 to 2001:db8:41::/64 lookup 42741
  owned_add_rule -4 priority 30020 fwmark 0x7421 lookup 42741
  owned_add_rule -6 priority 30020 fwmark 0x7421 lookup 42741
  owned_nft_intent=yes
  nft -f - <<'OWNEDNFT'
table inet sing-box {
  chain qa_foreign_owner {
    counter comment "independent QA owner: must survive core lifecycle"
  }
}
OWNEDNFT
  owned_foreign_nft=$(nft -j list table inet sing-box)
  owned_flags=$(cat /sys/class/net/sctunqa0/tun_flags)
  python3 - "$owned_flags" <<'PYOWNEDFLAGS'
import sys
flags=int(sys.argv[1],16)
assert flags & 0x5801 == 0x5801 and not flags & 0x0100, 'persistent/no-PI/vnet-header/single-queue mismatch'
PYOWNEDFLAGS
  echo "OWNED_TUN_CREATED(ifindex=$owned_tun_index mtu=1400 flags=$owned_flags)"
  owned_wait_addresses sctunqa0
  owned_before_start=$(owned_boundary_snapshot sctunqa0)
  owned_start_core
  owned_require_snapshot "$owned_before_start" core-start sctunqa0
  echo OWNED_TUN_NO_CORE_ROUTE_RULE_NFT_CREATION=PASS
  python3 - <<'PYOWNEDCAPTURE'
import json,subprocess
for family,destination in (('-4','5.22.0.10'),('-6','2001:db8:5::11')):
    def route(*extra):return json.loads(subprocess.check_output(['ip','-N','-j',family,'route','get',destination,*extra]))
    captured=route();bypassed=route('mark','0x7420')
    assert len(captured)==1 and captured[0]['dev']=='sctunqa0', 'Direct destination bypassed the QA TUN'
    assert len(bypassed)==1 and bypassed[0]['dev']=='scqaedge0', 'core mark did not select the underlay'
PYOWNEDCAPTURE

  expect_source 8.8.8.8 8.8.8.8
  udp_path 8.8.8.8 8.8.8.8 owned-foreign reply
  owned_direct_tx=$(cat /sys/class/net/sctunqa0/statistics/tx_packets)
  expect_source 5.22.0.10 10.254.72.1
  udp_path 5.22.0.10 10.254.72.1 owned-domestic reply
  test "$(cat /sys/class/net/sctunqa0/statistics/tx_packets)" -gt "$owned_direct_tx"
  ipv6_path tcp 2001:db8:8::8 2001:db8:8::8 reply
  ipv6_path udp 2001:db8:8::8 2001:db8:8::8 reply
  ipv6_path tcp 2001:db8:5::10 2001:db8:5::10 reply
  ipv6_path udp 2001:db8:5::10 2001:db8:5::10 reply
  owned_direct_tx=$(cat /sys/class/net/sctunqa0/statistics/tx_packets)
  ipv6_path tcp 2001:db8:5::11 fd73:1::1 reply
  ipv6_path udp 2001:db8:8::9 fd73:1::1 reply
  test "$(cat /sys/class/net/sctunqa0/statistics/tx_packets)" -gt "$owned_direct_tx"
  payload_path tcp 8.8.8.8 8.8.8.8 reply
  payload_path udp 8.8.8.8 8.8.8.8 reply
  test "$(direct_witness_packets)" = "$witness_baseline"
  test "$(direct_udp_witness_packets)" = "$udp_witness_baseline"
  test "$(ipv6_foreign_tcp_direct_packets)" = "$ipv6_foreign_tcp_baseline"
  test "$(ipv6_foreign_udp_direct_packets)" = "$ipv6_foreign_udp_baseline"
  test "$(ipv6_override_direct_packets)" = "$ipv6_override_baseline"
  test "$(ipv6_override_udp_direct_packets)" = "$ipv6_override_udp_baseline"
  test "$(payload_tcp_direct_packets)" = "$payload_tcp_baseline"
  test "$(payload_udp_direct_packets)" = "$payload_udp_baseline"
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  echo OWNED_TUN_REAL_DUALSTACK_AND_PAYLOAD=PASS
  echo OWNED_TUN_MARKED_DIRECT_AND_HOSTING=PASS

  owned_before=$(owned_boundary_snapshot sctunqa0)
  owned_stop_core KILL 137
  owned_require_snapshot "$owned_before" SIGKILL sctunqa0
  echo "OWNED_TUN_AFTER_SIGKILL(ifindex=$(cat /sys/class/net/sctunqa0/ifindex) flags=$(cat /sys/class/net/sctunqa0/tun_flags))"
  echo OWNED_TUN_SIGKILL_PRESERVES_FOREIGN_OBJECTS=PASS

  owned_start_core
  owned_require_snapshot "$owned_before" core-restart sctunqa0
  # Rename requires a short administrative down/up in this controlled QA
  # fixture. Snapshot AFTER that intentional event, before the core stop.
  ip link set dev sctunqa0 down
  ip link set dev sctunqa0 name scqaowned0
  ip link set dev scqaowned0 up
  ip -4 addr replace 172.31.98.9/32 dev scqaowned0
  ip -6 addr replace fd73:98::9/128 dev scqaowned0 nodad
  ip -4 route replace 198.18.40.0/24 dev scqaowned0 table 42741 proto 187 metric 42001
  ip -6 route replace 2001:db8:40::/64 dev scqaowned0 table 42741 proto 187 metric 42001
  owned_replacement_intent=yes
  ip link add sctunqa0 type dummy
  owned_replacement_index=$(cat /sys/class/net/sctunqa0/ifindex)
  test "$owned_replacement_index" != "$owned_tun_index"
  ip link set dev sctunqa0 alias scqa-foreign-replacement mtu 1350 up
  ip -4 addr add 172.31.97.9/32 dev sctunqa0
  ip -6 addr add fd73:97::9/128 dev sctunqa0 nodad
  ip -4 route add 198.18.42.0/24 dev sctunqa0 table 42741 proto 187 metric 42002
  ip -6 route add 2001:db8:42::/64 dev sctunqa0 table 42741 proto 187 metric 42002
  # New link-local DAD must settle before freezing a semantic baseline.
  owned_wait_addresses scqaowned0 sctunqa0
  owned_before=$(owned_boundary_snapshot scqaowned0 sctunqa0)
  owned_stop_core TERM 0
  owned_require_snapshot "$owned_before" renamed-graceful-stop scqaowned0 sctunqa0
  test "$(cat /sys/class/net/scqaowned0/ifindex)" = "$owned_tun_index"
  test "$(cat /sys/class/net/scqaowned0/tun_flags)" = "$owned_flags"
  test "$(cat /sys/class/net/sctunqa0/ifindex)" = "$owned_replacement_index"
  echo "OWNED_TUN_AFTER_GRACEFUL(original_ifindex=$owned_tun_index replacement_ifindex=$owned_replacement_index flags=$owned_flags)"
  echo OWNED_TUN_RENAME_REPLACEMENT_GRACEFUL_PRESERVED=PASS
  owned_boundary_cleanup
  owned_require_snapshot "$owned_baseline" explicit-native-cleanup
  expect_source 8.8.8.8 10.254.72.1
  ipv6_path tcp 2001:db8:8::8 fd73:1::1 reply
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  echo OWNED_TUN_NATIVE_BOUNDARY_CLEANUP=PASS
}
