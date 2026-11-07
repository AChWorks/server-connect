#!/usr/bin/env bash
# Disposable, explicitly authorized Linux host only. Deliberately narrow /32
# root-network-namespace TUN field trial; NOT product Smart Routing admission.
# Foreign network resources are never flushed or adopted. Optional pinned
# Iranian HTTPS sample is an independent Direct observation, not geo routing.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset PYTHONPATH PYTHONHOME PYTHONOPTIMIZE SC_FIELD_RECOVERY_LOCK_FD
work=/root/server-connect-field-root-qa
core=/opt/server-connect/current/bin/sing-box
manager=/usr/local/bin/server-connect
coreunit=server-connect-field-root-core
watch=server-connect-field-root-recovery
tun=scfhrt0
table=42441
priority=10391
mask=0x00ff0000
mark=0x00530000
ip4=''
owner=''
die() { echo "REFUSED: $*" >&2; exit 2; }
[[ $# == 4 || $# == 6 ]] || die 'usage: EXPECTED_HOSTNAME EXPECTED_PUBLIC_IPV4 UNDERLAY_INTERFACE FOREIGN_HTTPS_IPV4 [IRAN_HTTPS_FQDN IRAN_HTTPS_IPV4]'
expected_host=$1; expected_ip=$2; underlay=$3; foreign=$4
domestic_host=''; domestic=''
if [[ $# == 6 ]]; then domestic_host=$5; domestic=$6; fi
[[ "$expected_host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,100}$ && "$expected_ip" =~ ^[0-9.]+$ &&
   "$underlay" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$foreign" =~ ^[0-9.]+$ ]] || die 'invalid host binding'
if [[ -n "$domestic" ]]; then
  [[ "$domestic_host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,100}$ && "$domestic" =~ ^[0-9.]+$ ]] || die 'invalid Iranian HTTPS witness'
fi
[[ $EUID == 0 && $(hostname) == "$expected_host" ]] || die 'wrong host/privilege'
[[ $(. /etc/os-release; echo "$ID:$VERSION_ID") == debian:12 ]] || die 'expected disposable Debian 12'
[[ -x $manager && -x $core && -c /dev/net/tun ]] || die 'installed manager/core/TUN required'
[[ $(systemctl is-active ssh) == active ]] || die 'SSH unavailable'
[[ "$(readlink /proc/1/ns/net)" == "$(readlink /proc/self/ns/net)" ]] || die 'not the root network namespace'
[[ ! -e $work && ! -L $work && ! -e /sys/class/net/$tun ]] || die 'task resource occupied'
for unit in "$coreunit.service" "$watch.service" "$watch.timer"; do
  [[ $(systemctl show "$unit" -p LoadState --value 2>/dev/null) == not-found ]] || die "existing or unknown unit $unit"
done
ip -4 addr show dev "$underlay" | grep -Fq "inet $expected_ip/" || die 'underlay identity changed'
python3 - "$expected_ip" "$foreign" "$domestic_host" "$domestic" <<'PY'
import hashlib,ipaddress,json,pathlib,socket,sys
local,foreign,name,domestic=sys.argv[1:]
for text in (local,foreign)+((domestic,) if domestic else ()):
 a=ipaddress.ip_address(text)
 assert a.version == 4 and a.is_global and not a.is_private and not a.is_reserved
assert local != foreign and (not domestic or len({local,foreign,domestic})==3)
if domestic:
 p=pathlib.Path('/root/server-connect-field-iran-geo-2026-10.json')
 assert p.is_file() and not p.is_symlink() and p.stat().st_size < 128000
 raw=p.read_bytes()
 assert hashlib.sha256(raw).hexdigest()=='c1d00c21ff2df3814d4f04f28fb651401a6c0afb2c9ebad35b70a878b011dc6c'
 record=json.loads(raw)
 assert record['country']=='IR' and record['as_of']=='2026-10-01' and record['schema_version']==1
 assert record['prefix_sha256']=='edb8fc88cff754e9622695e03d980afec6640939cf53627f8800ac54d9170f0e'
 assert any(ipaddress.ip_address(domestic) in ipaddress.ip_network(pfx) for pfx in record['ipv4'])
 ips={v[4][0] for v in socket.getaddrinfo(name,443,socket.AF_INET,socket.SOCK_STREAM)}
 assert domestic in ips, 'observed DNS does not include the pinned domestic address'
 print('ROOT_IRAN_IP_PINNED_ESTIMATE_AND_DNS=PASS',flush=True)
PY
ip -4 route get "$foreign" | grep -Fq "dev $underlay" || die 'foreign baseline underlay unknown'
if [[ -n "$domestic" ]]; then
  ip -4 route get "$domestic" | grep -Fq "dev $underlay" || die 'Iranian witness baseline underlay unknown'
fi
[[ $(ip -4 rule show | grep -c -E "(^| )$priority:|lookup $table($| )" || :) == 0 ]] || die 'foreign RPDB ownership'
[[ -z $(ip -4 route show table "$table") ]] || die 'foreign table routes present'
[[ $(nft list tables | grep -c -E '^table inet scfhr_' || :) == 0 ]] || die 'existing task-like nft table'
for unit in server-connect-smart-tun.service server-connect-smart-health.timer server-connect-activation-recover.timer; do
  [[ $(systemctl is-active "$unit" 2>/dev/null || :) == inactive ]] || die 'product native/guard active'
done
for command in smart-tun-trial-status activation-journal-status; do
  "$manager" --json "$command" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["data"]["phase"]=="absent"' || die 'product journal exists'
done
"$manager" --json status | python3 -c 'import json,sys;r=json.load(sys.stdin);assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive"' || die 'product not Direct'
[[ $(sysctl -n net.ipv4.tcp_fwmark_accept) == 0 ]] || die 'unexpected foreign sysctl policy'
# No traffic can be captured before guarded nft rules are installed; a narrow
# test IP must not already host a long-lived service/management connection.
[[ -z $(ss -H -4tan state established | grep -F "$foreign:" || :) ]] || die 'existing foreign destination connections'
if [[ -n "$domestic" ]]; then
  [[ -z $(ss -H -4tan state established | grep -F "$domestic:" || :) ]] || die 'existing Iranian witness connections'
fi
baseline_routes=$(ip -4 route show table all | sha256sum | cut -d' ' -f1)
baseline_rules=$(ip -4 rule show | sha256sum | cut -d' ' -f1)
baseline_raw=$(iptables -t raw -S | sha256sum | cut -d' ' -f1)
baseline_nat=$(iptables -t nat -S | sha256sum | cut -d' ' -f1)
boot=$(cat /proc/sys/kernel/random/boot_id)
run_id=$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')
[[ "$run_id" =~ ^[0-9a-f]{16}$ ]] || die 'random owner unavailable'
owner="scfhr_$run_id"
mkdir -m 700 "$work"
: > "$work/recovery.lock"
printf '%s\n' "$owner" > "$work/owner"
printf '%s\n' "$boot" > "$work/boot"
printf '%s\n' "$baseline_routes" "$baseline_rules" "$baseline_raw" "$baseline_nat" > "$work/baseline"
cat > "$work/recover.sh" <<'RECOVER'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
work=/root/server-connect-field-root-qa
coreunit=server-connect-field-root-core
tun=scfhrt0
table=42441
priority=10391
fail() { echo "ROOT_RECOVERY_UNCERTAIN: $*" >&2; exit 3; }
# Timer and EXIT cleanup share one open-file-description lock. The parent
# finalizer retains its inherited FD through watchdog disarm and file cleanup.
[[ -d "$work" && ! -L "$work" && -f "$work/recovery.lock" && ! -L "$work/recovery.lock" ]] || fail 'recovery lock absent or replaced'
if [[ ${SC_FIELD_RECOVERY_LOCK_FD:-} == 9 ]]; then
  [[ /proc/self/fd/9 -ef "$work/recovery.lock" ]] || fail 'inherited recovery lock identity differs'
else
  [[ -z ${SC_FIELD_RECOVERY_LOCK_FD:-} ]] || fail 'invalid inherited recovery lock'
  exec 9<"$work/recovery.lock" || fail 'cannot open recovery lock'
fi
flock -x -w 20 9 || fail 'another exact recovery still holds the lock'
[[ /proc/self/fd/9 -ef "$work/recovery.lock" ]] || fail 'recovery lock changed while waiting'
[[ -f "$work/owner" && -f "$work/boot" && -f "$work/baseline" ]] || fail 'owner receipt absent'
owner=$(cat "$work/owner")
[[ "$owner" =~ ^scfhr_[0-9a-f]{16}$ ]] || fail 'owner receipt invalid'
boot=$(cat "$work/boot")
[[ "$boot" == "$(cat /proc/sys/kernel/random/boot_id)" ]] || fail 'boot changed; kernel resource identity unknown'
mapfile -t baseline < "$work/baseline"
[[ ${#baseline[@]} == 4 ]] || fail 'baseline incomplete'
for digest in "${baseline[@]}"; do [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail 'baseline invalid'; done
recorded=''; active_digest=''; retired_digest=''
load_nft_receipts() {
  [[ -s "$work/nft-receipt" && -s "$work/nft-handle" && -s "$work/nft-retired-receipt" ]] || fail 'nft effect-before-receipt; preserve unknown graph'
  recorded=$(cat "$work/nft-handle")
  active_digest=$(cat "$work/nft-receipt")
  retired_digest=$(cat "$work/nft-retired-receipt")
  [[ "$recorded" =~ ^[1-9][0-9]*$ && "$active_digest" =~ ^[0-9a-f]{64}$ &&
     "$retired_digest" =~ ^[0-9a-f]{64}$ && "$active_digest" != "$retired_digest" ]] || fail 'nft graph receipts invalid'
}
intent_text() {
  printf '%s\n' "$1" "$owner" "$boot" "$recorded" "$active_digest" "$retired_digest"
}
verify_intent() {
  [[ -f "$work/$1" && ! -L "$work/$1" ]] || return 1
  cmp -s "$work/$1" <(intent_text "$1")
}
persist_intent() {
  case "$1" in capture-retire-intent|nft-remove-intent) ;; *) fail 'invalid recovery intent';; esac
  if [[ -e "$work/$1" || -L "$work/$1" ]]; then
    verify_intent "$1" || fail 'recovery intent differs from exact operation'
  else
    ( set -o noclobber; intent_text "$1" > "$work/$1" ) || fail 'cannot publish recovery intent'
  fi
  # Re-sync a matching earlier intent too: its first fsync may have failed.
  sync -f "$work/$1" "$work" || fail 'recovery intent durability unavailable'
}
nft_table_present() {
  local tables count
  tables=$(nft list tables) || fail 'nft table inventory unavailable'
  count=$(printf '%s\n' "$tables" | grep -Fxc "table inet $owner" || :)
  [[ "$count" == 0 || "$count" == 1 ]] || fail 'nft table inventory ambiguous'
  [[ "$count" == 1 ]]
}
observe_nft_graph() {
  nft -j -a list table inet "$owner" | python3 -c '
import hashlib,json,sys
owner,handle=sys.argv[1:]
obj=json.load(sys.stdin)["nftables"]
tables=[item["table"] for item in obj if "table" in item]
assert len(tables)==1 and tables[0].get("family")=="inet" and tables[0].get("name")==owner
assert type(tables[0].get("handle")) is int and tables[0]["handle"]==int(handle)
for item in obj:
 for record in item.values():
  if isinstance(record,dict):
   record.pop("handle",None)
   for expr in record.get("expr",[]):
    if "counter" in expr: expr["counter"]={}
raw=json.dumps(obj,sort_keys=True,separators=(",",":"))
print(hashlib.sha256(raw.encode()).hexdigest())' "$owner" "$recorded"
}
# First retire capture while the independently hooked final-egress guard
# remains. Only the originally receipted graph or its precomputed exact
# capture-free graph is permitted; the latter also requires durable intent.
if nft_table_present; then
  [[ $(nft -a list table inet "$owner" | grep -Fc "table inet $owner {") == 1 ]] || fail 'nft table identity changed'
  load_nft_receipts
  observed=$(observe_nft_graph) || fail 'owned nft graph or handle unreadable'
  if [[ "$observed" == "$active_digest" ]]; then
    [[ ! -e "$work/nft-remove-intent" ]] || fail 'active graph reappeared after final removal intent'
    persist_intent capture-retire-intent
    nft flush chain inet "$owner" capture || fail 'cannot retire capture'
    observed=$(observe_nft_graph) || fail 'retired nft graph unreadable'
    [[ "$observed" == "$retired_digest" ]] || fail 'capture retirement changed an unowned graph'
  elif [[ "$observed" == "$retired_digest" ]]; then
    verify_intent capture-retire-intent || fail 'capture-free graph has no exact retirement intent'
  else
    fail 'foreign nft graph drift; do not flush'
  fi
elif [[ -e "$work/nft-receipt" || -e "$work/nft-handle" || -e "$work/nft-retired-receipt" ]]; then
  load_nft_receipts
  verify_intent capture-retire-intent && verify_intent nft-remove-intent || fail 'receipted containment vanished without final removal intent'
fi
state=$(systemctl show "$coreunit.service" -p LoadState --value)
if [[ "$state" != not-found ]]; then
  cmd=$(systemctl show "$coreunit.service" -p ExecStart --value)
  [[ "$cmd" == *"/opt/server-connect/current/bin/sing-box"* && "$cmd" == *"$work/config.json"* ]] || fail 'core unit ownership unproven'
  systemctl stop "$coreunit.service" || fail 'owned core stop failed'
  [[ $(systemctl is-active "$coreunit.service" 2>/dev/null || :) == inactive ]] || fail 'owned core still running'
fi
# Deletion is exact-value only; no flush of a shared routing/firewall table.
if ip -4 rule show | grep -q -E "^$priority:"; then
  ip -4 rule show | grep -q -E "^$priority:.*fwmark 0x530000/0xff0000.*lookup $table" || fail 'RPDB slot replaced'
  ip -4 rule del priority "$priority" fwmark 0x00530000/0x00ff0000 table "$table" || fail 'owned RPDB delete failed'
fi
if [[ -n $(ip -4 route show table "$table") ]]; then
  rows=$(ip -4 route show table "$table")
  [[ $(printf '%s\n' "$rows" | wc -l) -le 2 ]] || fail 'owned route table modified'
  if printf '%s\n' "$rows" | grep -q '^default dev scfhrt0 '; then
    ip -4 route del default dev "$tun" table "$table" metric 10 || fail 'owned TUN route delete failed'
  fi
  if ip -4 route show table "$table" | grep -q '^unreachable default '; then
    ip -4 route del unreachable default table "$table" metric 100 || fail 'owned fallback delete failed'
  fi
  [[ -z $(ip -4 route show table "$table") ]] || fail 'routing table not restored'
fi
[[ ! -e /sys/class/net/$tun ]] || fail 'TUN remains after core stop; ownership uncertain'
if nft_table_present; then
  load_nft_receipts
  verify_intent capture-retire-intent || fail 'final removal lacks capture retirement intent'
  observed=$(observe_nft_graph) || fail 'final guard identity unavailable'
  [[ "$observed" == "$retired_digest" ]] || fail 'foreign nft graph changed before final removal'
  persist_intent nft-remove-intent
  observed=$(observe_nft_graph) || fail 'final guard identity changed during durable intent'
  [[ "$observed" == "$retired_digest" ]] || fail 'foreign nft graph changed during durable intent'
  nft delete table inet "$owner" || fail 'owned nft table delete failed'
fi
if nft_table_present; then fail 'owned nft table remains after final removal'; fi
[[ $(ip -4 route show table all | sha256sum | cut -d' ' -f1) == "${baseline[0]}" ]] || fail 'host IPv4 routes differ from baseline'
[[ $(ip -4 rule show | sha256sum | cut -d' ' -f1) == "${baseline[1]}" ]] || fail 'host IPv4 RPDB differs from baseline'
[[ $(iptables -t raw -S | sha256sum | cut -d' ' -f1) == "${baseline[2]}" ]] || fail 'foreign raw policy changed'
[[ $(iptables -t nat -S | sha256sum | cut -d' ' -f1) == "${baseline[3]}" ]] || fail 'foreign NAT policy changed'
[[ $(systemctl is-active ssh) == active ]] || fail 'host SSH inactive'
echo 'ROOT_HOST_NETWORK_RESTORED=PASS'
RECOVER
chmod 700 "$work/recover.sh"
# Before prearming, only private data files exist. Never touch network yet.
prearm_cleanup() { rc=$?; trap - EXIT; rm -f "$work"/{owner,boot,baseline,recover.sh,config.json,provider-ip,provider-port,foreign-ip,direct-exit,nft.txt,nft-receipt,nft-handle,nft-retired-receipt,capture-retire-intent,nft-remove-intent,recovery.lock}; rmdir "$work" 2>/dev/null || :; exit "$rc"; }
trap prearm_cleanup EXIT
python3 - "$work" "$tun" "$underlay" "$foreign" "$domestic" <<'PY'
import json,ipaddress,pathlib,socket,sys
w=pathlib.Path(sys.argv[1]);tun,underlay,foreign,domestic=sys.argv[2:]
s=json.loads(pathlib.Path('/var/lib/server-connect/state.json').read_text())
p=json.loads((pathlib.Path('/var/lib/server-connect/profiles')/(s['selected']+'.json')).read_text())
out=p['outbound'];out=json.loads(out) if isinstance(out,str) else out
assert out['tag']=='upstream' and out['type']=='vless' and 1 <= out['server_port'] <= 65535
assert isinstance(out['server'],str) and out['server'] and out['server']!=foreign
ips={addr[4][0] for addr in socket.getaddrinfo(out['server'],out['server_port'],socket.AF_INET,socket.SOCK_STREAM)}
assert 0 < len(ips) <= 8 and foreign not in ips and (not domestic or domestic not in ips)
for ip in ips: assert ipaddress.ip_address(ip).is_global
out=dict(out);out['routing_mark']=0x00540000
cfg={'log':{'level':'warn'},'inbounds':[{'type':'tun','tag':'tun-in','interface_name':tun,'address':['172.30.244.1/30'],'mtu':1400,'stack':'gvisor','auto_route':False,'auto_redirect':False,'dns_mode':'disabled'}], 'outbounds':[out,{'type':'direct','tag':'direct','routing_mark':0x00540000}],'route':{'default_interface':underlay,'final':'upstream','rules':[{'ip_cidr':['172.30.244.0/30'],'action':'route','outbound':'direct'}]}}
(w/'config.json').write_text(json.dumps(cfg));(w/'config.json').chmod(0o600)
(w/'provider-ip').write_text('\n'.join(sorted(ips))+'\n')
(w/'provider-port').write_text(str(out['server_port']))
(w/'foreign-ip').write_text(foreign)
PY
timeout 20s "$core" check -c "$work/config.json" >/dev/null || die 'selected real VPN TUN config invalid'
direct_base=$(curl -q --noproxy '*' -fsS -4 --max-time 16 --resolve "api.ipify.org:443:$foreign" https://api.ipify.org) || die 'direct positive control unavailable'
[[ "$direct_base" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'direct exit response invalid'
printf '%s\n' "$direct_base" > "$work/direct-exit"
[[ "$direct_base" == "$expected_ip" ]] || echo 'DIRECT_HOST_EGRESS_ADDRESS_DIFFERS_FROM_UNDERLAY=OBSERVED'
echo 'DIRECT_ROOT_HOST_POSITIVE_CONTROL=PASS'
# The HTTPS certificate is checked for the original hostname against the
# operator's explicit DNS pin. This is a positive Direct control, not proof of
# national ownership, a publisher signature or blanket prefix admission.
check_domestic_https() {
  local code
  code=$(curl -q --noproxy '*' -sS -4 -o /dev/null -w '%{http_code}' --connect-timeout 6 --max-time 16 \
    --resolve "$domestic_host:443:$domestic" "https://$domestic_host/") || die 'Iranian HTTPS witness failed TLS or transport'
  [[ "$code" =~ ^[23][0-9][0-9]$ ]] || die 'Iranian HTTPS witness did not return HTTP 2xx/3xx'
}
if [[ -n "$domestic" ]]; then
  check_domestic_https
  echo 'ROOT_IRAN_DIRECT_POSITIVE_CONTROL=PASS'
fi
# Arm an independent durable systemd timer BEFORE the first host-network effect.
sync -f "$work/owner" "$work/boot" "$work/baseline" "$work/recover.sh" "$work/recovery.lock" "$work" || die 'recovery inputs are not durable'
if ! systemd-run --quiet --collect --unit="$watch" --on-active=300s --timer-property=AccuracySec=1s /usr/bin/bash "$work/recover.sh"; then
  # The creation result can be uncertain even after a reported error. Leave
  # any possibly armed watchdog's private recovery inputs intact.
  [[ $(systemctl show "$watch.timer" -p LoadState --value 2>/dev/null) == not-found ]] || { trap - EXIT; die 'watchdog launch uncertain; retained owner state'; }
  die 'independent watchdog could not be created'
fi
if [[ $(systemctl is-active "$watch.timer" 2>/dev/null || :) != active ]]; then
  trap - EXIT
  die 'independent watchdog not verifiably armed; keep private recovery inputs'
fi
finalize() {
  rc=$?; trap - EXIT
  [[ -f "$work/recovery.lock" && ! -L "$work/recovery.lock" ]] || { echo 'FIELD_ROOT_RECOVERY_LOCK_UNCERTAIN=FAIL' >&2; exit 3; }
  exec 9<"$work/recovery.lock" || { echo 'FIELD_ROOT_RECOVERY_LOCK_OPEN=FAIL' >&2; exit 3; }
  flock -x -w 20 9 || { echo 'FIELD_ROOT_RECOVERY_LOCK_BUSY=FAIL (owner state retained)' >&2; exit 3; }
  [[ /proc/self/fd/9 -ef "$work/recovery.lock" ]] || { echo 'FIELD_ROOT_RECOVERY_LOCK_REPLACED=FAIL' >&2; exit 3; }
  if SC_FIELD_RECOVERY_LOCK_FD=9 /usr/bin/bash "$work/recover.sh"; then
    if [[ $(systemctl is-active "$watch.timer" 2>/dev/null || :) == active ]]; then
      systemctl stop "$watch.timer" || { echo "OWNED_WATCHDOG_DISARM_FAILED=FAIL" >&2; exit 3; }
    fi
    [[ $(systemctl is-active "$watch.timer" 2>/dev/null || :) == inactive ]] || { echo "OWNED_WATCHDOG_UNCERTAIN=FAIL" >&2; exit 3; }
    for f in owner boot baseline recover.sh config.json provider-ip provider-port foreign-ip direct-exit nft.txt nft-receipt nft-handle nft-retired-receipt capture-retire-intent nft-remove-intent recovery.lock; do rm -f "$work/$f"; done
    rmdir "$work" || rc=3
    echo 'FIELD_ROOT_OWNED_CLEANUP=PASS'
  else
    echo 'FIELD_ROOT_RECOVERY_UNCERTAIN=FAIL (independent watchdog left armed)' >&2
    rc=3
  fi
  exit "$rc"
}
trap finalize EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! systemd-run --quiet --unit="$coreunit" --property=Restart=no "$core" run -c "$work/config.json"; then die 'selected TUN core launch failed'; fi
ready=no
for i in $(seq 1 15); do
  if ip link show dev "$tun" >/dev/null 2>&1; then ready=yes; break; fi
  sleep 1
done
[[ "$ready" == yes && $(systemctl is-active "$coreunit.service") == active ]] || die 'real root TUN did not activate'
ip -4 addr show dev "$tun" | grep -Fq '172.30.244.1/30' || die 'root TUN address unknown'
[[ -z $(ip -4 route show table "$table") ]] || die 'race: routing table changed'
# Only inert FIB entries may exist before the independent final-egress
# nft guard is durably observed. The RPDB selector is the first operation
# able to make this test's marked routing live.
ip -4 route add default dev "$tun" table "$table" metric 10
ip -4 route add unreachable default table "$table" metric 100
# One atomic nft creation packet: route capture and final-egress leak guard.
cat > "$work/nft.txt" <<NFT
add table inet $owner
add chain inet $owner capture { type route hook output priority -150; policy accept; }
add chain inet $owner guard { type filter hook postrouting priority 0; policy accept; }
add chain inet $owner observe { type filter hook output priority -75; policy accept; }
add rule inet $owner capture meta mark & 0x00ff0000 == 0x00540000 return
add rule inet $owner capture ip daddr $foreign meta l4proto { tcp, udp } meta mark set (meta mark & 0xff00ffff) | 0x00530000 counter
add rule inet $owner guard meta iif 0 ip daddr $foreign meta l4proto { tcp, udp } oifname "$tun" counter
add rule inet $owner guard meta iif 0 ip daddr $foreign meta l4proto { tcp, udp } oifname != "$tun" counter drop
NFT
if [[ -n "$domestic" ]]; then
  # A specific Iranian HTTPS /32 obtains an explicit Direct mark; it must
  # never share the foreign capture mark or the RPDB VPN rule. The second
  # independently hooked chain witnesses the actual physical-egress route.
  cat >> "$work/nft.txt" <<NFT
add chain inet $owner direct_witness { type filter hook postrouting priority -5; policy accept; }
add rule inet $owner capture ip daddr $domestic tcp dport 443 meta mark set (meta mark & 0xff00ffff) | 0x00540000 counter
add rule inet $owner direct_witness meta iif 0 ip daddr $domestic tcp dport 443 meta mark & 0x00ff0000 == 0x00540000 oifname "$underlay" counter
NFT
fi
while IFS= read -r upstream_ip; do
  printf 'add rule inet %s observe ip daddr %s tcp dport %s counter\n' "$owner" "$upstream_ip" "$(cat "$work/provider-port")" >> "$work/nft.txt"
done < "$work/provider-ip"
nft -f "$work/nft.txt" || die 'atomic target-selective capture or leak guard refused'
nft -j -a list table inet "$owner" | python3 -c 'import json,sys;rows=[x["table"].get("handle") for x in json.load(sys.stdin)["nftables"] if "table" in x];assert len(rows)==1 and type(rows[0]) is int and rows[0]>0;print(rows[0])' > "$work/nft-handle" || die 'nft ownership handle unavailable'
# Normalized immutable graph receipt: counters and generated kernel handles
# do not affect ownership, but altered expressions / foreign children do.
nft -j -a list table inet "$owner" | python3 -c '
import hashlib,json,sys
obj=json.load(sys.stdin)["nftables"]
for item in obj:
 for record in item.values():
  if isinstance(record,dict):
   record.pop("handle",None)
   for expr in record.get("expr",[]):
    if "counter" in expr: expr["counter"]={}
raw=json.dumps(obj,sort_keys=True,separators=(",",":"))
print(hashlib.sha256(raw.encode()).hexdigest())
' > "$work/nft-receipt" || die 'nft graph ownership receipt could not be written'
# Precompute the only permitted post-flush graph from the still-matching
# active graph. Recovery never learns a new allowed graph from changed state.
nft -j -a list table inet "$owner" | python3 -c '
import hashlib,json,pathlib,sys
work=pathlib.Path(sys.argv[1]); owner=sys.argv[2]
obj=json.load(sys.stdin)["nftables"]
tables=[item["table"] for item in obj if "table" in item]
assert len(tables)==1 and tables[0].get("family")=="inet" and tables[0].get("name")==owner
assert type(tables[0].get("handle")) is int and tables[0]["handle"]==int((work/"nft-handle").read_text())
for item in obj:
 for record in item.values():
  if isinstance(record,dict):
   record.pop("handle",None)
   for expr in record.get("expr",[]):
    if "counter" in expr: expr["counter"]={}
def digest(rows):
 return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
assert digest(obj)==(work/"nft-receipt").read_text().strip()
retired=[item for item in obj if not ("rule" in item and item["rule"].get("family")=="inet" and item["rule"].get("table")==owner and item["rule"].get("chain")=="capture")]
assert len(obj)-len(retired)>=2
print(digest(retired))
' "$work" "$owner" > "$work/nft-retired-receipt" || die 'permitted capture-retired graph could not be derived'
# A completed userspace write does not imply the receipt is durable. Do not
# admit any RPDB selector while the independently observed nft guard could
# be lost in a crash. This remains a test-only protocol, not product Apply.
sync -f "$work/nft-handle" "$work/nft-receipt" "$work/nft-retired-receipt" "$work" || die 'nft guard receipt durability unavailable'
nft -j list chain inet "$owner" guard | python3 -c '
import json,sys
rules=[x["rule"] for x in json.load(sys.stdin)["nftables"] if "rule" in x]
assert len(rules)==2
assert sum(any("drop" in exp for exp in r["expr"]) for r in rules)==1
' || die 'independent nft final-egress guard incomplete before RPDB'
# The final-egress guard and its durable graph receipt precede any routing
# selector. An incomplete or foreign-mutated table must never admit RPDB.
ip -4 rule add priority "$priority" fwmark "$mark"/"$mask" table "$table" || die 'guarded RPDB activation failed'
ip -4 rule show | grep -Fq "lookup $table" || die 'guarded RPDB not observed'
echo 'ROOT_GUARD_FIRST_RPDB=PASS'
printf 'ROOT_SELECTED_TUN_ACTIVE=PASS\n'
# Independently verify the two sibling kernel paths; do not mistake a real
# route-table entry or a Direct IP response for a selected VPN witness.
ip -4 rule show | grep -Fq "lookup $table" || die 'RPDB did not install'
direct=$(curl -q --noproxy '*' -fsS -4 --max-time 15 --resolve "api.ipify.org:443:$foreign" https://api.ipify.org) || die 'selected target unavailable'
[[ "$direct" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'selected egress response invalid'
[[ "$direct" != "$(cat "$work/direct-exit")" ]] && echo 'VPN_EXIT_DISTINCT_FROM_REAL_DIRECT=PASS' || die 'selected target was Direct, not VPN'
# The real upstream must have sent packets on the physical underlay while
# ordinary unproxied curl used the selected TUN. Successful HTTPS alone is
# insufficient attribution evidence.
provider_packets=$(nft -j list chain inet "$owner" observe | python3 -c 'import json,sys; print(sum(int(e["counter"].get("packets",0)) for o in json.load(sys.stdin)["nftables"] if "rule" in o for e in o["rule"].get("expr",[]) if "counter" in e))')
[[ "$provider_packets" =~ ^[0-9]+$ && "$provider_packets" -gt 0 ]] || die 'selected upstream underlay packet witness absent'
echo 'ROOT_SELECTED_UPSTREAM_PACKET_WITNESS=PASS'
guard_packets=$(nft -j list chain inet "$owner" guard | python3 -c 'import json,sys; print(sum(int(e["counter"].get("packets",0)) for o in json.load(sys.stdin)["nftables"] if "rule" in o and not any("drop" in e for e in o["rule"].get("expr",[])) for e in o["rule"].get("expr",[]) if "counter" in e))')
[[ "$guard_packets" =~ ^[0-9]+$ && "$guard_packets" -gt 0 ]] || die 'TUN final-egress observer saw no packet'
echo 'ROOT_TUN_FINAL_EGRESS=PASS'
if [[ -n "$domestic" ]]; then
  check_domestic_https
  direct_packets=$(nft -j list chain inet "$owner" direct_witness | python3 -c 'import json,sys;print(sum(int(e["counter"].get("packets",0)) for x in json.load(sys.stdin)["nftables"] if "rule" in x for e in x["rule"].get("expr",[]) if "counter" in e))')
  [[ "$direct_packets" =~ ^[0-9]+$ && "$direct_packets" -gt 0 ]] || die 'marked domestic physical-underlay egress witness missing'
  domestic_route=$(ip -4 route get "$domestic" mark 0x00540000)
  [[ "$domestic_route" == *"dev $underlay"* && "$domestic_route" != *"dev $tun"* ]] || die 'domestic direct marked route differs from physical underlay'
  echo 'ROOT_IRAN_PINNED_DIRECT_WHILE_VPN_ACTIVE=PASS'
fi
# Probe an explicitly unrelated public endpoint; its route must stay Direct.
route=$(ip -4 route get 1.1.1.1)
[[ "$route" == *"dev $underlay"* && "$route" != *"dev $tun"* ]] || die 'unrelated public Direct was captured'
echo 'UNRELATED_ROOT_HOST_DIRECT_ROUTE=PASS'
echo 'ACTIVE_FRESH_SSH_TEST_WINDOW=BEGIN'
sleep 30
echo 'ACTIVE_FRESH_SSH_TEST_WINDOW=END'
# Deliberately stop only the QA-owned Core, with nft capture/guard and RPDB
# still armed. Loss of the TUN link MUST leave an unreachable fallback, not
# silently fall through to main/Direct. The independent timer remains armed.
systemctl stop "$coreunit.service" || die 'QA core stop refused'
[[ $(systemctl is-active "$coreunit.service" 2>/dev/null || :) == inactive ]] || die 'QA core stop uncertain'
[[ ! -e /sys/class/net/$tun ]] || die 'QA TUN remained after core loss'
if ip -4 route get "$foreign" mark "$mark" >/dev/null 2>&1; then
  die 'VPN-required marked route unexpectedly survived Core/TUN loss'
fi
if curl -q --noproxy '*' -fsS -4 --max-time 6 --resolve "api.ipify.org:443:$foreign" https://api.ipify.org >/dev/null 2>&1; then
  die 'VPN-required HTTPS silently fell back Direct after Core outage'
fi
[[ $(systemctl is-active "$watch.timer" 2>/dev/null || :) == active ]] || die 'independent recovery guard vanished'
echo 'ROOT_CORE_LOSS_NO_DIRECT_FALLBACK=PASS'
if [[ -n "$domestic" ]]; then
  check_domestic_https
  echo 'ROOT_IRAN_PINNED_DIRECT_SURVIVES_VPN_CORE_LOSS=PASS'
fi
