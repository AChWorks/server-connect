#!/usr/bin/env bash
# Isolated Debian13/official sing-box 1.14.3 TCP reply-path experiment.
# Operates only within three task-named network namespaces; no host-route changes.
set -Eeuo pipefail
mode=${1:-}
case "$mode" in negative|marked|negative-public|marked-public|accepted-public) ;; *) echo 'Usage: $0 negative|marked|negative-public|marked-public|accepted-public' >&2; exit 2;; esac
test "$(id -u)" = 0
core="${SC_QA_CORE:-/opt/server-connect/current/bin/sing-box}"
test -x "$core"
test "$("$core" version | head -1)" = 'sing-box version 1.14.3'
suffix=0
case "$mode" in
 marked) suffix=1;;
 negative-public) suffix=2;;
 marked-public) suffix=3;;
 accepted-public) suffix=4;;
esac
if [[ "$mode" == *-public ]];then
 server_ip=203.0.113.10; gateway_ip=203.0.113.9
 gateway_client_ip=192.0.2.9; client_link_ip=192.0.2.10
else
 server_ip=10.224.101.2; gateway_ip=10.224.101.1
 gateway_client_ip=10.224.102.1; client_link_ip=10.224.102.2
fi
ns_srv=sc3s${suffix}; ns_gw=sc3g${suffix}; ns_cli=sc3c${suffix}
host_a=sc3va${suffix};host_b=sc3vb${suffix};host_c=sc3vc${suffix};host_d=sc3vd${suffix}
task="/root/sc-issue3-reply-lab-$mode"
for ns in "$ns_srv" "$ns_gw" "$ns_cli";do
 ! ip netns list | grep -Eq "^$ns( |$)" || { echo "namespace collision $ns";exit 20; }
done
for f in "$host_a" "$host_b" "$host_c" "$host_d";do
 ! ip link show "$f" >/dev/null 2>&1 || { echo "veth collision $f";exit 21; }
done
test ! -e "$task" && test ! -L "$task" || { echo "task path collision $task";exit 22; }
umask 077
mkdir -m 700 "$task"
ip -j route show table all > "$task/host-routes-before.json"
ip -j -4 rule show > "$task/host-rule4-before.json"
ip -j -6 rule show > "$task/host-rule6-before.json"
nft -j list ruleset > "$task/host-nft-before.json"
pids=()
cleanup() {
 status=$?
 trap - EXIT
 set +e
 for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null;done
 for pid in "${pids[@]}";do wait "$pid" 2>/dev/null;done
 for ns in "$ns_cli" "$ns_gw" "$ns_srv";do
  if ip netns list | grep -Eq "^$ns( |$)";then ip netns pids "$ns" | xargs -r kill 2>/dev/null; ip netns del "$ns" || status=98;fi
 done
 for f in "$host_a" "$host_b" "$host_c" "$host_d";do
  if ip link show "$f" >/dev/null 2>&1;then echo "unexpected host link $f";status=97;fi
 done
 ip -j route show table all | cmp - "$task/host-routes-before.json" || status=96
 ip -j -4 rule show | cmp - "$task/host-rule4-before.json" || status=95
 ip -j -6 rule show | cmp - "$task/host-rule6-before.json" || status=94
 nft -j list ruleset | cmp - "$task/host-nft-before.json" || status=93
 echo "QA_LAB_CLEANUP_EXIT=$status"
 exit "$status"
}
trap cleanup EXIT
ip netns add "$ns_srv";ip netns add "$ns_gw";ip netns add "$ns_cli"
ip link add "$host_a" type veth peer name "$host_b"
ip link add "$host_c" type veth peer name "$host_d"
ip link set "$host_a" netns "$ns_srv"
ip link set "$host_b" netns "$ns_gw"
ip link set "$host_c" netns "$ns_gw"
ip link set "$host_d" netns "$ns_cli"
for ns in "$ns_srv" "$ns_gw" "$ns_cli";do ip -n "$ns" link set lo up;done
ip -n "$ns_srv" addr add "$server_ip"/30 dev "$host_a"
ip -n "$ns_gw" addr add "$gateway_ip"/30 dev "$host_b"
ip -n "$ns_gw" addr add "$gateway_client_ip"/30 dev "$host_c"
ip -n "$ns_cli" addr add "$client_link_ip"/30 dev "$host_d"
ip -n "$ns_cli" addr add 198.51.100.77/32 dev lo
ip -n "$ns_srv" link set "$host_a" up
ip -n "$ns_gw" link set "$host_b" up
ip -n "$ns_gw" link set "$host_c" up
ip -n "$ns_cli" link set "$host_d" up
ip -n "$ns_srv" route add default via "$gateway_ip" dev "$host_a"
ip -n "$ns_gw" route add 198.51.100.77/32 via "$client_link_ip" dev "$host_c"
ip -n "$ns_gw" route add default via "$client_link_ip" dev "$host_c"
ip -n "$ns_cli" route add default via "$gateway_client_ip" dev "$host_d" src 198.51.100.77
ip netns exec "$ns_gw" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$ns_srv" ping -qn -c 1 -W 2 198.51.100.77 >/dev/null
ip netns exec "$ns_cli" ping -qn -I 198.51.100.77 -c 1 -W 2 "$server_ip" >/dev/null
echo 'QA_TOPOLOGY_DIRECT_V4_BIDIRECTIONAL=PASS'
cat > "$task/echo_server.py" <<'PY'
import socket
with socket.socket() as s:
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind((__import__("os").environ["SC3_SERVER_IP"],18222))
 s.listen(5)
 print("ECHO_SERVER_READY",flush=True)
 while True:
  conn,peer=s.accept()
  with conn:
   print("ECHO_CLIENT_CONNECTED",flush=True)
   while True:
    try: data=conn.recv(1024)
    except OSError as exc:
     print("ECHO_RECV_ERROR",type(exc).__name__,getattr(exc,"errno",None),flush=True)
     break
    if not data:break
    try:conn.sendall(data)
    except OSError as exc:
     print("ECHO_SEND_ERROR",type(exc).__name__,getattr(exc,"errno",None),flush=True)
     break
PY
cat > "$task/new_server.py" <<'PY'
import socket
with socket.socket() as s:
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind(("198.51.100.77",18223))
 s.listen(16)
 print("NEW_SERVER_READY",flush=True)
 while True:
  c,a=s.accept()
  with c:
   c.sendall(b"SELECTED_OK")
   print("NEW_OUTBOUND_ARRIVED",flush=True)
PY
cat > "$task/old_client.py" <<'PY'
import socket,time,sys
s=socket.socket()
s.settimeout(4)
s.bind(("198.51.100.77",0))
s.connect((__import__("os").environ["SC3_SERVER_IP"],18222))
print("OLD_SOCKET_READY",flush=True)
for n in range(1,28):
 try:
  packet=("old_nonce_%02d" % n).encode()
  s.sendall(packet)
  received=b""
  while len(received)<len(packet):
   part=s.recv(4096)
   if not part:raise EOFError("closed")
   received+=part
  if received!=packet:raise ValueError("unexpected reply")
  print("OLD_OK_%02d"%n,flush=True)
  time.sleep(1)
 except Exception as exc:
  print("OLD_SOCKET_FAILURE_%02d:%s"%(n,type(exc).__name__),flush=True)
  sys.exit(42)
print("OLD_SOCKET_COMPLETE_PASS",flush=True)
PY
cat > "$task/probe.py" <<'PY'
import socket,sys
s=socket.socket();s.settimeout(6)
s.connect(("198.51.100.77",18223))
x=s.recv(64)
assert x==b"SELECTED_OK",x
print("NEW_OUTBOUND_SELECTED_PEER_REACHED",flush=True)
PY
cat > "$task/peer.json" <<JSON
{"log":{"level":"info"},"inbounds":[{"type":"vless","tag":"qa-in","listen":"$gateway_ip","listen_port":18391,"users":[{"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"$host_c","final":"direct"}}
JSON
cat > "$task/core.json" <<JSON
{"log":{"level":"warn"},"inbounds":[{"type":"tun","tag":"qa-tun","interface_name":"sctun0","address":["172.31.99.1/30"],"stack":"gvisor","auto_route":true,"auto_redirect":true,"strict_route":true,"iproute2_rule_index":14200,"iproute2_table_index":27432,"dns_mode":"disabled"}],"outbounds":[{"type":"vless","tag":"upstream","server":"$gateway_ip","server_port":18391,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"},{"type":"direct","tag":"direct"}],"route":{"default_interface":"$host_a","rules":[{"ip_is_private":true,"action":"bypass","outbound":"direct"}],"final":"upstream"}}
JSON
"$core" check -c "$task/core.json" > "$task/core-check.log" 2>&1
"$core" check -c "$task/peer.json" > "$task/peer-check.log" 2>&1
ip netns exec "$ns_srv" env SC3_SERVER_IP="$server_ip" python3 -u "$task/echo_server.py" > "$task/echo.log" 2>&1 &
pids+=("$!")
ip netns exec "$ns_cli" python3 -u "$task/new_server.py" > "$task/new.log" 2>&1 &
pids+=("$!")
ip netns exec "$ns_gw" "$core" run -c "$task/peer.json" > "$task/peer.log" 2>&1 &
pids+=("$!")
for tries in {1..30};do
 if grep -q 'ECHO_SERVER_READY' "$task/echo.log" && grep -q 'NEW_SERVER_READY' "$task/new.log" &&
 ip netns exec "$ns_gw" ss -H -ltn '( sport = :18391 )' | grep -q ':18391';then break;fi
 sleep 0.2
done
grep -q 'ECHO_SERVER_READY' "$task/echo.log"
grep -q 'NEW_SERVER_READY' "$task/new.log"
kill -0 "${pids[2]}" || { echo 'QA_VLESS_PEER_DIED';cat "$task/peer.log";exit 44; }
ip netns exec "$ns_gw" ss -H -lnt '( sport = :18391 )' | grep -q ':18391'
ip netns exec "$ns_gw" nft -f - <<NFT
table inet sc3_wire_witness {
 chain selected_input {
  type filter hook input priority -50; policy accept;
  ip saddr $server_ip tcp dport 18391 counter comment "selected-vless-underlay"
 }
 chain direct_forward {
  type filter hook forward priority -50; policy accept;
  ip saddr $server_ip ip daddr 198.51.100.77 tcp dport 18223 counter comment "foreign-direct-escape"
 }
}
NFT
ip netns exec "$ns_srv" python3 "$task/probe.py" > "$task/pre-new-probe.log"
ip netns exec "$ns_gw" nft -j list table inet sc3_wire_witness > "$task/wire-before.json"
echo 'QA_NEW_REMOTE_DIRECT_PRECORE_POSITIVE_CONTROL=PASS'
ip netns exec "$ns_cli" env SC3_SERVER_IP="$server_ip" python3 -u "$task/old_client.py" > "$task/old.log" 2>&1 &
client_pid=$!
pids+=("$client_pid")
for tries in {1..40};do
 if grep -q 'OLD_OK_04' "$task/old.log";then break;fi
 sleep 0.2
done
grep -q 'OLD_OK_04' "$task/old.log"
echo 'QA_FOREIGN_PREEXISTING_TCP_SESSION_READY=PASS'
ip netns exec "$ns_srv" ip -j -4 rule show > "$task/ns-rules-before.json"
ip netns exec "$ns_srv" nft -j list ruleset > "$task/ns-nft-before.json"
if [[ "$mode" == marked* || "$mode" == accepted-public ]];then
 if [[ "$mode" == accepted-public ]];then
  # Observe a real accepted socket; *never* exempt the whole foreign IP
  # or every connection to its listener port. The matching nft set is
  # immutable during Core activation, as in the integrated Manager.
  peer_port=$(ip netns exec "$ns_srv" python3 - "$server_ip" <<'PYPORT'
import ipaddress,sys
server=ipaddress.IPv4Address(sys.argv[1])
foreign=ipaddress.IPv4Address("198.51.100.77")
def endpoint(s):
 a,p=s.split(":")
 return ipaddress.IPv4Address(bytes.fromhex(a)[::-1]),int(p,16)
rows=[x.split() for x in open("/proc/net/tcp").read().splitlines()[1:]]
found=[endpoint(x[2])[1] for x in rows
       if x[3]=="01" and endpoint(x[1])==(server,18222)
       and endpoint(x[2])[0]==foreign]
assert len(found)==1,found
print(found[0])
PYPORT
  )
  case "$peer_port" in ''|*[!0-9]*) echo 'invalid accepted peer port';exit 50;;esac
  test "$peer_port" -gt 0 && test "$peer_port" -le 65535
  ip netns exec "$ns_srv" nft -f - <<NFT
table inet sc3_reply_safety {
 set accepted4 {
  type ipv4_addr . inet_service . ipv4_addr . inet_service;
  elements = { $server_ip . 18222 . 198.51.100.77 . $peer_port }
 }
 set accepted6 {
  type ipv6_addr . inet_service . ipv6_addr . inet_service;
 }
 chain protected_reply {
  type route hook output priority -150; policy accept;
  ct direction reply meta mark 0 meta mark set 0x2024 counter
  ct direction original ip saddr . tcp sport . ip daddr . tcp dport @accepted4 meta mark 0 meta mark set 0x2024 counter
  ct direction original ip6 saddr . tcp sport . ip6 daddr . tcp dport @accepted6 meta mark 0 meta mark set 0x2024 counter
 }
}
NFT
  echo 'QA_EXACT_PREEXISTING_ACCEPTED_TCP_TUPLE_ARMED'
 else
  ip netns exec "$ns_srv" nft -f - <<'NFT'
table inet sc3_reply_safety {
 chain protected_reply {
  type route hook output priority -150; policy accept;
  ct direction reply meta mark 0 meta mark set 0x2024 counter
 }
}
NFT
  echo 'QA_EARLY_CT_REPLY_MARK_ARMED'
 fi
fi
ip netns exec "$ns_srv" "$core" run -c "$task/core.json" > "$task/core.log" 2>&1 &
core_pid=$!
pids+=("$core_pid")
ready=0
for tries in {1..40};do
 if ip -n "$ns_srv" link show sctun0 >/dev/null 2>&1 &&
    ip netns exec "$ns_srv" nft list table inet sing-box >/dev/null 2>&1 &&
    ip netns exec "$ns_srv" ip -4 rule show | grep -q '^1:.*lookup ';then ready=1;break;fi
 kill -0 "$core_pid" 2>/dev/null || { echo 'CORE_DIED'; cat "$task/core.log";exit 45; }
 sleep 0.25
done
test "$ready" = 1
echo 'QA_OFFICIAL_NATIVE_TUN_AND_NFT_READY'
kill -0 "${pids[2]}" || { echo 'VLESS_PEER_NOT_RUNNING_AFTER_NATIVE_START';cat "$task/peer.log";exit 47; }
ip netns exec "$ns_srv" python3 "$task/probe.py" > "$task/post-new-probe.log" 2>&1
ip netns exec "$ns_gw" nft -j list table inet sc3_wire_witness > "$task/wire-after.json"
python3 - "$task/wire-before.json" "$task/wire-after.json" <<'PYCOUNTERS'
import json,sys
def get(p):
 d=json.load(open(p))
 result={}
 for o in d.get("nftables",[]):
  r=o.get("rule",{})
  if r.get("table")!="sc3_wire_witness":continue
  counters=[x["counter"]["packets"] for x in r.get("expr",[]) if "counter" in x]
  if len(counters)!=1:raise AssertionError("counter shape")
  result[r["chain"]]=counters[0]
 return result
pre,post=get(sys.argv[1]),get(sys.argv[2])
assert set(pre)=={"selected_input","direct_forward"},pre
assert post["selected_input"]>pre["selected_input"],(pre,post)
assert post["direct_forward"]==pre["direct_forward"],(pre,post)
print("QA_VLESS_PEER_WIRE_POSITIVE_AND_DIRECT_NO_LEAK_PASS",pre,post)
PYCOUNTERS
echo 'QA_NEW_FOREIGN_SAME_IP_OUTBOUND_INDEPENDENT_VLESS_PROOF=PASS'
for tries in {1..150}; do
 if grep -Eq '^OLD_SOCKET_(COMPLETE_PASS|FAILURE_)' "$task/old.log";then break;fi
 sleep 0.2
done
old_count=$(grep -Ec '^OLD_OK_[0-9]+$' "$task/old.log" || :)
echo "QA_OLD_SOCKET_SUCCESSFUL_NONCES=$old_count"
if [[ "$mode" == marked* || "$mode" == accepted-public ]];then
 grep -qx 'OLD_SOCKET_COMPLETE_PASS' "$task/old.log" || { echo 'PROTECTED_OLD_TCP_FAILURE';cat "$task/old.log";exit 48; }
 echo 'QA_MARKED_FOREIGN_ESTABLISHED_TCP_SURVIVED=PASS'
else
 if grep -q 'OLD_SOCKET_FAILURE_' "$task/old.log";then
  echo 'QA_UNPROTECTED_CORE_RESET_REPRODUCED=PASS'
 elif grep -qx 'OLD_SOCKET_COMPLETE_PASS' "$task/old.log";then
  echo 'QA_UNPROTECTED_CORE_RESET_NOT_REPRODUCED=OBSERVED'
 else
  echo 'QA_UNPROTECTED_CORE_SSH_WITNESS_INDETERMINATE';cat "$task/old.log";exit 49
 fi
fi
# Core must not punch a global peer-IP exception; client remote is still selected
# for a *new* locally originated flow to exactly the same public client IP.
ip netns exec "$ns_srv" python3 "$task/probe.py" > "$task/post2-new-probe.log" 2>&1
ip netns exec "$ns_gw" nft -j list table inet sc3_wire_witness > "$task/wire-final.json"
python3 - "$task/wire-after.json" "$task/wire-final.json" <<'PYCOUNTERS'
import json,sys
def get(p):
 for x in json.load(open(p))["nftables"]:
  r=x.get("rule",{})
  if r.get("chain")=="selected_input":return next(y["counter"]["packets"] for y in r["expr"] if "counter" in y)
 raise AssertionError("missing selected input counter")
assert get(sys.argv[2])>get(sys.argv[1])
print("QA_SAME_FOREIGN_IP_NEW_OUTBOUND_STILL_SELECTED=PASS")
PYCOUNTERS
kill "$core_pid"
wait "$core_pid" 2>/dev/null || :
# Core owns all native routes. The extra reply-mark table belongs only to this QA.
if [[ "$mode" == marked* || "$mode" == accepted-public ]];then ip netns exec "$ns_srv" nft delete table inet sc3_reply_safety;fi
for tries in {1..40};do
 if ! ip -n "$ns_srv" link show sctun0 >/dev/null 2>&1;then break;fi
 sleep 0.2
done
! ip -n "$ns_srv" link show sctun0 >/dev/null 2>&1
ip netns exec "$ns_srv" ip -j -4 rule show | cmp - "$task/ns-rules-before.json"
ip netns exec "$ns_srv" nft -j list ruleset | cmp - "$task/ns-nft-before.json"
echo "QA_LAB_RESULT_MODE_$mode=PASS"
