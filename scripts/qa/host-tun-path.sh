#!/bin/sh
# Disposable GitHub Actions Docker --network none guest ONLY.
# This exercises a REAL sing-box Linux TUN with a separate VLESS server and
# HTTP origins in an isolated guest-owned network namespace. It is NOT a
# production Apply, Runtime Health Guard or geographic-prefix acceptance test.
set -eu
umask 077

core=/root/server-connect/bin/sing-box
client_cfg=/run/sc-qa-tun-client.json
server_cfg=/run/sc-qa-tun-upstream.json
peer=scqapeer
edge=scqaedge0
client_pid=
server_pid=
origin_pid=
hosting_pid=
edge_added=no
peer_added=no
default_added=no
tun_device_created=no
nft_before=

# iproute2 can emit an inconsequential trailing space after link deletion;
# retain strict route semantics while excluding display-only whitespace.
normalized_default_route() {
  route_text=$(ip -4 route show default) || return 1
  printf '%s\n' "$route_text" | sed 's/[[:space:]]*$//'
}

require_guest() {
  test "$(id -u)" -eq 0
  test -f /.dockerenv
  test "$(ps -p 1 -o comm=)" = systemd
  test -f /root/qa-host-assertions.sh
  test -x /root/qa-tun-config-qa
  test -x "$core"
  if [ ! -c /dev/net/tun ]; then
    if [ -e /dev/net/tun ] || [ -L /dev/net/tun ]; then
      echo 'REAL_TUN_LAB_PREFLIGHT=FAIL (conflicting TUN device path)' >&2
      return 1
    fi
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    tun_device_created=yes
  fi
  if [ ! -c /dev/net/tun ]; then
    echo 'REAL_TUN_LAB_PREFLIGHT=FAIL (no kernel TUN character device)' >&2
    return 1
  fi
  test "$(normalized_default_route)" = "default dev lo scope link metric 4242"
  test -z "$(ip -6 route show default)"
  test ! -e /sys/class/net/"$edge"
  test ! -e /sys/class/net/sctunqa0
  namespace_inventory=$(ip netns list) || { echo 'REAL_TUN_LAB_PREFLIGHT=FAIL (cannot enumerate network namespaces)' >&2; return 1; }
  peer_present=$(printf '%s\n' "$namespace_inventory" | awk -v expected="$peer" '$1 == expected { found=1 } END { print found+0 }') || return 1
  if [ "$peer_present" != 0 ]; then
    echo "QA peer network namespace already exists" >&2
    return 1
  fi
}

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  for pid in "$client_pid" "$server_pid" "$origin_pid" "$hosting_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || :
      wait "$pid" 2>/dev/null || :
    fi
  done
  if [ "$default_added" = yes ]; then
    ip -4 route del default via 10.254.72.2 dev "$edge" metric 100 2>/dev/null || rc=1
  fi
  if [ "$edge_added" = yes ]; then
    ip link del dev "$edge" 2>/dev/null || rc=1
  fi
  if [ "$peer_added" = yes ]; then
    ip netns del "$peer" 2>/dev/null || rc=1
  fi
  if [ "$tun_device_created" = yes ]; then
    rm -f /dev/net/tun || rc=1
  fi
  rm -f "$client_cfg" "$server_cfg" /run/sc-qa-tun-origin.log \
    /run/sc-qa-tun-hosting.log /run/sc-qa-tun-server.log /run/sc-qa-tun-client.log
  # Fail, rather than claim cleanup, if the real core leaked its TUN.
  if [ -e /sys/class/net/sctunqa0 ]; then
    echo "REAL_TUN_LAB_CLEANUP=FAIL (TUN still present)" >&2
    rc=1
  fi
  observed_default=$(normalized_default_route) || { echo 'REAL_TUN_LAB_CLEANUP=FAIL (default route read)' >&2; rc=1; observed_default=''; }
  if [ "$observed_default" != "default dev lo scope link metric 4242" ]; then
    echo "REAL_TUN_LAB_CLEANUP=FAIL (baseline default route changed; observed=[$observed_default])" >&2
    ip -4 route show table all >&2 || :
    ip -4 rule show >&2 || :
    ip -4 addr show dev lo >&2 || :
    rc=1
  fi
  if [ -n "$nft_before" ]; then
    nft_after=$(nft -j list ruleset) || { echo 'REAL_TUN_LAB_CLEANUP=FAIL (nft inspection)' >&2; rc=1; nft_after=''; }
    if [ "$nft_before" != "$nft_after" ]; then
      echo 'REAL_TUN_LAB_CLEANUP=FAIL (nftables ruleset drift)' >&2
      rc=1
    fi
  fi
  if [ "$rc" -eq 0 ]; then
    echo "REAL_TUN_LAB_CLEANUP=PASS (owned namespace, VETH, TUN, nftables and default removed)"
  fi
  exit "$rc"
}

peer_counter_packets() {
  counter_name=$1
  witness_json=$(ip netns exec "$peer" nft -j list counter inet scqawitness "$counter_name") || return 1
  printf '%s\n' "$witness_json" | python3 -c '
import json,sys
name=sys.argv[1]
items=json.load(sys.stdin)["nftables"]
counters=[item["counter"]["packets"] for item in items if "counter" in item and item["counter"].get("name")==name]
if len(counters) != 1 or not isinstance(counters[0],int):
    sys.exit("missing or ambiguous independent packet witness")
print(counters[0])
' "$counter_name"
}

direct_witness_packets() { peer_counter_packets direct_packets; }
hosting_reply_packets() { peer_counter_packets hosting_reply_packets; }

# The fault is injected only by the disposable installed-host regression.
# Wait for the real sing-box process to exit so its TUN policy is removed.
stop_tun_client_for_qa_fault() {
  test -n "$client_pid"
  kill "$client_pid"
  wait "$client_pid" 2>/dev/null || :
  client_pid=
  test ! -e /sys/class/net/sctunqa0 || {
    echo 'QA fault failed to remove the TUN interface' >&2
    return 1
  }
}

assert_tun_policy_active() {
  [ -n "$client_pid" ] && kill -0 "$client_pid" 2>/dev/null || return 1
  test -e /sys/class/net/sctunqa0 || return 1
  ip -4 route show table all | grep -F 'dev sctunqa0' >/dev/null || return 1
  ip -4 rule show >/dev/null || return 1
  installed_nft=$(nft -j list ruleset) || return 1
  [ "$installed_nft" != "$nft_before" ] || return 1
}

without_proxy() {
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/curl -q --fail --silent --show-error --noproxy '*' \
    --connect-timeout 3 --max-time 6 "$1"
}

expect_source() {
  destination=$1 source=$2
  response=$(without_proxy "http://$destination:19180/path") || return 1
  test "$response" = "SOURCE=$source"
}

# A synthetic foreign visitor makes a NEW inbound HTTP connection to the
# hosting-side address, without going through the VPN. The reply destination
# is a foreign public IP, so a response mistakenly captured by TUN would
# break an ordinary web server even when host-origin foreign egress works.
expect_foreign_hosted_reply() {
  response=$(ip netns exec "$peer" env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/curl -q --fail --silent --show-error --noproxy '*' \
    --interface 198.51.100.42 --connect-timeout 3 --max-time 6 \
    http://10.254.72.1:19184/foreign-visitor) || return 1
  test "$response" = 'HOST_REQUEST_SOURCE=198.51.100.42'
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo 'REAL_TUN_LAB_STAGE=guest-preflight'
if ! require_guest; then
  echo 'REAL_TUN_LAB_PREFLIGHT=FAIL' >&2
  exit 1
fi
echo 'REAL_TUN_LAB_PREFLIGHT=PASS'
nft_before=$(nft -j list ruleset)

# All addresses and processes exist only INSIDE the disconnected container.
ip netns add "$peer"
peer_added=yes
ip link add "$edge" type veth peer name scqapeer0
edge_added=yes
ip link set scqapeer0 netns "$peer"
ip addr add 10.254.72.1/30 dev "$edge"
ip link set "$edge" up
ip -n "$peer" link set lo up
ip -n "$peer" addr add 10.254.72.2/30 dev scqapeer0
ip -n "$peer" link set scqapeer0 up
# Synthetic address placement, NOT proof of a real Iran prefix dataset or
# Internet connectivity. Only source-path choice is under test.
ip -n "$peer" addr add 5.22.0.10/32 dev lo
ip -n "$peer" addr add 8.8.8.8/32 dev lo
ip -n "$peer" addr add 198.51.100.42/32 dev lo
# Independent peer-side packet counter: an ordinary Direct foreign TCP flow
# must cross this VETH; the VLESS server's local-origin flow cannot count.
ip netns exec "$peer" nft -f - <<'NFTWITNESS'
table inet scqawitness {
  counter direct_packets { }
  counter hosting_reply_packets { }
  chain incoming {
    type filter hook input priority filter; policy accept;
    iifname "scqapeer0" ip daddr 8.8.8.8 tcp dport 19180 counter name direct_packets
    iifname "scqapeer0" ip saddr 10.254.72.1 ip daddr 198.51.100.42 tcp sport 19184 counter name hosting_reply_packets
  }
}
NFTWITNESS
ip -4 route add default via 10.254.72.2 dev "$edge" metric 100
default_added=yes

ip netns exec "$peer" python3 -u - >/run/sc-qa-tun-origin.log 2>&1 <<'PYORIGIN' &
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data=("SOURCE="+self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self,*args):
        pass
ThreadingHTTPServer(("0.0.0.0",19180),Handler).serve_forever()
PYORIGIN
origin_pid=$!

# Host-side HTTP service simulates a website or administrative panel whose
# visitor connects from an independently controlled foreign address.
python3 -u - >/run/sc-qa-tun-hosting.log 2>&1 <<'PYHOSTING' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = ("HOST_REQUEST_SOURCE=" + self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass
ThreadingHTTPServer(("10.254.72.1", 19184), Handler).serve_forever()
PYHOSTING
hosting_pid=$!

cat > "$server_cfg" <<'JSONSERVER'
{"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"qa-vless","listen":"10.254.72.2","listen_port":19182,"users":[{"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
JSONSERVER
chmod 0600 "$server_cfg"
"$core" check -c "$server_cfg"
ip netns exec "$peer" "$core" run -c "$server_cfg" >/run/sc-qa-tun-server.log 2>&1 &
server_pid=$!

ready=no
attempt=0
while [ "$attempt" -lt 25 ]; do
  if expect_source 5.22.0.10 10.254.72.1 &&
     expect_source 8.8.8.8 10.254.72.1 &&
     expect_foreign_hosted_reply; then
    ready=yes
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || { echo "QA VLESS server exited" >&2; exit 1; }
  kill -0 "$hosting_pid" 2>/dev/null || { echo "QA hosting service exited" >&2; exit 1; }
  attempt=$((attempt+1))
  sleep 0.2
done
test "$ready" = yes || { echo "disposable origins not ready" >&2; exit 1; }
witness_baseline=$(direct_witness_packets)
if [ "$witness_baseline" -le 0 ]; then
  echo 'FAIL: direct-path packet witness did not detect positive-control traffic' >&2
  exit 1
fi
echo "REAL_TUN_LAB_UNTUNNELED_BASELINE=PASS (two native routes)"
echo "REAL_TUN_DIRECT_WITNESS=PASS (positive control observed $witness_baseline direct packets)"
hosting_baseline=$(hosting_reply_packets)
test "$hosting_baseline" -gt 0 || { echo 'FAIL: no positive control of foreign visitor hosting reply' >&2; exit 1; }
echo "REAL_TUN_FOREIGN_HOSTING_BASELINE=PASS (foreign visitor request/reply, packets=$hosting_baseline)"

# Generate the candidate via the actual manager compiler, not a manually
# duplicated sing-box config. The fixed lab credentials are not user secrets.
/root/qa-tun-config-qa > "$client_cfg"
chmod 0600 "$client_cfg"
"$core" check -c "$client_cfg"
"$core" run -c "$client_cfg" >/run/sc-qa-tun-client.log 2>&1 &
client_pid=$!

ready=no
attempt=0
while [ "$attempt" -lt 35 ]; do
  if [ -e /sys/class/net/sctunqa0 ]; then
    if expect_source 5.22.0.10 10.254.72.1 &&
       expect_source 8.8.8.8 8.8.8.8; then
      ready=yes
      break
    fi
  fi
  if ! kill -0 "$client_pid" 2>/dev/null; then
    cat /run/sc-qa-tun-client.log >&2
    echo "TUN client exited before verified selected-path delivery" >&2
    exit 1
  fi
  attempt=$((attempt+1))
  sleep 0.3
done
if [ "$ready" != yes ]; then
  cat /run/sc-qa-tun-client.log >&2
  echo "TUN route did not prove distinct direct/VLESS source paths" >&2
  exit 1
fi
echo "REAL_TUN_SELECTED_TCP_PATH=PASS (domestic Direct vs foreign VLESS; no HTTP proxy)"
assert_tun_policy_active || { echo 'FAIL: TUN not active before active hosting probe' >&2; exit 1; }
expect_foreign_hosted_reply
hosting_active=$(hosting_reply_packets)
test "$hosting_active" -gt "$hosting_baseline" || { echo 'FAIL: hosting replies did not reach foreign visitor while TUN active' >&2; exit 1; }
assert_tun_policy_active || { echo 'FAIL: TUN lost during active hosting probe' >&2; exit 1; }
echo "REAL_TUN_FOREIGN_HOSTING_ACTIVE=PASS (reply packets $hosting_baseline -> $hosting_active; TUN still active)"

# A completely separate proxy-unaware process must follow TUN too.
wget_result=$(env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
  /usr/bin/wget -q -T 6 -t 1 -O - http://8.8.8.8:19180/wget)
test "$wget_result" = SOURCE=8.8.8.8
echo "REAL_TUN_PROXY_UNAWARE_WGET=PASS"

assert_tun_policy_active || { echo 'FAIL: TUN and kernel policy not active before outage' >&2; exit 1; }
witness_before_outage=$(direct_witness_packets)
if [ "$witness_before_outage" -ne "$witness_baseline" ]; then
  echo 'FAIL: foreign Direct packets observed while VLESS was healthy' >&2
  exit 1
fi

# Stopping the actual VLESS server must not allow foreign-VPN-required traffic
# to silently use the ordinary direct veth path while TUN remains active.
kill "$server_pid"
wait "$server_pid" 2>/dev/null || :
server_pid=
assert_tun_policy_active || { echo 'FAIL: TUN and kernel policy lost on upstream termination' >&2; exit 1; }
if without_proxy http://8.8.8.8:19180/should-fail >/run/sc-qa-tun-leak-check 2>/dev/null; then
  echo "FAIL: VPN-required traffic silently escaped Direct" >&2
  rm -f /run/sc-qa-tun-leak-check
  exit 1
fi
if [ -s /run/sc-qa-tun-leak-check ]; then
  echo "FAIL: VPN-required origin data escaped during outage" >&2
  rm -f /run/sc-qa-tun-leak-check
  exit 1
fi
rm -f /run/sc-qa-tun-leak-check
assert_tun_policy_active || { echo 'FAIL: TUN and kernel policy did not remain active during failed foreign request' >&2; exit 1; }
witness_after_outage=$(direct_witness_packets)
if [ "$witness_after_outage" -ne "$witness_before_outage" ]; then
  echo "FAIL: foreign Direct TCP packets leaked ($witness_before_outage -> $witness_after_outage)" >&2
  exit 1
fi
echo 'REAL_TUN_POLICY_DURING_OUTAGE=PASS (live client, TUN route, installed nftables policy)'
echo 'REAL_TUN_NO_DIRECT_PACKETS_ON_UPSTREAM_LOSS=PASS (positive-controlled independent peer witness)'
expect_source 5.22.0.10 10.254.72.1
echo "REAL_TUN_UPSTREAM_LOSS=PASS (VPN path failed closed, domestic/underlay Direct preserved)"
# The isolated regression deliberately removes the real TUN after the
# preceding outage assertions, showing that a native Direct hosting reply
# alone must NEVER count as "hosting survived with active TUN".
case "${SC_QA_TUN_OUTAGE_FAULT-}" in
  '') ;;
  before-hosting)
    stop_tun_client_for_qa_fault
    expect_foreign_hosted_reply
    echo 'REAL_TUN_NEGATIVE_DIRECT_HOSTING=PASS (native reply works without TUN)'
    ;;
  after-hosting) ;;
  *) echo 'Invalid disposable TUN outage fault injection' >&2; exit 2 ;;
esac
assert_tun_policy_active || { echo 'REAL_TUN_FOREIGN_HOSTING_OUTAGE_GUARD=REJECTED (pre-hosting)' >&2; exit 1; }
expect_foreign_hosted_reply
hosting_outage=$(hosting_reply_packets)
test "$hosting_outage" -gt "$hosting_active" || { echo 'FAIL: hosting replies did not survive VLESS outage' >&2; exit 1; }
if [ "${SC_QA_TUN_OUTAGE_FAULT-}" = after-hosting ]; then
  stop_tun_client_for_qa_fault
  expect_foreign_hosted_reply
  echo 'REAL_TUN_NEGATIVE_DIRECT_HOSTING=PASS (native reply works without TUN)'
fi
assert_tun_policy_active || { echo 'REAL_TUN_FOREIGN_HOSTING_OUTAGE_GUARD=REJECTED (post-hosting)' >&2; exit 1; }
echo "REAL_TUN_FOREIGN_HOSTING_OUTAGE=PASS (reply packets $hosting_active -> $hosting_outage; TUN still active after VPN loss)"
