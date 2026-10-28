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
edge_added=no
peer_added=no
default_added=no
nft_before=

require_guest() {
  test "$(id -u)" -eq 0
  test -f /.dockerenv
  test "$(ps -p 1 -o comm=)" = systemd
  test -f /root/qa-host-assertions.sh
  test -x /root/qa-tun-config-qa
  test -x "$core"
  test -c /dev/net/tun
  test "$(ip -4 route show default)" = "default dev lo scope link metric 4242"
  test -z "$(ip -6 route show default)"
  test ! -e /sys/class/net/"$edge"
  test ! -e /sys/class/net/sctunqa0
  if ip netns list | grep -q "^$peer "; then
    echo "QA peer network namespace already exists" >&2
    exit 1
  fi
}

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  for pid in "$client_pid" "$server_pid" "$origin_pid"; do
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
  rm -f "$client_cfg" "$server_cfg" /run/sc-qa-tun-origin.log \
    /run/sc-qa-tun-server.log /run/sc-qa-tun-client.log
  # Fail, rather than claim cleanup, if the real core leaked its TUN.
  if [ -e /sys/class/net/sctunqa0 ]; then
    echo "REAL_TUN_LAB_CLEANUP=FAIL (TUN still present)" >&2
    rc=1
  fi
  if [ "$(ip -4 route show default)" != "default dev lo scope link metric 4242" ]; then
    echo "REAL_TUN_LAB_CLEANUP=FAIL (baseline default route changed)" >&2
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

require_guest
nft_before=$(nft -j list ruleset)
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
  if expect_source 5.22.0.10 10.254.72.1 && expect_source 8.8.8.8 10.254.72.1; then
    ready=yes
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || { echo "QA VLESS server exited" >&2; exit 1; }
  attempt=$((attempt+1))
  sleep 0.2
done
test "$ready" = yes || { echo "disposable origins not ready" >&2; exit 1; }
echo "REAL_TUN_LAB_UNTUNNELED_BASELINE=PASS (two native routes)"

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

# A completely separate proxy-unaware process must follow TUN too.
wget_result=$(env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
  /usr/bin/wget -q -T 6 -t 1 -O - http://8.8.8.8:19180/wget)
test "$wget_result" = SOURCE=8.8.8.8
echo "REAL_TUN_PROXY_UNAWARE_WGET=PASS"

# Stopping the actual VLESS server must not allow foreign-VPN-required traffic
# to silently use the ordinary direct veth path while TUN remains active.
kill "$server_pid"
wait "$server_pid" 2>/dev/null || :
server_pid=
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
expect_source 5.22.0.10 10.254.72.1
echo "REAL_TUN_UPSTREAM_LOSS=PASS (VPN path blocked, domestic/underlay Direct preserved)"
