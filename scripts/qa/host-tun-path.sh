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
udp_pid=
payload_pid=
ipv6_pid=
dns_pid=
tls_pid=
native_apps_pid=
native_apps_created=no
native_apps_dir=/run/sc-qa-tun-native-apps
wp_pid=
wp_fixture_created=no
wp_fixture_dir=/run/sc-qa-tun-wp
tls_cert=/run/sc-qa-tun-tls.crt
tls_key=/run/sc-qa-tun-tls.key
edge_added=no
peer_added=no
default_added=no
default_v6_added=no
tun_device_created=no
nft_before=
guard_routes_before=
guard_rules_before=
guard_v6_routes_before=
guard_v6_rules_before=

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
  test -f /root/qa-tun-sni-client.py
  test -f /root/qa-tun-native-apps.py
  test -f /root/qa-tun-payload-wire.py
  test -f /root/qa-tun-ipv6-wire.py
  test -f /root/qa-tun-wordpress-fpm.sh && test -f /root/qa-tun-wp-check.py
  test -x /usr/bin/apt-get && test -x /usr/bin/git
  test ! -e "$native_apps_dir" && test ! -L "$native_apps_dir"
  test ! -e "$wp_fixture_dir" && test ! -L "$wp_fixture_dir"
  command -v openssl >/dev/null
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
  # Keep the intended test status separate from restoration failures.
  # A deliberately rejected hosting test exits 1; any cleanup defect must
  # instead exit 97 and must NEVER emit the cleanup PASS marker.
  original_rc=$?
  cleanup_failed=no
  trap - EXIT INT TERM
  if [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ] &&
     command -v native_product_cleanup >/dev/null && ! native_product_cleanup; then
    echo 'PRODUCT_NATIVE_QA_FIXTURE_CLEANUP=FAIL (unresolved QA fixture ownership)' >&2
    cleanup_failed=yes
  fi
  # On failure during the installed product TUN experiment, the independent
  # prearmed systemd guard (NOT this shell) must own the stop/rollback.
  # Do not delete its VETH/peer first: that would destroy the exact native
  # baseline and make a valid watchdog report an unrecoverable drift.
  # The ORIGINAL test failure remains a failure even if recovery succeeds.
  if [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ] && [ "$original_rc" -ne 0 ] &&
     [ -f /var/lib/server-connect/route-activation-journal.json ]; then
    product_recovered=no
    product_receipt=
    tries=0
    while [ "$tries" -lt 65 ]; do
      if [ ! -e /var/lib/server-connect/route-activation-journal.json ]; then
        product_recovered=finalized
        break
      fi
      if product_receipt=$(/usr/local/bin/server-connect --json smart-tun-trial-status |
         /usr/bin/python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"],r
d=r["data"]
assert (d["phase"]=="trial_recovered" and d["revision"] in (2,3) and d["recovery_verified"]) or (d["phase"]=="trial_cleanup_pending" and d["revision"]==4),r
print(d["operation_id"],d["revision"])' 2>/dev/null); then
        product_recovered=yes
        break
      fi
      tries=$((tries+1))
      sleep 1
    done
    if [ "$product_recovered" = yes ]; then
      product_op=${product_receipt% *}
      product_revision=${product_receipt#* }
      if [ -n "$product_op" ] &&
         /usr/local/bin/server-connect --json smart-tun-trial-clear --operation-id "$product_op" --revision "$product_revision" |
           /usr/bin/python3 -c 'import json,sys;r=json.load(sys.stdin);assert r["ok"] and r["data"]["cleared"],r'; then
        product_recovered=finalized
      elif [ ! -e /var/lib/server-connect/route-activation-journal.json ]; then
        # The independent executor can finish between inspection and the
        # exact-operation retry. Verify the completed effects below.
        product_recovered=finalized
      else
        echo 'PRODUCT_TUN_FAILURE_CLEANUP=FAIL (exact recovered operation clearance unavailable)' >&2
        cleanup_failed=yes
      fi
    fi
    if [ "$product_recovered" = finalized ]; then
      if [ ! -e /var/lib/server-connect/route-activation-journal.json ] &&
         [ ! -e /var/lib/server-connect/smart-tun-trial.json ] &&
         [ ! -e /sys/class/net/sctunqa0 ] &&
         [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive ] &&
         [ "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive ] &&
         [ "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled ] &&
         command -v require_native_baseline >/dev/null && require_native_baseline; then
        echo 'PRODUCT_TUN_FAILURE_CLEANUP=PASS (verified finalization; QA remains failed)'
      else
        echo 'PRODUCT_TUN_FAILURE_CLEANUP=FAIL (finalization left product resources)' >&2
        cleanup_failed=yes
      fi
    elif [ "$product_recovered" = no ]; then
      echo 'PRODUCT_TUN_FAILURE_CLEANUP=FAIL (independent recovery not verified before guest teardown)' >&2
      cleanup_failed=yes
    fi
  fi
  if [ "${SC_QA_TUN_GUARD_LAB-}" = yes ] && ! qa_tun_guard_cleanup; then
    cleanup_failed=yes
  fi
  if [ "${SC_QA_TUN_OWNED_BOUNDARY-}" = yes ] && ! owned_boundary_cleanup; then
    cleanup_failed=yes
  fi
  for pid in "$client_pid" "$server_pid" "$origin_pid" "$hosting_pid" "$udp_pid" "$dns_pid" "$tls_pid" "$native_apps_pid" "$wp_pid" "$payload_pid" "$ipv6_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || :
      wait "$pid" 2>/dev/null || :
    fi
  done
  if [ "$default_v6_added" = yes ]; then
    ip -6 route del default via fd73:1::2 dev "$edge" metric 100 2>/dev/null ||
      { echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned IPv6 default route)' >&2; cleanup_failed=yes; }
  fi
  if [ "$default_added" = yes ]; then
    ip -4 route del default via 10.254.72.2 dev "$edge" metric 100 2>/dev/null ||
      { echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned default route deletion)' >&2; cleanup_failed=yes; }
  fi
  if [ "$edge_added" = yes ]; then
    ip link del dev "$edge" 2>/dev/null ||
      { echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned VETH deletion)' >&2; cleanup_failed=yes; }
  fi
  if [ "$peer_added" = yes ]; then
    # Only the disconnected disposable CI guest can request this deliberate
    # failed deletion. The outer harness must detect and repair the leak.
    if [ "${SC_QA_TUN_CLEANUP_FAULT-}" = retain-namespace ]; then
      echo 'REAL_TUN_LAB_CLEANUP=FAIL (injected namespace deletion failure)' >&2
      cleanup_failed=yes
    else
      ip netns del "$peer" 2>/dev/null ||
        { echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned namespace deletion)' >&2; cleanup_failed=yes; }
    fi
  fi
  if [ "$tun_device_created" = yes ]; then
    rm -f /dev/net/tun ||
      { echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned TUN device file deletion)' >&2; cleanup_failed=yes; }
  fi
  rm -f /run/scqa-tun-guard-controller.log "$client_cfg" "$server_cfg" /run/sc-qa-tun-origin.log \
    /run/sc-qa-tun-hosting.log /run/sc-qa-tun-udp.log /run/sc-qa-tun-payload.log \
    /run/sc-qa-tun-ipv6.log \
    /run/sc-qa-tun-dns.log /run/sc-qa-tun-server.log /run/sc-qa-tun-client.log \
    /run/sc-qa-tun-tls.log /run/sc-qa-tun-cert.log /run/sc-qa-tun-native-apps-server.log "$tls_cert" "$tls_key" ||
      { echo 'REAL_TUN_LAB_CLEANUP=FAIL (temporary QA file deletion)' >&2; cleanup_failed=yes; }
  if [ "$native_apps_created" = yes ]; then
    if ! rm -rf -- "$native_apps_dir" || [ -e "$native_apps_dir" ] || [ -L "$native_apps_dir" ]; then
      echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned native-app fixture)' >&2
      cleanup_failed=yes
    fi
  fi
  if [ "$wp_fixture_created" = yes ]; then
    if ! rm -rf -- "$wp_fixture_dir" || [ -e "$wp_fixture_dir" ] || [ -L "$wp_fixture_dir" ]; then
      echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned WordPress FPM fixture)' >&2
      cleanup_failed=yes
    fi
  fi
  # Fail, rather than claim cleanup, if the real core leaked its TUN.
  if [ -e /sys/class/net/sctunqa0 ]; then
    echo 'REAL_TUN_LAB_CLEANUP=FAIL (TUN still present)' >&2
    cleanup_failed=yes
  fi
  if [ -e /sys/class/net/scqaowned0 ]; then
    echo 'REAL_TUN_LAB_CLEANUP=FAIL (renamed QA TUN still present)' >&2
    cleanup_failed=yes
  fi
  if [ -e /sys/class/net/"$edge" ]; then
    echo 'REAL_TUN_LAB_CLEANUP=FAIL (VETH still present)' >&2
    cleanup_failed=yes
  fi
  if [ "$tun_device_created" = yes ] && { [ -e /dev/net/tun ] || [ -L /dev/net/tun ]; }; then
    echo 'REAL_TUN_LAB_CLEANUP=FAIL (created TUN device file still present)' >&2
    cleanup_failed=yes
  fi
  if namespace_inventory=$(ip netns list); then
    peer_present=$(printf '%s\n' "$namespace_inventory" |
      awk -v expected="$peer" '$1 == expected { found=1 } END { print found+0 }') ||
      { echo 'REAL_TUN_LAB_CLEANUP=FAIL (namespace inventory parsing)' >&2; cleanup_failed=yes; peer_present=1; }
    if [ "$peer_present" != 0 ]; then
      echo 'REAL_TUN_LAB_CLEANUP=FAIL (owned namespace still present)' >&2
      cleanup_failed=yes
    fi
  else
    echo 'REAL_TUN_LAB_CLEANUP=FAIL (namespace inventory inspection)' >&2
    cleanup_failed=yes
  fi
  observed_default=$(normalized_default_route) ||
    { echo 'REAL_TUN_LAB_CLEANUP=FAIL (default route read)' >&2; cleanup_failed=yes; observed_default=''; }
  if [ -n "$(ip -6 route show default)" ]; then
    echo 'REAL_TUN_LAB_CLEANUP=FAIL (IPv6 default route was not restored)' >&2
    cleanup_failed=yes
  fi
  if [ "$observed_default" != "default dev lo scope link metric 4242" ]; then
    echo "REAL_TUN_LAB_CLEANUP=FAIL (baseline default route changed; observed=[$observed_default])" >&2
    ip -4 route show table all >&2 || :
    ip -4 rule show >&2 || :
    ip -4 addr show dev lo >&2 || :
    cleanup_failed=yes
  fi
  if [ -n "$nft_before" ]; then
    if nft_after=$(nft -j list ruleset); then
      if [ "$nft_before" != "$nft_after" ]; then
        echo 'REAL_TUN_LAB_CLEANUP=FAIL (nftables ruleset drift)' >&2
        cleanup_failed=yes
      fi
    else
      echo 'REAL_TUN_LAB_CLEANUP=FAIL (nft inspection)' >&2
      cleanup_failed=yes
    fi
  fi
  if [ "$cleanup_failed" = yes ]; then
    echo "REAL_TUN_LAB_CLEANUP=FAIL (restoration incomplete; test_rc=$original_rc)" >&2
    exit 97
  fi
  echo 'REAL_TUN_LAB_CLEANUP=PASS (owned namespace, VETH, TUN, nftables and default removed)'
  exit "$original_rc"
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
direct_udp_witness_packets() { peer_counter_packets direct_udp_packets; }
visitor_origin_direct_packets() { peer_counter_packets visitor_origin_packets; }
public_icmp6_direct_packets() { peer_counter_packets public_icmp6_packets; }
payload_tcp_direct_packets() { peer_counter_packets payload_tcp_direct_packets; }
payload_udp_direct_packets() { peer_counter_packets payload_udp_direct_packets; }
ipv6_foreign_tcp_direct_packets() { peer_counter_packets ipv6_foreign_tcp_packets; }
ipv6_foreign_udp_direct_packets() { peer_counter_packets ipv6_foreign_udp_packets; }
ipv6_override_direct_packets() { peer_counter_packets ipv6_override_packets; }
ipv6_override_udp_direct_packets() { peer_counter_packets ipv6_override_udp_packets; }
direct_dns_udp_witness_packets() { peer_counter_packets direct_dns_udp_packets; }
direct_dns_tcp_witness_packets() { peer_counter_packets direct_dns_tcp_packets; }
hosting_reply_packets() { peer_counter_packets hosting_reply_packets; }
domestic_tls_direct_packets() { peer_counter_packets domestic_tls_direct_packets; }
foreign_tls_direct_packets() { peer_counter_packets foreign_tls_direct_packets; }
native_app_direct_packets() { peer_counter_packets native_app_direct_packets; }

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

# Pin the destination locally without resolver traffic; inspect actual Host.
expect_named_source() {
  host=$1 destination=$2 source=$3
  response=$(env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/curl -q --fail --silent --show-error --noproxy '*' \
    --resolve "$host:19180:$destination" --connect-timeout 3 --max-time 6 \
    "http://$host:19180/path") || return 1
  test "$response" = "SOURCE=$source"
}

# A real TLS ClientHello with operator-supplied SNI is sent to a pinned IP,
# bypassing system DNS. The independent peer reports the actual source path.
tls_path() {
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/python3 -I -B /root/qa-tun-sni-client.py "$1" "$2" "$3" "$4"
}

# Actual APT and Git clients run with empty environments, isolated private
# sources/cache and no application proxy. The peer-namespace HTTP origin
# independently records source addresses; nftables records native leaks.
native_apps() {
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/python3 -I -B /root/qa-tun-native-apps.py "$1"
}

wp_probe() {
  # WordPress/PHP-FPM performs a genuine HTTP API call without WP_PROXY_*,
  # per-application environment proxy or process tracking. The HTTP peer and
  # native nftables counter separately prove delivery versus Direct leakage.
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /bin/sh /root/qa-tun-wordpress-fpm.sh probe "$1" "$2"
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

# Genuine proxy-unaware UDP socket: the peer namespace reports its observed
# sender address and echoes a phase-specific token. No HTTP proxy, resolver,
# shell /dev/udp extension, or sing-box control-plane socket participates.
udp_path() {
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/python3 - "$1" "$2" "$3" "$4" <<'PYUDPCLIENT'
import errno
import socket
import sys

destination, expected_source, token, mode = sys.argv[1:]
if mode not in ("reply", "no-reply"):
    raise SystemExit("invalid UDP QA mode")
payload = ("scqa-udp:" + token).encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
reply = None
try:
    sock.sendto(payload, (destination, 19186))
    reply, _ = sock.recvfrom(256)
except socket.timeout:
    pass
except OSError as exc:
    # During a deliberately dead VLESS upstream, an explicit kernel error is
    # also a failed VPN-required request, not successful Direct delivery.
    if mode != "no-reply" or exc.errno not in (
        errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED,
        errno.EPERM, errno.EACCES
    ):
        raise
finally:
    sock.close()

if mode == "no-reply":
    if reply is not None:
        raise SystemExit("UDP VPN-required reply escaped during outage")
    print("REAL_TUN_UDP_OUTAGE_NO_RESPONSE=PASS")
else:
    expected = b"SOURCE=" + expected_source.encode() + b";ECHO=" + payload
    if reply != expected:
        raise SystemExit("UDP source-path/echo mismatch: " + repr(reply))
PYUDPCLIENT
}

ipv6_path() {
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/python3 -I -B /root/qa-tun-ipv6-wire.py "$@"
}

icmp6_path() {
  # Exact synthetic peer only: distinguish required local ND from a broad
  # public ICMPv6 exception. Kernel checksum handling is used for ICMPv6.
  python3 - "$1" <<'PYICMP6PATH'
import errno,os,socket,struct,sys,time
mode=sys.argv[1]
assert mode in ('reply','no-reply')
token=os.urandom(16);request=struct.pack('!BBHHH',128,0,0,0x5ca1,1)+token
found=False
with socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6) as sock:
    sock.bind(('fd73:1::1',0));sock.settimeout(2)
    try:sock.sendto(request,('2001:db8:8::8',0))
    except OSError as error:
        if mode!='no-reply' or error.errno not in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH):raise
        sys.exit(0)
    end=time.monotonic()+2
    while time.monotonic()<end:
        sock.settimeout(max(0.01,end-time.monotonic()))
        try:reply,source=sock.recvfrom(2048)
        except socket.timeout:break
        if source[0]=='2001:db8:8::8' and len(reply)==len(request) and reply[0]==129 and reply[4:]==request[4:]:
            found=True;break
assert found==(mode=='reply'), 'unexpected public ICMPv6 echo result'
PYICMP6PATH
}

payload_path() {
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/python3 -I -B /root/qa-tun-payload-wire.py "$@"
}

dns_path() {
  # Real DNS wire frames, not an HTTP proxy or fake DNS-success marker.
  # Unique query names prevent accepting cached answers.
  env -i HOME=/root PATH=/usr/bin:/bin:/sbin:/usr/sbin \
    /usr/bin/python3 -I -B /root/qa-tun-dns-client.py "$1" "$2" "$3" "$4" "$5"
}

case "${SC_QA_TUN_PRODUCT_LAB-}" in
  ''|'yes') ;;
  *) echo 'Invalid isolated installed-product TUN mode' >&2; exit 2 ;;
esac
case "${SC_QA_TUN_OWNED_BOUNDARY-}" in
  '') ;;
  yes)
    if [ "${SC_QA_TUN_IPV6-}" != yes ] ||
       [ -n "${SC_QA_TUN_PRODUCT_LAB-}" ] || [ -n "${SC_QA_TUN_GUARD_LAB-}" ] ||
       [ -n "${SC_QA_TUN_OUTAGE_FAULT-}" ] || [ -n "${SC_QA_TUN_CLEANUP_FAULT-}" ]; then
      echo 'OWNED_TUN_BOUNDARY=FAIL (requires exclusive explicit dual-stack fixture)' >&2; exit 2
    fi
    . /root/qa-owned-tun-boundary.sh ;;
  *) echo 'Invalid isolated owned TUN boundary mode' >&2; exit 2 ;;
esac
if [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ] && [ "${SC_QA_TUN_GUARD_LAB-}" = yes ]; then
  echo 'Concurrent distinct TUN guard modes are unsupported' >&2; exit 2
fi
case "${SC_QA_TUN_GUARD_LAB-}" in
  '' ) ;;
  yes ) . /root/qa-tun-guard-unit-lab.sh ;;
  * ) echo 'Invalid real-TUN guard laboratory mode' >&2; exit 2 ;;
esac
case "${SC_QA_TUN_GUARD_CLEANUP_FAULT-}" in
  '' ) ;;
  masked-recovery-unit )
    [ "${SC_QA_TUN_GUARD_LAB-}" = yes ] || exit 2 ;;
  * ) echo 'Invalid real-TUN guard cleanup fault mode' >&2; exit 2 ;;
esac

# The dual-stack trial is explicitly opted in, strictly disposable and
# excluded from manager-death/hosting/cleanup fault-injection scenarios.
case "${SC_QA_TUN_IPV6-}" in
  '') ipv6_trial=no ;;
  yes)
    if [ "${SC_QA_TUN_GUARD_LAB-}" = yes ] ||
       [ -n "${SC_QA_TUN_OUTAGE_FAULT-}" ] ||
       [ -n "${SC_QA_TUN_CLEANUP_FAULT-}" ]; then
      echo 'REAL_TUN_IPV6=FAIL (dual-stack trial cannot combine with fault modes)' >&2
      exit 2
    fi
    ipv6_trial=yes ;;
  *) echo 'REAL_TUN_IPV6=FAIL (unsupported QA mode)' >&2; exit 2 ;;
esac

# Large-payload QA runs only in the normal disposable positive/outage guest.
# Avoid expanding unrelated deadline, hosting and forced-cleanup regressions.
payload_trial=no
if [ "${SC_QA_TUN_GUARD_LAB-}" != yes ] &&
   [ -z "${SC_QA_TUN_OUTAGE_FAULT-}" ] &&
   [ -z "${SC_QA_TUN_CLEANUP_FAULT-}" ]; then
  payload_trial=yes
fi

guarded_real_tun_deadline_trial() {
  # Stop the original shell-owned test TUN first. The second activation is
  # from a different manager/controller, and PID1 must stop it independently.
  stop_tun_client_for_qa_fault
  test "$(nft -j list ruleset)" = "$nft_before" &&
    test "$(ip -N -j -4 route show table all)" = "$guard_routes_before" &&
    test "$(ip -N -j -4 rule show)" = "$guard_rules_before" &&
    test "$(ip -N -j -6 route show table all)" = "$guard_v6_routes_before" &&
    test "$(ip -N -j -6 rule show)" = "$guard_v6_rules_before" || {
      echo 'QA_TUN_GUARD_BASELINE=FAIL (initial TUN did not restore)' >&2
      return 1
    }
  qa_tun_guard_prepare
  # Discriminating negative: a loaded but INACTIVE timer is not an armed
  # recovery executor and must never be accepted before starting real TUN.
  if qa_tun_guard_prearmed || [ -e /sys/class/net/sctunqa0 ]; then
    echo 'QA_TUN_GUARD_UNARMED_FALSE_PASS=FAIL' >&2
    return 1
  fi
  echo 'QA_TUN_GUARD_UNARMED_FALSE_PASS_REJECTED=PASS'

  # The child must die from actual SIGKILL after starting a deadline timer
  # and a real TUN via separate systemd units. No parent-driven stop is used
  # before the deadline. The recovery service runs in PID1's unit lifecycle.
  controller_rc=0
  /bin/sh /root/qa-tun-guard-unit-lab.sh controller \
    >/run/scqa-tun-guard-controller.log 2>&1 || controller_rc=$?
  test "$controller_rc" -eq 137 &&
    grep -Fx 'QA_TUN_GUARD_TIMER_PREARMED=PASS' /run/scqa-tun-guard-controller.log >/dev/null &&
    grep -Fx 'QA_TUN_GUARD_CLIENT_STARTED=PASS' /run/scqa-tun-guard-controller.log >/dev/null || {
      echo "QA_TUN_GUARD_CONTROLLER=FAIL (rc=$controller_rc)" >&2
      cat /run/scqa-tun-guard-controller.log >&2
      return 1
    }
  echo 'QA_TUN_GUARD_CONTROLLER_SIGKILL=PASS'

  managed_pid=$(qa_tun_unit_state "$qa_tun_client_unit" MainPID)
  case "$managed_pid" in ''|0|*[!0-9]*)
    echo 'QA_TUN_GUARD_CLIENT_IDENTITY=FAIL (no fresh PID)' >&2; return 1 ;;
  esac
  test "$(readlink -f "/proc/$managed_pid/exe")" = "$core" &&
    test "$(qa_tun_unit_state "$qa_tun_client_unit" ActiveState)" = active &&
    test "$(qa_tun_unit_state "$qa_tun_recover_timer" ActiveState)" = active &&
    test "$(qa_tun_unit_state "$qa_tun_recover_unit" ExecMainStartTimestampMonotonic)" = 0 || {
      echo 'QA_TUN_GUARD_CLIENT_IDENTITY=FAIL (wrong managed process, fired timer or dead timer)' >&2
      return 1
    }

  managed_ready=no
  tries=0
  while [ "$tries" -lt 40 ]; do
    if [ -e /sys/class/net/sctunqa0 ] &&
      expect_source 5.22.0.10 10.254.72.1 &&
      expect_source 8.8.8.8 8.8.8.8; then
      managed_ready=yes
      break
    fi
    tries=$((tries + 1))
    sleep 0.2
  done
  test "$managed_ready" = yes || {
    echo 'QA_TUN_GUARD_SELECTED_PATH=FAIL (no live managed TUN)' >&2
    return 1
  }
  udp_path 8.8.8.8 8.8.8.8 guard-foreign-udp reply
  dns_path 8.8.8.8 192.0.2.22 guard-foreign-dns udp reply
  expect_foreign_hosted_reply
  test "$(direct_witness_packets)" -eq "$witness_baseline" &&
    test "$(direct_udp_witness_packets)" -eq "$udp_witness_baseline" &&
    test "$(direct_dns_udp_witness_packets)" -eq "$dns_udp_baseline" &&
    test "$(qa_tun_unit_state "$qa_tun_client_unit" ActiveState)" = active &&
    test "$(qa_tun_unit_state "$qa_tun_recover_timer" ActiveState)" = active || {
      echo 'QA_TUN_GUARD_SELECTED_PATH=FAIL (Direct leak/guard gone)' >&2
      return 1
    }
  echo 'QA_TUN_GUARD_SELECTED_PATH=PASS (real VLESS while controller dead)'

  # The original controller is dead. ONLY the prearmed systemd timer can
  # trigger its independent oneshot. A stale/default Result=success without
  # a fresh ExecMain timestamp cannot pass this assertion.
  recovered=no
  tries=0
  while [ "$tries" -lt 90 ]; do
    triggered=$(qa_tun_unit_state "$qa_tun_recover_unit" ExecMainStartTimestampMonotonic)
    case "$triggered" in ''|0|*[!0-9]*) triggered=0 ;; esac
    if [ "$triggered" -gt 0 ] &&
      [ "$(qa_tun_unit_state "$qa_tun_recover_unit" Result)" = success ] &&
      [ "$(qa_tun_unit_state "$qa_tun_recover_unit" ExecMainStatus)" = 0 ] &&
      [ "$(qa_tun_unit_state "$qa_tun_client_unit" ActiveState)" = inactive ] &&
      [ ! -e /sys/class/net/sctunqa0 ]; then
      recovered=yes
      break
    fi
    tries=$((tries + 1))
    sleep 0.5
  done
  test "$recovered" = yes || {
    echo 'QA_TUN_GUARD_DEADLINE=FAIL (no fresh independent stop)' >&2
    return 1
  }
  test "$(nft -j list ruleset)" = "$nft_before" &&
    test "$(ip -N -j -4 route show table all)" = "$guard_routes_before" &&
    test "$(ip -N -j -4 rule show)" = "$guard_rules_before" &&
    test "$(ip -N -j -6 route show table all)" = "$guard_v6_routes_before" &&
    test "$(ip -N -j -6 rule show)" = "$guard_v6_rules_before" || {
      echo 'QA_TUN_GUARD_RECOVERY=FAIL (native kernel did not restore)' >&2
      # Failure-only evidence: identify the exact native resource that drifted.
      # The guest contains fixed QA fixtures, never operator credentials.
      observed=$(nft -j list ruleset) || observed='INSPECTION_FAILED'
      if [ "$observed" != "$nft_before" ]; then
        printf 'QA_TUN_GUARD_DRIFT=nftables expected=%s observed=%s\n' "$nft_before" "$observed" >&2
      fi
      observed=$(ip -N -j -4 route show table all) || observed='INSPECTION_FAILED'
      if [ "$observed" != "$guard_routes_before" ]; then
        printf 'QA_TUN_GUARD_DRIFT=ipv4-routes expected=%s observed=%s\n' "$guard_routes_before" "$observed" >&2
      fi
      observed=$(ip -N -j -4 rule show) || observed='INSPECTION_FAILED'
      if [ "$observed" != "$guard_rules_before" ]; then
        printf 'QA_TUN_GUARD_DRIFT=ipv4-rules expected=%s observed=%s\n' "$guard_rules_before" "$observed" >&2
      fi
      observed=$(ip -N -j -6 route show table all) || observed='INSPECTION_FAILED'
      if [ "$observed" != "$guard_v6_routes_before" ]; then
        printf 'QA_TUN_GUARD_DRIFT=ipv6-routes expected=%s observed=%s\n' "$guard_v6_routes_before" "$observed" >&2
      fi
      observed=$(ip -N -j -6 rule show) || observed='INSPECTION_FAILED'
      if [ "$observed" != "$guard_v6_rules_before" ]; then
        printf 'QA_TUN_GUARD_DRIFT=ipv6-rules expected=%s observed=%s\n' "$guard_v6_rules_before" "$observed" >&2
      fi
      return 1
    }
  expect_source 5.22.0.10 10.254.72.1
  expect_source 8.8.8.8 10.254.72.1
  dns_path 8.8.8.8 192.0.2.11 guard-restored-direct udp reply
  expect_foreign_hosted_reply
  echo 'QA_TUN_GUARD_DEADLINE_RECOVERY=PASS (PID1 stop, exact guest baseline)'
  echo 'QA_TUN_GUARD_DIRECT_OFF=PASS (new Direct paths, no VPN-only block)'
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
if [ "$ipv6_trial" = yes ]; then
  # Disconnected guest only. No claimed Iranian IPv6 geolocation or
  # physical-host IPv6 safety. Loopback destinations are synthetic peers.
  test "$(cat /proc/sys/net/ipv6/conf/"$edge"/disable_ipv6)" = 0 || {
    echo 'REAL_TUN_IPV6=FAIL (guest IPv6 disabled)' >&2; exit 1;
  }
  ip -6 addr add fd73:1::1/64 dev "$edge"
  ip -n "$peer" -6 addr add fd73:1::2/64 dev scqapeer0
  for addr in 2001:db8:5::10 2001:db8:5::11 2001:db8:8::8 2001:db8:8::9; do
    ip -n "$peer" -6 addr add "$addr"/128 dev lo
  done
  ip -6 route add default via fd73:1::2 dev "$edge" metric 100
  default_v6_added=yes
fi
# Independent peer-side packet counter: an ordinary Direct foreign TCP flow
# must cross this VETH; the VLESS server's local-origin flow cannot count.
ip netns exec "$peer" nft -f - <<'NFTWITNESS'
table inet scqawitness {
  counter direct_packets { }
  counter direct_udp_packets { }
  counter visitor_origin_packets { }
  counter public_icmp6_packets { }
  counter ipv6_foreign_tcp_packets { }
  counter ipv6_foreign_udp_packets { }
  counter ipv6_override_packets { }
  counter ipv6_override_udp_packets { }
  counter payload_tcp_direct_packets { }
  counter payload_udp_direct_packets { }
  counter direct_dns_udp_packets { }
  counter direct_dns_tcp_packets { }
  counter domestic_tls_direct_packets { }
  counter foreign_tls_direct_packets { }
  counter native_app_direct_packets { }
  counter hosting_reply_packets { }
  chain incoming {
    type filter hook input priority filter; policy accept;
    iifname "scqapeer0" ip daddr 8.8.8.8 tcp dport 19180 counter name direct_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 udp dport 19186 counter name direct_udp_packets
    iifname "scqapeer0" ip daddr 198.51.100.42 tcp dport 19180 counter name visitor_origin_packets
    iifname "scqapeer0" ip6 daddr 2001:db8:8::8 icmpv6 type echo-request counter name public_icmp6_packets
    iifname "scqapeer0" ip6 daddr 2001:db8:8::8 tcp dport 19192 counter name ipv6_foreign_tcp_packets
    iifname "scqapeer0" ip6 daddr 2001:db8:8::8 udp dport 19193 counter name ipv6_foreign_udp_packets
    iifname "scqapeer0" ip6 daddr 2001:db8:5::10 tcp dport 19192 counter name ipv6_override_packets
    iifname "scqapeer0" ip6 daddr 2001:db8:5::10 udp dport 19193 counter name ipv6_override_udp_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 tcp dport 19188 counter name payload_tcp_direct_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 udp dport 19189 counter name payload_udp_direct_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 udp dport 53 counter name direct_dns_udp_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 tcp dport 53 counter name direct_dns_tcp_packets
    iifname "scqapeer0" ip daddr 5.22.0.10 tcp dport 19181 counter name domestic_tls_direct_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 tcp dport 19181 counter name foreign_tls_direct_packets
    iifname "scqapeer0" ip daddr 8.8.8.8 tcp dport 19187 counter name native_app_direct_packets
    iifname "scqapeer0" ip saddr 10.254.72.1 ip daddr 198.51.100.42 tcp sport 19184 counter name hosting_reply_packets
  }
}
NFTWITNESS
ip -4 route add default via 10.254.72.2 dev "$edge" metric 100
default_added=yes

# No public repository, package installation or host APT source edits:
# generate disposable index/Git objects in the guest before networking.
native_apps prepare
# Only a successful, atomic helper-created fixture can be removed by the
# parent. On any failed preflight/mkdir the path may be foreign-owned.
native_apps_created=yes
ip netns exec "$peer" /usr/bin/python3 -I -B -u /root/qa-tun-native-apps.py serve \
  >/run/sc-qa-tun-native-apps-server.log 2>&1 &
native_apps_pid=$!

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

# Ephemeral test certificate is generated entirely inside the disconnected
# guest; the QA client deliberately skips public-PKI verification. Only the
# TLS ClientHello/SNI and independently witnessed destination path matter.
if ! openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=scqa.test' -keyout "$tls_key" -out "$tls_cert" \
  >/run/sc-qa-tun-cert.log 2>&1; then
  cat /run/sc-qa-tun-cert.log >&2
  echo 'REAL_TUN_TLS_SETUP=FAIL (ephemeral guest certificate)' >&2
  exit 1
fi
ip netns exec "$peer" python3 -u - "$tls_cert" "$tls_key" \
  >/run/sc-qa-tun-tls.log 2>&1 <<'PYTLSSERVER' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import sys

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = ("SOURCE=" + self.client_address[0]).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass

# Do the TLS handshake INSIDE each worker thread, not on the listening
# socket's main accept() loop. A deliberately failed VPN/SNI handshake must
# not stall or reset an unrelated Direct positive control. The real packet
# route/source witnesses remain unchanged and still fail if Direct fails.
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=sys.argv[1], keyfile=sys.argv[2])
class TLSOrigin(ThreadingHTTPServer):
    def finish_request(self, request, client_address):
        request.settimeout(3)
        with ctx.wrap_socket(request, server_side=True) as secured:
            super().finish_request(secured, client_address)
TLSOrigin(("0.0.0.0", 19181), Handler).serve_forever()
PYTLSSERVER
tls_pid=$!

# Peer-side independent UDP echo endpoint. The observed sender proves whether
# a proxy-unaware UDP request reached it via native VETH or VLESS egress.
ip netns exec "$peer" python3 -u - >/run/sc-qa-tun-udp.log 2>&1 <<'PYUDPSERVER' &
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 19186))
while True:
    payload, sender = sock.recvfrom(256)
    if payload.startswith(b"scqa-udp:"):
        sock.sendto(b"SOURCE=" + sender[0].encode() + b";ECHO=" + payload, sender)
PYUDPSERVER
udp_pid=$!

# Independent peer receives full binary TCP/UDP transfers, not an application
# success marker. Actual observed source and echoed bytes prove delivery.
ip netns exec "$peer" /usr/bin/python3 -I -B -u /root/qa-tun-payload-wire.py serve \
  >/run/sc-qa-tun-payload.log 2>&1 &
payload_pid=$!

if [ "$ipv6_trial" = yes ]; then
  ip netns exec "$peer" /usr/bin/python3 -I -B -u /root/qa-tun-ipv6-wire.py serve \
    >/run/sc-qa-tun-ipv6.log 2>&1 &
  ipv6_pid=$!
fi

# The peer answers genuine DNS UDP and TCP messages. The A record identifies
# the request source observed by an independent authoritative server.
ip netns exec "$peer" /usr/bin/python3 -I -B -u /root/qa-tun-dns-peer.py \
  >/run/sc-qa-tun-dns.log 2>&1 &
dns_pid=$!

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
     tls_path native.scqa.test 5.22.0.10 10.254.72.1 reply &&
     tls_path native.scqa.test 8.8.8.8 10.254.72.1 reply &&
     udp_path 5.22.0.10 10.254.72.1 ready-domestic reply &&
     udp_path 8.8.8.8 10.254.72.1 ready-foreign reply &&
     dns_path 5.22.0.10 192.0.2.11 ready-domestic-udp udp reply &&
     dns_path 8.8.8.8 192.0.2.11 ready-foreign-udp udp reply &&
     dns_path 8.8.8.8 192.0.2.11 ready-foreign-tcp tcp reply &&
     expect_foreign_hosted_reply &&
     without_proxy http://8.8.8.8:19187/apt/dists/qa/Release | grep -Fq "Origin: Server Connect isolated TUN QA"; then
    ready=yes
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || { echo "QA VLESS server exited" >&2; exit 1; }
  kill -0 "$hosting_pid" 2>/dev/null || { echo "QA hosting service exited" >&2; exit 1; }
  kill -0 "$udp_pid" 2>/dev/null || { echo "QA UDP service exited" >&2; exit 1; }
  kill -0 "$tls_pid" 2>/dev/null || { echo "QA TLS service exited" >&2; cat /run/sc-qa-tun-tls.log >&2; exit 1; }
  kill -0 "$native_apps_pid" 2>/dev/null || { echo "QA APT/Git origin exited" >&2; cat /run/sc-qa-tun-native-apps-server.log >&2; exit 1; }
  kill -0 "$dns_pid" 2>/dev/null || { echo "QA DNS server exited" >&2; exit 1; }
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
if [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ]; then
  expect_source 198.51.100.42 10.254.72.1
  visitor_origin_baseline=$(visitor_origin_direct_packets)
  test "$visitor_origin_baseline" -gt 0
  echo PRODUCT_NATIVE_VISITOR_ORIGIN_DIRECT_CONTROL=PASS
fi
domestic_tls_baseline=$(domestic_tls_direct_packets)
foreign_tls_baseline=$(foreign_tls_direct_packets)
test "$domestic_tls_baseline" -gt 0 && test "$foreign_tls_baseline" -gt 0 || {
  echo "REAL_TUN_TLS_SNI_BASELINE=FAIL (missing positive native TLS witnesses)" >&2
  exit 1
}
echo "REAL_TUN_TLS_SNI_BASELINE=PASS (domestic/foreign positive native packet controls)"
native_apps_before=$(native_app_direct_packets)
native_apps baseline
native_apps_baseline=$(native_app_direct_packets)
test "$native_apps_baseline" -gt "$native_apps_before" || {
  echo 'REAL_TUN_NATIVE_APPS_BASELINE=FAIL (no native packet positive-control)' >&2
  exit 1
}
echo 'REAL_TUN_NATIVE_APPS_WITNESS=PASS (native APT/Git baseline positive-control)'
if [ "$ipv6_trial" = yes ]; then
  # IPv6 DAD and the independent server must both settle before claiming a
  # real native Direct positive-control baseline.
  ipv6_ready=no
  tries=0
  while [ "$tries" -lt 60 ]; do
    if ! ip -6 addr show dev "$edge" | grep -Eq 'tentative|dadfailed' &&
      ipv6_path tcp 2001:db8:8::8 fd73:1::1 reply &&
      ipv6_path udp 2001:db8:8::8 fd73:1::1 reply &&
      ipv6_path tcp 2001:db8:5::10 fd73:1::1 reply &&
      ipv6_path udp 2001:db8:5::10 fd73:1::1 reply; then
      ipv6_ready=yes
      break
    fi
    kill -0 "$ipv6_pid" 2>/dev/null || {
      echo 'REAL_TUN_IPV6=FAIL (independent IPv6 origin died)' >&2; exit 1;
    }
    tries=$((tries+1))
    sleep 0.2
  done
  test "$ipv6_ready" = yes || {
    echo 'REAL_TUN_IPV6=FAIL (native baseline or DAD unavailable)' >&2; exit 1;
  }
  ipv6_foreign_tcp_baseline=$(ipv6_foreign_tcp_direct_packets)
  ipv6_foreign_udp_baseline=$(ipv6_foreign_udp_direct_packets)
  ipv6_override_baseline=$(ipv6_override_direct_packets)
  ipv6_override_udp_baseline=$(ipv6_override_udp_direct_packets)
  test "$ipv6_foreign_tcp_baseline" -gt 0 &&
    test "$ipv6_foreign_udp_baseline" -gt 0 &&
    test "$ipv6_override_baseline" -gt 0 &&
    test "$ipv6_override_udp_baseline" -gt 0 || {
      echo 'REAL_TUN_IPV6=FAIL (missing native Direct positive-control counters)' >&2; exit 1;
    }
  echo 'REAL_TUN_IPV6_DIRECT_BASELINE=PASS (independent TCP/UDP source and native counters)'
  echo 'REAL_TUN_IPV6_OVERRIDE_UDP_DIRECT_BASELINE=PASS (native UDP positive-controlled counter)'
  if [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ]; then
    icmp6_path reply
    public_icmp6_baseline=$(public_icmp6_direct_packets)
    test "$public_icmp6_baseline" -gt 0
    echo PRODUCT_NATIVE_PUBLIC_ICMP6_DIRECT_CONTROL=PASS
  fi
fi
if [ "$payload_trial" = yes ]; then
  payload_path tcp 8.8.8.8 10.254.72.1 reply
  payload_path udp 8.8.8.8 10.254.72.1 reply
  payload_tcp_baseline=$(payload_tcp_direct_packets)
  payload_udp_baseline=$(payload_udp_direct_packets)
  test "$payload_tcp_baseline" -gt 0 && test "$payload_udp_baseline" -gt 0 || {
    echo 'REAL_TUN_PAYLOAD_DIRECT_BASELINE=FAIL (missing native positive controls)' >&2
    exit 1
  }
  echo 'REAL_TUN_PAYLOAD_DIRECT_BASELINE=PASS (TCP and UDP independent native counters)'
fi
if [ "${SC_QA_TUN_GUARD_LAB-}" != yes ]; then
  # mkdir is exclusive: only a successfully created QA-owned fixture is
  # eligible for cleanup, including when WordPress setup partially fails.
  mkdir -m 0755 "$wp_fixture_dir"
  wp_fixture_created=yes
  /bin/sh /root/qa-tun-wordpress-fpm.sh setup
  /usr/sbin/php-fpm8.4 --nodaemonize --fpm-config "$wp_fixture_dir/fpm.conf" \
    >"$wp_fixture_dir/fpm-start.log" 2>&1 &
  wp_pid=$!
  wp_ready=no
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if kill -0 "$wp_pid" 2>/dev/null && test -S "$wp_fixture_dir/fpm.sock"; then
      wp_ready=yes
      break
    fi
    sleep 0.2
  done
  test "$wp_ready" = yes || { echo 'REAL_TUN_WORDPRESS=FAIL (FPM failed to start)' >&2; exit 1; }
  wp_probe positive 10.254.72.1
  wp_baseline=$(native_app_direct_packets)
  test "$wp_baseline" -gt "$native_apps_baseline" || {
    echo 'REAL_TUN_WORDPRESS=FAIL (missing native Direct positive-control)' >&2; exit 1;
  }
  native_apps_baseline=$wp_baseline
fi
udp_witness_baseline=$(direct_udp_witness_packets)
test "$udp_witness_baseline" -gt 0 || { echo 'FAIL: no positive native foreign UDP packet witness' >&2; exit 1; }
echo "REAL_TUN_UDP_DIRECT_WITNESS=PASS (native foreign UDP packets=$udp_witness_baseline)"
dns_udp_baseline=$(direct_dns_udp_witness_packets)
dns_tcp_baseline=$(direct_dns_tcp_witness_packets)
test "$dns_udp_baseline" -gt 0 && test "$dns_tcp_baseline" -gt 0 || {
  echo "FAIL: native Direct DNS UDP/TCP packet witnesses lack positive controls" >&2
  exit 1
}
echo "REAL_TUN_DNS_DIRECT_WITNESS=PASS (native DNS UDP/TCP positive controls)"
hosting_baseline=$(hosting_reply_packets)
test "$hosting_baseline" -gt 0 || { echo 'FAIL: no positive control of foreign visitor hosting reply' >&2; exit 1; }
echo "REAL_TUN_FOREIGN_HOSTING_BASELINE=PASS (foreign visitor request/reply, packets=$hosting_baseline)"
if [ "${SC_QA_TUN_GUARD_LAB-}" = yes ] || [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ]; then
  # The disposable VETH may still be doing IPv6 duplicate-address detection.
  # Its fe80:: local /128 route appears only after DAD finishes. Capturing
  # before then produces a false rollback failure 25s later even when the
  # real TUN and all its routing state were removed correctly. Wait for the
  # guest's native link-local baseline to settle BEFORE the first TUN.
  if [ -r "/proc/sys/net/ipv6/conf/$edge/disable_ipv6" ] &&
     [ "$(cat "/proc/sys/net/ipv6/conf/$edge/disable_ipv6")" = 0 ]; then
    dad_ready=no
    tries=0
    while [ "$tries" -lt 80 ]; do
      if ip -6 route show table local dev "$edge" | grep -Eq '^local fe80:' &&
         ! ip -6 addr show dev "$edge" | grep -Eq 'tentative|dadfailed'; then
        dad_ready=yes
        break
      fi
      tries=$((tries + 1))
      sleep 0.1
    done
    if [ "$dad_ready" != yes ]; then
      echo 'QA_TUN_GUARD_IPV6_BASELINE=FAIL (guest link-local DAD did not settle)' >&2
      exit 1
    fi
    echo 'QA_TUN_GUARD_IPV6_BASELINE=PASS (native link-local DAD settled)'
  else
    echo 'QA_TUN_GUARD_IPV6_BASELINE=UNSUPPORTED (guest IPv6 disabled)'
  fi
  guard_routes_before=$(ip -N -j -4 route show table all)
  guard_rules_before=$(ip -N -j -4 rule show)
  guard_v6_routes_before=$(ip -N -j -6 route show table all)
  guard_v6_rules_before=$(ip -N -j -6 rule show)
fi

# Separate installed-product guard trial reuses the identical peer paths
# but starts the real TUN through its installed manager/systemd ownership.
if [ "${SC_QA_TUN_PRODUCT_LAB-}" = yes ]; then
  . /root/qa-product-tun-trial.sh
  product_tun_trial
  exit 0
fi
if [ "${SC_QA_TUN_OWNED_BOUNDARY-}" = yes ]; then
  owned_tun_boundary_trial
  exit 0
fi

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
  # TUN existence alone precedes completed native RPDB/nft installation.
  # Never send a foreign probe into that window: a correct startup can
  # otherwise leak a test packet before the redirect is armed. The exact
  # independent Direct-witness baseline stays fixed and must not be reset.
  if assert_tun_policy_active; then
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
# A positive VLESS response is not sufficient if an earlier attempt escaped
# to Direct. Preserve the pre-TUN positive-control witness across all retries
# and fail with the actual native count, not an unrelated downstream label.
witness_at_ready=$(direct_witness_packets) || {
  echo 'REAL_TUN_SELECTED_TCP_PATH=FAIL (native Direct witness unavailable)' >&2
  exit 1
}
if [ "$witness_at_ready" -ne "$witness_baseline" ]; then
  echo "REAL_TUN_SELECTED_TCP_PATH=FAIL (foreign Direct packets during startup: baseline=$witness_baseline observed=$witness_at_ready)" >&2
  exit 1
fi
echo "REAL_TUN_SELECTED_TCP_PATH=PASS (domestic Direct vs foreign VLESS; no HTTP proxy)"
if [ "$ipv6_trial" = yes ]; then
  ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null || {
    echo 'REAL_TUN_IPV6=FAIL (no active kernel IPv6 TUN route)' >&2; exit 1;
  }
  ipv6_path tcp 2001:db8:5::11 fd73:1::1 reply
  ipv6_path udp 2001:db8:5::11 fd73:1::1 reply
  # The explicitly VPN-only domestic host must override the /64 Direct rule.
  ipv6_path tcp 2001:db8:5::10 2001:db8:5::10 reply
  ipv6_path udp 2001:db8:5::10 2001:db8:5::10 reply
  # Foreign defaults to VLESS; explicit foreign host Direct stays deliberate.
  ipv6_path tcp 2001:db8:8::8 2001:db8:8::8 reply
  ipv6_path udp 2001:db8:8::8 2001:db8:8::8 reply
  ipv6_path tcp 2001:db8:8::9 fd73:1::1 reply
  ipv6_path udp 2001:db8:8::9 fd73:1::1 reply
  test "$(ipv6_foreign_tcp_direct_packets)" -eq "$ipv6_foreign_tcp_baseline" &&
    test "$(ipv6_foreign_udp_direct_packets)" -eq "$ipv6_foreign_udp_baseline" &&
    test "$(ipv6_override_direct_packets)" -eq "$ipv6_override_baseline" &&
    test "$(ipv6_override_udp_direct_packets)" -eq "$ipv6_override_udp_baseline" || {
      echo 'REAL_TUN_IPV6=FAIL (VPN-required IPv6 leaked native Direct)' >&2; exit 1;
    }
  assert_tun_policy_active || { echo 'REAL_TUN_IPV6=FAIL (TUN/IPv4 policy disappeared)' >&2; exit 1; }
  ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null || {
    echo 'REAL_TUN_IPV6=FAIL (IPv6 policy disappeared)' >&2; exit 1;
  }
  echo 'REAL_TUN_IPV6_OVERRIDE_UDP_SELECTED=PASS (VLESS source and unchanged native UDP counter)'
  echo 'REAL_TUN_IPV6_EXPLICIT_DIRECT_UDP_SELECTED=PASS (exact source and payload)'
  echo 'REAL_TUN_IPV6_SELECTED=PASS (native domestic Direct, explicit override, foreign VLESS, no Direct leak)'
fi
# Explicit, synthetic HTTP Host exceptions exercise native sing-box sniff.
# This does not prove DNS correlation, TLS SNI or geographic classification.
test "$(direct_witness_packets)" -eq "$witness_baseline" || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (pre-existing foreign leak)' >&2; exit 1;
}
expect_named_source vpn.scqa.test 5.22.0.10 5.22.0.10 || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (suffix VPN over domestic IP)' >&2; exit 1;
}
# The exact name MUST be outside the suffix fixture. Otherwise the suffix
# route would make this test falsely pass even if exact matching broke.
expect_named_source only-exact.test 5.22.0.10 5.22.0.10 || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (exact-only VPN over domestic IP)' >&2; exit 1;
}
# An exact match must NOT act as a suffix: this name uses domestic Direct.
expect_named_source child.only-exact.test 5.22.0.10 10.254.72.1 || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (exact-only overmatched subdomain)' >&2; exit 1;
}
assert_tun_policy_active || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (TUN policy lost during name proof)' >&2; exit 1;
}
expect_source 8.8.8.8 8.8.8.8 || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (raw IP foreign)' >&2; exit 1;
}
expect_source 5.22.0.10 10.254.72.1 || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (raw IP domestic)' >&2; exit 1;
}
test "$(direct_witness_packets)" -eq "$witness_baseline" || {
  echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=FAIL (VPN-only names leaked to Direct)' >&2; exit 1;
}
echo 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=PASS (VPN-only HTTP names; no Direct leak)'
# SNI is distinct from HTTP Host; verify a *real* TLS ClientHello is sniffed.
# Compare independent VETH counters on each path. The peer's VLESS outbound
# accesses destination loopback and MUST NOT increment a native VETH witness.
assert_tun_policy_active || { echo 'REAL_TUN_TLS_SNI_VPN_ONLY=FAIL (TUN unavailable)' >&2; exit 1; }
tls_path vpn.scqa.test 5.22.0.10 5.22.0.10 reply
tls_path only-exact.test 5.22.0.10 5.22.0.10 reply
test "$(domestic_tls_direct_packets)" -eq "$domestic_tls_baseline" || {
  echo 'REAL_TUN_TLS_SNI_VPN_ONLY=FAIL (matched domestic SNI leaked Direct)' >&2; exit 1;
}
# Exact-only must NOT match its children; no SNI must stay IP-only.
tls_path child.only-exact.test 5.22.0.10 10.254.72.1 reply
tls_path - 5.22.0.10 10.254.72.1 reply
domestic_tls_active=$(domestic_tls_direct_packets)
test "$domestic_tls_active" -gt "$domestic_tls_baseline" || {
  echo 'REAL_TUN_TLS_SNI_VPN_ONLY=FAIL (missing positive Direct negative-control)' >&2; exit 1;
}
tls_path unmatched.test 8.8.8.8 8.8.8.8 reply
test "$(foreign_tls_direct_packets)" -eq "$foreign_tls_baseline" || {
  echo 'REAL_TUN_TLS_SNI_VPN_ONLY=FAIL (foreign TLS leaked Direct)' >&2; exit 1;
}
assert_tun_policy_active || { echo 'REAL_TUN_TLS_SNI_VPN_ONLY=FAIL (TUN lost)' >&2; exit 1; }
echo 'REAL_TUN_TLS_SNI_VPN_ONLY=PASS (real suffix/exact ClientHello; positive-controlled Direct witnesses)'
assert_tun_policy_active || { echo 'FAIL: TUN not active before selected UDP path' >&2; exit 1; }
udp_path 5.22.0.10 10.254.72.1 tun-domestic reply
udp_path 8.8.8.8 8.8.8.8 tun-foreign reply
udp_witness_active=$(direct_udp_witness_packets)
test "$udp_witness_active" -eq "$udp_witness_baseline" || {
  echo "FAIL: VPN-required UDP escaped native Direct ($udp_witness_baseline -> $udp_witness_active)" >&2
  exit 1
}
assert_tun_policy_active || { echo 'FAIL: TUN disappeared during selected UDP proof' >&2; exit 1; }
echo "REAL_TUN_SELECTED_UDP_PATH=PASS (domestic Direct, foreign VLESS, no native foreign UDP packets)"
assert_tun_policy_active || { echo 'FAIL: TUN unavailable before DNS wire proof' >&2; exit 1; }
dns_path 5.22.0.10 192.0.2.11 tun-domestic-udp udp reply
dns_path 5.22.0.10 192.0.2.11 tun-domestic-tcp tcp reply
dns_path 8.8.8.8 192.0.2.22 tun-foreign-udp udp reply
dns_path 8.8.8.8 192.0.2.22 tun-foreign-tcp tcp reply
test "$(direct_dns_udp_witness_packets)" -eq "$dns_udp_baseline" &&
test "$(direct_dns_tcp_witness_packets)" -eq "$dns_tcp_baseline" || {
  echo 'FAIL: VPN-required DNS escaped native Direct with active TUN' >&2
  exit 1
}
assert_tun_policy_active || { echo 'FAIL: TUN disappeared during DNS wire proof' >&2; exit 1; }
echo "REAL_TUN_SELECTED_DNS_WIRE_PATH=PASS (UDP/TCP DNS answers source-bound, no foreign Direct leak)"
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

# Genuine native apt-get update + HTTP Git clone, not curl posing as apps.
# An independent origin and native packet counter distinguish VPN from Direct.
assert_tun_policy_active || { echo 'REAL_TUN_NATIVE_APPS_SELECTED=FAIL (TUN disappeared)' >&2; exit 1; }
native_apps selected
test "$(native_app_direct_packets)" -eq "$native_apps_baseline" || {
  echo 'REAL_TUN_NATIVE_APPS_SELECTED=FAIL (APT/Git escaped native Direct)' >&2
  exit 1
}
kill -0 "$native_apps_pid" 2>/dev/null &&
assert_tun_policy_active || {
  echo 'REAL_TUN_NATIVE_APPS_SELECTED=FAIL (fixture or TUN unavailable)' >&2
  exit 1
}
echo 'REAL_TUN_NATIVE_APPS_SELECTED_WITNESS=PASS (APT/Git VLESS, no native Direct leak)'
if [ "${SC_QA_TUN_GUARD_LAB-}" != yes ]; then
  wp_probe positive 8.8.8.8
  test "$(native_app_direct_packets)" -eq "$native_apps_baseline" || {
    echo 'REAL_TUN_WORDPRESS=FAIL (native Direct leak under VPN)' >&2; exit 1;
  }
  assert_tun_policy_active || {
    echo 'REAL_TUN_WORDPRESS=FAIL (policy disappeared during selected request)' >&2; exit 1;
  }
fi

if [ "$payload_trial" = yes ]; then
  assert_tun_policy_active || { echo 'REAL_TUN_PAYLOAD=FAIL (missing TUN before payload)' >&2; exit 1; }
  payload_path tcp 8.8.8.8 8.8.8.8 reply
  payload_path udp 8.8.8.8 8.8.8.8 reply
  # An underlay VETH with MTU 1280 must carry multi-packet VLESS traffic
  # through a 1400-byte TUN interface, without native Direct escape.
  test "$(cat /sys/class/net/sctunqa0/mtu)" = 1400 || {
    echo 'REAL_TUN_PAYLOAD=FAIL (unexpected TUN MTU)' >&2; exit 1;
  }
  edge_mtu=$(cat "/sys/class/net/$edge/mtu")
  peer_mtu=$(ip -n "$peer" -j link show dev scqapeer0 |
    python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["mtu"])')
  test "$edge_mtu" -gt 1280 && test "$peer_mtu" -gt 1280 || {
    echo 'REAL_TUN_PAYLOAD=FAIL (no meaningful underlay MTU reduction)' >&2; exit 1;
  }
  ip link set dev "$edge" mtu 1280
  ip -n "$peer" link set dev scqapeer0 mtu 1280
  test "$(cat "/sys/class/net/$edge/mtu")" = 1280 &&
    test "$(ip -n "$peer" -j link show dev scqapeer0 |
      python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["mtu"])')" = 1280 || {
      echo 'REAL_TUN_PAYLOAD=FAIL (underlay MTU reduction)' >&2; exit 1;
    }
  payload_path tcp 8.8.8.8 8.8.8.8 reply
  payload_path udp 8.8.8.8 8.8.8.8 reply
  payload_path df 8.8.8.8
  test "$(payload_tcp_direct_packets)" -eq "$payload_tcp_baseline" &&
    test "$(payload_udp_direct_packets)" -eq "$payload_udp_baseline" || {
      echo 'REAL_TUN_PAYLOAD=FAIL (foreign Direct leak under reduced MTU)' >&2; exit 1;
    }
  assert_tun_policy_active || { echo 'REAL_TUN_PAYLOAD=FAIL (TUN lost during reduced MTU)' >&2; exit 1; }
  ip link set dev "$edge" mtu "$edge_mtu"
  ip -n "$peer" link set dev scqapeer0 mtu "$peer_mtu"
  test "$(cat "/sys/class/net/$edge/mtu")" = "$edge_mtu" &&
    test "$(ip -n "$peer" -j link show dev scqapeer0 |
      python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["mtu"])')" = "$peer_mtu" || {
      echo 'REAL_TUN_PAYLOAD=FAIL (underlay MTU restoration)' >&2; exit 1;
    }
  echo 'REAL_TUN_PAYLOAD_REDUCED_MTU=PASS (real VLESS TCP/UDP echo, MTU 1280, no native Direct leak)'
fi

if [ "${SC_QA_TUN_GUARD_LAB-}" = yes ]; then
  guarded_real_tun_deadline_trial
  exit 0
fi

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
# Native apt-get and Git must also fail closed without silently escaping
# via Direct while the TUN policy is still active and the HTTP peer is alive.
native_apps outage
test "$(native_app_direct_packets)" -eq "$native_apps_baseline" || {
  echo 'REAL_TUN_NATIVE_APPS_OUTAGE=FAIL (native Direct packets after upstream loss)' >&2
  exit 1
}
kill -0 "$native_apps_pid" 2>/dev/null &&
assert_tun_policy_active || {
  echo 'REAL_TUN_NATIVE_APPS_OUTAGE=FAIL (fixture or TUN unavailable)' >&2
  exit 1
}
echo 'REAL_TUN_NATIVE_APPS_OUTAGE_WITNESS=PASS (APT/Git failed closed, independent Direct witness unchanged)'
if [ "$ipv6_trial" = yes ]; then
  ipv6_path tcp 2001:db8:8::8 none no-reply
  ipv6_path udp 2001:db8:8::8 none no-reply
  ipv6_path tcp 2001:db8:5::10 none no-reply
  ipv6_path udp 2001:db8:5::10 none no-reply
  kill -0 "$ipv6_pid" 2>/dev/null || {
    echo 'REAL_TUN_IPV6=FAIL (independent peer dead during outage)' >&2; exit 1;
  }
  # Direct still works after upstream loss and the origin is independently alive.
  ipv6_path tcp 2001:db8:5::11 fd73:1::1 reply
  ipv6_path udp 2001:db8:5::11 fd73:1::1 reply
  ipv6_path tcp 2001:db8:8::9 fd73:1::1 reply
  ipv6_path udp 2001:db8:8::9 fd73:1::1 reply
  test "$(ipv6_foreign_tcp_direct_packets)" -eq "$ipv6_foreign_tcp_baseline" &&
    test "$(ipv6_foreign_udp_direct_packets)" -eq "$ipv6_foreign_udp_baseline" &&
    test "$(ipv6_override_direct_packets)" -eq "$ipv6_override_baseline" &&
    test "$(ipv6_override_udp_direct_packets)" -eq "$ipv6_override_udp_baseline" || {
      echo 'REAL_TUN_IPV6=FAIL (native Direct IPv6 leak on upstream loss)' >&2; exit 1;
    }
  ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null &&
    assert_tun_policy_active || {
      echo 'REAL_TUN_IPV6=FAIL (IPv6 routing policy vanished during outage)' >&2; exit 1;
    }
  echo 'REAL_TUN_IPV6_OVERRIDE_UDP_OUTAGE=PASS (no reply and unchanged native UDP counter)'
  echo 'REAL_TUN_IPV6_EXPLICIT_DIRECT_UDP_OUTAGE=PASS (exact source and payload)'
  echo 'REAL_TUN_IPV6_OUTAGE=PASS (VPN-required TCP/UDP failed closed, native Direct preserved)'
fi
if [ "$payload_trial" = yes ]; then
  payload_path tcp 8.8.8.8 none no-reply
  payload_path udp 8.8.8.8 none no-reply
  kill -0 "$payload_pid" 2>/dev/null || {
    echo 'REAL_TUN_PAYLOAD=FAIL (independent peer died before outage witness)' >&2; exit 1;
  }
  # Positive native Direct control AFTER failure: the origin is still alive,
  # so a foreign no-reply cannot pass merely because the whole peer died.
  payload_path tcp 5.22.0.10 10.254.72.1 reply
  payload_path udp 5.22.0.10 10.254.72.1 reply
  test "$(payload_tcp_direct_packets)" -eq "$payload_tcp_baseline" &&
    test "$(payload_udp_direct_packets)" -eq "$payload_udp_baseline" || {
      echo 'REAL_TUN_PAYLOAD=FAIL (foreign TCP/UDP native Direct leak on upstream loss)' >&2; exit 1;
    }
  assert_tun_policy_active || { echo 'REAL_TUN_PAYLOAD=FAIL (TUN lost on upstream loss)' >&2; exit 1; }
  echo 'REAL_TUN_PAYLOAD_OUTAGE=PASS (large TCP/UDP fail closed, no native Direct packets)'
fi
wp_probe negative none
test "$(native_app_direct_packets)" -eq "$native_apps_baseline" || {
  echo 'REAL_TUN_WORDPRESS=FAIL (native Direct leak after VLESS loss)' >&2; exit 1;
}
assert_tun_policy_active || {
  echo 'REAL_TUN_WORDPRESS=FAIL (policy disappeared during outage)' >&2; exit 1;
}
# A domestic destination must NOT become Direct just because the upstream
# stopped when the explicit SNI rule still requires VPN. A nonmatching SNI
# to the SAME destination must remain Direct: independent routing proof.
assert_tun_policy_active || { echo 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=FAIL (TUN lost)' >&2; exit 1; }
tls_path vpn.scqa.test 5.22.0.10 - no-reply
tls_path only-exact.test 5.22.0.10 - no-reply
tls_path unmatched.test 8.8.8.8 - no-reply
test "$(domestic_tls_direct_packets)" -eq "$domestic_tls_active" &&
test "$(foreign_tls_direct_packets)" -eq "$foreign_tls_baseline" || {
  echo 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=FAIL (native VPN-only TLS leak)' >&2; exit 1;
}
if ! tls_path child.only-exact.test 5.22.0.10 10.254.72.1 reply; then
  echo 'REAL_TUN_TLS_DIRECT_AFTER_UPSTREAM_LOSS=FAIL (fresh Direct positive control)' >&2
  echo "QA_TLS_PEER_ALIVE=$(kill -0 "$tls_pid" 2>/dev/null && echo yes || echo no)" >&2
  # Failure-only diagnostic evidence from the isolated synthetic server.
  # Keep the original failure and do not retry away a routing regression.
  tail -n 20 /run/sc-qa-tun-tls.log >&2 || :
  exit 1
fi
test "$(domestic_tls_direct_packets)" -gt "$domestic_tls_active" || {
  echo 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=FAIL (Direct negative control missing)' >&2; exit 1;
}
test "$(foreign_tls_direct_packets)" -eq "$foreign_tls_baseline" || {
  echo 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=FAIL (foreign native TLS leak)' >&2; exit 1;
}
kill -0 "$tls_pid" 2>/dev/null &&
assert_tun_policy_active || {
  echo 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=FAIL (fixture or policy disappeared)' >&2; exit 1;
}
echo 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=PASS (matched domestic SNI fail-closed; unmatched Direct works)'
assert_tun_policy_active || { echo 'FAIL: TUN lost before foreign UDP outage probe' >&2; exit 1; }
udp_path 8.8.8.8 unused outage-foreign no-reply
udp_witness_outage=$(direct_udp_witness_packets)
test "$udp_witness_outage" -eq "$udp_witness_active" || {
  echo "FAIL: VPN-required UDP leaked native Direct on upstream loss ($udp_witness_active -> $udp_witness_outage)" >&2
  exit 1
}
udp_path 5.22.0.10 10.254.72.1 outage-domestic reply
assert_tun_policy_active || { echo 'FAIL: TUN lost during foreign UDP outage probe' >&2; exit 1; }
echo 'REAL_TUN_UDP_NO_DIRECT_PACKETS_ON_UPSTREAM_LOSS=PASS (positive-controlled peer witness)'
assert_tun_policy_active || { echo 'FAIL: TUN lost before DNS outage proof' >&2; exit 1; }
dns_path 8.8.8.8 none outage-foreign-udp udp no-reply
dns_path 8.8.8.8 none outage-foreign-tcp tcp no-reply
dns_path 5.22.0.10 192.0.2.11 outage-domestic-udp udp reply
dns_path 5.22.0.10 192.0.2.11 outage-domestic-tcp tcp reply
test "$(direct_dns_udp_witness_packets)" -eq "$dns_udp_baseline" &&
test "$(direct_dns_tcp_witness_packets)" -eq "$dns_tcp_baseline" || {
  echo 'FAIL: VPN-required DNS leaked native Direct after VLESS loss' >&2
  exit 1
}
assert_tun_policy_active || { echo 'FAIL: TUN lost during DNS outage proof' >&2; exit 1; }
echo 'REAL_TUN_DNS_NO_DIRECT_PACKETS_ON_UPSTREAM_LOSS=PASS (UDP/TCP negative with independent witness)'
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
