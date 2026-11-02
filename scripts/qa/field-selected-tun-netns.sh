#!/usr/bin/env bash
# Disposable operator-authorized field host only. Real selected VPN path via an isolated Linux TUN
# namespace. This is NOT general-host Smart Routing or an installer.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
namespace=scfieldqa
veth_host=scfqah
veth_guest=scfqap
tun=scfqat
work=/root/server-connect-field-netns-qa
watch=server-connect-field-netns-watch
comment=server-connect-field-netns-qa
manager=/usr/local/bin/server-connect
core=/opt/server-connect/current/bin/sing-box
expected_ip=''
host_if=''
subnet=172.31.249.0/30
guest_ip=172.31.249.2/30
host_ip=172.31.249.1/30
die() { echo "REFUSED: $*" >&2; exit 2; }
need() { "$@" >/dev/null 2>&1 || die "preflight failed: $*"; }
[[ "$#" -eq 5 || "$#" -eq 6 ]] || die "usage: root bash field-selected-tun-netns.sh EXPECTED_HOSTNAME EXPECTED_IPV4 UNDERLAY_INTERFACE DNS_PRIMARY_IPV4 DNS_SECONDARY_IPV4 [--split-exception]"
expected_host=$1
expected_ip=$2
host_if=$3
resolver_ip=$4
secondary_resolver=$5
split_mode=no
if [[ "$#" -eq 6 ]]; then
  [[ "$6" == --split-exception ]] || die "unknown sixth argument"
  split_mode=yes
fi
[[ "$expected_host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,100}$ &&
   "$expected_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ &&
   "$host_if" =~ ^[a-zA-Z0-9_.-]{1,15}$ &&
   "$resolver_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ &&
   "$secondary_resolver" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid bound host arguments"
[[ "$(hostname)" == "$expected_host" ]] || die "wrong host"
[[ "$EUID" -eq 0 ]] || die "root required"
[[ "$(cat /etc/debian_version)" == 12* ]] || die "expected disposable Debian 12"
[[ -e /dev/net/tun && -x "$manager" && -x "$core" ]] || die "missing installed manager/core/tun"
need ip -4 addr show dev "$host_if"
ip -4 addr show dev "$host_if" | grep -Fq "inet $expected_ip/" || die "host interface changed"
python3 - "$expected_ip" "$resolver_ip" "$secondary_resolver" <<'PYIP'
import ipaddress, sys
for ip in sys.argv[1:]:
    assert ipaddress.IPv4Address(ip).is_global, "Only public routable test IPs and DNS are accepted"
PYIP
# The fixed QA address slots must not overlap another owner's native
# connected/routed prefixes (including supernets not containing our literals).
ip -j -4 route show table all | python3 -c '
import ipaddress,json,sys
try:
    routes=json.load(sys.stdin)
    assert type(routes) is list
    for row in routes:
        assert type(row) is dict
        dst=row.get("dst","default")
        if dst=="default": continue
        subnet=ipaddress.ip_network(dst,strict=False)
        assert not any(subnet.overlaps(ipaddress.ip_network(x))
                       for x in ("172.31.249.0/30","172.30.124.0/30"))
except Exception:
    sys.exit(1)
' || die "QA native route inventory ambiguous or conflicts with private QA slots"
[[ "$(cat /proc/sys/net/ipv4/ip_forward)" == 1 ]] || die "requires existing IPv4 forwarding"
[[ ! -e "$work" && ! -e "/etc/netns/$namespace" ]] || die "existing trial state"
[[ ! -e "/sys/class/net/$veth_host" && ! -e "/sys/class/net/$veth_guest" && ! -e "/sys/class/net/$tun" ]] || die "link conflict"
existing_ns=$(ip netns list) || die "cannot inspect network namespaces"
if printf '%s\n' "$existing_ns" | grep -E "^$namespace([[:space:]]|$)" >/dev/null; then
  die "namespace conflict"
fi
for type in timer service; do
  state=$(systemctl show "$watch.$type" -p LoadState --value 2>/dev/null || echo unknown)
  [[ "$state" == not-found ]] || die "watchdog unit already exists or unknown ($type=$state)"
done
"$manager" --json status | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive"' || die "product not Direct/off"
for cmd in smart-tun-trial-status activation-journal-status; do
  "$manager" --json "$cmd" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["data"]["phase"]=="absent"' || die "active or unknown native journal"
done
for name in server-connect-smart-health.timer server-connect-activation-recover.timer server-connect-smart-tun.service; do
  [[ "$(systemctl show "$name" -p ActiveState --value)" == inactive ]] || die "active/uncertain product guard or TUN"
done
need iptables -S FORWARD
need iptables -t nat -S POSTROUTING
iptables_inventory=$(iptables-save) || die "cannot inspect existing firewall"
[[ "$iptables_inventory" != *"$comment"* ]] || die "tagged rule already exists"
baseline_routes=$(ip -4 route show table all | sha256sum | cut -d' ' -f1)
baseline_rpdb=$(ip -4 rule show | sha256sum | cut -d' ' -f1)
baseline_filter=$(iptables -t filter -S | sha256sum | cut -d' ' -f1)
baseline_nat=$(iptables -t nat -S | sha256sum | cut -d' ' -f1)
boot=$(cat /proc/sys/kernel/random/boot_id)

mkdir -m 700 "$work"
# Before the independent guard is armed no host networking has been touched.
# Clear only exact task-created private files if config validation fails.
pre_guard_cleanup() {
  rc=$?
  trap - EXIT
  # The guarded finalizer replaces this trap before systemd-run can be
  # invoked. Therefore no future watchdog can reference these files.
  rm -f "$work/config.json" "$work/resolver-port" "$work/owner" \
        "$work/cleanup.sh" "$work/resolv.conf" "$work/underlay-interface" "$work/split-ip"
  rmdir "$work" 2>/dev/null || echo 'PRIVATE_PREARM_STATE_RETAINED'
  exit "$rc"
}
trap pre_guard_cleanup EXIT
printf 'host=%s boot=%s owner=%s\n' "$expected_host" "$boot" "$comment" > "$work/owner"
printf '%s\n' "$host_if" > "$work/underlay-interface"
if [[ "$split_mode" == yes ]]; then
  split_ip=$(getent ahostsv4 www.cloudflare.com | awk 'NR==1 {print $1}')
  python3 - "$split_ip" <<'PYSPLIT'
import ipaddress,sys
assert ipaddress.IPv4Address(sys.argv[1]).is_global, "Nonpublic exception IP"
PYSPLIT
  printf '%s\n' "$split_ip" > "$work/split-ip"
fi
cat > "$work/cleanup.sh" <<'CLEANUP'
#!/usr/bin/env bash
set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
work=/root/server-connect-field-netns-qa
owner=server-connect-field-netns-qa
namespace=scfieldqa
host_if=$(cat "$work/underlay-interface" 2>/dev/null) || exit 2
[[ "$host_if" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 2
if [[ ! -f "$work/owner" ]] ||
   ! grep -Fq "owner=$owner" "$work/owner" ||
   ! grep -Fq "boot=$(cat /proc/sys/kernel/random/boot_id)" "$work/owner"; then
  echo 'REFUSED: missing exact QA cleanup ownership' >&2; exit 2
fi
if [[ -f "$work/pid" ]]; then
  pid=$(cat "$work/pid")
  if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/cmdline" ]] &&
     tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$work/config.json"; then
    kill -TERM "$pid" 2>/dev/null || :
    for i in 1 2 3 4 5; do [[ ! -e "/proc/$pid" ]] && break; sleep 1; done
  fi
fi
iptables -D FORWARD -i scfqah -o "$host_if" -m comment --comment "$owner" -j ACCEPT 2>/dev/null || :
iptables -D FORWARD -i "$host_if" -o scfqah -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$owner" -j ACCEPT 2>/dev/null || :
iptables -t nat -D POSTROUTING -s 172.31.249.0/30 -o "$host_if" -m comment --comment "$owner" -j MASQUERADE 2>/dev/null || :
if [[ -e /sys/class/net/scfqah ]]; then
  if [[ "$(cat /sys/class/net/scfqah/ifalias)" == "$owner" ]]; then
    ip link delete scfqah 2>/dev/null || :
  else
    echo 'REFUSED: unknown link ownership' >&2; exit 3
  fi
fi
if ip netns list | grep -Eq '^scfieldqa([[:space:]]|$)'; then
  if ip netns pids scfieldqa | grep -Eq '^[0-9]+$'; then
    echo 'REFUSED: unexpected active namespace process' >&2; exit 3
  fi
  ip netns delete scfieldqa || exit 3
fi
if [[ -f /etc/netns/scfieldqa/resolv.conf ]]; then
  if cmp -s /etc/netns/scfieldqa/resolv.conf "$work/resolv.conf"; then
    rm -f /etc/netns/scfieldqa/resolv.conf
    rmdir /etc/netns/scfieldqa 2>/dev/null || :
  else
    echo 'REFUSED: DNS fixture changed' >&2; exit 4
  fi
fi
if [[ -f "$work/created-resolver-parent" ]]; then
  rmdir /etc/netns 2>/dev/null || :
fi
echo QA_SCOPED_CLEANUP_ATTEMPTED
CLEANUP
chmod 0700 "$work/cleanup.sh"
python3 - "$work" <<'PY'
import json,pathlib,sys
w=pathlib.Path(sys.argv[1])
state=json.loads(pathlib.Path('/var/lib/server-connect/state.json').read_text())
profile=json.loads((pathlib.Path('/var/lib/server-connect/profiles')/(state['selected']+'.json')).read_text())
out=profile['outbound']
if isinstance(out,str):out=json.loads(out)
assert out['tag']=='upstream' and out['type']=='vless' and isinstance(out['server_port'],int)
# The selected VPN endpoint remains private; only the isolated namespace is
# affected by the direct/bypass rule and autonomous TUN interception.
rules=[{'ip_cidr':['172.31.249.0/30'],'action':'route','outbound':'direct'}]
split_path=w/'split-ip'
if split_path.exists():
    import ipaddress
    split_address=ipaddress.IPv4Address(split_path.read_text().strip())
    assert split_address.is_global
    rules.insert(0,{'ip_cidr':[str(split_address)+'/32'],'action':'route','outbound':'direct'})
cfg={'log':{'level':'warn'},
'inbounds':[{'type':'tun','tag':'tun-in','interface_name':'scfqat',
'address':['172.30.124.1/30'],'mtu':1400,'auto_route':True,
'auto_redirect':True,'strict_route':True,'dns_mode':'disabled',
'route_exclude_address':['172.31.249.0/30']}],
'outbounds':[out,{'type':'direct','tag':'direct'}],
'route':{'default_interface':'scfqap',
'rules':rules,'final':'upstream'}}
p=w/'config.json';p.write_text(json.dumps(cfg));p.chmod(0o600)
(w/'resolver-port').write_text(str(out['server_port']))
PY
"$core" check -c "$work/config.json" >/dev/null || die "real selected profile TUN config invalid"
printf 'nameserver %s\nnameserver %s\n' "$resolver_ip" "$secondary_resolver" > "$work/resolv.conf"

finalize() {
  rc=$?
  trap - EXIT
  echo 'CLEANUP START'
  # Keep the independent timer armed until exact native restoration is
  # verified; a signal/failure during cleanup must not lose its recovery path.
  bash "$work/cleanup.sh" || rc=1
  if [[ -e /sys/class/net/$veth_host ]] ||
     ip netns list | grep -Eq "^$namespace([[:space:]]|$)" ||
     [[ -e "/etc/netns/$namespace/resolv.conf" ]] ||
     { [[ -f "$work/created-resolver-parent" ]] && [[ -d /etc/netns ]]; }; then
    echo 'CLEANUP_CONFLICT=FAIL; evidence preserved' >&2
    rc=1
  fi
  [[ "$baseline_routes" == "$(ip -4 route show table all | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_ROUTES_CHANGED=FAIL'; rc=1; }
  [[ "$baseline_rpdb" == "$(ip -4 rule show | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_RPDB_CHANGED=FAIL'; rc=1; }
  [[ "$baseline_filter" == "$(iptables -t filter -S | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_FILTER_CHANGED=FAIL'; rc=1; }
  [[ "$baseline_nat" == "$(iptables -t nat -S | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_NAT_CHANGED=FAIL'; rc=1; }
  [[ "$boot" == "$(cat /proc/sys/kernel/random/boot_id)" ]] || { echo 'ROOT_BOOT_CHANGED=FAIL'; rc=1; }
  if [[ "$rc" -eq 0 ]]; then
    systemctl stop "$watch.timer" >/dev/null 2>&1 || rc=1
  fi
  if [[ "$rc" -eq 0 ]]; then
    echo 'ROOT_NETWORK_RESTORED=PASS'
    rm -f "$work/config.json" "$work/resolver-port" "$work/owner" "$work/cleanup.sh" "$work/resolv.conf" "$work/underlay-interface" "$work/pid" "$work/core.log" "$work/created-resolver-parent" "$work/split-ip"
    rmdir "$work" || rc=1
  else
    echo 'QA_FAILED_OR_UNCERTAIN; private evidence retained for manual reconciliation'
  fi
  exit "$rc"
}
trap finalize EXIT

# Independent, prearmed recovery in case the SSH test process is interrupted.
systemd-run --quiet --collect --unit="$watch" --on-active=150s \
  --timer-property=AccuracySec=1s /usr/bin/bash "$work/cleanup.sh" ||
  die "watchdog creation failed or has ambiguous outcome"
[[ "$(systemctl is-active "$watch.timer")" == active ]] || die "watchdog timer unavailable"
echo 'GUARD_TIMER=PASS'

ip netns add "$namespace"
ip link add "$veth_host" type veth peer name "$veth_guest"
ip link set "$veth_host" alias "$comment"
ip link set "$veth_guest" netns "$namespace"
ip addr add "$host_ip" dev "$veth_host"
ip link set "$veth_host" up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip addr add "$guest_ip" dev "$veth_guest"
ip netns exec "$namespace" ip link set "$veth_guest" up
ip netns exec "$namespace" ip route add default via 172.31.249.1 dev "$veth_guest"
if [[ ! -d /etc/netns ]]; then
  mkdir -m 755 /etc/netns
  : > "$work/created-resolver-parent"
fi
mkdir -m 755 "/etc/netns/$namespace"
cp "$work/resolv.conf" "/etc/netns/$namespace/resolv.conf"
iptables -I FORWARD 1 -i "$veth_host" -o "$host_if" -m comment --comment "$comment" -j ACCEPT
iptables -I FORWARD 1 -i "$host_if" -o "$veth_host" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT
iptables -t nat -I POSTROUTING 1 -s "$subnet" -o "$host_if" -m comment --comment "$comment" -j MASQUERADE
echo 'NETWORK_NAMESPACE=READY'

# Resolve once before TUN so the real HTTPS/VLESS test is independent of
# later DNS behavior. DNS under active TUN gets a separate FAIL/PASS result.
foreign_ip=$(ip netns exec "$namespace" getent ahostsv4 api.ipify.org | awk 'NR==1 {print $1}')
[[ "$foreign_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "cannot resolve test destination before TUN"
echo 'DIRECT_PRE_TUN_DNS=PASS'
direct=$(ip netns exec "$namespace" curl -q --noproxy '*' \
  --resolve "api.ipify.org:443:$foreign_ip" -sS -4 --max-time 15 https://api.ipify.org)
echo "ISOLATED_DIRECT_IP=$direct"
[[ "$direct" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "namespace Direct path did not return a public IPv4 witness"
if [[ "$direct" != "$expected_ip" ]]; then
  echo "ISOLATED_DIRECT_EXIT_DIFFERS_FROM_HOST_ADDRESS=OBSERVED"
fi
if [[ "$split_mode" == yes ]]; then
  split_direct_trace=$(ip netns exec "$namespace" curl -q --noproxy '*' \
    --resolve "www.cloudflare.com:443:$split_ip" -fsS -4 --max-time 15 \
    https://www.cloudflare.com/cdn-cgi/trace)
  split_direct=$(printf '%s\n' "$split_direct_trace" | sed -n 's/^ip=//p')
  [[ "$split_direct" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "split Direct baseline invalid"
  echo "SPLIT_EXCEPTION_PRE_TUN_DIRECT_IP=$split_direct"
fi

ip netns exec "$namespace" "$core" run -c "$work/config.json" >"$work/core.log" 2>&1 &
pid=$!
echo "$pid" > "$work/pid"
ready=no
for i in $(seq 1 12); do
  if ip netns exec "$namespace" ip link show dev "$tun" >/dev/null 2>&1; then ready=yes; break; fi
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
[[ "$ready" == yes ]] || die "sing-box TUN did not become available"
echo 'ISOLATED_TRANSPARENT_TUN=READY'
ip netns exec "$namespace" ip -4 rule show | tail -8
dns_during=FAIL
if ip netns exec "$namespace" timeout 9s getent ahostsv4 api.ipify.org >/dev/null 2>&1; then
  dns_during=PASS
fi
echo "DNS_RESOLUTION_WITH_TUN=$dns_during"
vpn=$(ip netns exec "$namespace" curl -q --noproxy '*' \
  --resolve "api.ipify.org:443:$foreign_ip" -sS -4 --max-time 22 https://api.ipify.org) || die "transparent VPN HTTPS request failed"
[[ "$vpn" != "$expected_ip" && "$vpn" != "$direct" &&
   "$vpn" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "possible direct leak or malformed VPN exit"
echo "ISOLATED_TUN_VPN_IP=$vpn"
if [[ "$split_mode" != yes ]]; then
  ip netns exec "$namespace" curl -q --noproxy '*' -sS -4 --max-time 15 \
    https://www.cloudflare.com/cdn-cgi/trace |
    grep -E '^(ip|loc|colo)=' || :
fi
echo 'ISOLATED_SELECTED_TRANSPARENT_HTTPS=PASS (pinned api.ipify.org)'
if [[ "$split_mode" == yes ]]; then
  ip netns exec "$namespace" iptables -I OUTPUT 1 -o "$veth_guest" -d "$split_ip/32" \
    -p tcp --dport 443 -m comment --comment "$comment-direct" -j ACCEPT
  split_trace=$(ip netns exec "$namespace" curl -q --noproxy '*' \
    --resolve "www.cloudflare.com:443:$split_ip" -fsS -4 --max-time 15 \
    https://www.cloudflare.com/cdn-cgi/trace)
  split_actual=$(printf '%s\n' "$split_trace" | sed -n 's/^ip=//p')
  split_packets=$(ip netns exec "$namespace" iptables -vxnL OUTPUT --line-numbers |
    awk -v label="$comment-direct" 'index($0,label)>0 {print $2}')
  [[ "$split_actual" == "$split_direct" ]] ||
    die "operator split Direct exception used an unexpected egress"
  [[ "$split_packets" =~ ^[0-9]+$ && "$split_packets" -gt 0 ]] ||
    die "operator split Direct exception has no independent underlay packet proof"
  [[ "$split_actual" != "$vpn" ]] || die "split Direct destination went through selected VPN"
  ip netns exec "$namespace" iptables -D OUTPUT -o "$veth_guest" -d "$split_ip/32" \
    -p tcp --dport 443 -m comment --comment "$comment-direct" -j ACCEPT
  echo "EXPLICIT_PUBLIC_CIDR_DIRECT_IP=$split_actual"
  echo "EXPLICIT_DIRECT_AND_FOREIGN_VPN_SPLIT=PASS"
fi

# Negative proof: while the TUN is still running, block its selected remote
# transport only inside this namespace. Pin the foreign HTTPS destination so
# resolver changes cannot disguise a direct leak. A separate no-op ACCEPT
# counter catches any direct underlay packet to that exact public destination.
port=$(cat "$work/resolver-port")
[[ "$port" =~ ^[1-9][0-9]{0,4}$ && "$port" -ge 1 && "$port" -le 65535 ]] || die "invalid selected remote port"
probe=$(ip netns exec "$namespace" curl -q --noproxy '*'   --resolve "api.ipify.org:443:$foreign_ip" -sS -4 --max-time 12 https://api.ipify.org)
[[ "$probe" != "$expected_ip" && "$probe" != "$direct" ]] || die "foreign pinned destination already Direct"
ip netns exec "$namespace" iptables -I OUTPUT 1 -o "$veth_guest" -d "$foreign_ip/32"   -p tcp --dport 443 -m comment --comment "$comment-witness" -j ACCEPT
ip netns exec "$namespace" iptables -I OUTPUT 2 -o "$veth_guest"   -p tcp --dport "$port" -m comment --comment "$comment-outage" -j DROP
outage_response=''
if outage_response=$(ip netns exec "$namespace" curl -q --noproxy '*'   --resolve "api.ipify.org:443:$foreign_ip" -fsS -4 --max-time 9 https://api.ipify.org 2>/dev/null); then
  echo "VPN_UPSTREAM_OUTAGE_FAILED_TO_BLOCK=$outage_response" >&2
  exit 1
fi
witness=$(ip netns exec "$namespace" iptables -vxnL OUTPUT --line-numbers |
  awk -v label="$comment-witness" 'index($0,label)>0 {print $2}')
[[ "$witness" =~ ^[0-9]+$ && "$witness" -eq 0 ]] || die "foreign Direct-underlay leak counter nonzero/unknown"
[[ -e "/var/run/netns/$namespace" ]] || die "namespace disappeared during outage"
ip netns exec "$namespace" ip link show "$tun" >/dev/null || die "TUN disappeared during outage"
echo 'VPN_REQUIRED_OUTAGE_NO_DIRECT_UNDERLAY=PASS'
ip netns exec "$namespace" iptables -D OUTPUT -o "$veth_guest"   -p tcp --dport "$port" -m comment --comment "$comment-outage" -j DROP
ip netns exec "$namespace" iptables -D OUTPUT -o "$veth_guest" -d "$foreign_ip/32"   -p tcp --dport 443 -m comment --comment "$comment-witness" -j ACCEPT
recovered=no
for i in 1 2; do
  if resumed=$(ip netns exec "$namespace" curl -q --noproxy '*'     --resolve "api.ipify.org:443:$foreign_ip" -fsS -4 --max-time 13 https://api.ipify.org 2>/dev/null) &&
    [[ "$resumed" != "$direct" && "$resumed" != "$expected_ip" ]]; then
    recovered=yes
    break
  fi
  sleep 2
done
[[ "$recovered" == yes ]] || die "selected VPN did not recover after namespace-only outage"
echo "VPN_AFTER_OUTAGE_IP=$resumed"
echo 'VPN_RECOVERED_WITHOUT_HOST_ROUTING_MUTATION=PASS'
echo 'NOTE: QA-only isolated namespace, not general-host Smart Routing'
if [[ "$dns_during" != PASS ]]; then
  echo 'FIELD_DNS_ACCEPTANCE=FAIL (selected HTTPS separately proved with pinned destination)' >&2
  exit 1
fi
