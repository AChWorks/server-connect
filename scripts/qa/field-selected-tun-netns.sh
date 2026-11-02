#!/usr/bin/env bash
# Disposable operator-authorized field host only. Real selected VPN path via an isolated Linux TUN
# namespace. This is NOT general-host Smart Routing or an installer.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
# Python assertions are safety gates; caller PYTHONOPTIMIZE must not disable them.
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME
namespace=''
veth_host=scfqah
veth_guest=scfqap
tun=scfqat
work=/root/server-connect-field-netns-qa
watch=server-connect-field-netns-watch
comment=''
manager=/usr/local/bin/server-connect
core=/opt/server-connect/current/bin/sing-box
expected_ip=''
host_if=''
subnet=172.31.249.0/30
guest_ip=172.31.249.2/30
host_ip=172.31.249.1/30
die() { echo "REFUSED: $*" >&2; exit 2; }
need() { "$@" >/dev/null 2>&1 || die "preflight failed: $*"; }
# Host preflight and parent post-cleanup use the same empty-safe listing
# parser; an empty namespace inventory is a legitimate successful result.
valid_netns_listing() {
  local entry
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    [[ "$entry" =~ ^[a-zA-Z0-9_.-]+([[:space:]]+\(id:[[:space:]]*[0-9]+\))?$ ]] ||
      return 1
  done <<< "$1"
}
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
# Per-invocation names and comments prevent fixed-name foreign adoption.
run_id=$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]') || die "random identity failed"
[[ "$run_id" =~ ^[0-9a-f]{16}$ ]] || die "invalid invocation identity"
namespace="scf$run_id"
comment="server-connect-field-netns-qa:$run_id"
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
# We move the pre-labelled veth end back to PID 1's network namespace.
# Refuse unusual containers where PID 1 is not in our initial host netns.
[[ "$(readlink /proc/1/ns/net)" == "$(readlink /proc/self/ns/net)" ]] ||
  die "PID 1 is not in the host network namespace"
[[ "$(systemctl is-active ssh 2>/dev/null || :)" == active ]] || die "SSH management service is not active"
[[ ! -e "$work" && ! -L "$work" && ! -e "/etc/netns/$namespace" &&
   ! -L "/etc/netns/$namespace" ]] || die "existing trial state"
[[ ! -L /etc/netns && ( ! -e /etc/netns || -d /etc/netns ) ]] || die "resolver parent is not a regular directory"
[[ ! -e "/sys/class/net/$veth_host" && ! -e "/sys/class/net/$veth_guest" && ! -e "/sys/class/net/$tun" ]] || die "link conflict"
existing_ns=$(ip netns list) || die "cannot inspect network namespaces"
valid_netns_listing "$existing_ns" || die "malformed preflight namespace inventory"
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
  rm -f "$work/config.json" "$work/resolver-port" "$work/provider-host" "$work/owner" \
        "$work/cleanup.sh" "$work/resolv.conf" "$work/underlay-interface" "$work/split-ip"         "$work/run-id" "$work/root-baseline"
  rmdir "$work" 2>/dev/null || echo 'PRIVATE_PREARM_STATE_RETAINED'
  exit "$rc"
}
trap pre_guard_cleanup EXIT
printf '%s\n' "$run_id" > "$work/run-id"
printf '%s %s %s %s %s\n' "$baseline_routes" "$baseline_rpdb" "$baseline_filter" "$baseline_nat" "$boot" > "$work/root-baseline"
printf 'host=%s boot=%s owner=%s\n' "$expected_host" "$boot" "$comment" > "$work/owner"
printf '%s\n' "$host_if" > "$work/underlay-interface"
if [[ "$split_mode" == yes ]]; then
  split_ip=$(timeout 12s getent ahostsv4 www.cloudflare.com | awk 'NR==1 {print $1}')
  python3 - "$split_ip" <<'PYSPLIT'
import ipaddress,sys
assert ipaddress.IPv4Address(sys.argv[1]).is_global, "Nonpublic exception IP"
PYSPLIT
  printf '%s\n' "$split_ip" > "$work/split-ip"
fi
cat > "$work/cleanup.sh" <<'CLEANUP'
#!/usr/bin/env bash
# Independent recovery: no removal on unknown namespace/DNS ownership and
# no successful watchdog exit until all owned changes are independently absent.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
work=/root/server-connect-field-netns-qa
fail() { echo "RECOVERY_UNCERTAIN: $*" >&2; exit 3; }
[[ -d "$work" && ! -L "$work" && -f "$work/run-id" ]] ||
  fail 'private owner directory or invocation identity unavailable'
run_id=$(cat "$work/run-id") || fail 'invocation identity unreadable'
[[ "$run_id" =~ ^[0-9a-f]{16}$ ]] || fail 'invalid invocation identity'
namespace="scf$run_id"
owner="server-connect-field-netns-qa:$run_id"
host_if=$(cat "$work/underlay-interface") || fail 'underlay receipt unavailable'
[[ "$host_if" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || fail 'invalid underlay receipt'
boot_now=$(cat /proc/sys/kernel/random/boot_id) || fail 'boot identity unavailable'
[[ -f "$work/owner" ]] &&
  grep -Fqx "host=$(hostname) boot=$boot_now owner=$owner" "$work/owner" ||
  fail 'host/boot/owner receipt mismatch'
read -r baseline_routes baseline_rpdb baseline_filter baseline_nat baseline_boot < "$work/root-baseline" ||
  fail 'original root-network fingerprints unavailable'
for digest in "$baseline_routes" "$baseline_rpdb" "$baseline_filter" "$baseline_nat"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid original root-network fingerprint'
done
[[ "$baseline_boot" == "$boot_now" ]] || fail 'root baseline boot changed'

# A successful but malformed listing is also UNKNOWN. iproute2 prints
# NAME or NAME (id: N); other formats are not proof of absence.
valid_netns_list() {
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[a-zA-Z0-9_.-]+([[:space:]]+\(id:[[:space:]]*[0-9]+\))?$ ]] ||
      return 1
  done <<< "$1"
}
# A failed namespace listing or PID query is UNKNOWN, never absence.
listed=$(ip netns list) || fail 'namespace listing failed'
valid_netns_list "$listed" || fail 'malformed namespace listing'
active=no
if printf '%s\n' "$listed" | grep -Eq "^$namespace([[:space:]]|$)"; then
  [[ -s "$work/namespace-id" && ! -L "$work/namespace-id" ]] ||
    fail 'namespace exists without confirmed creation receipt'
  observed=$(stat -Lc '%d:%i' "/var/run/netns/$namespace") ||
    fail 'namespace NSFS identity cannot be inspected'
  [[ "$observed" == "$(cat "$work/namespace-id")" ]] ||
    fail 'namespace NSFS identity changed or belongs to another actor'
  active=yes
else
  [[ ! -e "/var/run/netns/$namespace" && ! -L "/var/run/netns/$namespace" ]] ||
    fail 'namespace listing and path disagree'
  if [[ -f "$work/namespace-id" && ! -f "$work/namespace-deleted" ]]; then
    fail 'created namespace missing without verified deletion receipt'
  fi
fi

# Only the positively identified namespace may supply process candidates.
if [[ "$active" == yes ]]; then
  candidates=$(ip netns pids "$namespace") || fail 'namespace PID query failed'
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || fail 'malformed namespace PID inventory'
    [[ -r "/proc/$candidate/cmdline" && -r "/proc/$candidate/stat" ]] ||
      fail 'namespace process identity unavailable'
    if tr '\0' ' ' < "/proc/$candidate/cmdline" | grep -Fq "$work/config.json"; then
      candidate_tick=$(awk '{print $22}' "/proc/$candidate/stat") ||
        fail 'namespace process start tick unavailable'
      [[ "$candidate_tick" =~ ^[0-9]+$ ]] || fail 'invalid process start identity'
      if [[ -r "/proc/$candidate/stat" &&
            "$(awk '{print $22}' "/proc/$candidate/stat")" == "$candidate_tick" ]]; then
        kill -TERM "$candidate" 2>/dev/null || :
        for i in 1 2 3 4 5; do
          [[ ! -e "/proc/$candidate" ]] && break
          sleep 1
        done
        if [[ -r "/proc/$candidate/stat" &&
              "$(awk '{print $22}' "/proc/$candidate/stat")" == "$candidate_tick" ]] &&
           tr '\0' ' ' < "/proc/$candidate/cmdline" | grep -Fq "$work/config.json"; then
          kill -KILL "$candidate" 2>/dev/null || :
        fi
      fi
    fi
  done <<< "$candidates"
  remaining=$(ip netns pids "$namespace") ||
    fail 'post-signal namespace PID query failed'
  [[ -z "$remaining" ]] ||
    fail 'namespace has live/unknown processes; deletion refused'
fi

# Bounded xtables lock wait and retries. Missing and deletion failure are
# distinguished by a separately successful listing, never by suppressing -D.
remove_root_rule() {
  local table=$1 chain=$2 tag=$3 attempt current
  shift 3
  for attempt in 1 2 3; do
    current=$(iptables -w 2 -t "$table" -S "$chain") ||
      fail "root $table/$chain listing failed"
    if ! printf '%s\n' "$current" | grep -Fq -- "$tag"; then
      return 0
    fi
    if iptables -w 2 -t "$table" -D "$chain" "$@"; then
      continue
    fi
    sleep 1
  done
  current=$(iptables -w 2 -t "$table" -S "$chain") ||
    fail "root $table/$chain post-retry listing failed"
  if printf '%s\n' "$current" | grep -Fq -- "$tag"; then
    fail "root $table/$chain tagged rule remains after bounded deletion"
  fi
}
remove_root_rule filter FORWARD "$owner:forward-out" -i scfqah -o "$host_if" -m comment --comment "$owner:forward-out" -j ACCEPT
remove_root_rule filter FORWARD "$owner:forward-in" -i "$host_if" -o scfqah -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$owner:forward-in" -j ACCEPT
remove_root_rule nat POSTROUTING "$owner:nat" -s 172.31.249.0/30 -o "$host_if" -m comment --comment "$owner:nat" -j MASQUERADE
inventory=$(iptables-save) || fail 'independent firewall listing failed'
if printf '%s\n' "$inventory" | grep -Fq -- "$owner"; then
  fail 'one or more tagged root firewall rules remain'
fi

if [[ -e /sys/class/net/scfqah || -L /sys/class/net/scfqah ]]; then
  [[ -r /sys/class/net/scfqah/ifalias ]] || fail 'root veth alias unavailable'
  [[ "$(cat /sys/class/net/scfqah/ifalias)" == "$owner" ]] ||
    fail 'root veth alias is foreign or changed'
  ip link delete scfqah || fail 'owned root veth deletion failed'
  [[ ! -e /sys/class/net/scfqah ]] || fail 'root veth still present'
fi
if [[ "$active" == yes ]]; then
  ip netns delete "$namespace" || fail 'owned namespace deletion failed'
  after=$(ip netns list) || fail 'post-deletion namespace listing failed'
  valid_netns_list "$after" || fail 'malformed post-deletion namespace listing'
  if printf '%s\n' "$after" | grep -Eq "^$namespace([[:space:]]|$)"; then
    fail 'deleted namespace still listed'
  fi
  [[ ! -e "/var/run/netns/$namespace" && ! -L "/var/run/netns/$namespace" ]] ||
    fail 'namespace path still exists'
  : > "$work/namespace-deleted"
fi

dns_dir="/etc/netns/$namespace"
if [[ -d "$dns_dir" || -L "$dns_dir" ]]; then
  [[ -d "$dns_dir" && ! -L "$dns_dir" && -s "$work/created-resolver-dir" ]] ||
    fail 'DNS directory exists without verified creation'
  [[ "$(stat -Lc '%d:%i' "$dns_dir")" == "$(cat "$work/created-resolver-dir")" ]] ||
    fail 'DNS directory inode differs from receipt'
  temp="$dns_dir/resolv.conf.tmp.$run_id"
  if [[ -e "$temp" || -L "$temp" ]]; then
    [[ -f "$temp" && ! -L "$temp" ]] || fail 'DNS temporary entry unrecognized'
    rm -- "$temp" || fail 'owned partial DNS temporary removal failed'
  fi
  if [[ -e "$dns_dir/resolv.conf" || -L "$dns_dir/resolv.conf" ]]; then
    [[ -f "$dns_dir/resolv.conf" && ! -L "$dns_dir/resolv.conf" ]] ||
      fail 'active DNS fixture is not regular'
    cmp -s "$dns_dir/resolv.conf" "$work/resolv.conf" ||
      fail 'active DNS fixture changed or unreadable'
    rm -- "$dns_dir/resolv.conf" || fail 'owned DNS fixture removal failed'
  fi
  rmdir -- "$dns_dir" || fail 'DNS directory not empty or removal failed'
  [[ ! -e "$dns_dir" ]] || fail 'deleted DNS directory still exists'
  : > "$work/dns-dir-deleted"
elif [[ -f "$work/created-resolver-dir" && ! -f "$work/dns-dir-deleted" ]]; then
  fail 'created DNS directory missing without verified removal'
fi
if [[ -f "$work/created-resolver-parent-intent" ]]; then
  if [[ -d /etc/netns || -L /etc/netns ]]; then
    [[ -d /etc/netns && ! -L /etc/netns && -s "$work/created-resolver-parent" ]] ||
      fail 'DNS parent exists without verified creation'
    [[ "$(stat -Lc '%d:%i' /etc/netns)" == "$(cat "$work/created-resolver-parent")" ]] ||
      fail 'DNS parent inode differs from receipt'
    rmdir /etc/netns || fail 'DNS parent contains foreign entries or deletion failed'
    [[ ! -e /etc/netns ]] || fail 'deleted DNS parent still exists'
    : > "$work/dns-parent-deleted"
  elif [[ -f "$work/created-resolver-parent" && ! -f "$work/dns-parent-deleted" ]]; then
    fail 'created DNS parent missing without verified removal'
  fi
fi
# Independently verify actual root network even when only watchdog survives.
current=$(ip -4 route show table all | sha256sum | cut -d' ' -f1) ||
  fail 'root route fingerprint unavailable'
[[ "$current" == "$baseline_routes" ]] || fail 'root route baseline differs'
current=$(ip -4 rule show | sha256sum | cut -d' ' -f1) ||
  fail 'root RPDB fingerprint unavailable'
[[ "$current" == "$baseline_rpdb" ]] || fail 'root RPDB baseline differs'
current=$(iptables -w 2 -t filter -S | sha256sum | cut -d' ' -f1) ||
  fail 'root filter fingerprint unavailable'
[[ "$current" == "$baseline_filter" ]] || fail 'root filter baseline differs'
current=$(iptables -w 2 -t nat -S | sha256sum | cut -d' ' -f1) ||
  fail 'root NAT fingerprint unavailable'
[[ "$current" == "$baseline_nat" ]] || fail 'root NAT baseline differs'
[[ "$(systemctl is-active ssh)" == active ]] ||
  fail 'root SSH inactive'
echo 'QA_SCOPED_CLEANUP_VERIFIED=PASS'
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
assert isinstance(out.get('server'),str) and 1 <= len(out['server']) <= 253
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
(w/'provider-host').write_text(out['server'])
PY
timeout 20s "$core" check -c "$work/config.json" >/dev/null || die "real selected profile TUN config invalid"
printf 'nameserver %s\nnameserver %s\n' "$resolver_ip" "$secondary_resolver" > "$work/resolv.conf"

finalize() {
  rc=$?
  trap - EXIT
  echo 'CLEANUP START'
  # Keep the independent timer armed until exact native restoration is
  # verified; a signal/failure during cleanup must not lose its recovery path.
  cleanup_ok=yes
  bash "$work/cleanup.sh" || cleanup_ok=no
  post_namespaces=$(ip netns list) || { echo 'ROOT_NAMESPACE_DISCOVERY_FAILED=FAIL'; cleanup_ok=no; post_namespaces=''; }
  # Unlike a line-fed Python splitlines parser, this accepts no namespaces.
  if ! valid_netns_listing "$post_namespaces"; then
    echo 'ROOT_NAMESPACE_FORMAT_UNKNOWN=FAIL' >&2
    cleanup_ok=no
  fi
  if [[ -e /sys/class/net/$veth_host ]] ||
     printf '%s\n' "$post_namespaces" | grep -Eq "^$namespace([[:space:]]|$)" ||
     [[ -d "/etc/netns/$namespace" ]] ||
     { [[ -f "$work/created-resolver-parent-intent" ]] && [[ -d /etc/netns ]]; }; then
    echo 'CLEANUP_CONFLICT=FAIL; evidence preserved' >&2
    cleanup_ok=no
  fi
  [[ "$baseline_routes" == "$(ip -4 route show table all | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_ROUTES_CHANGED=FAIL'; cleanup_ok=no; }
  [[ "$baseline_rpdb" == "$(ip -4 rule show | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_RPDB_CHANGED=FAIL'; cleanup_ok=no; }
  [[ "$baseline_filter" == "$(iptables -t filter -S | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_FILTER_CHANGED=FAIL'; cleanup_ok=no; }
  [[ "$baseline_nat" == "$(iptables -t nat -S | sha256sum | cut -d' ' -f1)" ]] || { echo 'ROOT_NAT_CHANGED=FAIL'; cleanup_ok=no; }
  [[ "$boot" == "$(cat /proc/sys/kernel/random/boot_id)" ]] || { echo 'ROOT_BOOT_CHANGED=FAIL'; cleanup_ok=no; }
  [[ "$(systemctl is-active ssh 2>/dev/null || :)" == active ]] || { echo 'HOST_SSH_INACTIVE=FAIL'; cleanup_ok=no; }
  # Even when a packet-path assertion fails, a verified complete native
  # rollback must stop its still-pending watchdog and release private secrets.
  # A failed/ambiguous rollback retains both watchdog and private evidence.
  if [[ "$cleanup_ok" == yes ]]; then
    timer_state=$(systemctl show "$watch.timer" -p LoadState --value 2>/dev/null || echo unknown)
    if [[ "$timer_state" != not-found ]]; then
      service_exec=$(systemctl show "$watch.service" -p ExecStart --value 2>/dev/null || :)
      service_state=$(systemctl show "$watch.service" -p ActiveState --value 2>/dev/null || echo unknown)
      if [[ "$service_exec" != *"$work/cleanup.sh"* ]] ||
         [[ "$service_state" == active || "$service_state" == activating ]] ||
         ! systemctl stop "$watch.timer" >/dev/null 2>&1 ||
         [[ "$(systemctl is-active "$watch.timer" 2>/dev/null || :)" == active ]]; then
        echo 'WATCHDOG_DISARM_UNVERIFIED=FAIL; evidence retained' >&2
        cleanup_ok=no
      fi
    fi
  fi
  if [[ "$cleanup_ok" == yes ]]; then
    echo 'ROOT_NETWORK_RESTORED=PASS'
    rm -f "$work/config.json" "$work/resolver-port" "$work/provider-host" "$work/provider-ips" "$work/owner" "$work/cleanup.sh" "$work/resolv.conf" "$work/underlay-interface" "$work/pid" "$work/core.log" "$work/created-resolver-parent" "$work/created-resolver-dir" "$work/split-ip" "$work/run-id" "$work/root-baseline" "$work/namespace-intent" "$work/namespace-id" "$work/namespace-deleted" "$work/created-resolver-parent-intent" "$work/created-resolver-dir-intent" "$work/dns-dir-deleted" "$work/dns-parent-deleted"
    rmdir "$work" || rc=1
  else
    echo 'QA_FAILED_OR_UNCERTAIN; private evidence retained for manual reconciliation' >&2
    rc=1
  fi
  exit "$rc"
}
trap finalize EXIT

# Independent, prearmed recovery in case the SSH test process is interrupted.
if ! systemd-run --quiet --collect --unit="$watch" --on-active=360s \
  --timer-property=AccuracySec=1s /usr/bin/bash "$work/cleanup.sh"; then
  echo 'WATCHDOG_ARM_RETURNED_FAILURE; inspecting live unit identity' >&2
fi
[[ "$(systemctl is-active "$watch.timer" 2>/dev/null || :)" == active ]] ||
  die "watchdog timer not independently active"
[[ "$(systemctl show "$watch.service" -p ExecStart --value 2>/dev/null || :)" == *"$work/cleanup.sh"* ]] ||
  die "watchdog service command identity mismatch"
echo 'GUARD_TIMER=PASS'

# An intent is NOT an ownership receipt. Uncertain creation is retained.
: > "$work/namespace-intent"
ip netns add "$namespace"
stat -Lc '%d:%i' "/var/run/netns/$namespace" > "$work/namespace-id" ||
  die "created namespace identity unverified"
# Create BOTH veth ends inside our empty, exclusively named test namespace.
# Crashes before the alias assignment leave NO unknown root link: deleting
# the empty namespace destroys its temporary veth pair.
ip netns exec "$namespace" ip link add "$veth_guest" type veth peer name "$veth_host"
ip netns exec "$namespace" ip link set "$veth_host" alias "$comment"
ip netns exec "$namespace" ip link set "$veth_host" netns 1
[[ "$(cat "/sys/class/net/$veth_host/ifalias")" == "$comment" ]] ||
  die "root veth lost its required ownership label"
ip addr add "$host_ip" dev "$veth_host"
ip link set "$veth_host" up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip addr add "$guest_ip" dev "$veth_guest"
ip netns exec "$namespace" ip link set "$veth_guest" up
ip netns exec "$namespace" ip route add default via 172.31.249.1 dev "$veth_guest"
if [[ ! -d /etc/netns ]]; then
  : > "$work/created-resolver-parent-intent"
  mkdir -m 755 /etc/netns
  stat -Lc '%d:%i' /etc/netns > "$work/created-resolver-parent" ||
    die "created resolver parent identity unverified"
fi
: > "$work/created-resolver-dir-intent"
mkdir -m 755 "/etc/netns/$namespace"
stat -Lc '%d:%i' "/etc/netns/$namespace" > "$work/created-resolver-dir" ||
  die "created resolver directory identity unverified"
# An interrupted copy leaves only a private temp file, not an active resolver.
cp "$work/resolv.conf" "/etc/netns/$namespace/resolv.conf.tmp.$run_id"
cmp -s "$work/resolv.conf" "/etc/netns/$namespace/resolv.conf.tmp.$run_id" ||
  die "DNS temporary copy differs"
mv -T "/etc/netns/$namespace/resolv.conf.tmp.$run_id" "/etc/netns/$namespace/resolv.conf"
iptables -I FORWARD 1 -i "$veth_host" -o "$host_if" -m comment --comment "$comment:forward-out" -j ACCEPT
iptables -I FORWARD 1 -i "$host_if" -o "$veth_host" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment:forward-in" -j ACCEPT
iptables -t nat -I POSTROUTING 1 -s "$subnet" -o "$host_if" -m comment --comment "$comment:nat" -j MASQUERADE
echo 'NETWORK_NAMESPACE=READY'

# Resolve once before TUN so the real HTTPS/VLESS test is independent of
# later DNS behavior. DNS under active TUN gets a separate FAIL/PASS result.
foreign_ip=$(timeout 12s ip netns exec "$namespace" getent ahostsv4 api.ipify.org | awk 'NR==1 {print $1}')
[[ "$foreign_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "cannot resolve test destination before TUN"
echo 'DIRECT_PRE_TUN_DNS=PASS'
# Resolve only the real selected provider's IPv4 endpoint(s), in this
# namespace, before TUN. Port-only outage rules are invalid: many VLESS
# transports use TCP/443, exactly like the foreign HTTPS leak probe.
provider_host=$(cat "$work/provider-host")
provider_answers=$(timeout 12s ip netns exec "$namespace" getent ahostsv4 "$provider_host") ||
  die "cannot resolve the selected upstream from this namespace"
printf '%s\n' "$provider_answers" | awk '{print $1}' | sort -u > "$work/provider-ips"
python3 - "$work/provider-ips" "$foreign_ip" <<'PYPROVIDER'
import ipaddress, pathlib, sys
items=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert 1 <= len(items) <= 8, "selected upstream IPv4 set absent or too broad"
assert all(ipaddress.IPv4Address(i).is_global for i in items)
assert sys.argv[2] not in items, "foreign leak witness overlaps provider"
PYPROVIDER
port=$(cat "$work/resolver-port")
[[ "$port" =~ ^[1-9][0-9]{0,4}$ && "$port" -ge 1 && "$port" -le 65535 ]] ||
  die "invalid selected remote port"
echo "SELECTED_UPSTREAM_IPV4_COUNT=$(wc -l < "$work/provider-ips")"
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
  ! grep -Fxq "$split_ip" "$work/provider-ips" ||
    die "split Direct probe overlaps selected provider IPv4"
fi

# A pre-armed independent underlay counter must witness the selected
# upstream, not merely infer VPN transit from a reported exit address.
while IFS= read -r provider_ip; do
  ip netns exec "$namespace" iptables -I OUTPUT 1 -o "$veth_guest" \
    -d "$provider_ip/32" -p tcp --dport "$port" \
    -m comment --comment "$comment-upstream"
done < "$work/provider-ips"
ip netns exec "$namespace" "$core" run -c "$work/config.json" >"$work/core.log" 2>&1 &
pid=$!
start_tick=$(awk '{print $22}' "/proc/$pid/stat") || die "cannot identify selected sing-box process"
[[ "$start_tick" =~ ^[0-9]+$ ]] || die "invalid sing-box process start identity"
printf '%s %s\n' "$pid" "$start_tick" > "$work/pid"
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
upstream_packets=$(ip netns exec "$namespace" iptables -vxnL OUTPUT --line-numbers |
  awk -v label="$comment-upstream" 'index($0,label)>0 {sum+=$2} END {print sum+0}')
[[ "$upstream_packets" =~ ^[0-9]+$ && "$upstream_packets" -gt 0 ]] ||
  die "no independent selected-provider underlay packet witness"
echo "SELECTED_UPSTREAM_UNDERLAY_PACKETS=$upstream_packets"
if [[ "$split_mode" != yes ]]; then
  ip netns exec "$namespace" curl -q --noproxy '*' -sS -4 --max-time 15 \
    https://www.cloudflare.com/cdn-cgi/trace |
    grep -E '^(ip|loc|colo)=' || :
fi
echo 'ISOLATED_SELECTED_TRANSPARENT_HTTPS=PASS (pinned api.ipify.org)'
if [[ "$split_mode" == yes ]]; then
  ip netns exec "$namespace" iptables -I OUTPUT 1 -o "$veth_guest" -d "$split_ip/32" \
    -p tcp --dport 443 -m comment --comment "$comment-direct"
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
    -p tcp --dport 443 -m comment --comment "$comment-direct"
  echo "EXPLICIT_PUBLIC_CIDR_DIRECT_IP=$split_actual"
  echo "EXPLICIT_DIRECT_AND_FOREIGN_VPN_SPLIT=PASS"
fi

# Negative proof: block ONLY the selected provider's actual IPv4
# destination(s) AND transport port. A blanket --dport 443 DROP would
# also block foreign HTTPS Direct leaks, manufacturing a false PASS.
# An independent foreign-Destination OUTPUT counter MUST remain zero.
probe=$(ip netns exec "$namespace" curl -q --noproxy '*' \
  --resolve "api.ipify.org:443:$foreign_ip" -sS -4 --max-time 12 https://api.ipify.org)
[[ "$probe" != "$expected_ip" && "$probe" != "$direct" ]] ||
  die "foreign pinned destination already Direct"
ip netns exec "$namespace" iptables -I OUTPUT 1 -o "$veth_guest" \
  -d "$foreign_ip/32" -p tcp --dport 443 \
  -m comment --comment "$comment-witness"
while IFS= read -r provider_ip; do
  ip netns exec "$namespace" iptables -I OUTPUT 1 -o "$veth_guest" \
    -d "$provider_ip/32" -p tcp --dport "$port" \
    -m comment --comment "$comment-outage" -j DROP
done < "$work/provider-ips"
outage_response=''
if outage_response=$(ip netns exec "$namespace" curl -q --noproxy '*' \
  --resolve "api.ipify.org:443:$foreign_ip" -fsS -4 --max-time 9 https://api.ipify.org 2>/dev/null); then
  echo "VPN_UPSTREAM_OUTAGE_FAILED_TO_BLOCK=$outage_response" >&2
  exit 1
fi
blocked=$(ip netns exec "$namespace" iptables -vxnL OUTPUT --line-numbers |
  awk -v label="$comment-outage" 'index($0,label)>0 {sum+=$2} END {print sum+0}')
[[ "$blocked" =~ ^[0-9]+$ && "$blocked" -gt 0 ]] ||
  die "no selected-provider outage-block packet witness"
witness=$(ip netns exec "$namespace" iptables -vxnL OUTPUT --line-numbers |
  awk -v label="$comment-witness" 'index($0,label)>0 {sum+=$2} END {print sum+0}')
[[ "$witness" =~ ^[0-9]+$ && "$witness" -eq 0 ]] ||
  die "foreign Direct-underlay leak counter nonzero/unknown"
[[ -e "/var/run/netns/$namespace" ]] || die "namespace disappeared during outage"
ip netns exec "$namespace" ip link show "$tun" >/dev/null ||
  die "TUN disappeared during outage"
echo "SELECTED_PROVIDER_OUTAGE_BLOCKED_PACKETS=$blocked"
echo 'VPN_REQUIRED_OUTAGE_NO_DIRECT_UNDERLAY=PASS'
while IFS= read -r provider_ip; do
  ip netns exec "$namespace" iptables -D OUTPUT -o "$veth_guest" \
    -d "$provider_ip/32" -p tcp --dport "$port" \
    -m comment --comment "$comment-outage" -j DROP
done < "$work/provider-ips"
ip netns exec "$namespace" iptables -D OUTPUT -o "$veth_guest" \
  -d "$foreign_ip/32" -p tcp --dport 443 \
  -m comment --comment "$comment-witness"
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
