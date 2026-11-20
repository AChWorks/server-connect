#!/bin/sh
# Sourced by host-tun-path.sh in the disposable, network-disconnected
# systemd guest. This is the ACTUAL installed connect-smart/Core lifecycle,
# not the legacy smart-tun-trial-apply or a standalone compiled Core config.
# Its synthetic peer is not an Internet provider or physical field acceptance.
# The helper is sourced into a set -u shell whose EXIT trap can run before
# native_installed_trial reaches its baseline. Always initialize both claims
# so a preflight/import failure keeps the original diagnostic and full cleanup.
native_installed_prepared=no
native_installed_rule_added=no
# Preserve only the synthetic Core-owned output-chain rendering in memory,
# before independent recovery removes the table. Printed only on QA failure.
native_installed_output_nat_shape=
native_installed_baseline() {
  test "$(ip -N -j -4 route show table all)" = "$native_installed_routes4" &&
    test "$(ip -N -j -4 rule show)" = "$native_installed_rules4" &&
    test "$(ip -N -j -6 route show table all)" = "$native_installed_routes6" &&
    test "$(ip -N -j -6 rule show)" = "$native_installed_rules6" &&
    test "$(nft -j list ruleset)" = "$native_installed_nft" &&
    test ! -e /sys/class/net/sctunqa0 &&
    test "$(systemctl show server-connect-native-tun.service -p ActiveState --value)" = inactive &&
    test "$(systemctl show server-connect-smart-health.timer -p ActiveState --value)" = inactive &&
    test "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive &&
    test "$(systemctl is-enabled server-connect-smart-health.timer)" = disabled &&
    test "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled
}

native_installed_error() {
  python3 - "$1" <<'PYQAERROR'
import json,sys
try:
    with open(sys.argv[1],encoding="utf-8") as f: value=json.load(f)
    detail=value.get("error") or {}
    print("INSTALLED_NATIVE_CLI_ERROR="+json.dumps({
        "code":str(detail.get("code", ""))[:80],
        "message":str(detail.get("message", ""))[:180],
    },sort_keys=True))
except (OSError,TypeError,ValueError):
    print("INSTALLED_NATIVE_CLI_ERROR=unavailable")
PYQAERROR
}

native_installed_diagnostic() {
  # Synthetic, bounded, credential-free state only. Do not print the
  # installed selected profile or complete Core configuration.
  /usr/local/bin/server-connect --json native-status | python3 -c '
import json,sys
try:
    doc=json.load(sys.stdin)
    obj=doc.get("data") or {}
    print("INSTALLED_NATIVE_DIAGNOSTIC="+json.dumps({
        "ok":doc.get("ok"), "error":(doc.get("error") or {}).get("code"),
        "desired":obj.get("desired"), "observed":obj.get("observed"),
        "health_phase":obj.get("health_phase"), "health_reason":obj.get("health_reason"),
        "runtime_guard_verified":obj.get("runtime_guard_verified")},sort_keys=True))
except (ValueError,TypeError):print("INSTALLED_NATIVE_DIAGNOSTIC=unavailable")
' >&2 || :
  systemctl show server-connect-native-tun.service -p ActiveState -p Result -p MainPID >&2 || :
  systemctl show server-connect-smart-health.service -p ActiveState -p Result >&2 || :
  systemctl show server-connect-activation-recover.service -p ActiveState -p Result >&2 || :
  if [ -n "$native_installed_output_nat_shape" ]; then
    printf '%s\n' "$native_installed_output_nat_shape" |
      sed 's/^/INSTALLED_NATIVE_OUTPUT_NAT=/' >&2
  fi
  # Field shapes only: never print accepted TCP tuple or set element values.
  nft -j list table inet sc_reply_guard 2>/dev/null | python3 -c '
import json,sys
try:
    doc=json.load(sys.stdin)
    for node in doc.get("nftables",[]):
        if len(node)!=1:continue
        kind,obj=next(iter(node.items()))
        if kind=="metainfo":continue
        summary={"kind":kind,"fields":sorted(obj)}
        if kind=="set":
            summary["type"]=obj.get("type")
            summary["elements"]=len(obj.get("elem") or [])
        if kind=="rule":
            summary["expr_shapes"]=[sorted(expr) for expr in obj.get("expr",[])]
        print("INSTALLED_NATIVE_NFT_SHAPE="+json.dumps(summary,sort_keys=True))
except (OSError,TypeError,ValueError):
    print("INSTALLED_NATIVE_NFT_SHAPE=unavailable")
' >&2 || :
}

native_installed_cleanup() {
  # This hook runs BEFORE the caller removes its VETH/peer. A failed native
  # operation must keep the original failure and must not be called recovered
  # just because the outer disposable Docker container will be destroyed.
  if [ "$native_installed_prepared" != yes ]; then return 0; fi
  if ! /usr/local/bin/server-connect --json disconnect >/run/sc-qa-installed-native-off.json; then
    echo 'INSTALLED_NATIVE_CLEANUP=FAIL (official Disconnect failed)' >&2
    native_installed_error /run/sc-qa-installed-native-off.json >&2
    return 1
  fi
  if [ "$native_installed_rule_added" = yes ]; then
    if ! /usr/local/bin/server-connect --json smart-routing-rules remove --cidr 5.22.0.10/32 >/dev/null; then
      echo 'INSTALLED_NATIVE_CLEANUP=FAIL (owned operator rule not removed)' >&2
      return 1
    fi
    native_installed_rule_added=no
  fi
  if ! native_installed_baseline; then
    echo 'INSTALLED_NATIVE_CLEANUP=FAIL (kernel or native units differ from prior baseline)' >&2
    return 1
  fi
  if ! /usr/local/bin/server-connect --json status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive",r
'; then
    echo 'INSTALLED_NATIVE_CLEANUP=FAIL (status not Direct/inactive)' >&2
    return 1
  fi
  native_installed_prepared=no
  echo 'INSTALLED_NATIVE_CLEANUP=PASS (exact five kernel inventories, installed units, selected profile retained)'
}

native_installed_trial() {
  sc=/usr/local/bin/server-connect
  test -x "$sc" && test "$(ps -p 1 -o comm=)" = systemd || return 1
  test "$(systemctl show server-connect-native-tun.service -p ActiveState --value)" = inactive || return 1
  test "$(systemctl is-enabled server-connect-native-tun.service)" = disabled || return 1
  test ! -e /var/lib/server-connect/native-session.json || return 1
  test ! -e /var/lib/server-connect/native-tun.json || return 1
  native_installed_routes4=$(ip -N -j -4 route show table all) || return 1
  native_installed_rules4=$(ip -N -j -4 rule show) || return 1
  native_installed_routes6=$(ip -N -j -6 route show table all) || return 1
  native_installed_rules6=$(ip -N -j -6 rule show) || return 1
  native_installed_nft=$(nft -j list ruleset) || return 1
  native_installed_prepared=yes

  profile=$(
    printf '%s\n' '{"type":"vless","tag":"qa-profile","server":"10.254.72.2","server_port":19182,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}' |
      "$sc" --json import --file - | python3 -c '
import json,re,sys
r=json.load(sys.stdin)
assert r["ok"] and re.fullmatch("[a-f0-9]{16}",r["data"]["id"]),r
print(r["data"]["id"])'
  ) || return 1
  "$sc" --json select "$profile" >/dev/null || return 1
  # The manual Direct fixture is deliberately independent of approximate
  # country geolocation: selected foreign and explicit Direct are both real.
  "$sc" --json smart-routing-rules add --cidr 5.22.0.10/32 --via direct >/dev/null || return 1
  native_installed_rule_added=yes
  native_installed_baseline || return 1
  echo 'INSTALLED_NATIVE_PREARM_DIRECT_BASELINE=PASS'

  # Ten failed HTTPS health rounds allow a bounded packet-positive phase
  # without misrepresenting this guest's absent public/synthetic HTTPS server
  # as a healthy provider. The independent guards remain armed throughout.
  "$sc" --json connect-smart --underlay-if scqaedge0 --tunnel-if sctunqa0 \
    --tunnel-ipv4 172.31.99.1/30 --tunnel-ipv6 fd73:99::1/64 \
    --mode default --health-failures 10 > /run/sc-qa-installed-native-connect.json || {
      echo 'INSTALLED_NATIVE_APPLY=FAIL (installed CLI refused or did not stabilize)' >&2
      native_installed_error /run/sc-qa-installed-native-connect.json >&2
      native_installed_diagnostic
      return 1
    }
  "$sc" --json native-status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["desired"]=="smart" and r["data"]["observed"]=="active",r
assert r["data"]["recovery_claim_present"] and r["data"]["runtime_guard_verified"],r
assert r["data"]["inbound_reply_guard_verified"],r
' || return 1
  test -e /sys/class/net/sctunqa0 || return 1
  test "$(systemctl show server-connect-native-tun.service -p ActiveState --value)" = active || return 1
  test "$(systemctl show server-connect-smart-health.timer -p ActiveState --value)" = active || return 1
  test "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = active || return 1
  native_installed_output_nat_shape=$(nft list chain inet sing-box output) || return 1
  # nft may print Core's interface/host-local exceptions; in this disconnected
  # synthetic-only guest none contains credentials or customer destinations.
  test "${#native_installed_output_nat_shape}" -le 8192 || return 1

  # No selected packet is sent before the installed Core and both guards are
  # verified active. An independent native packet counter is fixed BEFORE
  # the first selected request, so a transient Direct leak cannot be ignored.
  direct_tcp_before=$(direct_witness_packets) || return 1
  direct_udp_before=$(direct_udp_witness_packets) || return 1
  direct_dns_udp_before=$(direct_dns_udp_witness_packets) || return 1
  direct_dns_tcp_before=$(direct_dns_tcp_witness_packets) || return 1
  test "$direct_tcp_before" -eq "$witness_baseline" || return 1
  expect_source 5.22.0.10 10.254.72.1 || return 1
  expect_source 8.8.8.8 8.8.8.8 || return 1
  udp_path 8.8.8.8 8.8.8.8 native-installed-vpn reply || return 1
  dns_path 8.8.8.8 192.0.2.33 native-installed-dnsudp udp reply || return 1
  dns_path 8.8.8.8 192.0.2.33 native-installed-dnstcp tcp reply || return 1
  expect_foreign_hosted_reply || return 1
  test "$(direct_witness_packets)" -eq "$direct_tcp_before" &&
    test "$(direct_udp_witness_packets)" -eq "$direct_udp_before" &&
    test "$(direct_dns_udp_witness_packets)" -eq "$direct_dns_udp_before" &&
    test "$(direct_dns_tcp_witness_packets)" -eq "$direct_dns_tcp_before" || {
      echo 'INSTALLED_NATIVE_SELECTED_PATH=FAIL (VPN-required packet leaked underlay Direct)' >&2
      return 1
    }
  echo 'INSTALLED_NATIVE_SELECTED_PATH=PASS (installed Core, selected TCP/UDP/DNS, manual Direct, foreign hosting, independent no-leak counters)'

  native_installed_cleanup || return 1
  echo 'INSTALLED_NATIVE_EXPLICIT_OFF=PASS (installed lifecycle, five exact inventories, independent guards inert)'

  # Real installed Health Executor must independently retire a session that
  # has no authenticated selected HTTPS target. This is NOT a provider-outage
  # test and does not establish healthy real Internet HTTPS. The first phase
  # above independently established a working selected VLESS data path.
  native_installed_prepared=yes
  "$sc" --json connect-smart --underlay-if scqaedge0 --tunnel-if sctunqa0 \
    --tunnel-ipv4 172.31.99.1/30 --tunnel-ipv6 fd73:99::1/64 \
    --mode default --health-failures 1 > /run/sc-qa-installed-native-outage.json || {
      echo 'INSTALLED_NATIVE_GUARD_APPLY=FAIL (installed CLI refused or did not stabilize)' >&2
      native_installed_error /run/sc-qa-installed-native-outage.json >&2
      native_installed_diagnostic
      return 1
    }
  independent_off=no
  for attempt in $(seq 1 45); do
    if "$sc" --json status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive",r
' 2>/dev/null; then
      independent_off=yes
      break
    fi
    sleep 1
  done
  test "$independent_off" = yes || {
    echo 'INSTALLED_NATIVE_UNHEALTHY_GUARD=FAIL (no independent Direct/off)' >&2
    return 1
  }
  "$sc" --json native-status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["health_phase"]=="off",r
assert r["data"]["health_failures"] >= 1 and r["data"]["health_rounds"] >= 1,r
assert r["data"]["health_reason"] in (
    "selected_tcp_unreachable", "selected_tls_unavailable",
    "selected_https_invalid_response", "selected_https_unreachable",
    "selected_https_write_failed", "selected_https_unhealthy",
    "selected_probe_timeout", "selected_path_failure_exhausted"),r
' || return 1
  echo 'INSTALLED_NATIVE_UNHEALTHY_GUARD=PASS (independent selected-HTTPS-missing Off, not genuine provider-outage acceptance)'
  native_installed_cleanup || return 1
}
