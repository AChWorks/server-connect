#!/bin/sh
# Sourced only by host-tun-path.sh in its disconnected Docker/systemd guest.
# Exercises the integrated NativeSmartRoutingConfig compiler with independent
# IPv4/IPv6 DNS packet witnesses, not the historical candidate compiler.
# No production service, external DNS, geographic claim, or host Apply.

native_dns_vpn_witnesses() {
  for name in native_dns_v6_vpn_udp native_dns_v6_vpn_tcp \
              native_dns_v6_foreign_udp native_dns_v6_foreign_tcp \
              native_dns_resolver_udp native_dns_resolver_tcp \
              native_dns_v4_vpn_udp native_dns_v4_vpn_tcp \
              direct_dns_udp_packets direct_dns_tcp_packets; do
    peer_counter_packets "$name" || return 1
  done
}

native_dns_unmatched_diagnostics() {
  echo "NATIVE_DNS_WIRE=FAIL (mode=$mode stage=unmatched)" >&2
  # Bounded synthetic guest-only packet counters; exact originals cannot
  # silently be treated as selected VPN DNS replies.
  for name in native_dns_v6_foreign_udp native_dns_v6_foreign_tcp \
              native_dns_resolver_udp native_dns_resolver_tcp \
              direct_dns_udp_packets direct_dns_tcp_packets; do
    count=$(peer_counter_packets "$name") || count=unavailable
    printf 'NATIVE_DNS_COUNTER name=%s packets=%s\n' "$name" "$count" >&2
  done
  tail -n 20 /run/sc-qa-tun-client.log >&2 || :
}

native_dns_policy_trial() {
  mode=$SC_QA_TUN_NATIVE_DNS_MODE
  [ "$native_dns_trial" = yes ] && [ "$ipv6_trial" = yes ] || return 1
  kill -0 "$dns_pid" && kill -0 "$server_pid" || return 1

  # Positive proof of every independent UDP/TCP peer endpoint before TUN:
  # the same endpoints must stop receiving native Direct VPN traffic after
  # activation. No missing responder can masquerade as fail-closed routing.
  for transport in udp tcp; do
    dns_path 2606:4700:5::10 192.0.2.11 "pre-v6-vpn-$transport" "$transport" reply
    dns_path 2606:4700:8::8 192.0.2.11 "pre-v6-foreign-$transport" "$transport" reply
    dns_path 2606:4700:8::9 192.0.2.11 "pre-v6-direct-$transport" "$transport" reply
    dns_path fd73:1::2 192.0.2.11 "pre-v6-private-$transport" "$transport" reply
    dns_path 1.1.1.1 192.0.2.11 "pre-vpn-resolver-$transport" "$transport" reply
    dns_path 5.22.0.11 192.0.2.11 "pre-v4-vpn-$transport" "$transport" reply
    dns_path 5.22.0.10 192.0.2.11 "pre-v4-country-$transport" "$transport" reply
  done
  native_dns_before=$(native_dns_vpn_witnesses)
  # Ten exact counters need independent positive controls, not just one.
  printf '%s\n' "$native_dns_before" | awk 'NF == 1 && $1 ~ /^[0-9]+$/ && $1 > 0 {passed++} END {exit passed == 10 ? 0 : 1}' || {
    echo 'NATIVE_DNS_WIRE=FAIL (missing independent pre-TUN packet witnesses)' >&2
    return 1
  }
  direct_before=$(peer_counter_packets native_dns_v6_direct_udp)
  test "$direct_before" -gt 0
  echo "NATIVE_DNS_PRE_TUN_POSITIVE_CONTROL=PASS ($mode)"

  SC_QA_TUN_NATIVE_DNS=yes SC_QA_TUN_IPV6=yes SC_QA_TUN_NATIVE_DNS_MODE="$mode" \
    /root/qa-tun-config-qa > "$client_cfg"
  chmod 0600 "$client_cfg"
  "$core" check -c "$client_cfg"
  "$core" run -c "$client_cfg" >/run/sc-qa-tun-client.log 2>&1 &
  client_pid=$!

  # Wait for kernel ownership before sending any VPN-required packet; keep
  # the positive-control native counters frozen across the entire admission.
  ready=no
  attempt=0
  while [ "$attempt" -lt 50 ]; do
    if assert_tun_policy_active &&
       ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null; then
      ready=yes
      break
    fi
    kill -0 "$client_pid" 2>/dev/null || { cat /run/sc-qa-tun-client.log >&2; return 1; }
    attempt=$((attempt+1))
    sleep 0.2
  done
  if [ "$ready" != yes ]; then
    cat /run/sc-qa-tun-client.log >&2
    echo 'NATIVE_DNS_WIRE=FAIL (native dual-stack TUN not admitted)' >&2
    return 1
  fi

  for transport in udp tcp; do
    dns_path fd73:1::2 192.0.2.11 "local-$transport" "$transport" reply
    dns_path 2606:4700:5::11 192.0.2.11 "direct-prefix-$transport" "$transport" reply
    dns_path 2606:4700:8::9 192.0.2.11 "direct-foreign-$transport" "$transport" reply
    dns_path 2606:4700:5::10 192.0.2.22 "vpn-except-$transport" "$transport" reply
    dns_path 5.22.0.11 192.0.2.22 "vpn-country-except-$transport" "$transport" reply
  done
  test "$(peer_counter_packets native_dns_v6_direct_udp)" -gt "$direct_before"
  test "$(native_dns_vpn_witnesses)" = "$native_dns_before" || {
    echo 'NATIVE_DNS_WIRE=FAIL (explicit-VPN IPv6 packets leaked native Direct)' >&2
    return 1
  }
  echo "NATIVE_DNS_SELECTED_ADDRESS_PRECEDENCE=PASS ($mode)"

  for transport in udp tcp; do
    dns_path 2606:4700:8::8 192.0.2.33 "unmatched-v6-$transport" "$transport" reply || {
      native_dns_unmatched_diagnostics
      return 1
    }
    dns_path 8.8.8.8 192.0.2.33 "unmatched-v4-$transport" "$transport" reply || {
      native_dns_unmatched_diagnostics
      return 1
    }
    if [ "$mode" = bypass_iran ]; then
      dns_path 5.22.0.10 192.0.2.11 "country-$transport" "$transport" reply
    else
      dns_path 5.22.0.10 192.0.2.33 "country-vpn-$transport" "$transport" reply
    fi
  done
  assert_tun_policy_active &&
    test "$(native_dns_vpn_witnesses)" = "$native_dns_before" || {
      echo 'NATIVE_DNS_WIRE=FAIL (unmatched DNS had a native Direct leak)' >&2
      return 1
    }
  echo "NATIVE_DNS_UNMATCHED_VPN_RESOLVER=PASS ($mode)"

  # Deliberately remove only the test VLESS provider while Core/TUN remain
  # active. No new VPN-required DNS may reach its original public address or
  # silently escape through the VETH underlay.
  kill "$server_pid"
  wait "$server_pid" 2>/dev/null || :
  server_pid=
  assert_tun_policy_active || return 1
  for transport in udp tcp; do
    dns_path 2606:4700:5::10 none "out-v6-vpn-$transport" "$transport" no-success
    dns_path 2606:4700:8::8 none "out-v6-default-$transport" "$transport" no-success
    dns_path 5.22.0.11 none "out-v4-vpn-$transport" "$transport" no-success
    dns_path 8.8.8.8 none "out-v4-default-$transport" "$transport" no-success
    if [ "$mode" = default ]; then
      dns_path 5.22.0.10 none "out-v4-country-$transport" "$transport" no-success
    fi
  done
  kill -0 "$dns_pid" && assert_tun_policy_active &&
    test "$(native_dns_vpn_witnesses)" = "$native_dns_before" || {
      echo 'NATIVE_DNS_WIRE=FAIL (selected DNS escaped Direct during outage)' >&2
      return 1
    }
  echo "NATIVE_DNS_OUTAGE_FAIL_CLOSED=PASS ($mode)"

  for transport in udp tcp; do
    dns_path fd73:1::2 192.0.2.11 "out-v6-private-$transport" "$transport" reply
    dns_path 2606:4700:8::9 192.0.2.11 "out-v6-direct-$transport" "$transport" reply
    if [ "$mode" = bypass_iran ]; then
      dns_path 5.22.0.10 192.0.2.11 "out-country-$transport" "$transport" reply
    fi
  done
  test "$(peer_counter_packets native_dns_v6_direct_udp)" -gt "$direct_before" &&
    test "$(native_dns_vpn_witnesses)" = "$native_dns_before" &&
    assert_tun_policy_active || {
      echo 'NATIVE_DNS_WIRE=FAIL (protected Direct or VPN-only witness changed)' >&2
      return 1
    }
  echo "NATIVE_DNS_DIRECT_OUTAGE_CONTROL=PASS ($mode)"
}
