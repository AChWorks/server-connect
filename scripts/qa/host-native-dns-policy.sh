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
              native_dns_v6_country_override_udp native_dns_v6_country_override_tcp \
              direct_dns_udp_packets direct_dns_tcp_packets; do
    peer_counter_packets "$name" || return 1
  done
  # In default mode the bundled estimated-country IPv6 destination must
  # ALSO be VPN-only. In bypass_iran it is intentionally native Direct.
  if [ "$mode" = default ]; then
    peer_counter_packets native_dns_v6_country_udp &&
      peer_counter_packets native_dns_v6_country_tcp || return 1
  fi
}

native_dns_direct_witnesses() {
  for name in native_dns_v4_direct_udp native_dns_v4_direct_tcp \
              native_dns_v4_private_udp native_dns_v4_private_tcp \
              native_dns_v6_country_udp native_dns_v6_country_tcp; do
    peer_counter_packets "$name" || return 1
  done
}

# Require BOTH transports on explicit IPv4 Direct and private IPv4 to grow.
# The estimated IPv6 country destination must grow only in bypass_iran;
# default mode must keep the old positive-control native packet counts flat.
native_dns_direct_progress() {
  printf '%s\n%s\n' "$1" "$2" | awk -v mode="$mode" '
    NR <= 6 { if ($1 !~ /^[0-9]+$/) invalid=1; previous[NR]=$1; next }
    {
      i=NR-6
      if (i > 6 || $1 !~ /^[0-9]+$/) invalid=1
      else if (i <= 4 || mode == "bypass_iran") {
        if ($1 <= previous[i]) invalid=1
      } else if ($1 != previous[i]) invalid=1
    }
    END { exit (NR == 12 && !invalid) ? 0 : 1 }
  '
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
    dns_path 9.9.9.9 192.0.2.11 "pre-v4-direct-$transport" "$transport" reply
    dns_path 10.254.72.2 192.0.2.11 "pre-v4-private-$transport" "$transport" reply
    dns_path 2001:470:f486::10 192.0.2.11 "pre-v6-country-$transport" "$transport" reply
    dns_path 2001:470:f486::11 192.0.2.11 "pre-v6-geo-vpn-$transport" "$transport" reply
  done
  native_dns_before=$(native_dns_vpn_witnesses)
  if [ "$mode" = default ]; then vpn_controls=14; else vpn_controls=12; fi
  printf '%s\n' "$native_dns_before" |
    awk -v expected="$vpn_controls" 'NF == 1 && $1 ~ /^[0-9]+$/ && $1 > 0 {passed++} END {exit passed == expected ? 0 : 1}' || {
    echo 'NATIVE_DNS_WIRE=FAIL (missing independent pre-TUN packet witnesses)' >&2
    return 1
  }
  direct_before=$(peer_counter_packets native_dns_v6_direct_udp)
  test "$direct_before" -gt 0
  native_dns_direct_baseline=$(native_dns_direct_witnesses)
  printf '%s\n' "$native_dns_direct_baseline" |
    awk 'NF == 1 && $1 ~ /^[0-9]+$/ && $1 > 0 {passed++} END {exit passed == 6 ? 0 : 1}' || {
      echo 'NATIVE_DNS_WIRE=FAIL (missing IPv4 Direct/private or IPv6 country positive witness)' >&2
      return 1
    }
  # Independent positive large-datagram control on the actual peer and
  # underlay before TUN: a missing or broken responder must not make an
  # outgoing VPN-only timeout look like an acceptable negative result.
  ipv6_path udp 2606:4700:5::10 fd73:1::1 reply 1353
  ipv6_path udp 2606:4700:5::10 fd73:1::1 reply 2400
  native_ipv6_payload_direct_before=$(peer_counter_packets ipv6_override_udp_packets)
  test "$native_ipv6_payload_direct_before" -gt 0 || return 1
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
    dns_path 9.9.9.9 192.0.2.11 "direct-v4-$transport" "$transport" reply
    dns_path 10.254.72.2 192.0.2.11 "private-v4-$transport" "$transport" reply
    dns_path 2001:470:f486::11 192.0.2.22 "geo-v6-vpn-$transport" "$transport" reply
    if [ "$mode" = bypass_iran ]; then
      dns_path 2001:470:f486::10 192.0.2.11 "geo-v6-direct-$transport" "$transport" reply
    else
      dns_path 2001:470:f486::10 192.0.2.33 "geo-v6-vpn-default-$transport" "$transport" reply
    fi
  done
  native_dns_direct_active=$(native_dns_direct_witnesses)
  native_dns_direct_progress "$native_dns_direct_baseline" "$native_dns_direct_active" || {
    echo 'NATIVE_DNS_WIRE=FAIL (IPv4 Direct/private or IPv6 country selection)' >&2
    return 1
  }
  test "$(peer_counter_packets native_dns_v6_direct_udp)" -gt "$direct_before"
  test "$(native_dns_vpn_witnesses)" = "$native_dns_before" || {
    echo 'NATIVE_DNS_WIRE=FAIL (explicit-VPN IPv6 packets leaked native Direct)' >&2
    return 1
  }
  echo "NATIVE_DNS_SELECTED_ADDRESS_PRECEDENCE=PASS ($mode)"

  # Prior 1400-byte virtual MTU fragmented the 1353-byte UDP application
  # payload (40 IPv6 + 8 UDP), and the selected gVisor/VLESS path silently
  # lost it. Verify both sides of that cutoff and a larger application
  # datagram on the CURRENT native compiler, never the retired candidate.
  test "$(cat /sys/class/net/sctunqa0/mtu)" = 9000 || {
    echo 'NATIVE_IPV6_UDP_MTU=FAIL (native TUN virtual MTU drift)' >&2
    return 1
  }
  for size in 1352 1353 2400; do
    ipv6_path udp 2606:4700:5::10 2606:4700:5::10 reply "$size"
  done
  test "$(peer_counter_packets ipv6_override_udp_packets)" = "$native_ipv6_payload_direct_before" &&
    assert_tun_policy_active || {
      echo 'NATIVE_IPV6_UDP_MTU=FAIL (selected IPv6 reply or native Direct leak)' >&2
      return 1
    }
  echo "NATIVE_IPV6_UDP_MTU=PASS ($mode)"

  # Real selected VLESS TCP underlay may have a smaller MTU than the TUN.
  # Lower the exclusive QA VETH to IPv6's minimum, prove a 2400-byte IPv6
  # UDP exchange still reaches the selected peer, then restore both ends.
  edge_mtu=$(cat "/sys/class/net/$edge/mtu")
  peer_mtu=$(ip -n "$peer" -j link show dev scqapeer0 |
    python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["mtu"])')
  test "$edge_mtu" -gt 1280 && test "$peer_mtu" -gt 1280 || return 1
  ip link set dev "$edge" mtu 1280
  ip -n "$peer" link set dev scqapeer0 mtu 1280
  test "$(cat "/sys/class/net/$edge/mtu")" = 1280 || return 1
  ipv6_path udp 2606:4700:5::10 2606:4700:5::10 reply 2400
  dns_path 10.254.72.2 192.0.2.11 'small-underlay-private-v4' udp reply
  ip link set dev "$edge" mtu "$edge_mtu"
  ip -n "$peer" link set dev scqapeer0 mtu "$peer_mtu"
  test "$(cat "/sys/class/net/$edge/mtu")" = "$edge_mtu" &&
    test "$(ip -n "$peer" -j link show dev scqapeer0 |
      python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["mtu"])')" = "$peer_mtu" &&
    test "$(peer_counter_packets ipv6_override_udp_packets)" = "$native_ipv6_payload_direct_before" &&
    assert_tun_policy_active || {
      echo 'NATIVE_IPV6_UDP_REDUCED_UNDERLAY=FAIL (selected path, leak or MTU restoration)' >&2
      return 1
    }
  echo "NATIVE_IPV6_UDP_REDUCED_UNDERLAY=PASS ($mode)"

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
    dns_path 2001:470:f486::11 none "out-v6-geo-vpn-$transport" "$transport" no-success
    if [ "$mode" = default ]; then
      dns_path 5.22.0.10 none "out-v4-country-$transport" "$transport" no-success
      dns_path 2001:470:f486::10 none "out-v6-country-$transport" "$transport" no-success
    fi
  done
  kill -0 "$dns_pid" && assert_tun_policy_active &&
    test "$(native_dns_vpn_witnesses)" = "$native_dns_before" || {
      echo 'NATIVE_DNS_WIRE=FAIL (selected DNS escaped Direct during outage)' >&2
      return 1
    }
  # The same large selected datagram must NOT escape Direct when the peer
  # transport fails; the separate positive control preceded this outage.
  ipv6_path udp 2606:4700:5::10 none no-reply 2400
  test "$(peer_counter_packets ipv6_override_udp_packets)" = "$native_ipv6_payload_direct_before" || {
    echo 'NATIVE_IPV6_UDP_OUTAGE=FAIL (selected IPv6 leaked native Direct)' >&2
    return 1
  }
  echo "NATIVE_IPV6_UDP_OUTAGE=PASS ($mode)"
  echo "NATIVE_DNS_OUTAGE_FAIL_CLOSED=PASS ($mode)"

  for transport in udp tcp; do
    dns_path fd73:1::2 192.0.2.11 "out-v6-private-$transport" "$transport" reply
    dns_path 2606:4700:8::9 192.0.2.11 "out-v6-direct-$transport" "$transport" reply
    dns_path 9.9.9.9 192.0.2.11 "out-v4-direct-$transport" "$transport" reply
    dns_path 10.254.72.2 192.0.2.11 "out-v4-private-$transport" "$transport" reply
    if [ "$mode" = bypass_iran ]; then
      dns_path 5.22.0.10 192.0.2.11 "out-country-$transport" "$transport" reply
      dns_path 2001:470:f486::10 192.0.2.11 "out-v6-country-$transport" "$transport" reply
    fi
  done
  native_dns_direct_progress "$native_dns_direct_active" "$(native_dns_direct_witnesses)" || {
    echo 'NATIVE_DNS_WIRE=FAIL (explicit Direct/private during selected-provider outage)' >&2
    return 1
  }
  test "$(peer_counter_packets native_dns_v6_direct_udp)" -gt "$direct_before" &&
    test "$(native_dns_vpn_witnesses)" = "$native_dns_before" &&
    assert_tun_policy_active || {
      echo 'NATIVE_DNS_WIRE=FAIL (protected Direct or VPN-only witness changed)' >&2
      return 1
    }
  ipv6_path udp 2606:4700:5::11 fd73:1::1 reply 2400
  test "$(peer_counter_packets ipv6_override_udp_packets)" = "$native_ipv6_payload_direct_before" || return 1
  echo "NATIVE_DNS_DIRECT_OUTAGE_CONTROL=PASS ($mode)"
}
