#!/bin/sh
# Sourced ONLY by host-tun-path.sh inside the existing Docker --network none,
# PID1-systemd QA guest. Tests the installed product's REAL sing-box TUN
# pending-activation/recovery, not the older QA-only systemd guard.
product_tun_trial() {
  sc=/usr/local/bin/server-connect
  test -x "$sc" && test -f /.dockerenv
  test "$(ps -p 1 -o comm=)" = systemd
  test "$(systemctl show server-connect-smart-tun.service -p LoadState --value)" = loaded
  test "$(systemctl show server-connect-smart-tun.service -p UnitFileState --value)" = static
  test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
  test "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive
  test ! -e /var/lib/server-connect/route-activation-journal.json
  test ! -e /var/lib/server-connect/smart-tun-trial.json

  profile=$(
    printf '%s\n' '{"type":"vless","tag":"qa-profile","server":"10.254.72.2","server_port":19182,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}' |
      "$sc" --json import --file - | python3 -c '
import json,sys,re
x=json.load(sys.stdin)
assert x["ok"] and re.fullmatch(r"[0-9a-f]{16}",x["data"]["id"]),x
print(x["data"]["id"])'
  )
  "$sc" --json select "$profile" >/dev/null
  "$sc" --json smart-tun-trial-status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["phase"]=="absent",r'
  echo PRODUCT_TUN_INSTALLED_PROFILE_AND_IDLE=PASS

  # Capture the guest's actual native kernel baseline *after* all test VETH,
  # DNS, hosting and QA peer services have been constructed.
  before_routes=$(ip -N -j -4 route show table all)
  before_rules=$(ip -N -j -4 rule show)
  before_v6_routes=$(ip -N -j -6 route show table all)
  before_v6_rules=$(ip -N -j -6 rule show)
  before_nft=$(nft -j list ruleset)

  apply() {
    deadline=$1
    shift
    "$sc" --json smart-tun-trial-apply \
      --tunnel-if sctunqa0 --underlay-if scqaedge0 \
      --tunnel-ipv4 172.31.99.1/30 --management-peer 10.254.72.2 \
      --domestic-cidr 5.22.0.10/32 --protected-cidr 10.254.72.0/30 \
      --deadline-seconds "$deadline" "$@"
  }
  pending_receipt() {
    "$sc" --json smart-tun-trial-status | python3 -c '
import json,sys,re
r=json.load(sys.stdin)
assert r["ok"],r
d=r["data"]
assert d["phase"]=="trial_pending" and d["revision"]==1 and d["experiment_only"],d
assert d["guard_scheduled"] and not d["activation_ready"] and not d["vpn_verified"],d
assert not d["recovery_verified"] and re.fullmatch("[0-9a-f]{32}",d["operation_id"]),d
print(d["operation_id"])'
  }
  require_recovered() {
    expected=$1
    result=no
    for n in $(seq 1 60); do
      if "$sc" --json smart-tun-trial-status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["experiment_only"],r
if r["data"]["phase"]=="trial_recovered":
    assert r["data"]["revision"]==2 and r["data"]["recovery_verified"],r
    assert not r["data"]["guard_scheduled"] and not r["data"]["activation_ready"],r
    sys.exit(0)
assert r["data"]["phase"]=="trial_pending",r
sys.exit(1)' 2>/dev/null; then
        result=yes
        break
      fi
      if [ "$(systemctl show server-connect-activation-recover.service -p Result --value)" = exit-code ]; then
        echo 'PRODUCT_TUN_RECOVERY=FAIL (independent executor failed)' >&2
        journalctl -u server-connect-activation-recover.service --no-pager -n 12 >&2 || :
        return 1
      fi
      sleep 1
    done
    [ "$result" = yes ] || {
      echo 'PRODUCT_TUN_RECOVERY=FAIL (deadline did not restore host)' >&2
      systemctl show server-connect-smart-tun.service -p ActiveState -p Result >&2 || :
      return 1
    }
    actual_id=$("$sc" --json smart-tun-trial-status | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["operation_id"])')
    [ "$actual_id" = "$expected" ]
    [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive ]
    [ ! -e /sys/class/net/sctunqa0 ]
    [ "$(ip -N -j -4 route show table all)" = "$before_routes" ]
    [ "$(ip -N -j -4 rule show)" = "$before_rules" ]
    [ "$(ip -N -j -6 route show table all)" = "$before_v6_routes" ]
    [ "$(ip -N -j -6 rule show)" = "$before_v6_rules" ]
    [ "$(nft -j list ruleset)" = "$before_nft" ]
    systemctl is-active --quiet server-connect-activation-recover.timer
    # The separate systemd oneshot must have completed successfully, not
    # merely a "recovered" field written by the initiating CLI process.
    [ "$(systemctl show server-connect-activation-recover.service -p Result --value)" = success ]
    [ "$(systemctl show server-connect-activation-recover.service -p ExecMainStatus --value)" = 0 ]
  }
  clear_recovered() {
    "$sc" --json smart-tun-trial-clear --operation-id "$1" --revision 2 | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["cleared"],r'
    [ ! -e /var/lib/server-connect/route-activation-journal.json ]
    [ ! -e /var/lib/server-connect/smart-tun-trial.json ]
    [ "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive ]
    [ "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled ]
    "$sc" --json status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive",r'
  }
  # The legacy QA generator starts sing-box as a shell child and its
  # assert_tun_policy_active predicate correctly checks $client_pid. This
  # installed product trial is owned by a separate systemd unit instead:
  # checking a nonexistent shell PID would reject every valid product Apply.
  assert_product_tun_policy_active() {
    [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = active ] || return 1
    [ -e /sys/class/net/sctunqa0 ] || return 1
    ip -4 route show table all | grep -F 'dev sctunqa0' >/dev/null || return 1
    ip -4 rule show >/dev/null || return 1
    observed=$(nft -j list ruleset) || return 1
    [ "$observed" != "$before_nft" ] || return 1
  }
  require_native_baseline() {
    # Explicit returns also protect callers inside a shell conditional,
    # where POSIX shells suppress errexit for the whole function body.
    [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive ] || return 1
    [ ! -e /sys/class/net/sctunqa0 ] || return 1
    [ "$(ip -N -j -4 route show table all)" = "$before_routes" ] || return 1
    [ "$(ip -N -j -4 rule show)" = "$before_rules" ] || return 1
    [ "$(ip -N -j -6 route show table all)" = "$before_v6_routes" ] || return 1
    [ "$(ip -N -j -6 rule show)" = "$before_v6_rules" ] || return 1
    [ "$(nft -j list ruleset)" = "$before_nft" ]
  }
  require_finalized() {
    require_native_baseline
    [ ! -e /var/lib/server-connect/route-activation-journal.json ]
    [ ! -e /var/lib/server-connect/smart-tun-trial.json ]
    [ "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive ]
    [ "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled ]
    "$sc" --json status | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive",r'
  }
  require_independent_finalization() {
    # Poll files only: status must never secretly finish cleanup and turn
    # this into a false claim that the independent systemd executor ran.
    for cleanup_try in $(seq 1 25); do
      if [ ! -e /var/lib/server-connect/route-activation-journal.json ] &&
         [ "$(systemctl show server-connect-activation-recover.service -p ActiveState --value)" = inactive ]; then
        break
      fi
      sleep 1
    done
    require_finalized
    [ "$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)" -gt "$executor_before" ]
    [ "$(systemctl show server-connect-activation-recover.service -p Result --value)" = success ]
    [ "$(systemctl show server-connect-activation-recover.service -p ExecMainStatus --value)" = 0 ]
  }
  require_selected_ready() {
    lifecycle_ready=no
    for ready_try in $(seq 1 35); do
      if assert_product_tun_policy_active &&
         expect_source 5.22.0.10 10.254.72.1 &&
         expect_source 8.8.8.8 8.8.8.8; then
        if [ "$ipv6_trial" != yes ] ||
           ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null; then
          lifecycle_ready=yes
          break
        fi
      fi
      sleep 0.2
    done
    [ "$lifecycle_ready" = yes ]
  }
  saved_policy_hashes() {
    # Hash actual durable bytes, including the selected profile, without
    # logging any credential or accepting metadata as persistence proof.
    sha256sum "/var/lib/server-connect/profiles/$profile.json" \
      /var/lib/server-connect/smart-tun-policy.json \
      /var/lib/server-connect/state.json
  }
  capture_saved_policy() {
    "$sc" --json smart-tun-trial-policy | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["present"] and r["data"]["experiment_only"],r
assert r["data"]["management_peer_ip"]=="10.254.72.2",r'
    saved_policy_before=$(saved_policy_hashes)
  }
  disconnect_now() {
    "$sc" --json smart-tun-trial-disconnect --operation-id "$1" --revision "$2" |
      python3 -c '
import json,sys
r=json.load(sys.stdin); d=r.get("data",{})
assert r["ok"] and d["phase"]=="trial_cleared" and d["revision"]==5,r
assert d["recovery_verified"] and not d["guard_scheduled"] and not d["activation_ready"],r'
    require_finalized
    [ "$(saved_policy_hashes)" = "$saved_policy_before" ]
  }
  reject_disconnect_unchanged() {
    # Verify the current operation bytes and live native policy as well as
    # the error. A nonzero exit alone cannot prove another trial survived.
    stale_before=$(sha256sum /var/lib/server-connect/route-activation-journal.json /var/lib/server-connect/smart-tun-trial.json)
    stale_routes=$(ip -N -j -4 route show table all)
    stale_rules=$(ip -N -j -4 rule show)
    stale_v6_routes=$(ip -N -j -6 route show table all)
    stale_v6_rules=$(ip -N -j -6 rule show)
    stale_nft=$(nft -j list ruleset)
    if "$sc" --json smart-tun-trial-disconnect --operation-id "$1" --revision "$2" > /run/sc-qa-product-tun-conflict.json; then
      echo 'Stale Disconnect unexpectedly accepted' >&2; return 1
    fi
    python3 - <<'PYSTALEDISCONNECT'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='activation_journal_conflict',r
PYSTALEDISCONNECT
    [ "$(sha256sum /var/lib/server-connect/route-activation-journal.json /var/lib/server-connect/smart-tun-trial.json)" = "$stale_before" ]
    [ "$(ip -N -j -4 route show table all)" = "$stale_routes" ]
    [ "$(ip -N -j -4 rule show)" = "$stale_rules" ]
    [ "$(ip -N -j -6 route show table all)" = "$stale_v6_routes" ]
    [ "$(ip -N -j -6 rule show)" = "$stale_v6_rules" ]
    [ "$(nft -j list ruleset)" = "$stale_nft" ]
    require_selected_ready
  }

  if [ "$ipv6_trial" = yes ]; then
    # No arbitrary IPv6 Apply. Refuse a partial/modified dual-stack
    # candidate BEFORE journaling, prearming or any kernel mutation.
    for kind in partial broad; do
      case "$kind" in
        partial)
          set -- --tunnel-ipv6 fd73:99::1/64 ;;
        broad)
          set -- --tunnel-ipv6 fd73:99::1/64 \
            --domestic-ipv6-cidr 2001:db8:5::/64 \
            --ipv6-vpn-cidr 2001:db8:5::10/128 \
            --ipv6-direct-cidr 2000::/3 ;;
      esac
      if apply 8 "$@" > /run/sc-qa-product-tun-conflict.json; then
        echo "Product admitted unsupported IPv6 $kind policy" >&2;return 1
      fi
      python3 - <<'PYV6REFUSED'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_unsupported',r
PYV6REFUSED
      test ! -e /var/lib/server-connect/route-activation-journal.json
      test ! -e /var/lib/server-connect/smart-tun-trial.json
      test "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive
      test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
      test "$(ip -N -j -6 route show table all)" = "$before_v6_routes"
      test "$(ip -N -j -6 rule show)" = "$before_v6_rules"
      test "$(nft -j list ruleset)" = "$before_nft"
    done
    echo PRODUCT_TUN_IPV6_UNSUPPORTED_INPUT_REJECTED=PASS

    # This is a separate *installed product* trial with the existing real
    # native dual-stack fixture, not the older QA shell-owned TUN process.
    apply 55 --tunnel-ipv6 fd73:99::1/64 \
      --domestic-ipv6-cidr 2001:db8:5::/64 \
      --ipv6-vpn-cidr 2001:db8:5::10/128 \
      --ipv6-direct-cidr 2001:db8:8::9/128 \
      > /run/sc-qa-product-tun-apply.json
    op=$(pending_receipt)
    # systemctl start does not prove that sing-box has finished installing
    # its native IPv4 and IPv6 policy. Never probe a VPN-required flow
    # before BOTH kernel TUN families are visibly present and the selected
    # IPv4 path is independently confirmed, as in the existing IPv4 trial.
    ready=no
    for n in $(seq 1 35); do
      if assert_product_tun_policy_active &&
         ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null &&
         expect_source 5.22.0.10 10.254.72.1 &&
         expect_source 8.8.8.8 8.8.8.8; then
        ready=yes
        break
      fi
      sleep 0.2
    done
    [ "$ready" = yes ] || {
      echo 'PRODUCT_TUN_IPV6_SELECTED_POLICY=FAIL (owned dual-stack policy not ready)' >&2
      systemctl status server-connect-smart-tun.service --no-pager >&2 || :
      return 1
    }
    # Native positive controls were obtained earlier by host-tun-path.sh;
    # its peer nftables counters distinguish every unsafe Direct leak.
    test "$ipv6_foreign_tcp_baseline" -gt 0
    test "$ipv6_foreign_udp_baseline" -gt 0
    test "$ipv6_override_baseline" -gt 0
    test "$ipv6_override_udp_baseline" -gt 0
    ipv6_path tcp 2001:db8:5::11 fd73:1::1 reply
    ipv6_path udp 2001:db8:5::11 fd73:1::1 reply
    ipv6_path tcp 2001:db8:5::10 2001:db8:5::10 reply
    ipv6_path udp 2001:db8:5::10 2001:db8:5::10 reply
    ipv6_path tcp 2001:db8:8::8 2001:db8:8::8 reply
    ipv6_path udp 2001:db8:8::8 2001:db8:8::8 reply
    ipv6_path tcp 2001:db8:8::9 fd73:1::1 reply
    ipv6_path udp 2001:db8:8::9 fd73:1::1 reply
    test "$(ipv6_foreign_tcp_direct_packets)" -eq "$ipv6_foreign_tcp_baseline"
    test "$(ipv6_foreign_udp_direct_packets)" -eq "$ipv6_foreign_udp_baseline"
    test "$(ipv6_override_direct_packets)" -eq "$ipv6_override_baseline"
    test "$(ipv6_override_udp_direct_packets)" -eq "$ipv6_override_udp_baseline"
    expect_source 5.22.0.10 10.254.72.1
    expect_source 8.8.8.8 8.8.8.8
    expect_foreign_hosted_reply
    /bin/sh /root/qa-host-coexistence.sh probe
    assert_product_tun_policy_active
    echo PRODUCT_TUN_IPV6_REAL_SELECTED=PASS

    # Real dual-stack Off/on lifecycle using the installed commands. The
    # peer witnesses must see native Direct after Off and selected VLESS
    # again under a NEW guarded operation using the same saved bytes.
    capture_saved_policy
    previous_op=$op
    disconnect_now "$op" 1
    expect_source 8.8.8.8 10.254.72.1
    ipv6_path tcp 2001:db8:8::8 fd73:1::1 reply
    ipv6_path udp 2001:db8:8::8 fd73:1::1 reply
    ipv6_path tcp 2001:db8:5::10 fd73:1::1 reply
    ipv6_path udp 2001:db8:5::10 fd73:1::1 reply
    test "$(ipv6_foreign_tcp_direct_packets)" -gt "$ipv6_foreign_tcp_baseline"
    test "$(ipv6_foreign_udp_direct_packets)" -gt "$ipv6_foreign_udp_baseline"
    test "$(ipv6_override_direct_packets)" -gt "$ipv6_override_baseline"
    test "$(ipv6_override_udp_direct_packets)" -gt "$ipv6_override_udp_baseline"
    ipv6_foreign_tcp_baseline=$(ipv6_foreign_tcp_direct_packets)
    ipv6_foreign_udp_baseline=$(ipv6_foreign_udp_direct_packets)
    ipv6_override_baseline=$(ipv6_override_direct_packets)
    ipv6_override_udp_baseline=$(ipv6_override_udp_direct_packets)
    "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 55 >/run/sc-qa-product-tun-apply.json
    op=$(pending_receipt)
    test "$op" != "$previous_op"
    require_selected_ready
    test "$(saved_policy_hashes)" = "$saved_policy_before"
    ipv6_path tcp 2001:db8:8::8 2001:db8:8::8 reply
    ipv6_path udp 2001:db8:8::8 2001:db8:8::8 reply
    ipv6_path tcp 2001:db8:5::10 2001:db8:5::10 reply
    ipv6_path udp 2001:db8:5::10 2001:db8:5::10 reply
    test "$(ipv6_foreign_tcp_direct_packets)" -eq "$ipv6_foreign_tcp_baseline"
    test "$(ipv6_foreign_udp_direct_packets)" -eq "$ipv6_foreign_udp_baseline"
    test "$(ipv6_override_direct_packets)" -eq "$ipv6_override_baseline"
    test "$(ipv6_override_udp_direct_packets)" -eq "$ipv6_override_udp_baseline"
    echo PRODUCT_TUN_IPV6_EXPLICIT_OFF_SAVED_REAPPLY=PASS

    # The selected VLESS upstream is genuinely killed. The product TUN
    # remains active until its independent deadline, and all VPN-required
    # IPv6 TCP/UDP must fail CLOSED, not leak native Direct packets.
    kill "$server_pid"
    wait "$server_pid" || :
    ipv6_path tcp 2001:db8:8::8 none no-reply
    ipv6_path udp 2001:db8:8::8 none no-reply
    ipv6_path tcp 2001:db8:5::10 none no-reply
    ipv6_path udp 2001:db8:5::10 none no-reply
    kill -0 "$ipv6_pid" 2>/dev/null
    ipv6_path tcp 2001:db8:5::11 fd73:1::1 reply
    ipv6_path udp 2001:db8:5::11 fd73:1::1 reply
    ipv6_path tcp 2001:db8:8::9 fd73:1::1 reply
    ipv6_path udp 2001:db8:8::9 fd73:1::1 reply
    test "$(ipv6_foreign_tcp_direct_packets)" -eq "$ipv6_foreign_tcp_baseline"
    test "$(ipv6_foreign_udp_direct_packets)" -eq "$ipv6_foreign_udp_baseline"
    test "$(ipv6_override_direct_packets)" -eq "$ipv6_override_baseline"
    test "$(ipv6_override_udp_direct_packets)" -eq "$ipv6_override_udp_baseline"
    ip -6 route show table all | grep -F 'dev sctunqa0' >/dev/null
    assert_product_tun_policy_active
    expect_foreign_hosted_reply
    echo PRODUCT_TUN_IPV6_OUTAGE_FAIL_CLOSED=PASS

    require_recovered "$op"
    /bin/sh /root/qa-host-coexistence.sh probe
    expect_foreign_hosted_reply
    clear_recovered "$op"
    rm -f /run/sc-qa-product-tun-apply.json /run/sc-qa-product-tun-conflict.json
    echo PRODUCT_TUN_IPV6_GUARD_ROLLBACK=PASS
    return 0
  fi

  # First: live normal product Apply and actual synthetic foreign/domestic
  # packet paths. Do not mistake TUN device creation for installed policy.
  if ! apply 32 > /run/sc-qa-product-tun-apply.json; then
    python3 - <<'PYAPPLYFAIL'
import json
with open('/run/sc-qa-product-tun-apply.json') as f:
    result=json.load(f)
assert not result.get("ok"),result
err=result.get("error") or {}
print("PRODUCT_TUN_APPLY_REFUSED="+str(err.get("code","unknown"))+": "+str(err.get("message","unspecified")))
PYAPPLYFAIL
    return 1
  fi
  python3 - <<'PYAPPLIED'
import json,re
with open('/run/sc-qa-product-tun-apply.json') as handle:r=json.load(handle)
assert r["ok"] and r["data"]["phase"]=="trial_pending" and r["data"]["guard_scheduled"],r
assert not r["data"]["activation_ready"] and not r["data"]["vpn_verified"],r
assert re.fullmatch("[0-9a-f]{32}",r["data"]["operation_id"]),r
PYAPPLIED
  op=$(pending_receipt)
  echo PRODUCT_TUN_GUARD_PREARMED_AND_PENDING=PASS
  if "$sc" --json connect >/run/sc-qa-product-tun-conflict.json 2>&1; then
    echo 'Product allowed Proxy Only while guarded TUN was pending' >&2;return 1
  fi
  python3 - <<'PYCONFLICT'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r["ok"] and r["error"]["code"]=="guard_pending",r
PYCONFLICT
  if "$sc" --json status >/run/sc-qa-product-tun-conflict.json 2>&1; then
    echo 'Product status incorrectly claimed Direct while TUN pending' >&2;return 1
  fi
  python3 - <<'PYSTATUS'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r["ok"] and r["error"]["code"]=="guard_pending",r
assert r["data"]["observed"]=="smart_tun_trial_pending",r
PYSTATUS
  echo PRODUCT_TUN_DIRECT_FALSE_STATUS_AND_PROXY_CONFLICT_REFUSED=PASS

  ready=no
  for n in $(seq 1 35); do
    if assert_product_tun_policy_active &&
       expect_source 5.22.0.10 10.254.72.1 &&
       expect_source 8.8.8.8 8.8.8.8; then
      ready=yes
      break
    fi
    sleep 0.2
  done
  [ "$ready" = yes ] || {
    echo 'PRODUCT_TUN_SELECTED_PATH=FAIL' >&2
    systemctl status server-connect-smart-tun.service --no-pager >&2 || :
    return 1
  }
  echo PRODUCT_TUN_INSTALLED_REAL_TCP_DIRECT_AND_VLESS=PASS
  udp_path 8.8.8.8 8.8.8.8 product-foreign-udp reply
  dns_path 8.8.8.8 192.0.2.22 product-foreign-dns udp reply
  expect_foreign_hosted_reply
  echo PRODUCT_TUN_INSTALLED_UDP_DNS_AND_FOREIGN_HOSTING=PASS

  # The actual packaged product TUN must also carry application traffic
  # without HTTP_PROXY, wrappers, PID attribution or cgroup steering.
  # Existing independent origin and nftables witnesses MUST record no
  # foreign Direct bypass, rather than merely trusting command exit status.
  assert_product_tun_policy_active
  native_apps selected
  [ "$(native_app_direct_packets)" -eq "$native_apps_baseline" ] || {
    echo 'PRODUCT_TUN_NATIVE_APPS=FAIL (APT/Git escaped native Direct)' >&2
    return 1
  }
  wp_probe positive 8.8.8.8
  [ "$(native_app_direct_packets)" -eq "$native_apps_baseline" ] || {
    echo 'PRODUCT_TUN_WORDPRESS=FAIL (proxy-unaware PHP escaped native Direct)' >&2
    return 1
  }
  [ "$(without_proxy http://8.8.8.8:19180/wget)" = 'SOURCE=8.8.8.8' ]
  assert_product_tun_policy_active
  echo PRODUCT_TUN_INSTALLED_APT_GIT_WORDPRESS=PASS
  require_recovered "$op"
  echo PRODUCT_TUN_SYSTEMD_DEADLINE_EXACT_BASELINE=PASS
  # Exercise Clear's cleanup path too, not only explicit Disconnect. A
  # persisted cleanup intent distinguishes this legitimate credential
  # removal from the tampered pending-credential negative case below.
  executor_before=$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)
  killed=0
  "$sc" --json smart-tun-trial-clear --operation-id "$op" --revision 2 \
    --qa-kill-at after-credential-remove >/dev/null 2>&1 || killed=$?
  [ "$killed" = 137 ]
  require_independent_finalization
  echo PRODUCT_TUN_CLEAR_SIGKILL_INDEPENDENT_FINALIZATION=PASS
  rm -f /run/sc-qa-product-tun-apply.json /run/sc-qa-product-tun-conflict.json
  echo PRODUCT_TUN_RECOVERED_CLEARED_DIRECT=PASS

  # Second: kill ONLY the initiating manager after a real systemd core
  # launch. The independent installed oneshot, not this shell, must recover.
  killed=0
  apply 12 --qa-kill-at after-start >/dev/null 2>&1 || killed=$?
  [ "$killed" = 137 ] || {
    echo "Product TUN controller did not die at post-start boundary: $killed" >&2;return 1
  }
  op=$(pending_receipt)
  [ -e /sys/class/net/sctunqa0 ] || {
    # A core that was just exec'd may take a moment to create the TUN;
    # do not construe this as an authorization to reapply or bypass.
    sleep 1
  }
  [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = active ]
  echo PRODUCT_TUN_CONTROLLER_SIGKILL_INDEPENDENT_PENDING=PASS
  require_recovered "$op"
  clear_recovered "$op"
  echo PRODUCT_TUN_SIGKILL_INDEPENDENT_SYSTEMD_ROLLBACK=PASS

  # Journal-first crash: the core and TUN were NEVER started. A fresh
  # systemd executor must still expire the exact operation, prove unchanged
  # routes/rules/firewall and permit cleaning an absent credential.
  killed=0
  apply 10 --qa-kill-at after-journal >/dev/null 2>&1 || killed=$?
  [ "$killed" = 137 ] || {
    echo "Product TUN controller did not die after journal: $killed" >&2;return 1
  }
  # No credential and no systemd TUN start: the independent executor may
  # already have reconciled the journal by the time this shell inspects it.
  # A *fresh* trial_recovered revision 2 is a valid (safer) observation;
  # requiring the intermediate pending state would turn prompt rollback
  # into a false failure. The exact operation ID, verified kernel baseline
  # and independent systemd completion are still checked below.
  op=$("$sc" --json smart-tun-trial-status | python3 -c '
import json,sys,re
r=json.load(sys.stdin)
assert r["ok"],r
d=r["data"]
assert d["experiment_only"] and not d["activation_ready"] and not d["vpn_verified"],d
assert re.fullmatch("[0-9a-f]{32}",d["operation_id"]),d
if d["phase"] == "trial_pending":
    assert d["revision"]==1 and d["guard_scheduled"] and not d["recovery_verified"],d
else:
    assert d["phase"]=="trial_recovered" and d["revision"]==2,d
    assert not d["guard_scheduled"] and d["recovery_verified"],d
print(d["operation_id"])')
  [ ! -e /var/lib/server-connect/smart-tun-trial.json ]
  [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive ]
  require_recovered "$op"
  clear_recovered "$op"
  echo PRODUCT_TUN_PRE_CREDENTIAL_SIGKILL_INDEPENDENT_ROLLBACK=PASS

  # If the independently prearmed timer is lost, even a healthy
  # product-owned TUN with a future deadline must be stopped on explicit
  # installed recovery. The pending receipt must not claim a live guard.
  apply 60 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  assert_product_tun_policy_active
  systemctl is-active --quiet server-connect-activation-recover.timer
  test "$(systemctl is-enabled server-connect-activation-recover.timer)" = enabled
  systemctl disable --now server-connect-activation-recover.timer
  test "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled
  test "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive
  assert_product_tun_policy_active
  python3 - "$op" <<'PYDEADLINE'
import json,sys
with open('/var/lib/server-connect/route-activation-journal.json') as f:r=json.load(f)
with open('/proc/uptime') as f:uptime=int(float(f.read().split()[0]))
assert r['operation_id']==sys.argv[1] and r['core_start_attempted'] is True,r
assert r['phase']=='trial_pending' and r['deadline_uptime_sec']>uptime+5,(r,uptime)
PYDEADLINE
  if "$sc" --json smart-tun-trial-status >/run/sc-qa-product-tun-conflict.json; then
    echo 'Disabled independent timer incorrectly reported an armed TUN guard' >&2;return 1
  fi
  python3 - <<'PYGUARDLOST'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_unavailable',r
PYGUARDLOST
  "$sc" --json activation-trial-recover >/run/sc-qa-product-tun-recover.json
  python3 - "$op" <<'PYCONTAINED'
import json,sys
with open('/run/sc-qa-product-tun-recover.json') as f:r=json.load(f)
d=r['data']
assert r['ok'] and d['operation_id']==sys.argv[1],r
assert d['phase']=='trial_recovered' and d['revision']==2,d
assert d['experiment_only'] and d['recovery_verified'] and not d['guard_scheduled'],d
assert not d['activation_ready'] and not d['vpn_verified'],d
PYCONTAINED
  test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
  test ! -e /sys/class/net/sctunqa0
  test "$(ip -N -j -4 route show table all)" = "$before_routes"
  test "$(ip -N -j -4 rule show)" = "$before_rules"
  test "$(ip -N -j -6 route show table all)" = "$before_v6_routes"
  test "$(ip -N -j -6 rule show)" = "$before_v6_rules"
  test "$(nft -j list ruleset)" = "$before_nft"
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  echo PRODUCT_TUN_GUARD_TIMER_LOSS_IMMEDIATE_CONTAINMENT=PASS
  clear_recovered "$op"

  # Separate executor-loss test: a guest-owned *runtime* mask and a
  # synthetic foreign nftables owner. The Manager must stop its TUN even
  # when the executor cannot run, but it must retain the pending journal
  # and not delete a foreign table or falsely claim exact recovery.
  apply 60 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  assert_product_tun_policy_active
  systemctl mask --runtime server-connect-activation-recover.service
  test "$(readlink /run/systemd/system/server-connect-activation-recover.service)" = /dev/null
  assert_product_tun_policy_active
  if "$sc" --json smart-tun-trial-status >/run/sc-qa-product-tun-conflict.json; then
    echo 'Masked executor incorrectly reported an armed TUN guard' >&2;return 1
  fi
  python3 - <<'PYEXECUTORLOST'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_unavailable',r
PYEXECUTORLOST
  nft add table inet scqa_guardloss_foreign
  foreign_table=$(nft -j list table inet scqa_guardloss_foreign)
  if "$sc" --json activation-trial-recover > /run/sc-qa-product-tun-conflict.json; then
    echo 'Foreign nftables conflict incorrectly reported recovered after executor loss' >&2;return 1
  fi
  python3 - "$op" <<'PYUNRESOLVED'
import json,sys
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_recovery_uncertain',r
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['revision']==1,j
assert j['phase']=='trial_pending' and j['core_start_attempted'] is True,j
PYUNRESOLVED
  test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
  test ! -e /sys/class/net/sctunqa0
  test "$(nft -j list table inet scqa_guardloss_foreign)" = "$foreign_table"
  test "$(ip -N -j -4 route show table all)" = "$before_routes"
  test "$(ip -N -j -4 rule show)" = "$before_rules"
  test "$(ip -N -j -6 route show table all)" = "$before_v6_routes"
  test "$(ip -N -j -6 rule show)" = "$before_v6_rules"
  if "$sc" --json status >/run/sc-qa-product-tun-conflict.json; then
    echo 'Unresolved guard/executor conflict incorrectly claimed Direct' >&2;return 1
  fi
  python3 - <<'PYUNRESOLVEDSTATUS'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_pending',r
assert r['data']['observed']=='smart_tun_trial_pending',r
PYUNRESOLVEDSTATUS
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  echo PRODUCT_TUN_GUARD_EXECUTOR_LOSS_FOREIGN_CONFLICT_RETAINED=PASS
  # Only the QA fixture, not product recovery, may remove its own table.
  nft delete table inet scqa_guardloss_foreign
  test "$(nft -j list ruleset)" = "$before_nft"
  "$sc" --json activation-trial-recover >/run/sc-qa-product-tun-recover.json
  python3 - "$op" <<'PYRESOLVED'
import json,sys
with open('/run/sc-qa-product-tun-recover.json') as f:r=json.load(f)
d=r['data']
assert r['ok'] and d['operation_id']==sys.argv[1],r
assert d['phase']=='trial_recovered' and d['revision']==2,d
assert d['recovery_verified'] and not d['guard_scheduled'],d
PYRESOLVED
  systemctl unmask --runtime server-connect-activation-recover.service
  test ! -e /run/systemd/system/server-connect-activation-recover.service
  test ! -L /run/systemd/system/server-connect-activation-recover.service
  # The timer may have recorded a failed oneshot while its runtime name
  # was conflicted. Restore and actually exercise the original installed
  # executor before permitting the next unrelated guest-only operation.
  systemctl reset-failed server-connect-activation-recover.service
  systemctl start server-connect-activation-recover.service
  test "$(systemctl show server-connect-activation-recover.service -p Result --value)" = success
  systemctl is-active --quiet server-connect-activation-recover.timer
  clear_recovered "$op"
  rm -f /run/sc-qa-product-tun-recover.json
  echo PRODUCT_TUN_GUARD_EXECUTOR_LOSS_GUEST_CLEANUP=PASS

  # Negative path: the manager DID durably attempt to start the core.
  # Removing its source credential must never be accepted as the benign
  # "crash before credential" case, even after systemd has stopped the
  # core and the native kernel baseline has returned to Direct.
  apply 30 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  credential=/var/lib/server-connect/smart-tun-trial.json
  saved=/run/sc-qa-product-tun-credential.saved
  test -f "$credential" && test ! -e "$saved"
  python3 - "$op" <<'PYSTARTED'
import json,sys
with open('/var/lib/server-connect/route-activation-journal.json') as f:r=json.load(f)
assert r['operation_id']==sys.argv[1] and r['phase']=='trial_pending',r
assert r['core_start_attempted'] is True,r
PYSTARTED
  mv -- "$credential" "$saved"
  test ! -e "$credential"
  # The installed independent recovery executor must stop the owned unit
  # and refuse to clear the operation until its exact credential returns.
  conflict=no
  for n in $(seq 1 30); do
    if [ "$(systemctl show server-connect-activation-recover.service -p Result --value)" = exit-code ] &&
       [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive ] &&
       [ ! -e /sys/class/net/sctunqa0 ]; then
      conflict=yes
      break
    fi
    sleep 1
  done
  [ "$conflict" = yes ] || {
    echo 'PRODUCT_TUN_CREDENTIAL_CONFLICT=FAIL (watchdog did not stop TUN)' >&2
    return 1
  }
  [ "$(ip -N -j -4 route show table all)" = "$before_routes" ]
  [ "$(ip -N -j -4 rule show)" = "$before_rules" ]
  [ "$(ip -N -j -6 route show table all)" = "$before_v6_routes" ]
  [ "$(ip -N -j -6 rule show)" = "$before_v6_rules" ]
  [ "$(nft -j list ruleset)" = "$before_nft" ]
  # A second independent invocation must still refuse a false success
  # after the first one changed the service state to inactive.
  for n in 1 2; do
    if "$sc" --json activation-trial-recover >/run/sc-qa-product-tun-conflict.json; then
      echo 'Missing credential was silently accepted on repeated recovery' >&2
      return 1
    fi
    python3 - "$op" <<'PYMISSING'
import json,sys
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['revision']==1,r
assert j['phase']=='trial_pending' and j['core_start_attempted'] is True,j
PYMISSING
  done
  echo PRODUCT_TUN_CREDENTIAL_REMOVAL_PERSISTENT_CONFLICT=PASS

  # Explicit isolated operator intervention supplies the original bytes;
  # only a *freshly executed* independent recovery unit may then confirm
  # the unchanged kernel baseline and permit exact operation clearance.
  mv -- "$saved" "$credential"
  systemctl reset-failed server-connect-activation-recover.service
  systemctl start server-connect-activation-recover.service
  require_recovered "$op"
  # Once the kernel is clean and the journal is recovered, a second
  # credential tamper must not disable its last independent timer BEFORE
  # rejecting an exact operation/revision clearance. This specifically
  # catches partial-success cleanup with the wrong ordering.
  mv -- "$credential" "$saved"
  if "$sc" --json smart-tun-trial-clear --operation-id "$op" --revision 2 > /run/sc-qa-product-tun-conflict.json; then
    echo 'Tampered recovered credential was wrongly cleared' >&2; return 1
  fi
  python3 - <<'PYCLEARREFUSED'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
PYCLEARREFUSED
  systemctl is-active --quiet server-connect-activation-recover.timer
  [ "$(systemctl is-enabled server-connect-activation-recover.timer)" = enabled ]
  [ -f /var/lib/server-connect/route-activation-journal.json ]
  echo PRODUCT_TUN_CLEAR_CONFLICT_GUARD_STAYS_ARMED=PASS
  mv -- "$saved" "$credential"
  clear_recovered "$op"
  rm -f /run/sc-qa-product-tun-apply.json /run/sc-qa-product-tun-conflict.json
  echo PRODUCT_TUN_CREDENTIAL_CONFLICT_RECONCILED=PASS

  # The practical off/on path: immediate explicit deactivation rather
  # than waiting for the pending deadline, while retaining operator state.
  apply 60 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  require_selected_ready
  capture_saved_policy
  reject_disconnect_unchanged 00000000000000000000000000000000 1
  reject_disconnect_unchanged "$op" 2
  previous_op=$op
  direct_before_off=$(direct_witness_packets)
  disconnect_now "$op" 1
  expect_source 8.8.8.8 10.254.72.1
  udp_path 8.8.8.8 10.254.72.1 product-off-native-udp reply
  test "$(direct_witness_packets)" -gt "$direct_before_off"
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  echo PRODUCT_TUN_EXPLICIT_OFF_EXACT_BASELINE=PASS

  # Reject corrupt saved inputs before prearming or touching the network.
  # Preserve the evidence bytes until this QA owner restores its backup.
  policy=/var/lib/server-connect/smart-tun-policy.json
  policy_backup=/run/sc-qa-product-tun-policy.saved
  test ! -e "$policy_backup"
  cp -- "$policy" "$policy_backup"
  python3 - "$policy" <<'PYCORRUPTPOLICY'
import json,sys
with open(sys.argv[1]) as f:policy=json.load(f)
policy['unrecognized_qa_key']=True
with open(sys.argv[1],'w') as f:json.dump(policy,f)
PYCORRUPTPOLICY
  corrupt_policy_hash=$(sha256sum "$policy")
  invalid_policy_units=$(systemctl show server-connect-activation-recover.timer \
    server-connect-activation-recover.service server-connect-smart-tun.service \
    -p ActiveEnterTimestampMonotonic -p InactiveEnterTimestampMonotonic -p ExecMainStartTimestampMonotonic)
  if "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 >/run/sc-qa-product-tun-conflict.json; then
    echo 'Saved policy with unknown schema key was accepted' >&2; return 1
  fi
  python3 - <<'PYINVALIDPOLICY'
import json
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='saved_policy_invalid',r
PYINVALIDPOLICY
  require_finalized
  test "$(sha256sum "$policy")" = "$corrupt_policy_hash"
  test "$(systemctl show server-connect-activation-recover.timer \
    server-connect-activation-recover.service server-connect-smart-tun.service \
    -p ActiveEnterTimestampMonotonic -p InactiveEnterTimestampMonotonic -p ExecMainStartTimestampMonotonic)" = "$invalid_policy_units"
  mv -- "$policy_backup" "$policy"
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  echo PRODUCT_TUN_INVALID_SAVED_POLICY_NO_PREARM=PASS

  "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  test "$op" != "$previous_op"
  require_selected_ready
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  # Replay a real previous operation identity against the new operation,
  # then mismatch only its revision; neither may interrupt the new TUN.
  reject_disconnect_unchanged "$previous_op" 1
  reject_disconnect_unchanged "$op" 2
  echo PRODUCT_TUN_STALE_DISCONNECT_NO_MUTATION=PASS
  echo PRODUCT_TUN_SAVED_REAPPLY_NEW_OPERATION=PASS

  # Another network owner appearing after Apply is retained, even though
  # this product can stop its own TUN. Cleanup resumes only after the QA
  # owner removes its exact fixture; no broad nftables reset is allowed.
  nft add table inet scqa_disconnect_foreign
  foreign_table=$(nft -j list table inet scqa_disconnect_foreign)
  executor_before=$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)
  if "$sc" --json smart-tun-trial-disconnect --operation-id "$op" --revision 1 >/run/sc-qa-product-tun-conflict.json; then
    echo 'Disconnect ignored foreign native policy drift' >&2; return 1
  fi
  python3 - "$op" <<'PYOFFCONFLICT'
import json,sys
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_recovery_uncertain',r
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['phase']=='trial_stop_requested' and j['revision']==2,j
PYOFFCONFLICT
  test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
  test ! -e /sys/class/net/sctunqa0
  test -f /var/lib/server-connect/smart-tun-trial.json
  test "$(nft -j list table inet scqa_disconnect_foreign)" = "$foreign_table"
  systemctl is-active --quiet server-connect-activation-recover.timer
  if "$sc" --json status >/run/sc-qa-product-tun-conflict.json; then
    echo 'Unresolved explicit Off incorrectly reported verified Direct' >&2; return 1
  fi
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  nft delete table inet scqa_disconnect_foreign
  require_independent_finalization
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  echo PRODUCT_TUN_OFF_FOREIGN_CONFLICT_RETAINED=PASS

  # An untrusted special-file credential must not block inspection or
  # prevent containment of the independently identified product TUN.
  # Preserve that foreign file and the operation instead of claiming Off.
  "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  require_selected_ready
  credential=/var/lib/server-connect/smart-tun-trial.json
  saved=/run/sc-qa-product-tun-credential.saved
  test -f "$credential" && test ! -e "$saved"
  mv -- "$credential" "$saved"
  mkfifo -m 600 "$credential"
  foreign_fifo=$(stat -c '%d:%i:%f' "$credential")
  fifo_rc=0
  timeout --signal=KILL 15 "$sc" --json smart-tun-trial-disconnect \
    --operation-id "$op" --revision 1 >/run/sc-qa-product-tun-conflict.json || fifo_rc=$?
  test "$fifo_rc" -ne 0 && test "$fifo_rc" -ne 124 && test "$fifo_rc" -ne 137
  python3 - "$op" <<'PYFIFOCONFLICT'
import json,sys
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['phase']=='trial_stop_requested' and j['revision']==2,j
PYFIFOCONFLICT
  require_native_baseline
  test -p "$credential"
  test "$(stat -c '%d:%i:%f' "$credential")" = "$foreign_fifo"
  systemctl is-active --quiet server-connect-activation-recover.timer
  if "$sc" --json status >/run/sc-qa-product-tun-conflict.json; then
    echo 'Credential FIFO conflict incorrectly reported verified Direct' >&2; return 1
  fi
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  executor_before=$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)
  # Only the QA owner may remove the exact FIFO it created and restore
  # the original credential bytes; product recovery never adopts it.
  rm -- "$credential"
  mv -- "$saved" "$credential"
  require_independent_finalization
  echo PRODUCT_TUN_OFF_FIFO_CONTAINMENT_RETAINED=PASS

  # Bounded crash cuts in the shared stop/finalization transaction. The
  # CLI really dies with SIGKILL, and only a fresh independent executor
  # invocation may remove the journal/credential and restore native paths.
  for kill_point in after-stop-request after-stop after-cleanup-intent after-credential-remove; do
    "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 >/run/sc-qa-product-tun-apply.json
    op=$(pending_receipt)
    require_selected_ready
    executor_before=$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)
    killed=0
    "$sc" --json smart-tun-trial-disconnect --operation-id "$op" --revision 1 \
      --qa-kill-at "$kill_point" >/dev/null 2>&1 || killed=$?
    test "$killed" = 137
    require_independent_finalization
    test "$(saved_policy_hashes)" = "$saved_policy_before"
    expect_source 8.8.8.8 10.254.72.1
    echo "PRODUCT_TUN_OFF_KILL_BOUNDARY($kill_point)=PASS"
  done
  echo PRODUCT_TUN_OFF_SIGKILL_INDEPENDENT_FINALIZATION=PASS

  # A crash after timer disarm is already network-safe but can retain its
  # cleanup receipt. A queued executor may finish it; otherwise the exact
  # operation/revision retry is explicit and is not called autonomous QA.
  "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 >/run/sc-qa-product-tun-apply.json
  op=$(pending_receipt)
  require_selected_ready
  executor_before=$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)
  killed=0
  "$sc" --json smart-tun-trial-disconnect --operation-id "$op" --revision 1 \
    --qa-kill-at after-guard-disarm >/dev/null 2>&1 || killed=$?
  test "$killed" = 137
  require_native_baseline
  test ! -e /var/lib/server-connect/smart-tun-trial.json
  test "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive
  # Wait for any invocation already queued by the timer before deciding
  # whether an exact retry is needed. Do not race its journal unlink.
  for idle_try in $(seq 1 50); do
    if [ "$(systemctl show server-connect-activation-recover.service -p ActiveState --value)" = inactive ]; then
      executor_job=$(systemctl show server-connect-activation-recover.service -p Job --value)
      case "$executor_job" in ''|0) break;; esac
    fi
    sleep 0.1
  done
  test "$(systemctl show server-connect-activation-recover.service -p ActiveState --value)" = inactive
  executor_job=$(systemctl show server-connect-activation-recover.service -p Job --value)
  case "$executor_job" in ''|0) :;; *) echo 'Recovery executor still has a queued job' >&2; return 1;; esac
  if [ -e /var/lib/server-connect/route-activation-journal.json ]; then
    python3 - "$op" <<'PYDISARMED'
import json,sys
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['phase']=='trial_cleanup_pending' and j['revision']==4,j
PYDISARMED
    disconnect_now "$op" 4
    echo PRODUCT_TUN_POST_DISARM_COMPLETION=explicit-exact-operation-retry
  else
    require_independent_finalization
    echo PRODUCT_TUN_POST_DISARM_COMPLETION=already-queued-independent-executor
  fi
  require_finalized
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  expect_source 8.8.8.8 10.254.72.1
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  rm -f /run/sc-qa-product-tun-apply.json /run/sc-qa-product-tun-conflict.json
  echo PRODUCT_TUN_OFF_POST_DISARM_RECONCILIATION=PASS
}
