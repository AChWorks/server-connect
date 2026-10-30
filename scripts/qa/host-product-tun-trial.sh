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
    if assert_tun_policy_active &&
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
  require_recovered "$op"
  echo PRODUCT_TUN_SYSTEMD_DEADLINE_EXACT_BASELINE=PASS
  clear_recovered "$op"
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
  op=$(pending_receipt)
  [ ! -e /var/lib/server-connect/smart-tun-trial.json ]
  [ "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive ]
  require_recovered "$op"
  clear_recovered "$op"
  echo PRODUCT_TUN_PRE_CREDENTIAL_SIGKILL_INDEPENDENT_ROLLBACK=PASS
}
