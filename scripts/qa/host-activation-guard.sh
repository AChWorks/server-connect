#!/bin/sh
# QA-only feasibility proof for an independent systemd deadline rollback.
# Runs exclusively inside the disposable Docker --network none systemd guest.
# THIS IS NOT a production Activation Guard or an operator-facing route applier.
set -eu
umask 077

ip=/usr/bin/ip
state=/run/sc-qa-activation-guard
service=sc-qa-activation-rollback.service
timer=sc-qa-activation-rollback.timer
inspect=/root/qa-activation-guard-inspect.py

require_disposable_guest() {
  test "$(id -u)" -eq 0
  test "$(ps -p 1 -o comm=)" = systemd
  test -f /.dockerenv
  test -f /root/qa-host-assertions.sh
  test -f /root/qa-activation-guard.sh
  test -f "$inspect"
  test -x "$ip"
  test -x /usr/bin/python3
  # The parent GitHub Actions harness additionally asserts Docker networking
  # mode=none and independently compares all guest links/routes/rules.
}

verify_kernel() {
  /usr/bin/python3 -I -B "$inspect" "$1"
}

# systemd *Monotonic properties are microseconds since CLOCK_MONOTONIC boot.
# A fresh execution must start strictly AFTER both timer activation and the
# independent test actor's foreign-resource injection. A previous unit's
# retained Result/ExecMainStatus cannot prove that chronology.
monotonic_us() {
  /usr/bin/python3 -I -B -c '
import time
print(time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000)'
}

unsigned_us() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  test "$1" -gt 0
}

require_state() {
  test -d "$state"
  test "$(stat -c '%a' "$state")" = 700
  test "$(cat "$state/identity")" = sc-qa-activation-guard-v1
}

arm() {
  # No existing foreign or product-owned kernel object can be adopted.
  test "$(ls -1 /sys/class/net)" = lo
  test -z "$(/usr/bin/ip -6 route show default)"
  test ! -e "$state" && test ! -L "$state"
  test ! -e "/run/systemd/system/$service"
  test ! -e "/run/systemd/system/$timer"
  verify_kernel preflight
  mkdir -m 0700 "$state"
  printf 'sc-qa-activation-guard-v1\n' > "$state/identity"
  chmod 0600 "$state/identity"
  # Both units live in the DISPOSABLE guest's /run. This proves an in-boot
  # independent deadline, not a durable reboot/power-loss recovery design.
  cat > "/run/systemd/system/$service" <<'UNIT'
[Unit]
Description=Disposable QA-only independent activation rollback
[Service]
Type=oneshot
TimeoutStartSec=15s
ExecStart=/bin/sh /root/qa-activation-guard.sh rollback
UNIT
  cat > "/run/systemd/system/$timer" <<'UNIT'
[Unit]
Description=Disposable QA-only activation rollback deadline
[Timer]
OnActiveSec=8s
AccuracySec=100ms
Unit=sc-qa-activation-rollback.service
UNIT
  chmod 0644 "/run/systemd/system/$service" "/run/systemd/system/$timer"
  systemctl daemon-reload
  # systemd preserves failures for stopped/reloaded oneshot units. The
  # previous negative cycle MUST NOT let a new cycle inherit its success
  # criterion. Reset the exact QA service before arming the new deadline.
  previous_result=$(systemctl show "$service" -p Result --value)
  case "$previous_result" in
    exit-code)
      # Only a CACHED failed unit can be reset: attempting reset-failed on
      # the never-loaded first-cycle service fails on Debian 13 systemd.
      # A new unit with no prior result has nothing to invalidate.
      echo 'ISOLATED_ACTIVATION_GUARD_PREVIOUS_FAILURE=OBSERVED (will invalidate)'
      systemctl reset-failed "$service"
      ;;
    success|'') ;;
    *) echo 'Unexpected previous QA service result' >&2; return 1 ;;
  esac
  case "$(systemctl show "$service" -p ActiveState --value)" in
    inactive|'') ;;
    *) echo 'QA guard service was not inactive before arming' >&2; return 1 ;;
  esac
  case "$(systemctl show "$service" -p Result --value)" in
    success|'') ;;
    *) echo 'Stale QA service failure survived prearm cleanup' >&2; return 1 ;;
  esac
  previous_start=$(systemctl show "$service" -p ExecMainStartTimestampMonotonic --value)
  # For a newly defined or unloaded (including reset-failed) unit,
  # systemd may omit previous execution data. No stale execution is trusted:
  # every accepted invocation must start after the NEW timer arm/injection.
  case "$previous_start" in
    '') previous_start=0 ;;
    *[!0-9]*) echo 'Invalid previous service timestamp' >&2; return 1 ;;
  esac
  printf '%s\n' "$previous_start" > "$state/previous-start-us"
  test ! -e "$state/refusal-proof"
  test ! -e "$state/injected-us"
  systemctl start "$timer"
  systemctl is-active --quiet "$timer"
  test "$(systemctl show "$timer" -p Unit --value)" = "$service"
  armed=$(systemctl show "$timer" -p ActiveEnterTimestampMonotonic --value)
  unsigned_us "$armed"
  test "$armed" -gt "$previous_start"
  printf '%s\n' "$armed" > "$state/armed-us"
  echo 'ISOLATED_ACTIVATION_GUARD_PREARM=PASS (fresh systemd timer; old failure invalidated)'
}

crash_controller() {
  require_state
  test "$#" -eq 1
  stage=$1
  case "$stage" in link|route|rule) ;; *) return 2 ;; esac
  systemctl is-active --quiet "$timer"
  test ! -e "$state/rollback-proof"
  verify_kernel preflight

  # Add independent foreign policy first, then perform each owned mutation.
  # Its resources occupy the SAME table but must survive the watchdog.
  "$ip" link add scqaf0 type dummy
  "$ip" link set dev scqaf0 alias sc-qa-guard-foreign-v1
  "$ip" link set dev scqaf0 address 02:53:43:00:00:02
  "$ip" link set dev scqaf0 addrgenmode none
  "$ip" link set dev scqaf0 up
  "$ip" -4 route add 9.9.9.0/24 dev scqaf0 table 20120
  "$ip" -4 rule add pref 30801 to 9.9.9.0/24 table 20120
  verify_kernel recovered

  # Stage 1: link exists, but own route/rule are absent.
  "$ip" link add scqao0 type dummy
  "$ip" link set dev scqao0 alias sc-qa-guard-owned-v1
  "$ip" link set dev scqao0 address 02:53:43:00:00:01
  "$ip" link set dev scqao0 addrgenmode none
  "$ip" link set dev scqao0 up
  verify_kernel partial_link
  if test "$stage" = link; then kill_controller; fi

  # Stage 2: route exists, but own RPDB rule remains absent.
  "$ip" -4 route add 8.8.8.0/24 dev scqao0 table 20120
  verify_kernel partial_route
  if test "$stage" = route; then kill_controller; fi

  # Stage 3: owned route and RPDB rule are both present.
  "$ip" -4 rule add pref 30800 to 8.8.8.0/24 table 20120
  verify_kernel applied
  kill_controller
}

kill_controller() {
  test "$(cat "$state/identity")" = sc-qa-activation-guard-v1
  # No stage marker or post-mutation on-disk state is written by the
  # controller: an actual crash can happen before either write. The
  # watchdog must infer owned progress from current native kernel evidence.
  echo "ISOLATED_ACTIVATION_CONTROLLER_BOUNDARY=$stage"
  kill -KILL "$$"
  echo 'UNREACHABLE_CONTROLLERS_MUST_NOT_SUCCEED' >&2
  exit 1
}

rollback() {
  require_state
  test ! -e "$state/controller-marker"
  test ! -e "$state/rollback-proof"
  # Require a unique, strictly validated native state BEFORE any deletion.
  # Do not trust the crashed controller's marker to select cleanup commands.
  # This remains a fixed disposable fixture, not race-free host ownership.
  if rollback_stage=$(verify_kernel classify); then
    :
  else
    # This marker is written ONLY by the independent systemd service after
    # the native classifier actually refuses the current kernel fixture.
    # It is never a controller stage marker or permission to delete.
    case "${INVOCATION_ID-}" in
      ????????????????????????????????) ;;
      *) echo 'Missing systemd service invocation identity' >&2; return 26 ;;
    esac
    printf 'native-classifier-refused:%s\n' "$INVOCATION_ID" > "$state/refusal-proof"
    echo 'ISOLATED_ACTIVATION_GUARD_NATIVE_CLASSIFIER_REFUSED' >&2
    return 24
  fi
  case "$rollback_stage" in
    applied)
      "$ip" -4 rule del pref 30800 to 8.8.8.0/24 table 20120
      ;;
    partial_route|partial_link) ;;
    *) echo 'Invalid native rollback stage' >&2; return 1 ;;
  esac
  case "$rollback_stage" in
    applied|partial_route)
      "$ip" -4 route del 8.8.8.0/24 dev scqao0 table 20120
      ;;
  esac
  "$ip" link del dev scqao0
  verify_kernel recovered
  printf 'independent-deadline-rollback-complete:%s\n' "$rollback_stage" > "$state/rollback-proof"
  echo "ISOLATED_ACTIVATION_GUARD_ROLLBACK=PASS (stage=$rollback_stage)"
}

await_recovery() {
  require_state
  test "$#" -eq 1
  stage=$1
  case "$stage" in link|route|rule) ;; *) return 2 ;; esac
  test ! -e "$state/controller-marker"
  attempt=0
  while test "$attempt" -lt 20; do
    if test -f "$state/rollback-proof"; then break; fi
    sleep 1
    attempt=$((attempt + 1))
  done
  expected_stage=$stage
  case "$stage" in link) expected_stage=partial_link ;; route) expected_stage=partial_route ;; rule) expected_stage=applied ;; esac
  if test "$(cat "$state/rollback-proof" 2>/dev/null || true)" != "independent-deadline-rollback-complete:$expected_stage" ||
     test "$(systemctl show "$service" -p Result --value)" != success; then
    echo 'ISOLATED_ACTIVATION_GUARD=FAIL (independent stage rollback did not complete)' >&2
    systemctl show "$service" "$timer" --no-pager \
      --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus >&2 || true
    journalctl --no-pager --output=cat -n 20 -u "$service" >&2 || true
    return 1
  fi
  verify_kernel recovered
  echo "ISOLATED_ACTIVATION_GUARD_TIMEOUT_SIGKILL=PASS (stage=$stage)"
  echo "ISOLATED_ACTIVATION_GUARD_FOREIGN_POLICY_PRESERVED=PASS (stage=$stage)"
}

# Explicit negative fixture: a separate test actor modifies the link after
# the controller is SIGKILLed, but before the independent timer expires.
# The watchdog must fail closed and leave the foreign resource observable.
inject_conflict() {
  require_state
  test "$#" -eq 1
  verify_kernel partial_link
  case "$1" in
    address)
      "$ip" -4 addr add 192.0.2.77/32 dev scqao0
      ;;
    other-table-route)
      "$ip" -4 route add 203.0.113.0/24 dev scqao0 table 20121
      ;;
    altname)
      "$ip" link property add dev scqao0 altname qa-foreign-added
      ;;
    *) return 2 ;;
  esac
  if verify_kernel classify >/dev/null 2>&1; then
    echo 'Unexpected foreign dependency was authorized for deletion' >&2
    return 1
  fi
  test ! -e "$state/injected-us"
  injected=$(monotonic_us)
  unsigned_us "$injected"
  test "$injected" -gt "$(cat "$state/armed-us")"
  printf '%s\n' "$injected" > "$state/injected-us"
  echo "ISOLATED_ACTIVATION_GUARD_CONFLICT_INJECTED=$1"
}

assert_conflict_present() {
  case "$1" in
    address)
      "$ip" -4 -j addr show dev scqao0 | /usr/bin/python3 -c '
import json,sys
rows=json.load(sys.stdin)
assert any(item.get("local")=="192.0.2.77" and item.get("prefixlen")==32
           for row in rows for item in row.get("addr_info", []))'
      ;;
    other-table-route)
      "$ip" -4 -j route show table 20121 | /usr/bin/python3 -c '
import json,sys
rows=json.load(sys.stdin)
assert len(rows)==1 and rows[0].get("dst")=="203.0.113.0/24" and rows[0].get("dev")=="scqao0"'
      ;;
    altname)
      "$ip" -j -d link show dev scqao0 | /usr/bin/python3 -c '
import json,sys
rows=json.load(sys.stdin)
assert len(rows)==1 and rows[0].get("ifname")=="scqao0"
assert rows[0].get("altnames")==["qa-foreign-added"]'
      ;;
    *) return 2 ;;
  esac
  "$ip" link show dev scqao0 >/dev/null
}

# A pure, non-waiting evidence predicate: NEVER accept stale Result=exit-code
# or a self-invoked verifier as proof that this cycle's systemd timer fired.
# Compare the unit's actual monotonic execution timestamps and invocation
# identity to the CURRENT timer activation and foreign injection timestamps.
fresh_refusal_evidence() {
  require_state
  test -f "$state/armed-us" && test -f "$state/injected-us" || return 1
  test -f "$state/refusal-proof" || return 1
  test ! -e "$state/rollback-proof" || return 1
  test "$(systemctl show "$service" -p Result --value)" = exit-code || return 1
  test "$(systemctl show "$service" -p ExecMainStatus --value)" = 24 || return 1
  start=$(systemctl show "$service" -p ExecMainStartTimestampMonotonic --value)
  finish=$(systemctl show "$service" -p ExecMainExitTimestampMonotonic --value)
  triggered=$(systemctl show "$timer" -p LastTriggerUSecMonotonic --value)
  armed=$(cat "$state/armed-us")
  injected=$(cat "$state/injected-us")
  previous_start=$(cat "$state/previous-start-us")
  for tick in "$start" "$finish" "$triggered" "$armed" "$injected"; do
    unsigned_us "$tick" || return 1
  done
  case "$previous_start" in ''|*[!0-9]*) return 1 ;; esac
  test "$start" -gt "$armed" && test "$start" -gt "$injected" &&
    test "$start" -gt "$previous_start" &&
    test "$triggered" -ge "$armed" &&
    test "$triggered" -le "$start" &&
    test "$finish" -ge "$start" || return 1
  invocation=$(systemctl show "$service" -p InvocationID --value)
  case "$invocation" in
    ????????????????????????????????) ;;
    *) return 1 ;;
  esac
  test "$(cat "$state/refusal-proof")" = "native-classifier-refused:$invocation" || return 1
}

# Discriminating stale-result regression: call the SAME evidence verifier
# after the injection but before this cycle's eight-second systemd timer.
# No past failure status may make this check pass prematurely.
assert_no_stale_refusal() {
  require_state
  test "$#" -eq 1
  case "$1" in address|other-table-route|altname) ;; *) return 2 ;; esac
  assert_conflict_present "$1"
  if fresh_refusal_evidence; then
    echo 'Prior systemd failure falsely accepted as fresh independent refusal' >&2
    return 1
  fi
  test ! -e "$state/refusal-proof"
  case "$(systemctl show "$service" -p Result --value)" in
    success|'') ;;
    *) echo 'Stale systemd failure remains before the new deadline' >&2; return 1 ;;
  esac
  echo "ISOLATED_ACTIVATION_GUARD_STALE_REFUSAL_REJECTED=PASS (kind=$1)"
}

await_refusal() {
  require_state
  test "$#" -eq 1
  case "$1" in address|other-table-route|altname) ;; *) return 2 ;; esac
  test -f "$state/injected-us"
  attempt=0
  while test "$attempt" -lt 20; do
    if fresh_refusal_evidence; then break; fi
    sleep 1
    attempt=$((attempt + 1))
  done
  if ! fresh_refusal_evidence; then
    echo 'ISOLATED_ACTIVATION_GUARD=FAIL (no FRESH independent classifier refusal)' >&2
    systemctl show "$service" "$timer" --no-pager \
      --property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,InvocationID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,LastTriggerUSecMonotonic >&2 || true
    journalctl --no-pager --output=cat -n 20 -u "$service" >&2 || true
    return 1
  fi
  assert_conflict_present "$1"
  if verify_kernel classify >/dev/null 2>&1; then
    echo 'Foreign dependency was accepted after failed watchdog' >&2
    return 1
  fi
  echo "ISOLATED_ACTIVATION_GUARD_FRESH_INVOCATION=PASS (kind=$1, invocation=$invocation, start_us=$start, injected_us=$injected, armed_us=$armed, trigger_us=$triggered)"
  echo "ISOLATED_ACTIVATION_GUARD_FOREIGN_DEPENDENCY_REFUSED=PASS (kind=$1)"
}

cleanup_refusal() {
  require_state
  test "$#" -eq 1
  fresh_refusal_evidence
  assert_conflict_present "$1"
  # Only the test harness, after proving the guard REFUSED destruction,
  # removes its own precisely created negative-test resource. Do not do this
  # in the rollback service; unknown foreign objects always block it.
  case "$1" in
    address) "$ip" -4 addr del 192.0.2.77/32 dev scqao0 ;;
    other-table-route) "$ip" -4 route del 203.0.113.0/24 dev scqao0 table 20121 ;;
    altname) "$ip" link property del dev scqao0 altname qa-foreign-added ;;
    *) return 2 ;;
  esac
  verify_kernel partial_link
  "$ip" link del dev scqao0
  verify_kernel recovered
  echo "ISOLATED_ACTIVATION_GUARD_FOREIGN_TEST_RESOURCE_CLEAN=PASS (kind=$1)"
}

cleanup() {
  require_state
  verify_kernel recovered
  "$ip" -4 rule del pref 30801 to 9.9.9.0/24 table 20120
  "$ip" -4 route del 9.9.9.0/24 dev scqaf0 table 20120
  "$ip" link del dev scqaf0
  verify_kernel clean
  systemctl stop "$timer"
  test "$(systemctl show "$timer" -p ActiveState --value)" != active
  rm -f -- "/run/systemd/system/$service" "/run/systemd/system/$timer"
  systemctl daemon-reload
  rm -rf -- "$state"
  test ! -e "$state" && test ! -L "$state"
  test ! -e "/run/systemd/system/$timer"
  test ! -e "/run/systemd/system/$service"
  echo 'ISOLATED_ACTIVATION_GUARD_FIXTURE_CLEANUP=PASS'
}

require_disposable_guest
case "${1-}" in
  arm) test "$#" -eq 1; arm ;;
  crash-controller) test "$#" -eq 2; crash_controller "$2" ;;
  rollback) test "$#" -eq 1; rollback ;;
  await-recovery) test "$#" -eq 2; await_recovery "$2" ;;
  inject-conflict) test "$#" -eq 2; inject_conflict "$2" ;;
  assert-no-stale-refusal) test "$#" -eq 2; assert_no_stale_refusal "$2" ;;
  await-refusal) test "$#" -eq 2; await_refusal "$2" ;;
  cleanup-refusal) test "$#" -eq 2; cleanup_refusal "$2" ;;
  cleanup) test "$#" -eq 1; cleanup ;;
  *) echo 'Usage: host-activation-guard.sh arm|crash-controller link|route|rule|rollback|await-recovery link|route|rule|inject-conflict address|other-table-route|altname|assert-no-stale-refusal address|other-table-route|altname|await-refusal address|other-table-route|altname|cleanup-refusal address|other-table-route|altname|cleanup' >&2; exit 2 ;;
esac
