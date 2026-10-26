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
  systemctl start "$timer"
  systemctl is-active --quiet "$timer"
  test "$(systemctl show "$timer" -p Unit --value)" = "$service"
  echo 'ISOLATED_ACTIVATION_GUARD_PREARM=PASS (systemd timer before route changes)'
}

crash_controller() {
  require_state
  systemctl is-active --quiet "$timer"
  test ! -e "$state/rollback-proof"
  verify_kernel preflight
  # The only native network mutations in this entire test are fixed dummy
  # link and RPDB objects within the disconnected Docker guest namespace.
  "$ip" link add scqao0 type dummy
  "$ip" link set dev scqao0 alias sc-qa-guard-owned-v1
  "$ip" -4 addr add 10.210.1.2/24 dev scqao0
  "$ip" link set dev scqao0 up
  "$ip" -4 route add 8.8.8.0/24 dev scqao0 table 20120
  "$ip" -4 rule add pref 30800 to 8.8.8.0/24 table 20120
  # A simulated foreign owner is added AFTER arming. The watchdog must not
  # delete its distinct rule, route or interface in the same table.
  "$ip" link add scqaf0 type dummy
  "$ip" link set dev scqaf0 alias sc-qa-guard-foreign-v1
  "$ip" -4 addr add 10.211.1.2/24 dev scqaf0
  "$ip" link set dev scqaf0 up
  "$ip" -4 route add 9.9.9.0/24 dev scqaf0 table 20120
  "$ip" -4 rule add pref 30801 to 9.9.9.0/24 table 20120
  verify_kernel applied
  test "$(cat "$state/identity")" = sc-qa-activation-guard-v1
  printf 'controller-arrived-before-sigkill\n' > "$state/controller-marker"
  # A separate child is deliberately SIGKILLed, while systemd PID 1 owns
  # the independent deadline and can still execute the guard service.
  kill -KILL "$$"
  echo 'UNREACHABLE_CONTROLLERS_MUST_NOT_SUCCEED' >&2
  exit 1
}

rollback() {
  require_state
  test -f "$state/controller-marker"
  test ! -e "$state/rollback-proof"
  # No mutation unless the *currently observed* kernel route, policy rule,
  # interface alias and simulated foreign objects all have exact identities.
  # A missing/changed object fails closed rather than deleting by table ID.
  verify_kernel applied
  "$ip" -4 rule del pref 30800 to 8.8.8.0/24 table 20120
  "$ip" -4 route del 8.8.8.0/24 dev scqao0 table 20120
  "$ip" link del dev scqao0
  verify_kernel recovered
  printf 'independent-deadline-rollback-complete\n' > "$state/rollback-proof"
  echo 'ISOLATED_ACTIVATION_GUARD_ROLLBACK=PASS (independent systemd service)'
}

await_recovery() {
  require_state
  test "$(cat "$state/controller-marker")" = controller-arrived-before-sigkill
  attempt=0
  while test "$attempt" -lt 20; do
    if test -f "$state/rollback-proof"; then break; fi
    sleep 1
    attempt=$((attempt + 1))
  done
  if test "$(cat "$state/rollback-proof" 2>/dev/null || true)" != independent-deadline-rollback-complete ||
     test "$(systemctl show "$service" -p Result --value)" != success; then
    echo 'ISOLATED_ACTIVATION_GUARD=FAIL (independent rollback did not complete)' >&2
    systemctl show "$service" "$timer" --no-pager \
      --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus >&2 || true
    journalctl --no-pager --output=cat -n 20 -u "$service" >&2 || true
    return 1
  fi
  verify_kernel recovered
  echo 'ISOLATED_ACTIVATION_GUARD_TIMEOUT_SIGKILL=PASS'
  echo 'ISOLATED_ACTIVATION_GUARD_FOREIGN_POLICY_PRESERVED=PASS'
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
  crash-controller) test "$#" -eq 1; crash_controller ;;
  rollback) test "$#" -eq 1; rollback ;;
  await-recovery) test "$#" -eq 1; await_recovery ;;
  cleanup) test "$#" -eq 1; cleanup ;;
  *) echo 'Usage: host-activation-guard.sh arm|crash-controller|rollback|await-recovery|cleanup' >&2; exit 2 ;;
esac
