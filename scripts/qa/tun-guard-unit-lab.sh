#!/bin/sh
# Source-only/disposable-guest QA. This file is sourced by host-tun-path.sh,
# or run as a deliberately killed controller. It does NOT provide a product
# Activation Guard, durable journal, host rollback ownership or field proof.

qa_tun_client_unit=scqa-tun-lab-client.service
qa_tun_recover_unit=scqa-tun-lab-recover.service
qa_tun_recover_timer=scqa-tun-lab-recover.timer
qa_tun_unit_root=/run/systemd/system
qa_tun_units_created=${qa_tun_units_created:-no}

qa_tun_guard_context() {
  test "$(id -u)" -eq 0 &&
    test -f /.dockerenv &&
    test "$(ps -p 1 -o comm=)" = systemd &&
    test -f /root/qa-host-assertions.sh &&
    test -x /root/server-connect/bin/sing-box &&
    test -r /run/sc-qa-tun-client.json &&
    test -e /sys/class/net/scqaedge0 &&
    test ! -e /sys/class/net/sctunqa0
}

qa_tun_unit_state() {
  /usr/bin/systemctl show "$1" -p "$2" --value
}

qa_tun_guard_prepare() {
  qa_tun_guard_context || {
    echo 'QA_TUN_GUARD_PREFLIGHT=FAIL (not an isolated, inactive TUN guest)' >&2
    return 1
  }
  for unit in "$qa_tun_client_unit" "$qa_tun_recover_unit" "$qa_tun_recover_timer"; do
    test ! -e "$qa_tun_unit_root/$unit" &&
      test ! -L "$qa_tun_unit_root/$unit" &&
      test "$(qa_tun_unit_state "$unit" LoadState)" = not-found || {
        echo 'QA_TUN_GUARD_PREFLIGHT=FAIL (existing/ambiguous unit identity)' >&2
        return 1
      }
  done

  # Absence is verified before claiming ownership of these QA-only files.
  # The flag must precede the first creation so partial writes are cleaned.
  qa_tun_units_created=yes
  cat >"$qa_tun_unit_root/$qa_tun_client_unit" <<'UNIT'
[Unit]
Description=Disposable QA-only genuine sing-box TUN process
[Service]
Type=simple
ExecStart=/root/server-connect/bin/sing-box run -c /run/sc-qa-tun-client.json
Restart=no
KillMode=control-group
TimeoutStopSec=4s
UMask=0077
UNIT
  cat >"$qa_tun_unit_root/$qa_tun_recover_unit" <<'UNIT'
[Unit]
Description=Disposable QA-only independent deadline stop of real TUN
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl stop scqa-tun-lab-client.service
TimeoutStartSec=12s
UNIT
  cat >"$qa_tun_unit_root/$qa_tun_recover_timer" <<'UNIT'
[Unit]
Description=Disposable QA-only real TUN deadline
[Timer]
OnActiveSec=25s
AccuracySec=1s
Unit=scqa-tun-lab-recover.service
UNIT
  chmod 0644 "$qa_tun_unit_root/$qa_tun_client_unit" \
    "$qa_tun_unit_root/$qa_tun_recover_unit" "$qa_tun_unit_root/$qa_tun_recover_timer"
  /usr/bin/systemctl daemon-reload
  for unit in "$qa_tun_client_unit" "$qa_tun_recover_unit" "$qa_tun_recover_timer"; do
    test "$(qa_tun_unit_state "$unit" LoadState)" = loaded &&
      test "$(qa_tun_unit_state "$unit" FragmentPath)" = "$qa_tun_unit_root/$unit" ||
      { echo 'QA_TUN_GUARD_PREFLIGHT=FAIL (unit file provenance)' >&2; return 1; }
  done
  echo 'QA_TUN_GUARD_UNIT_PROVENANCE=PASS'
}

qa_tun_guard_cleanup() {
  [ "${qa_tun_units_created:-no}" = yes ] || return 0
  cleanup_error=no
  # Stop ONLY the three freshly owned QA units. If systemd cannot be
  # inspected, cleanup fails rather than claiming a clean network.
  for unit in "$qa_tun_recover_timer" "$qa_tun_recover_unit" "$qa_tun_client_unit"; do
    if state=$(qa_tun_unit_state "$unit" LoadState); then
      if [ "$state" != not-found ]; then
        /usr/bin/systemctl stop "$unit" || cleanup_error=yes
      fi
    else
      cleanup_error=yes
    fi
  done
  for unit in "$qa_tun_client_unit" "$qa_tun_recover_unit" "$qa_tun_recover_timer"; do
    path="$qa_tun_unit_root/$unit"
    if [ -L "$path" ]; then
      cleanup_error=yes
    else
      rm -f -- "$path" || cleanup_error=yes
    fi
  done
  # Only a disposable-guest negative fixture deliberately masks one owned
  # recovery unit after deleting its file; final PID1 state must reject it.
  if [ "${SC_QA_TUN_GUARD_CLEANUP_FAULT-}" = masked-recovery-unit ]; then
    ln -s /dev/null "$qa_tun_unit_root/$qa_tun_recover_unit" || cleanup_error=yes
  fi
  final_units_ok=yes
  /usr/bin/systemctl daemon-reload || { cleanup_error=yes; final_units_ok=no; }
  # Stop/removal command success is not proof that PID1 released each unit.
  # Inspect the three exact names, paths and manager state after reload.
  for unit in "$qa_tun_client_unit" "$qa_tun_recover_unit" "$qa_tun_recover_timer"; do
    path="$qa_tun_unit_root/$unit"
    if [ -e "$path" ] || [ -L "$path" ]; then
      final_units_ok=no
    fi
    if load=$(qa_tun_unit_state "$unit" LoadState) &&
       active=$(qa_tun_unit_state "$unit" ActiveState) &&
       fragment=$(qa_tun_unit_state "$unit" FragmentPath); then
      if [ "$load" != not-found ] || [ "$active" != inactive ] || [ -n "$fragment" ]; then
        final_units_ok=no
      fi
    else
      final_units_ok=no
    fi
  done
  if [ "$final_units_ok" = yes ]; then
    echo 'QA_TUN_GUARD_UNIT_FINAL_STATE=PASS'
  else
    echo 'QA_TUN_GUARD_UNIT_FINAL_STATE=FAIL' >&2
    cleanup_error=yes
  fi
  if [ -e /sys/class/net/sctunqa0 ]; then
    cleanup_error=yes
  fi
  if [ "$cleanup_error" = yes ]; then
    echo 'QA_TUN_GUARD_UNIT_CLEANUP=FAIL' >&2
    return 1
  fi
  qa_tun_units_created=no
  echo 'QA_TUN_GUARD_UNIT_CLEANUP=PASS'
}

qa_tun_guard_prearmed() {
  test "$(qa_tun_unit_state "$qa_tun_recover_timer" ActiveState)" = active &&
    test "$(qa_tun_unit_state "$qa_tun_recover_timer" Unit)" = "$qa_tun_recover_unit" &&
    test "$(qa_tun_unit_state "$qa_tun_recover_unit" LoadState)" = loaded &&
    test "$(qa_tun_unit_state "$qa_tun_recover_unit" FragmentPath)" = "$qa_tun_unit_root/$qa_tun_recover_unit" || return 1
  next=$(qa_tun_unit_state "$qa_tun_recover_timer" NextElapseUSecMonotonic)
  test -n "$next" && test "$next" != n/a
}

qa_tun_guard_controller() {
  # The independent systemd timer is armed and verified BEFORE real TUN
  # startup. SIGKILL terminates only this initiating shell, while PID1 and
  # its owned service/recovery timer continue independently.
  qa_tun_guard_context || exit 2
  for unit in "$qa_tun_client_unit" "$qa_tun_recover_unit" "$qa_tun_recover_timer"; do
    test "$(qa_tun_unit_state "$unit" FragmentPath)" = "$qa_tun_unit_root/$unit" || exit 2
  done
  /usr/bin/systemctl start "$qa_tun_recover_timer"
  qa_tun_guard_prearmed || exit 2
  echo 'QA_TUN_GUARD_TIMER_PREARMED=PASS'
  /usr/bin/systemctl start "$qa_tun_client_unit"
  test "$(qa_tun_unit_state "$qa_tun_client_unit" ActiveState)" = active
  echo 'QA_TUN_GUARD_CLIENT_STARTED=PASS'
  kill -KILL "$$"
  exit 3
}

if [ "${1-}" = controller ]; then
  qa_tun_guard_controller
fi
