#!/usr/bin/env bash
# Acceptance of the REAL installer's incomplete-rollback path. This injects
# an actual read-only file mount at the previous recovery unit restore target,
# only inside a previously verified disconnected disposable systemd Docker
# guest. No installer failpoint, substituted rollback function or host mounts.
set -euo pipefail
umask 077
[[ $(printenv GITHUB_ACTIONS || true) == true && $(printenv CI || true) == true ]] || {
  echo 'Actual restoration-failure acceptance is CI-only' >&2; exit 2;
}
[[ $# -eq 4 ]] || {
  echo 'Usage: test-real-rollback-failure.sh CONTAINER BAD_RELEASE PREVIOUS_RELEASE SCRATCH' >&2; exit 2;
}
container=$1 bad_release=$2 previous_release=$3 scratch=$4
[[ $container == sc-hostqa-* && $bad_release =~ ^releases/[a-zA-Z0-9._-]+$ &&
   $previous_release =~ ^releases/[a-zA-Z0-9._-]+$ && $bad_release != "$previous_release" &&
   -d $scratch ]] || { echo 'Unexpected disposable QA identity' >&2; exit 2; }
[[ $(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container") == none ]]
docker exec "$container" /bin/sh -c '
  set -eu
  test -f /.dockerenv
  test "$(ps -p 1 -o comm=)" = systemd
  test "$(ls -1 /sys/class/net)" = lo
  test -d /root/server-connect-bad-update
  test ! -e /opt/server-connect/.guard-backup.placeholder
'

previous_service_sha=$(docker exec "$container" sha256sum /etc/systemd/system/server-connect-activation-recover.service | cut -d' ' -f1)
previous_timer_sha=$(docker exec "$container" sha256sum /etc/systemd/system/server-connect-activation-recover.timer | cut -d' ' -f1)
previous_unit_sha=$(docker exec "$container" sha256sum /etc/systemd/system/server-connect.service | cut -d' ' -f1)
[[ $(docker exec "$container" readlink /opt/server-connect/current) == "$previous_release" ]]

# Change only the guest's already-verified QA failure candidate. One-shot
# startup sleeps while an independent Docker exec mounts a READ-ONLY previous
# recovery service path; ExecStartPost then fails so the unmodified installer
# enters its actual post-switch rollback. The candidate recovery unit has
# deliberately different bytes, making the failed restoration observable.
docker exec "$container" /bin/sh -c '
 set -eu
 cd /root/server-connect-bad-update
 sed -i "s/^Type=simple$/Type=oneshot/" server-connect.service
 sed -i "s|^ExecStart=.*|ExecStart=/usr/bin/sleep 15|" server-connect.service
 sed -i "/^ExecStart=\/usr\/bin\/sleep 15$/a ExecStartPost=/usr/bin/false" server-connect.service
 grep -qx "Type=oneshot" server-connect.service
 grep -qx "ExecStartPost=/usr/bin/false" server-connect.service
 printf "\n# QA-only changed recovery service bytes (not a release)\n" >> server-connect-activation-recover.service
 sha256sum bin/server-connect bin/sing-box bin/libcronet.so \
   server-connect.service server-connect-activation-recover.service \
   server-connect-activation-recover.timer install.sh \
   THIRD-PARTY-LICENSES/sing-box-LICENSE manifest.json > checksums.sha256
 sha256sum --quiet --check checksums.sha256
'
echo '=== Real restoration-failure injection in isolated systemd guest ==='
# Only this QA candidate is launched. It must fail through systemctl start
# AFTER it replaces the units; no source/runtime hook modifies installer logic.
docker exec "$container" /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/server-connect-bad-update/install.sh --offline \
  >"$scratch/update-real-restore-fault.stdout" \
  2>"$scratch/update-real-restore-fault.stderr" &
installer_pid=$!
sleeping=no
for attempt in $(seq 1 100); do
  if docker exec "$container" /bin/sh -c '
   test "$(systemctl show server-connect.service -p ActiveState --value)" = activating
   test "$(systemctl show server-connect.service -p SubState --value)" = start
   grep -qx "ExecStart=/usr/bin/sleep 15" /etc/systemd/system/server-connect.service
  ' >/dev/null 2>&1;then
    sleeping=yes
    break
  fi
  if ! kill -0 "$installer_pid" 2>/dev/null;then break;fi
  sleep 0.2
done
[[ $sleeping == yes ]] || {
  echo 'Candidate did not reach the verified post-switch blocked-start boundary' >&2
  wait "$installer_pid" || true
  cat "$scratch/update-real-restore-fault.stdout" "$scratch/update-real-restore-fault.stderr" >&2
  exit 1
}
# The mount is PRIVATE to this disposable guest, is never placed on the CI
# runner/physical host, and blocks GNU install when the real rollback later
# tries to restore the prior recovery service unit at this exact destination.
docker exec "$container" /bin/sh -c '
 set -eu
 p=/etc/systemd/system/server-connect-activation-recover.service
 mount --bind "$p" "$p"
 mount -o remount,bind,ro "$p"
 findmnt -n -o OPTIONS -T "$p" | grep -Eq "(^|,)ro(,|$)"
 grep -q "QA-only changed recovery service bytes" "$p"
'
if wait "$installer_pid";then
  echo 'Candidate unexpectedly succeeded despite controlled service failure' >&2
  exit 1
fi
log="$scratch/update-real-restore-fault.stdout"
err="$scratch/update-real-restore-fault.stderr"
for required in \
  'candidate failed; attempting owned lifecycle rollback' \
  'RECOVERY_REQUIRED: prior recovery service unit restoration failed' \
  'RECOVERY_REQUIRED: prior service state could not be completely restored' \
  'RECOVERY_REQUIRED: exact previous unit backups retained:';do
  grep -F "$required" "$log" >/dev/null || {
    echo "Missing real restoration failure witness: $required" >&2
    cat "$log" "$err" >&2; exit 1;
  }
done
! grep -F 'previous owned service state restored; profiles retained' "$log"
grep -F '/etc/systemd/system/server-connect-activation-recover.service' "$err" || {
  echo 'The actual blocked native install operation was not logged' >&2
  cat "$err" >&2
  exit 1
}
echo 'RESTORE_FAILURE_OPERATION=install(previous recovery service unit -> read-only guest bind mount)'

# The REAL previous-unit backup bytes survive, while the current candidate
# service unit still differs from those bytes. This cannot pass based solely
# on an EXIT-hook test double or an already-successful restoration.
docker exec -i "$container" /bin/sh -s "$previous_service_sha" "$previous_timer_sha" \
 "$previous_unit_sha" "$previous_release" <<'VERIFY'
set -eu
expect_service=$1 expect_timer=$2 expect_unit=$3 expect_release=$4
set -- /opt/server-connect/.guard-backup.*
[ "$#" -eq 1 ] && [ -d "$1" ]
backup=$1
set -- /opt/server-connect/.unit-backup.*
[ "$#" -eq 1 ] && [ -f "$1" ]
unit_backup=$1
[ "$(sha256sum "$backup/server-connect-activation-recover.service" | cut -d' ' -f1)" = "$expect_service" ]
[ "$(sha256sum "$backup/server-connect-activation-recover.timer" | cut -d' ' -f1)" = "$expect_timer" ]
[ "$(sha256sum "$unit_backup" | cut -d' ' -f1)" = "$expect_unit" ]
[ "$(readlink /opt/server-connect/current)" = "$expect_release" ]
[ "$(sha256sum /etc/systemd/system/server-connect.service | cut -d' ' -f1)" = "$expect_unit" ]
! cmp -s "$backup/server-connect-activation-recover.service" \
 /etc/systemd/system/server-connect-activation-recover.service
printf 'REAL_ROLLBACK_BACKUP_SERVICE_SHA256=%s\n' "$expect_service"
printf 'REAL_ROLLBACK_BACKUP_TIMER_SHA256=%s\n' "$expect_timer"
printf 'REAL_ROLLBACK_BACKUP_MAIN_UNIT_SHA256=%s\n' "$expect_unit"
printf 'REAL_ROLLBACK_AFTER_FAILURE=previous_release:%s service:%s guard_unit:CONFLICT\n' \
 "$expect_release" "$(systemctl is-active server-connect.service || true)"
VERIFY

# Explicit console-equivalent repair IN GUEST ONLY: lift the fault, restore
# precisely the verified owned bytes, reload, verify provenance and current
# previous service, then clear only this scenario's verified obsolete backups.
docker exec "$container" umount /etc/systemd/system/server-connect-activation-recover.service
docker exec -i "$container" /bin/sh -s "$previous_service_sha" "$previous_timer_sha" \
 "$previous_unit_sha" "$previous_release" "$bad_release" <<'REPAIR'
set -eu
expect_service=$1 expect_timer=$2 expect_unit=$3 expect_release=$4 bad_release=$5
set -- /opt/server-connect/.guard-backup.*
[ "$#" -eq 1 ] && [ -d "$1" ]
backup=$1
set -- /opt/server-connect/.unit-backup.*
[ "$#" -eq 1 ] && [ -f "$1" ]
unit_backup=$1
for kind in service timer;do
 name=server-connect-activation-recover.$kind
 install -m 0644 "$backup/$name" "/etc/systemd/system/$name"
 install -m 0644 "$backup/$name.sha256" "/opt/server-connect/$name.sha256"
done
[ "$(sha256sum /etc/systemd/system/server-connect-activation-recover.service | cut -d' ' -f1)" = "$expect_service" ]
[ "$(sha256sum /etc/systemd/system/server-connect-activation-recover.timer | cut -d' ' -f1)" = "$expect_timer" ]
[ "$(sha256sum /etc/systemd/system/server-connect.service | cut -d' ' -f1)" = "$expect_unit" ]
[ "$(readlink /opt/server-connect/current)" = "$expect_release" ]
systemctl daemon-reload
systemctl is-active --quiet server-connect.service
[ "$(systemctl show server-connect-activation-recover.timer -p ActiveState --value)" = inactive ]
/usr/local/bin/server-connect installer-check-service >/dev/null
/usr/local/bin/server-connect installer-check-guard-clear >/dev/null
# The failed candidate was created by THIS attempt and never became current.
candidate=/opt/server-connect/$bad_release
[ -d "$candidate" ] && [ ! -L "$candidate" ]
[ "$(cat "$candidate/.owner")" = AChWorks/server-connect ]
[ "$(readlink /opt/server-connect/current)" != "$bad_release" ]
rm -rf -- "$candidate"
rm -f -- "$unit_backup" "$backup"/*
rmdir "$backup"
[ ! -e "$candidate" ]
set -- /opt/server-connect/.guard-backup.*
[ ! -e "$1" ]
set -- /opt/server-connect/.unit-backup.*
[ ! -e "$1" ]
echo 'REAL_ROLLBACK_REPAIR=PASS (verified prior owned bytes, systemd and backup cleanup)'
REPAIR
echo 'INSTALLED_REAL_RESTORATION_FAILURE_BACKUPS_RETAINED=PASS (native blocked restore, real rollback, guest repair)'
