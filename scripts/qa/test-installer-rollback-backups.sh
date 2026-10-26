#!/bin/sh
# Hermetic negative check of the actual installer EXIT/rollback lifecycle.
# Never invokes the installed product, systemd or a root/network mutation.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
sed -n '/^on_exit() {/,/^}/p' "$root/bundle/install.sh" > "$scratch/on_exit.sh"
[ "$(grep -c '^on_exit() {' "$scratch/on_exit.sh")" -eq 1 ]
[ "$(tail -n 1 "$scratch/on_exit.sh")" = '}' ]

for scenario in successful rollback_ok rollback_failed; do
 result=0
 SC_QA_SCENARIO=$scenario SC_QA_SCRATCH=$scratch /bin/sh -s > "$scratch/$scenario.out" <<'CHILD' || result=$?
set -eu
. "$SC_QA_SCRATCH/on_exit.sh"
unit_backup=/var/lib/server-connect/.test-unit-backup
 guard_backup=/var/lib/server-connect/.test-guard-backup
operation_done=no
failed=no
say() { printf '%s\n' "$*"; }
remove_backup() { printf 'removed\n' >> "$SC_QA_SCRATCH/$SC_QA_SCENARIO.effects"; }
rollback_candidate() {
 printf 'rollback\n' >> "$SC_QA_SCRATCH/$SC_QA_SCENARIO.effects"
 if [ "$SC_QA_SCENARIO" = rollback_failed ];then failed=yes;fi
}
trap on_exit EXIT
if [ "$SC_QA_SCENARIO" = successful ];then operation_done=yes;exit 0;fi
exit 37
CHILD
 case "$scenario" in
 successful)
  [ "$result" -eq 0 ]
  [ "$(cat "$scratch/$scenario.effects")" = removed ]
  ! grep -q 'RECOVERY_REQUIRED' "$scratch/$scenario.out"
  ;;
 rollback_ok)
  [ "$result" -eq 37 ]
  [ "$(cat "$scratch/$scenario.effects")" = "$(printf 'rollback\nremoved')" ]
  ! grep -q 'RECOVERY_REQUIRED' "$scratch/$scenario.out"
  ;;
 rollback_failed)
  [ "$result" -eq 37 ]
  [ "$(cat "$scratch/$scenario.effects")" = rollback ]
  grep -F 'RECOVERY_REQUIRED: exact previous unit backups retained: /var/lib/server-connect/.test-unit-backup /var/lib/server-connect/.test-guard-backup' "$scratch/$scenario.out" >/dev/null
  ;;
 esac
done
printf '%s\n' 'INSTALLER_EXIT_HOOK_BACKUP_RETENTION=PASS (mocked rollback path only)'
