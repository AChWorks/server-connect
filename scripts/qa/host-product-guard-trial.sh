#!/bin/sh
# Installed Server Connect binary, private v2/v3 experimental journals,
# and native IPv4 RPDB/loopback route (disconnected disposable guest only).
# Executable ONLY in disconnected disposable Debian13 systemd Docker guest.
set -eu
umask 077
SC=/usr/local/bin/server-connect
ip=/usr/bin/ip
service=server-connect-activation-recover.service
timer=server-connect-activation-recover.timer
[ "$(id -u)" -eq 0 ] && [ -f /.dockerenv ] &&
 [ "$(ps -p 1 -o comm=)" = systemd ] && [ -x "$SC" ]
[ "$(ls -1 /sys/class/net)" = lo ]
[ "$(systemctl is-enabled "$timer")" = disabled ]
[ "$(systemctl show "$timer" -p LoadState --value)" = loaded ]
[ "$(systemctl show "$service" -p LoadState --value)" = loaded ]

stage() {
 "$SC" --json selective-stage-intent --endpoint 8.8.8.8 \
  --management-peer 1.1.1.1 --tunnel-if scguard0 \
  --destination 9.9.9.0/24 | /usr/bin/python3 -c '
import json,sys,re
x=json.load(sys.stdin)
assert x["ok"] and x["data"]["phase"]=="prepared" and x["data"]["revision"]==1
op=x["data"]["operation_id"]
assert re.fullmatch("[0-9a-f]{32}",op)
print(op)'
}
phase() {
 "$SC" --json activation-trial-status | /usr/bin/python3 -c '
import json,sys
x=json.load(sys.stdin)
assert x["ok"] and x["data"]["experiment_only"] and not x["data"]["activation_ready"]
assert not x["data"]["vpn_verified"] and not x["data"]["recovery_verified"]
print(x["data"]["phase"])'
}
no_trial_rule() {
 "$ip" -4 rule show | grep -v -e '^0:' -e '^32766:' -e '^32767:' | grep . && return 1
 return 0
}
# Both allowed recovery fault points must reject every journal state except
# pending v3. Check the *installed Manager* and the real kernel inventories,
# not only a pure Go state predicate. No test changes foreign host resources.
assert_v3_recovery_fault_rejected() {
 case_name=$1
 journal=/var/lib/server-connect/route-activation-journal.json
 before_sha=absent
 if [ -e "$journal" ];then
  before_sha=$(/usr/bin/sha256sum "$journal" | cut -d' ' -f1)
 fi
 before_rules=$("$ip" -N -j -4 rule show)
 before_routes=$("$ip" -N -j -4 route show table all)
 for fault in route-delete recovered-journal-write;do
  if "$SC" --json activation-trial-recover --qa-fail-at "$fault" \
   >/run/sc-qa-invalid-recovery-fault.json 2>&1;then
   echo "v3 recovery fault $fault incorrectly succeeded for $case_name" >&2;exit 1
  fi
  /usr/bin/python3 - "$fault" <<'PYQAFAULTREFUSED'
import json,sys
with open('/run/sc-qa-invalid-recovery-fault.json',encoding='utf-8') as f:
    result=json.load(f)
assert result['ok'] is False and result['error']['code']=='invalid_arguments',(sys.argv[1],result)
PYQAFAULTREFUSED
  current_sha=absent
  if [ -e "$journal" ];then
   current_sha=$(/usr/bin/sha256sum "$journal" | cut -d' ' -f1)
  fi
  [ "$current_sha" = "$before_sha" ] || {
   echo 'Invalid recovery fault changed the private journal' >&2;exit 1;
  }
  [ "$("$ip" -N -j -4 rule show)" = "$before_rules" ] || {
   echo 'Invalid recovery fault changed native RPDB rules' >&2;exit 1;
  }
  [ "$("$ip" -N -j -4 route show table all)" = "$before_routes" ] || {
   echo 'Invalid recovery fault changed native routes' >&2;exit 1;
  }
 done
 rm -f /run/sc-qa-invalid-recovery-fault.json
 printf 'PRODUCT_GUARD_ROUTE_V3_QA_RECOVERY_FAULT_%s_REFUSAL=PASS\n' "$case_name"
}
assert_no_fault_recovery_phase() {
 expected=$1
 "$SC" --json activation-trial-recover | /usr/bin/python3 -c '
import json,sys
result=json.load(sys.stdin)
assert result["ok"] and result["data"]["experiment_only"] and result["data"]["phase"]==sys.argv[1],result' "$expected"
}

dump_guard_diagnostic() {
 echo 'PRODUCT_GUARD_TRIAL_RECOVERY_DIAGNOSTIC (bounded native/systemd evidence):' >&2
 systemctl show "$timer" -p ActiveState -p Unit -p LastTriggerUSecMonotonic -p NextElapseUSecMonotonic >&2 || true
 systemctl show "$service" -p ActiveState -p Result -p ExecMainCode -p ExecMainStatus -p ExecMainStartTimestampMonotonic -p InvocationID >&2 || true
 journalctl -u "$service" --no-pager -n 15 -o cat >&2 || true
 "$SC" --json activation-trial-status >&2 || true
 "$ip" -j -4 rule show >&2 || true
}
wait_recovered() {
 ok=no
 for n in $(seq 1 30);do
  if [ "$(phase)" = trial_recovered ];then ok=yes;break;fi
  # A genuine failed recovery is already diagnostic evidence; repeating the
  # same trial with its unchanged kernel state cannot repair the issue.
  if [ "$(systemctl show "$service" -p Result --value)" = exit-code ];then
   dump_guard_diagnostic;exit 1
  fi
  sleep 1
 done
 if [ "$ok" != yes ];then dump_guard_diagnostic;exit 1;fi
 [ "$(systemctl show "$service" -p Result --value)" = success ]
 [ "$(systemctl show "$service" -p ExecMainStatus --value)" = 0 ]
 no_trial_rule
}

# The independent systemd timer must actually be running BEFORE journal
# transition or any real native RPDB mutation. Proxy service remains Direct.
systemctl enable --now "$timer"
systemctl is-active --quiet "$timer"
echo PRODUCT_GUARD_TRIAL_TIMER_PREARM=PASS
[ "$(systemctl show "$timer" -p Unit --value)" = "$service" ]

[ ! -e /var/lib/server-connect/route-activation-journal.json ]
assert_v3_recovery_fault_rejected ABSENT
assert_no_fault_recovery_phase absent
op=$(stage)
echo PRODUCT_GUARD_TRIAL_STAGED_INTENT=PASS
assert_v3_recovery_fault_rejected UNARMED_V1
assert_no_fault_recovery_phase unarmed_prepared
if "$SC" --json selective-trial-apply --operation-id 00000000000000000000000000000000 \
 --revision 1 --deadline-seconds 8 >/run/sc-qa-wrong-id.log 2>&1;then
 echo 'Wrong trial operation unexpectedly accepted' >&2;exit 1
fi
/usr/bin/python3 - <<'PYWRONG'
import json
with open('/run/sc-qa-wrong-id.log',encoding='utf-8') as handle:
    result=json.load(handle)
assert not result['ok'] and result['error']['code']=='activation_journal_conflict'
PYWRONG
rm -f /run/sc-qa-wrong-id.log
# Start a deliberately killed author process after the exact owned rule is
# added; independent systemd must recover it without this shell intervening.
trial_exit=0
"$SC" selective-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 8 --qa-kill-after-rule >/dev/null 2>&1 || trial_exit=$?
[ "$trial_exit" -eq 137 ] || {
 echo 'Controller did not terminate by SIGKILL after the real rule add' >&2;exit 1;
}
[ "$(phase)" = trial_pending ]
echo PRODUCT_GUARD_TRIAL_PENDING_AFTER_SIGKILL=PASS
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
if /bin/sh /root/server-connect/install.sh --uninstall \
 >/run/sc-qa-trial-uninstall.log 2>&1;then
 echo 'Uninstall incorrectly removed active independent guard' >&2;exit 1
fi
if ! grep -F 'pending, uncertain or invalid activation journal; refuse installer mutation' \
 /run/sc-qa-trial-uninstall.log >/dev/null;then
 echo 'Uninstall refusal did not prove pending-journal protection' >&2;exit 1
fi
rm -f /run/sc-qa-trial-uninstall.log
[ -f /etc/systemd/system/server-connect-activation-recover.service ]
wait_recovered
echo PRODUCT_GUARD_TRIAL_INDEPENDENT_RECOVERY=PASS
if "$SC" --json activation-trial-clear --operation-id "$op" --revision 2 >/dev/null 2>&1;then
 echo 'Stale recovered revision cleared journal' >&2;exit 1
fi
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
printf '%s\n' 'PRODUCT_GUARD_TRIAL_SIGKILL_TIMEOUT=PASS'

# Deterministic SIGKILL on both sides of the durable pending-journal
# boundary: a pre-journal crash must leave the original unarmed v1 intent;
# a post-journal/pre-add crash must be reconciled by installed systemd despite
# there being NO trial rule to delete. Both use the real installed manager.
op=$(stage)
old_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
if "$SC" --json selective-trial-apply --operation-id "$op" --revision 1 \
 --qa-kill-at after-delete >/run/sc-qa-invalid-point.log 2>&1;then
 echo 'Recovery-only crash point was incorrectly accepted for apply' >&2;exit 1
fi
/usr/bin/python3 - <<'PYINVALID'
import json
with open('/run/sc-qa-invalid-point.log',encoding='utf-8') as f: r=json.load(f)
assert r['error']['code']=='invalid_arguments' and not r['ok']
PYINVALID
rm -f /run/sc-qa-invalid-point.log
[ "$old_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
pre_exit=0
"$SC" selective-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 8 --qa-kill-at before-journal >/dev/null 2>&1 || pre_exit=$?
[ "$pre_exit" -eq 137 ]
[ "$old_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
"$SC" --json selective-abandon-intent --operation-id "$op" --revision 1 >/dev/null
echo PRODUCT_GUARD_TRIAL_PRE_JOURNAL_SIGKILL=PASS
op=$(stage)
post_exit=0
"$SC" selective-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 6 --qa-kill-at after-journal >/dev/null 2>&1 || post_exit=$?
[ "$post_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
no_trial_rule
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_TRIAL_POST_JOURNAL_PRE_ADD_SIGKILL=PASS

# iproute2 renders configurable rt_protos/rt_tables aliases by default.
# A system administrator's naming choices must NOT strand an owned rule:
# the real installed watchdog must observe numeric kernel identities via -N.
# All alias edits stay inside the disconnected disposable guest.
alias_backup=/run/sc-qa-iproute2-alias-backup
mkdir -m 0700 "$alias_backup"
mkdir -p /etc/iproute2
for kind in rt_protos rt_tables;do
 if [ -e "/etc/iproute2/$kind" ] || [ -L "/etc/iproute2/$kind" ];then
  [ -f "/etc/iproute2/$kind" ] && [ ! -L "/etc/iproute2/$kind" ]
  cp -p "/etc/iproute2/$kind" "$alias_backup/$kind"
 else
  : > "$alias_backup/$kind.absent"
 fi
done
printf '247 scqa_guard_protocol\n' >> /etc/iproute2/rt_protos
printf '20000 scqa_guard_table\n' >> /etc/iproute2/rt_tables
op=$(stage)
alias_exit=0
"$SC" selective-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 8 --qa-kill-after-rule >/dev/null 2>&1 || alias_exit=$?
[ "$alias_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
"$ip" -j -4 rule show | /usr/bin/python3 -c '
import json,sys
items=[r for r in json.load(sys.stdin) if r.get("priority")==30000]
assert len(items)==1,items
assert items[0].get("protocol")=="scqa_guard_protocol",items
assert items[0].get("table")=="scqa_guard_table",items'
"$ip" -N -j -4 rule show | /usr/bin/python3 -c '
import json,sys
items=[r for r in json.load(sys.stdin) if r.get("priority")==30000]
assert len(items)==1,items
assert str(items[0].get("protocol"))=="247",items
assert str(items[0].get("table"))=="20000",items'
wait_recovered
[ "$(phase)" = trial_recovered ]
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
for kind in rt_protos rt_tables;do
 if [ -f "$alias_backup/$kind.absent" ];then
  rm -f "/etc/iproute2/$kind"
 else
  cp -p "$alias_backup/$kind" "/etc/iproute2/$kind"
 fi
done
rm -f "$alias_backup"/*
rmdir "$alias_backup"
printf '%s\n' 'PRODUCT_GUARD_TRIAL_NUMERIC_ALIAS_RECOVERY=PASS (custom protocol/table names, actual timer and SIGKILL)'


# A stopped independent timer must not produce a positive scheduled-guard
# receipt from an earlier journal. Expired recovery is still possible by
# operator invocation; after deleting the real rule a SIGKILL must leave
# pending evidence, then a separately restarted timer must finish recovery.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 9 >/dev/null
[ "$(phase)" = trial_pending ]
systemctl stop "$timer"
[ "$(systemctl show "$timer" -p ActiveState --value)" = inactive ]
assert_v3_recovery_fault_rejected PENDING_V2
[ "$(phase)" = trial_pending ]
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
if "$SC" --json activation-trial-recover >/run/sc-qa-timer-stopped.log 2>&1;then
 echo 'Stopped timer was incorrectly reported as scheduled' >&2;exit 1
fi
/usr/bin/python3 - <<'PYUNAVAILABLE'
import json
with open('/run/sc-qa-timer-stopped.log',encoding='utf-8') as f: r=json.load(f)
assert r['ok'] is False and r['error']['code']=='guard_unavailable',r
PYUNAVAILABLE
rm -f /run/sc-qa-timer-stopped.log
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
[ "$(phase)" = trial_pending ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
sleep 10
rec_exit=0
"$SC" activation-trial-recover --qa-kill-at after-delete >/dev/null 2>&1 || rec_exit=$?
[ "$rec_exit" -eq 137 ]
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
systemctl start "$timer"
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
echo PRODUCT_GUARD_TRIAL_DEGRADED_TIMER_AND_POST_DELETE_SIGKILL=PASS

# The second recovery boundary is after absent-rule reinspection but before
# marking the exact journal recovered. The timer must reconcile a pending
# journal whose rule is already gone, without claiming pre-crash success.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 6 >/dev/null
systemctl stop "$timer"
sleep 8
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
rec_exit=0
"$SC" activation-trial-recover --qa-kill-at before-recovered-journal >/dev/null 2>&1 || rec_exit=$?
[ "$rec_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
systemctl start "$timer"
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
echo PRODUCT_GUARD_TRIAL_PRE_RECOVERED_JOURNAL_SIGKILL=PASS

# Two distinct degraded-watchdog cases: an unexpected lower-precedence
# runtime override, and an EFFECTIVE mask of the actual installed unit.
# Systemd's /etc unit wins over /run, so a --runtime mask of an /etc unit
# is NOT evidence the executor was disabled. The product must still distrust
# the competing runtime declaration even when systemctl reports loaded/static.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 22 >/dev/null
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
systemctl is-active --quiet "$timer"
systemctl mask --runtime "$service"
[ "$(readlink "/run/systemd/system/$service")" = /dev/null ]
load_state=$(systemctl show "$service" -p LoadState --value)
file_state=$(systemctl show "$service" -p UnitFileState --value)
printf 'PRODUCT_GUARD_TRIAL_RUNTIME_OVERRIDE_OBSERVATION=LoadState:%s,UnitFileState:%s\n' "$load_state" "$file_state"
if "$SC" --json activation-trial-recover >/run/sc-qa-runtime-override.log 2>&1;then
 echo 'Competing runtime override incorrectly reported a scheduled guard' >&2;exit 1
fi
/usr/bin/python3 - <<'PYMASK'
import json
with open('/run/sc-qa-runtime-override.log',encoding='utf-8') as f: r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_unavailable',r
PYMASK
rm -f /run/sc-qa-runtime-override.log
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
systemctl unmask --runtime "$service"
[ ! -L "/run/systemd/system/$service" ]
echo PRODUCT_GUARD_TRIAL_RUNTIME_OVERRIDE_FALSE_GUARD_REFUSED=PASS

# An effective /etc mask requires moving the existing /etc unit out of the
# way. This privileged sabotage is permitted ONLY inside this disposable,
# no-network Docker guest; preserve exact bytes/metadata before mutation.
systemctl stop "$timer"
service_path="/etc/systemd/system/$service"
service_backup=/run/sc-qa-owned-service-before-mask
[ -f "$service_path" ] && [ ! -L "$service_path" ] && [ ! -e "$service_backup" ]
unit_sha=$(/usr/bin/sha256sum "$service_path" | cut -d' ' -f1)
cp -p "$service_path" "$service_backup"
[ "$unit_sha" = "$(/usr/bin/sha256sum "$service_backup" | cut -d' ' -f1)" ]
rm "$service_path"
ln -s /dev/null "$service_path"
[ "$(readlink "$service_path")" = /dev/null ]
systemctl daemon-reload
[ "$(systemctl show "$service" -p LoadState --value)" = masked ]
# Start the timer under an actually unavailable executor. It may fail to
# schedule; neither outcome is a recovered journal nor allowed to hide the
# still-present real kernel rule.
if systemctl start "$timer";then
 systemctl is-active --quiet "$timer"
else
 [ "$(systemctl show "$timer" -p ActiveState --value)" = inactive ]
fi
sleep 24
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
# Restore exactly the previously installed, digest-pinned product unit. Do
# not treat timer running as proof of recovery; native rule and journal must
# reconcile after the unit has been restored and independently rearmed.
systemctl stop "$timer"
[ "$(readlink "$service_path")" = /dev/null ]
rm "$service_path"
cp -p "$service_backup" "$service_path"
[ "$unit_sha" = "$(/usr/bin/sha256sum "$service_path" | cut -d' ' -f1)" ]
rm "$service_backup"
systemctl daemon-reload
[ "$(systemctl show "$service" -p LoadState --value)" = loaded ]
systemctl reset-failed "$service" || true
systemctl restart "$timer"
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_TRIAL_EFFECTIVE_MASK_NO_FALSE_RECOVERY=PASS

# The timer can remain active after its ExecStart binary becomes unavailable.
# Exercise the REAL installed oneshot, not a mocked systemctl Result value.
# Only the disposable, disconnected guest-owned binary is temporarily moved;
# its root-owned metadata and checksum must be restored before proceeding.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 25 >/dev/null
[ "$(phase)" = trial_pending ]
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
installed_bin=/opt/server-connect/current/bin/server-connect
# Keep the executable fixture on the trusted installed executable mount.
# /run may be noexec under container/systemd hardening and cannot be used as
# evidence that a copied manager program is runnable.
binary_backup=/opt/server-connect/current/bin/server-connect.qa-recovery-backup
[ -f "$installed_bin" ] && [ ! -L "$installed_bin" ] && [ ! -e "$binary_backup" ]
binary_sha=$(/usr/bin/sha256sum "$installed_bin" | cut -d' ' -f1)
cp -p "$installed_bin" "$binary_backup"
[ "$binary_sha" = "$(/usr/bin/sha256sum "$binary_backup" | cut -d' ' -f1)" ]
rm "$installed_bin"
[ ! -e "$installed_bin" ]
# A genuine ExecStart failure must not disable the timer itself.
if systemctl start "$service" >/run/sc-qa-executor-start.log 2>&1;then
 echo 'Missing installed recovery executable unexpectedly started' >&2;exit 1
fi
[ "$(systemctl show "$service" -p Result --value)" = exit-code ]
[ "$(systemctl show "$service" -p ExecMainStatus --value)" = 203 ]
systemctl is-active --quiet "$timer"
if "$binary_backup" --json activation-trial-recover >/run/sc-qa-executor-failed.json 2>/run/sc-qa-executor-failed.stderr;then
 echo 'Failed recovery executor incorrectly reported a scheduled guard' >&2;exit 1
fi
if [ ! -s /run/sc-qa-executor-failed.json ];then
 echo 'Installed-binary diagnostic produced no JSON' >&2
 sed -n '1,8p' /run/sc-qa-executor-failed.stderr >&2
 exit 1
fi
/usr/bin/python3 - <<'PYEXECFAIL'
import json
with open('/run/sc-qa-executor-failed.json',encoding='utf-8') as f: r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_unavailable',r
assert 'executor failed' in r['error']['message'],r
PYEXECFAIL
rm -f /run/sc-qa-executor-failed.json /run/sc-qa-executor-failed.stderr /run/sc-qa-executor-start.log
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
# Keep executable absent beyond expiry. An active timer with a failed
# executor must leave the pending journal and real native rule intact.
sleep 28
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
cp -p "$binary_backup" "$installed_bin"
[ "$binary_sha" = "$(/usr/bin/sha256sum "$installed_bin" | cut -d' ' -f1)" ]
rm "$binary_backup"
systemctl reset-failed "$service"
systemctl restart "$timer"
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_TRIAL_EXECUTOR_MISSING_ACTIVE_TIMER_FAIL_CLOSED=PASS

# A repeatedly started recovery oneshot may be systemd start-rate limited
# while the independent timer remains active. Use only this installed unit
# and require actual Result=start-limit-hit, not injected output or fakes.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 24 >/dev/null
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
burst=$(systemctl show "$service" -p StartLimitBurst --value)
case "$burst" in ''|*[!0-9]*|0) echo "Unsupported systemd recovery start-rate limit: $burst" >&2;exit 1 ;; esac
[ "$burst" -le 20 ]
limited=no
for n in $(seq 1 30);do
 systemctl start "$service" >/dev/null 2>&1 || :
 if [ "$(systemctl show "$service" -p Result --value)" = start-limit-hit ];then limited=yes;break;fi
done
[ "$limited" = yes ] || { dump_guard_diagnostic;echo 'No genuine start-limit-hit observed' >&2;exit 1; }
systemctl is-active --quiet "$timer"
if "$SC" --json activation-trial-recover >/run/sc-qa-start-limited.json 2>&1;then
 echo 'Start-limited recovery executor incorrectly reported a scheduled guard' >&2;exit 1
fi
/usr/bin/python3 - <<'PYLIMIT'
import json
with open('/run/sc-qa-start-limited.json',encoding='utf-8') as f: r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_unavailable',r
assert 'start-rate limited' in r['error']['message'],r
PYLIMIT
rm -f /run/sc-qa-start-limited.json
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
# Stop only this guest-owned timer, then repair the known failed executor
# state; the independently restarted timer must reconcile the expired rule.
systemctl stop "$timer"
sleep 26
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
systemctl reset-failed "$service"
systemctl restart "$timer"
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_TRIAL_START_LIMIT_ACTIVE_TIMER_FAIL_CLOSED=PASS

# After a completed recovery, a new external rule at the exact selector
# cannot be silently accepted as an unchanged previously recovered kernel.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 4 >/dev/null
wait_recovered
"$ip" -4 rule add pref 30000 to 9.9.9.0/24 table 20000 protocol 247
stale_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
stale_native=$("$ip" -N -j -4 rule show)
# Each of the three public APIs must independently refuse the SAME stale
# recovered journal, without any change to its bytes or the foreign rule.
assert_stale_refusal() {
 name=$1; expected=$2; shift 2
 if "$SC" --json "$@" >/run/sc-qa-stale-public.json 2>&1;then
  echo "Stale recovered kernel rule accepted by $name" >&2;exit 1
 fi
 /usr/bin/python3 - "$expected" <<'PYSTALE'
import json,sys
with open('/run/sc-qa-stale-public.json',encoding='utf-8') as f: r=json.load(f)
assert not r['ok'] and r['error']['code']==sys.argv[1],r
PYSTALE
 rm -f /run/sc-qa-stale-public.json
 [ "$stale_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
 [ "$stale_native" = "$("$ip" -N -j -4 rule show)" ]
}
assert_stale_refusal status trial_recovery_uncertain activation-trial-status
assert_stale_refusal recover trial_recovery_uncertain activation-trial-recover
assert_stale_refusal clear trial_resource_conflict activation-trial-clear --operation-id "$op" --revision 3
echo PRODUCT_GUARD_TRIAL_STALE_RECOVERED_ALL_PUBLIC_OPERATIONS_REFUSED=PASS
# This *lab-owned injected fixture* is removed by the test, not by product
# recovery: protocol 247 alone cannot authenticate a foreign writer.
"$ip" -4 rule del pref 30000 to 9.9.9.0/24 table 20000 protocol 247
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
systemctl reset-failed "$service"
no_trial_rule
echo PRODUCT_GUARD_TRIAL_STALE_RECOVERED_KERNEL_REFUSAL=PASS

# v3: the *installed product*, not the standalone QA-only fixture, now
# durably journals an actual IPv4 lo route + matching RPDB rule. The loopback
# route is intentionally unable to carry VPN traffic; Docker --network none
# and the product's root/systemd/loopback admission gate remain mandatory.
# A direct "show table 20000" can fail for an empty, unallocated Linux
# FIB table. A successful full inventory + strict table filter is required;
# never accept a failed ip pipeline's empty JSON stdout as absence proof.
trial_route_inventory() { "$ip" -N -j -4 route show table all; }
no_trial_route() {
 routes=$(trial_route_inventory) || return 1
 printf '%s\n' "$routes" | /usr/bin/python3 -c '
import json,sys
rows=json.load(sys.stdin)
selected=[r for r in rows if str(r.get("table","254"))=="20000"]
assert selected==[],"trial route table not empty"'
}
assert_trial_route() {
 routes=$(trial_route_inventory) || return 1
 printf '%s\n' "$routes" | /usr/bin/python3 -c '
import json,sys
rows=json.load(sys.stdin)
selected=[r for r in rows if str(r.get("table","254"))=="20000"]
assert len(selected)==1 and selected[0]["dst"]=="9.9.9.0/24" and selected[0]["dev"]=="lo",selected'
}
# A deliberate foreign kernel conflict may leave the *real* oneshot in a
# failed state while its independent timer stays active. A later trial must
# not silently rearm against a failed executor. Assert fresh cause-specific
# systemd failure for each v3 fixture, then clear only the known guest-owned
# failure AFTER exact journal clearance and kernel baseline restoration.
trial_injection_mark_us() {
 /usr/bin/python3 -c 'import time;print(time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000)'
}
await_v3_systemd_foreign_refusal() {
 injection_complete_us=$1
 [ "$(systemctl show "$timer" -p Unit --value)" = "$service" ]
 observed=no
 for n in $(seq 1 28);do
  if [ "$(systemctl show "$service" -p Result --value)" = exit-code ] &&
   [ "$(systemctl show "$service" -p ExecMainStatus --value)" = 41 ];then
   started_us=$(systemctl show "$service" -p ExecMainStartTimestampMonotonic --value)
   case "$started_us" in ''|*[!0-9]*) ;; *)
    if [ "$started_us" -gt "$injection_complete_us" ];then observed=yes;break;fi ;;
   esac
  fi
  sleep 1
 done
 if [ "$observed" != yes ];then
  echo 'No fresh cause-specific independent systemd v3 refusal' >&2
  dump_guard_diagnostic
  exit 1
 fi
 systemctl is-active --quiet "$timer"
 printf 'PRODUCT_GUARD_ROUTE_V3_FRESH_SYSTEMD_CONFLICT=PASS injection_complete_us=%s service_start_us=%s status=41\n' \
  "$injection_complete_us" "$started_us"
}
reset_v3_qa_executor_after_clear() {
 [ ! -e /var/lib/server-connect/route-activation-journal.json ]
 no_trial_rule
 no_trial_route
 state=$(systemctl show "$service" -p Result --value)
 case "$state" in
  success) ;;
  exit-code)
   [ "$(systemctl show "$service" -p ExecMainStatus --value)" = 41 ] || {
    dump_guard_diagnostic;exit 1;
   }
   systemctl reset-failed "$service"
   ;;
  *) dump_guard_diagnostic;exit 1 ;;
 esac
 [ "$(systemctl show "$service" -p Result --value)" = success ] || {
  dump_guard_diagnostic;exit 1;
 }
 systemctl is-active --quiet "$timer"
}

no_trial_route
op=$(stage)
route_exit=0
"$SC" selective-route-trial-apply --operation-id "$op" --revision 1  --deadline-seconds 7 --qa-kill-at after-route >/dev/null 2>&1 || route_exit=$?
[ "$route_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
assert_trial_route
no_trial_rule
wait_recovered
no_trial_route
assert_v3_recovery_fault_rejected RECOVERED_V3
assert_no_fault_recovery_phase trial_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_route
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_AFTER_ROUTE_SIGKILL_RECOVERY=PASS'

op=$(stage)
rule_exit=0
"$SC" selective-route-trial-apply --operation-id "$op" --revision 1  --deadline-seconds 7 --qa-kill-at after-add >/dev/null 2>&1 || rule_exit=$?
[ "$rule_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
assert_trial_route
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
wait_recovered
no_trial_route
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_route
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_AFTER_RULE_SIGKILL_RECOVERY=PASS'

# Kill the *independent recovery* in the middle of its two deletions:
# after the rule disappears but while the route still exists. A new timer
# invocation must reconcile precisely that partial state without broad flush.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 6 >/dev/null
systemctl stop "$timer"
sleep 8
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
partial_exit=0
"$SC" activation-trial-recover --qa-kill-at after-delete >/dev/null 2>&1 || partial_exit=$?
[ "$partial_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
assert_trial_route
systemctl start "$timer"
wait_recovered
no_trial_route
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_MID_ROLLBACK_SIGKILL_RECOVERY=PASS'

# Crash after the second deletion but BEFORE the durable recovered journal
# exists. The real timer must persist the recovered receipt on the next tick
# without inventing a new kernel rule or route.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 6 >/dev/null
systemctl stop "$timer"
sleep 8
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
last_exit=0
"$SC" activation-trial-recover --qa-kill-at after-route-delete >/dev/null 2>&1 || last_exit=$?
[ "$last_exit" -eq 137 ] && [ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
no_trial_route
systemctl start "$timer"
wait_recovered
no_trial_route
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_AFTER_ROUTE_DELETE_SIGKILL_RECOVERY=PASS'

# Four additional v3 failure-path cases. Native ip failures are induced by an
# explicitly invalid, NON-MUTATING native ip command in the same installed
# product error handler; journal-write failure is injected before attempting
# the recovered revision. These do NOT emulate netlink EIO, disk/fsync loss,
# or a production-host failure. All fault controls require the guest gate.
assert_v3_qa_fault() {
 expected=$1
 /usr/bin/python3 - "$expected" <<'PYV3FAULT'
import json,sys
with open('/run/sc-qa-v3-fault.json',encoding='utf-8') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']==sys.argv[1],r
PYV3FAULT
 rm -f /run/sc-qa-v3-fault.json
}
# Invalid QA injection must be refused BEFORE the journal and kernel change;
# v2 rule-only trials must not inherit the v3 error-injection capability.
op=$(stage)
prepared_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
if "$SC" --json selective-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 8 --qa-fail-at route-add >/run/sc-qa-v3-fault.json 2>&1;then
 echo 'v2 incorrectly accepted v3 fault injection' >&2;exit 1
fi
assert_v3_qa_fault invalid_arguments
[ "$prepared_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
no_trial_route
"$SC" --json selective-abandon-intent --operation-id "$op" --revision 1 >/dev/null
op=$(stage)
prepared_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
if "$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 8 --qa-fail-at route-delete >/run/sc-qa-v3-fault.json 2>&1;then
 echo 'v3 route apply incorrectly accepted recovery-only fault injection' >&2;exit 1
fi
assert_v3_qa_fault invalid_arguments
[ "$prepared_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
no_trial_route
"$SC" --json selective-abandon-intent --operation-id "$op" --revision 1 >/dev/null
echo PRODUCT_GUARD_ROUTE_V3_QA_INVALID_FAULT_REFUSAL=PASS

for injected in route-add rule-add;do
 op=$(stage)
 if "$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 \
  --deadline-seconds 8 --qa-fail-at "$injected" >/run/sc-qa-v3-fault.json 2>&1;then
  echo "v3 $injected QA native error unexpectedly succeeded" >&2;exit 1
 fi
 assert_v3_qa_fault trial_kernel_error
 pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
 [ "$(phase)" = trial_pending ]
 [ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
 no_trial_rule
 if [ "$injected" = route-add ];then no_trial_route;else assert_trial_route;fi
 wait_recovered
 no_trial_route
 "$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
 no_trial_rule
 if [ "$injected" = route-add ];then
  echo PRODUCT_GUARD_ROUTE_V3_QA_ROUTE_ADD_COMMAND_FAILURE=PASS
 else
  echo PRODUCT_GUARD_ROUTE_V3_QA_RULE_ADD_COMMAND_FAILURE=PASS
 fi
done

# Manual recovery after expiry with the independent timer intentionally
# stopped lets QA examine the exact partial delta before later rearming.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 6 >/dev/null
systemctl stop "$timer"
sleep 8
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
if "$SC" --json activation-trial-recover --qa-fail-at route-delete >/run/sc-qa-v3-fault.json 2>&1;then
 echo 'v3 route-delete QA native error unexpectedly succeeded' >&2;exit 1
fi
assert_v3_qa_fault trial_kernel_error
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
assert_trial_route
systemctl start "$timer"
wait_recovered
no_trial_route
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_ROUTE_V3_QA_ROUTE_DELETE_COMMAND_FAILURE=PASS

# Simulate inability to persist the recovered revision after BOTH kernel
# resources were removed; the journal remains pending and must be retried.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 6 >/dev/null
systemctl stop "$timer"
sleep 8
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
if "$SC" --json activation-trial-recover --qa-fail-at recovered-journal-write >/run/sc-qa-v3-fault.json 2>&1;then
 echo 'v3 recovered-journal QA persistence fault unexpectedly succeeded' >&2;exit 1
fi
assert_v3_qa_fault activation_journal_unavailable
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
no_trial_rule
no_trial_route
systemctl start "$timer"
wait_recovered
no_trial_route
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_ROUTE_V3_QA_RECOVERED_JOURNAL_WRITE_FAILURE=PASS

# Replace the owned route with a foreign protocol at the exact table/CIDR.
# A fresh scheduled systemd oneshot must report exact conflict exit 41, not
# merely a manual CLI refusal or a stale failure from an earlier fixture.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 7 >/dev/null
"$ip" -4 route del 9.9.9.0/24 dev lo table 20000 proto 247 scope link
"$ip" -4 route add 9.9.9.0/24 dev lo table 20000 proto 248 scope link
# Mark only AFTER the completed successful foreign native injection.
foreign_injected_us=$(trial_injection_mark_us)
foreign_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
foreign_native=$(trial_route_inventory)
await_v3_systemd_foreign_refusal "$foreign_injected_us"
[ "$foreign_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
[ "$foreign_native" = "$(trial_route_inventory)" ]
if "$SC" --json activation-trial-recover >/run/sc-qa-foreign-route-v3.json 2>&1;then
 echo 'v3 recovery adopted a foreign native route' >&2;exit 1
fi
/usr/bin/python3 - <<'PYROUTEFOREIGN'
import json
with open('/run/sc-qa-foreign-route-v3.json',encoding='utf-8') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
PYROUTEFOREIGN
rm -f /run/sc-qa-foreign-route-v3.json
[ "$(phase)" = trial_pending ]
[ "$foreign_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
[ "$foreign_native" = "$(trial_route_inventory)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
"$ip" -4 route del 9.9.9.0/24 dev lo table 20000 proto 248 scope link
"$SC" --json activation-trial-recover >/dev/null
[ "$(phase)" = trial_recovered ]
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
reset_v3_qa_executor_after_clear
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_FOREIGN_ROUTE_REFUSAL=PASS'

# A second unrelated RPDB rule referencing the chosen table is likewise an
# independent owner. No kernel deletion may occur until the guest fixture
# removes that rule and invokes the product's independent recovery path.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 7 >/dev/null
"$ip" -4 rule add pref 30200 to 9.9.9.0/24 table 20000 protocol 249
# Mark only AFTER the completed successful foreign native injection.
foreign_injected_us=$(trial_injection_mark_us)
foreign_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
foreign_native=$("$ip" -N -j -4 rule show)
await_v3_systemd_foreign_refusal "$foreign_injected_us"
[ "$foreign_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
[ "$foreign_native" = "$("$ip" -N -j -4 rule show)" ]
if "$SC" --json activation-trial-recover >/run/sc-qa-foreign-table-rule.json 2>&1;then
 echo 'v3 recovery removed a route consumed by a foreign rule' >&2;exit 1
fi
/usr/bin/python3 - <<'PYFOREIGNTABLE'
import json
with open('/run/sc-qa-foreign-table-rule.json',encoding='utf-8') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
PYFOREIGNTABLE
rm -f /run/sc-qa-foreign-table-rule.json
[ "$(phase)" = trial_pending ]
[ "$foreign_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
[ "$foreign_native" = "$("$ip" -N -j -4 rule show)" ]
assert_trial_route
"$ip" -4 rule del pref 30200 to 9.9.9.0/24 table 20000 protocol 249
"$SC" --json activation-trial-recover >/dev/null
[ "$(phase)" = trial_recovered ]
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
reset_v3_qa_executor_after_clear
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_FOREIGN_TABLE_RULE_REFUSAL=PASS'

# A recovered journal is NOT everlasting proof that an externally introduced
# route did not reappear. Status/recover/clear must each refuse this same
# exact matching but untrusted route without changing the journal or kernel.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 5 >/dev/null
wait_recovered
no_trial_route
"$ip" -4 route add 9.9.9.0/24 dev lo table 20000 proto 247 scope link
stale_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
stale_route=$(trial_route_inventory)
for mode in status recover clear;do
 case "$mode" in
 status) set -- activation-trial-status; expected=trial_recovery_uncertain ;;
 recover) set -- activation-trial-recover; expected=trial_recovery_uncertain ;;
 clear) set -- activation-trial-clear --operation-id "$op" --revision 3; expected=trial_resource_conflict ;;
 esac
 if "$SC" --json "$@" >/run/sc-qa-route-stale.json 2>&1;then
  echo "Stale recovered v3 route accepted by $mode" >&2;exit 1
 fi
 /usr/bin/python3 - "$expected" <<'PYSTALEROUTE'
import json,sys
with open('/run/sc-qa-route-stale.json',encoding='utf-8') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']==sys.argv[1],r
PYSTALEROUTE
 [ "$stale_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
 [ "$stale_route" = "$(trial_route_inventory)" ]
done
rm -f /run/sc-qa-route-stale.json
"$ip" -4 route del 9.9.9.0/24 dev lo table 20000 proto 247 scope link
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_route
no_trial_rule
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_STALE_RECOVERED_ROUTE_REFUSAL=PASS'

# A protocol-tagged route moved to a DIFFERENT table is foreign ownership
# evidence, not proof that the original experiment fully reconciled. Even
# while the recorded target table is empty, refuse a recovered receipt.
op=$(stage)
"$SC" --json selective-route-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 5 >/dev/null
wait_recovered
no_trial_route
"$ip" -4 route add 9.9.9.0/24 dev lo table 20001 proto 247 scope link
moved_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
moved_native=$(trial_route_inventory)
if "$SC" --json activation-trial-status >/run/sc-qa-v3-moved-route.json 2>&1;then
 echo 'Moved tagged route silently accepted as recovered' >&2;exit 1
fi
/usr/bin/python3 - <<'PYMOVEDROUTE'
import json
with open('/run/sc-qa-v3-moved-route.json',encoding='utf-8') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
PYMOVEDROUTE
rm -f /run/sc-qa-v3-moved-route.json
[ "$moved_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
[ "$moved_native" = "$(trial_route_inventory)" ]
no_trial_route
"$ip" -4 route del 9.9.9.0/24 dev lo table 20001 proto 247 scope link
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_route
no_trial_rule
printf '%s\n' 'PRODUCT_GUARD_ROUTE_V3_MOVED_TAGGED_ROUTE_REFUSAL=PASS'

# Negative ownership challenge: another actor replaces the exact priority
# with a foreign native rule. Watchdog must refuse removal and retain journal.
op=$(stage)
"$SC" selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 16 >/dev/null
[ "$(phase)" = trial_pending ]
"$ip" -4 rule del pref 30000 to 9.9.9.0/24 table 20000 protocol 247
"$ip" -4 rule add pref 30000 to 9.9.9.0/24 table 20000 protocol 248
before=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
injected_us=$(/usr/bin/python3 -c 'import time;print(time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000)')
foreign_observed=no
for n in $(seq 1 28);do
 if [ "$(systemctl show "$service" -p Result --value)" = exit-code ] &&
  [ "$(systemctl show "$service" -p ExecMainStatus --value)" = 41 ];then
  actual_us=$(systemctl show "$service" -p ExecMainStartTimestampMonotonic --value)
  case "$actual_us" in ''|*[!0-9]*) ;; *)
   if [ "$actual_us" -gt "$injected_us" ];then foreign_observed=yes;break;fi ;;
  esac
 fi
 sleep 1
done
[ "$foreign_observed" = yes ]
[ "$(phase)" = trial_pending ]
[ "$before" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
# Remove the deliberately injected fixture, then perform genuine product
# reconciliation after expiry. Neither recovery nor cleanup adopts foreign.
"$ip" -4 rule del pref 30000 to 9.9.9.0/24 table 20000 protocol 248
"$SC" --json activation-trial-recover >/dev/null
[ "$(phase)" = trial_recovered ]
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
systemctl disable --now "$timer"
[ "$(systemctl is-enabled "$timer")" = disabled ]
[ "$(systemctl show "$timer" -p ActiveState --value)" = inactive ]
# Reset only the exact owned failed recovery unit after its cause-specific
# refusal, private journal and recovered kernel baseline were all proved.
[ "$(systemctl show "$service" -p Result --value)" = exit-code ]
[ "$(systemctl show "$service" -p ExecMainStatus --value)" = 41 ]
systemctl reset-failed "$service"
[ "$(systemctl show "$service" -p ActiveState --value)" = inactive ]
printf '%s\n' 'PRODUCT_GUARD_TRIAL_FOREIGN_RULE_REFUSAL=PASS'
