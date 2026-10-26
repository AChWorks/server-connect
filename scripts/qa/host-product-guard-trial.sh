#!/bin/sh
# Installed Server Connect binary, private v2 journal, and native IPv4 RPDB.
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

op=$(stage)
echo PRODUCT_GUARD_TRIAL_STAGED_INTENT=PASS
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

# A real masked recovery service may prevent timer invocations. The pending
# record MUST NOT change to recovered while service is unavailable, nor may
# manual predeadline recovery claim the watchdog exists. Restoring the unit
# permits the independent timer to complete the overdue recovery.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 9 >/dev/null
pending_sha=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
# Freeze new timer invocations before masking the exact guest-owned unit.
systemctl stop "$timer"
systemctl mask --runtime "$service"
# Mask existence is independently verified. Debian 13 systemd may return
# cached LoadState=loaded,UnitFileState=static despite this real runtime
# mask; the product must inspect the override path itself, not trust cache.
[ "$(readlink "/run/systemd/system/$service")" = /dev/null ]
load_state=$(systemctl show "$service" -p LoadState --value)
file_state=$(systemctl show "$service" -p UnitFileState --value)
printf 'PRODUCT_GUARD_TRIAL_MASKED_UNIT_OBSERVATION=LoadState:%s,UnitFileState:%s\n' "$load_state" "$file_state"
# A masked target can prevent the timer itself from starting. That is a
# degraded-watchdog observation, NOT grounds for declaring recovery.
if systemctl start "$timer";then
 systemctl is-active --quiet "$timer"
else
 [ "$(systemctl show "$timer" -p ActiveState --value)" = inactive ]
fi
if "$SC" --json activation-trial-recover >/run/sc-qa-masked-service.log 2>&1;then
 echo 'Masked watchdog was incorrectly reported as scheduled' >&2;exit 1
fi
/usr/bin/python3 - <<'PYMASK'
import json
with open('/run/sc-qa-masked-service.log',encoding='utf-8') as f: r=json.load(f)
assert not r['ok'] and r['error']['code']=='guard_unavailable',r
PYMASK
rm -f /run/sc-qa-masked-service.log
sleep 11
[ "$(phase)" = trial_pending ]
[ "$pending_sha" = "$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)" ]
"$ip" -4 rule show | grep -F '9.9.9.0/24' >/dev/null
systemctl unmask --runtime "$service"
[ "$(systemctl show "$service" -p LoadState --value)" = loaded ]
systemctl reset-failed "$service" || true
systemctl restart "$timer"
wait_recovered
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
echo PRODUCT_GUARD_TRIAL_MASKED_WATCHDOG_NO_FALSE_RECOVERY=PASS

# After a completed recovery, a new external rule at the exact selector
# cannot be silently accepted as an unchanged previously recovered kernel.
op=$(stage)
"$SC" --json selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 4 >/dev/null
wait_recovered
"$ip" -4 rule add pref 30000 to 9.9.9.0/24 table 20000 protocol 247
if "$SC" --json activation-trial-status >/run/sc-qa-reintroduced-rule.log 2>&1;then
 echo 'Stale recovered journal incorrectly proved current kernel absence' >&2;exit 1
fi
/usr/bin/python3 - <<'PYREINTRO'
import json
with open('/run/sc-qa-reintroduced-rule.log',encoding='utf-8') as f: r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_recovery_uncertain',r
PYREINTRO
rm -f /run/sc-qa-reintroduced-rule.log
# This *lab-owned injected fixture* is removed by the test, not by product
# recovery: protocol 247 alone cannot authenticate a foreign writer.
"$ip" -4 rule del pref 30000 to 9.9.9.0/24 table 20000 protocol 247
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
systemctl reset-failed "$service"
no_trial_rule
echo PRODUCT_GUARD_TRIAL_STALE_RECOVERED_KERNEL_REFUSAL=PASS

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
