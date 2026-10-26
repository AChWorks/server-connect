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
wait_recovered() {
 ok=no
 for n in $(seq 1 30);do
  if [ "$(phase)" = trial_recovered ];then ok=yes;break;fi
  sleep 1
 done
 [ "$ok" = yes ]
 [ "$(systemctl show "$service" -p Result --value)" = success ]
 [ "$(systemctl show "$service" -p ExecMainStatus --value)" = 0 ]
 no_trial_rule
}

# The independent systemd timer must actually be running BEFORE journal
# transition or any real native RPDB mutation. Proxy service remains Direct.
systemctl enable --now "$timer"
systemctl is-active --quiet "$timer"
[ "$(systemctl show "$timer" -p Unit --value)" = "$service" ]

op=$(stage)
if "$SC" --json selective-trial-apply --operation-id 00000000000000000000000000000000 \
 --revision 1 --deadline-seconds 8 >/dev/null 2>&1;then
 echo 'Wrong trial operation unexpectedly accepted' >&2;exit 1
fi
# Start a deliberately killed author process after the exact owned rule is
# added; independent systemd must recover it without this shell intervening.
if "$SC" selective-trial-apply --operation-id "$op" --revision 1 \
 --deadline-seconds 8 --qa-kill-after-rule >/dev/null 2>&1;then
 echo 'Controller SIGKILL fixture returned success' >&2;exit 1
fi
[ "$(phase)" = trial_pending ]
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
if "$SC" --json activation-trial-clear --operation-id "$op" --revision 2 >/dev/null 2>&1;then
 echo 'Stale recovered revision cleared journal' >&2;exit 1
fi
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
printf '%s\n' 'PRODUCT_GUARD_TRIAL_SIGKILL_TIMEOUT=PASS'

# Negative ownership challenge: another actor replaces the exact priority
# with a foreign native rule. Watchdog must refuse removal and retain journal.
op=$(stage)
"$SC" selective-trial-apply --operation-id "$op" --revision 1 --deadline-seconds 16 >/dev/null
[ "$(phase)" = trial_pending ]
"$ip" -4 rule del pref 30000 to 9.9.9.0/24 table 20000 protocol 188
"$ip" -4 rule add pref 30000 to 9.9.9.0/24 table 20000 protocol 189
before=$(/usr/bin/sha256sum /var/lib/server-connect/route-activation-journal.json | cut -d' ' -f1)
injected_us=$(/usr/bin/python3 -c 'import time;print(time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000)')
foreign_observed=no
for n in $(seq 1 28);do
 if [ "$(systemctl show "$service" -p Result --value)" = exit-code ] &&
  [ "$(systemctl show "$service" -p ExecMainStatus --value)" != 0 ];then
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
"$ip" -4 rule del pref 30000 to 9.9.9.0/24 table 20000 protocol 189
"$SC" --json activation-trial-recover >/dev/null
[ "$(phase)" = trial_recovered ]
"$SC" --json activation-trial-clear --operation-id "$op" --revision 3 >/dev/null
no_trial_rule
systemctl disable --now "$timer"
[ "$(systemctl is-enabled "$timer")" = disabled ]
[ "$(systemctl show "$timer" -p ActiveState --value)" = inactive ]
printf '%s\n' 'PRODUCT_GUARD_TRIAL_FOREIGN_RULE_REFUSAL=PASS'
