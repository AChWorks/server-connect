#!/usr/bin/env bash
# Disposable Debian 13 systemd guest: boot-time QA state reconciliation ONLY.
# A Docker restart resets the container network namespace. It cannot prove
# physical host reboot, production Activation Guard or actual route rollback.
set -euo pipefail
umask 077

[[ $(printenv GITHUB_ACTIONS || true) == true && $(printenv CI || true) == true ]] || {
  echo 'Ephemeral GitHub Actions runner required for disconnected boot QA' >&2
  exit 2
}
[[ $# == 2 && -n $1 && -n $2 ]] || { echo 'Usage: test-activation-boot-qa.sh IMAGE ORIGINAL_GUEST' >&2; exit 2; }
image=$1
parent=$2
[[ $parent =~ ^sc-hostqa-[a-z0-9]+$ ]] || { echo 'Invalid owned original QA guest' >&2; exit 2; }
guest="$parent-boot"
label='sc.qa.activation-boot-only'
created=no
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)

cleanup() {
  local result=$?
  trap - EXIT
  if [[ $created == yes ]]; then
    if [[ $result -ne 0 ]]; then
      docker logs --tail 100 "$guest" >&2 || true
    fi
    if [[ $(docker inspect --format '{{index .Config.Labels "com.achworks.qa.purpose"}}' "$guest" 2>/dev/null || true) == "$label" ]]; then
      docker rm -f "$guest" >/dev/null || result=1
      if docker inspect "$guest" >/dev/null 2>&1; then
        echo 'Owned QA boot guest still exists after cleanup' >&2
        result=1
      fi
    else
      echo 'Refusing to delete a guest without exact QA ownership label' >&2
      result=1
    fi
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# No same-name guest can be adopted; this is a newly provisioned isolated one.
if docker inspect "$guest" >/dev/null 2>&1; then
  echo 'Refusing an already existing QA boot guest' >&2
  exit 2
fi
if ! docker run -d --name "$guest" --hostname sc-qa-boot \
  --label "com.achworks.qa.purpose=$label" \
  --network none --privileged --cgroupns=private \
  --tmpfs /run:rw,nosuid,nodev,mode=755 \
  --tmpfs /run/lock:rw,nosuid,nodev,mode=755 \
  "$image" >/dev/null; then
  # Even a failed Docker start may leave a labelled owned guest behind.
  if [[ $(docker inspect --format '{{index .Config.Labels "com.achworks.qa.purpose"}}' "$guest" 2>/dev/null || true) == "$label" ]]; then
    created=yes
  fi
  exit 1
fi
created=yes

wait_systemd() {
  local attempt
  for attempt in $(seq 1 30); do
    [[ $(docker inspect --format '{{.HostConfig.NetworkMode}}' "$guest") == none ]]
    if docker exec "$guest" /bin/sh -c \
      'test -d /run/systemd/system && test "$(ps -p 1 -o comm=)" = systemd && systemctl show sc-qa-activation-boot.service -p LoadState --value >/dev/null' >/dev/null 2>&1; then
      return 0
    fi
    [[ $(docker inspect --format '{{.State.Running}}' "$guest") == true ]] || return 1
    sleep 2
  done
  echo 'Isolated boot guest systemd not ready' >&2
  return 1
}
wait_systemd
docker cp "$root/scripts/qa/activation-boot-guard.py" "$guest:/root/qa-activation-boot.py"
docker exec -i "$guest" /bin/sh -s <<'GUEST'
set -eu
test ! -e /etc/systemd/system/sc-qa-activation-boot.service
test ! -e /var/lib/sc-qa-boot-recovery
cat > /etc/systemd/system/sc-qa-activation-boot.service <<'UNIT'
[Unit]
Description=Disposable QA-only boot pending-intent reconciliation
After=sc-qa-foreign-boot.service
[Service]
Type=oneshot
TimeoutStartSec=20s
ExecStart=/usr/bin/python3 -I -B /root/qa-activation-boot.py recover
[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/sc-qa-activation-boot.service
systemctl daemon-reload
systemctl enable sc-qa-activation-boot.service
test ! -e /var/lib/sc-qa-boot-recovery/intent.json
test "$(systemctl show sc-qa-activation-boot.service -p ActiveState --value)" = inactive
GUEST

# First restart: a durable QA-only pending journal must survive container
# restart and a NEW independent systemd boot unit must observe *absent*
# staged resources and durably acknowledge a safe no-op, not real rollback.
first='11111111111111111111111111111111'
second='22222222222222222222222222222222'
docker exec "$guest" /usr/bin/python3 -I -B /root/qa-activation-boot.py arm "$first"
pre_started=$(docker inspect --format '{{.State.StartedAt}}' "$guest")
docker restart --time 20 "$guest" >/dev/null
wait_systemd
post_started=$(docker inspect --format '{{.State.StartedAt}}' "$guest")
[[ -n $pre_started && $pre_started != "$post_started" ]] || {
  echo 'No independently observed Docker restart for positive boot QA' >&2
  exit 1
}
# Systemd bus readiness is NOT proof that an enabled oneshot has executed.
# Wait for the new boot's independently executed service to durably finish;
# a cached default Result=success before ExecMain is not sufficient.
positive_ready=no
for attempt in $(seq 1 30); do
  first_result=$(docker exec "$guest" /usr/bin/python3 -I -B /root/qa-activation-boot.py show)
  if [[ $first_result == *'"phase": "recovered_noop_qa"'* ]] &&
     [[ $(docker exec "$guest" systemctl show sc-qa-activation-boot.service -p Result --value) == success ]] &&
     [[ $(docker exec "$guest" systemctl show sc-qa-activation-boot.service -p ExecMainStatus --value) == 0 ]]; then
    positive_start=$(docker exec "$guest" systemctl show sc-qa-activation-boot.service -p ExecMainStartTimestampMonotonic --value)
    if [[ $positive_start =~ ^[1-9][0-9]*$ ]]; then
      positive_ready=yes
      break
    fi
  fi
  sleep 1
done
[[ $positive_ready == yes ]] || {
  echo 'Newly booted QA recovery service did not durably acknowledge exact no-op' >&2
  exit 1
}
first_invocation=$(printf '%s' "$first_result" | python3 -c \
  'import json,sys,re; x=json.load(sys.stdin); assert x["operation_id"]=="11111111111111111111111111111111" and x["phase"]=="recovered_noop_qa"; v=x["invocation"]; assert re.fullmatch("[0-9a-f]{32}",v); print(v)')
[[ -n $first_invocation ]]
[[ $(docker exec "$guest" /usr/bin/ip -o link show | wc -l) -eq 1 ]]
echo 'QA_BOOT_RESTART_DURABLE_NOOP=PASS (separate PID1, no kernel rollback)'

# Second restart: an independent systemd boot unit inserts an unexpected
# foreign link and policy route BEFORE the recovery observer. The observer
# must fail closed and preserve exact pending journal bytes + foreign objects.
docker exec "$guest" /usr/bin/python3 -I -B /root/qa-activation-boot.py arm "$second"
before_sha=$(docker exec "$guest" sha256sum /var/lib/sc-qa-boot-recovery/intent.json | cut -d' ' -f1)
docker exec -i "$guest" /bin/sh -s <<'GUEST'
set -eu
cat > /etc/systemd/system/sc-qa-foreign-boot.service <<'UNIT'
[Unit]
Description=QA-only foreign resource injected before boot recovery
Before=sc-qa-activation-boot.service
[Service]
Type=oneshot
TimeoutStartSec=20s
ExecStart=/usr/bin/ip link add scqafx0 type dummy
ExecStart=/usr/bin/ip link set dev scqafx0 up
ExecStart=/usr/bin/ip -4 route add 8.8.8.0/24 dev scqafx0 table 20120
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/sc-qa-foreign-boot.service
systemctl daemon-reload
systemctl enable sc-qa-foreign-boot.service
test ! -e /sys/class/net/scqafx0
GUEST
pre_started=$(docker inspect --format '{{.State.StartedAt}}' "$guest")
docker restart --time 20 "$guest" >/dev/null
wait_systemd
post_started=$(docker inspect --format '{{.State.StartedAt}}' "$guest")
[[ $pre_started != "$post_started" ]] || {
  echo 'No independently observed Docker restart for negative boot QA' >&2
  exit 1
}
# A previous service's retained status is never enough. This is a fresh
# container boot, and both independent unit invocations must have started.
negative_ready=no
for attempt in $(seq 1 30); do
  if [[ $(docker exec "$guest" systemctl show sc-qa-foreign-boot.service -p Result --value) == success ]] &&
     [[ $(docker exec "$guest" systemctl show sc-qa-activation-boot.service -p Result --value) == exit-code ]] &&
     [[ $(docker exec "$guest" systemctl show sc-qa-activation-boot.service -p ExecMainStatus --value) == 24 ]]; then
    foreign_start=$(docker exec "$guest" systemctl show sc-qa-foreign-boot.service -p ExecMainStartTimestampMonotonic --value)
    recovery_start=$(docker exec "$guest" systemctl show sc-qa-activation-boot.service -p ExecMainStartTimestampMonotonic --value)
    if [[ $foreign_start =~ ^[1-9][0-9]*$ && $recovery_start =~ ^[1-9][0-9]*$ ]] &&
       (( recovery_start > foreign_start )); then
      negative_ready=yes
      break
    fi
  fi
  sleep 1
done
[[ $negative_ready == yes ]] || {
  echo 'Fresh boot QA did not establish ordered foreign injection followed by refused recovery' >&2
  exit 1
}
docker exec "$guest" /usr/bin/ip link show dev scqafx0 >/dev/null
docker exec "$guest" /usr/bin/ip -4 route show table 20120 | grep -F '8.8.8.0/24 dev scqafx0' >/dev/null
after_sha=$(docker exec "$guest" sha256sum /var/lib/sc-qa-boot-recovery/intent.json | cut -d' ' -f1)
[[ $before_sha == "$after_sha" ]]
second_result=$(docker exec "$guest" /usr/bin/python3 -I -B /root/qa-activation-boot.py show)
printf '%s' "$second_result" | python3 -c \
  'import json,sys; x=json.load(sys.stdin); assert x["operation_id"]=="22222222222222222222222222222222" and x["phase"]=="pending_qa_only" and "invocation" not in x'
echo 'QA_BOOT_RESTART_FOREIGN_CONFLICT=PASS (fresh failure, original journal bytes and foreign objects preserved)'
echo 'QA_BOOT_RECOVERY_FEASIBILITY=PASS (Docker restarted, not physical host reboot or product Activation Guard)'
