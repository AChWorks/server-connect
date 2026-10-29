#!/usr/bin/env bash
# Exact QA-only lifecycle in ephemeral Debian 13 systemd containers.
# The original installer/lifecycle guest remains Docker --network none.
# A separate short-lived connected guest tests online prerequisite acquisition
# before its own network is disconnected. NEVER run on a production host;
# public publisher authenticity is out of scope.
set -euo pipefail
umask 077
# A privileged container needs an already disposable, credential-free runner.
# Do not allow an operator to accidentally invoke it on a production server.
if [[ $(printenv GITHUB_ACTIONS || true) != true || $(printenv CI || true) != true ]]; then
  echo 'Only ephemeral GitHub Actions runners may execute this QA harness' >&2
  exit 2
fi
if [[ $# != 4 || ! -f $1 || ! -f $2 || ! -f $3 || ! -f $4 ]]; then
  echo 'Usage: test-installed-host.sh BASE.tar.gz BOOTSTRAP.sh UPDATE.tar.gz BAD-UPDATE.tar.gz' >&2
  exit 2
fi
bundle=$(realpath -- "$1")
bootstrap=$(realpath -- "$2")
update_bundle=$(realpath -- "$3")
bad_update_bundle=$(realpath -- "$4")
digest=$(sha256sum "$bundle" | cut -d' ' -f1)
update_digest=$(sha256sum "$update_bundle" | cut -d' ' -f1)
bad_update_digest=$(sha256sum "$bad_update_bundle" | cut -d' ' -f1)
[[ $digest != "$update_digest" && $update_digest != "$bad_update_digest" ]] || {
  echo "Upgrade QA requires three distinct artifacts" >&2
  exit 2
}
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$root"
# Exercise the actual guest APT negative classifier with disposable fakes
# before any privileged Docker work; this is not a substitute for real APT.
bash scripts/qa/test-host-apt-only.sh
# Run candidate-version WordPress fail-closed regressions inside this script,
# since pull_request_target uses the trusted main workflow definition.
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-wp-fcgi-check.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-wp-proxy-prepend.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-tun-dns-wire.py
# The guard feasibility probe must be strictly guest-local and must reject
# ambiguous kernel identities before the privileged disconnected guest runs.
sh -n scripts/qa/host-activation-guard.sh
sh -n scripts/qa/host-product-guard-trial.sh
sh -n scripts/qa/host-tun-path.sh
sh -n scripts/qa/tun-guard-unit-lab.sh
bash scripts/qa/test-installer-rollback-backups.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-activation-guard-inspect.py
# Separate reboot-scheduling QA remains a disposable-container proof only.
bash -n scripts/qa/test-activation-boot-qa.sh
bash -n scripts/qa/test-real-rollback-failure.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B - <<'PYBOOTA'
import ast
from pathlib import Path
ast.parse(Path('scripts/qa/activation-boot-guard.py').read_text())
PYBOOTA
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-activation-boot-guard.py
# This distinct ephemeral systemd guest begins without Python/curl, acquires
# them through signed native Debian APT, installs the SAME QA archive through
# the actual online bootstrap, then disconnects to prove offline uninstall.
# It must finish and clean up before the disconnected lifetime harness starts.
# Run bounded fake-Docker failure-path regressions before privileged Docker.
bash scripts/qa/test-docker-owned-cleanup.sh
bash -n scripts/qa/test-online-minimal-host.sh
bash scripts/qa/test-online-minimal-host.sh "$bundle" "$bootstrap"
tmpdir=/tmp
if [[ -n $(printenv RUNNER_TEMP || true) ]]; then tmpdir=$(printenv RUNNER_TEMP); fi
scratch=$(mktemp -d "$tmpdir/server-connect-hostqa.XXXXXXXX")
suffix=$(basename "$scratch" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')
container="sc-hostqa-$suffix"
image="sc-hostqa:$suffix"
# This original disconnected guest uses the same exact-name cleanup.
# A partially created container/image must not remain after Docker failure.
source "$root/scripts/qa/docker-owned-cleanup.sh"
started=no
cleanup() {
  original_rc=$?
  trap - EXIT
  if [[ $started == yes && $original_rc -ne 0 ]]; then
    echo 'Disposable systemd diagnostics (failure only):' >&2
    docker logs --tail 100 "$container" >&2 ||
      echo 'Warning: could not collect container logs' >&2
  fi
  if ! sc_qa_cleanup_owned_docker "$container" "$image" "$scratch"; then
    if [[ $original_rc -eq 0 ]]; then original_rc=1; fi
  fi
  exit "$original_rc"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '=== Disposable Debian 13 preparation (network permitted BEFORE isolation) ==='
docker build --pull -f scripts/qa/Dockerfile.host-systemd -t "$image" scripts/qa
# Delegate the container's PRIVATE cgroup v2 filesystem through Docker.
# NEVER bind-mount the host cgroup root into a private cgroup namespace:
# it creates inconsistent ownership and can stop systemd before boot.
# The privileged container exists only on an ephemeral, credential-free
# GitHub runner; --network none remains enforced throughout its lifetime.
docker run -d --name "$container" --hostname sc-qa \
  --network none --privileged --cgroupns=private \
  --tmpfs /run:rw,nosuid,nodev,mode=755 \
  --tmpfs /run/lock:rw,nosuid,nodev,mode=755 \
  "$image" >/dev/null
started=yes
[[ $(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container") == none ]]
ready=no
for attempt in $(seq 1 30); do
  if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
    echo 'Disposable systemd container exited before service readiness' >&2
    docker inspect "$container" \
      --format 'State: exit={{.State.ExitCode}}, error={{.State.Error}}, OOM={{.State.OOMKilled}}, PID={{.State.Pid}}; cgroupns={{.HostConfig.CgroupnsMode}}; network={{.HostConfig.NetworkMode}}' >&2 || true
    docker logs "$container" >&2 || true
    exit 1
  fi
  if docker exec "$container" /bin/sh -c \
    'test -d /run/systemd/system && systemctl show server-connect.service -p LoadState --value >/dev/null'; then
    ready=yes
    break
  fi
  sleep 2
done
[[ $ready == yes ]] || { echo 'Isolated systemd PID1 did not become ready' >&2; exit 1; }
docker exec "$container" /bin/sh -c '
  set -eu
  . /etc/os-release
  test "$ID" = debian && test "$VERSION_ID" = 13
  test "$(ps -p 1 -o comm=)" = systemd
  test "$(uname -m)" = x86_64
  test "$(systemctl show server-connect.service -p LoadState --value)" = not-found
  test ! -e /opt/server-connect && test ! -e /var/lib/server-connect
  test ! -e /etc/systemd/system/server-connect.service
  test ! -e /usr/local/bin/server-connect
  test -z "$(ip -4 route show default)" && test -z "$(ip -6 route show default)"
'
network_digest() {
  docker exec "$container" /bin/sh /root/qa-host-assertions.sh network
}
assert_network_unchanged() {
  local phase=$1 baseline=$2 current
  if ! current=$(network_digest); then
    echo "NETWORK_PRESERVATION($phase)=FAIL (snapshot query)" >&2
    exit 1
  fi
  if [[ $current != "$baseline" ]]; then
    echo "NETWORK_PRESERVATION($phase)=FAIL (route/rule/link drift)" >&2
    exit 1
  fi
  echo "NETWORK_PRESERVATION($phase)=PASS"
}
verify_host_services() {
  local phase=$1
  docker exec "$container" /bin/sh /root/qa-host-coexistence.sh probe
  echo "ISOLATED_SSH_HTTP($phase)=PASS"
}

# Exercise real new SSH sessions and a separate HTTP origin on guest loopback.
# Docker --network none stays in force. Keep both services running while the
# installer is traced so they verify actual non-product service coexistence.
docker exec "$container" /sbin/ip link set lo up
docker cp "$root/scripts/qa/host-coexistence.sh" "$container:/root/qa-host-coexistence.sh"
docker exec "$container" /bin/sh /root/qa-host-coexistence.sh start
host_ready=no
for attempt in $(seq 1 20); do
  if docker exec "$container" /bin/sh /root/qa-host-coexistence.sh probe >/dev/null 2>&1; then
    host_ready=yes
    break
  fi
  sleep 1
done
if [[ $host_ready != yes ]]; then
  echo 'Isolated loopback SSH/HTTP fixtures did not become ready' >&2
  docker exec "$container" /bin/sh /root/qa-host-coexistence.sh probe
  exit 1
fi
echo 'ISOLATED_SSH_HTTP(initial)=PASS'

# The pinned sing-box direct outbound requires a detectable default interface
# even when its only test destination is guest loopback. Provide a *guest-only*
# synthetic default dev lo; Docker --network none forbids external connectivity.
# Capture it in the baseline BEFORE any Server Connect lifecycle operation.
docker exec "$container" /sbin/ip -4 route add default dev lo metric 4242
docker exec "$container" /bin/sh -c '
  test "$(ip -4 route show default)" = "default dev lo scope link metric 4242"
  test -z "$(ip -6 route show default)"
'
echo 'ISOLATED_LOOPBACK_DEFAULT=PASS (disconnected guest fixture only)'

# The guest's /run is a fresh Docker-managed tmpfs, not a bind of host /run.
# The systemd credential staging helper uses mount namespaces; ensure the
# isolated tmpfs allows its service-credential mounts to propagate within the
# guest. This must not change the GitHub runner's mount namespace.
docker exec "$container" /bin/sh -c '
  set -eu
  printf "GUEST_RUN_PROPAGATION_BEFORE=%s\n" "$(findmnt -n -o PROPAGATION -T /run)"
  mount --make-rshared /run
  test "$(findmnt -n -o PROPAGATION -T /run)" = shared
  printf "GUEST_RUN_PROPAGATION_AFTER=shared\n"
'

docker cp "$root/scripts/qa/host-qa-assertions.sh" "$container:/root/qa-host-assertions.sh"

docker cp "$bundle" "$container:/root/sc-qa-bundle.tar.gz"
docker cp "$update_bundle" "$container:/root/sc-qa-update.tar.gz"
docker cp "$bad_update_bundle" "$container:/root/sc-qa-bad-update.tar.gz"
docker cp "$bootstrap" "$container:/root/sc-qa-bootstrap.sh"
docker exec "$container" /bin/sh -c '
  set -eu
  mkdir -m 0700 /root/server-connect /root/qa-strace
  tar -xzf /root/sc-qa-bundle.tar.gz -C /root/server-connect \
    --strip-components=1 --no-same-owner --no-same-permissions
  test "$(stat -c %u /root/server-connect/install.sh)" = 0
'
[[ $(docker exec "$container" sha256sum /root/sc-qa-bundle.tar.gz | cut -d' ' -f1) == "$digest" ]]
[[ $(docker exec "$container" sha256sum /root/sc-qa-update.tar.gz | cut -d' ' -f1) == "$update_digest" ]]
[[ $(docker exec "$container" sha256sum /root/sc-qa-bad-update.tar.gz | cut -d' ' -f1) == "$bad_update_digest" ]]
docker exec "$container" /bin/sh -c '
  set -eu
  for variant in update bad-update; do
    mkdir -m 0700 "/root/server-connect-$variant"
    tar -xzf "/root/sc-qa-$variant.tar.gz" \
      -C "/root/server-connect-$variant" \
      --strip-components=1 --no-same-owner --no-same-permissions
    (cd "/root/server-connect-$variant" &&
      sha256sum --quiet --check checksums.sha256)
  done
'
offline_before=$(network_digest)

run_offline() {
  local label=$1 action=$2 source_dir=/root/server-connect
  if [[ $# -ge 3 ]]; then source_dir=$3; fi
  echo "=== Disconnected offline $label ==="
  docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
    -e trace=%network,%process \
    -o "/root/qa-strace/$label" /usr/bin/env -i \
    HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh "$source_dir/install.sh" "$action"
  assert_no_offline_fetch "$label"
}
# An active proxy is intentionally permitted to open its existing loopback
# readiness socket. The strict no-AF_INET offline trace scanner applies only
# to Direct/inactive phases; do not report ZERO for these active updates.
run_active_offline() {
  local label=$1 source_dir=$2
  echo "=== Disconnected guest active-proxy update $label ==="
  docker exec "$container" /usr/bin/env -i \
    HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh "$source_dir/install.sh" --offline
}
run_active_offline_expect_failure() {
  local label=$1 source_dir=$2
  echo "=== Disconnected guest expected active-update failure $label ==="
  if docker exec "$container" /usr/bin/env -i \
    HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh "$source_dir/install.sh" --offline \
    >"$scratch/$label.stdout" 2>"$scratch/$label.stderr"; then
    echo "Broken candidate unexpectedly installed: $label" >&2
    exit 1
  fi
}
assert_no_offline_fetch() {
  label=$1
  # Missing/unreadable traces, an entirely empty trace set, scanner
  # errors and forbidden execve/execveat or IPv4/IPv6 network attempts
  # MUST all fail acceptance (individual empty child traces are valid).
  docker exec "$container" /bin/sh /root/qa-host-assertions.sh \
    trace /root/qa-strace "$label"
  echo "OFFLINE_FETCH_ATTEMPTS($label)=ZERO"
}

verify_direct_install() {
  docker exec "$container" /bin/sh -c '
    set -eu
    test "$(cat /opt/server-connect/.owner)" = AChWorks/server-connect
    test -L /usr/local/bin/server-connect
    test "$(readlink /usr/local/bin/server-connect)" = /opt/server-connect/current/bin/server-connect
    test "$(systemctl show server-connect.service -p LoadState --value)" = loaded
    test "$(systemctl show server-connect.service -p ActiveState --value)" = inactive
    test "$(systemctl is-enabled server-connect.service)" = disabled
    test "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled
    test "$(systemctl show server-connect-activation-recover.service -p LoadState --value)" = loaded
    /usr/local/bin/server-connect version --json
  '
}
verify_clean_uninstall() {
  docker exec "$container" /bin/sh -c '
    set -eu
    test "$(systemctl show server-connect.service -p LoadState --value)" = not-found
    test ! -e /opt/server-connect
    test ! -e /usr/local/bin/server-connect
    test ! -e /etc/systemd/system/server-connect.service
    test ! -e /etc/systemd/system/server-connect-activation-recover.service
    test ! -e /etc/systemd/system/server-connect-activation-recover.timer
    test "$(stat -c %a /var/lib/server-connect)" = 700
    test "$(stat -c %a /var/lib/server-connect/profiles)" = 700
    test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
  '
}

run_offline verify-only --verify-only
assert_network_unchanged verify-only "$offline_before"
verify_host_services verify-only
docker exec "$container" /bin/sh -c 'test ! -e /opt/server-connect && test ! -e /var/lib/server-connect'

echo '=== Negative offline acceptance: missing pinned core must reject BEFORE mutation ==='
# This test mutates ONLY the private disposable source bundle, restores the
# original verified bytes before the next test, and never touches another host.
docker exec "$container" /bin/sh -c '
  set -eu
  test -f /root/server-connect/bin/sing-box
  mv /root/server-connect/bin/sing-box /root/server-connect/bin/sing-box.qa-hidden
'
if docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
  -e trace=%network,%process \
  -o /root/qa-strace/missing-core /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/server-connect/install.sh --offline \
  2>"$scratch/missing-core.stderr"; then
  echo 'Missing pinned sing-box unexpectedly installed' >&2
  exit 1
fi
grep -F 'missing or non-root-owned regular file' "$scratch/missing-core.stderr" >/dev/null || {
  echo 'Missing-core rejection was not the verified early payload failure' >&2
  cat "$scratch/missing-core.stderr" >&2
  exit 1
}
docker exec "$container" /bin/sh -c '
  set -eu
  test "$(systemctl show server-connect.service -p LoadState --value)" = not-found
  test ! -e /opt/server-connect
  test ! -e /var/lib/server-connect
  test ! -e /usr/local/bin/server-connect
  mv /root/server-connect/bin/sing-box.qa-hidden /root/server-connect/bin/sing-box
  (cd /root/server-connect && sha256sum --quiet --check checksums.sha256)
'
assert_network_unchanged missing-core "$offline_before"
verify_host_services missing-core

assert_no_offline_fetch missing-core
echo 'OFFLINE_MISSING_CORE_FAIL_CLOSED=PASS (installer NOT applied)'
run_offline first-install --offline
verify_direct_install
# Exercise the INSTALLED manager, not only Go unit tests: its embedded IR
# country estimate snapshot must work inside this --network none guest,
# without a selected profile, a live sing-box process or any routed policy.
docker exec "$container" /usr/local/bin/server-connect --json smart-routing-data |
  python3 -c '
import json,sys
reply=json.load(sys.stdin)
data=reply["data"]
assert reply["ok"] is True
assert data["country"]=="IR" and data["ipv4_count"]==2024 and data["ipv6_count"]==1014
assert data["basis"]=="dbip_lite_country_geolocation_estimate"
assert data["format_and_checksum_verified"] is True
assert data["publisher_signature_verified"] is False
assert data["safe_for_geographic_routing"] is False
assert data["activation_ready"] is False
assert data["license"]=="CC-BY-4.0"
assert data["attribution"].startswith("IP Geolocation by DB-IP")
'
echo 'IR_GEO_ESTIMATE_OFFLINE_INSTALLED_CLI=PASS (DB-IP country estimate only; no route activation)'
assert_network_unchanged first-install "$offline_before"
verify_host_services first-install
# The trusted-base CI workflow still syntax-checks the old fixture pathname.
# This installed-guest negative proves the retired command is actually gone.
docker cp "$root/scripts/qa/host-workload-descendants.sh" "$container:/root/qa-retired-workload.sh"
docker exec "$container" /bin/sh /root/qa-retired-workload.sh
assert_network_unchanged retired-workload-command "$offline_before"
verify_host_services retired-workload-command
docker exec "$container" /bin/rm -f /root/qa-retired-workload.sh
docker exec "$container" /bin/sh -c '
  printf "SC_QA_RETAIN_PROFILE_BYTES\n" > /var/lib/server-connect/profiles/qa-retained
  chmod 0600 /var/lib/server-connect/profiles/qa-retained
'
run_offline reinstall --offline
verify_direct_install
assert_network_unchanged reinstall "$offline_before"
verify_host_services reinstall
# A REAL Linux TUN+VLESS path is exercised only in the disconnected
# disposable guest; the installed product still has no public TUN Apply.
echo 'REAL_TUN_LAB_STAGE=build-guest-generator'
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o "$scratch/tun-config-qa" ./scripts/qa/tun_config_generator.go
test -x "$scratch/tun-config-qa"
docker cp "$scratch/tun-config-qa" "$container:/root/qa-tun-config-qa"
docker cp "$root/scripts/qa/tun-dns-peer.py" "$container:/root/qa-tun-dns-peer.py"
docker cp "$root/scripts/qa/tun-dns-client.py" "$container:/root/qa-tun-dns-client.py"
docker cp "$root/scripts/qa/host-tun-path.sh" "$container:/root/qa-host-tun-path.sh"
docker cp "$root/scripts/qa/tun-guard-unit-lab.sh" "$container:/root/qa-tun-guard-unit-lab.sh"
# Independently check resources omitted from the standard route/rule/link
# digest, in addition to the guest's own explicit cleanup verdict.
tun_netns_before=$(docker exec "$container" /sbin/ip netns list)
tun_nft_before=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
assert_tun_native_cleanup() {
  local phase=$1 current
  if ! current=$(docker exec "$container" /sbin/ip netns list); then
    echo "REAL_TUN_NATIVE_CLEANUP($phase)=FAIL (namespace inventory)" >&2
    exit 1
  fi
  [[ $current == "$tun_netns_before" ]] || {
    echo "REAL_TUN_NATIVE_CLEANUP($phase)=FAIL (named namespace drift)" >&2
    exit 1
  }
  if ! docker exec "$container" /bin/sh -c \
      'test ! -e /sys/class/net/scqaedge0 && test ! -e /sys/class/net/sctunqa0'; then
    echo "REAL_TUN_NATIVE_CLEANUP($phase)=FAIL (VETH or TUN still present)" >&2
    exit 1
  fi
  if ! current=$(docker exec "$container" /usr/sbin/nft -j list ruleset); then
    echo "REAL_TUN_NATIVE_CLEANUP($phase)=FAIL (nftables inspection)" >&2
    exit 1
  fi
  [[ $current == "$tun_nft_before" ]] || {
    echo "REAL_TUN_NATIVE_CLEANUP($phase)=FAIL (nftables drift)" >&2
    exit 1
  }
  assert_network_unchanged "$phase" "$offline_before"
  verify_host_services "$phase"
  echo "REAL_TUN_NATIVE_CLEANUP($phase)=PASS"
}
# A valid negative outcome requires BOTH guard rejection and a clean guest
# teardown. A cleanup error is never the expected guard's exit status.
accept_tun_guard_rejection() {
  local fault=$1 rc=$2 log=$3 expected_guard unexpected scan_rc
  [[ $rc == 1 ]] || return 1
  expected_guard=$([[ $fault == before-hosting ]] && echo pre-hosting || echo post-hosting)
  grep -Fx 'REAL_TUN_NEGATIVE_DIRECT_HOSTING=PASS (native reply works without TUN)' "$log" >/dev/null || return 1
  grep -Fx "REAL_TUN_FOREIGN_HOSTING_OUTAGE_GUARD=REJECTED ($expected_guard)" "$log" >/dev/null || return 1
  grep -Fx 'REAL_TUN_LAB_CLEANUP=PASS (owned namespace, VETH, TUN, nftables and default removed)' "$log" >/dev/null || return 1
  for unexpected in 'REAL_TUN_FOREIGN_HOSTING_OUTAGE=PASS' 'REAL_TUN_LAB_CLEANUP=FAIL'; do
    if grep -F -- "$unexpected" "$log" >/dev/null; then
      return 1
    else
      scan_rc=$?
      [[ $scan_rc == 1 ]] || return 1
    fi
  done
}
echo 'REAL_TUN_LAB_STAGE=execute-guest-path'
regular_tun_log="$scratch/real-tun-domain-path.log"
docker exec "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$regular_tun_log"
grep -Fx 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=PASS (manual HTTP name rules, raw IP intact)' "$regular_tun_log" >/dev/null
assert_tun_native_cleanup real-tun-candidate-cleanup
# The same genuine TUN is started again, but only after an independently
# armed systemd timer. SIGKILL the initiating controller and prove a fresh
# PID1 recovery executor restores native Direct without the parent doing it.
# This is a QA-only feasibility proof, NOT the product Activation Guard.
echo 'REAL_TUN_LAB_STAGE=prearmed-guard-controller-death'
clean_guard_log="$scratch/real-tun-guard-cleanup.log"
docker exec -e SC_QA_TUN_GUARD_LAB=yes "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$clean_guard_log"
grep -Fx 'QA_TUN_GUARD_UNIT_FINAL_STATE=PASS' "$clean_guard_log" >/dev/null
assert_tun_native_cleanup real-tun-independent-deadline-cleanup
# The real timer can restore Direct while a stale systemd unit persists.
# Deliberately mask only the QA recovery unit after its file is removed and
# require a distinct cleanup failure, not an overall PASS for the real TUN.
echo 'REAL_TUN_LAB_STAGE=guard-stale-unit-cleanup-negative'
unit_fault_log="$scratch/real-tun-guard-stale-unit-negative.log"
if docker exec -e SC_QA_TUN_GUARD_LAB=yes \
    -e SC_QA_TUN_GUARD_CLEANUP_FAULT=masked-recovery-unit \
    "$container" /bin/sh /root/qa-host-tun-path.sh >"$unit_fault_log" 2>&1; then
  unit_fault_rc=0
else
  unit_fault_rc=$?
fi
if [[ $unit_fault_rc != 97 ]] ||
   ! grep -Fx 'QA_TUN_GUARD_DEADLINE_RECOVERY=PASS (PID1 stop, exact guest baseline)' "$unit_fault_log" >/dev/null ||
   ! grep -Fx 'QA_TUN_GUARD_UNIT_FINAL_STATE=FAIL' "$unit_fault_log" >/dev/null ||
   ! grep -Fx 'QA_TUN_GUARD_UNIT_CLEANUP=FAIL' "$unit_fault_log" >/dev/null ||
   ! grep -F 'REAL_TUN_LAB_CLEANUP=FAIL (restoration incomplete;' "$unit_fault_log" >/dev/null ||
   grep -F 'QA_TUN_GUARD_UNIT_FINAL_STATE=PASS' "$unit_fault_log" >/dev/null ||
   grep -F 'QA_TUN_GUARD_UNIT_CLEANUP=PASS' "$unit_fault_log" >/dev/null ||
   grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$unit_fault_log" >/dev/null; then
  echo "QA_TUN_GUARD_STALE_UNIT_REJECTION=FAIL (rc=$unit_fault_rc)" >&2
  cat "$unit_fault_log" >&2
  exit 1
fi
# Release only the fixed fixture-injected symlink, then verify all three
# systemd names are absent, independently of the guest cleanup assertions.
docker exec "$container" /bin/sh -c '
  set -eu
  path=/run/systemd/system/scqa-tun-lab-recover.service
  test -L "$path" && test "$(readlink "$path")" = /dev/null
  rm -- "$path"
  systemctl daemon-reload
  for unit in scqa-tun-lab-client.service scqa-tun-lab-recover.service scqa-tun-lab-recover.timer; do
    test ! -e "/run/systemd/system/$unit" && test ! -L "/run/systemd/system/$unit"
    test "$(systemctl show "$unit" -p LoadState --value)" = not-found
    test "$(systemctl show "$unit" -p ActiveState --value)" = inactive
    test -z "$(systemctl show "$unit" -p FragmentPath --value)"
  done
'
assert_tun_native_cleanup real-tun-guard-stale-unit-negative-cleanup
echo 'QA_TUN_GUARD_STALE_UNIT_FALSE_PASS_REJECTED=PASS'
# Real sing-box faults must preserve native Direct HTTP and reject the
# hosting-outage PASS; the guest must prove COMPLETE cleanup independently
# of its intentional test exit 1, and the outer host independently verifies.
for fault in before-hosting after-hosting; do
  negative_log="$scratch/real-tun-$fault-negative.log"
  if docker exec -e "SC_QA_TUN_OUTAGE_FAULT=$fault" \
      "$container" /bin/sh /root/qa-host-tun-path.sh >"$negative_log" 2>&1; then
    negative_rc=0
  else
    negative_rc=$?
  fi
  if ! accept_tun_guard_rejection "$fault" "$negative_rc" "$negative_log"; then
    echo "TUN-loss rejection or cleanup failed validation ($fault; rc=$negative_rc)" >&2
    cat "$negative_log" >&2
    exit 1
  fi
  assert_tun_native_cleanup "real-tun-$fault-rejected-cleanup"
  echo "REAL_TUN_HOSTING_FALSE_PASS_REJECTED=PASS (fault=$fault)"
done
# Discriminating cleanup-failure test: deliberately retain ONLY our disposable
# namespace after genuine guard rejection. Both expected guard markers and
# the native hosting reply must still occur, but acceptance MUST refuse it.
cleanup_log="$scratch/real-tun-cleanup-failure-negative.log"
if docker exec -e SC_QA_TUN_OUTAGE_FAULT=before-hosting \
    -e SC_QA_TUN_CLEANUP_FAULT=retain-namespace \
    "$container" /bin/sh /root/qa-host-tun-path.sh >"$cleanup_log" 2>&1; then
  cleanup_rc=0
else
  cleanup_rc=$?
fi
[[ $cleanup_rc == 97 ]] &&
  grep -Fx 'REAL_TUN_NEGATIVE_DIRECT_HOSTING=PASS (native reply works without TUN)' "$cleanup_log" >/dev/null &&
  grep -Fx 'REAL_TUN_FOREIGN_HOSTING_OUTAGE_GUARD=REJECTED (pre-hosting)' "$cleanup_log" >/dev/null &&
  grep -Fx 'REAL_TUN_LAB_CLEANUP=FAIL (owned namespace still present)' "$cleanup_log" >/dev/null || {
    echo "Injected cleanup failure did not produce expected guard + distinct cleanup failure (rc=$cleanup_rc)" >&2
    cat "$cleanup_log" >&2
    exit 1
  }
if accept_tun_guard_rejection before-hosting "$cleanup_rc" "$cleanup_log"; then
  echo 'Cleanup failure was accepted as a valid negative test' >&2
  exit 1
fi
if grep -F 'REAL_TUN_FOREIGN_HOSTING_OUTAGE=PASS' "$cleanup_log" >/dev/null ||
   grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$cleanup_log" >/dev/null; then
  echo 'Injected cleanup failure emitted a forbidden success marker' >&2
  cat "$cleanup_log" >&2
  exit 1
fi
if ! docker exec "$container" /sbin/ip netns list | awk '$1 == "scqapeer" { found=1 } END { exit !found }'; then
  echo 'Injected cleanup fault did not leave its expected owned namespace' >&2
  exit 1
fi
# Recovery touches the single known QA namespace in this already-disposable
# guest. Never ignore an ambiguous deletion or claim cleanup before recheck.
docker exec "$container" /sbin/ip netns del scqapeer
assert_tun_native_cleanup real-tun-injected-cleanup-recovery
echo 'REAL_TUN_CLEANUP_FAILURE_REJECTED=PASS (guest cleanup failure != expected TUN rejection)'
docker exec "$container" /bin/rm -f /root/qa-tun-config-qa /root/qa-host-tun-path.sh /root/qa-tun-guard-unit-lab.sh
# Product code + installed inactive-by-default independent recovery units.
# The actual RPDB rule is added ONLY in the verified disconnected guest.
docker cp "$root/scripts/qa/host-product-guard-trial.sh" "$container:/root/qa-product-guard-trial.sh"
docker exec "$container" /bin/sh /root/qa-product-guard-trial.sh
assert_network_unchanged product-guard-recovered "$offline_before"
verify_host_services product-guard-recovered
echo '=== Installed real VLESS Proxy Only and owned offline update ==='
docker cp "$root/scripts/qa/host-proxy-only.sh" "$container:/root/qa-proxy-only.sh"
docker cp "$root/scripts/qa/host-apt-only.sh" "$container:/root/qa-apt-only.sh"
docker exec "$container" /bin/sh /root/qa-proxy-only.sh setup
docker exec "$container" /bin/sh /root/qa-apt-only.sh setup
# Do not discard route invariants to make the FPM fixture start: verify the
# full observed route/rule/link snapshot rather than brittle one-line CLI text.
assert_network_unchanged wordpress-preflight "$offline_before"
docker cp "$root/scripts/qa/host-wordpress-fpm.sh" "$container:/root/qa-wp-fpm.sh"
docker cp "$root/scripts/qa/wp-nonce-origin.py" "$container:/root/qa-wp-nonce-origin.py"
docker cp "$root/scripts/qa/wp-fcgi-check.py" "$container:/root/qa-wp-fcgi-check.py"
docker cp "$root/scripts/qa/wp-proxy-prepend.py" "$container:/root/qa-wp-proxy-prepend.py"
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh setup
docker exec "$container" /bin/sh /root/qa-apt-only.sh positive initial
assert_network_unchanged installed-vless-proxy "$offline_before"
verify_host_services installed-vless-proxy
docker exec "$container" /bin/sh /root/qa-proxy-only.sh upstream-failure
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh upstream-failure initial
assert_network_unchanged vless-upstream-failure "$offline_before"
verify_host_services vless-upstream-failure
docker exec "$container" /bin/sh /root/qa-proxy-only.sh core-failure
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh core-failure
assert_network_unchanged proxy-core-failure "$offline_before"
verify_host_services proxy-core-failure

original_link=$(docker exec "$container" readlink /opt/server-connect/current)
original_manager=$(docker exec "$container" sha256sum \
  /opt/server-connect/current/bin/server-connect | cut -d' ' -f1)
run_offline update-verify --verify-only /root/server-connect-update
assert_network_unchanged update-verify "$offline_before"
verify_host_services update-verify
run_active_offline update-distinct /root/server-connect-update
updated_link=$(docker exec "$container" readlink /opt/server-connect/current)
updated_manager=$(docker exec "$container" sha256sum \
  /opt/server-connect/current/bin/server-connect | cut -d' ' -f1)
[[ $original_link != "$updated_link" && $original_manager != "$updated_manager" ]] || {
  echo 'Offline update did not change the installed manager artifact' >&2
  exit 1
}
docker exec "$container" /bin/sh /root/qa-proxy-only.sh positive
docker exec "$container" /bin/sh /root/qa-apt-only.sh positive after-upgrade
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh positive after-upgrade
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh http-proxy-auth after-upgrade
docker exec "$container" /bin/sh /root/qa-proxy-only.sh upstream-failure upstream-after-upgrade
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh upstream-failure after-upgrade
assert_network_unchanged update-distinct "$offline_before"
verify_host_services update-distinct
echo 'INSTALLED_DISTINCT_BINARY_UPDATE=PASS (same-source QA builds)'

# The third binary is different and carries a deliberately broken service
# ExecStart. It must fail after switching and restore the ACTIVE prior proxy.
bad_release=$(docker exec "$container" /bin/sh -c '
  set -eu
  cd /root/server-connect-bad-update
  hash=$(sha256sum bin/server-connect bin/sing-box |
    cut -d" " -f1 | sha256sum | cut -c 1-16)
  printf "releases/0.1.0-dev-%s" "$hash"
')
[[ $bad_release != "$updated_link" && $bad_release != "$original_link" ]] || {
  echo 'Broken QA update did not have a distinct release identity' >&2
  exit 1
}
original_unit_digest=$(docker exec "$container" sha256sum \
  /etc/systemd/system/server-connect.service | cut -d' ' -f1)
run_active_offline_expect_failure update-broken-unit /root/server-connect-bad-update
grep -F 'candidate failed; attempting owned lifecycle rollback' \
  "$scratch/update-broken-unit.stdout" >/dev/null || {
  echo 'Broken update did not enter post-switch owned rollback' >&2
  cat "$scratch/update-broken-unit.stdout" >&2
  exit 1
}
grep -F 'previous owned service state restored; profiles retained' \
  "$scratch/update-broken-unit.stdout" >/dev/null || {
  echo 'Broken update did not confirm prior service restoration' >&2
  cat "$scratch/update-broken-unit.stdout" >&2
  exit 1
}
[[ $(docker exec "$container" readlink /opt/server-connect/current) == "$updated_link" ]]
[[ $(docker exec "$container" sha256sum \
  /opt/server-connect/current/bin/server-connect | cut -d' ' -f1) == "$updated_manager" ]]
[[ $(docker exec "$container" sha256sum \
  /etc/systemd/system/server-connect.service | cut -d' ' -f1) == "$original_unit_digest" ]]
docker exec "$container" test ! -e "/opt/server-connect/$bad_release"
docker exec "$container" /bin/sh /root/qa-proxy-only.sh positive
docker exec "$container" /bin/sh /root/qa-apt-only.sh positive after-rollback
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh positive after-rollback
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh http-proxy-auth after-rollback
docker exec "$container" /bin/sh /root/qa-proxy-only.sh upstream-failure upstream-after-rollback
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh upstream-failure after-rollback
assert_network_unchanged update-rollback "$offline_before"
verify_host_services update-rollback
echo 'INSTALLED_FAILED_UPDATE_ROLLBACK=PASS (active previous service restored)'

# REQUIRED-02: the separate acceptance injects a genuine filesystem
# restoration failure into the original installer's rollback_candidate().
# It verifies retained prior-unit hashes and performs controlled guest repair.
bash scripts/qa/test-real-rollback-failure.sh \
 "$container" "$bad_release" "$updated_link" "$scratch"
docker exec "$container" /bin/sh /root/qa-proxy-only.sh positive
assert_network_unchanged update-real-restore-fault "$offline_before"
verify_host_services update-real-restore-fault

docker exec "$container" /bin/sh /root/qa-proxy-only.sh disconnect
docker exec "$container" /bin/sh /root/qa-apt-only.sh negative disconnected
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh negative-disconnected
docker exec "$container" /bin/sh /root/qa-apt-only.sh verify-host-policy
assert_network_unchanged disconnect "$offline_before"
verify_host_services disconnect
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh cleanup
run_offline uninstall --uninstall
verify_clean_uninstall
assert_network_unchanged uninstall "$offline_before"
verify_host_services uninstall

echo 'DISCONNECTED_OFFLINE_CYCLE=PASS'
echo 'LIMITATION: WordPress/PHP-FPM verification used disconnected guest loopback and QA-only WP_PROXY_*; real hosting/foreign field acceptance is NOT_RUN'

echo '=== Independent activation-deadline feasibility in disconnected guest (QA ONLY) ==='
# Fixed dummy links and policy exist only inside the disposable Docker
# --network none namespace. systemd PID1 independently triggers rollback
# after a killed child. This is NOT a product Activation Guard, a real VPN,
# persistent reboot recovery or authorization to route a physical host.
docker cp "$root/scripts/qa/host-activation-guard.sh" \
  "$container:/root/qa-activation-guard.sh"
docker cp "$root/scripts/qa/activation-guard-inspect.py" \
  "$container:/root/qa-activation-guard-inspect.py"
# Run a distinct independently armed timer for each precise mutation stage.
# This makes interrupted partial apply an observable negative/positive gate,
# rather than assuming the entire route/rule transaction was applied first.
for guard_stage in link route rule; do
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh arm
  if crash_output=$(docker exec "$container" /bin/sh /root/qa-activation-guard.sh crash-controller "$guard_stage" 2>&1); then
    echo "Disposable controller unexpectedly survived SIGKILL at $guard_stage" >&2
    exit 1
  else
    killed_exit=$?
    printf '%s\n' "$crash_output"
    [[ $killed_exit == 137 ]] || {
      echo "Unexpected controller exit at $guard_stage (exit=$killed_exit)" >&2
      exit 1
    }
    [[ $crash_output == *"ISOLATED_ACTIVATION_CONTROLLER_BOUNDARY=$guard_stage"* ]] || {
      echo "No verified controller boundary witness for $guard_stage" >&2
      exit 1
    }
  fi
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh await-recovery "$guard_stage"
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh cleanup
  assert_network_unchanged "isolated-activation-guard-$guard_stage" "$offline_before"
  verify_host_services "isolated-activation-guard-$guard_stage"
  echo "ISOLATED_ACTIVATION_GUARD_STAGE_${guard_stage}=PASS"
done
# Three independent negative Linux cases: a foreign address, a foreign
# route in another table and a foreign interface altname are injected AFTER
# SIGKILL. Each new systemd cycle must be fresh (monotonic timer/service
# timestamps + service invocation identity); retained prior failure status
# must not turn a second run green before its own eight-second deadline.
# Only controlled disposable QA cleanup removes the surviving foreign state.
for conflict_kind in address other-table-route altname; do
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh arm
  if crash_output=$(docker exec "$container" /bin/sh /root/qa-activation-guard.sh crash-controller link 2>&1); then
    echo "Negative-test controller unexpectedly survived SIGKILL ($conflict_kind)" >&2
    exit 1
  else
    killed_exit=$?
    printf '%s\n' "$crash_output"
    [[ $killed_exit == 137 && $crash_output == *"ISOLATED_ACTIVATION_CONTROLLER_BOUNDARY=link"* ]] || {
      echo "Negative-test controller SIGKILL witness missing ($conflict_kind)" >&2
      exit 1
    }
  fi
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh inject-conflict "$conflict_kind"
  # The real verifier must NOT accept a stale negative service Result before
  # this cycle's deadline. This check uses the same evidence predicate as
  # the eventual positive refusal assertion.
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh assert-no-stale-refusal "$conflict_kind"
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh await-refusal "$conflict_kind"
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh cleanup-refusal "$conflict_kind"
  docker exec "$container" /bin/sh /root/qa-activation-guard.sh cleanup
  assert_network_unchanged "isolated-guard-foreign-$conflict_kind" "$offline_before"
  verify_host_services "isolated-guard-foreign-$conflict_kind"
  echo "ISOLATED_ACTIVATION_GUARD_FOREIGN_${conflict_kind}=PASS"
done
echo 'ISOLATED_ACTIVATION_GUARD_FEASIBILITY=PASS (not product guard/reboot proof)'

echo '=== Isolated LOOPBACK acquisition followed by the SAME real installer ==='
# Docker --network none remains active; loopback was enabled for the existing
# SSH/HTTP fixtures and remains the only networking available.
online_before=$(network_digest)
docker exec "$container" /bin/sh -c 'mkdir -m 0700 /root/qa-http'
docker cp "$bundle" "$container:/root/qa-http/bundle.tar.gz"
docker exec -d "$container" /bin/sh -c \
  'exec python3 -m http.server 19179 --bind 127.0.0.1 --directory /root/qa-http >/root/qa-http.log 2>&1'
web_ready=no
for attempt in $(seq 1 20); do
  if docker exec "$container" curl -q -f -s -I --max-time 3 --noproxy '*' \
     http://127.0.0.1:19179/bundle.tar.gz >/dev/null; then
    web_ready=yes
    break
  fi
  sleep 1
done
[[ $web_ready == yes ]] || { echo 'Local-loopback QA server unavailable' >&2; exit 1; }
docker exec "$container" /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/sc-qa-bootstrap.sh \
  --archive-url http://localhost:19179/bundle.tar.gz --sha256 "$digest"
verify_direct_install
assert_network_unchanged loopback-online-install "$online_before"
verify_host_services loopback-online-install
run_offline online-then-uninstall --uninstall
verify_clean_uninstall
assert_network_unchanged loopback-online-uninstall "$online_before"
verify_host_services loopback-online-uninstall

docker exec "$container" /bin/sh -c \
  'test -z "$(find /root -maxdepth 1 -name ".server-connect-bootstrap.*" -print)"'
echo 'LOCAL_LOOPBACK_ONLINE_INSTALL=PASS'

# Destructive fixture tests come LAST: nothing after this block requires the
# two independent guest-loopback services to remain available. A stopped
# service must never be described as a successfully completed lifecycle probe.
echo '=== Negative fixture acceptance (disposable guest only) ==='
# Stop HTTP first while SSH is still active: a rejected probe must be
# attributable to the stopped HTTP unit, not a previously failed SSH unit.
docker exec "$container" systemctl stop sc-qa-web.service
docker exec "$container" /bin/true
docker exec "$container" systemctl is-active --quiet sc-qa-ssh.service
if docker exec "$container" curl -q --fail --silent --show-error --max-time 3 \
  --noproxy '*' http://127.0.0.1:19180/index.html \
  >"$scratch/stopped-http.stdout" 2>"$scratch/stopped-http.stderr"; then
  echo 'ISOLATED_HTTP_UNREACHABLE=FAIL (GET unexpectedly succeeded)' >&2
  exit 1
fi
if docker exec "$container" /bin/sh /root/qa-host-coexistence.sh probe \
  >"$scratch/stopped-http-probe.stdout" 2>"$scratch/stopped-http-probe.stderr"; then
  echo 'ISOLATED_HTTP_STOPPED=FAIL (probe accepted stopped HTTP)' >&2
  exit 1
fi
echo 'ISOLATED_HTTP_STOPPED=PASS'

# Stop SSH next: the probe tests SSH service state BEFORE the HTTP fixture,
# so an unrelated already-stopped HTTP service cannot mask an SSH false PASS.
docker exec "$container" systemctl stop sc-qa-ssh.service
docker exec "$container" /bin/true
if docker exec "$container" /bin/sh /root/qa-host-coexistence.sh probe \
  >"$scratch/stopped-ssh.stdout" 2>"$scratch/stopped-ssh.stderr"; then
  echo 'ISOLATED_SSH_STOPPED=FAIL (probe accepted stopped SSH)' >&2
  exit 1
fi
echo 'ISOLATED_SSH_STOPPED=PASS'
echo 'LIMITATION: QA bundle is digest-matched but NOT a publisher-authenticated public release'
# A separate disconnected guest exercises a persistent /var/lib QA journal
# and independently enabled boot service across two real Docker restarts.
# Docker restart is NOT physical host reboot and resets its network namespace;
# the positive path is a deliberate no-op observation, not route rollback.
bash scripts/qa/test-activation-boot-qa.sh "$image" "$container"
echo 'LIMITATION: guest-loopback SSH/HTTP checks do not prove external SSH/aaPanel, foreign VPN reachability, reboot or field safety'
