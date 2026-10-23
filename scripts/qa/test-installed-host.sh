#!/usr/bin/env bash
# Exact QA-only lifecycle in an ephemeral Debian 13 systemd container.
# All installation paths run with Docker --network none. NEVER run on a
# production host; public publisher authenticity is out of scope.
set -euo pipefail
umask 077
# A privileged container needs an already disposable, credential-free runner.
# Do not allow an operator to accidentally invoke it on a production server.
if [[ $(printenv GITHUB_ACTIONS || true) != true || $(printenv CI || true) != true ]]; then
  echo 'Only ephemeral GitHub Actions runners may execute this QA harness' >&2
  exit 2
fi
if [[ $# != 2 || ! -f $1 || ! -f $2 ]]; then
  echo 'Usage: test-installed-host.sh BUNDLE.tar.gz BOOTSTRAP.sh' >&2
  exit 2
fi
bundle=$(realpath -- "$1")
bootstrap=$(realpath -- "$2")
digest=$(sha256sum "$bundle" | cut -d' ' -f1)
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$root"
tmpdir=/tmp
if [[ -n $(printenv RUNNER_TEMP || true) ]]; then tmpdir=$(printenv RUNNER_TEMP); fi
scratch=$(mktemp -d "$tmpdir/server-connect-hostqa.XXXXXXXX")
suffix=$(basename "$scratch" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')
container="sc-hostqa-$suffix"
image="sc-hostqa:$suffix"
started=no
image_built=no
cleanup() {
  original_rc=$?
  trap - EXIT
  cleanup_failed=no
  if [[ $started == yes ]]; then
    if (( original_rc != 0 )); then
      echo 'Disposable systemd diagnostics (failure only):' >&2
      docker logs --tail 100 "$container" >&2 ||
        echo 'Warning: could not collect container logs' >&2
    fi
    if ! docker rm -f "$container" >/dev/null; then
      echo "QA cleanup failed: docker container $container" >&2
      cleanup_failed=yes
    fi
  fi
  if [[ $image_built == yes ]]; then
    if ! docker image rm "$image" >/dev/null; then
      echo "QA cleanup failed: docker image $image" >&2
      cleanup_failed=yes
    fi
  fi
  if ! rm -rf -- "$scratch"; then
    echo 'QA cleanup failed: disposable scratch directory' >&2
    cleanup_failed=yes
  fi
  # Preserve the original test failure; never silently pass failed cleanup.
  if [[ $original_rc -eq 0 && $cleanup_failed == yes ]]; then original_rc=1; fi
  exit "$original_rc"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '=== Disposable Debian 13 preparation (network permitted BEFORE isolation) ==='
docker build --pull -f scripts/qa/Dockerfile.host-systemd -t "$image" scripts/qa
image_built=yes
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
docker cp "$root/scripts/qa/host-qa-assertions.sh" "$container:/root/qa-host-assertions.sh"

docker cp "$bundle" "$container:/root/sc-qa-bundle.tar.gz"
docker cp "$bootstrap" "$container:/root/sc-qa-bootstrap.sh"
docker exec "$container" /bin/sh -c '
  set -eu
  mkdir -m 0700 /root/server-connect /root/qa-strace
  tar -xzf /root/sc-qa-bundle.tar.gz -C /root/server-connect \
    --strip-components=1 --no-same-owner --no-same-permissions
  test "$(stat -c %u /root/server-connect/install.sh)" = 0
'
[[ $(docker exec "$container" sha256sum /root/sc-qa-bundle.tar.gz | cut -d' ' -f1) == "$digest" ]]
offline_before=$(network_digest)

run_offline() {
  label=$1
  action=$2
  echo "=== Disconnected offline $label ==="
  docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
    -e trace=%network,%process \
    -o "/root/qa-strace/$label" /usr/bin/env -i \
    HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh /root/server-connect/install.sh "$action"
  assert_no_offline_fetch "$label"
}
assert_no_offline_fetch() {
  label=$1
  # Missing/empty/unreadable child traces, scanner errors and forbidden
  # execve/execveat or IPv4/IPv6 network attempts MUST all fail acceptance.
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
    test "$(stat -c %a /var/lib/server-connect)" = 700
    test "$(stat -c %a /var/lib/server-connect/profiles)" = 700
    test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
  '
}

run_offline verify-only --verify-only
assert_network_unchanged verify-only "$offline_before"
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

assert_no_offline_fetch missing-core
echo 'OFFLINE_MISSING_CORE_FAIL_CLOSED=PASS (installer NOT applied)'
run_offline first-install --offline
verify_direct_install
assert_network_unchanged first-install "$offline_before"
docker exec "$container" /bin/sh -c '
  printf "SC_QA_RETAIN_PROFILE_BYTES\n" > /var/lib/server-connect/profiles/qa-retained
  chmod 0600 /var/lib/server-connect/profiles/qa-retained
'
run_offline reinstall --offline
verify_direct_install
assert_network_unchanged reinstall "$offline_before"
run_offline uninstall --uninstall
verify_clean_uninstall
assert_network_unchanged uninstall "$offline_before"

echo 'DISCONNECTED_OFFLINE_CYCLE=PASS'

echo '=== Isolated LOOPBACK acquisition followed by the SAME real installer ==='
# Docker --network none remains active; only this container loopback is enabled.
docker exec "$container" /sbin/ip link set lo up
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
run_offline online-then-uninstall --uninstall
verify_clean_uninstall
assert_network_unchanged loopback-online-uninstall "$online_before"

docker exec "$container" /bin/sh -c \
  'test -z "$(find /root -maxdepth 1 -name ".server-connect-bootstrap.*" -print)"'
echo 'LOCAL_LOOPBACK_ONLINE_INSTALL=PASS'
echo 'LIMITATION: QA bundle is digest-matched but NOT a publisher-authenticated public release'
echo 'LIMITATION: Docker systemd tests do not prove SSH/aaPanel coexistence, foreign VPN reachability, reboot or field safety'
