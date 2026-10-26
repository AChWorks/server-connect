#!/usr/bin/env bash
# Connected minimal-Debian systemd online-to-installed QA only. This runs
# exclusively in a disposable GitHub-hosted Docker guest, never on a live host.
# It proves native prerequisite acquisition and the shared installer end to
# end using a separately SHA-256-verified local QA archive. It is NOT a
# publisher-authenticated online distribution or real foreign VPN acceptance.
set -euo pipefail
umask 077
if [[ $(printenv GITHUB_ACTIONS || true) != true || $(printenv CI || true) != true ]]; then
  echo 'Connected privileged QA requires an ephemeral GitHub Actions runner' >&2
  exit 2
fi
if [[ $# != 2 || ! -f $1 || ! -f $2 ]]; then
  echo 'Usage: test-online-minimal-host.sh QA-BUNDLE.tar.gz BOOTSTRAP.sh' >&2
  exit 2
fi
bundle=$(realpath -- "$1")
bootstrap=$(realpath -- "$2")
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
digest=$(sha256sum "$bundle" | cut -d' ' -f1)
cd "$root"
scratch_root=/tmp
if [[ -n $(printenv RUNNER_TEMP || true) ]]; then scratch_root=$(printenv RUNNER_TEMP); fi
scratch=$(mktemp -d "$scratch_root/sc-online-minimal.XXXXXXXX")
suffix=$(basename "$scratch" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')
container="sc-online-minimal-$suffix"
image="sc-online-minimal:$suffix"
# Cleanup inspects the actual exact task-owned Docker names, including
# container-created/start-failed and image-tagged/build-failed cases.
source "$root/scripts/qa/docker-owned-cleanup.sh"
started=no
cleanup() {
  original_rc=$?
  trap - EXIT
  if [[ $started == yes && $original_rc -ne 0 ]]; then
    echo 'Connected disposable Debian systemd diagnostics (failure only):' >&2
    docker logs --tail 100 "$container" >&2 || true
  fi
  if ! sc_qa_cleanup_owned_docker "$container" "$image" "$scratch"; then
    if [[ $original_rc -eq 0 ]]; then original_rc=1; fi
  fi
  exit "$original_rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '=== Build native Debian 13 minimal systemd fixture while runner is disposable ==='
docker build --pull -f scripts/qa/Dockerfile.online-minimal-systemd \
  -t "$image" scripts/qa
# Bridge networking is required ONLY for the guest's native Debian APT
# prerequisite acquisition. No host networking, host files, credentials,
# custom APT repositories or external VPN endpoints are attached.
docker run -d --name "$container" --hostname sc-online-qa \
  --network bridge --privileged --cgroupns=private \
  --tmpfs /run:rw,nosuid,nodev,mode=755 \
  --tmpfs /run/lock:rw,nosuid,nodev,mode=755 \
  "$image" >/dev/null
started=yes
[[ $(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container") == bridge ]]
ready=no
for attempt in $(seq 1 30); do
  if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
    echo 'Connected disposable Debian systemd exited prematurely' >&2
    exit 1
  fi
  if docker exec "$container" /bin/sh -c \
    'test -d /run/systemd/system && systemctl show server-connect.service -p LoadState --value >/dev/null'; then
    ready=yes
    break
  fi
  sleep 2
done
[[ $ready == yes ]] || { echo 'Connected disposable systemd not ready' >&2; exit 1; }
docker exec "$container" /bin/sh -c '
  set -eu
  . /etc/os-release
  test "$ID" = debian && test "$VERSION_ID" = 13
  test "$(cat /proc/1/comm)" = systemd
  test "$(uname -m)" = x86_64
  test "$(systemctl show server-connect.service -p LoadState --value)" = not-found
  ! command -v python3
  ! command -v curl
  test ! -e /opt/server-connect
  test ! -e /var/lib/server-connect
  test ! -e /usr/local/bin/server-connect
  test ! -e /etc/systemd/system/server-connect.service
  test ! -e /etc/systemd/system/server-connect-activation-recover.service
  test ! -e /etc/systemd/system/server-connect-activation-recover.timer
'
# systemd service-credential mounts must propagate within this guest's own
# /run tmpfs. No host mount is changed or bound into the guest.
docker exec "$container" /bin/sh -c '
  set -eu
  mount --make-rshared /run
  test "$(findmnt -n -o PROPAGATION -T /run)" = shared
'
capture_network() {
  docker exec "$container" /bin/sh -ec '
    /usr/sbin/ip -j address show
    /usr/sbin/ip -j -4 route show table all
    /usr/sbin/ip -j -6 route show table all
    /usr/sbin/ip -j -4 rule show
    /usr/sbin/ip -j -6 rule show
    cat /etc/resolv.conf
  '
}
connected_baseline=$(capture_network)

# Bootstrap must acquire its OWN Python/curl tools; busybox is fixture-only
# and serves the previously verified bundle strictly over guest loopback.
docker exec "$container" /bin/sh -c 'mkdir -m 0700 /root/qa-http'
docker cp "$bundle" "$container:/root/qa-http/bundle.tar.gz"
docker cp "$bootstrap" "$container:/root/sc-qa-bootstrap.sh"
docker exec "$container" /bin/sh -c '
  set -eu
  printf "SC_ONLINE_LOCAL_FIXTURE\n" > /root/qa-http/probe.txt
  test -f /root/qa-http/bundle.tar.gz
  ! command -v curl
  ! command -v python3
'
[[ $(docker exec "$container" /usr/bin/sha256sum /root/qa-http/bundle.tar.gz | cut -d' ' -f1) == "$digest" ]]
docker exec -d "$container" /bin/sh -c \
  'exec /usr/bin/busybox httpd -f -p 127.0.0.1:19179 -h /root/qa-http >/root/qa-http.log 2>&1'
web_ready=no
for attempt in $(seq 1 20); do
  if docker exec "$container" /usr/bin/busybox wget -q -O /dev/null \
    http://127.0.0.1:19179/probe.txt >/dev/null 2>&1; then
    web_ready=yes
    break
  fi
  sleep 1
done
[[ $web_ready == yes ]] || { echo 'Guest-only QA HTTP origin unavailable' >&2; exit 1; }

echo '=== Install genuine QA artifact from missing-tools Debian 13 via native APT and shared installer ==='
docker exec "$container" /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/sc-qa-bootstrap.sh \
  --archive-url http://localhost:19179/bundle.tar.gz --sha256 "$digest"

# No partial success: assert actual installed manager, immutable release
# identity, Direct state, and complete network+DNS preservation.
docker exec "$container" /bin/sh -c '
  set -eu
  test "$(command -v curl)" = /usr/bin/curl
  test "$(command -v python3)" = /usr/bin/python3
  test "$(cat /opt/server-connect/.owner)" = AChWorks/server-connect
  test "$(readlink /usr/local/bin/server-connect)" = /opt/server-connect/current/bin/server-connect
  test "$(systemctl show server-connect.service -p LoadState --value)" = loaded
  test "$(systemctl show server-connect.service -p ActiveState --value)" = inactive
  test "$(systemctl is-enabled server-connect.service)" = disabled
  test "$(systemctl show server-connect-activation-recover.timer -p LoadState --value)" = loaded
  test "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled
  test "$(systemctl show server-connect-activation-recover.service -p LoadState --value)" = loaded
  /usr/local/bin/server-connect version --json
  test -z "$(find /root -maxdepth 1 -name ".server-connect-bootstrap.*" -print)"
'
[[ $(capture_network) == "$connected_baseline" ]] || {
  echo 'Connected host routes, rules, links or DNS changed during online installation' >&2
  exit 1
}
echo 'CONNECTED_MINIMAL_ONLINE_INSTALL=PASS (missing Python/curl, real APT, shared installer, Direct unchanged)'

# Disconnect external networking BEFORE testing offline uninstall. This is a
# deliberate Docker guest network transition, not a product routing change.
docker network disconnect bridge "$container"
[[ $(docker inspect --format '{{len .NetworkSettings.Networks}}' "$container") == 0 ]]
disconnected_baseline=$(capture_network)
docker exec "$container" /bin/sh -c '
  set -eu
  mkdir -m 0700 /root/server-connect
  tar -xzf /root/qa-http/bundle.tar.gz -C /root/server-connect \
    --strip-components=1 --no-same-owner --no-same-permissions
  (cd /root/server-connect && sha256sum --quiet --check checksums.sha256)
  printf "SC_ONLINE_MINIMAL_PROFILE_RETAINED\n" > /var/lib/server-connect/profiles/qa-retained
  chmod 0600 /var/lib/server-connect/profiles/qa-retained
'
docker exec "$container" /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/server-connect/install.sh --uninstall
docker exec "$container" /bin/sh -c '
  set -eu
  test "$(systemctl show server-connect.service -p LoadState --value)" = not-found
  test ! -e /opt/server-connect
  test ! -e /usr/local/bin/server-connect
  test ! -e /etc/systemd/system/server-connect.service
  test ! -e /etc/systemd/system/server-connect-activation-recover.service
  test ! -e /etc/systemd/system/server-connect-activation-recover.timer
  test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_ONLINE_MINIMAL_PROFILE_RETAINED
  test "$(stat -c %a /var/lib/server-connect/profiles)" = 700
  command -v curl
  command -v python3
'
[[ $(capture_network) == "$disconnected_baseline" ]] || {
  echo 'Disconnected host routes, rules, links or DNS changed during offline uninstall' >&2
  exit 1
}
echo 'DISCONNECTED_MINIMAL_ONLINE_TO_OFFLINE_UNINSTALL=PASS (profile retained, Direct preserved)'
echo 'LIMITATION: guest uses original Debian APT mirrors and fixture loopback, not publisher-authenticated public release or foreign VPN'
