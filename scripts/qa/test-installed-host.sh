#!/usr/bin/env bash
# Exact QA-only lifecycle in ephemeral Debian 12/13 systemd containers.
# Debian13 retains the full native product/guard experiment. Debian12 proves
# installed Direct/Proxy Only and legacy native-Apply refusal, plus a separate
# disconnected real-Core native TUN DNS packet lab (not product Apply).
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
qa_version=${SC_QA_DEBIAN_VERSION:-13}
case "$qa_version" in
  12) qa_suite=bookworm ;;
  13) qa_suite=trixie ;;
  *) echo 'QA target must be Debian 12 or Debian 13' >&2; exit 2 ;;
esac
export SC_QA_DEBIAN_VERSION=$qa_version
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
# Fixture trust is shared with Go tests, but its deliberately public private
# key must never enter any ordinary installable archive, including the binary.
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$bundle" "$update_bundle" "$bad_update_bundle" <<'PYTLSARCHIVE'
import base64, pathlib, sys, tarfile
key = pathlib.Path('internal/sc/testdata/smart-health-tls/qa-server-key.pem').read_bytes().strip()
der = base64.b64decode(b''.join(line for line in key.splitlines() if not line.startswith(b'-----')), validate=True)
assert key.startswith(b'-----BEGIN PRIVATE KEY-----') and len(der) > 100
needles = (key, der)
overlap = max(map(len, needles)) - 1
fixture_names = {path.name for path in pathlib.Path('internal/sc/testdata/smart-health-tls').glob('*.pem')}
for archive in sys.argv[1:]:
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            assert 'smart-health-tls' not in member.name and pathlib.PurePosixPath(member.name).name not in fixture_names, \
                'QA TLS fixture entered installation payload'
            if not member.isfile():
                continue
            with source.extractfile(member) as handle:
                tail = b''
                while True:
                    block = handle.read(65536)
                    if not block:
                        break
                    data = tail + block
                    assert not any(needle in data for needle in needles), 'QA private key entered an installation payload'
                    tail = data[-overlap:]
print('SMART_HEALTH_QA_KEYS_EXCLUDED_FROM_INSTALL_ARCHIVES=PASS')
PYTLSARCHIVE
# Exercise the actual guest APT negative classifier with disposable fakes
# before any privileged Docker work; this is not a substitute for real APT.
bash scripts/qa/test-host-apt-only.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-package-targets.py
sh -n scripts/qa/host-bundle-target-refusal.sh
# Run candidate-version WordPress fail-closed regressions inside this script,
# since pull_request_target uses the trusted main workflow definition.
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-wp-fcgi-check.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-wp-proxy-prepend.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-tun-dns-wire.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-tun-native-apps.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-tun-payload-wire.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-tun-ipv6-wire.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-tun-wp-check.py
sh -n scripts/qa/tun-wordpress-fpm.sh
# The guard feasibility probe must be strictly guest-local and must reject
# ambiguous kernel identities before the privileged disconnected guest runs.
sh -n scripts/qa/host-activation-guard.sh
sh -n scripts/qa/host-tun-path.sh
sh -n scripts/qa/host-native-dns-policy.sh
sh -n scripts/qa/host-native-docker-recovery.sh
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

# Compile only on the build host. Privileged native tests execute solely in
# the explicitly gated disconnected guest below, never on the runner/Dev.
# One candidate-built test executable serves the Debian12/13 native Docker
# crash-recovery kernel fixture; Debian13 also runs the existing nft CAS lab.
CGO_ENABLED=0 go test -c -o "$scratch/qa-native-nft-cas-test" ./internal/sc

printf '=== Disposable Debian %s preparation (network permitted BEFORE isolation) ===\n' "$qa_version"
docker build --pull -f scripts/qa/Dockerfile.host-systemd \
  --build-arg "DEBIAN_SUITE=$qa_suite" \
  --build-arg "SC_QA_DEBIAN_VERSION=$qa_version" -t "$image" scripts/qa
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
docker exec -e "SC_QA_DEBIAN_VERSION=$qa_version" "$container" /bin/sh -c '
  set -eu
  . /etc/os-release
  test "$ID" = debian && test "$VERSION_ID" = "$SC_QA_DEBIAN_VERSION"
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
if [[ $qa_version == 13 ]]; then

# Run before foreign nft fixtures or TUN topology exist. This proves the
# kernel generation-conditioned deletion primitive, including negative CAS
# and ACK-loss cases, without giving the test access to a routed host.
native_nft_network_before=$(network_digest)
native_nft_before=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
docker cp "$scratch/qa-native-nft-cas-test" "$container:/root/qa-native-nft-cas-test"
native_nft_log="$scratch/native-nft-cas.log"
docker exec -e SC_TEST_NATIVE_NFT_CAS=disconnected-systemd "$container" \
  /root/qa-native-nft-cas-test -test.run='^TestNativeNFTTableCAS$' -test.v -test.timeout=90s |
  tee "$native_nft_log"
for marker in EXACT_DELETE FOREIGN_CHILD DISJOINT REPLACEMENT ACK_LOSS CLEANUP; do
  grep -Fx "NATIVE_NFT_CAS_${marker}=PASS" "$native_nft_log" >/dev/null
done
assert_network_unchanged native-nft-cas "$native_nft_network_before"
native_nft_after=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
[[ $native_nft_after == "$native_nft_before" ]] || {
  echo 'NATIVE_NFT_CAS_INDEPENDENT_CLEANUP=FAIL (nftables drift)' >&2
  exit 1
}
docker exec "$container" /bin/rm -- /root/qa-native-nft-cas-test
echo NATIVE_NFT_CAS_INDEPENDENT_CLEANUP=PASS
# Retired v4-only mutator script; Native-installed acceptance below remains.
else
  echo 'NATIVE_KERNEL_PRIMITIVES=NOT_RUN (Debian12 installation compatibility lane)'
fi

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
      sha256sum --strict --quiet --check checksums.sha256)
  done
'
offline_before=$(network_digest)

run_offline() {
  local label=$1 action=$2 source_dir=/root/server-connect
  if [[ $# -ge 3 ]]; then source_dir=$3; fi
  echo "=== Disconnected offline $label ==="
  # First install exercises the no-key Offline contract. Retained explicit
  # LOCAL QA updates preserve the historical receipt regression path.
  # This script is Bash-executed, but the trusted workflow also runs sh -n.
  if [[ $label == first-install || $label == first-retry-* ]]; then
    set --
  else
    set -- --local-qa
  fi
  docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
    -e trace=%network,%process \
    -o "/root/qa-strace/$label" /usr/bin/env -i \
    HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh "$source_dir/install.sh" "$action" "$@"
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
    /bin/sh "$source_dir/install.sh" --offline --local-qa
}
run_active_offline_expect_failure() {
  local label=$1 source_dir=$2
  echo "=== Disconnected guest expected active-update failure $label ==="
  if docker exec "$container" /usr/bin/env -i \
    HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh "$source_dir/install.sh" --offline --local-qa \
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
    # Every installed release retains the exact original, complete bundle
    # manifest/checksums. Only the external archive signature can prove trust.
    test -f /opt/server-connect/current/manifest.json
    test -f /opt/server-connect/current/checksums.sha256
    (cd /opt/server-connect/current && sha256sum --strict --quiet -c checksums.sha256)
    identity=$(sha256sum /opt/server-connect/current/checksums.sha256 | cut -c 1-16)
    test "$(readlink /opt/server-connect/current)" = "releases/0.1.0-dev-$identity"
    test "$(systemctl show server-connect.service -p LoadState --value)" = loaded
    test "$(systemctl show server-connect.service -p ActiveState --value)" = inactive
    test "$(systemctl is-enabled server-connect.service)" = disabled
    test "$(systemctl is-enabled server-connect-activation-recover.timer)" = disabled
    test "$(systemctl show server-connect-smart-tun.service -p LoadState --value)" = not-found
    test "$(systemctl show server-connect-native-tun.service -p UnitFileState --value)" = disabled
    test "$(systemctl show server-connect-native-tun.service -p ActiveState --value)" = inactive
    test "$(systemctl show server-connect-smart-health.service -p LoadState --value)" = loaded
    test "$(systemctl show server-connect-smart-health.service -p UnitFileState --value)" = static
    test "$(systemctl show server-connect-smart-health.service -p ActiveState --value)" = inactive
    test "$(systemctl show server-connect-smart-health.timer -p LoadState --value)" = loaded
    test "$(systemctl show server-connect-smart-health.timer -p ActiveState --value)" = inactive
    test "$(systemctl is-enabled server-connect-smart-health.timer)" = disabled
    test "$(systemctl show server-connect-activation-recover.service -p LoadState --value)" = loaded
    for name in server-connect-activation-recover.service server-connect-smart-health.service; do
      test "$(systemctl show "$name" -p FragmentPath --value)" = "/etc/systemd/system/$name"
      test -z "$(systemctl show "$name" -p DropInPaths --value)"
      test "$(systemctl show "$name" -p Transient --value)" = no
      test "$(systemctl show "$name" -p UnitFileState --value)" = static
      test "$(systemctl show "$name" -p ActiveState --value)" = inactive
      test "$(systemctl show "$name" -p MainPID --value)" = 0
      test "$(systemctl show "$name" -p ControlPID --value)" = 0
      test -z "$(systemctl show "$name" -p Job --value)"
    done
    test "$(systemctl show server-connect-native-tun.service -p FragmentPath --value)" = /etc/systemd/system/server-connect-native-tun.service
    test -z "$(systemctl show server-connect-native-tun.service -p DropInPaths --value)"
    test "$(systemctl show server-connect-native-tun.service -p Transient --value)" = no
    test "$(systemctl show server-connect-native-tun.service -p UnitFileState --value)" = disabled
    test "$(systemctl show server-connect-native-tun.service -p ActiveState --value)" = inactive
    for name in server-connect-activation-recover.timer server-connect-smart-health.timer; do
      test "$(systemctl show "$name" -p ActiveState --value)" = inactive
      test -z "$(systemctl show "$name" -p Job --value)"
    done
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
    test ! -e /etc/systemd/system/server-connect-smart-tun.service
    test ! -e /etc/systemd/system/server-connect-native-tun.service
    test ! -e /etc/systemd/system/server-connect-smart-health.service
    test ! -e /etc/systemd/system/server-connect-smart-health.timer
    test "$(stat -c %a /var/lib/server-connect)" = 700
    test "$(stat -c %a /var/lib/server-connect/profiles)" = 700
    test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
  '
}

# New normal mode does not require a publisher key, while --verify-only
# must remain mutation-free and offline even on a complete Debian 12 bundle.
if [[ $qa_version == 12 ]]; then
  docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
    -e trace=%network,%process -o /root/qa-strace/keyless-verify \
    /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh /root/server-connect/install.sh --verify-only \
    >"$scratch/debian12-keyless-verify.log" 2>&1 || {
      echo 'Debian 12 checksum-verified no-key install preflight failed' >&2
      cat "$scratch/debian12-keyless-verify.log" >&2
      exit 1
    }
  assert_no_offline_fetch keyless-verify
  docker exec "$container" /bin/sh -c 'test ! -e /opt/server-connect && test ! -e /var/lib/server-connect'
  assert_network_unchanged keyless-verify "$offline_before"
  verify_host_services keyless-verify
  echo 'DEBIAN12_KEYLESS_OFFLINE_VERIFY_NO_MUTATION=PASS'
fi
run_offline verify-only --verify-only
assert_network_unchanged verify-only "$offline_before"
verify_host_services verify-only
docker exec "$container" /bin/sh -c 'test ! -e /opt/server-connect && test ! -e /var/lib/server-connect'
docker cp "$root/scripts/qa/host-bundle-target-refusal.sh" "$container:/root/qa-bundle-target-refusal.sh"
docker exec "$container" /bin/sh /root/qa-bundle-target-refusal.sh
assert_network_unchanged bundle-target-refusals "$offline_before"
verify_host_services bundle-target-refusals
docker exec "$container" /bin/rm -- /root/qa-bundle-target-refusal.sh

# Retired v4 preinstall saved-apply check; Native-installed acceptance below remains.
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
  /bin/sh /root/server-connect/install.sh --offline --local-qa \
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
  (cd /root/server-connect && sha256sum --strict --quiet --check checksums.sha256)
'
assert_network_unchanged missing-core "$offline_before"
verify_host_services missing-core

assert_no_offline_fetch missing-core
echo 'OFFLINE_MISSING_CORE_FAIL_CLOSED=PASS (installer NOT applied)'
# Exercise a genuine root-owned interrupted first installation on the
# disposable Debian guest: the exact bundle's source helpers publish the
# initial directory and .owner atomically, then this shell exits without
# installing a service or cleaning up. The normal next installer call must
# prove the private inode-bound receipt, safely resume and complete.
docker exec -i "$container" /bin/sh -s <<'QA_FIRST_PREFIX_INTERRUPT'
set -eu
umask 077
PREFIX=/opt/server-connect
STATE=/var/lib/server-connect
[ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ]
[ ! -e "$STATE" ] && [ ! -L "$STATE" ]
install -d -m 0700 "$STATE"
say() { printf 'Server Connect: %s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
check_root_file() {
 [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1")" = 0 ]
}
check_root_dir() {
 [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1")" = 0 ]
}
sed -n '/^FIRST_INSTALL_INTENT=/,/^# Inspect the \*effective\*/p'  /root/server-connect/install.sh > /root/qa-prefix-helpers.sh
. /root/qa-prefix-helpers.sh
first_install_publish
first_install_claimed_prefix
[ -f "$PREFIX/.owner" ] && [ ! -e "$PREFIX/releases" ]
[ ! -e /etc/systemd/system/server-connect.service ]
[ -f "$FIRST_INSTALL_INTENT" ]
rm -f -- /root/qa-prefix-helpers.sh
echo 'REAL_FIRST_INSTALL_INTERRUPTED_AFTER_ATOMIC_OWNER=PASS'
QA_FIRST_PREFIX_INTERRUPT
run_offline first-install --offline
docker exec "$container" /bin/sh -c '
 set -eu
 test ! -e /var/lib/server-connect/.first-install-intent
 test -f /opt/server-connect/current/integrity.sha256
 test ! -e /opt/server-connect/current/authentication.json
'
verify_direct_install
# Run the newly installed operator overview on BOTH target OS lanes. The
# installed service is verified inactive above; no host-route or VPN proof
# is inferred from that local service observation.
docker exec "$container" /usr/local/bin/server-connect --json mode-overview |
  python3 -c '
import json,sys
reply=json.load(sys.stdin)
assert reply["ok"] is True and "error" not in reply
data=reply["data"]
assert data["desired_mode"]=="direct"
assert data["observed_mode"]=="unknown"
assert data["proxy_service_state"]=="inactive"
assert data["status_health"]=="not_tested"
assert data["evidence_scope"]=="local_proxy_service_only"
assert data["host_direct_path_proof"]=="not_run"
assert data["vpn_path_proof"]=="not_run"
assert data["active_route_verified"] is False
assert [(mode["id"],mode["availability"],mode["general_host_activation"]) for mode in data["modes"]]==[
    ("direct","implemented",True),
    ("proxy_only","implemented",True),
    ("smart_routing","candidate_not_field_verified",False),
]
'
printf '18\n0\n' | docker exec -i "$container" /usr/local/bin/server-connect menu >"$scratch/installed-mode-menu.log"
python3 - "$scratch/installed-mode-menu.log" <<'PYMODEMENU'
import sys
from pathlib import Path
message=Path(sys.argv[1]).read_text()
assert "18 Mode Overview" in message
assert '"observed_mode": "unknown"' in message
assert '"host_direct_path_proof": "not_run"' in message
assert '"availability": "candidate_not_field_verified"' in message
assert '"general_host_activation": false' in message
PYMODEMENU
assert_network_unchanged installed-mode-overview "$offline_before"
verify_host_services installed-mode-overview
echo 'INSTALLED_OPERATOR_MODE_OVERVIEW=PASS (inactive service, honest Direct unknown, non-admitted TUN, CLI/menu parity)'
# Real installed terminal menu: the new native entry must not start anything
# until the final explicit confirmation. With no selected profile, even an
# intentionally confirmed request must be refused by the same guarded CLI.
# This is safe on both Debian lanes and never claims positive host TUN proof.
printf '21\ncancel\n22\n0\n' |
  docker exec -i "$container" /usr/local/bin/server-connect menu \
  >"$scratch/installed-native-menu-cancel.log" 2>"$scratch/installed-native-menu-cancel.err"
python3 - "$scratch/installed-native-menu-cancel.log" <<'PYNATIVECANCEL'
from pathlib import Path
import sys
out=Path(sys.argv[1]).read_text()
assert "21 Smart Routing (guarded QA)" in out
assert "22 Native Guard / Recovery Status" in out
assert "Canceled: no action started" in out
assert "Running native-status" in out
assert "Core started under native guards" not in out
PYNATIVECANCEL
printf '21\neth0\n1\nCONNECT-SMART\n0\n' |
  docker exec -i "$container" /usr/local/bin/server-connect menu \
  >"$scratch/installed-native-menu-refusal.log" 2>"$scratch/installed-native-menu-refusal.err"
python3 - "$scratch/installed-native-menu-refusal.log" "$scratch/installed-native-menu-refusal.err" <<'PYNATIVEREFUSAL'
from pathlib import Path
import sys
out=Path(sys.argv[1]).read_text()
err=Path(sys.argv[2]).read_text()
assert "NOT approved for general-host/production use" in out
assert "Not completed:" in out
assert "Core started under native guards" not in out
assert "Error [" in err and "State:" in err and "Next:" in err
PYNATIVEREFUSAL
docker exec "$container" /usr/local/bin/server-connect --json status |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] and r["data"]["desired"]=="direct" and r["data"]["observed"]=="inactive"
assert not r["data"].get("selected")
'
assert_network_unchanged installed-native-menu-refusal "$offline_before"
verify_host_services installed-native-menu-refusal
echo 'INSTALLED_NATIVE_MENU_SAFE_CANCEL_AND_SHARED_CLI_REFUSAL=PASS (Debian installed host, no TUN activation)'
# A separately named, never-applied private rule store proves real installed
# CLI/menu behavior without sharing experimental TUN journals or altering any
# host policy. Both Debian 12 and 13 must keep SSH/HTTP and routes unchanged.
rules_dir=/run/scqa-operator-rules
docker exec "$container" /bin/sh -c 'test ! -e /run/scqa-operator-rules && test ! -L /run/scqa-operator-rules'
docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json smart-routing-rules list |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] is True and r["data"]["revision"]==0 and not r["data"]["present"]
assert r["data"]["activation_ready"] is False and r["data"]["general_host_admitted"] is False
'
docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
  smart-routing-rules add --cidr 1.1.1.0/24 --via direct |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] is True and r["data"]["revision"]==1
assert r["data"]["rules"][0]["source"]=="manual"
assert r["data"]["rules"][0]["value"]=="1.1.1.0/24"
assert r["data"]["activation_ready"] is False
'
docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
  smart-routing-rules add --domain example.org --via vpn |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] is True and r["data"]["revision"]==2
assert len(r["data"]["rules"])==2
'
if docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
  smart-routing-rules add --domain example.org --via direct >"$scratch/operator-direct-domain-refusal.json"; then
  echo "INSTALLED_OPERATOR_ROUTING_RULES=FAIL (unauthenticated domain Direct accepted)" >&2
  exit 1
fi
python3 - "$scratch/operator-direct-domain-refusal.json" <<'PYRULESNEG'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["ok"] is False and r["error"]["code"]=="routing_rules_invalid"
PYRULESNEG
rules_blob='cidr vpn 9.9.9.9/32'
rules_sha=$(printf '%s\n' "$rules_blob" | sha256sum | cut -d ' ' -f1)
printf '%s\n' "$rules_blob" |
  docker exec -i "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
    smart-routing-rules import --source fixture --as-of 2026-10-01 --sha256 "$rules_sha" --file - |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] is True and r["data"]["revision"]==3
assert len(r["data"]["rules"])==3 and len(r["data"]["imports"])==1
assert r["data"]["imports"][0]["source"]=="fixture"
assert r["data"]["imports"][0]["publisher_signature_verified"] is False
assert r["data"]["state"]=="saved_not_applied"
assert r["data"]["activation_ready"] is False
'
if printf '%s\n' "$rules_blob" |
  docker exec -i "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
    smart-routing-rules import --source other --as-of 2026-10-01 \
      --sha256 0000000000000000000000000000000000000000000000000000000000000000 --file - \
    >"$scratch/operator-wrong-hash-refusal.json"; then
  echo "INSTALLED_OPERATOR_ROUTING_RULES=FAIL (wrong import digest accepted)" >&2
  exit 1
fi
python3 - "$scratch/operator-wrong-hash-refusal.json" <<'PYRULESHASH'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["ok"] is False and r["error"]["code"]=="routing_rules_hash_mismatch"
PYRULESHASH
printf '19\n1\n0\n' |
  docker exec -i "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" menu \
  >"$scratch/operator-rules-menu.log"
python3 - "$scratch/operator-rules-menu.log" <<'PYRULESMENU'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text()
assert "19 Routing Rules" in text
assert "saved_not_applied" in text
assert "9.9.9.9/32" in text
assert '"activation_ready": false' in text
PYRULESMENU
docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json smart-routing-rules list |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] is True and r["data"]["revision"]==3
assert r["data"]["activation_ready"] is False
assert len(r["data"]["rules"])==3
'
# Independent R2 REQUIRED-01: run the *installed executable's actual menu*
# mutation paths against a second unique private state root, including
# rejections and file-byte/revision preservation. The same guest-local
# fixture exercises positive CLI preview after selecting a real core-validated
# synthetic VLESS profile. No TUN activation or host-network mutation occurs.
docker exec -i "$container" python3 -B - <<'PYROUTINGMENU'
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BIN = "/usr/local/bin/server-connect"
# Run the actual installed menu with complete safe URLs but canceled/invalid
# choices. The guest is disconnected; a canceled prompt must not even enter
# dispatch, touch manager state, or start DNS/TCP/other network diagnostics.
with tempfile.TemporaryDirectory(prefix="scqa-operator-cancel-", dir="/run") as abort_tmp:
    cases = {
        "diagnose-back": "11\nhttps://one.example.test/\nhttps://two.example.test/\nback\n0\n",
        "diagnose-cancel": "11\nhttps://one.example.test/\nhttps://two.example.test/\ncancel\n0\n",
        "diagnose-invalid": "11\nhttps://one.example.test/\nhttps://two.example.test/\n3\n0\n",
        "diagnose-incomplete-eof": "11\nhttps://one.example.test/\nhttps://two.example.test/\n1",
        "retired-selective-menu": "12\n0\n",
        "dns-cancel": "14\nnode.example.test\n198.51.100.17\ncancel\n0\n",
        "tcp-optional-host-cancel": "13\n198.51.100.17\n443\nback\n0\n",
        "rule-via-cancel": "19\n2\n1.1.1.0/24\nback\n0\n",
        "retired-vm-menu": "20\n0\n",
    }
    for label, request in cases.items():
        untouched = Path(abort_tmp, label)
        result = subprocess.run([BIN, "--state-dir", str(untouched), "menu"],
                                input=request, text=True, capture_output=True, timeout=12)
        assert result.returncode == 0 and not result.stderr, (
            label, result.returncode, result.stderr)
        # Retired options 12 and 20 must be inert unknown choices rather than
        # entering the old selective planner or isolated-VM trial prompts.
        expected = "Unknown option." if label.startswith("retired-") else "Canceled:"
        assert expected in result.stdout and "Running " not in result.stdout, (
            label, "unexpected command dispatch/refusal", result.stdout[-500:])
        if label == "retired-selective-menu":
            assert "Selective Plan" not in result.stdout
            assert "Pinned VPN endpoint literal IP:" not in result.stdout
        if label == "retired-vm-menu":
            assert "20 Guarded Smart TUN" not in result.stdout
            assert "VM-CONNECT" not in result.stdout
        assert not untouched.exists(), (label, "inert menu created manager state")
    print("INSTALLED_OPERATOR_ADVANCED_CANCEL_NO_DISPATCH=PASS "
          f"({len(cases)} cancellations/refusals; zero command dispatch; no manager state)",
          flush=True)

with tempfile.TemporaryDirectory(prefix="scqa-operator-menu-", dir="/run") as tmp:
    state = Path(tmp, "state")
    fixture = Path(tmp, "rules.txt")
    original = b"cidr vpn 9.9.9.9/32\nsuffix vpn sub.example.org\n"
    updated = b"cidr vpn 4.4.4.4/32\n"
    fixture.write_bytes(original)
    os.chmod(fixture, 0o600)
    sha = hashlib.sha256(original).hexdigest()
    new_sha = hashlib.sha256(updated).hexdigest()
    count = 0

    def execute(*args, stdin=None):
        return subprocess.run([BIN, "--state-dir", str(state), *args],
                              input=stdin, text=True, capture_output=True, timeout=18)

    def cli(*args, stdin=None, ok=True):
        result = execute("--json", *args, stdin=stdin)
        reply = json.loads(result.stdout)
        assert (result.returncode == 0) == ok and reply["ok"] is ok and not result.stderr, (
            args, result.returncode, result.stderr, reply)
        return reply

    def snapshot():
        report = cli("smart-routing-rules", "list")["data"]
        path = state / "smart-routing-rules.json"
        return report, path.read_bytes() if path.exists() else None

    def menu(label, lines, expected_rev, expected_rules, rejected_code=None):
        global count
        previous, original_bytes = snapshot()
        result = execute("menu", stdin="19\n" + lines + "0\n")
        assert result.returncode == 0 and "Routing Rules:" in result.stdout, (
            label, result.returncode, result.stdout[-400:], result.stderr)
        current, now_bytes = snapshot()
        assert current["revision"] == expected_rev and len(current["rules"]) == expected_rules, (
            label, current)
        assert current["state"] == "saved_not_applied" and current["activation_ready"] is False
        assert current["general_host_admitted"] is False
        if rejected_code:
            # The operator renderer must surface the real stable failure
            # class and actionable advice. Never treat a friendly success
            # sentence or an unclassified exception as a valid refusal.
            assert result.stderr.startswith(f"Error [{rejected_code}]: ") and (
                "\nState: " in result.stderr and "\nNext: " in result.stderr
            ) and "Not completed:" in result.stdout, (
                label, rejected_code, result.stderr, result.stdout[-400:])
            assert now_bytes == original_bytes and current == previous, (
                label, result.stderr, "rejected operation changed saved rule state")
        else:
            assert not result.stderr and now_bytes != original_bytes, (
                label, result.stderr, "positive operation did not persist")
        count += 1

    menu("add CIDR", "2\n1.1.1.0/24\ndirect\n", 1, 1)
    menu("add VPN exact domain", "3\nexample.org\nn\n", 2, 2)
    menu("add VPN suffix domain", "3\ntest.example.org\ny\n", 3, 3)
    menu("import local file", f"4\n{fixture}\nmenu-source\n2026-10-01\n{sha}\n\n", 4, 5)
    menu("reject special IPv6", "2\n100::/64\ndirect\n", 4, 5, "routing_rules_invalid")
    menu("reject ICANN public suffix", "3\nco.uk\ny\n", 4, 5, "routing_rules_invalid")
    menu("reject PRIVATE public suffix", "3\ngithub.io\ny\n", 4, 5, "routing_rules_invalid")
    menu("reject duplicate CIDR", "2\n1.1.1.0/24\ndirect\n", 4, 5, "routing_rules_conflict")
    menu("reject import SHA mismatch",
         f"4\n{fixture}\nbad-source\n2026-10-01\n{'0'*64}\n\n", 4, 5, "routing_rules_hash_mismatch")
    menu("reject wrong replacement CAS",
         f"4\n{fixture}\nmenu-source\n2026-10-02\n{sha}\n{'0'*64}\n", 4, 5, "routing_rules_conflict")

    # Same regular CLI used by operators. Import performs actual installed
    # sing-box config checking, but it never opens a VPN connection.
    test_uri = ("vless://c2902f3a-1c25-41ef-a8dc-760b483aa247"
                "@8.8.8.8:443?type=tcp&security=none#QA-Offline-Preview")
    imported = cli("import", "--file", "-", stdin=test_uri)["data"]
    selected = imported["id"]
    cli("select", selected)
    preview_args = ("smart-routing-rules", "preview-native",
                    "--tunnel-if", "sctunqa0", "--underlay-if", "qaedge0",
                    "--tunnel-ipv4", "172.31.99.1/30",
                    "--tunnel-ipv6", "fd73:99::1/64", "--mode", "bypass_iran")
    before, saved_bytes = snapshot()
    p = cli(*preview_args)["data"]
    assert p["selected_profile_id"] == selected
    assert p["rules_revision"] == 4 and p["rule_count"] == 5
    assert p["validation_level"] == "pinned_official_core_check_only"
    assert p["core_config_accepted"] is True
    assert re.fullmatch(r"[0-9a-f]{64}", p["native_config_sha256"])
    assert all(p[key] is False for key in (
        "host_network_inspected", "activation_ready", "applied",
        "general_host_admitted"))
    assert cli(*preview_args)["data"] == p, "native preview emitted nondeterministic config"
    after, current_bytes = snapshot()
    assert before == after and saved_bytes == current_bytes, "native preview modified saved rules"
    assert not any(state.glob("*activation*journal*")), "native preview created an activation journal"
    print("INSTALLED_OPERATOR_CLI_NATIVE_PREVIEW=PASS "
          "(selected official-Core policy, exact rev/count/config digest, read-only)", flush=True)

    fixture.write_bytes(updated)
    menu("replace source", f"4\n{fixture}\nmenu-source\n2026-10-02\n{new_sha}\n{sha}\n", 5, 4)
    menu("reject stale source removal", f"7\nmenu-source\n{sha}\n", 5, 4, "routing_rules_conflict")
    menu("remove CIDR", "5\n1.1.1.0/24\n", 6, 3)
    menu("remove exact domain", "6\nexample.org\nn\n", 7, 2)
    menu("remove suffix domain", "6\ntest.example.org\ny\n", 8, 1)
    menu("remove imported source", f"7\nmenu-source\n{new_sha}\n", 9, 0)
    listed = execute("menu", stdin="19\n1\n0\n")
    assert listed.returncode == 0 and not listed.stderr
    assert '"activation_ready": false' in listed.stdout and "saved_not_applied" in listed.stdout
    final = cli("smart-routing-rules", "list")["data"]
    assert final["revision"] == 9 and final["rules"] == [] and final["imports"] == []
    assert final["state"] == "saved_not_applied" and final["activation_ready"] is False
    # The menu offers VPN-only domain entry; an explicitly attempted
    # Direct-domain CLI is separately rejected by the same validated store.
    direct = cli("smart-routing-rules", "add", "--domain", "example.org",
                 "--via", "direct", ok=False)
    assert direct["error"]["code"] == "routing_rules_invalid"
    assert cli("smart-routing-rules", "list")["data"] == final
    print(f"INSTALLED_OPERATOR_MENU_MUTATIONS_AND_REFUSALS=PASS "
          f"({count} positive/negative real stdin menu flows, byte/revision CAS, "
          "Direct-domain refusal, cleanup)", flush=True)
PYROUTINGMENU
assert_network_unchanged installed-rules-menu-r2 "$offline_before"
verify_host_services installed-rules-menu-r2
# Independent R1/R2 remediation: negative INPUTS must not persist, advance
# the revision, reclassify a public suffix as registrable, or affect any
# network/SSH/HTTP state. Re-run on the actual installed binary in D12/D13.
rule_file="$rules_dir/smart-routing-rules.json"
rules_before_sha=$(docker exec "$container" sha256sum "$rule_file" | cut -d ' ' -f1)
for invalid_cidr in 100::/64 2001::/64 2001:2::/64 3fff::/64; do
  if docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
      smart-routing-rules add --cidr "$invalid_cidr" --via direct >"$scratch/operator-v6-registry-refusal.json"; then
    echo "INSTALLED_OPERATOR_REGISTRY_R1_R2=FAIL (IANA IPv6 special-purpose accepted)" >&2
    exit 1
  fi
  python3 - "$scratch/operator-v6-registry-refusal.json" <<'PYR1'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["ok"] is False and r["error"]["code"]=="routing_rules_invalid"
PYR1
  blob="cidr vpn $invalid_cidr"
  invalid_sha=$(printf '%s\n' "$blob" | sha256sum | cut -d ' ' -f1)
  if printf '%s\n' "$blob" |
      docker exec -i "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
        smart-routing-rules import --source badv6 --as-of 2026-10-01 \
        --sha256 "$invalid_sha" --file - >"$scratch/operator-v6-registry-refusal.json"; then
    echo "INSTALLED_OPERATOR_REGISTRY_R1_R2=FAIL (IANA IPv6 import accepted)" >&2
    exit 1
  fi
done
for invalid_suffix in co.uk com.au github.io; do
  if docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
      smart-routing-rules add --domain "$invalid_suffix" --suffix --via vpn >"$scratch/operator-psl-refusal.json"; then
    echo "INSTALLED_OPERATOR_REGISTRY_R1_R2=FAIL (whole public/private suffix accepted)" >&2
    exit 1
  fi
  python3 - "$scratch/operator-psl-refusal.json" <<'PYR2'
import json,sys
r=json.load(open(sys.argv[1]))
assert r["ok"] is False and r["error"]["code"]=="routing_rules_invalid"
PYR2
  blob="suffix vpn $invalid_suffix"
  invalid_sha=$(printf '%s\n' "$blob" | sha256sum | cut -d ' ' -f1)
  if printf '%s\n' "$blob" |
      docker exec -i "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json \
        smart-routing-rules import --source badsuffix --as-of 2026-10-01 \
        --sha256 "$invalid_sha" --file - >"$scratch/operator-psl-refusal.json"; then
    echo "INSTALLED_OPERATOR_REGISTRY_R1_R2=FAIL (whole PSL import accepted)" >&2
    exit 1
  fi
done
test "$(docker exec "$container" sha256sum "$rule_file" | cut -d ' ' -f1)" = "$rules_before_sha"
docker exec "$container" /usr/local/bin/server-connect --state-dir "$rules_dir" --json smart-routing-rules list |
  python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r["ok"] is True and r["data"]["revision"]==3
assert len(r["data"]["rules"])==3 and len(r["data"]["imports"])==1
assert r["data"]["activation_ready"] is False
'
assert_network_unchanged installed-registry-r1-r2 "$offline_before"
verify_host_services installed-registry-r1-r2
echo 'INSTALLED_OPERATOR_REGISTRY_R1_R2=PASS (IANA IPv6 and ICANN/PRIVATE PSL manual/import refusal, byte/revision CAS unchanged, network and SSH/HTTP preserved)'
assert_network_unchanged installed-routing-rules "$offline_before"
verify_host_services installed-routing-rules
# Remove only our verified, unique QA private state path after verification.
docker exec "$container" /bin/sh -c '
set -eu
d=/run/scqa-operator-rules
test -d "$d" && test ! -L "$d" && test "$(stat -c %u "$d")" = 0
test "$(stat -c %a "$d")" = 700
rm -r -- "$d"
test ! -e "$d"
'
echo 'INSTALLED_OPERATOR_ROUTING_RULES=PASS (real CLI/menu, SHA-pinned import, no network effects, SSH/HTTP preserved)'
# Retired v4 installed Debian12 trial refusal; Native-installed acceptance below remains.
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

# Read-only native firewall drift evidence must come from the INSTALLED CLI.
# All nftables mutations below belong strictly to this disconnected, labelled
# disposable guest. Do not flush the ruleset or adopt any foreign host policy.
echo 'HOST_NFTABLES_PREFLIGHT_STAGE=installed-disconnected-guest'
nft_before=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
docker exec "$container" /usr/local/bin/server-connect --json host-preflight \
  --endpoint 127.0.0.1 --management-peer 127.0.0.2 --with-nftables \
  > "$scratch/qa-nft-baseline.json"
python3 - "$scratch/qa-nft-baseline.json" <<'PYNFTBASE'
import json,sys,re
with open(sys.argv[1],encoding='utf-8') as file: envelope=json.load(file)
assert envelope['ok'] is True
snapshot=envelope['data']
assert snapshot['mode']=='observation_with_nftables'
assert snapshot['read_only'] is True
assert snapshot['snapshot_atomic'] is False
assert snapshot['activation_ready'] is False
assert snapshot['firewall']['observed'] is True
assert re.fullmatch('[0-9a-f]{64}',snapshot['firewall']['ruleset_sha256'])
assert isinstance(snapshot['firewall']['object_count'],int)
assert snapshot['firewall']['object_count'] >= 1  # Native output always begins with metainfo.
assert 'nftables' not in snapshot['firewall']   # No raw ruleset disclosure
PYNFTBASE
docker cp "$scratch/qa-nft-baseline.json" "$container:/root/qa-nft-baseline.json"
docker exec "$container" /bin/chmod 0600 /root/qa-nft-baseline.json
docker exec "$container" /usr/local/bin/server-connect --json host-drift \
  --baseline /root/qa-nft-baseline.json >"$scratch/qa-nft-match.json"
python3 - "$scratch/qa-nft-match.json" <<'PYNFTMATCH'
import json,sys
with open(sys.argv[1],encoding='utf-8') as file: envelope=json.load(file)
assert envelope['ok'] is True
data=envelope['data']
assert data['mode']=='host_drift_diagnostic' and data['read_only'] is True
assert data['current_observed'] is True and data['changed'] is False
assert data['activation_ready'] is False and data['snapshot_atomic'] is False
assert len(data['components']) == 8
assert data['components'][-1]['name']=='nftables_ruleset'
assert all(not item['changed'] for item in data['components'])
PYNFTMATCH

# A structurally complete baseline may not silently drop only its firewall
# fingerprint. Reject this artificial downgrade before observing native state.
python3 - "$scratch/qa-nft-baseline.json" "$scratch/qa-nft-downgrade.json" <<'PYNFTDOWNGRADE'
import json,sys
with open(sys.argv[1],encoding='utf-8') as file: doc=json.load(file)
assert doc['data']['mode']=='observation_with_nftables'
del doc['data']['firewall']
with open(sys.argv[2],'w',encoding='utf-8') as file: json.dump(doc,file)
PYNFTDOWNGRADE
docker cp "$scratch/qa-nft-downgrade.json" "$container:/root/qa-nft-downgrade.json"
docker exec "$container" /bin/chmod 0600 /root/qa-nft-downgrade.json
if docker exec "$container" /usr/local/bin/server-connect --json host-drift \
    --baseline /root/qa-nft-downgrade.json >"$scratch/qa-nft-downgrade-result.json"; then
  echo 'HOST_NFTABLES_PREFLIGHT=FAIL (firewall baseline downgrade accepted)' >&2
  exit 1
fi
python3 - "$scratch/qa-nft-downgrade-result.json" <<'PYNFTREJECT'
import json,sys
with open(sys.argv[1],encoding='utf-8') as file: doc=json.load(file)
assert doc['ok'] is False and doc['error']['code']=='invalid_baseline'
assert 'data' not in doc
PYNFTREJECT

# Exact absence prevents hijacking a table installed by any pre-existing
# network owner. The guest-only chain is deliberately UNHOOKED: these named
# and anonymous counters cannot change packet filtering or host networking.
if docker exec "$container" /usr/sbin/nft list table inet sc_qa_foreign_fp >/dev/null 2>&1; then
  echo 'HOST_NFTABLES_PREFLIGHT=FAIL (foreign fixture table exists)' >&2
  exit 1
fi
docker exec "$container" /usr/sbin/nft add table inet sc_qa_foreign_fp
docker exec "$container" /usr/sbin/nft add counter inet sc_qa_foreign_fp sc_qa_named_fp
docker exec "$container" /usr/sbin/nft add chain inet sc_qa_foreign_fp sc_qa_unhooked
docker exec "$container" /usr/sbin/nft add rule inet sc_qa_foreign_fp sc_qa_unhooked counter
# The native exporter, unlike JSON rule-creation INPUT, must provide BOTH
# uint64 counter members. This tests real named/anonymous Debian 12/13 output,
# not only our synthetic Go fixtures, without touching any packet path.
docker exec "$container" /usr/sbin/nft -j list ruleset | python3 -c '
import json,sys
objects=json.load(sys.stdin)["nftables"]
named=[entry["counter"] for entry in objects if "counter" in entry
       and entry["counter"].get("table") == "sc_qa_foreign_fp"]
anonymous=[expr["counter"] for entry in objects if "rule" in entry
           and entry["rule"].get("table") == "sc_qa_foreign_fp"
           for expr in entry["rule"].get("expr",[]) if "counter" in expr]
assert len(named)==1 and len(anonymous)==1,(len(named),len(anonymous))
for record in named+anonymous:
    assert all(type(record.get(field)) is int and 0 <= record[field] <= 2**64-1
               for field in ("packets","bytes")),record
'
docker exec "$container" /usr/local/bin/server-connect --json host-preflight \
  --endpoint 127.0.0.1 --management-peer 127.0.0.2 --with-nftables |
  python3 -c '
import json,sys
result=json.load(sys.stdin)
assert result["ok"] is True
assert result["data"]["firewall"]["observed"] is True
assert result["data"]["firewall"]["object_count"] >= 5
'
echo 'HOST_NFTABLES_NATIVE_COUNTER_OUTPUT=PASS (real named/anonymous counters accepted by installed CLI)'
if docker exec "$container" /usr/local/bin/server-connect --json host-drift \
    --baseline /root/qa-nft-baseline.json >"$scratch/qa-nft-drift-result.json"; then
  echo 'HOST_NFTABLES_PREFLIGHT=FAIL (foreign nftables table was not detected)' >&2
  exit 1
fi
python3 - "$scratch/qa-nft-drift-result.json" <<'PYNFTDRIFT'
import json,sys
with open(sys.argv[1],encoding='utf-8') as file: doc=json.load(file)
assert doc['ok'] is False and doc['error']['code']=='host_drift_detected'
report=doc['data']
assert report['read_only'] is True and report['activation_ready'] is False
assert report['changed'] is True and report['current_observed'] is True
changed=[x['name'] for x in report['components'] if x['changed']]
assert changed==['nftables_ruleset'],changed
assert 'sc_qa_foreign_fp' not in json.dumps(doc)
PYNFTDRIFT
docker exec "$container" /usr/sbin/nft delete table inet sc_qa_foreign_fp
test "$(docker exec "$container" /usr/sbin/nft -j list ruleset)" = "$nft_before"
docker exec "$container" /usr/local/bin/server-connect --json host-drift \
  --baseline /root/qa-nft-baseline.json >"$scratch/qa-nft-restored.json"
python3 - "$scratch/qa-nft-restored.json" <<'PYNFTRESTORED'
import json,sys
with open(sys.argv[1],encoding='utf-8') as file: doc=json.load(file)
assert doc['ok'] is True and doc['data']['changed'] is False
PYNFTRESTORED
echo 'HOST_NFTABLES_PREFLIGHT=PASS (installed CLI, actual foreign table drift, exact cleanup, private evidence)'
assert_network_unchanged first-install "$offline_before"
verify_host_services first-install
# This post-SIGKILL kernel footprint came from a real Docker-enabled IRA-124
# field failure. Execute the actual native recovery binary against matching
# Linux/nft objects inside this disconnected Debian12/13 systemd guest.
# It does NOT claim an actual Core crash or selected-VPN field proof.
docker cp "$scratch/qa-native-nft-cas-test" "$container:/root/qa-native-recovery-test"
docker cp "$root/scripts/qa/host-native-docker-recovery.sh" "$container:/root/qa-native-docker-recovery.sh"
docker exec -e SC_QA_NATIVE_DOCKER_GUEST=yes "$container" \
  /bin/sh /root/qa-native-docker-recovery.sh |
  tee "$scratch/native-docker-recovery.log"
for marker in NATIVE_ORPHAN_REAL_KERNEL_BOUNDARY \
              NATIVE_DOCKER_SIGKILL_LAYOUT_RECOVERY \
              NATIVE_DOCKER_FOREIGN_BRIDGE_REFUSAL \
              NATIVE_DOCKER_FOREIGN_REFUSAL_RETRY \
              NATIVE_DOCKER_GUEST_FULL_BASELINE_RESTORED; do
  grep -F "$marker=PASS" "$scratch/native-docker-recovery.log" >/dev/null
done
docker exec "$container" rm -f /root/qa-native-recovery-test /root/qa-native-docker-recovery.sh
assert_network_unchanged native-docker-crash-recovery "$offline_before"
verify_host_services native-docker-crash-recovery
# A real Core SIGKILL can complete its kernel cleanup, retire the receipt,
# and leave failed systemd bookkeeping plus an inert private Core config.
# Recreate ONLY those installed-host artifacts in the disconnected guest:
# starting the disabled native unit without a claim must fail in ExecStartPre
# before Core/kernel mutation. Explicit Disconnect must then select native
# cleanup, not falsely return success from the Proxy Only branch.
docker exec -i "$container" /bin/sh -s <<'QANATIVEDISCONNECT'
set -eu
test "$(systemctl is-active server-connect-native-tun.service || :)" = inactive
test "$(systemctl is-enabled server-connect-native-tun.service)" = disabled
test ! -e /var/lib/server-connect/native-session.json
test ! -e /var/lib/server-connect/native-tun.json
printf 'qa-only-inert-config\n' > /var/lib/server-connect/native-tun.json
chmod 0600 /var/lib/server-connect/native-tun.json
if systemctl start server-connect-native-tun.service >/root/qa-native-direct-failed-start.log 2>&1; then
  echo 'NATIVE_DIRECT_DISCONNECT_FIXTURE=FAIL (unclaimed Core started)' >&2
  exit 1
fi
test "$(systemctl is-active server-connect-native-tun.service || :)" = failed
/usr/local/bin/server-connect --json native-status > /root/qa-native-direct-before.json
python3 -c 'import json
r=json.load(open("/root/qa-native-direct-before.json"))
d=r["data"]
assert r["ok"] and d["desired"]=="direct" and d["observed"]=="failed" and not d["recovery_claim_present"]'
/usr/local/bin/server-connect --json disconnect > /root/qa-native-direct-disconnect.json
python3 -c 'import json
r=json.load(open("/root/qa-native-direct-disconnect.json"))
assert r["ok"],r.get("error")'
test ! -e /var/lib/server-connect/native-tun.json
test ! -e /var/lib/server-connect/native-session.json
test "$(systemctl is-active server-connect-native-tun.service || :)" = inactive
/usr/local/bin/server-connect --json native-status > /root/qa-native-direct-after.json
python3 -c 'import json
r=json.load(open("/root/qa-native-direct-after.json"))
d=r["data"]
assert r["ok"] and d["desired"]=="direct" and d["observed"]=="inactive" and not d["recovery_claim_present"]'
for unit in server-connect-smart-health.timer server-connect-activation-recover.timer; do
  test "$(systemctl is-active "$unit" || :)" = inactive
done
rm -f -- /root/qa-native-direct-failed-start.log /root/qa-native-direct-before.json /root/qa-native-direct-after.json /root/qa-native-direct-disconnect.json
echo 'NATIVE_RECOVERED_CRASH_EXPLICIT_DISCONNECT=PASS (no claim, failed unit and inert config fully reconciled)'
QANATIVEDISCONNECT
assert_network_unchanged native-recovered-crash-explicit-disconnect "$offline_before"
test "$(docker exec "$container" /usr/sbin/nft -j list ruleset)" = "$nft_before"
verify_host_services native-recovered-crash-explicit-disconnect
echo 'NATIVE_RECOVERED_CRASH_DISCONNECT_BASELINE=PASS (kernel/nft and SSH/HTTP unaffected)'
# Keep the installed negative CLI contract, without a separate transitional
# script, container copy or an extra historical process-scanning fixture.
if docker exec "$container" /usr/local/bin/server-connect --json workload-observe \
    --pid 2 --descendants --sockets >"$scratch/qa-retired-workload.json"; then
  echo 'INSTALLED_RETIRED_WORKLOAD_COMMAND=FAIL (legacy action still available)' >&2
  exit 1
fi
python3 - "$scratch/qa-retired-workload.json" <<'PYRETIRED'
import json,sys
with open(sys.argv[1],encoding='utf-8') as source:
    response=json.load(source)
assert response.get('ok') is False
assert response.get('error',{}).get('code')=='unknown_command'
PYRETIRED
echo 'INSTALLED_RETIRED_WORKLOAD_COMMAND=PASS (unknown command, no per-job routing)'
assert_network_unchanged retired-workload-command "$offline_before"
verify_host_services retired-workload-command
docker exec "$container" /bin/sh -c '
  printf "SC_QA_RETAIN_PROFILE_BYTES\n" > /var/lib/server-connect/profiles/qa-retained
  chmod 0600 /var/lib/server-connect/profiles/qa-retained
'
# Exercise real installer compatibility with the precise PRE-PROVENANCE
# release layout and historic SHA256(manager/core)-derived release name.
# This is a synthetic old-layout guest receipt using actual packaged bytes,
# not a claim of having upgraded a historical deployed public release.
legacy_link=$(docker exec "$container" /bin/sh -c '
 set -eu
 existing=$(readlink /opt/server-connect/current)
 original=/opt/server-connect/$existing
 legacy_suffix=$(cd "$original" &&
   sha256sum bin/server-connect bin/sing-box |
     cut -d" " -f1 | sha256sum | cut -c 1-16)
 legacy_link=releases/0.1.0-dev-$legacy_suffix
 [ "$legacy_link" != "$existing" ]
 legacy=/opt/server-connect/$legacy_link
 [ ! -e "$legacy" ] && [ ! -L "$legacy" ]
 install -d -m 0755 "$legacy/bin" "$legacy/THIRD-PARTY-LICENSES"
 for path in bin/server-connect bin/sing-box bin/libcronet.so THIRD-PARTY-LICENSES/sing-box-LICENSE; do
  mode=0644
  case "$path" in bin/server-connect|bin/sing-box) mode=0755 ;; esac
  install -m "$mode" "$original/$path" "$legacy/$path"
 done
 printf "AChWorks/server-connect\n" > "$legacy/.owner"
 chmod 0644 "$legacy/.owner"
 [ "$(find "$legacy" -mindepth 1 -printf . | wc -c)" -eq 7 ]
 ln -s "$legacy_link" /opt/server-connect/.qa-legacy-current
 mv -Tf -- /opt/server-connect/.qa-legacy-current /opt/server-connect/current
 printf "%s\n" "$legacy_link"
')
[[ $legacy_link =~ ^releases/0\.1\.0-dev-[a-f0-9]{16}$ ]]
run_offline reinstall --offline
verify_direct_install
[[ $(docker exec "$container" readlink /opt/server-connect/current) != "$legacy_link" ]]
docker exec "$container" test -f "/opt/server-connect/$legacy_link/.owner"
echo 'INSTALLED_LEGACY_TO_FULL_REINSTALL=PASS (exact historical layout/name, actual installer, private guest)'
assert_network_unchanged reinstall "$offline_before"
verify_host_services reinstall
if [[ $qa_version == 12 ]]; then
  # This closes the source-generated native DNS *wire* gap on Debian 12,
  # without implying installed native connect-smart/guards, public IPv6 or
  # field support. All packets, DNS servers and real VLESS/Core peers remain
  # in this existing Docker --network none systemd guest.
  echo 'DEBIAN12_NATIVE_DNS_STAGE=build-disconnected-guest-generator'
  GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -o "$scratch/tun-config-qa" ./scripts/qa/tun_config_generator.go
  test -x "$scratch/tun-config-qa"
  docker cp "$scratch/tun-config-qa" "$container:/root/qa-tun-config-qa"
  for fixture in tun-dns-peer.py tun-dns-client.py tun-sni-client.py \
                 tun-native-apps.py tun-payload-wire.py tun-ipv6-wire.py \
                 host-tun-path.sh; do
    docker cp "$root/scripts/qa/$fixture" "$container:/root/qa-$fixture"
  done
  docker cp "$root/scripts/qa/host-native-dns-policy.sh" "$container:/root/qa-native-dns-policy.sh"
  docker cp "$root/scripts/qa/host-installed-native-connect.sh" "$container:/root/qa-installed-native-connect.sh"
  # Each mode starts independent selected and native Direct positive controls,
  # verifies UDP/TCP port-53 precedence and IPv6 UDP/MTU/outage containment,
  # then removes its own TUN, VETH, namespace, nft and Core resources.
  tun_netns_before=$(docker exec "$container" /sbin/ip netns list)
  tun_nft_before=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
  for native_mode in default bypass_iran; do
    echo "DEBIAN12_NATIVE_DNS_STAGE=$native_mode"
    native_dns_log="$scratch/debian12-native-dns-$native_mode.log"
    docker exec -e SC_QA_TUN_IPV6=yes -e SC_QA_TUN_NATIVE_DNS=yes \
      -e "SC_QA_TUN_NATIVE_DNS_MODE=$native_mode" \
      "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$native_dns_log"
    for marker in NATIVE_DNS_PRE_TUN_POSITIVE_CONTROL NATIVE_DNS_SELECTED_ADDRESS_PRECEDENCE \
                  NATIVE_IPV6_UDP_MTU NATIVE_IPV6_UDP_REDUCED_UNDERLAY NATIVE_IPV6_UDP_OUTAGE \
                  NATIVE_DNS_UNMATCHED_VPN_RESOLVER NATIVE_DNS_OUTAGE_FAIL_CLOSED \
                  NATIVE_DNS_DIRECT_OUTAGE_CONTROL; do
      grep -Fx "$marker=PASS ($native_mode)" "$native_dns_log" >/dev/null
    done
    grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$native_dns_log" >/dev/null
    [[ $(docker exec "$container" /sbin/ip netns list) == "$tun_netns_before" ]]
    [[ $(docker exec "$container" /usr/sbin/nft -j list ruleset) == "$tun_nft_before" ]]
    docker exec "$container" /bin/sh -c \
      'test ! -e /sys/class/net/scqaedge0 && test ! -e /sys/class/net/sctunqa0'
    assert_network_unchanged "debian12-native-dns-$native_mode" "$offline_before"
    verify_host_services "debian12-native-dns-$native_mode"
  done
  echo 'DEBIAN12_INSTALLED_NATIVE_STAGE=actual-connected-manager'
  installed_native_log="$scratch/debian12-installed-native.log"
  docker exec -e SC_QA_TUN_INSTALLED_NATIVE=yes \
    "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$installed_native_log"
  for marker in INSTALLED_NATIVE_PREARM_DIRECT_BASELINE INSTALLED_NATIVE_SELECTED_PATH \
                INSTALLED_NATIVE_EXPLICIT_OFF INSTALLED_NATIVE_UNHEALTHY_GUARD \
                INSTALLED_NATIVE_CLEANUP; do
    grep -F "${marker}=PASS" "$installed_native_log" >/dev/null
  done
  grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$installed_native_log" >/dev/null
  [[ $(docker exec "$container" /sbin/ip netns list) == "$tun_netns_before" ]]
  [[ $(docker exec "$container" /usr/sbin/nft -j list ruleset) == "$tun_nft_before" ]]
  assert_network_unchanged debian12-installed-native "$offline_before"
  verify_host_services debian12-installed-native
  echo 'DEBIAN12_INSTALLED_NATIVE=PASS (actual connect-smart/guards/Off; synthetic disconnected provider only)'
  docker exec "$container" rm -- /root/qa-tun-config-qa \
    /root/qa-tun-dns-peer.py /root/qa-tun-dns-client.py /root/qa-tun-sni-client.py \
    /root/qa-tun-native-apps.py /root/qa-tun-payload-wire.py /root/qa-tun-ipv6-wire.py \
    /root/qa-host-tun-path.sh /root/qa-native-dns-policy.sh \
    /root/qa-installed-native-connect.sh
  assert_network_unchanged debian12-native-dns-final "$offline_before"
  verify_host_services debian12-native-dns-final
  echo 'DEBIAN12_NATIVE_DNS_WIRE=PASS (source-generated Core/TUN/DNS lab only; installed native lifecycle tested separately)'
fi
if [[ $qa_version == 13 ]]; then
# A REAL Linux TUN+VLESS path is exercised only in the disconnected
# disposable guest; the installed product still has no public TUN Apply.
echo 'REAL_TUN_LAB_STAGE=build-guest-generator'
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o "$scratch/tun-config-qa" ./scripts/qa/tun_config_generator.go
test -x "$scratch/tun-config-qa"
# Native-only generated policy: no separate historical TUN compiler or
# artificial old candidate quotas. The installed Native policy has source tests.
docker cp "$scratch/tun-config-qa" "$container:/root/qa-tun-config-qa"
docker cp "$root/scripts/qa/tun-dns-peer.py" "$container:/root/qa-tun-dns-peer.py"
docker cp "$root/scripts/qa/tun-dns-client.py" "$container:/root/qa-tun-dns-client.py"
docker cp "$root/scripts/qa/tun-sni-client.py" "$container:/root/qa-tun-sni-client.py"
docker cp "$root/scripts/qa/tun-native-apps.py" "$container:/root/qa-tun-native-apps.py"
docker cp "$root/scripts/qa/tun-payload-wire.py" "$container:/root/qa-tun-payload-wire.py"
docker cp "$root/scripts/qa/tun-ipv6-wire.py" "$container:/root/qa-tun-ipv6-wire.py"
docker cp "$root/scripts/qa/tun-wordpress-fpm.sh" "$container:/root/qa-tun-wordpress-fpm.sh"
docker cp "$root/scripts/qa/tun-wp-check.py" "$container:/root/qa-tun-wp-check.py"
docker cp "$root/scripts/qa/host-tun-path.sh" "$container:/root/qa-host-tun-path.sh"
docker cp "$root/scripts/qa/host-installed-native-connect.sh" "$container:/root/qa-installed-native-connect.sh"
docker cp "$root/scripts/qa/host-native-dns-policy.sh" "$container:/root/qa-native-dns-policy.sh"
# Retired v4-only TLS staging and receipt fixture; Native-installed acceptance below remains.
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
      'test ! -e /sys/class/net/scqaedge0 && test ! -e /sys/class/net/sctunqa0 && test ! -e /sys/class/net/scqaowned0'; then
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
# Run the real Native compiler against both DNS routing policies.
for native_mode in default bypass_iran; do
  echo "NATIVE_DNS_LAB_STAGE=$native_mode"
  native_dns_log="$scratch/native-dns-$native_mode.log"
  docker exec -e SC_QA_TUN_IPV6=yes -e SC_QA_TUN_NATIVE_DNS=yes \
    -e "SC_QA_TUN_NATIVE_DNS_MODE=$native_mode" \
    "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$native_dns_log"
  for marker in NATIVE_DNS_PRE_TUN_POSITIVE_CONTROL NATIVE_DNS_SELECTED_ADDRESS_PRECEDENCE \
                NATIVE_IPV6_UDP_MTU NATIVE_IPV6_UDP_REDUCED_UNDERLAY NATIVE_IPV6_UDP_OUTAGE \
                NATIVE_DNS_UNMATCHED_VPN_RESOLVER NATIVE_DNS_OUTAGE_FAIL_CLOSED \
                NATIVE_DNS_DIRECT_OUTAGE_CONTROL; do
    grep -Fx "$marker=PASS ($native_mode)" "$native_dns_log" >/dev/null
  done
  grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$native_dns_log" >/dev/null
  assert_tun_native_cleanup "native-dns-$native_mode-cleanup"
done

# The separate precreated/addressless-gVisor owner experiment is retired.
# Current Native foreign-object refusal and exact owned cleanup are tested
# in the source Go real-kernel, Docker-crash and installed Core/Guard suites.
# The independently prearmed activation and crash recovery path is now
# exercised by the actual installed Native connect-smart / guard lifecycle.
# The retired parallel synthetic hosting fault suite is superseded by the
# installed Native failed-selected-HTTPS / independent guard Direct/off proof.
echo 'REAL_TUN_LAB_STAGE=installed-native-connect-smart'
installed_native_log="$scratch/debian13-installed-native.log"
docker exec -e SC_QA_TUN_INSTALLED_NATIVE=yes \
  "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$installed_native_log"
for marker in INSTALLED_NATIVE_PREARM_DIRECT_BASELINE INSTALLED_NATIVE_SELECTED_PATH \
              INSTALLED_NATIVE_EXPLICIT_OFF INSTALLED_NATIVE_UNHEALTHY_GUARD \
              INSTALLED_NATIVE_CLEANUP; do
  grep -F "${marker}=PASS" "$installed_native_log" >/dev/null
done
grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$installed_native_log" >/dev/null
assert_tun_native_cleanup installed-native-connect-smart
# Retired v4-only TLS cleanup; Native-installed acceptance below remains.
docker exec "$container" /bin/rm -f /root/qa-tun-config-qa /root/qa-host-tun-path.sh /root/qa-native-dns-policy.sh \
  /root/qa-tun-sni-client.py /root/qa-tun-native-apps.py \
  /root/qa-tun-dns-peer.py /root/qa-tun-dns-client.py \
  /root/qa-tun-wordpress-fpm.sh /root/qa-tun-wp-check.py /root/qa-tun-payload-wire.py \
  /root/qa-tun-ipv6-wire.py /root/qa-installed-native-connect.sh
else
  echo 'NATIVE_WIRE_LAB=NOT_RUN (Debian12 Native installed test runs separately)'
fi
echo '=== Installed real VLESS Proxy Only and owned offline update ==='
docker cp "$root/scripts/qa/host-proxy-only.sh" "$container:/root/qa-proxy-only.sh"
docker cp "$root/scripts/qa/host-apt-only.sh" "$container:/root/qa-apt-only.sh"
docker exec "$container" /bin/sh /root/qa-proxy-only.sh setup
docker exec "$container" /bin/sh /root/qa-apt-only.sh setup
if [[ $qa_version == 13 ]]; then
# Do not discard route invariants to make the FPM fixture start: verify the
# full observed route/rule/link snapshot rather than brittle one-line CLI text.
assert_network_unchanged wordpress-preflight "$offline_before"
docker cp "$root/scripts/qa/host-wordpress-fpm.sh" "$container:/root/qa-wp-fpm.sh"
docker cp "$root/scripts/qa/wp-nonce-origin.py" "$container:/root/qa-wp-nonce-origin.py"
docker cp "$root/scripts/qa/wp-fcgi-check.py" "$container:/root/qa-wp-fcgi-check.py"
docker cp "$root/scripts/qa/wp-proxy-prepend.py" "$container:/root/qa-wp-proxy-prepend.py"
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh setup
else
  echo 'PHP_WORDPRESS_PHASES=NOT_RUN (Debian12 installation and Proxy Only lane; no PHP compatibility claim)'
fi
docker exec "$container" /bin/sh /root/qa-apt-only.sh positive initial
docker exec "$container" /bin/sh /root/qa-apt-only.sh inherited-policy
docker cp "$root/scripts/qa/apt-disabled-trace.py" "$container:/root/qa-apt-disabled-trace.py"
docker exec "$container" /bin/sh /root/qa-apt-only.sh disabled-transports
docker exec "$container" /bin/rm -- /root/qa-apt-disabled-trace.py
assert_network_unchanged installed-vless-proxy "$offline_before"
verify_host_services installed-vless-proxy
docker exec "$container" /bin/sh /root/qa-proxy-only.sh upstream-failure
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh upstream-failure initial; fi
assert_network_unchanged vless-upstream-failure "$offline_before"
verify_host_services vless-upstream-failure
docker exec "$container" /bin/sh /root/qa-proxy-only.sh core-failure
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh core-failure; fi
assert_network_unchanged proxy-core-failure "$offline_before"
verify_host_services proxy-core-failure

# R1 fail-closed proof using the REAL root installer while a real selected
# VLESS service is active in the disconnected systemd guest. Invalid modern
# provenance must fail before stop, unit replacement or current-link changes.
docker exec -i "$container" /bin/sh -s <<'QA_PROVENANCE_CURRENT'
set -eu
systemctl is-active --quiet server-connect.service
link=$(readlink /opt/server-connect/current)
release=/opt/server-connect/$link
unit_hash=$(sha256sum /etc/systemd/system/server-connect.service | cut -d" " -f1)
mkdir -m 0700 /root/qa-provenance-original
for file in checksums.sha256 manifest.json server-connect-smart-health.service; do
 cp -p "$release/$file" "/root/qa-provenance-original/$file"
done
printf "do-not-delete-foreign\n" > /root/qa-provenance-foreign-sentinel
for scenario in no-checksums no-manifest no-both no-both-and-tampered-service; do
 case "$scenario" in
  no-checksums) rm "$release/checksums.sha256" ;;
  no-manifest) rm "$release/manifest.json" ;;
  no-both*) rm "$release/checksums.sha256" "$release/manifest.json" ;;
 esac
 if [ "$scenario" = no-both-and-tampered-service ]; then
  printf "unauthorized unit mutation\n" >> "$release/server-connect-smart-health.service"
 fi
 for action in --verify-only --offline --uninstall; do
  if /bin/sh /root/server-connect/install.sh "$action" --local-qa \
      >/root/qa-provenance-refusal.log 2>&1; then
   echo "INVALID_INSTALLED_PROVENANCE_WAS_ACCEPTED:$scenario:$action" >&2
   exit 1
  fi
  grep -F "Server Connect: ERROR:" /root/qa-provenance-refusal.log >/dev/null
  systemctl is-active --quiet server-connect.service
  [ "$(readlink /opt/server-connect/current)" = "$link" ]
  [ "$(sha256sum /etc/systemd/system/server-connect.service | cut -d" " -f1)" = "$unit_hash" ]
  [ "$(cat /root/qa-provenance-foreign-sentinel)" = do-not-delete-foreign ]
  [ "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES ]
 done
 for file in checksums.sha256 manifest.json server-connect-smart-health.service; do
  cp -p "/root/qa-provenance-original/$file" "$release/$file"
 done
 (cd "$release" && sha256sum --strict --quiet -c checksums.sha256)
done
rm -f /root/qa-provenance-refusal.log /root/qa-provenance-foreign-sentinel
rm -f /root/qa-provenance-original/*
rmdir /root/qa-provenance-original
echo 'INSTALLED_MODERN_METADATA_DOWNGRADE_REFUSALS=PASS (4 variants x 3 actual installer actions, active VLESS and foreign state preserved)'
QA_PROVENANCE_CURRENT
docker exec "$container" /bin/sh /root/qa-proxy-only.sh positive
assert_network_unchanged active-modern-provenance-refusals "$offline_before"
verify_host_services active-modern-provenance-refusals

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
if [[ $qa_version == 13 ]]; then
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh positive after-upgrade
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh http-proxy-auth after-upgrade
fi
docker exec "$container" /bin/sh /root/qa-proxy-only.sh upstream-failure upstream-after-upgrade
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh upstream-failure after-upgrade; fi
assert_network_unchanged update-distinct "$offline_before"
verify_host_services update-distinct
echo 'INSTALLED_DISTINCT_BINARY_UPDATE=PASS (same-source QA builds)'

# The previously installed modern release is no longer current. Uninstall
# must inspect ALL owned releases and refuse a damaged one BEFORE it stops
# the running product, even when the current release remains intact.
docker exec -i "$container" /bin/sh -s "$original_link" <<'QA_PROVENANCE_UNINSTALL'
set -eu
prior=$1
release=/opt/server-connect/$prior
[ -f "$release/checksums.sha256" ] && [ -f "$release/manifest.json" ]
active=$(readlink /opt/server-connect/current)
[ "$active" != "$prior" ]
systemctl is-active --quiet server-connect.service
digest=$(sha256sum /etc/systemd/system/server-connect.service | cut -d" " -f1)
cp -p "$release/checksums.sha256" /root/qa-old-provenance-checksums.saved
cp -p "$release/manifest.json" /root/qa-old-provenance-manifest.saved
rm "$release/checksums.sha256" "$release/manifest.json"
if /bin/sh /root/server-connect/install.sh --uninstall --local-qa \
    >/root/qa-old-provenance-refusal.log 2>&1; then
 echo "UNINSTALL_ACCEPTED_DAMAGED_NONCURRENT_RELEASE" >&2
 exit 1
fi
grep -F "unrecognized legacy release layout" /root/qa-old-provenance-refusal.log >/dev/null
systemctl is-active --quiet server-connect.service
[ "$(readlink /opt/server-connect/current)" = "$active" ]
[ "$(sha256sum /etc/systemd/system/server-connect.service | cut -d" " -f1)" = "$digest" ]
[ "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES ]
cp -p /root/qa-old-provenance-checksums.saved "$release/checksums.sha256"
cp -p /root/qa-old-provenance-manifest.saved "$release/manifest.json"
(cd "$release" && sha256sum --strict --quiet -c checksums.sha256)
rm -f /root/qa-old-provenance-checksums.saved /root/qa-old-provenance-manifest.saved \
      /root/qa-old-provenance-refusal.log
echo 'INSTALLED_NONCURRENT_DAMAGED_RELEASE_UNINSTALL_REFUSED=PASS (before service stop)'
QA_PROVENANCE_UNINSTALL
assert_network_unchanged noncurrent-modern-provenance-refusal "$offline_before"
verify_host_services noncurrent-modern-provenance-refusal

# The third binary is different and carries a deliberately broken service
# ExecStart. It must fail after switching and restore the ACTIVE prior proxy.
bad_release=$(docker exec "$container" /bin/sh -c '
  set -eu
  cd /root/server-connect-bad-update
  # Installed release identity is the complete checksum manifest, including
  # non-binary unit and source metadata, not only the two executables.
  hash=$(sha256sum checksums.sha256 | cut -c 1-16)
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
if [[ $qa_version == 13 ]]; then
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh positive after-rollback
docker exec "$container" /bin/sh /root/qa-wp-fpm.sh http-proxy-auth after-rollback
fi
docker exec "$container" /bin/sh /root/qa-proxy-only.sh upstream-failure upstream-after-rollback
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh upstream-failure after-rollback; fi
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
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh negative-disconnected; fi
docker exec "$container" /bin/sh /root/qa-apt-only.sh verify-host-policy
assert_network_unchanged disconnect "$offline_before"
verify_host_services disconnect
# Cross-mode recovery regression on the ALREADY configured real Proxy Only
# guest profile. The earlier native-only test proved Direct+residue cleanup;
# now prove the legacy Proxy+residue and partial failure-after-proxy-stop paths.
# The guest has --network none; no host or external service is touched.
docker exec -i "$container" /bin/sh -s <<'QANATIVEPROXY'
set -eu
sc=/usr/local/bin/server-connect
config=/var/lib/server-connect/native-tun.json
claim=/var/lib/server-connect/native-session.json
proxy=/var/lib/server-connect/runtime.json
unit=server-connect-native-tun.service
test ! -e "$config" && test ! -e "$claim" && test ! -e "$proxy"
test "$(systemctl is-active "$unit" || :)" = inactive
test "$(systemctl is-active server-connect.service || :)" = inactive
find /var/lib/server-connect/profiles -maxdepth 1 -type f -print0 |
  sort -z | xargs -0 sha256sum > /root/qa-native-proxy-profile-hashes

# A safe new Proxy Only Connect refuses the unresolved residual before
# writing any runtime credential or starting either owned service.
printf 'qa-inert-native-config\n' > "$config"
chmod 0600 "$config"
if "$sc" --json connect >/root/qa-native-proxy-connect-refusal.json; then
  echo 'NATIVE_PROXY_RESIDUE_CONNECT_REFUSAL=FAIL' >&2
  exit 1
fi
python3 -c 'import json
d=json.load(open("/root/qa-native-proxy-connect-refusal.json"))
assert d["ok"] is False and d["error"]["code"]=="guard_pending"'
test "$(systemctl is-active server-connect.service || :)" = inactive
test ! -e "$proxy" && test -e "$config"
echo 'NATIVE_PROXY_RESIDUE_CONNECT_REFUSAL=PASS'
"$sc" --json disconnect >/dev/null
test ! -e "$config"

# Recreate the PRE-PATCH reachable state with real Proxy Only active and a
# retained inert native config, without replaying the crash or networking.
"$sc" --json connect >/dev/null
test "$(systemctl is-active server-connect.service)" = active
printf 'qa-inert-native-config\n' > "$config"
chmod 0600 "$config"
if systemctl start "$unit" >/root/qa-native-proxy-failed-start.log 2>&1; then
  echo 'NATIVE_PROXY_FAILED_SERVICE=FAIL (unclaimed Core started)' >&2
  exit 1
fi
test "$(systemctl is-active "$unit" || :)" = failed
"$sc" --json disconnect >/dev/null
test "$(systemctl is-active server-connect.service || :)" = inactive
test "$(systemctl is-active "$unit" || :)" = inactive
test ! -e "$config" && test ! -e "$claim" && test ! -e "$proxy"
"$sc" --json native-status | python3 -c 'import json,sys
d=json.load(sys.stdin)["data"]
assert d["desired"]=="direct" and d["observed"]=="inactive" and not d["recovery_claim_present"]'
"$sc" --json disconnect >/dev/null
echo 'NATIVE_PROXY_RESIDUE_SINGLE_DISCONNECT=PASS (both owned units fully reconciled)'

# A failure AFTER Proxy Only systemctl start but BEFORE Desired=proxy was
# persisted can leave a genuinely ACTIVE owned proxy under saved Direct.
# Stage precisely that partial-write aftermath without trying to make the
# state directory unwritable (which would also sabotage safe Disconnect).
"$sc" --json connect >/dev/null
test "$(systemctl is-active server-connect.service)" = active
python3 - <<'PYPROXYSTATE'
import json,os
path="/var/lib/server-connect/state.json"
with open(path,encoding="utf-8") as f:
    state=json.load(f)
assert state["desired"]=="proxy"
state["desired"]="direct"
tmp=path+".qa-partial-write"
with open(tmp,"w",encoding="utf-8") as f:
    json.dump(state,f)
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp,0o600)
os.replace(tmp,path)
PYPROXYSTATE
printf 'qa-inert-native-config\n' > "$config"
chmod 0600 "$config"
if systemctl start "$unit" >/root/qa-native-proxy-failed-start.log 2>&1; then
  echo 'NATIVE_PROXY_FAILURE_BEFORE_MODE_SAVE=FAIL (unclaimed Core started)' >&2
  exit 1
fi
test "$(systemctl is-active "$unit" || :)" = failed
"$sc" --json disconnect >/dev/null
test "$(systemctl is-active server-connect.service || :)" = inactive
test "$(systemctl is-active "$unit" || :)" = inactive
test ! -e "$config" && test ! -e "$claim" && test ! -e "$proxy"
echo 'NATIVE_PROXY_FAILURE_BEFORE_MODE_SAVE=PASS (active Proxy retired despite saved Direct)'

# Failure of the SECOND owned cleanup must not be reported as success. The
# tamper is confined to the disposable guest; exact native unit bytes are
# restored before retry. No private profile or external resource is changed.
"$sc" --json connect >/dev/null
test "$(systemctl is-active server-connect.service)" = active
printf 'qa-inert-native-config\n' > "$config"
chmod 0600 "$config"
if systemctl start "$unit" >/root/qa-native-proxy-failed-start.log 2>&1; then
  echo 'NATIVE_PROXY_PARTIAL_FAILURE_SETUP=FAIL' >&2
  exit 1
fi
test "$(systemctl is-active "$unit" || :)" = failed
cp -p /etc/systemd/system/"$unit" /root/qa-native-proxy-original-unit
printf '\n#disconnected-qa-untrusted-unit-change\n' >> /etc/systemd/system/"$unit"
if "$sc" --json disconnect >/root/qa-native-proxy-partial.json; then
  echo 'NATIVE_PROXY_PARTIAL_FAILURE_REFUSED=FAIL (incorrect complete success)' >&2
  exit 1
fi
python3 -c 'import json
d=json.load(open("/root/qa-native-proxy-partial.json"))
assert d["ok"] is False and d["error"]["code"]=="service_conflict"'
test "$(systemctl is-active server-connect.service || :)" = inactive
test -e "$config" && test ! -e "$proxy"
cp -p /root/qa-native-proxy-original-unit /etc/systemd/system/"$unit"
"$sc" --json disconnect >/dev/null
test "$(systemctl is-active "$unit" || :)" = inactive
test "$(systemctl is-active server-connect.service || :)" = inactive
test ! -e "$config" && test ! -e "$claim" && test ! -e "$proxy"
(cd / && sha256sum --quiet -c /root/qa-native-proxy-profile-hashes)
for timer in server-connect-smart-health.timer server-connect-activation-recover.timer; do
  test "$(systemctl is-active "$timer" || :)" = inactive
done
rm -f /root/qa-native-proxy-connect-refusal.json /root/qa-native-proxy-failed-start.log \
      /root/qa-native-proxy-partial.json /root/qa-native-proxy-original-unit \
      /root/qa-native-proxy-profile-hashes
echo 'NATIVE_PROXY_PARTIAL_FAILURE_RETRY=PASS (error before complete cleanup, then safe retry)'
QANATIVEPROXY
assert_network_unchanged native-proxy-recovery "$offline_before"
test "$(docker exec "$container" /usr/sbin/nft -j list ruleset)" = "$nft_before"
verify_host_services native-proxy-recovery
echo 'NATIVE_PROXY_RECOVERY_BASELINE=PASS (unchanged kernel/nft and SSH/HTTP)'
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh cleanup; fi
run_offline uninstall --uninstall
verify_clean_uninstall
assert_network_unchanged uninstall "$offline_before"
verify_host_services uninstall

# R3-02: a genuine completed installed systemd footprint plus original
# inode-bound private receipts. Reconcile before touching any owned service,
# including a SIGKILL between the first and second retirement unlink. Do not
# invent an adoption rule for malformed/foreign residues.
echo '=== Real installed first-install receipt retirement and different-release reinstall ==='
run_offline first-retirement-install --offline
verify_direct_install
docker exec -i "$container" /usr/bin/python3 -I -S - <<'PY_COMMITTED_FIXTURE'
import os,pathlib
state=pathlib.Path('/var/lib/server-connect')
prefix=pathlib.Path('/opt/server-connect')
assert prefix.is_dir() and state.is_dir()
assert (state.stat().st_mode & 0o777)==0o700
assert not (state/'.first-install-intent').exists()
assert not (state/'.first-release-intent').exists()
target=(prefix/'current').readlink()
release=prefix/target
assert release.is_dir() and (prefix/'unit.sha256').is_file()
assert not list(pathlib.Path('/opt').glob('.server-connect-release.*'))
def claim(path, lines):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,lines.encode('ascii'));os.fsync(fd)
    finally:os.close(fd)
claim(state/'.first-install-intent',
      f"/opt/.server-connect-initial.QA123456\n{prefix.stat().st_dev}:{prefix.stat().st_ino}\n")
claim(state/'.first-release-intent',
      f"/opt/.server-connect-release.QA123456\n{release.stat().st_dev}:{release.stat().st_ino}\n{release.name}\n")
fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print('GUEST_COMMITTED_RECEIPT_FIXTURE=PASS (original owner/target/inodes; root-private)')
PY_COMMITTED_FIXTURE
# Before either unlink, the actual Installer must recognize the installed
# service as already committed instead of deleting/replacing it.
run_offline first-retirement-reconciled --offline
verify_direct_install
docker exec "$container" /bin/sh -c '
  set -eu
  test ! -e /var/lib/server-connect/.first-install-intent
  test ! -e /var/lib/server-connect/.first-release-intent
'
echo 'INSTALLED_FULL_TWO_INTENT_RECONCILE=PASS (full installed footprint preserved)'
assert_network_unchanged first-retirement-reconciled "$offline_before"
verify_host_services first-retirement-reconciled
# Recreate the exact two claims on the same verified service to simulate
# an abrupt SIGKILL in the tiny post-first-unlink/pre-second-unlink window.
docker exec -i "$container" /usr/bin/python3 -I -S - <<'PY_COMMITTED_WINDOW'
import os,pathlib
state=pathlib.Path('/var/lib/server-connect')
prefix=pathlib.Path('/opt/server-connect')
release=prefix/(prefix/'current').readlink()
for name,contents in (
 ('.first-install-intent',f"/opt/.server-connect-initial.QA123456\n{prefix.stat().st_dev}:{prefix.stat().st_ino}\n"),
 ('.first-release-intent',f"/opt/.server-connect-release.QA123456\n{release.stat().st_dev}:{release.stat().st_ino}\n{release.name}\n")
):
    fd=os.open(state/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:os.write(fd,contents.encode('ascii'));os.fsync(fd)
    finally:os.close(fd)
print('GUEST_COMMIT_RETIREMENT_WINDOW_ARMED=PASS')
PY_COMMITTED_WINDOW
run_offline first-retirement-verify-only --verify-only
if docker exec "$container" /bin/sh -c '
  set -eu
  test -f /var/lib/server-connect/.first-install-intent
  test -f /var/lib/server-connect/.first-release-intent
  rm /var/lib/server-connect/.first-install-intent
  kill -KILL $$
' >"$scratch/first-retirement-kill.out" 2>"$scratch/first-retirement-kill.err";then
  echo 'First-claim retirement injection unexpectedly survived SIGKILL' >&2
  exit 1
else
  killed_status=$?
  [[ $killed_status == 137 ]] || { echo "Unexpected retirement SIGKILL status $killed_status" >&2;exit 1; }
fi
docker exec "$container" /bin/sh -c '
 set -eu
 test ! -e /var/lib/server-connect/.first-install-intent
 test "$(stat -c "%u:%a:%h" /var/lib/server-connect/.first-release-intent)" = 0:600:1
 systemctl is-enabled server-connect.service | grep -Fx disabled
 test -f /opt/server-connect/current/manifest.json
'
echo 'ACTUAL_COMMIT_RECEIPT_RETIREMENT_SIGKILL=PASS (first unlinked, second intact, valid installed service)'
assert_network_unchanged first-retirement-kill "$offline_before"
verify_host_services first-retirement-kill
# Real uninstall must validate/reconcile the release-only orphan while it
# still has the corresponding installed bytes. It must NOT retire a marker
# merely because it has a familiar filename.
run_offline first-retirement-uninstall --uninstall
verify_clean_uninstall
docker exec "$container" test ! -e /var/lib/server-connect/.first-release-intent
assert_network_unchanged first-retirement-uninstall "$offline_before"
verify_host_services first-retirement-uninstall
# A distinct source/version, not only an identical retry, must now install
# and uninstall without seeing a stale receipt from the previous release.
run_offline first-retirement-different-release --offline /root/server-connect-update
verify_direct_install
docker exec "$container" /bin/sh -c '
 set -eu
 test ! -e /var/lib/server-connect/.first-release-intent
 test ! -e /var/lib/server-connect/.first-install-intent
 current=$(readlink /opt/server-connect/current)
 checksum=$(sha256sum /root/server-connect-update/checksums.sha256 | cut -c1-16)
 test "$current" = "releases/0.1.0-dev-$checksum"
'
assert_network_unchanged first-retirement-different-release "$offline_before"
verify_host_services first-retirement-different-release
run_offline first-retirement-different-release-uninstall --uninstall /root/server-connect-update
verify_clean_uninstall
assert_network_unchanged first-retirement-different-release-uninstall "$offline_before"
verify_host_services first-retirement-different-release-uninstall
echo 'REAL_COMMITTED_RECEIPT_SIGKILL_NEW_RELEASE_REINSTALL=PASS (both Debian versions)'

# Kill the *actual unmodified installer* at two observable filesystem
# transitions in an isolated Debian systemd guest. A distinct Python
# supervisor owns the PID; no system binary, source file or trust receipt is
# modified for fault injection. This is not a claim of physical host safety.
for kill_stage in payload-copy release-publication; do
  echo "=== Observed actual initial-installer SIGKILL: $kill_stage ==="
  docker exec -i "$container" /usr/bin/python3 -I -S - "$kill_stage" <<'PY_WATCH_INSTALL'
import os, pathlib, signal, subprocess, sys, time
stage = sys.argv[1]
prefix = pathlib.Path("/opt/server-connect")
state = pathlib.Path("/var/lib/server-connect")
assert stage in ("payload-copy", "release-publication")
assert not prefix.exists() and not prefix.is_symlink()
assert not (state / ".first-install-intent").exists()
assert not (state / ".first-release-intent").exists()
argv = ["/bin/sh", "/root/server-connect/install.sh", "--offline"]
proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, start_new_session=True,
                        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/root","LC_ALL":"C"})
witness = None
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    release_ready = (prefix / "releases").is_dir() and any(
        child.name.startswith("0.1.0-dev-") for child in (prefix / "releases").iterdir()
    )
    receipt_ready = (state / ".first-install-intent").is_file() and (
        state / ".first-release-intent").is_file()
    if stage == "payload-copy" and receipt_ready and not release_ready:
        for candidate in pathlib.Path("/opt").glob(".server-connect-release.*"):
            if ((candidate / "bin/server-connect").is_file()
                    and (candidate / "bin/sing-box").is_file()):
                witness = "partially or fully copied release Stage " + candidate.name
                break
    elif stage == "release-publication" and receipt_ready and release_ready:
        witness = "atomically published release directory before full commit"
    if witness:
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            witness = None
        break
    if proc.poll() is not None:
        break
    time.sleep(0.001)
if witness is None and proc.poll() is None:
    os.kill(proc.pid, signal.SIGKILL)
try:
    out, err = proc.communicate(timeout=18)
except subprocess.TimeoutExpired:
    proc.kill()
    out, err = proc.communicate(timeout=10)
if witness is None or proc.returncode != -signal.SIGKILL:
    print("FAILED actual installer interruption: desired stage=", stage,
          "witness=", witness, "exit=", proc.returncode, file=sys.stderr)
    print("stdout:", out[-1800:], "stderr:", err[-2400:], file=sys.stderr)
    sys.exit(1)
assert (state / ".first-install-intent").is_file()
assert (state / ".first-release-intent").is_file()
if stage == "payload-copy":
    assert not (pathlib.Path("/etc/systemd/system") / "server-connect.service").exists()
    assert not release_ready
else:
    assert any((prefix / "releases").glob("0.1.0-dev-*"))
assert not pathlib.Path("/usr/local/bin/server-connect").exists()
print(f"ACTUAL_INITIAL_INSTALL_SIGKILL_{stage}=PASS: {witness}; "
      f"PID={proc.pid} exit={proc.returncode}, no service or command")
PY_WATCH_INSTALL
  assert_network_unchanged "first-kill-$kill_stage" "$offline_before"
  verify_host_services "first-kill-$kill_stage"
  run_offline "first-retry-$kill_stage" --offline
  verify_direct_install
  docker exec "$container" /bin/sh -c '
    set -eu
    test ! -e /var/lib/server-connect/.first-install-intent
    test ! -e /var/lib/server-connect/.first-release-intent
    test -z "$(find /opt -maxdepth 1 -name ".server-connect-release.*" -print)"
  '
  assert_network_unchanged "first-retry-$kill_stage" "$offline_before"
  verify_host_services "first-retry-$kill_stage"
  run_offline "first-retry-$kill_stage-uninstall" --uninstall
  verify_clean_uninstall
  assert_network_unchanged "first-retry-$kill_stage-uninstall" "$offline_before"
  verify_host_services "first-retry-$kill_stage-uninstall"
done
echo 'INITIAL_INSTALL_REAL_SIGKILL_COPY_AND_PUBLISH_RETRY=PASS (both Debian versions, Direct, SSH/HTTP)'
echo 'DISCONNECTED_OFFLINE_CYCLE=PASS'
if [[ $qa_version == 13 ]]; then
echo 'LIMITATION: Proxy Only WordPress/PHP-FPM used guest loopback with QA-only WP_PROXY_*; transparent TUN WordPress used no application proxy and synthetic egress; physical host/foreign field acceptance is NOT_RUN'

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
else
  echo 'ACTIVATION_GUARD_FEASIBILITY=NOT_RUN (Debian12 native routing is outside this lane)'
fi

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
  --local-qa --archive-url http://localhost:19179/bundle.tar.gz --sha256 "$digest"
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

# The same immutable base archive also exercises the authenticated path.
# The public trust anchor is generated independently of the archive inside
# this existing disconnected disposable guest. It is an ephemeral QA key,
# never a selected publisher identity or public-release authorization.
echo '=== Signed offline install and retained offline uninstall (QA key) ==='
[[ -f "$bundle.release.json" && ! -L "$bundle.release.json" ]]
docker exec "$container" /bin/mkdir -m 0700 /root/qa-release-trust
docker cp "$bootstrap" "$container:/root/qa-release-trust/bootstrap-online.sh"
docker cp "$root/scripts/release-auth.py" "$container:/root/qa-release-trust/release-auth.py"
docker cp "$bundle.release.json" "$container:/root/qa-release-trust/release.json"
# docker cp retains source permission bits. Protect only these exact
# task-owned imports; never change /root or relax the production verifier.
# Report original metadata before replacing it with byte-identical root copies.
docker exec -i "$container" /usr/bin/env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/sh -s <<'QAPROTECT'
set -eu
umask 077
cd /root/qa-release-trust
for name in bootstrap-online.sh release-auth.py release.json archive.tar.gz; do
  source=$name
  if [ "$name" = archive.tar.gz ]; then source=/root/sc-qa-bundle.tar.gz; fi
  test -f "$source" && test ! -L "$source"
  test "$(stat -c %h -- "$source")" = 1
  stat -c 'SIGNED_QA_IMPORTED_INPUT path=%n uid=%u gid=%g mode=%a' -- "$source"
  test ! -e "protected-$name" && test ! -L "protected-$name"
  install -m 0600 -- "$source" "protected-$name"
  cmp -- "$source" "protected-$name"
  mv -T -- "protected-$name" "$name"
  test "$(stat -c %u:%a:%h -- "$name")" = 0:600:1
done
echo 'SIGNED_QA_IMPORTED_INPUTS_PROTECTED=PASS'
QAPROTECT
docker exec -i -e "SC_QA_DEBIAN_VERSION=$qa_version" "$container" /usr/bin/env -i \
  HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  "SC_QA_DEBIAN_VERSION=$qa_version" /bin/sh -s <<'QASIGN'
set -eu
umask 077
cd /root/qa-release-trust
# Keep any unrelated unsafe ancestry/payload as a hard failure with precise
# metadata diagnostics; do not normalize an extracted tree or an ancestor.
stat -c 'SIGNED_QA_SIGNER_PATH path=%n uid=%u gid=%g mode=%a' -- \
  / /root /root/qa-release-trust /root/server-connect \
  /root/server-connect/manifest.json /root/server-connect/checksums.sha256
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ephemeral-private.pem >/dev/null 2>&1
openssl pkey -in ephemeral-private.pem -pubout -out independent-public.pem >/dev/null 2>&1
python3 -I -B release-auth.py sign-local-qa \
  --metadata /root/qa-release-trust/release.json \
  --signature /root/qa-release-trust/release.sig \
  --signing-key /root/qa-release-trust/ephemeral-private.pem \
  --version 0.1.0-dev --target "debian-$SC_QA_DEBIAN_VERSION-amd64" \
  --archive /root/qa-release-trust/archive.tar.gz --bundle /root/server-connect
QASIGN
signed_before=$(network_digest)
# R3-01: real Signed first-install receipt creation, interrupted by SIGKILL
# at the two formerly ambiguous auth publication boundaries. A fresh,
# unmodified installer must cryptographically inspect/cleanup each stage and
# re-install the *same* Signed bundle. This runs in root Debian 12 and 13,
# never on the host or runner.
docker cp "$root/scripts/qa/signed-first-interruption.py" "$container:/root/qa-signed-first-interruption.py"
for signed_kill in before after; do
  docker exec "$container" /usr/bin/python3 -I -S /root/qa-signed-first-interruption.py \
    "$signed_kill" "$qa_version"
  assert_network_unchanged "signed-first-kill-$signed_kill" "$signed_before"
  verify_host_services "signed-first-kill-$signed_kill"
  docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
    -e trace=%network,%process -o "/root/qa-strace/signed-first-retry-$signed_kill" \
    /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh /root/server-connect/install.sh --offline \
    --metadata-file /root/qa-release-trust/release.json \
    --signature-file /root/qa-release-trust/release.sig \
    --publisher-key /root/qa-release-trust/independent-public.pem \
    --version 0.1.0-dev --target "debian-$qa_version-amd64"
  assert_no_offline_fetch "signed-first-retry-$signed_kill"
  verify_direct_install
  docker exec "$container" /bin/sh -c '
    set -eu
    test ! -e /var/lib/server-connect/.first-install-intent
    test ! -e /var/lib/server-connect/.first-release-intent
    test -z "$(find /opt -maxdepth 1 -name ".server-connect-release.*" -print)"
    test ! -e /opt/server-connect/releases/.stage.AUTHPRE0
    test ! -e /opt/server-connect/releases/.stage.AUTHPOST
    test -f /opt/server-connect/current/authentication.json
    test "$(stat -c "%u:%a:%h" /opt/server-connect/current/authentication.json)" = 0:600:1
  '
  assert_network_unchanged "signed-first-retry-$signed_kill" "$signed_before"
  verify_host_services "signed-first-retry-$signed_kill"
  run_offline "signed-first-retry-$signed_kill-uninstall" --uninstall
  verify_clean_uninstall
  assert_network_unchanged "signed-first-retry-$signed_kill-uninstall" "$signed_before"
  verify_host_services "signed-first-retry-$signed_kill-uninstall"
done
echo 'SIGNED_FIRST_INSTALL_REAL_SIGKILL_ANONYMOUS_PUBLICATION_RETRY=PASS (Debian12/13, crypto and Direct verified)'
docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
  -e trace=%network,%process -o /root/qa-strace/signed-offline-install \
  /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/qa-release-trust/bootstrap-online.sh \
  --archive-file /root/qa-release-trust/archive.tar.gz \
  --metadata-file /root/qa-release-trust/release.json \
  --signature-file /root/qa-release-trust/release.sig \
  --publisher-key /root/qa-release-trust/independent-public.pem \
  --version 0.1.0-dev --target "debian-$qa_version-amd64"
assert_no_offline_fetch signed-offline-install
verify_direct_install
assert_network_unchanged signed-offline-install "$signed_before"
verify_host_services signed-offline-install
signed_release=$(docker exec "$container" /usr/bin/readlink -f /opt/server-connect/current)
[[ $signed_release =~ ^/opt/server-connect/releases/0\.1\.0-dev-[a-f0-9]{16}$ ]]
docker exec -i "$container" /bin/sh -s "$signed_release" <<'QARETAINED'
set -eu
release=$1
test -f "$release/authentication.json" && test ! -L "$release/authentication.json"
test "$(stat -c %u:%a:%h "$release/authentication.json")" = 0:600:1
test ! -e "$release/local-qa.sha256"
python3 -I -B /root/qa-release-trust/release-auth.py verify-installed --bundle "$release"
# Remove only the exact transient inputs in this newly created QA directory.
# Later verification and uninstall cannot reuse bootstrap staging or keys.
rm -- /root/qa-release-trust/ephemeral-private.pem \
  /root/qa-release-trust/independent-public.pem \
  /root/qa-release-trust/release.json /root/qa-release-trust/release.sig \
  /root/qa-release-trust/archive.tar.gz
test ! -e /root/qa-release-trust/ephemeral-private.pem
test ! -e /root/qa-release-trust/independent-public.pem
test ! -e /root/qa-release-trust/release.json
test ! -e /root/qa-release-trust/release.sig
test ! -e /root/qa-release-trust/archive.tar.gz
test -z "$(find /root -maxdepth 1 -name ".server-connect-bootstrap.*" -print)"
QARETAINED
for action in verify-only uninstall; do
  docker exec "$container" /usr/bin/strace -ff -qq -yy -s 128 \
    -e trace=%network,%process -o "/root/qa-strace/signed-retained-$action" \
    /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /bin/sh "$signed_release/install.sh" "--$action"
  assert_no_offline_fetch "signed-retained-$action"
  assert_network_unchanged "signed-retained-$action" "$signed_before"
  verify_host_services "signed-retained-$action"
done
verify_clean_uninstall
docker exec "$container" /bin/sh -c '
  set -eu
  test ! -e /opt/server-connect
  rm -- /root/qa-release-trust/bootstrap-online.sh /root/qa-release-trust/release-auth.py
  rmdir /root/qa-release-trust
'
echo 'SIGNED_OFFLINE_INSTALL_RETAINED_AUTH_UNINSTALL=PASS (ephemeral QA key; original sidecars and key removed)'

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
if [[ $qa_version == 13 ]]; then
  bash scripts/qa/test-activation-boot-qa.sh "$image" "$container"
else
  echo 'NATIVE_ACTIVATION_BOOT_RECOVERY=NOT_RUN (Debian12 roles were verified inert; no reboot acceptance)'
fi
printf 'INSTALLED_DEBIAN%s_LIFECYCLE=PASS\n' "$qa_version"
echo 'LIMITATION: guest-loopback SSH/HTTP checks do not prove external SSH/aaPanel, foreign VPN reachability, reboot or field safety'
