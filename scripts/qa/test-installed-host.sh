#!/usr/bin/env bash
# Exact QA-only lifecycle in ephemeral Debian 12/13 systemd containers.
# Debian13 retains the full native experiment. Debian12 proves installed
# Direct/Proxy Only compatibility and an explicit native-Apply refusal.
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
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-smart-health-wire.py
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/qa/test-supervised-fixture.py
sh -n scripts/qa/tun-wordpress-fpm.sh
# The guard feasibility probe must be strictly guest-local and must reject
# ambiguous kernel identities before the privileged disconnected guest runs.
sh -n scripts/qa/host-activation-guard.sh
sh -n scripts/qa/host-product-guard-trial.sh
sh -n scripts/qa/host-tun-path.sh
sh -n scripts/qa/host-product-tun-trial.sh
sh -n scripts/qa/host-supervised-product-tun.sh
sh -n scripts/qa/host-native-product-tun.sh
sh -n scripts/qa/host-owned-tun-boundary.sh
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
for source in ('supervised-product-tun.py', 'smart-health-responder.py', 'smart-health-client.py'):
    ast.parse(Path('scripts/qa', source).read_text())
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
if [[ $qa_version == 13 ]]; then
  CGO_ENABLED=0 go test -c -o "$scratch/qa-native-nft-cas-test" ./internal/sc
fi

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
docker cp "$root/scripts/qa/host-native-product-tun.sh" "$container:/root/qa-native-product-tun.sh"

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
mutator_log="$scratch/native-mutator-lifetime.log"
docker exec "$container" /bin/sh /root/qa-native-product-tun.sh mutator-lifetime | tee "$mutator_log"
grep -Fx 'NATIVE_MUTATOR_IP_FD3_DEATH=PASS' "$mutator_log" >/dev/null
grep -Fx 'NATIVE_MUTATOR_NFT_FD3_DEATH=PASS' "$mutator_log" >/dev/null
assert_network_unchanged native-mutator-lifetime "$native_nft_network_before"
native_mutator_nft_after=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
[[ $native_mutator_nft_after == "$native_nft_before" ]]
echo NATIVE_MUTATOR_INDEPENDENT_BASELINE=PASS
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
    test "$(systemctl show server-connect-smart-tun.service -p LoadState --value)" = loaded
    test "$(systemctl show server-connect-smart-tun.service -p UnitFileState --value)" = static
    test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
    test "$(systemctl show server-connect-smart-health.service -p LoadState --value)" = loaded
    test "$(systemctl show server-connect-smart-health.service -p UnitFileState --value)" = static
    test "$(systemctl show server-connect-smart-health.service -p ActiveState --value)" = inactive
    test "$(systemctl show server-connect-smart-health.timer -p LoadState --value)" = loaded
    test "$(systemctl show server-connect-smart-health.timer -p ActiveState --value)" = inactive
    test "$(systemctl is-enabled server-connect-smart-health.timer)" = disabled
    test "$(systemctl show server-connect-activation-recover.service -p LoadState --value)" = loaded
    for name in server-connect-activation-recover.service server-connect-smart-tun.service server-connect-smart-health.service; do
      test "$(systemctl show "$name" -p FragmentPath --value)" = "/etc/systemd/system/$name"
      test -z "$(systemctl show "$name" -p DropInPaths --value)"
      test "$(systemctl show "$name" -p Transient --value)" = no
      test "$(systemctl show "$name" -p UnitFileState --value)" = static
      test "$(systemctl show "$name" -p ActiveState --value)" = inactive
      test "$(systemctl show "$name" -p MainPID --value)" = 0
      test "$(systemctl show "$name" -p ControlPID --value)" = 0
      test -z "$(systemctl show "$name" -p Job --value)"
    done
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
    test ! -e /etc/systemd/system/server-connect-smart-health.service
    test ! -e /etc/systemd/system/server-connect-smart-health.timer
    test "$(stat -c %a /var/lib/server-connect)" = 700
    test "$(stat -c %a /var/lib/server-connect/profiles)" = 700
    test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
  '
}

run_offline verify-only --verify-only
assert_network_unchanged verify-only "$offline_before"
verify_host_services verify-only
docker exec "$container" /bin/sh -c 'test ! -e /opt/server-connect && test ! -e /var/lib/server-connect'
docker cp "$root/scripts/qa/host-bundle-target-refusal.sh" "$container:/root/qa-bundle-target-refusal.sh"
docker exec "$container" /bin/sh /root/qa-bundle-target-refusal.sh
assert_network_unchanged bundle-target-refusals "$offline_before"
verify_host_services bundle-target-refusals
docker exec "$container" /bin/rm -- /root/qa-bundle-target-refusal.sh

if [[ $qa_version == 12 ]]; then
  saved_refusal_nft=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
  # Real saved-Apply entry points, before installation, in the disconnected
  # guest only. Failed assertions retain unexpected state for guest teardown.
  docker exec -i "$container" python3 - <<'PYSAVEDREFUSAL'
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

state = Path('/var/lib/server-connect')
policy = state / 'smart-tun-policy.json'
manager = '/root/server-connect/bin/server-connect'
expected = {
    'code': 'trial_unsupported',
    'message': 'native trials require Debian 13; Debian 12 installation supports Direct/Proxy Only only',
}
units = (
    'server-connect.service',
    'server-connect-activation-recover.service',
    'server-connect-activation-recover.timer',
    'server-connect-smart-tun.service',
    'server-connect-smart-health.service',
    'server-connect-smart-health.timer',
)

def absent_product():
    for path in ('/opt/server-connect', '/usr/local/bin/server-connect'):
        assert not os.path.lexists(path), 'unexpected installed product path'
    for unit in units:
        assert not os.path.lexists('/etc/systemd/system/' + unit), 'unexpected product unit'
        result = subprocess.run(
            ['systemctl', 'show', unit, '-p', 'LoadState', '--value'],
            capture_output=True, text=True, timeout=10)
        assert result.returncode in (0, 1) and result.stdout.strip() == 'not-found', \
            'product unit no longer absent'

def snapshot():
    if not os.path.lexists(state):
        return None
    root = state.lstat()
    assert stat.S_ISDIR(root.st_mode) and root.st_uid == 0
    paths = [state] + sorted(state.iterdir())
    records = []
    for path in paths:
        info = path.lstat()
        record = [
            str(path.relative_to(state)), info.st_dev, info.st_ino,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        ]
        if path != state:
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, \
                'unexpected state object'
            record.append(hashlib.sha256(path.read_bytes()).hexdigest())
        records.append(record)
    return records

valid = {
    'version': 1,
    'management_peer_ip': '10.254.72.2',
    'options': {
        'tunnel_interface': 'sctunqa0',
        'underlay_interface': 'scqaedge0',
        'tunnel_ipv4': '172.31.99.1/30',
        'tunnel_ipv6': '',
        'protected_cidrs': ['10.254.72.0/30'],
        'protected_ipv6_cidrs': [],
        'domestic_cidrs': ['5.22.0.10/32'],
        'domestic_ipv6_cidrs': [],
        'exceptions': [],
        'ipv6_exceptions': [],
        'domain_exceptions': [],
    },
}
cases = (
    ('absent', None),
    ('empty', None),
    ('malformed', b'{"version":'),
    ('valid', (json.dumps(valid, separators=(',', ':')) + '\n').encode()),
)
absent_product()
for label, content in cases:
    assert not os.path.lexists(state), 'prior state fixture remains'
    if label != 'absent':
        state.mkdir(mode=0o700)
    if content is not None:
        fd = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
    before = snapshot()
    for supervised in (False, True):
        args = [manager, '--json', 'smart-tun-trial-apply',
                '--saved', '--deadline-seconds', '600']
        if supervised:
            args.append('--supervised')
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        assert result.returncode == 1, 'saved Apply was not refused'
        reply = json.loads(result.stdout)
        assert reply['ok'] is False and reply['error'] == expected, \
            'saved Apply did not report the platform refusal'
        assert snapshot() == before, 'saved Apply mutated private state'
        absent_product()
        form = 'supervised' if supervised else 'pending'
        print(f'DEBIAN12_SAVED_APPLY_REFUSAL({label},{form})=PASS', flush=True)
    # Delete only exact unchanged fixtures; never erase unexpected state.
    assert snapshot() == before
    if content is not None:
        policy.unlink()
    if label != 'absent':
        state.rmdir()
assert not os.path.lexists(state)
PYSAVEDREFUSAL
  [[ $(docker exec "$container" /usr/sbin/nft -j list ruleset) == "$saved_refusal_nft" ]]
  assert_network_unchanged debian12-saved-apply-refusals "$offline_before"
  verify_host_services debian12-saved-apply-refusals
  echo 'DEBIAN12_SAVED_APPLY_PLATFORM_REFUSAL=PASS (both forms, four state cases, inert product)'
fi

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
    ("smart_routing","disposable_guest_only",False),
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
assert '"availability": "disposable_guest_only"' in message
assert '"general_host_activation": false' in message
PYMODEMENU
assert_network_unchanged installed-mode-overview "$offline_before"
verify_host_services installed-mode-overview
echo 'INSTALLED_OPERATOR_MODE_OVERVIEW=PASS (inactive service, honest Direct unknown, non-admitted TUN, CLI/menu parity)'
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
if [[ $qa_version == 12 ]]; then
  native_refusal_nft=$(docker exec "$container" /usr/sbin/nft -j list ruleset)
  private_state_digest() {
    docker exec -i "$container" python3 - <<'PYSTATE'
import hashlib,json,os,stat
from pathlib import Path
root=Path('/var/lib/server-connect')
records=[]
for directory,dirs,files in os.walk(root,followlinks=False):
    for name in ['.']+sorted(dirs+files):
        path=Path(directory) if name=='.' else Path(directory)/name
        info=path.lstat()
        record=[str(path.relative_to(root)),stat.S_IFMT(info.st_mode),stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid]
        if stat.S_ISREG(info.st_mode):record.append(hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISLNK(info.st_mode):record.append(os.readlink(path))
        records.append(record)
print(hashlib.sha256(json.dumps(sorted(records),separators=(',',':')).encode()).hexdigest())
PYSTATE
  }
  native_refusal_state=$(private_state_digest)
  if docker exec "$container" /usr/local/bin/server-connect --json smart-tun-trial-apply \
      --tunnel-if sctunqa0 --underlay-if scqaedge0 --tunnel-ipv4 172.31.99.1/30 \
      --management-peer 10.254.72.2 --domestic-cidr 5.22.0.10/32 \
      --protected-cidr 10.254.72.0/30 --deadline-seconds 600 \
      >"$scratch/debian12-native-refusal.json"; then
    echo 'DEBIAN12_NATIVE_APPLY_PLATFORM_REFUSAL=FAIL (Apply accepted)' >&2
    exit 1
  else
    native_refusal_rc=$?
  fi
  [[ $native_refusal_rc == 1 ]]
  python3 - "$scratch/debian12-native-refusal.json" <<'PYNATIVEREFUSAL'
import json,sys
with open(sys.argv[1],encoding='utf-8') as source: reply=json.load(source)
assert reply['ok'] is False
assert reply['error']=={
    'code':'trial_unsupported',
    'message':'native trials require Debian 13; Debian 12 installation supports Direct/Proxy Only only',
}
PYNATIVEREFUSAL
  [[ $(private_state_digest) == "$native_refusal_state" ]]
  [[ $(docker exec "$container" /usr/sbin/nft -j list ruleset) == "$native_refusal_nft" ]]
  verify_direct_install
  assert_network_unchanged debian12-native-apply-refusal "$offline_before"
  verify_host_services debian12-native-apply-refusal
  echo 'DEBIAN12_NATIVE_APPLY_PLATFORM_REFUSAL=PASS (exact OS reason, unchanged private/network state, inert guards)'
fi
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
if [[ $qa_version == 13 ]]; then
# A REAL Linux TUN+VLESS path is exercised only in the disconnected
# disposable guest; the installed product still has no public TUN Apply.
echo 'REAL_TUN_LAB_STAGE=build-guest-generator'
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o "$scratch/tun-config-qa" ./scripts/qa/tun_config_generator.go
test -x "$scratch/tun-config-qa"
docker cp "$scratch/tun-config-qa" "$container:/root/qa-tun-config-qa"
# The actual guest generator must refuse all unsafe Direct admissions
# BEFORE it emits runnable config or starts any TUN. This complements Go
# boundary tests with a disconnected installed-host execution witness.
for fault in broad-operator-direct aggregate-operator-direct \
             broad-domestic-direct aggregate-domestic-direct \
             domestic-rfc1918-overlap domestic-link-local-overlap \
             domestic-special-anycast; do
  rejected_config="$scratch/tun-direct-rejected-$fault.json"
  rejected_log="$scratch/tun-direct-rejected-$fault.stderr"
  if docker exec -e "SC_QA_TUN_IPV4_ADMISSION=$fault" \
      "$container" /root/qa-tun-config-qa >"$rejected_config" 2>"$rejected_log"; then
    echo "REAL_TUN_IPV4_DIRECT_ADMISSION=FAIL ($fault unexpectedly accepted)" >&2
    exit 1
  fi
  test ! -s "$rejected_config" || {
    echo "REAL_TUN_IPV4_DIRECT_ADMISSION=FAIL ($fault emitted config)" >&2
    exit 1
  }
  case "$fault" in
    broad-operator-direct)
      expected='IPv4 operator Direct exception exceeds /24 breadth' ;;
    aggregate-operator-direct)
      expected='aggregate IPv4 operator Direct exceptions exceed 64 distinct /24s' ;;
    broad-domestic-direct)
      expected='invalid, nonpublic or broad IPv4 domestic Direct prefix' ;;
    aggregate-domestic-direct)
      expected='aggregate IPv4 domestic Direct address coverage exceeds candidate limit' ;;
    domestic-rfc1918-overlap|domestic-link-local-overlap|domestic-special-anycast)
      expected='IPv4 domestic Direct prefix intersects special-purpose or nonpublic space' ;;
  esac
  grep -Fx "QA candidate generation failed: $expected" "$rejected_log" >/dev/null || {
    echo "REAL_TUN_IPV4_DIRECT_ADMISSION=FAIL ($fault wrong rejection)" >&2
    cat "$rejected_log" >&2
    exit 1
  }
done
echo 'REAL_TUN_IPV4_DIRECT_ADMISSION=PASS (invalid broad and aggregate Direct policies produce no runnable config)'
docker cp "$root/scripts/qa/tun-dns-peer.py" "$container:/root/qa-tun-dns-peer.py"
docker cp "$root/scripts/qa/tun-dns-client.py" "$container:/root/qa-tun-dns-client.py"
docker cp "$root/scripts/qa/tun-sni-client.py" "$container:/root/qa-tun-sni-client.py"
docker cp "$root/scripts/qa/tun-native-apps.py" "$container:/root/qa-tun-native-apps.py"
docker cp "$root/scripts/qa/tun-payload-wire.py" "$container:/root/qa-tun-payload-wire.py"
docker cp "$root/scripts/qa/tun-ipv6-wire.py" "$container:/root/qa-tun-ipv6-wire.py"
docker cp "$root/scripts/qa/tun-wordpress-fpm.sh" "$container:/root/qa-tun-wordpress-fpm.sh"
docker cp "$root/scripts/qa/tun-wp-check.py" "$container:/root/qa-tun-wp-check.py"
docker cp "$root/scripts/qa/host-tun-path.sh" "$container:/root/qa-host-tun-path.sh"
docker cp "$root/scripts/qa/host-product-tun-trial.sh" "$container:/root/qa-product-tun-trial.sh"
docker cp "$root/scripts/qa/host-supervised-product-tun.sh" "$container:/root/qa-supervised-product-tun.sh"
docker cp "$root/scripts/qa/supervised-product-tun.py" "$container:/root/qa-supervised-product-tun.py"
docker cp "$root/scripts/qa/smart-health-responder.py" "$container:/root/qa-smart-health-responder.py"
docker cp "$root/scripts/qa/smart-health-client.py" "$container:/root/qa-smart-health-client.py"
# Transfer only the exact source fixture bytes, never checkout ownership/modes.
# The guest creates private objects afresh; an incomplete stage aborts this
# harness and is retained for the existing exact disposable-container teardown.
tls_fixture_manifest="$scratch/smart-health-tls.sha256"
tls_fixture_packet="$scratch/smart-health-tls.json"
PYTHONDONTWRITEBYTECODE=1 python3 -I -B - "$root/internal/sc/testdata/smart-health-tls" \
    "$tls_fixture_packet" "$tls_fixture_manifest" <<'PYTLSINPUT'
import base64, hashlib, json, os, pathlib, stat, sys

def prepare_tls_fixture(source):
    names = {"qa-root.pem", "qa-server.pem", "qa-server-key.pem", "qa-wrong-name.pem", "qa-wrong-trust.pem",
             "qa-wrong-root.pem", "qa-expired.pem", "qa-client-auth-only.pem"}
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    directory = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(directory)
        assert set(os.listdir(directory)) == names, "TLS fixture source set changed"
        packet, manifest, identities = {}, [], {}
        for name in sorted(names):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 4096, \
                    f"TLS source refused: {name} mode={oct(info.st_mode)} uid={info.st_uid} links={info.st_nlink} size={info.st_size}"
                data = handle.read(4097)
                assert len(data) == info.st_size and identity(os.fstat(handle.fileno())) == identity(info)
                assert identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(info), "TLS source replaced"
                identities[name] = identity(info)
            digest = hashlib.sha256(data).hexdigest()
            packet[name] = {"data": base64.b64encode(data).decode("ascii"), "sha256": digest}
            manifest.append(f"{digest}  ./{name}\n")
        for name in sorted(names):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                assert identity(info) == identities[name], "TLS source changed after read"
                data = handle.read(4097)
                assert len(data) == info.st_size and hashlib.sha256(data).hexdigest() == packet[name]["sha256"], "TLS source content changed after read"
                assert identity(os.fstat(handle.fileno())) == identities[name], "TLS source changed during final read"
                assert identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identities[name], "TLS source replaced during final read"
        assert set(os.listdir(directory)) == names and identity(os.fstat(directory)) == identity(before)
        assert identity(source.lstat()) == identity(before), "TLS source directory replaced"
        encoded = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("ascii")
        assert 0 < len(encoded) <= 65536
        return encoded, "".join(manifest).encode("ascii")
    finally:
        os.close(directory)

if __name__ == "__main__":
    packet, manifest = prepare_tls_fixture(pathlib.Path(sys.argv[1]))
    for name, data in ((sys.argv[2], packet), (sys.argv[3], manifest)):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
PYTLSINPUT
docker exec -i "$container" /usr/bin/python3 -I -B -c "$(cat <<'PYTLSSTAGE'
import base64, hashlib, json, os, pathlib, stat, sys

def stage_tls_fixture(parent, raw):
    names = {"qa-root.pem", "qa-server.pem", "qa-server-key.pem", "qa-wrong-name.pem", "qa-wrong-trust.pem",
             "qa-wrong-root.pem", "qa-expired.pem", "qa-client-auth-only.pem"}
    assert 0 < len(raw) <= 65536, "TLS fixture packet exceeds its bound"
    packet, contents = json.loads(raw), {}
    assert type(packet) is dict and set(packet) == names, "TLS fixture packet set changed"
    assert json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("ascii") == raw, "TLS fixture packet is not canonical"
    for name in sorted(names):
        item = packet[name]
        assert type(item) is dict and set(item) == {"data", "sha256"}, "TLS fixture packet shape changed"
        data = base64.b64decode(item["data"], validate=True)
        assert 0 < len(data) <= 4096 and hashlib.sha256(data).hexdigest() == item["sha256"], "TLS fixture packet digest changed"
        contents[name] = data
    owner, root_name, receipt_name = os.geteuid(), "qa-smart-health-tls", "qa-smart-health-tls-receipt.json"
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_uid]
    def diagnostic(info):
        return f"mode={oct(info.st_mode)} uid={info.st_uid} gid={info.st_gid} links={info.st_nlink}"
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = None
    try:
        parent_info = os.fstat(parent_fd)
        assert parent_info.st_uid == owner and not parent_info.st_mode & 0o022, "TLS parent refused: " + diagnostic(parent_info)
        for name in (root_name, receipt_name):
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise AssertionError("TLS fixture path already exists: " + name + " " + diagnostic(info))
        assert identity(parent.lstat()) == identity(parent_info), "TLS fixture parent replaced before creation"
        os.mkdir(root_name, 0o700, dir_fd=parent_fd)
        created = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        directory = os.open(root_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(directory)
        assert identity(info) == identity(created) and stat.S_ISDIR(info.st_mode) and info.st_uid == owner \
            and stat.S_IMODE(info.st_mode) == 0o700, "TLS directory refused: " + diagnostic(info)
        receipt = {"parent": identity(parent_info), "directory": identity(info), "files": {}}
        def unchanged():
            assert identity(parent.lstat()) == receipt["parent"], "TLS fixture parent replaced"
            current = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
            assert identity(current) == receipt["directory"], "TLS fixture directory replaced: " + diagnostic(current)
        for name in sorted(names):
            unchanged()
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb") as handle:
                info = os.fstat(handle.fileno())
                assert stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 \
                    and stat.S_IMODE(info.st_mode) == 0o600, "TLS file refused: " + name + " " + diagnostic(info)
                created_file = identity(info)
                assert handle.write(contents[name]) == len(contents[name])
                handle.flush()
                os.fsync(handle.fileno())
                info = os.fstat(handle.fileno())
                assert identity(info) == created_file and info.st_nlink == 1 and info.st_size == len(contents[name]), "TLS created file changed"
            receipt["files"][name] = identity(info) + [info.st_size, packet[name]["sha256"]]
        unchanged()
        assert set(os.listdir(directory)) == names, "TLS staged fixture set changed"
        for name in sorted(names):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                data = handle.read(4097)
                assert identity(info) + [info.st_size, hashlib.sha256(data).hexdigest()] == receipt["files"][name], "TLS staged file changed"
                after = os.fstat(handle.fileno())
                assert identity(after) + [after.st_size, after.st_mtime_ns, after.st_ctime_ns] \
                    == identity(info) + [info.st_size, info.st_mtime_ns, info.st_ctime_ns], "TLS staged file changed during readback"
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                assert identity(current) + [current.st_size] == receipt["files"][name][:-1], "TLS staged file replaced"
        os.fsync(directory)
        unchanged()
        encoded_receipt = json.dumps(receipt, sort_keys=True).encode("ascii")
        descriptor = os.open(receipt_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        with os.fdopen(descriptor, "w+b") as handle:
            info = os.fstat(handle.fileno())
            assert info.st_uid == owner and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "TLS receipt refused: " + diagnostic(info)
            assert handle.write(encoded_receipt) == len(encoded_receipt)
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0)
            assert handle.read(8193) == encoded_receipt, "TLS receipt readback changed"
            assert identity(os.fstat(handle.fileno())) == identity(info), "TLS receipt metadata changed"
        unchanged()
        assert identity(os.stat(receipt_name, dir_fd=parent_fd, follow_symlinks=False)) == identity(info), "TLS receipt replaced"
        os.fsync(parent_fd)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent_fd)

if __name__ == "__main__":
    assert os.geteuid() == 0, "TLS fixture staging requires the disposable root guest"
    stage_tls_fixture(pathlib.Path("/root"), sys.stdin.buffer.read(65537))
PYTLSSTAGE
)" <"$tls_fixture_packet"
docker exec -i -w /root/qa-smart-health-tls "$container" sha256sum -c - <"$tls_fixture_manifest"
docker cp "$root/scripts/qa/host-owned-tun-boundary.sh" "$container:/root/qa-owned-tun-boundary.sh"
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
assert_tun_native_cleanup ipv4-direct-rejected-before-tun
echo 'REAL_TUN_LAB_STAGE=execute-guest-path'
regular_tun_log="$scratch/real-tun-domain-path.log"
docker exec "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$regular_tun_log"
grep -Fx 'REAL_TUN_SNIFFED_DOMAIN_EXCEPTION=PASS (VPN-only HTTP names; no Direct leak)' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_TLS_SNI_BASELINE=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_TLS_SNI_VPN_ONLY=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_TLS_SNI_NO_DIRECT_ON_UPSTREAM_LOSS=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_NATIVE_APPS_BASELINE=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_NATIVE_APPS_SELECTED_WITNESS=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_NATIVE_APPS_OUTAGE_WITNESS=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_WORDPRESS_positive_WITNESS=PASS' "$regular_tun_log" >/dev/null
grep -F 'REAL_TUN_WORDPRESS_negative_WITNESS=PASS' "$regular_tun_log" >/dev/null
grep -Fx 'REAL_TUN_PAYLOAD_DIRECT_BASELINE=PASS (TCP and UDP independent native counters)' "$regular_tun_log" >/dev/null
grep -Fx 'REAL_TUN_PAYLOAD_REDUCED_MTU=PASS (real VLESS TCP/UDP echo, MTU 1280, no native Direct leak)' "$regular_tun_log" >/dev/null
grep -Fx 'REAL_TUN_PAYLOAD_OUTAGE=PASS (large TCP/UDP fail closed, no native Direct packets)' "$regular_tun_log" >/dev/null
grep -Fx 'REAL_TUN_PAYLOAD_DF_LIMIT=PASS (oversized DF datagram rejected locally)' "$regular_tun_log" >/dev/null
assert_tun_native_cleanup real-tun-candidate-cleanup
# Separately opt in to the actual dual-stack candidate. Preserve every legacy
# IPv4/default trial unchanged; only the second synthetic guest trial enables
# IPv6 routing. Fresh peer counters and teardown evidence are mandatory.
echo 'REAL_TUN_LAB_STAGE=disconnected-dual-stack-ipv6'
ipv6_tun_log="$scratch/real-tun-ipv6-path.log"
docker exec -e SC_QA_TUN_IPV6=yes "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$ipv6_tun_log"
grep -Fx 'REAL_TUN_IPV6_DIRECT_BASELINE=PASS (independent TCP/UDP source and native counters)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_OVERRIDE_UDP_DIRECT_BASELINE=PASS (native UDP positive-controlled counter)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_EXPLICIT_DIRECT_UDP_SELECTED=PASS (exact source and payload)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_OVERRIDE_UDP_SELECTED=PASS (VLESS source and unchanged native UDP counter)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_SELECTED=PASS (native domestic Direct, explicit override, foreign VLESS, no Direct leak)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_EXPLICIT_DIRECT_UDP_OUTAGE=PASS (exact source and payload)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_OVERRIDE_UDP_OUTAGE=PASS (no reply and unchanged native UDP counter)' "$ipv6_tun_log" >/dev/null
grep -Fx 'REAL_TUN_IPV6_OUTAGE=PASS (VPN-required TCP/UDP failed closed, native Direct preserved)' "$ipv6_tun_log" >/dev/null
grep -F 'REAL_TUN_LAB_CLEANUP=PASS' "$ipv6_tun_log" >/dev/null
assert_tun_native_cleanup real-tun-ipv6-candidate-cleanup

# First native feasibility gate for an explicit manager-owned TUN boundary.
# It reuses the disconnected topology; no production Apply is enabled.
echo 'REAL_TUN_LAB_STAGE=addressless-owned-tun-boundary'
owned_tun_log="$scratch/real-tun-owned-boundary.log"
docker exec -e SC_QA_TUN_OWNED_BOUNDARY=yes -e SC_QA_TUN_IPV6=yes \
  "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$owned_tun_log"
for marker in \
  'OWNED_TUN_ADDRESSLESS_GVISOR_CONFIG=PASS' \
  'OWNED_TUN_NO_CORE_ROUTE_RULE_NFT_CREATION=PASS' \
  'OWNED_TUN_REAL_DUALSTACK_AND_PAYLOAD=PASS' \
  'OWNED_TUN_MARKED_DIRECT_AND_HOSTING=PASS' \
  'OWNED_TUN_SIGKILL_PRESERVES_FOREIGN_OBJECTS=PASS' \
  'OWNED_TUN_RENAME_REPLACEMENT_GRACEFUL_PRESERVED=PASS' \
  'OWNED_TUN_NATIVE_BOUNDARY_CLEANUP=PASS'; do
  grep -Fx "$marker" "$owned_tun_log" >/dev/null
done
assert_tun_native_cleanup addressless-owned-tun-boundary
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
echo 'REAL_TUN_LAB_STAGE=installed-product-guarded-real-tun-pending'
product_tun_log="$scratch/real-tun-product-guarded-apply.log"
docker exec -e SC_QA_TUN_PRODUCT_LAB=yes "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$product_tun_log"
for marker in \
  'PRODUCT_NATIVE_IPV4_TRANSIT_BASELINE=PASS' \
  'PRODUCT_NATIVE_IPV4_TRANSIT_ACTIVE=PASS' \
  'PRODUCT_TUN_INSTALLED_PROFILE_AND_IDLE=PASS' \
  'PRODUCT_TUN_GUARD_PREARMED_AND_PENDING=PASS' \
  'PRODUCT_TUN_DIRECT_FALSE_STATUS_AND_PROXY_CONFLICT_REFUSED=PASS' \
  'PRODUCT_TUN_INSTALLED_REAL_TCP_DIRECT_AND_VLESS=PASS' \
  'PRODUCT_TUN_INSTALLED_UDP_DNS_AND_FOREIGN_HOSTING=PASS' \
  'PRODUCT_TUN_INSTALLED_APT_GIT_WORDPRESS=PASS' \
  'PRODUCT_TUN_SYSTEMD_DEADLINE_EXACT_BASELINE=PASS' \
  'PRODUCT_TUN_CLEAR_SIGKILL_INDEPENDENT_FINALIZATION=PASS' \
  'PRODUCT_TUN_RECOVERED_CLEARED_DIRECT=PASS' \
  'PRODUCT_TUN_CONTROLLER_SIGKILL_INDEPENDENT_PENDING=PASS' \
  'PRODUCT_TUN_SIGKILL_INDEPENDENT_SYSTEMD_ROLLBACK=PASS' \
  'PRODUCT_TUN_PRE_CREDENTIAL_SIGKILL_INDEPENDENT_ROLLBACK=PASS' \
  'PRODUCT_TUN_GUARD_TIMER_LOSS_IMMEDIATE_CONTAINMENT=PASS' \
  'PRODUCT_NATIVE_EXECUTOR_LOSS_DISJOINT_PRESERVED=PASS' \
  'PRODUCT_TUN_GUARD_EXECUTOR_LOSS_GUEST_CLEANUP=PASS' \
  'PRODUCT_TUN_CREDENTIAL_REMOVAL_PERSISTENT_CONFLICT=PASS' \
  'PRODUCT_NATIVE_CREDENTIAL_CONFLICT_CONTAINMENT=PASS' \
  'PRODUCT_TUN_CLEAR_CONFLICT_GUARD_STAYS_ARMED=PASS' \
  'PRODUCT_TUN_CREDENTIAL_CONFLICT_RECONCILED=PASS' \
  'PRODUCT_TUN_EXPLICIT_OFF_EXACT_BASELINE=PASS' \
  'PRODUCT_TUN_INVALID_SAVED_POLICY_NO_PREARM=PASS' \
  'PRODUCT_TUN_STALE_DISCONNECT_NO_MUTATION=PASS' \
  'PRODUCT_TUN_SAVED_REAPPLY_NEW_OPERATION=PASS' \
  'PRODUCT_NATIVE_DISJOINT_FOREIGN_SURVIVES_OFF=PASS' \
  'PRODUCT_NATIVE_VISITOR_ORIGIN_DIRECT_CONTROL=PASS' \
  'PRODUCT_NATIVE_VISITOR_REPLY_AND_NEW_EGRESS=PASS' \
  'PRODUCT_TUN_OFF_FIFO_CONTAINMENT_RETAINED=PASS' \
  'PRODUCT_TUN_OFF_SIGKILL_INDEPENDENT_FINALIZATION=PASS' \
  'PRODUCT_TUN_OFF_POST_DISARM_RECONCILIATION=PASS'; do
  grep -Fx "$marker" "$product_tun_log" >/dev/null
done
assert_tun_native_cleanup installed-product-tun-deadline-and-sigkill

# Confirmed operation remains explicitly experimental and uses the SAME
# disconnected peer, real root SSH and installed native product lifecycle.
echo 'REAL_TUN_LAB_STAGE=installed-product-confirmed-supervision'
supervised_log="$scratch/real-tun-product-supervised.log"
docker exec -e SC_QA_TUN_PRODUCT_LAB=yes -e SC_QA_TUN_SUPERVISED=yes \
  "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$supervised_log"
for marker in \
  'DIRECT_CONTROLS' 'OFF_DIRECT_TCP_UDP_DNS' 'FRESH_SSH_SINGLE_USE_AND_NEGATIVES' \
  'ACTIVE_UPDATE_UNINSTALL_REFUSED' 'DISJOINT_FOREIGN_OWNER_PRESERVED' 'SAVED_REAPPLY' \
  'CONFIRMED_BEYOND_ACTIVATION_DEADLINE' 'ONE_TARGET_FALSE_ALARM_REJECTED' \
  'HTTPS_AUTHENTICATED_DIRECT_CONTROLS' 'HTTPS_AUTHENTICATED_SELECTED_PATH' \
  'HTTPS_TLS_HTTP_FAILURE_CLASSES' 'HTTPS_ONE_DESTINATION_PARTIAL_TOLERANCE' \
  'HTTPS_WRONG_SOURCE_CRITICAL_OFF' 'HTTPS_ONLY_RECONNECT_EXHAUSTION_AND_SAVED_STATE' \
  'OFF_DIRECT_AUTHENTICATED_HTTPS' \
  'DNS_FAILURE_AND_TRANSIENT_RECOVERY' 'LIVE_CORE_UPSTREAM_FAILURE_NO_DIRECT_LEAK' \
  'FINITE_EXHAUSTION_FLAPPING_AND_SAVED_STATE' 'EXPIRED_OFF_AND_REPLAY_REJECTED' \
  'PROTECTED_UNDERLAY_IMMEDIATE_OFF_NO_RETRY' \
  'SUPERVISOR_DEAD' 'SUPERVISOR_FAILED' 'SUPERVISOR_HUNG' \
  'SUPERVISOR_MASKED' 'SUPERVISOR_MISSING' \
  'CONFIRM_PUBLICATION_CONTROLLER_DEATH' 'HEALTH_PUBLICATION_CONTROLLER_DEATH' \
  'LEGACY_V1_REAPPLY_REQUIRED_OWNED_OFF' 'LEGACY_V1_INTERRUPTED_DURABLE_STOP' \
  'COMPLETE_EXPERIMENTAL_ONLY'; do
  grep -Fx "SUPERVISED_TUN_${marker}=PASS" "$supervised_log" >/dev/null
done
assert_tun_native_cleanup installed-product-confirmed-supervision

# The dual-stack variant repeats only real confirmation and ongoing path
# measurement, without duplicating the full failure matrix above.
supervised_v6_log="$scratch/real-tun-product-supervised-ipv6.log"
docker exec -e SC_QA_TUN_PRODUCT_LAB=yes -e SC_QA_TUN_SUPERVISED=yes -e SC_QA_TUN_IPV6=yes \
  "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$supervised_v6_log"
for marker in 'DIRECT_CONTROLS' 'OFF_DIRECT_TCP_UDP_DNS' 'CONFIRMED_BEYOND_ACTIVATION_DEADLINE' \
  'HTTPS_AUTHENTICATED_DIRECT_CONTROLS' 'HTTPS_AUTHENTICATED_SELECTED_PATH' \
  'OFF_DIRECT_AUTHENTICATED_HTTPS' 'DUALSTACK_AUTHENTICATED_HTTPS' \
  'DUALSTACK_SELECTED_TCP_UDP_DNS' 'COMPLETE_EXPERIMENTAL_ONLY'; do
  grep -Fx "SUPERVISED_TUN_${marker}=PASS" "$supervised_v6_log" >/dev/null
done
assert_tun_native_cleanup installed-product-confirmed-supervision-ipv6

# Separate opt-in product-owned IPv4+IPv6 v4 trial: distinct installed
# service and independent guard, with real selected/outage TCP/UDP wires.
echo 'REAL_TUN_LAB_STAGE=installed-product-guarded-dualstack-pending'
product_v6_log="$scratch/real-tun-product-guarded-ipv6.log"
docker exec -e SC_QA_TUN_PRODUCT_LAB=yes -e SC_QA_TUN_IPV6=yes \
  "$container" /bin/sh /root/qa-host-tun-path.sh | tee "$product_v6_log"
for marker in \
  'PRODUCT_NATIVE_IPV4_TRANSIT_BASELINE=PASS' \
  'PRODUCT_NATIVE_IPV4_TRANSIT_ACTIVE=PASS' \
  'PRODUCT_TUN_IPV6_UNSUPPORTED_INPUT_REJECTED=PASS' \
  'PRODUCT_TUN_IPV6_REAL_SELECTED=PASS' \
  'PRODUCT_TUN_IPV6_EXPLICIT_OFF_SAVED_REAPPLY=PASS' \
  'PRODUCT_NATIVE_PUBLIC_ICMP6_DIRECT_CONTROL=PASS' \
  'PRODUCT_NATIVE_COLD_ND_AND_PUBLIC_ICMP_BOUNDARY=PASS' \
  'PRODUCT_NATIVE_VISITOR_REPLY_AND_NEW_EGRESS=PASS' \
  'PRODUCT_NATIVE_OVERLAP_RETAINED(address)=PASS' \
  'PRODUCT_NATIVE_OVERLAP_RETAINED(route)=PASS' \
  'PRODUCT_NATIVE_OVERLAP_RETAINED(rule)=PASS' \
  'PRODUCT_NATIVE_OVERLAP_RETAINED(nft-child)=PASS' \
  'PRODUCT_NATIVE_OVERLAP_FOREIGN_PRESERVATION=PASS' \
  'PRODUCT_NATIVE_MUTATOR_FD3_ACTUAL_MODES=PASS' \
  'PRODUCT_NATIVE_POST_REARM_FAILURE_FINALIZATION=PASS' \
  'PRODUCT_NATIVE_LOSS_FAIL_CLOSED(route)=PASS' \
  'PRODUCT_NATIVE_LOSS_FAIL_CLOSED(rule)=PASS' \
  'PRODUCT_NATIVE_LOSS_FAIL_CLOSED(capture)=PASS' \
  'PRODUCT_NATIVE_CORE_SIGKILL_FAILED_PRE_RECOVERY=PASS' \
  'PRODUCT_NATIVE_LOSS_FAIL_CLOSED(core)=PASS' \
  'PRODUCT_NATIVE_ROUTE_RULE_CAPTURE_CORE_FAIL_CLOSED=PASS' \
  'PRODUCT_NATIVE_DURABLE_LINK_PERSIST_RECOVERY=PASS' \
  'PRODUCT_NATIVE_AMBIGUOUS_INDEPENDENT_STOP_INTENT_RETAINED=PASS' \
  'PRODUCT_NATIVE_AMBIGUOUS_ROUTE_REMEDIATION=explicit-QA-operator' \
  'PRODUCT_NATIVE_AMBIGUOUS_ROUTE_EFFECT_RETAINED=PASS' \
  'PRODUCT_NATIVE_POST_DELETE_SIGKILL_RECOVERY=PASS' \
  'PRODUCT_NATIVE_GUARD_LOSS_UNCERTAIN_CONTAINED=PASS' \
  'PRODUCT_NATIVE_GUARD_LOSS_REMEDIATION=explicit-QA-operator' \
  'PRODUCT_NATIVE_GUARD_LOSS_OPERATOR_ASSISTED_DIRECT=PASS' \
  'PRODUCT_TUN_IPV6_OUTAGE_FAIL_CLOSED=PASS' \
  'PRODUCT_TUN_IPV6_GUARD_ROLLBACK=PASS'; do
  grep -Fx "$marker" "$product_v6_log" >/dev/null
done
assert_tun_native_cleanup installed-product-guarded-dualstack

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
# Remove exactly the QA helpers copied for the completed TUN trials. This
# also closes the earlier WordPress intermediate guest-helper cleanup gap.
# The bounded helper verifies source hashes after authenticating its pinned
# objects; a path-following checksum reader must not run before those checks.
docker exec "$container" /usr/bin/python3 -I -B -c "$(cat <<'PYTLSCLEANUP'
import hashlib, json, os, pathlib, stat

def cleanup_tls_fixture(parent):
    names = {"qa-root.pem", "qa-server.pem", "qa-server-key.pem", "qa-wrong-name.pem", "qa-wrong-trust.pem",
             "qa-wrong-root.pem", "qa-expired.pem", "qa-client-auth-only.pem"}
    owner, root_name, receipt_name = os.geteuid(), "qa-smart-health-tls", "qa-smart-health-tls-receipt.json"
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_uid]
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = None
    try:
        descriptor = os.open(receipt_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(descriptor, "rb") as handle:
            receipt_info = os.fstat(handle.fileno())
            assert stat.S_ISREG(receipt_info.st_mode) and receipt_info.st_uid == owner \
                and stat.S_IMODE(receipt_info.st_mode) == 0o600 and receipt_info.st_nlink == 1 and 0 < receipt_info.st_size <= 8192
            raw = handle.read(8193)
            assert len(raw) == receipt_info.st_size
        receipt = json.loads(raw)
        assert identity(os.fstat(parent_fd)) == receipt["parent"], "TLS fixture cleanup parent changed"
        directory = os.open(root_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        assert identity(os.fstat(directory)) == receipt["directory"], "TLS fixture cleanup directory changed"
        def unchanged():
            assert identity(parent.lstat()) == receipt["parent"], "TLS fixture cleanup parent replaced"
            assert identity(os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)) == receipt["directory"], "TLS fixture cleanup directory replaced"
        def check_file(name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                assert stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 \
                    and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 4096
                assert identity(info) + [info.st_size, hashlib.sha256(handle.read(4097)).hexdigest()] == receipt["files"][name], "TLS fixture ownership changed"
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                assert identity(current) + [current.st_size] == receipt["files"][name][:-1], "TLS fixture cleanup file replaced"
        unchanged()
        assert set(os.listdir(directory)) == names and set(receipt["files"]) == names, "TLS fixture cleanup set changed"
        for name in sorted(names):
            check_file(name)
        for name in sorted(names):
            unchanged()
            check_file(name)
            os.unlink(name, dir_fd=directory)
        unchanged()
        os.rmdir(root_name, dir_fd=parent_fd)
        assert not os.path.lexists(parent / root_name)
        descriptor = os.open(receipt_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(descriptor, "rb") as handle:
            assert identity(os.fstat(handle.fileno())) == identity(receipt_info) and handle.read(8193) == raw, "TLS cleanup receipt changed"
        assert identity(parent.lstat()) == receipt["parent"], "TLS fixture cleanup parent replaced"
        assert identity(os.stat(receipt_name, dir_fd=parent_fd, follow_symlinks=False)) == identity(receipt_info), "TLS cleanup receipt replaced"
        os.unlink(receipt_name, dir_fd=parent_fd)
        assert not os.path.lexists(parent / receipt_name)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent_fd)

if __name__ == "__main__":
    assert os.geteuid() == 0, "TLS fixture cleanup requires the disposable root guest"
    cleanup_tls_fixture(pathlib.Path("/root"))
PYTLSCLEANUP
)"
echo 'SMART_HEALTH_QA_TLS_FIXTURE_EXACT_CLEANUP=PASS'
docker exec "$container" /bin/rm -f /root/qa-tun-config-qa /root/qa-host-tun-path.sh \
  /root/qa-tun-guard-unit-lab.sh /root/qa-product-tun-trial.sh /root/qa-tun-sni-client.py /root/qa-tun-native-apps.py \
  /root/qa-owned-tun-boundary.sh \
  /root/qa-native-product-tun.sh /root/qa-supervised-product-tun.sh \
  /root/qa-supervised-product-tun.py /root/qa-smart-health-responder.py /root/qa-smart-health-client.py \
  /root/qa-tun-dns-peer.py /root/qa-tun-dns-client.py /root/qa-tun-wordpress-fpm.sh \
  /root/qa-tun-wp-check.py /root/qa-tun-payload-wire.py /root/qa-tun-ipv6-wire.py
# Product code + installed inactive-by-default independent recovery units.
# The actual RPDB rule is added ONLY in the verified disconnected guest.
docker cp "$root/scripts/qa/host-product-guard-trial.sh" "$container:/root/qa-product-guard-trial.sh"
docker exec "$container" /bin/sh /root/qa-product-guard-trial.sh
assert_network_unchanged product-guard-recovered "$offline_before"
verify_host_services product-guard-recovered
else
  echo 'NATIVE_TUN_AND_GUARDED_RULE_POSITIVES=NOT_RUN (Debian12 is not admitted; exact refusal checked separately)'
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
if [[ $qa_version == 13 ]]; then docker exec "$container" /bin/sh /root/qa-wp-fpm.sh cleanup; fi
run_offline uninstall --uninstall
verify_clean_uninstall
assert_network_unchanged uninstall "$offline_before"
verify_host_services uninstall

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
if [[ $qa_version == 13 ]]; then
  bash scripts/qa/test-activation-boot-qa.sh "$image" "$container"
else
  echo 'NATIVE_ACTIVATION_BOOT_RECOVERY=NOT_RUN (Debian12 roles were verified inert; no reboot acceptance)'
fi
printf 'INSTALLED_DEBIAN%s_LIFECYCLE=PASS\n' "$qa_version"
echo 'LIMITATION: guest-loopback SSH/HTTP checks do not prove external SSH/aaPanel, foreign VPN reachability, reboot or field safety'
