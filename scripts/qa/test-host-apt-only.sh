#!/usr/bin/env bash
# Hermetic regressions for the ACTUAL installed APT QA assertions.
# Disposable fake subprocesses and paths; no Docker, privileged work, APT
# installation, network connections or mutation of host /etc/apt.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/failing-python" "$scratch/base" \
  "$scratch/state" "$scratch/native-apt"
printf '%s\n' 'deb [trusted=yes] http://127.0.0.1:19180/sc-qa-apt qa main' \
  > "$scratch/base/sources.list"

# Only swap the guest absolute paths in a temporary copy. All acceptance
# branches and assertions under test remain the actual production-QA code.
SC_QA_APT_TEST_ROOT=$scratch SC_QA_APT_SOURCE=$root/scripts/qa/host-apt-only.sh \
  /usr/bin/python3 - <<'PY'
import os
from pathlib import Path
scratch = Path(os.environ["SC_QA_APT_TEST_ROOT"])
source = Path(os.environ["SC_QA_APT_SOURCE"]).read_text()
edits = [
    ("manager=/usr/local/bin/server-connect", f"manager={scratch}/bin/manager"),
    ("apt_cache=/usr/bin/apt-cache", f"apt_cache={scratch}/bin/apt-cache"),
    ("apt_timeout=/usr/bin/timeout", f"apt_timeout={scratch}/bin/timeout"),
    ("base=/srv/sc-qa-apt", f"base={scratch}/base"),
    ("Path('/etc/apt')", f"Path('{scratch}/native-apt')"),
    ("find /var/lib/server-connect -name", f"find {scratch}/state -name"),
    ("[ -d /var/lib/server-connect ]", f"[ -d {scratch}/state ]"),
]
for original, replacement in edits:
    if source.count(original) != 1:
        raise SystemExit(f"Guest QA code changed without test reconciliation: {original}")
    source = source.replace(original, replacement)
target = scratch / "fixture.sh"
target.write_text(source)
target.chmod(0o700)
PY

cat > "$scratch/bin/manager" <<'QA_MANAGER'
#!/bin/sh
if [ "$1" = --json ] && [ "$2" = ready ]; then
  printf '%s\n' '{"ok":true,"data":{"local_listener_ready":true}}'
  exit 0
fi
exit 77
QA_MANAGER

cat > "$scratch/bin/timeout" <<'QA_TIMEOUT'
#!/bin/sh
[ "$1" = --kill-after=5s ] && [ "$2" = 35s ] || exit 125
[ "$3" = "$SC_QA_APT_TEST_ROOT/bin/manager" ] || exit 125
case "$SC_QA_TIMEOUT_CASE" in
  success) exit 0 ;;
  upstream)
    printf '%s\n' \
      'Err:1 http://127.0.0.1:19180/sc-qa-apt qa Release' \
      'E: Failed to fetch http://127.0.0.1:19180/sc-qa-apt/dists/qa/Release Connection refused'
    exit 100 ;;
  manager-unavailable)
    printf '%s\n' 'Error: local proxy is not active' >&2
    exit 1 ;;
  unrelated)
    printf '%s\n' 'Error: unable to initialize manager' >&2
    exit 1 ;;
  missing-evidence)
    printf '%s\n' 'W: unrelated non-acquisition error'
    exit 100 ;;
  exit-125) exit 125 ;;
  exit-126) exit 126 ;;
  exit-127) exit 127 ;;
  exit-124) exit 124 ;;
  exit-137) exit 137 ;;
  *) exit 125 ;;
esac
QA_TIMEOUT

cat > "$scratch/bin/apt-cache" <<'QA_APT_CACHE'
#!/bin/sh
case "$SC_QA_CACHE_CASE" in
  missing)
    printf 'E: No packages found\n' >&2
    exit 100 ;;
  package)
    printf '%s\n' 'Package: sc-qa-apt-route-proof'
    exit 0 ;;
  unavailable) exit 127 ;;
  broken) exit 6 ;;
  empty-error) exit 100 ;;
  wrong-error)
    printf 'E: unrelated APT configuration error\n' >&2
    exit 100 ;;
  *) exit 125 ;;
esac
QA_APT_CACHE

cat > "$scratch/bin/systemctl" <<'QA_SYSTEMCTL'
#!/bin/sh
[ "$1" = is-active ] && [ "$2" = --quiet ] &&
  [ "$3" = server-connect.service ] && [ "$SC_QA_UNIT_BAD" = no ]
QA_SYSTEMCTL

cat > "$scratch/bin/find" <<'QA_FIND'
#!/bin/sh
case "$SC_QA_FIND_CASE" in
  pass) exec /usr/bin/find "$@" ;;
  error) exit 7 ;;
  partial) printf 'partial inventory\n'; exit 7 ;;
  *) exit 7 ;;
esac
QA_FIND
cat > "$scratch/failing-python/python3" <<'QA_PY'
#!/bin/sh
exit 7
QA_PY
chmod 0700 "$scratch/bin/"* "$scratch/failing-python/python3"

export SC_QA_APT_TEST_ROOT=$scratch
export SC_QA_TIMEOUT_CASE=upstream SC_QA_CACHE_CASE=missing
export SC_QA_UNIT_BAD=no SC_QA_FIND_CASE=pass
export PATH="$scratch/bin:/usr/bin:/bin"
fixture=$scratch/fixture.sh
out=$scratch/out
err=$scratch/err

reset_phase() {
  rm -rf -- "$scratch/base"/lists-* "$scratch/base"/archives-*
}
require_pass() {
  local case_name=$1
  local marker=$2
  shift 2
  reset_phase
  if ! "$@" > "$out" 2> "$err"; then
    printf 'Expected QA PASS rejected: %s\n' "$case_name" >&2
    cat "$err" >&2
    exit 1
  fi
  grep -Fq "$marker" "$out" ||
    { printf 'Missing expected PASS marker: %s\n' "$case_name" >&2; exit 1; }
}
require_fail() {
  local case_name=$1
  shift
  reset_phase
  if "$@" > "$out" 2> "$err"; then
    printf 'Unsafe false-positive APT PASS: %s\n' "$case_name" >&2
    exit 1
  fi
  if grep -Fq '=PASS' "$out"; then
    printf 'Failed QA assertion emitted success marker: %s\n' "$case_name" >&2
    exit 1
  fi
}

require_pass 'genuine native upstream failure' 'INSTALLED_APT_FAIL_CLOSED(upstream-stopped)=PASS' \
  /bin/sh "$fixture" negative upstream-stopped
require_pass 'genuine core unavailable' 'INSTALLED_APT_FAIL_CLOSED(core-stopped)=PASS' \
  env SC_QA_TIMEOUT_CASE=manager-unavailable /bin/sh "$fixture" negative core-stopped
require_pass 'genuine disconnected' 'INSTALLED_APT_FAIL_CLOSED(disconnected)=PASS' \
  env SC_QA_TIMEOUT_CASE=manager-unavailable /bin/sh "$fixture" negative disconnected
require_pass 'native APT success' 'INSTALLED_APT_SELECTED(initial)=PASS' \
  env SC_QA_TIMEOUT_CASE=success SC_QA_CACHE_CASE=package \
  /bin/sh "$fixture" positive initial
require_pass 'selected upstream failure after update' 'INSTALLED_APT_FAIL_CLOSED(upstream-after-upgrade)=PASS' \
  /bin/sh "$fixture" negative upstream-after-upgrade
require_pass 'selected upstream failure after rollback' 'INSTALLED_APT_FAIL_CLOSED(upstream-after-rollback)=PASS' \
  /bin/sh "$fixture" negative upstream-after-rollback

for status in 125 126 127 124 137; do
  require_fail "timeout/executable failure $status" \
    env SC_QA_TIMEOUT_CASE="exit-$status" /bin/sh "$fixture" negative upstream-stopped
done
chmod 000 "$scratch/bin/manager"
require_fail 'non-executable manager binary' /bin/sh "$fixture" negative upstream-stopped
chmod 0700 "$scratch/bin/manager"
require_fail 'unrelated manager initialization failure' \
  env SC_QA_TIMEOUT_CASE=unrelated /bin/sh "$fixture" negative core-stopped
require_fail 'missing native acquisition evidence' \
  env SC_QA_TIMEOUT_CASE=missing-evidence /bin/sh "$fixture" negative upstream-stopped
require_fail 'wrong failure status in core-stopped phase' \
  env SC_QA_TIMEOUT_CASE=upstream /bin/sh "$fixture" negative core-stopped
require_fail 'failed apt-cache executable' \
  env SC_QA_CACHE_CASE=broken /bin/sh "$fixture" negative upstream-stopped
require_fail 'unavailable apt-cache executable' \
  env SC_QA_CACHE_CASE=unavailable /bin/sh "$fixture" negative upstream-stopped
require_fail 'apt-cache without positive absence evidence' \
  env SC_QA_CACHE_CASE=empty-error /bin/sh "$fixture" negative upstream-stopped
require_fail 'apt-cache unrelated error' \
  env SC_QA_CACHE_CASE=wrong-error /bin/sh "$fixture" negative upstream-stopped
require_fail 'index unexpectedly found after native update failure' \
  env SC_QA_CACHE_CASE=package /bin/sh "$fixture" negative upstream-stopped
require_fail 'lost local systemd service while upstream unavailable' \
  env SC_QA_UNIT_BAD=yes /bin/sh "$fixture" negative upstream-stopped
chmod 000 "$scratch/bin/timeout"
require_fail 'non-executable timeout wrapper' /bin/sh "$fixture" negative upstream-stopped
chmod 0700 "$scratch/bin/timeout"
chmod 000 "$scratch/bin/apt-cache"
require_fail 'non-executable apt-cache' /bin/sh "$fixture" negative upstream-stopped
chmod 0700 "$scratch/bin/apt-cache"

# Current policy digest of an empty fixture directory is SHA-256(empty).
/usr/bin/python3 -c 'import hashlib,sys; print(hashlib.sha256(b"").hexdigest())' \
  > "$scratch/base/host-apt-policy.sha256"
require_pass 'complete native policy and descriptor audit' \
  'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS' \
  /bin/sh "$fixture" verify-host-policy

mv "$scratch/base/host-apt-policy.sha256" "$scratch/base/expected-saved"
require_fail 'expected policy digest file unavailable' /bin/sh "$fixture" verify-host-policy
mv "$scratch/base/expected-saved" "$scratch/base/host-apt-policy.sha256"
require_fail 'current policy digest command failure' \
  env PATH="$scratch/failing-python:$PATH" /bin/sh "$fixture" verify-host-policy
require_fail 'failed private credential descriptor inventory' \
  env SC_QA_FIND_CASE=error /bin/sh "$fixture" verify-host-policy
require_fail 'partial inventory with output followed by failure' \
  env SC_QA_FIND_CASE=partial /bin/sh "$fixture" verify-host-policy
touch "$scratch/state/.apt-ephemeral-intentionally-retained"
require_fail 'retained credential-bearing APT fixture' /bin/sh "$fixture" verify-host-policy
rm -f "$scratch/state/.apt-ephemeral-intentionally-retained"
printf 'invalid\n' > "$scratch/base/host-apt-policy.sha256"
require_fail 'invalid expected APT policy digest' /bin/sh "$fixture" verify-host-policy

# Real GNU timeout SIGTERM -> SIGKILL behavior, including a descendant
# that deliberately ignores TERM; all processes are in a disposable session.
SC_QA_APT_TEST_ROOT=$scratch /usr/bin/python3 - <<'PY'
import os
from pathlib import Path
import subprocess
import sys
import time
root = Path(os.environ["SC_QA_APT_TEST_ROOT"])
pidfile = root / "ignored-term-child.pid"
descendant = (
    "import os,signal,time,sys;"
    "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
    "open(sys.argv[1],'w').write(str(os.getpid()));"
    "time.sleep(60)"
)
parent = (
    "import os,signal,subprocess,sys;"
    "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
    "child=subprocess.Popen(['/usr/bin/python3','-c',sys.argv[2],sys.argv[1]]);"
    "child.wait()"
)
try:
    result = subprocess.run(
        ['/usr/bin/timeout', '--kill-after=1s', '1s',
         '/usr/bin/python3', '-c', parent, str(pidfile), descendant],
        capture_output=True, timeout=7, start_new_session=True,
    )
except subprocess.TimeoutExpired as exc:
    raise SystemExit("Forced-termination QA timed out") from exc
if result.returncode == 0 or not pidfile.exists():
    raise SystemExit("GNU timeout did not exercise a TERM-ignoring descendant")
pid = int(pidfile.read_text())
for attempt in range(20):
    statfile = Path(f"/proc/{pid}/stat")
    if not statfile.exists():
        break
    # A zombie is not executing. PID1 may reap it asynchronously.
    state = statfile.read_text().rsplit(") ", 1)[1].split()[0]
    if state == "Z":
        break
    time.sleep(0.1)
else:
    raise SystemExit("TERM-ignoring descendant survived the forced deadline")
print("APT_QA_SIGTERM_SIGKILL_PROCESS_GROUP=PASS")
PY

echo 'HOST_APT_NEGATIVE_CLASSIFICATION_REGRESSIONS=PASS'
echo 'HOST_APT_DIGEST_AND_DESCRIPTOR_FAIL_CLOSED_REGRESSIONS=PASS'
