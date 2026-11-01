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
# One inclusive set retains all network syscalls and process creation,
# execution, wait and termination. Do NOT use two -e trace selectors:
# on strace the second can select ALL syscalls except tgkill.
selector = "-e trace=%network,clone,clone3,fork,vfork,execve,execveat,wait4,waitid,exit,exit_group,futex"
if source.count(selector) != 2 or "-e trace=!tgkill" in source:
    raise SystemExit("Native APT trace must use the exact bounded syscall selector")
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
  inventory-refusal)
    printf '%s\n' 'Error: unsupported APT acquisition method installed' \
      'Private diagnostic http://qa-user:qa-secret-must-stay-private@127.0.0.1/' >&2
    exit 1 ;;
  path-refusal)
    printf '%s\n' 'Error: trusted native APT executable path configuration not established' >&2
    exit 1 ;;
  method-override-refusal)
    printf '%s\n' 'Error: APT per-method execution override is not the verified disabled policy' >&2
    exit 1 ;;
  owned-policy-refusal)
    printf '%s\n' 'Error: APT disabled acquisition method policy not established' >&2
    exit 1 ;;
  unclassified-secret)
    printf '%s\n' 'Error: unsupported APT acquisition method installed http://qa-user:qa-secret-must-stay-private@127.0.0.1/' >&2
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

# Public diagnostics are an exact fixed-label projection, never a raw log.
# A near-match containing a credential-bearing URL must stay unclassified.
while IFS='|' read -r refusal expected_label; do
  require_fail "safe public preflight classification: $refusal" \
    env SC_QA_TIMEOUT_CASE="$refusal" /bin/sh "$fixture" positive initial
  grep -Fx "INSTALLED_APT_FAILURE_CAUSE=$expected_label" "$err" >/dev/null ||
    { echo 'Public APT preflight classification missing or imprecise' >&2; exit 1; }
  if grep -F 'qa-secret-must-stay-private' "$out" "$err" >/dev/null; then
    echo 'Private APT diagnostic escaped into public QA output' >&2
    exit 1
  fi
done <<'SAFE_LABEL_CASES'
inventory-refusal|METHOD_INVENTORY_REFUSAL
path-refusal|NATIVE_PATH_POLICY_REFUSAL
method-override-refusal|METHOD_OVERRIDE_REFUSAL
owned-policy-refusal|DISABLED_METHOD_POLICY_REFUSAL
unclassified-secret|UNCLASSIFIED
unrelated|UNCLASSIFIED
SAFE_LABEL_CASES
echo 'HOST_APT_SAFE_PREFLIGHT_CLASSIFICATION=PASS'

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

# Exercise the ACTUAL inline config_digest function with nested files.
# sitecustomize raises errors from os.scandir() and Path.read_bytes(), without
# editing the digest implementation or requiring root/permission changes.
mkdir -p "$scratch/native-apt/nested/deep" "$scratch/inject-python"
printf 'APT::Periodic::Enable "0";\n' > "$scratch/native-apt/nested/deep/config"
cat > "$scratch/inject-python/sitecustomize.py" <<'QA_SCAN_FAULT'
import errno
import os
from pathlib import Path

mode = os.environ.get("SC_QA_DIGEST_FAULT")
target = os.environ.get("SC_QA_DIGEST_TARGET")
if mode and target:
    if mode in ("scan-permission", "scan-io"):
        scandir = os.scandir
        def faulty_scandir(path):
            if os.fspath(path) == target:
                if mode == "scan-permission":
                    raise PermissionError(errno.EACCES, "disposable injected nested directory failure", target)
                raise OSError(errno.EIO, "disposable injected nested directory failure", target)
            return scandir(path)
        os.scandir = faulty_scandir
    elif mode == "read-io":
        read_bytes = Path.read_bytes
        def faulty_read_bytes(path):
            if os.fspath(path) == target:
                raise OSError(errno.EIO, "disposable injected file read failure", target)
            return read_bytes(path)
        Path.read_bytes = faulty_read_bytes
QA_SCAN_FAULT
# The sourced function is byte-identical to the guest's real config_digest.
# Only the existing hermetic test's absolute fixture path substitution applies.
awk '/^case "/ {exit} {print}' "$fixture" > "$scratch/digest-functions.sh"
[ -s "$scratch/digest-functions.sh" ] || exit 1
/bin/sh -c '. "$1"; config_digest' QA "$scratch/digest-functions.sh" \
  > "$scratch/base/host-apt-policy.sha256"
require_pass 'baseline includes nested APT file' \
  'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS' \
  /bin/sh "$fixture" verify-host-policy

for fault in scan-permission scan-io; do
  target=$scratch/native-apt/nested
  require_fail "nested $fault during final policy inventory" \
    env PYTHONPATH="$scratch/inject-python" SC_QA_DIGEST_FAULT="$fault" \
    SC_QA_DIGEST_TARGET="$target" /bin/sh "$fixture" verify-host-policy
  # The same config_digest is used by initial baseline creation in setup.
  if env PYTHONPATH="$scratch/inject-python" SC_QA_DIGEST_FAULT="$fault" \
    SC_QA_DIGEST_TARGET="$target" /bin/sh -c \
    '. "$1"; config_digest' QA "$scratch/digest-functions.sh" >"$out" 2>"$err"; then
    echo "Incomplete initial APT policy baseline accepted: $fault" >&2
    exit 1
  fi
  if [[ -s $out ]]; then
    echo "A partial policy baseline hash escaped: $fault" >&2
    exit 1
  fi
done
require_fail 'nested APT policy content read error' \
  env PYTHONPATH="$scratch/inject-python" SC_QA_DIGEST_FAULT=read-io \
  SC_QA_DIGEST_TARGET="$scratch/native-apt/nested/deep/config" \
  /bin/sh "$fixture" verify-host-policy

mv "$scratch/native-apt" "$scratch/native-apt-saved"
require_fail 'missing APT policy root' /bin/sh "$fixture" verify-host-policy
ln -s "$scratch/native-apt-saved" "$scratch/native-apt"
require_fail 'symlink-substituted APT policy root' \
  /bin/sh "$fixture" verify-host-policy
rm "$scratch/native-apt"
mv "$scratch/native-apt-saved" "$scratch/native-apt"

printf 'APT::Periodic::Enable "1";\n' > "$scratch/native-apt/nested/deep/config"
require_fail 'modified nested APT policy file' \
  /bin/sh "$fixture" verify-host-policy
printf 'APT::Periodic::Enable "0";\n' > "$scratch/native-apt/nested/deep/config"
require_pass 'restored full nested policy inventory' \
  'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS' \
  /bin/sh "$fixture" verify-host-policy
# The inventory must still observe regular-file mode and symlink identity
# while deliberately not traversing symlink targets.
original_mode=$(stat -c '%a' "$scratch/native-apt/nested/deep/config")
if [[ $original_mode == 600 ]]; then changed_mode=644; else changed_mode=600; fi
chmod "$changed_mode" "$scratch/native-apt/nested/deep/config"
require_fail 'APT policy file mode mutation' \
  /bin/sh "$fixture" verify-host-policy
chmod "$original_mode" "$scratch/native-apt/nested/deep/config"
require_pass 'restored APT file mode' \
  'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS' \
  /bin/sh "$fixture" verify-host-policy

ln -s nested/deep/config "$scratch/native-apt/config-link"
/bin/sh -c '. "$1"; config_digest' QA "$scratch/digest-functions.sh" \
  > "$scratch/base/host-apt-policy.sha256"
require_pass 'symlink identity included in APT inventory' \
  'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS' \
  /bin/sh "$fixture" verify-host-policy
rm "$scratch/native-apt/config-link"
ln -s nested/deep/other "$scratch/native-apt/config-link"
require_fail 'APT policy symlink target mutation' \
  /bin/sh "$fixture" verify-host-policy
rm "$scratch/native-apt/config-link"
ln -s nested/deep/config "$scratch/native-apt/config-link"
require_pass 'restored APT symlink identity' \
  'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS' \
  /bin/sh "$fixture" verify-host-policy
echo 'HOST_APT_STRICT_NESTED_POLICY_WALK_REGRESSIONS=PASS'

# Import only the pure trace reader. Synthetic traces and ordinary owned
# temporary files exercise refusal logic; no tracing/native APT runs here.
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B - \
  "$root/scripts/qa/apt-disabled-trace.py" "$scratch" <<'PY'
import importlib.util
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("apt_disabled_trace", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def execution(path, args):
    quoted = ", ".join('"' + value + '"' for value in [path, *args])
    return f'execve("{path}", [{quoted}], ["LC_ALL=C"]) = 0\n'

owned = []
for method in module.DISABLED:
    owned.extend(["-o", f"Dir::Bin::Methods::{method}={module.DISABLED_PATH}"])

valid = {
    10: execution("/usr/local/bin/server-connect", ["apt", "--", "apt-get", "update"])
        + 'clone(child_stack=NULL, flags=SIGCHLD) = 11\n'
        + 'clone(child_stack=NULL, flags=SIGCHLD) = 12\n'
        + 'clone(child_stack=NULL, flags=SIGCHLD) = 13\n'
        + 'exit_group(100) = ?\n+++ exited with 100 +++\n',
    11: execution("/usr/bin/apt-config", ["-c", "/proc/self/fd/3", "dump"])
        + 'exit_group(0) = ?\n+++ exited with 0 +++\n',
    12: execution("/usr/bin/apt-config", ["-c", "/proc/self/fd/3", *owned, "dump"])
        + 'exit_group(0) = ?\n+++ exited with 0 +++\n',
    13: execution("/usr/bin/apt-get", ["-c", "/proc/self/fd/3", "update", *owned, "--error-on=any"])
        + 'exit_group(100) = ?\n+++ exited with 100 +++\n',
}
module.check_payloads(valid)

def refused(name, payloads, reason=None):
    try:
        module.check_payloads(payloads)
    except module.TraceFailure as error:
        if reason is not None and str(error) != reason:
            raise SystemExit("Wrong safe trace refusal: " + name)
    else:
        raise SystemExit("Unsafe trace evidence accepted: " + name)

def altered(pid, old, new):
    result = dict(valid)
    if old not in result[pid]:
        raise SystemExit("Synthetic trace fixture drifted")
    result[pid] = result[pid].replace(old, new, 1)
    return result

refused("no process files", {})
missing = dict(valid)
del missing[12]
refused("missing descendant", missing, "missing descendant trace")
refused("unrelated orphan", {**valid, 99: "+++ exited with 0 +++\n"})
refused("disconnected cycle", {
    **valid,
    90: "fork() = 91\n+++ exited with 0 +++\n",
    91: "fork() = 90\n+++ exited with 0 +++\n",
}, "disconnected process evidence")
refused("duplicate descendant", altered(10, " = 12\n", " = 11\n"))
refused("self descendant", altered(10, " = 11\n", " = 10\n"))
refused("empty process file", {**valid, 12: ""})
refused("missing final newline", {**valid, 12: valid[12].rstrip("\n")})
refused("missing exit record", altered(12, "+++ exited with 0 +++\n", ""))
refused("nontextual byte", altered(12, "exit_group(0)", "\x00exit_group(0)"))
refused("unrecognized record", altered(12, "exit_group(0)", "truncated record\nexit_group(0)"))
refused("record after exit", {**valid, 12: valid[12] + "exit_group(0) = ?\n"})
refused("timeout killed child", altered(13, "+++ exited with 100 +++", "+++ killed by SIGKILL +++"))
refused("wrong native status", altered(13, "exited with 100", "exited with 0"))
refused("wrong manager status", altered(10, "exited with 100", "exited with 0"))

for family in ("AF_INET", "AF_INET6", "AF_PACKET"):
    payloads = altered(13, "exit_group(100)", f"socket({family}, SOCK_STREAM, 0) = 4\nexit_group(100)")
    refused(family, payloads, "nonlocal network attempt")
for decoded in ("TCP", "UDP", "TCPv6", "UDPv6", "IP", "IPv6"):
    payloads = altered(13, "exit_group(100)", f'sendto(4<{decoded}:[127.0.0.1:9]>, "x", 1, 0, NULL, 0) = 1\nexit_group(100)')
    refused(decoded, payloads, "decoded Internet descriptor used")
for method in (*module.DISABLED, "false"):
    attempted = f'execve("/usr/lib/apt/methods/{method}", ["{method}"], []) = -1 ENOENT (No such file or directory)\n'
    refused(method, altered(13, "exit_group(100)", attempted + "exit_group(100)"),
            "unsupported transport execution attempted")
refused("execveat", altered(13, "exit_group(100)", 'execveat(4, "", [], [], AT_EMPTY_PATH) = -1 ENOENT (No such file or directory)\nexit_group(100)'))
for method in module.DISABLED:
    setting = f'Dir::Bin::Methods::{method}={module.DISABLED_PATH}'
    refused("lost acquisition denial " + method, altered(13, setting, "Debug::NoLocking=1"))
    refused("lost effective denial " + method, altered(12, setting, "Debug::NoLocking=1"))
refused("private configuration absent", altered(13, '"/proc/self/fd/3"', '"/tmp/other"'))
refused("only version executed", altered(13, '"update"', '"--version"'))
refused("missing owned policy pass", {**valid, 12: valid[11]})
refused("missing baseline policy pass", {**valid, 11: valid[12]})

interrupted = altered(10,
    'clone(child_stack=NULL, flags=SIGCHLD) = 11\n',
    'clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n'
    '--- SIGCHLD {si_signo=SIGCHLD, si_pid=11, si_status=0} ---\n'
    '<... clone resumed>) = 11\n')
module.check_payloads(interrupted)
# strace can split exit_group across an unfinished line and the terminal
# record. It is safe only when the exact exit status is independently recorded.
partial_exit = altered(13, 'exit_group(100) = ?\n',
                      'exit_group(100 <unfinished ...>\n')
module.check_payloads(partial_exit)
# When a Go thread exits during a traced futex synchronization wait, the
# kernel exit receipt closes its lifetime without a network/exec/fork effect.
# The strace selector MUST name futex; an ambiguous unselected ???( remains
# untrusted and must NEVER be treated as an equivalent benign wait.
partial_futex = altered(13, 'exit_group(100) = ?\n',
                        'futex(0x1234, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n')
module.check_payloads(partial_futex)
refused("unknown unfinished syscall stays rejected",
        altered(13, 'exit_group(100) = ?\n', '???( <unfinished ...>\n'),
        "incomplete syscall at process exit (unknown)")
refused("futex-looking hidden network remains rejected",
        altered(13, 'exit_group(100) = ?\n',
                'futex(AF_INET, FUTEX_WAIT_PRIVATE <unfinished ...>\n'),
        "nonlocal network attempt")
refused("conflicting interrupted exit code",
        altered(13, 'exit_group(100) = ?\n', 'exit_group(0 <unfinished ...>\n'),
        "incomplete syscall at process exit (exit_group)")
refused("incomplete clone must stay rejected",
        altered(13, 'exit_group(100) = ?\n', 'clone(child_stack=NULL <unfinished ...>\n'),
        "incomplete syscall at process exit (clone)")
refused("unfinished execve must stay rejected",
        altered(13, 'exit_group(100) = ?\n', 'execve(\"/usr/bin/true\" <unfinished ...>\n'),
        "incomplete syscall at process exit (execve)")
refused("lost clone resumption", {**interrupted, 10: interrupted[10].replace('<... clone resumed>) = 11\n', '')})
refused("mismatched resumption", {**interrupted, 10: interrupted[10].replace('<... clone resumed>', '<... fork resumed>')})
refused("standalone resumption", altered(10, 'clone(child_stack=NULL, flags=SIGCHLD) = 11', '<... clone resumed>) = 11'))

trace_dir = Path(sys.argv[2]) / "trace-reader-fixture"
trace_dir.mkdir(mode=0o700)
for pid, payload in valid.items():
    path = trace_dir / f"trace.{pid}"
    path.write_text(payload, encoding="ascii")
    path.chmod(0o600)
module.check_directory(trace_dir)

def refused_directory(name):
    try:
        module.check_directory(trace_dir)
    except (module.TraceFailure, OSError, UnicodeError):
        return
    raise SystemExit("Unsafe trace directory accepted: " + name)

subject = trace_dir / "trace.12"
subject.unlink()
subject.symlink_to("trace.11")
refused_directory("symlink")
subject.unlink()
subject.write_text("", encoding="ascii")
refused_directory("empty file")
subject.write_text(valid[12], encoding="ascii")
subject.chmod(0o622)
refused_directory("writable trace")
subject.chmod(0o600)
trace_dir.chmod(0o722)
refused_directory("writable directory")
trace_dir.chmod(0o700)
subject.write_bytes(b"\xff\n")
refused_directory("non-ASCII trace")
subject.write_text(valid[12], encoding="ascii")
module.check_directory(trace_dir)
print("HOST_APT_DISABLED_TRACE_READER_REGRESSIONS=PASS")
PY

# Real GNU timeout SIGTERM -> SIGKILL behavior, including a descendant
# that deliberately ignores TERM; all processes are in a disposable session.
SC_QA_APT_TEST_ROOT=$scratch /usr/bin/python3 - <<'PY'
import errno
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
    # After kill(), procfs may report ENOENT or ESRCH as PID1 reaps the
    # descendant. Only these two missing-process errors count as termination;
    # unexpected I/O/permission failures must not prove a process exited.
    try:
        status = statfile.read_text()
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ESRCH):
            break
        raise
    # A zombie is not executing. PID1 may reap it asynchronously.
    state = status.rsplit(") ", 1)[1].split()[0]
    if state == "Z":
        break
    time.sleep(0.1)
else:
    raise SystemExit("TERM-ignoring descendant survived the forced deadline")
print("APT_QA_SIGTERM_SIGKILL_PROCESS_GROUP=PASS")
PY

echo 'HOST_APT_NEGATIVE_CLASSIFICATION_REGRESSIONS=PASS'
echo 'HOST_APT_DIGEST_AND_DESCRIPTOR_FAIL_CLOSED_REGRESSIONS=PASS'
