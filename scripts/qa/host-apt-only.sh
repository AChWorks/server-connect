#!/bin/sh
# Disposable disconnected Debian 12/13 systemd guest ONLY.
# Exercise native installed apt-get via the manager's selected VLESS route.
# The HTTP APT repository and all cache/source files live inside this guest.
set -eu
umask 077

manager=/usr/local/bin/server-connect
apt_cache=/usr/bin/apt-cache
apt_timeout=/usr/bin/timeout
base=/srv/sc-qa-apt
source_file=$base/sources.list
origin=http://127.0.0.1:19180/sc-qa-apt

config_digest() {
  python3 - <<'PY'
from pathlib import Path
import hashlib, os, stat
root = Path('/etc/apt')
if not root.is_dir() or root.is_symlink():
    raise SystemExit('Native APT policy directory unavailable')
# pathlib.Path.rglob() on Python 3.13 silently suppresses nested scandir
# errors. A partial inventory would then yield a valid-looking SHA-256.
# os.walk(onerror=raise) is mandatory: no skipped subtree can compare equal.
def fail_on_scan(error):
    raise error

paths = []
for parent, dirs, files in os.walk(root, topdown=True, onerror=fail_on_scan, followlinks=False):
    dirs.sort()
    files.sort()
    paths.extend(Path(parent) / entry for entry in dirs)
    paths.extend(Path(parent) / entry for entry in files)
records = []
for path in sorted(paths):
    name = str(path)
    m = path.lstat()
    kind = stat.S_IFMT(m.st_mode)
    row = [name, str(kind), str(stat.S_IMODE(m.st_mode)), str(m.st_uid), str(m.st_gid)]
    if stat.S_ISLNK(m.st_mode):
        row.append(os.readlink(path))
    elif stat.S_ISREG(m.st_mode):
        row.append(hashlib.sha256(path.read_bytes()).hexdigest())
    records.append('\0'.join(row))
print(hashlib.sha256('\n'.join(records).encode()).hexdigest())
PY
}

setup() {
  test "$(ps -p 1 -o comm=)" = systemd
  test -d /root/qa-web
  test ! -e "$base"
  mkdir -m 0755 "$base"
  python3 - <<'PY'
from pathlib import Path
from datetime import datetime, timezone
from email.utils import format_datetime
import gzip
import hashlib

root = Path('/root/qa-web/sc-qa-apt/dists/qa')
index_dir = root / 'main/binary-amd64'
index_dir.mkdir(parents=True)
packages = (
    'Package: sc-qa-apt-route-proof\n'
    'Version: 1.0\n'
    'Architecture: amd64\n'
    'Maintainer: Disposable Host QA <qa@invalid.test>\n'
    'Description: harmless index-only route acceptance fixture\n'
    '\n'
).encode('ascii')
zipped = gzip.compress(packages, mtime=0)
(index_dir / 'Packages').write_bytes(packages)
(index_dir / 'Packages.gz').write_bytes(zipped)
hash_entry = lambda name, blob: f' {hashlib.sha256(blob).hexdigest()} {len(blob)} {name}\n'
release = (
    'Origin: Server Connect disposable QA\n'
    'Label: Isolated native APT selected-path verification\n'
    'Suite: qa\nCodename: qa\nArchitectures: amd64\nComponents: main\n'
    'Date: ' + format_datetime(datetime.now(timezone.utc)) + '\n'
    'SHA256:\n'
    + hash_entry('main/binary-amd64/Packages', packages)
    + hash_entry('main/binary-amd64/Packages.gz', zipped)
)
(root / 'Release').write_text(release, encoding='ascii')
Path('/srv/sc-qa-apt/sources.list').write_text(
    'deb [trusted=yes] http://127.0.0.1:19180/sc-qa-apt qa main\n',
    encoding='ascii'
)
PY
  chmod 0644 "$source_file"
  # Direct HTTP is a control, not evidence of selected-path APT.
  curl -q --fail --silent --show-error --max-time 4 --noproxy '*'     "$origin/dists/qa/Release" >/dev/null
  config_digest > "$base/host-apt-policy.sha256"
  baseline=$(cat "$base/host-apt-policy.sha256") || exit 1
  assert_digest "$baseline" || exit 1
  echo 'INSTALLED_APT_FIXTURE=PASS (local unsigned index; trusted=yes disposable QA only)'
}

fail_apt() {
  echo "INSTALLED_APT_QA=FAIL ($1; raw guest diagnostics withheld)" >&2
  return 1
}

# Publish only fixed labels from complete known product error lines. Never
# echo the raw child log, effective APT configuration or proxy credentials.
classify_preflight_failure() {
  evidence=$1
  if [ -f "$evidence" ] && [ ! -L "$evidence" ] && [ -r "$evidence" ]; then
    while IFS='|' read -r message label; do
      if grep -Fx "$message" "$evidence" >/dev/null; then
        printf 'INSTALLED_APT_FAILURE_CAUSE=%s\n' "$label" >&2
        return 0
      fi
    done <<'SAFE_APT_ERRORS'
Error: unsupported APT acquisition method installed|METHOD_INVENTORY_REFUSAL
Error: native APT compatibility version cannot be verified|VERSION_IDENTITY_REFUSAL
Error: trusted native APT executable path configuration not established|NATIVE_PATH_POLICY_REFUSAL
Error: APT executable or acquisition method path differs from native Debian layout|NATIVE_PATH_POLICY_REFUSAL
Error: APT per-method execution override is not the verified disabled policy|METHOD_OVERRIDE_REFUSAL
Error: APT disabled acquisition method policy not established|DISABLED_METHOD_POLICY_REFUSAL
Error: cannot verify effective APT configuration; refusing Direct fallback|EFFECTIVE_CONFIG_REFUSAL
Error: local proxy is not active|PROXY_UNAVAILABLE
SAFE_APT_ERRORS
  fi
  echo 'INSTALLED_APT_FAILURE_CAUSE=UNCLASSIFIED' >&2
}

assert_digest() {
  case "$1" in *[!0-9a-f]*|'') return 1;; esac
  [ "$(printf '%s' "$1" | wc -c)" -eq 64 ]
}

# Negative evidence must distinguish APT method failure from a manager
# initialization error, a broken timeout wrapper or an unrelated command.
# Never echo APT logs: a real APT origin might carry credential-bearing URLs.
check_failure_cause() {
  phase=$1
  rc=$2
  log_file=$3
  [ -f "$log_file" ] && [ -r "$log_file" ] && [ -s "$log_file" ] ||
    { fail_apt "missing private APT command evidence: $phase"; return 1; }
  case "$rc" in
    0|124|125|126|127|137)
      fail_apt "unexpected/timeout/infrastructure exit $rc: $phase"
      return 1 ;;
  esac
  case "$phase" in
    upstream-stopped|upstream-after-upgrade|upstream-after-rollback)
      [ "$rc" -eq 100 ] ||
        { fail_apt "upstream failure was not native APT exit 100: $phase"; return 1; }
      # Native APT failed to acquire the known guest-local origin, not a
      # manager error that exits before the APT method is launched.
      grep -Eq '^Err:[0-9]+ http://127\.0\.0\.1:19180/sc-qa-apt ' "$log_file" &&
        grep -Fq 'E: Failed to fetch http://127.0.0.1:19180/sc-qa-apt/' "$log_file" ||
        { fail_apt "native APT origin acquisition failure not established: $phase"; return 1; }
      ;;
    core-stopped|disconnected)
      [ "$rc" -eq 1 ] && [ "$(cat "$log_file")" = 'Error: local proxy is not active' ] ||
        { fail_apt "expected precise manager proxy-unavailable rejection: $phase"; return 1; }
      ;;
    *) fail_apt "unsupported negative phase: $phase"; return 1 ;;
  esac
}

# apt-cache show for a nonexistent package returns 100 with exactly this
# diagnostic in forced C locale. A command/configuration error, missing
# executable or partial read is NOT equivalent to an absent index.
check_absent_index() {
  lists=$1
  label=$2
  cache_source=${3:-$source_file}
  out=$base/$label.cache-out
  err=$base/$label.cache-err
  rc=0
  LC_ALL=C "$apt_cache" \
    -o "Dir::Etc::sourcelist=$cache_source" \
    -o "Dir::Etc::sourceparts=-" \
    -o "Dir::State::lists=$lists" \
    show sc-qa-apt-route-proof >"$out" 2>"$err" || rc=$?
  observed=$(cat "$err") ||
    { fail_apt "native apt-cache diagnostic unreadable: $label"; return 1; }
  [ "$rc" -eq 100 ] && [ ! -s "$out" ] &&
    [ "$observed" = 'E: No packages found' ] ||
    { fail_apt "native apt-cache absence could not be verified: $label"; return 1; }
}

run_selected() {
  label=$1
  expected=$2
  case "$label" in
    initial|upstream-stopped|core-stopped|after-upgrade|after-rollback|disconnected|upstream-after-upgrade|upstream-after-rollback) ;;
    *) echo "Unrecognized APT QA phase" >&2; return 2 ;;
  esac
  [ -x "$manager" ] && [ -x "$apt_cache" ] && [ -x "$apt_timeout" ] &&
    [ -x /usr/bin/apt-get ] && [ -r "$source_file" ] ||
    { fail_apt "native commands/fixture not executable or readable"; return 1; }
  if [ "$expected" = failure ]; then
    case "$label" in
      upstream-stopped|upstream-after-upgrade|upstream-after-rollback)
        systemctl is-active --quiet server-connect.service ||
          { fail_apt "selected local proxy unit unavailable during upstream failure"; return 1; }
        ready=$("$manager" --json ready 2>/dev/null) ||
          { fail_apt "selected local listener not ready during upstream failure"; return 1; }
        printf '%s\n' "$ready" | python3 -c '
import json, sys
o=json.load(sys.stdin)
if o.get("ok") is not True or (o.get("data") or {}).get("local_listener_ready") is not True:
    raise SystemExit("Selected local listener is not ready")
' || { fail_apt "local listener state not verified"; return 1; }
        ;;
    esac
  fi

  lists=$base/lists-$label
  archives=$base/archives-$label
  test ! -e "$lists"
  mkdir -m 0755 -p "$lists/partial" "$archives/partial"
  log=$base/$label.log
  # One isolated guest source fixture, but FRESH lists/archives per phase.
  # GNU timeout signals its subprocess group and enforces SIGKILL after 5s;
  # any timeout or command-infrastructure failure invalidates the test.
  rc=0
  LC_ALL=C "$apt_timeout" --kill-after=5s 35s "$manager" apt -- apt-get update \
    -o "Dir::Etc::sourcelist=$source_file" \
    -o "Dir::Etc::sourceparts=-" \
    -o "Dir::State::lists=$lists" \
    -o "Dir::Cache::archives=$archives" \
    -o "Dir::Cache::pkgcache=/dev/null" \
    -o "Dir::Cache::srcpkgcache=/dev/null" \
    -o "APT::Get::List-Cleanup=0" \
    -o "Debug::NoLocking=1" >"$log" 2>&1 || rc=$?

  if [ "$expected" = success ]; then
    if [ "$rc" -ne 0 ]; then
      classify_preflight_failure "$log"
      fail_apt "selected APT wrapper exited $rc: $label"
      return 1
    fi
    # Successful native index acquisition, not a cached prior-phase result.
    out=$base/$label.cache-out
    err=$base/$label.cache-err
    LC_ALL=C "$apt_cache" \
      -o "Dir::Etc::sourcelist=$source_file" \
      -o "Dir::Etc::sourceparts=-" \
      -o "Dir::State::lists=$lists" \
      show sc-qa-apt-route-proof >"$out" 2>"$err" ||
      { fail_apt "native apt-cache failed after successful APT update: $label"; return 1; }
    grep -Fxq 'Package: sc-qa-apt-route-proof' "$out" &&
      [ ! -s "$err" ] ||
      { fail_apt "expected fresh package index missing: $label"; return 1; }
    printf 'INSTALLED_APT_SELECTED(%s)=PASS (native apt-get index through selected loopback VLESS)\n' "$label"
  else
    check_failure_cause "$label" "$rc" "$log" || return 1
    check_absent_index "$lists" "$label" || return 1
    printf 'INSTALLED_APT_FAIL_CLOSED(%s)=PASS (classified failure, verified native empty APT index)\n' "$label"
  fi
}

inherited_policy() {
  [ "$(id -u)" = 0 ] && [ -f /.dockerenv ] &&
    [ "$(cat /proc/1/comm)" = systemd ] && [ "$(ls -1 /sys/class/net)" = lo ] ||
    { fail_apt 'inherited-policy QA requires the disconnected systemd guest'; return 1; }
  inherited_before=$(config_digest) ||
    { fail_apt 'inherited-policy baseline unavailable'; return 1; }
  assert_digest "$inherited_before" ||
    { fail_apt 'inherited-policy baseline invalid'; return 1; }

  python3 - "$manager" "$apt_timeout" "$base" "$source_file" <<'PY' ||
from pathlib import Path
import hashlib
import os
import stat
import subprocess
import sys

manager, timeout, base_arg, source = sys.argv[1:]
base = Path(base_arg)
work = base / "inherited-policy"
policy = Path("/etc/apt/apt.conf.d/99server-connect-qa-inherited-policy")
debug_error = (
    b"Error: APT per-host proxy, auto-detection or binary policy may bypass selected route\n"
)
update_error = (
    b"Error: inherited APT combined update policy is unsupported in Proxy Only\n"
)

# No credential-bearing configuration or child output is printed. The only
# APT policy mutation is this exclusively owned disconnected-guest file.
def require(condition, label):
    if not condition:
        raise RuntimeError(label)

def identity(info):
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode), info.st_nlink,
    )

def with_policy(payload, callback):
    data = payload.encode("ascii")
    fd = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    owned = identity(os.fstat(fd))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        require(identity(policy.lstat()) == owned, "owned policy identity changed")
        require(policy.read_bytes() == data, "owned policy write incomplete")
        callback()
    finally:
        # Preserve unexpected replacements/content for exact guest teardown.
        info = policy.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and identity(info) == owned
            and hashlib.sha256(policy.read_bytes()).digest()
                == hashlib.sha256(data).digest(),
            "owned policy cleanup identity uncertain",
        )
        policy.unlink()

def run_command(label, executable, expected):
    folder = work / label
    folder.mkdir(mode=0o700)
    lists = folder / "lists"
    archives = folder / "archives"
    (lists / "partial").mkdir(parents=True, mode=0o755)
    (archives / "partial").mkdir(parents=True, mode=0o755)
    log = folder / "command.log"
    argv = [
        timeout, "--kill-after=5s", "35s",
        manager, "apt", "--", executable, "install", "--simulate", "bash",
        "-o", "Dir::Etc::sourcelist=" + source,
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Dir::State::lists=" + str(lists),
        "-o", "Dir::Cache::archives=" + str(archives),
        "-o", "Dir::Cache::pkgcache=/dev/null",
        "-o", "Dir::Cache::srcpkgcache=/dev/null",
        "-o", "APT::Get::List-Cleanup=0",
        "-o", "Debug::NoLocking=1",
    ]
    with log.open("xb") as stream:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
            env={"HOME": "/root", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            check=False,
        )
    require(log.stat().st_size <= 65536, "unexpected command output size")
    output = log.read_bytes()
    require(secret not in output, "private credential appeared in command output")
    if expected is None:
        require(result.returncode == 0, "canonical package simulation failed")
    else:
        require(
            result.returncode == 1 and output == expected,
            "precise inherited-policy preflight refusal missing",
        )

try:
    require(not os.path.lexists(policy), "inherited-policy fixture already exists")
    require(
        os.access(manager, os.X_OK) and os.access(timeout, os.X_OK)
        and os.access("/usr/bin/apt", os.X_OK) and os.access("/usr/bin/apt-get", os.X_OK),
        "native command unavailable",
    )
    secret = Path("/var/lib/server-connect/proxy-auth").read_bytes()
    require(
        len(secret) == 48 and all(c in b"0123456789abcdef" for c in secret),
        "installed proxy credential unavailable",
    )
    work.mkdir(mode=0o700)
    cases = [
        ("update-global", "apt-get", 'APT::Update "true";\n', update_error),
        ("update-global-case", "apt", 'aPt::uPdAtE "On";\n', update_error),
        ("update-apt", "apt", 'Binary::apt::APT::Update "yes";\n', update_error),
        ("update-apt-get", "apt-get", 'Binary::apt-get::APT::Update "1";\n', update_error),
        ("update-apt-case", "apt", 'bInArY::aPt::aPt::uPdAtE "ENABLE";\n', update_error),
        ("update-apt-get-case", "apt-get", 'BiNaRy::ApT-GeT::ApT::UpDaTe "with";\n', update_error),
        ("debug-apt", "apt", 'Binary::apt::Debug::pkgAcquire::Worker "true";\n', debug_error),
        ("debug-apt-get", "apt-get", 'Binary::apt-get::Debug::pkgAcquire::Worker "true";\n', debug_error),
        ("debug-apt-case", "apt", 'bInArY::aPt::dEbUg::PkGaCqUiRe::wOrKeR "1";\n', debug_error),
        ("debug-apt-get-case", "apt-get", 'BiNaRy::ApT-GeT::DeBuG::pKgAcQuIrE::WoRkEr "yes";\n', debug_error),
    ]
    for label, executable, payload, expected in cases:
        with_policy(
            payload,
            lambda label=label, executable=executable, expected=expected:
                run_command(label, executable, expected),
        )

    # Empty parents/hooks, canonical disabled values and normal presentation
    # settings remain usable by both real native package frontends.
    safe_policy = (
        'APT::Update "";\n'
        'APT::Update::Post-Invoke {"true";};\n'
        'Binary::apt::APT::Update "false";\n'
        'Binary::apt-get::APT::Update "off";\n'
        'Binary::apt::APT::Color "0";\n'
    )
    def positive_controls():
        run_command("safe-apt-get", "apt-get", None)
        run_command("safe-apt", "apt", None)
    with_policy(safe_policy, positive_controls)
    require(not os.path.lexists(policy), "owned inherited policy remains")
except Exception:
    raise SystemExit("INSTALLED_APT_INHERITED_POLICY=FAIL (private diagnostics withheld)")
PY
    { fail_apt 'inherited-policy regression failed'; return 1; }

  inherited_after=$(config_digest) ||
    { fail_apt 'inherited-policy final inventory unavailable'; return 1; }
  assert_digest "$inherited_after" &&
    [ "$inherited_before" = "$inherited_after" ] ||
    { fail_apt 'inherited-policy cleanup did not restore native policy'; return 1; }
  echo 'INSTALLED_APT_INHERITED_POLICY=PASS (10 precise refusals, both native package controls, full policy restored)'
}

disabled_transports() {
  [ "$(id -u)" = 0 ] && [ -f /.dockerenv ] &&
    [ "$(cat /proc/1/comm)" = systemd ] && [ "$(ls -1 /sys/class/net)" = lo ] ||
    { fail_apt 'disabled-method QA requires the disconnected systemd guest'; return 1; }
  [ -x /usr/bin/strace ] && [ -f /root/qa-apt-disabled-trace.py ] &&
    [ ! -L /root/qa-apt-disabled-trace.py ] ||
    { fail_apt 'disabled-method trace checker unavailable'; return 1; }
  # A real Direct HTTP control proves that the known origin is reachable and
  # this exact scanner detects actual Internet-family socket activity.
  disabled_control=$base/trace-disabled-control
  mkdir -m 0700 "$disabled_control"
  # Go's runtime may leave a self-thread tgkill(SIGURG) unfinished when
  # the process group exits. Exclude only that signal syscall; keep all
  # fork/exec/exit and network attempts in the complete trace witness.
  /usr/bin/strace -ff -q -yy -v -s 2048 -e trace=%network,%process -e trace=!tgkill \
    -o "$disabled_control/trace" /usr/bin/curl -q --fail --silent --show-error \
    --max-time 4 --noproxy '*' "$origin/dists/qa/Release" \
    >"$base/disabled-control.out" 2>"$base/disabled-control.err" ||
    { fail_apt 'disabled-method reachable-origin trace control failed'; return 1; }
  if python3 /root/qa-apt-disabled-trace.py "$disabled_control" \
      >"$base/disabled-control-check.out" 2>"$base/disabled-control-check.err"; then
    fail_apt 'network trace control was incorrectly accepted'; return 1
  fi
  grep -Fx 'APT_DISABLED_TRANSPORT_TRACE=FAIL (nonlocal network attempt)' \
    "$base/disabled-control-check.err" >/dev/null ||
    { fail_apt 'real network trace control was not specifically detected'; return 1; }
  echo 'APT_DISABLED_TRANSPORT_NETWORK_CONTROL=PASS (live loopback origin, actual network attempt detected)'
  for transport in ftp rsh ssh mirror+ftp; do
    disabled_source=$base/source-disabled-$transport.list
    disabled_lists=$base/lists-disabled-$transport
    disabled_archives=$base/archives-disabled-$transport
    disabled_trace=$base/trace-disabled-$transport
    disabled_log=$base/disabled-$transport.log
    test ! -e "$disabled_source" && test ! -e "$disabled_lists" && test ! -e "$disabled_archives"
    mkdir -m 0755 -p "$disabled_lists/partial" "$disabled_archives/partial"
    mkdir -m 0700 "$disabled_trace"
    printf 'deb [trusted=yes] %s://127.0.0.1:19180/sc-qa-apt qa main\n' "$transport" >"$disabled_source"
    chmod 0644 "$disabled_source"
    disabled_rc=0
    "$apt_timeout" --kill-after=5s 35s /usr/bin/strace -ff -q -yy -v -s 2048 \
      -e trace=%network,%process -e trace=!tgkill -o "$disabled_trace/trace" \
      /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
      "$manager" apt -- apt-get update \
      -o "Dir::Etc::sourcelist=$disabled_source" -o 'Dir::Etc::sourceparts=-' \
      -o "Dir::State::lists=$disabled_lists" -o "Dir::Cache::archives=$disabled_archives" \
      -o 'Dir::Cache::pkgcache=/dev/null' -o 'Dir::Cache::srcpkgcache=/dev/null' \
      -o 'APT::Get::List-Cleanup=0' -o 'Debug::NoLocking=1' \
      >"$disabled_log" 2>&1 || disabled_rc=$?
    [ "$disabled_rc" -eq 100 ] ||
      { classify_preflight_failure "$disabled_log"; fail_apt "disabled-method native exit not established: $transport"; return 1; }
    grep -Fx "E: The method '$transport' is explicitly disabled via configuration." "$disabled_log" >/dev/null ||
      { fail_apt "exact native disabled-method reason missing: $transport"; return 1; }
    python3 /root/qa-apt-disabled-trace.py "$disabled_trace" ||
      { fail_apt "disabled-method process/network evidence incomplete: $transport"; return 1; }
    check_absent_index "$disabled_lists" "disabled-$transport" "$disabled_source" || return 1
    printf 'INSTALLED_APT_DISABLED_%s=PASS (native denial, complete trace, zero Internet attempts, empty fresh index)\n' "$transport"
  done
}

case "${1:-}" in
  setup)
    test "$#" -eq 1
    setup
    ;;
  positive)
    test "$#" -eq 2
    run_selected "$2" success
    ;;
  negative)
    test "$#" -eq 2
    run_selected "$2" failure
    ;;
  inherited-policy)
    test "$#" -eq 1
    inherited_policy
    ;;
  disabled-transports)
    test "$#" -eq 1
    disabled_transports
    ;;
  verify-host-policy)
    test "$#" -eq 1
    [ -f "$base/host-apt-policy.sha256" ] && [ ! -L "$base/host-apt-policy.sha256" ] &&
      [ -r "$base/host-apt-policy.sha256" ] ||
      { fail_apt 'expected APT policy digest missing or unreadable'; exit 1; }
    original=$(cat "$base/host-apt-policy.sha256") ||
      { fail_apt 'expected policy digest read failed'; exit 1; }
    current=$(config_digest) ||
      { fail_apt 'current policy digest computation failed'; exit 1; }
    assert_digest "$original" && assert_digest "$current" && [ "$original" = "$current" ] ||
      { fail_apt 'native APT policy digest invalid or changed'; exit 1; }
    [ -d /var/lib/server-connect ] ||
      { fail_apt 'installed state directory unavailable for descriptor audit'; exit 1; }
    descriptors=$(find /var/lib/server-connect -name '.apt-ephemeral-*' -print) ||
      { fail_apt 'private descriptor inventory incomplete'; exit 1; }
    [ -z "$descriptors" ] ||
      { fail_apt 'persistent private APT proxy descriptor present'; exit 1; }
    echo 'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS'
    ;;
  *)
    echo 'Usage: host-apt-only.sh setup|positive PHASE|negative PHASE|inherited-policy|disabled-transports|verify-host-policy' >&2
    exit 2
    ;;
esac
