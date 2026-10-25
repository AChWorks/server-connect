#!/bin/sh
# Disposable disconnected Debian 13 systemd guest ONLY.
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
records = []
for path in sorted(root.rglob('*')):
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
  echo "INSTALLED_APT_QA=FAIL ($1; private guest diagnostics retained)" >&2
  return 1
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
  out=$base/$label.cache-out
  err=$base/$label.cache-err
  rc=0
  LC_ALL=C "$apt_cache" \
    -o "Dir::Etc::sourcelist=$source_file" \
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
      fail_apt "native APT update exited $rc: $label"
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
    echo 'Usage: host-apt-only.sh setup|positive PHASE|negative PHASE|verify-host-policy' >&2
    exit 2
    ;;
esac
