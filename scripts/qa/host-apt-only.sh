#!/bin/sh
# Disposable disconnected Debian 13 systemd guest ONLY.
# Exercise native installed apt-get via the manager's selected VLESS route.
# The HTTP APT repository and all cache/source files live inside this guest.
set -eu
umask 077

manager=/usr/local/bin/server-connect
base=/srv/sc-qa-apt
source_file=$base/sources.list
origin=http://127.0.0.1:19180/sc-qa-apt

config_digest() {
  python3 - <<'PY'
from pathlib import Path
import hashlib, os, stat
records = []
for path in sorted(Path('/etc/apt').rglob('*')):
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
  echo 'INSTALLED_APT_FIXTURE=PASS (local unsigned index; trusted=yes disposable QA only)'
}

run_selected() {
  label=$1
  expected=$2
  case "$label" in
    initial|upstream-stopped|core-stopped|after-upgrade|after-rollback|disconnected) ;;
    *) echo "Unrecognized APT QA phase" >&2; return 2 ;;
  esac
  lists=$base/lists-$label
  archives=$base/archives-$label
  test ! -e "$lists"
  mkdir -m 0755 -p "$lists/partial" "$archives/partial"
  log=$base/$label.log
  # APT gets a fresh private source and empty index directory every time.
  # No /etc/apt modification, no host package installation, no foreign fetch.
  # A bounded process lifetime rejects indefinitely hung selected paths.
  status=0
  timeout 35 "$manager" apt -- apt-get update     -o "Dir::Etc::sourcelist=$source_file"     -o "Dir::Etc::sourceparts=-"     -o "Dir::State::lists=$lists"     -o "Dir::Cache::archives=$archives"     -o "Dir::Cache::pkgcache=/dev/null"     -o "Dir::Cache::srcpkgcache=/dev/null"     -o "APT::Get::List-Cleanup=0"     -o "Debug::NoLocking=1" >"$log" 2>&1 || status=$?

  if [ "$expected" = success ]; then
    if [ "$status" -ne 0 ]; then
      echo "INSTALLED_APT_SELECTED($label)=FAIL (APT exit $status; private guest diagnostics retained)" >&2
      return 1
    fi
    # This checks actual native package-index acquisition, not an HTTP 200
    # from a generic client or a cached index from a previous phase.
    result=$(apt-cache       -o "Dir::Etc::sourcelist=$source_file"       -o "Dir::Etc::sourceparts=-"       -o "Dir::State::lists=$lists"       show sc-qa-apt-route-proof) || return 1
    printf '%s\n' "$result" | grep -Fx 'Package: sc-qa-apt-route-proof' >/dev/null
    printf 'INSTALLED_APT_SELECTED(%s)=PASS (native apt-get index through selected loopback VLESS)\n' "$label"
  else
    if [ "$status" -eq 0 ]; then
      echo "INSTALLED_APT_FAIL_CLOSED($label)=FAIL (unexpected successful APT update)" >&2
      return 1
    fi
    if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
      echo "INSTALLED_APT_FAIL_CLOSED($label)=FAIL (APT hung until timeout)" >&2
      return 1
    fi
    # A failed acquisition must not silently supply a previous cached index.
    if apt-cache       -o "Dir::Etc::sourcelist=$source_file"       -o "Dir::Etc::sourceparts=-"       -o "Dir::State::lists=$lists"       show sc-qa-apt-route-proof >/dev/null 2>&1; then
      echo "INSTALLED_APT_FAIL_CLOSED($label)=FAIL (index unexpectedly available)" >&2
      return 1
    fi
    printf 'INSTALLED_APT_FAIL_CLOSED(%s)=PASS (native update failed, no cached index)\n' "$label"
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
    test "$(config_digest)" = "$(cat "$base/host-apt-policy.sha256")"
    if find /var/lib/server-connect -name '.apt-ephemeral-*' -print | grep .; then
      echo 'Persisted private APT proxy descriptor path' >&2
      exit 1
    fi
    echo 'INSTALLED_APT_NATIVE_HOST_POLICY_UNCHANGED=PASS'
    ;;
  *)
    echo 'Usage: host-apt-only.sh setup|positive PHASE|negative PHASE|verify-host-policy' >&2
    exit 2
    ;;
esac
