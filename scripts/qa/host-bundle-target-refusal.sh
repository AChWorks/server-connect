#!/bin/sh
# Exact installer target refusals in the parent's disconnected systemd guest.
# Every altered manifest is a private QA fixture, not a release artifact.
set -eu
umask 077
[ "$(id -u)" = 0 ] && [ -f /.dockerenv ]
[ "$(cat /proc/1/comm)" = systemd ]
[ "$(uname -m)" = x86_64 ]
[ "$(ls -1 /sys/class/net)" = lo ]
[ -d /root/server-connect ] && [ ! -L /root/server-connect ]
[ -f /root/qa-host-assertions.sh ] && [ -d /root/qa-strace ]
. /etc/os-release
[ "$ID" = debian ]
case "$VERSION_ID" in 12|13) ;; *) exit 1 ;; esac
target="debian-$VERSION_ID-amd64"
if [ "$VERSION_ID" = 12 ]; then opposite=debian-13-amd64; else opposite=debian-12-amd64; fi
(cd /root/server-connect && sha256sum --quiet --check checksums.sha256)
python3 - "$target" <<'PYPOSITIVE'
import json,sys
from pathlib import Path
manifest=json.loads(Path('/root/server-connect/manifest.json').read_text())
assert manifest['target']==sys.argv[1]
PYPOSITIVE

assert_absent() {
 for path in /opt/server-connect /var/lib/server-connect /usr/local/bin/server-connect; do
  [ ! -e "$path" ] && [ ! -L "$path" ]
 done
 for name in server-connect.service server-connect-activation-recover.service \
   server-connect-activation-recover.timer server-connect-smart-tun.service \
   server-connect-smart-health.service server-connect-smart-health.timer; do
  [ ! -e "/etc/systemd/system/$name" ] && [ ! -L "/etc/systemd/system/$name" ]
  [ "$(systemctl show "$name" -p LoadState --value)" = not-found ]
 done
}
assert_absent
fixture_root=$(mktemp -d /root/sc-target-refusal.XXXXXXXX)
trap 'rm -rf -- "$fixture_root"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for variant in opposite missing duplicate unsupported malformed; do
 fixture="$fixture_root/server-connect"
 mkdir -m 0700 "$fixture"
 cp -a /root/server-connect/. "$fixture/"
 python3 - "$fixture" "$variant" "$target" "$opposite" <<'PYMANIFEST'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]); variant,target,opposite=sys.argv[2:]
manifest=root/'manifest.json'
doc=json.loads(manifest.read_text())
assert doc['target']==target
if variant=='opposite':
    doc['target']=opposite
elif variant=='missing':
    del doc['target']
elif variant=='unsupported':
    doc['target']='debian-14-amd64'
if variant=='duplicate':
    # Put the correct host target LAST: a last-value-wins decoder would
    # accept this ambiguous metadata, making the rejection discriminating.
    doc['target']=opposite
    raw=json.dumps(doc)[:-1]+',"target":'+json.dumps(target)+'}\n'
elif variant=='malformed':
    raw='{"schema":1,"target":'
else:
    raw=json.dumps(doc)+'\n'
manifest.write_text(raw)
checks=root/'checksums.sha256'
lines=checks.read_text().splitlines()
matches=[i for i,line in enumerate(lines) if line.endswith('  manifest.json')]
assert len(matches)==1
lines[matches[0]]=hashlib.sha256(manifest.read_bytes()).hexdigest()+'  manifest.json'
checks.write_text('\n'.join(lines)+'\n')
PYMANIFEST
 (cd "$fixture" && sha256sum --quiet --check checksums.sha256)
 label="target-$variant"
 if /usr/bin/strace -ff -qq -yy -s 128 -e trace=%network,%process \
     -o "/root/qa-strace/$label" /usr/bin/env -i \
     PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
     /bin/sh "$fixture/install.sh" --offline \
     >"$fixture_root/$label.stdout" 2>"$fixture_root/$label.stderr"; then
  echo "BUNDLE_TARGET_REFUSAL=FAIL ($variant accepted)" >&2
  exit 1
 else
  rejected=$?
 fi
 [ "$rejected" -eq 1 ]
 grep -Fx 'Server Connect: ERROR: bundle target does not match this supported host' \
   "$fixture_root/$label.stderr" >/dev/null
 assert_absent
 /bin/sh /root/qa-host-assertions.sh trace /root/qa-strace "$label"
 printf 'BUNDLE_TARGET_REFUSAL_%s=PASS (explicit target failure, no installed state, no dependency fetch)\n' "$variant"
 rm -rf -- "$fixture"
done
(cd /root/server-connect && sha256sum --quiet --check checksums.sha256)
echo 'BUNDLE_TARGET_HOST_MATCH_AND_NEGATIVES=PASS'
