#!/bin/sh
# Build versioned, exact-source release-candidate or default LOCAL QA bundles. Never publish.
set -eu
umask 077
usage() {
 echo 'Usage: scripts/package.sh /trusted/path/sing-box-1.14.3-linux-amd64.tar.gz [debian-12-amd64|debian-13-amd64] [--version VERSION]' >&2
 exit 2
}
[ "$#" -ge 1 ] || usage
CORE_ARCHIVE=$1
shift
[ -f "$CORE_ARCHIVE" ] || usage
package_target=debian-13-amd64
if [ "$#" -gt 0 ] && [ "$1" != --version ]; then
 package_target=$1
 shift
fi
package_version=0.1.0-dev
if [ "$#" -gt 0 ]; then
 [ "$#" -eq 2 ] && [ "$1" = --version ] || usage
 package_version=$2
fi
printf '%s\n' "$package_version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.+-]*)?$' || {
 echo 'Invalid release version (use a semantic version without v prefix)' >&2;exit 2;
}
[ "${#package_version}" -le 64 ] || { echo 'Invalid release version length' >&2;exit 2; }
case "$package_version" in
 *-dev|*-dev.*) package_kind=qa ;;
 *) package_kind=release-candidate ;;
esac
case "$package_target" in
 debian-12-amd64) artifact_target=debian12-amd64 ;;
 debian-13-amd64) artifact_target=debian13-amd64 ;;
 *) echo 'Unsupported package target; choose debian-12-amd64 or debian-13-amd64' >&2;exit 2 ;;
esac
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ "$package_kind" = qa ]; then
 artifact="$ROOT/dist/server-connect-$package_version-$artifact_target-local-qa.tar.gz"
 redistribution='not authorized; local QA only'
else
 artifact="$ROOT/dist/server-connect-$package_version-$artifact_target.tar.gz"
 redistribution='Owner-attested sources; publication is a separate Owner decision'
 [ -z "$(git -C "$ROOT" status --porcelain)" ] || {
  echo 'Release candidate requires an exact clean committed source tree' >&2;exit 1;
 }
fi
[ ! -e "$artifact.sig" ] && [ ! -L "$artifact.sig" ] || {
 echo 'Refusing to overwrite an already signed QA artifact; use a fresh output checkout' >&2;exit 1;
}
CORE_ARCHIVE=$(realpath "$CORE_ARCHIVE")
EXPECTED=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
printf '%s  %s\n' "$EXPECTED" "$CORE_ARCHIVE" | sha256sum --quiet -c - || { echo 'Pinned upstream core archive digest mismatch' >&2;exit 1; }
cd "$ROOT"
# A fresh Git checkout has no ignored build/ directory. Staging must work
# without relying on a previous CI step or a developer-created directory.
mkdir -p "$ROOT/build"
work=$(mktemp -d "$ROOT/build/pack.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir -p "$work/extract" "$work/server-connect/bin" "$work/server-connect/THIRD-PARTY-LICENSES" "$ROOT/dist"
tar -xzf "$CORE_ARCHIVE" -C "$work/extract"
up="$work/extract/sing-box-1.14.3-linux-amd64"
[ -f "$up/sing-box" ] && [ -f "$up/libcronet.so" ] && [ -f "$up/LICENSE" ] || { echo 'Expected upstream binary/library/license missing' >&2;exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo 'This local builder currently supports linux/amd64 only' >&2;exit 1; }
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X main.managerVersion=$package_version" -o "$work/server-connect/bin/server-connect" ./cmd/server-connect
cp "$up/sing-box" "$work/server-connect/bin/sing-box"
cp "$up/libcronet.so" "$work/server-connect/bin/libcronet.so"
cp "$up/LICENSE" "$work/server-connect/THIRD-PARTY-LICENSES/sing-box-LICENSE"
# The manager includes golang.org/x/net/publicsuffix in its compiled binary.
# Preserve the vendored BSD-3-Clause notice in the distributable payload.
cp vendor/golang.org/x/net/LICENSE "$work/server-connect/THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE"
# The compiled x/net/publicsuffix tables embed an MPL-2.0 Public Suffix List
# snapshot. Preserve the exact upstream source and license alongside the BSD
# Go-code notice; source provenance does not itself authorize publication.
grep -Fq '63cbc63d470d7b52c35266aa96c4c98c96ec499c' vendor/golang.org/x/net/publicsuffix/table.go || {
 echo 'Vendored publicsuffix revision differs from pinned source' >&2; exit 1;
}
printf '%s\n' \
 '66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172  third_party/publicsuffix/LICENSE' \
 '4dd388d5006a37c0748f17e1088ecd05c821da88eff36963bcc36297d7dea96e  third_party/publicsuffix/public_suffix_list.dat' \
 | sha256sum --strict --quiet --check - || {
 echo 'Pinned Public Suffix List source/license changed' >&2; exit 1;
}
cp third_party/publicsuffix/LICENSE "$work/server-connect/THIRD-PARTY-LICENSES/publicsuffix-LICENSE"
cp third_party/publicsuffix/public_suffix_list.dat "$work/server-connect/THIRD-PARTY-LICENSES/publicsuffix-list.dat"
# Include the exact separately licensed source data and its GPL-3.0 text
# in the complete, independently checksummed offline bundle. A bundle is
# still LOCAL QA ONLY until Owner approves publication/license obligations.
printf '%s\n' \
 'c80922639511fc817957f1ecb018b0f13855decc59c5fbe492fac5bdb6638616  internal/sc/data/iran-chocolate4u-2026-11.json' \
 '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986  third_party/chocolate4u/LICENSE' \
 | sha256sum --strict --quiet --check - || {
 echo 'Pinned Chocolate4U source/license changed' >&2;exit 1;
}
cp internal/sc/data/iran-chocolate4u-2026-11.json "$work/server-connect/THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json"
cp third_party/chocolate4u/LICENSE "$work/server-connect/THIRD-PARTY-LICENSES/chocolate4u-LICENSE"
# The embedded DB-IP Lite country estimate is a CC BY 4.0 adaptation.
# Keep its exact modified data and provider/license/change attribution in
# the immutable offline artifact; this does not clear other release gates.
printf '%s\n' \
 'c1d00c21ff2df3814d4f04f28fb651401a6c0afb2c9ebad35b70a878b011dc6c  internal/sc/data/iran-dbip-lite-2026-10.json' \
 '85d558b73fe325b0fc1c3c7794561199fcc9bc11a0f550c3b3cfce192026131c  third_party/dbip/ATTRIBUTION.txt' \
 | sha256sum --strict --quiet --check - || {
 echo 'Pinned DB-IP Lite data or attribution changed' >&2;exit 1;
}
cp internal/sc/data/iran-dbip-lite-2026-10.json "$work/server-connect/THIRD-PARTY-LICENSES/dbip-iran-prefixes.json"
cp third_party/dbip/ATTRIBUTION.txt "$work/server-connect/THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt"

cp bundle/install.sh bundle/server-connect.service bundle/server-connect-activation-recover.service bundle/server-connect-activation-recover.timer bundle/server-connect-native-tun.service bundle/server-connect-smart-health.service bundle/server-connect-smart-health.timer "$work/server-connect/"
cp scripts/release-auth.py "$work/server-connect/release-auth.py"
cp LICENSE "$work/server-connect/LICENSE"
chmod 0755 "$work/server-connect/install.sh" "$work/server-connect/bin/server-connect" "$work/server-connect/bin/sing-box"
source_revision=$(git rev-parse HEAD)
[ "$package_kind" = qa ] || [ -z "$(git status --porcelain)" ] || {
 echo 'Release candidate source tree changed during compilation' >&2;exit 1;
}
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then source_state=clean;else source_state=dirty;fi
printf '{"schema":1,"manager":"%s","core":"sing-box 1.14.3","core_archive_sha256":"%s","source_revision":"%s","source_state":"%s","target":"%s","redistribution":"%s"}\n' "$package_version" "$EXPECTED" "$source_revision" "$source_state" "$package_target" "$redistribution" > "$work/server-connect/manifest.json"
(
 cd "$work/server-connect"

 sha256sum bin/server-connect bin/sing-box bin/libcronet.so server-connect.service server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-native-tun.service server-connect-smart-health.service server-connect-smart-health.timer install.sh release-auth.py LICENSE THIRD-PARTY-LICENSES/sing-box-LICENSE THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE THIRD-PARTY-LICENSES/publicsuffix-LICENSE THIRD-PARTY-LICENSES/publicsuffix-list.dat THIRD-PARTY-LICENSES/chocolate4u-LICENSE THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt THIRD-PARTY-LICENSES/dbip-iran-prefixes.json manifest.json > checksums.sha256
 sha256sum --quiet -c checksums.sha256
 ./bin/server-connect version --json | python3 -I -S -c '
import json,sys
try:
    data=json.load(sys.stdin)
    assert data["ok"] is True and data["data"]=={"manager":sys.argv[1],"sing_box":"1.14.3"}
except (AssertionError,KeyError,ValueError,TypeError):sys.exit(1)
' "$package_version" || { echo 'Versioned manager binary failed manifest identity preflight' >&2;exit 1; }
 ./bin/sing-box version | head -n 1
)
# Normalize archive order, ownership and timestamps. A QA reviewer can
# independently rebuild the same byte-identical artifact from pinned inputs.
source_date_epoch=$(git show -s --format=%ct HEAD)
LC_ALL=C TZ=UTC tar --format=gnu --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -cf - -C "$work" server-connect | gzip -n > "$artifact"
tar -tzf "$artifact" >/dev/null || { echo 'Generated QA archive is malformed' >&2;exit 1; }
archive_digest=$(sha256sum "$artifact" | cut -d' ' -f1)
checksums_digest=$(sha256sum "$work/server-connect/checksums.sha256" | cut -d' ' -f1)
manifest_digest=$(sha256sum "$work/server-connect/manifest.json" | cut -d' ' -f1)
# This unsigned sidecar describes exact immutable inputs. Creating it never
# chooses a publisher key or grants publication permission.
printf '{"schema":1,"purpose":"server-connect-release","version":"%s","target":"%s","archive_sha256":"%s","checksums_sha256":"%s","manifest_sha256":"%s","source_revision":"%s","source_state":"%s","core":"sing-box 1.14.3","core_archive_sha256":"%s"}\n' \
 "$package_version" "$package_target" "$archive_digest" "$checksums_digest" "$manifest_digest" "$source_revision" "$source_state" "$EXPECTED" > "$artifact.release.json"
sha256sum "$artifact"
if [ "$package_kind" = qa ]; then
 echo 'LOCAL QA ONLY: artifact is not public Stable; optional signed-QA verification is available.'
else
 echo 'UNPUBLISHED RELEASE CANDIDATE: exact clean-source artifact generated; public release and mirror synchronization need separate Owner approval.'
fi
