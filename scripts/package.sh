#!/bin/sh
# Build a LOCAL QA candidate bundle. Does not download a core or publish assets.
set -eu
umask 077
CORE_ARCHIVE=${1:-}
[ "$#" -ge 1 ] && [ "$#" -le 2 ] && [ -n "$CORE_ARCHIVE" ] && [ -f "$CORE_ARCHIVE" ] || {
 echo 'Usage: scripts/package.sh /trusted/path/sing-box-1.14.3-linux-amd64.tar.gz [debian-12-amd64|debian-13-amd64]' >&2
 exit 2
}
package_target=${2-debian-13-amd64}
case "$package_target" in
 debian-12-amd64) artifact_target=debian12-amd64 ;;
 debian-13-amd64) artifact_target=debian13-amd64 ;;
 *) echo 'Unsupported package target; choose debian-12-amd64 or debian-13-amd64' >&2;exit 2 ;;
esac
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
CORE_ARCHIVE=$(realpath "$CORE_ARCHIVE")
EXPECTED=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
printf '%s  %s\n' "$EXPECTED" "$CORE_ARCHIVE" | sha256sum --quiet -c - || { echo 'Pinned upstream core archive digest mismatch' >&2;exit 1; }
cd "$ROOT"
work=$(mktemp -d "$ROOT/build/pack.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir -p "$work/extract" "$work/server-connect/bin" "$work/server-connect/THIRD-PARTY-LICENSES" "$ROOT/dist"
tar -xzf "$CORE_ARCHIVE" -C "$work/extract"
up="$work/extract/sing-box-1.14.3-linux-amd64"
[ -f "$up/sing-box" ] && [ -f "$up/libcronet.so" ] && [ -f "$up/LICENSE" ] || { echo 'Expected upstream binary/library/license missing' >&2;exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo 'This local builder currently supports linux/amd64 only' >&2;exit 1; }
GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$work/server-connect/bin/server-connect" ./cmd/server-connect
cp "$up/sing-box" "$work/server-connect/bin/sing-box"
cp "$up/libcronet.so" "$work/server-connect/bin/libcronet.so"
cp "$up/LICENSE" "$work/server-connect/THIRD-PARTY-LICENSES/sing-box-LICENSE"
cp bundle/install.sh bundle/server-connect.service bundle/server-connect-activation-recover.service bundle/server-connect-activation-recover.timer bundle/server-connect-smart-tun.service bundle/server-connect-smart-health.service bundle/server-connect-smart-health.timer "$work/server-connect/"
chmod 0755 "$work/server-connect/install.sh" "$work/server-connect/bin/server-connect" "$work/server-connect/bin/sing-box"
source_revision=$(git rev-parse HEAD)
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then source_state=clean;else source_state=dirty;fi
printf '{"schema":1,"manager":"0.1.0-dev","core":"sing-box 1.14.3","core_archive_sha256":"%s","source_revision":"%s","source_state":"%s","target":"%s","redistribution":"not authorized; local QA only"}\n' "$EXPECTED" "$source_revision" "$source_state" "$package_target" > "$work/server-connect/manifest.json"
(
 cd "$work/server-connect"
 sha256sum bin/server-connect bin/sing-box bin/libcronet.so server-connect.service server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer install.sh THIRD-PARTY-LICENSES/sing-box-LICENSE manifest.json > checksums.sha256
 sha256sum --quiet -c checksums.sha256
 ./bin/server-connect version --json
 ./bin/sing-box version | head -n 1
)
artifact="$ROOT/dist/server-connect-0.1.0-dev-$artifact_target-local-qa.tar.gz"
# Normalize archive order, ownership and timestamps. A QA reviewer can
# independently rebuild the same byte-identical artifact from pinned inputs.
source_date_epoch=$(git show -s --format=%ct HEAD)
LC_ALL=C TZ=UTC tar --format=gnu --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -cf - -C "$work" server-connect | gzip -n > "$artifact"
tar -tzf "$artifact" >/dev/null || { echo 'Generated QA archive is malformed' >&2;exit 1; }
sha256sum "$artifact"
echo 'LOCAL QA ONLY: no publisher signature, no product license, no public binary release authorization.'
