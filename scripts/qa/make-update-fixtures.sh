#!/bin/sh
# Generate disposable same-source upgrade candidates with distinct executable
# bytes. These are NOT version-migration or authenticated release artifacts.
set -eu
umask 077
[ "$(printenv GITHUB_ACTIONS || true)" = true ] && [ "$(printenv CI || true)" = true ] || {
  echo 'QA upgrade fixtures are CI-only' >&2
  exit 2
}
[ "$#" -eq 2 ] && [ -f "$1" ] && [ -d "$2" ] || {
  echo 'Usage: make-update-fixtures.sh BASE_ARCHIVE OUTPUT_DIR' >&2
  exit 2
}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
archive=$(realpath -- "$1")
output=$(realpath -- "$2")
scratch=$(mktemp -d "$output/.sc-update-fixtures.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
mkdir "$scratch/base"
# The input comes only from the exact local scripts/package.sh CI output.
tar -xzf "$archive" -C "$scratch/base"
base="$scratch/base/server-connect"
test -f "$base/checksums.sha256"
(cd "$base" && sha256sum --quiet --check checksums.sha256)
original_digest=$(sha256sum "$base/bin/server-connect" | cut -d' ' -f1)
source_date_epoch=$(cd "$root" && git show -s --format=%ct HEAD)

for variant in valid invalid-unit; do
  dest="$scratch/$variant/server-connect"
  mkdir -p "$(dirname "$dest")"
  cp -a "$base" "$dest"
  (
    cd "$root"
    GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath \
      -ldflags "-s -w -buildid=sc-hostqa-$variant" \
      -o "$dest/bin/server-connect" ./cmd/server-connect
  )
  variant_digest=$(sha256sum "$dest/bin/server-connect" | cut -d' ' -f1)
  [ "$variant_digest" != "$original_digest" ] || {
    echo 'QA manager binary was not changed' >&2
    exit 1
  }
  if [ "$variant" = invalid-unit ]; then
    # Exercise a real post-switch failure after preflight, new release staging
    # and service restart. This broken unit stays in a CI-only archive.
    sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/false|' "$dest/server-connect.service"
    grep -qx 'ExecStart=/usr/bin/false' "$dest/server-connect.service"
  fi
  (
    cd "$dest"
    sha256sum bin/server-connect bin/sing-box bin/libcronet.so \
      server-connect.service server-connect-activation-recover.service \
      server-connect-activation-recover.timer install.sh \
      THIRD-PARTY-LICENSES/sing-box-LICENSE manifest.json > checksums.sha256
    sha256sum --quiet --check checksums.sha256
    ./bin/server-connect version --json | grep -q '"sing_box":"1.14.3"'
    test "$(./bin/sing-box version | head -n 1)" = 'sing-box version 1.14.3'
  )
  target="$output/server-connect-hostqa-update-$variant.tar.gz"
  LC_ALL=C TZ=UTC tar --format=gnu --sort=name \
    --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
    -cf - -C "$scratch/$variant" server-connect | gzip -n > "$target"
  tar -tzf "$target" >/dev/null
  sha256sum "$target"
done
valid_digest=$(tar -xOzf "$output/server-connect-hostqa-update-valid.tar.gz" \
  server-connect/bin/server-connect | sha256sum | cut -d' ' -f1)
invalid_digest=$(tar -xOzf "$output/server-connect-hostqa-update-invalid-unit.tar.gz" \
  server-connect/bin/server-connect | sha256sum | cut -d' ' -f1)
[ "$valid_digest" != "$invalid_digest" ] || {
  echo 'QA failure candidate is not distinct from successful update' >&2
  exit 1
}
echo 'QA fixture only: distinct same-source binaries; no real cross-version schema migration or publisher authentication.'
