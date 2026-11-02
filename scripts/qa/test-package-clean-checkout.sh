#!/usr/bin/env bash
# QA-only: reproduce the developer package from an independent clean checkout.
# Requires the already verified pinned upstream core archive. Never installs
# a package, modifies routing or downloads a dependency.
set -euo pipefail
umask 077

if [[ $# != 1 || ! -f $1 ]]; then
  echo 'Usage: test-package-clean-checkout.sh /trusted/path/sing-box-1.14.3-linux-amd64.tar.gz' >&2
  exit 2
fi
root=$(git rev-parse --show-toplevel)
core=$(realpath -- "$1")
artifact=server-connect-0.1.0-dev-debian13-amd64-local-qa.tar.gz
expected="$root/dist/$artifact"
if [[ ! -f $expected ]]; then
  echo 'Build the regular source QA package before this clean-checkout comparison' >&2
  exit 2
fi
if [[ -n $(git -C "$root" status --porcelain) ]]; then
  echo 'Refusing to compare a dirty source checkout' >&2
  exit 2
fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/sc-clean-package.XXXXXXXX")
checkout="$scratch/checkout"
attached=no
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ $attached == yes ]]; then
    if ! git -C "$root" worktree remove --force "$checkout"; then
      echo "Could not safely remove the exact task-owned QA worktree: $checkout" >&2
      exit 1
    fi
  fi
  if ! rmdir "$scratch"; then
    echo "Could not safely remove the exact task-owned QA scratch: $scratch" >&2
    exit 1
  fi
  exit "$rc"
}
trap cleanup EXIT

git -C "$root" worktree add --detach "$checkout" HEAD
attached=yes
test ! -e "$checkout/build" || {
  echo 'Detached checkout was not clean of ignored build/ state' >&2
  exit 1
}

# The CI checkout can be runner-owned while the Debian container runs as
# root. Trust precisely these two local checkout paths, not all Git paths.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="$root"
export GIT_CONFIG_KEY_1=safe.directory
export GIT_CONFIG_VALUE_1="$checkout"

(
  cd "$checkout"
  scripts/package.sh "$core"
  test -f "dist/$artifact"
)
expected_digest=$(sha256sum "$expected" | cut -d ' ' -f1)
actual_digest=$(sha256sum "$checkout/dist/$artifact" | cut -d ' ' -f1)
if [[ $actual_digest != "$expected_digest" ]]; then
  echo 'Independent clean-checkout QA bundle differs from the regular build' >&2
  exit 1
fi
echo "PASS: clean checkout packaged successfully without preexisting build/; deterministic bundle SHA256=$actual_digest"
