#!/usr/bin/env bash
# Hermetic negative tests of the ACTUAL probe command path.
# All network/service commands are PATH-scoped fake executables; this script
# never starts a service or connects to the host's network.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
probe="$root/scripts/qa/host-coexistence.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/bin"

cat >"$scratch/bin/systemctl" <<'SERVICE'
#!/bin/sh
test "$1" = is-active && test "$2" = --quiet || exit 2
test "${SC_QA_DOWN:-}" != "$3"
SERVICE

cat >"$scratch/bin/curl" <<'HTTP'
#!/bin/sh
printf '%s' "${SC_QA_WEB_BODY-SC_QA_WEB_OK}"
exit "${SC_QA_WEB_RC:-0}"
HTTP

cat >"$scratch/bin/timeout" <<'SSH'
#!/bin/sh
# Stand in for the timeout-wrapped ssh command; stdout alone is insufficient.
printf '%s' "${SC_QA_SSH_BODY-SC_QA_SSH_OK}"
exit "${SC_QA_SSH_RC:-0}"
SSH
chmod 0700 "$scratch/bin/systemctl" "$scratch/bin/curl" "$scratch/bin/timeout"
export PATH="$scratch/bin:/usr/bin:/bin"

expect_ok() {
  local case_name=$1
  shift
  if ! "$@" >"$scratch/out" 2>"$scratch/err"; then
    echo "Successful fixture unexpectedly rejected: $case_name" >&2
    exit 1
  fi
  if [[ -s $scratch/out ]]; then
    echo "Fixture emitted unexpected stdout: $case_name" >&2
    exit 1
  fi
}
expect_rejected() {
  local case_name=$1
  shift
  if "$@" >"$scratch/out" 2>"$scratch/err"; then
    echo "Unsafe fixture accepted: $case_name" >&2
    exit 1
  fi
  if [[ -s $scratch/out ]]; then
    echo "Rejected fixture emitted a success-looking stdout marker: $case_name" >&2
    exit 1
  fi
}

expect_ok "both commands succeed" /bin/sh "$probe" probe
expect_rejected "HTTP expected body but curl exits nonzero" \
  env SC_QA_WEB_RC=7 /bin/sh "$probe" probe
expect_rejected "SSH expected body but ssh exits nonzero" \
  env SC_QA_SSH_RC=255 /bin/sh "$probe" probe
expect_rejected "SSH emits marker then timeout exits 124" \
  env SC_QA_SSH_RC=124 /bin/sh "$probe" probe
expect_rejected "HTTP endpoint unreachable" \
  env SC_QA_WEB_BODY= SC_QA_WEB_RC=7 /bin/sh "$probe" probe
expect_rejected "SSH authentication fails" \
  env SC_QA_SSH_BODY= SC_QA_SSH_RC=255 /bin/sh "$probe" probe
expect_rejected "HTTP unexpected body despite exit 0" \
  env SC_QA_WEB_BODY=INVALID /bin/sh "$probe" probe
expect_rejected "SSH unexpected body despite exit 0" \
  env SC_QA_SSH_BODY=INVALID /bin/sh "$probe" probe
expect_rejected "HTTP systemd unit stopped" \
  env SC_QA_DOWN=sc-qa-web.service /bin/sh "$probe" probe
expect_rejected "SSH systemd unit stopped" \
  env SC_QA_DOWN=sc-qa-ssh.service /bin/sh "$probe" probe
echo 'HOST_COEXISTENCE_NEGATIVE_REGRESSIONS=PASS'
