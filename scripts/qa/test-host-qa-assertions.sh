#!/usr/bin/env bash
# Hermetic fail-closed regression tests; no Docker, root, Internet or host changes.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
checker="$root/scripts/qa/host-qa-assertions.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/traces" "$scratch/fakebin"
trace_file="$scratch/traces/check.101"
safe_trace='execve("/usr/bin/env", ["env"], ["HOME=/root"]) = 0
socket(AF_UNIX, SOCK_STREAM, 0) = 3
exit_group(0) = ?'
printf '%s\n' "$safe_trace" >"$trace_file"

expect_trace_ok() {
  sh "$checker" trace "$scratch/traces" check >/dev/null ||
    { echo "Expected clean trace rejected: $1" >&2; exit 1; }
}
expect_trace_rejected() {
  local captured
  if captured=$(sh "$checker" trace "$scratch/traces" check 2>&1); then
    echo "Unsafe trace was accepted: $1" >&2
    exit 1
  fi
  [[ $captured == *'Host QA assertion failed:'* && $captured != *'=ZERO'* ]] ||
    { echo "Unsafe trace had no safe failure diagnostics: $1" >&2; exit 1; }
}

expect_trace_ok 'safe AF_UNIX operation'
printf '%s\n' "$safe_trace" 'socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 4' >"$trace_file"
expect_trace_rejected 'IPv6 socket attempt'
printf '%s\n' "$safe_trace" \
  'connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH' >"$trace_file"
expect_trace_rejected 'failed IPv4 connection attempt'
printf '%s\n' "$safe_trace" \
  'sendmsg(4<UDP:[127.0.0.1:1]>, {msg_name=NULL}, 0) = -1 EHOSTUNREACH' >"$trace_file"
expect_trace_rejected 'send on decoded UDP descriptor'
printf '%s\n' "$safe_trace" 'execve("/usr/bin/curl", ["curl"], []) = 0' >"$trace_file"
expect_trace_rejected 'forbidden execve'
printf '%s\n' "$safe_trace" \
  'execveat(AT_FDCWD, "/usr/bin/apt-get", ["apt-get"], [], 0) = 0' >"$trace_file"
expect_trace_rejected 'forbidden execveat'
printf '%s\n' "$safe_trace" \
  'execveat(3, "", ["unresolved"], [], AT_EMPTY_PATH) = 0' >"$trace_file"
expect_trace_rejected 'unresolved fd-only execveat'
printf '%s\n' "$safe_trace" >"$trace_file"
printf '\000' >>"$trace_file"
expect_trace_rejected 'binary or corrupted trace'
rm "$trace_file"
expect_trace_rejected 'missing process trace'
: >"$trace_file"
expect_trace_rejected 'empty process trace'
printf '%s\n' "$safe_trace" >"$trace_file"
mkdir "$scratch/traces/check.102"
expect_trace_rejected 'non-regular child trace'
rmdir "$scratch/traces/check.102"
ln -s "$trace_file" "$scratch/traces/check.102"
expect_trace_rejected 'symlinked child trace'
rm "$scratch/traces/check.102"
chmod 000 "$trace_file"
if [[ $(id -u) -ne 0 ]]; then
  expect_trace_rejected 'unreadable trace'
fi
chmod 600 "$trace_file"
cat > "$scratch/fakebin/grep" <<'BAD_GREP'
#!/bin/sh
# A partial scanner failure must never be treated as no matches.
printf 'partial-scan\n'
exit 2
BAD_GREP
chmod +x "$scratch/fakebin/grep"
if captured=$(PATH="$scratch/fakebin:$PATH" sh "$checker" trace "$scratch/traces" check 2>&1); then
  echo 'grep I/O error was accepted as clean trace' >&2
  exit 1
fi
[[ $captured == *'grep exit 2'* && $captured != *'=ZERO'* ]] ||
  { echo 'grep I/O error did not retain scanner failure diagnostics' >&2; exit 1; }
expect_trace_ok 'clean trace after injected errors'

cat > "$scratch/fakebin/ip" <<'FAKE_IP'
#!/bin/sh
set -eu
if [ "$SC_QA_FAKE_IP_FAIL" = "$*" ]; then
  echo 'simulated ip query failure' >&2
  exit 88
fi
printf '%s %s\n' "$SC_QA_FAKE_IP_ALTER" "$*"
FAKE_IP
chmod +x "$scratch/fakebin/ip"
export PATH="$scratch/fakebin:$PATH" SC_QA_FAKE_IP_FAIL='none' SC_QA_FAKE_IP_ALTER=no
first=$(sh "$checker" network)
second=$(sh "$checker" network)
[[ $first == "$second" && $first =~ ^[0-9a-f]{64}$ ]] ||
  { echo 'stable complete five-component snapshot failed' >&2; exit 1; }
SC_QA_FAKE_IP_ALTER=yes
export SC_QA_FAKE_IP_ALTER
third=$(sh "$checker" network)
[[ $first != "$third" ]] ||
  { echo 'network change was not reflected by digest' >&2; exit 1; }
SC_QA_FAKE_IP_ALTER=no
export SC_QA_FAKE_IP_ALTER
for failed_query in \
  '-j -4 route show table all' \
  '-j -6 route show table all' \
  '-j -4 rule show' \
  '-j -6 rule show' \
  '-j link show'; do
  SC_QA_FAKE_IP_FAIL=$failed_query
  export SC_QA_FAKE_IP_FAIL
  if captured=$(sh "$checker" network 2>&1); then
    echo "Failed ip query produced a successful hash: $failed_query" >&2
    exit 1
  fi
  [[ $captured == *'snapshot query failed'* ]] ||
    { echo "Missing phase-specific failed ip diagnostic: $failed_query" >&2; exit 1; }
done
echo 'HOST_QA_ASSERTION_NEGATIVE_REGRESSIONS=PASS'
