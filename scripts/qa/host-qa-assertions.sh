#!/bin/sh
# Read-only checks for disposable Server Connect installed-host QA.
# The caller owns isolation. Never use these checks to authorize host mutation.
set -eu
LC_ALL=C
export LC_ALL

fail() {
  printf 'Host QA assertion failed: %s\n' "$*" >&2
  exit 1
}

# GNU grep -q may return success despite an I/O error after a match.
# Scan each trace to completion without -q: 0=unexpected match, 1=clean,
# anything else=scanner error. Never print raw strace arguments or secrets.
reject_pattern() {
  description=$1
  expression=$2
  trace_file=$3
  if grep -aE -- "$expression" "$trace_file" >/dev/null; then
    fail "$description in trace $trace_file"
  else
    status=$?
    [ "$status" -eq 1 ] ||
      fail "cannot completely scan $trace_file for $description (grep exit $status)"
  fi
}

case "$1" in
  trace)
    [ "$#" -eq 3 ] || fail 'trace usage: trace DIRECTORY PHASE'
    trace_dir=$2
    phase=$3
    case "$phase" in
      ''|*[!a-z0-9-]*) fail 'unsafe trace phase name' ;;
    esac
    [ -d "$trace_dir" ] || fail "trace directory missing: $trace_dir"
    # strace -ff writes one PHASE.PID file per traced process.
    set -- "$trace_dir"/"$phase".*
    [ -f "$1" ] || fail "no process traces for phase $phase"
    for trace_file do
      [ -f "$trace_file" ] && [ ! -L "$trace_file" ] &&
        [ -r "$trace_file" ] && [ -s "$trace_file" ] ||
        fail "missing, empty, unreadable or non-regular trace: $trace_file"

      # A trace containing raw binary/control bytes cannot be treated as
      # complete textual syscall evidence (strace normally escapes them).
      reject_pattern 'invalid binary/control evidence' \
        '[^[:print:][:space:]]' "$trace_file"

      # Offline contract: no IPv4/IPv6 socket creation, and no attempt
      # to connect/bind/send on an IPv4/IPv6 endpoint or decoded TCP/UDP
      # descriptor. AF_UNIX local IPC and AF_NETLINK inspection are allowed.
      # strace must use -yy and trace=%network,%process to cover these
      # calls, both execve variants, and child process exits.
      reject_pattern 'IPv4/IPv6 network attempt' \
        'socket\(AF_INET(6)?[,)]|(connect|bind|send|sendto|sendmsg|sendmmsg)\(.*(sa_family=AF_INET(6)?|<(TCP|UDP|IP):)' \
        "$trace_file"
      reject_pattern 'offline fetch/package helper execution' \
        'execve(at)?\(.*/(curl|wget|apt-get|apt|git)(["/>[:space:]]|$)' \
        "$trace_file"
      # An fd-only execution without a resolved path is unverifiable:
      # it could conceal a prohibited fetch executable.
      reject_pattern 'unverifiable fd-only execution' \
        'execveat\(.*AT_EMPTY_PATH' "$trace_file"
    done
    ;;
  network)
    [ "$#" -eq 1 ] || fail 'network usage: network'
    scratch=$(mktemp -d /tmp/sc-qa-network.XXXXXXXX) ||
      fail 'cannot create network snapshot staging'
    trap 'rm -rf -- "$scratch"' EXIT
    # Each query runs separately and must succeed BEFORE hashing. Do not
    # pipe a failing ip command into sha256sum (which would hash partial data).
    ip -j -4 route show table all >"$scratch/routes4" ||
      fail 'IPv4 route snapshot query failed'
    ip -j -6 route show table all >"$scratch/routes6" ||
      fail 'IPv6 route snapshot query failed'
    ip -j -4 rule show >"$scratch/rules4" ||
      fail 'IPv4 policy-rule snapshot query failed'
    ip -j -6 rule show >"$scratch/rules6" ||
      fail 'IPv6 policy-rule snapshot query failed'
    ip -j link show >"$scratch/links" ||
      fail 'link snapshot query failed'
    : >"$scratch/combined" || fail 'cannot create combined snapshot'
    for part in routes4 routes6 rules4 rules6 links; do
      printf '===%s===\n' "$part" >>"$scratch/combined" ||
        fail "cannot label $part"
      cat "$scratch/$part" >>"$scratch/combined" ||
        fail "cannot read $part"
      printf '\n' >>"$scratch/combined" ||
        fail "cannot separate $part"
    done
    checksum=$(sha256sum "$scratch/combined") ||
      fail 'cannot hash complete network snapshot'
    set -- $checksum
    [ "$#" -eq 2 ] && [ "$1" != '' ] ||
      fail 'invalid network snapshot checksum'
    printf '%s\n' "$1"
    ;;
  *)
    fail 'usage: host-qa-assertions.sh trace DIRECTORY PHASE | network'
    ;;
esac
