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
  recovery-receipt)
    [ "$#" -eq 3 ] || fail 'recovery-receipt usage: recovery-receipt JSONL_FILE OPERATION_ID'
    [ -f "$2" ] && [ ! -L "$2" ] && [ -r "$2" ] ||
      fail 'missing or non-regular recovery journal evidence'
    # Caller captures a journal cursor BEFORE the action and supplies only
    # current-boot entries after it. systemd can garbage-collect an inactive
    # oneshot's execution statistics; trusted journal stream identity lasts.
    python3 - "$2" "$3" <<'PYRECOVERYRECEIPT'
import json
import re
import sys


def refuse(reason):
    raise ValueError(reason)


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON field in recovery evidence")
        result[key] = value
    return result


try:
    path, expected = sys.argv[1:]
    if not re.fullmatch(r"[0-9a-f]{32}", expected):
        refuse("invalid expected recovery operation")
    with open(path, "rb") as handle:
        payload = handle.read(1024 * 1024 + 1)
    if not payload or len(payload) > 1024 * 1024:
        refuse("empty or oversized recovery journal evidence")
    rows = payload.decode("utf-8").splitlines()
    if len(rows) > 2048:
        refuse("excessive recovery journal records")
    streams = {}
    cursors = set()
    for line in rows:
        row = json.loads(line, object_pairs_hook=unique_fields)
        if not isinstance(row, dict):
            refuse("invalid recovery journal record")
        if row.get("_SYSTEMD_UNIT") != "server-connect-activation-recover.service" or row.get("_TRANSPORT") != "stdout":
            continue
        invocation, stream, pid = (row.get(key) for key in
                                  ("_SYSTEMD_INVOCATION_ID", "_STREAM_ID", "_PID"))
        if (not isinstance(invocation, str) or not re.fullmatch(r"[0-9a-f]{32}", invocation)
                or invocation == "0" * 32
                or not isinstance(stream, str) or not re.fullmatch(r"[0-9a-f]{32}", stream)
                or not isinstance(pid, str) or not re.fullmatch(r"[1-9][0-9]*", pid)
                or int(pid) <= 1):
            refuse("missing or malformed trusted recovery stream identity")
        cursor, message = row.get("__CURSOR"), row.get("MESSAGE")
        if not isinstance(cursor, str) or not cursor or cursor in cursors or not isinstance(message, str):
            refuse("missing, duplicate or malformed recovery journal entry")
        cursors.add(cursor)
        streams.setdefault((invocation, stream, pid), []).append(message)

    matches = []
    for identity, messages in streams.items():
        try:
            receipt = json.loads("\n".join(messages), object_pairs_hook=unique_fields)
        except (ValueError, TypeError):
            # Other invocations may report an earlier pending operation or
            # an actual refusal. They cannot supply parts of this receipt.
            continue
        if not isinstance(receipt, dict) or receipt.get("operation_id") != expected:
            continue
        if receipt.get("phase") != "trial_cleared":
            continue
        if (type(receipt.get("revision")) is int and receipt["revision"] == 5
                and receipt.get("experiment_only") is True
                and receipt.get("recovery_verified") is True
                and receipt.get("guard_scheduled") is False
                and receipt.get("activation_ready") is False
                and receipt.get("vpn_verified") is False
                and "error" not in receipt and "ok" not in receipt):
            matches.append(identity)
        else:
            refuse("conflicting completed receipt for expected operation")
    if len(matches) != 1:
        refuse("missing or ambiguous exact-operation successful finalization receipt")
    identity = matches[0]
    if sum(key[0] == identity[0] for key in streams) != 1:
        refuse("conflicting streams in successful recovery invocation")
    print(identity[0])
except (OSError, UnicodeError, ValueError, TypeError) as error:
    print("Host QA assertion failed: recovery receipt: " + str(error), file=sys.stderr)
    sys.exit(1)
PYRECOVERYRECEIPT
    ;;
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
    nonempty_seen=no
    for trace_file do
      [ -f "$trace_file" ] && [ ! -L "$trace_file" ] &&
        [ -r "$trace_file" ] ||
        fail "missing, unreadable or non-regular trace: $trace_file"
      # -ff may create an empty trace for a child that exits without any
      # selected syscalls. A single empty child is valid, but the full
      # invocation must contain at least one actual trace record.
      [ ! -s "$trace_file" ] || nonempty_seen=yes

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
    [ "$nonempty_seen" = yes ] ||
      fail "all process traces were empty for phase $phase"
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
    fail 'usage: host-qa-assertions.sh trace DIRECTORY PHASE | network | recovery-receipt JSONL_FILE OPERATION_ID'
    ;;
esac
