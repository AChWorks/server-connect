#!/bin/sh
# Transitional compatibility fixture: the trusted-base pull_request_target
# workflow still syntax-checks this historical path until its updated version
# reaches main. The former procfs/descendant census is deliberately retired.
# Do not revive process-level routing or privileged host mutations.
set -eu
umask 077

result=/run/sc-qa-retired-workload.json
trap 'rm -f "$result"' EXIT INT TERM

if /usr/local/bin/server-connect --json workload-observe --pid 2 --descendants --sockets >"$result"; then
  echo 'FAIL: retired workload-observe command remains available' >&2
  exit 1
fi

python3 - "$result" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    response = json.load(source)
assert response.get("ok") is False, response
assert response.get("error", {}).get("code") == "unknown_command", response
PY

echo 'INSTALLED_RETIRED_WORKLOAD_COMMAND=PASS (unknown command, no per-job routing)'
