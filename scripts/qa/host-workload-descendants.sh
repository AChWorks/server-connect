#!/bin/sh
# Disposable Debian 13 installed-host QA only. Observe a genuine Python
# installer-like parent -> child process/socket without changing kernel routes.
set -eu
umask 077
scratch=$(mktemp -d /run/sc-qa-descendants.XXXXXXXX)
parent=
unrelated=
child=
cleanup() {
  test -z "$child" || kill "$child" 2>/dev/null || :
  test -z "$parent" || kill "$parent" 2>/dev/null || :
  test -z "$unrelated" || kill "$unrelated" 2>/dev/null || :
  test -z "$parent" || wait "$parent" 2>/dev/null || :
  test -z "$unrelated" || wait "$unrelated" 2>/dev/null || :
  rm -rf -- "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A child creates a real loopback TCP connection and retains its own socket
# descriptors. Only this parent created it; an unrelated sibling is launched
# separately to discriminate ancestry. Neither worker uses a VPN or proxy.
python3 -u - "$scratch" >"$scratch/parent.log" 2>&1 <<'PYWORKER' &
import os
import subprocess
import sys

directory = sys.argv[1]
child_source = r"""
import os
import socket
import sys
import time
directory = sys.argv[1]
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(listener.getsockname())
peer, _ = listener.accept()
with open(directory + "/child.ready", "w", encoding="utf-8") as output:
    output.write(str(os.getpid()) + " " + str(listener.getsockname()[1]) + "\n")
time.sleep(40)
"""
child = subprocess.Popen([sys.executable, "-u", "-c", child_source, directory])
with open(directory + "/parent.ready", "w", encoding="utf-8") as output:
    output.write(str(os.getpid()) + " " + str(child.pid) + "\n")
child.wait()
PYWORKER
parent=$!
sleep 30 &
unrelated=$!
ready=no
i=0
while test "$i" -lt 100; do
  if test -f "$scratch/parent.ready" && test -f "$scratch/child.ready"; then
    ready=yes
    break
  fi
  kill -0 "$parent" 2>/dev/null || break
  i=$((i+1))
  sleep 0.1
done
if test "$ready" != yes; then
  echo 'Guest descendant worker did not become ready' >&2
  cat "$scratch/parent.log" >&2 || :
  exit 1
fi
read worker_pid child_from_parent <"$scratch/parent.ready"
read child listen_port <"$scratch/child.ready"
test "$worker_pid" = "$parent"
test "$child_from_parent" = "$child"
/usr/local/bin/server-connect --json workload-observe \
  --pid "$parent" --descendants --sockets >"$scratch/evidence.json"
python3 - "$scratch/evidence.json" "$parent" "$child" "$listen_port" "$unrelated" <<'PYASSERT'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert report["ok"], report
data = report["data"]
assert data["read_only"] and data["descendant_survey"] == "two_non_atomic_procfs_censuses", data
assert not any(data[key] for key in (
    "snapshot_atomic", "attribution_verified", "descendants_covered",
    "traffic_path_verified", "activation_ready"
)), data
assert data["process"]["pid"] == int(sys.argv[2]), data
children = data["observed_descendants"]
assert len(children) == 1, children
only_child = children[0]
assert only_child["process"]["pid"] == int(sys.argv[3]), only_child
assert only_child["process"]["parent_pid"] == int(sys.argv[2]), only_child
assert only_child["process"]["pid"] != int(sys.argv[5]), only_child
sockets = only_child["sockets"]
assert sockets["read_only"] and not any(sockets[key] for key in (
    "snapshot_atomic", "job_owner_verified", "descendants_covered",
    "traffic_path_verified", "activation_ready"
)), sockets
assert any(
    item["protocol"] == "tcp4" and
    item["remote"] == "127.0.0.1:" + sys.argv[4] and
    item["state"] == "01"
    for item in sockets["observed_tcp_udp_sockets"]
), sockets
PYASSERT
echo 'INSTALLED_WORKLOAD_DESCENDANT_SOCKET_EVIDENCE=PASS (live parent/child TCP, unrelated sibling excluded; no job or routing proof)'
