#!/usr/bin/env bash
# Real-kernel proof: untracked hosted TCP reply sockets may inherit a
# SYN mark only when tcp_fwmark_accept is enabled in the same netns.
# The root host's routing/firewall/sysctl is NEVER modified by this test.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE
[[ $# == 0 && $EUID -eq 0 ]] || { echo 'NOT_RUN: root is required' >&2; exit 2; }
for name in unshare ip nft python3 sysctl readlink; do
  command -v "$name" >/dev/null || { echo "NOT_RUN: missing $name" >&2; exit 2; }
done
unshare -n /bin/bash <<'GUEST'
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
root_ns=$(readlink /proc/1/ns/net) || { echo 'REFUSED: root namespace identity unavailable' >&2; exit 3; }
test_ns=$(readlink /proc/self/ns/net) || { echo 'REFUSED: test namespace identity unavailable' >&2; exit 3; }
[[ $root_ns =~ ^net:\[[0-9]+\]$ && $test_ns =~ ^net:\[[0-9]+\]$ && "$root_ns" != "$test_ns" ]] || {
  echo 'REFUSED: test namespace is not independent of root' >&2; exit 3;
}
ip link set lo up
nft add table inet scfmarkqa
nft 'add chain inet scfmarkqa preraw { type filter hook prerouting priority -310; policy accept; }'
nft 'add chain inet scfmarkqa untracked_in { type filter hook prerouting priority -300; policy accept; }'
nft 'add chain inet scfmarkqa untracked_out { type filter hook output priority -300; policy accept; }'
nft 'add chain inet scfmarkqa output_witness { type filter hook output priority -150; policy accept; }'
nft 'add rule inet scfmarkqa preraw iifname "lo" tcp dport { 28888, 28889 } tcp flags & (syn | ack) == syn meta mark set 0x00540000'
nft 'add rule inet scfmarkqa untracked_in tcp dport { 28888, 28889 } notrack'
nft 'add rule inet scfmarkqa untracked_out tcp sport { 28888, 28889 } notrack'
nft 'add rule inet scfmarkqa output_witness tcp sport 28889 meta mark 0x00540000 counter'
sysctl -q -w net.ipv4.tcp_fwmark_accept=0
python3 -I -S -B - 28888 0 <<'PY'
import socket
import sys

port, expected = int(sys.argv[1]), int(sys.argv[2])
# The kernel completes connect against the listening socket before accept.
# Keep both ends on the main thread so every assertion is a process failure.
with socket.socket() as server, socket.socket() as client:
    server.settimeout(4)
    server.bind(('127.0.0.1', port))
    server.listen(1)
    client.settimeout(4)
    client.connect(('127.0.0.1', port))
    conn, _ = server.accept()
    with conn:
        conn.settimeout(4)
        mark = conn.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
        assert mark == expected, f'negative control inherited unexpected mark {mark:#x}'
        client.sendall(b'hi')
        assert conn.recv(2) == b'hi'
        conn.sendall(b'ok')
        assert client.recv(2) == b'ok'
print('NOTRACK_MARK_DISABLED_NEGATIVE_CONTROL=PASS')
PY
sysctl -q -w net.ipv4.tcp_fwmark_accept=1
python3 -I -S -B - 28889 5505024 <<'PY'
import socket
import sys

port, expected = int(sys.argv[1]), int(sys.argv[2])
# The kernel completes connect against the listening socket before accept.
# Keep both ends on the main thread so every assertion is a process failure.
with socket.socket() as server, socket.socket() as client:
    server.settimeout(4)
    server.bind(('127.0.0.1', port))
    server.listen(1)
    client.settimeout(4)
    client.connect(('127.0.0.1', port))
    conn, _ = server.accept()
    with conn:
        conn.settimeout(4)
        mark = conn.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
        assert mark == expected, f'positive control failed to inherit bypass mark {mark:#x}'
        client.sendall(b'hi')
        assert conn.recv(2) == b'hi'
        conn.sendall(b'ok')
        assert client.recv(2) == b'ok'
print('NOTRACK_ACCEPTED_SOCKET_BYPASS_MARK=PASS')
PY
nft -j list chain inet scfmarkqa output_witness | python3 -I -S -B -c '
import json,sys
rules=[x["rule"] for x in json.load(sys.stdin)["nftables"] if "rule" in x]
assert len(rules)==1
assert sum(e["counter"]["packets"] for r in rules for e in r["expr"] if "counter" in e)>0
print("NOTRACK_MARKED_OUTPUT_ON_WIRE=PASS")'
GUEST
