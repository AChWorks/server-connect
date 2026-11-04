#!/usr/bin/env bash
# Real-kernel proof: untracked hosted TCP reply sockets may inherit a
# SYN mark only when tcp_fwmark_accept is enabled in the same netns.
# The root host's routing/firewall/sysctl is NEVER modified by this test.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[[ $EUID -eq 0 ]] || { echo 'NOT_RUN: root is required' >&2; exit 2; }
command -v unshare >/dev/null && command -v nft >/dev/null && command -v ip >/dev/null || {
  echo 'NOT_RUN: unshare/ip/nft not installed' >&2; exit 2;
}
unshare -n /bin/bash <<'GUEST'
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[[ "$(readlink /proc/1/ns/net)" != "$(readlink /proc/self/ns/net)" ]] || {
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
python3 - 28888 0 <<'PY'
import socket,threading,sys
port=int(sys.argv[1]); expected=int(sys.argv[2]);SO_MARK=36
server=socket.socket();server.settimeout(4);server.bind(('127.0.0.1',port));server.listen(1)
def client():
 c=socket.socket();c.settimeout(4);c.connect(('127.0.0.1',port));c.sendall(b'hi');assert c.recv(2)==b'ok';c.close()
worker=threading.Thread(target=client);worker.start()
conn,_=server.accept();mark=conn.getsockopt(socket.SOL_SOCKET,SO_MARK)
assert mark==expected, f'negative control inherited unexpected mark {mark:#x}'
assert conn.recv(2)==b'hi';conn.sendall(b'ok');conn.close();server.close();worker.join()
print('NOTRACK_MARK_DISABLED_NEGATIVE_CONTROL=PASS')
PY
sysctl -q -w net.ipv4.tcp_fwmark_accept=1
python3 - 28889 5505024 <<'PY'
import socket,threading,sys
port=int(sys.argv[1]); expected=int(sys.argv[2]);SO_MARK=36
server=socket.socket();server.settimeout(4);server.bind(('127.0.0.1',port));server.listen(1)
def client():
 c=socket.socket();c.settimeout(4);c.connect(('127.0.0.1',port));c.sendall(b'hi');assert c.recv(2)==b'ok';c.close()
worker=threading.Thread(target=client);worker.start()
conn,_=server.accept();mark=conn.getsockopt(socket.SOL_SOCKET,SO_MARK)
assert mark==expected, f'positive control failed to inherit bypass mark {mark:#x}'
assert conn.recv(2)==b'hi';conn.sendall(b'ok');conn.close();server.close();worker.join()
print('NOTRACK_ACCEPTED_SOCKET_BYPASS_MARK=PASS')
PY
nft -j list chain inet scfmarkqa output_witness | python3 -c '
import json,sys
rules=[x["rule"] for x in json.load(sys.stdin)["nftables"] if "rule" in x]
assert len(rules)==1
assert sum(e["counter"]["packets"] for r in rules for e in r["expr"] if "counter" in e)>0
print("NOTRACK_MARKED_OUTPUT_ON_WIRE=PASS")'
GUEST
