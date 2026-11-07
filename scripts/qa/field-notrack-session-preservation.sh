#!/usr/bin/env bash
# Read-only root host: all nft, sysctl and socket changes occur in a fresh
# Linux network namespace. Tests existing and new NOTRACK hosted TCP replies.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE
[[ $# == 0 && $EUID == 0 ]] || { echo 'NOT_RUN: isolated kernel proof needs root with no args' >&2; exit 2; }
for cmd in unshare nft ip python3; do command -v "$cmd" >/dev/null || { echo 'NOT_RUN: missing tool' >&2; exit 2; }; done
unshare -n /usr/bin/python3 -I -S -B - <<'PY'
import json
import os
import socket
import struct
import subprocess
import sys

# A shell namespace flag is never authority to alter host networking. Check
# actual kernel namespace identity, independently of the operator arguments.
assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino, 'root network namespace refused'
assert os.geteuid() == 0

def run(*args, input=None):
    return subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=8, check=True).stdout

def nft(commands):
    run('/usr/sbin/nft', '-f', '-', input=commands)

def count(chain, predicate=lambda r: True):
    raw = json.loads(run('/usr/sbin/nft', '-j', 'list', 'chain', 'inet', 'sc_notrack_qa', chain))
    return sum(int(e['counter']['packets']) for x in raw['nftables'] if 'rule' in x
               and predicate(x['rule']) for e in x['rule'].get('expr', []) if 'counter' in e)

run('/usr/sbin/ip', 'link', 'set', 'lo', 'up')
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_fwmark_accept=0')
nft('''
add table inet sc_notrack_qa
add chain inet sc_notrack_qa mark_syn { type filter hook prerouting priority -310; policy accept; }
add chain inet sc_notrack_qa untracked_in { type filter hook prerouting priority -300; policy accept; }
add chain inet sc_notrack_qa untracked_out { type filter hook output priority -300; policy accept; }
add chain inet sc_notrack_qa old_session { type route hook output priority -175; policy accept; }
add chain inet sc_notrack_qa capture { type route hook output priority -150; policy accept; }
add chain inet sc_notrack_qa guard { type filter hook postrouting priority 0; policy accept; }
add rule inet sc_notrack_qa untracked_in iifname "lo" tcp dport 28988 notrack
add rule inet sc_notrack_qa untracked_out oifname "lo" tcp sport 28988 notrack
''')
# Existing connection accepted before SYN marking / sysctl activation.
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.settimeout(3)
server.bind(('127.0.0.1', 28988))
server.listen(4)

def accept_one():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(1.2)
    client.connect(('127.0.0.1', 28988))
    accepted, peer = server.accept()
    accepted.settimeout(1.2)
    return client, accepted, peer[1]

def exchange(client, accepted, value):
    accepted.sendall(value)
    assert client.recv(len(value)) == value

old_client, old_accepted, old_peer_port = accept_one()
assert old_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
# Only the exact known preexisting 4-tuple is exempted. A source-port-only
# bypass is forbidden: it would let arbitrary new host-origin traffic Direct.
nft('''
add rule inet sc_notrack_qa old_session ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 28988 tcp dport %d counter meta mark set (meta mark & 0xff00ffff) | 0x00540000
add rule inet sc_notrack_qa capture oifname "lo" tcp sport 28988 meta mark & 0x00ff0000 != 0x00540000 counter meta mark set (meta mark & 0xff00ffff) | 0x00530000
add rule inet sc_notrack_qa guard meta iif 0 tcp sport 28988 meta mark & 0x00ff0000 == 0x00530000 counter drop
''' % old_peer_port)
exchange(old_client, old_accepted, b'old')
assert count('old_session') > 0 and count('capture') == 0
print('NOTRACK_EXISTING_EXACT_SOCKET_REPLY=PASS', flush=True)
# Correctly ordered new inbound SYN marking, BEFORE foreign raw NOTRACK.
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_fwmark_accept=1')
nft('''
add rule inet sc_notrack_qa mark_syn iifname "lo" tcp dport 28988 tcp flags & (syn | ack) == syn meta mark set 0x00540000
''')
new_client, new_accepted, new_peer_port = accept_one()
assert new_peer_port != old_peer_port
assert new_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0x00540000
exchange(new_client, new_accepted, b'new')
assert count('capture') == 0
print('NOTRACK_NEW_ACCEPTED_SOCKET_REPLY=PASS', flush=True)
# Negative: a third accepted socket without the SYN mark must never inherit
# another connection's exception merely because the service port matches.
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_fwmark_accept=0')
# An unprotected initial SYN/ACK would itself be dropped by the final-egress
# guard. Temporarily remove *only our test-owned* capture and guard to admit
# the negative-control socket, then restore both before its first payload.
nft('flush chain inet sc_notrack_qa capture\nflush chain inet sc_notrack_qa guard')
other_client, other_accepted, other_peer_port = accept_one()
assert other_peer_port not in (old_peer_port, new_peer_port)
assert other_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
nft('''
add rule inet sc_notrack_qa capture oifname "lo" tcp sport 28988 meta mark & 0x00ff0000 != 0x00540000 counter meta mark set (meta mark & 0xff00ffff) | 0x00530000
add rule inet sc_notrack_qa guard meta iif 0 tcp sport 28988 meta mark & 0x00ff0000 == 0x00530000 counter drop
''')
other_accepted.sendall(b'X')
try:
    received = other_client.recv(1)
except socket.timeout:
    received = None
assert received is None, 'unmarked hosted response delivered bytes or EOF past guard'
assert count('capture') > 0 and count('guard') > 0
print('NOTRACK_UNPROTECTED_REPLY_FAIL_CLOSED=PASS', flush=True)
# An already-marked accepted socket continues to receive its replies.
exchange(new_client, new_accepted, b'ok')
# Negative: even an exact 4-tuple cannot identify the ORIGINAL socket
# generation. Close the old session with RST, bind a new connection to the
# same client port and demonstrate that the stale tuple rule still bypasses
# capture. This must stay a failure witness, NEVER an Apply workaround.
linger_rst = struct.pack('ii', 1, 0)
old_accepted.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger_rst)
old_client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger_rst)
old_accepted.close()
old_client.close()
reused_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
reused_client.settimeout(1.2)
reused_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
reused_client.bind(('127.0.0.1', old_peer_port))
reused_client.connect(('127.0.0.1', 28988))
reused_accepted, reused_peer = server.accept()
reused_accepted.settimeout(1.2)
assert reused_peer[1] == old_peer_port
assert reused_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
prior_old_rule_packets = count('old_session')
exchange(reused_client, reused_accepted, b'reused')
assert count('old_session') > prior_old_rule_packets, 'stale tuple did not match reused socket'
print('NOTRACK_STALE_SOCKET_TUPLE_REUSE_BYPASS=REPRODUCED', flush=True)
for conn in (reused_client, reused_accepted, new_client, new_accepted, other_client, other_accepted, server):
    conn.close()
print('NOTRACK_TEST_NETNS_EXIT_WITHOUT_HOST_MUTATION=PASS', flush=True)
PY
