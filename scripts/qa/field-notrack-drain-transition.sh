#!/usr/bin/env bash
# Only a disposable network namespace is modified. This is a feasibility
# witness for draining preexisting unmarked hosted replies before an otherwise
# unsafe general-host Apply. It is NOT a product mutator or activation gate.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE
[[ $# == 0 && $EUID == 0 ]] || { echo 'NOT_RUN: root with no arguments required' >&2; exit 2; }
for name in unshare ip nft python3; do
  command -v "$name" >/dev/null || { echo "NOT_RUN: missing $name" >&2; exit 2; }
done
unshare -n /usr/bin/python3 -I -S -B - <<'PY'
import json
import os
import socket
import struct
import subprocess

def tcp_stat(name):
    lines = open("/proc/net/netstat").read().splitlines()
    for i, line in enumerate(lines[:-1]):
        if line.startswith("TcpExt:") and name in line.split():
            return int(dict(zip(line.split()[1:], lines[i+1].split()[1:]))[name])
    raise AssertionError("missing kernel TCP counter: " + name)

assert os.geteuid() == 0, 'must be root in disposable namespace'
assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino, 'root namespace refused'

def run(*args, input=None):
    p = subprocess.run(args, text=True, input=input, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=8, check=True)
    return p.stdout

def nft(text):
    run('/usr/sbin/nft', '-f', '-', input=text)

def packets(chain):
    data = json.loads(run('/usr/sbin/nft', '-j', 'list', 'chain', 'inet', 'sc_drain_qa', chain))
    return sum(int(expr['counter']['packets']) for item in data['nftables']
               for rule in [item.get('rule', {})]
               for expr in rule.get('expr', []) if 'counter' in expr)


# INET_DIAG_MARK is a kernel response attribute (15) available only to
# CAP_NET_ADMIN. Its socket cookie + inode distinguish generations. A
# missing mark, malformed netlink message or incomplete dump is not green.
def kernel_socket_marks():
    diag = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4)  # NETLINK_SOCK_DIAG
    diag.settimeout(2)
    diag.bind((0, 0))
    request = bytearray(72)  # nlmsghdr + inet_diag_req_v2
    struct.pack_into('=IHHII', request, 0, 72, 20, 0x301, 1, 0)
    struct.pack_into('=BBBBI', request, 16, socket.AF_INET, socket.IPPROTO_TCP,
                     0, 0, sum(1 << x for x in (1, 2, 3, 4, 5, 6, 8, 9, 11, 12)))
    struct.pack_into('=II', request, 64, 0xffffffff, 0xffffffff)
    diag.sendto(request, (0, 0))
    rows = {}
    try:
        for _ in range(32):
            buffer, _, flags, addr = diag.recvmsg(32768)
            assert not flags & socket.MSG_TRUNC and addr[0] == 0
            offset = 0
            while offset < len(buffer):
                assert len(buffer) - offset >= 16
                nlen, kind, flags, seq, pid = struct.unpack_from('=IHHII', buffer, offset)
                assert nlen >= 16 and offset + nlen <= len(buffer) and seq == 1 and pid in (0, diag.getsockname()[0])
                # NLM_F_DUMP_INTR may occur on any data message or DONE.
                # A dump with missing sockets cannot authorize a drain.
                assert not flags & 0x10, 'interrupted inet_diag dump'
                raw = buffer[offset + 16:offset + nlen]
                if kind == 3:  # NLMSG_DONE
                    assert len(raw) >= 4 and struct.unpack_from('=I', raw)[0] == 0
                    assert offset + ((nlen + 3) & ~3) == len(buffer), 'records after inet_diag DONE'
                    return rows
                assert kind == 20 and len(raw) >= 72 and raw[0] == socket.AF_INET
                local, peer = struct.unpack_from('!HH', raw, 4)
                if local == 28993:
                    cookie_lo, cookie_hi = struct.unpack_from('=II', raw, 44)
                    inode = struct.unpack_from('=I', raw, 68)[0]
                    cookie = cookie_lo | cookie_hi << 32
                    assert inode > 0 and cookie not in (0, 0xffffffffffffffff)
                    attr, mark = 72, None
                    while attr < len(raw):
                        assert len(raw) - attr >= 4
                        alen, typ = struct.unpack_from('=HH', raw, attr)
                        assert 4 <= alen <= len(raw) - attr
                        if typ == 15:
                            assert alen == 8 and mark is None
                            mark = struct.unpack_from('=I', raw, attr + 4)[0]
                        attr += (alen + 3) & ~3
                    assert attr == len(raw) and mark is not None
                    assert peer not in rows, 'duplicate socket tuple in inet_diag dump'
                    rows[peer] = (inode, cookie, mark)
                offset += (nlen + 3) & ~3
            assert offset == len(buffer)
    finally:
        diag.close()
    raise AssertionError('kernel TCP dump did not complete')

# Docker may disable IPv6 in its enclosing fixture. Enable it ONLY inside
# this independently checked namespace before testing the IPv6 cookie path.
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=0',
    'net.ipv6.conf.default.disable_ipv6=0', 'net.ipv6.conf.lo.disable_ipv6=0')
run('/usr/sbin/ip', 'link', 'set', 'lo', 'up')
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_fwmark_accept=0')
nft('''
add table inet sc_drain_qa
add chain inet sc_drain_qa syn { type filter hook prerouting priority -310; policy accept; }
add chain inet sc_drain_qa foreign_in { type filter hook prerouting priority -300; policy accept; }
add chain inet sc_drain_qa foreign_out { type filter hook output priority -300; policy accept; }
add chain inet sc_drain_qa capture { type route hook output priority -150; policy accept; }
add chain inet sc_drain_qa guard { type filter hook postrouting priority 0; policy accept; }
add rule inet sc_drain_qa foreign_in iifname "lo" tcp dport 28993 notrack
add rule inet sc_drain_qa foreign_out oifname "lo" tcp sport 28993 notrack
''')
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.settimeout(2)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 28993))
server.listen(8)

def new_session(port=None):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(1.2)
    if port is not None:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.bind(('127.0.0.1', port))
    client.connect(('127.0.0.1', 28993))
    accepted, remote = server.accept()
    accepted.settimeout(1.2)
    return client, accepted, remote[1]

def exchange(client, accepted, content):
    accepted.sendall(content)
    assert client.recv(len(content)) == content, 'hosted response was lost'

# Old accepted sockets cannot inherit a SYN mark retroactively.
old_client, old_accepted, old_client_port = new_session()
assert old_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_fwmark_accept=1')
nft('''
add rule inet sc_drain_qa syn iifname "lo" tcp dport 28993 meta mark set (meta mark & 0xff00ffff) | 0x00540000
''')
assert old_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
exchange(old_client, old_accepted, b'old-before-apply')
print('DRAIN_PREEXISTING_UNMARKED_REPLY_STILL_WORKS=PASS', flush=True)

# Mark every incoming TCP packet on the scoped service, including the final
# cookie ACK. A SYN-only marker loses inheritance with tcp_syncookies=2.
# This is an ingress mark, NEVER a source-port-based OUTPUT exemption.
# All newly accepted sockets have the bypass mark in their socket identity,
# independent of their future four-tuple and service source port.
new_client, new_accepted, _ = new_session()
assert new_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0x00540000
exchange(new_client, new_accepted, b'new-before-apply')
marks = kernel_socket_marks()
assert marks[old_client_port][2] == 0, 'old accepted socket was retro-marked'
assert marks[new_accepted.getpeername()[1]][2] == 0x00540000, 'new socket missing inet_diag fwmark'
assert marks[old_client_port][:2] != marks[new_accepted.getpeername()[1]][:2]
print('DRAIN_KERNEL_GENERATION_AND_SOCKET_MARK_VERIFIED=PASS', flush=True)
print('DRAIN_NEW_ACCEPTED_SOCKET_INHERITED_BYPASS=PASS', flush=True)

# Kernel documentation: a listener with its own SO_MARK is NOT overridden by
# tcp_fwmark_accept. The real product must detect/refuse that foreign owner,
# never assume every post-transition connection inherited our bypass mark.
nft('''
add rule inet sc_drain_qa syn iifname "lo" tcp dport 28994 meta mark set 0x00540000
add rule inet sc_drain_qa foreign_in iifname "lo" tcp dport 28994 notrack
add rule inet sc_drain_qa foreign_out oifname "lo" tcp sport 28994 notrack
''')
foreign_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
foreign_listener.settimeout(1.2)
foreign_listener.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x00220000)
foreign_listener.bind(('127.0.0.1', 28994))
foreign_listener.listen(1)
foreign_client = socket.create_connection(('127.0.0.1', 28994), 1.2)
foreign_accepted, _ = foreign_listener.accept()
assert foreign_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0x00220000, 'foreign listener mark was unexpectedly overwritten'
foreign_accepted.close()
foreign_client.close()
foreign_listener.close()
print('DRAIN_FOREIGN_MARKED_LISTENER_MUST_BE_REFUSED=PASS', flush=True)

# Refuse capture while even one old generation remains unmarked. The only
# legitimate migration is to wait for it to close; never exempt its 4-tuple.
def unmarked_accepted(connections):
    return [s for s in connections if s.fileno() >= 0
            and s.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) != 0x00540000]
assert unmarked_accepted([old_accepted, new_accepted]) == [old_accepted]
print('DRAIN_EARLY_CAPTURE_ADMISSION_REFUSED=PASS', flush=True)
linger_rst = struct.pack('ii', 1, 0)
old_accepted.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger_rst)
old_client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger_rst)
old_accepted.close()
old_client.close()
assert unmarked_accepted([old_accepted, new_accepted]) == []
assert kernel_socket_marks() and all((mark & 0x00ff0000) == 0x00540000
                                     for _, _, mark in kernel_socket_marks().values())
print('DRAIN_OLD_GENERATION_QUIESCED_BEFORE_CAPTURE=PASS', flush=True)

# Capture and final-egress guard are created only AFTER old socket drainage.
# No static 4-tuple or service-port bypass exception exists.
nft('''
add rule inet sc_drain_qa capture oifname "lo" tcp sport 28993 meta mark & 0x00ff0000 != 0x00540000 counter meta mark set (meta mark & 0xff00ffff) | 0x00530000
add rule inet sc_drain_qa guard meta iif 0 tcp sport 28993 meta mark & 0x00ff0000 == 0x00530000 counter drop
''')
exchange(new_client, new_accepted, b'new-after-apply')
assert packets('capture') == 0 and packets('guard') == 0
# A replacement TCP connection reusing the exact old tuple has a NEW socket
# and inherits the correct mark, so no stale exception can be exploited.
reused_client, reused_accepted, reused_port = new_session(old_client_port)
assert reused_port == old_client_port
assert reused_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0x00540000
exchange(reused_client, reused_accepted, b'new-same-four-tuple')
assert packets('capture') == 0 and packets('guard') == 0
print('DRAIN_SOCKET_GENERATION_REUSE_PROTECTED=PASS', flush=True)

# SYN cookies reconstruct the request from the final ACK, not retained SYN
# state. Prove the production design requirement on the real kernel with
# cookies forced and independently counted, for IPv4 AND IPv6. A SYN-only
# marker is a counterexample; the corrected ingress rule covers cookie ACKs.
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_syncookies=2')
for family, address, label in ((socket.AF_INET, '127.0.0.1', 'IPV4'),
                               (socket.AF_INET6, '::1', 'IPV6')):
    for syn_only, port in ((True, 28995), (False, 28996)):
        flags = 'tcp flags & (syn | ack) == syn ' if syn_only else ''
        nft(f'''
add rule inet sc_drain_qa syn iifname "lo" tcp dport {port} {flags}meta mark set (meta mark & 0xff00ffff) | 0x00540000
add rule inet sc_drain_qa foreign_in iifname "lo" tcp dport {port} notrack
add rule inet sc_drain_qa foreign_out oifname "lo" tcp sport {port} notrack
''')
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.settimeout(2)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((address, port))
        listener.listen(8)
        sent, received = tcp_stat('SyncookiesSent'), tcp_stat('SyncookiesRecv')
        client = socket.socket(family, socket.SOCK_STREAM)
        client.settimeout(1.2)
        client.connect((address, port))
        accepted, _ = listener.accept()
        accepted.settimeout(1.2)
        assert tcp_stat('SyncookiesSent') > sent and tcp_stat('SyncookiesRecv') > received, 'not a cookie handshake'
        expected = 0 if syn_only else 0x00540000
        assert accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == expected, 'cookie mark evidence changed'
        # Positive baseline before capture distinguishes a real lost reply
        # from an unsupported address family, kernel cookie or dead listener.
        exchange(client, accepted, b'cookie-direct-control')
        chain = 'cookie_' + label.lower() + ('_syn' if syn_only else '_ack')
        nft(f'''
add chain inet sc_drain_qa {chain} {{ type filter hook postrouting priority 10; policy accept; }}
add rule inet sc_drain_qa {chain} meta iif 0 tcp sport {port} meta mark & 0x00ff0000 != 0x00540000 counter drop
''')
        if syn_only:
            accepted.sendall(b'cookie-unprotected-reply')
            try:
                leaked = client.recv(len(b'cookie-unprotected-reply'))
            except socket.timeout:
                leaked = None
            assert leaked is None and packets(chain) > 0, 'unprotected cookie reply delivered bytes or EOF, or guard did not drop'
            print('DRAIN_' + label + '_SYN_ONLY_COOKIE_REPLY_LOSS=REPRODUCED', flush=True)
        else:
            exchange(client, accepted, b'cookie-ack-protected-reply')
            assert packets(chain) == 0, 'cookie ACK protected socket hit guard'
            print('DRAIN_' + label + '_COOKIE_ACK_REPLY_PROTECTED=PASS', flush=True)
        # Remove only this fixture chain's rule after its observation. No
        # shared table is flushed and no root-namespace object exists here.
        nft('flush chain inet sc_drain_qa ' + chain)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        accepted.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        accepted.close()
        client.close()
        listener.close()

# The corrected main marker also retains generation safety for an accepted
# cookie socket while the original capture/guard are already active.
sent, received = tcp_stat('SyncookiesSent'), tcp_stat('SyncookiesRecv')
cookie_client, cookie_accepted, _ = new_session()
assert tcp_stat('SyncookiesSent') > sent and tcp_stat('SyncookiesRecv') > received
assert cookie_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0x00540000
exchange(cookie_client, cookie_accepted, b'cookie-after-capture')
assert packets('capture') == 0 and packets('guard') == 0
print('DRAIN_COOKIE_ACCEPTED_AFTER_CAPTURE=PASS', flush=True)
cookie_client.close()
cookie_accepted.close()

# The inbound marker also sees return packets for a host-origin socket
# deliberately bound to the hosted source port. Those packets MUST NOT
# retroactively grant its active socket a passive-server bypass mark.
# Positively control this connection without our capture, then restore the
# guard and prove its new outbound payload is dropped, not exempt by port.
nft('flush chain inet sc_drain_qa capture\nflush chain inet sc_drain_qa guard')
remote_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
remote_listener.settimeout(2)
remote_listener.bind(('127.0.0.3', 28997))
remote_listener.listen(1)
bound_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bound_client.settimeout(1.2)
bound_client.bind(('127.0.0.2', 28993))
bound_client.connect(remote_listener.getsockname())
remote_accepted, _ = remote_listener.accept()
remote_accepted.settimeout(1.2)
assert bound_client.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
bound_client.sendall(b'outbound-control')
assert remote_accepted.recv(len(b'outbound-control')) == b'outbound-control'
remote_accepted.sendall(b'reply-control')
assert bound_client.recv(len(b'reply-control')) == b'reply-control'
assert bound_client.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0, 'return packet granted active socket a bypass'
nft('''
add rule inet sc_drain_qa capture oifname "lo" tcp sport 28993 meta mark & 0x00ff0000 != 0x00540000 counter meta mark set (meta mark & 0xff00ffff) | 0x00530000
add rule inet sc_drain_qa guard meta iif 0 tcp sport 28993 meta mark & 0x00ff0000 == 0x00530000 counter drop
''')
bound_client.sendall(b'outbound-must-not-bypass')
try:
    leaked = remote_accepted.recv(len(b'outbound-must-not-bypass'))
except socket.timeout:
    leaked = None
assert leaked is None and packets('capture') > 0 and packets('guard') > 0, 'host-origin payload delivered bytes or EOF'
print('DRAIN_HOST_ORIGIN_SERVICE_SOURCE_PORT_FAILS_CLOSED=PASS', flush=True)
for item in (bound_client, remote_accepted, remote_listener):
    item.close()

# Negative: if sysctl drifts OFF, a newly accepted socket lacks a mark.
# Temporarily remove only test-owned guard while admitting that handshake;
# then restore capture and final guard before any protected payload.
run('/usr/sbin/sysctl', '-q', '-w', 'net.ipv4.tcp_fwmark_accept=0')
nft('flush chain inet sc_drain_qa capture\nflush chain inet sc_drain_qa guard')
bad_client, bad_accepted, _ = new_session()
assert bad_accepted.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
nft('''
add rule inet sc_drain_qa capture oifname "lo" tcp sport 28993 meta mark & 0x00ff0000 != 0x00540000 counter meta mark set (meta mark & 0xff00ffff) | 0x00530000
add rule inet sc_drain_qa guard meta iif 0 tcp sport 28993 meta mark & 0x00ff0000 == 0x00530000 counter drop
''')
bad_accepted.sendall(b'failclosed')
try:
    unexpected = bad_client.recv(len(b'failclosed'))
except socket.timeout:
    unexpected = None
assert unexpected is None, 'missing inherited mark delivered bytes or EOF around guard'
assert packets('capture') > 0 and packets('guard') > 0
print('DRAIN_SYSCTL_DRIFT_FAILS_CLOSED=PASS', flush=True)
for s in (new_client, new_accepted, reused_client, reused_accepted,
          bad_client, bad_accepted, server):
    s.close()
PY
echo 'DRAIN_NAMESPACE_DESTROYED_WITHOUT_ROOT_HOST_MUTATION=PASS'
