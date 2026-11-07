#!/usr/bin/env python3
"""Unprivileged regression for the root-host field QA's two shell hazards."""
import ast
import hashlib
import ipaddress
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
PILOT = ROOT / 'scripts/qa/field-root-selected-tun.sh'
SOCKET = ROOT / 'scripts/qa/field-notrack-inherited-mark.sh'
SESSION = ROOT / 'scripts/qa/field-notrack-session-preservation.sh'
DRAIN = ROOT / 'scripts/qa/field-notrack-drain-transition.sh'
for path in (PILOT, SOCKET, SESSION, DRAIN):
    subprocess.run(['bash', '-n', str(path)], check=True)
source = PILOT.read_text()
necessary = (
    '[[ "$(readlink /proc/1/ns/net)" == "$(readlink /proc/self/ns/net)" ]]',
    '[[ $(nft -a list table inet "$owner" | grep -Fc "table inet $owner {") == 1 ]]',
    '[[ "$observed" == "$(cat "$work/nft-receipt")" ]]',
    '[[ "$current_handle" == "$recorded" ]]',
    'systemd-run --quiet --collect --unit="$watch" --on-active=300s',
    'ROOT_CORE_LOSS_NO_DIRECT_FALLBACK=PASS',
)
for clause in necessary:
    assert clause in source, f'missing guarded QA invariant: {clause}'
assert 'nft -a list table inet "$owner" | grep -Fq' not in source
print('FIELD_ROOT_STATIC_GUARD_INVARIANTS=PASS')
# Guard-first is a kernel safety property: the root-host field QA must
# never publish its first live RPDB selector before the nft leak guard and
# its ownership receipt are independently durable/observed.
guard_create = source.index('nft -f "$work/nft.txt"')
guard_receipt = source.index('sync -f "$work/nft-handle" "$work/nft-receipt" "$work"')
guard_observation = source.index('nft -j list chain inet "$owner" guard | python3')
route_selector = source.index('ip -4 rule add priority "$priority" fwmark "$mark"/"$mask" table "$table"')
assert source.index('systemd-run --quiet --collect --unit="$watch"') < source.index('ip -4 route add default dev "$tun" table "$table"')
assert guard_create < guard_receipt < guard_observation < route_selector
assert 'ROOT_GUARD_FIRST_RPDB=PASS' in source
assert source.index('ip -4 route add unreachable default table "$table" metric 100') < guard_create
print('FIELD_ROOT_GUARD_FIRST_ACTIVATION_ORDER=PASS')
# Real Bash pattern matching: a namespace string contains literal brackets.
check = subprocess.run(
    ['bash', '-c', 'set -eu; ns="net:[4026531840]"; '
     '[[ "$ns" == "$ns" ]] && echo PASS'],
    capture_output=True, text=True, check=True)
assert check.stdout.strip() == 'PASS'
print('FIELD_ROOT_NAMESPACE_LITERAL_IDENTITY=PASS')
# grep -q with pipefail can stop the producer via SIGPIPE after finding an
# early match. A full-stream count preserves both consumers' exit status.
producer = 'python3 -c \'print("table inet scfhr_test {");print("x"*100000)\''
command = 'set -o pipefail; ' + producer + ' | grep -Fc "table inet scfhr_test {"'
check = subprocess.run(['bash', '-c', command], capture_output=True, text=True, check=True)
assert check.stdout.strip() == '1'
print('FIELD_ROOT_PIPEFAIL_OWNERSHIP_CHECK=PASS')

# This proof must never use or mutate the root host network namespace.
proof = SESSION.read_text()
for required in (
    'unshare -n /usr/bin/python3 -B -',
    "assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino",
    'NOTRACK_EXISTING_EXACT_SOCKET_REPLY=PASS',
    'NOTRACK_NEW_ACCEPTED_SOCKET_REPLY=PASS',
    'NOTRACK_UNPROTECTED_REPLY_FAIL_CLOSED=PASS',
    'NOTRACK_STALE_SOCKET_TUPLE_REUSE_BYPASS=REPRODUCED',
):
    assert required in proof, f'isolated NOTRACK QA invariant missing: {required}'
print('FIELD_NOTRACK_SESSION_ISOLATION_GUARD=PASS')

# A generation-aware drain is only a feasibility witness until a durable
# product guard owns the staged sysctl/rule change and real socket inspection.
drain = DRAIN.read_text()
# bash -n does not parse the actual Python executed after unshare.
assert drain.count("<<'PY'\n") == 1
ast.parse(drain.split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0])
assert drain.index("unshare -n /usr/bin/python3 -B -") < drain.index("nft('''")
for required in (
    "assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino",
    "INET_DIAG_MARK",
    "DRAIN_PREEXISTING_UNMARKED_REPLY_STILL_WORKS=PASS",
    "DRAIN_KERNEL_GENERATION_AND_SOCKET_MARK_VERIFIED=PASS",
    "DRAIN_NEW_ACCEPTED_SOCKET_INHERITED_BYPASS=PASS",
    "DRAIN_FOREIGN_MARKED_LISTENER_MUST_BE_REFUSED=PASS",
    "DRAIN_EARLY_CAPTURE_ADMISSION_REFUSED=PASS",
    "DRAIN_OLD_GENERATION_QUIESCED_BEFORE_CAPTURE=PASS",
    "DRAIN_SOCKET_GENERATION_REUSE_PROTECTED=PASS",
    "DRAIN_COOKIE_ACCEPTED_AFTER_CAPTURE=PASS",
    "net.ipv4.tcp_syncookies=2",
    "tcp_stat('SyncookiesSent') > sent and tcp_stat('SyncookiesRecv') > received",
    "DRAIN_HOST_ORIGIN_SERVICE_SOURCE_PORT_FAILS_CLOSED=PASS",
    "DRAIN_SYSCTL_DRIFT_FAILS_CLOSED=PASS",
    "DRAIN_NAMESPACE_DESTROYED_WITHOUT_ROOT_HOST_MUTATION=PASS",
):
    assert required in drain, f'isolated staged-drain QA invariant missing: {required}'
assert 'old_session' not in drain and 'flush ruleset' not in drain
print('FIELD_NOTRACK_DRAIN_INDEPENDENT_NAMESPACE_GUARD=PASS')

# The optional real Iranian Direct witness is explicitly bounded to the
# source-pinned *estimate* and does not widen the foreign VPN /32 capture.
snapshot_file = ROOT / 'internal/sc/data/iran-dbip-lite-2026-10.json'
raw_snapshot = snapshot_file.read_bytes()
assert hashlib.sha256(raw_snapshot).hexdigest() == 'c1d00c21ff2df3814d4f04f28fb651401a6c0afb2c9ebad35b70a878b011dc6c'
geo = json.loads(raw_snapshot)
assert geo['as_of'] == '2026-10-01' and geo['country'] == 'IR'
assert any(ipaddress.ip_address('185.143.233.133') in ipaddress.ip_network(cidr)
           for cidr in geo['ipv4'])
assert not any(ipaddress.ip_address('1.1.1.1') in ipaddress.ip_network(cidr)
               for cidr in geo['ipv4'])
for clause in (
    '[[ $# == 4 || $# == 6 ]]',
    'ROOT_IRAN_IP_PINNED_ESTIMATE_AND_DNS=PASS',
    'ROOT_IRAN_DIRECT_POSITIVE_CONTROL=PASS',
    'ROOT_IRAN_PINNED_DIRECT_WHILE_VPN_ACTIVE=PASS',
    'ROOT_IRAN_PINNED_DIRECT_SURVIVES_VPN_CORE_LOSS=PASS',
    'ip daddr $domestic tcp dport 443 meta mark set (meta mark & 0xff00ffff) | 0x00540000',
    'oifname "$underlay" counter',
    'ROOT_CORE_LOSS_NO_DIRECT_FALLBACK=PASS',
    'FIELD_ROOT_OWNED_CLEANUP=PASS',
):
    assert clause in source, f'root-host Direct/VPN QA invariant missing: {clause}'
assert 'add rule inet $owner capture ip daddr $domestic meta mark set (meta mark & 0xff00ffff) | 0x00530000' not in source
print('FIELD_ROOT_PINNED_IRAN_DIRECT_SCOPE=PASS')
