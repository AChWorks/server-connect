#!/usr/bin/env python3
"""Unprivileged regression for the root-host field QA's two shell hazards."""
import hashlib
import ipaddress
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
PILOT = ROOT / 'scripts/qa/field-root-selected-tun.sh'
SOCKET = ROOT / 'scripts/qa/field-notrack-inherited-mark.sh'
SESSION = ROOT / 'scripts/qa/field-notrack-session-preservation.sh'
for path in (PILOT, SOCKET, SESSION):
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
