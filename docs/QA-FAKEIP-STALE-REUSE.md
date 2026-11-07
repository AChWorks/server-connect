# FakeIP cached-address reuse: known failing release gate

The DNS-correlated compiler is compile-only. Its fixed FakeIP pool and the
pinned Core's default in-memory map do not preserve a cached application's
domain decision across a Core restart. A synthetic address previously issued
for a VPN name can be reassigned to a Direct name. A later connection using the
old numeric address then reaches Direct.

This is a required DNS/reconnect acceptance blocker, not an admitted host
operation. The current installed v9 supervisor factory does not use this
DNS-correlated configuration. This finding must not be extrapolated into a
failure of unrelated native IP-only tests, or into successful native DNS
capture.

## Replay

Use the official Linux amd64 sing-box 1.14.3 binary from the already pinned
archive. The regression checks the extracted executable's SHA256 before
execution:

- Upstream archive: `e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee`
- Extracted executable: `768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93`
- Core-reported revision: `7054cac5124465ffdb145870d7c01885566711b1`

Ordinary suites explicitly skip this known failing gate. Opting in preserves
the safety assertion and intentionally fails the current implementation:

```sh
SC_TEST_SINGBOX=/verified/path/to/sing-box \
SC_TEST_DNS_STALE_REUSE=known-defect-negative \
go test ./internal/sc \
  -run '^TestRealPinnedCoreDNSCorrelationStaleAddressReuseAfterRestart$' \
  -count=1 -v -timeout=60s
```

Missing Core configuration or an incorrect binary is a test failure after
opt-in. Do not change the assertion to expect Direct, turn the failure into a
skip, or describe successful ordinary CI as passing this release gate.

The harness calls the production correlated compiler. It retains the DNS
actions, FakeIP configuration and ordered routing policy. As in the existing
unprivileged DNS runtime test, it substitutes a loopback numeric mixed inbound,
independent loopback Direct/VPN SOCKS witnesses, and a task-owned test
certificate for the local authenticated DoH endpoint. It changes no host
routes, firewall, resolver settings, TUN devices or system services.

## Recorded reproduction

The initial author-team reproduction ran on Dev on 2026-11-07:

- Worker source: `19dfb2d80c0a0c40f81772a87239e1ef34ecf2d4`.
- DNS compiler, capture contract and runtime helper source were unchanged from
  PR candidate `4865cd123fbfafeb5acb9bc70105cbf1ae8d7279`.
- Temporary Go overlay only; repository files were unchanged during that run.
- Persistent job: `1794017957601188568`; completed with exit `1`.
- Runtime test duration: `0.338s`.
- Initial overlay test SHA256:
  `9c66cbc942bcfbe5efd4119322761d8c380d2d455c64a1b3746c6fe560339010`.
- Original runtime helper source SHA256:
  `d17049024282f93499b4450a558d4696e72460a9b14114f0dbdb27d8d40df3d0`.

The retained regression was then replayed in job `1794018183538910473`:
ordinary invocation explicitly skipped, focused routing CLI tests passed
(`0.159s`), and the opt-in safety assertion failed with independently observed
Direct delivery (`0.664s`). The retained test file SHA256 was
`6dbfc92cb0e1fcb7164f617af334b4e20dd6e850b28dd5b8b9ba58d0498d1799`.

| Step | Actual result |
|---|---|
| Resolve `vpn.example.org`, then use its numeric FakeIP | `198.18.0.2`; VPN payload and independent VPN witness |
| SIGKILL and reap that Core, start the same configuration, reuse the cached address before any allocation | Refused; no outbound witness |
| Resolve `direct.example.org` in the new Core | The same `198.18.0.2`; Direct payload and independent Direct witness |
| Reuse the old cached VPN address after reassignment | Direct payload and independent Direct witness; required safety assertion fails |

Both domain names resolve through the authenticated test DoH endpoint to the
same numeric target `76.76.21.21`. A forged HTTP Host does not grant authority;
the failure is the reset and reuse of the numeric FakeIP identity itself.

The retained assertion allows the old address to remain VPN or fail closed.
It rejects Direct. The positive controls distinguish real wrong-path delivery
from a dead Core, broken resolver or missing witness.

## Source explanation and remaining gate

Pinned upstream [FakeIP store initialization and allocation](https://github.com/SagerNet/sing-box/blob/v1.14.3/dns/transport/fakeip/store.go)
resets the allocation cursor when no persistent map is configured.
[Memory storage](https://github.com/SagerNet/sing-box/blob/v1.14.3/dns/transport/fakeip/memory.go)
replaces an address's domain mapping on reuse. Upstream allocation also wraps
at the pool boundary; this is a source finding, not an additional executed
exhaustion test.

Unknown-map refusal does not prove stale-map safety after reuse. Before
correlated DNS can join admitted activation or automatic reconnect, its
mapping lifetime and cached-address treatment must remain safe across Core
replacement, operation changes, reboot and pool reuse. Merely enabling a
persistent cache does not establish all of those properties.

This unprivileged IPv4/TCP regression does not establish native TCP/UDP DNS
interception, real-provider behavior, IPv6 stale-address behavior, or installed
reconnect/reboot acceptance. Independent exact-candidate review and those
installed tests remain required.
