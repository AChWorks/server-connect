# Test and release acceptance

**Current status: all implementation, packaging, and live network tests are NOT_RUN.** No published executable exists. This is a **test contract**, not a claimed test report.

## Evidence grades

- **Source/contract:** review or pure tests; no evidence of real packet delivery.
- **Isolated Linux:** disposable VM/namespace/systemd environment that exercises genuine Linux interfaces/routes and crash/reboot simulation.
- **Physical field:** two-sided observations on real accessible Iran/foreign network paths, including under actual relevant restrictions where legally/operationally permitted.
- **Packaged host:** exact release archive, installer/updater and binary identities on advertised OS/arch.
- **Production:** a separate Owner-authorized rollout with backups, rescue console and rollback; not implied by any preceding grade.

Record exact commit SHA, artifact digest, sing-box version, OS/kernel/arch, baseline host network, probe destination class (without secrets), test duration, pass/fail/NOT_RUN and rollback evidence. Do not convert a simulated restricted connection into proof of connectivity during a real war/outage.

## Required matrix

| Scenario | What must be demonstrated | Minimum evidence |
| --- | --- | --- |
| Offline first install | Whole package works with foreign Internet/GitHub blocked and refuses absent prerequisites without host mutation | Packaged isolated host, exact artifact |
| Direct baseline | Install, off, disable, reboot, uninstall leave server networking/SSH/sites untouched except clearly owned state | Real Linux host state diff |
| Import/profile | Known compatible sing-box/VLESS profile validates; malformed/malicious/unsupported inputs fail without secret exposure | Unit + real-core integration |
| Proxy Only | Selected APT/download/WordPress test client can access foreign test service; unselected host traffic unchanged | Real Linux core and packet-route check |
| VPN endpoint underlay | No recursive tunnel path; mixed Iran/private/foreign destinations take expected route | Linux network path observation |
| Selective/Broad routing | Inbound SSH (existing/new), web requests and responses, IPv4/IPv6, DNS and aaPanel coexist across connect/off | Disposable hosting VM + selected field |
| Activation expiry | 600-second/default or shorter test-configured expiry without new approved control connection returns to baseline | systemd and route journal check |
| Activation confirmation | Fresh bound SSH/console identity accepted; stale/replayed/cross-operation confirmation rejected | Real SSH, negative tests |
| Crash/uncertain | Kill manager or sing-box between mutation stages, concurrent apply, fsync failure and foreign rule conflict do not clobber unowned resources | Fault injection + host state diff |
| Reboot while pending | Uncommitted route effects are not silently persisted; recovery reconciles journal | Real reboot from installed artifact |
| Runtime failure | Core exit, unreachable VPN endpoint, simulated packet drop, multi-probe outage return network to valid operator policy | Path-bound probe and host route evidence |
| False failure | One blocked Ping, broken single foreign website, transient DNS issue do not spuriously tear down healthy profile | Deterministic + actual profile |
| Fail-closed exceptions | Selected VPN-required flows cannot silently egress direct while other hosting/domestic/management paths recover | Packet trace / rules inspection |
| Ingress optional | When not selected, blocked foreign site does not prevent download-only use; when required, external nonce reaches origin (not CDN cache) | Independent external test + origin receipt |
| Package update/uninstall | Offline update preserves user profiles and offers supported recovery; uninstall does not erase unrelated firewall/routes | Exact release + host evidence |
| Performance | Compare steady/peak CPU, memory, latency, throughput and recovery overhead in Direct, Proxy, Tunnel | Same representative VM/host and workload |
| Host coexistence | No blind modification of actual aaPanel, SSH, Fail2Ban, Docker, existing VPN/STL or provider network configs | Snapshot + scoped before/after diff |

## First evidence-producing slice

Before implementing the complete menu or speculative protocols, demonstrate:
1. A pinned genuine sing-box VLESS profile can run **Proxy Only** on a disposable Linux host.
2. A representative app's request can be forced through it, verified independently from a Direct request.
3. Stopping sing-box or losing foreign network access cannot affect ordinary host routes or SSH in this mode.
4. The exact files required for the supported target can be installed with foreign networking disabled.

Then advance to guarded Selective Tunnel with independent recovery; do not deploy an unguarded system-wide TUN just to accelerate a demo.

## Acceptance and authorization gates

- Every substantive network/privileged change must pass meaningful fault and safety tests and **fresh author-separated independent high-assurance review** before integration or release.
- A green unit test is not a successful field test. Recheck only evidence invalidated by exact candidate changes.
- Owner approval is required before touching a production panel/website server, changing routing on a real customer environment, or publishing a production release when not already specifically authorized.
- Never use production connectivity as the first demonstration of rollback. Keep a provider console/snapshot and observable escape route on disposable test hosts.
- A release is not accepted merely because a GitHub Issue or PR closed; installation, guards and recovery on the exact artifact are separate proof.

This matrix is authoritative for acceptance categories; GitHub Issues own which categories remain actionable and CI/run artifacts own the actual results.
