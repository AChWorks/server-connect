# Test and release acceptance

**Current status: initial source/core tests are in development; no signed public release, foreign VPN field test, or complete installed-host acceptance has been established.** PR/CI/test logs own exact candidate evidence. This is a **test contract**, not a claimed test report.

## Evidence grades

- **Source/contract:** review or pure tests; no evidence of real packet delivery.
- **Isolated Linux:** disposable VM/namespace/systemd environment that exercises genuine Linux interfaces/routes and crash/reboot simulation.
- **Physical field:** two-sided observations on real accessible Iran/foreign network paths, including under actual relevant restrictions where legally/operationally permitted.
- **Packaged host:** exact release archive, installer/updater and binary identities on advertised OS/arch.
- **Production:** a separate Owner-authorized rollout with backups, rescue console and rollback; not implied by any preceding grade.

Record exact commit SHA, artifact digest, sing-box version, OS/kernel/arch, baseline host network, probe destination class (without secrets), test duration, pass/fail/NOT_RUN and rollback evidence. Do not convert a simulated restricted connection into proof of connectivity during a real war/outage.

## Disposable Debian 13 installed-host QA harness

The path-scoped GitHub Actions workflow `.github/workflows/installed-host-qa.yml` builds a **QA-only** bundle from the independently SHA-256-verified pinned official core, then starts a disposable Debian 13 Docker container with real `systemd` PID 1, no external Docker networking and no prior product installation. The test script `scripts/qa/test-installed-host.sh` is restricted to ephemeral GitHub Actions runners. It exercises the root-owned shared offline installer in `--verify-only`, install, reinstall and uninstall modes. Syscall tracing rejects DNS/HTTP/network attempts and external fetch tools during each **offline** operation. It checks that the installed service remains Direct/inactive, product-owned resources disappear on uninstall, private test profile bytes survive, and container routes/rules/links match the initial snapshot.

A second **isolated-loopback-only** acquisition validates the development online bootstrap handoff to the same installer and subsequent uninstall. Image preparation and genuine upstream core download happen on the connected disposable GitHub runner **before** the disconnected installer test. This does **not** prove an authenticated public one-line channel, physical disconnected server, upgrade to a different release, SSH/aaPanel coexistence, foreign VPN reachability, reboot/power-loss recovery or safe host routing. Root-capable Docker is confined to a disposable no-secret hosted CI runner; it is not a supported server-install mechanism. Base any PASS claim on the exact completed CI run and job logs, not the existence of this test. Field-host acceptance and publisher/licensing decisions remain independent gates.

## Required matrix

| Scenario | What must be demonstrated | Minimum evidence |
| --- | --- | --- |
| Online one-line install | Connected disposable host automatically acquires compatible pinned manager/core and prerequisites; verifies publisher/artifact identity before installation, then runs the shared installer without host network takeover | Real connected Linux host, full fetch/verify/install trace, artifact identity |
| Offline first install | Whole package works with foreign Internet/GitHub blocked, attempts **no** DNS/HTTP/package fetch and refuses absent prerequisites without host mutation | Packaged isolated host, exact artifact |
| Direct baseline | Install, off, disable, reboot, uninstall leave server networking/SSH/sites untouched except clearly owned state | Real Linux host state diff |
| Import/profile | Known compatible sing-box/VLESS profile validates; malformed/malicious/unsupported inputs fail without secret exposure | Unit + real-core integration |
| Proxy Only | Opted-in curl/APT, and WordPress where supported, must demonstrate the intended proxy route independently of Direct. APT children must be rooted in verified native executables **and effective native acquisition-method paths**; shadow binaries, caller/inherited `Dir::Bin` or `RootDir` redirection and alternative combined-update modes must be refused before any untrusted executable can receive selected-route traffic. APT child settings must be temporary and private with no host-wide `/etc/apt` changes; other apps/services stay Direct. Fail if a selected app accidentally falls back to Direct, if its temporary secret config lingers, or if a dead core causes unrelated host network failure. Do not infer WordPress coverage from PHP/cURL alone. | Real Linux core, APT/process settings, app-specific HTTP evidence and independent path attribution; mark missing WordPress/foreign testing NOT_RUN |
| VPN endpoint underlay and bootstrap DNS | Endpoint is addressable before VPN is active; no recursive tunnel path or resolver loop; Iran/private/foreign traffic uses expected route | Offline/restricted-DNS simulation and real Linux path observation |
| Selective/Broad routing | Inbound SSH (existing/new), web requests and responses, IPv4/IPv6, DNS and aaPanel coexist across connect/off | Disposable hosting VM + selected field |
| Activation expiry | 600-second/default or shorter test-configured expiry without new approved control connection returns to baseline | systemd and route journal check |
| Activation confirmation | Fresh bound SSH/console identity accepted; stale/replayed/cross-operation confirmation rejected | Real SSH, negative tests |
| Crash/uncertain | Kill manager or sing-box between mutation stages, concurrent apply, fsync failure and foreign rule conflict do not clobber unowned resources | Fault injection + host state diff |
| Reboot while pending | Uncommitted route effects are not silently persisted; recovery reconciles journal | Real reboot from installed artifact |
| Runtime failure | Core exit, unreachable VPN endpoint, simulated packet drop, multi-probe outage return network to valid operator policy | Path-bound probe and host route evidence |
| Guard liveness failure | Stop/hang/disable Runtime Health Guard while routed VPN remains; an independent bounded recovery mechanism prevents indefinite unmanaged interception | Real systemd/service supervision and host route recovery evidence |
| False failure | One blocked Ping, broken single foreign website, transient DNS issue do not spuriously tear down healthy profile | Deterministic + actual profile |
| Fail-closed exceptions | Selected VPN-required flows cannot silently egress direct while other hosting/domestic/management paths recover | Packet trace / rules inspection |
| Ingress optional | When not selected, blocked foreign site does not prevent download-only use; when required, external nonce reaches origin (not CDN cache) | Independent external test + origin receipt |
| Package update/uninstall | Both online and offline update use the same verified artifact/install transaction, preserve profiles and offer recovery; uninstall does not erase unrelated firewall/routes | Exact release + host evidence |
| Performance | Compare steady/peak CPU, memory, latency, throughput and recovery overhead in Direct, Proxy, Tunnel | Same representative VM/host and workload |
| Host coexistence | No blind modification of actual aaPanel, SSH, Fail2Ban, Docker, existing VPN/STL or provider network configs | Snapshot + scoped before/after diff |

## First evidence-producing slice

Before implementing the complete menu or speculative protocols, demonstrate:
1. A pinned genuine sing-box VLESS profile can run **Proxy Only** on a disposable Linux host.
2. A representative app's request can be forced through it, verified independently from a Direct request.
3. Stopping sing-box or losing foreign network access cannot affect ordinary host routes or SSH in this mode; any product-owned app proxy settings are restored rather than left pointing to an unavailable local port.
4. The exact files required for the supported target can be installed with foreign networking disabled.

Then advance to guarded Selective Tunnel with independent recovery; do not deploy an unguarded system-wide TUN just to accelerate a demo.

## Acceptance and authorization gates

- Every substantive network/privileged change must pass meaningful fault and safety tests and **fresh author-separated independent high-assurance review** before integration or release.
- A green unit test is not a successful field test. Recheck only evidence invalidated by exact candidate changes.
- Owner approval is required before touching a production panel/website server, changing routing on a real customer environment, or publishing a production release when not already specifically authorized.
- Never use production connectivity as the first demonstration of rollback. Keep a provider console/snapshot and observable escape route on disposable test hosts.
- A release is not accepted merely because a GitHub Issue or PR closed; installation, guards and recovery on the exact artifact are separate proof.

This matrix is authoritative for acceptance categories; GitHub Issues own which categories remain actionable and CI/run artifacts own the actual results.
