# Server Connect

**Status: Development candidate — no signed or published installable release is available yet.**

Server Connect is an **offline-first Linux server connectivity manager** for administrators of hosting servers, including Iran-based servers running aaPanel, WordPress, and other web services. Its goal is to provide simple, controlled access to external networks when direct connections are unavailable, without disrupting SSH, domestic routes, hosted websites, or other server workloads.

The initial connectivity engine is **official pinned sing-box**. The primary goal is **Windows-TUN-like transparent outbound connectivity** for Linux hosting servers, with safe Iranian Direct / other-public VPN split routing, operator-defined domain/IP exceptions, independent recovery and no per-job or per-app setup.

## Planned operating modes

| Mode | Behavior |
| --- | --- |
| **Direct** | Original host networking, no product-owned tunnel policy |
| **Proxy Only** | Existing explicit local SOCKS/HTTP proxy opt-in |
| **Smart Routing (TUN)** | Transparently capture supported host outbound traffic; Iran/local/protected Direct, other public destinations VPN by default, with operator-managed domain/IP/CIDR and local rule-list exceptions |

The operator selects a verified profile and connects once; ordinary supported programs (aaPanel, WordPress, APT, Git, installers, raw TCP/UDP clients) do **not** need individual proxy settings. Real DNS/IPv4/IPv6/UDP and domain-match behavior must be validated against the chosen upstream and Linux host; unsupported traffic must not silently leak Direct. Existing SSH, hosted website **inbound replies including foreign clients**, local networking and VPN endpoint underlay are independently protected. An Activation Guard with fresh SSH/console confirmation and an ongoing Runtime Health Guard are mandatory before routed production use.

Rule priority is protected host paths, explicit operator rules, validated locally available Iranian IP prefixes, then VPN for other public destinations. Users can import versioned rule lists or define Direct/VPN domain, IP and CIDR rules manually; optional Direct-first checks for selected foreign exceptions are not necessary for the first working mode. There is **no per-job/PID/cgroup routing engine**. See [canonical specification](docs/PROJECT-SPEC.md).

**Optional future website ingress:** [Cloudflare Tunnel (#48)](https://github.com/AChWorks/server-connect/issues/48) can publish operator-authorized HTTP(S) origins for foreign visitors using outbound cloudflared connectivity (Direct or verified VPN as needed). It is **not** a public port-forwarding guarantee of the VPN profile, and not a prerequisite for an outbound-only first release. Outbound and inbound connector health must remain independent. The separately deferred [concurrent-profile idea (#7)](https://github.com/AChWorks/server-connect/issues/7) is not part of the current architecture.

## Planned installation experience

**Three sources, one authenticated bundle and one shared installer:** (1) official online; (2) a user-selected **Iranian/operator-hosted HTTPS mirror** containing the identical signed bundle and metadata; or (3) **manual upload and fully offline one-folder/one-command installation**. Online download and mirror differ only in where the immutable verified bytes come from. Offline mode attempts no network access; runtime and update must not depend on foreign Internet. The installer, profile state, guards, update and uninstall are shared. A self-hosted static mirror does not need a separate service or signing key.

**No public signed/approved install command or release is available yet.** Do not run unverified curl-to-shell instructions; publisher authenticity is separate from HTTPS or a checksum supplied by the same archive. See [distribution contract](docs/OFFLINE-DISTRIBUTION.md).

## Development status and diagnostics

The current validated **development** target is Debian 13/amd64, built in Go with an official pinned sing-box core. Direct and opt-in Proxy Only have isolated test evidence; **production Smart Routing TUN, independent runtime recovery, a signed release and real Cloudflare Tunnel integration do not yet exist**. Run source checks with `go test ./...` and consult the [development/QA commands](docs/DEVELOPMENT-DIAGNOSTICS.md) for detailed, accurate diagnostics. Those optional historical job/route observations are **not** required before implementing transparent Smart Routing.

## Documentation and project status

| Source | Responsibility |
| --- | --- |
| [Project specification](docs/PROJECT-SPEC.md) | **Canonical** product goals, behavior, constraints, and non-goals |
| [Architecture](docs/ARCHITECTURE.md) | Component boundaries, host resource ownership, and upstream reuse |
| [Safety and recovery](docs/SAFETY-RECOVERY.md) | Guarded activation, health monitoring, rollback, and crash/reboot safety |
| [Installation and distribution](docs/OFFLINE-DISTRIBUTION.md) | Official online, operator-hosted mirror and manual offline sources; one shared installer, release trust and updates |
| [Acceptance criteria](docs/ACCEPTANCE.md) | Reproducible test matrix and evidence needed before release |
| [Development diagnostics](docs/DEVELOPMENT-DIAGNOSTICS.md) | Historical developer/QA-only CLI behavior, not operator installation guidance |
| [Contributor instructions](AGENTS.md) | Engineering, review, and project-continuity rules |
| [GitHub Issues](https://github.com/AChWorks/server-connect/issues) | Current work, dependencies, and release acceptance |

The existing [Proxy Only foundation (#1)](https://github.com/AChWorks/server-connect/issues/1) leads to the current critical path: [real Smart Routing TUN (#2)](https://github.com/AChWorks/server-connect/issues/2), [ongoing guard (#3)](https://github.com/AChWorks/server-connect/issues/3), [operator UX (#4)](https://github.com/AChWorks/server-connect/issues/4) and [release gate (#5)](https://github.com/AChWorks/server-connect/issues/5). [Cloudflare website ingress (#48)](https://github.com/AChWorks/server-connect/issues/48) is a separate optional follow-on. No production server change is authorized by this repository.

## Boundaries and security

Server Connect owns only its verified host changes. It must not take over unrelated firewall rules, SSH settings, aaPanel services, existing Cloudflare tunnels or customer applications. It is **not** a VPN provider, universal raw ingress relay, or new packet-forwarding engine; the optional integration may manage an explicitly approved official cloudflared connector.

Do not commit real VPN subscriptions, endpoints containing credentials, customer details, secrets, private keys, or runtime state.

## License status

The repository is publicly readable, but **no software license has been selected**. Public visibility does not grant general rights to reuse or redistribute the code. Any open-source license or binary redistribution policy requires an explicit project-owner decision.
