# Server Connect

**Status: development candidate. There is no publisher-authenticated public release or approved production install command yet.**

Server Connect is an offline-first Linux server connectivity manager, designed especially for Iran-hosted aaPanel, WordPress and web servers. Its intended main use is **transparent outbound VPN routing** with Iranian destinations Direct and most other public destinations through the selected VPN — without per-application proxy configuration or identifying individual background jobs.

## Planned user experience

| Mode | Purpose |
| --- | --- |
| **Direct** | Leave the host's ordinary networking unchanged. |
| **Proxy Only** | Optional local HTTP/SOCKS proxy for applications that explicitly use it. |
| **Smart Routing (TUN)** | One host-level destination policy using official sing-box and Linux TUN: Iran/local/protected paths Direct, other public traffic VPN by default, with operator domain/IP/CIDR and trusted-list exceptions. |

Smart Routing must protect SSH, aaPanel, website replies, connected networks and the VPN endpoint; it requires independent activation and ongoing recovery safeguards. **Working TUN for all claimed TCP/UDP/DNS/IPv4/IPv6 combinations still needs real evidence.** Optional Cloudflare Tunnel website ingress is a **separate later feature**, not a property of the outbound VPN.

## Installation approach

The planned distribution offers **official online**, **operator-hosted HTTPS mirror** (including Iranian static hosts), and **manual fully offline upload**. Each delivers the same independently verified versioned bundle to **one shared installer**; the disconnected host must not need GitHub or outside Internet. No public one-line install URL should be treated as genuine until release signing, support and licensing are resolved.

## Implementation status and development

The existing source includes a Go CLI, secure profile storage, real pinned sing-box **Proxy Only** development tests, a shared offline installer and a developer online bootstrap. **Production Smart Routing, independent runtime recovery, real foreign-path acceptance and Cloudflare Tunnel integration are not implemented/released.** Current installed-host QA is primarily Debian 13/amd64 in disposable Linux guests, not a public support promise.

For source checks, run `go test ./...`. Actual CLI flags and development diagnostics are maintained in [the CLI help/source](cmd/server-connect/main.go); the reproducible isolated test procedures live in [the QA scripts](scripts/qa/) and CI. Older process-census, unarmed selective-intent and loopback-rule trial commands are **developer diagnostics, not production routing**. Never run privileged disposable-only QA experiments on a customer server.

## Documentation

- **[Project specification](docs/PROJECT-SPEC.md)** — the canonical goal, product limits and delivery direction.
- [Architecture](docs/ARCHITECTURE.md) — traffic paths, host resource ownership and integrations.
- [Safety and recovery](docs/SAFETY-RECOVERY.md) — guard and rollback requirements.
- [Distribution](docs/OFFLINE-DISTRIBUTION.md) — official/mirror/offline trust and lifecycle.
- [Acceptance](docs/ACCEPTANCE.md) — test matrix, evidence levels and valuable prior QA lessons.
- [Contributor guidance](AGENTS.md) — repository editing and safety conventions.

[GitHub Issues](https://github.com/AChWorks/server-connect/issues) track pending work; PRs, Actions and Releases provide current evidence. These are not duplicated into the permanent product specification.

**License:** The repository is publicly readable but has no selected software license. Public access does not grant general redistribution rights; licensing and upstream binary obligations require Owner approval before publishing a release.
