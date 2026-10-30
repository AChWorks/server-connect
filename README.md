# Server Connect

**Status: development candidate. There is no publisher-authenticated public release or approved production install command yet.**

Server Connect is an offline-first Linux server connectivity manager, designed especially for Iran-hosted aaPanel, WordPress and web servers. Its intended main use is **transparent outbound VPN routing** with Iranian destinations Direct and most other public destinations through the selected VPN — without per-application proxy configuration or identifying individual background jobs.

## Planned user experience

| Mode | Purpose |
| --- | --- |
| **Direct** | Leave the host's ordinary networking unchanged. |
| **Proxy Only** | Optional local HTTP/SOCKS proxy for applications that explicitly use it. |
| **Smart Routing (TUN)** | One host-level destination policy using official sing-box and Linux TUN: Iran/local/protected paths Direct, other public traffic VPN by default, with operator domain/IP/CIDR and trusted-list exceptions. |

Switching Smart Routing **off** must restore the server's ordinary network paths, without leftover VPN-only blocking, while keeping saved profiles and routing rules for the next guarded activation. The disposable installed TUN trial exercises this lifecycle with an exact-operation Disconnect and saved-policy reapply. **General-host Smart Routing remains unimplemented and unavailable for production.**

Smart Routing must protect SSH, aaPanel, website replies, connected networks and the VPN endpoint; it requires independent activation and ongoing recovery safeguards. **Working TUN for all claimed TCP/UDP/DNS/IPv4/IPv6 combinations still needs real evidence.** Optional Cloudflare Tunnel website ingress is a **separate later feature**, not a property of the outbound VPN.

## Installation approach

The planned distribution offers **official online**, **operator-hosted HTTPS mirror** (including Iranian static hosts), and **manual fully offline upload**. Each delivers the same independently verified versioned bundle to **one shared installer**; the disconnected host must not need GitHub or outside Internet. No public one-line install URL should be treated as genuine until release signing, support and licensing are resolved.

## Implementation status and development

The existing source includes a Go CLI, secure profile storage, real pinned sing-box **Proxy Only** development tests, a shared offline installer and a developer online bootstrap. **General-host Smart Routing, the production Runtime Health Guard, real foreign-path acceptance and Cloudflare Tunnel integration remain unavailable.** The disposable native trial includes an independent expiry/recovery executor; its explicit supervised mode adds fresh SSH confirmation, selected-path health checks and bounded recovery inside the same isolated fixture. Target-specific Debian 12/amd64 and Debian 13/amd64 QA bundles support the Direct/Proxy Only installation lifecycle. New native trials additionally require Debian 13 and the existing isolated fixture; installing on Debian 12 does not admit TUN. See [the distribution contract](docs/OFFLINE-DISTRIBUTION.md) for these development targets and their limits; they are not a public support promise.

For source checks, run `go test ./...`. Actual CLI flags and development diagnostics are maintained in [the CLI help/source](cmd/server-connect/main.go); the reproducible isolated test procedures live in [the QA scripts](scripts/qa/) and CI. Older unarmed selective-intent and loopback-rule trial commands are **developer diagnostics, not production routing**. A separate installed, **Docker-only Smart TUN trial** exercises real sing-box through a prearmed independent expiry guard. Its default pending mode expires without confirmation. The explicit `--supervised` mode requires a new authenticated root SSH connection and a single-use operation challenge before experimental confirmation, then runs bounded selected-path health rounds under independently monitored liveness. Neither mode grants general-host `ACTIVE_VERIFIED`. Its strictly synthetic fixture supports IPv4 and explicitly requested IPv4+IPv6 policy with exact Direct/VPN exceptions and native rollback checks. The manager owns the persistent TUN and native interception/containment policy; the core attaches with automatic host policy disabled. Operation-bound Disconnect removes only resources covered by the durable ownership record, preserving supported disjoint changes by other owners. Ambiguous ownership retains recovery evidence and reports uncertainty instead of guessing at cleanup. The validated trial policy and selected profile remain saved for a fresh guarded reapply; interrupted stop/cleanup retains durable recovery evidence. It is not available for customer/physical-host operation, nor proof that Smart Routing is production-ready. Never run privileged disposable-only QA experiments on a customer server.

The read-only `server-connect smart-routing-data` command works entirely offline and reports a pinned **DB-IP Country Lite geolocation estimate** for Iran (IPv4/IPv6 counts, source, month, age, hashes and license). **Data credit: [IP Geolocation by DB-IP](https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).** The project extracts IR rows from DB-IP Country Lite (October 2026) and converts the original IP ranges into sorted CIDR prefixes. DB-IP Lite has reduced coverage/accuracy; its country estimates are **not** independent packet-path proof. These entries are deliberately **not automatically used as Direct exemptions** and the report explicitly declares geographic-route safety and activation readiness false. This is not a publisher-signed update, operator rule import or production Apply. Regeneration from a separately downloaded, pinned source archive is supported by `scripts/qa/generate-iran-dbip-lite-snapshot.py`; installation and inspection do not contact DB-IP, GitHub or any outside network. Independent field testing, update/rollback policy and guards remain mandatory.

## Documentation

- **[Project specification](docs/PROJECT-SPEC.md)** — the canonical goal, product limits and delivery direction.
- [Architecture](docs/ARCHITECTURE.md) — traffic paths, host resource ownership and integrations.
- [Safety and recovery](docs/SAFETY-RECOVERY.md) — guard and rollback requirements.
- [Distribution](docs/OFFLINE-DISTRIBUTION.md) — official/mirror/offline trust and lifecycle.
- [Acceptance](docs/ACCEPTANCE.md) — test matrix, evidence levels and valuable prior QA lessons.
- [Contributor guidance](AGENTS.md) — repository editing and safety conventions.

[GitHub Issues](https://github.com/AChWorks/server-connect/issues) track pending work; PRs, Actions and Releases provide current evidence. These are not duplicated into the permanent product specification.

**License:** The repository is publicly readable but has no selected software license. Public access does not grant general redistribution rights; licensing and upstream binary obligations require Owner approval before publishing a release.
