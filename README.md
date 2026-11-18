# Server Connect

**Development / QA candidate — no publisher-authenticated public release, production approval, or verified public install URL.**

Server Connect is an offline-first Linux connectivity manager for servers, including Iran-hosted aaPanel and WordPress systems. Its goal is transparent **outbound** routing through an official sing-box TUN, without per-application proxy settings or selecting jobs, PIDs or cgroups. It is not a VPN provider or an inbound-port relay.

## Modes and present support

| Mode | Intended behavior | Current evidence |
| --- | --- | --- |
| **Direct** | Original host networking, with no Server Connect-owned VPN routing or blocking rules | Implemented; source and installed-host QA |
| **Proxy Only** | Opt-in local HTTP/SOCKS proxy for compatible applications | Implemented; real pinned-Core and installed-host QA |
| **Smart Routing (TUN)** | Iranian, private and protected paths Direct; other public outbound traffic through the selected VPN, with validated operator exceptions | Native official-Core candidate tested on isolated Debian 12/13 guests; **general-host/production acceptance remains open** |

For a real Smart Routing session, existing/new SSH administration, aaPanel and foreign-client website replies must remain reachable; VPN-required traffic must not escape Direct while routed or degraded. A verified Disconnect or guard-driven switch to Direct must remove precisely owned VPN-only rules while **preserving saved profiles and routing settings**. A healthy Core process, selected HTTPS probe or synthetic guest run alone does not prove all TCP/UDP/DNS/IPv4/IPv6 and provider paths.

**Implemented development components:** Go menu/CLI with structured JSON, private profiles, saved routing rules, pinned sing-box, common offline installer, signed-aware QA acquisition for official/mirror/offline sources, and an independently supervised native TUN candidate. A separate older guarded TUN trial remains for legacy disposable QA and is not the recommended runtime. The current native candidate has exact clean-source installed-guest evidence; field-path safety and the first stable release are **not accepted**. Consult [Acceptance](docs/ACCEPTANCE.md) and live [Issues](https://github.com/AChWorks/server-connect/issues) rather than treating historical PR or CI results as approval of the current host.

## Operator and developer entry points

The installed CLI offers an interactive menu and script-friendly `--json` commands. On a **development or separately authorized QA installation**, useful inspection commands include:

```console
server-connect --json mode-overview
server-connect --json native-status
server-connect --json smart-routing-data
server-connect --json smart-routing-rules list
```

`mode-overview` reports desired versus observed state; `native-status` exposes the bounded native guard/health observations. These commands are **diagnostics**, not proofs of field-safe activation. Status inspection may initialize private manager state/locks; it does not intentionally change host routes. The menu keeps ordinary Connection, Profiles and Routing Rules actions up front; advanced legacy QA commands are separate. Use the CLI's `help` and the installed binary's actual output for current flags and status meanings.

For one supported `vless://` profile link, import from a **private file or stdin** instead of placing bearer credentials in shell arguments or logs:

```console
server-connect --json import --file /private/profile-link.txt
```

The importer supports a bounded set of compatible TCP/WebSocket/HTTPUpgrade links, not subscription downloads or arbitrary Xray transport options. Unsupported or insecure variants must be rejected rather than silently remapped. Native sing-box JSON import is available for other validated profile formats. Stored profiles are secrets.

For local **nonprivileged source validation**:

```console
go test ./...
go vet ./...
go run ./cmd/server-connect help
```

Reproducible installed-host, exact pinned-Core, TUN wire and failure scenarios live in [scripts/qa/](scripts/qa/) and the repository's GitHub Actions workflows. Do **not** run privileged TUN/route/firewall experiments on a customer host or assume an installed guest passing CI grants authority for a physical server. Field runs require an explicitly authorized target, exact source/bundle identity, baseline, recovery path and independent Direct/VPN packet evidence.

## Acquisition and release boundary

The planned installation options are **official online**, **operator-hosted HTTPS mirror**, and **manual fully offline bundle upload**. All must authenticate the **same immutable versioned bytes** and use **one shared installer**; a mirror is not a new publisher. The source includes QA-only acquisition/signature checks and packaging tools, but the Owner has not approved a publisher identity, software license, public release channel or production installer. See [Distribution and update](docs/OFFLINE-DISTRIBUTION.md) for the concrete trust, packaging, update, audit and rollback contract. Never guess a public one-liner.

Bundled Iranian-prefix classification uses an offline **DB-IP Country Lite estimate** (credit: [DB-IP](https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)). It is versioned input to the experimental `bypass_iran` policy, **not authenticated geographic reachability**. Operator rules and domain/IP correlation have separate acceptance limits.

## Where the project truth lives

- [Project specification](docs/PROJECT-SPEC.md): durable product goal, three modes, scope and boundaries.
- [Architecture](docs/ARCHITECTURE.md): official-Core runtime, packet decisions, components and resource ownership.
- [Safety and recovery](docs/SAFETY-RECOVERY.md): activation/health supervision, precise rollback, unsafe/uncertain states and legacy compatibility.
- [Distribution](docs/OFFLINE-DISTRIBUTION.md): official/mirror/offline trust, shared installer and update/rollback.
- [Acceptance](docs/ACCEPTANCE.md): required evidence, physical-vs-guest boundaries and test procedures.
- [AGENTS.md](AGENTS.md): contributor and independent-review rules.

**Live work:** [MVP foundation #1](https://github.com/AChWorks/server-connect/issues/1), [Smart Routing #2](https://github.com/AChWorks/server-connect/issues/2), [Recovery #3](https://github.com/AChWorks/server-connect/issues/3), [Operator UX #4](https://github.com/AChWorks/server-connect/issues/4), [Release gate #5](https://github.com/AChWorks/server-connect/issues/5), and [legacy cleanup #50](https://github.com/AChWorks/server-connect/issues/50). [Cloudflare website ingress #48](https://github.com/AChWorks/server-connect/issues/48) is post-core; [concurrent VPN profiles #7](https://github.com/AChWorks/server-connect/issues/7) requires a new Owner decision. PRs, Actions and Releases—not this README—own exact SHA-specific execution evidence.

**License:** This publicly readable repository has **no selected software license**. Public visibility does not grant redistribution rights. Publisher identity, upstream notices and rights must be resolved before distribution.
