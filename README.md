# Server Connect

**Development / QA candidate — no publisher-authenticated public release, production approval, or verified public install URL.**

Server Connect is an offline-first Linux connectivity manager for servers, including Iran-hosted aaPanel and WordPress systems. Its goal is transparent **outbound** routing through an official sing-box TUN, without per-application proxy settings or selecting jobs, PIDs or cgroups. It is not a VPN provider or an inbound-port relay.

## Modes and present support

| Mode | Intended behavior | Current evidence |
| --- | --- | --- |
| **Direct** | Original host networking, with no Server Connect-owned VPN routing or blocking rules | Implemented; source and installed-host QA |
| **Proxy Only** | Opt-in local HTTP/SOCKS proxy for compatible applications | Implemented; real pinned-Core and installed-host QA |
| **Smart Routing (TUN)** | Iranian, private and protected paths Direct; other public outbound traffic through the selected VPN, with validated operator exceptions | Official-Core native installed-host QA on Debian 12/13; the current unreviewed lifetime-guard implementation also has installed-VM and nonproduction IRPT-101 real selected VLESS/IPv4, actual Core SIGKILL and manual-stop packet witnesses, independently observed foreign SSH/HTTP, and exact Direct/off restoration. Evidence is source-bound in [Issue #5](https://github.com/AChWorks/server-connect/issues/5) and [PR #127](https://github.com/AChWorks/server-connect/pull/127); REALITY and positive selected public IPv6 remain unproven. |

For a real Smart Routing session, existing/new SSH administration, aaPanel and foreign-client website replies must remain reachable; VPN-required traffic must not escape Direct while routed or degraded. A verified Disconnect or guard-driven switch to Direct must remove precisely owned VPN-only rules while **preserving saved profiles and routing settings**. A healthy Core process, selected HTTPS probe or synthetic guest run alone does not prove all TCP/UDP/DNS/IPv4/IPv6 and provider paths.

**Implemented development components:** Go menu/CLI with structured JSON, private profiles, saved routing rules, pinned sing-box, common offline installer, signed-aware QA acquisition for official/mirror/offline sources, and an independently supervised native TUN candidate. Obsolete parallel v1/v2/v3/v4 trial creation and the v4 experimental service are retired in the development source; historical operation state remains a fail-closed installation/Native activation blocker until explicitly reconciled. Field-path safety and the first stable release are **not accepted**. Consult [Acceptance](docs/ACCEPTANCE.md) and live [Issues](https://github.com/AChWorks/server-connect/issues) rather than treating historical PR or CI results as approval of the current host.

## Operator and developer entry points

The guarded `connect-smart` CLI defaults to 3 Core-process replacements
per explicit activation, a 1000 ms initial backoff and a 60000 ms
per-incident deadline. Use `--core-restart-attempts`,
`--core-restart-backoff-ms` and `--core-restart-deadline-ms` on
an **authorized QA host** to tune the bounded behavior; `--core-restart-attempts 0`
disables automatic process replacements. An unexpected unguarded Core
exit still stops into verified owned Direct/off (or explicit uncertainty)
rather than improvising a restart. Source tests alone cannot prove
installed systemd/TUN safety; bounded installed-guest and authorized
nonproduction field evidence is tracked in [Acceptance](docs/ACCEPTANCE.md)
and Issue #5. Such evidence does not itself authorize production.

The installed CLI offers an interactive menu and script-friendly `--json` commands. On a **development or separately authorized QA installation**, useful inspection commands include:

```console
server-connect --json mode-overview
server-connect --json native-status
server-connect --json smart-routing-data
server-connect --json smart-routing-rules list
```

`mode-overview` reports desired versus observed state; `native-status` exposes bounded native guard/health observations and, for managed Core recovery, consumed attempts, result and last confirmed before/after PID. These commands are **diagnostics**, not proofs of field-safe activation. Status inspection may initialize private manager state/locks; it does not intentionally change host routes. The menu header distinguishes requested **Direct**, **Proxy Only** and **Smart Routing** from observed state, including native starting/degraded/recovering/synthetic-QA health and uncertain recovery; a running native Core is not independent VPN-path proof and failed recovery must not be labeled verified Direct/off.

On a **separately authorized, recoverable QA host only**, menu option **21 Smart Routing (guarded QA)** requests the underlay interface, `bypass_iran` (estimated Iran Direct / other public VPN) or `default` (all public destinations, including Iran, through VPN except protected/private and explicitly authorized Direct exceptions) policy, and an exact `CONNECT-SMART` acknowledgement before invoking the existing guarded `connect-smart` CLI path. Option **22 Native Guard / Recovery Status** invokes `native-status`. Option **7 Disconnect / Return to Direct** invokes the same owned-resource `disconnect` as the CLI for Proxy Only and native Smart Routing. None of these menu options admits general hosts, proves the actual selected VPN/Direct packet paths or authorizes a production change.

Ordinary Connection, Profiles and Routing Rules actions stay up front. The superseded isolated-VM trial is no longer offered in the operator menu. Historical v1 selective staging and v2/v3 rule/route trial creation are retired; strict persisted-journal validation, exact safe abandonment and owned recovery remain. The new installed QA uses current Native tests; retired v4 experimental commands are neither installed nor accepted as a second operator mode. Use the CLI's `help` and the installed binary's actual output for current flags and status meanings.

For one supported `vless://` profile link, import from a **private file or stdin** instead of placing bearer credentials in shell arguments or logs:

```console
server-connect --json import --file /private/profile-link.txt
```

The importer supports a bounded set of compatible TCP/WebSocket/HTTPUpgrade links, not subscription downloads or arbitrary Xray transport options. Unsupported or insecure variants must be rejected rather than silently remapped. Native sing-box JSON import is available for other validated profile formats. Stored profiles are secrets. The optional `--port` accepts any TCP port 1–65535 for the authenticated loopback proxy; OS bind permissions and port conflicts determine runtime availability.

**Saved routing-rule list import** uses a local ASCII file with LF (not CRLF) line endings, up to 1 MiB (the existing protected state-file ceiling). Each nonempty, non-comment line is `kind via value`: `cidr` with `direct` or `vpn`, or exact `domain` / apex-and-subdomains `suffix` with `vpn` only. For example, `/private/operator-rules.txt` can contain:

```text
# explicit exceptions; these do not authenticate Iranian geography
cidr direct 1.1.1.0/24
cidr vpn 9.9.9.9/32
domain vpn example.org
suffix vpn test.example.org
```

Import with a source ID, nonfuture source date and independently pinned SHA-256 of the **exact file bytes** (replace the example placeholders):

```console
sha256sum /private/operator-rules.txt
server-connect --json smart-routing-rules import --file /private/operator-rules.txt --source operator-list --as-of YYYY-MM-DD --sha256 EXPECTED_LOWERCASE_SHA256
```

`--file -` accepts stdin. Updating an existing source also requires `--replaces-sha256 CURRENT_SOURCE_SHA256`; `smart-routing-rules remove-source --source operator-list --sha256 CURRENT_SOURCE_SHA256` removes it. Unsafe, overlapping or uncanonical rules are rejected; saving/importing rules **does not activate routing**. A matching local hash is not a publisher signature or trustworthy geographic evidence.

For local **nonprivileged source validation**:

```console
go test ./...
go vet ./...
go run ./cmd/server-connect help
```

Reproducible installed-host, exact pinned-Core, TUN wire and failure scenarios live in [scripts/qa/](scripts/qa/) and the repository's GitHub Actions workflows. Do **not** run privileged TUN/route/firewall experiments on a customer host or assume an installed guest passing CI grants authority for a physical server. Field runs require an explicitly authorized target, exact source/bundle identity, baseline, recovery path and independent Direct/VPN packet evidence.

## Acquisition and release boundary

The planned installation options are **official online**, **operator-hosted HTTPS mirror**, and **manual fully offline bundle upload**. All must authenticate the **same immutable versioned bytes** and use **one shared installer**; a mirror is not a new publisher. The source includes QA-only acquisition/signature checks and packaging tools, and the Owner has selected MPL-2.0 for first-party source, but has not approved a publisher identity, public release channel or production installer. See [Distribution and update](docs/OFFLINE-DISTRIBUTION.md) for the concrete trust, packaging, update, audit and rollback contract. Never guess a public one-liner.

Bundled Iranian-prefix classification combines two versioned offline estimates: [DB-IP Country Lite](https://db-ip.com) (**CC BY 4.0**) and [Chocolate4U Iran sing-box rules](https://github.com/Chocolate4U/Iran-sing-box-rules) (**GPL v3 repository; underlying source conditions require separate review**). The default `bypass_iran` policy uses the **CIDR-accurate intersection** (currently 2,917 IPv4/IPv6 prefixes) rather than a naïve union: Chocolate4U also lists certain externally hosted provider IPs that must not silently become Direct. `--iran-coverage dbip` preserves the prior DB-IP-only estimate where an operator explicitly chooses broader coverage. All unmatched public destinations remain on the selected VPN. `smart-routing-data` reports both pinned sources and the consensus; no installation/Connect-time GitHub access is needed. This is **not authenticated physical geography or reachability**, and operator Direct-domain rules still require trusted DNS/IP association. The large Chocolate4U `geosite-ir` directory is **not used for automatic domain Direct** without that association.

For offline attribution, new local-QA archives include the transformed DB-IP Lite IR-prefix source and its CC BY 4.0 provider/license/change notice as separately authenticated third-party payload members. Existing installed releases remain auditable. These preserved source/notice bytes neither authenticate physical IP geography nor clear all upstream redistribution obligations; see [Distribution](docs/OFFLINE-DISTRIBUTION.md).

For dual-stack application compatibility, the native candidate defaults to **selected-VPN IPv6 disabled** until the remote exit is verified IPv6-capable: intercepted application DNS gets empty AAAA responses and unknown IPv6 traffic is rejected **inside the TUN**, not leaked Direct. An operator with independently verified selected exit IPv6 can opt in using `connect-smart --enable-selected-ipv6`; this is an explicit assertion, **not an automatic capability check**. System/underlay DNS and protected Direct exceptions are separately scoped. Real field default HTTPS, IPv6 leak/positive cases and recovery must pass on the exact candidate before release.

## Where the project truth lives

- [Project specification](docs/PROJECT-SPEC.md): durable product goal, three modes, scope and boundaries.
- [Architecture](docs/ARCHITECTURE.md): official-Core runtime, packet decisions, components and resource ownership.
- [Safety and recovery](docs/SAFETY-RECOVERY.md): activation/health supervision, precise rollback, unsafe/uncertain states and legacy compatibility.
- [Distribution](docs/OFFLINE-DISTRIBUTION.md): official/mirror/offline trust, shared installer and update/rollback.
- [Acceptance](docs/ACCEPTANCE.md): required evidence, physical-vs-guest boundaries and test procedures.
- [AGENTS.md](AGENTS.md): contributor and independent-review rules.

**Active work, dependencies, release gates and deferred ideas:** consult the [GitHub Issues](https://github.com/AChWorks/server-connect/issues) rather than a potentially stale issue-by-issue status copy here. PRs, Actions and Releases own exact SHA-specific execution evidence.

**License:** Original Server Connect source is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](LICENSE), following [AChrix](https://github.com/AChWorks/achrix). This license covers the project's first-party code, **not** separately licensed upstream binaries, vendored code or data: sing-box and Chocolate4U retain GPL-3.0 obligations, DB-IP Lite is CC BY 4.0, vendored Go code retains its own notices, and Public Suffix List data has its own MPL-2.0 provenance. The QA bundle carries the first-party `LICENSE` and separate third-party notices; choosing MPL-2.0 does **not** approve public distribution, publisher identity or upstream redistribution rights.
