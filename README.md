# Server Connect

**Status: Development candidate — no signed or published installable release is available yet.**

Server Connect is an **offline-first Linux server connectivity manager** for administrators of hosting servers, including Iran-based servers running aaPanel, WordPress, and other web services. Its goal is to provide simple, controlled access to external networks when direct connections are unavailable, without disrupting SSH, domestic routes, hosted websites, or other server workloads.

The initial connectivity engine is **sing-box**. Rather than reinventing VPN protocols, Server Connect will manage compatible connection profiles, selective proxy/tunnel routing, safe activation, continuous connection health checks, and automatic recovery when a configured route fails.

## Planned operating modes

| Mode | Intended behavior |
| --- | --- |
| **Direct** | Keep the existing server network unchanged; the default when no profile is active. |
| **Proxy Only** | Use a local proxy for explicitly selected downloads, updates, or applications without changing the host's default route. |
| **Selective Tunnel** | Route selected external traffic through the active profile while preserving domestic and protected management/service paths. |
| **Broad Tunnel** | Route a wider, explicitly chosen set of outbound traffic through the profile, with host safety exceptions. |

A tunnel-affecting change must pass a guarded activation and an operator confirmation window before it is committed. If an active profile stops working, independent health/recovery mechanisms must restore the selected safe network policy. **Checking whether websites are reachable from abroad is optional**, depending on the operator's goal; a client VPN alone does not grant public inbound connectivity.

Direct and single-active-profile Proxy Only are implemented as **development candidates** and tested with a local genuine sing-box VLESS TCP relay; guarded host-wide routing and automatic recovery are **not implemented or accepted**. A profile that works in Windows v2rayN/Karing may not be reachable from a particular Linux datacenter. No VPN protocol can restore international connectivity when the underlying network has no usable path.

Future multi-active profiles and per-workload outbound selection are [parked in Issue #7](https://github.com/AChWorks/server-connect/issues/7), not required for the first release. Profile identity, traffic policy and the data-plane runtime are distinct future migration boundaries; the MVP's single active selection and internal sing-box tag are not permanent API promises. Public ingress, Marzban/Xray node forwarding and Backhaul-like relays are separate operator-owned deployments, not an effect of activating an outbound VPN.

## Planned installation experience

Two equally supported one-command installation paths are planned: **Online**, where a trusted bootstrap fetches and verifies the exact compatible release and required prerequisites on a connected host, and **Offline**, where an operator downloads a complete trusted bundle elsewhere, copies one folder to the target, and runs one local command without foreign connectivity. Both paths use the **same installation, update, uninstall, validation, state and recovery logic**. Offline-first means offline operation is fully supported, **not** that installation must be offline.

A development-only `install.sh`, Go CLI, pinned-core packaging script and online bootstrap **candidate** now exist in source. They have **not** been authenticated or published as a release; the offline/online installed-host support matrix and redistribution gate remain open. Do not treat illustrative release URLs or commands in design documents as operational installation instructions.

## Development candidate checks (not a released installer)

The current initial Linux target is **Debian 13 / amd64**. The manager is implemented in Go using only the standard library. Run `go test ./...` for source tests. Optional genuine local VLESS core tests require `SC_TEST_SINGBOX=/absolute/path/to/the/pinned/sing-box` and `go test ./...`. To create a **local QA-only** bundle from the separately fetched and digest-verified official upstream archive, run `scripts/package.sh /path/to/sing-box-1.14.3-linux-amd64.tar.gz`. The resulting artifact is not a public release; its local checksum alone is not a publisher signature.

The online bootstrap candidate at `scripts/bootstrap-online.sh` requires an explicit HTTPS archive URL and independently obtained SHA-256 digest; it downloads the **complete** offline bundle and invokes the **same** local installer. Actual online installation requires root-owned staging from the beginning; non-root `--verify-only` remains possible. A short public one-line release command must wait for the Owner-approved release endpoint, publisher authentication and license decision. Never use a made-up download URL or execute unverified release code as root.

### Read-only host network preflight (Issue #2 development)

On a Linux host with trusted native `/usr/bin/ip`, `server-connect --json host-preflight --endpoint 198.51.100.10 --management-peer 203.0.113.42` records actual IPv4/IPv6 routes, rules, links and kernel route lookups for **literal IPs**. Broadcast, multicast, unspecified, IPv4-mapped IPv6 and link-local addresses without a usable interface scope are rejected before native inspection; private IPv4, IPv6 ULA and loopback literals remain supported. It does not resolve DNS, touch state, enable a tunnel, change kernel networking or prove those peers are reachable. Both peer arguments are optional; supplying them is useful for future underlay and management-path planning. The report deliberately says `activation_ready: false` and `snapshot_atomic: false`: it is **not** an ownership journal, firewall inspection, activation authorization or replacement for the independent guards and SSH/reboot/field acceptance specified in Issue #2. This is a dependent development feature, not a released installation instruction.

### Proxy Only compatibility and application opt-in

- The link importer deliberately supports a **subset** of VLESS TCP/WebSocket and TLS/Reality query fields, rejecting unrecognized or incompatible parameters. **Local TCP VLESS through the pinned sing-box core has live integration evidence; TLS/WebSocket/Reality interoperability with real foreign providers is NOT_RUN.** Import and `validate` establish syntax/core-configuration acceptance, not remote reachability.
- A selected application may opt in explicitly with `server-connect exec -- curl ...`, or with its own authenticated HTTP/SOCKS proxy settings. `server-connect probe --via proxy --url https://...` tests the selected path; `--via direct` independently tests host Direct connectivity. These commands require an already installed, selected and running development candidate.
- **Multi-target, read-only path diagnostics (Issue #3 foundation; not an active health guard):**
  `server-connect --json diagnose-path --via proxy --url https://one.example --url https://two.example`
  checks two to four distinct hostnames through the selected Proxy Only transport, with **no Direct fallback**.
  Run an independent `--via direct` invocation for the Direct baseline; Direct successes never count as Proxy
  results. Responses contain only target indexes, bounded HTTP codes/error classifications, counts, and
  `all_targets_reachable`, `mixed_results`, or `no_targets_reachable`; no URL, query or credentials are returned.
  A single failed target returns `probe_set_partial`, **not** proof of a dead VPN. Redirects are never followed;
  HTTP 3xx is `probe_redirect_unverified`, not verified destination content. At most four 12-second target
  requests are made, without modifying host routes or firewall. Results explicitly mark
  `tunnel_health_verified: false` and `activation_ready: false`. The existing selected-proxy lookup may
  initialize private application state. These checks **do not attest foreign egress identity, independently
  prove VPN-bound TUN routing, supervise a live tunnel, recover automatically, or replace the Activation or
  Runtime Health Guards**. Real foreign-provider, reboot and field acceptance remain NOT_RUN.
- **APT does not reliably honor generic HTTP proxy variables.** The opt-in `sudo server-connect apt -- apt-get update` (or menu option **9**, confirmed with `UPDATE`) explicitly configures `Acquire::http::Proxy` and `Acquire::https::Proxy` only for that child process. Native, root-owned Debian APT executables at `/usr/bin/apt-get`, `/usr/bin/apt` and `/usr/bin/apt-config` are verified before any proxy credential is accessed. Unqualified `apt-get` and `apt` are accepted only when PATH resolves to their native installation; `/bin` aliases from Debian usrmerge are also supported. Other same-basename programs, PATH shadows and substituted binaries are refused. The child runs with a fixed trusted PATH and without inherited proxy/loader overrides. The private proxy config is an unlinked mode-0600 descriptor; `/etc/apt` is never modified. Existing per-host `DIRECT`/proxy policy, proxy autodetection, untrusted extra config and conflicting caller overrides cause a clear fail-closed error. The **full APT execution path** is checked: the effective Debian 13 `Dir::Bin::*` native-method/compressor paths, `RootDir`/`Dir` roots, applicable binary-specific redirections and **all present native acquisition-method executables** (including PDiff `rred` and `mirror`) plus their exact native aliases must match the supported trusted installation. Missing optional Debian 13 helpers are accepted; unknown or untrusted additional transport methods are not supported. Caller method/root/compressor overrides are rejected *before* credentials are loaded; inherited conflicts cause a credential-safe policy error rather than rewriting system APT configuration. Custom APT method directories and redirected execution layouts are not yet supported. Standalone `apt-get update` and `apt update` enforce `--error-on=any`, even when cached indexes exist. Combined `-U`/`--update` package operations are deliberately **unsupported**: use a separate strict `apt-get update`, followed by the intended `apt-get install` command. APT retains its ordinary repository signatures and HTTPS verification; do not downgrade repository trust. Only the APT acquisition transport is covered, not arbitrary maintainer scripts or other applications. Never enable wire-debug traces that could expose `Proxy-Authorization` credentials.
- **WordPress/PHP-FPM and plugins may use different HTTP clients or ignore shell environment variables.** For WordPress, an explicitly configured supported HTTP transport/proxy integration, isolated site test, and restoration plan are necessary; `server-connect exec` alone is not proof of WordPress API compatibility. Do not globally rewrite APT, PHP-FPM, aaPanel or customer proxy configuration. A disposable WordPress 7.1.3 + SQLite backend PHP CLI test of real \`wp_remote_get()\` using operator-set \`WP_PROXY_*\` succeeded over the actual installed Server Connect + pinned VLESS, and failed closed when the upstream died. This **does not** establish PHP-FPM/aaPanel coexistence, live site compatibility, safe persistent secret provisioning or foreign-provider field operation; the product never edits a WordPress site automatically.
- A user-facing inbound VPN/relay service (for example Marzban Node or Backhaul) does not automatically opt into `HTTP_PROXY`. Raw TCP/UDP forwarding and established inbound reply paths require their own explicitly verified routing/relay architecture.

The current Go JSON/CLI and offline installer are **not production-supported interfaces** until review findings and exact-artifact acceptance are resolved.

## Documentation and project status

| Source | Responsibility |
| --- | --- |
| [Project specification](docs/PROJECT-SPEC.md) | **Canonical** product goals, behavior, constraints, and non-goals |
| [Architecture](docs/ARCHITECTURE.md) | Component boundaries, host resource ownership, and upstream reuse |
| [Safety and recovery](docs/SAFETY-RECOVERY.md) | Guarded activation, health monitoring, rollback, and crash/reboot safety |
| [Online and offline distribution](docs/OFFLINE-DISTRIBUTION.md) | Both installation paths, release trust, updates, and shared lifecycle |
| [Acceptance criteria](docs/ACCEPTANCE.md) | Reproducible test matrix and evidence needed before release |
| [Contributor instructions](AGENTS.md) | Engineering, review, and project-continuity rules |
| [GitHub Issues](https://github.com/AChWorks/server-connect/issues) | Current work, dependencies, and release acceptance |

**Development starts with [Issue #1 — Offline-first sing-box Proxy Only](https://github.com/AChWorks/server-connect/issues/1)**. Implement and validate it on disposable Linux hosts before advancing to host-wide routing. No production server change is authorized by this repository.

## Boundaries and security

Server Connect owns only its own host changes. It must not take over unrelated firewall rules, SSH settings, aaPanel services, other tunnels, or customer applications. It is **not** a VPN provider, public relay network, reverse proxy, or new packet-forwarding engine.

Do not commit real VPN subscriptions, endpoints containing credentials, customer details, secrets, private keys, or runtime state.

## License status

The repository is publicly readable, but **no software license has been selected**. Public visibility does not grant general rights to reuse or redistribute the code. Any open-source license or binary redistribution policy requires an explicit project-owner decision.
