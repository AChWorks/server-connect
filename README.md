# Server Connect

**Status: Design and planning — no installable release is available yet.**

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

These are **accepted design requirements, not implemented or tested capabilities**. A profile that works in Windows v2rayN/Karing may not be reachable from a particular Linux datacenter. No VPN protocol can restore international connectivity when the underlying network has no usable path.

## Planned installation experience

The goal is a verified, self-contained release bundle that can be downloaded on another device, copied onto a Linux server, and installed with **one local command**, including when the target server cannot access GitHub or foreign package repositories. Bundled binaries, dependency checks, updates, and recovery must work offline for each advertised supported system.

**There is no installer, executable release, or supported host matrix yet.** Do not treat example paths or commands in the design documents as functional installation instructions.

## Documentation and project status

| Source | Responsibility |
| --- | --- |
| [Project specification](docs/PROJECT-SPEC.md) | **Canonical** product goals, behavior, constraints, and non-goals |
| [Architecture](docs/ARCHITECTURE.md) | Component boundaries, host resource ownership, and upstream reuse |
| [Safety and recovery](docs/SAFETY-RECOVERY.md) | Guarded activation, health monitoring, rollback, and crash/reboot safety |
| [Offline distribution](docs/OFFLINE-DISTRIBUTION.md) | Complete local bundle, release trust, installation, and update behavior |
| [Acceptance criteria](docs/ACCEPTANCE.md) | Reproducible test matrix and evidence needed before release |
| [Contributor instructions](AGENTS.md) | Engineering, review, and project-continuity rules |
| [GitHub Issues](https://github.com/AChWorks/server-connect/issues) | Current work, dependencies, and release acceptance |

**Development starts with [Issue #1 — Offline-first sing-box Proxy Only](https://github.com/AChWorks/server-connect/issues/1)**. Implement and validate it on disposable Linux hosts before advancing to host-wide routing. No production server change is authorized by this repository.

## Boundaries and security

Server Connect owns only its own host changes. It must not take over unrelated firewall rules, SSH settings, aaPanel services, other tunnels, or customer applications. It is **not** a VPN provider, public relay network, reverse proxy, or new packet-forwarding engine.

Do not commit real VPN subscriptions, endpoints containing credentials, customer details, secrets, private keys, or runtime state.

## License status

The repository is publicly readable, but **no software license has been selected**. Public visibility does not grant general rights to reuse or redistribute the code. Any open-source license or binary redistribution policy requires an explicit project-owner decision.
