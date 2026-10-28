# Server Connect — Project Specification

**Purpose:** This is the canonical, long-lived product definition. It states **what Server Connect must achieve and why**, its boundaries, and the direction of development. Implementation design, safety procedures, packaging details, acceptance tests, current tasks, and evidence belong to their respective sources linked below.

## Vision

Server Connect is a lightweight, offline-first Linux connectivity manager for servers, particularly Iran-hosted aaPanel, WordPress, and general hosting systems. It should make a compatible outbound VPN usable **as simply as enabling TUN in a desktop VPN client**, without configuring each application, while keeping administrator access, hosted services, and domestic networking safe.

The product manages a selected upstream connection using **official sing-box** and native Linux facilities. It is not a VPN provider or a new networking protocol. It cannot overcome an entirely unavailable underlying network path.

## User-visible behavior

The product has **three modes**:

| Mode | Intended outcome |
| --- | --- |
| **Direct** | Normal host networking, without active Server Connect interception. |
| **Proxy Only** | Optional explicit HTTP/SOCKS proxy use by applications that opt in. |
| **Smart Routing (TUN)** | Transparent routing of supported ordinary outbound host traffic, regardless of application proxy awareness. |

When Smart Routing is enabled, its **default destination policy** is:

1. Keep local/private/on-link traffic, verified protected administrator and hosting reply paths, and the VPN endpoint's own underlay safe and Direct.
2. Honor explicitly configured **domain, IP, CIDR, and trusted rule-list** exceptions with clear precedence, without overriding essential host protections.
3. Route validated **Iranian public IP ranges Direct** using locally available versioned data.
4. Route **other public outbound destinations through the VPN by default**.

Operators can manage rules manually and use trusted local or updated lists. A foreign destination may be explicitly allowed Direct if it works without the VPN. Automatic reachability-based selection is an **optional later refinement**, not necessary to deliver the core mode.

**Transparent means network-level routing, not per-process selection.** Users must not need to identify aaPanel jobs, PIDs, process trees, or individual application's proxy settings. The desired breadth includes common TCP, UDP, DNS, IPv4 and IPv6 traffic wherever the actual Linux environment and upstream transport support it. Unsupported paths must be identified rather than silently bypassing required VPN routing.

## Installation and operation

One independently authenticated, complete, versioned bundle and **one shared installer** must support:

- **Official online** installation and update.
- **Operator-hosted online mirror**, including a static Iranian web host holding the same verified release bytes.
- **Manual upload and fully offline** installation and update, with no network downloads on the target.

Operators should manage compatible profiles, routing rules, connection state, diagnostics, safe Disconnect, updates, and recovery through one understandable menu and stable CLI. When off, the original host routing should remain intact. Avoid mandatory cloud management, additional background services while unused, and unnecessary resource consumption.

## Non-negotiable boundaries

- Protect existing and new SSH/administrative access, aaPanel, websites and **their replies to foreign visitors**, local/connected routes, VPN bootstrap, and third-party network owners.
- Any host-affecting routing activation requires an independently effective **Activation Guard** and exact owned-resource rollback. Active routed operation requires an independent **Runtime Health Guard**; failures must not silently leak VPN-required traffic Direct.
- Privileged changes must be narrow, reversible, independently testable and conservative when host networking is ambiguous.
- No speculative per-job routing framework, second VPN data plane, universal plugin system, or mandatory multi-profile concurrency.
- **Inbound foreign website access is separate from outbound VPN.** An **optional, separately controlled Cloudflare Tunnel** integration may publish operator-approved HTTP(S) origins over a reachable outbound connector. It must not become a prerequisite for outbound VPN use or claim universal raw public TCP/UDP forwarding.

## Delivery direction

1. Preserve the already established Direct/Proxy Only and shared installation foundation; do not expand obsolete application/job diagnostics.
2. Make **real Smart Routing TUN** work end-to-end on disposable Linux, proving independent Direct/VPN packet paths and safe coexistence.
3. Complete independent activation/runtime protection, recovery and practical operator controls.
4. Validate official, mirror and offline installation/update, real supported traffic paths, compatibility, resource footprint and release authenticity before the first stable outbound-capable release.
5. Add the optional Cloudflare website connector and any other future features **only as separate, justified work**. Concurrent active VPN profiles are deferred, not a dependency.

A release is complete only for the features **actually implemented, independently validated, documented and safely distributed**. Source tests, isolated simulations or a successful Windows VPN profile alone do not establish production-ready Linux TUN or Iran-datacenter connectivity.

## Detailed contracts

- [Architecture](ARCHITECTURE.md) — components, traffic-policy mechanics, routing and resource ownership.
- [Safety and recovery](SAFETY-RECOVERY.md) — activation, independent health protection, failure policy and rollback.
- [Distribution](OFFLINE-DISTRIBUTION.md) — authenticated official/mirror/offline package and installation lifecycle.
- [Acceptance](ACCEPTANCE.md) — reproducible test matrix, evidence thresholds and historical lessons worth retaining.

**Work and history live in their natural systems:** GitHub Issues track remaining tasks; PRs, CI and Releases track implementation and evidence. They do not redefine this specification.
