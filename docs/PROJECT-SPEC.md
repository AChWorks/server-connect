# Server Connect — Project Specification

- Status: **Canonical product intent / initial Proxy Only candidate under development**
- Repository: **AChWorks/server-connect**
- Owner: **AChWorks**
- Authoritative for: **purpose, accepted behavior, safety invariants, scope, and delivery criteria**.
- Not authoritative for: live work (GitHub Issues/PRs), build identity (Git), released artifacts (Releases), installed-host state, or secrets.

## 1. Mission and users

Server Connect is a **small, offline-first Linux server connectivity manager** for operators of Iran-hosted servers, including aaPanel and multi-tenant WordPress/web hosting. It makes approved upstream VPN/proxy configurations usable on a server **without jeopardizing the server's ordinary network, management access, or hosted services**.

In normal conditions the host uses its direct Internet connection. A user may optionally activate a profile to reach unavailable/region-restricted foreign destinations, or—during severe international restrictions—to use a **demonstrably reachable** alternative path to the international Internet while domestic connectivity remains available.

Primary operator: a server administrator with root/sudo authority and an out-of-band recovery option. Affected parties: hosted sites and customers. This is **not** a consumer VPN service, public proxy network, or CDN.

A configuration working in Windows v2rayN/Karing is useful compatibility evidence, **not proof** that the same remote endpoint is reachable from a particular Iranian datacenter. No protocol can create international connectivity when no usable path exists.

## 2. Required outcomes

1. **Two easy one-command installation paths:** Online: on a connected host, a trusted one-line bootstrap automatically fetches and authenticates the compatible manager, pinned sing-box, and needed prerequisites before installing. Offline: download the complete authenticated OS/architecture-specific bundle elsewhere, copy one folder to the host, and run one local command with **zero attempted external downloads**. Both paths use the same installer, state, validation and lifecycle. Runtime operations, recovery and offline updates must work without foreign Internet or GitHub.
2. **Easy daily use:** menu and stable noninteractive CLI support import/validate/list/select/test profiles; Connect, Disconnect, Status, Diagnostics, Recovery, and Online/Offline Update. Switching off removes the product's networking effects. Machine callers use structured output, never scrape interactive menus.
3. **Choice of traffic scope:** allow **Direct** (default), **Proxy Only** for selected applications/downloads/updates, **Selective Tunnel** for chosen foreign traffic while retaining domestic/direct and protected hosting/management flows, and **Broad Tunnel** for a larger user-selected outbound scope. Not every mode needs host-wide TUN.
4. **First connectivity core:** **sing-box**, with an immutable validated version per distribution bundle. Reuse upstream VPN/data-plane implementation; do not build a novel tunnel protocol or packet-forwarding engine. Additional upstream cores/protocols require demonstrated compatibility gaps and bounded adapters, not a speculative plugin framework.
5. **Real-world profile compatibility:** first support validated sing-box profiles and a demonstrably compatible VLESS link/import journey. Do not claim all v2rayN/Karing, WireGuard, OpenVPN or L2TP formats work before adapter-specific evidence. Optional additional protocols remain replaceable, not mandatory MVP dependencies.
6. **Host safety:** preserve direct Iranian networking, site availability, SSH, aaPanel and third-party services; prevent proxy recursion, accidental route hijacks, asymmetric reply routing, DNS/IPv6 bypasses, and unowned firewall mutations. Only manage exactly attributed resources; do not assume all network state is product-owned.
7. **Bounded, independent rollback on activation:** host-affecting network changes require pre-armed, crash/reboot-aware **Activation Guard**. Default confirmation window: **10 minutes, operator-configurable**. A successful command/session is not proof of reachability.
8. **Automatic recovery during ongoing use:** independent **Runtime Health Guard** detects an unusable active profile by **path-bound real probes**, not a single ICMP ping or a direct-path false positive. On confirmed failure the product promptly removes/undoes its failed routing effects and returns to the last safe, independently valid baseline (by default ordinary Direct routing), applying any explicitly configured fail-closed policy for selected traffic. A failed, stalled or unexpectedly disabled health supervisor must not leave a routed VPN running indefinitely without protection.
9. **Flexible acceptance and failure policy:** users choose purpose-specific probes, thresholds, failure response and, where relevant, confirmation of foreign access to hosted sites. **Public ingress from abroad is not required for a downloads/updates-only use case.** If ingress is selected as an acceptance condition, prove a fresh uncached foreign request reached the real origin; operator confirmation alone or a cached CDN response is insufficient.
10. **Low footprint:** no permanent global routing change while off; do not require an external dashboard, cloud controller, always-on data plane when unused, or broad new runtime dependencies. Quantify performance on representative hosts rather than promising an unmeasured memory/CPU budget.

## 3. Operating modes and semantics

| Mode | Default behavior | Network risk / activation | Foreign ingress |
| --- | --- | --- | --- |
| Direct | Existing host network unchanged; sing-box optional/stopped | No host routing change | Not a condition |
| Proxy Only | Local loopback/Unix-socket proxy for explicit applications; no global default-route change | Low; local configuration/validation | Not a condition |
| Selective Tunnel | User-approved foreign destinations through chosen profile; Iran/internal and protected management/service reply traffic direct | High; Activation Guard mandatory | Optional, if selected by operator |
| Broad Tunnel | Wider outbound policy with explicit hosting/management/underlay exceptions | High; Activation Guard mandatory | Optional, if selected by operator |

Policies apply to **outbound connectivity**. Incoming public traffic from abroad is a separate concern: a typical paid VLESS/consumer VPN profile does not grant public inbound ports. If an operator chooses foreign-origin site reachability, an existing CDN/reverse relay can be used **through the VPN where reachable**, or a separately approved inbound architecture may be required. Never promise that switching on a VPN automatically opens the website or SSH globally.

The tool must let users keep the website/SSH ingress goal out of scope, test it optionally, or make it an explicit acceptance gate for a hosting-oriented activation. Paid-gateway/IP-allowlisted APIs, SMTP and other applications may need independent route and fail-closed policy.

**Proxy Only** must also be safe when the VPN core stops: prefer opt-in per-command/application proxy settings. If Server Connect itself creates persistent application-level proxy settings, it must remove or restore exactly those owned changes on disconnect, failure and uninstall; never overwrite operator-managed settings or leave clients unintentionally pointing at a dead local proxy.

## 4. Safety invariants

- Fresh install and post-uninstall baseline is **Direct with no product-owned host-wide interception**. A verified explicitly persistent active configuration may be restored after reboot only under the same safety checks; a pending/unverified activation must not silently become committed.
- **Preflight -> snapshot/journal -> arm independent recovery -> verify guard armed -> apply narrow changes -> path-specific verify -> operator confirmation when required -> commit.** No risky apply if a trustworthy recoverable baseline cannot be captured.
- Resource attribution and ownership checks cover routes, rules, interfaces, local listeners, firewall/nftables fragments, resolver modifications (if ever separately authorized), service units and credentials. Do not flush tables, overwrite the global firewall, alter aaPanel/Fail2Ban/Docker/STL resources, stop foreign services, or reset host networking blindly.
- Capture and preserve the existing management/control path, the route to the VPN endpoint (underlay), and established inbound connection reply behavior. Bootstrap endpoint addressing/DNS must be possible on a path available **before** establishing the VPN; tunneled DNS policy must not create loops or require unowned global resolver rewrites. Model conntrack, policy routing, IPv4/IPv6, reverse path filtering, DNS, MTU and third-party networking as risks to test, not universal guesses.
- State-changing operations use stable operation identity, durable atomic records, exclusive ownership/locking, idempotent observe/repair behavior and explicit **UNKNOWN/CONFLICT** states; no blind replay after ambiguous effects.
- Rollback means **restore the owned network delta to a verified safe baseline**, not magically restore lost international Internet, and not overwrite third-party changes made while a profile was active. Conflict/uncertain ownership must remain visible and conservatively contained.
- No credentials, VLESS URLs, provider subscriptions or private keys in Git, logs, diagnostic exports or release bundles. Installed private state and operator configuration have restrictive permissions.
- Global Direct fallback must not silently leak traffic marked **VPN-required**: retain narrow fail-closed egress restrictions for those designated flows while preserving normal hosting, domestic routing and emergency control. This is configurable, not an unconditional host-wide kill switch.
- No production deployment/host-network change without separate authorized rollout, actual recoverability and high-assurance validation.

## 5. Activation Guard contract

High-risk route changes begin as **PENDING_CONFIRMATION**, with a default **600-second configurable** confirmation deadline. Before touching routes, journal the observed safe configuration (including absence), prepare a narrow resource delta and independently arm a local rollback mechanism that survives sing-box failure. Use a monotonic active-session deadline; recover pending journals safely on reboot, where an old timer alone does not suffice.

Collect configurable pass/fail probes for the selected goal:
- core/process/config health and a real outbound result constrained to the selected profile;
- domestic/direct reachability and no VPN endpoint routing loop;
- control/management path; for material host-routing changes, **new SSH session or explicitly authorized out-of-band console confirmation** bound to a fresh operation ID, not just a still-open old session;
- optional foreign website/origin verification only when explicitly enabled as a condition for this activation.

If a critical gate fails, deadline elapses, the process dies, reboot interrupts confirmation, or no valid acknowledgement arrives, restore the owned delta to the safe baseline. Stale acknowledgements and concurrent/conflicting activate attempts must not commit. On confirmation, atomically commit selected desired state and disarm that operation's deadline. Exact timing, bypass controls and acceptable confirmation channel must be visible before Apply.

The safeguard must be implemented independently of the upstream sing-box process. A timer/service may use native systemd facilities on supported systems, but its correctness requires durable recovery journals and reboot validation. Provider console/snapshot remains the out-of-band last resort; kernel failure cannot be fixed by an in-host script.

## 6. Runtime Health Guard contract

While a profile is enabled, monitor whether **its intended path is actually usable**. Evidence includes live process/interface/route state, authenticated TCP/TLS/HTTPS probes forced through the chosen outbound, distinct targets where sensible, and independent diagnostics for DNS and domestic/control connectivity. A single failed site or ping is insufficient to declare a dead VPN. No silent direct fallback on probes.

Probe intervals, startup grace and failure thresholds are operator-tunable; suggested initial values and exceptional fast-recovery cases are owned by [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md), subject to actual field validation rather than fixed performance promises.

On confirmed failure: stop using the bad profile, recover product-owned network changes promptly, verify local/direct management and domestic reachability, record reason/operation ID, and apply the operator-selected policy:
- **restore_direct** (default): recover ordinary host routing; foreign connectivity might remain unavailable;
- **restore_previous_verified**: only when the previous profile is still independently testable and the transition is guarded;
- **hold_selected_egress**: recover host network, but block only user-designated VPN-required flows instead of leaking them direct.

Retries/failover must be bounded with cooldown/backoff and no unbounded reconnect flapping. Automatic profile selection/failover is **not required in the first slice**. A foreign ingress probe failure does not disable a healthy outbound VPN unless the user explicitly made ingress a required Runtime policy. Self-healing must not introduce greater outage risk than the original issue.

## 7. Packaging and lifecycle

- **Online path:** one documented command fetches a trusted bootstrap on a connected host; it downloads and verifies immutable, compatible release artifacts plus any required prerequisites, then invokes the **same local installer** used offline. No unverified/latest-at-random dependency execution, and no silent host network reconfiguration. An inaccessible remote source fails explicitly with an offline alternative.
- **Offline path:** a self-contained, independently authenticated, versioned bundle carries manager, pinned sing-box, rules/templates and all otherwise-required local packages for the supported OS/architecture. One folder + one command UX (target example, not yet runnable): **sudo bash /root/server-connect/install.sh --offline**. Offline mode makes **no DNS/HTTP/package-download attempt**; a missing prerequisite fails before mutation.
- One shared installer performs preflight, verification, staging, activation, update, uninstall and rollback for both paths; network acquisition is only a pre-verification input phase of online mode. Detect unsupported OS/architecture, kernel/TUN/systemd/network-tool availability and conflicts rather than guessing or altering global routing.
- Keep runtime credentials/config/state apart from replaceable binaries, support staged online and offline updates and independently verified executable provenance. A checksum in the same untrusted archive is not an independent authenticity guarantee.
- Startup/shutdown/update/uninstall must preserve unrelated network and application state; ordinary uninstall should preserve operator credentials/config unless explicitly purged.
- Stable releases require evidence of both installation paths, disconnect, online/offline update, interrupted apply, reboot and rollback on a supported real representative Linux host.

## 8. Scope, reuse and non-goals

- **Independent AChWorks Linux CLI component** with its own lifecycle and protected state; it is not a new Foundation.
- **sing-box** is the initial external core. **STL** manages independent point-to-point private links and does not own arbitrary system-wide VPN policy. **SSO** manages server tuning and is not the connectivity manager. Both products have separate release and operating boundaries; integrate only when a real use case warrants it.
- No new VPN protocol, custom packet-forwarder, universal plugin framework, multi-server orchestrator, customer-facing hosting panel, mandatory SaaS, or automatic DNS/mirror rewriting in MVP.
- DNS diagnosis and official signed mirror suggestions may later be added; do not treat them as required activation behaviors. Inbound hosting/relay integration is optional and must earn scope with practical use and safety evidence.
- No obligation to support every OS, protocol, country-route feed, arbitrary network topology, or Windows client; publish only tested compatibility.

## 9. Validation and delivery contract

A release requires independently inspectable evidence of **all accepted product outcomes**: authenticated online and offline installation/update on the exact advertised OS/arch; safe Direct and opt-in Proxy Only behavior; routed connectivity preserving domestic, management and hosting paths; both activation and ongoing-health recovery; operator-selected (never universally mandatory) foreign-origin checks; and representative resource measurements.

The precise scenarios, negative cases, evidence grades, and exact-artifact criteria are **owned by [ACCEPTANCE.md](ACCEPTANCE.md)**. A separate [release-gate Issue](https://github.com/AChWorks/server-connect/issues/5) tracks remaining release-specific work and authorization; it must not duplicate the full matrix. Passing simulations, source tests or a Windows connection is not evidence of working Iran-datacenter connectivity or safe installed-host routing. A healthy VPN cannot guarantee passage over a fully isolated underlying network.

## 10. Truth and implementation handoff

- This document holds accepted **product behavior and non-goals** only.
- docs/ARCHITECTURE.md owns the implementation boundary and host-resource model; docs/SAFETY-RECOVERY.md owns detailed transaction/probe/rollback behavior; docs/OFFLINE-DISTRIBUTION.md owns packaging assumptions and operator installation path; docs/ACCEPTANCE.md owns a reproducible test matrix and proof levels.
- README.md is the human entry point; AGENTS.md holds short contributor/recovery instructions; achworks.yaml is discovery metadata.
- GitHub Issues own **uncompleted work**, dependency order and release gates; PRs/CI own evidence. A replacement MASTER starts from current main, relevant Issues/PRs/CI and this document rather than chat history.
- Core version, manager language, final target OS/arch matrix, measured performance, and real field VPN/provider reliability remain **implementation/validation decisions**, not fictitious accepted test results. Do not widen support claims before proofs.

The contracts needed to implement this public project are self-contained in the repository documents linked above; access to another organization's private documentation is not a prerequisite.
