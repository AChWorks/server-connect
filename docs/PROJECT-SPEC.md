# Server Connect — Project Specification

- Status: **Canonical product intent / pre-implementation**
- Repository: **AChWorks/server-connect** (private)
- Owner: **AChWorks**
- Authoritative for: **purpose, accepted behavior, safety invariants, scope, and delivery criteria**.
Not authoritative for: live work (GitHub Issues/PRs), build identity (Git), released artifacts (Releases), installed-host state, or secrets.

## 1. Mission and users

Server Connect is a **small, offline-first Linux server connectivity manager** for operators of Iran-hosted servers, including aaPanel and multi-tenant WordPress/web hosting. It makes approved upstream VPN/proxy configurations usable on a server **without jeopardizing the server's ordinary network, management access, or hosted services**.

In normal conditions the host uses its direct Internet connection. A user may optionally activate a profile to reach unavailable/region-restricted foreign destinations, or—during severe international restrictions—to use a **demonstrably reachable** alternative path to the international Internet while domestic connectivity remains available.

Primary operator: a server administrator with root/sudo authority and an out-of-band recovery option. Affected parties: hosted sites and customers. This is **not** a consumer VPN service, public proxy network, or CDN.

A configuration working in Windows v2rayN/Karing is useful compatibility evidence, **not proof** that the same remote endpoint is reachable from a particular Iranian datacenter. No protocol can create international connectivity when no usable path exists.

## 2. Required outcomes

1. **One simple offline installation:** download an architecture/OS-appropriate complete trusted release on another machine, upload to a folder such as /root/server-connect/, and execute one documented local installation command. First-run, core start, profile import, routing, guard operation, recovery, and uninstall must not demand foreign Internet or GitHub. No hidden fetches or missing unbundled required artifacts.
2. **Easy daily use:** menu and stable noninteractive CLI support import/validate/list/select/test profiles; Connect, Disconnect, Status, Diagnostics, Recovery, and Offline Update. Switching off removes the product's networking effects. Machine callers use structured output, never scrape interactive menus.
3. **Choice of traffic scope:** allow **Direct** (default), **Proxy Only** for selected applications/downloads/updates, **Selective Tunnel** for chosen foreign traffic while retaining domestic/direct and protected hosting/management flows, and **Broad Tunnel** for a larger user-selected outbound scope. Not every mode needs host-wide TUN.
4. **First connectivity core:** **sing-box**, with an immutable validated version per distribution bundle. Reuse upstream VPN/data-plane implementation; do not build a novel tunnel protocol or packet-forwarding engine. Additional upstream cores/protocols require demonstrated compatibility gaps and bounded adapters, not a speculative plugin framework.
5. **Real-world profile compatibility:** first support validated sing-box profiles and a demonstrably compatible VLESS link/import journey. Do not claim all v2rayN/Karing, WireGuard, OpenVPN or L2TP formats work before adapter-specific evidence. Optional additional protocols remain replaceable, not mandatory MVP dependencies.
6. **Host safety:** preserve direct Iranian networking, site availability, SSH, aaPanel and third-party services; prevent proxy recursion, accidental route hijacks, asymmetric reply routing, DNS/IPv6 bypasses, and unowned firewall mutations. Only manage exactly attributed resources; do not assume all network state is product-owned.
7. **Bounded, independent rollback on activation:** host-affecting network changes require pre-armed, crash/reboot-aware **Activation Guard**. Default confirmation window: **10 minutes, operator-configurable**. A successful command/session is not proof of reachability.
8. **Automatic recovery during ongoing use:** independent **Runtime Health Guard** detects an unusable active profile by **path-bound real probes**, not a single ICMP ping or a direct-path false positive. On confirmed failure the product promptly removes/undoes its failed routing effects and returns to the last safe, independently valid baseline (by default ordinary Direct routing), applying any explicitly configured fail-closed policy for selected traffic.
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

## 4. Safety invariants

- Fresh install and post-uninstall baseline is **Direct with no product-owned host-wide interception**. A verified explicitly persistent active configuration may be restored after reboot only under the same safety checks; a pending/unverified activation must not silently become committed.
- **Preflight -> snapshot/journal -> arm independent recovery -> verify guard armed -> apply narrow changes -> path-specific verify -> operator confirmation when required -> commit.** No risky apply if a trustworthy recoverable baseline cannot be captured.
- Resource attribution and ownership checks cover routes, rules, interfaces, local listeners, firewall/nftables fragments, resolver modifications (if ever separately authorized), service units and credentials. Do not flush tables, overwrite the global firewall, alter aaPanel/Fail2Ban/Docker/STL resources, stop foreign services, or reset host networking blindly.
- Capture and preserve the existing management/control path, the route to the VPN endpoint (underlay), and established inbound connection reply behavior. Model conntrack, policy routing, IPv4/IPv6, reverse path filtering, DNS, MTU and third-party networking as risks to test, not universal guesses.
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

Initial configurable *candidates* (not performance guarantees): check every **15 seconds**, allow **30 seconds** connection grace, and classify confirmed failure after **three** consecutive unsuccessful probe rounds. Fatal process exit or loss of owned interface may bypass ordinary grace after identity verification.

On confirmed failure: stop using the bad profile, recover product-owned network changes promptly, verify local/direct management and domestic reachability, record reason/operation ID, and apply the operator-selected policy:
- **restore_direct** (default): recover ordinary host routing; foreign connectivity might remain unavailable;
- **restore_previous_verified**: only when the previous profile is still independently testable and the transition is guarded;
- **hold_selected_egress**: recover host network, but block only user-designated VPN-required flows instead of leaking them direct.

Retries/failover must be bounded with cooldown/backoff and no unbounded reconnect flapping. Automatic profile selection/failover is **not required in the first slice**. A foreign ingress probe failure does not disable a healthy outbound VPN unless the user explicitly made ingress a required Runtime policy. Self-healing must not introduce greater outage risk than the original issue.

## 7. Packaging and lifecycle

- Distribute a **self-contained, signed/independently authenticated, versioned offline bundle** tailored to supported OS/architecture and documented prerequisites. Include the manager, pinned sing-box executable, required rules/config/templates and all necessary compatible local packages for the advertised target; a shared generic installer may not guess missing downloads.
- One folder + one command UX (example target, not yet runnable): extract into /root/server-connect/ and run **sudo bash /root/server-connect/install.sh --offline**.
- Installer does not fetch dependencies; missing/unverifiable material is an explicit pre-mutation error. Preflight kernel/TUN/systemd/route-firewall tools, OS and architectural support; explicitly distinguish unsupported from broken.
- Keep runtime credentials/config/state apart from replaceable binaries, support staged offline updates and independently verified executable provenance. A checksum in the same untrusted archive is not an independent authenticity guarantee.
- Startup/shutdown/update/uninstall must preserve unrelated network and application state; ordinary uninstall should preserve operator credentials/config unless explicitly purged.
- Stable releases require evidence of install, disconnect, offline update, interrupted apply, reboot and rollback on a supported real representative Linux host.

## 8. Scope, reuse and non-goals

- **Independent AChWorks Linux CLI component** with its own lifecycle and protected state; it is not a new Foundation.
- **sing-box** is the initial external core. **STL** manages independent point-to-point private Links and does not own arbitrary system-wide VPN policy. **SSO** manages server tuning and is not the connectivity manager. Optional integration can occur later only for a proven real use case. AChrix is not a fit for this Linux CLI host-control workload.
- No new VPN protocol, custom packet-forwarder, universal plugin framework, multi-server orchestrator, customer-facing hosting panel, mandatory SaaS, or automatic DNS/mirror rewriting in MVP.
- DNS diagnosis and official signed mirror suggestions may later be added; do not treat them as required activation behaviors. Inbound hosting/relay integration is optional and must earn scope with practical use and safety evidence.
- No obligation to support every OS, protocol, country-route feed, arbitrary network topology, or Windows client; publish only tested compatibility.

## 9. Validation and delivery contract

A project candidate is ready for user-host release only with evidence of:
- **Offline** first installation/update on each advertised OS/arch, including no foreign network/GitHub, package authenticity and prerequisite failure handling.
- **Direct** pristine baseline and complete owned-state restoration after disconnect/uninstall/reboot.
- Real compatible **VLESS/sing-box** profile import and outbound probes from an actual Linux target; Windows success alone insufficient.
- **Proxy Only** use without touching site/SSH host routing.
- **Selective/Broad** correctness for Iranian routes, VPN endpoint underlay, established/new inbound SSH and HTTP(S), IPv4/IPv6 and DNS, fail-open/fail-closed policy, and third-party aaPanel/Fail2Ban/Docker network coexistence where claimed.
- **Activation Guard:** unconfirmed expiry, stale/wrong confirmation, loss of SSH, concurrent request, crash and reboot recover reliably.
- **Runtime Health Guard:** stopped core, broken upstream, partial DNS failure, unreachable one probe, confirmed multiple-probe outage, recovery/fallback, no routing leaks or flapping.
- **Optional ingress proof:** when selected, an external independent request with nonce and origin observation, not a CDN cache hit or unverifiable user's click.
- Representative CPU/RAM/latency/throughput before/after, with honest environmental limits.
- Independent high-assurance code review and real disposable-host integration before consequential production host-network changes.

Tests must distinguish unit/simulation, actual Linux namespace or VM, live tunnel/datacenter, installed artifact, and customer production. No simulated check is evidence of public-network passage. A healthy VPN cannot guarantee a hostile/fully isolated external network path.

## 10. Truth and implementation handoff

- This document holds accepted **product behavior and non-goals** only.
- docs/ARCHITECTURE.md owns the implementation boundary and host-resource model; docs/SAFETY-RECOVERY.md owns detailed transaction/probe/rollback behavior; docs/OFFLINE-DISTRIBUTION.md owns packaging assumptions and operator installation path; docs/ACCEPTANCE.md owns a reproducible test matrix and proof levels.
- README.md is the human entry point; AGENTS.md holds short contributor/recovery instructions; achworks.yaml is discovery metadata.
- GitHub Issues own **uncompleted work**, dependency order and release gates; PRs/CI own evidence. A replacement MASTER starts from current main, relevant Issues/PRs/CI and this document rather than chat history.
- Core version, manager language, final target OS/arch matrix, measured performance, and real field VPN/provider reliability remain **implementation/validation decisions**, not fictitious accepted test results. Do not widen support claims before proofs.

Relevant upstream contracts: [Koinon new-project intake](https://github.com/AChWorks/koinon/blob/main/docs/workflows/new-project-intake.md), [Linux distribution](https://github.com/AChWorks/koinon/blob/main/docs/contracts/linux-tool-distribution.md), [validation](https://github.com/AChWorks/koinon/blob/main/docs/contracts/validation-evidence.md), [external-effect safety](https://github.com/AChWorks/koinon/blob/main/docs/contracts/external-effect-safety.md).
