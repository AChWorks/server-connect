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

1. **Three acquisition choices, one shared installer:** official online download, operator-selected HTTPS **Iranian/static mirror** of the same immutable authenticated bundle, or manual upload and local offline install with **zero attempted network fetches**. One versioned OS/architecture-specific complete bundle, one installer and one update/uninstall/recovery lifecycle serve all three. The mirror is a byte source, not a separate publisher trust authority; the bootstrap must itself be trusted before privileged execution.
2. **Easy daily use:** menu and stable noninteractive CLI support import/validate/list/select/test profiles; Connect, Disconnect, Status, Diagnostics, Recovery, and Online/Offline Update. Switching off removes the product's networking effects. Machine callers use structured output, never scrape interactive menus.
3. **Three simple modes:** **Direct**, existing opt-in **Proxy Only**, and **Smart Routing** — real sing-box Linux TUN/system routing for transparent host-origin outbound traffic. Iran/private/protected paths stay Direct; other public destinations use VPN by default, except operator-controlled domain/IP/CIDR or verified list exceptions. No separate Selective/Broad engines or per-application/job routing framework.
4. **First connectivity core:** **sing-box**, with an immutable validated version per distribution bundle. Reuse upstream VPN/data-plane implementation; do not build a novel tunnel protocol or packet-forwarding engine. Additional upstream cores/protocols require demonstrated compatibility gaps and bounded adapters, not a speculative plugin framework.
5. **Real-world profile compatibility:** first support validated sing-box profiles and a demonstrably compatible VLESS link/import journey. Do not claim all v2rayN/Karing, WireGuard, OpenVPN or L2TP formats work before adapter-specific evidence. Optional additional protocols remain replaceable, not mandatory MVP dependencies.
6. **Host safety:** preserve direct Iranian networking, site availability, SSH, aaPanel and third-party services; prevent proxy recursion, accidental route hijacks, asymmetric reply routing, DNS/IPv6 bypasses, and unowned firewall mutations. Only manage exactly attributed resources; do not assume all network state is product-owned.
7. **Bounded, independent rollback on activation:** host-affecting network changes require pre-armed, crash/reboot-aware **Activation Guard**. Default confirmation window: **10 minutes, operator-configurable**. A successful command/session is not proof of reachability.
8. **Automatic recovery during ongoing use:** independent **Runtime Health Guard** detects an unusable active profile by **path-bound real probes**, not a single ICMP ping or a direct-path false positive. On confirmed failure the product promptly removes/undoes its failed routing effects and returns to the last safe, independently valid baseline (by default ordinary Direct routing), applying any explicitly configured fail-closed policy for selected traffic. A failed, stalled or unexpectedly disabled health supervisor must not leave a routed VPN running indefinitely without protection.
9. **Flexible acceptance and failure policy:** users choose purpose-specific probes, thresholds and failure responses. Public ingress is **not** mandatory for outbound Smart Routing; if explicitly enabled as a test or separate Cloudflare connector, prove a fresh uncached external request reached the actual origin, not just a CDN response.
10. **Low footprint:** no permanent global routing change while off; do not require an external dashboard, cloud controller, always-on data plane when unused, or broad new runtime dependencies. Quantify performance on representative hosts rather than promising an unmeasured memory/CPU budget.
11. **Optional website ingress after core egress:** offer an operator-authorized **Cloudflare Tunnel/cloudflared** integration for HTTP(S) origins whose foreign visitors cannot directly reach the Iran host. Its outbound connector may need the Smart Routing VPN; it is independently controlled and health-checked and is **not** a general raw TCP/UDP public-ingress or mandatory first outbound-release feature. See [Issue #48](https://github.com/AChWorks/server-connect/issues/48).

## 3. Operating modes and semantics

| Mode | Default behavior | Network risk |
| --- | --- | --- |
| Direct | Existing host network unchanged | No host routing change |
| Proxy Only | Existing opt-in SOCKS/HTTP application proxy without host interception | Low |
| Smart Routing (TUN) | All supported ordinary host-origin outbound traffic follows one Iran-Direct / other-public-VPN destination policy with explicit exceptions | High: independent Activation and Runtime Guards required |

### Smart Routing — transparent host-level destination policy

**The default routing selector is the destination, never a process or aaPanel Job.** A real sing-box Linux TUN plus the required host routing/policy captures ordinary outbound traffic from aaPanel, APT, Git, WordPress, Python, installers and non-proxy-aware programs without per-application configuration. No PID, process-tree, socket, UID, cgroup or job-specific selector is required. Existing read-only process diagnostics are optional historical troubleshooting features, not an MVP or release prerequisite.

**Deterministic rule priority:**
1. **Protected infrastructure:** connected/private/local addresses, current/new management access, already established website replies including foreign clients, VPN server underlay and bootstrap DNS use separately verified safe Direct/control routing. No user list may override a critical control-path protection.
2. **Operator exceptions:** exact domain/suffix, IP or CIDR, and locally imported trusted rule sets can explicitly select Direct or VPN. Expose effective priority, overlaps and conflicts, and permit manual overrides without editing application settings. A domain rule applies only when the DNS/sniff/routing path can genuinely associate that name with the flow; raw-IP traffic is classified by IP rules.
3. **Iranian public IPs:** locally bundled, versioned and validated Iranian IPv4/IPv6 prefixes use Direct; support authenticated online/mirror update and manual offline import with checks, safe replacement and rollback. IP-based country classification is imperfect, particularly for CDN/anycast/stale lists.
4. **Remaining public destinations:** selected VPN by default. Explicit foreign Direct rules do not need a built-in availability-learning engine. Optional Direct-first probes with VPN for **new connections** on Direct failure are secondary; never replay ambiguous or non-idempotent application requests.

**TUN-like breadth must be proved:** demonstrate transparent TCP, UDP, DNS and IPv4/IPv6 behavior for the advertised Linux environments and supported upstream transports, without shell proxy variables. Unsupported protocols, namespace boundaries or domain visibility are **explicit support limitations**, not silent Direct bypasses. Traffic requiring VPN must fail closed rather than leak if VPN transport cannot carry it. A fully blocked international underlay cannot be bypassed by software alone.

**Host invariants:** preserve SSH, aaPanel, native inbound-hosted HTTP(S) replies (even when foreign client IPs), Docker/Fail2Ban/existing firewall/network owners, direct local/Iran paths, and VPN endpoint underlay. Prearm/verify independent Activation Guard before owned route/rule/firewall mutations; retain Runtime Health Guard and exact-resource rollback while active. Off/Direct must restore only owned effects.

**Proxy Only** is still a useful explicit low-risk option and retains its current safe opt-in behavior, but is never a substitute for the whole-host TUN.

### Optional inbound websites: Cloudflare Tunnel

A separately enabled **cloudflared** connector creates an outbound tunnel to Cloudflare and publishes explicitly approved HTTP(S) hostnames to a specified local origin. This is a **post-core optional integration**, not automatic public ingress supplied by a VLESS client. It may use Smart Routing/VPN when Cloudflare is not reachable Direct, but requires a separately proven connector path; if all external underlay paths fail, no tunnel is guaranteed. The operator controls the Cloudflare account/domain, secret, DNS change and origin; Server Connect must not silently claim/overwrite aaPanel, Nginx, ports, DNS records, existing tunnels or third-party routing.

Connector start/stop/health/rollback must be independent of outbound VPN health. For origin acceptance, prove a fresh uncached external request reaches the actual origin; unselected ingress checks never stop a healthy outbound VPN. Standard public website routing is HTTP(S); arbitrary public TCP/UDP port forwarding is **not** promised, and non-HTTP Cloudflare use cases may require client-side software or another service. See [Issue #48](https://github.com/AChWorks/server-connect/issues/48) and [Cloudflare Tunnel documentation](https://developers.cloudflare.com/tunnel/).

### Deferred expansion boundaries (not MVP or first-release acceptance)

- **Stored profiles are not active paths.** The current manager selects one active outbound. Preserve stable stored profile IDs and migratable private state. Concurrent profiles and their selection policies are [Owner-deferred in #7](https://github.com/AChWorks/server-connect/issues/7), not requirements for MVP or the first release; do not build per-job/per-workload infrastructure in anticipation.
- **Policy and runtime remain distinct.** Direct reachability is not proof of VPN health. Preserve explicit VPN-required fail-closed behavior and backward-safe state migration; do not turn an internal singleton tag or schema into a permanent public API.
- **Other inbound relays are separate products/use cases.** Cloudflare Tunnel for optional web origins does not implement a Marzban/Xray Node, Backhaul, raw TCP/UDP port forwarder or VPN-selling service. No such feature is an MVP obligation.


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

- **Online official or operator mirror:** a trusted bootstrap fetches exactly the authenticated compatible release and prerequisites from the official endpoint or an operator-chosen HTTPS static mirror (including an Iranian host). The same immutable publisher trust applies regardless of source; a mirror-served installer is authenticated **before privileged execution**. No unverified dependencies or silent host network changes; an unreachable source offers mirror/manual alternatives.
- **Manual offline upload:** the **same complete authenticated bundle** carries the manager, pinned sing-box, local Iranian IP/rule lists, templates and all otherwise-required local packages for supported OS/architecture. Upload/extract one verified folder and execute one trusted local command; **no DNS/HTTP/package-download attempts**. Public install instructions remain gated by signing/licensing.
- One shared installer performs preflight, verification, staging, activation, update, uninstall and rollback for both paths; network acquisition is only a pre-verification input phase of online mode. Detect unsupported OS/architecture, kernel/TUN/systemd/network-tool availability and conflicts rather than guessing or altering global routing.
- Keep runtime credentials/config/state apart from replaceable binaries, support staged online and offline updates and independently verified executable provenance. A checksum in the same untrusted archive is not an independent authenticity guarantee.
- Startup/shutdown/update/uninstall must preserve unrelated network and application state; ordinary uninstall should preserve operator credentials/config unless explicitly purged.
- Stable releases require evidence of all **three acquisition choices** (official online, operator HTTPS mirror, manual offline) converging on identical verified installation/update semantics, plus the agreed route/guard/disconnect/reboot/rollback matrix on real representative Linux hosts. Optional Cloudflare Tunnel is accepted on its own later gate.

## 8. Scope, reuse and non-goals

- **Independent AChWorks Linux CLI component** with its own lifecycle and protected state; it is not a new Foundation.
- **sing-box** is the initial external core. **STL** manages independent point-to-point private links and does not own arbitrary system-wide VPN policy. **SSO** manages server tuning and is not the connectivity manager. Both products have separate release and operating boundaries; integrate only when a real use case warrants it.
- No new VPN protocol, custom packet-forwarder, universal plugin framework, multi-server orchestrator, customer-facing hosting panel, mandatory SaaS, or automatic DNS/mirror rewriting in MVP.
- **Operator-hosted verified software mirrors and local routing-rule imports are accepted requirements**, not speculative DNS rewrites. Cloudflare Tunnel is an optional separate web-ingress feature; no generic relay or automatic mirror-selection service is needed.
- No obligation to support every OS, protocol, country-route feed, arbitrary network topology, or Windows client; publish only tested compatibility.

## 9. Validation and delivery contract

A release requires inspectable evidence of **its accepted scope**: authenticated official/mirror online and offline acquisition, one shared installer, safe Direct/Proxy Only, transparent Smart Routing preserving domestic/management/hosting across the advertised protocols, independent Activation/Runtime Guards, and representative resource measurements. An outbound-only first release need not implement optional Cloudflare website ingress; a release advertising that integration requires its separate field acceptance.

The precise scenarios, negative cases, evidence grades, and exact-artifact criteria are **owned by [ACCEPTANCE.md](ACCEPTANCE.md)**. A separate [release-gate Issue](https://github.com/AChWorks/server-connect/issues/5) tracks remaining release-specific work and authorization; it must not duplicate the full matrix. Passing simulations, source tests or a Windows connection is not evidence of working Iran-datacenter connectivity or safe installed-host routing. A healthy VPN cannot guarantee passage over a fully isolated underlying network.

## 10. Truth and implementation handoff

- This document holds accepted **product behavior and non-goals** only.
- docs/ARCHITECTURE.md owns the implementation boundary and host-resource model; docs/SAFETY-RECOVERY.md owns detailed transaction/probe/rollback behavior; docs/OFFLINE-DISTRIBUTION.md owns packaging assumptions and operator installation path; docs/ACCEPTANCE.md owns a reproducible test matrix and proof levels.
- README.md is the human entry point; AGENTS.md holds short contributor/recovery instructions; achworks.yaml is discovery metadata.
- GitHub Issues own **uncompleted work**, dependency order and release gates; PRs/CI own evidence. A replacement MASTER starts from current main, relevant Issues/PRs/CI and this document rather than chat history.
- Core version, manager language, final target OS/arch matrix, measured performance, and real field VPN/provider reliability remain **implementation/validation decisions**, not fictitious accepted test results. Do not widen support claims before proofs.

The contracts needed to implement this public project are self-contained in the repository documents linked above; access to another organization's private documentation is not a prerequisite.
