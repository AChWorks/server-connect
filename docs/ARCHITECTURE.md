# Architecture and integration boundaries

- **Status:** authoritative design contract; a Proxy Only development candidate has source and isolated installed-host CI evidence. Host-wide guarded routing, production guards and physical field acceptance remain unimplemented or unproven; this is not a released build.
- **Product requirements:** [PROJECT-SPEC.md](PROJECT-SPEC.md) — canonical.

The development-only product-integrated recovery foundation installs
checksum-verified systemd service/timer units, **disabled and inactive by
default**, and supports two strictly versioned, exact-operation experiments
inside a **disconnected, disposable Docker/systemd guest only**:

- **v2 rule-only:** the private v2 journal precedes one tagged IPv4 RPDB rule
  pointing to an otherwise empty, unused routing table; no route is added.
- **v3 loopback route + rule:** a separate v3 journal precedes one real IPv4
  route through the guest's existing `lo` interface into the selected table,
  followed by its matching destination-specific RPDB rule. No new link or
  tunnel is created. After the deadline or controller crash, recovery removes
  only the classified rule **before** the classified loopback route and
  confirms both are absent before marking the operation recovered.

Both experiments share the descriptor-pinned, fsync-backed private journal
and the same independently prearmed installed systemd recovery service/timer.
The service must reobserve native kernel identity and refuse foreign or
ambiguous resources, retaining the pending journal instead of flushing or
adopting another owner's objects. Neither experiment activates a TUN, a real
VPN path, production route policy or Runtime Health Guard. Production routed
modes remain unavailable pending complete Activation/Runtime Guards and
physical field acceptance. The ordinary Proxy Only installation does **not**
enable this timer or add these experimental kernel resources.

## 1. Shape

A single-host, offline-first CLI/terminal manager with a small control plane and **upstream sing-box** as the initial optional data plane. Avoid a universal daemon, a second VPN engine, a mandatory UI server or new Foundation.

~~~text
Operator / automation
     | menu / stable CLI+JSON
     v
Server Connect control plane
   |-- profile validation + protected configuration
   |-- reachability/diagnostics + routing policy planning
   |-- transaction coordinator + owned network resources
   |-- independent Activation Guard and Runtime Health Guard
   |-- official/mirror online fetch OR manual offline bundle -> one shared installer
     |
     +--> sing-box (pinned third-party core)
     |       | Proxy Only (loopback) or guarded TUN
     |       + selected remote VPN/proxy transport
     |
     +--> Linux kernel routing/nftables/conntrack/systemd (observed authority)
~~~

The menu and machine interface call the same application behavior; interactive presentation is not an automation contract. The system should be small enough to understand and uninstall; select implementation language and packaging only after the representative host capability spike.

## 2. Trust and ownership boundaries

| Boundary | Owner / rule |
| --- | --- |
| User intent and profile selection | Local authorized operator; no cloud account necessary |
| Saved manager desired state | Server Connect; private protected local store, versioned schema |
| Effective Linux network | Linux kernel/host and other applications, **not** Server Connect's private state |
| Product-owned route/rule/mark/interface/unit fragments | Server Connect only when identity/provenance is verified |
| All other host routes, firewall policy, SSH, aaPanel, Docker, Fail2Ban and STL | Their respective owners; never adopt or flush |
| Connectivity protocols and packet forwarding | Official pinned sing-box runtime; no reimplementation |
| Optional cloudflared connector, hostname and account | Operator-approved Cloudflare integration only; never an implicit VPN inbound service |
| Keys, tokens and profile URLs | Protected runtime secret material, never Git/logs/artifacts |

Separate **desired**, **observed**, **pending/uncertain**, and **last verified safe** states. A saved profile or a live process alone proves neither actual foreign reachability nor safe host routing.

## 3. Routes and process behavior

1. **Direct:** no product-owned host-wide routes or firewall changes. Clean-off is a real product feature.
2. **Proxy Only:** an explicit local SOCKS/HTTP endpoint (prefer loopback or Unix socket); users/apps opt in. Prefer per-invocation application/environment proxy selection. When an application proxy file is product-managed, its prior exact content/absence and owner must be recorded and its owned change undone on disable/core failure. Never take over operator-owned proxy settings or silently alter global DNS/default routes.
3. **Smart Routing (TUN):** one transparent host-wide destination-based Iran Direct / other-public VPN policy via sing-box TUN plus owned Linux policy; protect the VPN underlay, domestic routes and independently classified ingress replies. No separate Selective/Broad engine or per-job policy.

#### Smart Routing: one destination policy, not a per-job routing engine

Capture ordinary supported outbound traffic at the Linux TUN/system-routing layer, independent of each program's proxy support. **Routing is destination-based**, not PID, UID, cgroup or aaPanel task ID. Existing Proxy Only exec/APT/WordPress paths remain separate explicit opt-in behavior; optional read-only workload-observe diagnostics do not select flows and are not acceptance gates.

Rule precedence: (1) protected management, VPN endpoint underlay/bootstrap DNS, established and new inbound hosting replies, local/private/on-link routes; (2) explicit operator domain/IP/CIDR and trusted local-list exceptions, with deterministic collision handling and override limits; (3) verified offline-available Iranian public IP prefixes; (4) remaining public destinations to the selected VPN. Domain rules need a real DNS/sniff correlation path; a raw IP flow must not be misclassified from an unavailable hostname. Allow rule lists shipped offline, authenticated online/mirror updates and validated manual imports, with rollback on invalid/stale data. Direct-first availability probing and new-flow VPN fallback for explicit foreign exceptions may follow the working core; no replay or automatic learning is required.

The objective is Windows-TUN-like **transparent coverage for all supported ordinary outbound programs**, including non-proxy-aware aaPanel installers. Verify actual TCP/UDP/DNS/IPv4/IPv6 packet paths (and distinguish protocol, VPN transport and Linux namespace limits); do not claim universal traffic capture from a TUN configuration alone. VPN-required traffic must never silently escape via Direct on an unsupported protocol or core outage.

A country-prefix list alone cannot protect foreign-client SSH or HTTP reply flows. Inspect native route/rule/nftables/conntrack ownership, reverse path filtering, DNS, MTU, interfaces and foreign owners first. Only the exact manager-owned delta may be applied/undone, after independent Activation Guard is armed and verified; Runtime Health Guard is mandatory while active. Protect the VPN endpoint's independent Direct path and bootstrap resolution. Refuse ambiguous host state rather than overwrite Docker/aaPanel/Fail2Ban/STL resources. [Simple Connect](https://github.com/AChWorks/simple-connect) is a conceptual IPv4 TCP/DNS interception reference, not the transport engine or UDP/IPv6 proof.

### Future-compatible state only (no speculative framework)

The current manager uses one selected profile and one upstream tag; preserve stable stored profile identity, explicit migrations and independent path-bound health, without making internal tags public APIs. [Issue #7](https://github.com/AChWorks/server-connect/issues/7) remains Owner-deferred for possible concurrent profiles. Do not implement per-job/per-workload routing, multiple competing TUN owners or profile-specific daemon infrastructure now.

## 4. Optional Cloudflare Tunnel website ingress (separate feature)

The core Smart Routing mode is **outbound only**. A consumer VLESS profile does not expose public ports or restore direct foreign-to-Iran reachability. An opt-in official **cloudflared** connector can instead publish approved HTTP(S) hostnames by creating an **outbound** connection to Cloudflare and forwarding to an approved local origin (such as a protected aaPanel/Nginx virtual host). If Cloudflare is inaccessible Direct, that connector may use the Smart Routing VPN **after independent path proof**; Cloudflare uses outbound QUIC/UDP or HTTP2/TCP on port 7844, subject to actual path/transport availability.

Keep this as a separately controlled/observed unit: Cloudflare credentials, account/domain/DNS operations, origin binding, trusted proxy/client-IP headers and TLS need explicit operator authorization and secure state. Never seize another existing tunnel, DNS record, port, origin configuration or web-service owner. An unavailable connector must not tear down healthy outbound VPN traffic; conversely a VPN failure may legitimately disrupt only a connector dependent on it. External nonce checks must reach the origin, not just a CDN cache. A generic raw public TCP/UDP/Marzban/Backhaul relay is **not** supplied; non-HTTP Cloudflare publication has different client and plan restrictions.

Core safe outbound release remains independent of this post-core [Cloudflare integration Issue #48](https://github.com/AChWorks/server-connect/issues/48); [Issue #4](https://github.com/AChWorks/server-connect/issues/4) owns optional visibility/check UX. Reference: [Cloudflare published routes](https://developers.cloudflare.com/tunnel/concepts/routing/) and [connector egress requirements](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/).

## 5. Modularity without speculative frameworks

Keep implementation concepts separate, not necessarily separate processes:
- Profile parser/adapter: accepted input, secret handling, compatibility validation.
- Core runner: exact pinned sing-box executable and state; future alternative adapter only after observed need.
- Routing planner/applier: exact resource identities, validate/plan/apply/undo.
- Guards: activation transaction, runtime proof/failure resolution, and a minimal independent liveness/recovery trigger for **health-guard failure itself**; no unmonitored host-wide interception.
- Host inspector: Linux/network/systemd/aaPanel coexistence evidence without taking ownership.
- Shared lifecycle: official HTTPS, operator-hosted HTTPS mirror or manual offline upload of the same authenticated bundle feed identical installer/update/owned-state cleanup.
- Terminal/CLI: commands, concise operator errors, structured machine results.

Do not introduce public Go libraries, generic plugin registries, distributed orchestration, databases or additional always-on services by default. Keep a simple replaceable boundary around sing-box instead of baking a provider-specific format into every command.

## 6. Dependencies and support targets

- Target initially Debian/Ubuntu with systemd and supported Linux TUN/network facilities, **subject to an explicit tested OS/kernel/arch matrix** before any release. No promise of every Debian/Ubuntu or arbitrary Linux version.
- Integrate native host tools carefully; avoid global NetworkManager, resolv.conf or arbitrary iptables/nftables ownership assumptions.
- Offline packaging must carry every required runtime artifact and verified local Iranian IP/rule data for the advertised target; no hidden GitHub/API dependency. Official and user-hosted HTTPS mirror online acquisition must verify identical publisher-authenticated bytes before invoking the same installer.
- The standalone packaging, validation, and state-recovery requirements are owned by this repository's [offline distribution](OFFLINE-DISTRIBUTION.md), [acceptance](ACCEPTANCE.md), and [safety](SAFETY-RECOVERY.md) contracts. No private framework or governance repository is a runtime or contributor prerequisite.
- Existing [STL](https://github.com/ach1992/simple-tun-link) is a separate point-to-point Link product; [SSO](https://github.com/ach1992/simple-server-optimizer) is a separate tuning/host utility. Neither owns global server VPN routing or is modified here.

## 7. Evolution gates

Cheap-to-preserve seams: additional profile parser, different probe target, local rule-source format, optional Cloudflare Tunnel connector and OS-specific host adapter. Implement only accepted modes. Operator-hosted **static mirrors are required acquisition options**, but automatic mirror discovery or DNS rewriting, profile marketplaces and permanent process telemetry are not.

Implementation evidence and acceptance: [ACCEPTANCE.md](ACCEPTANCE.md). Recovery detail: [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md).
