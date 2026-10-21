# Architecture and integration boundaries

- **Status:** design contract; no implementation or installed system is claimed.
- **Product requirements:** [PROJECT-SPEC.md](PROJECT-SPEC.md) — canonical.

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
   |-- offline installer/updater lifecycle
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
| Foreign relay/CDN, if optionally configured | External service or operator; not implied by a client VPN |
| Keys, tokens and profile URLs | Protected runtime secret material, never Git/logs/artifacts |

Separate **desired**, **observed**, **pending/uncertain**, and **last verified safe** states. A saved profile or a live process alone proves neither actual foreign reachability nor safe host routing.

## 3. Routes and process behavior

1. **Direct:** no product-owned host-wide routes or firewall changes. Clean-off is a real product feature.
2. **Proxy Only:** an explicit local SOCKS/HTTP endpoint (prefer loopback or Unix socket); users/apps opt in. Prefer per-invocation application/environment proxy selection. When an application proxy file is product-managed, its prior exact content/absence and owner must be recorded and its owned change undone on disable/core failure. Never take over operator-owned proxy settings or silently alter global DNS/default routes.
3. **Selective Tunnel:** user-selected foreign routes via TUN/policy routing, domestic/direct routes retained; protect VPN endpoint underlay and ingress reply behavior.
4. **Broad Tunnel:** wider outbound scope, still preserving positively established host/control/underlay exemptions; never equate it with unconditional default-route replacement.

For routed modes, plan/observe exact Linux route tables, ip rules, marks, IPv4/IPv6 and active packet-filter authority before applying. An Iranian geo-IP list alone is not a correct routing model for established inbound connections, private networks or control-plane traffic; require live-route/connection-aware checks. Separate the **route to the remote VPN server** from traffic carried inside that VPN. Before any tunnel, resolve or pin its endpoint using a pre-existing reachable underlay path; foreign name resolution for applications using the tunnel must respect the selected routing/DNS policy without silently replacing the host's shared resolver.

If a needed assumption is unprovable (routing owner, baseline, MTU/IPv6 behavior, firewall coexistence, initial management access), stop with a precise diagnostic rather than apply speculative host-wide changes.

## 4. External access is not the outbound VPN

The manager may be used only for outgoing updates and API access; do not require any CDN or external inbound probes. Operators who need foreign users to reach hosted sites can configure an independent already-available CDN/reverse path and optionally force its **outgoing connector** through the selected VPN where it is reachable.

A consumer VLESS profile is not a hosted ingress endpoint; enabling a client tunnel does not create public forwarded ports. Do not add a reverse-proxy server or rewrite customers' web-server configuration merely to claim ingress success.

## 5. Modularity without speculative frameworks

Keep implementation concepts separate, not necessarily separate processes:
- Profile parser/adapter: accepted input, secret handling, compatibility validation.
- Core runner: exact pinned sing-box executable and state; future alternative adapter only after observed need.
- Routing planner/applier: exact resource identities, validate/plan/apply/undo.
- Guards: activation transaction, runtime proof/failure resolution, and a minimal independent liveness/recovery trigger for **health-guard failure itself**; no unmonitored host-wide interception.
- Host inspector: Linux/network/systemd/aaPanel coexistence evidence without taking ownership.
- Offline lifecycle: signed bundle verification, installation, update and owned-state cleanup.
- Terminal/CLI: commands, concise operator errors, structured machine results.

Do not introduce public Go libraries, generic plugin registries, distributed orchestration, databases or additional always-on services by default. Keep a simple replaceable boundary around sing-box instead of baking a provider-specific format into every command.

## 6. Dependencies and support targets

- Target initially Debian/Ubuntu with systemd and supported Linux TUN/network facilities, **subject to an explicit tested OS/kernel/arch matrix** before any release. No promise of every Debian/Ubuntu or arbitrary Linux version.
- Integrate native host tools carefully; avoid global NetworkManager, resolv.conf or arbitrary iptables/nftables ownership assumptions.
- Offline packaging must carry every required runtime artifact for the advertised target; no hidden GitHub/API dependency.
- The standalone packaging, validation, and state-recovery requirements are owned by this repository's [offline distribution](OFFLINE-DISTRIBUTION.md), [acceptance](ACCEPTANCE.md), and [safety](SAFETY-RECOVERY.md) contracts. No private framework or governance repository is a runtime or contributor prerequisite.
- Existing [STL](https://github.com/ach1992/simple-tun-link) is a separate point-to-point Link product; [SSO](https://github.com/ach1992/simple-server-optimizer) is a separate tuning/host utility. Neither owns global server VPN routing or is modified here.

## 7. Evolution gates

Cheap-to-preserve seams: alternative upstream core, additional profile parser, different probing destination, optional inbound reachability checker, OS-specific host adapter. Implement only the **currently exercised** variants. No speculative DNS/mirror automation, profile-marketplace, auto-discovery of censorship-resistant transports, or permanent background data collection.

Implementation evidence and acceptance: [ACCEPTANCE.md](ACCEPTANCE.md). Recovery detail: [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md).
