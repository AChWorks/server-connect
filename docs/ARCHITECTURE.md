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
   |-- online fetch + offline bundle -> shared installer/updater lifecycle
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

#### Source selection is not the same as destination selection

The application selector must remain an explicit **workload attribution** layer above the same single policy/guard core, not a second networking engine. `server-connect exec` can pass proxy settings to a supported HTTP-aware command and its children, but this proves nothing about binaries that ignore those variables, native package managers with their own proxy semantics, or background aaPanel App Store operations spawned by long-running panel workers. A selected HTTP-aware client may use the local listener; a selected non-proxy-aware panel installer may need a **guarded source/job or destination policy** for TCP/UDP flows. Source/process identity must be established from the real worker/service and tested across subprocesses; a bare PID, shared root UID, process name or terminal environment is not sufficient ownership. Treat DNS resolver requests and IPv6 as part of the traffic contract, not an implicit proxy side effect.

The development-only `workload-observe --pid N` diagnostic reads procfs stat
birth ticks, parent PID and unified cgroup-v2 membership twice to reject
observed reuse/reparenting/migration. The explicitly opted-in `--sockets`
mode additionally correlates numeric TCP/UDP socket entries in that PID's
network namespace with actual socket inode references held in its FD table.
It rechecks network namespace, FD inode set and ancestry after the scan,
refuses unavailable/ambiguous inputs and never follows unrelated FD targets.
These **non-atomic read-only observations** are not authenticated job selection,
continuous descendant tracking, exclusive socket/source ownership, DNS/packet
path proof or permission to change routing. A shared socket/cgroup and a GUI
click cannot identify an individual aaPanel installation. True source and
selected egress must be independently verified on a representative real job.

A high-risk implementation must bind an explicit operator-selected job/service or approved destination set to a narrowly owned policy, ensure the remote VPN endpoint itself remains underlay-reachable, prove live selected egress, and preserve unrelated panel UI/control plane, SSH, hosted HTTP(S) replies, Docker/STL/other manager resources and domestic routes. Unknown workers and unsupported protocols must fail closed. Which Linux source attribution mechanism is used (e.g., validated systemd unit/cgroup, verified dedicated process group or a suitable future kernel primitive) depends on supported-host proof; do **not** silently classify every root-owned process as the chosen app. An aaPanel app-install click is not itself a policy identity. No service-scoped or host-wide routing is active until Issue #2's real recovery guard, Issue #3's ongoing health supervisor and the physical acceptance gates are complete.

For routed modes, plan/observe exact Linux route tables, ip rules, marks, IPv4/IPv6 and active packet-filter authority before applying. An Iranian geo-IP list alone is not a correct routing model for established inbound connections, private networks or control-plane traffic; require live-route/connection-aware checks. Separate the **route to the remote VPN server** from traffic carried inside that VPN. Before any tunnel, resolve or pin its endpoint using a pre-existing reachable underlay path; foreign name resolution for applications using the tunnel must respect the selected routing/DNS policy without silently replacing the host's shared resolver.

If a needed assumption is unprovable (routing owner, baseline, MTU/IPv6 behavior, firewall coexistence, initial management access), stop with a precise diagnostic rather than apply speculative host-wide changes.

### Future-proof profile and policy seams (deferred; not a new implementation layer)

The MVP state format has one `selected` profile and one `upstream` sing-box tag. These are **internal single-active-outbound implementation details**, not contractual proof that future versions must own exactly one outbound or overwrite all routes when one profile changes. Keep independent stable profile identities separate from ephemeral runtime outbound tags, and use explicit versioned migrations rather than silently reinterpreting stored `desired` state. The canonical desired/observed store may later represent multiple outbound statuses and per-workload bindings while preserving Direct and a reliable last-known-safe baseline.

Future [concurrent profiles](https://github.com/AChWorks/server-connect/issues/7) can preferably share one supported sing-box instance with unique tagged outbounds, selected listeners and policy rules, when verified against the pinned core. Do not assume per-process `HTTP_PROXY` covers raw TCP/UDP apps or a reverse relay, and do not add extra TUN/default-route owners just to enable multiple profiles. Each route decision, loopback listener, DNS/underlay dependency, proof of health, failure response and owned resource must be attributable to its selected path; unrelated active outbounds must not be stopped by one broken path. These are **design constraints only** until Issue #7 is explicitly activated by the Owner.

## 4. External access is not the outbound VPN

The manager may be used only for outgoing updates and API access; do not require any CDN or external inbound probes. Operators who need foreign users to reach hosted sites can configure an independent already-available CDN/reverse path and optionally force its **outgoing connector** through the selected VPN where it is reachable.

A consumer VLESS profile is not a hosted ingress endpoint; enabling a client tunnel does not create public forwarded ports. Do not add a reverse-proxy server or rewrite customers' web-server configuration merely to claim ingress success.

Likewise, **Marzban panel outbound control traffic** is not the same as **public client ingress** or an **Iran-public-IP-to-foreign-Xray-node relay**. The latter is a separate externally reachable public listener and operator-owned relay/forwarding design (e.g., Backhaul or STL where appropriate), with TCP/UDP/return-path and firewall ownership verified on each side. Server Connect may in the future supply an opt-in outbound path for a compatible connector, but does not implement its ingress, forward its users automatically or guarantee connectivity when no independently usable underlay remains. Preserve existing sockets, listening ports, conntrack replies and service-owned routes across host-network policy changes.


## 5. Modularity without speculative frameworks

Keep implementation concepts separate, not necessarily separate processes:
- Profile parser/adapter: accepted input, secret handling, compatibility validation.
- Core runner: exact pinned sing-box executable and state; future alternative adapter only after observed need.
- Routing planner/applier: exact resource identities, validate/plan/apply/undo.
- Guards: activation transaction, runtime proof/failure resolution, and a minimal independent liveness/recovery trigger for **health-guard failure itself**; no unmonitored host-wide interception.
- Host inspector: Linux/network/systemd/aaPanel coexistence evidence without taking ownership.
- Shared lifecycle: optional online acquisition + complete offline bundle both feed identical release verification, install, update and owned-state cleanup.
- Terminal/CLI: commands, concise operator errors, structured machine results.

Do not introduce public Go libraries, generic plugin registries, distributed orchestration, databases or additional always-on services by default. Keep a simple replaceable boundary around sing-box instead of baking a provider-specific format into every command.

## 6. Dependencies and support targets

- Target initially Debian/Ubuntu with systemd and supported Linux TUN/network facilities, **subject to an explicit tested OS/kernel/arch matrix** before any release. No promise of every Debian/Ubuntu or arbitrary Linux version.
- Integrate native host tools carefully; avoid global NetworkManager, resolv.conf or arbitrary iptables/nftables ownership assumptions.
- Offline packaging must carry every required runtime artifact for the advertised target; no hidden GitHub/API dependency. Online bootstrap may explicitly download and verify prerequisites only on the connected path, before handing identical artifacts to the shared installer.
- The standalone packaging, validation, and state-recovery requirements are owned by this repository's [offline distribution](OFFLINE-DISTRIBUTION.md), [acceptance](ACCEPTANCE.md), and [safety](SAFETY-RECOVERY.md) contracts. No private framework or governance repository is a runtime or contributor prerequisite.
- Existing [STL](https://github.com/ach1992/simple-tun-link) is a separate point-to-point Link product; [SSO](https://github.com/ach1992/simple-server-optimizer) is a separate tuning/host utility. Neither owns global server VPN routing or is modified here.

## 7. Evolution gates

Cheap-to-preserve seams: alternative upstream core, additional profile parser, different probing destination, optional inbound reachability checker, OS-specific host adapter. Implement only the **currently exercised** variants. No speculative DNS/mirror automation, profile-marketplace, auto-discovery of censorship-resistant transports, or permanent background data collection.

Implementation evidence and acceptance: [ACCEPTANCE.md](ACCEPTANCE.md). Recovery detail: [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md).
