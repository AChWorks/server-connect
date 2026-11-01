# Architecture and integration boundaries

**Product goal:** [PROJECT-SPEC.md](PROJECT-SPEC.md). This document owns *how components interact*, how traffic is classified, and which host resources Server Connect may change. It does not record active Issues, test runs or the history of experimental implementations.

## Components and lifecycle

```text
Operator -> one menu / CLI + structured JSON
         -> manager: profiles, validated rules, desired/observed state
            |-> official pinned sing-box: local Proxy Only or TUN + selected outbound
            |-> Linux policy: exact owned routes/rules/nftables/interfaces
            |-> independent Activation Guard and Runtime Health Guard
            |-> shared installer: official / mirror download or offline bundle
Optional: independent cloudflared connector -> Cloudflare -> approved HTTP(S) origin
```

The manager is a small Linux CLI/control plane, not a replacement tunnel protocol or a mandatory hosted dashboard. The current usable development foundation is Direct and opt-in Proxy Only; **production Smart Routing and its guards are not yet implemented/accepted**. Source and CI history must not be confused with a released or field-proven build.

Use one authenticated stored-profile identity and **one selected active outbound** for the first version. Keep profile data, rules, runtime state and replaceable binaries separate. A saved profile/rule set is **configuration**, not an active Linux route: explicit Disconnect or guard-confirmed fallback to Direct removes the precisely owned TUN/policy and any VPN-only egress blocks, but preserves stored settings for the next independently guarded Apply. While routing is active or degraded, an unavailable VPN-required path must not silently bypass through Direct. Do not introduce multi-outbound abstractions or a per-job router for possible future features.

## Smart Routing — one transparent host policy

Smart Routing uses the **official sing-box Linux TUN data plane** plus minimal native Linux packet/routing integration required on the supported host. It captures ordinary supported outbound host connections regardless of process identity or proxy awareness. Existing `server-connect exec` / APT / WordPress explicit-proxy helpers belong **only to optional Proxy Only**; they are not required to route background aaPanel installers or any other compatible application through Smart Routing.

Traffic policy is deterministic and has these conceptual priorities:

1. **Protected host paths:** connected/loopback/private networks, VPN endpoint and bootstrap DNS underlay, verified SSH/panel administration and existing/new inbound-service replies. A foreign client IP alone never makes its server reply VPN-bound.
2. **Operator-controlled rules:** exact domain/suffix, IP/CIDR or validated local rule-list Direct/VPN exceptions. Define deterministic overlap/priority, show effective decisions and prevent rules from overriding essential protections.
3. **Iranian public IPs:** locally bundled, validated and versioned IPv4/IPv6 prefixes; Direct by default. Imported/updated data must remain independently verifiable, usable offline and rollback-safe.
4. **Other public destinations:** the selected VPN by default; never silently use Direct when VPN-required routing fails. An optional Direct-first probe for explicitly exempted foreign destinations can affect **new flows**, not replay an application operation.

**Domain rules require real knowledge of the destination name** from supported DNS/routing correlation, not merely an IP geolocation guess. Raw-IP connections follow IP rules. Handle resolver bootstrap versus application DNS without recursive tunnel loops. Verify actual support for TCP/UDP, IPv4/IPv6 and DNS along the selected upstream, including failure/leak cases; TUN configuration alone does not prove comprehensive capture. Detect unsupported network namespaces or other host-specific exclusions instead of reporting false coverage.

Linux policy must coexist with existing kernel routing, nftables/iptables, conntrack, reverse-path filters, Docker/Fail2Ban, aaPanel, hosting and other VPN tools. A manager plan is not a reservation: reobserve identities immediately before guarded mutation. Never flush global tables, rewrite the system resolver speculatively, seize third-party listeners, or restore an old snapshot over changes made by another owner.

The VPN server's *outer transport* needs an independently reachable bootstrap path before it can carry any tunneled traffic. Underlay reachability, selected VPN data-plane delivery and hosted inbound replies are **three different proofs**.

## Resource ownership and recovery boundaries

| State or resource | Responsibility |
| --- | --- |
| Desired profiles, rule configuration, secrets | Manager-owned protected versioned local storage |
| Actual routes/rules/firewall/networks | Linux host and existing owners; only precisely attributed Server Connect deltas are mutable |
| Sing-box and its service/listeners | Manager-controlled only for the installed selected profile |
| Activation/Runtime Guard | Independently supervised host-local recovery, not reliant on sing-box or international access |
| SSH, aaPanel, WordPress, Docker, Fail2Ban, STL | Independent owners; preserve their existing services and traffic |
| Cloudflare account, DNS, site origin | Operator/external service; modify only explicitly approved objects |

Track **desired, observed, pending/uncertain and last verified safe** states separately. An observed process, successful Direct probe, route-plan fingerprint or private intent journal is not proof of safe TUN activation. Exact transaction semantics and recovery belong to [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md).

## Inert product units and disposable native integration

The development installer carries a static, unenabled
`server-connect-smart-tun.service` distinct from the existing unprivileged
`server-connect.service` Proxy Only unit. The TUN service has the capabilities
needed for its narrowly admitted native link and marked sockets, and reads its
exact staged policy using a systemd `LoadCredential` copy. The ordinary proxy
unit remains unprivileged. The installer fingerprints and transactionally
restores the TUN unit, independent recovery service/timer and separate health
service/timer, and refuses updates while any of them is active. Installation
alone does not enable either experimental timer.

`smart-tun-trial-apply` is limited to the known disconnected Docker/systemd
fixture, with an exact synthetic VLESS endpoint and IPv4 or opt-in IPv4+IPv6
policy. Its default pending mode uses the v4 journal's distinct
`smart_tun_native_pending_trial_v1` intent with a required typed native ledger;
it expires without confirmation. The explicit `--supervised` mode adds a
separate strict lifecycle record for one-use fresh management confirmation,
selected-path health and bounded reconnect. Older v4 automatic-policy and
native-pending records retain their original recovery semantics and cannot
be interpreted as confirmed supervised authority. All of these modes remain
experimental and unavailable for general-host Apply.

The supervised health role is a separate bounded systemd oneshot, scheduled
by an inert-at-install timer. The independent recovery role checks both its
unit provenance/state and its operation-bound progress deadline; an active
timer alone cannot prove healthy supervision. The health role also checks the
independent recovery role before continuing. Network probes execute outside
the shared operation lock, followed by exact-state revalidation before any
result is published. The service execution deadline bounds a stalled health
process even if it stops making progress while holding the lock. Reconnect
retains the native containment policy, restarts only the selected owned core,
and must acquire fresh attachment and selected-path proof before reporting
experimental recovery. The attempt and elapsed-time budgets span flapping
within an outage incident. Exhaustion ends in exact owned recovery or retained
uncertainty; it never creates an unlimited restart loop.

The independent executor selects the journal version and runs its recovery
handler under one continuous manager lock. Concurrent Apply cannot publish
a new journal between version selection and legacy interpretation.

The manager validates the selected profile, pinned core, native baseline and
reserved resource absence, then independently prearms the installed recovery
oneshot/timer outside the shared journal lock. It repeats admission under the
lock and persists the operation before any native network mutation. Native ownership binds
the network namespace, actual interface index, complete addresses and relevant
dependencies, exact route/rule receipts, and the nftables table and ordered
child handles. The original host fingerprint remains diagnostic evidence; it
is not a restoration snapshot or permission to delete changed foreign state.

The manager creates an exclusive, initially nonpersistent TUN, configures its
addresses and disables automatic IPv6 address generation, then durably records
the observed identity before making the link persistent. The official core
attaches to this link with an empty address list, explicit gVisor stack,
`auto_route=false`, `auto_redirect=false` and `dns_mode=disabled`. The manager
owns capture routes, RPDB entries and one operation-specific nftables table.
Core socket marks are injected into the narrowly supported native profile so
the outer VPN and core Direct outbounds use the underlay without recursion.
The existing Proxy Only profile-import behavior is unchanged.

**Experimental DNS ownership (exact supervised Debian13 QEMU guest only):** an
explicit public IPv4 resolver may be attached as a route-only `~.` domain to
the *product-owned* TUN link through `resolvectl`, with a durable effect intent
before mutation, exact link-index/readback receipts and the same pinned journal
lock as native network mutators. The existing `ens3`/global resolver is never
modified. The independent Guard must verify the receipted link setting during
pending supervision and refuse a foreign/resolver mismatch during cleanup;
removing the precisely owned TUN also removes its link-scoped DNS state. This
optional QA setting does **not** enable sing-box DNS hijack or constitute
trusted DNS/IP correlation, geographic domain policy, full DNS health
verification or general-host DNS support. Unsupported systemd-resolved/link
identity or resolver states are refused before a new guarded operation.
A bounded disposable-only `--qa-kill-at after-native-dns-effect` SIGKILL
boundary tests recovery after the first DNS setter but before the routing
`~.` domain is installed. An executor failure can make
`guard_scheduled=false` and report `guard_unavailable` even while the
systemd Timer remains armed; this field represents verified effective Guard
readiness, not the Timer's raw `ActiveState`. After an exact guest-only
foreign-resolver collision is resolved and all owned network resources are
observed absent, use `smart-tun-trial-reconcile-idle-guard` to reset an
independently proven idle failed recovery service. Never discard the journal
or force-clean an unknown owner merely to get a green status.

Native OUTPUT capture and a separate POSTROUTING containment chain classify
the same protected paths. OUTPUT route hooks can change the packet's route
while later OUTPUT hooks still observe the initial output interface. The guard
therefore checks the final selected interface in POSTROUTING. Its final drop
applies only to host-origin packets with no ingress interface; forwarded
traffic retains its existing owner. The guard classifies eligible traffic
independently of the capture mark, so losing a capture rule or RPDB entry is
not permission to fall through to Direct. Connection-tracking reply direction
protects hosted replies without
exempting new outbound connections to the visitor's IP. Explicit local link
control exceptions are bounded to the fixture underlay; they do not advertise
arbitrary ICMP, fragmentation or PMTUD support. The existing core compiler
retains protected/operator/domestic/default precedence and rejects unsupported
or untrusted policy inputs.

Each native resource-changing phase records durable intent. Successful
observations produce resource receipts; initial nonpersistent TUN setup is
one FD-scoped phase whose complete identity is recorded before persistence.
An effect that exists without its receipt is not adopted merely because its
name or attributes look expected. Mutating native subprocesses inherit the
existing operation lock and a parent-death signal; recovery must not run past
an outstanding command after controller death. Core attachment also requires
a bounded link-event observation and durable verified-start receipt. Missing
or lost observation remains uncertainty, even if a later snapshot looks normal.

Exact-operation Disconnect persists stop intent, contains the core, then
removes proven routes/rules/link while the complete independent guard remains
present for a receipted active policy. Before policy creation, or after an
unreceipted policy is conclusively absent and outstanding mutators are excluded,
cleanup may proceed without a guard. A present unreceipted graph remains uncertain. It removes the nftables guard last using a stable observed generation
and an exact table-handle deletion conditioned on that generation. A concurrent
committed nftables change invalidates deletion instead of allowing recursive
foreign-child removal. Supported disjoint changes survive Off; overlapping,
replaced or uninspectable dependencies retain resources and evidence. Only
verified removal and protected underlay observations permit truthful Direct
finalization. The precise ordering and uncertainty cases are in
[Safety and recovery](SAFETY-RECOVERY.md#native-ownership-and-containment).

One private saved trial policy holds validated, non-secret settings separately
from the transient sing-box credential and operation journal. Explicit Off,
timeout and cleanup preserve this policy and the selected profile. Saved
reapply validates them again, repeats admission and independent prearm, and
creates a fresh operation/deadline. Stored policy alone is never authority to
start a service or restore a prior active state. Unresolved operations block
Proxy Only and installer transitions and prevent status from claiming Direct.

Supported foreign nftables coexistence is limited to observed non-rewriting
filtering/counters and the admitted passive statement forms. NAT, packet or
metadata rewriting, redirection/duplication/forwarding, userspace queueing,
connection-tracking assignment and offload are unsupported and must remain
absent while routed. A later privileged path-affecting change can invalidate
routing assumptions before the periodic executor observes it; stopping the core
is not instantaneous containment against such a new foreign policy.

This boundary does not authenticate arbitrary simultaneous privileged writers,
route/rule generations, geographic data or DNS-to-IP correlation. Fresh root
SSH confirmation applies only to the admitted disposable transport; provider
console attestation, general permanent commitment, field-tested Runtime Health
Guard and physical power-loss recovery remain unavailable. General production
activation remains unavailable. Legacy automatic-policy cleanup has additional
[ownership limits](SAFETY-RECOVERY.md#automatic-policy-ownership-limit); it is not
used as native-transaction deletion authority.

## Optional inbound website connectivity

A selected consumer VPN does **not** create public inbound ports. A separately enabled **official cloudflared** connector may open an outbound connection to Cloudflare and serve an explicitly approved HTTP(S) hostname from a bounded local origin, via Direct or the verified Smart Routing VPN if needed. Its account/domain/DNS, credentials, trusted proxy/source-IP handling, TLS, origin binding and service lifecycle are separately authorized and independently diagnosed.

The connector must not change aaPanel/Nginx virtual hosts, intercept another tunnel, or couple its failure to healthy outbound VPN service. Cloudflare Tunnel is not a generic public raw TCP/UDP, Xray/Marzban or Backhaul relay. Further service-specific ingress is outside this design.

## Packaging and host targets

Target only **tested** Linux OS/kernel/architecture/sing-box combinations with systemd and the required TUN/network capabilities. Acquire immutable verified bytes via official online, operator-hosted HTTPS mirror, or manual offline upload; all invoke one shared installer. Keep host-specific package, signature and installation rules in [OFFLINE-DISTRIBUTION.md](OFFLINE-DISTRIBUTION.md).

Operational safety details live in [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md); real scenario coverage and known limits in [ACCEPTANCE.md](ACCEPTANCE.md). Existing development-only unarmed selective plans and loopback RPDB trials remain code/test diagnostics, **not** release-blocking implementations of Smart Routing.
