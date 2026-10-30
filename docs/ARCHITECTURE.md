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

## Inert product TUN unit and disposable pending integration

The development installer carries a third supplementary **static, unenabled**
`server-connect-smart-tun.service` distinct from the existing unprivileged
`server-connect.service` Proxy Only unit. The TUN service alone has
`CAP_NET_ADMIN`/`CAP_NET_RAW`, and reads its exact staged policy using a
systemd `LoadCredential` copy; the ordinary proxy unit remains unprivileged.
The installer fingerprints and transactionally restores this unit alongside
its existing independent recovery service/timer, and refuses updates while
any of them is active.

`smart-tun-trial-apply` is **not** the product Smart Routing Apply: it is a
short-lived, v4-journal-bound real sing-box test *only* in the known disconnected
two-interface Docker systemd fixture, with synthetic VLESS endpoint and CIDRs.
It admits only the original exact IPv4 policy or one opt-in, strictly pinned
synthetic IPv4+IPv6 variant: the same owned TUN unit, journal v4, recovery
executor, isolated underlay and baseline verification; never an arbitrary
IPv6 host, public prefix list, or production dual-stack rollout. IPv6
operator Direct/VPN host exceptions demonstrate precedence only in this QA
fixture; no geolocation or trusted DNS-to-IP correlation is inferred.
It first validates selected profile, pinned core and complete native
route/rule/link/nftables baseline (including any pre-existing QA-guest
firewall owners), then independently prearms and executes
the installed recovery oneshot **outside** the shared journal lock. A second
locked admission must match, followed by fsynced pending journal, credential persistence
and only then an explicit `systemctl start` of the exact owned
TUN unit. An independent systemd timer detects timeout, manager death, core
exit or reboot, stops only that exact unit and requires the original semantic
kernel and nftables baseline before recording `trial_recovered`. Exact
operation-bound Disconnect records durable stop intent before stopping the
owned TUN service. The independent executor can complete an interrupted stop;
wrong or stale operation identities never authorize stopping a later trial.
Finalization records its cleanup intent before sensitive credential removal,
so interruption is distinguishable from unauthorized credential loss after
core start. Only a verified restored native baseline permits clearance.
Unresolved trial operations block Proxy Only mode changes and prevent generic
status from claiming ordinary Direct.

One private saved trial policy holds validated, non-secret settings separately
from the transient sing-box credential and operation journal. Explicit Off,
timeout and cleanup preserve this policy and the selected profile. Saved
reapply validates the policy/profile again, repeats the full native admission
and independent prearm, and creates a fresh operation/deadline. Stored policy
alone is never authority to start a service or restore a prior active state.

This deliberately cannot **commit** TUN, cannot authenticate foreign host
owners or geographic data, and does not have fresh SSH/provider confirmation
or Runtime Health Guard. Production activation still needs exactly owned
multi-owner kernel transactions and a separate permission/review boundary.

## Optional inbound website connectivity

A selected consumer VPN does **not** create public inbound ports. A separately enabled **official cloudflared** connector may open an outbound connection to Cloudflare and serve an explicitly approved HTTP(S) hostname from a bounded local origin, via Direct or the verified Smart Routing VPN if needed. Its account/domain/DNS, credentials, trusted proxy/source-IP handling, TLS, origin binding and service lifecycle are separately authorized and independently diagnosed.

The connector must not change aaPanel/Nginx virtual hosts, intercept another tunnel, or couple its failure to healthy outbound VPN service. Cloudflare Tunnel is not a generic public raw TCP/UDP, Xray/Marzban or Backhaul relay. Further service-specific ingress is outside this design.

## Packaging and host targets

Target only **tested** Linux OS/kernel/architecture/sing-box combinations with systemd and the required TUN/network capabilities. Acquire immutable verified bytes via official online, operator-hosted HTTPS mirror, or manual offline upload; all invoke one shared installer. Keep host-specific package, signature and installation rules in [OFFLINE-DISTRIBUTION.md](OFFLINE-DISTRIBUTION.md).

Operational safety details live in [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md); real scenario coverage and known limits in [ACCEPTANCE.md](ACCEPTANCE.md). Existing development-only unarmed selective plans and loopback RPDB trials remain code/test diagnostics, **not** release-blocking implementations of Smart Routing.
