# Safe activation, health, and recovery contract

- **Status:** normative requirements for the still-unimplemented production Activation Guard and Runtime Health Guard. Isolated QA-only in-boot rollback and disconnected Docker-restart pending-intent tests exist. The latter checks durable private fixture state and fresh boot-service no-op/conflict behavior after its kernel namespace resets. Neither demonstrates product guard integration, physical reboot/power-loss recovery or field acceptance.
- **Source of product intent:** [PROJECT-SPEC.md](PROJECT-SPEC.md). This document details the behaviors necessary to implement those requirements.

## Experimental product-integrated rule-only guard (not production ready)

The development candidate now installs a root-owned independent recovery
service and timer **disabled by default**. In a strict disconnected Docker
systemd guest, the real Manager can durably transition an exact single-IPv4
unarmed Selective intent into a v2 `trial_pending` record, after verifying an
active independent timer and before creating any kernel rule. Only a
protocol-tagged **RPDB rule to an empty routing table** is created; no tunnel,
route, DNS, firewall, default route or product-active policy is installed.
Its exact operation ID, plan/observations, boot identity, monotonic deadline,
prior absence and proposed identity are protected by the existing shared
Manager lock and fsync-safe private journal. Recovery inspects the native
priority and exact selector; unknown/foreign identity refuses deletion and
retains evidence. Successful rule-only recovery writes `trial_recovered`
revision 3. Distinct `trial_rule_recovered` does **not** set the product-level
`recovery_verified` or `activation_ready` fields. The actual kernel journal
is blocked from generic v1 abandonment, and the installer refuses to remove
its independent recovery units while pending/uncertain evidence exists.

The installed disposable-only trial also rechecks the **current native
kernel rule** before returning an existing `trial_recovered` receipt; a
reintroduced exact selector or modified foreign priority now refuses a
misleading recovered response. When the timer/service becomes unavailable
*during a still-pending deadline*, manual recovery returns `guard_unavailable`
rather than asserting `guard_scheduled`. This does not automatically restart
an externally disabled or masked watchdog: its overdue operation can recover
when the independent service becomes available again, or through controlled
operator recovery after expiry. Runtime unit masks/overrides in
`/run/systemd/system` are rejected by direct filesystem inspection: `systemctl`
may still report `loaded/static` because an installed `/etc` unit takes
precedence over a lower-priority runtime mask. A runtime mask alone cannot
prove that executor stopped; the guest acceptance separately masks the
actual installed service while preserving/restoring its exact bytes.
The current installed trial additionally inspects native systemd `Result`
and `ActiveState` for its service and timer. A failed or start-rate-limited
oneshot executor cannot produce a positive `guard_scheduled` response even
when the timer remains active; classification uses `guard_unavailable` with a
bounded executor-failed versus start-rate-limited diagnostic. The disposable
guest must prove real executor failure, intact pending journal and kernel
rule after expiry, and independent recovery after exact executable repair.
An active timer still cannot guarantee its **future** executor availability:
no autonomous repair exists if the executable stays missing. A persistent
unmonitored rule is therefore an **unresolved unsafe/uncertain condition**,
not success. These checks do not
make a protocol tag an authenticated ownership credential or replace Runtime
Health Guard #3.

This is a **bounded prerequisite experiment**, not a network-effective route
activation, general ownership proof, physically rebooted field deployment,
or demonstration of the required fresh SSH confirmation and ongoing health
supervision. Follow-up implementation must reuse the guarded transaction
rather than treating an experiment-only protocol tag as unconditional
ownership. No production host may invoke the trial path.

## 1. Operational principle

The recovery mechanism must **not need the VPN to work**. It must not need GitHub, Cloudflare, an external API, functioning DNS, or the sing-box process to perform its local fallback. The local console/provider rescue option remains an emergency requirement; no in-host mechanism can repair an unbootable kernel or provider-side outage.

A successful rollback is **verified restoration of the last safe host network condition** within the manager's authority. If the original direct foreign Internet is intentionally restricted, rollback cannot promise to restore international Internet; it must recover domestic networking, ordinary site ingress/replies and management paths.

## 2. State model

| State | Meaning | Allowed next steps |
| --- | --- | --- |
| DIRECT | No product-owned host-wide interception | Stage profile or Proxy Only |
| PREPARED | Verified baseline captured; proposed owned delta and recovery guard prepared | Apply trial or abandon |
| PENDING_CONFIRMATION | Guarded high-risk routing trial active; deadline and operation identity persisted | Commit on evidence or rollback |
| ACTIVE_VERIFIED | Committed desired profile, runtime health supervised | Continue / change via new transaction / recover |
| DEGRADED | Suspected insufficient connectivity with classified probe data | Bounded recheck; recover if confirmed |
| RECOVERING | Guard is reconciling owned resources to safe baseline | Verify then DIRECT/previous verified or explicit UNCERTAIN |
| UNCERTAIN | Identity/foreign-resource conflict or incomplete rollback | Preserve evidence, restrict further mutation, operator recovery |

The current version-1 `selective-stage-intent` developer command records only an **unarmed** journal labelled `prepared` after two non-atomic read-only observations; it does **not** satisfy this table's guarded PREPARED state, does not prove an owned interface, and is not authorization to apply network changes. Only a complete `unarmed_selective_v1` record with a consistent, persisted plan binding and exact paired route/rule identities can be abandoned by the Selective-specific command, under the existing Manager lock. Generic, modified, uncertain and future guarded records cannot be selectively abandoned; they retain their evidence. The stage/abandon responses acknowledge their exact committed operation, **not** whichever journal another manager may have written after the lock was released. These digests are not a MAC or protection against a privileged filesystem owner who can rewrite and rehash the entire record. Future guarded activation must establish independent rollback and revalidate every live network identity after this advisory stage.

Persist only necessary durable state with per-operation identity, original observed values including **absence**, expected objects, last verified safe state, and mutation progress. Prevent concurrent/stale operations and force fresh observation under lock before touching host state. Never treat a commit of desired state as evidence that foreign packets reach a peer.

## 3. Activation Guard

**Risky tunnel changes are always guard-protected.** The UI lets operators choose appropriate tests and a confirmation deadline (default 600 seconds) but may not silently disable the only recovery mechanism for host-wide routing modifications.

Sequence:
1. Inspect management route, domestic reachability, IPv4/IPv6, local resolver, current selected core/profiles, owned and foreign network objects, and operator's specified purposes.
2. Prepare deterministic minimal change plan plus trusted baseline and persistent operation journal. If the baseline or ownership cannot be established, **do not apply**.
3. Independently arm rollback with a verified local scheduler/service **before any route/rule mutation**; persist crash/reboot recovery intent and verify the guard really exists and can run. A timer alone is insufficient for reboot.
4. Validate sing-box configuration/transport and VPN endpoint underlay. Apply only the intended delta. Record each committed host effect before/after as required for crash reconciliation.
5. Verify requested egress path **through the selected outbound** and direct domestic/control paths, with independent DNS diagnosis. Require newly established SSH/admin console proof for material route mutation, bound to **this exact operation**. An already established terminal does not count.
6. Run an external fresh nonce/origin proof **only when operator selected ingress as an acceptance gate**. A user-facing link alone and a CDN cached response are not enough.
7. Commit only on all selected mandatory checks and authenticated operator acknowledgement within the deadline; disarm exactly the matching operation guard. Wrong/stale/late confirmations must fail.
8. Timeout, crash, reboot while pending, fatal preflight/dynamic safety loss, or failed mandatory check => immediate owned-delta rollback, last safe state verification and truthful report of missing proofs.

On reboot, do not blindly reapply an unconfirmed TUN. Recover the prior durable intent conservatively before any attempted activation.

## 4. Runtime Health Guard

Independent lightweight supervisory logic runs while a profile actively changes network routing. It observes core process/service, exact owned interface/rules, path-constrained real HTTPS/TCP probes and separately domestic/control connectivity. A healthy process or ICMP echo is not enough. A direct Internet request that bypasses the profile may **not** count as VPN health.

**Guard liveness is also an observed safety property.** An independently recoverable watchdog/supervisor (prefer a native, narrowly owned service/timer rather than a second full daemon) must detect an unexpectedly stopped, hung or disabled Runtime Health Guard while a host-wide route remains active. Failure to restore trustworthy observation within a bounded, tested interval must initiate safe owned-delta recovery instead of leaving an unmonitored dead route. Guard restart alone is not proof of route health; any conflicting or uncertain recovery must be reported explicitly. Neither this mechanism nor any local script can promise recovery after complete OS/kernel/provider failure.

Initial suggested defaults, operator-tunable and subject to physical validation:
- Health interval: 15 seconds.
- Startup grace: 30 seconds.
- Confirm path failure: 3 consecutive unhealthy rounds using meaningful independent probes.
- Terminal core loss or destroyed owned interface: prompt recovery without waiting for a DNS/ICMP timeout where identity is clear.
- Avoid declaring dead on one inaccessible website, one blocked Ping endpoint or temporary DNS failure that leaves other profile-bound connectivity healthy.

**On confirmed failure:** atomically/identity-safely remove the broken profile's owned routing effects; evaluate and apply the operator's failure policy; verify restored local routes and critical hosted/control paths; publish an explicit result and reason. The product must not remain stuck with an unusable intercepted default route.

Failure policy:
- **restore_direct (default):** retain/recover baseline host routing; no promise of foreign access.
- **restore_previous_verified (optional):** only if a previously committed configuration remains objectively valid; treat the transition as a new guarded operation.
- **hold_selected_egress (optional):** restore local management/domestic/hosting paths, but enforce a narrow fail-closed rule for operator-tagged VPN-required flows; never an unrequested whole-host lockout.

Backoff, retry count, eligibility for reconnect, cooldown and alerting are adjustable. Default should not infinitely switch/reconnect after failure. A disabled/not-required ingress probe failure is diagnostic only, not a reason to tear down working VPN egress.

## 5. Host conflicts, failure and crash

- Apply and undo only identity-verified owned changes; on conflict with modified foreign/host state, refuse destructive cleanup and report **UNCERTAIN** with actionable console-safe diagnostics.
- Detect if another manager changed an overlapping interface/route during the trial; do not replay an obsolete snapshot that overwrites newer external state.
- Test interruption between every meaningful mutation stage, failed fsync/journal/lock, process killing, disabled/hung health supervisor, disarmed timer, reboot during trial and reboot after committed activity.
- Local diagnostics must preserve original failure category: DNS, TCP, TLS, profile transport, route, firewall, interface, service, changed host baseline, insufficient permissions or probe endpoint failure.
- Protect opaque operation identifiers and provenance without logging bearer tokens, credentials, full VLESS links or private keys.
- Keep health state bounded and diagnosable; service restart does not magically attest that outbound traffic works.

## 6. Mandatory acceptance signals before production

Evidence must include real new SSH and real HTTP(S) requests to representative hosted services across enabled/disabled/failed states, both direct domestic and profile-bound foreign probes, local network ownership diff, rollback from an unconfirmed 10-minute activation, confirmed runtime outage, and power-cycle/reboot-stage recovery. Test nonfatal false positives to avoid spurious customer downtime.

Record: exact build/profile engine version (never secret profile content), test host OS/kernel/arch, baseline route/firewall/SSH conditions, captured failure class, expected versus observed route and exit state, measured resource footprint, and whether a real foreign datacenter endpoint was reachable.

**No claims of successful rollback or live connectivity exist before that evidence is collected.**
