# Safety, activation and recovery contract

**Product intent:** [PROJECT-SPEC.md](PROJECT-SPEC.md). **Host/resource design:** [ARCHITECTURE.md](ARCHITECTURE.md). This document defines the safety behavior required for a *future production Smart Routing TUN*, not proof that it has already been implemented.

## Invariants

- **Off/Direct restores ordinary baseline networking.** Explicit Disconnect and verified guard-driven deactivation remove **all** Server Connect-owned host-wide interception and VPN-only egress blocks. Original host routes/services operate normally, including foreign destinations if the baseline host permits them. Saved profiles and operator routing rules persist as inactive configuration and are revalidated/reapplied on the next guarded activation; a saved policy is not an active kernel policy. Enable, disable, update, crash recovery and uninstall change only identified Server Connect resources, never unrelated routes, DNS, firewall, SSH, aaPanel, Docker, Fail2Ban, STL or tunnels.
- **No unguarded host routing:** record a trustworthy pre-change host state, prearm and independently verify the recovery mechanism, then apply only an exact, reversible product-owned delta. If ownership or baseline is uncertain, refuse Apply and retain diagnostic evidence.
- **Protect access:** preserve present and fresh SSH/provider-console paths, panel, established inbound hosting replies (including foreign clients), local/Iran routes and the outer VPN endpoint's independent underlay/DNS bootstrap.
- **No hidden Direct fallback while routed:** while Smart Routing remains active or degraded, a failed/unsupported VPN transport must not silently send VPN-required public traffic Direct. Explicit operator Direct exceptions are a deliberate policy. A **verified transition to Direct/off** is different: the routed policy is disabled, its owned containment rules are removed, and the ordinary host routing policy resumes; never describe this as continuing VPN protection. Protect domestic, management and hosted traffic during diagnosis and transition.
- Recovery must work locally without functioning sing-box, remote VPN, Cloudflare, GitHub, foreign DNS or other external service. A provider rescue console remains necessary for kernel/host-wide failure outside in-host recovery control.

## Transaction states

| State | Required meaning |
| --- | --- |
| `DIRECT` | No product-owned host-wide interception. |
| `PREPARED` | Verified baseline, deterministic proposed delta and independently recoverable operation are established; no unsafe mutation yet. |
| `PENDING_CONFIRMATION` | Independently guarded network policy is active temporarily within one exact operation deadline. |
| `ACTIVE_VERIFIED` | All required selected-path, host safety and operator-confirmation gates passed; Runtime Guard is supervising the committed policy. |
| `DEGRADED` / `RECOVERING` | Real path/guard uncertainty under bounded diagnosis or exact-resource recovery. |
| `UNCERTAIN` | Conflict, incomplete proof or incomplete rollback; preserve evidence and refuse destructive guesses. |

**Beware historical naming:** the developer's `selective-stage-intent` may report `prepared`, but its private **unarmed, non-atomic** journal is **not** the guarded `PREPARED` state above. QA-only v2 RPDB-rule and v3 loopback-route trials also do not create a real TUN or production Activation Guard. Their limits and reproducible tests are recorded in [ACCEPTANCE.md](ACCEPTANCE.md).

### Disposable v4 guarded TUN trial (not production acceptance)

The installed experimental v4 journal never reaches `ACTIVE_VERIFIED`.
A pending trial is `trial_pending` (revision 1); ordinary timeout recovery
retains `trial_recovered` (revision 2). Explicit Disconnect durably advances
to `trial_stop_requested` (revision 2), then verified `trial_recovered`
(revision 3). Finalization uses `trial_cleanup_pending` (revision 4) before
credential removal. Its successful `trial_cleared` (revision 5) response is
an operation receipt, not a retained journal or permission to reactivate.
The journal binds the operation, profile, synthetic endpoint, native baseline digest, sing-box configuration digest, boot ID and monotonic
deadline. One opt-in synthetic dual-stack fixture uses the same v4 journal
and native IPv4/IPv6 baseline: the selected policy's exact bytes are bound by
its configuration digest; the IPv6 addresses/rules do not grant arbitrary
production routing authority. It records the journal **before** the credential, then durably records a
`core_start_attempted` transition before invoking the actual pinned sing-box
Linux TUN in a separate static service. A missing credential from a journal-first
crash is distinguishable from a vanished credential after start intent, even
on successive independent recovery ticks. A credential mismatch is not an
owned resource to discard simply because the kernel returned to baseline.
The recovery oneshot and 5-second systemd timer are independently prearmed
and verified before starting the TUN. The default expiry
is 600 seconds, configurable from 4 to 600 seconds in disconnected QA only.
A failed/uncertain restoration retains the journal, never presents Direct
as safely verified and blocks installer/update/profile/Proxy Only transitions.
The native fingerprint includes preexisting guest nftables objects. The current
foreign-object QA demonstrates retention of a separate table outside the core's
automatic cleanup targets; broader ownership is limited as described below.
If a running pending TUN loses its independently verified recovery timer or
executor, an explicit recovery invocation must stop **only the provenance-verified TUN
service immediately**, even before the recorded deadline. Loss of the guard
is never permission to keep an active pending interception running. Only full
native IP/nftables equality after stopping the verified service permits
`trial_recovered`, with `guard_scheduled=false`; unresolved stop, credential
or foreign-resource conflicts retain the operation and block Direct/Proxy Only.
Exact operation-ID/revision clearance disarms the remaining guard after
rechecking the credential. This is an observed-loss containment path in the
isolated guest, **not** a substitute for independent guard-liveness supervision
or the future production Runtime Health Guard (#3).

The dedicated trial Disconnect is bound to the exact current operation and
revision. It durably records deactivation intent before stopping the trusted
unit, verifies the complete native baseline, and finalizes only that operation.
A stale command cannot stop a replacement trial. Cleanup intent must be durable
before deleting a credential, so authorized removal can be resumed without
accepting an unexplained missing credential from a running or recovered trial.
An already visible cleanup phase is not proof that an earlier directory fsync
succeeded. Every cleanup retry must establish a successful durability barrier
for the exact current operation before removing its credential; a failed barrier
preserves the credential and recovery evidence for another attempt.
Observed foreign-resource drift or changed credential/unit provenance retains evidence
and blocks a successful Direct claim. The independent executor resumes durable
stop and cleanup intent while its timer is armed; status inspection alone must
not advance either phase. After native restoration and credential removal,
a crash following timer disarm may leave only a cleanup journal. That interval
requires an exact-operation retry of Disconnect or clearance at revision 4;
it is not claimed as autonomous timer recovery. The retained journal continues
to block installer/lifecycle changes until finalization succeeds.

The selected profile and validated, non-secret saved trial settings survive
Off. Saved reapply binds the policy and profile across both admission passes,
repeats guard prearming, and creates a new operation instead of restoring old
authority. Invalid or missing saved input is rejected before prearm. A saved
policy change detected during prearm blocks TUN activation and reconciles only
an uncommitted guard; it cannot disarm another journaled operation.

#### Automatic-policy ownership limit

The pinned core still creates and removes automatic Linux policy. Its
[sing-box constructor](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/tun/inbound.go#L375)
uses the fixed nftables table name `sing-box`; the pinned dependency's
[cleanup](https://github.com/SagerNet/sing-tun/blob/bca4bf029237/redirect_nftables.go#L392)
deletes that entire `inet` table by name. Its
[RPDB cleanup](https://github.com/SagerNet/sing-tun/blob/bca4bf029237/tun_linux.go#L1143)
uses a priority interval and fallback priority, rather than an operation-owned
object ledger. Other automatic route and compatibility-rule effects also need
an explicit ownership boundary before general host support.

The current link/profile/fixture admission does not exclude every overlapping
foreign object. Collisions or replacements inside the core's automatic cleanup
targets are **unsupported and unaccepted**, even in a guest that passes those
admission checks. A trusted service identity does not authenticate every kernel
object its upstream teardown can delete. The whole-host baseline is compared
**after** stopping the core: an overlapping object added after the baseline can
be deleted by that stop and leave baseline equality. Equality therefore cannot
prove that all foreign objects survived or detect every such deletion.

The accepted current evidence covers the controlled, nonoverlapping fixture
case only. General preservation, including overlapping owners and replacement
objects, remains an unfinished required product gate. These limits do not relax
the safety invariants or authorize wider activation.

This is one step toward the real activation state machine, **not** a
substitute for privileged third-party ownership/conntrack proof, SSH
confirmation, permanent commit, Runtime Health Guard, VPN-bound health
monitoring or physical crash/reboot tests. A restored guest baseline does
not certify production rollback safety or authorize public installation.

## Activation Guard

Default confirmation window: **600 seconds**, operator configurable. High-risk route changes require:

1. Inspect actual IPv4/IPv6 addresses, routes/rules, relevant packet filtering, conntrack/return paths, local resolver, VPN underlay, management access and foreign owners. Collect a deterministic minimum proposed delta and verified safe baseline, including expected **absence**.
2. Serialize the operation and durably journal its exact ID, resource identities, before/after intent, phase, boot identity and rollback deadline. Reject stale or conflicting operations; use crash-safe fsync/atomic storage. Judge deadlines with a **monotonic clock within the same boot**; reboot, clock changes or unverifiable deadline state must conservatively trigger reconciliation, not extend an unconfirmed Apply.
3. **Before any risky change**, arm and verify a recovery executor independent of the manager and sing-box; it must survive controller death and safely reconcile pending operations across reboot. A running timer alone is not sufficient proof that its executor can recover.
4. Validate the selected sing-box/profile and endpoint bootstrap. Reobserve resource identity against competing host owners immediately before each bounded apply.
5. Verify **real VPN-bound foreign egress**, **Direct Iranian/local**, endpoint underlay, active website/SSH replies and other selected checks through independent path-bound observations. A successful Direct probe is never proof of VPN delivery.
6. Require a **fresh SSH management session or explicitly approved provider-console confirmation** tied to this exact operation, within its deadline; an old still-open session, unrelated/replayed ID or a cached site response cannot authorize commitment.
7. Commit the desired state and disarm only the matching operation on complete evidence. On timeout, crash, reboot while pending, invalid confirmation or critical failure, restore only classified owned changes and verify the safest reachable baseline. Never reapply an unconfirmed TUN blindly after boot.

If an existing resource was replaced or altered by another owner, classify `UNCERTAIN`, preserve it and require controlled operator recovery instead of deleting/overwriting it. Reobserve native kernel identity and all relevant foreign dependencies before cleanup: an `ip route`/RPDB protocol tag or a matching rule number alone is **not authenticated proof of Server Connect ownership**, and a Manager lock cannot exclude independent privileged writers.

## Runtime Health Guard

An **independent** active supervisor tests the exact selected data path, owned interfaces/rules and a set of meaningful TCP/TLS/HTTPS endpoints. Direct-path success, process existence or a lone ICMP Ping is insufficient. Monitor actual DNS and supported IPv4/IPv6/UDP behavior and invalid/aged routing data when these can undermine the selected routing contract. Avoid treating one unreachable website as a dead VPN.

Suggested **initial field-calibrated defaults**, not validated performance guarantees: health interval **15 s**, startup grace **30 s**, and **3** consecutive unhealthy rounds before declaring a recoverable path outage. A definitive core exit or lost owned interface may justify faster recovery.

The guard's **own liveness** must be supervised independently; a dead, disabled, masked, hung or start-rate-limited executor is not healthy merely because its systemd timer shows active. If bounded trustworthy supervision cannot be restored, reconcile the owned tunnel policy to a safe state rather than leaving indefinite unmonitored interception.

On confirmed failure, prevent **unobserved** Direct bypass while the Smart Routing policy remains active/degraded. If independent guard, host access and resource ownership remain safe, attempt a short, bounded reconnect sequence; report `RECOVERING` and require fresh selected VPN-path proof before returning to healthy `ACTIVE_VERIFIED`. If attempts are exhausted, the failure is critical or the guard cannot safely continue, deactivate the policy, recover the exact owned network delta, preserve management/domestic/hosting connectivity, and report the resulting mode and reason. A state is not `DIRECT` merely because the VPN process exited; incomplete ownership/recovery is `UNCERTAIN`.

- `restore_direct` (MVP default): **deactivate** Smart Routing, remove its verified product-owned TUN/routing and any temporary VPN-only blocking rules, and restore normal host routing. Preserve the selected profile and saved routing settings for the next guarded enablement. Foreign Internet may or may not work over the restored Direct path; do not claim VPN protection or foreign reachability while off.
- `restore_previous_verified` (optional, only if separately supported): transition to another previously verified active configuration only through a newly guarded, independently verified Apply; never treat it as Direct/off or switch blindly.

**Deferred, not an MVP/release requirement:** an operator-selected persistent block for VPN-designated destinations while the VPN is **off** (formerly `hold_selected_egress`) would be a different explicit policy. Do not build, apply or test it as part of the first release without a new Owner decision. The current Direct/off state has no such product-owned blocking.

**Initial, field-calibrated reconnect candidate:** at most **3 automatic attempts per confirmed outage incident**, with short increasing delays and an overall recovery deadline; allow operator adjustment of the bounded attempt/time budget. Flapping must not reset the incident budget into an endless loop; reconnect only the selected VPN transport, **never replay interrupted application requests or arbitrary host operations**. Exhaustion triggers verified `restore_direct` and **no further automatic retries until an explicit new enable action**. Critical guard, ownership or protected-host-access failures bypass the retry delay and restore the safest available host baseline immediately. Report the failure cause, attempt count, last result and true current mode in status and credential-safe local logs. **Optional outage/recovery notifications are Owner-deferred**; no mandatory external alerting service, delivery dependency or separate notification worker in the first release. **Cloudflare Tunnel**, if separately enabled, has its own connector health: an unselected/failed website-origin check must not tear down healthy outbound Smart Routing.

## Required proof

The exact evidence and negative/physical test matrix lives in [ACCEPTANCE.md](ACCEPTANCE.md). Safety claims require at least authentic fresh SSH/hosting reply preservation, independent Direct versus VPN path evidence, expiry/replay/kill/reboot scenarios, competing host-network rules, and **failure of both the VPN and the guard itself**. Simulated or Docker-reset tests do not establish physical power-loss recovery.
