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
The default unconfirmed path uses the following control phases. A pending trial is `trial_pending` (revision 1); ordinary timeout recovery
retains `trial_recovered` (revision 2). Explicit Disconnect durably advances
to `trial_stop_requested` (revision 2), then verified `trial_recovered`
(revision 3). Finalization uses `trial_cleanup_pending` (revision 4) before
credential removal. Its successful `trial_cleared` (revision 5) response is
an operation receipt, not a retained journal or permission to reactivate.
The journal binds the operation, profile, synthetic endpoint, native baseline digest, sing-box configuration digest, boot ID and monotonic
deadline. New operations use the distinct native intent described below; legacy
automatic-policy records remain readable with their original semantics. One
opt-in synthetic dual-stack fixture uses the same v4 lifecycle and IPv4/IPv6 evidence: the selected policy's exact bytes are bound by
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
Journal version selection and recovery share one uninterrupted manager lock;
an absent or legacy observation cannot be reused after a concurrent Apply.
A failed executor cannot be reported as an available guard. New Apply does
not clear or ignore its failed result.
A failed/uncertain restoration retains the journal, never presents Direct
as safely verified and blocks installer/update/profile/Proxy Only transitions.
The native fingerprint includes preexisting guest nftables objects. Native
transactions additionally require durable per-object ownership receipts; legacy
automatic-policy trials have the narrower ownership limit described below.
If a running pending TUN loses its independently verified recovery timer or
executor, an explicit recovery invocation must stop **only the provenance-verified TUN
service immediately**, even before the recorded deadline. Loss of the guard
is never permission to keep an active pending interception running. A recovered result requires the intent-specific restoration proof: exact native
delta removal for the new intent, or full native IP/nftables equality for legacy
automatic policy. Unresolved stop, credential or ownership conflicts retain the
operation and block Direct/Proxy Only. A lost timer is reported honestly as
`guard_scheduled=false`; it never grants broader deletion authority.
Exact operation-ID/revision clearance disarms the remaining guard after
rechecking the credential. For the default pending mode, this is an observed-loss containment path in the
isolated guest; it does not establish independent guard-liveness supervision.
The explicitly supervised mode below adds that role within the same fixture.
Neither mode establishes the production Runtime Health Guard.

The dedicated trial Disconnect is bound to the exact current operation and
revision. It durably records deactivation intent before stopping the trusted
unit, verifies the intent-specific native restoration, and finalizes only that operation.
A stale command cannot stop a replacement trial. Cleanup intent must be durable
before deleting a credential, so authorized removal can be resumed without
accepting an unexplained missing credential from a running or recovered trial.
An already visible cleanup phase is not proof that an earlier directory fsync
succeeded. Every cleanup retry must establish a successful durability barrier
for the exact current operation before removing its credential; a failed barrier
preserves the credential and recovery evidence for another attempt.
Conflicting or uninspectable foreign ownership and changed credential/unit provenance
retain evidence and block a successful Direct claim. Supported disjoint changes
do not require a native transaction to overwrite the host with an old snapshot. The independent executor resumes durable
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

Native and legacy trial recovery share one owned core-stop proof. Without a
durable core-start attempt, recovery is observation-only: both the original and
a fresh same-owned unit observation must prove `inactive`/`dead`, successful and
without live work. Unexpected activity is left unchanged so a recovery command
cannot erase the conflict before the next attempt. A started operation still
contains its owned core when the credential is missing or changed, while
retaining that credential conflict.

An acknowledged `systemctl stop` may leave an already failed service in `failed`
([systemd stop handling](https://github.com/systemd/systemd/blob/v257/src/core/unit.c)).
Before normalizing that bookkeeping, require the same installed unit identity
and digest, no queued job or main/control PID, and a released systemd cgroup.
During [systemd's inactive/failed cleanup](https://github.com/systemd/systemd/blob/v257/src/core/cgroup.c),
the path is released only after recursive emptiness.
Only that quiescent, authenticated core, with a durable core-start attempt and
an unchanged operation-bound credential, may have its failed state reset. Then
reobserve the same unit as `inactive`/`dead` with no live work before declaring
containment complete. Preserve the original pre-stop state for credential-trust
decisions. Query/stop/reset uncertainty, residual work or changed provenance
retains recovery evidence and native protection. This deactivation-only action
does not reset a failed guard or authorize another activation.


#### Supervised native lifecycle

`smart-tun-trial-apply --supervised` retains the exact disposable admission,
independent recovery prearm and native ownership contract. It adds a required
strict `supervised` record under a separate intent. The top-level transaction
phase/revision continues to describe pending resources, stop, recovery and
cleanup; it does not by itself describe confirmation. The receipt's separate
`supervision_state` distinguishes awaiting confirmation, healthy, degraded,
reconnecting, stopped and uncertain. Neither a confirmed experiment nor a
healthy probe grants general-host `ACTIVE_VERIFIED`.

A random one-use challenge is returned only by successful initial Apply after
the native capture policy is complete. The private journal retains its digest,
not a recoverable challenge value. Status cannot reissue it. Confirmation must
match the operation, control revision, boot, selected configuration and deadline,
and must carry the fresh authenticated management evidence described below.
A replay, stale operation or old multiplexed transport cannot confirm another
activation. Publishing confirmation requires the unchanged complete journal and
current native ownership proof; interrupted publication retains recovery state.

The installed health oneshot has a 20-second systemd execution limit and a
separate 5-second timer. It publishes operation-bound progress; independent
recovery checks actual executor provenance, state and bounded progress, not
just an active timer. Dead, failed, disabled, masked, missing or hung supervision
must end in exact owned restoration or explicit uncertainty. The health role
also refuses to keep routing when independent recovery is unavailable. Network
probes run outside the manager lock, and their results require exact journal,
boot and ownership revalidation before publication. Stale concurrent results
cannot revive a stopped or replacement operation.

Health separates a device/source/mark-bound protected underlay witness from
ordinary selected-path TCP, UDP and DNS wire probes. The latter use fresh
nonces and independent peer-observed source evidence; Direct responses cannot
satisfy VPN health. Each enabled address family has two destinations, so one
failed site is not a total-path failure. The custom TCP witness proves that
fixture's TCP delivery; it does not imply TLS/HTTPS health or foreign Internet
reachability. DNS is a fresh bounded wire exchange, not a cached host resolver
answer. DNS evidence is UDP transport with an IN/A question, including when
the transport uses IPv6; it does not establish system-resolver/bootstrap or
AAAA-answer behavior. The aggregate probe round is bounded to four seconds.

Defaults are a 15-second probe interval, 30-second startup grace, three failed
rounds, at most three reconnect attempts for the entire operation and a
120-second deadline for each degraded incident. A successful interval can end
an incident, but never replenishes the operation's consumed attempt budget.
These are experimental bounds, not field-calibrated promises. Native
containment remains present during reconnect. Restart affects only the exact
selected core and requires durable pre-start intent, a fresh attachment witness
and fresh selected-path success. A missing attachment receipt remains uncertain
even if a later process snapshot appears healthy. Short healthy intervals cannot
erase an incident's consumed budget. Exhaustion or a critical guard/underlay
failure enters owned Off recovery; incomplete ownership is `UNCERTAIN`.
A core exit or unapproved process generation change is classified as critical
and goes directly to owned Off; only selected-path failure with the same live,
trusted core is eligible for bounded reconnect. Saved policy and profile
survive, and another activation requires an explicit new Apply. No application
request or arbitrary host operation is replayed.

A killed or timed-out health oneshot can leave failed systemd bookkeeping after
verified Off. Fresh Apply refuses that failed role until the exact trusted idle
unit is explicitly reconciled; it does not silently reset a changed, masked or
missing executor. The disposable QA labels any such operator remediation
separately. Both health and independent recovery emit the operation-bound
reason, attempt count and timestamped evidence in their structured local
service output, including the final Off receipt after journal removal.

#### Native ownership and containment

Native pending trials use exact intent `smart_tun_native_pending_trial_v1`;
explicitly supervised trials use `smart_tun_native_supervised_trial_v1`.
Both require the versioned native subrecord. The complete native and, where
applicable, supervision subrecords participate in journal substitution checks
and are copied before progress changes. Legacy v4 keysets remain strict;
unknown intents, partial records or mixed legacy/native/supervised authority
are rejected. Saved settings never supply deletion rights.

The native ledger binds namespace identity, underlay and TUN indices, observed
link/address/dependency hashes, route/rule stages and receipts, and the complete
ordered nftables graph with original handles. Resource labels, route protocols,
priorities and intended configuration identify the scope to inspect; they do
not authenticate ownership by themselves. Whole-host equality is not used to
remove objects added by another owner after admission.

Nftables JSON is a compiler representation, not a byte-for-byte echo of the
submitted commands. The native policy emits the supported canonical chain,
prefix and expression shape; observed rules keep their full fields and order.
Numeric-output flags do not force numeric interface indices in nftables 1.1.3:
its [interface printer](https://sources.debian.org/src/nftables/1.1.3-1/src/meta.c/)
and [JSON serializer](https://sources.debian.org/src/nftables/1.1.3-1/src/json.c/)
render an existing index as a name and an absent index as a decimal string.
Only typed `iif`/`oif` operands receive index normalization, using complete
name/index observations before and after the nft dump and the pinned underlay
and any present TUN identity. Ambiguous names or changed mappings are refused;
`iifname`/`oifname` retain their distinct name semantics. Nft generation checks
remain separate from link identity checks, and original handles remain part of
the ownership receipt after the owned link disappears.

TUN creation is exclusive and initially scoped to an open nonpersistent FD.
The manager disables IPv6 address autogeneration before bringing up the link,
records the complete observed identity durably, and only then makes it
persistent. The core receives an addressless explicit gVisor configuration with
automatic route, redirect and DNS management disabled. This prevents the core's
broad automatic-policy teardown from owning the native transaction. Its CLI
still attaches by name and may change link state/MTU: a bounded link-event watch,
exact pre/post identities and a durable verified-start receipt constrain that
boundary. Failed or incomplete start observation cannot be converted into
success by a later snapshot.

Every mutating `ip`/`nft` subprocess inherits the existing shared lock's open
file description and a parent-death SIGKILL. The creating OS thread is pinned
through synchronous Run/Wait because Linux binds that signal to the creating
thread's lifetime. The manager joins the child before releasing the thread or
normally unlocking. On controller death, the independent executor waits until that
child releases the inherited lock; a late command must not install policy after
an absence snapshot was finalized. This reuses the existing serialization
boundary and does not reserve resources against independent privileged owners.
Command timeouts, ACK loss and post-effect/pre-receipt crashes remain explicit
uncertain outcomes. A present object with no durable receipt is never adopted
from matching fields. An absent object can be reconciled only after outstanding
mutators are excluded and the complete current ownership graph is observed.

The independent nftables guard reclassifies public traffic rather than trusting
only the capture mark. It checks the resulting output interface in POSTROUTING:
a later OUTPUT filter still sees the initial interface after an OUTPUT route
hook reroutes the packet. The final drop requires zero ingress interface so
this host-origin policy does not intercept unrelated forwarded traffic.
Core bypass, protected local traffic and inbound-service
reply direction have narrowly shared exceptions; new host-origin traffic to a
foreign visitor remains subject to VPN policy. Unsupported public protocols
must not silently bypass. Local IPv6 neighbor discovery and other explicitly
supported link control use constrained underlay exceptions, not broad public
ICMP allowances. A compiler configuration is not packet-level proof of these
properties; the required native witnesses are in [Acceptance](ACCEPTANCE.md).

Recovery first contains the exact core and reobserves the entire owned graph.
For a receipted native policy, it requires the intact original guard subgraph
before removing remaining capture routes/rules or the TUN. Before policy
creation, or when an unreceipted policy is conclusively absent after outstanding
mutators are excluded, cleanup may proceed without a guard. A present
unreceipted graph remains uncertain. Losing only capture can therefore recover;
losing the guard/drop identity retains the remaining footprint and reports
`UNCERTAIN`. Original-handle subset ownership alone is insufficient containment.
Unexpected credential loss/tampering after native core-start intent also
contains the core but retains protection and recovery evidence. Stopping the
process is not a Direct transition.

Before link deletion, observe all addresses and relevant native dependencies,
including foreign routes and interface selectors. Unsupported indirect forms
must be refused, not ignored. Before nftables table deletion, obtain a nonzero
generation, inspect the complete table and its ordered original child handles,
and recheck the generation. Delete only that exact table handle in a kernel
batch conditioned on the same generation. Concurrent committed changes force a
bounded retry or uncertainty. A missing/invalid commit ACK is an unknown result,
not permission to retry an unconditional delete. The guard is removed last,
after the remaining native routing footprint is proven absent. Direct is
reported only after final independent reobservation and protected underlay checks.

Supported disjoint objects survive automatic Off. A foreign same-link address,
route/rule collision, new/replaced nftables child, observation loss or ambiguous
receipt can require separately controlled operator recovery. Recreating an
object with a new handle does not restore its original identity. QA that removes
exact guest-owned conflicting resources is explicitly operator-assisted and
never presented as automatic rollback. The timer remains armed and evidence is
retained while recovery is incomplete. Status inspection does not perform repair.

Foreign nftables admission accepts only the supported passive matching,
counter/filter/log/limit/quota and jump/goto statement forms, followed by the
mark/interface dependency checks. NAT, packet/metadata assignment, redirection,
duplication/forwarding, userspace queueing, notrack/connection-tracking assignment,
flowtable/offload and unknown effect statements are unsupported. They must
remain absent throughout the pending operation. Later independent privileged
path rewriting can affect packets before the periodic executor observes the
conflict. Detection contains the owned core and retains evidence; it does not
prove instantaneous containment against that newly introduced foreign policy.

The nft generation condition covers committed nftables changes, not an
unobservable identical route/rule replacement by a concurrent privileged writer.
Network namespace/boot changes cannot authenticate reused native identifiers.
This fixture-only boundary does not establish arbitrary multi-owner host
support, physical power-loss recovery, permanent `ACTIVE_VERIFIED`, trusted
Iranian routing data or DNS/domain authority. Those remain required gates for
general Smart Routing.

#### Automatic-policy ownership limit

The retained legacy automatic-policy trial and standalone compiler QA let the
pinned core create and remove automatic Linux policy. Its
[sing-box constructor](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/tun/inbound.go#L375)
uses the fixed nftables table name `sing-box`; the pinned dependency's
[cleanup](https://github.com/SagerNet/sing-tun/blob/bca4bf029237/redirect_nftables.go#L392)
deletes that entire `inet` table by name. Its
[RPDB cleanup](https://github.com/SagerNet/sing-tun/blob/bca4bf029237/tun_linux.go#L1143)
uses a priority interval and fallback priority, rather than an operation-owned
object ledger. Other automatic route and compatibility-rule effects also need
an explicit ownership boundary before general host support.

Legacy automatic-policy link/profile/fixture admission does not exclude every overlapping
foreign object. Collisions or replacements inside the core's automatic cleanup
targets are **unsupported and unaccepted**, even in a guest that passes those
admission checks. A trusted service identity does not authenticate every kernel
object its upstream teardown can delete. The whole-host baseline is compared
**after** stopping the core: an overlapping object added after the baseline can
be deleted by that stop and leave baseline equality. Equality therefore cannot
prove that all foreign objects survived or detect every such deletion.

This legacy evidence covers the controlled, nonoverlapping fixture case only.
The native transaction above avoids that automatic cleanup and adds per-object
refusal/reconciliation, but general preservation against arbitrary overlapping
owners and replacement objects remains an unfinished product gate. These limits do not relax
the safety invariants or authorize wider activation.

This legacy evidence is one step toward the real activation state machine;
it does not establish privileged third-party ownership/conntrack proof, SSH
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

### Fresh management confirmation evidence

For the disposable supervised native lifecycle, confirmation is deliberately
limited to a new authenticated root OpenSSH connection over the admitted guest
management path. An operation challenge is issued only after native capture is
complete. Its monotonic boot-relative time, operation, configuration and control
revision bind the confirmation. The original Apply shell and a new channel on an
older SSH multiplexed connection cannot satisfy that requirement.

The observer verifies the caller's actual process ancestry, trusted installed
OpenSSH executable identity, root session ownership and network namespace. A
bounded read-only Linux `SOCK_DIAG_BY_FAMILY` dump binds an established TCP tuple,
inode and kernel socket cookie to a descriptor held by that ancestor. The oldest
transport-owning session process must have started strictly after the challenge;
process lifetime, ancestry, descriptor and socket generation are checked again
before returning evidence. `SSH_CONNECTION`, `SSH_CLIENT`, process names and
operator-supplied timestamps are not authentication. Ambiguous, missing or
changed evidence refuses confirmation. Provider-console confirmation and
non-root/sudo management sessions require their own future accepted proof; they
are not silently treated as equivalent to this root-only fixture.

The kernel's [process lifetime documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
and [socket diagnostic UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/inet_diag.h)
explain the observation boundary. OpenSSH's [per-session executable split](https://www.openssh.com/releasenotes.html)
is handled through the installed `sshd` / `sshd-session` executable identities.
These are Linux/session observations, not an external management attestation or
a general physical-host acceptance claim.

## Runtime Health Guard

An **independent** active supervisor tests the exact selected data path, owned interfaces/rules and a set of meaningful TCP/TLS/HTTPS endpoints. Direct-path success, process existence or a lone ICMP Ping is insufficient. Monitor actual DNS and supported IPv4/IPv6/UDP behavior and invalid/aged routing data when these can undermine the selected routing contract. Avoid treating one unreachable website as a dead VPN.

Suggested **initial defaults for future field calibration**, not validated performance guarantees: health interval **15 s**, startup grace **30 s**, and **3** consecutive unhealthy rounds before declaring a recoverable path outage. A definitive core exit or lost owned interface may justify faster recovery.

The guard's **own liveness** must be supervised independently; a dead, disabled, masked, hung or start-rate-limited executor is not healthy merely because its systemd timer shows active. If bounded trustworthy supervision cannot be restored, reconcile the owned tunnel policy to a safe state rather than leaving indefinite unmonitored interception.

On confirmed failure, prevent **unobserved** Direct bypass while the Smart Routing policy remains active/degraded. If independent guard, host access and resource ownership remain safe, attempt a short, bounded reconnect sequence; report `RECOVERING` and require fresh selected VPN-path proof before returning to healthy `ACTIVE_VERIFIED`. If attempts are exhausted, the failure is critical or the guard cannot safely continue, deactivate the policy, recover the exact owned network delta, preserve management/domestic/hosting connectivity, and report the resulting mode and reason. A state is not `DIRECT` merely because the VPN process exited; incomplete ownership/recovery is `UNCERTAIN`.

- `restore_direct` (MVP default): **deactivate** Smart Routing, remove its verified product-owned TUN/routing and any temporary VPN-only blocking rules, and restore normal host routing. Preserve the selected profile and saved routing settings for the next guarded enablement. Foreign Internet may or may not work over the restored Direct path; do not claim VPN protection or foreign reachability while off.
- `restore_previous_verified` (optional, only if separately supported): transition to another previously verified active configuration only through a newly guarded, independently verified Apply; never treat it as Direct/off or switch blindly.

**Deferred, not an MVP/release requirement:** an operator-selected persistent block for VPN-designated destinations while the VPN is **off** (formerly `hold_selected_egress`) would be a different explicit policy. Do not build, apply or test it as part of the first release without a new Owner decision. The current Direct/off state has no such product-owned blocking.

**Initial reconnect candidate, subject to field calibration:** at most **3 automatic attempts per confirmed outage incident**, with short increasing delays and an overall recovery deadline; allow operator adjustment of the bounded attempt/time budget. Flapping must not reset the incident budget into an endless loop; reconnect only the selected VPN transport, **never replay interrupted application requests or arbitrary host operations**. Exhaustion triggers verified `restore_direct` and **no further automatic retries until an explicit new enable action**. Critical guard, ownership or protected-host-access failures bypass the retry delay and restore the safest available host baseline immediately. Report the failure cause, attempt count, last result and true current mode in status and credential-safe local logs. **Optional outage/recovery notifications are Owner-deferred**; no mandatory external alerting service, delivery dependency or separate notification worker in the first release. **Cloudflare Tunnel**, if separately enabled, has its own connector health: an unselected/failed website-origin check must not tear down healthy outbound Smart Routing.

## Required proof

The exact evidence and negative/physical test matrix lives in [ACCEPTANCE.md](ACCEPTANCE.md). Safety claims require at least authentic fresh SSH/hosting reply preservation, independent Direct versus VPN path evidence, expiry/replay/kill/reboot scenarios, competing host-network rules, and **failure of both the VPN and the guard itself**. Simulated or Docker-reset tests do not establish physical power-loss recovery.
