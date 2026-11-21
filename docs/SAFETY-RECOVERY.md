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

**Historical journal compatibility:** persisted v1 `prepared` selective records were unarmed, non-atomic advisory intent, not the guarded `PREPARED` state above. Creation of new v1/v2/v3 experiments is retired. Strict recognition, exact v1 abandonment and ownership-aware v2/v3 recovery remain until safe cleanup has been demonstrated; none proves active VPN routing. See [ACCEPTANCE.md](ACCEPTANCE.md).

### Retired journal and Native guard admission

Historical v4 experimental trial creation, confirmation and management are
retired; the old v4 Core systemd unit is absent in the new package. A
persisted v4/unknown journal or installed old unit is **not** proof of safe
Direct/off and blocks fresh Native activation. The installer never adopts
a legacy operation, replays its saved policy or replaces its recovery binary
over uncertain state. A disposable QA release may be uninstalled only after
verifying that its own claimed resources have been removed.

Native `ExecStartPre` independently verifies a current-boot,
configuration-bound one-use claim and effective trusted Health/Recovery
roles. A stale claim cannot authorize activation; the owned stop/recovery path
may still complete Direct/off after verifying kernel identities and preserving
foreign owners.

### Native inbound-reply guard (Issue #3, development candidate)

The pinned official sing-box 1.14.3 `auto_redirect` adds a separate TCP NAT
`OUTPUT` hook. During physical Debian 13 QA, applying that policy produced a
locally generated, spoofed-foreign-peer TCP RST and dropped an **already
established** authenticated foreign SSH connection. The same SSH witness ran
57/57 replies with Direct/off and 4/57 or 29/57 without correction.
An independently preinstalled narrow route hook at priority `-150` preserved
58/58 authenticated replies while the identical Core executed. That manually
staged proof alone is **not** integrated-product or production acceptance.

The integrated candidate's single fixed `inet sc_reply_guard` table has
one `route OUTPUT` chain at priority `-150`, using the official
`auto_redirect_output_mark` (`0x2024`). A conntrack `REPLY` rule
protects the ordinary tracked inbound case. This alone was insufficient in
physical QA: on a host where TCP sessions were established **before**
conntrack began observing them, their first observed packet can be from
server to client and conntrack may call that direction `ORIGINAL`
(or have no existing row).

Immediately before native activation, the manager takes a read-only snapshot
from the kernel's IPv4/IPv6 TCP socket tables of *established accepted TCP
sockets whose local endpoint matches a currently listening socket*. Two
concatenated nft sets store only those specific
`local IP . local port . peer IP . peer port` tuples, one per address
family. The additional rules mark `ct direction original` **only** when
the packet matches a preexisting accepted tuple. These constant-count,
hash-lookup rules create no blanket direct exception for a foreign IP, an
entire listening port, or a subnet. A new server-originated connection to
that same foreign IP with another TCP four-tuple is not in either set and
remains VPN-required. The immutable snapshot also protects the case where
an old accepted connection has not yet entered conntrack at activation.
This is an admission-specific TCP fix, **not** broad UDP/DNS/IPv6 routing
or hosted-HTTP acceptance.

In the field comparison, reply-only installed candidates failed after
5 SSH replies; a separate exact-accepted-socket guard preserved 58/58
original SSH replies on the same physical target and observed 9 matches
of the reversed/previously untracked tuple rule. That separately staged
experiment passed; the subsequently integrated **snapshot-backed**
candidate still requires its own full installed field proof. The existing
three-namespace fixture also checks selected VLESS wire counters versus
direct egress but does not reproduce the original physical SSH failure.

The native one-use, configuration-bound current-boot session and both
independent timers must be durable **before** installing the nftables reply
guard. The manager computes the canonical accepted-tuple fingerprint and
persists it in the one-use native claim **before** the atomic nft transaction,
then durably records the observed table handle before `systemctl start`.
An interrupted table-creation/handle-commit window can therefore still be
recovered by the independent stop guard without adopting a foreign table.
`ExecStartPre` rechecks fresh startup authorization, complete native
admission, exact table handle **and** complete accepted-tuple fingerprint,
then durably consumes a one-use Core-start grant before Core execution.
A failed preflight or Core start cannot silently reuse a stale receipt.
Runtime status and health independently attest the same table, hook,
rules, tuple sets and fingerprint. Merely seeing an active Core never
establishes selected-path health.

**Native startup packet admission (unmerged candidate):** An observed
release-blocking Direct TCP SYN escaped while `desired=smart` and the
systemd Core unit was already `active` but the TUN did not yet exist. The
manager must install a distinct, one-operation `inet sc_pre_<operation-id>`
nft OUTPUT filter **before publishing `desired=smart`**, not merely
before `systemctl start`. The independent Health/Recovery roles and narrow
accepted-reply guard are prearmed first; the temporary filter blocks new
unmarked public egress on **all** host interfaces. Only the official Core's
output-marked sockets (`0x2024`), proven accepted-session replies,
loopback and validated connected/private destinations are exempt. There is
**no** public operating-system DNS exception and **no** general IP/port
exception for the VPN peer: either could allow unrelated applications
to bypass VPN-required startup containment. A precommitted private
digest-bound plan,
exact rule/chain/handle receipt, and generation-conditional deletion
prevent name-only cleanup or adoption of a foreign table. It is **not**
a permanent kill switch, second router, or an off-mode block.

A `Type=exec`/PID-active Core does **not** release the filter. Admission
requires independent actual TUN, kernel RPDB, marked selected route and
official-Core redirect proof; status remains starting while the filter is
armed. On failed start or unverified release the owned recovery path
must first restore exact Direct/off and remove precisely its own filter
alongside Core and reply guard resources. The guard retains a bounded
pre-Core grace only while the real packet filter is independently
verified. A post-CLI check alone misses the earlier state-commit gap;
the disposable VM packet-capture regression is
[`native-startup-concurrent-syn.py`](../scripts/qa/native-startup-concurrent-syn.py).
No physical-server/no-leak or public release conclusion follows from VM
observations alone.

The Debian 12 (`nftables` 1.0.6) installed-Core candidate exposed a
real version-specific enumeration difference: it lists `table,set,set,chain,rule,rule,rule`,
where Debian 13 lists `table,chain,set,set,rule,rule,rule`. The initial
single-order strict parser refused to verify its *own* newly installed
reply hook, then retained the early precommitted claim and table as
`UNCERTAIN`. Inspection now admits **only these two exact known layouts**;
within both, the original set identities and order, chain hook/priority,
all rule bodies and order, accepted-socket digest, table handle and
netlink generation-CAS owner checks remain unchanged. No arbitrary nft
object sorting, table-name-only deletion or broad policy flush is allowed.
The installed Debian 12 Health/Recovery executor exposed an additional
format-only difference: nftables 1.0.6 writes the TCP protocol as numeric
`meta l4proto 6 counter`, while nftables 1.1.3 writes
`meta l4proto tcp counter`. The read-only native health policy witness
requires a **single output-NAT-chain redirect rule** that contains the
actual TCP (IPPROTO_TCP=6) match, counter and redirect in order, after that
chain's own expected hook. A counter in `output_prematch`, or a detached,
uncounted, UDP/other-protocol redirect, cannot substitute. Every
preceding output-chain rule is also checked for terminal/diverting effects:
an earlier TCP/general `return`, `accept`, transfer or destination rewrite
cannot hide behind a valid later redirect. Core's explicitly scoped
underlay/conntrack marks, local-address sets, unsupported-family rejection
and MPTCP exception remain permitted; no arbitrary number-of-rules limit
is imposed. This is a read-only policy witness, not full proof against
arbitrary foreign nft ruleset changes. All fixed RPDB, marked selected
route, native capture
hook/redirect, chain and reply-guard identity checks still apply. A
missing/changed policy remains fail-closed, with independent Core stop
and exact-owned Direct restoration.
Success requires the exact-candidate Debian 12/13 installed lifecycle CI
and separate physical evidence; a source fix alone is not acceptance.

On normal Disconnect, Core exit, or a failed preflight, independent
`ExecStopPost` first recovers the exact owned Core resources, then inspects
the reply-guard table and deletes only its verified table handle using the
existing nftables generation-conditional Netlink transaction.

A physical Debian 13 native-Core `SIGKILL` exposed a distinct orphan
ordering: Core's randomized redirect-table RPDB identity, nft table and TUN
can disappear while its *fixed-slot* 14200-series/32768 IPv4/IPv6 RPDB
rules survive. Previously, the missing randomized identity always blocked
recovery, leaving the guarded host in an explicitly failed Smart state.
For this one post-crash case, cleanup of the remaining **exact fixed-slot
RPDB rule bodies and priorities only** (14200, 14201, 14202 and **32768** per
family) is permitted only under the already-consumed one-use Core-start claim.
The receipt is bound to the previously staged **health operation ID**, exact
configuration digest and current **boot ID**. The installed stop path must
reattest the **actual nftables reply-guard table handle, complete hook/rule/
accepted-tuple structure and committed fingerprint before any orphan-RPDB
deletion**. A stale operation/boot, replaced/missing table, or uncertain read
cannot authorize orphan-rule deletion.

Systemd Core quiescence is more than `MainPID=0`: stopped/failed idle units
must have no ControlPID, Job or cgroup. The installed **ExecStopPost** itself
is the narrow exception while systemd reports `deactivating/stop-post`: its
`ControlPID` must identify the current recovery process. Pending
`ExecStartPre`, start jobs and unrelated control processes are not stopped
Core proof. These observations are checked again before kernel recovery.

Both IPv4 and IPv6 RPDB rule inventories are inspected **before any
mutation**, including foreign references to the reserved table at priorities
below/above the Core interval. All admission, recovery and active-health
RPDB checks and selected marked-route observations request numeric
`ip -N` table identities; configurable `rt_tables` names must never hide
a foreign reference to table 27432. A lookalike fallback rule at priority
30000 cannot be adopted as the fixed priority-32768 Core rule. The Core's reserved
route table must be empty, the randomized redirect and Core nft identities
absent, no foreign Docker-compatibility rules may survive, the native TUN must
be absent and no unattributed loopback redirect route to the underlay may
remain. Any malformed or duplicate rule, foreign identity or unverified
lifecycle blocks mutation. Legitimate partial subsets of exactly owned rules
remain retryable, and the reply table is deleted **after** RPDB cleanup, with
its original generation-conditional netlink delete.

A completely clean Direct kernel is separately verified read-only and may
finish a retained claim even when its already-deleted reply table is absent;
it is **not** permission to delete orphan RPDB without the owner. An
interrupted preflight can have the guard table but not its handle; the
previously persisted fingerprint still authorizes only that narrow
pre-start guard cleanup, never the consumed-start orphan exception.
A later foreign replacement, additional/missing rule or tuple, changed mark,
nft generation drift, uncertain deletion or mismatched handle **retains the
recovery claim and blocks success** rather than deleting by name or presenting
unverified Direct/off. The shared installer must refuse orphaned reply-guard
objects without a cleared claim; idle Direct must not contain this table.

This guard **does not** grant general-host acceptance for SSH/HTTP hosting,
UDP, DNS, IPv6, real Iran Direct, or an actual foreign VPN provider. Record
separate positive old/new SSH and hosted-HTTP replies, negative same-client-IP
outbound-VPN proof, guard-loss/failure cases and exact post-recovery kernel
identity on the reviewed integrated binary before V1 release.

For the separate *native sing-box lifecycle*, an independently verified
Direct/off transition may leave either or both of the exact installed Health
and Recovery oneshots in systemd `failed` bookkeeping. A fresh Connect may
wait for previously scheduled executors to finish and then normalize **only**
their proven idle owned records before new prearm. Likewise, the shared offline
installer checks the cleared private native/legacy claims and Direct intent
under its existing lifecycle lock, both disabled timers, stopped native/legacy
cores and no live guard PID, job or cgroup before normalizing either stale
failed oneshot. Partial reset failures abort installer mutation; unrelated
systemd services and kernel routing are never reset by this bookkeeping
repair. This does not grant production admission or assume a failed guard is
healthy while an operation remains active.

The installed Native systemd roles and their operation-bound resource
receipts—not a retired v4 trial journal—are authoritative for Core stop,
cleanup and failed-executor bookkeeping. Before any fresh Connect or
installer mutation, the manager establishes Direct intent, no active
owned operation/guard job or PID, and exact service/timer quiescence.
Only a verified idle owned unit may have stale `failed` systemd
bookkeeping normalized. A pending or unknown historical journal,
unexpected service activity, failed stop or ambiguous kernel/foreign
ownership keeps the recovery evidence and blocks Native activation.
Neither the installer nor idle health checks reset unrelated units.

The current Native lifecycle does not use the retired trial's
`--saved` reapply, manually created addressless TUN, experimental
confirmation socket, v4 operation credential, or custom RPDB/nftables
engine. Profiles and saved operator routing rules survive Off; a fresh
`connect-smart` revalidates them and establishes a new one-use,
current-boot Guard claim. Detailed Native stop, orphan RPDB recovery,
inbound-reply guard, kernel ownership and selected-path Health contracts
follow below and define current installed QA acceptance independently
of historical trial evidence.

#### Single official-Core Native lifecycle

The Native candidate uses official sing-box `auto_route`/`auto_redirect`,
an independently receipted inbound-reply guard, and operation-bound
Health/Recovery roles. The custom manager-owned TUN/route/nftables engine,
supervised v4 QA TLS client, and automatic-policy experiment were retired,
not converted into another data plane.

Before Native Core startup both Guard roles must be freshly armed and
ownership verified. While active or degraded, VPN-required traffic must not
silently return Direct. An independent Health failure or manual Disconnect
triggers exact owned-resource cleanup and preserves saved profiles/rules.
Ambiguous kernel resources or interrupted rollback retain the operation
claim and report `UNCERTAIN`, never silently reset foreign ownership.
Installed Debian 12/13 QA exercises the current Native Core, selected
VPN/Direct packet witnesses, missing HTTPS fallback, and verified Direct/off.
The remaining physical field and healthy selected-HTTPS gates are separate.

## Native candidate stop and reboot recovery (not production admission)

The candidate's official sing-box native TUN service is **started per session,
not enabled for reboot**. Its owned systemd `ExecStopPost` independently
recovers only proven native route/RPDB/nftables resources after a normal stop,
Core crash or host shutdown. Once exact recovery succeeds, it persists
`desired=direct` before durably retiring the one-use recovery claim. A failed
or unproven native cleanup retains the claim and must not be described as
Direct/off. The private inactive compiled Core config is removed by the next
explicit Disconnect. Ordinary systemd failure bookkeeping may still show
`failed` after a SIGKILL; this is not proof that a VPN path remains active.
Saved profile and rules persist and the next Smart Routing activation must
revalidate them. No native session resumes VPN automatically after reboot. The independently
scheduled recovery role can retire a verified Direct/off health receipt and
disarm remaining health timers without adopting a replacement session. This
candidate lifecycle and its guard do **not** license general-host deployment.

### Native selected-path Runtime Health Guard candidate

Native Connect prearms the existing **two independent systemd timer/oneshot
roles**, staging a private configuration digest, boot ID, operation nonce,
monotonic heartbeat and bounded failure counters. Do not mistake process
`active` for selected-VPN health. Each health round binds IPv4 HTTPS TCP
to sing-box's reserved native `SO_MARK=0x2023` and requires independent
pre/post proof that the exact native RPDB rule, selected TUN routing table,
marked FIB lookup and official nftables OUTPUT capture are still present.
This is required because a direct `SO_BINDTODEVICE` on the sing-box TUN
fails to route on supported Debian guests; an unmarked probe could
wrongly succeed Direct after capture loss. The compiled Core policy must
independently classify each literal health destination as VPN-bound using
first-match route precedence, including operator CIDR and inline country
rule-set Direct exemptions; an HTTPS 200 received Direct is not proof.
The two fixed target hosts
use ordinary TLS hostname verification, bounded read/timeout and no
inherited HTTP proxy; in the synthetic QA scope the pinned test CA and
fresh nonce/peer-source proof are used instead. No DNS request, arbitrary
hostname, peer override or operator-selected URL is accepted as health
proof. **Only IPv4 HTTPS is measured here; UDP, DNS, IPv6 and trusted
Iranian-country routing need separate acceptance.**

The default fixed health schedule is a five-second post-round timer,
20-second first-start grace and a **3-round consecutive** failure
threshold. At Connect, an explicit positive integer selects the threshold;
**0** selects the default **3**, with no arbitrary maximum of 10. There is
also a non-replenishing cumulative flapping budget of three times the
selected threshold, evaluated using overflow-safe division. One unreachable
HTTPS endpoint alone does not mark the VPN down when the other has fresh
positive selected-path proof. The existing Core stays active for these
short re-probes, allowing its own transport to recover; there is **no
blind service restart**, credential rotation or application replay.
Fresh selected-path verification is mandatory before returning to
`healthy`. Exhausted failures or critical Core, ownership, health lease or
supervisor failure call the same exact scoped stop/Direct recovery.
The second timer monitors the health executor's authenticated role,
heartbeat and schedule; health checks the recovery role. A missing/failed
single timer triggers safe Direct recovery from the other.

A failed Off attempt is **not** success: retain recovery claims and
report `guard_pending`/`UNCERTAIN` as appropriate. A verified Off persists
`desired=direct`, retires only owned kernel state and both timer roles,
and preserves the selected profile and saved rules. Last health cause,
round count and failed-round count remain in private diagnostics, while
no automatic re-enable occurs after exhaustion. The synthetic installed
VM health evidence does **not** prove public-provider reachability,
production route ownership or safe hosted ingress/SSH behavior.

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

### Fresh management confirmation — pending production acceptance

The former **v4 disposable supervised trial** implemented an experimental
fresh-root-OpenSSH challenge using process ancestry, socket identity and
monotonic session timing. That implementation and its confirmation CLI have
been retired. **Current Native `connect-smart` does not issue or validate
a fresh SSH challenge or provider-console confirmation.** Historical v4
observations are not current Native authentication or field evidence.

The current Native candidate instead uses a durable, configuration-bound,
current-boot one-use Core-start claim, independently armed Health/Recovery
roles and a narrowly owned inbound-reply guard. These safeguards protect
startup and existing accepted connections but do **not** prove that a
new management connection can reach the host after activation.

For future production acceptance, an independently verified, fresh
operation-bound SSH session or explicitly approved provider-console
confirmation remains required under the Activation Guard contract above.
Neither source tests nor disconnected installed-guest QA satisfy this
physical management-access requirement.

## Runtime Health Guard

An **independent** active supervisor tests the exact selected data path, owned interfaces/rules and a set of meaningful TCP/TLS/HTTPS endpoints. Direct-path success, process existence or a lone ICMP Ping is insufficient. Monitor actual DNS and supported IPv4/IPv6/UDP behavior and invalid/aged routing data when these can undermine the selected routing contract. Avoid treating one unreachable website as a dead VPN.

Suggested **initial defaults for future field calibration**, not validated performance guarantees: health interval **15 s**, startup grace **30 s**, and **3** consecutive unhealthy rounds before declaring a recoverable path outage. A definitive core exit or lost owned interface may justify faster recovery.

The guard's **own liveness** must be supervised independently; a dead, disabled, masked, hung or start-rate-limited executor is not healthy merely because its systemd timer shows active. If bounded trustworthy supervision cannot be restored, reconcile the owned tunnel policy to a safe state rather than leaving indefinite unmonitored interception.

On confirmed failure, prevent **unobserved** Direct bypass while the Smart Routing policy remains active/degraded. If independent guard, host access and resource ownership remain safe, attempt a short, bounded reconnect sequence; report `RECOVERING` and require fresh selected VPN-path proof before returning to healthy `ACTIVE_VERIFIED`. If attempts are exhausted, the failure is critical or the guard cannot safely continue, deactivate the policy, recover the exact owned network delta, preserve management/domestic/hosting connectivity, and report the resulting mode and reason. A state is not `DIRECT` merely because the VPN process exited; incomplete ownership/recovery is `UNCERTAIN`.

- `restore_direct` (MVP default): **deactivate** Smart Routing, remove its verified product-owned TUN/routing and any temporary VPN-only blocking rules, and restore normal host routing. Preserve the selected profile and saved routing settings for the next guarded enablement. Foreign Internet may or may not work over the restored Direct path; do not claim VPN protection or foreign reachability while off.
- `restore_previous_verified` (optional, only if separately supported): transition to another previously verified active configuration only through a newly guarded, independently verified Apply; never treat it as Direct/off or switch blindly.

**Deferred, not an MVP/release requirement:** an operator-selected persistent block for VPN-designated destinations while the VPN is **off** (formerly `hold_selected_egress`) would be a different explicit policy. Do not build, apply or test it as part of the first release without a new Owner decision. The current Direct/off state has no such product-owned blocking.

**Initial reconnect candidate, subject to field calibration:** at most **3 automatic attempts per confirmed outage incident**, with short increasing delays and an overall recovery deadline; allow operator adjustment of the bounded attempt/time budget. Flapping must not reset the incident budget into an endless loop; reconnect only the selected VPN transport, **never replay interrupted application requests or arbitrary host operations**. Exhaustion triggers verified `restore_direct` and **no further automatic retries until an explicit new enable action**. Critical guard, ownership or protected-host-access failures bypass the retry delay and restore the safest available host baseline immediately. Report the failure cause, attempt count, last result and true current mode in status and credential-safe local logs. **Optional outage/recovery notifications are Owner-deferred**; no mandatory external alerting service, delivery dependency or separate notification worker in the first release. **Cloudflare Tunnel**, if separately enabled, has its own connector health: an unselected/failed website-origin check must not tear down healthy outbound Smart Routing.

### Current Native guarded Core-process candidate (Draft PR #126)

The original sing-box Core now executes as a directly supervised child inside
its existing managed systemd unit. The supervisor is **not** an unguarded
systemd restart facility: a Health-confirmed selected-path failure can request
at most the configured operation-wide number of restarts, only after installing
an exact, operation-bound, verified nft OUTPUT barrier ahead of Core teardown.
Each attempt must observe a changed physical process PID, recreated Core
kernel interception and a fresh selected HTTPS proof; the initial defaults are
3 attempts, 1 s exponential backoff and 60 s incident deadline. Restarts
require both independent guard roles and the original operation claim; spent
attempts are never replenished by a flapping provider. If the child exits
unexpectedly without prearmed restart containment, the supervisor exits so
`ExecStopPost=native-recover` restores the exact owned Direct/off state,
rather than risking a Direct leak by improvising a restart. An incomplete
ownership or cleanup proof is `UNCERTAIN`.

A verified Direct/off native stop may leave an inert private Core config
behind. The first subsequent Proxy Only Connect can remove **that file only**
under the existing transition lock after proving a matching final Off health
receipt, trusted service/guard ownership and zero remaining native Core work
or reserved network resources; it can never adopt or delete kernel objects
on the strength of a retired receipt. Ambiguous artifacts still require
operator diagnosis and explicit owned recovery.

Neither this code nor old-head field evidence constitutes physical acceptance
of the new PID-replacement path. Current new-head source tests exercise a
real (unprivileged) child PID replacement and fail-closed exits, not installed
kernel/TUN/SSH safety under actual systemd, reboot or foreign network writers.

## Required proof

The exact evidence and negative/physical test matrix lives in [ACCEPTANCE.md](ACCEPTANCE.md). Safety claims require at least authentic fresh SSH/hosting reply preservation, independent Direct versus VPN path evidence, expiry/replay/kill/reboot scenarios, competing host-network rules, and **failure of both the VPN and the guard itself**. Simulated or Docker-reset tests do not establish physical power-loss recovery.
