# Architecture and integration boundaries

**Product goal:** [PROJECT-SPEC.md](PROJECT-SPEC.md). This document owns *how components interact*, how traffic is classified, and which host resources Server Connect may change. It does not record active Issues, test runs or the history of experimental implementations.

## Selected implementation direction (2026-11-07)

The Owner selected **simplifying this same Server Connect product**: use the
**official sing-box native Linux TUN, routing, DNS, and rule-set facilities**
instead of extending the experimental custom Go route/RPDB/nftables ownership
stack. Keep the existing CLI, stored profiles/rules, three modes, signed
official/mirror/offline distribution, and the canonical product requirements.
Retire old QA-only native machinery only after replacement acceptance, rather
than breaking Direct/Proxy Only or deleting negative safety evidence.

The bounded new compiler/CLI entry point is
`smart-routing-rules preview-native`: it reads the selected saved profile and
operator rules, generates one official-Core-owned `auto_route`/`auto_redirect`
policy, checks that config against the pinned Core, and reports an opaque
digest with **activation_ready=false** and **applied=false**. A successful
preview is **not** an activation, a field safety proof, or authorization to
remove older experimental safeguards.

Isolated user/network-namespace testing has positively witnessed genuine
VLESS TCP/UDP delivery for VPN-required traffic, a Direct exception, and a foreign
inbound hosted reply while another new outbound to that same foreign IP
continues through the VPN. An independent UDP DNS responder additionally
demonstrated that an explicit native port-53 route hijack plus
dns_mode=disabled must be used: TUN dns_mode=hijack in the fixture rerouted
directly attached DNS peers into the VPN and broke them during provider outage.
With native DNS interception disabled, the public DNS request still enters TUN
and is redirected by route rules through the selected VPN resolver, while the
on-link DNS peer remains Direct even when the VPN provider is down.
That early namespace run alone did not test TCP DNS, other DNS transports
or IPv6 DNS; subsequent native DNS-policy guest tests cover specific TCP and
IPv6 wire cases, not arbitrary field DNS. Provider shutdown did not otherwise
fall back to Direct. Graceful Core stop restored its namespace-owned kernel
state. A **physical native Core SIGKILL** exposed orphaned fixed-slot RPDB
rules even after the Core removed its randomized redirect and TUN identities.
The integrated native recovery now has a narrow current-boot, consumed
Core-start-claim exception to clean only independently attested orphan
rule bodies while rejecting alias/foreign references and preserving unknown
ownership. See [the current guard rules](SAFETY-RECOVERY.md#native-inbound-reply-guard-issue-3-development-candidate).
That source/isolated repair is **not yet physical crash-recovery acceptance
for the current integrated candidate**; never flush unrelated host rules.

### Native Smart Routing candidate lifecycle (not general-host admitted)

This candidate extends the compile-only native preview with a guarded
Connect/Disconnect lifecycle. The Manager uses one shared state/journal lock
to read the saved profile and rules, validates the compiled official sing-box
config, checks free policy slots, and stages a private digest-bound recovery
claim before requesting systemd activation. No second Go router is created.
The short-lived Native startup OUTPUT containment is one additional
**admission/rollback guard**, not a second traffic classifier: after
the independent timers and accepted-reply guard are armed, it blocks
new unmarked public egress **across interfaces** until the Core has
installed its TUN/policy. Only official-Core-marked bootstrap sockets,
proven accepted replies and connected/private destinations are exempt.
There is no blanket public OS DNS or selected peer-IP/port bypass.
Only then may the manager report Smart active and
remove the exact receipt-bound containment table. Crucially,
`desired=smart` is persisted **after** that barrier is installed and
independently verified; otherwise an application may emit Direct packets
while Smart has been requested but the TUN is not yet effective.

The current official-Core native TUN config uses a 9000-byte **virtual**
MTU, not a statement about the physical underlay MTU. The previous 1400-byte
native setting fragmented ordinary IPv6 UDP application bodies above 1352
bytes, and the selected pinned gVisor path did not deliver those fragments.
Avoiding premature fragmentation at this bounded payload size does not prove
arbitrary IPv6 fragment reassembly or PMTUD. The obsolete parallel manager-owned v4 trial has been retired from the
installable code. Official-Core Native alone creates the active TUN; a
persisted legacy claim still blocks unsafe in-place replacement or adoption.

The native systemd unit uses ExecStartPre to check the desired mode, selected
profile, config receipt, underlay and vacant native policy resources. Its
ExecStopPost independently invokes scoped recovery after normal stop, failed
start or unexpected Core termination. The fixed native table/rule indices are
not enough for SIGKILL recovery: official sing-tun's auto_redirect separately
creates a random route table and priority-1 lookup. Recovery validates native
resources before removing them. Unknown foreign objects are retained and
reported uncertain for operator repair/retry. Only after exact kernel
restoration is verified does the native stop hook persist Direct and retire
its recovery receipt. A mismatched or unverified receipt remains intact for
operator investigation; a private inactive Core config may remain until the
next explicit Disconnect. Connect starts the owned native unit without
enabling it for future boots: a reboot never blindly reapplies unconfirmed
Smart Routing. The old service might remain in systemd's failed bookkeeping
after SIGKILL even when the hook has restored Direct; status must show that
failed unit, never infer healthy from the missing recovery receipt.

The **Debian 12 and 13 installed-host QA candidates** now exercise the
installed `connect-smart` CLI, official-Core native systemd unit, both independent
Guard timers, real selected VLESS versus manual Direct TCP/UDP/DNS paths, no
selected Direct packet leak and exact five-inventory kernel restoration in
isolated disconnected systemd guests. A deliberately missing authenticated
selected HTTPS endpoint must also produce autonomous Direct/off. These
scenarios count as `PASS` **only on successful exact-candidate CI**; they do
**not** prove a healthy selected HTTPS provider or a physical deployment.
Debian 12's older `nftables` emits the installed inbound-reply-guard
sets before the chain; the newer Debian 13 emits chain before sets.
The native receipt now recognizes exactly these two layouts while still
checking exact hook/rule order, accepted TCP tuple fingerprint, persisted
handle and generation-conditional deletion. The independent Native Health
inspector also recognizes Debian 12 numeric TCP protocol `6` and Debian 13
`tcp`, but still requires the actual TCP counter and all other read-only
selected route and capture evidence (see SAFETY-RECOVERY).
The old v4 supervised trial and its service are no longer part of the
new package or installed acceptance. Debian 12 and 13 instead run the same
Native `connect-smart` acceptance matrix.
Earlier single-VM tests demonstrated narrower SIGKILL/foreign-object cases;
they are not a different production runtime. The native policy has also passed
synthetic independent VLESS/Direct witnesses in rootless namespaces. These
are **development-candidate proofs**, not authenticated real Iran/foreign-provider
field paths, trustworthy Direct domain identity or production admission. Historical journals remain detectable and blocking; they are never
promoted to Native activation authority.

Native port-53 traffic uses the same address policy as other transports: the
Core first honors private/local destinations and validated operator IP/CIDR
Direct/VPN choices. In `bypass_iran`, the bundled country-estimate Direct
rule also matches port 53 before the fallback DNS hijack; otherwise a broad
DNS hijack would silently override those address decisions. Unmatched port-53
traffic is hijacked to the explicitly VPN-detoured resolver, before TCP
Host/SNI sniffing. Operator VPN-domain rules still precede the remaining
(non-DNS) country-estimate Direct decision. The estimate is **not** proof
of authentic Iranian geography, and compiling/checking these ordered rules
does not establish selected DNS packet-path or failure/leak acceptance.

### Bundled two-source Iran country policy and selected IPv6 capability

The default `bypass_iran` implementation now evaluates **two immutable, separately attributed** offline inputs: pinned DB-IP Lite (2026-10-01, CC BY 4.0) and the `Chocolate4U/Iran-sing-box-rules` `geoip-ir.srs` from exact commit `085deb78a67cc3452ee0ad071ed476024d34d92f` (GPL v3 repository, upstream source terms require review). The binary rule-set was decompiled by the pinned official Core, retained as a digest-checked source JSON, and packaged with its upstream GPL-3.0 license, separate from the first-party MPL-2.0 license. Native policy validation computes the **address intersection** (not literal prefix string equality or a union), producing 2,023 IPv4 and 894 IPv6 Direct CIDRs. These two estimates may share upstream sources; their agreement is not independent reachability/geolocation proof. `--iran-coverage dbip` optionally retains the existing DB-IP-only 3,038 CIDRs, after the same DB-IP integrity checks. Explicit operator CIDR VPN overrides take precedence over either country set, including port-53 traffic. Unknown public IPs take the VPN. Updates require a reviewed new versioned package; no runtime remote auto-fetch or trusting a second unsigned authority.

The `geosite-ir` list is **not** directly compiled into Direct-domain rules. A claimed Host/SNI, a raw IP or a third-party resolver answer without trustworthy name-to-IP association must not promote a foreign destination into a Direct bypass. Native operator domain rules currently support **VPN-only** decisions; adding country domain-to-Direct correlation is a separate acceptance design.

A local private TUN IPv6 address does not prove that the selected remote VPN can carry IPv6. Unless the operator enables a selected IPv6 exit after external verification, the native Core's TUN **DNS** intercept returns a predefined empty/no-error AAAA response scoped to `smart-tun` inbound only (never the selected Core bootstrap resolver). Foreign IPv6 literals/new application flows that still enter the TUN are explicitly **rejected** after essential private, operator Direct and country Direct precedence, not sent via the public underlay. The regular default VPN remains the only route for unmatched public IPv4. Official Core 1.14.3 testing showed that `prefer_ipv4` alone leaves AAAA responses intact, while an inbound-scoped AAAA rule returns an empty answer; this source/loopback result is **not** proof of physical TUN application-path success. `--enable-selected-ipv6` switches off the AAAA filter and fallback IPv6 reject only when the operator explicitly opts in; it does not run a magic remote capability check. Future automatic IPv6 capability management requires independently selected-path positive/negative evidence and a fail-closed transition design.


The **unreleased native Runtime Health Guard candidate** reuses the two
previously installed, independently scheduled `server-connect-smart-health`
and `server-connect-activation-recover` timer/executor roles. The only VPN
transport is still the **same official sing-box Core**; the Manager never
installs a competing data plane or a broad network repair layer. Before
Core start, Connect durably records an operation/boot/config-bound health
receipt and arms both roles. The health executor tests two fixed HTTPS
paths with fresh TLS/nonce evidence and a native `SO_MARK=0x2023` socket:
`auto_route` sends this mark to the owned TUN table. Binding the socket
with `SO_BINDTODEVICE=sctun0` is **not** valid with sing-box's
`auto_redirect` on the tested Debian guests (kernel returns
`ENETUNREACH`); accepting an ordinary unmarked Direct reply would also be
unsafe. Separate pre/post read-only IPv4/IPv6 RPDB, selected-marked IPv4
FIB and nftables-capture checks prevent health from treating lost native
interception as a good VPN path. The admission and each health round also
resolve the generated Core route rules in order, including inline Iranian
CIDR rule-sets, explicit VPN overrides and destination-port constraints:
TLS success for a destination routed Direct is never selected-VPN proof.
The synthetic nonce/peer fixture is
**development-only**. Field-mode HTTPS targets measure authenticated
IPv4 HTTPS/TLS over the selected Core, not Iranian geography or general
DNS/UDP/IPv6 policy, and a successful HTTPS endpoint alone cannot certify
the separate production Activation Guard.

A transient failed round is `degraded`; independent selected HTTPS/TLS
targets avoid treating one unreachable site as a total VPN outage. A confirmed
selected-path failure threshold (default **3** consecutive failed rounds, with
the existing cumulative-flapping cutoff) enters `recovering` only while the
**original managed Core child is still running**, the independent guards
remain effective, the selected kernel capture is intact, and its original
one-use operation receipt still owns the session.

The installed Native systemd unit now runs a **small managed supervisor as
MainPID**, with official sing-box as its direct child. An authenticated
operation-bound `SIGUSR1` request is checked against the current persisted
restart attempt, Core PID, current boot, owned service/guard identities and
the exact installed nft OUTPUT containment barrier **before and after**
stopping the old child. The barrier is installed **before** any intentional
Core process exit and remains effective while the new child and its native
TUN/kernel interception are established. After independently verifying a
**distinct Core PID/start time** and effective TUN, RPDB and redirect policy,
the manager releases the **exact receipt-owned temporary barrier**; the
restored Core-owned interception then protects the selected path while
fresh selected HTTPS is reprobed. Only positive selected-path proof changes
Health to `healthy`. Failed reproof remains `recovering` under independently
verified interception and the bounded retry budget, or triggers owned
Direct/off recovery when its safety or budget conditions fail. The temporary
barrier is **not** retained through selected HTTPS reproof. The existing
`ExecStopPost=native-recover`, `Restart=no`, independently scheduled guards
and one-use owned kernel cleanup are **not** bypassed. An unexpected Core exit
without an already committed barrier is fatal and proceeds to owned
Direct/off recovery; a blind `systemctl restart` or `SIGHUP` is not a safe
fallback.

`connect-smart` selects at most **3 Core-process restarts per activation**
by default, an initial **1000 ms** exponential backoff (bounded at 30 seconds)
and **60000 ms** per-outage deadline, configurable with
`--core-restart-attempts` (`0` disables process restart),
`--core-restart-backoff-ms`, and `--core-restart-deadline-ms`. Even after
an initially successful retry, its operation-wide consumed attempt counter
**never resets** on flapping. A retry requires a new PID and fresh selected
HTTPS; selected-path failure after a replacement consumes the attempt and
continues under verified Core interception/backoff. On exhaustion, lost
ownership/guard, Core crash or expired deadline, stop the owned unit and
recover the precise Direct/off state; an incomplete cleanup remains
`UNCERTAIN`, never guessed as safe. `native-status` exposes the remaining
guarded mode, attempts, last result and the last verified before/after PID.
These are source-level implementation properties awaiting new-head physical
fault injection, not production or multi-protocol field guarantees.

A recovered Direct/off Native stop hook may retain only an inert private
`native-tun.json` even though its one-use kernel claim has been retired.
Before the first Proxy Only Connect, the shared native transition lock and
Manager lock now permit a **private-file-only reconciliation** *if and only if*
the plan digest matches a persisted final `off` receipt, no native or proxy
operation/job/guard is live, the root-owned units are trusted, and the reserved
TUN/RPDB/routes/nft slots are independently empty. No missing claim may
authorize kernel deletion; ambiguous or foreign resources retain
`guard_pending`. The selected profile and routing preferences are preserved.

The second timer detects a stalled/unavailable
health executor, and the health executor checks the recovery timer. On a
fresh Connect after Core `SIGKILL` (including an older candidate without a
native health record), systemd's retained `failed` state is normalized **before** prearming timers, but only after the prior operation
has proven Direct/off, the old claim is absent, MainPID is zero and the
new scope's native policy slots are vacant. The timers must never confuse
old failure bookkeeping with the new operation's actual Core state.
The installed native `ExecStartPre` accepts only the just-staged,
configuration-bound `starting` health receipt with the **current boot ID**,
current uptime inside the existing startup grace, and both effective owned
Health/Recovery timer roles. Retained old-boot or old-phase claims can still be
used for exact `ExecStopPost` cleanup, but cannot authorize an enabled systemd
unit to reapply routing on reboot or by an implicit manual restart. No second
activation receipt or always-on boot service is required.
Previous timer-driven oneshots can still be exiting after `ExecStopPost`
has independently finalized Direct; fresh Connect first disarms both old
schedules, waits a bounded interval for the two exact owned executors to
become idle, and rechecks the Direct/no-claim/no-legacy-session/native-kernel
boundary before reusing the existing strict failed-oneshot reconciler. It
cannot reset an active, foreign or unknown guard merely to force a restart.
Owned native redirect cleanup removes only preinspected Core-owned routes and
managed policy rules, deletes the verified sing-box nftables table, and removes
the exact priority-1 RPDB redirect-table identity **last**. On Docker
hosts, the official Core can leave one extra `local 127.0.0.1 dev docker0`
route in this **already identified private table** and two TUN-specific
`!sing-box` rules in Docker's `ip filter DOCKER-USER` chain after SIGKILL.
Recovery prevalidates exact route shape and the two nft JSON rule bodies and
unique handles, deleting only these Core-origin effects without changing
Docker's chain, other rules or ordinary bridge routes. Unsupported additional
bridges, routes or ambiguous rules refuse cleanup and preserve the claim.
An interrupted route, nftables or priority-1 delete still retains the
randomized redirect-table identity for safe retry; unrelated native network
owners remain protected.
Selected-path health aggregation returns on the first authenticated positive
without letting another slow target replace success with timeout; cancellation
never upgrades a stale result to healthy. The
saved profile and routing rules are never erased by a health fault.
This limited native guard candidate is **not** complete field acceptance,
SSH confirmation, authenticated distribution or production authorization.

The old custom routing/resource engine is no longer compiled. The single
Native official-Core path has the recovery and foreign-ownership limits
documented in [Safety and recovery](SAFETY-RECOVERY.md). Historical v1/v2/v3
journal readers remain for exact refusal/abandon and independent recovery;
unknown v4 state is never automatically adopted.

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

The manager is a small Linux CLI/control plane, not a replacement tunnel protocol or a mandatory hosted dashboard. Direct and opt-in Proxy Only remain the accepted baseline; native Smart Routing has a VM-tested **candidate lifecycle**, not an accepted production path or complete runtime guard. Source and CI history must not be confused with a released or field-proven build.

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

## Installed Native units and recovery

The Native package installs only `server-connect-native-tun.service` as its
official-Core TUN executor, plus the independently supervised
`server-connect-smart-health` and `server-connect-activation-recover`
service/timer pairs. These are inactive by default. `connect-smart` stages
operation-bound recovery claims and verifies both Guard roles before starting
the Core. `ExecStopPost` provides independent native cleanup on ordinary stop,
Core failure and interrupted start. Verified Direct/off retains saved profiles
and routing settings; an ownership conflict preserves evidence and reports
uncertainty. A pending or unknown legacy journal blocks fresh Native admission.

The retired `server-connect-smart-tun.service` is not in the new signed
release manifest. The installer refuses to adopt an old copy of it in place.
An authorized disposable QA host may first uninstall the old owned release
and reset only its verified test-owned state, then install a fresh Native
candidate. Production migration is not implied. The Debian 12/13 installed
QA matrix runs actual Native `connect-smart`, DNS selected-path packet
witnesses, Core exit/Off and exact rollback, not a second custom data plane.
Source, guest and field acceptance remain distinct.

## Optional inbound website connectivity

A selected consumer VPN does **not** create public inbound ports. A separately enabled **official cloudflared** connector may open an outbound connection to Cloudflare and serve an explicitly approved HTTP(S) hostname from a bounded local origin, via Direct or the verified Smart Routing VPN if needed. Its account/domain/DNS, credentials, trusted proxy/source-IP handling, TLS, origin binding and service lifecycle are separately authorized and independently diagnosed.

The connector must not change aaPanel/Nginx virtual hosts, intercept another tunnel, or couple its failure to healthy outbound VPN service. Cloudflare Tunnel is not a generic public raw TCP/UDP, Xray/Marzban or Backhaul relay. Further service-specific ingress is outside this design.

## Packaging and host targets

Target only **tested** Linux OS/kernel/architecture/sing-box combinations with systemd and the required TUN/network capabilities. Acquire immutable verified bytes via official online, operator-hosted HTTPS mirror, or manual offline upload; all invoke one shared installer. Keep host-specific package, signature and installation rules in [OFFLINE-DISTRIBUTION.md](OFFLINE-DISTRIBUTION.md).

Operational safety details live in [SAFETY-RECOVERY.md](SAFETY-RECOVERY.md); real scenario coverage and known limits in [ACCEPTANCE.md](ACCEPTANCE.md).
