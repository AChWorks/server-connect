# Safety, activation and recovery contract

**Product intent:** [PROJECT-SPEC.md](PROJECT-SPEC.md). **Host/resource design:** [ARCHITECTURE.md](ARCHITECTURE.md). This document defines the safety behavior required for a *future production Smart Routing TUN*, not proof that it has already been implemented.

## Invariants

- **Off/Direct preserves baseline routing.** Enable, disable, update, crash recovery and uninstall change only clearly identified Server Connect resources, never arbitrary routes, DNS, firewall, SSH, aaPanel, Docker, Fail2Ban, STL or unrelated tunnels.
- **No unguarded host routing:** record a trustworthy pre-change host state, prearm and independently verify the recovery mechanism, then apply only an exact, reversible product-owned delta. If ownership or baseline is uncertain, refuse Apply and retain diagnostic evidence.
- **Protect access:** preserve present and fresh SSH/provider-console paths, panel, established inbound hosting replies (including foreign clients), local/Iran routes and the outer VPN endpoint's independent underlay/DNS bootstrap.
- **No VPN-required Direct leak:** a failed/unsupported VPN transport must not silently reroute VPN-required public traffic Direct. Explicit operator Direct exceptions are a deliberate policy, not an automatic outage bypass. Maintain safe domestic, management and hosted traffic while containing selected VPN-required flows.
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

## Activation Guard

Default confirmation window: **600 seconds**, operator configurable. High-risk route changes require:

1. Inspect actual IPv4/IPv6 addresses, routes/rules, relevant packet filtering, conntrack/return paths, local resolver, VPN underlay, management access and foreign owners. Collect a deterministic minimum proposed delta and verified safe baseline, including expected **absence**.
2. Serialize the operation and durably journal its exact ID, resource identities, before/after intent, phase, boot identity and rollback deadline. Reject stale or conflicting operations; prefer crash-safe fsync/atomic storage.
3. **Before any risky change**, arm and verify a recovery executor independent of the manager and sing-box; it must survive controller death and safely reconcile pending operations across reboot. A running timer alone is not sufficient proof that its executor can recover.
4. Validate the selected sing-box/profile and endpoint bootstrap. Reobserve resource identity against competing host owners immediately before each bounded apply.
5. Verify **real VPN-bound foreign egress**, **Direct Iranian/local**, endpoint underlay, active website/SSH replies and other selected checks through independent path-bound observations. A successful Direct probe is never proof of VPN delivery.
6. Require a **fresh SSH management session or explicitly approved provider-console confirmation** tied to this exact operation, within its deadline; an old still-open session, unrelated/replayed ID or a cached site response cannot authorize commitment.
7. Commit the desired state and disarm only the matching operation on complete evidence. On timeout, crash, reboot while pending, invalid confirmation or critical failure, restore only classified owned changes and verify the safest reachable baseline. Never reapply an unconfirmed TUN blindly after boot.

If an existing resource was replaced or altered by another owner, classify `UNCERTAIN`, preserve it and require controlled operator recovery instead of deleting/overwriting it.

## Runtime Health Guard

An **independent** active supervisor tests the exact selected data path, owned interfaces/rules and a set of meaningful TCP/TLS/HTTPS endpoints. Direct-path success, process existence or a lone ICMP Ping is insufficient. Monitor actual DNS and supported IPv4/IPv6/UDP behavior and invalid/aged routing data when these can undermine the selected routing contract. Avoid treating one unreachable website as a dead VPN.

Suggested **initial field-calibrated defaults**, not validated performance guarantees: health interval **15 s**, startup grace **30 s**, and **3** consecutive unhealthy rounds before declaring a recoverable path outage. A definitive core exit or lost owned interface may justify faster recovery.

The guard's **own liveness** must be supervised independently; a dead, disabled, masked, hung or start-rate-limited executor is not healthy merely because its systemd timer shows active. If bounded trustworthy supervision cannot be restored, reconcile the owned tunnel policy to a safe state rather than leaving indefinite unmonitored interception.

On confirmed failure, recover the exact owned network delta, preserve verified management/domestic/hosting routes, record the reason, and apply the operator's chosen failure policy:

- `restore_direct` (default): restore host baseline; **do not** claim foreign reachability where Direct is blocked. VPN-required flows must still observe their designated fail-closed constraints.
- `restore_previous_verified` (optional): only through a newly guarded independently verified transition, not blind profile switching.
- `hold_selected_egress` (optional): restore safe host routes but keep narrowly designated VPN-required flows blocked rather than leaked.

Retries, cooldown/backoff and failure thresholds are bounded and visible; no automatic endless reconnect loops. **Cloudflare Tunnel**, if separately enabled, has its own connector health: an unselected/failed website-origin check must not tear down healthy outbound Smart Routing.

## Required proof

The exact evidence and negative/physical test matrix lives in [ACCEPTANCE.md](ACCEPTANCE.md). Safety claims require at least authentic fresh SSH/hosting reply preservation, independent Direct versus VPN path evidence, expiry/replay/kill/reboot scenarios, competing host-network rules, and **failure of both the VPN and the guard itself**. Simulated or Docker-reset tests do not establish physical power-loss recovery.
