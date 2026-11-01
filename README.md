# Server Connect

**Status: development candidate. There is no publisher-authenticated public release or approved production install command yet.**

Server Connect is an offline-first Linux server connectivity manager, designed especially for Iran-hosted aaPanel, WordPress and web servers. Its intended main use is **transparent outbound VPN routing** with Iranian destinations Direct and most other public destinations through the selected VPN — without per-application proxy configuration or identifying individual background jobs.

## Planned user experience

| Mode | Purpose |
| --- | --- |
| **Direct** | Leave the host's ordinary networking unchanged. |
| **Proxy Only** | Optional local HTTP/SOCKS proxy for applications that explicitly use it. |
| **Smart Routing (TUN)** | One host-level destination policy using official sing-box and Linux TUN: Iran/local/protected paths Direct, other public traffic VPN by default, with operator domain/IP/CIDR and trusted-list exceptions. |

Switching Smart Routing **off** must restore the server's ordinary network paths, without leftover VPN-only blocking, while keeping saved profiles and routing rules for the next guarded activation. The disposable installed TUN trial exercises this lifecycle with an exact-operation Disconnect and saved-policy reapply. **General-host Smart Routing remains unimplemented and unavailable for production.**

Smart Routing must protect SSH, aaPanel, website replies, connected networks and the VPN endpoint; it requires independent activation and ongoing recovery safeguards. **Working TUN for all claimed TCP/UDP/DNS/IPv4/IPv6 combinations still needs real evidence.** Optional Cloudflare Tunnel website ingress is a **separate later feature**, not a property of the outbound VPN.

## Installation approach

The planned distribution offers **official online**, **operator-hosted HTTPS mirror** (including Iranian static hosts), and **manual fully offline upload**. Each delivers the same independently verified versioned bundle to **one shared installer**; the disconnected host must not need GitHub or outside Internet. No public one-line install URL should be treated as genuine until release signing, support and licensing are resolved.

## Implementation status and development

The existing source includes a Go CLI, secure profile storage, real pinned sing-box **Proxy Only** development tests, a shared offline installer and a developer online bootstrap. **General-host Smart Routing, the production Runtime Health Guard, real foreign-path acceptance and Cloudflare Tunnel integration remain unavailable.** The disposable native trial includes an independent expiry/recovery executor; its explicit supervised mode adds fresh SSH confirmation, selected-path TCP/UDP/DNS and authenticated fixture HTTPS health checks, and bounded recovery inside the same isolated fixture. Target-specific Debian 12/amd64 and Debian 13/amd64 QA bundles support the Direct/Proxy Only installation lifecycle. New native trials additionally require Debian 13 and the existing isolated fixture; installing on Debian 12 does not admit TUN. See [the distribution contract](docs/OFFLINE-DISTRIBUTION.md) for these development targets and their limits; they are not a public support promise.

**Profile URL compatibility (development candidate):** one `vless://` link can
be imported with `server-connect --json import --file /private/link.txt`
or on stdin (never put bearer links in the command line or shared logs).
The URI parser supports plain TCP, WebSocket and HTTPUpgrade with their
appropriate native sing-box 1.14.3 transport mapping; inert Xray
`headerType=none` / empty metadata is accepted. TCP HTTP-header
camouflage (`headerType=http`), XHTTP, unknown or repeated options, and
insecure TLS overrides are **not** silently reinterpreted. Full subscription
URL downloading, bulk URI import and automatic refresh are not currently
implemented; supported Trojan/VMess profiles require explicit native
sing-box JSON inputs. Saved profiles are secrets and require private
operator-controlled state. This URL compatibility is separate from general-host
TUN admission and does not make the project production-ready.

For operator inspection, `server-connect --json mode-overview` (or menu option **18 Mode Overview**) reports the **desired** mode, the observed Proxy Only service state and whether the experimental Smart Routing trial blocks an ordinary Direct claim. It exposes three mode choices but explicitly marks general-host Smart Routing as **unavailable**: neither an inactive Proxy Only service nor an experimental journal proves baseline Direct routes, selected VPN egress or safe production TUN. `not_run` is retained for real path evidence until measured separately; a guard/service error remains a nonzero, structured failure. This diagnostic may initialize private manager state/locks, as the existing `status` command does, but never changes host routing.

### Saved Smart Routing rules (not activated)

Use the same CLI and **19 Routing Rules** interactive menu to store explicit routing exceptions without changing Linux routes, DNS, nftables, or TUN. This private, versioned operator configuration does **not** prove selected VPN reachability or general-host Smart Routing admission. `smart-routing-rules list` returns `saved_not_applied`, `activation_ready=false` and `general_host_admitted=false` even when rules have been saved.

```console
server-connect --json smart-routing-rules list
server-connect --json smart-routing-rules add --cidr 1.1.1.0/24 --via direct
server-connect --json smart-routing-rules add --domain example.org --via vpn
server-connect --json smart-routing-rules add --domain test.example.org --suffix --via vpn
server-connect --json smart-routing-rules remove --cidr 1.1.1.0/24
```

An offline ASCII/LF-only import file (up to 64 KiB) uses `kind action value` per line:

```text
# local operator exceptions, not authenticated Iran geography
cidr direct 1.1.1.0/24
cidr vpn 9.9.9.9/32
domain vpn example.org
suffix vpn test.example.org
```

Pin the SHA-256 of the **exact raw file bytes** independently, then import:

```console
sha256sum /private/operator-rules.txt
server-connect --json smart-routing-rules import --file /private/operator-rules.txt --source operator-list --as-of 2026-10-31 --sha256 EXACT_64_CHAR_SHA256
```

Use `--file -` for stdin with the CLI, not the menu. Source replacement requires `--replaces-sha256 CURRENT_SOURCE_HASH`, while `smart-routing-rules remove-source --source operator-list --sha256 CURRENT_SOURCE_HASH` removes one exact imported source. Invalid/special-purpose/overlapping CIDRs, dangerous broad Direct rules and unauthenticated Direct-domain exceptions are rejected. IPv6 operator inputs must fit the currently allocated 2000::/3 unicast space **and** exclude the offline IANA IPv6 special-purpose registry snapshot (2025-10-09); Go's IsGlobalUnicast alone is insufficient. Suffix rules must be **registrable names beyond** the ICANN **or PRIVATE** public suffix, including multi-label roots (co.uk, com.au, github.io). This is enforced by the pinned, locally vendored, BSD-3-Clause golang.org/x/net/publicsuffix v0.36.0 snapshot; unknown/unmanaged TLDs fail closed until deliberate policy updates. Both registries are static, explicit inputs to review/update, **not** proof that a prefix is geographic, live or actually reachable. List metadata exposes source age, SHA and staleness over 30 days: **a matching hash is not a publisher signature or proof of trusted geography**.

The read-only `smart-routing-rules preview --tunnel-if TUN --underlay-if IFACE --tunnel-ipv4 PRIVATE_CIDR --domestic-cidr EXPLICIT_CIDR` compiles the saved exceptions and selected compatible profile using the existing native TUN candidate compiler. It returns a configuration hash with `native_policy_compile_only`; it does not run sing-box, inspect the real host, apply rules or verify a VPN. Actual general-host routing and independent guards remain open under Issues #2 and #3.

For source checks, run `go test ./...`. Actual CLI flags and development diagnostics are maintained in [the CLI help/source](cmd/server-connect/main.go); the reproducible isolated test procedures live in [the QA scripts](scripts/qa/) and CI. Older unarmed selective-intent and loopback-rule trial commands are **developer diagnostics, not production routing**. A separate installed **Docker or exact isolated Debian 13 QEMU VM Smart TUN trial** exercises real sing-box through a prearmed independent expiry guard. Its default pending mode expires without confirmation. The explicit `--supervised` mode requires a new authenticated root SSH connection (or the exact QEMU test guest's verified `scqa` session executing the root manager through `sudo`) and a single-use operation challenge before experimental confirmation, then runs bounded selected-path health rounds under independently monitored liveness. Neither mode grants general-host `ACTIVE_VERIFIED`. Its strictly isolated fixture supports IPv4 and explicitly requested IPv4+IPv6 policy with exact Direct/VPN exceptions and native rollback checks; public-shaped 2606:4700::/32 IPv6 test addresses are used **only within disconnected disposable guests**, never as accepted real routing/geographic evidence. The manager owns the persistent TUN and native interception/containment policy; the core attaches with automatic host policy disabled. Operation-bound Disconnect removes only resources covered by the durable ownership record, preserving supported disjoint changes by other owners. Ambiguous ownership retains recovery evidence and reports uncertainty instead of guessing at cleanup. The validated trial policy and selected profile remain saved for a fresh guarded reapply; interrupted stop/cleanup retains durable recovery evidence. It is not available for customer/physical-host operation, nor proof that Smart Routing is production-ready. Never run privileged disposable-only QA experiments on a customer server.

### Non-Docker Smart TUN: narrowly admitted Debian 13 QA VM

The **unreleased** systemd-managed native Smart TUN can now be experimentally admitted on exactly the isolated `sc-qa-vm-us01` QEMU Debian 13 IPv4 guest, with its fixed `ens3`/`10.0.2.15` underlay and `10.0.2.2` peer. This is not a generic VM, aaPanel or production-host admission and it never sets `general_host_activation=true`. IPv6 must be excluded from this specific fixture because the QEMU NAT's indirect IPv6 nexthop objects are not covered by the native ownership model. Its selected-VPN health evidence checks genuine HTTPS with a TUN-bound socket and a separate protected underlay; the detailed evidence explicitly marks UDP, DNS and IPv6 **not run**. It cannot establish full protocol coverage, trusted Iranian geography or Internet-provider readiness.

On the **disposable guest only**, with the offline-pinned development bundle installed and a selected compatible VLESS profile:

```console
sudo server-connect --json smart-tun-trial-apply --supervised \
  --tunnel-if scqavm0 --underlay-if ens3 --tunnel-ipv4 172.31.99.1/30 \
  --management-peer 10.0.2.2 --domestic-cidr 5.22.0.10/32 \
  --protected-cidr 10.0.2.2/32 --deadline-seconds 600
```

The output contains an operation ID, revision, short-lived challenge and a mandatory recovery deadline. To confirm, **open a genuinely new authenticated SSH connection** and run `sudo server-connect --json smart-tun-trial-confirm --operation-id ID --revision N --challenge HEX`; reusing a multiplexed/old SSH transport is rejected. Use menu **20 Guarded Smart TUN (QA VM)** for the same bounded trial/Off lifecycle. Disconnect with `smart-tun-trial-disconnect --operation-id ID --revision N` using the currently observed exact values. After verified Off, the selected profile, non-secret policy and saved IPv4 CIDR operator exceptions persist for `smart-tun-trial-apply --saved --supervised --deadline-seconds 600`; all inputs are revalidated before a new operation. The saved-rule registry is atomically bound to the trial admission, allowing at most eight IPv4 CIDR exceptions in this VM, never an exemption for the fixed VPN health witness.

If an independent Recovery Guard oneshot remains `failed` **after a separately verified Direct/off**, a subsequent Apply must still refuse it; never disable the guard to get past admission. On this exact isolated QA VM, the operator may explicitly run `sudo server-connect --json smart-tun-trial-reconcile-idle-guard` (menu **20 > 7**) to reconcile only the exact owned failed systemd bookkeeping. The command requires an absent private activation journal and TUN credential, a quiescent trusted core and Health executor, disabled timers, independent native TUN/route/rule/firewall collision preflight and a failed recovery executor with **no live PID, job or cgroup**. It rechecks unit and digest identity before/after `reset-failed`, refuses unsupported or changed states, and never starts TUN or routing. It reports `activation_ready=false`. This is a narrowly authorized manual VM repair, **not** an automatic retry, production recovery or proof of future VPN health. Capture traffic for QA with non-promiscuous `tcpdump -p`; the default promiscuous capture changes TUN link flags monitored by the native ownership guard.

A failed/expired/supervisor-unavailable operation must be reconciled by the independent owned guard **without reboot**. Only after the journal is absent, the recovery timer is disarmed, the core is observed quiescent and the owned health timer is disabled may a stale systemd `smart-health.service` failure status be normalized for a new VM trial or verified offline update. Never disable guards or remove network rules manually merely to bypass a pending/uncertain journal. The test scope, outstanding negative scenarios, provenance requirements and final acceptance remain under [Issue #2](https://github.com/AChWorks/server-connect/issues/2) and [Issue #3](https://github.com/AChWorks/server-connect/issues/3).

The read-only `server-connect smart-routing-data` command works entirely offline and reports a pinned **DB-IP Country Lite geolocation estimate** for Iran (IPv4/IPv6 counts, source, month, age, hashes and license). **Data credit: [IP Geolocation by DB-IP](https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).** The project extracts IR rows from DB-IP Country Lite (October 2026) and converts the original IP ranges into sorted CIDR prefixes. DB-IP Lite has reduced coverage/accuracy; its country estimates are **not** independent packet-path proof. These entries are deliberately **not automatically used as Direct exemptions** and the report explicitly declares geographic-route safety and activation readiness false. This is not a publisher-signed update, operator rule import or production Apply. Regeneration from a separately downloaded, pinned source archive is supported by `scripts/qa/generate-iran-dbip-lite-snapshot.py`; installation and inspection do not contact DB-IP, GitHub or any outside network. Independent field testing, update/rollback policy and guards remain mandatory.

## Documentation

- **[Project specification](docs/PROJECT-SPEC.md)** — the canonical goal, product limits and delivery direction.
- [Architecture](docs/ARCHITECTURE.md) — traffic paths, host resource ownership and integrations.
- [Safety and recovery](docs/SAFETY-RECOVERY.md) — guard and rollback requirements.
- [Distribution](docs/OFFLINE-DISTRIBUTION.md) — official/mirror/offline trust and lifecycle.
- [Acceptance](docs/ACCEPTANCE.md) — test matrix, evidence levels and valuable prior QA lessons.
- [Contributor guidance](AGENTS.md) — repository editing and safety conventions.

[GitHub Issues](https://github.com/AChWorks/server-connect/issues) track pending work; PRs, Actions and Releases provide current evidence. These are not duplicated into the permanent product specification.

**License:** The repository is publicly readable but has no selected software license. Public access does not grant general redistribution rights; licensing and upstream binary obligations require Owner approval before publishing a release.
