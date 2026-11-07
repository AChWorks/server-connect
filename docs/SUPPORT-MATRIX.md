# Development support and evidence matrix

**Status: unreleased QA scopes, not a public support promise.** The
[Project specification](PROJECT-SPEC.md) retains the full product goals.
This table separates package compatibility, command/intent admission and
measured behavior. It grants no new host authority, ownership exception or
release waiver. [Acceptance](ACCEPTANCE.md) owns the required test thresholds;
[Distribution](OFFLINE-DISTRIBUTION.md) owns artifact trust and installation.

| Development lane | Admitted OS / fixture | Bounded behavior and evidence | Remaining boundary |
| --- | --- | --- | --- |
| Direct / Proxy Only package lifecycle | Target-specific Debian 12/amd64 and Debian 13/amd64 with systemd | Local QA install/update/rollback/uninstall and saved-state tests; real selected proxy behavior in its stated fixtures | Package compatibility alone proves neither publisher trust nor general-host Smart Routing. Application-specific suites retain their own OS limits. |
| Legacy v4 `smart-tun-trial-apply`, pending or supervised | Debian 13 disconnected Docker/systemd fixture | Exact synthetic selected endpoint; IPv4 or explicitly requested synthetic dual stack; independent expiry, selected-path and supported Off cases | Debian 12 new v4 Apply refuses. The fixture's TCP/UDP/DNS/HTTPS evidence is not a provider or arbitrary-host support promise. |
| Legacy v4 non-Docker trial | Exact `sc-qa-vm-us01` Debian 13 QEMU fixture, pinned underlay and management identity | IPv4-only native trial, fresh authenticated `scqa` SSH with root OpenSSH ancestry and `sudo`; selected HTTPS and protected underlay TCP health | UDP/DNS/IPv6 are not measured by this health receipt. QEMU indirect IPv6 nexthops remain refused; other VMs and management identities are not admitted. |
| v6 `host-capture-preparation-qa` | Explicitly disposable, admitted Debian 12/13 host; operator-owned preexisting `tcp_fwmark_accept=1` and exact NOTRACK/underlay/Guard prerequisites | Durable ingress-mark and kernel-grace preparation, independent recovery and operation-bound terminal Clear | No Core, traffic TUN, FIB/RPDB capture, DNS or Runtime Health authority. Refusal to drain an old session is not preparation success. |
| v7 `host-capture-preparation-qa --native-link-if` | Same explicit preparation admission | Adds an exclusively created native TUN link to the same parent; controlled link-first recovery | No selected VPN delivery or public capture. Changed/unreceipted identity and foreign link dependencies must refuse cleanup. |
| v8 `host-core-preparation-qa` | Same explicit disposable-host admission plus pinned selected VLESS/WS/TLS identity | Actual installed Core attachment to the receipted link; credential/start/stop intent and controlled Core-first recovery | No public FIB/RPDB/nft capture or general-host Runtime Health acceptance; a live Core alone proves no selected egress. |
| v9 immediate-recovery source lanes | Fresh attested disposable Linux network namespaces; exact kernel/tool/Core identities recorded per run | Simulated Core ownership composition, actual pinned Core attachment, and separate nested selected VLESS/TLS/WS TCP/UDP witnesses with relay/Core loss and controlled Off | The synthetic relay is not an external provider. DNS, geographic Direct, broad IPv6/MTU, installed supervision, reboot and arbitrary owner coexistence require separate evidence. |
| v9 `host_native_supervised_policy_v1` installed QA | Explicitly authorized, independently resettable Debian 13 QEMU guest; source-bound checkpoint linked in [Acceptance](ACCEPTANCE.md#installed-v9-supervised-guest-evidence) | QA factory plus installed Health/Recovery; real selected VLESS/TLS/WS, two external IPv4 HTTPS witnesses, proxy-unaware TCP, fresh SSH/replay controls and Health-timer-loss exact Off | No public Connect or wider host admission. The full fault/reconnect matrix, UDP/DNS/IPv6, hosted replies, reboot and ownership blockers remain unaccepted. Older parents do not gain supervised authority on upgrade. |
| Saved rules, DB-IP data and DNS/FakeIP-correlated preview | Offline source/CLI and separately bounded runtime fixtures | Saved configuration and compile-only prefixes/domain rules; exact-source dual-stack estimate compilation | No native DNS capture or trusted Iranian classification is established. Imported/compiled input does not authorize activation; cached mapping lifetime and reconnect remain acceptance gates. |
| Source-only field helpers | Separately authorized disposable Debian 12 field topology, with each helper's own netns or narrow host scope and recovery prerequisites | Bounded selected-provider path, explicit Direct exception, no-leak and cleanup witnesses where actually executed | Not the installed general-host lifecycle. A single pinned Iranian HTTPS candidate is not country-wide trusted Direct; helper recovery tests are not product ownership or physical-host rescue proof. |

**Ownership applies across every native lane.** Supported disjoint changes,
observable conflicts, and same-shape replacement are different cases. Durable
attribute receipts do not authenticate route/RPDB lifetime. The real IPv4
replacement and last-observation counterexamples deliberately fail the safety
assertion; controlled successful Off does not resolve them. See
[route and RPDB identity limits](SAFETY-RECOVERY.md#route-and-rpdb-identity-limits).
No table, protocol, priority or manager lock silently creates exclusive
ownership.

**Platform evidence is more specific than a distro name.** Record the exact
kernel, architecture, systemd, iproute2, nftables and pinned official sing-box
identities and required capabilities for each run. Debian 12 and Debian 13
containers can share a runner kernel; they are not two independent kernel
acceptances. A generic public IPv6 path, MTU/PMTUD, resolver or transport must
remain `NOT_RUN` or `UNSUPPORTED` until its actual advertised combination is
verified. QMP reset of a guest is not physical-host rescue or power-loss proof.

**Host prerequisites remain independently owned.** Installed preparation
requires preexisting `tcp_fwmark_accept=1`; product observation does not acquire
permission to set or restore it. Mark-capable actors include relevant
`CAP_NET_RAW` holders on Linux 5.17 and later as well as `CAP_NET_ADMIN`
holders; a packet/socket mark is not caller authentication. See the
[mark and staged-drain boundary](SAFETY-RECOVERY.md).

General-host Apply and authenticated publication remain blocked until the
canonical requirements, exact candidate tests, required field evidence,
publisher/license decisions and separate HIGH_ASSURANCE review are satisfied.
