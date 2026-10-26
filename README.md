# Server Connect

**Status: Development candidate — no signed or published installable release is available yet.**

Server Connect is an **offline-first Linux server connectivity manager** for administrators of hosting servers, including Iran-based servers running aaPanel, WordPress, and other web services. Its goal is to provide simple, controlled access to external networks when direct connections are unavailable, without disrupting SSH, domestic routes, hosted websites, or other server workloads.

The initial connectivity engine is **sing-box**. Rather than reinventing VPN protocols, Server Connect will manage compatible connection profiles, selective proxy/tunnel routing, safe activation, continuous connection health checks, and automatic recovery when a configured route fails.

## Planned operating modes

| Mode | Intended behavior |
| --- | --- |
| **Direct** | Keep the existing server network unchanged; the default when no profile is active. |
| **Proxy Only** | Use a local proxy for explicitly selected downloads, updates, or applications without changing the host's default route. |
| **Selective Tunnel** | Route selected external traffic through the active profile while preserving domestic and protected management/service paths. |
| **Broad Tunnel** | Route a wider, explicitly chosen set of outbound traffic through the profile, with host safety exceptions. |

A tunnel-affecting change must pass a guarded activation and an operator confirmation window before it is committed. If an active profile stops working, independent health/recovery mechanisms must restore the selected safe network policy. **Checking whether websites are reachable from abroad is optional**, depending on the operator's goal; a client VPN alone does not grant public inbound connectivity.

**Selection is more than `curl`.** A real aaPanel App Store install may use a panel worker, a Python download helper, Git/wget or a separate installer subprocess, so a proxy exported in an operator's shell is not evidence that the panel's background job used it. The development Proxy Only wrapper supports explicitly opted-in **proxy-aware** commands; per-app support must be demonstrated by selected-path tests. Future guarded Selective routing must also support a precisely identified compatible panel job/service or destination scope, without redirecting the entire panel, root account, SSH or hosted services. Until this is physically tested and protected by route-activation and runtime guards, **transparent aaPanel installer selection is NOT IMPLEMENTED**. The detailed product rule lives in [PROJECT-SPEC.md](docs/PROJECT-SPEC.md) and the acceptance criteria in [ACCEPTANCE.md](docs/ACCEPTANCE.md).

Direct and single-active-profile Proxy Only are implemented as **development candidates** and tested with a local genuine sing-box VLESS TCP relay; guarded host-wide routing and automatic recovery are **not implemented or accepted**. A profile that works in Windows v2rayN/Karing may not be reachable from a particular Linux datacenter. No VPN protocol can restore international connectivity when the underlying network has no usable path.

Future multi-active profiles and per-workload outbound selection are [parked in Issue #7](https://github.com/AChWorks/server-connect/issues/7), not required for the first release. Profile identity, traffic policy and the data-plane runtime are distinct future migration boundaries; the MVP's single active selection and internal sing-box tag are not permanent API promises. Public ingress, Marzban/Xray node forwarding and Backhaul-like relays are separate operator-owned deployments, not an effect of activating an outbound VPN.

## Planned installation experience

Two equally supported one-command installation paths are planned: **Online**, where a trusted bootstrap fetches and verifies the exact compatible release and required prerequisites on a connected host, and **Offline**, where an operator downloads a complete trusted bundle elsewhere, copies one folder to the target, and runs one local command without foreign connectivity. Both paths use the **same installation, update, uninstall, validation, state and recovery logic**. Offline-first means offline operation is fully supported, **not** that installation must be offline.

A development-only `install.sh`, Go CLI, pinned-core packaging script and online bootstrap **candidate** now exist in source. They have **not** been authenticated or published as a release; the offline/online installed-host support matrix and redistribution gate remain open. Do not treat illustrative release URLs or commands in design documents as operational installation instructions.

## Development candidate checks (not a released installer)

The current initial Linux target is **Debian 13 / amd64**. The manager is implemented in Go using only the standard library. Run `go test ./...` for source tests. Optional genuine local VLESS core tests require `SC_TEST_SINGBOX=/absolute/path/to/the/pinned/sing-box` and `go test ./...`. To create a **local QA-only** bundle from the separately fetched and digest-verified official upstream archive, run `scripts/package.sh /path/to/sing-box-1.14.3-linux-amd64.tar.gz`. The resulting artifact is not a public release; its local checksum alone is not a publisher signature.

The online bootstrap candidate at `scripts/bootstrap-online.sh` requires an explicit HTTPS archive URL and independently obtained SHA-256 digest; it downloads the **complete** offline bundle and invokes the **same** local installer. The supported root invocation uses trusted Debian 13 `sudo` with standard environment reset followed by `/usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/sh /root/bootstrap-online.sh ...`; this environment boundary must be applied **before** the interpreter starts, not merely via script-body `unset`. Custom sudo environment preservation and hostile root shells are unsupported. Actual online installation uses private `/root` staging, ignores inherited `TMPDIR` and archive overrides, enforces a **96 MiB** download-time ceiling (including chunked responses), and uses bounded Python 3 stdlib archive preflight/extraction with **128 MiB per-file / 192 MiB expanded aggregate** limits, a kernel per-file limit, time/memory/metadata limits, and at least 1 GiB or 10% host-filesystem free-space reserve. The exact official pinned core measures 31,678,266 compressed and 93,255,156 expanded bytes; these caps allow additional manager/metadata room without unbounded staging. Space is checked before transfer/extraction and before each extraction write, while concurrent host writers remain a limitation without a filesystem quota. Test-only HTTP is allowed only for parsed loopback hosts, with no redirects and no inherited proxy; production URLs and their redirects must use HTTPS. Python 3 and `timeout` are required for this **online development bootstrap only**, not for the offline installer. For a real root online installation on Debian 13, missing `curl`, Python 3 or HTTPS CA certificates are installed through the host's existing APT trust configuration (native essential `coreutils` must already be intact); this changes OS packages even if subsequent archive acquisition fails, and never changes product/network state on such a failure. `--verify-only` remains available to non-root callers but **never** installs prerequisites. This is not a published or publisher-authenticated one-line release. The offline installer refuses source paths with unsafe or symlinked ancestors before privileged payload use. A short public one-line release command must wait for the Owner-approved release endpoint, publisher authentication and license decision. Never use a made-up download URL or execute unverified release code as root.

### Read-only host network preflight (Issue #2 development)

On a Linux host with trusted native `/usr/bin/ip`, `server-connect --json host-preflight --endpoint 198.51.100.10 --management-peer 203.0.113.42` records actual IPv4/IPv6 routes, rules, links and kernel route lookups for **literal IPs**. Broadcast, multicast, unspecified, IPv4-mapped IPv6 and link-local addresses without a usable interface scope are rejected before native inspection; private IPv4, IPv6 ULA and loopback literals remain supported. It does not resolve DNS, touch state, enable a tunnel, change kernel networking or prove those peers are reachable. Both peer arguments are optional; supplying them is useful for future underlay and management-path planning. The report deliberately says `activation_ready: false` and `snapshot_atomic: false`: it is **not** an ownership journal, firewall inspection, activation authorization or replacement for the independent guards and SSH/reboot/field acceptance specified in Issue #2. This is a dependent development feature, not a released installation instruction.

### Advisory selective route planning (Issue #2 development)

The development command below previews **only explicitly selected public CIDR destinations** against the live native Linux route, rule and link inventory. Both endpoint and current management/SSH peer must be literal IPs. The TUN name must be unused; it does not create an interface. For example, using **documentation-only placeholder peers** (replace them before a meaningful operator preview):

~~~sh
server-connect --json selective-plan --endpoint 198.51.100.10 \
  --management-peer 203.0.113.42 --tunnel-if scplan0 \
  --destination 8.8.8.0/24
~~~

A valid preview returns a deterministic bounded set of **candidate** table/priorities, destination-specific route/rule identities, and fingerprints for that observation and proposed plan. It rejects overlapping destinations, common private/special-purpose ranges, routes overlapping any existing non-default host route, reused interface identity, unsupported rule/table descriptions, and input that would capture the specified VPN endpoint or management peer. The planner also checks whether **earlier policy rules** could intercept selected traffic via a matching default route in another table (including source-, destination-, or mark-specific rules); unknown rule actions or unprovable precedence fail closed with `route_plan_uncertain` instead of silently overwriting third-party policy. Observation and plan fingerprints cover canonicalized route/rule/link inventories **plus the native route-get results for both protected endpoint and management peer**; missing or inconsistent protected lookup evidence is rejected. It is callable from menu option **12**; option **11** remains the previously merged read-only Path Diagnostics.

**Safety boundary:** the output always states `read_only: true`, `activation_ready: false`, `snapshot_atomic: false`, `guard_armed: false`, `ownership_verified: false`. No table or priority is actually reserved; nothing is applied or saved. An unchanged preview, hash or apparently unused ID **does not** prove network ownership or safe SSH/HTTP(S) replies, domestic reachability, DNS/bootstrap or a bound VPN path. Do not run the displayed candidate policy manually. The internal fsync-backed PREPARED/UNCERTAIN intent journal does not attest route ownership or apply network changes. Guarded owned-route activation and rollback, an independent 600-second Activation Guard, authenticated new-session confirmation, reboot/timeout recovery and Runtime Health Guard (#3) remain separate mandatory implementation and acceptance gates.

#### Private, unarmed Selective intent staging (Issue #2 development)

The CLI can now bind a fresh Selective preview to a version-1 **private journal intent**, and explicitly abandon **only** its untouched PREPARED revision:

~~~sh
server-connect --json selective-stage-intent --endpoint 198.51.100.10 \
  --management-peer 203.0.113.42 --tunnel-if scplan0 \
  --destination 8.8.8.0/24
server-connect --json activation-journal-status
server-connect --json selective-abandon-intent --operation-id OPERATION_ID --revision 1
~~~

Use actual endpoints instead of documentation placeholders. Staging performs **two independent, non-atomic native preflights**, requires identical observation and plan SHA-256 fingerprints, and durably records a deterministic proposed *route/rule intent* linked to those fingerprints. It refuses ambiguous kernel observations, conflicting prior journals, incomplete/modified plan identities, and drift during staging. The journal is descriptor-pinned, mode 0600 and fsync-backed; only bounded phase, ID, revision and resource count reach the CLI. The returned ID is an exact-match identifier, **not** proof of host authorization. Staging creates private state (unlike `selective-plan`), may prevent starting another stage until the prior record is deliberately abandoned, and never writes `runtime.json` or `proxy-auth`.

**Critical boundary:** `prepared` means **no kernel mutation and no armed recovery guard**. It does not establish an owned TUN/interface, actually reserve the proposed table/rules, install routes or start sing-box; all `guard_armed`, `activation_ready` and `recovery_verified` fields remain **false**. This journal label is NOT the normative guarded PREPARED activation state in `SAFETY-RECOVERY.md`. After even two matching snapshots, another system can change kernel networking before a future activation. Real route execution must re-observe natively under its own guarded transaction and independently verify an armed reboot-capable rollback and ongoing health guard before applying anything. `selective-abandon-intent` fails closed on mismatched ID/revision, uncertain/corrupt journals or replay and **never** deletes network resources. Do not use these developer commands as a routing workaround or a production activation interface.

### Explicit underlay TCP diagnostic (Issue #2 dependent development)

For a *known* literal TCP endpoint and port, run
`server-connect --json underlay-tcp --endpoint 198.51.100.10 --port 443`.
If the configured VPN endpoint also uses a DNS name, explicitly verify that
the **current host resolver** includes the intended pinned IP *before* the
TCP attempt:
`server-connect --json underlay-tcp --endpoint 198.51.100.10 --hostname vpn.example.net --port 443`.
The hostname check rejects malformed/ambiguous names, resolves an absolute
DNS-style name (never silently adding a local search suffix), caps resolution
to three seconds, checks A/AAAA records against the pinned literal, refuses
oversized or unsuitable resolver results, and **does not connect** if that
literal is absent. It never silently substitutes another resolved address.
The IP-only command remains a literal-only test and does not invoke DNS.

Either form makes one bounded TCP connection attempt **with no application bytes**,
using a Linux kernel route lookup qualified by **TCP protocol, the exact
destination port and the CLI process UID**, followed by `SO_BINDTODEVICE` on
that selected interface. The **same flow-qualified route and the relevant
policy rules** are checked again afterward. Source-dependent, source-port,
mark, VRF, output-interface or unrecognized rule selectors are classified as
`underlay_policy_unsupported` instead of guessing the socket's effective
route. It rejects ambiguous/missing/down interfaces and **never falls back
to an unbound socket** when binding fails. Unreachable/refused/timeouts
produce a nonzero exit code and a machine-readable partial report
(`ok: false`). Invalid endpoint/port/hostname arguments return an error
**without a fabricated `data` report**; failures after the diagnostic starts
retain `read_only: true` and bounded partial observations. The
command does not depend on proxy environment variables, saved profiles or
systemd services. The optional --hostname mode **does** use the current host
name resolver and requires a DNS-style ASCII hostname with at least two labels;
IP-only mode never invokes name resolution. Both must be explicitly invoked by
the operator rather than automatically testing an arbitrary endpoint.

**Scope limitation:** TCP reachability on the selected current interface
is not proof of a safe unmodified pre-VPN underlay, VPN/TLS authentication,
UDP/QUIC transport, endpoint DNS bootstrap, existing/new SSH reply paths,
aaPanel ingress or any Activation/Runtime Guard. The hostname match uses
the **host-configured resolver** (which may use local hosts records/caches
or an already-tunneled DNS path). It cannot prove a DNS query succeeded
over an independent Direct underlay. Pinning an IP does not guarantee the
VPN client will use that address later; activation planning must independently
protect actual resolver, endpoint and management paths. This diagnostic never
mutates routes, firewall, resolver files or host state; `activation_ready`
and `dns_bootstrap_verified` both remain **false**, even on success.
Existing third-party routing is possible; observations are non-atomic. The interactive diagnostic is menu option **13**; existing Path Diagnostics and Selective Plan retain options **11** and **12**.

### Explicit resolver-bound DNS diagnostic (Issue #2, dependent development)

The operator may separately check an **explicit DNS resolver path** rather than
silently trusting the host's current resolver or cached hostname data:

`server-connect --json underlay-dns --hostname vpn.example.net --endpoint 198.51.100.10 --resolver 1.1.1.1`

Optionally set `--resolver-port 53` to target an explicitly selected nonstandard
DNS service. This command validates the literal resolver and pinned endpoint,
uses trusted native `/usr/bin/ip` to observe UDP and TCP resolver routes
for the **exact DNS port and process UID**, and sends bounded standard DNS
A/AAAA queries **only to that literal server**, with `SO_BINDTODEVICE` on
the selected interface. Differing UDP/TCP paths, unknown routing selectors,
source/mark/VRF/source-port-sensitive policies, and post-query route changes
fail closed. There is no unbound or host-resolver fallback. Invalid input
omits `data` rather than reporting fictitious safety flags. It refuses
hosts-file-only answers, malformed inputs,
a missing/unreachable resolver, unsupported address results, route drift,
and any response lacking the operator-pinned endpoint IP. Each failure has
structured `ok: false` evidence without connecting to the VPN endpoint or
changing host DNS, system networking, profiles or services. Queries may reveal
the supplied hostname to that resolver; invoke only with an operator-approved
resolver.

**Not an activation gate:** the resolver's response is not DNSSEC/TLS
authenticated; an existing tunnel could still carry the interface-bound
resolver traffic, and an eventual routing change could interrupt the route.
Even a match leaves `read_only: true`, `dns_bootstrap_verified: false` and
`activation_ready: false`. Independent route ownership, an owned-network transaction journal,
activation/recovery guards, management proofs and physical post-change
tests are still mandatory; the existing PREPARED/UNCERTAIN intent journal
is not an applied route transaction. The exact CLI/API remains a development
candidate, not a published stable release.

The explicit resolver diagnostic is menu option **14**; existing Path Diagnostics **11**, Selective Plan **12**, and Underlay TCP **13** are retained.

### Compare host routes and policy rules against a recorded baseline (Issue #2 development)

Capture a baseline on the host *before* the intended maintenance or experiment;
keep it private because interface and route information can be sensitive:

```sh
umask 077
server-connect --json host-preflight --endpoint 198.51.100.10 --management-peer 203.0.113.42 > ./host-baseline.json
server-connect --json host-drift --baseline ./host-baseline.json
```

The comparison repeats native, read-only Linux route/rule/link inspection
including the **same literal** endpoint and management-peer queries from the
baseline, but retains their addresses only as private lookup inputs. The Host
Drift report does **not** print those baseline target addresses in JSON, text
or menu output; component names indicate whether each optional lookup was
compared. It reports per-component SHA-256 fingerprints (never raw baseline
contents), `changed` flags and a nonzero `host_drift_detected` error when
an observation differs. The **non-JSON CLI and interactive menu option 15**
also display the safe per-component report on detected drift, together with
an explicit classified failure; they never silently print only a generic
error. Route and link arrays ignore enumeration-order differences;
policy-rule ordering remains significant. Invalid, oversized,
symlinked, non-private or structurally incomplete baseline files are
rejected **before** any kernel inspection (including empty link inventories,
identity-free kernel route lookups, policy rules lacking priority/action, or
missing explicit `snapshot_atomic: false` and `activation_ready: false`
assertions); no baseline file paths or raw file content appear in errors or
diagnostic output. Legitimate empty route/rule families and verified
iproute2 6.15 policy-rule formats are supported: table/lookup, numeric
goto, terminal `action` (`blackhole`, `unreachable`, `prohibit`,
`throw`, `anycast`, `multicast`, `xresolve`), null-valued `nop`
and `l3mdev`, and deprecated NAT markers (`masquerade: null` or
`nat_gateway`). Route-style policy `type` and
boolean-valued native action markers are rejected as incomplete evidence.
These formats are based on
[iproute2 v6.15 print_rule()](https://github.com/iproute2/iproute2/blob/v6.15.0/ip/iprule.c)
and actual isolated Linux namespace captures; validation establishes only
minimal shape, not baseline authenticity or compatibility with unverified
future `iproute2` serializers.

**Important:** both snapshots are non-atomic and the saved file is
operator-provided, not a trusted/cryptographically authenticated kernel
record. A matching comparison is **not proof** of network resource ownership,
DNS/bootstrap reachability, safe SSH or HTTP(S) replies, nftables/conntrack,
independent activation/rollback guards or production readiness. It never
touches routes, rules, services, DNS or manager state. A changing route report
is a diagnostic requiring operator investigation, **not an instruction for
Server Connect to overwrite foreign-owned network configuration**. This
command is a development diagnostic and is not a routed-mode release.

### Inspect the internal activation intent journal (Issue #2 development)

`server-connect --json activation-journal-status` (interactive menu **16**)
reports only the phase (`absent`, `prepared` or `uncertain`),
operation identity, revision, creation timestamp and resource **count**
from the existing strictly validated private version-1 intent journal.
Private route/rule/interface `before` and `intended` records, observed
destinations, and plan fingerprints are **not returned**. A corrupt, unsafe
or untrusted record fails closed with a nonzero classified error and **no**
fabricated safe-absent data; the record is retained for investigation.
`prepared` and `uncertain` both explicitly require operator review.
An `absent` record is *not* a verified safe network baseline.

This command does not inspect or change host networking, authorize a route
apply, arm a guard, commit a profile or perform rollback. The current journal
still supports **only** `prepared` and `uncertain` phases. Pending
confirmation, independent timers, fresh SSH authorization, actual owned
resource reconciliation and reboot recovery remain **unimplemented**.
Like existing Manager state operations, first inspection may create a private
state directory and lifecycle `.lock` file; it does not create an intent
journal or affect routes, firewall, DNS or service configuration. This
development diagnostic is not an activation/release capability.

### Proxy Only compatibility and application opt-in

`server-connect --json status` distinguishes the saved desired state from the native systemd service observation; it does **not** claim a healthy outbound path. If native systemd inspection is unavailable or an active service's ownership cannot be verified, both JSON **and ordinary text status** now return a classified nonzero error and retain any verified-safe desired/observed/health fields (without inventing a state when loading failed). Internal service control uses only the trusted native `/usr/bin/systemctl` with a fixed sanitized child environment, not an operator-provided `PATH` or inherited systemd/DBus overrides. `connect` refuses an unknown, contradictory or newly active service at both the initial check and the post-core-validation recheck, **before writing persistent proxy credentials or runtime configuration**; a pending activation must never overwrite a possibly active service's runtime.

- The link importer deliberately supports a **subset** of VLESS TCP/WebSocket and TLS/Reality query fields, rejecting unrecognized or incompatible parameters. **Local TCP VLESS through the pinned sing-box core has live integration evidence; TLS/WebSocket/Reality interoperability with real foreign providers is NOT_RUN.** Import and `validate` establish syntax/core-configuration acceptance, not remote reachability.
- A selected application may opt in explicitly with `server-connect exec -- curl ...`, or with its own authenticated HTTP/SOCKS proxy settings. `server-connect probe --via proxy --url https://...` tests the selected path; `--via direct` independently tests host Direct connectivity. These commands require an already installed, selected and running development candidate.
- **Multi-target, read-only path diagnostics (Issue #3 foundation; not an active health guard):**
  `server-connect --json diagnose-path --via proxy --url https://one.example --url https://two.example`
  checks two to four distinct hostnames through the selected Proxy Only transport, with **no Direct fallback**.
  Run an independent `--via direct` invocation for the Direct baseline; Direct successes never count as Proxy
  results. Responses contain only target indexes, bounded HTTP codes/error classifications, counts, and
  `all_targets_reachable`, `mixed_results`, or `no_targets_reachable`; no URL, query or credentials are returned.
  Proxy diagnostics pin one selected profile/runtime and service invocation across the target set, checking
  identity before and after each request without holding the lifecycle lock during network I/O. If that
  identity changes or becomes unverifiable, the whole set returns `path_changed_unverified` /
  `diagnostic_path_changed`, with no sample marked reachable; prior successful samples are invalidated.
  A single failed target returns `probe_set_partial`, **not** proof of a dead VPN. Redirects are never followed;
  HTTP 3xx is `probe_redirect_unverified`, not verified destination content. Contradictory path/result
  combinations never expose a success status; TLS hostname mismatches report `probe_tls`. At most four 12-second target
  requests are made, without modifying host routes or firewall. Results explicitly mark
  `tunnel_health_verified: false` and `activation_ready: false`. The existing selected-proxy lookup may
  initialize private application state. These checks **do not attest foreign egress identity, independently
  prove VPN-bound TUN routing, supervise a live tunnel, recover automatically, or replace the Activation or
  Runtime Health Guards**. Real foreign-provider, reboot and field acceptance remain NOT_RUN.
- **APT does not reliably honor generic HTTP proxy variables.** The opt-in `sudo server-connect apt -- apt-get update` (or menu option **9**, confirmed with `UPDATE`) explicitly configures `Acquire::http::Proxy` and `Acquire::https::Proxy` only for that child process. Native, root-owned Debian APT executables at `/usr/bin/apt-get`, `/usr/bin/apt` and `/usr/bin/apt-config` are verified before any proxy credential is accessed. Unqualified `apt-get` and `apt` are accepted only when PATH resolves to their native installation; `/bin` aliases from Debian usrmerge are also supported. Other same-basename programs, PATH shadows and substituted binaries are refused. The child runs with a fixed trusted PATH and without inherited proxy/loader overrides. The private proxy config is an unlinked mode-0600 descriptor; `/etc/apt` is never modified. Existing per-host `DIRECT`/proxy policy, proxy autodetection, untrusted extra config and conflicting caller overrides cause a clear fail-closed error. The **full APT execution path** is checked: the effective Debian 13 `Dir::Bin::*` native-method/compressor paths, `RootDir`/`Dir` roots, applicable binary-specific redirections and **all present native acquisition-method executables** (including PDiff `rred` and `mirror`) plus their exact native aliases must match the supported trusted installation. Missing optional Debian 13 helpers are accepted; unknown or untrusted additional transport methods are not supported. Caller method/root/compressor overrides are rejected *before* credentials are loaded; inherited conflicts cause a credential-safe policy error rather than rewriting system APT configuration. Custom APT method directories and redirected execution layouts are not yet supported. Standalone `apt-get update` and `apt update` enforce `--error-on=any`, even when cached indexes exist. Combined `-U`/`--update` package operations are deliberately **unsupported**: use a separate strict `apt-get update`, followed by the intended `apt-get install` command. APT retains its ordinary repository signatures and HTTPS verification; do not downgrade repository trust. Only the APT acquisition transport is covered, not arbitrary maintainer scripts or other applications. Never enable wire-debug traces that could expose `Proxy-Authorization` credentials.
- **WordPress/PHP-FPM and plugins may use different HTTP clients or ignore shell environment variables.** For WordPress, an explicitly configured supported HTTP transport/proxy integration, isolated site test, and restoration plan are necessary; `server-connect exec` alone is not proof of WordPress API compatibility. Do not globally rewrite APT, PHP-FPM, aaPanel or customer proxy configuration. Earlier independent disposable tests covered WordPress PHP CLI with an installed manager and WordPress PHP-FPM with an independently started sing-box core, **not their combination**. The isolated installed-host QA now exercises genuine WordPress 7.1.3 + SQLite Database Integration 3.0.2 from **PHP-FPM and FastCGI alongside the same installed manager**, with QA-only pool-scoped `WP_PROXY_*`, fresh-origin nonce acquisition over selected VLESS, outage fail-closed, recovery, active same-source update, rollback and disconnect. Treat this as a PASS **only when the exact-candidate installed-host CI completes successfully**. This is not a test of an actual customer WordPress site, aaPanel, foreign network, signed release or safe persistent customer secret provisioning; Server Connect never edits a site automatically.
- A user-facing inbound VPN/relay service (for example Marzban Node or Backhaul) does not automatically opt into `HTTP_PROXY`. Raw TCP/UDP forwarding and established inbound reply paths require their own explicitly verified routing/relay architecture.

The current Go JSON/CLI and offline installer are **not production-supported interfaces** until review findings and exact-artifact acceptance are resolved.

## Documentation and project status

| Source | Responsibility |
| --- | --- |
| [Project specification](docs/PROJECT-SPEC.md) | **Canonical** product goals, behavior, constraints, and non-goals |
| [Architecture](docs/ARCHITECTURE.md) | Component boundaries, host resource ownership, and upstream reuse |
| [Safety and recovery](docs/SAFETY-RECOVERY.md) | Guarded activation, health monitoring, rollback, and crash/reboot safety |
| [Online and offline distribution](docs/OFFLINE-DISTRIBUTION.md) | Both installation paths, release trust, updates, and shared lifecycle |
| [Acceptance criteria](docs/ACCEPTANCE.md) | Reproducible test matrix and evidence needed before release |
| [Contributor instructions](AGENTS.md) | Engineering, review, and project-continuity rules |
| [GitHub Issues](https://github.com/AChWorks/server-connect/issues) | Current work, dependencies, and release acceptance |

**Development starts with [Issue #1 — Offline-first sing-box Proxy Only](https://github.com/AChWorks/server-connect/issues/1)**. Implement and validate it on disposable Linux hosts before advancing to host-wide routing. No production server change is authorized by this repository.

## Boundaries and security

Server Connect owns only its own host changes. It must not take over unrelated firewall rules, SSH settings, aaPanel services, other tunnels, or customer applications. It is **not** a VPN provider, public relay network, reverse proxy, or new packet-forwarding engine.

Do not commit real VPN subscriptions, endpoints containing credentials, customer details, secrets, private keys, or runtime state.

## License status

The repository is publicly readable, but **no software license has been selected**. Public visibility does not grant general rights to reuse or redistribute the code. Any open-source license or binary redistribution policy requires an explicit project-owner decision.
