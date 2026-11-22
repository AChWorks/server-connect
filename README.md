# Server Connect

Server Connect manages **outbound** connectivity on Linux servers using a single pinned, official [sing-box](https://github.com/SagerNet/sing-box) Core. It provides a terminal menu and a structured JSON CLI, preserves local service/SSH access, and restores only its own networking changes on Disconnect or guarded recovery. It is **not** a VPN provider, a website ingress tunnel, or a per-process routing engine.

**Release state:** The first Stable `0.1.0` is being prepared, **not publicly published**. Do not use the GitHub `releases/latest` install examples until a release with verified artifacts exists. Current source/physical acceptance is recorded in [Issue #5](https://github.com/AChWorks/server-connect/issues/5), [CI](https://github.com/AChWorks/server-connect/actions) and reviewed PRs; a passing test is not production-deployment authorization.

## Modes and support

| Mode | Behavior | Status |
| --- | --- | --- |
| **Direct** | Original host networking without Server Connect-owned VPN routing or blocking rules | Implemented; installed-host QA |
| **Proxy Only** | Explicit local HTTP/SOCKS proxy for supported applications; no transparent host-wide routing | Implemented; installed-host QA |
| **Smart Routing** | Independently guarded TUN: Iranian/private/protected destinations Direct; other public destinations via the selected VPN, subject to operator rules | Implemented; source-bound Debian 12/13 guest and authorized nonproduction selected IPv4/VLESS field evidence; no blanket provider/IPv6 guarantee |

First Stable targets **Debian 12 and Debian 13, amd64**, with systemd and usable TUN/nftables. Other distributions, architectures and untested real provider paths are **not advertised as supported**. Public selected IPv6 positive field-path evidence is incomplete; live REALITY testing remains Owner-deferred. No claim about country classification is proof of real physical routing or provider reachability.

### Iran traffic policy

The versioned offline datasets are the Owner-approved [DB-IP Country Lite](https://db-ip.com/db/lite.php) snapshot (October 2026, CC BY 4.0) and [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules) snapshot (November 2026, GPLv3 repository). The default `bypass_iran` policy uses their **CIDR-accurate intersection** (currently 2,917 IPv4/IPv6 prefixes); `--iran-coverage dbip` explicitly opts into the broader DB-IP-only estimate. Protected/private networks and explicitly validated Direct exceptions remain Direct. Other public addresses use the selected VPN; saved CIDR VPN rules take precedence. No live external dataset download is needed to connect. `geosite-ir` is **not** converted into unauthenticated Direct-domain exemptions.

## Use on an authorized host

Inspect without enabling host-wide Smart Routing:

```sh
sudo server-connect --json status
sudo server-connect --json mode-overview
sudo server-connect --json native-status
sudo server-connect --json smart-routing-data
sudo server-connect --json smart-routing-rules list
```

Use `sudo server-connect` for the terminal menu or `server-connect help` for current CLI flags. In a real interactive SSH/console TTY the menu uses an isolated full-screen view with a concise host/mode/profile header; `a` opens a separate advanced page, each action leaves its result visible until Enter, and exit restores the previous terminal screen. Narrow terminals show shorter labels without dropping actions. `NO_COLOR`, `TERM=dumb`, redirected output and JSON remain usable without terminal-only color/controls. Privileged state inspection requires root; these read-only commands do not enable Smart Routing. Keep VPN credentials in a private file or stdin; do not place them in shell command arguments or logs:

```sh
sudo server-connect --json import --file /private/profile-link.txt
sudo server-connect --json profiles list
sudo server-connect --json select PROFILE_ID
```

A supported `vless://` link or validated sing-box JSON can be imported; the importer does not promise arbitrary subscriptions/transports. Stored profiles and routing-rule sources are private.

For Smart Routing, first verify the selected connection, management access, underlay interface and console recovery path. On a **separately authorized recoverable host**:

```sh
sudo server-connect connect-smart --underlay-if eth0 --mode bypass_iran
```

The first guarded activation is **provisional** and displays a short `sudo server-connect confirm TOKEN` command. Run that exact command from a **new SSH connection opened after activation**, within the displayed countdown (currently 600 seconds). Reusing the old session or the token, or allowing the countdown to expire, cannot commit Smart Routing; the independent recovery path returns the host to owned Direct/off. After successful one-time confirmation, ongoing Core/health supervision is automatic; no repeated manual confirmation is needed. `server-connect native-status` reports confirmed versus pending state and recovery details. To return to Direct:

```sh
sudo server-connect disconnect
```

The menu displays short, readable **Status**, **Mode Overview**, **Profiles**, **Routing Rules** and **Native Guard / Recovery Status** pages instead of machine JSON for everyday inspection; `server-connect --json COMMAND` remains the unchanged, complete programmatic interface. Advanced tools, exact error codes and non-verified states remain accessible. Destructive operations are explicitly acknowledged. If a guard reports `UNCERTAIN`, investigate from console/SSH instead of assuming Direct was safely restored. For limits, rollback and protected traffic see [Safety and recovery](docs/SAFETY-RECOVERY.md) and [Architecture](docs/ARCHITECTURE.md).

**Operator routing rules:** The native import accepts a private ASCII/LF file with `cidr direct|vpn PREFIX`, or `domain vpn NAME` / `suffix vpn NAME` entries (see `server-connect help`). Pin the exact file bytes with SHA256 and provide a source identifier and source date; updates/removals require the previous source hash. Saving rules never activates routing. Unverified DNS-to-IP associations cannot justify Direct-domain bypass.

**Selected IPv6:** By default, an unverified selected VPN IPv6 exit is disabled inside TUN and intercepted AAAA answers are empty; it must not leak unknown public IPv6 Direct. `connect-smart --enable-selected-ipv6` is an explicit operator assertion for an independently verified IPv6-capable VPN exit, not automatic discovery.

## Installation and release

There is **one installer** and a target-specific, SHA256-verified archive containing the manager, pinned sing-box Core, data, systemd units and notices. The intended acquisition paths are **Official GitHub HTTPS**, an operator-controlled **HTTPS Mirror**, and **manual local-archive upload** (no external project downloads). Mirror and local-archive modes do not silently contact GitHub or fetch Core/rules separately. For all installation modes, the bootstrap checks native capabilities and installs **only missing** Debian OS packages through the host's existing trusted APT sources; these can be domestic mirrors even when international access is blocked. Online acquisition may need `curl` and HTTPS CA certificates; local-archive mode does **not**, but may need `python3`, `nftables`, `iproute2`, or optional signed-QA `openssl`. No installed tool is deliberately upgraded just to satisfy a version preference; APT may resolve dependencies of newly needed packages. A fully equipped host skips APT and local-archive installation makes no network requests. If the configured APT repositories are unreachable, the installer reports the missing packages and how to repair those sources or install them manually. `--verify-only` never installs packages. Essential Debian bootstrap utilities and systemd must still be functional; stripped/untrusted host images may need correction before a safe install. Debian APT packages are separate from the project Mirror. The selected HTTPS/upload source is the trust authority; hashes hosted by that same source are integrity checks, not independent publisher authentication. No mandatory signing key is required. Successful interactive bootstrap installations and updates open the full-screen menu when a controlling TTY and a supported `TERM` are available; the provided Official/Mirror launchers preserve only `TERM` across their otherwise clean privileged environment; automated or headless scripts simply print `sudo server-connect`. Add `--no-menu` to the shared bootstrap to skip the automatic menu even with a TTY.

[Distribution, release-build commands and installation instructions](docs/OFFLINE-DISTRIBUTION.md) distinguish the current unpublished candidate from runnable public release URLs. The operator's private Mirror hostname/path are intentionally **not** documented in this public repository. Actual release artifacts and hashes will belong to [GitHub Releases](https://github.com/AChWorks/server-connect/releases) after separate publication approval.

## Development and evidence

```sh
go test ./...
go vet ./...
go run ./cmd/server-connect help
```

Default source builds report `0.1.0-dev`; a clean, immutable versioned `0.1.0` release-candidate build embeds the version shown in its manifest, checksum identity and CLI. Never publish a local QA artifact as Stable. Exact installed-host/TUN/SSH and negative-path procedures are in [Acceptance](docs/ACCEPTANCE.md) and `scripts/qa/`. Run privileged network experiments only on explicitly authorized recoverable targets, not customer servers.

Project truth has one owner per topic: [Project specification](docs/PROJECT-SPEC.md) (product scope), [Architecture](docs/ARCHITECTURE.md) (design), [Safety and recovery](docs/SAFETY-RECOVERY.md) (runtime and rollback), [Distribution](docs/OFFLINE-DISTRIBUTION.md) (packages and installation), [Acceptance](docs/ACCEPTANCE.md) (test contracts), [Issues](https://github.com/AChWorks/server-connect/issues) (open decisions) and PRs/CI/Releases (exact results). See [AGENTS.md](AGENTS.md) for contributor constraints.

**License:** The first-party project is [MPL-2.0](LICENSE). The bundled upstream Core, Go dependencies, Public Suffix List and Iranian datasets retain their applicable third-party notices and attribution in the immutable archives. Approved data sources remain unchanged; publishing is a separate Owner decision.
