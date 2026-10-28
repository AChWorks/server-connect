# Online and offline distribution, install, and update

**Status:** installation contract; development-only installers exist in source, but **no authenticated, licensed release or official one-line install endpoint is available yet**.

## 1. Three acquisition choices, one installer

**Official online (connected server):** one published command obtains an independently authenticated bootstrap and downloads the exact compatible publisher-authenticated immutable release bundle and required verified prerequisites. Support an optional pinned release version; only resolve an official latest channel under publisher policy. Network acquisition occurs before product installation and cannot silently alter host routing. Native package prerequisite acquisition may itself mutate OS packages on supported connected hosts, as stated below.

**Operator-hosted online mirror (Iranian or other):** the operator uploads the **identical signed release bundle plus authenticated manifest/metadata** to a static HTTPS web host and gives the installer an explicit mirror base URL. A single documented command retrieves and authenticates the trusted bootstrap **before privileged execution**, then fetches and verifies the publisher's exact pinned version/architecture bytes from that mirror and invokes the **same local installer**. No mirror-specific daemon, installer logic, private key, rewrite or mandatory foreign Internet is needed. The mirror is untrusted transport storage, not an authority allowed to replace release identity; HTTPS, redirects, metadata and version pinning must be validated. DNS/TLS reachability to the Iranian host and trusted local prerequisites still matter.

**Manual offline upload (disconnected server):** the operator obtains **the same complete bundle per supported OS/CPU target** elsewhere, independently verifies its provenance, copies/extracts it into a root-owned private staging folder, and runs **one local command**. No network fetch (including DNS, APT or GitHub) is allowed in offline mode. The offline archive also includes the needed locally verified Iranian IP-prefix and routing rule lists.

The bootstrap and release artifact must be authenticated against an independent trusted publisher key or digest. HTTPS and hashes delivered by the same untrusted script/archive are insufficient on their own. Source the bootstrap from an explicitly trusted operator-chosen distribution endpoint; never silently execute redirect-provided shell scripts. Before release, publish the real one-line online command and a separately verifiable trust procedure.

**All three acquisition choices:** the official/mirror online bootstrap is only an acquisition/verification frontend. One shared installer handles version checks, preflight, staging, owned resources, state preservation, rollback, offline/online update and uninstall. The bundle must be byte-identical for the same release/OS/arch across all sources. No mirror service process, persistent fetch daemon, second installer state machine or feature difference is permitted.

On a connected Linux host, privileged installation must create **root-owned private download/extraction staging before fetching or unpacking anything**; escalating a user-owned mutable archive directory after verification is not sufficient. Non-root dry-run archive `--verify-only` remains acceptable when no privileged installation follows. The development bootstrap needs Debian 13 native `curl`, `sha256sum`, `timeout` and `python3` for online-only bounded acquisition/archive parsing; it can install missing `curl`, Python 3 and CA certificates through Debian 13 APT only in a real root installation (not `--verify-only`), while requiring the Debian base's own `coreutils` without automatic system repair. Python is **not** an offline-installer dependency. The online preflight enforces an in-flight **96 MiB compressed transfer ceiling** (operator may only lower it with `--max-download-bytes`), **128 MiB per regular file / 192 MiB total expanded bytes** and a kernel-enforced per-file write limit, a hard memory/time limit on archive parsing, a 1 MiB metadata budget and strict member types/paths before staged extraction. These ceilings are anchored to the exact official pinned sing-box 1.14.3 upstream archive: **31,678,266 compressed and 93,255,156 expanded bytes** (independently SHA256-verified), leaving significant fixed room for the manager, license, manifest and packaging. Before transfer the bootstrap verifies filesystem available space can sustain the maximum transfer+expansion **plus a 1 GiB or 10% filesystem free-space reserve**, whichever is larger; after validation and before every extraction write it checks the remaining reserve again while enforcing the process-local aggregate byte budget. A concurrent unrelated writer could still consume disk independently between checks: these checks are not an atomic host-wide filesystem quota, so extremely small/unreliable shared volumes fail closed rather than proceeding. The bootstrap validates/extracts with one parser to avoid parser differences, rejecting unsafe links, duplicates and traversal. Production acquisition and redirects must be HTTPS-only. CI-only HTTP requires a parsed genuine `127.0.0.1` or `localhost` authority with a valid explicit port; rejects userinfo, does not follow any redirect, bypasses proxy environment variables and pins localhost resolution to `127.0.0.1`. For a **real root online installation on Debian 13**, the development bootstrap now detects missing native `curl`, Python 3 and HTTPS CA certificates and acquires only those fixed packages through the host's existing APT trust policy (without changing package sources or upgrading the whole host). It refuses unsupported OS versions and missing trust/staging preconditions before APT. This is an **OS package mutation before the release archive has been fetched**: an APT-installed prerequisite can remain even if later acquisition or signature/digest checks fail. No Server Connect installation or host-network routing is attempted on that failure. In contrast, `--verify-only` **never** installs packages and reports missing tools instead, whether invoked as root or non-root; the offline installer never uses APT. If the native Debian package path is blocked, use an independently verified complete offline bundle rather than forcing a new repository or proxy. No authenticated public one-line release is advertised yet. A matching user-supplied checksum only verifies the bytes against that value and does not resolve the separate publisher authenticity/release-authorization gate.

The first implementation's installer and CLI share an exclusive product lifecycle lock for operations that change service/profile state. Uninstall preserves stored profiles but explicitly clears active proxy intent and owned runtime configuration; reinstall starts Direct unless an explicitly separately approved restore policy exists. A failed staging or update transaction must not leave an unowned service, a dangling command link or unverified previous active state; print recovery-required evidence when restoration cannot be proved.


Current local QA candidate layout (future signed release may add authentication metadata):

~~~text
/root/server-connect/
  install.sh
  server-connect.service
  bin/
    server-connect
    sing-box
    libcronet.so
  THIRD-PARTY-LICENSES/
    sing-box-LICENSE
  manifest.json
  checksums.sha256
  # Publisher authentication still required before public release.
~~~

Local QA **offline** one-command invocation (disposable hosts only; not an authenticated release):

~~~sh
sudo -- /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/server-connect/install.sh --offline
~~~

The supported privileged entry is a trusted Debian 13 `sudo` privilege transition with default `env_reset` (no `sudo -E`, `--preserve-env`, custom environment forwarding or writable sudo policy), followed by an explicit `/usr/bin/env -i` allowlist **before** `/bin/sh` starts. The allowlist intentionally passes only `HOME`, a native system `PATH`, and `LC_ALL`. Do not launch with `sudo bash` or a noninteractive Bash interpreter inherited from an untrusted environment: `BASH_ENV` and loader variables can affect processes **before** shell-body `unset` commands run. A custom sudo policy preserving dangerous loader variables is outside the supported security boundary and must be corrected at the privilege-transition configuration, not inside the script. For an already trusted root shell, use the same `/usr/bin/env -i ... /bin/sh` invocation; this cannot retroactively repair a root shell that has already executed untrusted startup code.

The offline source must be an absolute, canonical, non-symlinked, independently verified path whose **every ancestor** from `/` is root-owned and not writable by group/others; private `/root/server-connect` is the recommended staging location. Do not invoke the privileged script from `/tmp`, a user-managed mount, a symlinked alias, or a mutable parent. Verify provenance **before** asking a root interpreter to read the script; in-script ancestry checks protect subsequent reads and service mutations, not a hostile initial source file. Actual installed-host verification remains separate.

This local command can run only after an exact trusted bundle is staged and verified. It is **not** production installation guidance while the publisher authentication and license gates remain unresolved. The **online** one-line release command will be published after its authenticated release URL and bootstrap trust chain exist; do not invent a URL. Do not recommend fetching an installer over GitHub during a foreign network shutdown.

## 2. Offline mode means no implicit online dependencies

For every advertised target:
- The package carries the pinned manager, sing-box binary, **verified versioned Iranian IP-prefix rules and other required local domain/IP rule sets**, templates, and every dependency not guaranteed and verified on the supported base OS; no post-download fetch of a core, dashboard, GitHub release, runtime library or APT repository.
- Installer startup, preflight, install, first launch, profile import (from local file/link), routing activation, guards, recovery, disable, uninstall and **offline update** all work without Internet outside Iran.
- Package the necessary distro-signed local OS packages when required. Check exact ABI/library/kernel/TUN/systemd/capability versions; do not pretend one arbitrary .deb works for every Debian/Ubuntu release.
- An incompatible kernel/OS/architecture, missing local package, signature failure or foreign service conflict is an actionable error **before changing host networking**. No silent APT install and no trust downgrade **in offline mode**. In online mode, fetch prerequisite packages from explicitly verified supported sources; do not run an unbounded system upgrade.
- A network-free install test must detect even accidental external HTTP/DNS resolution attempted by a script.

A bundle may support additional optional cores **only when tested and intentionally supplied**. Missing optional cores do not block a supported sing-box installation.

## 3. Trust and lifecycle

- Release references immutable version, artifact digest, upstream sing-box version/identity, local routing-list versions/hashes, support matrix and generated provenance. Authenticate **manager release** and **third-party binary** separately. A mirror cannot redefine the publisher's version, trusted public key, digest or allowed redirect destinations.
- A same-bundle checksum provides integrity against accidental corruption, **not trusted publisher identity**. The operator obtains a trustworthy signature/public key or signed digest through an independent trusted channel before privileged execution. Keep installation guidance usable in offline conditions.
- Protect private staging from other local users, refuse unsafe symbolic links/file ownership, validate archive entries and reject path traversal. Treat executable shell code as trusted only after provenance review; running ./install.sh is already privileged execution.
- Verify all required bytes/config/schema and local preconditions first; stage replacements; preserve existing profiles/secrets and unowned host state; activate binaries only after validation, with an independently available rollback/recovery path.
- Installation should produce a clear inventory of owned files and units. No mandatory new public port or always-on management API.
- Ordinary uninstall removes owned executable/service/network resources but **preserves operator profile material** by default; destructive purge is separately confirmed.
- Online and offline package updates converge on the same verified local-bundle path and never silently replaces unrelated applications or network controls. A failed update must leave a usable prior version or explicit recoverable state.
- Default after first install: **Direct**, no active TUN/host-wide routing takeover. The two product-owned independent recovery service/timer units for the experimental rule-only acceptance path are packaged and installed **disabled/inactive**; they do not cause a background service or host-policy change on ordinary Proxy Only hosts. Both online bounded-archive allowlist and offline shared-installer manifest include these exact units. A pending or unresolved trial blocks update/uninstall until conservatively recovered and explicitly cleared.
- Opt-in `server-connect apt -- apt-get ...` uses only verified root-owned system APT executables (and `/usr/bin/apt-config` for policy preflight), an unlinked private mode-0600 config descriptor, and a sanitized child environment. It **never** persists `/etc/apt` proxy settings. Host/caller proxy overrides are rejected. Native Debian 13 method-handler paths, root-directory resolution and relevant executable/compressor settings must also pass private effective-policy verification; a nonstandard host APT layout fails closed without modifying the host. The standalone `update` action enforces `--error-on=any`; combined `-U`/`--update` operations are rejected instead of risking a silent partial index refresh. Run a separate strict update before an ordinary package operation. APT/download applications are not required to honor generic environment variables; unrelated services must remain unchanged.

## 4. Versioned compatibility and honest support

The implementation must publish a table of supported distro release, architecture, kernel/network primitives, package prerequisites and file formats, derived from **tested** packaged artifacts. Before this exists, do not advertise Debian/Ubuntu versions, protocol combinations or CPU memory requirements as production-compatible.

Package and security claims for **both** acquisition paths require the tested, exact-artifact evidence defined by [ACCEPTANCE.md](ACCEPTANCE.md); no external private contract is required to implement or validate the shared installer.

## 5. Failure states and safe assistance

Errors must report the stage, failed requirement, exact local corrective step and whether host state changed. If an offline prerequisite is absent, instruct the user which trusted file to download **on another machine** and where to place it. If online fetch fails, report the exact failure, do not partially install, and offer the offline procedure. Never ask the disconnected host to curl the missing file.

If a new sing-box version changes config schema, migration must be explicitly tested against stored profiles. Keep old readable state and rollback boundaries; unsupported combinations are refused, not silently reinterpreted. Rule-list updates/imports from either download source or local files require independent provenance/format validation, atomic replacement, version and stale-data diagnostics, and safe rollback without mandatory foreign downloads.
