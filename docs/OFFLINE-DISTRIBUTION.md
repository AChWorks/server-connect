# Online and offline distribution, install, and update

**Status:** installation contract; development-only installers exist in source, but **no authenticated, licensed release or official one-line install endpoint is available yet**.

## 1. Two installation paths, one installer

**Online (connected server):** one published installer command downloads a trusted bootstrap and lets it fetch the exact OS/architecture-specific, immutable release bundle, pinned upstream sing-box and any required verified prerequisites, then invoke the **same local installer** as offline mode. Support an optional pinned release version; resolve and verify an official latest channel only where publication policy allows. Network acquisition occurs **before** privileged installation, and failed downloads do not mutate installation or host networking.

**Offline (disconnected server):** the operator downloads **one complete release bundle per supported OS/CPU target** on another trusted Internet-connected device. The operator verifies provenance, copies/extracts it into a root-owned private staging folder on the target, and runs **one local command**. No network fetch (including DNS, APT or GitHub) is allowed in offline mode.

The bootstrap and release artifact must be authenticated against an independent trusted publisher key or digest. HTTPS and hashes delivered by the same untrusted script/archive are insufficient on their own. Source the bootstrap from an explicitly trusted operator-chosen distribution endpoint; never silently execute redirect-provided shell scripts. Before release, publish the real one-line online command and a separately verifiable trust procedure.

**Both paths:** the online bootstrap is only an acquisition/verification frontend. One shared installer handles version checks, preflight, staging, owned resources, state preservation, rollback, offline/online update and uninstall. No extra persistent fetch daemon, second installation state machine or feature difference is permitted.

On a connected Linux host, privileged installation must create **root-owned private download/extraction staging before fetching or unpacking anything**; escalating a user-owned mutable archive directory after verification is not sufficient. Non-root dry-run archive `--verify-only` remains acceptable when no privileged installation follows. Reject unsupported archive member types, duplicate paths and traversal before extraction. A matching user-supplied checksum only verifies the bytes against that value and does not resolve the separate publisher authenticity/release-authorization gate.

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
sudo bash /root/server-connect/install.sh --offline
~~~

The local command can run only after an exact trusted bundle is staged and verified. It is **not** production installation guidance while the publisher authentication and license gates remain unresolved. The **online** one-line release command will be published after its authenticated release URL and bootstrap trust chain exist; do not invent a URL. Do not recommend fetching an installer over GitHub during a foreign network shutdown.

## 2. Offline mode means no implicit online dependencies

For every advertised target:
- The package carries the pinned manager, sing-box binary, local routing rule sets, templates, and **every dependency not already guaranteed and verified on the supported base OS**; no post-download fetch of a core, dashboard, GitHub release, runtime library or APT repository.
- Installer startup, preflight, install, first launch, profile import (from local file/link), routing activation, guards, recovery, disable, uninstall and **offline update** all work without Internet outside Iran.
- Package the necessary distro-signed local OS packages when required. Check exact ABI/library/kernel/TUN/systemd/capability versions; do not pretend one arbitrary .deb works for every Debian/Ubuntu release.
- An incompatible kernel/OS/architecture, missing local package, signature failure or foreign service conflict is an actionable error **before changing host networking**. No silent APT install and no trust downgrade **in offline mode**. In online mode, fetch prerequisite packages from explicitly verified supported sources; do not run an unbounded system upgrade.
- A network-free install test must detect even accidental external HTTP/DNS resolution attempted by a script.

A bundle may support additional optional cores **only when tested and intentionally supplied**. Missing optional cores do not block a supported sing-box installation.

## 3. Trust and lifecycle

- Release references immutable version, artifact digest, upstream sing-box version/identity, support matrix and generated provenance. Authenticate **manager release** and **third-party binary** separately.
- A same-bundle checksum provides integrity against accidental corruption, **not trusted publisher identity**. The operator obtains a trustworthy signature/public key or signed digest through an independent trusted channel before privileged execution. Keep installation guidance usable in offline conditions.
- Protect private staging from other local users, refuse unsafe symbolic links/file ownership, validate archive entries and reject path traversal. Treat executable shell code as trusted only after provenance review; running ./install.sh is already privileged execution.
- Verify all required bytes/config/schema and local preconditions first; stage replacements; preserve existing profiles/secrets and unowned host state; activate binaries only after validation, with an independently available rollback/recovery path.
- Installation should produce a clear inventory of owned files and units. No mandatory new public port or always-on management API.
- Ordinary uninstall removes owned executable/service/network resources but **preserves operator profile material** by default; destructive purge is separately confirmed.
- Online and offline package updates converge on the same verified local-bundle path and never silently replaces unrelated applications or network controls. A failed update must leave a usable prior version or explicit recoverable state.
- Default after first install: **Direct**, no active TUN/host-wide routing takeover.
- Opt-in `server-connect apt -- apt-get ...` uses an unlinked read-only config descriptor and **never** persists `/etc/apt` proxy settings. APT/download applications are not required to honor generic environment variables; operator-selected applications must have a tested proxy mechanism, and unrelated services must remain unchanged.

## 4. Versioned compatibility and honest support

The implementation must publish a table of supported distro release, architecture, kernel/network primitives, package prerequisites and file formats, derived from **tested** packaged artifacts. Before this exists, do not advertise Debian/Ubuntu versions, protocol combinations or CPU memory requirements as production-compatible.

Package and security claims for **both** acquisition paths require the tested, exact-artifact evidence defined by [ACCEPTANCE.md](ACCEPTANCE.md); no external private contract is required to implement or validate the shared installer.

## 5. Failure states and safe assistance

Errors must report the stage, failed requirement, exact local corrective step and whether host state changed. If an offline prerequisite is absent, instruct the user which trusted file to download **on another machine** and where to place it. If online fetch fails, report the exact failure, do not partially install, and offer the offline procedure. Never ask the disconnected host to curl the missing file.

If a new sing-box version changes config schema, migration must be explicitly tested against stored profiles. Keep old readable state and rollback boundaries; unsupported combinations are refused, not silently reinterpreted.
