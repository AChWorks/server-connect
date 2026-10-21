# Offline distribution, install, and update

**Status:** target contract for a future installer; **no release or executable installer exists yet**.

## 1. User experience

The operator downloads **one complete release bundle per supported OS/CPU target** on a separate trusted Internet-connected device. The operator verifies release provenance, copies/extracts it into a root-owned private staging folder on the Iran server, and executes **one local command**.

Expected future layout (illustrative until implemented):

~~~text
/root/server-connect/
  install.sh
  bin/
    server-connect
    sing-box
  rules/
    required-bundled-rules.srs
  templates/
  packages/                 # only required local packages for exact supported target
  manifest.json
  checksums.sha256
  signatures/
~~~

Desired one-command UX **after the official package exists**:

~~~sh
sudo bash /root/server-connect/install.sh --offline
~~~

This is documentation of the future interface, **not a runnable command today**. Do not recommend fetching an installer over GitHub during a foreign network shutdown.

## 2. Offline means no implicit online dependencies

For every advertised target:
- The package carries the pinned manager, sing-box binary, local routing rule sets, templates, and **every dependency not already guaranteed and verified on the supported base OS**; no post-download fetch of a core, dashboard, GitHub release, runtime library or APT repository.
- Installer startup, preflight, install, first launch, profile import (from local file/link), routing activation, guards, recovery, disable, uninstall and **offline update** all work without Internet outside Iran.
- Package the necessary distro-signed local OS packages when required. Check exact ABI/library/kernel/TUN/systemd/capability versions; do not pretend one arbitrary .deb works for every Debian/Ubuntu release.
- An incompatible kernel/OS/architecture, missing local package, signature failure or foreign service conflict is an actionable error **before changing host networking**. No silent APT install and no trust downgrade.
- A network-free install test must detect even accidental external HTTP/DNS resolution attempted by a script.

A bundle may support additional optional cores **only when tested and intentionally supplied**. Missing optional cores do not block a supported sing-box installation.

## 3. Trust and lifecycle

- Release references immutable version, artifact digest, upstream sing-box version/identity, support matrix and generated provenance. Authenticate **manager release** and **third-party binary** separately.
- A same-bundle checksum provides integrity against accidental corruption, **not trusted publisher identity**. The operator obtains a trustworthy signature/public key or signed digest through an independent trusted channel before privileged execution. Keep installation guidance usable in offline conditions.
- Protect private staging from other local users, refuse unsafe symbolic links/file ownership, validate archive entries and reject path traversal. Treat executable shell code as trusted only after provenance review; running ./install.sh is already privileged execution.
- Verify all required bytes/config/schema and local preconditions first; stage replacements; preserve existing profiles/secrets and unowned host state; activate binaries only after validation, with an independently available rollback/recovery path.
- Installation should produce a clear inventory of owned files and units. No mandatory new public port or always-on management API.
- Ordinary uninstall removes owned executable/service/network resources but **preserves operator profile material** by default; destructive purge is separately confirmed.
- An offline package update uses the same verified local-bundle path and never silently replaces unrelated applications or network controls. A failed update must leave a usable prior version or explicit recoverable state.
- Default after first install: **Direct**, no active TUN/host-wide routing takeover.

## 4. Versioned compatibility and honest support

The implementation must publish a table of supported distro release, architecture, kernel/network primitives, package prerequisites and file formats, derived from **tested** packaged artifacts. Before this exists, do not advertise Debian/Ubuntu versions, protocol combinations or CPU memory requirements as production-compatible.

Package and security claims require the tested, exact-artifact evidence defined by [ACCEPTANCE.md](ACCEPTANCE.md); no external private contract is required to implement or validate the offline installer.

## 5. Failure states and safe assistance

Errors must report the stage, failed requirement, exact local corrective step and whether host state changed. If offline prerequisite is absent, instruct the user which trusted file to download **on another machine** and where to place it. Never ask the disconnected host to curl the missing file.

If a new sing-box version changes config schema, migration must be explicitly tested against stored profiles. Keep old readable state and rollback boundaries; unsupported combinations are refused, not silently reinterpreted.
