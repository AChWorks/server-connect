# Distribution, installation and update

**Product requirements:** [PROJECT-SPEC.md](PROJECT-SPEC.md). This document owns the **package/trust and installation contract**; actual release identities, CI outcomes and installed-host evidence belong to GitHub and [ACCEPTANCE.md](ACCEPTANCE.md).

## One bundle and one installer

Publish one complete **versioned, target-specific, independently authenticated release bundle** for each supported OS/architecture. It includes the manager, pinned official sing-box binary and licenses, necessary local routing/Iranian IP-prefix data and other non-base runtime dependencies.

| How the operator gets the bundle | Required behavior |
| --- | --- |
| **Official online** | Trusted bootstrap retrieves an immutable authenticated official release and required verified prerequisites. |
| **Operator-hosted HTTPS mirror** | The operator uploads the **same immutable artifact and signed metadata** to a normal static website, including a host in Iran; a documented one-command bootstrap selects that URL, verifies **the publisher's** identity and installs it. |
| **Manual offline upload** | Operator obtains and independently verifies the complete bundle elsewhere, uploads/extracts it to a private local directory and runs one local command with **no network access or attempted downloads**. |

An official source, an Iranian mirror and an offline copy differ only in **acquisition**. All call the **same local installer** for preflight, staging, validation, install, update, rollback, uninstall and state preservation. No second installer, mirror-side daemon, per-source feature divergence or mandatory foreign-host fetch.

A mirror is an **untrusted byte host, not a signing authority**: even valid HTTPS or a checksum delivered alongside the archive cannot independently establish publisher identity. Verify a trusted publisher key/signed digest obtained through an independent channel **before privileged code executes**. Pin version/artifact/architecture; validate TLS, redirects, archive format and manifest. Never publish a `curl | sh` command that executes an unverified arbitrary mirror script.

**Current truth:** source includes developer offline packaging and an online bootstrap, but no authenticated public release, official/mirror one-liner, approved publisher key/licensing decision or accepted physical support matrix is available. Examples are **not** safe public installation instructions until those gates pass.

## Lifecycle and offline guarantees

- Check exact distro/kernel/architecture/ABI, systemd/TUN/network primitives, local dependency availability, package signatures and resource conflicts **before host-network activation**. Never claim arbitrary Debian/Ubuntu versions are supported without tests.
- **Offline acquisition/install/update and inactive first launch** must not attempt implicit DNS, HTTP(S), APT, GitHub or other network **dependency downloads**. Local profile/rule import, offline recovery, disable and uninstall must not fetch missing components either: supply all required runtime and rule data or fail with a concrete missing-file diagnostic. This is **not** a ban on an operator's later explicit **Connect**: contacting the selected VPN endpoint, its required bootstrap DNS and deliberate path-bound health probes is intentional VPN traffic, **not a packaging fetch**. Never use VPN activation as a pretext for implicit dependency acquisition.
- Verified online prerequisites may be acquired through the host's existing trusted OS package system. On the Debian 12/13 QA installation targets, the current root online bootstrap may install missing `curl`, Python 3 or CA certificates **before bundle acquisition**; those OS packages can remain if a later fetch/verification fails. `--verify-only` must never perform that mutation; offline install never uses APT. Do not claim a full host transaction rollback here.
- Treat downloaded archives and files as untrusted until verified: bound transfer and expansion size, metadata/parser cost, symlinks, traversal, nested paths, disk reserve and redirects. Use protected **root-owned private staging with trusted ancestry** for privileged work. Remove inherited untrusted loader/shell/proxy environment **before the interpreter starts**; script-body cleanup alone is too late.
- Installed profile IDs, secrets, selected rules and relevant operator state survive an ordinary verified update/reinstall; disabling/uninstalling removes precisely owned runtime/network resources. Default first installation is **Direct**. Purging private operator data is a separately authorized destructive action.
- Package and routing-list updates are separately validated, versioned and rollback-safe. A bad/old Iranian data feed must not force an untrusted online download or enable a silent foreign Direct leak. Do not rewrite system DNS or change APT repositories to make a mirror appear reachable.
- Existing pending/uncertain activation or guard-trial journal must be safely reconciled before replacing/removing its recovery executable. Ordinary install must not silently arm a production TUN or keep experimental timers running. The separately packaged health executor and timer are also inactive by default, included in bundle validation and unit-digest ownership checks, and covered by the same exact prior-unit backup/rollback and uninstall path. Active or uncertain health execution blocks installer mutation; installing a health unit never authorizes routing.

## Reproducible developer evidence

The **current QA-only** bundle is built by `scripts/package.sh` from an independently checked pinned sing-box archive; the shared installer is `install.sh`; the online development bootstrap is `scripts/bootstrap-online.sh`. Source and exact tests own concrete CLI flags, archive size limits and compatibility checks — do not maintain a second changing copy of them here.

The builder accepts exactly these target identities; omitting its optional target argument retains the Debian 13 default. Each artifact has its own target-specific filename and manifest, with the same installer and pinned upstream core.

| QA package target | Installed development evidence | Native Smart Routing acceptance boundary |
| --- | --- | --- |
| `debian-12-amd64` | Clean-source offline install, Direct/Proxy Only, retained profiles and exact network baseline | Experimental guarded native `connect-smart`, selected VLESS and recovery proved **only on an isolated disposable Incus VM** |
| `debian-13-amd64` | Clean-source offline install, Direct/Proxy Only, retained profiles and exact network baseline | Same isolated native QA lane, plus Core-crash, authenticated private SSH and manual route-exception witnesses |

After verifying payload ownership and checksums, the installer uses the bundled manager to bind a bounded, unambiguous manifest to the **actual** Debian version and native Linux/amd64 host. Opposite-version, missing, malformed, duplicate and unsupported targets fail before product state or service changes. This read-only check needs no Python dependency or host-version override. It is not publisher authentication or a general ABI/transport support claim. Recovery and inspection of existing native records retain their own ownership checks. Historic Docker-only and fixed-VM trial commands retain their separate environment constraints; the current native `connect-smart` tests on both Debian 12 and 13 do **not** grant general-host activation or production support.

### Installed development-release audit

A successful QA offline install retains the **complete checksum-covered bundle** (including `manifest.json`, `checksums.sha256`, managed service templates and original installer) in its selected `/opt/server-connect/releases/<id>/` directory. The release suffix derives from the digest of the **entire checksum manifest**, not just executable hashes: different source metadata or managed unit bytes cannot silently reuse the same installed identity. Existing pre-change development releases lack this metadata and remain supported as rollback/uninstall predecessors **only if their original binary-derived release-name digest and exact seven-entry historic owned layout match**. Absence of both modern metadata files is never, by itself, sufficient legacy evidence: an incomplete modern release with remaining unit/install files fails preflight before any service change, including on uninstall. Unrecognized or partially damaged legacy directories require controlled recovery, not implicit repair or deletion. Genuine legacy predecessors are **not** source-exact audit successes.

On an authorized installed QA host, inspect without changing networking:

```console
readlink /opt/server-connect/current
(cd /opt/server-connect/current && sha256sum --strict --quiet --check checksums.sha256)
cat /opt/server-connect/current/manifest.json
sha256sum /opt/server-connect/current/checksums.sha256
```

For a meaningful source/build claim, independently compare the installed checksum-manifest digest, manifest source revision/target and original pinned QA archive against the **externally recorded expected artifact identity**. A successful self-contained checksum audit proves only that the stored files agree with their local checksums: it is **not publisher authentication**, a public release signature, source reproducibility, validated network locality, production support or Smart Routing proof. Installed-host tests additionally compare package-provided identities and verify lifecycle/rollback. Corrupt checksum-bearing installed releases fail closed before reuse/uninstall; controlled recovery requires exact independently verified bytes. Private profiles and unrelated systemd/network resources are excluded from the public release snapshot.

Online `--verify-only` validates acquisition, digest, archive bounds and required layout only. It neither executes the bundled manager/core/installer nor proves target installability; a layout-valid archive for another target can pass this acquisition check and must still be refused by installation.

Relevant test entry points: `scripts/test_bootstrap_online.py`, `scripts/qa/test-package-targets.py`, `scripts/qa/test-installed-release-provenance.py`, `scripts/qa/test-online-minimal-host.sh`, `scripts/qa/test-installed-host.sh`, and `.github/workflows/installed-host-qa.yml`. CI's disconnected Docker/systemd tests and the separately recorded installed Debian 12/13 Incus VM QA are distinct evidence levels. Neither establishes official publisher authenticity, an Iranian public mirror, verified Iranian-origin/foreign-provider field paths or a stable release. The separately authorized real-host driver and its evidence limits are described in [Acceptance](ACCEPTANCE.md#existing-tests-and-their-limits).

A release must publish reproducible per-target archive identity, signature/public-key verification procedure, tested OS/arch and upstream versions, upstream license compliance, installation commands for **all three choices**, and matching user-visible update/uninstall instructions. See [release acceptance](ACCEPTANCE.md).
