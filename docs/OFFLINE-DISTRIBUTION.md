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

**Current truth:** source includes shared signed acquisition and local QA signing fixtures, but no authenticated public release, approved publisher key/licensing decision, official installation URL or accepted physical support matrix is available. Examples are **not** safe public installation instructions until those gates pass.

## Authenticated acquisition interface

The trusted entrypoint and its adjacent authentication helper must themselves
arrive through an independently authenticated channel. A script or public key
downloaded from the same untrusted mirror as an archive does not supply that
trust. For privileged use, place the trusted tools and public key under
protected root-owned ancestry and enter through a trusted launcher that clears
loader and shell startup variables before the interpreter starts. The bootstrap
never fetches a public key and never executes a downloaded verifier.

The archive has two detached siblings: `<archive>.release.json` and
`<archive>.sig`. The signature covers the exact bounded JSON bytes using
[OpenSSL SHA-256 signature verification](https://docs.openssl.org/3.0/man1/openssl-dgst/), with a public key supplied by the
operator. Duplicate/extra JSON fields, noncanonical identities, an unclean
source revision, a different version/target or a different pinned Core are
rejected. The signed identity binds the complete archive digest, full checksum
manifest digest, package manifest digest, manager version, exact source revision,
source state, target and upstream Core identity. It is never interpreted as
shell code.

All three acquisition paths authenticate the archive before extraction. The
same bounded extractor rejects links, traversal, duplicates, special files,
decompression abuse and a missing/corrupt gzip trailer. After extraction the
trusted helper checks that the actual package manifest and every covered file
match the signed identity before any bundle executable can run. The same
installer then rechecks authentication, ownership and actual-host target
admission before lifecycle changes. There is no CLI acknowledgement that
substitutes for a signature. A verified signature proves control of the
independently supplied key; it does not choose the Owner's publisher identity,
license, key rotation/revocation policy or production promotion decision.

For an already trusted tool directory and independently installed public key,
the interface for an authorized signed QA artifact is:

```console
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/trusted-sc-tools/bootstrap-online.sh \
  --archive-url https://mirror.example/immutable/bundle.tar.gz \
  --publisher-key /root/sc-trust/publisher.pem \
  --version 0.1.0-dev --target debian-13-amd64 --verify-only
```

Official and operator mirror URLs use exactly this path and the same immutable
archive/metadata/signature bytes. The URL above is a placeholder, not an
available official channel. HTTPS redirects remain HTTPS; plain HTTP is limited
to loopback and requires explicit `--local-qa` for disposable tests.
The bootstrap appends the sidecar suffixes to the URL path, preserving its
query, and applies separate bounded transfers. Operators may instead supply
both `--metadata-file` and `--signature-file` from local storage.

The fully offline acquisition interface uses those same bytes:

```console
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh /root/trusted-sc-tools/bootstrap-online.sh \
  --archive-file /root/incoming/bundle.tar.gz \
  --publisher-key /root/sc-trust/publisher.pem \
  --version 0.1.0-dev --target debian-13-amd64 --verify-only
```

The sibling metadata/signature files are read locally; no DNS, downloader, APT
or other dependency fetch is attempted. Omitting `--verify-only` runs the
shared installer after the same checks. Signed verification uses trusted Python 3 and OpenSSL. Online installation can
acquire missing native prerequisites through the existing verified Debian APT
policy, while offline mode requires them to be preinstalled and refuses clearly
when they are missing. Supplying an
authenticated verifier/prerequisite set for a completely minimal disconnected
Debian target remains a release packaging gate. An offline transfer of bytes
authenticated elsewhere remains legitimate authenticated manual acquisition;
it must preserve the verified identity and trusted staging through execution,
and must not rely on an unverified extracted script to authenticate itself.

`scripts/package.sh` produces the archive and unsigned identity sidecar.
It refuses to overwrite a sibling signature, preserving signed artifact
immutability. Its manifest still declares **LOCAL QA ONLY**. For isolated
cryptographic tests, `scripts/release-auth.py sign-local-qa` accepts an
explicit ephemeral private key, exact archive/metadata paths and version/target
pins; it generates no key, never replaces an existing signature and grants no
redistribution permission. Production signing identity, approved product license,
third-party redistribution compliance and immutable publication remain blocked.
No private key belongs in source, CI output or release assets.

A signed installation persists `authentication.json` as root-owned mode 0600
inside the exact immutable installed release. It contains the signed identity,
signature and canonical **public** key plus its SHA-256 SPKI fingerprint. The
key comes from the independently supplied input after successful verification;
the archive cannot carry a trust receipt, and an incoming bundle cannot borrow
authority merely by placing a key beside itself. File and directory fsyncs
precede release publication; the parent rename is fsynced before selection.
Retries re-establish durability even when a failed write left readable bytes.

Later signed preflight, update, rollback and uninstall revalidate the receipt's
strict schema, protected ownership, exact release binding, signature, key
fingerprint and payload. Missing, mixed, tampered or cross-release receipts
fail closed before lifecycle mutation. The installer retains the previous
release's receipt on update/rollback and removes only validated owned receipts
during cleanup. No signature/key downloads are needed to inspect or remove an
installed signed release after acquisition staging has disappeared.

For an already authenticated installed release, canonical offline uninstall is:

```console
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/sh "$(/usr/bin/readlink -f /opt/server-connect/current/install.sh)" --uninstall
```

A fresh incoming update still supplies its own signed metadata/signature and
an independent trust anchor through the trusted bootstrap. Reusing an existing
installed identity requires the same receipt; implicit key replacement or
promotion of an unsigned installation is refused. Deliberate key rotation and
trust recovery remain separate Owner-controlled procedures.

New unsigned QA installations instead retain an explicit `local-qa.sha256`
marker bound to the full checksum manifest. They still require `--local-qa`;
absence of a signed receipt never authorizes unsigned fallback. Previous
12-entry development releases retain their earlier verified rollback/uninstall
format and are never relabelled as publisher-authenticated.

Unsigned development use is deliberately explicit:
`bootstrap-online.sh --local-qa --sha256 TRUSTED_DIGEST ...` and the
already independently inspected local bundle's
`install.sh --offline --local-qa` (similarly for verify-only/uninstall).
These commands cannot report publisher authentication. Existing QA workflows
use these flags; passing a local-QA flag alongside signed inputs never suppresses
a bad signature.

## Lifecycle and offline guarantees

- Check exact distro/kernel/architecture/ABI, systemd/TUN/network primitives, local dependency availability, package signatures and resource conflicts **before host-network activation**. Never claim arbitrary Debian/Ubuntu versions are supported without tests.
- **Offline acquisition/install/update and inactive first launch** must not attempt implicit DNS, HTTP(S), APT, GitHub or other network **dependency downloads**. Local profile/rule import, offline recovery, disable and uninstall must not fetch missing components either: supply all required runtime and rule data or fail with a concrete missing-file diagnostic. This is **not** a ban on an operator's later explicit **Connect**: contacting the selected VPN endpoint, its required bootstrap DNS and deliberate path-bound health probes is intentional VPN traffic, **not a packaging fetch**. Never use VPN activation as a pretext for implicit dependency acquisition.
- Verified online prerequisites may be acquired through the host's existing trusted OS package system. On the Debian 12/13 QA installation targets, the current root online bootstrap may install missing `curl`, Python 3, OpenSSL (for signed acquisition) or CA certificates **before bundle acquisition**; those OS packages can remain if a later fetch/verification fails. `--verify-only` must never perform that mutation; offline install never uses APT. Do not claim a full host transaction rollback here.
- Treat downloaded archives and files as untrusted until verified: bound transfer and expansion size, metadata/parser cost, symlinks, traversal, nested paths, disk reserve and redirects. Use protected **root-owned private staging with trusted ancestry** for privileged work. Remove inherited untrusted loader/shell/proxy environment **before the interpreter starts**; script-body cleanup alone is too late.
- Installed profile IDs, secrets, selected rules and relevant operator state survive an ordinary verified update/reinstall; disabling/uninstalling removes precisely owned runtime/network resources. Default first installation is **Direct**. Purging private operator data is a separately authorized destructive action.
- Package and routing-list updates are separately validated, versioned and rollback-safe. A bad/old Iranian data feed must not force an untrusted online download or enable a silent foreign Direct leak. Do not rewrite system DNS or change APT repositories to make a mirror appear reachable.
- Existing pending/uncertain activation or guard-trial journal must be safely reconciled before replacing/removing its recovery executable. Ordinary install must not silently arm a production TUN or keep experimental timers running. The separately packaged health executor and timer are also inactive by default, included in bundle validation and unit-digest ownership checks, and covered by the same exact prior-unit backup/rollback and uninstall path. Active or uncertain health execution blocks installer mutation; installing a health unit never authorizes routing.

## Reproducible developer evidence

The **current QA-only** bundle is built by `scripts/package.sh` from an independently checked pinned sing-box archive; the shared installer is `bundle/install.sh`; the trusted acquisition entrypoint is `scripts/bootstrap-online.sh` with the adjacent `scripts/release-auth.py`. The interface examples above describe trusted acquisition; source and exact tests own byte limits and detailed compatibility checks.

The builder accepts exactly these target identities; omitting its optional target argument retains the Debian 13 default. Each artifact has its own target-specific filename and manifest, with the same installer and pinned upstream core.

| QA package target | Installation scope | New native trial admission |
| --- | --- | --- |
| `debian-12-amd64` | Direct/Proxy Only lifecycle on Debian 12 with systemd | Rejected before fixture, profile or host-policy mutation |
| `debian-13-amd64` | Direct/Proxy Only lifecycle on Debian 13 with systemd | Still restricted to the existing disconnected disposable Docker fixture |

After verifying payload ownership and checksums, the installer uses the bundled manager to bind a bounded, unambiguous manifest to the **actual** Debian version and native Linux/amd64 host. Opposite-version, missing, malformed, duplicate and unsupported targets fail before product state or service changes. This read-only check needs no Python dependency or host-version override. It is not publisher authentication or a general ABI/transport support claim. Recovery and inspection of existing native records retain their own ownership checks; the additional Debian 13 restriction applies to new trial activation.

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

Acquisition `--verify-only` never executes the bundled manager/core/installer and does not prove actual-host installability. In signed mode it verifies the exact version and target pins, signature, archive digest, strict layout, manifest/source/Core binding and every checksum-covered payload byte. Explicit unsigned `--local-qa --sha256` retains the narrower digest/layout-only behavior; a different-target QA archive can pass that check and must still be refused by the shared installer.

Relevant test entry points: `scripts/test_bootstrap_online.py` (real ephemeral signatures and offline Linux syscall isolation), `scripts/qa/test-package-targets.py`, `scripts/qa/test-installed-release-provenance.py`, `scripts/qa/test-online-minimal-host.sh`, `scripts/qa/test-installed-host.sh`, and `.github/workflows/installed-host-qa.yml`. The disconnected QA uses Docker/systemd and a local loopback test source; it does **not** establish official publisher authenticity, an Iranian public mirror, field-host access or a stable release. The separately authorized real-host driver and its evidence limits are described in [Acceptance](ACCEPTANCE.md#existing-tests-and-their-limits).

A release must publish reproducible per-target archive identity, signature/public-key verification procedure, tested OS/arch and upstream versions, upstream license compliance, installation commands for **all three choices**, and matching user-visible update/uninstall instructions. See [release acceptance](ACCEPTANCE.md).
