# Distribution, installation, mirror and update

**Scope:** This owns the release package and acquisition contract. [PROJECT-SPEC.md](PROJECT-SPEC.md) owns product direction; [ACCEPTANCE.md](ACCEPTANCE.md) and GitHub Issues/PRs own actual release evidence.

## Status and supported platforms

**No public Stable release is published yet.** The commands below are the intended verified interface **after** Owner acceptance and publication; they are not currently working public download links. Never represent a generated LOCAL QA artifact as a Stable release. The first Stable support matrix is **Debian 12 amd64 and Debian 13 amd64 only**, with systemd and functional TUN/nftables. Explicit runtime acceptance is required on both systems.

All three methods use the **same target-specific, versioned, complete archive** and **same `bundle/install.sh` lifecycle implementation**. The bundle contains the Server Connect manager, official pinned sing-box 1.14.3, its required runtime library, all required systemd units and rule/data assets, an exact target/source manifest, `checksums.sha256`, first-party MPL-2.0 source license and the required third-party source/notice materials. The manager validates the actual host OS/architecture and pinned Core before mutations. Profiles and saved routing rules remain private and survive normal updates, uninstall policy and verified Direct/off recovery. Existing foreign services and kernel resources are never installer-owned by default.

**Trust model:** The operator explicitly trusts the selected HTTPS host (Official GitHub or its own private HTTPS mirror), or the separately obtained and manually uploaded local files for offline use. The archive's `.release.json` sidecar and per-file SHA256 checks enforce integrity and exact version/target/source identity; a digest supplied by the **same** host is **not independent publisher authentication**. There is **no required publisher signing key, detached signature, imported public key or manual version/architecture selector** for normal installation. The local signed QA verifier and retained signed receipts are optional for verifying historically signed installations only; they do not change the current trust model.

### Acquisition interfaces (only after first Stable is actually published)

**Official GitHub release channel (after publication):**

Download the **complete** bootstrap through HTTPS into a root-only temporary
file, verify the end marker and execute it only after a successful transfer.
GitHub HTTPS redirects are allowed; failures or partial transfers execute no
script. One pasteable command (the root-owned temporary file is removed on
every exit):

```sh
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -eu -c '
  umask 077
  bootstrap=$(mktemp /root/.server-connect-entry.XXXXXXXX)
  trap "rm -f -- $bootstrap" 0
  curl --fail --silent --show-error --location --max-redirs 5 \
    --proto "=https" --proto-redir "=https" \
    --output "$bootstrap" \
    https://github.com/AChWorks/server-connect/releases/latest/download/bootstrap-online.sh
  [ "$(tail -n 1 "$bootstrap")" = "# SERVER_CONNECT_BOOTSTRAP_END" ] || {
    echo "Incomplete bootstrap; execution refused" >&2; exit 1;
  }
  /bin/sh "$bootstrap" --official
'
```

**Operator-hosted HTTPS mirror (generic example; substitute a mirror you control):**

The bootstrap URL is derived from the *same selected mirror base* as its
release index and archives. **Even an HTTPS redirect is refused** for this
first executable download; it never silently falls back to GitHub or a foreign
host. A complete HTTPS transfer is required before any execution:

```sh
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -eu -c '
  umask 077
  bootstrap=$(mktemp /root/.server-connect-entry.XXXXXXXX)
  trap "rm -f -- $bootstrap" 0
  # curl --fail alone accepts 3xx without following it. Require HTTP 200
  # from the selected mirror before inspecting or executing any body.
  status=$(curl --fail --silent --show-error --proto "=https" \
    --write-out "%{http_code}" --output "$bootstrap" \
    "${1%/}/bootstrap-online.sh")
  [ "$status" = 200 ] || {
    echo "Mirror bootstrap HTTP status $status refused; no script executed" >&2; exit 1;
  }
  [ "$(tail -n 1 "$bootstrap")" = "# SERVER_CONNECT_BOOTSTRAP_END" ] || {
    echo "Incomplete bootstrap; execution refused" >&2; exit 1;
  }
  /bin/sh "$bootstrap" --mirror-base "$1"
' sc-bootstrap https://mirror.example/server-connect/
```

**Completely offline manual transfer:** On a different machine obtain the same verified release archive, its `*.release.json` sidecar and `bootstrap-online.sh` from the intended release, check the source and SHA256, then upload all three files into a trusted private directory on the disconnected host. No signing keys are needed. On that host:

```sh
sudo /bin/sh /root/sc-upload/bootstrap-online.sh \
  --archive-file /root/sc-upload/server-connect-<version>-<target>.tar.gz
```

The offline archive's identity file must exist at `<archive>.release.json`. The offline entrypoint performs **no DNS, HTTP, package download, APT or other network dependency request**, even if prerequisites are missing. Existing Debian system packages must supply the required native tooling; missing prerequisites produce actionable errors. For online installations only, missing fixed Debian prerequisites can be installed through the host's already trusted signed APT policy. A separate `--verify-only` option performs full acquisition/extraction checks but never installs packages or the product. Advanced explicit `--archive-url` and `--archive-file` are retained for controlled verification/QA. There is no GitHub fallback in mirror mode.

**Trust before execution:** Both online launchers stage complete root-owned bootstrap bytes, check a terminal completeness marker and execute only after a successful HTTPS download; no executable script is piped directly from curl. This protects against incomplete transfers, but the marker is **not** a publisher signature: the operator still trusts the selected HTTPS source. HTTPS validates the server's certificate. The bounded downloader permits HTTPS redirects for GitHub, refuses redirects for an operator Mirror (to keep all project assets on the selected mirror), and refuses plaintext except explicit loopback-only QA. The bootstrap validates the restricted release index, source/target/version, exact archive SHA256 and gzip/tar member layout **before executing any extracted script**; a second check binds metadata to the extracted package manifest and all checksummed members. The shared local installer repeats checksum, manager/Core, OS target, ownership and active guard preflights before changing units or releases. Symlinks/traversal/duplicate members, malformed JSON, unlisted files, decompression bombs, wrong target, modified data and partial downloads fail closed. Update and failed installation use narrowly owned state and rollback. On a first install the complete owner marker is staged before atomic no-replace publication of `/opt/server-connect`; root-private inode-bound intents under `/var/lib/server-connect/` identify the exact first prefix and release stage, including a partially copied release, its atomically reparented `.stage.*` path inside the original managed signed-receipt namespace, and the finally published release. On a retry, while holding the lifecycle lock, the installer verifies its full original file/service footprint and recovers exactly owned partial resources before a fresh install. Unexpected files, changed ownership/inodes, foreign services or active units are preserved and refused, never silently adopted or deleted. The intents are retired only after verified initial installation, and uncertain foreign network/kernel resources are preserved for operator recovery.

### Release index and mirrored bytes

`release-index.json` is a small HTTPS-served channel selector. It contains one version and **both** exact supported archive filenames and SHA256 digests. The bootstrap selects `debian-12-amd64` or `debian-13-amd64` from the real host identity; operators never select target versions by hand. For each target, the index points at a **relative immutable asset name** (no external/absolute URL):

```json
{"schema":1,"version":"<released-version>","artifacts":{"debian-12-amd64":{"archive":"<debian12-archive>.tar.gz","sha256":"<64hex>"},"debian-13-amd64":{"archive":"<debian13-archive>.tar.gz","sha256":"<64hex>"}}}
```

The source release ships `bootstrap-online.sh`, `release-index.json`, both archive files, and both corresponding `*.release.json` sidecars. Those are the **complete** project release acquisitions; sing-box and routing data are already inside each bundle. The index is a mutable channel pointer; archive filenames and bytes are immutable once published. `scripts/make-release-index.py --version <version> --dist-dir dist --output dist/release-index.json` validates both exact archives, their source revision and sidecars, and generates a local index without uploading/publishing anything. It refuses overwrite. This script does **not** grant release or redistribution approval.

### Initialize, synchronize and recover a generic HTTPS mirror

1. Create an operator-owned static HTTPS directory with normal least-privilege web permissions and **no writable CGI or public listing**. The operator provides that base URL to the target; the project source contains **no private host/domain/path**. Keep archive history in private mirror storage if useful, but expose the selected assets at the relative paths referenced by `release-index.json`.
2. On a trusted staging machine, obtain the exact official released `bootstrap-online.sh`, both **immutable** archives, both `.release.json` sidecars and the release index. Verify HTTPS and the per-target SHA256 against the official release before copying; check the index/source revision and target metadata. Do not regenerate modified binary archives or replace immutable filenames.
3. Upload the verified files as temporary non-public names, verify hashes again at destination, then **atomically publish the immutable files and sidecars first** and `release-index.json` **last**. This prevents new installations seeing an index for missing files. Never overwrite a live archive path with different bytes. A failed/partial sync must not change the current index.
4. From a disposable Debian 12 and Debian 13 target with GitHub and other foreign project-asset sources blocked, run the generic Mirror command. Verify that every project-asset request stays on the chosen mirror, APT (if needed) uses only configured trusted Debian repositories, and no runtime rule list/Core is fetched separately. Compare installed package and manifests to official bytes; test Direct/off, updates, stop/recovery and SSH preservation. Do not equate an untested prepared mirror directory with a published release.
5. To **roll back the mirror channel**, atomically restore the previously validated index only while retaining its original immutable archives and sidecars. Per-host installed release rollback is separately owned by the shared installer; changing the channel index does not immediately uninstall or downgrade any host.

### Packaging and third-party redistribution

`scripts/package.sh` creates two pinned-target **LOCAL QA** archives using an independently checksum-verified upstream official sing-box 1.14.3 archive and offline Go build. It checks release manifest and all source/licensing data. It currently labels artifacts `0.1.0-dev` and `redistribution: not authorized; local QA only`. **No Stable binaries may be publicly published from that QA state**. Produce and run an exact candidate through Independent Review and complete legal/licensing and installed-host/field gates before version promotion and public release.

The first-party license is **MPL-2.0**. Preserve distinct third-party obligations:

- **sing-box**: its exact pinned upstream binary/library, license and associated redistribution/source obligations.
- **golang.org/x/net/publicsuffix**: BSD-3-Clause Go dependency notice plus the embedded MPL-2.0 Public Suffix List snapshot, matching pinned upstream publicsuffix revision `63cbc63d470d7b52c35266aa96c4c98c96ec499c`, exact source list and MPL notice.
- **Chocolate4U/Iran-sing-box-rules**: pinned source/derived geoip material and GPL-3.0 notice; check the original data/source terms and copyleft/source availability before publication. Do not assume bundled GPL notice alone settles redistribution compliance.
- **DB-IP Country Lite**: CC BY 4.0 source attribution, original source digest, modified October 2026 Iranian-prefix snapshot and transformation disclosure. The package includes `THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt` and `dbip-iran-prefixes.json`.

The packager pins the source/data digests and new bundles cannot omit these materials. Historical installed releases may retain their exact older (verified) layouts for safe audit/removal, but older incomplete packages must not be newly imported as first-Stable inputs. No publisher signature requirement supersedes or removes these redistribution responsibilities.

**Release and acceptance gates:** Author-separated high-assurance review of the exact candidate, actual Debian 12/13 installed acquisition/update/offline/no-network evidence, new-SSH confirmation/600-second rollback/reboot/crash and foreign-owner preservation, real selected-provider path/physical host evidence where required, no unresolved legal redistribution blockers, explicit Owner publication approval. See [ACCEPTANCE.md](ACCEPTANCE.md) and [Issue #5](https://github.com/AChWorks/server-connect/issues/5). Do not publish from a generic mirror or advertise a placeholder release before these gates pass.
