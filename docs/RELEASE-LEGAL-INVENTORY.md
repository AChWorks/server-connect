# Release component, notice and source inventory

**Status: factual author audit, publication incomplete.** This document records
verified component identities, known packaging gaps and decisions still needed
before public distribution. It selects no product license, grants no legal
clearance and changes none of the [release acceptance](ACCEPTANCE.md),
[distribution](OFFLINE-DISTRIBUTION.md) or [host safety](SAFETY-RECOVERY.md)
requirements. Missing notices and source inventories are engineering work;
they are not all external approval blockers.

## Evidence scope

Repository inspection used integrated source
`79f4c7c5f95161d2da81b1959a4b272ce4a556dd` on 2026-11-07, including
`go.mod`, `go.sum`, vendor files, embedded data, `scripts/package.sh`
and the installer/acquisition allowlists.

The two inspected QA archives were built from
`6e1329df192c0d8c809dcba72b863ebc99030dc3` with Go 1.27.3.
They are not artifacts of the later integrated source or the pinned Go 1.27.1
CI build. The packager is byte-identical in both inspected source revisions:
SHA256 `9e02283e53a0ce81a0161ad0393547cfdd2d6a548fe63e7c7b42347e10f084e3`.
Its manifest still says `redistribution: not authorized; local QA only`.

| Inspected artifact | SHA256 |
| --- | --- |
| `server-connect-0.1.0-dev-debian12-amd64-local-qa.tar.gz` | `5a9e5be2dec3d5c08da981c82a571bb3feb9464252cdd7ad6dffed70921bd496` |
| `server-connect-0.1.0-dev-debian13-amd64-local-qa.tar.gz` | `82d82bc83766bb06f3b55776dceacecce4770d4374a1eb0217073e60548f9e05` |
| Official `sing-box-1.14.3-linux-amd64.tar.gz` | `e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee` |
| Extracted official `sing-box`, unchanged in both QA bundles | `768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93` |
| Official `libcronet.so`, unchanged in both QA bundles | `23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294` |

The [official v1.14.3 release metadata](https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.14.3)
agrees with the upstream archive digest. That archive contains only the
executable, `libcronet.so` and a short `LICENSE`. The inspected Server Connect
archives retain only `THIRD-PARTY-LICENSES/sing-box-LICENSE`; they contain no
separate full GPL text, native dependency notices or source-availability
instructions. This is an archive inventory, not a claim that every embedded
string or every transitive license has been audited.

## Components: present evidence and unresolved coverage

| Component | Verified evidence | Packaging or assessment gap |
| --- | --- | --- |
| Server Connect first-party code | No selected software license in the inspected repository; existing README and QA manifest retain that limitation | Owner must choose the first-party license and identify the applicable rights holder before public licensing claims. |
| Manager Go module | `go.mod` declares only `golang.org/x/net v0.36.0`; `go.sum` pins its module and go.mod hashes; `vendor/modules.txt` lists `publicsuffix` | This is the manager's dependency boundary, not an inventory of the bundled Core. |
| Go and x/net code | BSD text is retained in `vendor/golang.org/x/net/LICENSE`; upstream [x/net v0.36.0](https://github.com/golang/net/blob/v0.36.0/LICENSE), [Go 1.27.3](https://github.com/golang/go/blob/go1.27.3/LICENSE) and [Go 1.26.8](https://github.com/golang/go/blob/go1.26.8/LICENSE) require preservation of notices/conditions/disclaimer in binary-distribution materials | Those texts are absent from the inspected QA archives. Account for runtime/standard-library code as well as module dependencies. |
| sing-box 1.14.3 | Original GPL-3.0-or-later notice and naming/non-association condition preserved | The short notice is not the full GPL text. Corresponding Source and clear acquisition directions are not supplied by the current bundle. |
| Core Go dependencies | Official executable build information reports **140 dependency modules**, including cronet-go bindings and the native-library module | A version-pinned notice/source inventory for these actual dependencies has not been completed. Neither manager go.mod nor all entries in upstream go.sum alone proves the shipped set. |
| libcronet native code | Exact library bytes bind to the source chain below; Chromium/NaiveProxy source includes BSD binary-attribution terms | No corresponding native notices are present in the bundle. The complete native build dependency/license set remains unverified; the top-level BSD file is not evidence that all native components share one license. |
| Embedded DB-IP Lite October 2026 IR data | Snapshot and manager report attribution, CC-BY-4.0 identifier, original source/hash and the IR-extraction/CIDR conversion; repository README links the license | Preserve this existing credit and make attribution, changes and license URI clearly available with the distributed artifact. README is not currently bundled. |
| Generated Public Suffix List data | Vendored table pins revision `63cbc63d470d7b52c35266aa96c4c98c96ec499c`; its [source list header](https://github.com/publicsuffix/list/blob/63cbc63d470d7b52c35266aa96c4c98c96ec499c/public_suffix_list.dat) and [license](https://github.com/publicsuffix/list/blob/63cbc63d470d7b52c35266aa96c4c98c96ec499c/LICENSE) state MPL-2.0 | Review the generated-data notice/source treatment separately from the BSD Go implementation. This audit does not decide that legal classification or claim that the entire manager becomes MPL. |

[DB-IP's terms](https://db-ip.com/db/lite.php) identify CC BY 4.0 and attribution.
[CC BY 4.0 section 3](https://creativecommons.org/licenses/by/4.0/legalcode)
requires the applicable attribution information, indication of modifications
and the license text **or URI**. Do not invent a universal requirement to ship
the complete CC text when its permitted URI route is used.

## Exact Core and libcronet source chain

The official Core's build information records Go `1.26.8`, source revision
`7054cac5124465ffdb145870d7c01885566711b1`, `CGO_ENABLED=0`, and tags including
`with_purego` and `with_naive_outbound`.
Its [v1.14.3 go.mod](https://github.com/SagerNet/sing-box/blob/v1.14.3/go.mod)
and executable metadata agree on:

- cronet-go bindings and `all` module:
  `0d28acc44093df24b2526dea3d6ffefd6b0a54f0`;
- `cronet-go/lib/linux_amd64`:
  `c10c03c318db6d47bec8705c8290bad34bc32b64`;
- both cronet-go trees pin the
  [NaiveProxy submodule](https://api.github.com/repos/SagerNet/cronet-go/git/trees/c10c03c318db6d47bec8705c8290bad34bc32b64?recursive=1)
  to `72a06c9fca0e2d228588c7f3074bf7efff3ff686`;
  [.gitmodules](https://github.com/SagerNet/cronet-go/blob/0d28acc44093df24b2526dea3d6ffefd6b0a54f0/.gitmodules)
  identifies `SagerNet/naiveproxy`.

The inspected library has 11,915,768 bytes. Its Git blob digest,
`135430bbffc9fb76a7ef3d7bb5aa153e3781153e`, equals the
[lib/linux_amd64/libcronet.so tree entry](https://api.github.com/repos/SagerNet/cronet-go/git/trees/c10c03c318db6d47bec8705c8290bad34bc32b64?recursive=1).
The pinned NaiveProxy [CHROMIUM_VERSION](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/CHROMIUM_VERSION)
is `150.0.7871.63`.

Keep the licenses distinct:
[sing-box](https://github.com/SagerNet/sing-box/blob/v1.14.3/LICENSE) and
[cronet-go bindings](https://github.com/SagerNet/cronet-go/blob/0d28acc44093df24b2526dea3d6ffefd6b0a54f0/LICENSE)
carry GPL-3.0-or-later notices, while the native source's
[root LICENSE](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/LICENSE)
and [src/LICENSE](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/LICENSE)
contain Chromium BSD conditions. These top-level files do not replace a
native third-party inventory.

## Source distribution and legal boundary

[GPLv3 sections 1, 4 and 6](https://www.gnu.org/licenses/gpl-3.0.en.html)
define Corresponding Source, notice/license preservation and binary
distribution methods. Section 6(d) allows source on another server with clear
directions beside the binary and equivalent access; the distributor remains
responsible for availability. A three-year written offer belongs to specific
section 6 alternatives, not every download. A public tag URL alone does not
demonstrate a complete, available source set for this binary. Assess required
libraries and build inputs rather than assuming bundled libcronet is a System
Library.

Separate executables do not automatically force the first-party manager to
use GPL, nor automatically establish aggregation. [FSF guidance](https://www.gnu.org/licenses/gpl-faq.en.html#MereAggregation)
distinguishes independent aggregation from combined programs using both the
communication mechanism and its semantics. The manager's dependency list is
engineering evidence, not legal clearance of that boundary. Preserve the
upstream naming/non-association notice and do not imply upstream endorsement.

## Next coherent engineering package

This work can be prepared without selecting the product license or generating
a publisher key. It requires its own bounded implementation/review scope; no
partial notices payload was added by this documentation audit.

1. **Generate the exact executable inventory.** Verify each input SHA256, then
   read its Go build information with `go version -m` or Go's
   `debug/buildinfo`, without executing that binary. Record the main module,
   dependency versions, replacements, module sums, Go version, VCS identity
   and build tags. Cross-check against the
   [pinned Core go.sum](https://github.com/SagerNet/sing-box/blob/v1.14.3/go.sum).
   Resolve notices from the exact dependency sources and retain hashes.
   Handle modules whose license lives in a parent source tree explicitly;
   do not equate a missing module-local LICENSE with no obligations.
2. **Complete the native inventory.** Use the verified libcronet/source chain,
   exact platform/build configuration and GN/Ninja compile/link dependency
   graph to identify shipped native components and their notices/source
   requirements. Go metadata identifies the library module, not its C/C++
   contents. A scan can generate candidates, but no complete native notice
   generator or complete build closure has been verified in this audit.
3. **Prepare notice and source materials for review.** Assemble original
   license/notice texts, attribution and modification records, source
   revisions/hashes, build inputs/scripts and clear source-acquisition
   directions. Verify the source kit against the actual binary configuration.
   Publish no assumed license classification; retain unresolved entries.
   Runtime offline installation must remain free of dependency downloads;
   source delivery does not require building software on the target.
4. **Bind the completed payload to distribution integrity.** Include notice
   and source-manifest identities in the authenticated release metadata and
   checksum coverage, with the same immutable materials available through
   official, mirror and manual acquisition. Preserve independent publisher
   trust; a key supplied by an untrusted mirror does not authenticate itself.
5. **Update the shared packaging contract and test it.** Coordinate
   `scripts/package.sh`, `bundle/install.sh`,
   `scripts/bootstrap-online.sh`, `scripts/release-auth.py` and their
   package/provenance/update/uninstall fixtures: current exact allowlists
   contain only the sing-box notice. Require missing, altered, unexpected or
   wrongly signed notice/source-manifest cases to fail safely; verify
   install/update/rollback/uninstall ownership and source availability.
   Do not weaken exact artifact validation to accept an arbitrary directory.

Module inventory, source retrieval, factual notice collection, deterministic
packaging and tamper tests are ordinary engineering remediation. They can make
the final publication decision concrete. Unknown license applicability and
publication authority remain separately identified decisions.

## Explicit Owner decisions before publication

- **First-party license and rights:** which license will govern Server Connect,
  under which copyright holder, and are the relevant contribution rights
  established? This audit proposes none.
- **Unresolved component classification:** who will resolve the manager/Core
  combination boundary, generated PSL-data treatment and any native dependency
  ambiguities, and what determination is accepted? Engineering evidence must
  be supplied first; this document is not that determination.
- **Source-delivery responsibility:** which appropriate distribution method
  and maintained source location will the publisher support for the actual
  online/mirror/manual release? Do not promise an offer or retention obligation
  without an owner responsible for fulfilling it.
- **Publisher identity and trust:** what publisher identity and approved public
  key will operators verify through an
  independent channel, and who controls signing and trust changes? Ephemeral
  QA signatures establish neither an approved publisher nor release authority.
- **Final release authorization:** after the engineering package, product
  acceptance and separate HIGH_ASSURANCE review, is the exact authenticated
  artifact authorized for publication? Notice completeness alone does not
  resolve networking, recovery or support gates.
