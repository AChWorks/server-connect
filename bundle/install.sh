#!/bin/sh
# Server Connect local installer: no curl, wget, APT or host route modification.
set -eu
umask 077
# A trusted sudo + env -i launcher must clear startup/loader variables
# BEFORE the shell starts. This reset is defense in depth for descendants;
# it cannot repair an already compromised privilege-entry interpreter.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_ORIGIN_PATH
unset PYTHONPATH PYTHONHOME CDPATH

PREFIX=/opt/server-connect
STATE=/var/lib/server-connect
UNIT=/etc/systemd/system/server-connect.service
COMMAND=/usr/local/bin/server-connect
GUARD_SERVICE=/etc/systemd/system/server-connect-activation-recover.service
GUARD_TIMER=/etc/systemd/system/server-connect-activation-recover.timer
SOURCE_DIR=$(dirname -- "$0")
ACTION=${1:---offline}
[ "$#" -eq 0 ] || shift
local_qa=no
retained_auth=no
unsigned_release=no
abandon_incomplete=no
publisher_key=''
metadata_file=''
signature_file=''
pinned_version=''
pinned_target=''

say() { printf 'Server Connect: %s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required host tool: $1"; }
check_dir() { [ -d "$1" ] && [ ! -L "$1" ] || die "unsafe or missing directory: $1"; }
check_root_file() {
 [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u' "$1")" = 0 ] || die "missing or non-root-owned regular file: $1"
 mode=$(stat -c '%a' "$1")
 [ "$((0$mode & 022))" -eq 0 ] || die "unsafe writable file permissions: $1"
}
check_root_dir() {
 check_dir "$1"
 [ "$(stat -c '%u' "$1")" = 0 ] || die "non-root-owned directory: $1"
 mode=$(stat -c '%a' "$1")
 [ "$((0$mode & 022))" -eq 0 ] || die "unsafe writable directory: $1"
}
require_root() { [ "$(id -u)" -eq 0 ] || die 'run as root with sudo'; }
# An installed release retains the same complete, independently inspected
# payload and checksum manifest as its input archive. This is local byte
# integrity, never a publisher signature or a host-routing admission token.
release_payload_files() {
 cat <<'RELEASE_FILES'
bin/server-connect
bin/sing-box
bin/libcronet.so
server-connect.service
server-connect-activation-recover.service
server-connect-activation-recover.timer
server-connect-native-tun.service
server-connect-smart-health.service
server-connect-smart-health.timer
install.sh
RELEASE_FILES
 # Preserve exact previously installed 12/13/14/15-entry QA layouts for
 # verified update, rollback and uninstall. Newly staged releases include the
 # MPL-covered PSL source and its license; a partial pair is never admitted.
 if [ -e "$1/release-auth.py" ] || [ -L "$1/release-auth.py" ]; then
  printf '%s\n' release-auth.py
 fi
 # Older verified installed releases predate the first-party MPL notice;
 # newer incoming releases require it in their complete payload.
 if [ -e "$1/LICENSE" ] || [ -L "$1/LICENSE" ]; then
  printf '%s\n' LICENSE
 fi
 printf '%s\n' THIRD-PARTY-LICENSES/sing-box-LICENSE
 if [ -e "$1/THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE" ]; then
  printf '%s\n' THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE
 fi
 if [ -e "$1/THIRD-PARTY-LICENSES/publicsuffix-LICENSE" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/publicsuffix-LICENSE" ] ||
    [ -e "$1/THIRD-PARTY-LICENSES/publicsuffix-list.dat" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/publicsuffix-list.dat" ]; then
  printf '%s\n' THIRD-PARTY-LICENSES/publicsuffix-LICENSE
  printf '%s\n' THIRD-PARTY-LICENSES/publicsuffix-list.dat
 fi
 # Preserve verified historic installations without these files. Any
 # upgraded/current release must include the Chocolate4U data/license pair;
 # a partial pair is never admitted as a valid release.
 if [ -e "$1/THIRD-PARTY-LICENSES/chocolate4u-LICENSE" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/chocolate4u-LICENSE" ] ||
    [ -e "$1/THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json" ]; then
  printf '%s\n' THIRD-PARTY-LICENSES/chocolate4u-LICENSE
  printf '%s\n' THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json
 fi
 # Historical verified bundles had embedded DB-IP data but no separate
 # attribution/source pair. Preserve their installed removal/update, but
 # reject partially present pair members in any installed layout.
 if [ -e "$1/THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt" ] ||
    [ -e "$1/THIRD-PARTY-LICENSES/dbip-iran-prefixes.json" ] ||
    [ -L "$1/THIRD-PARTY-LICENSES/dbip-iran-prefixes.json" ]; then
  printf '%s\n' THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt
  printf '%s\n' THIRD-PARTY-LICENSES/dbip-iran-prefixes.json
 fi
 printf '%s\n' manifest.json
}
verify_release_payload() (
 root=$1
 prior_installed=no
 if [ "$#" -eq 2 ]; then prior_installed=$2; fi
 check_root_dir "$root"
 check_root_dir "$root/bin"
 check_root_dir "$root/THIRD-PARTY-LICENSES"

 check_root_file "$root/checksums.sha256"
 # New archive inputs always have a complete source-verified package layout.
 # An installed 12/13/14/15-entry release can be verified under its old
 # immutable manifest; incoming packages must contain both PSL materials.
 if [ "$prior_installed" = no ]; then
  # Publisher verification is optional for a new official, mirror or
  # offline bundle; source trust is the selected HTTPS host/uploaded source.
  # A previous signed QA bundle may retain its helper and signed receipt.
  check_root_file "$root/LICENSE" ||
   die 'incoming release must contain first-party MPL-2.0 license'
  check_root_file "$root/THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE" ||
   die 'incoming release must contain x/net third-party license notice'
  check_root_file "$root/THIRD-PARTY-LICENSES/publicsuffix-LICENSE" ||
   die 'incoming release must contain Public Suffix List license'
  check_root_file "$root/THIRD-PARTY-LICENSES/publicsuffix-list.dat" ||
   die 'incoming release must contain Public Suffix List source'
  check_root_file "$root/THIRD-PARTY-LICENSES/chocolate4u-LICENSE" ||
   die 'incoming release must contain Chocolate4U source license'
  check_root_file "$root/THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json" ||
   die 'incoming release must contain pinned Chocolate4U source data'
  check_root_file "$root/THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt" ||
   die 'incoming release must contain DB-IP Lite attribution'
  check_root_file "$root/THIRD-PARTY-LICENSES/dbip-iran-prefixes.json" ||
   die 'incoming release must contain pinned DB-IP Lite modified data'
 fi
 expected=$(release_payload_files "$root")
 if [ "$prior_installed" = yes ] && [ "$(wc -l < "$root/checksums.sha256")" -eq 12 ]; then
  [ ! -e "$root/release-auth.py" ] && [ ! -L "$root/release-auth.py" ] ||
   die 'signed-aware release cannot use historic checksum manifest'
  expected=$(release_payload_files "$root" | sed '/^server-connect-native-tun.service$/d')
 fi
 for path in $expected; do
  check_root_file "$root/$path"
 done
 actual=$(sed -n 's/^[0-9a-f]\{64\}  //p' "$root/checksums.sha256") ||
  die 'cannot read release checksum manifest'
 [ "$expected" = "$actual" ] &&
 [ "$(wc -l < "$root/checksums.sha256")" -eq "$(printf '%s\n' "$expected" | wc -l)" ] ||
  die 'release checksum manifest does not cover the exact owned payload'
 (cd "$root" && sha256sum --strict --quiet -c checksums.sha256) ||
  die 'release checksum mismatch; no mutation permitted'
)
# New-format installed releases always record their trust policy separately
# from the immutable archive payload. Missing signed data cannot silently be
# reclassified as unsigned. Historic 12-entry releases retain their old rules.
release_trust_file() (
 root=$1
 if [ ! -e "$root/release-auth.py" ] && [ ! -L "$root/release-auth.py" ]; then return 0;fi
 if [ -e "$root/authentication.json" ] || [ -L "$root/authentication.json" ]; then
  [ ! -e "$root/local-qa.sha256" ] && [ ! -L "$root/local-qa.sha256" ] &&
  [ ! -e "$root/integrity.sha256" ] && [ ! -L "$root/integrity.sha256" ] ||
   die 'conflicting signed and integrity installation receipts'
  printf '%s\n' authentication.json
 elif [ -e "$root/local-qa.sha256" ] || [ -L "$root/local-qa.sha256" ]; then
  [ ! -e "$root/integrity.sha256" ] && [ ! -L "$root/integrity.sha256" ] ||
   die 'conflicting local QA and integrity receipts'
  printf '%s\n' local-qa.sha256
 else
  [ -e "$root/integrity.sha256" ] || [ -L "$root/integrity.sha256" ] ||
   die 'installed release integrity receipt is missing'
  printf '%s\n' integrity.sha256
 fi
)
verify_release_trust() (
 root=$1
 receipt=$(release_trust_file "$root") || exit 1
 [ -n "$receipt" ] || return 0
 check_root_file "$root/$receipt"
 [ "$(stat -c '%a:%h' "$root/$receipt")" = 600:1 ] ||
  die 'installed trust receipt is not private and singly owned'
 if [ "$receipt" = authentication.json ]; then
  need python3;need openssl
  python3 -I -S "$root/release-auth.py" verify-installed --bundle "$root" >/dev/null ||
   die 'installed publisher authentication receipt is invalid'
 else
  [ "$(wc -c < "$root/$receipt")" -eq 65 ] &&
   [ "$(cat "$root/$receipt")" = "$(sha256sum "$root/checksums.sha256" | cut -d' ' -f1)" ] ||
   die 'installed integrity receipt does not match the immutable release'
 fi
)
write_release_trust() (
 root=$1
 if [ "$local_qa" = yes ] || [ "${unsigned_release:-no}" = yes ]; then
  [ ! -e "$root/authentication.json" ] && [ ! -L "$root/authentication.json" ] ||
   die 'cannot replace a signed receipt with unsigned state'
  if [ "$local_qa" = yes ]; then receipt=local-qa.sha256;else receipt=integrity.sha256;fi
  [ ! -e "$root/local-qa.sha256" ] && [ ! -L "$root/local-qa.sha256" ] &&
  [ ! -e "$root/integrity.sha256" ] && [ ! -L "$root/integrity.sha256" ] ||
   die 'cannot overwrite an existing integrity receipt'
  (set -C; sha256sum "$root/checksums.sha256" | cut -d' ' -f1 > "$root/$receipt") ||
   die 'cannot create immutable release integrity receipt'
  chmod 0600 "$root/$receipt" || die 'cannot protect integrity receipt'
 else
  [ "$retained_auth" = no ] || die 'unexpected new stage from a retained installed source'
  python3 -I -S "$root/release-auth.py" install-receipt \
   --metadata "$metadata_file" --signature "$signature_file" \
   --publisher-key "$publisher_key" --version "$pinned_version" \
   --target "$pinned_target" --bundle "$root" ||
   die 'cannot persist authenticated installation receipt'
 fi
)
# A missing modern manifest is NOT evidence of a legacy release. The old
# installer used only four payload files, a .owner marker and an ID derived
# from the manager/core binary digests. Admit exactly that format.
verify_installed_release() (
 root=$1
 name=$(basename -- "$root") || die 'installed release name unreadable'
 case "$name" in 0.1.0-dev-*) ;; *) die 'invalid installed release name' ;; esac
 suffix=$(printf '%s' "$name" | sed 's/^0.1.0-dev-//')
 case "$suffix" in ''|*[!0123456789abcdef]*) die 'invalid installed release digest' ;; esac
 [ "$(printf '%s' "$suffix" | wc -c)" -eq 16 ] ||
  die 'invalid installed release digest length'
 check_root_dir "$root"
 check_root_file "$root/.owner"
 [ "$(cat "$root/.owner")" = 'AChWorks/server-connect' ] ||
  die 'installed release owner conflict'
 if [ -e "$root/checksums.sha256" ] || [ -L "$root/checksums.sha256" ] ||
    [ -e "$root/manifest.json" ] || [ -L "$root/manifest.json" ]; then
  verify_release_payload "$root" yes || die 'installed release checksum conflict'
  full_identity=$(sha256sum "$root/checksums.sha256" | cut -c 1-16) ||
   die 'installed release checksum identity unreadable'
  [ "$full_identity" = "$suffix" ] || die 'installed release full identity changed'
  verify_release_trust "$root"
 else
  check_root_dir "$root/bin"
  check_root_dir "$root/THIRD-PARTY-LICENSES"
  for path in bin/server-connect bin/sing-box bin/libcronet.so THIRD-PARTY-LICENSES/sing-box-LICENSE; do
   check_root_file "$root/$path"
  done
  # The historic release has exactly seven entries: two directories,
  # four payload files and the owner marker. Any additional entry means
  # it cannot be safely classified as the old format.
  legacy_entries=$(find "$root" -mindepth 1 -printf . | wc -c) ||
   die 'legacy release inventory unavailable'
  [ "$legacy_entries" -eq 7 ] || die 'unrecognized legacy release layout'
  legacy_identity=$(
   cd "$root" &&
   sha256sum bin/server-connect bin/sing-box |
    cut -d' ' -f1 | sha256sum | cut -c 1-16
  ) || die 'legacy release identity unreadable'
  [ "$legacy_identity" = "$suffix" ] ||
   die 'unrecognized legacy release binary identity'
 fi
)
# Never canonicalize away a symlinked or replaceable source ancestor.
# Every component is inspected from / outward, before referencing any
# payload binary or modifying installed services. A trusted, root-owned,
# non-group/other-writable chain cannot be renamed by unprivileged users.
check_source_ancestry() {
 case "$0" in /*) ;; *) die 'invoke the staged installer by its absolute trusted path' ;; esac
 case "$0" in *'//'*|*'/./'*|*'/../'*|*'/.'|*'/..') die 'non-canonical installer source path' ;; esac
 check_root_dir /
 rest=${SOURCE_DIR#/}
 current=''
 while [ -n "$rest" ]; do
  part=${rest%%/*}
  [ -n "$part" ] && [ "$part" != . ] && [ "$part" != .. ] ||
   die 'untrusted installer source path component'
  current=$current/$part
  check_root_dir "$current"
  case "$rest" in */*) rest=${rest#*/} ;; *) rest='' ;; esac
 done
 [ "$(readlink -f -- "$0")" = "$0" ] || die 'installer path contains a symlink or alias'
}
check_platform() {
 [ "$(uname -m)" = x86_64 ] || die 'unsupported CPU; this candidate supports only x86_64'
 # Distro/target admission belongs to the verified manager in verify_payload,
 # after ownership/checksums; its bounded OS-identity parser never sources shell.
 need systemctl; need sha256sum; need install; need mktemp; need readlink; need cmp; need mv; need tar; need stat; need flock; need find; need basename
 [ -d /run/systemd/system ] || die 'systemd is not PID 1; use a supported systemd host'
}
verify_payload() {
 check_root_dir "$(dirname -- "$SOURCE_DIR")"
 verify_release_payload "$SOURCE_DIR" >/dev/null || die 'bundle checksum mismatch; no changes applied'
 # The outer trusted bootstrap authenticates the archive before executing
 # this installer. Repeat the same signature and full payload binding here
 # before any bundled executable or installed-service observation.
 if [ "$local_qa" = yes ]; then
  say 'LOCAL QA ONLY: publisher authentication was not requested'
 elif [ "${unsigned_release:-no}" = yes ]; then
  say 'Checksum-verified bundle; publisher authentication is not claimed (trust the chosen HTTPS host or uploaded source)'
 elif [ "$retained_auth" = yes ]; then
  # Only an already managed canonical installed release can reuse its
  # root-private trust store. No incoming bundle can supply an authority key.
  case "$SOURCE_DIR" in "$PREFIX"/releases/0.1.0-dev-*) ;; *) die 'incoming bundles require an independently supplied publisher key' ;; esac
  verify_installed_release "$SOURCE_DIR" || die 'installed source authentication is unavailable'
  [ "$(release_trust_file "$SOURCE_DIR")" = authentication.json ] ||
   die 'installed source is LOCAL QA; select --local-qa explicitly'
  say 'retained publisher authentication verified offline'
 else
  need python3; need openssl
  check_root_file "$SOURCE_DIR/release-auth.py"
  python3 -I -S "$SOURCE_DIR/release-auth.py" verify \
   --metadata "$metadata_file" --signature "$signature_file" \
   --publisher-key "$publisher_key" --version "$pinned_version" \
   --target "$pinned_target" --bundle "$SOURCE_DIR" ||
   die 'publisher authentication failed before candidate execution'
 fi
 # The same installer serves both target-specific bundles. The verified
 # manager reads the actual host identity; callers cannot override its OS.
 "$SOURCE_DIR/bin/server-connect" installer-check-target --manifest "$SOURCE_DIR/manifest.json" >/dev/null ||
  die 'bundle target does not match this supported host'
 version=$($SOURCE_DIR/bin/server-connect version --json) || die 'candidate manager fails version check'
 echo "$version" | grep -q '"sing_box":"1.14.3"' || die 'manager requires a different core version'
 core=$($SOURCE_DIR/bin/sing-box version 2>/dev/null | head -n 1) || die 'candidate sing-box not executable'
 [ "$core" = 'sing-box version 1.14.3' ] || die 'unexpected sing-box core version'
}
# A first-install claim is created inside the already root-only STATE and
# bound to the *directory inode* published at PREFIX. Never infer ownership
# from a familiar path or a freely copyable .owner text marker alone.
FIRST_INSTALL_INTENT=$STATE/.first-install-intent
first_install_read_intent() {
 first_stage=''
 first_inode=''
 first_trust=''
 [ -f "$FIRST_INSTALL_INTENT" ] && [ ! -L "$FIRST_INSTALL_INTENT" ] || return 1
 check_root_file "$FIRST_INSTALL_INTENT"
 [ "$(stat -c '%a:%h' "$FIRST_INSTALL_INTENT")" = 600:1 ] || return 1
 [ "$(wc -l < "$FIRST_INSTALL_INTENT")" -eq 3 ] || return 1
 first_stage=$(sed -n '1p' "$FIRST_INSTALL_INTENT")
 first_inode=$(sed -n '2p' "$FIRST_INSTALL_INTENT")
 first_trust=$(sed -n '3p' "$FIRST_INSTALL_INTENT")
 case "$first_stage" in /opt/.server-connect-initial.[a-zA-Z0-9]*) ;; *) return 1 ;; esac
 case "$first_inode" in ''|*[!0123456789:]*|:*|*:) return 1 ;; esac
 case "$first_trust" in
  unsigned|local-qa) ;;
  signed:*) printf '%s\n' "$first_trust" |
   grep -Eq '^signed(:[0-9a-f]{64}){3}$' || return 1 ;;
  *) return 1 ;;
 esac
 return 0
}
first_install_is_empty_owned_dir() {
 candidate=$1
 expected_inode=$2
 [ -d "$candidate" ] && [ ! -L "$candidate" ] || return 1
 check_root_dir "$candidate"
 [ "$(stat -c '%d:%i' "$candidate")" = "$expected_inode" ] || return 1
 check_root_file "$candidate/.owner"
 [ "$(cat "$candidate/.owner")" = 'AChWorks/server-connect' ] || return 1
 for child in "$candidate"/* "$candidate"/.[!.]* "$candidate"/..?*; do
  [ -e "$child" ] || [ -L "$child" ] || continue
  case "$child" in
   "$candidate/.owner") ;;
   "$candidate/releases")
    [ -d "$child" ] && [ ! -L "$child" ] || return 1
    for nested in "$child"/* "$child"/.[!.]* "$child"/..?*; do
     [ -e "$nested" ] || [ -L "$nested" ] || continue
     return 1
    done
    ;;
   *) return 1 ;;
  esac
 done
 return 0
}
first_install_claimed_prefix() {
 first_install_read_intent || return 1
 first_install_is_empty_owned_dir "$PREFIX" "$first_inode"
}
# Called only under the existing product lifecycle flock. The stage was
# never installed; its exact inode and empty file-set are required for cleanup.
first_install_reconcile_abandoned_stage() {
 [ -e "$FIRST_INSTALL_INTENT" ] || [ -L "$FIRST_INSTALL_INTENT" ] || return 0
 first_install_read_intent || die 'first-install claim invalid; preserve for console inspection'
 [ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] ||
  die 'first-install claim exists with unexpected installed prefix; preserve foreign resources'
 if [ -e "$first_stage" ] || [ -L "$first_stage" ];then
  first_install_is_empty_owned_dir "$first_stage" "$first_inode" ||
   die 'first-install staging identity changed; preserve for console inspection'
  rm -f -- "$first_stage/.owner" || die 'cannot remove verified empty initial stage owner'
  rmdir "$first_stage" || die 'cannot remove verified empty initial stage'
 fi
 rm -f -- "$FIRST_INSTALL_INTENT" || die 'cannot retire abandoned initial claim'
}
# Atomic no-replace publication avoids the two-hardlink gap: a SIGKILL
# between ln(temp, intent) and unlink(temp) previously left nlink=2 and an
# otherwise valid recovery receipt unreadable on the next installation.
first_install_noreplace() {
 python3 -I -S - "$1" "$2" <<'SC_FIRST_INSTALL_NOREPLACE'
import ctypes, errno, os, sys
source, target = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, 'renameat2', None)
if renameat2 is None:
    raise OSError(errno.ENOSYS, 'atomic no-replace rename unavailable')
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
if renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
    code = ctypes.get_errno()
    raise OSError(code, os.strerror(code), target)
SC_FIRST_INSTALL_NOREPLACE
}
first_install_publish() {
 check_root_dir /opt
 [ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] ||
  die 'refusing to publish first install over an existing prefix'
 [ ! -e "$FIRST_INSTALL_INTENT" ] && [ ! -L "$FIRST_INSTALL_INTENT" ] ||
  die 'unreconciled first-install claim'
 first_trust=$(first_install_trust_binding) ||
  die 'unable to bind initial installation to original source trust'
 first_stage=$(mktemp -d /opt/.server-connect-initial.XXXXXXXX) ||
  die 'unable to create private first-install stage'
 printf 'AChWorks/server-connect\n' > "$first_stage/.owner" || die 'cannot stage root owner marker'
 chmod 0644 "$first_stage/.owner" || die 'cannot protect root owner marker'
 chmod 0755 "$first_stage" || die 'cannot set normal product prefix permissions'
 first_inode=$(stat -c '%d:%i' "$first_stage") || die 'cannot identify first-install directory'
 first_temp=$(mktemp "$STATE/.first-install-intent.XXXXXXXX") ||
  die 'cannot stage durable first-install intent'
 printf '%s\n%s\n%s\n' "$first_stage" "$first_inode" "$first_trust" > "$first_temp" ||
  die 'cannot write first-install intent'
 chmod 0600 "$first_temp" || die 'cannot protect first-install intent'
 first_install_noreplace "$first_temp" "$FIRST_INSTALL_INTENT" ||
  die 'cannot atomically publish first-install intent without overwrite'
 # Flush the owner marker, intent and their parents before atomic publication.
 # Linux renameat2(NO_REPLACE) avoids replacing an independently created
 # foreign prefix, even during the last pre-rename scheduling window.
 python3 -I -S - "$first_stage" "$PREFIX" "$FIRST_INSTALL_INTENT" "$STATE" <<'SC_FIRST_INSTALL_RENAME'
import ctypes,errno,os,sys
src,dst,intent,state=sys.argv[1:]
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
for path in (src+'/.owner',src,intent,state):
    sync(path)
libc=ctypes.CDLL(None,use_errno=True)
renameat2=getattr(libc,'renameat2',None)
if renameat2 is None: raise OSError(errno.ENOSYS,'atomic noreplace rename unavailable')
renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
if renameat2(-100,os.fsencode(src),-100,os.fsencode(dst),1)!=0:
    error=ctypes.get_errno()
    raise OSError(error,os.strerror(error),dst)
sync('/opt')
SC_FIRST_INSTALL_RENAME
 # The intent survives SIGKILL after publication. Retry recognizes only the
 # exact inode + owner + empty prefix; it never adopts foreign files.
}

# Inspect the complete root-private first-install transaction before cleanup.
# This is the only exception to normal *committed* service/receipt preflights.
FIRST_RELEASE_INTENT=$STATE/.first-release-intent
# Persist the originally selected trust decision with the release-stage
# inode *before* copying its first payload member. Only hashes are retained,
# never a private key, raw signature or publisher material. Normal keyless
# installations remain keyless; explicit Signed first-install retries must
# reproduce their original selected authority.
first_install_trust_binding() {
 case "$trust_kind" in
  unsigned|local-qa) printf '%s\n' "$trust_kind" ;;
  signed)
   check_root_file "$metadata_file"
   check_root_file "$signature_file"
   check_root_file "$publisher_key"
   metadata_digest=$(sha256sum "$metadata_file" | cut -d ' ' -f1) ||
    die 'original Signed metadata identity unavailable'
   signature_digest=$(sha256sum "$signature_file" | cut -d ' ' -f1) ||
    die 'original Signed signature identity unavailable'
   canonical_key=$(openssl pkey -pubin -in "$publisher_key" -pubout 2>/dev/null) ||
    die 'original Signed publisher key unavailable'
   [ -n "$canonical_key" ] || die 'original Signed publisher key empty'
   key_digest=$(printf '%s\n' "$canonical_key" | sha256sum | cut -d ' ' -f1) ||
    die 'original Signed publisher key identity unavailable'
   for digest in "$metadata_digest" "$signature_digest" "$key_digest"; do
    case "$digest" in ''|*[!0123456789abcdef]*) die 'malformed Signed authority digest' ;; esac
    [ "${#digest}" -eq 64 ] || die 'incorrect Signed authority digest length'
   done
   printf 'signed:%s:%s:%s\n' "$metadata_digest" "$signature_digest" "$key_digest"
   ;;
  *) die 'unknown first-install trust selection' ;;
 esac
}
first_install_reconcile_transaction() {
 python3 -I -S - "$SOURCE_DIR" "$PREFIX" "$STATE" /etc/systemd/system "$COMMAND" "$release_name" "$1" "$trust_kind" "$metadata_file" "$signature_file" "$publisher_key" <<'PY_FIRST_INSTALL_RECOVER'
# Embedded in the already-verified root-only installer. Never execute this
# against arbitrary prefixes or without the private first-install receipt.
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

(source, prefix, state, unitdir, command, release_name, action, trust_kind,
 metadata_file, signature_file, publisher_key) = sys.argv[1:]
if trust_kind not in ("signed", "local-qa", "unsigned"):
    raise ValueError("first-install source trust mode invalid")
source, prefix, state, unitdir, command = map(Path, (source, prefix, state, unitdir, command))
assert action in ("inspect", "recover", "inspect-abandon", "abandon")
abandon = action in ("inspect-abandon", "abandon")
uid = os.geteuid()
owned_state = state.lstat()
if not stat.S_ISDIR(owned_state.st_mode) or owned_state.st_uid != uid or stat.S_IMODE(owned_state.st_mode) != 0o700:
    raise ValueError("first-install private state directory unsafe")
initial = state / ".first-install-intent"
stage_intent = state / ".first-release-intent"
release = prefix / "releases" / release_name
names = (
    "server-connect.service", "server-connect-activation-recover.service",
    "server-connect-activation-recover.timer", "server-connect-native-tun.service",
    "server-connect-smart-health.service", "server-connect-smart-health.timer",
)

def refuse(message):
    raise ValueError("first-install recovery refused: " + message)

def node(path, kind):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    # Symlink mode bits are meaningless on Linux (normally 0777); verify
    # their exact target separately rather than rejecting our own links.
    if info.st_uid != uid or (kind != "link" and info.st_mode & 0o022):
        refuse("unowned or unsafe mode: " + str(path))
    if kind == "dir" and not stat.S_ISDIR(info.st_mode):
        refuse("non-directory: " + str(path))
    if kind == "file" and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        refuse("nonregular or linked file: " + str(path))
    if kind == "link" and not stat.S_ISLNK(info.st_mode):
        refuse("non-symlink: " + str(path))
    return info

def entries(path):
    return sorted(path.iterdir(), key=lambda x:x.name) if path.is_dir() else []

def receipt(path, count):
    info = node(path,"file")
    if info is None or stat.S_IMODE(info.st_mode) != 0o600:
        refuse("missing root-private receipt: " + str(path))
    lines=path.read_text("ascii").splitlines()
    if len(lines) != count:
        refuse("malformed receipt: " + str(path))
    return lines

def identity(info):
    return f"{info.st_dev}:{info.st_ino}"

first = receipt(initial,3)
original_first_trust = first[2]
if not re.fullmatch(r"\.server-connect-initial\.[A-Za-z0-9]{8}",Path(first[0]).name) or Path(first[0]).parent != prefix.parent:
    refuse("unexpected initial stage location")
if not re.fullmatch(r"[0-9]+:[0-9]+",first[1]):
    refuse("invalid initial directory identity")

root_info=node(prefix,"dir")
if root_info is not None:
    if identity(root_info) != first[1]:
        refuse("installed prefix inode swapped")
    owner=node(prefix/".owner","file")
    if owner is not None and (prefix/".owner").read_bytes()!=b"AChWorks/server-connect\n":
        refuse("initial owner differs")
else:
    # An interruption before initial-prefix publication or during exact
    # cleanup. Only the recorded empty initial stage may be adopted.
    if any((unitdir/name).exists() for name in names) or command.is_symlink():
        refuse("no prefix but installed service or command exists")
    staged=Path(first[0])
    if node(staged,"dir") is not None:
        if identity(node(staged,"dir")) != first[1]:
            refuse("abandoned outer stage inode changed")
        if {p.name for p in entries(staged)} - {".owner"}:
            refuse("abandoned outer stage has foreign entries")
        if node(staged/".owner","file") is not None and (staged/".owner").read_bytes()!=b"AChWorks/server-connect\n":
            refuse("abandoned outer owner changed")

allowed_files = {}
for line in (source / "checksums.sha256").read_text("ascii").splitlines():
    if not re.fullmatch(r"[0-9a-f]{64}  [A-Za-z0-9_.\-/]+",line):
        refuse("invalid verified source file list")
    digest,name=line.split("  ",1)
    if name in allowed_files: refuse("duplicated source file")
    allowed_files[name]=digest
allowed_files.update({".owner":None,"checksums.sha256":None,
                      "integrity.sha256":None,"local-qa.sha256":None,
                      "authentication.json":None})
allowed_dirs = {"bin","THIRD-PARTY-LICENSES"}

def expected_trust_binding():
    if trust_kind in ("unsigned", "local-qa"):
        return trust_kind
    try:
        meta = Path(metadata_file).read_bytes()
        signature = Path(signature_file).read_bytes()
        result = subprocess.run(("/usr/bin/openssl", "pkey", "-pubin", "-in",
                                 publisher_key, "-pubout"),
                                capture_output=True, timeout=20, check=True,
                                env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin",
                                     "LC_ALL":"C","OPENSSL_CONF":"/dev/null"})
    except (OSError, subprocess.SubprocessError) as exc:
        refuse("original Signed authority cannot be recovered: "+str(exc))
    return "signed:"+":".join(hashlib.sha256(v).hexdigest()
                              for v in (meta, signature, result.stdout))

recorded_trust = None
if original_first_trust not in ("unsigned", "local-qa") and not re.fullmatch(
        r"signed(?::[0-9a-f]{64}){3}", original_first_trust):
    refuse("malformed or missing first-prefix original trust binding")
if not abandon and original_first_trust != expected_trust_binding():
    refuse("original first-install trust selection changed; retry with the original Signed "
           "publisher inputs or run --offline --abandon-incomplete for verified cleanup only")

def check_signed_receipt(root):
    # An interrupted signed first-install may leave a single final name
    # after O_TMPFILE/linkat. Cryptographically check the receipt and bind it
    # to the *original operator-selected* signed inputs before deleting it.
    auth = root / "authentication.json"
    info = node(auth, "file")
    if info is None:
        return
    if recorded_trust is None or not recorded_trust.startswith("signed:") or root not in (owned_inner, release):
        refuse("signed receipt cannot be adopted without an original Signed claim")
    if stat.S_IMODE(info.st_mode) != 0o600:
        refuse("signed receipt is not root-private")
    if not abandon and not all((metadata_file, signature_file, publisher_key)):
        refuse("original Signed authority inputs absent")
    check = subprocess.run(
        (sys.executable, "-I", "-S", str(source / "release-auth.py"),
         "verify-installed", "--bundle", str(root)),
        capture_output=True, text=True, timeout=30,
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C",
             "OPENSSL_CONF":"/dev/null"})
    if check.returncode:
        refuse("signed receipt failed existing cryptographic verifier: " +
               check.stderr[-300:])
    try:
        material = json.loads(auth.read_text("ascii"))
        original_metadata = base64.b64decode(material["metadata_b64"], validate=True)
        original_signature = base64.b64decode(material["signature_b64"], validate=True)
        original_public_key = base64.b64decode(material["publisher_key_b64"], validate=True)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        refuse("signed receipt binding cannot be established: " + str(exc))
    embedded = "signed:"+":".join(hashlib.sha256(v).hexdigest() for v in
                                  (original_metadata, original_signature,
                                   original_public_key))
    if embedded != recorded_trust:
        refuse("published Signed receipt differs from durable original authority")
    if not abandon and expected_trust_binding() != recorded_trust:
        refuse("Signed receipt differs from currently selected original authority")

def scan_release(root):
    if node(root,"dir") is None:
        return []
    observed=[]
    for parent, directory_names, file_names in os.walk(root,topdown=True,followlinks=False):
        base=Path(parent)
        relbase=base.relative_to(root)
        for dirname in directory_names:
            relative=(relbase / dirname).as_posix()
            if relative not in allowed_dirs:
                refuse("foreign release directory: "+relative)
            node(base / dirname, "dir")
            observed.append(base / dirname)
        for filename in file_names:
            relative=(relbase / filename).as_posix()
            if relative not in allowed_files:
                refuse("foreign release file: "+relative)
            node(base / filename,"file")
            observed.append(base / filename)
    for name, kind in (("authentication.json", "signed"),
                       ("integrity.sha256", "unsigned"),
                       ("local-qa.sha256", "local-qa")):
        candidate = root / name
        if candidate.exists() or candidate.is_symlink():
            if recorded_trust is None or recorded_trust.split(":", 1)[0] != kind:
                refuse("trust receipt conflicts with durable first-install selection")
    if (root / "authentication.json").exists() or (root / "authentication.json").is_symlink():
        check_signed_receipt(root)
    return observed

outside=None
owned_inner=None
published=None
if stage_intent.exists() or stage_intent.is_symlink():
    stage_receipt=receipt(stage_intent,4)
    recorded_trust=stage_receipt[3]
    if recorded_trust not in ("unsigned", "local-qa") and not re.fullmatch(
            r"signed(?::[0-9a-f]{64}){3}", recorded_trust):
        refuse("malformed or missing original first-install trust binding")
    if recorded_trust != original_first_trust:
        refuse("prefix and release-stage original trust claims disagree")
    if not abandon and recorded_trust != expected_trust_binding():
        refuse("interrupted first install has a different original trust selection; "
               "retry with the original Signed inputs or run --offline --abandon-incomplete")
    outside=Path(stage_receipt[0])
    if outside.parent != prefix.parent or not re.fullmatch(
            r"\.server-connect-release\.[A-Za-z0-9]{8}",outside.name):
        refuse("unexpected release-stage location")
    if not re.fullmatch(r"[0-9]+:[0-9]+",stage_receipt[1]) or stage_receipt[2] != release_name:
        refuse("different source release or stage inode")
    # The same inode is first copied in an external private stage, then moved
    # into the exact managed release-auth namespace for signed receipts, and
    # finally published under its immutable release name.
    owned_inner = prefix / "releases" / (".stage." + outside.name.rsplit(".",1)[-1])
    for candidate in (outside,owned_inner,release):
        info=node(candidate,"dir")
        if info is not None:
            if identity(info) != stage_receipt[1]:
                refuse("release stage inode replaced: "+str(candidate))
            if published is not None:
                refuse("two release-stage names present")
            published=candidate
            scan_release(candidate)
elif release.exists() or release.is_symlink():
    refuse("published release lacks its private inode receipt")

if root_info is not None:
    expected={"releases",".owner","current","unit.sha256"}
    expected.update(name+".sha256" for name in names[1:])
    for item in entries(prefix):
        if item.name in (".owner","unit.sha256") or item.name.endswith(".sha256") and item.name in expected:
            node(item,"file")
        elif item.name=="releases":
            node(item,"dir")
            for child in entries(item):
                if published != child or child not in (release, owned_inner):
                    refuse("unexpected release path: "+str(child))
        elif item.name=="current":
            node(item,"link")
            if os.readlink(item) != "releases/"+release_name:
                refuse("current link points at foreign release")
        elif re.fullmatch(r"\.current\.[0-9]+",item.name):
            node(item,"link")
            if os.readlink(item)!="releases/"+release_name:
                refuse("foreign candidate link")
        elif re.fullmatch(r"\.guard-backup\.[A-Za-z0-9]{8}",item.name):
            node(item,"dir")
            if entries(item):
                refuse("unexpected first-install guard backup content")
        else:
            refuse("unexpected first-install file: "+str(item))
    if (prefix/"current").is_symlink() and published != release:
        refuse("selected release has no owned publication")

if node(command,"link") is not None:
    if os.readlink(command) != str(prefix / "current/bin/server-connect"):
        refuse("foreign command link")
elif command.exists():
    refuse("foreign command")

# Use the effective systemd identity, including vendor/transient/drop-in
# units. A similarly named foreign loaded service is never taken over.
unit_files=[]
for name in names:
    target=unitdir/name
    info=node(target,"file")
    if info is not None:
        if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256((source/name).read_bytes()).digest():
            refuse("foreign or partially written service unit: "+name)
        unit_files.append(target)
    if unitdir == Path("/etc/systemd/system"):
        info=subprocess.run(("/usr/bin/systemctl","show",name,
            "-p","LoadState","-p","FragmentPath","-p","DropInPaths",
            "-p","Transient","-p","ActiveState","-p","UnitFileState"),
            capture_output=True,text=True,timeout=10,check=True)
        props=dict(line.split("=",1) for line in info.stdout.splitlines() if "=" in line)
        if props.get("LoadState") not in ("not-found","loaded") or props.get("Transient") != "no" or props.get("DropInPaths"):
            refuse("unknown effective systemd identity: "+name)
        if props.get("LoadState")=="loaded" and props.get("FragmentPath") != str(target):
            refuse("foreign loaded systemd unit: "+name)
        if props.get("ActiveState")!="inactive" or props.get("UnitFileState") in ("enabled","enabled-runtime","linked","linked-runtime"):
            refuse("active or enabled unit must be examined from console: "+name)

if action in ("inspect", "inspect-abandon"):
    print("INITIAL_CLAIM_INSPECTION_PASS")
    sys.exit(0)

# Validate EVERYTHING above before destructive cleanup. These paths were
# generated under the same exact initial-prefix and staged-release receipts.
# Re-entering after SIGKILL is idempotent: partial owned inventories remain
# a subset of the verified paths; unrecognized files abort without deletion.
for target in unit_files:
    target.unlink()
if node(command,"link") is not None:
    command.unlink()
if root_info is not None:
    for item in entries(prefix):
        if item.name=="current" or item.name.startswith(".current.") or item.name.endswith(".sha256"):
            item.unlink()
        if item.name.startswith(".guard-backup."):
            item.rmdir()
for candidate in (release,owned_inner,outside):
    if candidate is None or node(candidate,"dir") is None:
        continue
    observed=scan_release(candidate)
    for path in sorted(observed,key=lambda p:len(p.parts),reverse=True):
        if path.is_dir(): path.rmdir()
        else: path.unlink()
    candidate.rmdir()
if root_info is not None:
    releases=prefix/"releases"
    if node(releases,"dir") is not None: releases.rmdir()
    if node(prefix/".owner","file") is not None: (prefix/".owner").unlink()
    prefix.rmdir()
else:
    staged=Path(first[0])
    if node(staged,"dir") is not None:
        if node(staged/".owner","file") is not None: (staged/".owner").unlink()
        staged.rmdir()
# A crash after removing the unit files but before daemon-reload must be
# restartable while the private initial receipt still exists. Never retire
# that receipt until the effective unit registry is reconciled as well.
if unitdir==Path("/etc/systemd/system"):
    subprocess.run(("/usr/bin/systemctl","daemon-reload"),check=True,timeout=15)
if stage_intent.exists(): stage_intent.unlink()
initial.unlink()
print("FIRST_INSTALL_EXACT_RECOVERY_PASS")
PY_FIRST_INSTALL_RECOVER
}
first_install_stage_receipt() {
 [ ! -e "$FIRST_RELEASE_INTENT" ] && [ ! -L "$FIRST_RELEASE_INTENT" ] ||
  die 'unreconciled first-release stage claim'
 first_release_inode=$(stat -c '%d:%i' "$stage") || die 'cannot identify first-release stage'
 original_trust=$(first_install_trust_binding) ||
  die 'unable to bind first release to original source trust'
 first_release_temp=$(mktemp "$STATE/.first-release-intent.XXXXXXXX") ||
  die 'cannot create private first-release receipt'
 printf '%s\n%s\n%s\n%s\n' "$stage" "$first_release_inode" "$release_name" "$original_trust" > "$first_release_temp" ||
  die 'cannot persist first-release identity'
 chmod 0600 "$first_release_temp" || die 'cannot protect first-release identity'
 first_install_noreplace "$first_release_temp" "$FIRST_RELEASE_INTENT" ||
  die 'cannot atomically publish first-release receipt'
 python3 -I -S - "$FIRST_RELEASE_INTENT" "$STATE" "$stage" <<'PY_FIRST_RELEASE_SYNC'
import os,sys
for path in sys.argv[1:]:
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
PY_FIRST_RELEASE_SYNC
}

# A committed first install and its last two root-private receipts are
# separate from an incomplete installation. A crash between receipt unlinks
# must not force a second install or strand the old release receipt across
# uninstall/reinstall. Verify the *installed* release (not the new source
# candidate) and exact inode-bound transaction before retiring either name.
first_install_committed_identity() {
 python3 -I -S - "$STATE" "$PREFIX" "$COMMAND" "$UNIT" <<'PY_FIRST_COMMITTED_IDENTITY'
import os, re, stat, sys
from pathlib import Path

state, prefix, command, unit = map(Path, sys.argv[1:])
uid=os.geteuid()
def fail(message):
    raise ValueError("committed first-install claim refused: "+message)
def file_lines(path, count):
    try: info=path.lstat()
    except FileNotFoundError: return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=uid
            or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
        fail("malformed or foreign private receipt: "+str(path))
    raw=path.read_bytes()
    try: lines=raw.decode("ascii").splitlines(keepends=True)
    except UnicodeDecodeError: fail("non-ASCII private receipt")
    if len(lines)!=count or any(not line.endswith("\n") for line in lines):
        fail("malformed private receipt length")
    return [line[:-1] for line in lines]
def node(path, kind):
    try: info=path.lstat()
    except FileNotFoundError: fail("missing committed object: "+str(path))
    if info.st_uid != uid or (kind!="link" and info.st_mode & 0o022):
        fail("unowned committed object: "+str(path))
    if (kind=="file" and not stat.S_ISREG(info.st_mode)) or (
        kind=="dir" and not stat.S_ISDIR(info.st_mode)) or (
        kind=="link" and not stat.S_ISLNK(info.st_mode)):
        fail("wrong committed object type: "+str(path))
    return info
def identity(info):
    return f"{info.st_dev}:{info.st_ino}"

state_info=node(state,"dir")
if stat.S_IMODE(state_info.st_mode)!=0o700:
    fail("private state mode changed")
initial=file_lines(state/".first-install-intent",3)
release_claim=file_lines(state/".first-release-intent",4)
if initial is None and release_claim is None:
    fail("no outstanding first-install receipt")
# A first-prefix-only claim is still pre-commit; never classify it as a
# completed install. A release-only claim is the original (pre-fix) crash
# window after first-intent retirement, not an ownership-free shortcut.
if release_claim is None:
    fail("first-release claim missing from completed first install")
prefix_info=node(prefix,"dir")
owner=prefix/".owner"
node(owner,"file")
if owner.read_bytes()!=b"AChWorks/server-connect\n":
    fail("installed owner marker changed")
if initial is not None:
    original, prefix_identity, first_trust=initial
    first_path=Path(original)
    if (first_path.parent!=prefix.parent or not re.fullmatch(
        r"\.server-connect-initial\.[A-Za-z0-9]{8}",first_path.name)
            or not re.fullmatch(r"[0-9]+:[0-9]+",prefix_identity)
            or prefix_identity!=identity(prefix_info) or first_path.exists()):
        fail("installed prefix no longer matches first-install identity")
stage,stage_identity,release_name,original_trust=release_claim
if original_trust not in ("unsigned", "local-qa") and not re.fullmatch(
        r"signed(?::[0-9a-f]{64}){3}",original_trust):
    fail("committed original source trust receipt malformed")
if initial is not None and first_trust != original_trust:
    fail("committed prefix/release original trust claims disagree")
stage_path=Path(stage)
if (stage_path.parent!=prefix.parent or not re.fullmatch(
    r"\.server-connect-release\.[A-Za-z0-9]{8}",stage_path.name)
        or not re.fullmatch(r"[0-9]+:[0-9]+",stage_identity)
        or not re.fullmatch(r"0\.1\.0-dev-[0-9a-f]{16}",release_name)):
    fail("first-release receipt identity malformed")
release_dir=prefix/"releases"
node(release_dir,"dir")
selected=release_dir/release_name
if identity(node(selected,"dir"))!=stage_identity:
    fail("completed release directory inode changed")
if stage_path.exists() or (release_dir/(".stage."+stage_path.name.rsplit(".",1)[-1])).exists():
    fail("first-release staging still present")
current=prefix/"current"
node(current,"link")
if os.readlink(current)!="releases/"+release_name:
    fail("committed release is no longer current")
node(unit,"file")
node(prefix/"unit.sha256","file")
node(command,"link")
if os.readlink(command)!=str(prefix/"current/bin/server-connect"):
    fail("installed command identity changed")
for name in ("server-connect-activation-recover.service",
             "server-connect-activation-recover.timer",
             "server-connect-native-tun.service",
             "server-connect-smart-health.service",
             "server-connect-smart-health.timer"):
    node(Path("/etc/systemd/system")/name,"file")
    node(prefix/(name+".sha256"),"file")
print("FIRST_INSTALL_COMMITTED_IDENTITY_PASS")
PY_FIRST_COMMITTED_IDENTITY
}
first_install_is_committed() (
 first_install_committed_identity >/dev/null 2>&1 || return 1
 check_owned >/dev/null 2>&1 || return 1
 check_service_owner >/dev/null 2>&1 || return 1
 [ "$unit_identity" = owned ] || return 1
 check_guard_units >/dev/null 2>&1 || return 1
 "$SOURCE_DIR/bin/server-connect" installer-check-service >/dev/null 2>&1 || return 1
)
first_install_retire_committed_claims() {
 first_install_is_committed ||
  die 'committed first-install claim changed; preserve for console inspection'
 # After the original successful install, retiring FIRST_INSTALL_INTENT
 # before FIRST_RELEASE_INTENT is safe *only because* a release-only orphan
 # now has the same full committed-identity check on the next invocation.
 # No foreign or stale receipt may be deleted by name alone.
 if [ -e "$FIRST_INSTALL_INTENT" ] || [ -L "$FIRST_INSTALL_INTENT" ];then
  rm -- "$FIRST_INSTALL_INTENT" ||
   die 'cannot retire verified committed first-prefix claim'
 fi
 if [ -e "$FIRST_RELEASE_INTENT" ] || [ -L "$FIRST_RELEASE_INTENT" ];then
  # Revalidate release-only identity immediately after the first unlink.
  first_install_is_committed ||
   die 'committed first-release identity changed during retirement'
  rm -- "$FIRST_RELEASE_INTENT" ||
   die 'cannot retire verified committed first-release claim'
 fi
 python3 -I -S - "$STATE" <<'PY_COMMIT_SYNC'
import os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
PY_COMMIT_SYNC
}

# Fresh service files are created completely before an atomic, no-replace
# publication. A SIGKILL during their copy cannot expose a partial final
# unit that an interrupted first-install recovery would have to adopt.
first_install_atomic_unit() {
 python3 -I -S - "$1" "$2" <<'PY_INITIAL_UNIT'
import ctypes,os,sys,tempfile
source,target=sys.argv[1:]
parent=os.path.dirname(target)
fd,tmp=tempfile.mkstemp(prefix=".server-connect-initial.",dir=parent)
try:
    with open(source,"rb") as incoming:
        while True:
            piece=incoming.read(65536)
            if not piece: break
            os.write(fd,piece)
    os.fchmod(fd,0o644)
    os.fsync(fd)
    os.close(fd)
    fd=-1
    libc=ctypes.CDLL(None,use_errno=True)
    renameat2=getattr(libc,"renameat2",None)
    if renameat2 is None: raise OSError("atomic unit publication unavailable")
    renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    if renameat2(-100,os.fsencode(tmp),-100,os.fsencode(target),1)!=0:
        code=ctypes.get_errno()
        raise OSError(code,os.strerror(code),target)
    d=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(d)
    finally: os.close(d)
finally:
    if fd>=0: os.close(fd)
    if os.path.exists(tmp): os.unlink(tmp)
PY_INITIAL_UNIT
}

# Inspect the *effective* systemd identity before ANY stop/disable/enable or
# replacement. No local unit path does not mean there is no vendor/transient
# unit of the same name in another directory.
check_service_owner() {
 props=$(systemctl show server-connect.service    --property=LoadState --property=FragmentPath    --property=DropInPaths --property=Transient --property=UnitFileState) ||
     die 'cannot inspect systemd service provenance'
 load=$(printf '%s\n' "$props" | sed -n 's/^LoadState=//p')
 fragment=$(printf '%s\n' "$props" | sed -n 's/^FragmentPath=//p')
 dropins=$(printf '%s\n' "$props" | sed -n 's/^DropInPaths=//p')
 transient=$(printf '%s\n' "$props" | sed -n 's/^Transient=//p')
 enabled=$(printf '%s\n' "$props" | sed -n 's/^UnitFileState=//p')
 case "$load" in
 not-found)
  [ -z "$fragment" ] && [ -z "$dropins" ] && [ "$transient" = no ] &&
   [ -z "$enabled" ] || die 'conflicting or stale same-name systemd unit; refusing mutation'
  [ ! -e "$UNIT" ] && [ ! -L "$UNIT" ] ||
   die 'systemd does not recognize existing local unit; repair via console'
  if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then
   [ "$ACTION" = --offline ] && first_install_claimed_prefix ||
    die 'partial or foreign product prefix without loaded unit; preserve for inspection'
   unit_identity=partial_initial
  else
   unit_identity=absent
  fi
  ;;
 loaded)
  [ "$fragment" = "$UNIT" ] && [ -z "$dropins" ] && [ "$transient" = no ] ||
   die 'foreign same-name systemd unit or drop-in; refusing mutation'
  check_root_file "$PREFIX/.owner"
  [ "$(cat "$PREFIX/.owner")" = 'AChWorks/server-connect' ] ||
   die 'product install marker conflict; refusing service mutation'
  check_root_file "$UNIT"
  check_root_file "$PREFIX/unit.sha256"
  printf '%s  %s\n' "$(cat "$PREFIX/unit.sha256")" "$UNIT" |
   sha256sum --quiet --check - || die 'systemd unit ownership digest conflict'
  unit_identity=owned
  ;;
 *) die 'systemd service provenance not safely absent or owned'
 esac
}
# Independently installed recovery units start DISABLED. The exact owner and
# manifest digest of each are checked before ANY subsequent replacement.
check_guard_units() (
 # Do not silently strand a previous QA Core by adopting the new Native
 # package. A retained old unit needs the old release's verified uninstall.
 if [ -e /etc/systemd/system/server-connect-smart-tun.service ] ||
    [ -L /etc/systemd/system/server-connect-smart-tun.service ] ||
    [ -e "$PREFIX/server-connect-smart-tun.service.sha256" ]; then
  die 'retired v4 QA Core unit remains; uninstall the old QA release before Native-only install'
 fi
 for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-native-tun.service server-connect-smart-health.service server-connect-smart-health.timer; do
  target=/etc/systemd/system/$name
  digest_file=$PREFIX/$name.sha256
  props=$(systemctl show "$name" --property=LoadState --property=FragmentPath --property=DropInPaths --property=Transient) ||
    die 'cannot inspect independent recovery unit provenance'
  load=$(printf '%s\n' "$props" | sed -n 's/^LoadState=//p')
  fragment=$(printf '%s\n' "$props" | sed -n 's/^FragmentPath=//p')
  dropins=$(printf '%s\n' "$props" | sed -n 's/^DropInPaths=//p')
  transient=$(printf '%s\n' "$props" | sed -n 's/^Transient=//p')
  if [ -e "$target" ] || [ -L "$target" ] || [ -e "$digest_file" ] || [ -L "$digest_file" ]; then
   check_root_file "$target"
   check_root_file "$digest_file"
   printf '%s  %s\n' "$(cat "$digest_file")" "$target" | sha256sum --quiet --check - ||
    die 'recovery unit differs from owned manifest'
   [ "$load" = loaded ] && [ "$fragment" = "$target" ] && [ -z "$dropins" ] && [ "$transient" = no ] ||
    die 'effective managed unit identity conflict'
   if [ "$name" = server-connect-smart-health.service ]; then
    [ "$(systemctl show "$name" -p UnitFileState --value)" = static ] ||
      die 'experimental health executor must remain static'
   fi
   if [ "$name" = server-connect-native-tun.service ]; then
    case "$(systemctl show "$name" -p UnitFileState --value)" in
      enabled|disabled) ;;
      *) die 'native Smart Routing unit has unsupported activation state' ;;
    esac
   fi
  else
   [ "$load" = not-found ] && [ -z "$fragment" ] && [ -z "$dropins" ] && [ "$transient" = no ] ||
    die 'foreign recovery unit name already registered'
  fi
 done
)
# After a native Core SIGKILL, independently scheduled recovery and health
# oneshots can both exit FAILED even after exact Direct restoration. The
# installer holds the shared product journal lock and has already checked the
# saved desired mode and absence of native/legacy recovery claims. Normalize
# only these exact idle, manifest-owned oneshots, never a live guard, timer or
# another service. A failed reset remains an error unless re-observation proves
# systemd independently garbage-collected the same failed state.
normalize_idle_health_failure() {
 health_unit_name=server-connect-smart-health.service
 recovery_unit_name=server-connect-activation-recover.service
 health_state=$(systemctl show "$health_unit_name" -p ActiveState --value) ||
  die 'health executor state cannot be inspected'
 recovery_state=$(systemctl show "$recovery_unit_name" -p ActiveState --value) ||
  die 'recovery executor state cannot be inspected'
 if [ "$health_state" = inactive ] && [ "$recovery_state" = inactive ]; then
  [ "$(systemctl show "$health_unit_name" -p Result --value)" = success ] &&
  [ "$(systemctl show "$recovery_unit_name" -p Result --value)" = success ] ||
   die 'inactive native guard executor has an unresolved failure result'
  return 0
 fi
 # Do not reset either failed executor while an independent timer, core or
 # conflicting legacy role is still active or uncertain.
 for role in server-connect-activation-recover.timer server-connect-native-tun.service server-connect-smart-health.timer; do
  [ "$(systemctl show "$role" -p ActiveState --value)" = inactive ] ||
   die 'cannot normalize guard failure while another TUN/timer role is active'
 done
 for guard_unit in "$health_unit_name" "$recovery_unit_name"; do
  state=$(systemctl show "$guard_unit" -p ActiveState --value) ||
   die 'independent guard executor state unavailable'
  outcome=$(systemctl show "$guard_unit" -p Result --value) ||
   die 'independent guard executor result unavailable'
  case "$state:$outcome" in
   inactive:success|failed:exit-code|failed:timeout|failed:signal|failed:core-dump) ;;
   *) die 'independent guard executor not safely idle for normalization' ;;
  esac
  [ "$(systemctl show "$guard_unit" -p MainPID --value)" = 0 ] &&
  [ "$(systemctl show "$guard_unit" -p ControlPID --value)" = 0 ] &&
  [ -z "$(systemctl show "$guard_unit" -p Job --value)" ] &&
  [ -z "$(systemctl show "$guard_unit" -p ControlGroup --value)" ] ||
   die 'cannot normalize guard failure with a live executor or job'
 done
 check_guard_units
 for guard_unit in "$health_unit_name" "$recovery_unit_name"; do
  state=$(systemctl show "$guard_unit" -p ActiveState --value) ||
   die 'independent guard executor changed before normalization'
  if [ "$state" = failed ]; then
   if ! systemctl reset-failed "$guard_unit"; then
    [ "$(systemctl show "$guard_unit" -p ActiveState --value)" = inactive ] ||
     die 'owned guard executor failure could not be normalized'
   fi
  fi
  [ "$(systemctl show "$guard_unit" -p ActiveState --value)" = inactive ] &&
  [ "$(systemctl show "$guard_unit" -p Result --value)" = success ] ||
   die 'owned guard executor did not return to an inactive healthy state'
 done
 check_guard_units
}

# An active timer or oneshot may own pending kernel state. Updating or
# uninstalling its recovery executable would sever the only independent guard.
require_guard_inactive() {
 for name in server-connect-activation-recover.timer server-connect-activation-recover.service server-connect-native-tun.service server-connect-smart-health.service server-connect-smart-health.timer; do
  case "$(systemctl show "$name" -p ActiveState --value)" in
   inactive) ;; *) die 'independent recovery guard active or uncertain; refuse installer change' ;;
  esac
 done
}
check_owned() {
 if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then
  check_root_dir "$PREFIX"
  check_root_file "$PREFIX/.owner"
  [ -f "$PREFIX/.owner" ] && [ ! -L "$PREFIX/.owner" ] || die 'unowned install root'
  [ "$(cat "$PREFIX/.owner")" = 'AChWorks/server-connect' ] || die 'unowned install root'
 fi
 if [ -e "$COMMAND" ] || [ -L "$COMMAND" ]; then
  [ -L "$COMMAND" ] && [ "$(readlink "$COMMAND")" = "$PREFIX/current/bin/server-connect" ] || die "unowned executable at $COMMAND"
 fi
 if [ -e "$UNIT" ] || [ -L "$UNIT" ]; then
  check_root_file "$UNIT"
  check_root_file "$PREFIX/unit.sha256"
  printf '%s  %s\n' "$(cat "$PREFIX/unit.sha256")" "$UNIT" | sha256sum --quiet -c - || die 'systemd unit changed externally; refusing overwrite'
 fi
 if [ -e "$PREFIX/current" ] || [ -L "$PREFIX/current" ]; then
  [ -L "$PREFIX/current" ] || die 'unowned current release path'
  existing_target=$(readlink "$PREFIX/current") ||
   die 'installed release link unreadable'
  case "$existing_target" in
   releases/0.1.0-dev-*) ;;
   *) die 'invalid current release link' ;;
  esac
  # Preserve the old canonical link contract: basename() alone accepts
  # trailing slashes and parent-directory aliases, while a stored symlink
  # must identify exactly one direct child of the owned releases directory.
  [ "$existing_target" = "releases/$(basename -- "$existing_target")" ] ||
   die 'noncanonical current release link'
  check_root_dir "$PREFIX/releases"
  verify_installed_release "$PREFIX/$existing_target"
 fi
 if [ -e "$STATE" ] || [ -L "$STATE" ]; then
  check_root_dir "$STATE"
  perms=$(stat -c '%a' "$STATE")
  [ "$perms" = 700 ] || die "unsafe private state permissions: $perms"
 fi
}

if [ "$ACTION" = --help ]; then
 say 'Use a trusted HTTPS bootstrap or uploaded local bundle; no publisher key is required.'
 say 'Actions: --offline | --verify-only | --uninstall; optional historical signed QA remains supported.'
 say 'For interrupted initial installs only: --offline --abandon-incomplete (verified cleanup ONLY; does not install).'
 exit 0
fi
while [ "$#" -gt 0 ]; do
 case "$1" in
  --local-qa) [ "$local_qa" = no ] || die 'duplicate local QA flag';local_qa=yes;shift;;
  --abandon-incomplete) [ "$abandon_incomplete" = no ] || die 'duplicate abandon-incomplete flag';abandon_incomplete=yes;shift;;
  --publisher-key) [ "$#" -ge 2 ] && [ -z "$publisher_key" ] || die 'invalid publisher key option';publisher_key=$2;shift 2;;
  --metadata-file) [ "$#" -ge 2 ] && [ -z "$metadata_file" ] || die 'invalid metadata option';metadata_file=$2;shift 2;;
  --signature-file) [ "$#" -ge 2 ] && [ -z "$signature_file" ] || die 'invalid signature option';signature_file=$2;shift 2;;
  --version) [ "$#" -ge 2 ] && [ -z "$pinned_version" ] || die 'invalid version pin';pinned_version=$2;shift 2;;
  --target) [ "$#" -ge 2 ] && [ -z "$pinned_target" ] || die 'invalid target pin';pinned_target=$2;shift 2;;
  *) die 'unknown installer argument';;
 esac
done
if [ "$local_qa" = yes ]; then
 [ -z "$publisher_key$metadata_file$signature_file$pinned_version$pinned_target" ] ||
  die 'local QA and publisher trust options cannot be mixed'
elif [ -z "$publisher_key$metadata_file$signature_file$pinned_version$pinned_target" ]; then
 # Exact new source bundles use HTTPS/manual-upload trust with full SHA256
 # integrity. Retained previous signed installations are verified by the
 # existing receipt when they are used for update/rollback/uninstall.
 unsigned_release=yes
else
 [ -n "$publisher_key" ] && [ -n "$metadata_file" ] && [ -n "$signature_file" ] &&
  [ -n "$pinned_version" ] && [ -n "$pinned_target" ] ||
  die 'publisher verification is required; use trusted bootstrap or explicitly select --local-qa'
fi
case "$ACTION" in --offline|--verify-only|--uninstall) ;; *) die 'only --offline, --verify-only, --uninstall supported; online bootstrap fetches a verified bundle first' ;; esac
[ "$abandon_incomplete" = no ] || [ "$ACTION" = --offline ] ||
 die '--abandon-incomplete requires --offline; it never performs a new installation'
require_root
check_source_ancestry
check_platform
verify_payload
# A signed interrupted release cannot be retried with unsigned/local QA
# source trust; use the original signer, metadata and signature when present.
if [ "$local_qa" = yes ];then
 trust_kind=local-qa
elif [ "${unsigned_release:-no}" = yes ];then
 trust_kind=unsigned
else
 trust_kind=signed
fi
# Bind an interrupted initial install to the same verified source digest.
release_name="0.1.0-dev-$(sha256sum "$SOURCE_DIR/checksums.sha256" | cut -c 1-16)"
pending_first=no
pending_committed=no
if [ -e "$FIRST_INSTALL_INTENT" ] || [ -L "$FIRST_INSTALL_INTENT" ];then
 if first_install_is_committed;then
  [ "$abandon_incomplete" = no ] ||
   die 'cannot abandon a committed installation; use ordinary --uninstall'
  pending_committed=yes
  check_owned
  check_service_owner
  check_guard_units
 elif [ "$ACTION" = --offline ];then
  if [ "$abandon_incomplete" = yes ];then
   first_install_reconcile_transaction inspect-abandon ||
    die 'incomplete installation is not exactly owned; abandon refused'
  else
   first_install_reconcile_transaction inspect ||
    die 'unrecognized interrupted initial installation or changed original trust; preserve for inspection'
  fi
  pending_first=yes
 else
  die 'first-install intent not committed; verification/uninstall cannot adopt incomplete state'
 fi
else
 check_owned
 check_service_owner
 check_guard_units
 if [ -e "$FIRST_RELEASE_INTENT" ] || [ -L "$FIRST_RELEASE_INTENT" ];then
  first_install_is_committed ||
   die 'orphan first-release receipt invalid; preserve foreign state'
  pending_committed=yes
 fi
fi

if [ "$abandon_incomplete" = yes ] && [ "$pending_first" != yes ];then
 die 'no exactly owned incomplete first installation to abandon; committed or foreign resources preserved'
fi
if [ "$ACTION" = --verify-only ]; then say 'bundle integrity, selected trust policy and owned-resource preflight PASS'; exit 0;fi

# The installer and all manager state changes coordinate through one flock.
# A fresh state directory may be created only after complete payload preflight.
if [ ! -d "$STATE" ]; then
 [ "$ACTION" != --uninstall ] || die 'cannot uninstall without the owned state directory'
 install -d -m 0700 "$STATE"
fi
check_root_dir "$STATE"
if [ -e "$STATE/.lock" ] || [ -L "$STATE/.lock" ]; then check_root_file "$STATE/.lock";fi
exec 9>"$STATE/.lock"
chmod 0600 "$STATE/.lock"
flock -w 30 -x 9 || die 'another Server Connect operation holds the lifecycle lock'
"$SOURCE_DIR/bin/server-connect" installer-check-guard-clear >/dev/null ||
 die 'pending, uncertain or invalid activation journal; refuse installer mutation'
if [ "$pending_committed" = yes ];then
 first_install_retire_committed_claims
elif [ "$pending_first" = yes ];then
 if [ "$abandon_incomplete" = yes ];then
  first_install_reconcile_transaction inspect-abandon ||
   die 'incomplete first-install ownership changed before explicit abandonment'
  first_install_reconcile_transaction abandon ||
   die 'explicit incomplete first-install abandonment refused; original resources preserved'
  say 'exactly owned incomplete first installation abandoned; no new installation attempted'
  exit 0
 fi
 first_install_reconcile_transaction inspect ||
  die 'interrupted initial installation changed under lifecycle lock'
 first_install_reconcile_transaction recover ||
  die 'interrupted initial installation cannot be reconciled safely'
fi
check_owned
check_service_owner
check_guard_units
if [ "$unit_identity" = owned ]; then
 "$SOURCE_DIR/bin/server-connect" installer-check-service >/dev/null ||
  die 'effective installed systemd unit provenance conflict'
fi
if [ "$unit_identity" = partial_initial ];then
 first_install_claimed_prefix ||
  die 'first-install prefix identity changed before locked recovery'
fi

if [ "$ACTION" = --uninstall ]; then
 normalize_idle_health_failure
 require_guard_inactive
 [ -f "$PREFIX/.owner" ] || die 'Server Connect not installed'
 # Validate all release ownership before destructive changes to the service/unit.
 if [ -d "$PREFIX/releases" ]; then
  check_root_dir "$PREFIX/releases"
  for release in "$PREFIX"/releases/*; do
   [ -d "$release" ] || continue
   [ ! -L "$release" ] || die 'unsafe release symlink'
   verify_installed_release "$release" || die 'installed release integrity conflict; uninstall refused'
  done
 fi
 systemctl stop server-connect.service || die 'cannot stop owned proxy; uninstall aborted'
 systemctl disable server-connect.service || die 'cannot disable owned proxy; uninstall aborted'
 "$SOURCE_DIR/bin/server-connect" installer-reconcile-direct >/dev/null ||
  die 'proxy stopped but retained Direct intent could not be reconciled; uninstall aborted'
 if systemctl is-failed --quiet server-connect.service; then
  systemctl reset-failed server-connect.service || say 'WARNING: failed owned service state could not be cleared'
 fi
 for timer in server-connect-activation-recover.timer server-connect-smart-health.timer; do
  if [ -f "/etc/systemd/system/$timer" ]; then
   systemctl disable "$timer" || die 'cannot disable owned recovery/health timer'
  fi
 done
 if [ -f /etc/systemd/system/server-connect-native-tun.service ]; then
  systemctl disable server-connect-native-tun.service ||
   die 'cannot disable owned native unit during uninstall'
 fi
 rm -f -- "$COMMAND" "$UNIT" "$PREFIX/current" "$PREFIX/unit.sha256" "$PREFIX/.owner" \
  "$GUARD_SERVICE" "$GUARD_TIMER" \
  /etc/systemd/system/server-connect-native-tun.service \
  "$PREFIX/server-connect-activation-recover.service.sha256" \
  "$PREFIX/server-connect-activation-recover.timer.sha256" \
  "$PREFIX/server-connect-native-tun.service.sha256" \
  /etc/systemd/system/server-connect-smart-health.service \
  /etc/systemd/system/server-connect-smart-health.timer \
  "$PREFIX/server-connect-smart-health.service.sha256" \
  "$PREFIX/server-connect-smart-health.timer.sha256"
 systemctl daemon-reload || die 'unit removed but daemon-reload failed; inspect systemd'
 if [ -d "$PREFIX/releases" ] && [ ! -L "$PREFIX/releases" ]; then
  for release in "$PREFIX"/releases/*; do
   [ -d "$release" ] || continue
   [ ! -L "$release" ] || die 'unsafe release symlink retained'
   [ -f "$release/.owner" ] && [ "$(cat "$release/.owner")" = 'AChWorks/server-connect' ] || die 'release ownership conflict; preserve for inspection'
   receipt=$(release_trust_file "$release") || die 'owned release receipt cannot be enumerated'
   for path in $(release_payload_files "$release"); do
    rm -f -- "$release/$path" || die 'owned release removal failed'
   done
   for path in $receipt; do rm -f -- "$release/$path" || die 'owned trust receipt removal failed'; done
   rm -f -- "$release/checksums.sha256" "$release/.owner" || die 'release marker removal failed'
   rmdir "$release/bin" "$release/THIRD-PARTY-LICENSES" "$release" 2>/dev/null || say "retained modified release at $release"
  done
  rmdir "$PREFIX/releases" 2>/dev/null || true
 fi
 rmdir "$PREFIX" 2>/dev/null || true
 say "uninstalled managed binaries and unit; private profiles retained under $STATE"
 exit 0
fi

# Installation and offline update share this path. No networking is performed.
# Never normalize a failed oneshot until the exact activation journal has
# already been checked clear under the product lock.
normalize_idle_health_failure
require_guard_inactive
# The shared .lock is held across observation, activation and rollback.
# Bind the installed release identity to the verified exact binary bytes in
# one assignment. A malformed or absent hash must not be interpreted as a
# valid named release or proceed into service changes.
# Include the complete canonical checksummed payload in the installed
# identity, not just the manager and core executables. Two distinct bundles
# with identical binaries but different units/manifest must not collide.
release_suffix=${release_name#0.1.0-dev-}
case "$release_suffix" in ''|*[!0123456789abcdef]*) die 'candidate binary release digest is invalid' ;; esac
[ "${#release_suffix}" -eq 16 ] || die 'candidate binary release digest length is invalid'
release="$PREFIX/releases/$release_name"
previous=''
if [ -L "$PREFIX/current" ]; then previous=$(readlink "$PREFIX/current");fi
was_active=no
was_enabled=no
if [ "$unit_identity" = owned ];then
 if systemctl is-active --quiet server-connect.service;then was_active=yes;fi
 if systemctl is-enabled --quiet server-connect.service;then was_enabled=yes;fi
fi
[ -z "$previous" ] || [ -f "$UNIT" ] || die 'previous owned release has no systemd unit; repair via console before update'

prefix_created=no
command_created=no
release_created=no
release_stage_identity=''
unit_backup=''
guard_backup=''
stage=''
rollback_needed=no
operation_done=no

remove_backup() {
 if [ -n "$unit_backup" ] && [ -f "$unit_backup" ];then rm -f -- "$unit_backup";fi
 if [ -n "$guard_backup" ] && [ -d "$guard_backup" ];then rm -f -- "$guard_backup"/*;rmdir "$guard_backup";fi
}
rollback_candidate() {
 # Do not claim rollback if a stop, restore or previous restart failed.
 # Never touch a unit beyond the verified product-owned identity.
 set +e
 failed=no
 say 'candidate failed; attempting owned lifecycle rollback'
 if [ "$prefix_created" = yes ] && [ -e "$FIRST_INSTALL_INTENT" ];then
  if first_install_reconcile_transaction recover;then
   failed=no
  else
   failed=yes
   say 'RECOVERY_REQUIRED: first-install exact ownership cannot be reconciled; retain evidence'
  fi
  return
 fi
 if [ "$rollback_needed" = yes ];then
  systemctl stop server-connect.service || { say 'RECOVERY_REQUIRED: owned unit stop failed';failed=yes; }
  if [ -n "$previous" ];then
   ln -s "$previous" "$PREFIX/.restore.$$" && mv -Tf -- "$PREFIX/.restore.$$" "$PREFIX/current" ||
    { say 'RECOVERY_REQUIRED: previous release link restoration failed';failed=yes; }
  else
   rm -f -- "$PREFIX/current" || { say 'RECOVERY_REQUIRED: candidate release link removal failed';failed=yes; }
  fi
  if [ -n "$unit_backup" ];then
   install -m 0644 "$unit_backup" "$UNIT" ||
    { say 'RECOVERY_REQUIRED: previous unit restoration failed';failed=yes; }
   sha256sum "$UNIT" | cut -d' ' -f1 > "$PREFIX/unit.sha256" ||
    { say 'RECOVERY_REQUIRED: previous unit digest restoration failed';failed=yes; }
  else
   rm -f -- "$UNIT" "$PREFIX/unit.sha256" ||
    { say 'RECOVERY_REQUIRED: new unit removal failed';failed=yes; }
  fi
  # Restore precisely the previous supplemental unit bytes (or absence).
  for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-native-tun.service server-connect-smart-health.service server-connect-smart-health.timer;do
   path=/etc/systemd/system/$name
   digest=$PREFIX/$name.sha256
   if [ -n "$guard_backup" ] && [ -f "$guard_backup/$name" ];then
    install -m 0644 "$guard_backup/$name" "$path" ||
     { say "RECOVERY_REQUIRED: prior managed $name unit restoration failed";failed=yes; }
    install -m 0644 "$guard_backup/$name.sha256" "$digest" ||
     { say "RECOVERY_REQUIRED: prior managed $name digest restoration failed";failed=yes; }
   else
    rm -f -- "$path" "$digest" || failed=yes
   fi
  done
  if [ "$command_created" = yes ] && [ -L "$COMMAND" ] &&
     [ "$(readlink "$COMMAND")" = "$PREFIX/current/bin/server-connect" ];then
    rm -f -- "$COMMAND" || { say 'RECOVERY_REQUIRED: new command link removal failed';failed=yes; }
  fi
  systemctl daemon-reload || { say 'RECOVERY_REQUIRED: systemd reload failed';failed=yes; }
  if [ "$unit_identity" = owned ];then
   if [ "$was_enabled" = yes ];then
    systemctl enable server-connect.service ||
     { say 'RECOVERY_REQUIRED: previous enabled state restoration failed';failed=yes; }
   else
    systemctl disable server-connect.service ||
     { say 'RECOVERY_REQUIRED: previous disabled state restoration failed';failed=yes; }
   fi
  fi
  if [ "$was_active" = yes ];then
   systemctl start server-connect.service ||
    { say 'RECOVERY_REQUIRED: previous service restart failed';failed=yes; }
   if [ "$failed" = no ];then
    "$PREFIX/current/bin/server-connect" ready --json >/dev/null ||
     { say 'RECOVERY_REQUIRED: previous listener readiness unverified';failed=yes; }
   fi
  fi
 fi
 if [ -n "$stage" ] && [ -d "$stage" ] && [ ! -L "$stage" ];then
   case "$stage" in "$PREFIX"/releases/.stage.*) rm -rf -- "$stage" || failed=yes;; *) failed=yes;; esac
 fi
 # Remove only resources newly created by this operation, never an old
 # release or any path still referenced by the active symlink.
 if [ "$failed" = no ] && [ "$release_created" = yes ] &&
    [ -d "$release" ] && [ ! -L "$release" ] &&
    [ -f "$release/.owner" ] &&
    [ "$(cat "$release/.owner")" = 'AChWorks/server-connect' ] &&
    [ "$(readlink "$PREFIX/current" 2>/dev/null)" != "releases/$release_name" ];then
  # The create-intent precedes rename. If a different/foreign target appeared
  # during that window, do not adopt its owner marker and delete its files.
  if [ -n "$release_stage_identity" ] &&
     [ "$(stat -c '%d:%i' "$release" 2>/dev/null || :)" = "$release_stage_identity" ] &&
     verify_release_payload "$release" >/dev/null 2>&1 &&
     verify_release_trust "$release" >/dev/null 2>&1 &&
     receipt=$(release_trust_file "$release") &&
     cmp -s "$SOURCE_DIR/checksums.sha256" "$release/checksums.sha256"; then
   for path in $(release_payload_files "$release"); do
    rm -f -- "$release/$path" || { say 'RECOVERY_REQUIRED: candidate release payload cleanup failed';failed=yes; }
   done
   for path in $receipt; do
    rm -f -- "$release/$path" || { say 'RECOVERY_REQUIRED: candidate trust receipt cleanup failed';failed=yes; }
   done
   rm -f -- "$release/checksums.sha256" "$release/.owner" ||
    { say 'RECOVERY_REQUIRED: candidate release marker cleanup failed';failed=yes; }
   rmdir "$release/bin" "$release/THIRD-PARTY-LICENSES" "$release" 2>/dev/null ||
     { say 'RECOVERY_REQUIRED: candidate release directory retained';failed=yes; }
  else
   say 'RECOVERY_REQUIRED: new release identity uncertain; no cleanup attempted'
   failed=yes
  fi
 fi
 if [ "$failed" = no ] && [ "$prefix_created" = yes ];then
  # Never remove even an empty-looking foreign directory: the private
  # persistent first-install claim must still match the inode and owner.
  if first_install_claimed_prefix;then
   remove_backup
   rm -f -- "$PREFIX/.owner" || failed=yes
   [ ! -d "$PREFIX/releases" ] || rmdir "$PREFIX/releases" || failed=yes
   rmdir "$PREFIX" || { say 'RECOVERY_REQUIRED: first-install prefix retained';failed=yes; }
   if [ "$failed" = no ];then
    rm -f -- "$FIRST_INSTALL_INTENT" || failed=yes
   fi
  else
   say 'RECOVERY_REQUIRED: first-install claim changed; foreign prefix preserved'
   failed=yes
  fi
 fi
 if [ "$failed" = yes ];then
  say 'RECOVERY_REQUIRED: prior service state could not be completely restored; inspect systemd and owned paths from console'
 else
  say 'previous owned service state restored; profiles retained'
 fi
}
on_exit() {
 code=$?
 trap - EXIT HUP INT TERM
 if [ "$code" -ne 0 ] && [ "$operation_done" != yes ];then rollback_candidate;fi
 if [ "${failed:-no}" = yes ];then
  # If old unit/service restoration failed, preserving the exact previous
  # unit bytes is essential for console recovery. Never erase the only
  # candidate-independent copy solely because the shell is exiting.
  say "RECOVERY_REQUIRED: exact previous unit backups retained: ${unit_backup:-none} ${guard_backup:-none}"
 else
  remove_backup
 fi
 exit "$code"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ ! -d "$PREFIX" ];then
 first_install_reconcile_abandoned_stage
 prefix_created=yes
 first_install_publish
elif [ "$unit_identity" = partial_initial ];then
 first_install_claimed_prefix || die 'first-install recovery identity invalid'
 prefix_created=yes
fi
check_root_dir "$PREFIX"
if [ -e "$PREFIX/releases" ] || [ -L "$PREFIX/releases" ];then
 check_root_dir "$PREFIX/releases"
else
 install -d -m 0755 "$PREFIX/releases"
fi
if [ -e "$release" ] || [ -L "$release" ];then
 check_root_dir "$release"
 [ -f "$release/.owner" ] && [ ! -L "$release/.owner" ] &&
 [ "$(cat "$release/.owner")" = 'AChWorks/server-connect' ] ||
  die 'unowned candidate release directory'
 verify_installed_release "$release" || die 'existing release integrity or trust failed'
 for path in $(release_payload_files "$SOURCE_DIR"); do
  cmp -s "$SOURCE_DIR/$path" "$release/$path" || die "existing release differs from candidate: $path"
 done
 cmp -s "$SOURCE_DIR/checksums.sha256" "$release/checksums.sha256" ||
  die 'existing release checksum manifest differs from candidate'
 # An existing valid release may not be silently promoted or downgraded:
 # its original receipt and exact checksummed payload must remain intact.
 # verify_installed_release above already checked that identity.
else
 if [ "$prefix_created" = yes ];then
  # Interrupted copies stay outside the already published prefix, but are
  # owned by a private exact dev:inode receipt before any payload is copied.
  stage=$(mktemp -d /opt/.server-connect-release.XXXXXXXX) ||
   die 'cannot create first-release stage'
  first_install_stage_receipt
 else
  stage=$(mktemp -d "$PREFIX/releases/.stage.XXXXXXXX") || die 'cannot stage release'
 fi
 install -d -m 0755 "$stage/bin" "$stage/THIRD-PARTY-LICENSES"
 for path in $(release_payload_files "$SOURCE_DIR"); do
  mode=0644
  case "$path" in bin/server-connect|bin/sing-box|install.sh) mode=0755 ;; esac
  install -m "$mode" "$SOURCE_DIR/$path" "$stage/$path" ||
   die 'cannot stage checked release payload'
 done
 install -m 0644 "$SOURCE_DIR/checksums.sha256" "$stage/checksums.sha256" ||
  die 'cannot stage release checksum manifest'
 printf 'AChWorks/server-connect\n' > "$stage/.owner"
 chmod 0644 "$stage/.owner"
 chmod 0755 "$stage"
 verify_release_payload "$stage" || die 'staged release integrity failed'
 if [ "$prefix_created" = yes ];then
  # The copy/crash phase is kept outside PREFIX. Reparent only the complete
  # verified stage into the original release-auth.py managed namespace before
  # recording an authenticated receipt. This must not relax signed path trust.
  stage_inner="$PREFIX/releases/.stage.${stage##*.}"
  [ ! -e "$stage_inner" ] && [ ! -L "$stage_inner" ] ||
   die 'foreign first-release staging name exists'
  first_install_noreplace "$stage" "$stage_inner" ||
   die 'cannot atomically reparent initial release into signed namespace'
  [ "$(stat -c '%d:%i' "$stage_inner")" = "$first_release_inode" ] ||
   die 'first-release inode changed during namespace transition'
  stage=$stage_inner
 fi
 write_release_trust "$stage"
 verify_release_trust "$stage" || die 'staged release trust failed'
 # Mark the intended new release for rollback BEFORE publishing the final
 # directory. A signal between a successful rename and the next statement
 # must not orphan an unchecked release: cleanup still verifies its exact
 # owner and refuses any current-link consumer. The dev+inode receipt
 # distinguishes THIS renamed directory from an identical foreign candidate
 # that raced into the release name between preflight and publication.
 release_stage_identity=$(stat -c '%d:%i' "$stage") ||
  die 'staged release filesystem identity unavailable'
 [ -n "$release_stage_identity" ] || die 'staged release identity empty'
 release_created=yes
 # A foreign directory can appear even after the earlier absence check.
 # GNU mv -n refuses to replace it; verify identity because -n may return
 # success without moving anything. Both paths are on the same filesystem.
 mv -Tn -- "$stage" "$release" ||
  die 'candidate release publication failed'
 [ "$(stat -c '%d:%i' "$release" 2>/dev/null || :)" = "$release_stage_identity" ] ||
  die 'release name collision; foreign directory preserved'
 if [ "$local_qa" != yes ]; then
  # The receipt/file and stage directory were fsynced before publication.
  # Make the release-directory rename durable before selecting its binaries.
  python3 -I -S - "$PREFIX/releases" <<'PYSYNCRELEASE'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PYSYNCRELEASE
 fi
 stage=''
fi
chmod 0755 "$release"
if [ ! -d "$STATE/profiles" ];then install -d -m 0700 "$STATE/profiles";fi
check_root_dir "$STATE/profiles"
[ "$(stat -c '%a' "$STATE/profiles")" = 700 ] || die 'unsafe profile directory'

# Validate candidate against retained active runtime before touching service.
if [ -e "$STATE/runtime.json" ];then
 check_root_file "$STATE/runtime.json"
 "$release/bin/sing-box" check -c "$STATE/runtime.json" >/dev/null 2>&1 ||
  die 'candidate rejects retained runtime configuration; existing service unchanged'
fi

# Capture the EXACT prior supplemental unit bytes before the candidate can
# replace them. Guard is inactive by the preceding authoritative inspection.
guard_backup=$(mktemp -d "$PREFIX/.guard-backup.XXXXXXXX") || die 'guard unit backup unavailable'
for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-native-tun.service server-connect-smart-health.service server-connect-smart-health.timer;do
 if [ -f "/etc/systemd/system/$name" ];then
  install -m 0644 "/etc/systemd/system/$name" "$guard_backup/$name"
  install -m 0644 "$PREFIX/$name.sha256" "$guard_backup/$name.sha256"
 fi
done

if [ -f "$UNIT" ];then
 unit_backup=$(mktemp "$PREFIX/.unit-backup.XXXXXXXX") || die 'unit backup unavailable'
 install -m 0644 "$UNIT" "$unit_backup"
fi

# From this point any failure must restore the previous unit/release/service.
rollback_needed=yes
if [ "$was_active" = yes ];then
 systemctl stop server-connect.service || die 'owned service stop failed; rolling back'
fi
link_temp="$PREFIX/.current.$$"
ln -s "releases/$release_name" "$link_temp" || die 'candidate release link failed'
mv -Tf -- "$link_temp" "$PREFIX/current" || die 'candidate activation failed'

if [ ! -e "$COMMAND" ] && [ ! -L "$COMMAND" ];then
 ln -s "$PREFIX/current/bin/server-connect" "$COMMAND" || die 'owned command link failed'
 command_created=yes
fi
if [ "$prefix_created" = yes ];then
 first_install_atomic_unit "$SOURCE_DIR/server-connect.service" "$UNIT" ||
  die 'atomic first service publication failed'
else
 install -m 0644 "$SOURCE_DIR/server-connect.service" "$UNIT" ||
  die 'owned unit installation failed'
fi
sha256sum "$UNIT" | cut -d' ' -f1 > "$PREFIX/unit.sha256" || die 'owned unit digest write failed'
for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-native-tun.service server-connect-smart-health.service server-connect-smart-health.timer;do
 if [ "$prefix_created" = yes ];then
  first_install_atomic_unit "$SOURCE_DIR/$name" "/etc/systemd/system/$name" ||
   die 'atomic first supplemental unit publication failed'
 else
  install -m 0644 "$SOURCE_DIR/$name" "/etc/systemd/system/$name" ||
   die 'managed unit installation failed'
 fi
 sha256sum "/etc/systemd/system/$name" | cut -d' ' -f1 > "$PREFIX/$name.sha256" ||
  die 'managed unit digest write failed'
 chmod 0644 "$PREFIX/$name.sha256" || die 'managed unit digest mode failed'
done
chmod 0644 "$PREFIX/unit.sha256" || die 'unit digest permissions failed'
systemctl daemon-reload || die 'systemd daemon reload failed'
check_guard_units

"$PREFIX/current/bin/server-connect" installer-check-service >/dev/null ||
 die 'installed unit provenance could not be verified'
if [ "$was_active" = yes ];then
 systemctl start server-connect.service || die 'updated service start failed'
 "$PREFIX/current/bin/server-connect" ready --json >/dev/null ||
  die 'updated service listener readiness failed'
else
 # An owned crashed/inactive service may remain enabled; committed Direct
 # must be *both* inactive and disabled before discarding runtime credentials.
 systemctl disable server-connect.service ||
  die 'cannot disable owned inactive service before Direct reconciliation'
 "$PREFIX/current/bin/server-connect" installer-reconcile-direct >/dev/null ||
  die 'Direct state reconciliation failed after installation'
 if systemctl is-failed --quiet server-connect.service;then
  systemctl reset-failed server-connect.service ||
   die 'cannot reconcile historical owned service failure state'
 fi
fi
# Retire only the receipt for the exact installed prefix. Interrupted
# operations retain the private claim for a bounded verified retry.
if [ "$prefix_created" = yes ];then
 # Completion is recognized by the exact installed release+systemd ownership
 # and matching initial-prefix/release-inode receipts, never by a name alone.
 # Any SIGKILL between unlinks is an idempotently recoverable committed state.
 first_install_is_committed ||
  die 'completed installation identity cannot be proven; preserve claims'
 operation_done=yes
 first_install_retire_committed_claims
fi
operation_done=yes
rollback_needed=no
say "local verified payload installed at $release; Direct preserved unless an owned proxy was already active"
if [ "$local_qa" = yes ]; then
 say 'LOCAL QA ONLY: checksums confirm byte integrity; no publisher authenticity asserted'
elif [ "${unsigned_release:-no}" = yes ]; then
 say 'SHA256 integrity verified; source trust is the selected HTTPS host or manually uploaded files, not a publisher signature'
else
 say 'Signed legacy QA payload verified; public release approval remains separate'
fi
