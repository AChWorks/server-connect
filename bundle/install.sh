#!/bin/sh
# Server Connect local installer: no curl, wget, APT or host route modification.
set -eu
umask 077

PREFIX=/opt/server-connect
STATE=/var/lib/server-connect
UNIT=/etc/systemd/system/server-connect.service
COMMAND=/usr/local/bin/server-connect
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ACTION=${1:---offline}

say() { printf 'Server Connect: %s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required host tool: $1"; }
check_dir() { [ -d "$1" ] && [ ! -L "$1" ] || die "unsafe or missing directory: $1"; }
require_root() { [ "$(id -u)" -eq 0 ] || die 'run as root with sudo'; }
check_platform() {
 [ "$(uname -m)" = x86_64 ] || die 'unsupported CPU; this candidate supports only x86_64'
 [ -r /etc/os-release ] || die 'missing /etc/os-release'
 # shellcheck disable=SC1091
 . /etc/os-release
 [ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ] || die 'unsupported OS; this candidate targets Debian 13 only'
 need systemctl; need sha256sum; need install; need mktemp; need readlink; need cmp; need mv; need tar
 [ -d /run/systemd/system ] || die 'systemd is not PID 1; use a supported systemd host'
}
verify_payload() {
 for name in bin/server-connect bin/sing-box bin/libcronet.so server-connect.service install.sh THIRD-PARTY-LICENSES/sing-box-LICENSE manifest.json; do
  [ -f "$SOURCE_DIR/$name" ] && [ ! -L "$SOURCE_DIR/$name" ] || die "missing or unsafe bundle file: $name"
 done
 [ -f "$SOURCE_DIR/checksums.sha256" ] && [ ! -L "$SOURCE_DIR/checksums.sha256" ] || die 'missing checksum manifest'
 (cd "$SOURCE_DIR" && sha256sum --quiet -c checksums.sha256) || die 'bundle checksum mismatch; no changes applied'
 version=$($SOURCE_DIR/bin/server-connect version --json) || die 'candidate manager fails version check'
 echo "$version" | grep -q '"sing_box":"1.14.3"' || die 'manager requires a different core version'
 core=$($SOURCE_DIR/bin/sing-box version 2>/dev/null | head -n 1) || die 'candidate sing-box not executable'
 [ "$core" = 'sing-box version 1.14.3' ] || die 'unexpected sing-box core version'
}
check_owned() {
 if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then
  check_dir "$PREFIX"
  [ -f "$PREFIX/.owner" ] && [ ! -L "$PREFIX/.owner" ] || die 'unowned install root'
  [ "$(cat "$PREFIX/.owner")" = 'AChWorks/server-connect' ] || die 'unowned install root'
 fi
 if [ -e "$COMMAND" ] || [ -L "$COMMAND" ]; then
  [ -L "$COMMAND" ] && [ "$(readlink "$COMMAND")" = "$PREFIX/current/bin/server-connect" ] || die "unowned executable at $COMMAND"
 fi
 if [ -e "$UNIT" ] || [ -L "$UNIT" ]; then
  [ -f "$UNIT" ] && [ ! -L "$UNIT" ] || die 'unowned systemd unit'
  [ -r "$PREFIX/unit.sha256" ] || die 'unit ownership record missing'
  printf '%s  %s\n' "$(cat "$PREFIX/unit.sha256")" "$UNIT" | sha256sum --quiet -c - || die 'systemd unit changed externally; refusing overwrite'
 fi
 if [ -e "$PREFIX/current" ] || [ -L "$PREFIX/current" ]; then
  [ -L "$PREFIX/current" ] || die 'unowned current release path'
  case "$(readlink "$PREFIX/current")" in releases/[a-zA-Z0-9._-]*) ;; *) die 'invalid current release link' ;; esac
 fi
 if [ -e "$STATE" ] || [ -L "$STATE" ]; then
  check_dir "$STATE"
  perms=$(stat -c '%a' "$STATE")
  [ "$perms" = 700 ] || die "unsafe private state permissions: $perms"
 fi
}

if [ "$ACTION" = --help ]; then
 say 'Usage: sudo sh install.sh --offline | --verify-only | --uninstall'
 exit 0
fi
case "$ACTION" in --offline|--verify-only|--uninstall) ;; *) die 'only --offline, --verify-only, --uninstall supported; online bootstrap fetches a verified bundle first' ;; esac
require_root
check_platform
if [ "$ACTION" != --uninstall ]; then verify_payload;fi
check_owned

if [ "$ACTION" = --verify-only ]; then say 'local bundle and owned-resource preflight PASS; publisher signature must be independently verified'; exit 0;fi

if [ "$ACTION" = --uninstall ]; then
 [ -f "$PREFIX/.owner" ] || die 'Server Connect not installed'
 # Validate all release ownership before destructive changes to the service/unit.
 if [ -d "$PREFIX/releases" ]; then
  check_dir "$PREFIX/releases"
  for release in "$PREFIX"/releases/*; do
   [ -d "$release" ] || continue
   [ ! -L "$release" ] || die 'unsafe release symlink'
   [ -f "$release/.owner" ] && [ ! -L "$release/.owner" ] && [ "$(cat "$release/.owner")" = 'AChWorks/server-connect' ] || die 'unowned release content; uninstall aborted'
   check_dir "$release/bin"
   check_dir "$release/THIRD-PARTY-LICENSES"
   for path in bin/server-connect bin/sing-box bin/libcronet.so THIRD-PARTY-LICENSES/sing-box-LICENSE; do
    [ -f "$release/$path" ] && [ ! -L "$release/$path" ] || die "release content modified: $path"
   done
  done
 fi
 systemctl stop server-connect.service || die 'cannot stop owned proxy; uninstall aborted'
 systemctl disable server-connect.service || die 'cannot disable owned proxy; uninstall aborted'
 rm -f -- "$COMMAND" "$UNIT" "$PREFIX/current" "$PREFIX/unit.sha256" "$PREFIX/.owner"
 systemctl daemon-reload || die 'unit removed but daemon-reload failed; inspect systemd'
 if [ -d "$PREFIX/releases" ] && [ ! -L "$PREFIX/releases" ]; then
  for release in "$PREFIX"/releases/*; do
   [ -d "$release" ] || continue
   [ ! -L "$release" ] || die 'unsafe release symlink retained'
   [ -f "$release/.owner" ] && [ "$(cat "$release/.owner")" = 'AChWorks/server-connect' ] || die 'release ownership conflict; preserve for inspection'
   rm -f -- "$release/bin/server-connect" "$release/bin/sing-box" "$release/bin/libcronet.so" "$release/THIRD-PARTY-LICENSES/sing-box-LICENSE" "$release/.owner"
   rmdir "$release/bin" "$release/THIRD-PARTY-LICENSES" "$release" 2>/dev/null || say "retained modified release at $release"
  done
  rmdir "$PREFIX/releases" 2>/dev/null || true
 fi
 rmdir "$PREFIX" 2>/dev/null || true
 say "uninstalled managed binaries and unit; private profiles retained under $STATE"
 exit 0
fi

# Installation and offline update share this path. No networking is performed.
release_hash=$(sha256sum "$SOURCE_DIR/bin/server-connect" "$SOURCE_DIR/bin/sing-box" | cut -d' ' -f1 | sha256sum | cut -c 1-16)
release_name="0.1.0-dev-$release_hash"
release="$PREFIX/releases/$release_name"
previous=''
if [ -L "$PREFIX/current" ]; then previous=$(readlink "$PREFIX/current"); fi
was_active=no
if systemctl is-active --quiet server-connect.service; then was_active=yes; fi

if [ ! -d "$PREFIX" ]; then install -d -m 0755 "$PREFIX";printf 'AChWorks/server-connect\n' > "$PREFIX/.owner";chmod 0644 "$PREFIX/.owner";fi
if [ -e "$PREFIX/releases" ] || [ -L "$PREFIX/releases" ]; then
 check_dir "$PREFIX/releases"
else
 install -d -m 0755 "$PREFIX/releases"
fi
if [ -e "$release" ] || [ -L "$release" ]; then
 check_dir "$release"
 [ -f "$release/.owner" ] && [ ! -L "$release/.owner" ] && [ "$(cat "$release/.owner")" = 'AChWorks/server-connect' ] || die 'unowned candidate release directory'
 for path in bin/server-connect bin/sing-box bin/libcronet.so THIRD-PARTY-LICENSES/sing-box-LICENSE; do
  [ -f "$release/$path" ] && [ ! -L "$release/$path" ] || die "candidate release missing owned file: $path"
  cmp -s "$SOURCE_DIR/$path" "$release/$path" || die "existing release differs from candidate: $path"
 done
fi
if [ ! -d "$release" ]; then
 stage=$(mktemp -d "$PREFIX/releases/.stage.XXXXXXXX") || die 'cannot stage release'
 install -d -m 0755 "$stage/bin" "$stage/THIRD-PARTY-LICENSES"
 install -m 0755 "$SOURCE_DIR/bin/server-connect" "$stage/bin/server-connect"
 install -m 0755 "$SOURCE_DIR/bin/sing-box" "$stage/bin/sing-box"
 install -m 0644 "$SOURCE_DIR/bin/libcronet.so" "$stage/bin/libcronet.so"
 install -m 0644 "$SOURCE_DIR/THIRD-PARTY-LICENSES/sing-box-LICENSE" "$stage/THIRD-PARTY-LICENSES/sing-box-LICENSE"
 printf 'AChWorks/server-connect\n' > "$stage/.owner";chmod 0644 "$stage/.owner"
 # mktemp creates 0700 directories; the unprivileged systemd DynamicUser
 # must traverse the root-owned executable release directory after install.
 chmod 0755 "$stage"
 mv -- "$stage" "$release"
fi
# An exact, identity-verified prior candidate may have the old 0700 mode.
# Correct only the verified product-owned release, never a foreign tree.
chmod 0755 "$release"
if [ ! -d "$STATE" ]; then install -d -m 0700 "$STATE";fi
if [ ! -d "$STATE/profiles" ]; then install -d -m 0700 "$STATE/profiles";fi
check_dir "$STATE/profiles"
if [ "$(stat -c '%a' "$STATE/profiles")" != 700 ]; then die 'unsafe profile directory; manual correction required';fi

# Prevalidate any existing runtime with candidate core BEFORE interrupting it.
if [ -e "$STATE/runtime.json" ]; then
 [ -f "$STATE/runtime.json" ] && [ ! -L "$STATE/runtime.json" ] || die 'unsafe runtime config path'
 "$release/bin/sing-box" check -c "$STATE/runtime.json" >/dev/null 2>&1 || die 'candidate rejected existing runtime; no service change applied'
fi

unit_backup=''
if [ -f "$UNIT" ]; then
 unit_backup=$(mktemp "$PREFIX/.unit-backup.XXXXXXXX") || die 'cannot reserve unit backup'
 install -m 0644 "$UNIT" "$unit_backup"
fi
remove_backup() {
 if [ -n "$unit_backup" ] && [ -f "$unit_backup" ]; then rm -f -- "$unit_backup";fi
}
trap remove_backup EXIT HUP INT TERM
rollback_candidate() {
 say 'candidate failed; restoring previous owned release and unit'
 systemctl stop server-connect.service || say 'WARNING: stop of failed candidate was not confirmed'
 if [ -n "$previous" ]; then
  ln -s "$previous" "$PREFIX/.restore.$$" && mv -Tf -- "$PREFIX/.restore.$$" "$PREFIX/current" || say 'WARNING: prior release link restoration failed'
 else
  rm -f -- "$PREFIX/current"
 fi
 if [ -n "$unit_backup" ]; then
  install -m 0644 "$unit_backup" "$UNIT" || say 'WARNING: unit restoration failed'
  sha256sum "$UNIT" | cut -d' ' -f1 > "$PREFIX/unit.sha256" || say 'WARNING: unit identity restoration failed'
 else
  rm -f -- "$UNIT" "$PREFIX/unit.sha256"
 fi
 systemctl daemon-reload || say 'WARNING: systemd reload failed during recovery'
 if [ "$was_active" = yes ]; then
  if systemctl start server-connect.service; then
   "$PREFIX/current/bin/server-connect" ready --json >/dev/null || say 'WARNING: previous proxy readiness was not restored'
  else
   say 'WARNING: previous proxy service restart failed'
  fi
 fi
}
if [ "$was_active" = yes ]; then
 systemctl stop server-connect.service || die 'cannot stop owned running service; update aborted'
fi
link_temp="$PREFIX/.current.$$"
ln -s "releases/$release_name" "$link_temp" || { rollback_candidate;die 'cannot stage release symlink'; }
if ! mv -Tf -- "$link_temp" "$PREFIX/current"; then
 rm -f -- "$link_temp"
 rollback_candidate
 die 'cannot activate release link'
fi
if [ ! -e "$COMMAND" ]; then
 ln -s "$PREFIX/current/bin/server-connect" "$COMMAND" || { rollback_candidate;die 'cannot create owned executable link'; }
fi
install -m 0644 "$SOURCE_DIR/server-connect.service" "$UNIT" || { rollback_candidate;die 'cannot install unit'; }
sha256sum "$UNIT" | cut -d' ' -f1 > "$PREFIX/unit.sha256"
chmod 0644 "$PREFIX/unit.sha256"
if ! systemctl daemon-reload; then
 rollback_candidate
 die 'systemd reload failed; previous owned unit/release restoration attempted'
fi
if [ "$was_active" = yes ]; then
 if ! systemctl start server-connect.service || ! "$PREFIX/current/bin/server-connect" ready --json >/dev/null; then
  rollback_candidate
  die 'updated service readiness failed; previous owned unit/release restoration attempted'
 fi
fi
say "local verified payload installed at $release; Direct preserved unless an owned proxy was already active"
say 'Bundle checksums confirm byte integrity only; release authenticity requires independently trusted provenance'
