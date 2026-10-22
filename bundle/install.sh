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
check_platform() {
 [ "$(uname -m)" = x86_64 ] || die 'unsupported CPU; this candidate supports only x86_64'
 [ -r /etc/os-release ] || die 'missing /etc/os-release'
 # shellcheck disable=SC1091
 . /etc/os-release
 [ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ] || die 'unsupported OS; this candidate targets Debian 13 only'
 need systemctl; need sha256sum; need install; need mktemp; need readlink; need cmp; need mv; need tar; need stat; need flock
 [ -d /run/systemd/system ] || die 'systemd is not PID 1; use a supported systemd host'
}
verify_payload() {
 for name in bin/server-connect bin/sing-box bin/libcronet.so server-connect.service install.sh THIRD-PARTY-LICENSES/sing-box-LICENSE manifest.json; do
  check_root_file "$SOURCE_DIR/$name"
 done
 check_root_file "$SOURCE_DIR/checksums.sha256"
 check_root_dir "$SOURCE_DIR"
 check_root_dir "$(dirname -- "$SOURCE_DIR")"
 (cd "$SOURCE_DIR" && sha256sum --quiet -c checksums.sha256) || die 'bundle checksum mismatch; no changes applied'
 version=$($SOURCE_DIR/bin/server-connect version --json) || die 'candidate manager fails version check'
 echo "$version" | grep -q '"sing_box":"1.14.3"' || die 'manager requires a different core version'
 core=$($SOURCE_DIR/bin/sing-box version 2>/dev/null | head -n 1) || die 'candidate sing-box not executable'
 [ "$core" = 'sing-box version 1.14.3' ] || die 'unexpected sing-box core version'
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
  case "$(readlink "$PREFIX/current")" in releases/[a-zA-Z0-9._-]*) ;; *) die 'invalid current release link' ;; esac
 fi
 if [ -e "$STATE" ] || [ -L "$STATE" ]; then
  check_root_dir "$STATE"
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
verify_payload
check_owned

if [ "$ACTION" = --verify-only ]; then say 'local bundle and owned-resource preflight PASS; publisher signature must be independently verified'; exit 0;fi

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
check_owned
if [ -f "$UNIT" ]; then
 "$SOURCE_DIR/bin/server-connect" installer-check-service >/dev/null ||
  die 'effective installed systemd unit provenance conflict'
fi

if [ "$ACTION" = --uninstall ]; then
 [ -f "$PREFIX/.owner" ] || die 'Server Connect not installed'
 # Validate all release ownership before destructive changes to the service/unit.
 if [ -d "$PREFIX/releases" ]; then
  check_root_dir "$PREFIX/releases"
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
 "$SOURCE_DIR/bin/server-connect" installer-reconcile-direct >/dev/null ||
  die 'proxy stopped but retained Direct intent could not be reconciled; uninstall aborted'
 if systemctl is-failed --quiet server-connect.service; then
  systemctl reset-failed server-connect.service || say 'WARNING: failed owned service state could not be cleared'
 fi
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
# The shared .lock is held across observation, activation and rollback.
release_hash=$(sha256sum "$SOURCE_DIR/bin/server-connect" "$SOURCE_DIR/bin/sing-box" | cut -d' ' -f1 | sha256sum | cut -c 1-16)
release_name="0.1.0-dev-$release_hash"
release="$PREFIX/releases/$release_name"
previous=''
if [ -L "$PREFIX/current" ]; then previous=$(readlink "$PREFIX/current");fi
was_active=no
if systemctl is-active --quiet server-connect.service; then was_active=yes;fi
[ -z "$previous" ] || [ -f "$UNIT" ] || die 'previous owned release has no systemd unit; repair via console before update'

prefix_created=no
command_created=no
release_created=no
unit_backup=''
stage=''
rollback_needed=no
operation_done=no

remove_backup() {
 if [ -n "$unit_backup" ] && [ -f "$unit_backup" ];then rm -f -- "$unit_backup";fi
}
rollback_candidate() {
 # Do not claim rollback if a stop, restore or previous restart failed.
 # Never touch a unit beyond the verified product-owned identity.
 set +e
 failed=no
 say 'candidate failed; attempting owned lifecycle rollback'
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
  if [ "$command_created" = yes ] && [ -L "$COMMAND" ] &&
     [ "$(readlink "$COMMAND")" = "$PREFIX/current/bin/server-connect" ];then
    rm -f -- "$COMMAND" || { say 'RECOVERY_REQUIRED: new command link removal failed';failed=yes; }
  fi
  systemctl daemon-reload || { say 'RECOVERY_REQUIRED: systemd reload failed';failed=yes; }
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
  rm -f -- "$release/bin/server-connect" "$release/bin/sing-box" "$release/bin/libcronet.so"     "$release/THIRD-PARTY-LICENSES/sing-box-LICENSE" "$release/.owner" ||
     { say 'RECOVERY_REQUIRED: candidate release file cleanup failed';failed=yes; }
  rmdir "$release/bin" "$release/THIRD-PARTY-LICENSES" "$release" 2>/dev/null ||
    { say 'RECOVERY_REQUIRED: candidate release directory retained';failed=yes; }
 fi
 if [ "$failed" = no ] && [ "$prefix_created" = yes ];then
  # Fresh install failed: no previous release/command/unit was present.
  rm -f -- "$PREFIX/.owner" || failed=yes
  rmdir "$PREFIX/releases" "$PREFIX" 2>/dev/null ||
    { say 'RECOVERY_REQUIRED: new installation directory retained';failed=yes; }
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
 remove_backup
 exit "$code"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ ! -d "$PREFIX" ];then
 install -d -m 0755 "$PREFIX"
 printf 'AChWorks/server-connect\n' > "$PREFIX/.owner"
 chmod 0644 "$PREFIX/.owner"
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
 for path in bin/server-connect bin/sing-box bin/libcronet.so THIRD-PARTY-LICENSES/sing-box-LICENSE;do
  check_root_file "$release/$path"
  cmp -s "$SOURCE_DIR/$path" "$release/$path" || die "existing release differs from candidate: $path"
 done
else
 stage=$(mktemp -d "$PREFIX/releases/.stage.XXXXXXXX") || die 'cannot stage release'
 install -d -m 0755 "$stage/bin" "$stage/THIRD-PARTY-LICENSES"
 install -m 0755 "$SOURCE_DIR/bin/server-connect" "$stage/bin/server-connect"
 install -m 0755 "$SOURCE_DIR/bin/sing-box" "$stage/bin/sing-box"
 install -m 0644 "$SOURCE_DIR/bin/libcronet.so" "$stage/bin/libcronet.so"
 install -m 0644 "$SOURCE_DIR/THIRD-PARTY-LICENSES/sing-box-LICENSE" "$stage/THIRD-PARTY-LICENSES/sing-box-LICENSE"
 printf 'AChWorks/server-connect\n' > "$stage/.owner"
 chmod 0644 "$stage/.owner"
 chmod 0755 "$stage"
 mv -- "$stage" "$release"
 stage=''
 release_created=yes
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
install -m 0644 "$SOURCE_DIR/server-connect.service" "$UNIT" || die 'owned unit installation failed'
sha256sum "$UNIT" | cut -d' ' -f1 > "$PREFIX/unit.sha256" || die 'owned unit digest write failed'
chmod 0644 "$PREFIX/unit.sha256" || die 'unit digest permissions failed'
systemctl daemon-reload || die 'systemd daemon reload failed'

"$PREFIX/current/bin/server-connect" installer-check-service >/dev/null ||
 die 'installed unit provenance could not be verified'
if [ "$was_active" = yes ];then
 systemctl start server-connect.service || die 'updated service start failed'
 "$PREFIX/current/bin/server-connect" ready --json >/dev/null ||
  die 'updated service listener readiness failed'
else
 # Never silently reactivate a proxy retained from an old uninstall.
 "$PREFIX/current/bin/server-connect" installer-reconcile-direct >/dev/null ||
  die 'Direct state reconciliation failed after installation'
fi
operation_done=yes
rollback_needed=no
say "local verified payload installed at $release; Direct preserved unless an owned proxy was already active"
say 'Bundle checksums confirm byte integrity only; release authenticity requires independently trusted provenance'
