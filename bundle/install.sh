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
 [ -r /etc/os-release ] || die 'missing /etc/os-release'
 # shellcheck disable=SC1091
 . /etc/os-release
 [ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ] || die 'unsupported OS; this candidate targets Debian 13 only'
 need systemctl; need sha256sum; need install; need mktemp; need readlink; need cmp; need mv; need tar; need stat; need flock
 [ -d /run/systemd/system ] || die 'systemd is not PID 1; use a supported systemd host'
}
verify_payload() {
 for name in bin/server-connect bin/sing-box bin/libcronet.so server-connect.service server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer install.sh THIRD-PARTY-LICENSES/sing-box-LICENSE manifest.json; do
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
  [ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] ||
   die 'partial product installation lacks a verified loaded unit; repair via console'
  unit_identity=absent
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
check_guard_units() {
 for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer; do
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
   if [ "$name" = server-connect-smart-tun.service ] || [ "$name" = server-connect-smart-health.service ]; then
    [ "$(systemctl show "$name" -p UnitFileState --value)" = static ] ||
      die 'TUN and health executors must remain static and unenabled'
   fi
  else
   [ "$load" = not-found ] && [ -z "$fragment" ] && [ -z "$dropins" ] && [ "$transient" = no ] ||
    die 'foreign recovery unit name already registered'
  fi
 done
}
# An active timer or oneshot may own pending kernel state. Updating or
# uninstalling its recovery executable would sever the only independent guard.
require_guard_inactive() {
 for name in server-connect-activation-recover.timer server-connect-activation-recover.service server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer; do
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
check_source_ancestry
check_platform
verify_payload
check_owned
check_service_owner
check_guard_units

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
"$SOURCE_DIR/bin/server-connect" installer-check-guard-clear >/dev/null ||
 die 'pending, uncertain or invalid activation journal; refuse installer mutation'
check_owned
check_service_owner
if [ "$unit_identity" = owned ]; then
 "$SOURCE_DIR/bin/server-connect" installer-check-service >/dev/null ||
  die 'effective installed systemd unit provenance conflict'
fi

if [ "$ACTION" = --uninstall ]; then
 require_guard_inactive
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
 for timer in server-connect-activation-recover.timer server-connect-smart-health.timer; do
  if [ -f "/etc/systemd/system/$timer" ]; then
   systemctl disable "$timer" || die 'cannot disable owned recovery/health timer'
  fi
 done
 rm -f -- "$COMMAND" "$UNIT" "$PREFIX/current" "$PREFIX/unit.sha256" "$PREFIX/.owner" \
  "$GUARD_SERVICE" "$GUARD_TIMER" /etc/systemd/system/server-connect-smart-tun.service \
  "$PREFIX/server-connect-activation-recover.service.sha256" \
  "$PREFIX/server-connect-activation-recover.timer.sha256" \
  "$PREFIX/server-connect-smart-tun.service.sha256" \
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
require_guard_inactive
# The shared .lock is held across observation, activation and rollback.
# Bind the installed release identity to the verified exact binary bytes in
# one assignment. A malformed or absent hash must not be interpreted as a
# valid named release or proceed into service changes.
release_name="0.1.0-dev-$(sha256sum "$SOURCE_DIR/bin/server-connect" "$SOURCE_DIR/bin/sing-box" | cut -d' ' -f1 | sha256sum | cut -c 1-16)"
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
  for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer;do
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
  rm -f -- "$release/bin/server-connect" "$release/bin/sing-box" "$release/bin/libcronet.so"     "$release/THIRD-PARTY-LICENSES/sing-box-LICENSE" "$release/.owner" ||
     { say 'RECOVERY_REQUIRED: candidate release file cleanup failed';failed=yes; }
  rmdir "$release/bin" "$release/THIRD-PARTY-LICENSES" "$release" 2>/dev/null ||
    { say 'RECOVERY_REQUIRED: candidate release directory retained';failed=yes; }
 fi
 if [ "$failed" = no ] && [ "$prefix_created" = yes ];then
  remove_backup
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

# Capture the EXACT prior supplemental unit bytes before the candidate can
# replace them. Guard is inactive by the preceding authoritative inspection.
guard_backup=$(mktemp -d "$PREFIX/.guard-backup.XXXXXXXX") || die 'guard unit backup unavailable'
for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer;do
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
install -m 0644 "$SOURCE_DIR/server-connect.service" "$UNIT" || die 'owned unit installation failed'
sha256sum "$UNIT" | cut -d' ' -f1 > "$PREFIX/unit.sha256" || die 'owned unit digest write failed'
for name in server-connect-activation-recover.service server-connect-activation-recover.timer server-connect-smart-tun.service server-connect-smart-health.service server-connect-smart-health.timer;do
 install -m 0644 "$SOURCE_DIR/$name" "/etc/systemd/system/$name" || die 'managed unit installation failed'
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
operation_done=yes
rollback_needed=no
say "local verified payload installed at $release; Direct preserved unless an owned proxy was already active"
say 'Bundle checksums confirm byte integrity only; release authenticity requires independently trusted provenance'
