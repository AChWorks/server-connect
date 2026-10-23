#!/bin/sh
# Development bootstrap. Public one-line channel is gated on publisher signing.
# Supply an independently trusted 64-character SHA-256 digest.
set -eu
umask 077
# This script may run as root. Never resolve tools from a caller-controlled PATH,
# load curlrc options, or let GNU tar/gzip environment variables change parsing.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset TAR_OPTIONS GZIP GZIP_OPT
url=''
digest=''
verify_only=no
while [ "$#" -gt 0 ]; do
 case "$1" in
  --archive-url) [ "$#" -ge 2 ] || exit 2; url=$2;shift 2;;
  --sha256) [ "$#" -ge 2 ] || exit 2; digest=$2;shift 2;;
  --verify-only)verify_only=yes;shift;;
  *) echo 'Usage: bootstrap-online.sh --archive-url HTTPS_URL --sha256 TRUSTED_DIGEST [--verify-only]' >&2;exit 2;;
 esac
done
case "$url" in https://*|http://127.0.0.1:*|http://localhost:*) ;; *) echo 'Only HTTPS release endpoints (or isolated local test hosts) are supported' >&2; exit 2;; esac
[ "${#digest}" -eq 64 ] || { echo 'A trusted 64-character SHA-256 digest is required' >&2;exit 2; }
case "$digest" in *[!0123456789abcdefABCDEF]*) echo 'Invalid digest syntax' >&2;exit 2;; esac
command -v curl >/dev/null 2>&1 || { echo 'A supported downloader (curl) is required for the online bootstrap' >&2;exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required' >&2;exit 1; }
command -v tar >/dev/null 2>&1 || { echo 'tar is required' >&2;exit 1; }
command -v stat >/dev/null 2>&1 || { echo 'stat is required for trusted staging' >&2;exit 1; }
# Privileged installation requires root-owned staging from the first download.
# Root authority is acquired before network acquisition, never after a user
# controls a temporary archive/extraction directory.
user_id=$(id -u)
if [ "$verify_only" != yes ] && [ "$user_id" -ne 0 ];then
 echo 'Run the online installation command as root; non-root --verify-only is supported.' >&2
 exit 1
fi
if [ "$user_id" -eq 0 ];then
 # Ignore TMPDIR even for --verify-only as root. An attacker-owned parent can
 # rename a temporary tree between verification and privileged installation.
 [ -d /root ] && [ ! -L /root ] && [ "$(stat -c '%u' /root)" = 0 ] ||
  { echo 'No trusted root-owned staging parent at /root' >&2;exit 1; }
 root_mode=$(stat -c '%a' /root) || exit 1
 [ "$((0$root_mode & 022))" -eq 0 ] ||
  { echo 'Root staging parent is group/other writable' >&2;exit 1; }
 work=$(mktemp -d /root/.server-connect-bootstrap.XXXXXXXX) || exit 1
else
 work=$(mktemp -d) || exit 1
fi
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
# Download a complete offline artifact: no secondary/floating prerequisites.
case "$url" in
 https://*) allowed_proto='=https';;
 *) allowed_proto='=http,https';;
esac
if ! curl -q --fail --location --proto "$allowed_proto" --proto-redir "$allowed_proto" --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 --output "$work/bundle.tar.gz" "$url";then
 echo 'Online acquisition failed without installation changes. Use the complete offline bundle instead.' >&2
 exit 1
fi
printf '%s  %s\n' "$digest" "$work/bundle.tar.gz" | sha256sum --quiet --check - || { echo 'Publisher-supplied independent digest mismatch' >&2;exit 1; }
# Metadata must be fully readable before extraction. Reject dangerous member
# types, repetitions, traversal, control chars and unbounded expansion.
archive_bytes=$(wc -c < "$work/bundle.tar.gz")
[ "$archive_bytes" -le 1073741824 ] || { echo 'Archive exceeds supported 1 GiB compressed size' >&2;exit 1; }
tar -tzf "$work/bundle.tar.gz" > "$work/names.txt" ||
 { echo 'Malformed archive entry listing' >&2;exit 1; }
tar -tvzf "$work/bundle.tar.gz" > "$work/members.txt" ||
 { echo 'Malformed archive metadata' >&2;exit 1; }
LC_ALL=C awk '
 BEGIN {seen=0; bad=0}
 {
  seen++
  if ($0 !~ /^server-connect\// || $0 ~ /(^|\/)\.\.(\/|$)/ || $0 ~ /(^|\/)\.(\/|$)/ ||
   $0 ~ /\/\// || $0 ~ /\\/ || $0 ~ /[[:cntrl:]]/) bad=1
 }
 END {if (bad || seen==0 || seen>10000) exit 1}
' "$work/names.txt" || { echo 'Unsafe archive name or excessive entries' >&2;exit 1; }
if LC_ALL=C sort "$work/names.txt" | uniq -d | grep -q .;then
 echo 'Duplicate archive member path; refusing extraction' >&2;exit 1
fi
LC_ALL=C awk '
 BEGIN {count=0; total=0;bad=0}
 {
  count++
  type=substr($1,1,1)
  if ((type!="-" && type!="d") || $3 !~ /^[0-9]+$/) bad=1
  total+=$3
  if ($3>4294967296 || total>8589934592) bad=1
 }
 END {if (bad || count==0 || count>10000) exit 1}
' "$work/members.txt" || { echo 'Unsupported archive member type or expanded size' >&2;exit 1; }
tar -xzf "$work/bundle.tar.gz" -C "$work" --no-same-owner --no-same-permissions
[ -f "$work/server-connect/install.sh" ] && [ ! -L "$work/server-connect/install.sh" ] || { echo 'Missing local installer' >&2;exit 1; }
if [ "$verify_only" = yes ];then
 echo 'Online fetch, trusted digest and archive layout: verified. Installation was not attempted.'
 exit 0
fi
sh "$work/server-connect/install.sh" --offline
