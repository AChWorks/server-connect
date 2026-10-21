#!/bin/sh
# Development bootstrap. Public one-line channel is gated on publisher signing.
# Supply an independently trusted 64-character SHA-256 digest.
set -eu
umask 077
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
work=$(mktemp -d) || exit 1
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
# Download a complete offline artifact: no secondary/floating prerequisites.
if ! curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 --output "$work/bundle.tar.gz" "$url";then
 echo 'Online acquisition failed without installation changes. Use the complete offline bundle instead.' >&2
 exit 1
fi
printf '%s  %s\n' "$digest" "$work/bundle.tar.gz" | sha256sum --quiet --check - || { echo 'Publisher-supplied independent digest mismatch' >&2;exit 1; }
# Do not let an archive member escape the private extraction directory.
# An accepted top-level prefix alone does not reject server-connect/../../etc.
if ! tar -tzf "$work/bundle.tar.gz" | LC_ALL=C awk '
  BEGIN {seen=0; invalid=0}
  {
    seen++
    if ($0 !~ /^server-connect\// || $0 ~ /(^|\/)\.\.(\/|$)/ || $0 ~ /(^|\/)\.(\/|$)/ || $0 ~ /\/\// || $0 ~ /\\/ || $0 ~ /[[:cntrl:]]/) invalid=1
  }
  END {if (seen==0 || invalid) exit 1}
';then echo 'Unsafe archive entry; refusing extraction' >&2;exit 1;fi
if tar -tvzf "$work/bundle.tar.gz" | LC_ALL=C grep -E '^[lh]' >/dev/null;then echo 'Archive contains link entries; refusing extraction' >&2; exit 1;fi
tar -xzf "$work/bundle.tar.gz" -C "$work" --no-same-owner --no-same-permissions
[ -f "$work/server-connect/install.sh" ] && [ ! -L "$work/server-connect/install.sh" ] || { echo 'Missing local installer' >&2;exit 1; }
if [ "$verify_only" = yes ];then
 echo 'Online fetch, trusted digest and archive layout: verified. Installation was not attempted.'
 exit 0
fi
if [ "$(id -u)" -eq 0 ];then
 sh "$work/server-connect/install.sh" --offline
else
 command -v sudo >/dev/null 2>&1 || { echo 'sudo required for privileged installation' >&2;exit 1; }
 sudo sh "$work/server-connect/install.sh" --offline
fi
