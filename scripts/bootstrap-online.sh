#!/bin/sh
# Development bootstrap. Public one-line channel is gated on publisher signing.
# Supply an independently trusted 64-character SHA-256 digest.
set -eu
umask 077
# Privileged entry must be through trusted sudo + env -i BEFORE this
# interpreter is started. These resets further constrain subprocesses, but
# cannot protect a shell/loader already initialized by a hostile root env.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset TAR_OPTIONS GZIP GZIP_OPT ENV BASH_ENV CDPATH
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_ORIGIN_PATH
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP
url=''
digest=''
verify_only=no
# This ceiling is enforced by curl WHILE receiving bytes, including when
# the peer streams with no Content-Length. Operators may only lower it.
max_download_bytes=1073741824
while [ "$#" -gt 0 ]; do
 case "$1" in
  --archive-url) [ "$#" -ge 2 ] || exit 2; url=$2;shift 2;;
  --sha256) [ "$#" -ge 2 ] || exit 2; digest=$2;shift 2;;
  --verify-only)verify_only=yes;shift;;
  --max-download-bytes) [ "$#" -ge 2 ] || exit 2; max_download_bytes=$2;shift 2;;
  *) echo 'Usage: bootstrap-online.sh --archive-url HTTPS_URL --sha256 TRUSTED_DIGEST [--verify-only] [--max-download-bytes 1..1073741824]' >&2;exit 2;;
 esac
done
case "$url" in https://*|http://127.0.0.1:*|http://localhost:*) ;; *) echo 'Only HTTPS release endpoints (or isolated local test hosts) are supported' >&2; exit 2;; esac
[ "${#digest}" -eq 64 ] || { echo 'A trusted 64-character SHA-256 digest is required' >&2;exit 2; }
case "$digest" in *[!0123456789abcdefABCDEF]*) echo 'Invalid digest syntax' >&2;exit 2;; esac
case "$max_download_bytes" in ''|*[!0123456789]*) echo 'Invalid download ceiling' >&2;exit 2;; esac
# Strip leading zeroes without using arbitrary precision/signed shell math.
max_download_bytes=$(printf '%s' "$max_download_bytes" | sed 's/^0*//')
[ -n "$max_download_bytes" ] || max_download_bytes=0
[ "${#max_download_bytes}" -le 10 ] && [ "$max_download_bytes" -ge 1 ] &&
 [ "$max_download_bytes" -le 1073741824 ] || { echo 'Download ceiling outside supported range' >&2;exit 2; }
command -v curl >/dev/null 2>&1 || { echo 'A supported downloader (curl) is required for the online bootstrap' >&2;exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required' >&2;exit 1; }
command -v stat >/dev/null 2>&1 || { echo 'stat is required for trusted staging' >&2;exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required for bounded ONLINE archive processing (not needed offline)' >&2;exit 1; }
command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for bounded ONLINE archive processing' >&2;exit 1; }
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
# curl's byte ceiling applies before accepting response bodies, including
# chunked/unknown-length responses. Its time limits remain independent.
if ! curl -q --fail --location --proto "$allowed_proto" --proto-redir "$allowed_proto" \
 --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 \
 --max-filesize "$max_download_bytes" \
 --output "$work/bundle.tar.gz" "$url"; then
 echo 'Online acquisition failed or exceeded the transfer ceiling; no installation changes.' >&2
 exit 1
fi
archive_bytes=$(wc -c < "$work/bundle.tar.gz")
[ "$archive_bytes" -le "$max_download_bytes" ] || {
 echo 'Downloaded archive exceeded the permitted size' >&2;exit 1;
}
printf '%s  %s\n' "$digest" "$work/bundle.tar.gz" |
 sha256sum --quiet --check - || { echo 'Independent artifact digest mismatch' >&2;exit 1; }

# One isolated stdlib parser validates AND privately extracts with the
# same tar semantics, including for --verify-only. No unbounded tar listing files or parser discrepancies.
# Enforce memory/time ceilings BEFORE parsing gzip/pax/longname metadata.
# Online mode needs Debian's python3; the standalone OFFLINE installer does not.
(
 ulimit -v 262144 || exit 1
 timeout -s TERM -k 3s 150s python3 -I -S - \
  "$work/bundle.tar.gz" "$work" <<'PYARCHIVE'
import gzip
import os
from pathlib import Path
import sys
import tarfile

archive_path, root_path = sys.argv[1:]
root = Path(root_path)
MAX_MEMBERS = 10000
MAX_FILE = 4294967296
MAX_EXPANDED = 8589934592
MAX_METADATA = 1048576
MAX_RAW = MAX_EXPANDED + MAX_METADATA
MAX_READ = 2097152
REQUIRED_FILES = {
    "server-connect/install.sh",
    "server-connect/server-connect.service",
    "server-connect/manifest.json",
    "server-connect/checksums.sha256",
    "server-connect/bin/server-connect",
    "server-connect/bin/sing-box",
    "server-connect/bin/libcronet.so",
    "server-connect/THIRD-PARTY-LICENSES/sing-box-LICENSE",
}
ALLOWED_DIRS = {
    "server-connect",
    "server-connect/bin",
    "server-connect/THIRD-PARTY-LICENSES",
}
EXECUTABLES = {
    "server-connect/install.sh",
    "server-connect/bin/server-connect",
    "server-connect/bin/sing-box",
}


class Budget:
    # tarfile r| reads sequentially, never seeking. Restrict both overall
    # decompression and each individual metadata allocation request.
    def __init__(self, source):
        self.source = source
        self.used = 0

    def read(self, n=-1):
        if n < 0 or n > MAX_READ:
            raise ValueError("archive metadata read too large")
        data = self.source.read(n)
        self.used += len(data)
        if self.used > MAX_RAW:
            raise ValueError("archive decompression ceiling")
        return data


def archive_pass(extract):
    seen = set()
    seen_files = set()
    total_files = 0
    padded_file_bytes = 0
    with open(archive_path, "rb") as source, gzip.GzipFile(fileobj=source) as gzip_stream:
        bounded = Budget(gzip_stream)
        with tarfile.open(fileobj=bounded, mode="r|") as stream:
            for member in stream:
                name = member.name
                if (
                    not isinstance(name, str)
                    or len(name.encode("utf-8")) > 2048
                    or any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in name)
                ):
                    raise ValueError("unsupported archive member name")
                canonical = name.rstrip("/")
                components = canonical.split("/")
                if (
                    any(piece in ("", ".", "..") for piece in components)
                    or canonical in seen
                ):
                    raise ValueError("duplicate or unsafe archive member path")
                if member.type == tarfile.DIRTYPE:
                    if canonical not in ALLOWED_DIRS or member.size != 0:
                        raise ValueError("unexpected directory")
                elif member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    if canonical not in REQUIRED_FILES or getattr(member, "sparse", None):
                        raise ValueError("unsupported archive file or sparse data")
                    if member.size < 0 or member.size > MAX_FILE:
                        raise ValueError("oversized archive file")
                    total_files += member.size
                    padded_file_bytes += ((member.size + 511) // 512) * 512
                    if total_files > MAX_EXPANDED:
                        raise ValueError("archive expanded size ceiling")
                    seen_files.add(canonical)
                else:
                    raise ValueError("links, devices and special members are forbidden")
                seen.add(canonical)
                if len(seen) > MAX_MEMBERS or bounded.used > padded_file_bytes + MAX_METADATA:
                    raise ValueError("archive metadata/member ceiling")
                if extract:
                    destination = root.joinpath(*components)
                    if member.type == tarfile.DIRTYPE:
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd, "wb") as output:
                            data = stream.extractfile(member)
                            if data is None:
                                raise ValueError("missing archive payload")
                            remaining = member.size
                            while remaining:
                                piece = data.read(min(65536, remaining))
                                if not piece:
                                    raise ValueError("truncated archive file")
                                output.write(piece)
                                remaining -= len(piece)
                        os.chmod(destination, 0o700 if canonical in EXECUTABLES else 0o600)
        if seen_files != REQUIRED_FILES:
            raise ValueError("missing or unexpected release payload")
    return


try:
    archive_pass(False)
    # Reparse with the identical library and perform bounded private staging.
    # --verify-only retains this extraction check, but never invokes install.sh.
    archive_pass(True)
except (OSError, EOFError, ValueError, tarfile.TarError, OverflowError, MemoryError):
    print("Archive preflight failed (layout, decompression or resource ceiling); no installation attempted", file=sys.stderr)
    sys.exit(1)
PYARCHIVE
) || { echo 'Online archive rejected before installation; staging will be removed' >&2;exit 1; }

if [ "$verify_only" = yes ];then
 echo 'Online fetch, independent digest, bounded archive and release layout: verified. Installation was not attempted.'
 exit 0
fi
# The shared local installer independently verifies ownership, ancestry,
# complete payload checksums and service identity before lifecycle mutation.
sh "$work/server-connect/install.sh" --offline
