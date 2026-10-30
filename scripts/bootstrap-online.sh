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
# Official pinned core 1.14.3 is 31,678,266 compressed / 93,255,156
# expanded bytes. These conservative QA bundle caps allow manager/metadata
# headroom without permitting multi-GiB disk consumption on hosting servers.
# The curl ceiling applies while receiving bytes; operators may only lower it.
max_download_bytes=100663296
max_expanded_bytes=201326592
max_file_bytes=134217728
while [ "$#" -gt 0 ]; do
 case "$1" in
  --archive-url) [ "$#" -ge 2 ] || exit 2; url=$2;shift 2;;
  --sha256) [ "$#" -ge 2 ] || exit 2; digest=$2;shift 2;;
  --verify-only)verify_only=yes;shift;;
  --max-download-bytes) [ "$#" -ge 2 ] || exit 2; max_download_bytes=$2;shift 2;;
  *) echo 'Usage: bootstrap-online.sh --archive-url HTTPS_URL --sha256 TRUSTED_DIGEST [--verify-only] [--max-download-bytes 1..100663296]' >&2;exit 2;;
 esac
done
[ "${#digest}" -eq 64 ] || { echo 'A trusted 64-character SHA-256 digest is required' >&2;exit 2; }
case "$digest" in *[!0123456789abcdefABCDEF]*) echo 'Invalid digest syntax' >&2;exit 2;; esac
case "$max_download_bytes" in ''|*[!0123456789]*) echo 'Invalid download ceiling' >&2;exit 2;; esac
# Strip leading zeroes without using arbitrary precision/signed shell math.
max_download_bytes=$(printf '%s' "$max_download_bytes" | sed 's/^0*//')
[ -n "$max_download_bytes" ] || max_download_bytes=0
[ "${#max_download_bytes}" -le 10 ] && [ "$max_download_bytes" -ge 1 ] &&
 [ "$max_download_bytes" -le 100663296 ] || { echo 'Download ceiling outside supported range' >&2;exit 2; }
# A real connected installation may acquire *missing* native Debian 13
# prerequisites via the host's existing signed APT policy. This is a separate
# OS package transaction, not a second Server Connect installer. --verify-only
# NEVER changes OS packages, even when invoked as root.
case "$url" in
 https://?*|http://127.0.0.1:*|http://localhost:*) ;;
 *) echo 'Unsupported URL scheme or missing authority' >&2; exit 2;;
esac
user_id=$(id -u)
if [ "$verify_only" != yes ] && [ "$user_id" -ne 0 ]; then
 echo 'Run the online installation command as root; non-root --verify-only is supported.' >&2
 exit 1
fi
# The supported Debian 13 base must provide every native helper used by
# this bootstrap, including staging, measurement and EXIT-trap cleanup tools.
# Fail before APT on an incomplete base; never auto-repair essential packages.
# Require native /usr/bin executables (not a custom PATH wrapper).
for native_tool in id sed sha256sum stat timeout mktemp rm wc cut; do
 if [ ! -x "/usr/bin/$native_tool" ] ||
    [ "$(command -v "$native_tool")" != "/usr/bin/$native_tool" ]; then
  echo "Missing native Debian bootstrap utility: /usr/bin/$native_tool" >&2
  exit 1
 fi
done
set --
command -v curl >/dev/null 2>&1 || set -- "$@" curl
command -v python3 >/dev/null 2>&1 || set -- "$@" python3
case "$url" in
 https://*)
  [ -r /etc/ssl/certs/ca-certificates.crt ] || set -- "$@" ca-certificates ;;
esac
if [ "$#" -gt 0 ]; then
 if [ "$verify_only" = yes ]; then
  echo 'Online --verify-only needs existing curl, Python 3 and HTTPS CA certificates; no packages installed' >&2
  exit 1
 fi
 # The first advertised online target is Debian 13. Never guess an apt
 # command or install packages on another distribution.
 [ -r /etc/os-release ] || { echo 'OS identity unavailable; cannot safely install online prerequisites' >&2; exit 1; }
 . /etc/os-release
 [ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ] &&
 [ -x /usr/bin/apt-get ] || {
  echo 'Automatic online prerequisites are supported only on Debian 13 with native APT' >&2
  exit 1
 }
 # Refuse an unsafe root staging parent BEFORE any OS package mutation.
 [ -d /root ] && [ ! -L /root ] &&
 [ "$(stat -c '%u' /root)" = 0 ] || {
  echo 'Trusted root-owned staging is required before prerequisite installation' >&2
  exit 1
 }
 root_mode=$(stat -c '%a' /root) || exit 1
 [ "$((0$root_mode & 022))" -eq 0 ] || {
  echo 'Root staging parent is group/other writable' >&2
  exit 1
 }
 echo 'Installing missing Debian 13 online-bootstrap prerequisites through native APT' >&2
 # Fixed package names only; no user-provided package, source, repository or
 # global APT policy changes. Failure leaves the Server Connect install alone.
 unset APT_CONFIG DPKG_ROOT
 if ! DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get \
   -o Acquire::AllowInsecureRepositories=false \
   -o Acquire::AllowDowngradeToInsecureRepositories=false \
   -o APT::Get::AllowUnauthenticated=false \
   -o APT::Update::Error-Mode=any \
   -o Acquire::Retries=1 \
   -o Acquire::http::Timeout=15 \
   -o Acquire::https::Timeout=15 update; then
  echo 'Debian prerequisite index update failed; no Server Connect installation attempted' >&2
  exit 1
 fi
 if ! DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get \
   -o APT::Get::AllowUnauthenticated=false \
   -o Acquire::Retries=1 \
   -o Acquire::http::Timeout=15 \
   -o Acquire::https::Timeout=15 \
   install -y --no-remove --no-install-recommends "$@"; then
  echo 'Debian prerequisites could not be installed; no Server Connect installation attempted' >&2
  exit 1
 fi
fi
command -v curl >/dev/null 2>&1 || { echo 'A supported downloader (curl) is required for the online bootstrap' >&2;exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required' >&2;exit 1; }
command -v stat >/dev/null 2>&1 || { echo 'stat is required for trusted staging' >&2;exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required for bounded ONLINE archive processing (not needed offline)' >&2;exit 1; }
command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for bounded ONLINE archive processing' >&2;exit 1; }
# Parse the effective authority, never textual localhost prefixes. Test-only
# HTTP permits only explicit IPv4 loopback / localhost with a numeric port.
# URL credentials, encoded authority, fragments and unsafe bytes are refused.
acquisition_mode=$(python3 -I -S - "$url" <<'PYURL'
import sys
from urllib.parse import urlsplit

url = sys.argv[1]
try:
    if len(url) > 4096 or any(ord(c) < 33 or ord(c) > 126 or c == "\\" for c in url):
        raise ValueError("unsafe URL")
    parsed = urlsplit(url)
    if (parsed.scheme not in ("https", "http") or not parsed.netloc
            or parsed.username is not None or parsed.password is not None
            or "@" in parsed.netloc or "%" in parsed.netloc or parsed.fragment):
        raise ValueError("unsupported URL authority")
    host = parsed.hostname
    port = parsed.port
    if not host or len(host) > 253 or port == 0:
        raise ValueError("invalid host/port")
    if parsed.scheme == "http":
        if host not in ("127.0.0.1", "localhost") or port is None:
            raise ValueError("HTTP must use actual loopback")
        print("http_localhost:" + str(port) if host == "localhost" else "http_loopback")
    else:
        print("https")
except ValueError:
    sys.exit(1)
PYURL
) || { echo 'Unsupported URL: HTTPS required except for strict loopback HTTP test host' >&2;exit 2; }
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
# Before download, require enough available staging capacity for the maximum
# permitted compressed and expanded artifacts PLUS a reserve for other services.
# This is a conservative gate, not a filesystem quota; the bounded extractor
# also enforces its own byte budget and checks reserve at every write.
if ! python3 -I -S - "$work" "$max_download_bytes" "$max_expanded_bytes" <<'PYSPACE'
import os
import sys

root, compressed, expanded = sys.argv[1:]
fs = os.statvfs(root)
available = fs.f_bavail * fs.f_frsize
capacity = fs.f_blocks * fs.f_frsize
reserve = max(1073741824, capacity // 10)
needed = reserve + int(compressed) + int(expanded) + 16777216
sys.exit(0 if available >= needed else 1)
PYSPACE
then
 echo 'Insufficient reserved staging capacity; no download or installation attempted' >&2
 exit 1
fi

# Production HTTPS redirects are bounded and HTTPS-only. Test HTTP has ZERO
# redirects; no proxy and no external resolution are allowed. Pin localhost
# to IPv4 loopback, rather than trusting mutable resolver configuration.
case "$acquisition_mode" in
 https)
  allowed_proto='=https'; max_redirs=5; set --;;
 http_loopback)
  allowed_proto='=http'; max_redirs=0; set --;;
 http_localhost:*)
  allowed_proto='=http'; max_redirs=0
  loopback_port=$(printf '%s' "$acquisition_mode" | cut -d: -f2)
  set -- --resolve "localhost:$loopback_port:127.0.0.1";;
 *) echo 'Unsupported download mode' >&2; exit 2;;
esac
# curl's byte ceiling is active DURING the receive, even for chunked bodies.
# stderr is private and never reflects an input URL/token in CLI output.
if ! curl -q --fail --location --max-redirs "$max_redirs" \
 --proto "$allowed_proto" --proto-redir "$allowed_proto" --noproxy '*' "$@" \
 --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 \
 --max-filesize "$max_download_bytes" \
 --output "$work/bundle.tar.gz" "$url" 2>"$work/download.err"; then
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
  "$work/bundle.tar.gz" "$work" "$max_expanded_bytes" "$max_file_bytes" <<'PYARCHIVE'
import gzip
import os
from pathlib import Path
import resource
import sys
import tarfile

archive_path, root_path, expanded_arg, file_arg = sys.argv[1:]
root = Path(root_path)
MAX_MEMBERS = 64
MAX_FILE = int(file_arg)
MAX_EXPANDED = int(expanded_arg)
# Kernel-enforced per-file ceiling complements the application's strict
# aggregate write budget; neither relies solely on a stale free-space check.
resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
MAX_METADATA = 1048576
MAX_RAW = MAX_EXPANDED + MAX_METADATA
MAX_READ = 2097152
SAFETY_MARGIN = 16777216

def check_staging_capacity(next_write):
    fs = os.statvfs(root)
    free = fs.f_bavail * fs.f_frsize
    capacity = fs.f_blocks * fs.f_frsize
    reserved = max(1073741824, capacity // 10) + SAFETY_MARGIN
    if free < reserved + next_write:
        raise ValueError("insufficient reserved staging capacity")


REQUIRED_FILES = {
    "server-connect/install.sh",
    "server-connect/server-connect.service",
    "server-connect/server-connect-activation-recover.service",
    "server-connect/server-connect-activation-recover.timer",
    "server-connect/server-connect-smart-tun.service",
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
    written_bytes = 0
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
                        check_staging_capacity(member.size)
                        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        try:
                            data = stream.extractfile(member)
                            if data is None:
                                raise ValueError("missing archive payload")
                            remaining = member.size
                            while remaining:
                                piece = data.read(min(65536, remaining))
                                if not piece:
                                    raise ValueError("truncated archive file")
                                check_staging_capacity(len(piece))
                                if written_bytes + len(piece) > MAX_EXPANDED:
                                    raise ValueError("aggregate extraction byte budget")
                                view = memoryview(piece)
                                while view:
                                    count = os.write(fd, view)
                                    if count <= 0:
                                        raise OSError("short extraction write")
                                    view = view[count:]
                                written_bytes += len(piece)
                                remaining -= len(piece)
                        finally:
                            os.close(fd)
                        os.chmod(destination, 0o700 if canonical in EXECUTABLES else 0o600)
        if seen_files != REQUIRED_FILES:
            raise ValueError("missing or unexpected release payload")
    return total_files


try:
    # Verify full member layout before writing a single extracted file.
    declared = archive_pass(False)
    check_staging_capacity(declared)
    # Reparse with the identical library and perform bounded private staging.
    # --verify-only retains this extraction check, but never invokes install.sh.
    if archive_pass(True) != declared:
        raise ValueError("inconsistent archive extraction")
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
