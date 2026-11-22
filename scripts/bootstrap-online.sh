#!/bin/sh
# Shared Official/Mirror/Offline acquisition bootstrap (keyless normal mode).
# The selected HTTPS host or manually uploaded source is the source of trust.
# SHA256 verifies bytes, not independent publisher identity; no Stable release yet.
# Optional historical signed QA and explicit local digest QA remain available.
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

# A literal parser, not a shell evaluator. Keep this pure stdin operation
# separate from the fixed trusted-path reader so ordinary tests need no host
# identity override. Canonical Debian metadata uses printable ASCII and blanks.
bootstrap_parse_os_identity() (
 LC_ALL=C
 export LC_ALL
 # Preserve trailing newlines with a sentinel. A failed bounded read emits a
 # control byte, so the final pipeline command fails rather than hiding it.
 os_identity_raw=$(
  { /usr/bin/head -c 16385 || printf '\001'; printf '.'; } |
   /usr/bin/sed '/[^[:print:][:blank:]]/q 1'
 ) || return 1
 case "$os_identity_raw" in *.) os_identity_raw=${os_identity_raw%.} ;; *) return 1 ;; esac
 [ "${#os_identity_raw}" -gt 0 ] && [ "${#os_identity_raw}" -le 16384 ] || return 1
 os_identity_id=''
 os_identity_version=''
 while IFS= read -r os_identity_line || [ -n "$os_identity_line" ]; do
  os_identity_line=${os_identity_line#"${os_identity_line%%[![:blank:]]*}"}
  os_identity_line=${os_identity_line%"${os_identity_line##*[![:blank:]]}"}
  case "$os_identity_line" in ''|\#*) continue ;; esac
  case "$os_identity_line" in
   *=*) os_identity_key=${os_identity_line%%=*}; os_identity_value=${os_identity_line#*=} ;;
   *) return 1 ;;
  esac
  case "$os_identity_key" in ''|[0-9]*|*[!a-zA-Z0-9_]*) return 1 ;; esac
  case "$os_identity_key" in
   [Ii][Dd])
    [ "$os_identity_key" = ID ] && [ -z "$os_identity_id" ] || return 1
    case "$os_identity_value" in debian|'"debian"'|"'debian'") os_identity_id=debian ;; *) return 1 ;; esac
    ;;
   [Vv][Ee][Rr][Ss][Ii][Oo][Nn]_[Ii][Dd])
    [ "$os_identity_key" = VERSION_ID ] && [ -z "$os_identity_version" ] || return 1
    case "$os_identity_value" in
     12|'"12"'|"'12'") os_identity_version=12 ;;
     13|'"13"'|"'13'") os_identity_version=13 ;;
     *) return 1 ;;
    esac
    ;;
   *) ;; # Descriptive values are never expanded, sourced or executed.
  esac
 done <<SC_OS_IDENTITY_LITERAL
$os_identity_raw
SC_OS_IDENTITY_LITERAL
 [ "$os_identity_id" = debian ] && [ -n "$os_identity_version" ] || return 1
 printf '%s\n' "$os_identity_version"
)

bootstrap_os_path_owned() {
 os_identity_owner=$(/usr/bin/stat -c '%u' -- "$1") || return 1
 [ "$os_identity_owner" = 0 ] || return 1
 os_identity_mode=$(/usr/bin/stat -c '%a' -- "$1") || return 1
 case "$os_identity_mode" in ''|*[!0-7]*) return 1 ;; esac
 [ "$((0$os_identity_mode & 022))" -eq 0 ]
}

bootstrap_read_os_version() (
 LC_ALL=C
 export LC_ALL
 for os_identity_directory in / /etc; do
  [ -d "$os_identity_directory" ] && [ ! -L "$os_identity_directory" ] &&
   bootstrap_os_path_owned "$os_identity_directory" || return 1
 done
 os_identity_before=$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%s:%y:%z' -- /etc/os-release) || return 1
 os_identity_owner=$(/usr/bin/stat -c '%u' -- /etc/os-release) || return 1
 [ "$os_identity_owner" = 0 ] || return 1
 os_identity_link=''
 if [ -L /etc/os-release ]; then
  # Preserve target bytes, including trailing newlines, before allowlisting.
  os_identity_link=$(/usr/bin/readlink -n -- /etc/os-release && printf '.') || return 1
  os_identity_link=${os_identity_link%.}
  case "$os_identity_link" in ../usr/lib/os-release|/usr/lib/os-release) ;; *) return 1 ;; esac
  os_identity_path=/usr/lib/os-release
  for os_identity_directory in /usr /usr/lib; do
   [ -d "$os_identity_directory" ] && [ ! -L "$os_identity_directory" ] &&
    bootstrap_os_path_owned "$os_identity_directory" || return 1
  done
 else
  os_identity_path=/etc/os-release
 fi
 [ -f "$os_identity_path" ] && [ ! -L "$os_identity_path" ] &&
  bootstrap_os_path_owned "$os_identity_path" || return 1
 os_identity_size=$(/usr/bin/stat -c '%s' -- "$os_identity_path") || return 1
 case "$os_identity_size" in ''|*[!0-9]*) return 1 ;; esac
 [ "$os_identity_size" -gt 0 ] && [ "$os_identity_size" -le 16384 ] || return 1
 os_identity_file_before=$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%s:%y:%z' -- "$os_identity_path") || return 1
 os_identity_version=$(bootstrap_parse_os_identity < "$os_identity_path") || return 1
 os_identity_file_after=$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%s:%y:%z' -- "$os_identity_path") || return 1
 os_identity_after=$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%s:%y:%z' -- /etc/os-release) || return 1
 [ "$os_identity_file_before" = "$os_identity_file_after" ] &&
  [ "$os_identity_before" = "$os_identity_after" ] || return 1
 if [ -n "$os_identity_link" ]; then
  os_identity_link_after=$(/usr/bin/readlink -n -- /etc/os-release && printf '.') || return 1
  os_identity_link_after=${os_identity_link_after%.}
  [ "$os_identity_link" = "$os_identity_link_after" ] || return 1
  for os_identity_directory in /usr /usr/lib; do
   [ -d "$os_identity_directory" ] && [ ! -L "$os_identity_directory" ] &&
    bootstrap_os_path_owned "$os_identity_directory" || return 1
  done
 fi
 for os_identity_directory in / /etc; do
  [ -d "$os_identity_directory" ] && [ ! -L "$os_identity_directory" ] &&
   bootstrap_os_path_owned "$os_identity_directory" || return 1
 done
 printf '%s\n' "$os_identity_version"
)

# Validate the acquisition authority with POSIX shell *before* APT, even on
# minimal Debian without Python/curl. The full Python URL parser below runs
# again after missing prerequisites are acquired. This rejects ambiguous
# authorities rather than modifying OS packages to inspect a bad source.
bootstrap_preflight_source_url() {
 source_url=$1
 case "$source_url" in
  *[![:print:]]*|*' '*|*'\'*|*'#'*) return 1 ;;
  https://*) source_scheme=https ;;
  http://*) [ "$local_qa" = yes ] || return 1; source_scheme=http ;;
  *) return 1 ;;
 esac
 source_remainder=${source_url#*://}
 source_authority=${source_remainder%%/*}
 source_authority=${source_authority%%\?*}
 case "$source_authority" in ''|*'@'*|*'%'*) return 1 ;; esac
 source_host=''
 source_port=''
 case "$source_authority" in
  \[*)
   # IPv6 literal parsing needs the exact Python inet_pton-based URL parser.
   # Do not modify OS packages merely to examine an uncertain literal.
   command -v python3 >/dev/null 2>&1 || return 1
   source_host=${source_authority#\[}
   case "$source_host" in *\]*) ;; *) return 1 ;; esac
   source_suffix=${source_host#*\]}
   source_host=${source_host%%\]*}
   case "$source_host" in ''|*[!0123456789abcdefABCDEF:.]*) return 1 ;; esac
   ;;
  *)
   source_host=${source_authority%%:*}
   source_suffix=${source_authority#"$source_host"}
   case "$source_host" in ''|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-]*) return 1 ;; esac
   ;;
 esac
 case "$source_suffix" in
  '') ;;
  :*)
   source_port=${source_suffix#:}
   case "$source_port" in ''|*[!0123456789]*) return 1 ;; esac
   [ "${#source_port}" -le 5 ] && [ "$source_port" -gt 0 ] && [ "$source_port" -le 65535 ] || return 1
   ;;
  *) return 1 ;;
 esac
 if [ "$source_scheme" = http ];then
  case "$source_host" in 127.0.0.1|localhost) [ -n "$source_port" ] || return 1 ;; *) return 1 ;; esac
 fi
 return 0
}

# Use the same strict URL parser both before APT (when Python already exists)
# and after package acquisition. There is exactly one authority policy.
bootstrap_parse_acquisition_mode() {
 python3 -I -S - "$1" <<'PYURL'
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
}

url=''
source_base=''
source_kind=''
index_digest=''
archive_file=''
metadata_file=''
signature_file=''
publisher_key=''
version=''
target=''
local_qa=no
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
  --official) [ -z "$source_kind" ] || exit 2;source_kind=official;source_base='https://github.com/AChWorks/server-connect/releases/latest/download/';shift;;
  --mirror-base) [ "$#" -ge 2 ] && [ -z "$source_kind" ] || exit 2;source_kind=mirror;source_base=$2;shift 2;;
  --archive-url) [ "$#" -ge 2 ] && [ -z "$url" ] || exit 2; url=$2;shift 2;;
  --archive-file) [ "$#" -ge 2 ] && [ -z "$archive_file" ] || exit 2; archive_file=$2;shift 2;;
  --metadata-file) [ "$#" -ge 2 ] && [ -z "$metadata_file" ] || exit 2; metadata_file=$2;shift 2;;
  --signature-file) [ "$#" -ge 2 ] && [ -z "$signature_file" ] || exit 2; signature_file=$2;shift 2;;
  --publisher-key) [ "$#" -ge 2 ] && [ -z "$publisher_key" ] || exit 2; publisher_key=$2;shift 2;;
  --version) [ "$#" -ge 2 ] && [ -z "$version" ] || exit 2; version=$2;shift 2;;
  --target) [ "$#" -ge 2 ] && [ -z "$target" ] || exit 2; target=$2;shift 2;;
  --local-qa) [ "$local_qa" = no ] || exit 2; local_qa=yes;shift;;
  --sha256) [ "$#" -ge 2 ] && [ -z "$digest" ] || exit 2; digest=$2;shift 2;;
  --verify-only)verify_only=yes;shift;;
  --max-download-bytes) [ "$#" -ge 2 ] || exit 2; max_download_bytes=$2;shift 2;;
  *) echo 'Usage: bootstrap-online.sh (--official | --mirror-base HTTPS_BASE | --archive-url HTTPS_URL | --archive-file ABSOLUTE_FILE) [--verify-only]; optional legacy signed QA --publisher-key; digest-pinned local QA --local-qa --sha256 SHA256' >&2;exit 2;;
 esac
done
# Ordinary Official, operator Mirror and Offline use release metadata and
# SHA256 integrity; the selected HTTPS host/uploaded file is the trust root.
# Historical optional signed QA is retained for auditing earlier installed
# releases, not required for any normal acquisition.
[ -z "$source_kind" ] || {
 [ -z "$url$archive_file$metadata_file$signature_file$publisher_key$digest" ] || {
  echo 'Do not mix a release channel with manual archive, key or digest options' >&2;exit 2;
 }
 case "$source_base" in https://?*) ;; *) echo 'Mirror base requires HTTPS' >&2;exit 2;; esac
 case "$source_base" in *'?'*|*'#'*|*'@'*|*'\'*|*' '*) echo 'Mirror base may contain no credentials, query, fragment or escape characters' >&2;exit 2;; esac
 case "$source_base" in */) ;; *) source_base=$source_base/;; esac
 url=${source_base}release-index.json
}
if { [ -n "$url" ] && [ -n "$archive_file" ]; } ||
   { [ -z "$url" ] && [ -z "$archive_file" ]; }; then
 echo 'Choose exactly one release channel, URL or offline archive file' >&2;exit 2
fi
authenticated=integrity
if [ "$local_qa" = yes ] && [ -z "$publisher_key" ];then
 authenticated=no
 [ -z "$source_kind$publisher_key$version$target$metadata_file$signature_file" ] || {
  echo 'Local QA is only for an explicit archive and independent digest' >&2;exit 2;
 }
 [ "${#digest}" -eq 64 ] || { echo 'A trusted 64-character SHA-256 digest is required for LOCAL QA' >&2;exit 2; }
 case "$digest" in *[!0123456789abcdefABCDEF]*) echo 'Invalid digest syntax' >&2;exit 2;; esac
elif [ -n "$publisher_key" ];then
 authenticated=yes
 [ -z "$source_kind$digest" ] && [ -n "$version" ] && [ -n "$target" ] || {
  echo 'Signed historical QA requires an explicit version and target' >&2;exit 2;
 }
 case "$publisher_key" in /*) ;; *) echo 'An independent local public-key path is required' >&2;exit 2;; esac
 [ -f "$publisher_key" ] && [ ! -L "$publisher_key" ] || {
  echo 'Independent public key is missing or not a regular local file' >&2;exit 2;
 }
 [ -z "$metadata_file$signature_file" ] ||
  { [ -n "$metadata_file" ] && [ -n "$signature_file" ]; } || {
  echo 'Metadata and signature file overrides must be supplied together' >&2;exit 2;
 }
else
 [ -z "$signature_file$digest" ] || {
  echo 'Normal installation does not take detached signatures or independent digests' >&2;exit 2;
 }
fi
if [ -n "$archive_file" ]; then
 case "$archive_file" in /*) ;; *) echo 'Offline archive must use an absolute local path' >&2;exit 2;; esac
 if [ -z "$metadata_file" ] && [ "$authenticated" != no ]; then
  metadata_file=$archive_file.release.json
  if [ "$authenticated" = yes ]; then signature_file=$archive_file.sig;fi
 fi
fi
case "$max_download_bytes" in ''|*[!0123456789]*) echo 'Invalid download ceiling' >&2;exit 2;; esac
# Strip leading zeroes without using arbitrary precision/signed shell math.
max_download_bytes=$(printf '%s' "$max_download_bytes" | sed 's/^0*//')
[ -n "$max_download_bytes" ] || max_download_bytes=0
[ "${#max_download_bytes}" -le 10 ] && [ "$max_download_bytes" -ge 1 ] &&
 [ "$max_download_bytes" -le 100663296 ] || { echo 'Download ceiling outside supported range' >&2;exit 2; }
# A real connected installation may acquire *missing* native Debian 12/13
# prerequisites via the host's existing signed APT policy. This is a separate
# OS package transaction, not a second Server Connect installer. --verify-only
# NEVER changes OS packages, even when invoked as root.
if [ -n "$url" ]; then
 case "$url" in
  https://?*) ;;
  http://127.0.0.1:*|http://localhost:*)
   [ "$local_qa" = yes ] || { echo 'HTTP requires explicit --local-qa' >&2;exit 2; };;
  *) echo 'Unsupported URL scheme or missing authority' >&2;exit 2;;
 esac
fi
user_id=$(id -u)
if [ "$verify_only" != yes ] && [ "$user_id" -ne 0 ]; then
 echo 'Run the online installation command as root; non-root --verify-only is supported.' >&2
 exit 1
fi
# The supported Debian 12/13 base must provide every native helper used by
# this bootstrap, including staging, measurement and EXIT-trap cleanup tools.
# Fail before APT on an incomplete base; never auto-repair essential packages.
# Require native /usr/bin executables (not a custom PATH wrapper).
for native_tool in id sed sha256sum stat timeout mktemp rm wc cut head readlink; do
 if [ ! -x "/usr/bin/$native_tool" ] ||
    [ "$(command -v "$native_tool")" != "/usr/bin/$native_tool" ]; then
  echo "Missing native Debian bootstrap utility: /usr/bin/$native_tool" >&2
  exit 1
 fi
done
# Admission BEFORE any package transaction. A source's URL/authority, actual
# CPU and canonical Debian identity cannot be deferred until curl/Python is
# installed. Only genuinely supported hosts can acquire prerequisites.
host_target=''
if [ -n "$url" ];then
 if ! bootstrap_preflight_source_url "$url";then
  echo 'Unsupported URL: unsafe acquisition authority (before APT)' >&2;exit 2
 fi
 [ "$(/usr/bin/uname -m)" = x86_64 ] || {
  echo 'Only Debian 12/13 amd64 is supported; no APT attempted' >&2;exit 1;
 }
 host_os=$(bootstrap_read_os_version) || {
  echo 'Verified Debian 12/13 host identity required before APT' >&2;exit 1;
 }
 host_target=debian-$host_os-amd64
 # If Python already exists, perform the complete URL parser before any
 # package changes. A minimal host without Python may acquire it only for
 # authorities the earlier portable shell preflight can fully classify.
 if command -v python3 >/dev/null 2>&1;then
  bootstrap_parse_acquisition_mode "$url" >/dev/null || {
   echo 'Unsupported URL: invalid parsed authority before APT' >&2;exit 2;
  }
 fi
 if [ -n "$source_kind" ] && [ -n "$target" ] && [ "$target" != "$host_target" ];then
  echo 'Release target differs from actual host; no APT attempted' >&2;exit 2
 fi
fi
set --
if [ -n "$url" ]; then
 command -v curl >/dev/null 2>&1 || set -- "$@" curl
fi
command -v python3 >/dev/null 2>&1 || set -- "$@" python3
# The offline installer must inspect the native reply-guard nftables table
# *before* any product mutation, including a first install. On connected
# installs acquire the real kernel inspector through signed Debian APT;
# --verify-only never installs packages and offline remains fail-closed.
if [ "$verify_only" != yes ] && [ -n "$url" ]; then
 command -v nft >/dev/null 2>&1 || set -- "$@" nftables
fi
if [ "$authenticated" = yes ]; then
 command -v openssl >/dev/null 2>&1 || set -- "$@" openssl
fi
case "$url" in
 https://*)
  [ -r /etc/ssl/certs/ca-certificates.crt ] || set -- "$@" ca-certificates ;;
esac
if [ "$#" -gt 0 ]; then
 if [ -n "$archive_file" ]; then
  echo 'Offline verification needs preinstalled Python 3 (and OpenSSL only for optional signed QA); no packages or downloads attempted' >&2
  exit 1
 fi
 if [ "$verify_only" = yes ]; then
  echo 'Online --verify-only needs existing curl, Python 3 and HTTPS CA certificates (OpenSSL only for signed QA); no packages installed' >&2
  exit 1
 fi
 # Read only the fixed trusted host identity. No shell evaluation or caller
 # override may authorize a prerequisite package transaction.
 prerequisite_version=$(bootstrap_read_os_version) || {
  echo 'Verified Debian 12 or Debian 13 OS identity is required for automatic online prerequisites' >&2
  exit 1
 }
 [ -x /usr/bin/apt-get ] || {
  echo 'Automatic online prerequisites require native Debian APT' >&2
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
 echo "Installing missing Debian $prerequisite_version online-bootstrap prerequisites through native APT" >&2
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
if [ -n "$url" ]; then
 command -v curl >/dev/null 2>&1 || { echo 'A supported downloader (curl) is required for the online bootstrap' >&2;exit 1; }
fi
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required' >&2;exit 1; }
command -v stat >/dev/null 2>&1 || { echo 'stat is required for trusted staging' >&2;exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required for bounded archive processing' >&2;exit 1; }
command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for bounded ONLINE archive processing' >&2;exit 1; }
# Parse the effective authority, never textual localhost prefixes. Test-only
# HTTP permits only explicit IPv4 loopback / localhost with a numeric port.
# URL credentials, encoded authority, fragments and unsafe bytes are refused.
acquisition_mode=offline
if [ -n "$url" ]; then
 acquisition_mode=$(bootstrap_parse_acquisition_mode "$url") || {
  echo 'Unsupported URL: HTTPS required except for strict loopback HTTP test host' >&2;exit 2;
 }
fi
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

# Copy only bounded local regular files into private staging. A local input
# may be uploaded by an unprivileged operator; authentication covers the copy,
# never a later reread of the replaceable original. Offline has no curl/APT.
copy_input() {
 python3 -I -S - "$1" "$2" "$3" <<'PYCOPY'
import os, stat, sys
source, target, limit = sys.argv[1:]
limit = int(limit)
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, "rb") as src:
    info = os.fstat(src.fileno())
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        sys.exit(1)
    count = 0
    with open(target, "xb") as dst:
        while piece := src.read(min(65536, limit + 1 - count)):
            count += len(piece)
            if count > limit:
                sys.exit(1)
            dst.write(piece)
    if count != info.st_size:
        sys.exit(1)
PYCOPY
}
download() {
 # HTTPS redirects stay HTTPS; mirror redirects are refused so every
 # project/runtime asset must originate from the selected mirror itself.
 case "$acquisition_mode" in
  https)
   allowed_proto='=https';max_redirs=5
   if [ "$source_kind" = mirror ];then max_redirs=0;fi
   set -- "$1" "$2" "$3";;
  http_loopback) allowed_proto='=http'; max_redirs=0; set -- "$1" "$2" "$3";;
  http_localhost:*)
   allowed_proto='=http'; max_redirs=0
   loopback_port=$(printf '%s' "$acquisition_mode" | cut -d: -f2)
   set -- "$1" "$2" "$3" --resolve "localhost:$loopback_port:127.0.0.1";;
  *) return 1;;
 esac
 download_url=$1; download_output=$2; download_limit=$3; shift 3
 curl -q --fail --location --max-redirs "$max_redirs" \
  --proto "$allowed_proto" --proto-redir "$allowed_proto" --noproxy '*' "$@" \
  --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 \
  --max-filesize "$download_limit" \
  --output "$download_output" "$download_url" 2>"$work/download.err"
}
# Select the exact supported target from verified Debian 12/13 host data;
# the index is strict bounded JSON. No shell evaluation of metadata fields.
if [ -n "$source_kind" ]; then
 [ -n "$host_target" ] || { echo 'Release host preflight missing; no install' >&2;exit 1; }
 target=$host_target
 download "$url" "$work/release-index.json" 16384 || {
  echo 'Release index unavailable from the selected HTTPS source; nothing installed' >&2;exit 1;
 }
 # Enforce the small transfer limit even if a server ignored --max-filesize.
 [ "$(wc -c < "$work/release-index.json")" -le 16384 ] || exit 1
 selection=$(python3 -I -S - "$work/release-index.json" "$target" <<'PYRELEASEINDEX'
import json,re,sys
try:
    data=open(sys.argv[1],"rb").read(16385)
    if len(data)>16384: raise ValueError("oversized index")
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out: raise ValueError("duplicate release index key")
            out[k]=v
        return out
    obj=json.loads(data,object_pairs_hook=unique)
    if set(obj)!={"schema","version","artifacts"} or obj["schema"]!=1 or type(obj["version"]) is not str or not re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,63}",obj["version"]):
        raise ValueError("unsupported index schema")
    artifacts=obj["artifacts"]
    if set(artifacts)!={"debian-12-amd64","debian-13-amd64"}: raise ValueError("unsupported targets")
    for value in artifacts.values():
        if type(value) is not dict or set(value)!={"archive","sha256"}: raise ValueError("unsupported target entry")
        name=value["archive"]
        if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_.\-/]+",name) or name.startswith("/") or any(part in ("",".","..") for part in name.split("/")) or not name.endswith(".tar.gz"):
            raise ValueError("unsafe artifact path")
        if type(value["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}",value["sha256"]):
            raise ValueError("invalid artifact hash")
    current=artifacts[sys.argv[2]]
    print(obj["version"])
    print(current["archive"])
    print(current["sha256"])
except (ValueError,TypeError,KeyError,UnicodeDecodeError,json.JSONDecodeError):
    sys.exit(1)
PYRELEASEINDEX
 ) || { echo 'Release index validation failed; no installation attempted' >&2;exit 1; }
 version=$(printf '%s\n' "$selection" | sed -n '1p')
 relative_archive=$(printf '%s\n' "$selection" | sed -n '2p')
 index_digest=$(printf '%s\n' "$selection" | sed -n '3p')
 url=$source_base$relative_archive
fi
if [ -n "$archive_file" ]; then
 copy_input "$archive_file" "$work/bundle.tar.gz" "$max_download_bytes" || {
  echo 'Offline archive copy rejected before installation' >&2;exit 1;
 }
elif ! download "$url" "$work/bundle.tar.gz" "$max_download_bytes"; then
 echo 'Online acquisition failed or exceeded the transfer ceiling; no installation changes.' >&2
 exit 1
fi
archive_bytes=$(wc -c < "$work/bundle.tar.gz")
[ "$archive_bytes" -le "$max_download_bytes" ] || {
 echo 'Downloaded archive exceeded the permitted size' >&2;exit 1;
}
if [ "$authenticated" = yes ]; then
 if [ -n "$metadata_file" ]; then
  copy_input "$metadata_file" "$work/release.json" 16384 &&
   copy_input "$signature_file" "$work/release.sig" 4096 || {
   echo 'Release identity or signature copy refused' >&2;exit 1;
  }
 else
  # Preserve a URL's query without treating it as part of a filename. Both
  # sidecars share the already validated authority; no downloaded key exists.
  for sidecar in release.json sig; do
   sidecar_url=$(python3 -I -S - "$url" "$sidecar" <<'PYURLSIDECAR'
import sys
from urllib.parse import urlsplit, urlunsplit
url = urlsplit(sys.argv[1])
print(urlunsplit((url.scheme, url.netloc, url.path + "." + sys.argv[2], url.query, "")))
PYURLSIDECAR
   ) || exit 1
   case "$sidecar" in release.json) limit=16384; destination=$work/release.json;; sig) limit=4096; destination=$work/release.sig;; esac
   download "$sidecar_url" "$destination" "$limit" || {
    echo 'Signed release identity acquisition failed' >&2;exit 1;
   }
  done
 fi
 # This helper belongs to the independently trusted bootstrap distribution,
 # never to the as-yet unauthenticated archive.
 auth_helper=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/release-auth.py
 [ -f "$auth_helper" ] && [ ! -L "$auth_helper" ] || {
  echo 'Trusted release-auth.py is required beside the trusted bootstrap' >&2;exit 1;
 }
 if [ "$user_id" -eq 0 ]; then
  # The trusted shell must not load adjacent Python code from a directory
  # replaceable by an unprivileged user. Check the complete ancestry before
  # the helper can execute; the helper independently checks the key/payload.
  trusted_path=$auth_helper
  while :; do
   [ ! -L "$trusted_path" ] && bootstrap_os_path_owned "$trusted_path" || {
    echo 'Authentication helper requires protected root-owned ancestry' >&2;exit 1;
   }
   [ "$trusted_path" != / ] || break
   trusted_path=$(dirname -- "$trusted_path") || exit 1
  done
 fi
 python3 -I -S "$auth_helper" verify --metadata "$work/release.json" \
  --signature "$work/release.sig" --publisher-key "$publisher_key" \
  --version "$version" --target "$target" --archive "$work/bundle.tar.gz" || exit 1
elif [ "$authenticated" = integrity ];then
 if [ -n "$metadata_file" ]; then
  copy_input "$metadata_file" "$work/release.json" 16384 || {
   echo 'Local release identity unavailable; no install' >&2;exit 1;
  }
 else
  metadata_url=$(python3 -I -S - "$url" <<'PYRELEASESIDECAR'
import sys
from urllib.parse import urlsplit,urlunsplit
u=urlsplit(sys.argv[1]);print(urlunsplit((u.scheme,u.netloc,u.path+'.release.json',u.query,'')))
PYRELEASESIDECAR
  ) || exit 1
  download "$metadata_url" "$work/release.json" 16384 || {
   echo 'Release identity sidecar unavailable from selected source; no install' >&2;exit 1;
  }
 fi
 python3 -I -S - "$work/release.json" "$work/bundle.tar.gz" "$version" "$target" "$index_digest" <<'PYRELEASEVERIFY'
import hashlib,json,re,sys
try:
    def read(path,cap):
        with open(path,'rb') as f:
            raw=f.read(cap+1)
        if not raw or len(raw)>cap: raise ValueError('unbounded or empty input')
        return raw
    def unique(pairs):
        value={}
        for k,v in pairs:
            if k in value: raise ValueError('duplicate release member')
            value[k]=v
        return value
    obj=json.loads(read(sys.argv[1],16384),object_pairs_hook=unique)
    fields={'schema','purpose','version','target','archive_sha256','checksums_sha256','manifest_sha256','source_revision','source_state','core','core_archive_sha256'}
    if set(obj)!=fields or type(obj['schema']) is not int or obj['schema']!=1 or obj['purpose']!='server-connect-release': raise ValueError('invalid release identity schema')
    if obj['target'] not in ('debian-12-amd64','debian-13-amd64') or not re.fullmatch(r'[0-9][0-9A-Za-z.+_-]{0,63}',obj['version']): raise ValueError('invalid version or target')
    if (sys.argv[3] and obj['version']!=sys.argv[3]) or (sys.argv[4] and obj['target']!=sys.argv[4]): raise ValueError('release selection mismatch')
    for field in ('archive_sha256','checksums_sha256','manifest_sha256','core_archive_sha256'):
        if type(obj[field]) is not str or not re.fullmatch(r'[0-9a-f]{64}',obj[field]): raise ValueError('invalid checksum')
    if type(obj['source_revision']) is not str or not re.fullmatch(r'[0-9a-f]{40}',obj['source_revision']) or obj['source_state']!='clean' or obj['core']!='sing-box 1.14.3': raise ValueError('unverified source/core identity')
    if sys.argv[5] and obj['archive_sha256']!=sys.argv[5]: raise ValueError('index and release identity disagree')
    h=hashlib.sha256()
    with open(sys.argv[2],'rb') as f:
        for part in iter(lambda:f.read(65536),b''):h.update(part)
    if h.hexdigest()!=obj['archive_sha256']:raise ValueError('archive checksum mismatch')
except (ValueError,KeyError,TypeError,UnicodeDecodeError,json.JSONDecodeError) as exc:
    print('Release identity, source, target or archive integrity mismatch: '+str(exc)+'; nothing installed',file=sys.stderr)
    sys.exit(1)
PYRELEASEVERIFY
 echo 'Release SHA256 integrity matches the selected source. HTTPS/upload trust is not publisher authentication.' >&2
else
 printf '%s  %s\n' "$digest" "$work/bundle.tar.gz" |
  sha256sum --quiet --check - || { echo 'Independent artifact digest mismatch' >&2;exit 1; }
 echo 'LOCAL QA ONLY: unsigned archive; publisher authentication was not performed.' >&2
fi

# One isolated stdlib parser validates AND privately extracts with the
# same tar semantics, including for --verify-only. No unbounded tar listing files or parser discrepancies.
# Enforce memory/time ceilings BEFORE parsing gzip/pax/longname metadata.
# Both acquisition modes use the same preinstalled trusted Python extractor.
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
    "server-connect/release-auth.py",
    "server-connect/LICENSE",
    "server-connect/server-connect.service",
    "server-connect/server-connect-activation-recover.service",
    "server-connect/server-connect-activation-recover.timer",
    "server-connect/server-connect-native-tun.service",
    "server-connect/server-connect-smart-health.service",
    "server-connect/server-connect-smart-health.timer",
    "server-connect/manifest.json",
    "server-connect/checksums.sha256",
    "server-connect/bin/server-connect",
    "server-connect/bin/sing-box",
    "server-connect/bin/libcronet.so",
    "server-connect/THIRD-PARTY-LICENSES/sing-box-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/golang.org-x-net-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/publicsuffix-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/publicsuffix-list.dat",
    "server-connect/THIRD-PARTY-LICENSES/chocolate4u-LICENSE",
    "server-connect/THIRD-PARTY-LICENSES/chocolate4u-geoip-ir.json",
    "server-connect/THIRD-PARTY-LICENSES/dbip-ATTRIBUTION.txt",
    "server-connect/THIRD-PARTY-LICENSES/dbip-iran-prefixes.json",
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
        # tar EOF may precede the gzip trailer. Drain through the same byte
        # budget so a signed but truncated/corrupt gzip cannot pass preflight.
        while bounded.read(65536):
            pass
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

if [ "$authenticated" = yes ]; then
 python3 -I -S "$auth_helper" verify --metadata "$work/release.json" \
  --signature "$work/release.sig" --publisher-key "$publisher_key" \
  --version "$version" --target "$target" --bundle "$work/server-connect" || exit 1
elif [ "$authenticated" = integrity ];then
 python3 -I -S - "$work/release.json" "$work/server-connect" <<'PYRELEASEPAYLOAD'
import hashlib,json,re,sys
from pathlib import Path
try:
    root=Path(sys.argv[2]);meta=json.loads(Path(sys.argv[1]).read_bytes())
    for filename,field in [('manifest.json','manifest_sha256'),('checksums.sha256','checksums_sha256')]:
        if hashlib.sha256((root/filename).read_bytes()).hexdigest()!=meta[field]:
            raise ValueError(filename+' digest mismatch')
    manifest=json.loads((root/'manifest.json').read_bytes())
    if (manifest['schema']!=1 or manifest['manager']!=meta['version'] or manifest['target']!=meta['target'] or manifest['source_revision']!=meta['source_revision'] or manifest['source_state']!=meta['source_state'] or manifest['core']!=meta['core'] or manifest['core_archive_sha256']!=meta['core_archive_sha256']):
        raise ValueError('manifest identity mismatch')
    lines=(root/'checksums.sha256').read_text('ascii').splitlines()
    all_files=set()
    for line in lines:
        if not re.fullmatch(r'[0-9a-f]{64}  [A-Za-z0-9_.\-/]+',line): raise ValueError('invalid checksums manifest')
        digest,name=line.split('  ',1)
        if name in all_files or not (root/name).is_file() or hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest: raise ValueError('file integrity mismatch')
        all_files.add(name)
    if set(all_files)!={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}-{'checksums.sha256'}: raise ValueError('unlisted archive member')
except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError):
    print('Release file checksums or manifest identity invalid; nothing installed',file=sys.stderr);sys.exit(1)
PYRELEASEPAYLOAD
fi
if [ "$verify_only" = yes ];then
 echo 'Acquisition, bounded archive and release layout verified. Installation was not attempted.'
 exit 0
fi
# The shared local installer independently verifies ownership, ancestry,
# complete payload checksums and service identity before lifecycle mutation.
if [ "$authenticated" = yes ]; then
 sh "$work/server-connect/install.sh" --offline \
  --publisher-key "$publisher_key" --metadata-file "$work/release.json" \
  --signature-file "$work/release.sig" --version "$version" --target "$target"
elif [ "$authenticated" = integrity ];then
 sh "$work/server-connect/install.sh" --offline
else
 sh "$work/server-connect/install.sh" --offline --local-qa
fi
# SERVER_CONNECT_BOOTSTRAP_END
