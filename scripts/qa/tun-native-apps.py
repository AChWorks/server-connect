#!/usr/bin/env python3
"""Disposable, disconnected real-TUN QA: native APT and Git without proxy setup.

Only the fixed synthetic IP/port is contacted. A peer-namespace HTTP origin
records the actual TCP peer IP for every successful fetch. Never install a
package, edit /etc/apt, or access a public repository.
"""

import gzip
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
from datetime import datetime, timezone
from email.utils import format_datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path("/run/sc-qa-tun-native-apps")
PUBLIC = ROOT / "public"
WITNESS = ROOT / "native-http-witness.log"
ORIGIN = "http://8.8.8.8:19187"
PACKAGE = "sc-qa-tun-route-proof"
PORT = 19187

BASE_ENV = {
    "HOME": str(ROOT),
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    # Diagnostic only; the fake repository never contains operator secrets.
    "GIT_TRACE_CURL": "1",
    "GIT_TRACE_CURL_NO_DATA": "1",
}


def run(argv, timeout=22):
    # Native APT and Git spawn helpers. A timeout must terminate the entire
    # QA-owned subprocess group, not abandon a child that can keep sockets open.
    proc = subprocess.Popen(
        argv, env=BASE_ENV, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate(timeout=5)
        witnessed = (
            WITNESS.read_text(encoding="ascii").splitlines()[-14:]
            if WITNESS.is_file() else []
        )
        # All URLs and credentials here are generated inside the disposable
        # guest. Failure-only bounded output helps distinguish stalled Git
        # object transport from a missing fixture or wrong native path.
        detail = stderr.decode("utf-8", errors="replace")[-2600:]
        raise RuntimeError(
            f"native client exceeded bounded timeout: {argv[0]}; "
            f"stderr_tail={detail!r}; peer_requests={witnessed!r}"
        ) from exc
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def checked(argv):
    result = run(argv)
    if result.returncode:
        raise RuntimeError(f"fixture command failed: {argv[0]} (exit {result.returncode})")
    return result.stdout


def prepare():
    if ROOT.exists() or ROOT.is_symlink():
        raise RuntimeError("native-app QA fixture already exists")
    ROOT.mkdir(mode=0o755)
    PUBLIC.mkdir(mode=0o755)
    (ROOT / "home").mkdir(mode=0o700)
    # The native APT method drops to _apt; permit fixture metadata traversal
    # even when the parent QA shell runs with umask 077.
    ROOT.chmod(0o755)
    PUBLIC.chmod(0o755)
    apt_dir = PUBLIC / "apt/dists/qa"
    index_dir = apt_dir / "main/binary-amd64"
    index_dir.mkdir(parents=True)
    index = (
        f"Package: {PACKAGE}\nVersion: 1.0\nArchitecture: amd64\n"
        "Maintainer: Disposable TUN QA <qa@invalid.test>\n"
        "Description: synthetic index-only, never installed\n\n"
    ).encode("ascii")
    compressed = gzip.compress(index, mtime=0)
    (index_dir / "Packages").write_bytes(index)
    (index_dir / "Packages.gz").write_bytes(compressed)
    entry = lambda name, blob: (
        f" {hashlib.sha256(blob).hexdigest()} {len(blob)} {name}\n"
    )
    release = (
        "Origin: Server Connect isolated TUN QA\n"
        "Label: Synthetic native APT routing proof\n"
        "Suite: qa\nCodename: qa\nArchitectures: amd64\nComponents: main\n"
        f"Date: {format_datetime(datetime.now(timezone.utc))}\n"
        "SHA256:\n"
        + entry("main/binary-amd64/Packages", index)
        + entry("main/binary-amd64/Packages.gz", compressed)
    )
    (apt_dir / "Release").write_text(release, encoding="ascii")
    (ROOT / "sources.list").write_text(
        f"deb [trusted=yes] {ORIGIN}/apt qa main\n", encoding="ascii"
    )

    source = ROOT / "git-source"
    bare = PUBLIC / "git/fixture.git"
    bare.parent.mkdir(parents=True)
    checked(["/usr/bin/git", "init", "-q", "-b", "main", str(source)])
    (source / "route-proof.txt").write_text(
        "Server Connect TUN native Git route proof\n", encoding="ascii"
    )
    checked(["/usr/bin/git", "-C", str(source), "add", "route-proof.txt"])
    checked([
        "/usr/bin/git", "-C", str(source),
        "-c", "user.name=QA", "-c", "user.email=qa@invalid.test",
        "commit", "-q", "-m", "disposable route proof",
    ])
    sha = checked(["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"]).decode().strip()
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise RuntimeError("invalid synthetic Git commit identity")
    checked(["/usr/bin/git", "clone", "--bare", "-q", str(source), str(bare)])
    checked(["/usr/bin/git", "-C", str(bare), "update-server-info"])
    (ROOT / "expected-git-sha").write_text(sha + "\n", encoding="ascii")
    WITNESS.touch(mode=0o600)
    print("REAL_TUN_NATIVE_APP_FIXTURES=PASS (isolated APT index and Git objects)")


class OriginHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC), **kwargs)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/apt/") or path.startswith("/git/fixture.git/"):
            # Shared guest filesystem, different independently controlled
            # network namespace. Append each observed TCP sender, never a
            # claimed route inferred from a client's exit code.
            with WITNESS.open("a", encoding="ascii") as fp:
                fp.write(f"{self.client_address[0]}\t{path}\n")
        super().do_GET()

    def log_message(self, *args):
        pass


def serve():
    if not (PUBLIC / "apt/dists/qa/Release").is_file() or not WITNESS.is_file():
        raise RuntimeError("native-app fixture not prepared")
    ThreadingHTTPServer(("0.0.0.0", PORT), OriginHandler).serve_forever()


def apt_args(phase):
    base = ROOT / f"apt-{phase}"
    lists = base / "lists"
    (lists / "partial").mkdir(parents=True, exist_ok=False)
    (base / "archives/partial").mkdir(parents=True, exist_ok=False)
    for directory in (base, lists, lists / "partial", base / "archives", base / "archives/partial"):
        directory.chmod(0o755)
    options = [
        f"-oDir::Etc::sourcelist={ROOT / 'sources.list'}",
        "-oDir::Etc::sourceparts=-",
        f"-oDir::State::lists={lists}",
        f"-oDir::Cache::archives={base / 'archives'}",
        "-oDir::Cache::pkgcache=/dev/null",
        "-oDir::Cache::srcpkgcache=/dev/null",
        "-oAPT::Get::List-Cleanup=0",
        "-oAcquire::Retries=0",
        "-oAcquire::http::Timeout=4",
        "-oAPT::Update::Error-Mode=any",
        "-oDebug::NoLocking=1",
    ]
    return ["/usr/bin/apt-get", "update", *options], [
        "/usr/bin/apt-cache", *options[0:5], "show", PACKAGE,
    ]


def check_witness(expected, required):
    records = [line.split("\t", 1) for line in WITNESS.read_text(encoding="ascii").splitlines()]
    if any(len(parts) != 2 or parts[0] != expected for parts in records):
        raise RuntimeError("wrong native HTTP-origin source observed")
    for prefix in required:
        if not any(parts[1].startswith(prefix) for parts in records):
            raise RuntimeError(f"no independently witnessed HTTP request: {prefix}")
    if not required and records:
        raise RuntimeError("native-app HTTP requests escaped via unexpected path")


def exercise(phase):
    if phase not in ("baseline", "selected", "outage"):
        raise RuntimeError("invalid native-app phase")
    if not WITNESS.is_file():
        raise RuntimeError("missing independent witness")
    WITNESS.write_text("", encoding="ascii")  # unique phase; no stale PASS
    apt_update, apt_cache = apt_args(phase)
    apt = run(apt_update, timeout=20)
    package = run(apt_cache, timeout=7)
    if phase == "selected":
        print(f"REAL_TUN_NATIVE_APT_SELECTED_STEP=OBSERVED (update={apt.returncode}, show={package.returncode})", flush=True)
    clone_path = ROOT / f"git-clone-{phase}"
    clone = run([
        "/usr/bin/git",
        "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=4",
        "clone", "-q", f"{ORIGIN}/git/fixture.git", str(clone_path)
    ], timeout=19)

    if phase == "outage":
        # Prior phases proved both executables, fixture bytes and a live
        # selected VLESS path. Unreachable VPN-required flows must neither
        # install a fresh native index nor yield a complete Git checkout.
        if apt.returncode != 100 or package.returncode != 100 or clone.returncode != 128:
            raise RuntimeError(
                f"unexpected native app outage statuses (APT={apt.returncode}, "
                f"cache={package.returncode}, Git={clone.returncode})"
            )
        # Require the actual native HTTP acquisition paths to have failed,
        # not an unrelated APT syntax error, missing binary or Git setup fault.
        if (
            f"E: Failed to fetch {ORIGIN}/apt/dists/qa/".encode() not in apt.stderr
            or b"E: No packages found" not in package.stderr
            or f"fatal: unable to access '{ORIGIN}/git/fixture.git/".encode() not in clone.stderr
        ):
            raise RuntimeError("native-app failure was not an origin acquisition failure")
        check_witness(expected="", required=[])
        print("REAL_TUN_NATIVE_APPS_OUTAGE=PASS (APT/Git origin failed, no delivery)")
        return

    if apt.returncode != 0 or package.returncode != 0:
        raise RuntimeError(f"native APT fixture rejected (update={apt.returncode}, show={package.returncode})")
    if f"Package: {PACKAGE}\n".encode() not in package.stdout:
        raise RuntimeError("APT did not retrieve the freshly generated package index")
    if clone.returncode != 0:
        raise RuntimeError(f"native Git clone rejected (exit {clone.returncode})")
    expected_sha = (ROOT / "expected-git-sha").read_text(encoding="ascii").strip()
    actual_sha = checked(["/usr/bin/git", "-C", str(clone_path), "rev-parse", "HEAD"]).decode().strip()
    if actual_sha != expected_sha or (
        clone_path / "route-proof.txt"
    ).read_text(encoding="ascii") != "Server Connect TUN native Git route proof\n":
        raise RuntimeError("Git data or revision differs from independently prepared fixture")
    observed_source = "10.254.72.1" if phase == "baseline" else "8.8.8.8"
    check_witness(observed_source, ["/apt/dists/qa/Release", "/git/fixture.git/info/refs"])
    print(f"REAL_TUN_NATIVE_APPS_{phase.upper()}=PASS (real APT/Git, independently witnessed source)")


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: tun-native-apps.py prepare|serve|baseline|selected|outage")
    if sys.argv[1] == "prepare":
        prepare()
    elif sys.argv[1] == "serve":
        serve()
    else:
        exercise(sys.argv[1])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, UnicodeError) as error:
        print(f"REAL_TUN_NATIVE_APPS=FAIL ({error})", file=sys.stderr)
        sys.exit(1)
