#!/usr/bin/env python3
"""Isolated Debian systemd guest fixture: actual Signed receipt SIGKILL.

Only run inside the disconnected, disposable --network none installed-host
container. Prepares the exact root-private first-install inode receipts and
checksum-verified stage, kills the real Signed receipt helper before/after its
single atomic link, and leaves real install.sh to inspect/recover/reinstall.
Never mutate production systems or patch a shipped release-auth.py.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

if len(sys.argv) != 3 or sys.argv[1] not in ("before", "after") or sys.argv[2] not in ("12", "13"):
    raise SystemExit("usage: signed-first-interruption.py before|after 12|13")
when, version = sys.argv[1:]
source = Path("/root/server-connect")
trust = Path("/root/qa-release-trust")
prefix = Path("/opt/server-connect")
state = Path("/var/lib/server-connect")
command = Path("/usr/local/bin/server-connect")
unit = Path("/etc/systemd/system/server-connect.service")
assert os.geteuid() == 0
assert not prefix.exists() and not prefix.is_symlink()
assert not (state / ".first-install-intent").exists()
assert not (state / ".first-release-intent").exists()
assert not command.exists() and not command.is_symlink()
assert not unit.exists() and not unit.is_symlink()
assert state.is_dir() and stat.S_IMODE(state.stat().st_mode) == 0o700
checksums = (source / "checksums.sha256").read_bytes()
name = "0.1.0-dev-" + hashlib.sha256(checksums).hexdigest()[:16]
suffix = "AUTH" + ("PRE0" if when == "before" else "POST")
outer = Path("/opt/.server-connect-release." + suffix)
inner = prefix / "releases" / (".stage." + suffix)
assert not outer.exists() and not inner.exists()
prefix.mkdir(mode=0o755)
(prefix / ".owner").write_bytes(b"AChWorks/server-connect\n")
(prefix / ".owner").chmod(0o644)
(prefix / "releases").mkdir(mode=0o755)
inner.mkdir(mode=0o755)
for line in checksums.decode("ascii").splitlines():
    sha, leaf = line.split("  ", 1)
    source_path = source / leaf
    target = inner / leaf
    target.parent.mkdir(parents=True, exist_ok=True)
    with source_path.open("rb") as inp, target.open("xb") as out:
        while data := inp.read(65536):
            out.write(data)
    target.chmod(stat.S_IMODE(source_path.stat().st_mode))
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
(inner / "checksums.sha256").write_bytes(checksums)
(inner / "checksums.sha256").chmod(0o644)
(inner / ".owner").write_bytes(b"AChWorks/server-connect\n")
(inner / ".owner").chmod(0o644)
def claim(path: Path, content: str) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, content.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
public = subprocess.run(
    ["/usr/bin/openssl", "pkey", "-pubin",
     "-in", str(trust / "independent-public.pem"), "-pubout"],
    check=True, capture_output=True, timeout=15).stdout
original_trust = "signed:" + ":".join(
    hashlib.sha256(raw).hexdigest() for raw in (
        (trust / "release.json").read_bytes(),
        (trust / "release.sig").read_bytes(),
        public))
claim(state / ".first-install-intent",
      f"/opt/.server-connect-initial.{suffix}\n{prefix.stat().st_dev}:{prefix.stat().st_ino}\n{original_trust}\n")
claim(state / ".first-release-intent",
      f"{outer}\n{inner.stat().st_dev}:{inner.stat().st_ino}\n{name}\n{original_trust}\n")
for path in (inner, inner.parent, prefix, state):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
# The child imports the *unaltered* first-party Signed verifier and executes
# exactly install-receipt. Only a guest-local hook interrupts the publish
# function; there is no fake receipt or mocked successful signature.
child_program = """
import importlib.util, os, signal, sys
helper, when, bundle, version = sys.argv[1:]
spec=importlib.util.spec_from_file_location("signed_guest_sigkill",helper)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original=module.link_anonymous_receipt
def terminate(fd, directory):
    if when=="before":
        os.kill(os.getpid(),signal.SIGKILL)
    original(fd,directory)
    os.kill(os.getpid(),signal.SIGKILL)
module.link_anonymous_receipt=terminate
sys.argv=[helper,"install-receipt","--bundle",bundle,
          "--metadata","/root/qa-release-trust/release.json",
          "--signature","/root/qa-release-trust/release.sig",
          "--publisher-key","/root/qa-release-trust/independent-public.pem",
          "--version","0.1.0-dev","--target",f"debian-{version}-amd64"]
module.main()
"""
process = subprocess.run(
    ["/usr/bin/python3", "-I", "-S", "-c", child_program,
     str(source / "release-auth.py"), when, str(inner), version],
    capture_output=True, text=True, timeout=30)
if process.returncode != -signal.SIGKILL:
    raise RuntimeError("expected SIGKILL of real Signed helper; "
                       f"exit={process.returncode}; stderr={process.stderr[-1600:]}")
if list(inner.glob(".authentication.*")):
    raise RuntimeError("named Signed authentication intermediates leaked")
auth = inner / "authentication.json"
if when == "before":
    assert not auth.exists() and not auth.is_symlink()
else:
    assert auth.is_file()
    assert (auth.stat().st_nlink, stat.S_IMODE(auth.stat().st_mode)) == (1, 0o600)
assert (state / ".first-install-intent").is_file()
assert (state / ".first-release-intent").is_file()
assert not (prefix / "current").exists()
assert not command.exists()
assert not unit.exists()
print(f"SIGNED_FIRST_ANONYMOUS_SIGKILL_{when.upper()}=PASS "
      f"(real Signed helper pid exit=-9, exact owned stage+receipts, "
      f"final_auth={'present_single_name' if auth.exists() else 'absent'})", flush=True)
