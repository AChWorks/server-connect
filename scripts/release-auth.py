#!/usr/bin/env python3
"""Authenticate release bytes with an independently supplied publisher key.

Run this trusted copy before executing anything from a downloaded bundle.
OpenSSL supplies signature operations; no network access or custom crypto.
The sign operation is deliberately limited to explicit local QA key testing.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_ARCHIVE = 100663296
MAX_FILE = 134217728
CORE = "sing-box 1.14.3"
CORE_ARCHIVE = "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"
FIELDS = {
    "schema", "purpose", "version", "target", "archive_sha256",
    "checksums_sha256", "manifest_sha256", "source_revision", "source_state",
    "core", "core_archive_sha256",
}
PAYLOAD = (
    "bin/server-connect", "bin/sing-box", "bin/libcronet.so",
    "server-connect.service", "server-connect-activation-recover.service",
    "server-connect-activation-recover.timer", "server-connect-smart-tun.service",
    "server-connect-smart-health.service", "server-connect-smart-health.timer",
    "install.sh", "release-auth.py", "THIRD-PARTY-LICENSES/sing-box-LICENSE",
    "manifest.json",
)


def fail(message):
    raise ValueError(message)


def protected_path(path):
    """Root must never use a replaceable trust anchor or staged payload."""
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.abspath(path):
        fail("an absolute canonical path is required")
    for part in (Path("/"), *reversed(path.parents[:-1]), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode):
            fail("symlink in trusted input path")
        if os.geteuid() == 0 and (info.st_uid != 0 or info.st_mode & 0o022):
            fail("trusted input must have protected root-owned ancestry")
    return path


def open_input(path, ceiling):
    path = protected_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(fd, "rb")
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= ceiling:
        source.close()
        fail("input is not a bounded regular file")
    return source, info


def unchanged(source, before):
    after = os.fstat(source.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                   after.st_mtime_ns, after.st_ctime_ns):
        fail("input changed during verification")


def read_input(path, ceiling):
    source, info = open_input(path, ceiling)
    with source:
        data = source.read(ceiling + 1)
        if len(data) != info.st_size:
            fail("input changed or exceeded its limit")
        unchanged(source, info)
        return data


def digest_file(path, ceiling=MAX_FILE):
    source, info = open_input(path, ceiling)
    with source:
        digest = hashlib.sha256()
        count = 0
        while piece := source.read(65536):
            count += len(piece)
            if count > ceiling:
                fail("input exceeded its limit")
            digest.update(piece)
        if count != info.st_size:
            fail("input changed during hashing")
        unchanged(source, info)
        return digest.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON member")
        result[key] = value
    return result


def parse_json(raw):
    if not raw or any(byte not in (9, 10, 13) and not 32 <= byte <= 126 for byte in raw):
        fail("release identity must be bounded ASCII JSON")
    value = json.loads(raw, object_pairs_hook=unique_object,
                       parse_constant=lambda _: fail("non-finite JSON value"))
    if type(value) is not dict:
        fail("release identity must be an object")
    return value


def identity(raw, version, target):
    metadata = parse_json(raw)
    if set(metadata) != FIELDS or type(metadata["schema"]) is not int or metadata["schema"] != 1:
        fail("unsupported release identity schema")
    if metadata["purpose"] != "server-connect-release":
        fail("wrong signature purpose")
    if (not re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,63}", version or "")
            or target not in ("debian-12-amd64", "debian-13-amd64")):
        fail("explicit supported version and target pins are required")
    if metadata["version"] != version or metadata["target"] != target:
        fail("signed version or target does not match the operator pin")
    for name in ("archive_sha256", "checksums_sha256", "manifest_sha256", "core_archive_sha256"):
        if type(metadata[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", metadata[name]):
            fail("invalid signed digest")
    if (type(metadata["source_revision"]) is not str
            or not re.fullmatch(r"[0-9a-f]{40}", metadata["source_revision"])
            or metadata["source_state"] != "clean"):
        fail("a clean exact source revision is required for signing")
    if metadata["core"] != CORE or metadata["core_archive_sha256"] != CORE_ARCHIVE:
        fail("unsupported signed Core identity")
    return metadata


def openssl(*args):
    # Ignore inherited provider/configuration/loader settings. The trusted
    # launcher must already have cleared interpreter startup environment.
    result = subprocess.run(
        ["/usr/bin/openssl", *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
             "OPENSSL_CONF": "/dev/null"},
        timeout=20, check=False,
    )
    if result.returncode:
        fail("publisher signature or key validation failed")


def check_bundle(bundle, metadata):
    root = protected_path(bundle)
    manifest_raw = read_input(root / "manifest.json", 16384)
    checksums = read_input(root / "checksums.sha256", 16384)
    if hashlib.sha256(manifest_raw).hexdigest() != metadata["manifest_sha256"]:
        fail("signed manifest digest mismatch")
    if hashlib.sha256(checksums).hexdigest() != metadata["checksums_sha256"]:
        fail("signed checksum-manifest digest mismatch")
    manifest = parse_json(manifest_raw)
    expected = {
        "schema": 1, "manager": metadata["version"], "core": metadata["core"],
        "core_archive_sha256": metadata["core_archive_sha256"],
        "source_revision": metadata["source_revision"], "source_state": metadata["source_state"],
        "target": metadata["target"],
        "redistribution": "not authorized; local QA only",
    }
    # Do not erase or silently promote the current product/licensing boundary.
    if manifest != expected or type(manifest.get("schema")) is not int:
        fail("manifest does not match the signed release identity")
    expected_checksums = "".join(
        digest_file(root / name) + "  " + name + "\n" for name in PAYLOAD
    ).encode("ascii")
    if checksums != expected_checksums:
        fail("release payload is not covered by its exact checksum manifest")


# A retained key is a trust-store entry created only after the explicit
# external-key path above succeeds. An incoming archive cannot carry it:
# it is outside PAYLOAD and the acquisition extractor rejects extra files.
INSTALLED_RELEASES = Path("/opt/server-connect/releases")
RECEIPT_NAME = "authentication.json"
RECEIPT_FIELDS = {
    "schema", "purpose", "owner", "release_checksums_sha256",
    "publisher_spki_sha256", "metadata_b64", "signature_b64", "publisher_key_b64",
}


def receipt_location(bundle, metadata):
    root = protected_path(bundle)
    if root.parent != INSTALLED_RELEASES:
        fail("retained trust is restricted to the managed installed-release namespace")
    expected = "0.1.0-dev-" + metadata["checksums_sha256"][:16]
    if root.name != expected and not re.fullmatch(r"\.stage\.[A-Za-z0-9]{8}", root.name):
        fail("authentication receipt is not associated with this release identity")
    if read_input(root / ".owner", 128) != b"AChWorks/server-connect\n":
        fail("authentication receipt has no verified managed-release owner")
    return root


def decode_receipt(raw):
    receipt = parse_json(raw)
    if (set(receipt) != RECEIPT_FIELDS or type(receipt["schema"]) is not int
            or receipt["schema"] != 1
            or receipt["purpose"] != "server-connect-installed-authentication"
            or receipt["owner"] != "AChWorks/server-connect"):
        fail("unrecognized installed authentication receipt")
    for name in ("release_checksums_sha256", "publisher_spki_sha256"):
        if type(receipt[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", receipt[name]):
            fail("malformed installed authentication binding")
    decoded = {}
    for name, limit in (("metadata", 16384), ("signature", 4096), ("publisher_key", 16384)):
        encoded = receipt[name + "_b64"]
        if type(encoded) is not str:
            fail("malformed installed authentication material")
        value = base64.b64decode(encoded, validate=True)
        if not 0 < len(value) <= limit:
            fail("oversized installed authentication material")
        decoded[name] = value
    return receipt, decoded


def read_receipt(bundle):
    path = Path(bundle) / RECEIPT_NAME
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        fail("installed authentication receipt must be private and singly owned")
    raw = read_input(path, 65536)
    receipt, material = decode_receipt(raw)
    # Mixed unsigned/signed records are uncertain, never a fallback route.
    if (Path(bundle) / "local-qa.sha256").exists() or (Path(bundle) / "local-qa.sha256").is_symlink():
        fail("conflicting signed and local QA receipts")
    return raw, receipt, material


def persist_receipt(bundle, metadata, raw, signature, public_key, fingerprint):
    root = receipt_location(bundle, metadata)
    if (root / "local-qa.sha256").exists() or (root / "local-qa.sha256").is_symlink():
        fail("an unsigned release cannot be silently promoted to a signed trust store")
    receipt = {
        "schema": 1, "purpose": "server-connect-installed-authentication",
        "owner": "AChWorks/server-connect",
        "release_checksums_sha256": metadata["checksums_sha256"],
        "publisher_spki_sha256": fingerprint,
        "metadata_b64": base64.b64encode(raw).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "publisher_key_b64": base64.b64encode(public_key).decode("ascii"),
    }
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    destination = root / RECEIPT_NAME
    if destination.exists() or destination.is_symlink():
        existing, _, _ = read_receipt(root)
        if existing != encoded:
            fail("existing authentication receipt differs; no overwrite or key replacement permitted")
        # A prior interrupted publication may have left the complete file
        # before its directory fsync. Reuse must establish durability again,
        # not convert a merely readable receipt into a successful write claim.
        fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.close(fd)
        return
    # The installer calls this in its fresh owned release stage before
    # publishing it. Link is an atomic no-replace publication, unlike rename
    # over a pathname that another actor could have created.
    fd, temporary = tempfile.mkstemp(prefix=".authentication.", dir=root)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
            os.unlink(temporary)
            os.fsync(directory)
        finally:
            os.close(directory)
        if read_receipt(root)[0] != encoded:
            fail("persisted authentication receipt did not match verified inputs")
    finally:
        # Only our exact unprivileged-inaccessible temporary filename. Never
        # remove a destination on uncertain publication; the caller's owned
        # staging rollback retains responsibility for that outcome.
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "sign-local-qa", "install-receipt", "verify-installed"))
    parser.add_argument("--metadata")
    parser.add_argument("--signature")
    parser.add_argument("--publisher-key")
    parser.add_argument("--signing-key")
    parser.add_argument("--version")
    parser.add_argument("--target")
    parser.add_argument("--archive")
    parser.add_argument("--bundle")
    args = parser.parse_args()
    os.umask(0o077)
    receipt = None
    material = None
    if args.action == "verify-installed":
        if not args.bundle or any((args.archive, args.metadata, args.signature, args.publisher_key,
                                   args.signing_key, args.version, args.target)):
            fail("installed verification accepts only the canonical managed bundle path")
        _, receipt, material = read_receipt(args.bundle)
        raw = material["metadata"]
        parsed = parse_json(raw)
        args.version, args.target = parsed.get("version"), parsed.get("target")
    else:
        if not args.metadata or not args.signature or not args.version or not args.target:
            fail("explicit metadata, signature, version and target are required")
        raw = read_input(args.metadata, 16384)
    if not args.archive and not args.bundle:
        fail("an archive or extracted bundle is required")
    metadata = identity(raw, args.version, args.target)
    if receipt is not None:
        receipt_location(args.bundle, metadata)
        if receipt["release_checksums_sha256"] != metadata["checksums_sha256"]:
            fail("installed authentication receipt names a different release")
    if args.action == "install-receipt" and not args.bundle:
        fail("receipt creation requires the exact owned release stage")
    # Private copies prevent a verify/parse race. Root's staging parent is
    # itself protected; no TMPDIR controlled by an unprivileged caller.
    parent = "/root" if os.geteuid() == 0 else None
    if parent:
        protected_path(parent)
    with tempfile.TemporaryDirectory(prefix=".server-connect-auth-", dir=parent) as scratch:
        work = Path(scratch)
        message = work / "release.json"
        message.write_bytes(raw)
        signature = work / "release.sig"
        key = work / "key.pem"
        if args.action != "sign-local-qa":
            if receipt is None:
                if not args.publisher_key or args.signing_key:
                    fail("an independently trusted public key is required")
                key.write_bytes(read_input(args.publisher_key, 16384))
                signature.write_bytes(read_input(args.signature, 4096))
            else:
                key.write_bytes(material["publisher_key"])
                signature.write_bytes(material["signature"])
            openssl("dgst", "-sha256", "-verify", str(key),
                    "-signature", str(signature), str(message))
        else:
            if not args.signing_key or args.publisher_key or not args.archive:
                fail("local QA signing requires a private key and exact archive")
            key.write_bytes(read_input(args.signing_key, 16384))
        if args.archive and digest_file(args.archive, MAX_ARCHIVE) != metadata["archive_sha256"]:
            fail("signed archive digest mismatch")
        if args.bundle:
            check_bundle(args.bundle, metadata)
        if args.action == "sign-local-qa":
            # This never creates a key or selects a production signing identity.
            openssl("dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(message))
            public = work / "public.pem"
            openssl("pkey", "-in", str(key), "-pubout", "-out", str(public))
            openssl("dgst", "-sha256", "-verify", str(public),
                    "-signature", str(signature), str(message))
            output = Path(args.signature)
            protected_path(output.parent)
            # Never overwrite a signature: signed outputs are immutable.
            with output.open("xb") as destination:
                destination.write(signature.read_bytes())
                destination.flush()
                os.fsync(destination.fileno())
            print("LOCAL QA signature created; no publication or redistribution approval.")
        elif args.action in ("install-receipt", "verify-installed"):
            public = work / "public.pem"
            der = work / "public.der"
            openssl("pkey", "-pubin", "-in", str(key), "-pubout", "-out", str(public))
            openssl("pkey", "-pubin", "-in", str(key), "-outform", "DER", "-out", str(der))
            fingerprint = hashlib.sha256(der.read_bytes()).hexdigest()
            if args.action == "install-receipt":
                persist_receipt(args.bundle, metadata, raw, signature.read_bytes(),
                                public.read_bytes(), fingerprint)
                print("Managed release authentication receipt persisted with the independently supplied trust anchor.")
            else:
                if receipt["publisher_spki_sha256"] != fingerprint:
                    fail("retained publisher key fingerprint mismatch")
                print("Managed release authentication receipt and immutable payload verified offline.")
        else:
            print("Publisher signature and pinned release identity verified against the supplied trust anchor.")
            print("This development payload remains LOCAL QA ONLY; no public release approval is asserted.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        # All application reasons are fixed strings; JSON decoder errors
        # report syntax positions, never key bytes or URL credentials.
        print("Release authentication refused: " + str(error) + "; no installation permitted.", file=sys.stderr)
        sys.exit(1)
    except (OSError, TypeError, RecursionError, subprocess.SubprocessError):
        print("Release authentication refused: local input, parser or OpenSSL operation unavailable; no installation permitted.",
              file=sys.stderr)
        sys.exit(1)
