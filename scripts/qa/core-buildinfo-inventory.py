#!/usr/bin/env python3
"""Read pinned official sing-box build metadata without executing the Core.

This is binary provenance evidence, NOT a license inventory, corresponding
source kit, or permission to redistribute. No downloads, host mutations,
or execution of the inspected sing-box/libcronet binaries occur.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

CORE_SHA256 = "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93"
CRONET_SHA256 = "23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294"
CORE_REVISION = "7054cac5124465ffdb145870d7c01885566711b1"
CORE_MODULE = "github.com/sagernet/sing-box"
CORE_VERSION = "v1.14.3"
CORE_MAIN = "github.com/sagernet/sing-box/cmd/sing-box"
DEP_COUNT = 140
SHA256_CHUNK = 1024 * 1024
SUM_PATTERN = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")


class InventoryError(ValueError):
    pass


def verified_file(path: Path, expected: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise InventoryError("input must be a non-symlink regular file")
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(SHA256_CHUNK), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if digest != expected:
        raise InventoryError(f"pinned binary digest mismatch: observed={digest}")
    return digest


def _module(parts: list[str], context: str, main: bool = False) -> dict[str, str]:
    if len(parts) < 3 or len(parts) > 4:
        raise InventoryError(f"invalid {context} module metadata")
    path, version = parts[1:3]
    if not path or any(c.isspace() for c in path) or not version.startswith("v"):
        raise InventoryError(f"invalid {context} module identity")
    if main and len(parts) != 3:
        raise InventoryError("unexpected main-module sum")
    if not main and (len(parts) != 4 or not SUM_PATTERN.fullmatch(parts[3])):
        raise InventoryError(f"missing or malformed {context} module sum")
    result = {"path": path, "version": version}
    if len(parts) == 4:
        result["sum"] = parts[3]
    return result


def parse_buildinfo(output: str) -> dict:
    """Strictly parse 'go version -m' for this immutable official Core."""
    lines = output.splitlines()
    if not lines or not re.fullmatch(r".+: go1\.26\.8", lines[0]):
        raise InventoryError("unexpected Core Go version or buildinfo header")
    main_path = None
    main_module = None
    modules = []
    settings = {}
    seen = set()
    for line in lines[1:]:
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[0] == "path":
            if main_path is not None:
                raise InventoryError("duplicate main path")
            main_path = parts[1]
        elif parts[0] == "mod":
            if main_module is not None:
                raise InventoryError("duplicate main module")
            main_module = _module(parts, "main", main=True)
        elif parts[0] == "dep":
            module = _module(parts, "dependency")
            if module["path"] in seen:
                raise InventoryError(f"duplicate dependency {module['path']}")
            seen.add(module["path"])
            modules.append(module)
        elif parts[0] == "build":
            if len(parts) != 2 or "=" not in parts[1]:
                raise InventoryError("invalid build setting")
            key, value = parts[1].split("=", 1)
            if not key or key in settings:
                raise InventoryError(f"missing or duplicate build setting {key}")
            settings[key] = value
        else:
            # No silent disappearance of replacement/module provenance.
            raise InventoryError(f"unsupported or unexpected buildinfo record {parts[0]!r}")
    if main_path != CORE_MAIN:
        raise InventoryError("unexpected Core main package")
    if main_module != {"path": CORE_MODULE, "version": CORE_VERSION}:
        raise InventoryError("unexpected Core module")
    if len(modules) != DEP_COUNT:
        raise InventoryError(f"Core dependency metadata count {len(modules)} != {DEP_COUNT}")
    for key, expected in {
        "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0",
        "vcs": "git", "vcs.revision": CORE_REVISION,
        "vcs.modified": "false",
    }.items():
        if settings.get(key) != expected:
            raise InventoryError(f"missing or mismatched Core build setting {key}")
    if not settings.get("-tags"):
        raise InventoryError("missing selected build tags")
    modules.sort(key=lambda x: x["path"])
    return {
        "go_version": "go1.26.8",
        "main_package": main_path,
        "main_module": main_module,
        "build_settings": settings,
        "dependencies": modules,
    }


def produce(core: Path, cronet: Path, go: str = "go") -> dict:
    verified_file(core, CORE_SHA256)
    verified_file(cronet, CRONET_SHA256)
    try:
        process = subprocess.run(
            [go, "version", "-m", str(core.resolve())], capture_output=True,
            text=True, check=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InventoryError(f"unable to read pinned binary build information: {error}") from error
    details = parse_buildinfo(process.stdout)
    return {
        "schema": 1,
        "purpose": "pinned Core binary Go build information only; NOT a notice or source-closure audit",
        "binary": {"name": "sing-box", "version": CORE_VERSION, "sha256": CORE_SHA256},
        "native_library": {"name": "libcronet.so", "sha256": CRONET_SHA256,
                           "transitive_components_audited": False},
        **details,
        "dependency_count": len(details["dependencies"]),
        "license_notice_audit_complete": False,
        "corresponding_source_verified": False,
        "public_redistribution_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path,
                        help="verified, pinned official sing-box executable")
    parser.add_argument("--libcronet", required=True, type=Path,
                        help="verified, pinned official libcronet.so")
    args = parser.parse_args()
    try:
        inventory = produce(args.core, args.libcronet)
    except InventoryError as error:
        print(f"CORE_BUILDINFO_INVENTORY=REFUSED ({error})", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
