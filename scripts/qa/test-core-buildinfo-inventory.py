#!/usr/bin/env python3
"""Pure stdlib negative tests of the pinned, read-only Core inventory."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("core-buildinfo-inventory.py")
spec = importlib.util.spec_from_file_location("core_buildinfo_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)

SUM = "h1:" + "A" * 43 + "="


def sample() -> str:
    deps = "".join(f"\tdep\texample.org/mod{i:03d}\tv1.2.3\t{SUM}\n"
                   for i in range(inventory.DEP_COUNT))
    return (
        "/tmp/executable: go1.26.8\n"
        "\tpath\tgithub.com/sagernet/sing-box/cmd/sing-box\n"
        "\tmod\tgithub.com/sagernet/sing-box\tv1.14.3\t\n"
        + deps
        + "\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n"
        "\tbuild\tCGO_ENABLED=0\n\tbuild\tvcs=git\n"
        f"\tbuild\tvcs.revision={inventory.CORE_REVISION}\n"
        "\tbuild\tvcs.modified=false\n\tbuild\t-tags=with_purego\n"
    )


class ParserTests(unittest.TestCase):
    def test_immutable_identity_and_complete_sorted_inventory(self):
        result = inventory.parse_buildinfo(sample())
        self.assertEqual(len(result["dependencies"]), 140)
        self.assertEqual(result["main_module"]["version"], "v1.14.3")
        self.assertEqual(result["dependencies"][0]["sum"], SUM)

    def test_no_missing_or_ambiguous_metadata(self):
        text = sample()
        for broken in (
            text.replace("go1.26.8", "go1.27.1", 1),
            text.replace("v1.14.3", "v1.14.2", 1),
            text.replace(inventory.CORE_REVISION, "0" * 40, 1),
            text.replace("vcs.modified=false", "vcs.modified=true", 1),
            text.replace("\tbuild\tGOARCH=amd64\n", "", 1),
            text.replace("\tbuild\t-tags=with_purego\n", "", 1),
            text.replace(f"\tdep\texample.org/mod001\tv1.2.3\t{SUM}\n", "", 1),
            text.replace(f"\tdep\texample.org/mod001\tv1.2.3\t{SUM}\n",
                         f"\tdep\texample.org/mod000\tv1.2.3\t{SUM}\n", 1),
            text.replace(SUM, "h1:malformed", 1),
            text.replace("\tdep\texample.org/mod000\tv1.2.3\t",
                         "\treplace\texample.org/mod000\tv1.2.3\t", 1),
            text.replace("\tbuild\tGOOS=linux\n", "\tbuild\tGOOS=linux\n\tbuild\tGOOS=linux\n", 1),
        ):
            with self.subTest(case=broken[:50], length=len(broken)):
                with self.assertRaises(inventory.InventoryError):
                    inventory.parse_buildinfo(broken)

    def test_verify_digest_refuses_before_reading_go(self):
        with tempfile.TemporaryDirectory(prefix="sc-buildinfo-negative-") as temporary:
            tmp = Path(temporary)
            core = tmp / "core"
            lib = tmp / "lib"
            core.write_bytes(b"NOT THE OFFICIAL CORE")
            lib.write_bytes(b"NOT THE OFFICIAL LIBRARY")
            with patch.object(inventory.subprocess, "run") as invoke:
                with self.assertRaisesRegex(inventory.InventoryError, "digest mismatch"):
                    inventory.produce(core, lib)
                invoke.assert_not_called()
                # A valid Core identity must not excuse an altered native
                # companion library or allow even metadata inspection.
                fake_core_sha = hashlib.sha256(core.read_bytes()).hexdigest()
                with patch.object(inventory, "CORE_SHA256", fake_core_sha):
                    with self.assertRaisesRegex(inventory.InventoryError, "digest mismatch"):
                        inventory.produce(core, lib)
                invoke.assert_not_called()
            core.unlink()
            core.symlink_to(lib)
            with self.assertRaisesRegex(inventory.InventoryError, "non-symlink"):
                inventory.verified_file(core, inventory.CORE_SHA256)


if __name__ == "__main__":
    unittest.main()
