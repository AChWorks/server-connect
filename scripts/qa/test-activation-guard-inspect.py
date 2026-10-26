#!/usr/bin/env python3
"""Hermetic false-PASS tests for isolated QA-only kernel inventory verifier."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "sc_activation_guard_inspector", Path(__file__).with_name("activation-guard-inspect.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(mode):
    links = [{"ifname": "lo"}]
    routes = []
    rules = []
    lookups = {}
    if mode in ("applied", "recovered"):
        resources = [mod.FOREIGN]
        if mode == "applied":
            resources.insert(0, mod.OWNED)
        for name, alias, cidr, priority in resources:
            links.append({"ifname": name, "ifalias": alias,
                          "linkinfo": {"info_kind": "dummy"}})
            routes.append({"dst": cidr, "dev": name, "table": mod.TABLE})
            rules.append({"priority": priority, "table": mod.TABLE,
                          "dst": cidr.split('/')[0], "dstlen": int(cidr.split('/')[1])})
        lookups = {"selected": [{"dev": mod.OWNED[0] if mode == "applied" else "lo"}],
                   "foreign": [{"dev": mod.FOREIGN[0]}],
                   "direct": [{"dev": "lo"}]}
    return links, routes, rules, lookups


class IsolatedActivationGuardClassifier(unittest.TestCase):
    def test_exact_modes(self):
        for mode in ("preflight", "applied", "recovered", "clean"):
            with self.subTest(mode=mode):
                mod.validate(mode, *fixture(mode))

    def test_wrong_resource_identity_or_false_recovery_rejected(self):
        cases = (
            ("applied", 0, 1, "ifalias", "foreign-replaced-interface"),
            ("applied", 1, 0, "dev", "wrong-device"),
            ("applied", 2, 0, "table", 254),
            ("applied", 2, 0, "dstlen", None),
            ("applied", 2, 0, "priority", "30800"),
            ("applied", 2, 0, "dst", "0.0.0.0"),
            ("applied", 2, 0, "not", True),
            ("recovered", 0, 1, "ifname", "scqao0"),
            ("recovered", 1, 0, "dst", "8.8.8.0/24"),
            ("recovered", 2, 0, "priority", 30800),
        )
        for mode, section, idx, key, value in cases:
            with self.subTest(mode=mode, section=section, key=key):
                sections = list(copy.deepcopy(fixture(mode)))
                sections[section][idx][key] = value
                with self.assertRaises(ValueError):
                    mod.validate(mode, *sections)

    def test_unowned_extra_route_or_missing_live_lookup_rejected(self):
        for mode in ("applied", "recovered"):
            sections = list(fixture(mode))
            sections[1].append({"dst": "1.1.1.0/24", "dev": "lo", "table": mod.TABLE})
            with self.subTest(mode=mode, case="unowned_route"):
                with self.assertRaises(ValueError):
                    mod.validate(mode, *sections)
            sections = list(fixture(mode))
            sections[3]["selected"] = [{"dev": "lo" if mode == "applied" else "scqao0"}]
            with self.subTest(mode=mode, case="wrong_selected_path"):
                with self.assertRaises(ValueError):
                    mod.validate(mode, *sections)
            sections = list(fixture(mode))
            sections[3]["direct"] = [{"dev": "scqao0"}]
            with self.subTest(mode=mode, case="lost_direct_path"):
                with self.assertRaises(ValueError):
                    mod.validate(mode, *sections)

    def test_additional_table_rule_refused_even_with_unused_priority(self):
        for mode in ("preflight", "applied", "recovered", "clean"):
            sections = list(fixture(mode))
            sections[2].append({"priority": 30890, "table": mod.TABLE,
                                "dst": "1.1.1.0", "dstlen": 24})
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    mod.validate(mode, *sections)

    def test_untrusted_shapes_and_preflight_refuse(self):
        with self.assertRaises(ValueError):
            mod.validate("unknown", *fixture("clean"))
        parts = list(fixture("preflight"))
        parts[0].append({"ifname": "eth0"})
        with self.assertRaises(ValueError):
            mod.validate("preflight", *parts)
        parts = list(fixture("applied"))
        parts[2] = None
        with self.assertRaises(ValueError):
            mod.validate("applied", *parts)


if __name__ == "__main__":
    unittest.main()
