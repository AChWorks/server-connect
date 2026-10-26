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
    dependencies = {"addresses4": [], "addresses6": [], "routes4": [],
                    "routes6": [], "rules6": [], "nexthops": []}
    if mode in ("applied", "partial_link", "partial_route", "recovered"):
        resources = [mod.FOREIGN]
        if mode in ("applied", "partial_link", "partial_route"):
            resources.insert(0, mod.OWNED)
        for name, alias, cidr, priority, mac in resources:
            links.append({
                "ifname": name, "ifalias": alias, "linkinfo": {"info_kind": "dummy"},
                "address": mac, "mtu": 1500, "link_type": "ether",
                "broadcast": "ff:ff:ff:ff:ff:ff", "qdisc": "noqueue",
                "group": "default", "linkmode": "DEFAULT", "operstate": "UNKNOWN",
                "txqlen": 1000, "promiscuity": 0, "allmulti": 0,
                "inet6_addr_gen_mode": "none",
                "flags": ["BROADCAST", "NOARP", "UP", "LOWER_UP"],
            })
            dependencies["routes6"].append({
                "type": "5", "dst": "ff00::/8", "dev": name,
                "table": "255", "protocol": "2", "metric": 256,
                "flags": [], "pref": "medium",
            })
            if name != mod.OWNED[0] or mode in ("applied", "partial_route"):
                routes.append({"dst": cidr, "dev": name, "table": str(mod.TABLE),
                               "scope": "253", "flags": []})
            if name != mod.OWNED[0] or mode == "applied":
                rules.append({"priority": priority, "table": str(mod.TABLE),
                              "src": "all", "dst": cidr.split('/')[0],
                              "dstlen": int(cidr.split('/')[1])})
        lookups = {"selected": [{"dev": mod.OWNED[0] if mode == "applied" else "lo"}],
                   "foreign": [{"dev": mod.FOREIGN[0]}],
                   "direct": [{"dev": "lo"}]}
    dependencies["routes4"] = copy.deepcopy(routes)
    return links, routes, rules, lookups, dependencies


class IsolatedActivationGuardClassifier(unittest.TestCase):
    def test_exact_modes(self):
        for mode in ("preflight", "partial_link", "partial_route", "applied", "recovered", "clean"):
            with self.subTest(mode=mode):
                mod.validate(mode, *fixture(mode))

    def test_exact_partial_stage_inference_and_no_orphan_adoption(self):
        for mode in ("partial_link", "partial_route", "applied"):
            with self.subTest(stage=mode):
                self.assertEqual(mod.infer_rollback_stage(*fixture(mode)), mode)
        for mode in ("preflight", "recovered", "clean"):
            with self.subTest(unsafe_stage=mode):
                with self.assertRaises(ValueError):
                    mod.infer_rollback_stage(*fixture(mode))

    def test_partial_identity_mutations_refuse_any_rollback_stage(self):
        for mode in ("partial_link", "partial_route"):
            mutations = [
                (0, 1, "ifalias", "foreign-replaced-owned-link"),
                (0, 2, "ifalias", "foreign-replaced-foreign-link"),
                (1, -1, "metric", 57),  # changed foreign route
                (2, -1, "protocol", 123),  # changed foreign policy
                (3, "selected", "dev", "scqao0"),  # false Direct
            ]
            if mode == "partial_route":
                mutations += [(1, 0, "metric", 57), (1, 0, "protocol", "123")]
            for section, idx, key, value in mutations:
                with self.subTest(mode=mode, section=section, key=key):
                    parts = list(copy.deepcopy(fixture(mode)))
                    if section == 3:
                        parts[3][idx][0][key] = value
                    else:
                        parts[section][idx][key] = value
                    with self.assertRaises(ValueError):
                        mod.infer_rollback_stage(*parts)
            # Unrecorded partial progress must never be normalized into an
            # apparently valid earlier stage when any stray owned key exists.
            parts = list(copy.deepcopy(fixture(mode)))
            parts[2].append({"priority": 30800, "table": str(mod.TABLE),
                             "src": "all", "dst": "8.8.8.0", "dstlen": 24})
            if mode == "partial_route":
                parts[2][-1]["metric"] = 1
            with self.subTest(mode=mode, case="unexpected_early_rule"):
                with self.assertRaises(ValueError):
                    mod.infer_rollback_stage(*parts)
        parts = list(copy.deepcopy(fixture("partial_link")))
        parts[0][1]["linkinfo"] = None
        with self.assertRaises(ValueError):
            mod.infer_rollback_stage(*parts)

    def test_r1_interface_and_dependency_mutations_fail_closed(self):
        # The exact fixed QA stage is valid; changing the link, adding an
        # address, or adding a route in ANY table makes deletion unsafe.
        for mode in ("partial_link", "partial_route", "applied"):
            with self.subTest(mode=mode, case="native_healthy"):
                self.assertEqual(mod.infer_rollback_stage(*fixture(mode)), mode)
            mutations = [
                ("mtu_changed", lambda p: p[0][1].update(mtu=1400)),
                ("foreign_altname", lambda p: p[0][1].update(
                    altnames=["qa-foreign-added"])),
                ("foreign_link_unknown", lambda p: p[0][1].update(
                    foreign_extended_attribute=1)),
                ("foreign_queue_metadata", lambda p: p[0][1].update(
                    gso_max_size=2048)),
                ("foreign_master", lambda p: p[0][1].update(master="foreign-br0")),
                ("changed_mac", lambda p: p[0][1].update(address="02:53:43:ab:cd:ef")),
                ("changed_promisc", lambda p: p[0][1].update(promiscuity=1)),
                ("unexpected_ipv4_address", lambda p: p[4]["addresses4"].append({
                    "ifname": mod.OWNED[0], "addr_info": [{"family": "inet",
                    "local": "192.0.2.77", "prefixlen": 32}]})),
                ("unexpected_ipv6_address", lambda p: p[4]["addresses6"].append({
                    "ifname": mod.OWNED[0], "addr_info": [{"family": "inet6",
                    "local": "2001:db8::77", "prefixlen": 128}]})),
                ("foreign_route_other_table", lambda p: p[4]["routes4"].append({
                    "dst": "203.0.113.0/24", "dev": mod.OWNED[0],
                    "table": "20121", "scope": "253", "flags": []})),
                ("foreign_ipv6_route", lambda p: p[4]["routes6"].append({
                    "dst": "2001:db8::/64", "dev": mod.OWNED[0],
                    "table": "20122", "flags": []})),
                ("foreign_nexthop", lambda p: p[4]["nexthops"].append({
                    "id": 10, "dev": mod.OWNED[0]})),
                ("foreign_ipv6_iif", lambda p: p[4]["rules6"].append({
                    "priority": 100, "table": "254", "iif": mod.OWNED[0]})),
                ("foreign_ipv4_oif", lambda p: p[2].append({
                    "priority": 100, "table": "254", "oif": mod.OWNED[0]})),
            ]
            for name, change in mutations:
                with self.subTest(mode=mode, case=name):
                    parts = list(copy.deepcopy(fixture(mode)))
                    change(parts)
                    with self.assertRaises(ValueError):
                        mod.infer_rollback_stage(*parts)
        # Even a foreign interface identity must be non-adoptable.
        for name, change in [
            ("foreign_link_master", lambda p: p[0][-1].update(master="br0")),
            ("foreign_link_altname", lambda p: p[0][-1].update(
                altnames=["qa-foreign-secondary"])),
            ("foreign_ipv4_addr", lambda p: p[4]["addresses4"].append({
                "ifname": mod.FOREIGN[0], "addr_info": [{"local": "192.0.2.1"}]})),
        ]:
            with self.subTest(case=name):
                parts = list(copy.deepcopy(fixture("applied")))
                change(parts)
                with self.assertRaises(ValueError):
                    mod.infer_rollback_stage(*parts)

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

    def test_required_r1_changed_native_metadata_must_fail_before_rollback(self):
        # Required finding R1: matching device/destination/table/priority
        # MUST NOT authorize destructive rollback of an adopted foreign rule
        # or route with additional/different kernel identity fields.
        mutations = (
            ("rule_protocol", 2, 0, "protocol", "55"),
            ("rule_src", 2, 0, "src", "192.0.2.0"),
            ("rule_srclen", 2, 0, "srclen", 24),
            ("rule_uid_start", 2, 0, "uid_start", 1000),
            ("rule_uid_end", 2, 0, "uid_end", 3000),
            ("rule_realms", 2, 0, "realms", "1234"),
            ("rule_unrecognized_attr", 2, 0, "extension_selector", "foreign"),
            ("route_protocol", 1, 0, "protocol", "188"),
            ("route_scope", 1, 0, "scope", "254"),
            ("route_metric", 1, 0, "metric", 100),
            ("route_prefsrc", 1, 0, "prefsrc", "10.210.1.2"),
            ("route_flags", 1, 0, "flags", ["onlink"]),
            ("route_unrecognized_attr", 1, 0, "extension_route", "foreign"),
        )
        for case, section, index, key, value in mutations:
            for owner in (0, 1):
                with self.subTest(case=case, owner=owner):
                    sections = list(copy.deepcopy(fixture("applied")))
                    sections[section][index + owner][key] = value
                    with self.assertRaises(ValueError):
                        mod.validate("applied", *sections)

    def test_required_r1_exact_native_json_is_accepted(self):
        for mode in ("applied", "recovered"):
            with self.subTest(mode=mode):
                links, routes, rules, lookups, dependencies = fixture(mode)
                self.assertTrue(all(rule.get("src") == "all" for rule in rules))
                self.assertTrue(all(route.get("scope") == "253" for route in routes))
                self.assertTrue(all(route.get("flags") == [] for route in routes))
                mod.validate(mode, links, routes, rules, lookups, dependencies)

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
        for mode in ("preflight", "partial_link", "partial_route", "applied", "recovered", "clean"):
            sections = list(fixture(mode))
            sections[2].append({"priority": 30890, "table": mod.TABLE,
                                "dst": "1.1.1.0", "dstlen": 24})
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    mod.validate(mode, *sections)

    def test_missing_detailed_link_kind_rejected(self):
        parts = list(fixture("applied"))
        parts[0][1].pop("linkinfo")
        with self.assertRaises(ValueError):
            mod.validate("applied", *parts)

    def test_native_all_table_discovery_not_false_empty(self):
        row = {"dst": "8.8.8.0/24", "dev": mod.OWNED[0], "table": mod.TABLE}
        self.assertEqual(mod.routes_from_all([{"dst": "default", "dev": "lo"}, row]), [row])
        self.assertEqual(mod.routes_from_all([{"table": "local", "dst": "127.0.0.1"}]), [])
        self.assertEqual(mod.routes_from_all([{**row, "table": str(mod.TABLE)}]),
                         [{**row, "table": str(mod.TABLE)}])
        with self.assertRaises(ValueError):
            mod.routes_from_all([row, None])
        parts = list(copy.deepcopy(fixture("applied")))
        parts[1][0] = dict(row, table=254)
        with self.assertRaises(ValueError):
            mod.validate("applied", *parts)

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
