#!/usr/bin/env python3
"""Strict native-kernel inventory for a disposable, non-product guard experiment.

This never mutates routing. It is not activation ownership verification for a
real host. Its fixed objects exist only in a Docker --network none guest.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

TABLE = 20120
OWNED = ("scqao0", "sc-qa-guard-owned-v1", "8.8.8.0/24", 30800, "02:53:43:00:00:01")
FOREIGN = ("scqaf0", "sc-qa-guard-foreign-v1", "9.9.9.0/24", 30801, "02:53:43:00:00:02")


def valid_integer(value, expected):
    return type(value) is int and value == expected


def in_qa_table(row):
    # Native iproute2 table-all reports numeric IDs for nonstandard tables;
    # tolerate the canonical decimal spelling but not aliases or coercion.
    table = row.get("table")
    return valid_integer(table, TABLE) or (type(table) is str and table == str(TABLE))


def routes_from_all(rows):
    if type(rows) is not list or any(type(row) is not dict for row in rows):
        raise ValueError("native all-table route inventory is incomplete")
    return [row for row in rows if in_qa_table(row)]


# These are the *entire* supported kernel JSON identities of our two fixed
# QA-only objects as observed from native Debian 13 `ip -j -N` inside a
# disposable Linux user+network namespace. Never use a partial denylist:
# a same-key route or RPDB rule with changed metadata belongs to UNKNOWN,
# and the independent systemd rollback MUST refuse to delete it.
RULE_KEYS_NATIVE = frozenset({"priority", "table", "src", "dst", "dstlen"})
RULE_KEYS_CIDR = frozenset({"priority", "table", "src", "dst"})
ROUTE_KEYS_NATIVE = frozenset({"dst", "dev", "table", "scope", "flags"})


def validate_rule(row, resource):
    name, alias, cidr, priority, mac = resource
    network, bits = cidr.split("/")
    if (frozenset(row) not in (RULE_KEYS_NATIVE, RULE_KEYS_CIDR) or
            not valid_integer(row.get("priority"), priority) or
            not in_qa_table(row) or
            row.get("src") != "all"):
        return False
    # iproute2 Debian 13 emits dst and dstlen as separate JSON keys.
    # Only the exact CIDR-string variant is also accepted; extensions and
    # missing/null prefix lengths cannot be mistaken for a full identity.
    if frozenset(row) == RULE_KEYS_NATIVE:
        return (row["dst"] == network and
                valid_integer(row["dstlen"], int(bits)))
    return row["dst"] == cidr


def validate_route(row, resource):
    name, alias, cidr, priority, mac = resource
    # Native `-N` reports the non-gateway link scope as numeric string 253,
    # and the empty fixed-route flags as []. No protocol, metric, prefsrc,
    # realm, type, priority, extra selector or other metadata is permitted.
    # Deletion of a foreign same-key route with even one such extension
    # would otherwise violate the QA experiment's ownership claim.
    return (frozenset(row) == ROUTE_KEYS_NATIVE and
            row["dst"] == cidr and row["dev"] == name and
            in_qa_table(row) and row["scope"] == "253" and
            type(row["flags"]) is list and row["flags"] == [])


# Exactly the known, supported native Debian 13 dummy-link JSON fields.
# `ip -j -d link show` omits counters unless separately requested, and the
# ifindex may legitimately vary across disposable guest cycles. Any new link
# attribute (including `altnames`, `master`, `link`, XDP, netns ownership,
# new mutable attributes or unknown kernel extensions) MUST block link deletion.
# Do not silently adopt extra state with a partial denylist.
LINK_KEYS_NATIVE = frozenset({
    "ifindex", "ifname", "flags", "mtu", "qdisc", "operstate", "linkmode",
    "group", "txqlen", "link_type", "address", "broadcast", "promiscuity",
    "allmulti", "min_mtu", "max_mtu", "linkinfo", "inet6_addr_gen_mode",
    "num_tx_queues", "num_rx_queues", "gso_max_size", "gso_max_segs",
    "tso_max_size", "tso_max_segs", "gro_max_size", "gso_ipv4_max_size",
    "gro_ipv4_max_size", "ifalias",
})

# Mutable or deletion-relevant values of our zero-address, fixed-MAC dummy
# fixture. Kernel-assigned ifindex is intentionally not tied to a constant.
LINK_NATIVE_OPTIONAL_DEFAULTS = {
    "min_mtu": 0, "max_mtu": 0,
    "num_tx_queues": 1, "num_rx_queues": 1,
    "gso_max_size": 65536, "gso_max_segs": 65535,
    "tso_max_size": 65536, "tso_max_segs": 65535,
    "gro_max_size": 65536, "gso_ipv4_max_size": 65536,
    "gro_ipv4_max_size": 65536,
}


def validate_link(row, resource):
    name, alias, cidr, priority, mac = resource
    # This fixed guest fixture deliberately has NO assigned IPv4/IPv6
    # addresses and a deterministic MAC, so foreign link modifications
    # can be rejected from native evidence without adoption-by-name.
    # Kernel-generated ifindex/queue sizing are not ownership tokens.
    if (not frozenset(row).issubset(LINK_KEYS_NATIVE) or
            any(type(row[key]) is not int or row[key] != expected
                for key, expected in LINK_NATIVE_OPTIONAL_DEFAULTS.items()
                if key in row) or
            ("ifindex" in row and
             (type(row["ifindex"]) is not int or row["ifindex"] <= 0))):
        return False
    return (row.get("ifname") == name and row.get("ifalias") == alias and
            row.get("linkinfo") == {"info_kind": "dummy"} and
            row.get("address") == mac and row.get("mtu") == 1500 and
            row.get("link_type") == "ether" and
            row.get("broadcast") == "ff:ff:ff:ff:ff:ff" and
            row.get("qdisc") == "noqueue" and
            row.get("group") == "default" and
            row.get("linkmode") == "DEFAULT" and
            row.get("operstate") == "UNKNOWN" and
            row.get("txqlen") == 1000 and
            row.get("promiscuity") == 0 and row.get("allmulti") == 0 and
            row.get("inet6_addr_gen_mode") == "none" and
            set(row.get("flags", [])) == {"BROADCAST", "NOARP", "UP", "LOWER_UP"} and
            type(row.get("flags")) is list and len(row["flags"]) == 4 and
            not any(key in row for key in
                    ("master", "link", "link_netnsid", "parentdev", "parentbus", "xdp")))


def references_device(route, name):
    if route.get("dev") == name or route.get("oif") == name:
        return True
    hops = route.get("nexthops")
    if hops is not None:
        if type(hops) is not list:
            raise ValueError("unsupported multipath route dependencies")
        return any(type(hop) is dict and
                   (hop.get("dev") == name or hop.get("oif") == name)
                   for hop in hops)
    return False


def validate_dependencies(mode, links, routes, rules, dependencies):
    # Never remove a dummy link without checking all of its IPv4/IPv6
    # addresses and route dependencies, including other routing tables.
    # This is a strict *fixed guest* contract, NOT global host provenance.
    keys = {"addresses4", "addresses6", "routes4", "routes6", "rules6", "nexthops"}
    if type(dependencies) is not dict or set(dependencies) != keys:
        raise ValueError("incomplete interface dependency inventory")
    for field in keys:
        rows = dependencies[field]
        if type(rows) is not list or any(type(row) is not dict for row in rows):
            raise ValueError("interface dependency inventory has unsupported JSON")
    # Any unsupported global nexthop object might refer to the fixture via
    # a nexthop group/ID, even when route JSON has no direct 'dev' field.
    if dependencies["nexthops"]:
        raise ValueError("unexpected kernel nexthop ownership/dependency")
    if routes != routes_from_all(dependencies["routes4"]):
        raise ValueError("reserved-table routes disagree with full IPv4 inventory")
    for family in ("addresses4", "addresses6"):
        for row in dependencies[family]:
            if row.get("ifname") in (OWNED[0], FOREIGN[0]):
                raise ValueError("unexpected address on a removable QA interface")
    # Neither the test-owned IPv4 rule nor any foreign IPv6 rule may bind an
    # iif/oif to a fixture link. Both families must be inspected.
    for row in dependencies["rules6"]:
        if in_qa_table(row):
            raise ValueError("unexpected IPv6 rule in reserved QA table")
    for resource, present, has_route in (
        (OWNED, mode in ("partial_link", "partial_route", "applied"),
         mode in ("partial_route", "applied")),
        (FOREIGN, mode in ("partial_link", "partial_route", "applied", "recovered"),
         mode in ("partial_link", "partial_route", "applied", "recovered")),
    ):
        name = resource[0]
        for row in dependencies["routes4"]:
            # Reject nhid-based indirect ownership rather than silently
            # assuming an unknown nexthop identifier cannot depend on us.
            if "nhid" in row:
                raise ValueError("unresolved route nexthop dependency")
        related4 = [row for row in dependencies["routes4"]
                    if references_device(row, name)]
        if (len(related4) != int(has_route) or
                (has_route and not validate_route(related4[0], resource))):
            raise ValueError("unexpected IPv4 route depends on removable QA interface")
        related6 = [row for row in dependencies["routes6"]
                    if references_device(row, name)]
        # Native Linux may automatically create an IPv6 multicast route
        # for a link with no IPv6 address. Only that exact kernel identity
        # can be tolerated; any additional IPv6 dependency is foreign.
        auto6 = {"type": "5", "dst": "ff00::/8", "dev": name,
                 "table": "255", "protocol": "2", "metric": 256,
                 "flags": [], "pref": "medium"}
        if (len(related6) > 1 or (related6 and related6[0] != auto6) or
                (not present and related6)):
            raise ValueError("unexpected IPv6 route depends on removable QA interface")
        for row in dependencies["rules6"]:
            if any(row.get(key) == name for key in ("iif", "oif", "iifname", "oifname")):
                raise ValueError("foreign IPv6 rule depends on removable QA interface")
    # Also reject IPv4 foreign policy selectors tied to an owned interface;
    # a QA test rule has no iif/oif selector.
    for row in rules:
        if any(row.get(key) in (OWNED[0], FOREIGN[0])
               for key in ("iif", "oif", "iifname", "oifname")):
            raise ValueError("foreign IPv4 rule depends on removable QA interface")


def validate(mode, links, routes, rules, lookups, dependencies):
    if mode not in ("preflight", "partial_link", "partial_route",
                    "applied", "recovered", "clean"):
        raise ValueError("unsupported fixture observation mode")
    for rows in (links, routes, rules):
        if type(rows) is not list or any(type(x) is not dict for x in rows):
            raise ValueError("kernel JSON inventory is incomplete or malformed")
    aliases = {row.get("ifname"): row for row in links}
    if len(aliases) != len(links) or not all(type(k) is str for k in aliases):
        raise ValueError("kernel link identity is ambiguous")

    # The independent timer may fire after ANY native mutation. Do not
    # require the full fixture or trust a controller-written stage marker:
    # every individual present object must have its COMPLETE native identity,
    # and every absent object must genuinely be absent before any deletion.
    owned_link = mode in ("partial_link", "partial_route", "applied")
    owned_route = mode in ("partial_route", "applied")
    owned_rule = mode == "applied"
    foreign_present = mode in ("partial_link", "partial_route", "applied", "recovered")
    for resource, want_link, want_route, want_rule in (
            (OWNED, owned_link, owned_route, owned_rule),
            (FOREIGN, foreign_present, foreign_present, foreign_present)):
        name, alias, cidr, priority, mac = resource
        device = aliases.get(name)
        matching_routes = [x for x in routes if x.get("dst") == cidr]
        matching_rules = [x for x in rules if x.get("priority") == priority]
        if want_link:
            if device is None or not validate_link(device, resource):
                raise ValueError("fixture network interface identity was replaced")
        elif device is not None:
            raise ValueError("fixture network interface unexpectedly present")
        if want_route:
            if len(matching_routes) != 1 or not validate_route(matching_routes[0], resource):
                raise ValueError("fixture route is absent, duplicated or changed")
        elif matching_routes:
            raise ValueError("fixture route unexpectedly present")
        if want_rule:
            if len(matching_rules) != 1 or not validate_rule(matching_rules[0], resource):
                raise ValueError("fixture policy rule is absent, duplicated or changed")
        elif matching_rules:
            raise ValueError("fixture policy rule unexpectedly present")

    # Unknown policy in the reserved table is never taken over even when
    # its priority is distinct from either expected fixture-owned rule.
    expected_priorities = ({FOREIGN[3]} if foreign_present else set())
    if owned_rule:
        expected_priorities.add(OWNED[3])
    actual_priorities = set()
    for row in rules:
        if in_qa_table(row):
            priority = row.get("priority")
            if type(priority) is not int or priority in actual_priorities:
                raise ValueError("duplicate or malformed RPDB rule in reserved table")
            actual_priorities.add(priority)
    if actual_priorities != expected_priorities:
        raise ValueError("unexpected policy rule in reserved QA table")
    expected_routes = int(foreign_present) + int(owned_route)
    if len(routes) != expected_routes:
        raise ValueError("unexpected route in reserved QA table")
    if mode in ("preflight", "clean"):
        if set(aliases) != {"lo"}:
            raise ValueError("the disposable guest is not loopback-only")
    if foreign_present:
        if type(lookups) is not dict or set(lookups) != {"selected", "foreign", "direct"}:
            raise ValueError("guest route lookups are missing")
        want = {"selected": OWNED[0] if owned_rule else "lo",
                "foreign": FOREIGN[0], "direct": "lo"}
        for label, device in want.items():
            entries = lookups[label]
            if (type(entries) is not list or len(entries) != 1 or
                    type(entries[0]) is not dict or entries[0].get("dev") != device):
                raise ValueError("live guest kernel did not select expected route for " + label)

    validate_dependencies(mode, links, routes, rules, dependencies)


def infer_rollback_stage(links, routes, rules, lookups, dependencies):
    # All supported stages are mutually exclusive. If an object is missing,
    # modified, duplicated or foreign, NO rollback command is authorized.
    matches = []
    for mode in ("partial_link", "partial_route", "applied"):
        try:
            validate(mode, links, routes, rules, lookups, dependencies)
        except ValueError:
            continue
        matches.append(mode)
    if len(matches) != 1:
        raise ValueError("no unique fully verified native rollback stage")
    return matches[0]


def native_json(*args):
    result = subprocess.run(["/usr/bin/ip", "-j", *args],
                            env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=5)
    if len(result.stdout) > 131072:
        raise ValueError("native kernel observation exceeded fixture bounds")
    data = json.loads(result.stdout)
    if type(data) is not list:
        raise ValueError("native kernel JSON is not an array")
    return data


def main():
    if len(sys.argv) != 2:
        raise ValueError("expected one fixture mode")
    mode = sys.argv[1]
    # Native iproute2 often omits linkinfo.info_kind without -d. The
    # ownership classifier requires the actual dummy kind, not a guess.
    links = native_json("-d", "link", "show")
    # Querying an ABSENT numeric FIB table exits 2 on Debian 13. Never
    # interpret a failed native command as an empty table. Query every table
    # successfully and force numeric IDs (-N) to avoid local rt_tables aliases,
    # then filter by the exact reserved table identity.
    routes4 = native_json("-N", "-4", "route", "show", "table", "all")
    routes = routes_from_all(routes4)
    rules = native_json("-N", "-4", "rule", "show")
    dependencies = {
        "routes4": routes4,
        "routes6": native_json("-N", "-6", "route", "show", "table", "all"),
        "addresses4": native_json("-4", "addr", "show"),
        "addresses6": native_json("-6", "addr", "show"),
        "rules6": native_json("-N", "-6", "rule", "show"),
        "nexthops": native_json("nexthop", "show"),
    }
    lookups = {}
    if mode in ("applied", "partial_link", "partial_route", "recovered", "classify"):
        for label, ip in (("selected", "8.8.8.8"), ("foreign", "9.9.9.9"),
                          ("direct", "198.51.100.99")):
            lookups[label] = native_json("-4", "route", "get", ip)
    if mode == "classify":
        print(infer_rollback_stage(links, routes, rules, lookups, dependencies))
    else:
        validate(mode, links, routes, rules, lookups, dependencies)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as e:
        # Only bounded static inventory/error classes, no credentials or URLs.
        print("ISOLATED_ACTIVATION_GUARD_INVENTORY=FAIL: " + str(e), file=sys.stderr)
        sys.exit(1)
