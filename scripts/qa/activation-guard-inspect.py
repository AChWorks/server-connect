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
OWNED = ("scqao0", "sc-qa-guard-owned-v1", "8.8.8.0/24", 30800)
FOREIGN = ("scqaf0", "sc-qa-guard-foreign-v1", "9.9.9.0/24", 30801)


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


def validate_rule(row, resource):
    name, alias, cidr, priority = resource
    network, bits = cidr.split("/")
    if not valid_integer(row.get("priority"), priority):
        return False
    if not in_qa_table(row):
        return False
    if row.get("dst") == network:
        if not valid_integer(row.get("dstlen"), int(bits)):
            return False
    elif row.get("dst") == cidr:
        if "dstlen" in row and not valid_integer(row["dstlen"], int(bits)):
            return False
    else:
        return False
    # An inverted, marked or otherwise conditional rule is not this fixture.
    disallowed = {"not", "invert", "goto", "l3mdev", "fwmark", "fwmask",
                  "iif", "oif", "uidrange", "tos", "ipproto", "sport", "dport",
                  "suppress_prefixlength", "suppress_ifgroup", "nat"}
    if disallowed.intersection(row):
        return False
    if row.get("action", "to_tbl") not in ("to_tbl", "lookup"):
        return False
    if row.get("type", "unicast") != "unicast":
        return False
    return True


def validate_route(row, resource):
    name, alias, cidr, priority = resource
    return (row.get("dst") == cidr and row.get("dev") == name and
            in_qa_table(row) and
            not any(key in row for key in ("gateway", "via", "nhid", "multipath",
                                               "encap", "nexthops", "onlink")) and
            row.get("type", "unicast") == "unicast")


def validate_link(row, resource):
    name, alias, cidr, priority = resource
    return (row.get("ifname") == name and row.get("ifalias") == alias and
            row.get("linkinfo", {}).get("info_kind") == "dummy")


def validate(mode, links, routes, rules, lookups):
    if mode not in ("preflight", "applied", "recovered", "clean"):
        raise ValueError("unsupported fixture observation mode")
    for rows in (links, routes, rules):
        if type(rows) is not list or any(type(x) is not dict for x in rows):
            raise ValueError("kernel JSON inventory is incomplete or malformed")
    aliases = {row.get("ifname"): row for row in links}
    if len(aliases) != len(links) or not all(type(k) is str for k in aliases):
        raise ValueError("kernel link identity is ambiguous")
    owned_required = mode == "applied"
    foreign_required = mode in ("applied", "recovered")
    for resource, expected in ((OWNED, owned_required), (FOREIGN, foreign_required)):
        name, alias, cidr, priority = resource
        device = aliases.get(name)
        matching_routes = [x for x in routes if x.get("dst") == cidr]
        matching_rules = [x for x in rules if x.get("priority") == priority]
        if expected:
            if device is None or not validate_link(device, resource):
                raise ValueError("fixture network interface identity was replaced")
            if len(matching_routes) != 1 or not validate_route(matching_routes[0], resource):
                raise ValueError("fixture route is absent, duplicated or changed")
            if len(matching_rules) != 1 or not validate_rule(matching_rules[0], resource):
                raise ValueError("fixture policy rule is absent, duplicated or changed")
        elif device is not None or matching_routes or matching_rules:
            raise ValueError("fixture-owned resource unexpectedly survived")
    # A third-party RPDB policy referencing our reserved table is a conflict
    # even when its priority does not match either test-owned rule. Do not
    # assume that unused priorities imply exclusive table ownership.
    expected_priorities = ({OWNED[3], FOREIGN[3]} if mode == "applied" else
                           {FOREIGN[3]} if mode == "recovered" else set())
    actual_priorities = set()
    for row in rules:
        if in_qa_table(row):
            priority = row.get("priority")
            if type(priority) is not int or priority in actual_priorities:
                raise ValueError("duplicate or malformed RPDB rule in reserved table")
            actual_priorities.add(priority)
    if actual_priorities != expected_priorities:
        raise ValueError("unexpected policy rule in reserved QA table")
    # This disposable guest's reserved table must contain only its exact two
    # planned resources. An unknown third entry prevents any destructive undo.
    expected_routes = 2 if mode == "applied" else 1 if mode == "recovered" else 0
    if len(routes) != expected_routes:
        raise ValueError("unexpected route in reserved QA table")
    if mode in ("preflight", "clean"):
        if set(aliases) != {"lo"}:
            raise ValueError("the disposable guest is not loopback-only")
    if mode in ("applied", "recovered"):
        if type(lookups) is not dict or set(lookups) != {"selected", "foreign", "direct"}:
            raise ValueError("guest route lookups are missing")
        want = {"selected": OWNED[0] if mode == "applied" else "lo",
                "foreign": FOREIGN[0], "direct": "lo"}
        for label, device in want.items():
            entries = lookups[label]
            if (type(entries) is not list or len(entries) != 1 or
                    type(entries[0]) is not dict or entries[0].get("dev") != device):
                raise ValueError("live guest kernel did not select expected route for " + label)


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
    # successfully, then filter by its exact numeric identity instead.
    routes = routes_from_all(native_json("-4", "route", "show", "table", "all"))
    rules = native_json("-4", "rule", "show")
    lookups = {}
    if mode in ("applied", "recovered"):
        for label, ip in (("selected", "8.8.8.8"), ("foreign", "9.9.9.9"),
                          ("direct", "198.51.100.99")):
            lookups[label] = native_json("-4", "route", "get", ip)
    validate(mode, links, routes, rules, lookups)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as e:
        # Only bounded static inventory/error classes, no credentials or URLs.
        print("ISOLATED_ACTIVATION_GUARD_INVENTORY=FAIL: " + str(e), file=sys.stderr)
        sys.exit(1)
