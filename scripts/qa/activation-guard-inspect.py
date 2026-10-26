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


# These are the *entire* supported kernel JSON identities of our two fixed
# QA-only objects as observed from native Debian 13 `ip -j -N` inside a
# disposable Linux user+network namespace. Never use a partial denylist:
# a same-key route or RPDB rule with changed metadata belongs to UNKNOWN,
# and the independent systemd rollback MUST refuse to delete it.
RULE_KEYS_NATIVE = frozenset({"priority", "table", "src", "dst", "dstlen"})
RULE_KEYS_CIDR = frozenset({"priority", "table", "src", "dst"})
ROUTE_KEYS_NATIVE = frozenset({"dst", "dev", "table", "scope", "flags"})


def validate_rule(row, resource):
    name, alias, cidr, priority = resource
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
    name, alias, cidr, priority = resource
    # Native `-N` reports the non-gateway link scope as numeric string 253,
    # and the empty fixed-route flags as []. No protocol, metric, prefsrc,
    # realm, type, priority, extra selector or other metadata is permitted.
    # Deletion of a foreign same-key route with even one such extension
    # would otherwise violate the QA experiment's ownership claim.
    return (frozenset(row) == ROUTE_KEYS_NATIVE and
            row["dst"] == cidr and row["dev"] == name and
            in_qa_table(row) and row["scope"] == "253" and
            type(row["flags"]) is list and row["flags"] == [])


def validate_link(row, resource):
    name, alias, cidr, priority = resource
    details = row.get("linkinfo")
    return (row.get("ifname") == name and row.get("ifalias") == alias and
            type(details) is dict and details.get("info_kind") == "dummy")


def validate(mode, links, routes, rules, lookups):
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
        name, alias, cidr, priority = resource
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


def infer_rollback_stage(links, routes, rules, lookups):
    # All supported stages are mutually exclusive. If an object is missing,
    # modified, duplicated or foreign, NO rollback command is authorized.
    matches = []
    for mode in ("partial_link", "partial_route", "applied"):
        try:
            validate(mode, links, routes, rules, lookups)
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
    routes = routes_from_all(native_json("-N", "-4", "route", "show", "table", "all"))
    rules = native_json("-N", "-4", "rule", "show")
    lookups = {}
    if mode in ("applied", "partial_link", "partial_route", "recovered", "classify"):
        for label, ip in (("selected", "8.8.8.8"), ("foreign", "9.9.9.9"),
                          ("direct", "198.51.100.99")):
            lookups[label] = native_json("-4", "route", "get", ip)
    if mode == "classify":
        print(infer_rollback_stage(links, routes, rules, lookups))
    else:
        validate(mode, links, routes, rules, lookups)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as e:
        # Only bounded static inventory/error classes, no credentials or URLs.
        print("ISOLATED_ACTIVATION_GUARD_INVENTORY=FAIL: " + str(e), file=sys.stderr)
        sys.exit(1)
