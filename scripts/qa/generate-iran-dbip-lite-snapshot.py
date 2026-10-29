#!/usr/bin/env python3
"""Manually derive a pinned CC BY 4.0 DB-IP Lite IR country estimate.

Input: October 2026 free DB-IP Country Lite CSV.gz. Obtain separately over
HTTPS from https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz.

This development-only generator accepts a LOCAL, SHA-pinned archive. Neither
install, manager CLI nor offline runtime downloads or regenerates this data.
Country geolocation is an estimate, NOT independent proof for automatic Direct.

Attribution: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
Changes: IR rows extracted, IP ranges summarized as canonical CIDR prefixes.
"""
import argparse
import csv
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path

ARCHIVE_SHA256 = '097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80'
SOURCE = 'https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz'


def snapshot_from_archive(archive: Path) -> dict:
    if archive.stat().st_size > 6_000_000:
        raise ValueError('archive exceeds pinned resource size bound')
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for part in iter(lambda: stream.read(131072), b''):
            digest.update(part)
    if digest.hexdigest() != ARCHIVE_SHA256:
        raise ValueError('archive SHA-256 does not match pinned official bytes')
    families = {'ipv4': [], 'ipv6': []}
    rows = 0
    with gzip.open(archive, 'rt', encoding='utf-8', newline='') as stream:
        for line in csv.reader(stream):
            rows += 1
            if rows > 2_000_000 or len(line) != 3:
                raise ValueError('unsupported DB-IP Lite CSV source')
            first, last, country = line
            if not (len(country) == 2 and country.isascii() and country.isupper()):
                raise ValueError('invalid ISO country field')
            lo, hi = ipaddress.ip_address(first), ipaddress.ip_address(last)
            if lo.version != hi.version or lo > hi:
                raise ValueError('invalid IP source interval')
            if country != 'IR':
                continue
            family = 'ipv4' if lo.version == 4 else 'ipv6'
            for network in ipaddress.summarize_address_range(lo, hi):
                if not network.is_global:
                    raise ValueError('private/reserved address in IR estimate')
                families[family].append(network)
    if rows < 500_000:
        raise ValueError('incomplete or truncated country dataset')
    result = {}
    for family, networks in families.items():
        if not 20 <= len(networks) <= 10000:
            raise ValueError('implausible country prefix count')
        ordered = sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))
        if len(set(ordered)) != len(ordered):
            raise ValueError('duplicate source prefix')
        for a, b in zip(ordered, ordered[1:]):
            if a.overlaps(b):
                raise ValueError('overlapping source prefix')
        result[family] = [str(n) for n in ordered]
    canonical = ''.join(f'{family}:{prefix}\n' for family in ('ipv4', 'ipv6')
                        for prefix in result[family]).encode('ascii')
    return {
        'schema_version': 1,
        'country': 'IR',
        'basis': 'dbip_lite_country_geolocation_estimate',
        'as_of': '2026-10-01',
        'source': SOURCE,
        'source_sha256': ARCHIVE_SHA256,
        'license': 'CC-BY-4.0',
        'attribution': 'IP Geolocation by DB-IP (https://db-ip.com)',
        'changes': 'IR rows extracted; IP intervals converted to canonical CIDR prefixes.',
        'prefix_sha256': hashlib.sha256(canonical).hexdigest(),
        **result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path,
                        help='locally downloaded, pinned October 2026 CSV.gz')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    snapshot = snapshot_from_archive(args.archive)
    args.output.write_text(json.dumps(snapshot, indent=2, ensure_ascii=True)+'\n', encoding='ascii')
    print('DBIP_LITE_IR_SNAPSHOT=GENERATED (CC BY 4.0; geo estimate only; no routing activation)')


if __name__ == '__main__':
    main()
