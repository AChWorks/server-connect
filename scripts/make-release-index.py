#!/usr/bin/env python3
"""Create an inspectable release-channel index from BOTH immutable bundles.

LOCAL QA until independently reviewed, licensed and explicitly published by
Owner. Never uploads, signs, overwrites or contacts a remote host.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile

TARGETS = ('debian-12-amd64', 'debian-13-amd64')
CORE_DIGEST = 'e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee'
SOURCE_FIELDS = {'schema', 'purpose', 'version', 'target', 'archive_sha256', 'checksums_sha256',
                 'manifest_sha256', 'source_revision', 'source_state', 'core', 'core_archive_sha256'}


def unique(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError(f'duplicate JSON key: {name}')
        obj[name] = value
    return obj


def load_json(path, max_size=16384):
    with path.open('rb') as handle:
        raw = handle.read(max_size + 1)
    if not raw or len(raw) > max_size:
        raise ValueError(f'invalid JSON length: {path.name}')
    return json.loads(raw, object_pairs_hook=unique)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def inspect_archive(archive, metadata):
    if archive.stat().st_size > 100663296:
        raise ValueError('archive exceeds supported transfer ceiling')
    checksum_manifest = None
    bundle_manifest = None
    with tarfile.open(archive, mode='r:gz') as stream:
        names = set()
        for member in stream:
            name = member.name.rstrip('/')
            if name in names or not name.startswith('server-connect/') or any(
                part in ('', '.', '..') for part in name.split('/')
            ) or (not member.isfile() and not member.isdir()):
                raise ValueError('unsafe archive member')
            names.add(name)
            if member.name == 'server-connect/checksums.sha256':
                if member.size > 16384:
                    raise ValueError('checksums too long')
                checksum_manifest = stream.extractfile(member).read()
            if member.name == 'server-connect/manifest.json':
                if member.size > 16384:
                    raise ValueError('manifest too long')
                bundle_manifest = stream.extractfile(member).read()
    if not checksum_manifest or not bundle_manifest:
        raise ValueError('missing checksums or bundle manifest')
    if hashlib.sha256(checksum_manifest).hexdigest() != metadata['checksums_sha256']:
        raise ValueError('checksums digest mismatch')
    if hashlib.sha256(bundle_manifest).hexdigest() != metadata['manifest_sha256']:
        raise ValueError('manifest digest mismatch')
    manifest = json.loads(bundle_manifest, object_pairs_hook=unique)
    for left, right in (('manager', 'version'), ('target', 'target'),
                        ('source_revision', 'source_revision'), ('source_state', 'source_state'),
                        ('core', 'core'), ('core_archive_sha256', 'core_archive_sha256')):
        if manifest.get(left) != metadata[right]:
            raise ValueError(f'archive manifest identity mismatch: {left}')


def make_index(directory, version):
    if not re.fullmatch(r'[0-9][0-9A-Za-z.+_-]{0,63}', version):
        raise ValueError('invalid release version')
    items = {}
    identity = None
    for target in TARGETS:
        sidecars = []
        for path in directory.glob('*.tar.gz.release.json'):
            metadata = load_json(path)
            if metadata.get('version') == version and metadata.get('target') == target:
                sidecars.append((path, metadata))
        if len(sidecars) != 1:
            raise ValueError(f'{target}: require exactly one matching archive and sidecar')
        sidecar, metadata = sidecars[0]
        archive = directory / sidecar.name.removesuffix('.release.json')
        if (set(metadata) != SOURCE_FIELDS or type(metadata['schema']) is not int or
            metadata['schema'] != 1 or metadata['purpose'] != 'server-connect-release' or
            metadata['source_state'] != 'clean' or metadata['core'] != 'sing-box 1.14.3' or
            metadata['core_archive_sha256'] != CORE_DIGEST or
            not re.fullmatch(r'[0-9a-f]{40}', metadata['source_revision'])):
            raise ValueError(f'{target}: unsupported or unclean bundle identity')
        for key in ('archive_sha256', 'checksums_sha256', 'manifest_sha256'):
            if not re.fullmatch(r'[0-9a-f]{64}', metadata[key]):
                raise ValueError(f'{target}: invalid {key}')
        if not archive.is_file() or archive.is_symlink() or sha256_file(archive) != metadata['archive_sha256']:
            raise ValueError(f'{target}: archive bytes differ from sidecar')
        inspect_archive(archive, metadata)
        # Run the exact trusted source bootstrap's full bounded parser and
        # per-member integrity verifier, with zero installation/downloads.
        checked = subprocess.run(
            ['/bin/sh', str(Path(__file__).with_name('bootstrap-online.sh')),
             '--archive-file', str(archive.resolve()), '--verify-only'],
            capture_output=True, text=True, timeout=180,
        )
        if checked.returncode != 0 or 'Installation was not attempted.' not in checked.stdout:
            raise ValueError(f'{target}: shared bootstrap refused archive: {checked.stderr.strip()[:380]}')
        if identity is not None and identity != metadata['source_revision']:
            raise ValueError('both supported targets must derive from the same commit')
        identity = metadata['source_revision']
        items[target] = {'archive': archive.name, 'sha256': metadata['archive_sha256']}
    return {'schema': 1, 'version': version, 'artifacts': items}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist-dir', type=Path, default=Path('dist'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, default=Path('dist/release-index.json'))
    args = parser.parse_args()
    if not args.dist_dir.is_dir():
        parser.error('distribution directory is absent')
    if args.output.exists() or args.output.is_symlink():
        parser.error('refusing to overwrite an existing channel index')
    try:
        index = make_index(args.dist_dir, args.version)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, json.JSONDecodeError) as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(index, sort_keys=True, separators=(',', ':')) + '\n')
    print('LOCAL INDEX ONLY: both target archives match the same exact source; publication requires Owner review and license clearance')


if __name__ == '__main__':
    main()
