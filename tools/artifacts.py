#!/usr/bin/env python3
"""Checksum-locked artifact recovery and static signature verification."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def is_lfs_pointer(path, item):
    """True when path is the Git LFS v1 pointer for exactly this item."""
    if path.stat().st_size > 1024:
        return False
    lines = path.read_bytes().decode('ascii', 'replace').splitlines()
    return (lines[:1] == ['version https://git-lfs.github.com/spec/v1']
            and f"oid sha256:{item['sha256']}" in lines and f"size {item['size']}" in lines)


def check(path, item):
    path = Path(path)
    if type(item) is not dict or 'size' not in item or 'sha256' not in item:
        raise ValueError(f'Invalid artifact record: {path}')
    if not path.is_file():
        raise ValueError(f'Missing artifact: {path}')
    if path.stat().st_size != item['size'] or digest(path) != item['sha256']:
        if is_lfs_pointer(path, item):
            raise ValueError(f'Git LFS pointer, not the artifact: {path}; run git lfs pull')
        raise ValueError(f'Artifact size/SHA-256 mismatch: {path}')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate key in artifact manifest: {key}')
        result[key] = value
    return result


def load_manifest(root=ROOT):
    """Load artifact identities without ambiguous keys, paths or record shapes."""
    manifest = json.loads((root / 'provenance/artifacts.json').read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
    if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
        raise ValueError('Invalid artifact manifest')
    if any(not isinstance(item, dict) or 'path' not in item for item in manifest['files']):
        raise ValueError('Invalid artifact record')
    paths = [item['path'] for item in manifest['files']]
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate path in artifact manifest')
    return manifest


def manifest_item(root, relative):
    item = next((i for i in load_manifest(root)['files'] if i['path'] == relative), None)
    if item is None:
        raise ValueError(f'No provenance/artifacts.json entry for {relative}')
    return item


def fetch_one(root, item):
    path = root / item['path']
    if path.exists():
        check(path, item)
        return
    url = item.get('recovery_url')
    if not url:
        raise ValueError(f'No upstream recovery URL for {path}; run git lfs pull / git restore')
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    written = 0
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.part', delete=False) as f:
            temp = Path(f.name)
            with urllib.request.urlopen(url, timeout=120) as response:
                for block in iter(lambda: response.read(1024 * 1024), b''):
                    if len(block) > item['size'] - written:
                        raise ValueError(f'Artifact exceeds manifest size: {path}')
                    f.write(block)
                    written += len(block)
        check(temp, item)
        temp.chmod(0o644)
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def fetch_all(root, manifest):
    """Try every item, so one unrecoverable file does not block the others."""
    failures = []
    for item in manifest['files']:
        try:
            fetch_one(root, item)
        except (OSError, ValueError, http.client.HTTPException) as error:
            failures.append(f"{item['path']}: {error}")
    if failures:
        raise ValueError('Not recovered by fetch:\n  ' + '\n  '.join(failures))


KEY = 'artifacts/keys/pub_key.asc'


def signature_pairs(manifest):
    """Derive detached-signature coverage from the artifact manifest itself.

    The manifest is the authority for the retained inputs, so an artifact added
    there must be verified without editing this module. A detached signature
    without its signed file, a binary artifact without a signature, or a
    manifest that records no signatures at all is an incomplete record and
    fails closed.
    """
    paths = {item['path'] for item in manifest['files']}
    pairs = sorted((path[:-4], path) for path in paths
                   if path.endswith('.asc') and path != KEY)
    for binary, signature in pairs:
        if binary not in paths:
            raise ValueError(f'Detached signature without a signed artifact: {signature}')
    unsigned = sorted(path for path in paths
                      if not path.endswith(('.asc', '.json')) and path + '.asc' not in paths)
    if unsigned:
        raise ValueError(f'Artifact without a detached signature: {unsigned[0]}')
    if not pairs:
        raise ValueError('Artifact manifest records no detached signatures')
    return pairs


def verify_signatures(root, manifest):
    fingerprint = manifest['signing_fingerprint']
    pairs = signature_pairs(manifest)
    with tempfile.TemporaryDirectory(prefix='hl-verify-') as home:
        # This workflow imports only a public verification key. It must not
        # require starting a secret-key agent or other helper in a sandbox.
        base = ['gpg', '--batch', '--no-options', '--no-autostart', '--homedir', home]
        subprocess.run(base + ['--import', str(root / KEY)],
                       check=True, capture_output=True)
        for relative, signature in pairs:
            binary = root / relative
            try:
                result = subprocess.run(base + ['--status-fd', '1', '--verify', str(root / signature), str(binary)],
                                        check=True, capture_output=True, text=True, encoding='utf-8')
            except subprocess.CalledProcessError as error:
                detail = (error.stderr or '').strip().partition('\n')[0] or f'gpg exited {error.returncode}'
                raise ValueError(f'GPG verification failed: {relative}: {detail}') from None
            valid = [line.split() for line in result.stdout.splitlines()
                     if line.startswith('[GNUPG:] VALIDSIG ')]
            if not any(row[2] == fingerprint or row[-1] == fingerprint for row in valid):
                raise ValueError(f'Expected signing fingerprint not found: {relative}')
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) > 1 and fields[0] == '[GNUPG:]' and fields[1] in {
                        'REVKEYSIG', 'EXPKEYSIG', 'KEYEXPIRED', 'SIGEXPIRED'}:
                    raise ValueError(f'Signature is not currently valid: {relative}: {line}')
            print(f'Valid signature: {relative}')


PAIRS = [
    ('artifacts/node/94/hl-node', 'references/can1357-hl/bin/hl-node-mainnet-new'),
    ('artifacts/node/94/hl-node.asc', 'references/can1357-hl/bin/hl-node-mainnet-new.asc'),
    ('artifacts/keys/pub_key.asc', 'upstream/node/pub_key.asc'),
]


def verify_pinned_pairs(root):
    """Compare retained artifacts with the pinned submodule copies."""
    for left, right in PAIRS:
        if not (root / right).is_file():
            raise ValueError(f'Missing pinned reference: {right}; run git submodule update --init --recursive')
        if digest(root / left) != digest(root / right):
            raise ValueError(f'Pinned upstream mismatch: {left} != {right}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['verify', 'fetch'])
    args = parser.parse_args()
    manifest = load_manifest(ROOT)
    if args.command == 'fetch':
        fetch_all(ROOT, manifest)
    for item in manifest['files']:
        check(ROOT / item['path'], item)
        print(f"SHA-256 OK: {item['path']}")
    if 'signing_fingerprint' not in manifest:
        raise ValueError('Invalid artifact manifest')
    verify_signatures(ROOT, manifest)
    verify_pinned_pairs(ROOT)
    print('Pinned upstream binary, signature and public key match.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(f'artifacts: {error}', file=sys.stderr)
        raise SystemExit(1)
