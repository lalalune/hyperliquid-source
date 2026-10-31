#!/usr/bin/env python3
"""Checksum-locked artifact recovery and static signature verification."""
import argparse
import hashlib
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


def check(path, item):
    path = Path(path)
    if not path.is_file():
        raise ValueError(f'Missing artifact: {path}')
    if path.stat().st_size != item['size'] or digest(path) != item['sha256']:
        raise ValueError(f'Artifact size/SHA-256 mismatch: {path}')


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
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.part', delete=False) as f:
            temp = Path(f.name)
            with urllib.request.urlopen(url, timeout=120) as response:
                for block in iter(lambda: response.read(1024 * 1024), b''):
                    f.write(block)
        check(temp, item)
        temp.chmod(0o644)
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def verify_signatures(root, fingerprint):
    with tempfile.TemporaryDirectory(prefix='hl-verify-') as home:
        base = ['gpg', '--batch', '--no-options', '--homedir', home]
        subprocess.run(base + ['--import', str(root / 'artifacts/keys/pub_key.asc')],
                       check=True, capture_output=True)
        for rel in ['node/94/hl-node', 'node/115/hl-node', 'visor/captured/hl-visor']:
            binary = root / 'artifacts' / rel
            result = subprocess.run(base + ['--status-fd', '1', '--verify', str(binary) + '.asc', str(binary)],
                                    check=True, capture_output=True, text=True)
            valid = [line.split() for line in result.stdout.splitlines()
                     if line.startswith('[GNUPG:] VALIDSIG ')]
            if not any(row[2] == fingerprint or row[-1] == fingerprint for row in valid):
                raise ValueError(f'Expected signing fingerprint not found: {rel}')
            print(f'Valid signature: {rel}')


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
    manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
    for item in manifest['files']:
        if args.command == 'fetch':
            fetch_one(ROOT, item)
        check(ROOT / item['path'], item)
        print(f"SHA-256 OK: {item['path']}")
    verify_signatures(ROOT, manifest['signing_fingerprint'])
    verify_pinned_pairs(ROOT)
    print('Pinned upstream binary, signature and public key match.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(f'artifacts: {error}', file=sys.stderr)
        raise SystemExit(1)
