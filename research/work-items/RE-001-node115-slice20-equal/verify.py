#!/usr/bin/env python3
"""Verify the exact slice20-equal packet whitelist and regenerate its evidence."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_slice20_equal as subject

# Deliberately explicit; manifest contents cannot extend verification scope.
WHITELIST = frozenset({
    'README.md', 'records.json', 'verify.py',
    'tools/node115_slice20_equal.py', 'tests/test_node115_slice20_equal.py',
    'tools/elf_index.py', 'tools/fde_extents.py',
})
PACKET_FILES = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}


def verify(packet=None, root=None):
    packet = Path(packet) if packet is not None else Path(__file__).resolve().parent
    root = Path(root) if root is not None else ROOT
    names = {p.name for p in packet.iterdir() if p.name != '__pycache__'}
    if names != PACKET_FILES or any(not (packet / name).is_file() for name in PACKET_FILES):
        raise ValueError('packet file whitelist mismatch')
    entries = {}
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None:
            raise ValueError('malformed manifest entry')
        digest, name = match.groups()
        if name in entries or name not in WHITELIST:
            raise ValueError('manifest whitelist mismatch')
        entries[name] = digest
    if entries.keys() != WHITELIST:
        raise ValueError('manifest whitelist mismatch')
    for name, expected in entries.items():
        path = root / name if '/' in name else packet / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'manifest hash mismatch: {name}')
    record = subject.collect(root / 'artifacts/node/115/hl-node')
    if (packet / 'records.json').read_bytes() != subject.encoded_json(record):
        raise ValueError('records regeneration mismatch')
    if (packet / 'README.md').read_bytes() != subject.readme(record):
        raise ValueError('README regeneration mismatch')
    return record['metrics']


if __name__ == '__main__':
    print('Verified slice20-equal:', verify())
