#!/usr/bin/env python3
"""Fail-closed whitelist, manifest and target-byte verification for this packet."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from tools import node115_ring_ranges as binding

WHITELIST = frozenset({
    'README.md', 'records.json', 'verify.py',
    'tools/node115_ring_ranges.py', 'tests/test_node115_ring_ranges.py',
})
PACKET_FILES = frozenset({'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'})


def manifest_entries(text):
    entries = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)', line)
        if match is None:
            raise ValueError('Malformed manifest row')
        expected, name = match.groups()
        if name not in WHITELIST or name in entries:
            raise ValueError('Manifest path is not whitelisted or is duplicated')
        entries[name] = expected
    if entries.keys() != WHITELIST:
        raise ValueError('Manifest whitelist is incomplete')
    return entries


def verify(packet=PACKET, root=ROOT):
    actual = {p.name for p in packet.iterdir()}
    if actual != PACKET_FILES:
        raise ValueError('Packet file whitelist differs')
    entries = manifest_entries((packet / 'MANIFEST.sha256').read_text(encoding='utf-8'))
    for name, expected in entries.items():
        path = root / name if name.startswith(('tools/', 'tests/')) else packet / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Manifest requires regular files')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Manifest hash mismatch: {name}')
    with binding.mapped(root / 'artifacts/node/115/hl-node') as data:
        binding.authenticate(data)
        record = binding.inspect(data)
    if (packet / 'records.json').read_bytes() != binding.records_bytes(record):
        raise ValueError('Regenerated semantic records differ')
    if (packet / 'README.md').read_bytes() != binding.render_readme(record).encode('utf-8'):
        raise ValueError('Regenerated README differs')
    return record['counts']


if __name__ == '__main__':
    try:
        print('Verified node #115 ring-range packet:', verify())
    except (ValueError, OSError) as error:
        raise SystemExit(f'verify: {error}')
