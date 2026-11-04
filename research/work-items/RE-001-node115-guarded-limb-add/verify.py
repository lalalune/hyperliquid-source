#!/usr/bin/env python3
"""Whitelist, hash, and regenerate this packet against the authenticated target."""
import hashlib
import mmap
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_guarded_limb_add as bind

ALLOWED = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}
HASHED = ALLOWED - {'MANIFEST.sha256'}


def verify():
    if {p.name for p in PACKET.iterdir()} != ALLOWED:
        raise ValueError('Packet file whitelist mismatch')
    entries = {}
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if name in entries or name not in HASHED:
            raise ValueError('Unexpected or duplicate manifest entry')
        entries[name] = digest
    if set(entries) != HASHED:
        raise ValueError('Incomplete manifest')
    for name, digest in entries.items():
        path = PACKET / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Packet hash mismatch: ' + name)
    with bind.TARGET.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if bind.render(bind.collect(data)) != (PACKET / 'records.json').read_bytes():
            raise ValueError('Regenerated record mismatch')
    print('Packet whitelist, hashes and authenticated regeneration verified')


if __name__ == '__main__':
    verify()
