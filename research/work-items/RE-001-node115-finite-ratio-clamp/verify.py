#!/usr/bin/env python3
"""Verify the exact finite-ratio-clamp whitelist and regenerate its byte evidence."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_finite_ratio_clamp as subject

PACKET_NAMES = {'README.md', 'records.json', 'verify.py'}
WHITELIST = PACKET_NAMES | {
    'tools/node115_finite_ratio_clamp.py',
    'tests/test_node115_finite_ratio_clamp.py',
    'tools/elf_index.py',
    'tools/fde_extents.py',
}


def verify(packet=subject.PACKET):
    packet = Path(packet)
    require = subject.require
    actual = {p.name for p in packet.iterdir() if p.name != '__pycache__'}
    require(actual == PACKET_NAMES | {'MANIFEST.sha256'}, 'packet file whitelist mismatch')
    entries = {}
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None, 'malformed manifest row')
        digest, name = match.groups()
        require(name in WHITELIST and name not in entries, 'manifest whitelist mismatch')
        entries[name] = digest
    require(set(entries) == WHITELIST, 'manifest whitelist incomplete')
    for name, digest in entries.items():
        target = packet / name if name in PACKET_NAMES else ROOT / name
        require(target.is_file() and not target.is_symlink(), 'missing or symlinked whitelist file')
        require(hashlib.sha256(target.read_bytes()).hexdigest() == digest, 'manifest hash mismatch')
    record, expected = subject.generate()
    for name, content in expected.items():
        require((packet / name).read_bytes() == content, f'regeneration mismatch: {name}')
    return record


if __name__ == '__main__':
    try:
        record = verify()
        print(f"Verified node #115 {record['window']['start']:#x}: whitelist and regeneration passed")
    except (ValueError, OSError) as error:
        print(f'finite-ratio-clamp verify: {error}', file=sys.stderr)
        raise SystemExit(1)
