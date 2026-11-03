#!/usr/bin/env python3
"""Verify an exact manifest whitelist and regenerate the subtraction evidence."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_sub256_borrow as subject

PACKET_REL = 'research/work-items/RE-001-node115-sub256-borrow'
WHITELIST = frozenset({
    f'{PACKET_REL}/README.md',
    f'{PACKET_REL}/records.json',
    f'{PACKET_REL}/verify.py',
    'tools/node115_sub256_borrow.py',
    'tests/test_node115_sub256_borrow.py',
    'tools/elf_index.py',
    'tools/fde_extents.py',
})


def verify_manifest(root=ROOT):
    root = Path(root).resolve()
    rows = (root / PACKET_REL / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
    entries = {}
    for row in rows:
        match = re.fullmatch(r'([0-9a-f]{64})  (\S+)', row)
        subject.require(match is not None, 'malformed manifest row')
        digest, relative = match.groups()
        subject.require(relative in WHITELIST, 'path outside manifest whitelist')
        subject.require(relative not in entries, 'duplicate manifest path')
        entries[relative] = digest
    subject.require(set(entries) == WHITELIST, 'manifest whitelist incomplete')
    for relative, expected in entries.items():
        path = root / relative
        subject.require(path.is_file() and not path.is_symlink()
                        and path.resolve().is_relative_to(root), 'missing or unsafe manifest file')
        subject.require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                        'manifest digest mismatch: ' + relative)
    return len(entries)


def verify(root=ROOT):
    count = verify_manifest(root)
    root = Path(root)
    record = subject.collect(root / 'artifacts/node/115/hl-node')
    packet = root / PACKET_REL
    subject.require((packet / 'records.json').read_bytes() == subject.encoded_records(record),
                    'regenerated semantic records differ')
    subject.require((packet / 'README.md').read_bytes()
                    == subject.render_readme(record).encode('utf-8'), 'regenerated README differs')
    return count


if __name__ == '__main__':
    try:
        checked = verify()
        print(f'node #115 {subject.START:#x}: manifest ({checked} files) and regenerated evidence verified')
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
