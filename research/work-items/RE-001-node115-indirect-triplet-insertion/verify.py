#!/usr/bin/env python3
"""Verify exactly this packet and regenerate its static semantic evidence. MIT."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
import node115_indirect_triplet_insertion as subject

WHITELIST = (
    'README.md', 'records.json', 'verify.py',
    'tools/node115_indirect_triplet_insertion.py',
    'tests/test_node115_indirect_triplet_insertion.py',
    'tools/elf_index.py', 'tools/fde_extents.py',
)
PACKET_FILES = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}


def verify(packet=PACKET):
    packet = Path(packet)
    subject.require(not packet.is_symlink(), 'Symlinked packet directory')
    subject.require({p.name for p in packet.iterdir()} == PACKET_FILES,
                    'Packet file whitelist mismatch')
    manifest = packet / 'MANIFEST.sha256'
    subject.require(not manifest.is_symlink(), 'Symlinked manifest')
    lines = manifest.read_text(encoding='ascii').splitlines()
    seen = []
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        subject.require(match is not None, 'Malformed manifest row')
        want, name = match.groups()
        subject.require(name in WHITELIST and name not in seen, 'Manifest whitelist/duplicate violation')
        seen.append(name)
        base = packet if '/' not in name else ROOT
        path = base / name
        subject.require(path.is_file() and not path.is_symlink(), 'Missing/symlinked manifest member')
        subject.require(path.resolve().is_relative_to(base.resolve()), 'Manifest member escapes its directory')
        for parent in path.parents:
            if parent == base:
                break
            subject.require(not parent.is_symlink(), 'Symlinked manifest directory')
        subject.require(hashlib.sha256(path.read_bytes()).hexdigest() == want,
                        f'Manifest digest mismatch: {name}')
    subject.require(tuple(seen) == WHITELIST, 'Manifest whitelist incomplete or reordered')
    record = subject.analyze_path()
    subject.require((packet / 'records.json').read_bytes() == subject.json_bytes(record),
                    'Regenerated semantic records differ')
    subject.require((packet / 'README.md').read_bytes() == subject.readme(record),
                    'Regenerated README differs')
    return record


if __name__ == '__main__':
    try:
        record = verify()
        print('Verified node #115 indirect triplet insertion: manifest and static regeneration agree.')
    except (ValueError, OSError, UnicodeError) as error:
        print(f'indirect-triplet-insertion: {error}', file=sys.stderr)
        sys.exit(1)
