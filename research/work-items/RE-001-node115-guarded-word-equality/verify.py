#!/usr/bin/env python3
"""Verify the exact packet whitelist and rederive its semantic evidence."""
import hashlib
import mmap
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_guarded_word_equality as subject

# Independent literal whitelist: an edited manifest cannot widen the scope.
FILES = (
    'README.md', 'records.json', 'verify.py',
    'tools/node115_guarded_word_equality.py',
    'tests/test_node115_guarded_word_equality.py',
    'tools/elf_index.py', 'tools/fde_extents.py',
)


def verify_manifest(packet):
    packet = Path(packet)
    expected_payloads = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}
    actual_payloads = {p.name for p in packet.iterdir() if p.name != '__pycache__'}
    if actual_payloads != expected_payloads:
        raise ValueError('Packet payload whitelist mismatch')
    rows = []
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None:
            raise ValueError('Malformed manifest entry')
        rows.append(match.groups())
    if tuple(name for _, name in rows) != FILES:
        raise ValueError('Manifest whitelist/order mismatch')
    for want, name in rows:
        path = packet / name if '/' not in name else ROOT / name
        if not path.is_file() or path.is_symlink():
            raise ValueError('Manifest file missing or symlinked')
        if hashlib.sha256(path.read_bytes()).hexdigest() != want:
            raise ValueError(f'Manifest digest mismatch: {name}')


def verify(packet=None):
    packet = Path(packet) if packet is not None else Path(__file__).resolve().parent
    verify_manifest(packet)
    with subject.TARGET.open('rb') as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            payloads = subject.generated_files(data)
    for name, content in payloads.items():
        if (packet / name).read_bytes() != content:
            raise ValueError(f'Regenerated evidence mismatch: {name}')
    return True


if __name__ == '__main__':
    verify()
    print('Verified node #115 guarded word equality: manifest and byte-identical evidence')
