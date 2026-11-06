#!/usr/bin/env python3
"""Verify the exact decimal-cursor packet whitelist, hashes and regenerated evidence."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
LOCAL_FILES = frozenset(('README.md', 'records.json', 'instructions.txt', 'verify.py'))
DEPENDENCIES = frozenset(('tools/node115_decimal_cursor.py', 'tests/test_node115_decimal_cursor.py',
                          'tools/elf_index.py', 'tools/fde_extents.py'))
ENTRY = re.compile(r'([0-9a-f]{64})  (\S+)')


def check_manifest(packet=PACKET, root=ROOT):
    packet, root = Path(packet), Path(root)
    actual = {p.name for p in packet.iterdir()}
    if actual != LOCAL_FILES | {'MANIFEST.sha256'}:
        raise ValueError('packet file whitelist mismatch')
    if any(p.is_symlink() or not p.is_file() for p in packet.iterdir()):
        raise ValueError('packet must contain only regular files')
    entries = {}
    for line in (packet / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        match = ENTRY.fullmatch(line)
        if not match or match[2] in entries:
            raise ValueError('malformed or duplicate manifest entry')
        entries[match[2]] = match[1]
    if entries.keys() != LOCAL_FILES | DEPENDENCIES:
        raise ValueError('manifest whitelist mismatch')
    for name, digest in entries.items():
        path = packet / name if name in LOCAL_FILES else root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('manifest file missing or symlinked: ' + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('manifest digest mismatch: ' + name)
    return len(entries)


def verify():
    entries = check_manifest()
    sys.path.insert(0, str(ROOT / 'tools'))
    import node115_decimal_cursor as producer
    record = producer.load_record()
    for name, expected in producer.payloads(record).items():
        if (PACKET / name).read_bytes() != expected:
            raise ValueError('regenerated evidence mismatch: ' + name)
    print(f"Verified node #115 {producer.START:#x}: {entries} manifest entries; byte-identical evidence.")


if __name__ == '__main__':
    try:
        verify()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
