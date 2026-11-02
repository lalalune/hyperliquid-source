#!/usr/bin/env python3
"""Verify this packet's whitelist, manifest, and authenticated regeneration."""
import hashlib
import json
import mmap
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import word_complement_94 as bind

FILES = {'README.md', 'records.json', 'walk.txt', 'verify.py', 'MANIFEST.sha256'}


def verify():
    if {p.name for p in HERE.iterdir()} != FILES or any(not p.is_file() or p.is_symlink() for p in HERE.iterdir()):
        raise ValueError('packet whitelist mismatch')
    expected_manifest = ''.join(f"{hashlib.sha256((HERE / name).read_bytes()).hexdigest()}  {name}\n"
                                for name in sorted(FILES - {'MANIFEST.sha256'}))
    if (HERE / 'MANIFEST.sha256').read_text(encoding='utf-8') != expected_manifest:
        raise ValueError('manifest mismatch')
    with bind.BINARY.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record, walk = bind.collect(data)
    if (HERE / 'records.json').read_text(encoding='utf-8') != json.dumps(record, indent=2) + '\n':
        raise ValueError('records differ from binary')
    if (HERE / 'walk.txt').read_text(encoding='utf-8') != walk:
        raise ValueError('instruction walk differs from binary')
    print('Packet whitelist, manifest, and binary-derived evidence verified.')


if __name__ == '__main__':
    verify()
