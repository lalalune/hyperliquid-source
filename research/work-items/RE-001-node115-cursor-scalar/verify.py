#!/usr/bin/env python3
"""Check this packet's exact whitelist and regenerate its semantic record."""
import hashlib
import mmap
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cursor_scalar as bind


def verify():
    expected = {'README.md': HERE / 'README.md', 'records.json': HERE / 'records.json',
                'verify.py': HERE / 'verify.py',
                'tools/node115_cursor_scalar.py': ROOT / 'tools/node115_cursor_scalar.py',
                'tests/test_node115_cursor_scalar.py': ROOT / 'tests/test_node115_cursor_scalar.py'}
    lines = (HERE / 'MANIFEST.sha256').read_text().splitlines()
    rows = {}
    for line in lines:
        digest, separator, name = line.partition('  ')
        if not separator or name in rows or name not in expected or len(digest) != 64:
            raise ValueError('invalid manifest entry')
        rows[name] = digest
    if set(rows) != set(expected) or {p.name for p in HERE.iterdir()} != {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}:
        raise ValueError('packet whitelist mismatch')
    for name, digest in rows.items():
        if hashlib.sha256(expected[name].read_bytes()).hexdigest() != digest:
            raise ValueError('packet hash mismatch: ' + name)
    with bind.TARGET.open('rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            actual = bind.render(bind.collect(data))
    if actual != (HERE / 'records.json').read_bytes():
        raise ValueError('semantic record mismatch')
    print('Packet whitelist, hashes and regenerated records verified.')


if __name__ == '__main__':
    verify()
