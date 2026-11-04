#!/usr/bin/env python3
"""Check this packet's fixed manifest without trusting manifest paths."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ('README.md', 'records.json', 'verify.py')


def verify():
    if {p.name for p in HERE.iterdir()} != set(FILES) | {'MANIFEST.sha256'}:
        raise ValueError('unexpected packet files')
    rows = []
    for name in FILES:
        rows.append(hashlib.sha256((HERE / name).read_bytes()).hexdigest() + '  ' + name + '\n')
    if (HERE / 'MANIFEST.sha256').read_text() != ''.join(rows):
        raise ValueError('manifest mismatch')
    print('Packet manifest verified')


if __name__ == '__main__':
    verify()
