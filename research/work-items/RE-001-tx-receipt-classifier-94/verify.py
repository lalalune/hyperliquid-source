#!/usr/bin/env python3
"""Verify exact packet membership, hashes, and binary-derived contents."""
import mmap
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools import node94_tx_receipt as tool

HERE = Path(__file__).resolve().parent
WHITELIST = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}

def verify():
    if {p.name for p in HERE.iterdir()} != WHITELIST:
        raise ValueError('packet whitelist mismatch')
    with tool.BINARY.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        records, walk = tool.collect(m)
    expected = tool.render(records, walk, (HERE / 'verify.py').read_bytes())
    for name, data in expected.items():
        if (HERE / name).read_bytes() != data:
            raise ValueError('packet content mismatch: ' + name)
    print('ALL CHECKS PASSED')

if __name__ == '__main__':
    verify()
