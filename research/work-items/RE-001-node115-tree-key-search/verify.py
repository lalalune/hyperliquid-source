#!/usr/bin/env python3
"""Verify this packet's exact file whitelist and content hashes."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMES = ('README.md', 'records.json', 'verify.py')

def main():
    if {p.name for p in HERE.iterdir()} != set(NAMES) | {'MANIFEST.sha256'}:
        raise ValueError('packet file whitelist mismatch')
    rows = (HERE / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
    expected = [hashlib.sha256((HERE / n).read_bytes()).hexdigest() + '  ' + n for n in NAMES]
    if rows != expected:
        raise ValueError('packet manifest mismatch')
    print('Packet whitelist and hashes verified.')

if __name__ == '__main__':
    main()
