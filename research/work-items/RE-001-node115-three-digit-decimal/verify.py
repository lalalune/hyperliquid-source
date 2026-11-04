#!/usr/bin/env python3
"""Verify the exact packet whitelist and its SHA-256 manifest."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ('README.md', 'records.json', 'verify.py',
         '../../../tools/node115_three_digit_decimal.py',
         '../../../tests/test_node115_three_digit_decimal.py')


def verify():
    if {p.name for p in HERE.iterdir()} != {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}:
        raise ValueError('unexpected packet files')
    lines = ''.join(f'{hashlib.sha256((HERE/name).read_bytes()).hexdigest()}  {name}\n' for name in FILES)
    if (HERE/'MANIFEST.sha256').read_text() != lines:
        raise ValueError('manifest mismatch')
    print('Verified packet whitelist and SHA-256 manifest')


if __name__ == '__main__':
    verify()
