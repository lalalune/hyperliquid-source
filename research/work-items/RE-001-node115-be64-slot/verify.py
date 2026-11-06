#!/usr/bin/env python3
"""Fail-closed verification of the packet's fixed file whitelist."""
import hashlib
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
EXPECTED = {'README.md', 'records.json', 'verify.py'}

def verify():
    lines = (HERE/'MANIFEST.sha256').read_text().splitlines()
    seen = set()
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-zA-Z0-9_.-]+)', line)
        if not match:
            raise ValueError('invalid manifest row')
        digest, name = match.groups()
        if name not in EXPECTED or name in seen:
            raise ValueError('unexpected or duplicate file')
        seen.add(name)
        if hashlib.sha256((HERE/name).read_bytes()).hexdigest() != digest:
            raise ValueError('hash mismatch: '+name)
    if seen != EXPECTED or {x.name for x in HERE.iterdir()} != EXPECTED | {'MANIFEST.sha256'}:
        raise ValueError('packet whitelist mismatch')
    print('Verified packet whitelist and hashes')

if __name__ == '__main__':
    verify()
