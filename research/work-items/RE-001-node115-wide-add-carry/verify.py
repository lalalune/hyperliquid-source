#!/usr/bin/env python3
"""Check this packet's exact file whitelist and SHA-256 manifest."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent
names = {'README.md', 'records.json', 'verify.py'}
if {p.name for p in root.iterdir()} != names | {'MANIFEST.sha256'}:
    raise SystemExit('unexpected packet contents')
lines = (root / 'MANIFEST.sha256').read_text().splitlines()
expected = [f'{hashlib.sha256((root / n).read_bytes()).hexdigest()}  {n}' for n in sorted(names)]
if lines != expected:
    raise SystemExit('packet manifest mismatch')
print('Packet whitelist and SHA-256 manifest verified')
