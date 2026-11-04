#!/usr/bin/env python3
"""Verify the exact packet whitelist and its SHA-256 manifest."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMES = ('README.md', 'records.json', 'verify.py')
lines = (HERE / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines()
if len(lines) != len(NAMES):
    raise SystemExit('manifest entry count mismatch')
for name, line in zip(NAMES, lines):
    digest, sep, actual = line.partition('  ')
    if sep != '  ' or actual != name or len(digest) != 64 or hashlib.sha256((HERE / name).read_bytes()).hexdigest() != digest:
        raise SystemExit('manifest mismatch: ' + name)
if {p.name for p in HERE.iterdir()} != set(NAMES) | {'MANIFEST.sha256'}:
    raise SystemExit('unexpected packet file')
print('Packet manifest verified')
