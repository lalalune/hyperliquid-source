#!/usr/bin/env python3
"""Verify this packet's exact file whitelist and SHA-256 manifest."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent
names = ('README.md', 'records.json', 'verify.py')
expected = set(names) | {'MANIFEST.sha256'}
if {p.name for p in root.iterdir()} != expected:
    raise SystemExit('unexpected or missing packet files')
manifest = ''.join(hashlib.sha256((root / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
if (root / 'MANIFEST.sha256').read_text(encoding='ascii') != manifest:
    raise SystemExit('manifest mismatch')
print('Packet whitelist and SHA-256 manifest verified')
