#!/usr/bin/env python3
"""Verify precisely the expected evidence packet files and their hashes."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent
names = ('README.md', 'records.json', 'verify.py')
expected = set(names) | {'MANIFEST.sha256'}
if {p.name for p in root.iterdir()} != expected:
    raise SystemExit('unexpected packet files')
manifest = ''.join(hashlib.sha256((root/name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
if (root/'MANIFEST.sha256').read_text(encoding='ascii') != manifest:
    raise SystemExit('manifest mismatch')
print('packet manifest OK')
