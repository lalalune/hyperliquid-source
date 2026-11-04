#!/usr/bin/env python3
"""Verify the exact packet whitelist and manifest without executing the target."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent
names = ('README.md', 'records.json', 'verify.py')
actual = {p.name for p in root.iterdir()}
if actual != set(names) | {'MANIFEST.sha256'}:
    raise SystemExit('unexpected or missing packet files')
expected = ''.join(hashlib.sha256((root/name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names)
if (root/'MANIFEST.sha256').read_text(encoding='utf-8') != expected:
    raise SystemExit('manifest mismatch')
print('Packet whitelist and SHA-256 manifest OK')
