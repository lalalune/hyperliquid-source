#!/usr/bin/env python3
"""Fail closed on packet file additions or changed content."""
import hashlib
from pathlib import Path

folder = Path(__file__).resolve().parent
expected = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}
if {p.name for p in folder.iterdir()} != expected:
    raise SystemExit('packet whitelist mismatch')
lines = (folder/'MANIFEST.sha256').read_text().splitlines()
expected_files = ('README.md', 'records.json', 'verify.py')
if len(lines) != len(expected_files):
    raise SystemExit('manifest length mismatch')
for line, name in zip(lines, expected_files):
    digest, separator, filename = line.partition('  ')
    if separator != '  ' or filename != name or digest != hashlib.sha256((folder/name).read_bytes()).hexdigest():
        raise SystemExit('manifest mismatch')
print('Packet whitelist and manifest verified')
