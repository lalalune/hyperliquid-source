#!/usr/bin/env python3
"""Check the packet whitelist, hashes, and freshly generated evidence."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

here = Path(__file__).resolve().parent
root = here.parents[2]
allowed = {'README.md', 'records.json', 'verify.py'}
if {p.name for p in here.iterdir()} != allowed | {'MANIFEST.sha256'}:
    raise SystemExit('Unexpected packet files')
rows = (here / 'MANIFEST.sha256').read_text().splitlines()
expected = {}
for row in rows:
    digest, name = row.split('  ', 1)
    if name not in allowed or name in expected or len(digest) != 64:
        raise SystemExit('Invalid manifest whitelist')
    expected[name] = digest
if set(expected) != allowed:
    raise SystemExit('Incomplete manifest')
for name, digest in expected.items():
    if hashlib.sha256((here / name).read_bytes()).hexdigest() != digest:
        raise SystemExit('Manifest mismatch: ' + name)
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, str(root / 'tools/node115_checked_read32.py'), '--out', tmp], check=True)
    for name in allowed | {'MANIFEST.sha256'}:
        if (here / name).read_bytes() != (Path(tmp) / name).read_bytes():
            raise SystemExit('Regenerated file differs: ' + name)
print('Packet whitelist, hashes and regeneration verified')
