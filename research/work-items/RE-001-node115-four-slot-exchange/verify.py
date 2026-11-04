#!/usr/bin/env python3
"""Check the packet whitelist, hashes and reproducible target-bound records."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FILES = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}


def main():
    if {p.name for p in HERE.iterdir()} != FILES:
        raise ValueError('packet whitelist mismatch')
    lines = (HERE / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
    entries = {}
    for line in lines:
        digest, name = line.split('  ', 1)
        if name in entries or name not in FILES - {'MANIFEST.sha256'}:
            raise ValueError('manifest entry mismatch')
        entries[name] = digest
    if set(entries) != FILES - {'MANIFEST.sha256'}:
        raise ValueError('incomplete manifest')
    for name, expected in entries.items():
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != expected:
            raise ValueError('manifest digest mismatch: ' + name)
    with tempfile.TemporaryDirectory() as temp:
        subprocess.run([sys.executable, str(ROOT / 'tools/node115_four_slot_exchange.py'), '--out', temp], check=True)
        if (Path(temp) / 'records.json').read_bytes() != (HERE / 'records.json').read_bytes():
            raise ValueError('regenerated records differ')
    print('Packet manifest and regenerated records verified.')


if __name__ == '__main__':
    main()
