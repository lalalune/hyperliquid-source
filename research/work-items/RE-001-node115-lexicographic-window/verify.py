#!/usr/bin/env python3
"""Verify the exact packet whitelist, hashes and regenerated semantic records."""
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import node115_lexicographic_window as bind


def main():
    names = {'README.md','records.json','verify.py','MANIFEST.sha256'}
    if {p.name for p in HERE.iterdir()} != names or any(p.is_symlink() or not p.is_file() for p in HERE.iterdir()):
        raise ValueError('packet whitelist differs')
    entries = {}
    for line in (HERE/'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
        digest, name = line.split('  ',1)
        if name in entries or name not in names-{'MANIFEST.sha256'}:
            raise ValueError('bad manifest entry')
        entries[name] = digest
    if set(entries) != names-{'MANIFEST.sha256'}:
        raise ValueError('missing manifest entry')
    for name,digest in entries.items():
        if hashlib.sha256((HERE/name).read_bytes()).hexdigest() != digest:
            raise ValueError('manifest hash mismatch: '+name)
    expected = json.dumps(bind.analyze(bind.TARGET),indent=2)+'\n'
    if (HERE/'records.json').read_text(encoding='utf-8') != expected:
        raise ValueError('regenerated records differ')
    print('Packet whitelist, hashes and authenticated records verified.')

if __name__ == '__main__':
    main()
