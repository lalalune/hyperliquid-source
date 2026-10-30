#!/usr/bin/env python3
"""Verify packet integrity and regenerate its target-bound inventory offline."""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import dex_registry_inventory as inv


def main():
    expected = {'README.md', 'inventory.json', 'objdump-excerpts.txt', 'verify.py'}
    entries = {}
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if name not in expected or name in entries:
            raise ValueError('unexpected or duplicate manifest entry')
        entries[name] = digest
    if set(entries) != expected:
        raise ValueError('incomplete manifest')
    for name, digest in entries.items():
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != digest:
            raise ValueError('manifest mismatch: ' + name)
    output = inv.render(inv.build(inv.TARGET.read_bytes(), inv.REF.read_bytes()))
    if output != (HERE / 'inventory.json').read_bytes():
        raise ValueError('regeneration mismatch')
    print('PASS: manifest and digest-bound byte-identical regeneration')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        print('FAIL:', exc, file=sys.stderr)
        raise SystemExit(1)
