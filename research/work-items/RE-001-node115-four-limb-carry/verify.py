#!/usr/bin/env python3
"""Check only the declared packet files and regenerate the semantic record."""
import hashlib
import json
import mmap
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_four_limb_carry as binding

HERE = Path(__file__).resolve().parent


def main():
    lines = (HERE / 'MANIFEST.sha256').read_text().splitlines()
    if len(lines) != len(binding.FILES):
        raise ValueError('manifest length')
    for line, name in zip(lines, binding.FILES):
        digest, sep, found = line.partition('  ')
        if not sep or found != name or len(digest) != 64:
            raise ValueError('manifest whitelist')
        path = HERE / name if not name.startswith('../../../') else ROOT / name[9:]
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('manifest hash: ' + name)
    with binding.TARGET.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = binding.extract(data)
    if (HERE / 'records.json').read_text() != json.dumps(record, indent=2) + '\n':
        raise ValueError('semantic record differs')
    print('Manifest and authenticated semantic record verified.')


if __name__ == '__main__':
    main()
