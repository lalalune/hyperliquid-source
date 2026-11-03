#!/usr/bin/env python3
"""Verify the closed manifest and regenerate evidence without executing the target."""
import hashlib
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ALLOWED = ('README.md', 'records.json', 'verify.py',
           '../../../tools/node115_record20_equality.py',
           '../../../tests/test_node115_record20_equality.py')
sys.path.insert(0, str(ROOT / 'tools'))
import node115_record20_equality as producer


def main():
    if {p.name for p in HERE.iterdir()} != {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}:
        raise ValueError('packet file set changed')
    rows = (HERE / 'MANIFEST.sha256').read_text().splitlines()
    paths = []
    for row in rows:
        digest, path = row.split('  ', 1)
        if path not in ALLOWED or path in paths:
            raise ValueError('manifest whitelist violation')
        paths.append(path)
        if hashlib.sha256((HERE / path).read_bytes()).hexdigest() != digest:
            raise ValueError('manifest digest mismatch: ' + path)
    if tuple(paths) != ALLOWED:
        raise ValueError('manifest file set changed')
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory)
        producer.generate(out)
        for name in ('README.md', 'records.json'):
            if (out / name).read_bytes() != (HERE / name).read_bytes():
                raise ValueError('regenerated evidence differs: ' + name)
    print('Manifest and regenerated evidence verified.')


if __name__ == '__main__':
    main()
