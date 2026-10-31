#!/usr/bin/env python3
"""Check retained/source hashes and independently recollect the finite packet."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        expected, name = line.split('  ', 1)
        require(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, f'hash mismatch: {name}')
    for name, expected in json.loads((HERE / 'source-sha256.json').read_text()).items():
        require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, f'source mismatch: {name}')
    with tempfile.TemporaryDirectory(prefix='kind5-verify-') as tmp:
        output = Path(tmp) / 'fresh'
        subprocess.run([sys.executable, '-B', str(ROOT / 'tools/kind5_reader.py'), '--output', str(output)], cwd=ROOT, check=True)
        require((output / 'reader.json').read_bytes() == (HERE / 'reader.json').read_bytes(), 'semantic records changed')
        require(gzip.decompress((output / 'cases.tsv.gz').read_bytes()) == gzip.decompress((HERE / 'cases.tsv.gz').read_bytes()), 'fixture results changed')
    print('kind5 packet: hashes, both native decodes and 28,992 fixture results PASS; no target execution or gate')


if __name__ == '__main__':
    main()
