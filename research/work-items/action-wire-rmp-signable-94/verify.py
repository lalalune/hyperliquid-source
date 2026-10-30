#!/usr/bin/env python3
"""Verify packet hashes and regenerate its digest-pinned JSON, without target execution."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_path as evidence

FILES = {'README.md', 'RESULT.md', 'rmp-signable-path.json', 'objdump-excerpts.txt', 'verify.py'}
JSON_SHA256 = '3c1edd32f4ad2805bccb6216fd94a061087972896fdb0bdd61342a1b4094d85a'


def verify(directory=HERE, binary=evidence.TARGET):
    entries = {}
    for line in (directory / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if name not in FILES or name in entries or len(digest) != 64:
            raise ValueError('invalid manifest entry')
        entries[name] = digest
    if set(entries) != FILES:
        raise ValueError('incomplete manifest')
    for name, digest in entries.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'manifest mismatch: {name}')
    rendered = evidence.render(evidence.build(binary.read_bytes()))
    if hashlib.sha256(rendered).hexdigest() != JSON_SHA256:
        raise ValueError('regenerated JSON hash mismatch')
    if rendered != (directory / 'rmp-signable-path.json').read_bytes():
        raise ValueError('regenerated JSON differs')
    result = json.loads(rendered)
    if len(result['scoped_locations']) != 3 or result['connectionId_raw_file_occurrences'] != 0:
        raise ValueError('unexpected evidence counts')


def main():
    try:
        verify()
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
