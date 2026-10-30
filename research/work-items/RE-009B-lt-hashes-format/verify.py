#!/usr/bin/env python3
"""Regenerate lt-hashes-format.json from node #94 and compare byte-for-byte with pinned hashes."""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import lt_hashes_format as m  # noqa: E402
import bincode_varint as bv  # noqa: E402

BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_SHA = '007928510442778665a87e3bb086cd96be5c41f3c83f2ed69350f9b87aed6cfb'


def main():
    data = bv.TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != BIN_SHA:
        print('FAIL: binary is not node #94')
        return 1
    want = (Path(__file__).parent / 'lt-hashes-format.json').read_bytes()
    got = m.render(m.scan(data))
    if got != want or hashlib.sha256(got).hexdigest() != JSON_SHA:
        print('FAIL: lt-hashes-format.json differs from regenerated output')
        return 1
    print(f'PASS lt-hashes-format.json sha256 {JSON_SHA}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
