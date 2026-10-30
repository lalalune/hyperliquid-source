#!/usr/bin/env python3
"""Regenerate evm-db-blake3.json from node #94 and compare byte-for-byte with pinned hashes."""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_db_blake3 as m  # noqa: E402
import bincode_varint as bv  # noqa: E402

BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_SHA = 'd0047969a9226409e8d74480d57df9cd76bd4c8d91fcbbb38792c9a85fbead4e'


def main():
    data = bv.TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != BIN_SHA:
        print('FAIL: binary is not node #94')
        return 1
    want = (Path(__file__).parent / 'evm-db-blake3.json').read_bytes()
    got = m.render(m.scan(data))
    if got != want or hashlib.sha256(got).hexdigest() != JSON_SHA:
        print('FAIL: evm-db-blake3.json differs from regenerated output')
        return 1
    print(f'PASS evm-db-blake3.json sha256 {JSON_SHA}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
