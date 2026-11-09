#!/usr/bin/env python3
"""Verify retained synthetic vectors with local OpenSSL; no target execution."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / 'src/node115-bridge-preimage/tests/openssl-vectors.txt'


def main():
    data = VECTORS.read_bytes()
    count = 0
    for line in data.decode('ascii').splitlines():
        first, second, preimage, expected = map(bytes.fromhex, line.split())
        if [len(x) for x in (first, second, preimage, expected)] != [20, 32, 64, 32]:
            raise ValueError('vector lengths')
        if preimage != bytes(12) + first + second:
            raise ValueError('vector layout')
        actual = subprocess.run(['openssl', 'dgst', '-KECCAK-256', '-binary'],
                                input=preimage, capture_output=True, check=True).stdout
        if actual != expected:
            raise ValueError(f'OpenSSL mismatch at case {count}')
        count += 1
    if count != 64:
        raise ValueError('expected64 cases')
    print(json.dumps({'reference': subprocess.check_output(['openssl', 'version'], text=True).strip(),
                      'cases': count, 'vector_sha256': hashlib.sha256(data).hexdigest(),
                      'result': 'all matched', 'target_execution': False}, indent=2))


if __name__ == '__main__':
    main()
