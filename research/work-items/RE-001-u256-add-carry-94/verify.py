#!/usr/bin/env python3
"""Whitelist and reproduce this packet; static, Python standard library only."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from u256_add_carry import BINARY, verify_packet

if __name__ == '__main__':
    try:
        verify_packet(Path(__file__).resolve().parent, BINARY)
    except (OSError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        raise SystemExit(1)
    print('ALL CHECKS PASSED (static evidence; target not executed)')
