#!/usr/bin/env python3
"""Whitelist/hash-check and regenerate this static packet; never execute the target."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from system_user_capped_advance import TARGET, verify_packet  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    try:
        verify_packet(Path(__file__).resolve().parent, args.binary)
    except (OSError, ValueError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('ALL CHECKS PASSED: whitelist, manifest, target identity and regenerated evidence.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
