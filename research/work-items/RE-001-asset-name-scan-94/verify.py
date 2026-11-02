#!/usr/bin/env python3
"""Verify this packet's exact manifest whitelist and digest-bound regeneration."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools import asset_name_scan as bind

# Deliberately explicit: no arbitrary manifest paths, globs, or shell commands.
WHITELIST = frozenset({
    'README.md', 'records.json', 'instructions.txt', 'verify.py',
    'tools/asset_name_scan.py', 'tests/test_asset_name_scan.py',
})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=bind.BINARY)
    args = parser.parse_args()
    bind.require(WHITELIST == bind.WHITELIST, 'verifier whitelist drift')
    bind.check_packet(Path(__file__).resolve().parent, args.binary)
    print('ALL CHECKS PASSED: static asset-name scan bind; no target execution')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print('verify: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
