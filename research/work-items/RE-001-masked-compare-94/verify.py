#!/usr/bin/env python3
"""Verify a closed file whitelist, then regenerate static node94 evidence."""
import argparse
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
PREFIX = 'research/work-items/RE-001-masked-compare-94/'
WHITELIST = {
    PREFIX + 'README.md', PREFIX + 'records.json', PREFIX + 'instructions.txt',
    PREFIX + 'callers.txt', PREFIX + 'verify.py',
    'tools/foundation_masked_compare.py', 'tests/test_foundation_masked_compare.py',
    'tools/elf_index.py', 'tools/fde_extents.py',
}


def verify_manifest():
    seen = set()
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        digest, separator, name = line.partition('  ')
        if (not separator or len(digest) != 64 or
                any(c not in '0123456789abcdef' for c in digest) or
                name not in WHITELIST or name in seen):
            raise ValueError('manifest syntax/whitelist/duplicate violation')
        seen.add(name)
        path = ROOT / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('manifest hash/symlink violation: ' + name)
    if seen != WHITELIST:
        raise ValueError('manifest omits a required file')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    args = parser.parse_args()
    try:
        verify_manifest()
        sys.path.insert(0, str(ROOT / 'tools'))
        from foundation_masked_compare import check_packet
        check_packet(args.binary, PACKET)
    except (ValueError, OSError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('ALL CHECKS PASSED (static only; no target execution)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
