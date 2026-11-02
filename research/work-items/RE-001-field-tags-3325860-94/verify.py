#!/usr/bin/env python3
"""Verify the exact whitelist and regenerate semantic evidence from node #94."""
import hashlib
import json
import mmap
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import field_tags_3325860 as bind

WHITELIST = ('README.md', 'instructions.txt', 'records.json', 'verify.py')


def verify(packet=PACKET, binary=ROOT / 'artifacts/node/94/hl-node'):
    lines = (packet / 'MANIFEST.sha256').read_text().splitlines()
    entries = {}
    for line in lines:
        digest, sep, name = line.partition('  ')
        if not sep or name not in WHITELIST or name in entries or len(digest) != 64:
            raise ValueError('invalid manifest entry')
        entries[name] = digest
    if set(entries) != set(WHITELIST): raise ValueError('manifest whitelist mismatch')
    for name in WHITELIST:
        if hashlib.sha256((packet/name).read_bytes()).hexdigest() != entries[name]:
            raise ValueError('manifest digest mismatch: ' + name)
    with open(binary, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        records, walk = bind.analyze(data)
    expected = json.dumps(records, indent=2) + '\n'
    if (packet/'records.json').read_text() != expected: raise ValueError('records mismatch')
    if (packet/'instructions.txt').read_text() != '\n'.join(walk) + '\n': raise ValueError('walk mismatch')
    return records

if __name__ == '__main__':
    try:
        verify()
        print('ALL CHECKS PASSED')
    except (ValueError, OSError) as exc:
        print('FAIL:', exc, file=sys.stderr)
        sys.exit(1)
