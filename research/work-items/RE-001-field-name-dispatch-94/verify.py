#!/usr/bin/env python3
"""Verify the complete packet and its digest-bound binary evidence."""
import mmap
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools import field_name_dispatch_94 as bind

PACKET = Path(__file__).resolve().parent
WHITELIST = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}


def verify(packet=PACKET):
    if {p.name for p in packet.iterdir()} != WHITELIST:
        raise ValueError('packet whitelist mismatch')
    with bind.BINARY.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        rec, lines = bind.analyze(data)
    if (packet / 'records.json').read_bytes() != bind.records_bytes(rec):
        raise ValueError('semantic records mismatch')
    if (packet / 'MANIFEST.sha256').read_bytes() != bind.manifest_bytes(packet):
        raise ValueError('manifest mismatch')
    readme = (packet / 'README.md').read_text()
    expected = {'window_bytes': rec['window']['size'],
                'padding_bytes': len(bytes.fromhex(rec['window']['padding_hex'])),
                'branches': len(rec['branches']), 'direct_callees': len(rec['direct_callees']),
                'indirect_callees': len(rec['indirect_callees']),
                'direct_call_candidates': len(rec['incoming_rel32_byte_candidates']['calls']),
                'direct_jump_candidates': len(rec['incoming_rel32_byte_candidates']['jumps']),
                'vectors': len(rec['vectors'])}
    table = '| Metric | Count |\n| --- | ---: |\n' + '\n'.join(
        f'| {k} | {v} |' for k, v in expected.items())
    if readme.count(table) != 1: raise ValueError('README counts mismatch')
    rows = '\n'.join(f'| `0x{a:x}` | `{b}` | `{c}` |' for a,b,c in lines)
    if rows not in readme: raise ValueError('README instruction walk mismatch')
    return rec

if __name__ == '__main__':
    try:
        verify()
    except (ValueError, OSError) as exc:
        print('FAIL:', exc, file=sys.stderr)
        sys.exit(1)
    print('ALL CHECKS PASSED')
