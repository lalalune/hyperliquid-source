#!/usr/bin/env python3
"""Recompute RE-005 evidence (encode + decode) from the pinned node #94 artifact and check it byte-for-byte.

Run from the repo root:  python3 -I -B research/work-items/RE-005-bincode-varint/verify.py
Uses explicit checks (no assert), so it is also valid under python -O.
"""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402
import bincode_varint_decode as dv  # noqa: E402


def fail(msg):
    print(f'RE-005 verify: FAIL: {msg}', file=sys.stderr)
    raise SystemExit(1)


PACKET_FILES = frozenset({
    'decode-objdump-excerpts.txt', 'decode-sites.json',
    'objdump-excerpts.txt', 'varint-sites.json',
})


def main():
    listed = set()
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        want, name = line.split('  ', 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if got != want:
            fail(f'{name} sha256 {got} != manifest {want}')
        listed.add(name)
    # This packet's manifest pins the evidence files only; README.md and
    # this script are committed unlisted. Comparing the manifest only
    # against the directory is not enough: an evidence file deleted
    # together with its manifest row leaves the two sets equal. So the
    # listed set must also equal the pinned evidence set, and the
    # directory must not hold unlisted evidence files.
    if listed != PACKET_FILES:
        fail(f'manifest file set differs from the pinned packet files: '
             f'missing rows {sorted(PACKET_FILES - listed)}, unexpected rows {sorted(listed - PACKET_FILES)}')
    present = {p.name for p in HERE.iterdir() if p.is_file()} - {'MANIFEST.sha256', 'README.md', 'verify.py'}
    if listed != present:
        fail(f'manifest file set differs from packet contents: '
             f'unlisted {sorted(present - listed)}, missing {sorted(listed - present)}')
    data = bv.TARGET.read_bytes()
    for fname, mod in (('varint-sites.json', bv), ('decode-sites.json', dv)):
        try:
            text = bv.render(mod.scan(data))
        except bv.EvidenceError as e:
            fail(f'{fname}: {e}')
        if text != (HERE / fname).read_text():
            fail(f'recomputed {fname} differs from committed copy')
        print('RE-005 verify: OK', fname, hashlib.sha256(text.encode()).hexdigest())


if __name__ == '__main__':
    main()
