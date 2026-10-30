#!/usr/bin/env python3
"""Recompute RE-010 evidence from the pinned node #94 artifact and check it byte-for-byte.

Run from the repo root:  python3 -I -B research/work-items/RE-010-exchange-handlers/verify.py
Uses explicit checks (no assert), so it is also valid under python -O.
"""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_dispatch as ed  # noqa: E402

EXPECTED = {
    'table_entries': 88,
    'reconstruction_claims': 76,
    'fde_count': 121299,
    'status_counts': {'inline_claim_no_call': 1, 'real_first_call': 74, 'real_first_call_on_branch': 1},
    'address_survey_counts': {'at_fde_start': 206, 'inside_fde': 3},
}


def fail(msg):
    print(f'RE-010 verify: FAIL: {msg}', file=sys.stderr)
    raise SystemExit(1)


PACKET_FILES = frozenset({
    'README.md', 'exchange-dispatch.json', 'objdump-excerpts.txt',
})


def main():
    listed = set()
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        want, name = line.split('  ', 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if got != want:
            fail(f'{name} sha256 {got} != manifest {want}')
        listed.add(name)
    # This packet's manifest pins the evidence files and README.md; this
    # script is committed unlisted. Comparing the manifest only against
    # the directory is not enough: an evidence file deleted together with
    # its manifest row leaves the two sets equal. So the listed set must
    # also equal the pinned packet file set, and the directory must not
    # hold unlisted files.
    if listed != PACKET_FILES:
        fail(f'manifest file set differs from the pinned packet files: '
             f'missing rows {sorted(PACKET_FILES - listed)}, unexpected rows {sorted(listed - PACKET_FILES)}')
    present = {p.name for p in HERE.iterdir() if p.is_file()} - {'MANIFEST.sha256', 'verify.py'}
    if listed != present:
        fail(f'manifest file set differs from packet contents: '
             f'unlisted {sorted(present - listed)}, missing {sorted(listed - present)}')
    try:
        result = ed.build(ed.TARGET.read_bytes())
    except ed.EvidenceError as e:
        fail(str(e))
    for k, v in EXPECTED.items():
        if result[k] != v:
            fail(f'{k} = {result[k]!r}, expected {v!r}')
    text = ed.render(result)
    if text != (HERE / 'exchange-dispatch.json').read_bytes():
        fail('recomputed exchange-dispatch.json differs from committed copy')
    print('RE-010 verify: OK exchange-dispatch.json', hashlib.sha256(text).hexdigest())


if __name__ == '__main__':
    main()
