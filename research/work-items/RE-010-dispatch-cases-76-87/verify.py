#!/usr/bin/env python3
"""Recompute the RE-010 cases 76..87 / shared-tail evidence and check it byte-for-byte.

Run from the repo root:
  python3 -I -B research/work-items/RE-010-dispatch-cases-76-87/verify.py
Explicit checks (no assert), so it is also valid under python -O.
"""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_dispatch as ed  # noqa: E402
import exchange_dispatch_tail as edt  # noqa: E402

EXPECTED_COUNTS = {
    'name_agreement_counts': {'action_suffix': 13, 'different': 1, 'exact': 51,
                              'first_letter_case': 6, 'first_letter_case_and_action_suffix': 5},
    'unclaimed_join_counts': {0x275A182: 2, 0x275A186: 10},
    'tail_branch_source_counts': {0x275A136: 8, 0x275A180: 2, 0x275A182: 9, 0x275A186: 78},
}
EXPECTED_TABLES = [0x56C46E0, 0x56E8BD0, 0x5733130]


def fail(msg):
    print(f'RE-010 cases 76..87 verify: FAIL: {msg}', file=sys.stderr)
    raise SystemExit(1)


def main():
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        want, name = line.split('  ', 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if got != want:
            fail(f'{name} sha256 {got} != manifest {want}')
    try:
        result = edt.build(ed.TARGET.read_bytes())
    except ed.EvidenceError as e:
        fail(str(e))
    for k, v in EXPECTED_COUNTS.items():
        if result[k] != v:
            fail(f'{k} = {result[k]!r}, expected {v!r}')
    if [t['va'] for t in result['variant_tables']] != EXPECTED_TABLES:
        fail('variant table addresses moved')
    if [c['index'] for c in result['unclaimed_cases']] != list(range(76, 88)):
        fail('unclaimed case indices are not exactly 76..87')
    if len(result['variant_names']) != 88:
        fail('variant name count is not 88')
    text = edt.render(result)
    if text != (HERE / 'dispatch-tail.json').read_bytes():
        fail('recomputed dispatch-tail.json differs from committed copy')
    print('RE-010 cases 76..87 verify: OK dispatch-tail.json', hashlib.sha256(text).hexdigest())


if __name__ == '__main__':
    main()
