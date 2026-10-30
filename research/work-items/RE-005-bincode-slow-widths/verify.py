#!/usr/bin/env python3
"""Recompute RE-005 slow/widths evidence and check it byte-for-byte.

Run from the repo root:
  python3 -I -B research/work-items/RE-005-bincode-slow-widths/verify.py
Explicit checks (no assert), so it is also valid under python -O.
"""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402
import bincode_varint_slow as sv  # noqa: E402

EXPECTED_READER_CALL_COUNTS = {'0x466d850': 2, '0x466d980': 12}
EXPECTED_VECTORS = 22
EXPECTED_READERS = 2
EXPECTED_CMP_FB_SITES = 35
EXPECTED_LEN2_HITS = ['0x134698d']


def fail(msg):
    print(f'RE-005 slow/widths verify: FAIL: {msg}', file=sys.stderr)
    raise SystemExit(1)


def main():
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        want, name = line.split('  ', 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if got != want:
            fail(f'{name} sha256 {got} != manifest {want}')
    try:
        result = sv.scan(bv.TARGET.read_bytes())
    except bv.EvidenceError as e:
        fail(str(e))
    if result['reader_call_counts'] != EXPECTED_READER_CALL_COUNTS:
        fail(f'reader_call_counts = {result["reader_call_counts"]!r}')
    if len(result['readers']) != EXPECTED_READERS:
        fail(f'reader count {len(result["readers"])} != {EXPECTED_READERS}')
    if len(result['decode_vectors']) != EXPECTED_VECTORS:
        fail(f'vector count {len(result["decode_vectors"])} != {EXPECTED_VECTORS}')
    u = result['u16_marker_scan']
    if u['cmp_0xfb_instruction_count'] != EXPECTED_CMP_FB_SITES or len(u['sites']) != EXPECTED_CMP_FB_SITES:
        fail(f'cmp 0xfb site count {u["cmp_0xfb_instruction_count"]} != {EXPECTED_CMP_FB_SITES}')
    if u['length2_adjacent_hits'] != EXPECTED_LEN2_HITS:
        fail(f'length-2-adjacent hits {u["length2_adjacent_hits"]!r} != {EXPECTED_LEN2_HITS!r}')
    if result['negative_control_fast_path_json_sha256'] != sv.FAST_PATH_JSON_SHA256:
        fail('negative-control hash field drifted')
    text = sv.render(result)
    if text != (HERE / 'slow-sites.json').read_bytes():
        fail('recomputed slow-sites.json differs from committed copy')
    print('RE-005 slow/widths verify: OK slow-sites.json', hashlib.sha256(text).hexdigest())


if __name__ == '__main__':
    main()
