#!/usr/bin/env python3
"""Regenerate RE-009-C with the tool and compare to the committed packet."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import lthash_mechanism as tool  # noqa: E402

PACKET_JSON = HERE / 'lthash-mechanism.json'
JSON_SHA256 = 'fd44957c759ec48f8499ac966e89cfab7c92a5405ab3087a1476df3897b9339e'
EXPECT = {'leaves': 3, 'lattice_loops': 6, 'count_blocks': 3}
EXPECT_REFS = {'closure_functions_per_leaf': [11, 11, 11], 'closure_edges_per_leaf': [16, 16, 16],
               'writer_callers': 3, 'top_function_callers': 2}

EXPECT_SLOTS = [
    {'slot': '0x57700b0', 'target': '0x14f7e40', 'role': 'blake3 XOF fill slot 0x57700b0 (target 0x14f7e40; ROOT flag 8, 64-byte output blocks)'},
    {'slot': '0x57700c0', 'target': '0x14fa220', 'role': 'blake3 platform-detect slot 0x57700c0 (target 0x14fa220; constructor inlined)'},
    {'slot': '0x57700c8', 'target': '0x14f93e0', 'role': 'blake3 update slot 0x57700c8 (target 0x14f93e0; 0x400-byte chunk buffer)'},
]
EXPECT_SLOT_KEYS = {'platform_detect': '0x57700c0', 'update': '0x57700c8', 'xof_fill': '0x57700b0'}


def slot_errors(result):
    """Exact check of the GOT slot labels; any other label (e.g. 'blake3 new') fails."""
    errors = []
    if result.get('blake3_slots') != EXPECT_SLOTS:
        errors.append(f"blake3 slot table {result.get('blake3_slots')} != pinned")
    for L in result['leaves']:
        if L['blake3_slots'] != EXPECT_SLOT_KEYS:
            errors.append(f"{L['leaf']}: blake3 slot keys {L['blake3_slots']} != pinned")
    return errors


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = []
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errors.append('regenerated output sha256 mismatch')
    if PACKET_JSON.read_text() != text:
        errors.append('committed json differs from regenerated output')
    if result['counts'] != EXPECT:
        errors.append(f"counts {result['counts']} != {EXPECT}")
    rc = result['reference_closure']
    if rc['counts'] != EXPECT_REFS:
        errors.append(f"reference counts {rc['counts']} != {EXPECT_REFS}")
    for x in rc['leaves']:
        if [e[2] for e in x['entry_from_top']] != ['0x3269ae0']:
            errors.append(f"{x['leaf']}: entry from outside the closure is not exactly one call from 0x3269ae0")
    for L in result['leaves']:
        for key in ('lattice_entry_add', 'lattice_merge_add'):
            r = L[key]
            if (r['u16_words_total'], r['bytes_covered'], r['byte_order'], r['overflow']) != \
                    (1024, 0x800, 'big-endian', 'wrapping-mod-2^16'):
                errors.append(f"{L['leaf']} {key}: mechanism fields")
        if L['count_add']['overflow'] != 'saturating-u64' or L['xof_len'] != '0x800':
            errors.append(f"{L['leaf']}: count/xof fields")
    errors += slot_errors(result)
    for e in errors:
        print('FAIL', e)
    print(f'verify: leaves=3 loops=6 count_blocks=3 closure_functions=11/11/11 closure_edges=16/16/16 '
          f'writer_callers=3 top_callers=2 errors={len(errors)}')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
