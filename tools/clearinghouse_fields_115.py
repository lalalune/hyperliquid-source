#!/usr/bin/env python3
"""Bind the node #115 Clearinghouse and PerpMeta serde field tables (stage 104).

Continues #6207 and the stage 103 PR. The Clearinghouse serializer 0x4482170 writes
19 named fields; each name is loaded by `lea rsi,[rip+...]` with its length in
`mov edx, imm`, and each value comes from rbx (the 0x510-byte Locus cls element)
plus a fixed displacement. Four fields are written through one-field helpers that
load their own name. The field matcher 0x445dd80 returns the same index as the
serialization position (0..18, 0x13 = unknown). The PerpMeta serializer 0x3c40400
writes 5 fields of `meta` (+0x0 of the element).

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import SHA256, read_va

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-fields-115'

CH_SERIALIZER = 0x4482170
CH_MATCHER = 0x445dd80
META_SERIALIZER = 0x3c40400

# name, name-load VA, length, offset-instruction VA, offset-instruction bytes, offset,
# matcher index-store VA, index-store bytes, index
CLEARINGHOUSE = (
    ('meta', 0x44821c1, 4, 0x448220d, '4889df', 0x0, 0x445e0e4, '31c9', 0),
    ('user_states', 0x4482226, 11, 0x4482244, '488d7b60', 0x60, 0x445e018, 'b101', 1),
    ('oracle', 0x448228c, 6, 0x44822aa, '488dbb48010000', 0x148, 0x445dfea, 'b102', 2),
    ('total_net_deposit', 0x44822f5, 17, 0x4482341, '488bb3a8040000', 0x4a8, 0x445e0f8, 'b103', 3),
    ('total_non_bridge_deposit', 0x448235c, 24, 0x4482355, '488d8bb0040000', 0x4b0, 0x445de60, 'b104', 4),
    ('perform_auto_deleveraging', 0x448238a, 25, 0x4482383, '488d8b08050000', 0x508, 0x445ddf2, 'b105', 5),
    ('adl_shortfall_remaining', 0x44823b8, 23, 0x44823b1, '488d8bb8040000', 0x4b8, 0x445dee5, 'b106', 6),
    ('bridge2_withdraw_fee', 0x44823e6, 20, 0x44823df, '488d8bc0040000', 0x4c0, 0x445e0ee, 'b107', 7),
    ('daily_exchange_scaled_and_raw_vlms', 0x44f46e8, 34, 0x4482403, '488db3f8020000', 0x2f8, 0x445df95, 'b108', 8),
    ('halted_assets', 0x448242c, 13, 0x4482425, '488d8bc8040000', 0x4c8, 0x445deae, 'b109', 9),
    ('override_max_signed_distances_from_oracle', 0x448245a, 41, 0x4482453, '488d8b18030000', 0x318,
     0x445dfc7, 'b10a', 10),
    ('max_withdraw_leverage', 0x44f4908, 21, 0x4482477, '488db309050000', 0x509, 0x445de29, 'b10b', 11),
    ('last_set_global_time', 0x44824a0, 20, 0x4482499, '488d8bf0040000', 0x4f0, 0x445e078, 'b10c', 12),
    ('lnsgt', 0x44824ce, 5, 0x44824c7, '488d8bfc040000', 0x4fc, 0x445de80, 'b10d', 13),
    ('usdc_ntl_scale', 0x44f40c8, 14, 0x44824eb, '488db3e0040000', 0x4e0, 0x445df35, 'b10e', 14),
    ('isolated_external', 0x4482514, 17, 0x448250d, '488d8b38030000', 0x338, 0x445e102, 'b10f', 15),
    ('isolated_oracle', 0x448253e, 15, 0x4482537, '488d8b58030000', 0x358, 0x445df63, 'b110', 16),
    ('moh', 0x44f3d14, 3, 0x4482557, '488db378030000', 0x378, 0x445ddbb, 'b111', 17),
    ('znfn', 0x4482578, 4, 0x4482571, '4881c3e8040000', 0x4e8, 0x445df07, 'b112', 18),
)
# helpers called by the serializer that load the name themselves: call site -> helper
HELPER_CALLS = {0x448240d: 0x44f46e0, 0x4482481: 0x44f4900, 0x44824f5: 0x44f40c0, 0x4482561: 0x44f3d00}
UNKNOWN_STORE = (0x445e0da, 'b113')

# name, name-load VA, length, offset-instruction VA, bytes, offset
PERP_META = (
    ('universe', 0x3c40450, 8, 0x3c40461, '4889d9', 0x0),
    ('pdi', 0x3c4047d, 3, 0x3c404cf, '488b7350', 0x50),
    ('marginTableIdToMarginTable', 0x3c404e1, 26, 0x3c404dd, '488d4b30', 0x30),
    ('collateralToken', 0x3c40507, 15, 0x3c40503, '488d4b58', 0x58),
    ('collateralTokenName', 0x3c4052d, 19, 0x3c40529, '4883c318', 0x18),
)
META_CALL = (0x4482213, META_SERIALIZER)


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_lea_target(data, va):
    raw = read_va(data, va, 7)
    if raw[:3] != b'\x48\x8d\x35':
        raise ValueError(f'name load at {va:#x} changed')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def name_at(data, lea_va, length):
    target = rip_lea_target(data, lea_va)
    length_insn = read_va(data, lea_va + 7, 12)
    if bytes([0xba]) + struct.pack('<I', length) not in length_insn:
        raise ValueError(f'name length near {lea_va:#x} changed')
    return target, read_va(data, target, length).decode()


def bind(data, fdes=None):
    clearinghouse = []
    for (name, lea_va, length, off_va, off_bytes, offset, idx_va, idx_bytes, index) in CLEARINGHOUSE:
        target, text = name_at(data, lea_va, length)
        if text != name:
            raise ValueError(f'field name at {target:#x} changed')
        fixed(data, off_va, off_bytes)
        fixed(data, idx_va, idx_bytes)
        clearinghouse.append({'index': index, 'name': name, 'name_va': hex(target), 'offset': hex(offset),
                              'offset_insn': hex(off_va), 'matcher_store': hex(idx_va)})
    for site, helper in HELPER_CALLS.items():
        if call_target(data, site) != helper:
            raise ValueError(f'helper call at {site:#x} changed')
    fixed(data, *UNKNOWN_STORE)
    if call_target(data, META_CALL[0]) != META_CALL[1]:
        raise ValueError('meta serializer call changed')
    perp_meta = []
    for (name, lea_va, length, off_va, off_bytes, offset) in PERP_META:
        target, text = name_at(data, lea_va, length)
        if text != name:
            raise ValueError(f'PerpMeta name at {target:#x} changed')
        fixed(data, off_va, off_bytes)
        perp_meta.append({'name': name, 'name_va': hex(target), 'offset': hex(offset), 'offset_insn': hex(off_va)})
    indices = [row['index'] for row in clearinghouse]
    if indices != list(range(19)):
        raise ValueError('matcher indices no longer follow serialization order')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'clearinghouse': {
            'serializer': hex(CH_SERIALIZER), 'matcher': hex(CH_MATCHER),
            'unknown_index': '0x13 at ' + hex(UNKNOWN_STORE[0]),
            'name_helpers': {hex(k): hex(v) for k, v in HELPER_CALLS.items()},
            'fields': clearinghouse,
        },
        'perp_meta': {'serializer': hex(META_SERIALIZER), 'called_at': hex(META_CALL[0]),
                      'element_offset': '0x0 (Clearinghouse.meta)', 'fields': perp_meta},
        'cross_checks': {
            '+0x8/+0x10 (#6207 list, len)': 'meta.universe Vec (ptr +0x8, len +0x10)',
            '+0x50 (#6207 index check)': 'meta.pdi',
            '+0x58 (stage 103)': 'meta.collateralToken',
            '+0x4a8 (#6213 move_token balance)': 'total_net_deposit',
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    result = bind(data)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('clearinghouse fields=%d perp_meta fields=%d' % (
        len(result['clearinghouse']['fields']), len(result['perp_meta']['fields'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
