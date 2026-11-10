#!/usr/bin/env python3
"""Bind the node #115 Clearinghouse/PerpMeta field behind cls element +0x58 (stage 103).

Stage 102 (#6216) found that the 14 paired move_token call sites test the
word at Locus cls element +0x58 (elements of 0x510 bytes at box +0x7c8).
This tool binds that word to a named field:

1. the Clearinghouse field-identifier matcher 0x445dd80 (jump table 0x7ce8b0
   on name length - 3) returns index 9 for halted_assets, 13 for lnsgt,
   14 for usdc_ntl_scale and 17 for moh;
2. the Clearinghouse JSON serializer 0x4482170 writes meta from +0x0,
   user_states from +0x60, oracle from +0x148 and total_net_deposit from
   +0x4a8 (the balance stage 100 debits and credits);
3. the PerpMeta serializer 0x3c40400 writes universe from +0x0, pdi from
   +0x50, marginTableIdToMarginTable from +0x30, collateralToken from +0x58
   and collateralTokenName from +0x18;
4. the PerpMeta seq visitor 0x2f88180 stores pdi at +0x50 and element 3 at
   +0x58 (invalid_length(3) at 0x2f88574); the map visitor 0x30e94a0 stores
   +0x58 at 0x30eaddb.

So cls element +0x58 is meta.collateralToken. The captured binary is not
executed; objdump and readelf are not started.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import read_va, fixed, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-field-58-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

MATCHER = 0x445dd80
MATCHER_TABLE = 0x7ce8b0
CH_SER = 0x4482170
PM_SER = 0x3c40400
PM_SEQ = 0x2f88180
PM_MAP = 0x30e94a0

FIXED = {
    # matcher arms: mov cl, index
    0x445ddbb: 'b111',              # moh -> 17
    0x445de80: 'b10d',              # lnsgt -> 13
    0x445deae: 'b109',              # halted_assets -> 9
    0x445df35: 'b10e',              # usdc_ntl_scale -> 14
    0x445dd84: '4883c2fd',          # add rdx, -3
    0x445dd88: '4883fa26',          # cmp rdx, 0x26
    # Clearinghouse serializer field operands
    0x44821cb: 'ba04000000',        # len("meta")
    0x4482244: '488d7b60',          # lea rdi, [rbx+0x60]   user_states
    0x44822aa: '488dbb48010000',    # lea rdi, [rbx+0x148]  oracle
    0x4482341: '488bb3a8040000',    # mov rsi, [rbx+0x4a8]  total_net_deposit
    # PerpMeta serializer field operands
    0x3c40461: '4889d9',            # mov rcx, rbx          universe (+0x0)
    0x3c404cf: '488b7350',          # mov rsi, [rbx+0x50]   pdi
    0x3c404dd: '488d4b30',          # lea rcx, [rbx+0x30]   marginTableIdToMarginTable
    0x3c40503: '488d4b58',          # lea rcx, [rbx+0x58]   collateralToken
    0x3c40513: 'ba0f000000',        # len("collateralToken")
    0x3c40529: '4883c318',          # add rbx, 0x18         collateralTokenName
    0x3c40539: 'ba13000000',        # len("collateralTokenName")
    # PerpMeta seq visitor output
    0x2f88429: '4c8b642410',        # mov r12, [rsp+0x10]
    0x2f884a7: '49894650',          # mov [r14+0x50], rax   pdi
    0x2f884ab: '4d896658',          # mov [r14+0x58], r12   collateralToken
    0x2f88574: 'be03000000',        # invalid_length(3)
    # PerpMeta map visitor output
    0x30eaddb: '48894358',          # mov [rbx+0x58], rax
}
REFERENCES = (
    (0x44821c1, b'\x48\x8d\x35', 7, 0x459ef4, b'meta'),
    (0x4482226, b'\x48\x8d\x35', 7, 0x7d07c9, b'user_states'),
    (0x448228c, b'\x48\x8d\x35', 7, 0x7d19dd, b'oracle'),
    (0x44822f5, b'\x48\x8d\x35', 7, 0x7d19e3, b'total_net_deposit'),
    (0x3c40450, b'\x48\x8d\x35', 7, 0x459be0, b'universe'),
    (0x3c4047d, b'\x48\x8d\x35', 7, 0x7bbef0, b'pdi'),
    (0x3c404e1, b'\x48\x8d\x35', 7, 0x7bbef3, b'marginTableIdToMarginTable'),
    (0x3c40507, b'\x48\x8d\x35', 7, 0x7bbf0d, b'collateralToken'),
    (0x3c4052d, b'\x48\x8d\x35', 7, 0x7bbf1c, b'collateralTokenName'),
    (0x445dd92, b'\x48\x8d\x0d', 7, MATCHER_TABLE, None),
)
MATCHER_NAMES = {          # arm compare immediate -> (name, index)
    0x445ddbb: ('moh', 17),
    0x445de80: ('lnsgt', 13),
    0x445deae: ('halted_assets', 9),
    0x445df35: ('usdc_ntl_scale', 14),
}

def bind(data):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    refs = {}
    for va, prefix, length, target, text in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
        if text is not None:
            if read_va(data, target, len(text)) != text:
                raise ValueError(f'string at {target:#x} changed')
            refs[text.decode()] = hex(va)
    fixed(data, 0x445dda5, '81f16d6f0000')
    fixed(data, 0x445de6a, 'b96c6e7367')
    fixed(data, 0x445de8a, '48b968616c7465645f61')
    if read_va(data, 0x445df11, 10) != bytes.fromhex('48b975736463') + b'_ntl':
        raise ValueError('usdc_ntl_scale immediate changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'clearinghouse_matcher': {
            'fn': hex(MATCHER), 'table': hex(MATCHER_TABLE),
            'indices': {n: i for n, i in MATCHER_NAMES.values()},
        },
        'clearinghouse_layout': {
            'serializer': hex(CH_SER),
            'meta': '+0x0', 'user_states': '+0x60', 'oracle': '+0x148',
            'total_net_deposit': '+0x4a8',
        },
        'perp_meta_layout': {
            'serializer': hex(PM_SER),
            'universe': '+0x0', 'collateralTokenName': '+0x18',
            'marginTableIdToMarginTable': '+0x30', 'pdi': '+0x50',
            'collateralToken': '+0x58',
        },
        'perp_meta_visitors': {
            'seq': hex(PM_SEQ) + ': element 3 -> +0x58 at 0x2f884ab, pdi -> +0x50 at 0x2f884a7',
            'map': hex(PM_MAP) + ': store +0x58 at 0x30eaddb',
        },
        'field_58': 'Clearinghouse.meta.collateralToken',
        'name_refs': refs,
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
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
    print('field_58 =', result['field_58'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
