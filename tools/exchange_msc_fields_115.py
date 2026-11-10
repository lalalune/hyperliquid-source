#!/usr/bin/env python3
"""Bind the node #115 Exchange field `msc` type and its 12 field names (90th stage).

Continues the Exchange field map (open PR #6095, 'msc' is Exchange index 58 at
box +0x3908..+0x3a00) and the Locus map (open PR #6097). This tool binds:

1. the Exchange seq visitor 0x49da420 decodes element 58 with 0x488f5c0
   (call 0x49df2fa), which calls the struct deserialiser 0x490d9b0; a missing
   element 58 raises invalid_length(0x3a) (0x49df969);
2. 0x490d9b0's expecting record 0x6497dc8 points to
   "struct ExchangeMisc with 12 elements" (0x90f523, 36 bytes);
3. map form: the field identifier comes from slot 0x64e3a28; its index byte
   selects a case through jump table 0x825408 (indices 0..11 are fields,
   12 ignores, 13 ends); each field case tests an "already set" slot and
   jumps to a duplicate-field block that loads the field name and length;
   the names in index order are
   uta mou sgd sog tde tce i mtpt pmc sre vpv aci;
4. field 6 `i` is decoded by 0x47922c0 (call 0x490e0e9) into a (u64, byte)
   pair stored at rsp+0x408 / rsp+0x238; 0x47922c0 writes byte 2 for a
   msgpack nil (0xc0, at 0x47923bf/0x47923c3), otherwise the decoded pair;
5. assembly: msc is built at rsp+0x2e8 and copied out with a 0xf8-byte copy
   (0x490f33a..0x490f34a); `i`'s u64 lands at rsp+0x388 = msc+0xa0 and its
   byte at rsp+0x390 = msc+0xa8, with an unset field (3) mapped to 2.
   With msc at Exchange box +0x3908 (layout A, #6095) these are box
   +0x39a8 / +0x39b0: the simulate-panic stop pair from #6090/#6091.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, fixed, rip_target, relative_relocations, direct_calls

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-exchange-msc-fields-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

EXCHANGE_VISITOR = 0x49da420
ELEMENT_DECODE = 0x488f5c0
MSC_DESER = 0x490d9b0
FIELD_DECODER_I = 0x47922c0
EXPECTING_RECORD = 0x6497dc8
EXPECTING_STR = (0x90f523, b'struct ExchangeMisc with 12 elements')
IDENT_SLOT = 0x64e3a28
JUMP_TABLE = 0x825408
MSC_BOX_A = 0x3908

# (index, case va, jcc va, jcc bytes, name-block va, name va, name length)
FIELDS = (
    (0, 0x490dc51, 0x490dc63, '0f8566250000', 0x49101cf, 0x90f505, 3),
    (1, 0x490dfde, 0x490dff1, '0f85d7220000', 0x49102ce, 0x90f508, 3),
    (2, 0x490decf, 0x490ded8, '0f8545240000', 0x4910323, 0x90f50b, 3),
    (3, 0x490df27, 0x490df30, '0f85ef210000', 0x4910125, 0x90f50e, 3),
    (4, 0x490ddc7, 0x490ddcf, '0f8551220000', 0x4910026, 0x90f511, 3),
    (5, 0x490e08c, 0x490e094, '0f85e11f0000', 0x491007b, 0x90f514, 3),
    (6, 0x490e0d0, 0x490e0d8, '0f859b210000', 0x4910279, 0x90e933, 1),
    (7, 0x490df89, 0x490df8f, '0f84e5210000', 0x491017a, 0x459e64, 4),
    (8, 0x490e1c8, 0x490e1d0, '0f854e200000', 0x4910224, 0x90f517, 3),
    (9, 0x490de33, 0x490de39, '0f8540210000', 0x490ff7f, 0x90f51a, 3),
    (10, 0x490e124, 0x490e133, '0f85971f0000', 0x49100d0, 0x90f51d, 3),
    (11, 0x490dd81, 0x490dd8a, '0f85e5250000', 0x4910375, 0x90f520, 3),
)

FIXED = {
    # Exchange visitor: element 58 decode, Err (3) and missing (2) checks, invalid_length(0x3a)
    0x49df34c: '4883f903',              # cmp rcx, 3
    0x49df371: '83bc245001000002',      # cmp dword [rsp+0x150], 2
    0x49df969: 'be3a000000',            # mov esi, 0x3a
    # field 6 case: unset test, decode, store pair
    0x490e0d0: '80bc243802000003',      # cmp byte [rsp+0x238], 3
    0x490e100: '488b842430010000',      # mov rax, [rsp+0x130]
    0x490e108: '4889842408040000',      # mov [rsp+0x408], rax
    0x490e110: '0fb6842438010000',      # movzx eax, byte [rsp+0x138]
    0x490e118: '88842438020000',        # mov [rsp+0x238], al
    # 0x47922c0: nil -> byte 2; Some -> (u64, byte)
    0x47923bf: '3cc0',                  # cmp al, 0xc0
    0x47923c3: 'c6431002',              # mov byte [rbx+0x10], 2
    0x479240c: '48894308',              # mov [rbx+0x8], rax
    0x4792410: '884b10',                # mov [rbx+0x10], cl
    # assembly: byte (unset 3 -> 2), u64, output copy
    0x490f0b7: '80f903',                # cmp cl, 3
    0x490f0bd: 'ba02000000',            # mov edx, 2
    0x490f0c2: '0f45d1',                # cmovne edx, ecx
    0x490f288: '488bb42408040000',      # mov rsi, [rsp+0x408]
    0x490f290: '4889b42488030000',      # mov [rsp+0x388], rsi   (msc+0xa0)
    0x490f298: '88942490030000',        # mov [rsp+0x390], dl    (msc+0xa8)
    0x490f33a: '488db424e8020000',      # lea rsi, [rsp+0x2e8]   (msc+0x0)
    0x490f342: 'baf8000000',            # mov edx, 0xf8
    0x490f347: '4889df',                # mov rdi, rbx
}
REFERENCES = (
    (0x49df2fa, b'\xe8', 5, ELEMENT_DECODE),
    (0x488f5e3, b'\xe8', 5, MSC_DESER),
    (0x490dc29, b'\xff\x15', 6, IDENT_SLOT),
    (0x490dc41, b'\x48\x8d\x0d', 7, JUMP_TABLE),
    (0x490e0e9, b'\xe8', 5, FIELD_DECODER_I),
    (0x490f34a, b'\xff\x15', 6, 0x64df508),
)


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    if rel.get(EXPECTING_RECORD) != EXPECTING_STR[0]:
        raise ValueError('expecting record changed')
    if struct.unpack('<Q', read_va(data, EXPECTING_RECORD + 8, 8))[0] != len(EXPECTING_STR[1]):
        raise ValueError('expecting length changed')
    if read_va(data, EXPECTING_STR[0], len(EXPECTING_STR[1])) != EXPECTING_STR[1]:
        raise ValueError('expecting string changed')
    if rel.get(IDENT_SLOT) is None:
        raise ValueError('identifier slot not relocated')

    fields = []
    for index, case, jcc, jcc_bytes, block, name_va, length in FIELDS:
        entry = struct.unpack('<i', read_va(data, JUMP_TABLE + 4 * index, 4))[0]
        if JUMP_TABLE + entry != case:
            raise ValueError(f'jump table entry {index} changed')
        fixed(data, jcc, jcc_bytes)
        if jcc + 6 + struct.unpack('<i', bytes.fromhex(jcc_bytes)[2:])[0] != block:
            raise ValueError(f'field {index} duplicate branch changed')
        if rip_target(data, block, b'\x48\x8d\x05', 7) != name_va:
            raise ValueError(f'field {index} name pointer changed')
        fixed(data, block + 12, '48c7442428%02x000000' % length)
        name = read_va(data, name_va, length).decode()
        fields.append({'index': index, 'name': name, 'case': hex(case), 'name_va': hex(name_va)})
    names = [f['name'] for f in fields]
    if names != ['uta', 'mou', 'sgd', 'sog', 'tde', 'tce', 'i', 'mtpt', 'pmc', 'sre', 'vpv', 'aci']:
        raise ValueError('field names changed')
    tail = [struct.unpack('<i', read_va(data, JUMP_TABLE + 4 * k, 4))[0] + JUMP_TABLE for k in (12, 13)]
    calls = direct_calls(data, MSC_DESER)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'element_58': {
            'visitor': hex(EXCHANGE_VISITOR),
            'decode_call': '0x49df2fa -> %s -> %s (call 0x488f5e3)' % (hex(ELEMENT_DECODE), hex(MSC_DESER)),
            'missing': 'tag 2 -> invalid_length(0x3a) at 0x49df969; tag 3 = Err',
        },
        'type': {
            'expecting_record': hex(EXPECTING_RECORD),
            'expecting': EXPECTING_STR[1].decode(),
            'deserialiser_direct_calls': [hex(v) for v in calls],
        },
        'fields': fields,
        'identifier': 'slot %s -> %s; index byte -> jump table %s; 12 -> %s (ignore), 13 -> %s (end)'
                      % (hex(IDENT_SLOT), hex(rel[IDENT_SLOT]), hex(JUMP_TABLE), hex(tail[0]), hex(tail[1])),
        'field_i': {
            'decoder': hex(FIELD_DECODER_I) + ' (nil 0xc0 -> byte 2; else (u64, byte))',
            'temps': {'u64': 'rsp+0x408', 'byte': 'rsp+0x238 (3 = unset)'},
            'output': {'msc+0xa0': 'u64 (0x490f290)', 'msc+0xa8': 'byte, unset 3 -> 2 (0x490f298)'},
            'box_layout_a': {'+0x39a8': 'i u64', '+0x39b0': 'i byte'},
        },
        'output_copy': 'rsp+0x2e8 -> out, 0xf8 bytes (0x490f33a..0x490f34a)',
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
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
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
    print('ExchangeMisc fields=%s' % ' '.join(f['name'] for f in result['fields']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
