#!/usr/bin/env python3
"""Bind the node #115 Locus field names to their abci box offsets (stage 89).

Continues #6093 (Locus seq visitor 0x2fc21d0, record 0x6464530 -> 'struct Locus
with 16 elements') and #6095 (Exchange field k = abci hash slot k; Locus is
slot 0). This tool binds:

1. the 16 Locus field names, stored back to back at 0x794e8a just before the
   record string 0x794eba: ctx cls scl ftr ust chn pdl uaR blp qus ctr uac vlt
   hcm pmu msc;
2. the field-identifier matcher 0x5472fd0: length must be 3; 16 blocks of
   (word xor, byte xor, or, je) give each name its list index 0..15; any other
   input gives 16;
3. the seq visitor 0x2fc21d0: element k is decoded by one call, kept in one
   stack slot, and copied by the final assembly to one box offset. The 16
   offsets tile +0x0..+0xb9b with no gap and equal #6027's slot-0 address order.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, relative_relocations

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-locus-msc-fields-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

NAMES = ('ctx', 'cls', 'scl', 'ftr', 'ust', 'chn', 'pdl', 'uaR',
         'blp', 'qus', 'ctr', 'uac', 'vlt', 'hcm', 'pmu', 'msc')
NAME_TABLE = 0x794e8a
RECORD_STR = (0x794eba, b'struct Locus with 16 elements')
RECORD = 0x6464530
MATCHER = 0x5472fd0
BLOCK0, BLOCK_LEN = 0x5472fdf, 0x19
VISITOR = (0x2fc21d0, 0x2fc35b6)
DEFAULT_F64 = (0x459098, 0.4)

# (field, decode call, stack store, final store, box offset, size)
ELEMENTS = (
    ('ctx', 0x2fc225c, 0x2fc2261, 0x2fc31f4, 0x0, 0x80),
    ('cls', 0x2fc23c8, 0x2fc240a, 0x2fc3040, 0x7c0, 0x18),
    ('scl', 0x2fc244f, 0x2fc25b8, 0x2fc3047, 0x80, 0x5f0),
    ('ftr', 0x2fc2600, 0x2fc26fa, 0x2fc3065, 0x7d8, 0x190),
    ('ust', 0x2fc273e, 0x2fc2833, 0x2fc309c, 0x968, 0x48),
    ('chn', 0x2fc2878, 0x2fc288d, 0x2fc32ad, 0xb9a, 0x1),
    ('pdl', 0x2fc28a4, 0x2fc28b9, 0x2fc3297, 0xb98, 0x1),
    ('uaR', 0x2fc28db, 0x2fc2a90, 0x2fc30d7, 0x9f8, 0x20),
    ('blp', 0x2fc2aa3, 0x2fc2b65, 0x2fc30e5, 0x670, 0x150),
    ('qus', 0x2fc2b78, 0x2fc2ba1, 0x2fc310d, 0xb78, 0x18),
    ('ctr', 0x2fc2bfc, 0x2fc2c09, 0x2fc3272, 0xa78, 0x100),
    ('uac', 0x2fc2c82, 0x2fc2d45, 0x2fc3158, 0x9b0, 0x48),
    ('vlt', 0x2fc2d58, 0x2fc2de6, 0x2fc3176, 0xa18, 0x20),
    ('hcm', 0x2fc2df9, 0x2fc2e0e, 0x2fc32a2, 0xb99, 0x1),
    ('pmu', 0x2fc2e30, 0x2fc2e5b, 0x2fc328b, 0xb90, 0x8),
    ('msc', 0x2fc2e6e, 0x2fc2e73, 0x2fc31f7, 0xa38, 0x40),
)
# #6027 slot-0 group: base then 15 field addresses, in builder order
SLOT0 = (0x0, 0x7c0, 0x80, 0x7d8, 0x968, 0xb9a, 0xb98, 0x9f8, 0x670, 0xb78,
         0xa78, 0x9b0, 0xa18, 0xb99, 0xb90, 0xa38)

FIXED = {
    0x2fc225c: 'e8ffb72501',
    0x2fc2261: '4c8bac24300300',
    0x2fc23c8: 'e8a3904a01',
    0x2fc240a: '4c89642468',
    0x2fc244f: 'e8ecaec300',
    0x2fc25b8: '4c89bc24000d00',
    0x2fc2600: 'e84bacc500',
    0x2fc26fa: '4c89bc24700a00',
    0x2fc273e: 'e8ad107501',
    0x2fc2833: '4c89bc24080100',
    0x2fc2878: 'e8c3cf6b01',
    0x2fc288d: '884c2407',
    0x2fc28a4: 'e8b788ba00',
    0x2fc28b9: '884c2406',
    0x2fc28db: 'e8508eba00',
    0x2fc2a90: '48898424c80000',
    0x2fc2aa3: 'e878eeba00',
    0x2fc2b65: '48898424200900',
    0x2fc2b78: 'e82395ba00',
    0x2fc2ba1: '4889542460',
    0x2fc2bfc: 'e84f95ba00',
    0x2fc2c09: '4889442448',
    0x2fc2c82: 'e869a1ba00',
    0x2fc2d45: '48898424e80100',
    0x2fc2d58: 'e893e1ba00',
    0x2fc2de6: '48898424e80000',
    0x2fc2df9: 'e87281ba00',
    0x2fc2e0e: '884c2405',
    0x2fc2e30: 'e8ebc3ba00',
    0x2fc2e5b: '48898424b80000',
    0x2fc2e6e: 'e85de9ba00',
    0x2fc2e73: '4c8bb424300300',
    0x2fc2fcc: '4c3bb424c00000',
    0x2fc2feb: 'f20f1005a56049',
    0x2fc303b: '0f10442468',
    0x2fc3040: '0f1183c0070000',
    0x2fc3047: '488dbb80000000',
    0x2fc304e: '488db424000d00',
    0x2fc305d: 'baf0050000',
    0x2fc3065: '488dbbd8070000',
    0x2fc306c: '488db424700a00',
    0x2fc3074: 'ba90010000',
    0x2fc307c: '0f108424080100',
    0x2fc309c: '0f118368090000',
    0x2fc30c7: '0f108424c80000',
    0x2fc30d7: '0f1183f8090000',
    0x2fc30e5: '488dbb70060000',
    0x2fc30ec: '488db424200900',
    0x2fc30f4: 'ba50010000',
    0x2fc30fc: '488b442460',
    0x2fc310d: '0f1183780b0000',
    0x2fc3123: '0f108424e80100',
    0x2fc3158: '0f1183b0090000',
    0x2fc315f: '0f108424e80000',
    0x2fc3176: '0f1183180a0000',
    0x2fc31f4: '4c892b',
    0x2fc31f7: '4c89b3380a0000',
    0x2fc326d: '488b442448',
    0x2fc3272: '488983780a0000',
    0x2fc3283: '488b8424b80000',
    0x2fc328b: '488983900b0000',
    0x2fc3292: '0fb6442406',
    0x2fc3297: '8883980b0000',
    0x2fc329d: '0fb6442405',
    0x2fc32a2: '8883990b0000',
    0x2fc32a8: '0fb6442407',
    0x2fc32ad: '88839a0b0000',
}


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def matcher_indices(data):
    """Decode the 16 compare blocks; return {name: index}."""
    out = {}
    head = read_va(data, MATCHER, 15)
    if head != bytes.fromhex('4889f8b1104883fa030f859a010000'):
        raise ValueError('matcher prologue changed')
    for k in range(16):
        va = BLOCK0 + BLOCK_LEN * k
        b = read_va(data, va, BLOCK_LEN)
        if b[:5] != bytes.fromhex('0fb70e81f1') or b[7:9] != b'\x00\x00' or b[9:15] != bytes.fromhex('0fb6560283f2'):
            raise ValueError(f'matcher block {k} changed')
        name = struct.pack('<H', struct.unpack_from('<H', b, 5)[0]) + bytes([b[15]])
        if k < 15:
            if b[16:19] != bytes.fromhex('6609ca') or b[19:21] != b'\x0f\x84':
                raise ValueError(f'matcher block {k} branch changed')
            target = va + 25 + struct.unpack_from('<i', b, 21)[0]
            arm = read_va(data, target, 2)
            idx = 0 if arm == b'\x31\xc9' else (arm[1] if arm[0] == 0xb1 else None)
            if idx is None:
                raise ValueError(f'matcher arm {k} changed')
        else:
            tail = read_va(data, va + 16, 17)
            if tail != bytes.fromhex('6609ca0f94c2b11028d1884801c60009c3'):
                raise ValueError('matcher last block changed')
            idx = 15
        out[name.decode()] = idx
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    if read_va(data, NAME_TABLE, 48) != ''.join(NAMES).encode():
        raise ValueError('Locus name table changed')
    if read_va(data, *[RECORD_STR[0], len(RECORD_STR[1])]) != RECORD_STR[1]:
        raise ValueError('record string changed')
    rel = relative_relocations(data)
    if rel.get(RECORD) != RECORD_STR[0]:
        raise ValueError('record relocation changed')
    if struct.unpack('<d', read_va(data, DEFAULT_F64[0], 8))[0] != DEFAULT_F64[1]:
        raise ValueError('msc default f64 changed')
    idx = matcher_indices(data)
    if idx != {n: i for i, n in enumerate(NAMES)}:
        raise ValueError('matcher index order changed')
    for name, call, store, final, off, size in ELEMENTS:
        if not (VISITOR[0] <= call < store < VISITOR[1] and VISITOR[0] <= final < VISITOR[1]):
            raise ValueError(f'{name} sites outside the visitor')
    if [e[4] for e in ELEMENTS] != list(SLOT0):
        raise ValueError('field order differs from slot-0 order')
    spans = sorted((e[4], e[4] + e[5]) for e in ELEMENTS)
    for (a, b), (c, _) in zip(spans, spans[1:]):
        if b != c:
            raise ValueError('Locus layout has a gap or overlap')
    calls = []
    for name, call, *_ in ELEMENTS:
        raw = read_va(data, call, 5)
        calls.append(hex(call + 5 + struct.unpack_from('<i', raw, 1)[0]))
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'names': {'table': hex(NAME_TABLE), 'record': hex(RECORD), 'record_string': hex(RECORD_STR[0])},
        'matcher': {'fn': hex(MATCHER), 'length': 3, 'unknown_index': 16,
                    'indices': {n: i for n, i in idx.items()}},
        'fields': [{'index': i, 'name': e[0], 'decoder': calls[i], 'decode_call': hex(e[1]),
                    'stack_store': hex(e[2]), 'box_store': hex(e[3]),
                    'box_offset': hex(e[4]), 'size': hex(e[5])} for i, e in enumerate(ELEMENTS)],
        'layout': {'start': '0x0', 'end': hex(spans[-1][1]), 'contiguous': True},
        'slot0_order_equal': True,
        'labels_inferred': {'ctx': 'context: height +0x28, round +0x30, consensus time +0x60 (#6090, #5970 assertion text self.locus.context.height())',
                            'chn': 'selector byte +0xb9a tested against 2/3 by the simulate-panic check (#6091)'},
        'msc_default': {'branch': hex(0x2fc2fcc), 'f64': hex(DEFAULT_F64[0]), 'value': DEFAULT_F64[1]},
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
    print('locus fields=%d end=%s' % (len(result['fields']), result['layout']['end']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
