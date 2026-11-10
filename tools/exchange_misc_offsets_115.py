#!/usr/bin/env python3
"""Bind the node #115 ExchangeMisc field offsets and the field `i` stop byte (stage 91).

Stage 90 (open PR #6098) typed Exchange field `msc` (index 58) as
`struct ExchangeMisc with 12 elements`, decoded by 0x490d9b0, and placed field
`i` at msc+0xa0 (u64) / msc+0xa8 (byte). This tool binds:

1. the map-form field switch: jump table 0x825408 maps field index 0..11 to a
   case, and each case calls one decoder and stores into fixed stack slots;
2. the 0xf8-byte output: the visitor assembles the struct at rsp+0x2e8 and
   copies 0xf8 bytes to the output (0x490f342), so each stack store at
   rsp+0x2e8+k is struct offset k; the field -> offset table below follows
   each field's slot into that buffer, with the visitor's defaults;
3. field `i`'s byte: the decoder 0x47922c0 writes 2 for msgpack nil (0xc0),
   otherwise the byte returned by its inner decode; the six simulate-panic
   sites from #6091 read box +0x39b0 (layout B +0x4520) as follows: three
   (begin A/B, 0x2bdf270) arm on `byte & 1 != 0`, three (quorum-entry builders
   A/B, 0x2c71eb0) arm on `byte == 0`; byte 2 satisfies neither test.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, fixed, frame

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-exchange-misc-offsets-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VISITOR = 0x490d9b0
I_DECODER = 0x47922c0
JUMP_TABLE = 0x825408
NAMES = (0x90f505, b'utamousgdsogtdetcepmcsrevpvaci')
STRUCT_NAME = (0x90f523, b'struct ExchangeMisc with 12 elements')
BUCKET_GUARD = (0x93a3c8, b'BucketGuard')

# index: (name, case address, decoder, struct offset, size, type hint, default when absent)
FIELDS = {
    0: ('uta', 0x490dc51, 0x4acc0f0, 0x60, 0x20, 'Option-like, None 0x8000000000000001', 'None'),
    1: ('mou', 0x490dfde, 0x49a7790, 0x10, 0x50, 'Option-like 0x50-byte value, None 0x8000000000000000', 'None'),
    2: ('sgd', 0x490decf, 0x4d440e0, 0x00, 0x10, 'Option<f64> (tag, f64)', 'tag 0'),
    3: ('sog', 0x490df27, 0x47b2fe0, 0xb0, 0x10, 'BucketGuard (two words)', 'first word 3000'),
    4: ('tde', 0x490ddc7, 0x586a170, 0xf4, 0x01, 'bool', 'false'),
    5: ('tce', 0x490e08c, 0x586a170, 0xf5, 0x01, 'bool', 'true'),
    6: ('i', 0x490e0d0, 0x47922c0, 0xa0, 0x09, '(u64 height, byte) Option-like, None byte 2', 'byte 2'),
    7: ('mtpt', 0x490df89, None, 0xc8, 0x08, 'u64 (slot 0x64dfeb0)', '1000'),
    8: ('pmc', 0x490e1c8, 0x4e36ad0, 0xe8, 0x0c, 'dword + qword', 'dword 0xf6401a, qword 0'),
    9: ('sre', 0x490de33, 0x4af3450, 0xd0, 0x18, 'three words', 'zeros'),
    10: ('vpv', 0x490e124, 0x4b250d0, 0x80, 0x20, 'four words (Vec-like)', '{0, 4, 0, 0}'),
    11: ('aci', 0x490dd81, 0x4ff2810, 0xc0, 0x08, 'u64', '1000 when 0'),
}
UNKNOWN_CASE = 0x490de0b

FIXED = {
    0x490dc41: '488d0dc077f1fb',  # lea    rcx,[rip+0xfffffffffbf177c0] (825408)
    0x490dc79: 'e872e41b00',  # call   4acc0f0
    0x490dcb4: '48898424a8020000',  # mov    QWORD PTR [rsp+0x2a8],rax
    0x490dcbc: '4889ac24b0020000',  # mov    QWORD PTR [rsp+0x2b0],rbp
    0x490dcc4: '4c89a424b8020000',  # mov    QWORD PTR [rsp+0x2b8],r12
    0x490dccc: '4c89bc24c0020000',  # mov    QWORD PTR [rsp+0x2c0],r15
    0x490e004: 'e887970900',  # call   49a7790
    0x490e063: '48896c2460',  # mov    QWORD PTR [rsp+0x60],rbp
    0x490e068: '4889442468',  # mov    QWORD PTR [rsp+0x68],rax
    0x490e06d: '4889942400040000',  # mov    QWORD PTR [rsp+0x400],rdx
    0x490e07a: '4c89642478',  # mov    QWORD PTR [rsp+0x78],r12
    0x490e07f: '4c89bc2480000000',  # mov    QWORD PTR [rsp+0x80],r15
    0x490e049: '488dbc2488000000',  # lea    rdi,[rsp+0x88]
    0x490dee9: 'e8f2614300',  # call   4d440e0
    0x490df08: '4889842460020000',  # mov    QWORD PTR [rsp+0x260],rax
    0x490df19: 'f20f118424f8030000',  # movsd  QWORD PTR [rsp+0x3f8],xmm0
    0x490df4d: 'e88e50eaff',  # call   47b2fe0
    0x490df6c: '4889842420010000',  # mov    QWORD PTR [rsp+0x120],rax
    0x490df7c: '4889842478020000',  # mov    QWORD PTR [rsp+0x278],rax
    0x490dde0: 'e88bc3f500',  # call   586a170
    0x490ddf5: '888c24b8000000',  # mov    BYTE PTR [rsp+0xb8],cl
    0x490e0a5: 'e8c6c0f500',  # call   586a170
    0x490e0ba: '888c2418010000',  # mov    BYTE PTR [rsp+0x118],cl
    0x490e0e9: 'e8d241e8ff',  # call   47922c0
    0x490e108: '4889842408040000',  # mov    QWORD PTR [rsp+0x408],rax
    0x490e118: '88842438020000',  # mov    BYTE PTR [rsp+0x238],al
    0x490e662: 'ff154818bd01',  # call   QWORD PTR [rip+0x1bd1848] (64dfeb0)
    0x490e682: '4889ac2480020000',  # mov    QWORD PTR [rsp+0x280],rbp
    0x490e6a7: '41bfe8030000',  # mov    r15d,0x3e8
    0x490e6ad: '4c0f45bc2480020000',  # cmovne r15,QWORD PTR [rsp+0x280]
    0x490e1e1: 'e8ea885200',  # call   4e36ad0
    0x490e1ff: '89842430020000',  # mov    DWORD PTR [rsp+0x230],eax
    0x490e20e: '48898424b0000000',  # mov    QWORD PTR [rsp+0xb0],rax
    0x490de55: 'e8f6551e00',  # call   4af3450
    0x490de90: '4889842458020000',  # mov    QWORD PTR [rsp+0x258],rax
    0x490dea0: '4889942470020000',  # mov    QWORD PTR [rsp+0x270],rdx
    0x490deb0: '48898c2420020000',  # mov    QWORD PTR [rsp+0x220],rcx
    0x490e149: 'e8826f2100',  # call   4b250d0
    0x490e189: '4889ac24f0030000',  # mov    QWORD PTR [rsp+0x3f0],rbp
    0x490e199: '4c89a424e0030000',  # mov    QWORD PTR [rsp+0x3e0],r12
    0x490e1a9: '4c89bc24e8030000',  # mov    QWORD PTR [rsp+0x3e8],r15
    0x490e1b9: '4889442448',  # mov    QWORD PTR [rsp+0x48],rax
    0x490dd9b: 'e8704a6e00',  # call   4ff2810
    0x490ddba: '4889842410010000',  # mov    QWORD PTR [rsp+0x110],rax
    0x490f07d: 'b8b80b0000',  # mov    eax,0xbb8
    0x490f082: '4889842420010000',  # mov    QWORD PTR [rsp+0x120],rax
    0x490f08d: '80a424b800000001',  # and    BYTE PTR [rsp+0xb8],0x1
    0x490f0a7: 'b801000000',  # mov    eax,0x1
    0x490f0bd: 'ba02000000',  # mov    edx,0x2
    0x490f0c2: '0f45d1',  # cmovne edx,ecx
    0x490f0d0: 'b91a40f600',  # mov    ecx,0xf6401a
    0x490f15a: '41bae8030000',  # mov    r10d,0x3e8
    0x490f194: '4c89a424e8020000',  # mov    QWORD PTR [rsp+0x2e8],r12
    0x490f1a5: 'f20f118424f0020000',  # movsd  QWORD PTR [rsp+0x2f0],xmm0
    0x490f1b3: '0f118424f8020000',  # movups XMMWORD PTR [rsp+0x2f8],xmm0
    0x490f1c3: '4c899c2408030000',  # mov    QWORD PTR [rsp+0x308],r11
    0x490f1d3: '4c899c2460030000',  # mov    QWORD PTR [rsp+0x360],r11
    0x490f1e3: '4c899c2440030000',  # mov    QWORD PTR [rsp+0x340],r11
    0x490f1f3: '4c899c2448030000',  # mov    QWORD PTR [rsp+0x348],r11
    0x490f230: '0f11842450030000',  # movups XMMWORD PTR [rsp+0x350],xmm0
    0x490f250: '0f11942430030000',  # movups XMMWORD PTR [rsp+0x330],xmm2
    0x490f258: '0f118c2420030000',  # movups XMMWORD PTR [rsp+0x320],xmm1
    0x490f260: '0f11842410030000',  # movups XMMWORD PTR [rsp+0x310],xmm0
    0x490f268: '4889b42468030000',  # mov    QWORD PTR [rsp+0x368],rsi
    0x490f270: '4889bc2470030000',  # mov    QWORD PTR [rsp+0x370],rdi
    0x490f278: '4c89842478030000',  # mov    QWORD PTR [rsp+0x378],r8
    0x490f280: '4c898c2480030000',  # mov    QWORD PTR [rsp+0x380],r9
    0x490f290: '4889b42488030000',  # mov    QWORD PTR [rsp+0x388],rsi
    0x490f298: '88942490030000',  # mov    BYTE PTR [rsp+0x390],dl
    0x490f2a7: '4889942498030000',  # mov    QWORD PTR [rsp+0x398],rdx
    0x490f2af: '4889ac24a0030000',  # mov    QWORD PTR [rsp+0x3a0],rbp
    0x490f2b7: '4c899424a8030000',  # mov    QWORD PTR [rsp+0x3a8],r10
    0x490f2bf: '4c89bc24b0030000',  # mov    QWORD PTR [rsp+0x3b0],r15
    0x490f2cf: '48899424b8030000',  # mov    QWORD PTR [rsp+0x3b8],rdx
    0x490f2df: '48899424c0030000',  # mov    QWORD PTR [rsp+0x3c0],rdx
    0x490f2ef: '48899424c8030000',  # mov    QWORD PTR [rsp+0x3c8],rdx
    0x490f2f7: '898c24d0030000',  # mov    DWORD PTR [rsp+0x3d0],ecx
    0x490f306: '48898c24d4030000',  # mov    QWORD PTR [rsp+0x3d4],rcx
    0x490f316: '888c24dc030000',  # mov    BYTE PTR [rsp+0x3dc],cl
    0x490f31d: '888424dd030000',  # mov    BYTE PTR [rsp+0x3dd],al
    0x490f33a: '488db424e8020000',  # lea    rsi,[rsp+0x2e8]
    0x490f342: 'baf8000000',  # mov    edx,0xf8
    0x47923bf: '3cc0',  # cmp    al,0xc0
    0x47923c3: 'c6431002',  # mov    BYTE PTR [rbx+0x10],0x2
    0x5483903: '41f685b039000001',  # test   BYTE PTR [r13+0x39b0],0x1
    0x548390d: '493b95a8390000',  # cmp    rdx,QWORD PTR [r13+0x39a8]
    0x5483916: '4180bd9a0b000003',  # cmp    BYTE PTR [r13+0xb9a],0x3
    0x5484003: '41f6852045000001',  # test   BYTE PTR [r13+0x4520],0x1
    0x548400d: '493b9518450000',  # cmp    rdx,QWORD PTR [r13+0x4518]
    0x5484016: '4180bd0a17000003',  # cmp    BYTE PTR [r13+0x170a],0x3
    0x2bdf30d: 'f683b039000001',  # test   BYTE PTR [rbx+0x39b0],0x1
    0x2bdf317: '483bbba8390000',  # cmp    rdi,QWORD PTR [rbx+0x39a8]
    0x2bdf325: '80bb9a0b000003',  # cmp    BYTE PTR [rbx+0xb9a],0x3
    0x5488ed4: '80bd2045000000',  # cmp    BYTE PTR [rbp+0x4520],0x0
    0x5488ee3: '488b8d18450000',  # mov    rcx,QWORD PTR [rbp+0x4518]
    0x5488ef3: '80bd0a17000003',  # cmp    BYTE PTR [rbp+0x170a],0x3
    0x548bfc9: '4180bc24b039000000',  # cmp    BYTE PTR [r12+0x39b0],0x0
    0x548bfdb: '498b8c24a8390000',  # mov    rcx,QWORD PTR [r12+0x39a8]
    0x548bfed: '4180bc249a0b000003',  # cmp    BYTE PTR [r12+0xb9a],0x3
    0x2c7444e: '4180beb039000000',  # cmp    BYTE PTR [r14+0x39b0],0x0
    0x2c7445c: '4180be9a0b000003',  # cmp    BYTE PTR [r14+0xb9a],0x3
    0x2c74469: '493b96a8390000',  # cmp    rdx,QWORD PTR [r14+0x39a8]
}

# decoder call site per case (direct rel32 call, except mtpt which calls slot 0x64dfeb0)
CASE_CALLS = {0: 0x490dc79, 1: 0x490e004, 2: 0x490dee9, 3: 0x490df4d, 4: 0x490dde0, 5: 0x490e0a5,
              6: 0x490e0e9, 8: 0x490e1e1, 9: 0x490de55, 10: 0x490e149, 11: 0x490dd9b}
MTPT_SLOT_CALL = (0x490e662, 0x64dfeb0)
OUTPUT_BASE = 0x2e8
OUTPUT_COPY = (0x490f33a, 0x490f342)
# stack stores into the output buffer: va -> (stack offset, width)
OUTPUT_STORES = {
    0x490f194: (0x2e8, 8), 0x490f1a5: (0x2f0, 8), 0x490f1b3: (0x2f8, 16), 0x490f1c3: (0x308, 8),
    0x490f260: (0x310, 16), 0x490f258: (0x320, 16), 0x490f250: (0x330, 16), 0x490f1e3: (0x340, 8),
    0x490f1f3: (0x348, 8), 0x490f230: (0x350, 16), 0x490f1d3: (0x360, 8), 0x490f268: (0x368, 8),
    0x490f270: (0x370, 8), 0x490f278: (0x378, 8), 0x490f280: (0x380, 8), 0x490f290: (0x388, 8),
    0x490f298: (0x390, 1), 0x490f2a7: (0x398, 8), 0x490f2af: (0x3a0, 8), 0x490f2b7: (0x3a8, 8),
    0x490f2bf: (0x3b0, 8), 0x490f2cf: (0x3b8, 8), 0x490f2df: (0x3c0, 8), 0x490f2ef: (0x3c8, 8),
    0x490f2f7: (0x3d0, 4), 0x490f306: (0x3d4, 8), 0x490f316: (0x3dc, 1), 0x490f31d: (0x3dd, 1),
}
# simulate-panic sites: function, stop-byte instruction, arm rule
PANIC_SITES = (
    (0x5483850, 0x5483903, 'byte & 1 != 0', 'begin A'),
    (0x5483f50, 0x5484003, 'byte & 1 != 0', 'begin B'),
    (0x2bdf270, 0x2bdf30d, 'byte & 1 != 0', 'catch-up step'),
    (0x5486720, 0x5488ed4, 'byte == 0', 'quorum-entry builder B'),
    (0x54897e0, 0x548bfc9, 'byte == 0', 'quorum-entry builder A'),
    (0x2c71eb0, 0x2c7444e, 'byte == 0', '0x2c71eb0'),
)


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def slot_target(data, va):
    raw = read_va(data, va, 6)
    if raw[:2] != b'\xff\x15':
        raise ValueError(f'slot call at {va:#x} changed')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0]


def arm(rule, byte):
    return bool(byte & 1) if rule == 'byte & 1 != 0' else byte == 0


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    if read_va(data, NAMES[0], len(NAMES[1])) != NAMES[1]:
        raise ValueError('field names changed')
    if read_va(data, STRUCT_NAME[0], len(STRUCT_NAME[1])) != STRUCT_NAME[1]:
        raise ValueError('struct name changed')
    if read_va(data, BUCKET_GUARD[0], len(BUCKET_GUARD[1])) != BUCKET_GUARD[1]:
        raise ValueError('BucketGuard name changed')

    cases = {}
    for idx in range(13):
        rel = struct.unpack('<i', read_va(data, JUMP_TABLE + 4 * idx, 4))[0]
        cases[idx] = JUMP_TABLE + rel
    for idx, f in FIELDS.items():
        if cases[idx] != f[1] or frame(fdes, f[1]) != VISITOR:
            raise ValueError(f'field {idx} case changed')
    if cases[12] != UNKNOWN_CASE:
        raise ValueError('unknown-field case changed')
    for idx, va in CASE_CALLS.items():
        if call_target(data, va) != FIELDS[idx][2]:
            raise ValueError(f'field {idx} decoder changed')
    if slot_target(data, MTPT_SLOT_CALL[0]) != MTPT_SLOT_CALL[1]:
        raise ValueError('mtpt decoder slot changed')

    covered = []
    for va, (off, width) in sorted(OUTPUT_STORES.items(), key=lambda kv: kv[1]):
        if frame(fdes, va) != VISITOR:
            raise ValueError('output store moved')
        covered.append((off - OUTPUT_BASE, width))
    spans = sorted((f[3], f[3] + f[4], f[0]) for f in FIELDS.values())
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        if a1 > b0:
            raise ValueError(f'{an} overlaps {bn}')
    if spans[-1][1] > 0xf8:
        raise ValueError('field past the 0xf8-byte struct')
    for off, width in covered:
        if not any(s0 <= off and off + width <= s1 for s0, s1, _ in spans):
            raise ValueError(f'output store at struct +{off:#x} is outside every field')

    sites = []
    for fn, va, rule, label in PANIC_SITES:
        if frame(fdes, va) != fn:
            raise ValueError(f'panic site {va:#x} moved')
        sites.append({'function': hex(fn), 'stop_byte_instruction': hex(va), 'site': label, 'arms_on': rule,
                      'arms_for_byte': {str(b): arm(rule, b) for b in (0, 1, 2)}})

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'visitor': hex(VISITOR),
        'output': {'stack_buffer': f'rsp+{OUTPUT_BASE:#x}', 'size': '0xf8', 'copy': hex(OUTPUT_COPY[1]),
                   'box_base_layout_A': '+0x3908'},
        'fields': [{'index': i, 'name': f[0], 'case': hex(f[1]),
                    'decoder': hex(f[2]) if f[2] else f'slot {MTPT_SLOT_CALL[1]:#x}',
                    'struct_offset': hex(f[3]), 'size': hex(f[4]), 'box_offset_A': hex(0x3908 + f[3]),
                    'type_hint': f[5], 'default_when_absent': f[6]}
                   for i, f in sorted(FIELDS.items())],
        'field_i': {'decoder': hex(I_DECODER), 'nil': 'msgpack 0xc0 -> byte 2 (0x47923bf, 0x47923c3)',
                    'height': 'struct +0xa0 (box +0x39a8)', 'byte': 'struct +0xa8 (box +0x39b0)'},
        'panic_sites': sites,
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
    print(f"fields={len(result['fields'])} panic_sites={len(result['panic_sites'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
