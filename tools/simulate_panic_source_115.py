#!/usr/bin/env python3
"""Bind which node #115 deserialisers fill the abci box (stage 87).

Stage 86 (#6091) named three stack builders (0x199ce60, 0x32caf70,
0x49da420) as the next lead for the simulate-panic stop fields at layout-A
box +0x39a8/+0x39b0, and the selector byte +0xb9a written once at
0x2fc32ad in 0x2fc21d0. This tool binds:

1. the three builders are rmp-serde struct visitors whose `expected` slice
   is `struct Exchange with 59 elements` (records 0x641f220, 0x6464800,
   0x6499c28, all relocated to 0x457700, length 32); each returns a
   0x27a8-byte value through the out pointer saved at rsp+0xf8;
2. their callers (0x1b45512 and twins) are field visitors that match the
   8-byte key `exchange` (movabs at 0x1b454db) and move the value into a
   fresh 0x27a8-byte heap allocation (mov edi, 0x27a8 at 0x1b450f1), so
   the Exchange value is boxed and the builders' rsp+0x39b0 accesses are
   stack temporaries, not box +0x39a8;
3. 0x2fc21d0 is the rmp-serde visitor for `struct Locus with 16 elements`
   (record 0x6464530 -> 0x794eba, length 29); it writes its fields through
   rbx = rdi; its final block stores +0xb90/+0xb98/+0xb99/+0xb9a, and the
   selector byte +0xb9a is the element decoded into [rsp+0x7] at 0x2fc288d.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va, relative_relocations, direct_calls

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-simulate-panic-source-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

EXCHANGE_VISITORS = (0x199ce60, 0x32caf70, 0x49da420)
EXCHANGE_RECORDS = (0x641f220, 0x6464800, 0x6499c28)
EXCHANGE_STR = (0x457700, b'struct Exchange with 59 elements')
LOCUS_VISITOR = 0x2fc21d0
LOCUS_RECORD = 0x6464530
LOCUS_STR = (0x794eba, b'struct Locus with 16 elements')

FIXED = {
    # Exchange visitor 0x199ce60: expected record, Ok copy to out, stack temp
    0x199d76b: '488d15ae1aa804',        # lea rdx, [rip] -> 0x641f220
    0x32cb87b: '488d157e8f1903',        # lea rdx, [rip] -> 0x6464800 (twin)
    0x49dad2b: '488d15f6eeab01',        # lea rdx, [rip] -> 0x6499c28 (twin)
    0x199ea85: 'baa8270000',            # mov edx, 0x27a8
    0x199ea8a: '488bbc24f8000000',      # mov rdi, [rsp+0xf8]       (out)
    0x199e478: '0f298424b0390000',      # movaps [rsp+0x39b0], xmm0 (stack temp)
    # field visitor 0x1b44f30: key 'exchange', box the value
    0x1b454db: '48b965786368616e6765',  # movabs rcx, 'exchange'
    0x1b450f1: 'bfa8270000',            # mov edi, 0x27a8           (alloc size)
    # Locus visitor 0x2fc21d0
    0x2fc21f0: '4889fb',                # mov rbx, rdi              (out)
    0x2fc2201: '488d1528234a03',        # lea rdx, [rip] -> 0x6464530
    0x2fc288d: '884c2407',              # mov [rsp+0x7], cl         (element byte)
    0x2fc328b: '488983900b0000',        # mov [rbx+0xb90], rax
    0x2fc3297: '8883980b0000',          # mov [rbx+0xb98], al
    0x2fc32a2: '8883990b0000',          # mov [rbx+0xb99], al
    0x2fc32ad: '88839a0b0000',          # mov [rbx+0xb9a], al
}
CALLERS = {0x199ce60: [0x1b45512, 0x1b4587b], 0x32caf70: [0x3266b02, 0x3266e6b],
           0x49da420: [0x4bad4c2, 0x4bad82b]}


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    rel = relative_relocations(data)
    for rec in EXCHANGE_RECORDS:
        if rel.get(rec) != EXCHANGE_STR[0] or struct.unpack('<Q', read_va(data, rec + 8, 8))[0] != len(EXCHANGE_STR[1]):
            raise ValueError(f'Exchange expected-record {rec:#x} changed')
    if rel.get(LOCUS_RECORD) != LOCUS_STR[0] or struct.unpack('<Q', read_va(data, LOCUS_RECORD + 8, 8))[0] != len(LOCUS_STR[1]):
        raise ValueError('Locus expected-record changed')
    for va, text_ in (EXCHANGE_STR, LOCUS_STR):
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    exchange_refs = sorted(k for k, v in rel.items() if v == EXCHANGE_STR[0])
    calls = {}
    for fn, want in CALLERS.items():
        got = direct_calls(data, fn)
        if got != want:
            raise ValueError(f'call census of {fn:#x} changed: {[hex(v) for v in got]}')
        calls[hex(fn)] = [hex(v) for v in got]
    if direct_calls(data, LOCUS_VISITOR) == []:
        locus_callers = []
    else:
        locus_callers = [hex(v) for v in direct_calls(data, LOCUS_VISITOR)]
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'exchange_visitors': {
            'functions': [hex(v) for v in EXCHANGE_VISITORS],
            'expected_records': [hex(v) for v in EXCHANGE_RECORDS],
            'expected': EXCHANGE_STR[1].decode(),
            'all_relocations_to_string': [hex(v) for v in exchange_refs],
            'ok_copy': '0x199ea85 mov edx, 0x27a8; 0x199ea8a mov rdi, [rsp+0xf8] (out)',
            'stack_temp': '0x199e478 movaps [rsp+0x39b0], xmm0 (stack slot, not box +0x39a8)',
            'direct_callers': calls,
        },
        'exchange_field_visitor': {
            'key': '0x1b454db movabs rcx, 0x65676e6168637865 (\'exchange\')',
            'boxing': '0x1b450f1 mov edi, 0x27a8 then alloc slot 0x64df480 and memcpy',
        },
        'locus_visitor': {
            'function': hex(LOCUS_VISITOR),
            'expected_record': hex(LOCUS_RECORD),
            'expected': LOCUS_STR[1].decode(),
            'out': '0x2fc21f0 mov rbx, rdi',
            'final_stores': ['0x2fc328b [rbx+0xb90] qword', '0x2fc3297 [rbx+0xb98] byte',
                             '0x2fc32a2 [rbx+0xb99] byte', '0x2fc32ad [rbx+0xb9a] byte'],
            'selector_source': '0x2fc288d mov [rsp+0x7], cl (decoded element byte)',
            'direct_callers': locus_callers,
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
    print('exchange visitors', len(result['exchange_visitors']['functions']), 'locus visitor', result['locus_visitor']['function'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
