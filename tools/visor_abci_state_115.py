#!/usr/bin/env python3
"""Bind the node #115 visor_abci_state value and its four writers (35th stage).

Continues the hyperliquid_data packet (open PR #6002), which found that
hyperliquid_data/visor_abci_state.json is written by the wrapper 0x5942b40
(four callers) and by 0x5a39630, both through the value writer 0x50de010.
This tool binds:

1. the JSON serializer 0x51adf60 (only direct caller 0x50de010, which has
   only two direct callers: the wrapper and 0x5a39630): an object with six
   fields in this order, each at a fixed offset of the value:
   hardfork_version +0x10, initial_height +0x18, height +0x20 (one u64
   serializer 0x507d670), scheduled_freeze_height +0x0 (0x509b5b0, 16
   bytes), consensus_time +0x28 and wall_clock_time +0x34 (one 12-byte time
   serializer 0x508f390);
2. how the four wrapper callers fill that value from the engine box:
   hardfork_version = box +0x18, initial_height = box +0x10 (one 16-byte
   load, halves swapped with pshufd 0x4e), height = box +0x28,
   consensus_time = box +0x60 (qword) and +0x68 (dword), wall_clock_time =
   the wall-clock tuple from slot 0x64e0990 (0x1629690);
   scheduled_freeze_height = box +0x10e8 in 0x5443930, 0x59ec200 and
   0x5a07ec0, but box +0x1c58 (the freeze setter's field, #5970) in
   0x5a08720; the byte each step passes to slot 0x64e1220 moves by the same
   0xb70 (+0xb9a in 0x5a07ec0, +0x170a in 0x5a08720);
3. the name slice (visor_abci_state, 16 bytes) and the Location each
   caller passes: node/src/node.rs:659:50 (0x5443930, 0x59ec200) and
   l1/src/abci/engine.rs:316:46 (0x5a07ec0, 0x5a08720).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, direct_calls, fixed, read_va, relative_relocations,
                                 rip_target)

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-visor-abci-state-115'

WRAPPER = 0x5942b40
VALUE_WRITER = 0x50de010
JSON_SER = 0x51adf60
RMP_SER = 0x51ae110
U64_SER = 0x507d670
OPT_SER = 0x509b5b0
TIME_SER = 0x508f390
CLOCK_SLOT, CLOCK = 0x64e0990, 0x1629690

# (lea rsi site, string va, length, value offset, serializer call site, serializer)
FIELDS = (
    (0x51adfb4, 0x4504e0, 0x10, 0x10, 0x51adfc5, U64_SER, b'hardfork_version'),
    (0x51adfe2, 0x91f96f, 0x0e, 0x18, 0x51adff3, U64_SER, b'initial_height'),
    (0x51ae010, 0x91f97d, 0x06, 0x20, 0x51ae021, U64_SER, b'height'),
    (0x51ae036, 0x91f983, 0x17, 0x00, 0x51ae04a, OPT_SER, b'scheduled_freeze_height'),
    (0x51ae05f, 0x91f99a, 0x0e, 0x28, 0x51ae070, TIME_SER, b'consensus_time'),
    (0x51ae085, 0x91f9a8, 0x0f, 0x34, 0x51ae099, TIME_SER, b'wall_clock_time'),
)
FIELD_OFFSET_INSNS = {
    0x51adfb0: '488d4b10',          # lea rcx, [rbx+0x10]
    0x51adfde: '488d4b18',          # lea rcx, [rbx+0x18]
    0x51ae00c: '488d4b20',          # lea rcx, [rbx+0x20]
    0x51ae047: '4889d9',            # mov rcx, rbx        (+0x0)
    0x51ae05b: '488d4b28',          # lea rcx, [rbx+0x28]
    0x51ae081: '4883c334',          # add rbx, 0x34
}
LENGTH_INSNS = {0x51adfc0: 'ba10000000', 0x51adfee: 'ba0e000000', 0x51ae01c: 'ba06000000',
                0x51ae042: 'ba17000000', 0x51ae06b: 'ba0e000000', 0x51ae091: 'ba0f000000'}
CALLER_FILL = {
    # 0x5443930: box from engine value +0x450, value built at rsp
    0x54439b9: '488b8550040000',         # mov rax, [rbp+0x450]
    0x54439c0: '488b5828',               # mov rbx, [rax+0x28]          (height)
    0x54439e6: 'f30f6f80e8100000',       # movdqu xmm0, [rax+0x10e8]     (freeze)
    0x54439f7: '8b4868',                 # mov ecx, [rax+0x68]
    0x5443a01: '488b4060',               # mov rax, [rax+0x60]
    0x5443a1e: '660f708424800100004e',   # pshufd xmm0, [rsp+0x180], 0x4e
    0x5443a28: '660f7f442410',           # movdqa [rsp+0x10], xmm0
    0x5443a2e: '48895c2420',             # mov [rsp+0x20], rbx
    0x5443a3c: '660f7f0424',             # movdqa [rsp], xmm0
    0x5443a49: '4889442428',             # mov [rsp+0x28], rax
    0x5443a55: '89442430',               # mov [rsp+0x30], eax
    0x5443a61: '4889442434',             # mov [rsp+0x34], rax
    0x5443a6d: '8944243c',               # mov [rsp+0x3c], eax
    0x5443a7f: '4889e6',                 # mov rsi, rsp
    # freeze source and paired byte per caller
    0x59ec2e1: 'f30f6f80e8100000',       # 0x59ec200: [rax+0x10e8]
    0x5a081f4: '0f1080e8100000',         # 0x5a07ec0: [rax+0x10e8]
    0x5a081cb: '0fb6b89a0b0000',         # 0x5a07ec0: byte [rax+0xb9a]
    0x5a08a54: '0f1080581c0000',         # 0x5a08720: [rax+0x1c58]
    0x5a08a2b: '0fb6b80a170000',         # 0x5a08720: byte [rax+0x170a]
}
CALLERS = {
    # caller fn: (wrapper call, lea rdi name site, lea rdx location site, clock call)
    0x5443930: (0x5443a82, 0x5443a71, 0x5443a78, 0x5443a18),
    0x59ec200: (0x59ec380, 0x59ec36d, 0x59ec374, 0x59ec313),
    0x5a07ec0: (0x5a08250, 0x5a0823f, 0x5a08246, 0x5a08218),
    0x5a08720: (0x5a08ab0, 0x5a08a9f, 0x5a08aa6, 0x5a08a78),
}
FREEZE_SOURCE = {0x5443930: '+0x10e8', 0x59ec200: '+0x10e8', 0x5a07ec0: '+0x10e8', 0x5a08720: '+0x1c58'}
NAME = b'visor_abci_state'


def location(data, rel, va):
    ptr = rel[va]
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return '%s:%d:%d' % (read_va(data, ptr, length).decode(), line, col)


def bind(data, fdes):
    for table in (FIELD_OFFSET_INSNS, LENGTH_INSNS, CALLER_FILL):
        for va, expect in table.items():
            fixed(data, va, expect)
    rel = relative_relocations(data)
    if rel.get(CLOCK_SLOT) != CLOCK:
        raise ValueError('clock slot changed')

    fields = []
    for lea, sva, length, offset, call, ser, name in FIELDS:
        if rip_target(data, lea, b'\x48\x8d\x35', 7) != sva or read_va(data, sva, length) != name:
            raise ValueError(f'field name at {lea:#x} changed')
        if rip_target(data, call, b'\xe8', 5) != ser:
            raise ValueError(f'serializer call at {call:#x} changed')
        fields.append({'name': name.decode(), 'offset': hex(offset), 'serializer': hex(ser)})

    callers = {}
    for fn, (call, name_site, loc_site, clock_site) in CALLERS.items():
        if rip_target(data, call, b'\xe8', 5) != WRAPPER:
            raise ValueError(f'wrapper call at {call:#x} changed')
        if rip_target(data, clock_site, b'\xff\x15', 6) != CLOCK_SLOT:
            raise ValueError(f'clock call at {clock_site:#x} changed')
        name_slot = rip_target(data, name_site, b'\x48\x8d\x3d', 7)
        ptr = rel[name_slot]
        n = struct.unpack('<Q', read_va(data, name_slot + 8, 8))[0]
        if read_va(data, ptr, n) != NAME:
            raise ValueError(f'name at {name_site:#x} changed')
        loc_slot = rip_target(data, loc_site, b'\x48\x8d\x15', 7)
        callers[hex(fn)] = {'wrapper_call': hex(call), 'location': location(data, rel, loc_slot),
                            'scheduled_freeze_height_from': 'box ' + FREEZE_SOURCE[fn]}

    census = {hex(t): [hex(v) for v in direct_calls(data, t)]
              for t in (WRAPPER, VALUE_WRITER, JSON_SER, RMP_SER)}
    if census[hex(WRAPPER)] != [hex(CALLERS[k][0]) for k in sorted(CALLERS)]:
        raise ValueError('wrapper census changed')
    if census[hex(JSON_SER)] != ['0x50de1d8'] or census[hex(VALUE_WRITER)] != ['0x5942b6f', '0x5a396ef']:
        raise ValueError('serializer census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'json_serializer': hex(JSON_SER),
        'fields_in_order': fields,
        'fill_from_box': {
            'hardfork_version': 'box +0x18', 'initial_height': 'box +0x10', 'height': 'box +0x28',
            'consensus_time': 'box +0x60 (qword) + box +0x68 (dword)',
            'wall_clock_time': 'slot %s -> %s' % (hex(CLOCK_SLOT), hex(CLOCK)),
        },
        'callers': callers,
        'freeze_and_byte_shift': {'freeze': hex(0x1c58 - 0x10e8), 'slot_0x64e1220_byte': hex(0x170a - 0xb9a)},
        'direct_call_census': census,
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
    print('fields=%s' % ','.join(f['name'] for f in result['fields_in_order']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
