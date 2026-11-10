#!/usr/bin/env python3
"""Bind where the node #115 slow abci runner goes and the thread that drives it (40th stage).

Continues #6010, which found that 0x5a6bfb0 builds a fast runner (0x567bd50)
and a slow runner (slot 0x64ebc98 -> 0x5649680, name node_slow_abci_engine).
This tool binds:

1. 0x5a6bfb0 returns both runners as Arcs: rax = the fast runner Arc (0xb38
   allocation kept in r14 since 0x5a6c300), rdx = the slow runner Arc (a 0xb80
   allocation holding {1, 1, 0xb70-byte runner});
2. both pollers keep rdx after the slot 0x64e7440 call (0x2aec3ef, 0x2cb7a0f);
3. both pollers later call slot 0x64e7458 -> 0x5a6cbc0 (0x2aed2f5, 0x2cb8915),
   which calls slot 0x64ebca0 -> 0x5649df0 on its rsi+0x10, builds a
   'slow abci block' handle with 0x1388 (5000), boxes a 0xb8-byte closure and
   passes it to slot 0x64e1750 -> 0x15d63c0 with the name
   'node slow abci_state driver' and vtable 0x64b8a00 (drop 0x5a579d0, size
   0xb8, align 8, call 0x5a34440);
4. the closure body 0x5a34440: 'get' through 0x4f19fa0 on [ctx+0xa0]+0x140;
   [[ctx+0x78]+0xb58]+0x80 (slow runner +0xb48, the pool) to 0x59edc50;
   'spawn_slow_abci_driver_apply_block' through 0x4e47900 with edx = 1;
   'spawn_slow_abci_driver_write_greeting' through 0x4f18bd0 with edx = 0 on
   [ctx+0xa8]+0x140. 0x4f19fa0 and 0x4f18bd0 reference base/src/lock_id.rs;
   0x4e47900 references 'asked to exit when not entered';
5. the two constant blocks: 0x5649680 stores {0, 60000, 525600, 0} at slow
   runner +0xb20..+0xb38 and +0xb50..+0xb68; the same 60000 / 525600 pair is
   stored by 0x434b950 at +0x3a0 / +0x3a8. The 32-bit value 525600 occurs
   three times in .text.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, RELATIVE, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target, text)

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-runner-poll-115'

FIXED = {
    # 0x5a6bfb0 tail: wrap the slow runner in a {1, 1, runner} Arc, return both Arcs
    0x5a6c2ec: 'bf380b0000',          # mov edi, 0xb38   (fast runner Arc)
    0x5a6c300: '4989c6',              # mov r14, rax
    0x5a6c647: 'ba700b0000',          # mov edx, 0xb70   (slow runner bytes)
    0x5a6c655: 'bf800b0000',          # mov edi, 0xb80   (slow runner Arc)
    0x5a6c665: '4989c7',              # mov r15, rax
    0x5a6c670: 'ba800b0000',          # mov edx, 0xb80
    0x5a6c67e: '4c89f0',              # mov rax, r14     (fast Arc)
    0x5a6c681: '4c89fa',              # mov rdx, r15     (slow Arc)
    # pollers keep both halves of the pair
    0x2aec3f5: '4989c6',              # mov r14, rax
    0x2aec400: '4889942430010000',    # mov [rsp+0x130], rdx
    0x2cb7a15: '4989c6',
    0x2cb7a20: '4889942430010000',
    # 0x5a6cbc0: slow driver start
    0x5a6cbf8: '488d7e10',            # lea rdi, [rsi+0x10]
    0x5a6cc02: '89c3',                # mov ebx, eax
    0x5a6cc04: 'bf200b0000',          # mov edi, 0xb20
    0x5a6cd5f: '48c74424580f000000',  # mov qword [rsp+0x58], 15   (len 'slow abci block')
    0x5a6cd68: '48c744246088130000',  # mov qword [rsp+0x60], 5000
    0x5a6ce10: '889c2430010000',      # mov [rsp+0x130], bl
    0x5a6ce24: 'bfb8000000',          # mov edi, 0xb8    (closure box)
    0x5a6ce43: 'bab8000000',          # mov edx, 0xb8
    0x5a6ce5f: 'be1b000000',          # mov esi, 27      (len thread name)
    0x5a6ce64: '4889da',              # mov rdx, rbx     (boxed closure)
    # 0x5a34440: closure body
    0x5a34dd1: '488bb0a0000000',      # mov rsi, [rax+0xa0]
    0x5a34de8: '48c744245003000000',  # len 'get'
    0x5a34dfa: '4881c640010000',      # add rsi, 0x140
    0x5a34e22: '488b4378',            # mov rax, [rbx+0x78]
    0x5a34e26: '488bb0580b0000',      # mov rsi, [rax+0xb58]  (slow runner +0xb48)
    0x5a34e2d: '4883ee80',            # sub rsi, -0x80
    0x5a34e83: '48c78424f000000022000000',  # len 34
    0x5a34f08: 'ba01000000',          # mov edx, 1
    0x5a34f2f: '488bb8a8000000',      # mov rdi, [rax+0xa8]
    0x5a34f74: '48c78424f800000025000000',  # len 37
    0x5a34f8c: '4881c740010000',      # add rdi, 0x140
    0x5a34faa: '31d2',                # xor edx, edx
    # 0x5649680: the two constant blocks and the pool slot
    0x5649c35: '49c786200b000000000000',  # [r14+0xb20] = 0
    0x5649c40: '49c786280b000060ea0000',  # [r14+0xb28] = 60000
    0x5649c4b: '49c786300b000020050800',  # [r14+0xb30] = 525600
    0x5649c61: '410f9586400b0000',        # setne [r14+0xb40]
    0x5649c6e: '498986480b0000',          # [r14+0xb48] = pool
    0x5649c80: '49c786580b000060ea0000',  # [r14+0xb58] = 60000
    0x5649c8b: '49c786600b000020050800',  # [r14+0xb60] = 525600
    # 0x434b950: the same pair in another struct
    0x434b97e: '48c787a003000060ea0000',  # [rdi+0x3a0] = 60000
    0x434b989: '48c787a803000020050800',  # [rdi+0x3a8] = 525600
}
REFERENCES = (
    (0x2aec3ef, b'\xff\x15', 6, 0x64e7440),
    (0x2cb7a0f, b'\xff\x15', 6, 0x64e7440),
    (0x2aed2f5, b'\xff\x15', 6, 0x64e7458),
    (0x2cb8915, b'\xff\x15', 6, 0x64e7458),
    (0x5a6cbfc, b'\xff\x15', 6, 0x64ebca0),
    (0x5a6cd53, b'\x48\x8d\x0d', 7, 0x93afd9),
    (0x5a6ce51, b'\x48\x8d\x3d', 7, 0x93afe8),
    (0x5a6ce58, b'\x48\x8d\x0d', 7, 0x64b8a00),
    (0x5a6ce67, b'\xff\x15', 6, 0x64e1750),
    (0x5a34ddc, b'\x48\x8d\x05', 7, 0x93b00c),
    (0x5a34e18, b'\xe8', 5, 0x4f19fa0),
    (0x5a34e49, b'\xe8', 5, 0x59edc50),
    (0x5a34e74, b'\x48\x8d\x0d', 7, 0x93b00f),
    (0x5a34f0d, b'\xe8', 5, 0x4e47900),
    (0x5a34f65, b'\x48\x8d\x0d', 7, 0x93b031),
    (0x5a34fb3, b'\xe8', 5, 0x4f18bd0),
)
RELOCS = {0x64e7440: 0x5a6bfb0, 0x64e7458: 0x5a6cbc0, 0x64ebca0: 0x5649df0, 0x64e1750: 0x15d63c0,
          0x64b8a00: 0x5a579d0, 0x64b8a18: 0x5a34440}
STRINGS = {0x93afd9: b'slow abci block', 0x93afe8: b'node slow abci_state driver', 0x93b00c: b'get',
           0x93b00f: b'spawn_slow_abci_driver_apply_block',
           0x93b031: b'spawn_slow_abci_driver_write_greeting'}
STRING_REFS = (  # (instruction, prefix, frame, expected string start)
    (0x4f1a239, b'\x48\x8d\x05', 0x4f19fa0, b'base/src/lock_id.rs'),
    (0x4f18e33, b'\x48\x8d\x05', 0x4f18bd0, b'base/src/lock_id.rs'),
    (0x4e47c0e, b'\x48\x8d\x3d', 0x4e47900, b'asked to exit when not entered'),
)


def slot_calls(data, slot):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(rb'\xff\x15', code)
            if m.start() + 6 <= len(code) and base + m.start() + 6 + struct.unpack_from('<i', code, m.start() + 2)[0] == slot]


def imm32_sites(data, value):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(re.escape(struct.pack('<I', value)), code)]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    size, align = struct.unpack('<QQ', read_va(data, 0x64b8a08, 16))
    if (size, align) != (0xb8, 8):
        raise ValueError('closure vtable layout changed')
    for va, text_ in STRINGS.items():
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    for va, prefix, fn, start in STRING_REFS:
        if frame(fdes, va) != fn or read_va(data, rip_target(data, va, prefix, 7), len(start)) != start:
            raise ValueError(f'string reference at {va:#x} changed')
    for va in (0x2aec3ef, 0x2aed2f5):
        if frame(fdes, va) != 0x2aeaef0:
            raise ValueError('poller frame changed')
    for va in (0x2cb7a0f, 0x2cb8915):
        if frame(fdes, va) != 0x2cb6500:
            raise ValueError('poller frame changed')

    start_calls = slot_calls(data, 0x64e7458)
    pair_calls = slot_calls(data, 0x64e7440)
    sites_525600 = imm32_sites(data, 525600)
    if start_calls != [0x2aed2f5, 0x2cb8915] or pair_calls != [0x2aec3ef, 0x2cb7a0f]:
        raise ValueError('slot call census changed')
    if direct_calls(data, 0x5a6cbc0) or direct_calls(data, 0x5a34440):
        raise ValueError('direct call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'runner_pair': {
            'builder': '0x5a6bfb0',
            'returns': 'rax = fast runner Arc (0xb38 allocation, r14 since 0x5a6c300); '
                       'rdx = slow runner Arc (0xb80 allocation = {1, 1, 0xb70-byte runner})',
            'slot_0x64e7440_calls': [hex(v) for v in pair_calls],
            'pollers_keep_rdx': '[rsp+0x130] at 0x2aec400 and 0x2cb7a20',
        },
        'slow_driver_start': {
            'fn': '0x5a6cbc0',
            'slot_0x64e7458_calls': [hex(v) for v in start_calls],
            'direct_calls': 0,
            'reads': 'slot 0x64ebca0 -> 0x5649df0 on rsi+0x10, result byte kept in ebx',
            'handle': "'slow abci block' (15 bytes) with 0x1388 (5000); 0xb20-byte allocation",
            'spawn': "slot 0x64e1750 -> 0x15d63c0, name 'node slow abci_state driver' (27 bytes), "
                     'boxed 0xb8-byte closure, vtable 0x64b8a00',
            'vtable': {'drop': '0x5a579d0', 'size': '0xb8', 'align': 8, 'call': '0x5a34440'},
        },
        'driver_body': {
            'fn': '0x5a34440',
            'read_lock': "'get' (3 bytes) through 0x4f19fa0 on [ctx+0xa0]+0x140",
            'pool': '[[ctx+0x78]+0xb58]+0x80 (slow runner +0xb48) to 0x59edc50',
            'apply_block': "'spawn_slow_abci_driver_apply_block' (34 bytes) through 0x4e47900, edx = 1",
            'write_greeting': "'spawn_slow_abci_driver_write_greeting' (37 bytes) through 0x4f18bd0, "
                              'edx = 0, on [ctx+0xa8]+0x140',
            'helper_strings': {'0x4f19fa0': 'base/src/lock_id.rs', '0x4f18bd0': 'base/src/lock_id.rs',
                               '0x4e47900': 'asked to exit when not entered'},
        },
        'constant_blocks': {
            'slow_runner': {'+0xb20': 0, '+0xb28': 60000, '+0xb30': 525600, '+0xb38': 0,
                            '+0xb50': 0, '+0xb58': 60000, '+0xb60': 525600, '+0xb68': 0},
            'same_pair_elsewhere': '0x434b950 stores 60000 at +0x3a0 and 525600 at +0x3a8',
            'imm32_525600_sites': [hex(v) for v in sites_525600],
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
    print(f"start_calls={len(result['slow_driver_start']['slot_0x64e7458_calls'])} "
          f"sites_525600={len(result['constant_blocks']['imm32_525600_sites'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
