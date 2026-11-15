#!/usr/bin/env python3
"""Bind the node #115 engine value tag, the height assert and the 3.0 s gate (stage 82).

Continues #6064 (the 'abci_engine' singleton fill) and #6081 (the shared
height counter checked by the step wrappers when engine dword +0x0 is 2).
This tool binds:

1. The fill 0x38c6590 is reached only through slot 0x64e80e8 (three slot
   calls: 0x2d2760c, 0x5a08fbc, 0x5a6c104). It keeps the input tag: when the
   input dword +0x0 is 2 it copies a local whose first qword is 2 (0x38c65a1),
   otherwise it copies the input itself. Its output +0x0 is that copy, so the
   output tag is 2 exactly when the input tag is 2. It registers 'abci_engine'
   (11 bytes) with "true" (4) when the tag is 2, else "false" (5).
2. Every input that reaches the three fill calls has tag 2:
   - fast engine value: qword 2 at rsp+0xe20 (0x5a6c0e0), passed at 0x5a6c104;
   - slow (layout-A) input: qword 2 at rsp+0x1240 (0x5a6c3b6, #6081), passed
     to 0x5a08f80 at 0x5a6c5f8, which calls the fill at 0x5a08fbc with the
     same rsi;
   - catch-up shim input: qword 2 at rsp+0x200 (0x2b1e1d9), passed to the
     shim 0x2d275d0 at 0x2b1e1f8, which calls the fill at 0x2d2760c.
   So every engine value built here has tag 2 and runs the wrapper check.
3. The wrapper mismatch slot 0x64e1e68 is relocated to 0x167bbeb, a
   two-pointer trampoline that calls slot 0x64e1810 (relocated to 0x1680d35);
   0x1680d35 loads "assertion `left" templates (0x4338f7, 0x4317ce). The
   wrappers pass edi = 0, ecx = 0 and Location l1/src/abci/engine.rs:262:17,
   i.e. an equality assertion that panics (inference: assert_eq).
4. In the fast_height read body 0x4fc1660, when wait + hold > 3.0 s, it reads
   the byte at root cell 0x64f06c0 +0x48 (slot 0x64e0918) and, when that byte
   is in the set {14, 15, 19, 20, 21, 22, 32} (mask 0x10078c000), forces the
   lazy cell 0x64f01c0 (state 0x64f01d8) through slot 0x64df9f0 and returns
   (jmp 0x4fc18fd). No string is loaded on this path.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target, text)

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-engine-tag-counter-115'

FILL = 0x38c6590
FILL_SLOT = 0x64e80e8
FILL_CALLS = [0x2d2760c, 0x5a08fbc, 0x5a6c104]
SHIM = 0x2d275d0
A_BUILDER = 0x5a08f80
ASSERT_SLOT = 0x64e1e68
ASSERT_TRAMP = 0x167bbeb
ASSERT_INNER_SLOT = 0x64e1810
ASSERT_INNER = 0x1680d35
LOC_ENGINE = 0x64b7fb0
READ_BODY = 0x4fc1660
ROOT_SLOT = 0x64e0918
ROOT_CELL = 0x64f06c0
LAZY_STATE = 0x64f01d8
ONCE_SLOT = 0x64df9f0
THRESHOLD = 0x459608
MASK = 0x10078c000
STRINGS = {
    0x459fd8: b'true',
    0x7a145d: b'false',
    0x7a14dc: b'abci_engine',
    0x4338f7: b'\x10assertion `left',
}

FIXED = {
    # fill 0x38c6590: tag pass-through and the singleton value
    0x38c65a1: '48c744240802000000',        # mov qword [rsp+8], 2
    0x38c65aa: '833e02',                    # cmp dword [rsi], 2
    0x38c65ad: '751a',                      # jne (copy the input)
    0x38c65bc: 'ba20040000',                # mov edx, 0x420
    0x38c65f1: '4983fc02',                  # cmp r12, 2
    0x38c65f5: '410f94c6',                  # sete r14b
    0x38c65f9: '4983f605',                  # xor r14, 5   (len 4 or 5)
    0x38c6624: '480f44f0',                  # cmove rsi, rax ("true")
    0x38c6640: 'ba0b000000',                # mov edx, 11  ("abci_engine")
    0x38c6667: 'ba20040000',                # mov edx, 0x420
    0x38c666c: '4889df',                    # mov rdi, rbx (output +0x0)
    # tag-2 inputs at the three paths
    0x5a6c0e0: '48c78424200e000002000000',  # fast: mov [rsp+0xe20], 2
    0x5a6c0fc: '488db424200e0000',          # lea rsi, [rsp+0xe20]
    0x5a6c3b6: '48c784244012000002000000',  # slow: mov [rsp+0x1240], 2
    0x2b1e1d9: '48c7842400020000' '02000000',  # catch-up: mov [rsp+0x200], 2
    0x2b1e1ed: '4c8da42400020000',          # lea r12, [rsp+0x200]
    0x2b1e1f5: '4c89e6',                    # mov rsi, r12
    # wrapper assert arguments
    0x5a0563a: '31ff',                      # xor edi, edi
    0x5a0563c: '31c9',                      # xor ecx, ecx
    0x5a06e6f: '31ff',                      # xor edi, edi
    # 3.0 s gate in 0x4fc1660
    0x4fc18ca: '8b4350',                    # mov eax, [rbx+0x50]
    0x4fc18d5: '0fb64348',                  # movzx eax, byte [rbx+0x48]
    0x4fc18d9: '4883f820',                  # cmp rax, 0x20
    0x4fc18df: '48b900c0780001000000',      # movabs rcx, 0x10078c000
    0x4fc18e9: '480fa3c1',                  # bt rcx, rax
}
REFERENCES = (
    (0x38c6616, b'\x48\x8d\x05', 7, 0x459fd8),
    (0x38c661d, b'\x48\x8d\x35', 7, 0x7a145d),
    (0x38c6634, b'\x48\x8d\x35', 7, 0x7a14dc),
    (0x2d2760c, b'\xff\x15', 6, FILL_SLOT),
    (0x5a08fbc, b'\xff\x15', 6, FILL_SLOT),
    (0x5a6c104, b'\xff\x15', 6, FILL_SLOT),
    (0x2b1e1f8, b'\xe8', 5, SHIM),
    (0x5a6c5f8, b'\xe8', 5, A_BUILDER),
    (0x5a0563e, b'\xff\x15', 6, ASSERT_SLOT),
    (0x5a06e73, b'\xff\x15', 6, ASSERT_SLOT),
    (0x5a05623, b'\x4c\x8d\x0d', 7, LOC_ENGINE),
    (0x167bc1a, b'\xff\x15', 6, ASSERT_INNER_SLOT),
    (0x1680db6, b'\x48\x8d\x3d', 7, 0x4338f7),
    (0x4fc18b9, b'\x66\x0f\x2e\x05', 8, THRESHOLD),
    (0x4fc18c3, b'\x48\x8b\x1d', 7, ROOT_SLOT),
    (0x4fc18ef, b'\x8b\x05', 6, LAZY_STATE),
    (0x4fc1b45, b'\x48\x8d\x3d', 7, LAZY_STATE),
    (0x4fc1b64, b'\xff\x15', 6, ONCE_SLOT),
    (0x4fc1b6a, b'\xe9', 5, 0x4fc18fd),
)
RELOCATIONS = {
    FILL_SLOT: FILL,
    ASSERT_SLOT: ASSERT_TRAMP,
    ASSERT_INNER_SLOT: ASSERT_INNER,
    ROOT_SLOT: ROOT_CELL,
}


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def location(data, va):
    ptr = relative_relocations(data).get(va)
    if ptr is None:
        raise ValueError(f'Location {va:#x} has no relocation')
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, ptr, length).decode(), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    threshold, = struct.unpack('<d', read_va(data, THRESHOLD, 8))
    if threshold != 3.0:
        raise ValueError('threshold changed')
    fill_calls = slot_calls(data, FILL_SLOT)
    if fill_calls != FILL_CALLS:
        raise ValueError('fill call census changed')
    if direct_calls(data, FILL):
        raise ValueError('fill gained a direct caller')
    if direct_calls(data, SHIM) != [0x2b1e1f8] or direct_calls(data, A_BUILDER) != [0x5a6c5f8]:
        raise ValueError('builder census changed')
    if [frame(fdes, v) for v in FILL_CALLS] != [SHIM, A_BUILDER, 0x5a6bfb0]:
        raise ValueError('fill caller frames changed')
    assert_calls = slot_calls(data, ASSERT_SLOT)
    loc = location(data, LOC_ENGINE)
    if loc != ('l1/src/abci/engine.rs', 262, 17):
        raise ValueError('engine Location changed')
    levels = [i for i in range(64) if (MASK >> i) & 1]
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'fill': {
            'fn': hex(FILL),
            'slot': hex(FILL_SLOT),
            'slot_calls': [hex(v) for v in fill_calls],
            'tag': 'input dword +0x0 == 2 -> output from a local whose first qword is 2; else output = copy of the input (0x420 bytes); output +0x0 tag == input tag',
            'singleton': "'abci_engine' (11) = 'true' (4) when tag 2, else 'false' (5)",
        },
        'tag_sources': {
            'fast': '0x5a6c0e0 qword 2 at rsp+0xe20 -> fill at 0x5a6c104',
            'slow_layout_A': '0x5a6c3b6 qword 2 at rsp+0x1240 -> 0x5a08f80 (0x5a6c5f8) -> fill at 0x5a08fbc',
            'catch_up': '0x2b1e1d9 qword 2 at rsp+0x200 -> shim 0x2d275d0 (0x2b1e1f8) -> fill at 0x2d2760c',
        },
        'mismatch': {
            'slot': hex(ASSERT_SLOT),
            'target': hex(ASSERT_TRAMP),
            'inner': '%s via slot %s; loads %s' % (hex(ASSERT_INNER), hex(ASSERT_INNER_SLOT), STRINGS[0x4338f7][1:].decode()),
            'slot_calls': [hex(v) for v in assert_calls],
            'args': 'edi = 0, ecx = 0, r9 = Location %s %s:%d:%d' % ((hex(LOC_ENGINE),) + loc),
        },
        'slow_lock_gate': {
            'fn': hex(READ_BODY),
            'threshold_s': threshold,
            'root_cell': '%s via slot %s, byte +0x48 (state dword +0x50)' % (hex(ROOT_CELL), hex(ROOT_SLOT)),
            'mask': hex(MASK),
            'levels': levels,
            'action': 'force lazy cell 0x64f01c0 (state %s) through slot %s, then return (no string loaded)' % (hex(LAZY_STATE), hex(ONCE_SLOT)),
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
    print('fill slot calls=%s' % result['fill']['slot_calls'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
