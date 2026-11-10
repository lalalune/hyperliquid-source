#!/usr/bin/env python3
"""Bind the node #115 begin_block A per-key action 0x5582180 and its record gates (stage 96).

Continues #6164 and #6205. The stage 95 cursor loop collects 20-byte keys
whose record byte +0x3c is 4, whose box byte +0x7b8 bit 0 is clear and for
which slot 0x64e7190 returns true, then passes each key to 0x5582180. This
tool binds:

1. the four direct calls of 0x5582180 and the ecx/r8 arguments each passes;
2. 0x5582180's two input modes (r8 == 1 walks box +0x6c8..+0x6e0, a ring
   of 0xb8-byte items in Locus blp; otherwise one boxed item from r9) and
   its per-clearinghouse read of +0x50 over Locus cls (0x510-byte stride,
   box +0x7c8/+0x7d0);
3. its one box store: a saturating increment of box +0xab0 (Locus ctr) when
   r8 != 0 and a local flag byte is set;
4. begin_block A frees the returned Vec unread;
5. the gate 0x3693030 (slot 0x64e7190): true when any 0x28-byte element has a
   non-zero +0x10 word (ring/Vec form) or any map value has a non-zero +0x8
   word (map form).

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from freeze_snapshot_115 import (  # noqa: E402
    RELATIVE, SHA256, TARGET, direct_calls, fixed, frame, read_va, relative_relocations,
)

PACKET = ROOT / 'research/work-items/RE-008-begin-block-key-action-115'

ACTION = 0x5582180
ACTION_END = 0x5585283
GATE = 0x3693030
GATE_SLOT = 0x64e7190

FIXED = {
    # begin_block A: record gates and the call
    0x54c00ef: '41807d3c04',            # cmp byte [r13+0x3c], 4
    0x54c00ff: 'f680b807000001',        # test byte [rax+0x7b8], 1
    0x54c010f: 'ff157b700201',          # call [rip] -> slot 0x64e7190
    0x54c0115: '84c0',                  # test al, al
    0x54c0332: '41b801000000',          # mov r8d, 1
    0x54c0343: '31c9',                  # xor ecx, ecx
    0x54c0345: 'e8361e0c00',            # call 0x5582180
    # begin_block A: result Vec freed unread
    0x54c034a: '488b742460',            # mov rsi, [rsp+0x60]
    0x54c034f: '48b80000000000000080',  # movabs rax, 0x8000000000000000
    0x54c0359: '4839c6',                # cmp rsi, rax
    0x54c0363: '488b7c2468',            # mov rdi, [rsp+0x68]
    0x54c0368: '48c1e603',              # shl rsi, 3
    0x54c036e: '41ffd4',                # call r12 (dealloc)
    # other callers: ecx
    0x5588e2d: '31c9',                  # xor ecx, ecx
    0x5588e2f: '4d89f9',                # mov r9, r15
    0x558b7b3: 'b901000000',            # mov ecx, 1
    0x558b990: 'b901000000',            # mov ecx, 1
    # 0x5582180: input modes
    0x55821af: '4c89442458',            # mov [rsp+0x58], r8
    0x55821b4: '4983f801',              # cmp r8, 1
    0x55821ba: '498b85c8060000',        # mov rax, [r13+0x6c8]
    0x5582279: '4869f9b8000000',        # imul rdi, rcx, 0xb8
    # 0x5582180: clearinghouse +0x50 per 0x510 stride
    0x55822fe: '4d8bb5d0070000',        # mov r14, [r13+0x7d0]
    0x5582314: '498b9dc8070000',        # mov rbx, [r13+0x7c8]
    0x5582380: '488db3800f0000',        # lea rsi, [rbx+0xf80]
    0x5582390: '488bbed0f0ffff',        # mov rdi, [rsi-0xf30]  (elem0 +0x50)
    0x558239b: '488bbee0f5ffff',        # mov rdi, [rsi-0xa20]  (elem1 +0x50)
    0x55823a7: '488bbef0faffff',        # mov rdi, [rsi-0x510]  (elem2 +0x50)
    # 0x5582180: the one box store
    0x5583256: '48837c245800',          # cmp qword [rsp+0x58], 0
    0x558325c: '0f95c0',                # setne al
    0x558325f: '84442428',              # test [rsp+0x28], al
    0x5583273: '498b85b00a0000',        # mov rax, [r13+0xab0]
    0x558327a: '48ffc0',                # inc rax
    0x558327d: '48c7c1ffffffff',        # mov rcx, -1
    0x5583284: '480f44c1',              # cmove rax, rcx
    0x5583288: '498985b00a0000',        # mov [r13+0xab0], rax
    # gate 0x3693030
    0x3693150: '4883791000',            # cmp qword [rcx+0x10], 0
    0x369315a: 'b001',                  # mov al, 1
    0x3693180: '48837a0800',            # cmp qword [rdx+0x8], 0
    0x36931d6: '31c0',                  # xor eax, eax
}
CALL_SITES = {0x54c0345: 0x54b66b0, 0x5588e32: 0x5588d90, 0x558b7c6: 0x558b730, 0x558b9a0: 0x558b730}
LOCATIONS = {
    0x648b990: ('l1/src/dex_registry/clearinghouses.rs', 11, 29),
    0x6476588: ('l1/src/qtys/mod.rs', 847, 1),
    0x64765a0: ('l1/src/qtys/impl_ntl.rs', 70, 1),
    0x6487478: ('l1/src/qtys/impl_wei.rs', 6, 1),
}
LOCATION_LEAS = (0x5584dff, 0x5584e36, 0x5584e6d)


def location(data, rel, va):
    ptr = rel.get(va)
    if ptr is None:
        raise ValueError(f'no relocation for Location {va:#x}')
    length = struct.unpack('<Q', read_va(data, va + 8, 8))[0]
    line, col = struct.unpack('<II', read_va(data, va + 16, 8))
    return read_va(data, ptr, length).decode(), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    rel = relative_relocations(data)
    if rel.get(GATE_SLOT) != GATE:
        raise ValueError('gate slot changed')
    calls = direct_calls(data, ACTION)
    if sorted(calls) != sorted(CALL_SITES):
        raise ValueError('action call census changed')
    for site, fn in CALL_SITES.items():
        if frame(fdes, site) != fn:
            raise ValueError(f'caller of {site:#x} changed')
    if frame(fdes, ACTION) != ACTION or frame(fdes, ACTION_END - 1) != ACTION:
        raise ValueError('action extent changed')
    if direct_calls(data, GATE):
        raise ValueError('gate gained a direct call')
    locs = {}
    for va, want in LOCATIONS.items():
        got = location(data, rel, va)
        if got != want:
            raise ValueError(f'Location {va:#x} changed')
        locs[hex(va)] = '%s:%d:%d' % got
    for va in LOCATION_LEAS:
        raw = read_va(data, va, 7)
        if raw[:3] != b'\x4c\x8d\x05' or va + 7 + struct.unpack_from('<i', raw, 3)[0] != 0x648b990:
            raise ValueError(f'Location load at {va:#x} changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'action': {
            'fn': [hex(ACTION), hex(ACTION_END)],
            'call_sites': {hex(s): {'in': hex(f)} for s, f in sorted(CALL_SITES.items())},
            'args': 'rdi out Vec<8-byte>; rsi box; rdx &20-byte key; ecx flag; r8 mode; r9 item',
            'ecx_r8': {'0x54c0345': 'ecx 0, r8 1', '0x5588e32': 'ecx 0, r8 1 or 0 (r9 = r15)',
                       '0x558b7c6': 'ecx 1, r8 = r15', '0x558b9a0': 'ecx 1, r8 = r15'},
            'mode_r8_1': 'walks box +0x6c8 (tag) / +0x6d0 ptr / +0x6d8 head / +0x6e0 len, 0xb8-byte items (Locus blp)',
            'mode_other': 'one 8-byte item boxed from r9',
            'clearinghouses': 'reads +0x50 of each 0x510-byte element of box +0x7c8 (len +0x7d0, Locus cls)',
            'box_store': '+0xab0 (Locus ctr) saturating += 1 when r8 != 0 and [rsp+0x28] flag set (0x5583288)',
            'locations': locs,
        },
        'begin_block_a': {
            'gates': 'record byte +0x3c == 4 (0x54c00ef), box +0x7b8 bit0 clear (0x54c00ff), slot 0x64e7190 true',
            'result': 'Vec freed unread (0x54c034a..0x54c036e)',
        },
        'gate': {
            'fn': hex(GATE), 'slot': hex(GATE_SLOT), 'direct_calls': 0,
            'true_when': 'any 0x28-byte element with [elem+0x10] != 0 (0x3693150), or map form any value [v+0x8] != 0 (0x3693180)',
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
    print('action calls=%d' % len(result['action']['call_sites']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
