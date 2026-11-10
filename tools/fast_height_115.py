#!/usr/bin/env python3
"""Bind the node #115 `fast_height` read and the shared height counter (stage 81).

Continues #5916 (the `fast_abci_engine` runner and the `fast_height` call at
0x5a6c364) and #6014. This tool binds:

1. 0x4f1b280 has one direct caller, 0x5a6c364. It receives rdi = allocation
   +0x140, rsi = the runner, rdx = {0, "fast_height", 11}, ecx = 0 and the
   Location node.rs:623:40. When byte [rdi+0x20] is 0 it tail-jumps to
   0x4fc1660 (runner, name); otherwise it walks a thread-local list of
   0x38-byte entries first and then calls 0x4fc1660 at 0x4f1bace.
2. 0x4fc1660 takes a read lock on runner +0x6a8 (add 0x10, slow path with
   1000000000), clones the Arc at runner +0xb08 (lock inc), releases the lock
   (xadd -0x10), and returns the clone. It times the wait and the hold in f64
   seconds and enters a level-gated path when their sum is above 3.0.
   Runner +0xb08 is engine value +0x458 (engine value at runner +0x6b0, #5916).
3. 0x5a6bfb0 puts the returned clone at slow-engine input +0x428 (rsp+0x1668),
   replacing a fresh {1, 1, box+0x28} Arc it had just built and drops; the
   input (tag word 2 at +0x0, box at +0x420) is copied (0x438 bytes) and the
   layout-A builder 0x5a08f80 moves input +0x428 to engine value +0x458.
4. Both step wrappers (A 0x5a055f2, B 0x5a06e2a): when the engine value's
   dword +0x0 is 2 they `lock inc` the u64 at [+0x458]+0x10, read it back and
   assert it equals box +0x28 through slot 0x64e1e68 with Location
   l1/src/abci/engine.rs:262:17.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target)

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-fast-height-115'

TRACKED_READ = 0x4f1b280
READ_BODY = 0x4fc1660
BUILDER = 0x5a6bfb0
LAYOUT_A_BUILDER = 0x5a08f80
WRAP_A = 0x5a04e40
WRAP_B = 0x5a06600
NAME = (0x93afb9, b'fast_height')
LOC_NODE = 0x64b89e8
LOC_ENGINE = 0x64b7fb0
ASSERT_SLOT = 0x64e1e68
THRESHOLD = 0x459608
NANOS = 0x458d50

FIXED = {
    # 0x5a6bfb0: tracked read of fast_height on allocation +0x140
    0x5a6c349: '4c89f7',                    # mov rdi, r14
    0x5a6c34c: '4881c740010000',            # add rdi, 0x140
    0x5a6c362: '31c9',                      # xor ecx, ecx
    # fresh {1,1,height} Arc, tag 2, then the clone replaces it
    0x5a6c389: '48c70001000000',            # mov [rax], 1
    0x5a6c390: '48c7400801000000',          # mov [rax+8], 1
    0x5a6c398: '4c897810',                  # mov [rax+0x10], r15
    0x5a6c39c: '48899c2460160000',          # mov [rsp+0x1660], rbx   (input +0x420 box)
    0x5a6c3ae: '4889842468160000',          # mov [rsp+0x1668], rax   (input +0x428)
    0x5a6c3b6: '48c784244012000002000000',  # mov [rsp+0x1240], 2     (input +0x0 tag)
    0x5a6c3c2: 'f048ff08',                  # lock dec [rax]
    0x5a6c3d6: '4c89a42468160000',          # mov [rsp+0x1668], r12   (fast_height clone)
    0x5a6c5c3: '488dbc2408550000',          # lea rdi, [rsp+0x5508]
    0x5a6c5cb: '488db42440120000',          # lea rsi, [rsp+0x1240]
    0x5a6c5d3: 'ba38040000',                # mov edx, 0x438
    # 0x5a08f80: input +0x428 -> engine value +0x458
    0x5a08f92: '4c8bb620040000',            # mov r14, [rsi+0x420]
    0x5a08f99: '4c8bbe28040000',            # mov r15, [rsi+0x428]
    0x5a08fc2: '4c89b42460040000',          # mov [rsp+0x460], r14    (value +0x450)
    0x5a08fd2: '4c89bc2468040000',          # mov [rsp+0x468], r15    (value +0x458)
    # 0x4f1b280: tracking switch and tail jump
    0x4f1b299: '807f2000',                  # cmp byte [rdi+0x20], 0
    0x4f1b2f5: '4889f7',                    # mov rdi, rsi
    0x4f1b2f8: '4889d6',                    # mov rsi, rdx
    # 0x4fc1660: read lock, Arc clone, unlock, slow-hold threshold
    0x4fc1677: '0fb687200b0000',            # movzx eax, byte [rdi+0xb20]
    0x4fc1692: '4c8da3a8060000',            # lea r12, [rbx+0x6a8]
    0x4fc16b8: 'b900ca9a3b',                # mov ecx, 1000000000
    0x4fc173c: '81bb2801000000ca9a3b',      # cmp dword [rbx+0x128], 1000000000
    0x4fc174c: '488b83080b0000',            # mov rax, [rbx+0xb08]
    0x4fc1753: 'f048ff00',                  # lock inc [rax]
    0x4fc176b: '48c7c0f0ffffff',            # mov rax, -0x10
    0x4fc1772: '488dbba8060000',            # lea rdi, [rbx+0x6a8]
    0x4fc1779: 'f0480fc107',                # lock xadd [rdi], rax
    0x4fc18ad: 'f20f10442468',              # movsd xmm0, [rsp+0x68]
    0x4fc18b3: 'f20f58442458',              # addsd xmm0, [rsp+0x58]
    0x4fc18df: '48b900c0780001000000',      # movabs rcx, 0x10078c000 (level mask)
    # wrappers: tag 2 -> lock inc counter, compare with box height
    0x5a055f2: '41833c2402',                # cmp dword [r12], 2
    0x5a055f9: '498b8c2458040000',          # mov rcx, [r12+0x458]
    0x5a05601: 'f048ff4110',                # lock inc [rcx+0x10]
    0x5a0561a: '4839c8',                    # cmp rax, rcx
    0x5a06e2a: '41833f02',                  # cmp dword [r15], 2
    0x5a06e30: '498b8f58040000',            # mov rcx, [r15+0x458]
    0x5a06e37: 'f048ff4110',                # lock inc [rcx+0x10]
    0x5a06e4f: '4839c8',                    # cmp rax, rcx
}
REFERENCES = (
    (0x5a6c322, b'\x48\x8d\x05', 7, NAME[0]),
    (0x5a6c353, b'\x4c\x8d\x05', 7, LOC_NODE),
    (0x5a6c364, b'\xe8', 5, TRACKED_READ),
    (0x5a6c5f8, b'\xe8', 5, LAYOUT_A_BUILDER),
    (0x4f1b30c, b'\xe9', 5, READ_BODY),
    (0x4f1bace, b'\xe8', 5, READ_BODY),
    (0x4fc18b9, b'\x66\x0f\x2e\x05', 8, THRESHOLD),
    (0x4fc17fe, b'\xf2\x0f\x5e\x05', 8, NANOS),
    (0x5a05623, b'\x4c\x8d\x0d', 7, LOC_ENGINE),
    (0x5a0563e, b'\xff\x15', 6, ASSERT_SLOT),
    (0x5a06e58, b'\x4c\x8d\x0d', 7, LOC_ENGINE),
    (0x5a06e73, b'\xff\x15', 6, ASSERT_SLOT),
)


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
    if read_va(data, NAME[0], len(NAME[1])) != NAME[1]:
        raise ValueError('fast_height name changed')
    threshold, = struct.unpack('<d', read_va(data, THRESHOLD, 8))
    nanos, = struct.unpack('<d', read_va(data, NANOS, 8))
    if (threshold, nanos) != (3.0, 1e9):
        raise ValueError('time constants changed')
    tracked_callers = direct_calls(data, TRACKED_READ)
    body_callers = direct_calls(data, READ_BODY)
    if tracked_callers != [0x5a6c364] or body_callers != [0x4f1bace]:
        raise ValueError('call census changed')
    if frame(fdes, 0x5a055f2) != WRAP_A or frame(fdes, 0x5a06e2a) != WRAP_B:
        raise ValueError('wrapper frames changed')
    node_loc = location(data, LOC_NODE)
    engine_loc = location(data, LOC_ENGINE)
    if engine_loc != ('l1/src/abci/engine.rs', 262, 17):
        raise ValueError('engine Location changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'tracked_read': {
            'fn': hex(TRACKED_READ),
            'direct_callers': [hex(v) for v in tracked_callers],
            'args': 'rdi=allocation+0x140, rsi=runner, rdx={0,%s %r,%d}, ecx=0, r8=%s %s:%d:%d'
                    % ((hex(NAME[0]), NAME[1].decode(), len(NAME[1]), hex(LOC_NODE)) + node_loc),
            'switch': 'byte [rdi+0x20] == 0 -> tail jump to %s; else thread-local 0x38-byte list, then call at 0x4f1bace'
                      % hex(READ_BODY),
        },
        'read_body': {
            'fn': hex(READ_BODY),
            'direct_callers': [hex(v) for v in body_callers],
            'lock': 'runner +0x6a8: +0x10 reader (slow path with 1000000000), released with xadd -0x10',
            'returns': 'clone of the Arc at runner +0xb08 (lock inc [rax]) = engine value +0x458',
            'timing': 'wait and hold in f64 seconds (nanos / %s); sum > %s enters a path gated by mask 0x10078c000'
                      % (nanos, threshold),
        },
        'shared_counter': {
            'builder': hex(BUILDER),
            'slow_input': 'tag word 2 at +0x0 (0x5a6c3b6), box +0x420, fresh {1,1,box+0x28} Arc at +0x428 dropped and replaced by the fast_height clone (0x5a6c3d6)',
            'copy': '0x438 bytes rsp+0x1240 -> rsp+0x5508, then %s moves input +0x428 to engine value +0x458' % hex(LAYOUT_A_BUILDER),
        },
        'wrappers': {
            'A': '%s: dword [engine+0x0] == 2 -> lock inc [[+0x458]+0x10], compare with box +0x28' % hex(WRAP_A),
            'B': '%s: same at 0x5a06e2a' % hex(WRAP_B),
            'mismatch': 'slot %s with Location %s %s:%d:%d' % ((hex(ASSERT_SLOT), hex(LOC_ENGINE)) + engine_loc),
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
    print('tracked read callers=%s' % result['tracked_read']['direct_callers'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
