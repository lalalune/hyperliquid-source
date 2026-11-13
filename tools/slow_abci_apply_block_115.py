#!/usr/bin/env python3
"""Bind the node #115 slow abci driver apply-block closure (44th stage).

Continues the slow-engine packets. The 43rd stage found that the slow driver
passes its parallel-collect result and the message to the name
`spawn_slow_abci_driver_apply_block` through `0x4e47900` with `edx = 1`. This
tool binds:

1. the wrapper: `0x4e47900` passes the 0x58-byte closure to `0x4f152a0`
   (Location `0x649ee50`), a lock-ordering-checked runner (`lock ordering
   violations`, `base/src/lock_id.rs`) whose direct calls into the body are
   `0x4f1532c` and `0x4f15ae2`;
2. the body `0x4fcac10`: it reads runner byte `+0xb40`, takes the write side
   of the lock word `+0x6a8` (0 -> 8), calls `0x59ec200` with the locked value
   at `+0x6b0`, releases (8 -> 0), and times the wait and the hold;
3. the step: `0x59ec200` (one direct caller, `0x4fcae48`) calls `0x56185e0`,
   which calls `0x5a04e40`, which calls the layout-A step `0x5a07ec0`; it also
   calls the `visor_abci_state` wrapper `0x5942b40`;
4. a discarded draw: when runner `+0xb40` is set and `+0x3f8` is 1, the body
   calls slot `0x64e1028` -> `0x1562120` (`random % edi == 0`) with
   `edi = 50` and does not read the result;
5. the recorder: slot `0x64eb1a8` -> `0x4770c90` is called with runner
   `+0xb20`, the name, `[runner+0x18]`, `[runner+0x20]` and the two times; it
   reads none of those arguments, counts calls per minute in the block
   `{lock, 60000, last minute, count}`, and records `profiled_rw_lock_increment`
   with (0.01, 0.05) through `0x4780430`.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target)

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-apply-block-115'
WRAPPER, RUNNER, BODY, STEP = 0x4e47900, 0x4f152a0, 0x4fcac10, 0x59ec200
RECORDER = (0x4770c90, 0x4770f33)
RECORDER_SHA256 = '01483c34ec1c0f3a95f2ea8576682b37cab1d5cd1ee72113c1bcbfe3c3a0900e'

FIXED = {
    0x5a34f08: 'ba01000000',                 # mov edx, 1
    0x4fcac4d: '410fb687400b0000',           # movzx eax, byte [r15+0xb40]
    0x4fcac68: '4181bf2801000000ca9a3b',     # cmp dword [r15+0x128], 1e9
    0x4fcac81: 'b908000000',                 # mov ecx, 8
    0x4fcac88: 'f0490fb18fa8060000',         # lock cmpxchg [r15+0x6a8], rcx  (0 -> 8)
    0x4fcae24: '498d8fb0060000',             # lea rcx, [r15+0x6b0]
    0x4fcae4f: 'b808000000',                 # mov eax, 8
    0x4fcae59: 'f0480fb10f',                 # lock cmpxchg [rdi], rcx       (8 -> 0)
    0x4fcaf3c: '4180bff803000001',           # cmp byte [r15+0x3f8], 1
    0x4fcaf46: 'bf32000000',                 # mov edi, 50
    0x4fcaf51: '488b842480000000',           # mov rax, [rsp+0x80]  (result of the draw not tested)
    0x4fcafaf: '498dbf200b0000',             # lea rdi, [r15+0xb20]
    0x1562290: '4885d2',                     # test rdx, rdx
    0x1562293: '0f94c0',                     # sete al
    0x4770e45: '488b4b08',                   # mov rcx, [rbx+0x8]   (divisor)
    0x4770e5b: '48f7f1',                     # div rcx
    0x4770e62: '4839c8',                     # cmp rax, rcx         (vs [rbx+0x10])
    0x4770e67: '48894310',                   # mov [rbx+0x10], rax
    0x4770ea3: '488b4318',                   # mov rax, [rbx+0x18]  (count)
}
REFERENCES = (
    (0x5a34e74, b'\x48\x8d\x0d', 7, 0x93b00f),
    (0x5a34f0d, b'\xe8', 5, WRAPPER),
    (0x4e47a6b, b'\x4c\x8d\x05', 7, 0x649ee50),
    (0x4e47a7c, b'\xe8', 5, RUNNER),
    (0x4f1532c, b'\xe8', 5, BODY),
    (0x4fcae48, b'\xe8', 5, STEP),
    (0x4fcaf4b, b'\xff\x15', 6, 0x64e1028),
    (0x4fcafd2, b'\xff\x15', 6, 0x64eb1a8),
    (0x59ec2a7, b'\x40\xe8', 6, 0x56185e0),
    (0x59ec380, b'\xe8', 5, 0x5942b40),
    (0x5618630, b'\xe8', 5, 0x5a04e40),
    (0x5a05fc9, b'\xe8', 5, 0x5a07ec0),
    (0x4770e6e, b'\x48\x8d\x05', 7, 0x7e1450),
    (0x4770e83, b'\x0f\x28\x05', 7, 0x453530),
    (0x4770e9e, b'\xe8', 5, 0x4780430),
)
STRINGS = {
    0x93b00f: b'spawn_slow_abci_driver_apply_block',
    0x93b031: b'spawn_slow_abci_driver_write_greeting',
    0x7e1450: b'profiled_rw_lock_increment',
    0x9198d0: b'lock ordering violations',
    0x444a53: b'base/src/lock_id.rs',
}
SLOTS = {0x64e1028: 0x1562120, 0x64eb1a8: RECORDER[0], 0x64e70a0: 0x47718a0}


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text_ in STRINGS.items():
        if read_va(data, va, len(text_)) != text_:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if rel.get(0x649ee50) != 0x432e59:
        raise ValueError('wrapper Location changed')
    lo, hi = RECORDER
    if frame(fdes, lo) != lo or hashlib.sha256(read_va(data, lo, hi - lo)).hexdigest() != RECORDER_SHA256:
        raise ValueError('recorder bytes changed')
    consts = struct.unpack('<dd', read_va(data, 0x453530, 16))
    if consts != (0.01, 0.05):
        raise ValueError('recorder constants changed')
    body_calls = direct_calls(data, BODY)
    step_calls = direct_calls(data, STEP)
    if body_calls != [0x4f1532c, 0x4f15ae2] or step_calls != [0x4fcae48]:
        raise ValueError('call census changed')
    for va in body_calls:
        if frame(fdes, va) != RUNNER:
            raise ValueError('body caller outside the runner')
    if frame(fdes, 0x4fcae48) != BODY or frame(fdes, 0x4fcafd2) != BODY:
        raise ValueError('body extent changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'wrapper': {
            'call': '%s -> %s (edx = 1, name %s)' % (hex(0x5a34f0d), hex(WRAPPER), STRINGS[0x93b00f].decode()),
            'runner': '%s -> %s (Location %s), lock-ordering checks (%s, %s)'
                      % (hex(0x4e47a7c), hex(RUNNER), hex(0x649ee50), STRINGS[0x9198d0].decode(),
                         STRINGS[0x444a53].decode()),
            'body_calls': [hex(v) for v in body_calls],
        },
        'body': {
            'fn': hex(BODY),
            'flag': 'runner +0xb40 (byte)',
            'write_lock': 'lock cmpxchg [runner+0x6a8] 0 -> 8 at %s; release 8 -> 0 at %s'
                          % (hex(0x4fcac88), hex(0x4fcae59)),
            'locked_value': 'runner +0x6b0 passed in rcx to %s at %s' % (hex(STEP), hex(0x4fcae48)),
            'times': 'wait (start -> acquire) and hold (acquire -> release) as f64 seconds',
            'discarded_draw': 'if +0xb40 and [runner+0x3f8] == 1: slot 0x64e1028 -> 0x1562120 '
                              '(random %% edi == 0) with edi = 50; result not read (%s)' % hex(0x4fcaf51),
            'recorder_call': 'slot 0x64eb1a8 -> %s with rdi = runner +0xb20, name, [runner+0x18], '
                             '[runner+0x20], wait, hold' % hex(RECORDER[0]),
        },
        'step_chain': ['0x4fcac10 -0x4fcae48-> 0x59ec200', '0x59ec200 -0x59ec2a8-> 0x56185e0',
                       '0x56185e0 -0x5618630-> 0x5a04e40', '0x5a04e40 -0x5a05fc9-> 0x5a07ec0 (layout A step)',
                       '0x59ec200 -0x59ec380-> 0x5942b40 (visor_abci_state wrapper)'],
        'step_direct_calls': [hex(v) for v in step_calls],
        'recorder': {
            'extent': [hex(lo), hex(hi)],
            'extent_sha256': RECORDER_SHA256,
            'block': '+0x0 lock byte, +0x8 divisor (60000), +0x10 last minute (525600 at build), +0x18 count',
            'minute': 'now_ms / [block+0x8]; store if greater than [block+0x10]',
            'record': '%s (0.01, 0.05) through %s' % (STRINGS[0x7e1450].decode(), hex(0x4780430)),
            'count': '[block+0x18] += 1, saturating',
            'unused_arguments': 'rsi, rdx, rcx and xmm0 are written before any read; xmm1 is not used',
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
    print('body calls=%d step calls=%d' % (len(result['wrapper']['body_calls']), len(result['step_direct_calls'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
