#!/usr/bin/env python3
"""Bind the node #115 channel behind the slow driver's hardfork_hashes send (56th stage).

Continues #6037 (stage 55), which found that the slow abci driver closure
0x5a34440 sends a 0x28-byte {height, 32 bytes} message on [closure+0x28] when
the closure's first byte is 0. This tool binds:

1. where [closure+0x28] comes from: the builder 0x5a6cbc0 copies its 4th
   argument (0x78 bytes at r15) to closure +0x0..+0x78; both pollers pass a
   copy of their state +0x9d0 (0x2aed259 / 0x2cb8879); poller 0x2aeaef0 fills
   +0x9d0 from field +0x758 of a 0x7f0-byte value it awaits;
2. the channel type: an unbounded block-list channel with 0x28-byte slots and
   0x520-byte blocks (push 0x581a4f0); its four push sites and the sender /
   counter fields each one loads;
3. the matching pop 0x5819770: called only from two drop functions reached
   through relocations, so the live receive is not this copy; a second pop
   with the same block layout, 0x2ccf3d0, and its callers (networking
   boundary, not followed);
4. the 32 bytes: 0x452aab0 is the runtime's run-blocking-in-place helper
   (edx = 1); it calls the closure body 0x457cf60, a timed BLAKE3 that logs
   "computed l1 hash".

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, frame, read_va, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-hardfork-hashes-receiver-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

BUILDER, DRIVER = 0x5a6cbc0, 0x5a34440
PUSH, POP, POP2 = 0x581a4f0, 0x5819770, 0x2ccf3d0
BLOCKING, L1_HASH = 0x452aab0, 0x457cf60
WORKER_CALL = 0x54847aa

FIXED = {
    # builder: closure +0x0..+0x78 copied from arg 4 (r15), runner at +0x78, block chan +0x80
    0x5a6cd71: '4c89b424f80000',        # mov [rsp+0xf8], r14         (closure +0x78)
    0x5a6cd79: '410f1007',              # movups xmm0, [r15]          (closure +0x0)
    0x5a6cd7d: '410f104f10',            # movups xmm1, [r15+0x10]
    0x5a6cdd3: '498b5770',              # mov rdx, [r15+0x70]
    0x5a6cddf: '4c89a424000100',        # mov [rsp+0x100], r12        (closure +0x80)
    0x5a6cde7: '48898424080100',        # mov [rsp+0x108], rax        (closure +0x88)
    0x5a6ce24: 'bfb8000000',            # mov edi, 0xb8
    0x5a6ce43: 'bab8000000',            # mov edx, 0xb8
    # pollers: arg 4 = copy of state +0x9d0
    0x2aed259: '488d83d0090000',        # lea rax, [rbx+0x9d0]
    0x2aed2ea: '488d8c24e00300',        # lea rcx, [rsp+0x3e0]
    0x2cb8879: '488d83d0090000',        # lea rax, [rbx+0x9d0]
    0x2cb890a: '488d8c24300700',        # lea rcx, [rsp+0x730]
    # poller 0x2aeaef0: +0x9d0 from the awaited 0x7f0 value (+0x758)
    0x2aeca29: 'baf0070000',            # mov edx, 0x7f0
    0x2aecad9: '0f108424982e00',        # movups xmm0, [rsp+0x2e98]
    0x2aecaf9: '0f1183d0090000',        # movups [rbx+0x9d0], xmm0
    # push 0x581a4f0: block list, 0x520 blocks
    0x581a4fb: 'bb01000000',            # mov ebx, 1
    0x581a500: 'f0480fc15f08',          # lock xadd [rdi+8], rbx      (tail index)
    0x581a513: '482b8200050000',        # sub rax, [rdx+0x500]        (block start index)
    0x581a577: 'bf20050000',            # mov edi, 0x520              (new block)
    0x581a592: '4889a800050000',        # mov [rax+0x500], rbp
    # pop 0x5819770: same layout, 0x28-byte slot read
    0x5819784: '48398800050000',        # cmp [rax+0x500], rcx
    0x58197bb: '4c8b8110050000',        # mov r8, [rcx+0x510]         (ready bits)
    0x581988f: 'be20050000',            # mov esi, 0x520              (free block)
    0x58198f0: '488d1492',              # lea rdx, [rdx+rdx*4]        (slot * 5 * 8 = 0x28)
    0x58198f4: '4c8b44d020',            # mov r8, [rax+rdx*8+0x20]
    # second pop 0x2ccf3d0: same block layout
    0x2ccf506: 'be20050000',            # mov esi, 0x520
    0x2ccf51f: '488b9010050000',        # mov rdx, [rax+0x510]
    0x2ccf52e: '488d0c89',              # lea rcx, [rcx+rcx*4]
    0x2ccf532: '488b54c820',            # mov rdx, [rax+rcx*8+0x20]
    # push sites: sender / counter loads
    0x5a3455d: '488b5828',              # driver: mov rbx, [rax+0x28]
    0x5a34554: '488b4830',              # driver: mov rcx, [rax+0x30]
    0x5a6dc09: '4c8b7928',              # 0x5a6db30: mov r15, [rcx+0x28]
    0x5a6dc00: '488b5130',              # 0x5a6db30: mov rdx, [rcx+0x30]
    0x59ed32e: '498b5c2450',            # 0x59ec200: mov rbx, [r12+0x50]
    0x59ed324: '498b4c2458',            # 0x59ec200: mov rcx, [r12+0x58]
    0x5a6cae6: '488b1e',                # 0x5a6c8f0: mov rbx, [rsi]
    0x5a6cadd: '488b4e08',              # 0x5a6c8f0: mov rcx, [rsi+8]
    # l1 hash under block-in-place
    0x54847a5: 'ba01000000',            # mov edx, 1
    0x452aac4: '85d2',                  # test edx, edx
    0x452ac61: 'e8fa220500',            # call 0x457cf60
    0x457d14a: 'ba20000000',            # mov edx, 0x20
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a6ce51, b'\x48\x8d\x3d', 7, 0x93afe8),     # 'node slow abci_state driver'
    (0x5a6ce58, b'\x48\x8d\x0d', 7, 0x64b8a00),    # driver closure vtable
    (0x457cfae, b'\x0f\x10\x15', 7, 0x457ae0),     # BLAKE3 IV
    (0x457d313, b'\x48\x8d\x05', 7, 0x431bda),     # 'computed l1 hash: '
    (0x457d3c3, b'\x48\x8d\x3d', 7, 0x43df63),     # WARN template
)
RELOCATIONS = {0x64df510: 0x160b3a0, 0x64df518: 0x160bcd0,          # BLAKE3 update / finalize slots
               0x64e7230: 0x5a8b510, 0x64e72f8: 0x5a8d5b0}          # channel drop functions
STRINGS = {
    0x93afe8: b'node slow abci_state driver',
    0x431bdb: b'computed l1 hash: ',
    0x7d3def: b'can call blocking only when running on the multi-threaded runtime',
    0x94cd2d: b'closure claimed permanent executor',
}
PUSH_SITES = {0x59ed370: 0x59ec200, 0x5a3459c: DRIVER, 0x5a6cb1d: 0x5a6c8f0, 0x5a6dc49: 0x5a6db30}


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def block_frees(data, fdes):
    """Functions holding `mov esi, 0x520` (free a 0x520-byte block)."""
    base, code = text(data)
    return sorted({frame(fdes, base + m.start()) for m in re.finditer(rb'\xbe\x20\x05\x00\x00', code)})


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, s in STRINGS.items():
        if read_va(data, va, len(s)) != s:
            raise ValueError(f'string at {va:#x} changed')

    pushes = direct_calls(data, PUSH)
    if {va: frame(fdes, va) for va in pushes} != PUSH_SITES:
        raise ValueError('push census changed')
    pop_callers = [frame(fdes, va) for va in direct_calls(data, POP)]
    pop2_callers = sorted({frame(fdes, va) for va in direct_calls(data, POP2)})
    if direct_calls(data, BLOCKING) and WORKER_CALL not in direct_calls(data, BLOCKING):
        raise ValueError('worker no longer calls the blocking helper')
    callers_db30 = sorted({frame(fdes, va) for va in direct_calls(data, 0x5a6db30)})
    callers_c8f0 = sorted({frame(fdes, va) for va in direct_calls(data, 0x5a6c8f0)})

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'sender_origin': {
            'builder': hex(BUILDER) + ': closure +0x0..+0x78 = arg 4 (r15) bytes 0..0x78; +0x78 runner; '
                       '+0x80/+0x88 slow abci block channel and counter; 0xb8 closure boxed, vtable 0x64b8a00',
            'closure_sender': '+0x28 (driver 0x5a3455d), counter +0x30 (0x5a34554)',
            'pollers': {'0x2aeaef0': 'rcx = copy of state +0x9d0 (0x2aed259 → 0x2aed2ea)',
                        '0x2cb6500': 'rcx = copy of state +0x9d0 (0x2cb8879 → 0x2cb890a)'},
            'poller_state': '0x2aeaef0 stores +0x9d0 from rsp+0x2e98 (0x2aecaf9) = field +0x758 of the 0x7f0-byte '
                            'awaited value copied at 0x2aeca29',
            'so': 'sender = poller state +0x9f8, counter = +0xa00',
        },
        'channel': {
            'push': hex(PUSH) + ': tail index xadd [chan+8]; blocks of 0x520 bytes (32 slots x 0x28), '
                    'start index +0x500, next +0x508, ready bits +0x510, observed tail +0x518',
            'push_sites': {hex(k): hex(v) for k, v in sorted(PUSH_SITES.items())},
            'sender_fields': {'0x5a34440': '[closure+0x28] / +0x30', '0x5a6db30': '[rcx+0x28] / +0x30',
                              '0x59ec200': '[r12+0x50] / +0x58', '0x5a6c8f0': '[rsi] / +0x8'},
            'callers_0x5a6db30': [hex(v) for v in callers_db30],
            'callers_0x5a6c8f0': [hex(v) for v in callers_c8f0],
        },
        'receive': {
            'pop': hex(POP) + ' (same block layout, 0x28-byte slot read at +rdx*8)',
            'pop_callers': [hex(v) for v in pop_callers],
            'pop_callers_reached_by': {'0x64e7230': '0x5a8b510', '0x64e72f8': '0x5a8d5b0'},
            'second_pop': hex(POP2),
            'second_pop_callers': [hex(v) for v in pop2_callers],
            'functions_freeing_0x520_blocks': [hex(v) for v in block_frees(data, fdes)],
        },
        'l1_hash': {
            'blocking_helper': hex(BLOCKING) + ': edx != 0 enters blocking mode; then calls ' + hex(L1_HASH)
                               + ' (0x452ac61)',
            'worker_call': hex(WORKER_CALL) + ' with edx = 1 (0x54847a5)',
            'body': hex(L1_HASH) + ': BLAKE3 IV 0x457ae0, update slot 0x64df510 → 0x160b3a0, finalize slot '
                    '0x64df518 → 0x160bcd0, 32-byte output; WARN "computed l1 hash: " with height and elapsed',
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
    print(f"pushes={len(result['channel']['push_sites'])} pop_callers={len(result['receive']['pop_callers'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
