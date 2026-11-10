#!/usr/bin/env python3
"""Bind who sends into the node #115 'slow abci block' handle (41st stage).

The 40th stage found that both pollers call 0x5a6cbc0 (slot 0x64e7458),
which builds a 'slow abci block' handle and starts the 'node slow
abci_state driver' thread. This tool binds:

1. the handle 0x5a6cbc0 returns at [rdi]: +0x0 a channel Arc allocated
   0x200 bytes with alignment 2^7, +0x8 a {1, 1, 0} counter Arc, +0x10/+0x18
   the name 'slow abci block' (15 bytes), +0x20 the number 5000;
2. both pollers keep it at state +0xaf0..+0xb18 and move those 0x28 bytes
   into the 0x718-byte 'node handle client blocks' task (vtable 0x64471a0),
   whose body 0x2a92960 passes &handle (closure +0x6e0) as rcx to
   0x5a6e1e0 through slot 0x64e71d0;
3. the one send into the handle's channel: 0x5a6e1e0 holds the channel at
   [rsp+0x110] and chan+0x80 at [rsp+0x398]; at 0x5a6fd83 it increments
   counter +0x10, takes a permit on the word at chan+0x1c0 (bit 0 = closed,
   +2 per message, -2 = overflow path), pushes through 0x581a2d0 on
   chan+0x80 (the only direct call of 0x581a2d0) and wakes the receiver
   through the word at chan+0x110; on a closed channel it drops the message
   and decrements the counter. Nothing in this path compares against 5000;
4. the observer groups built by 0x51c9cb0 (slot 0x64ebbc8, #5872): the
   sender passes 'node_fast' and 0.35, the driver 'node_slow' and 0.5;
5. the driver's own send on a second channel (closure +0x28, counter
   closure +0x30) with the same permit shape, through 0x581a4f0.

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
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, read_va,
                                 relative_relocations, rip_target, text)

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-block-sender-115'

BUILDER, SENDER, TASK_BODY, DRIVER, GROUPS = 0x5a6cbc0, 0x5a6e1e0, 0x2a92960, 0x5a34440, 0x51c9cb0
PUSH, DRIVER_PUSH = 0x581a2d0, 0x581a4f0
SLOTS = {0x64e7458: BUILDER, 0x64e71d0: SENDER, 0x64ebbc8: GROUPS,
         0x64471b8: TASK_BODY}
STRINGS = {
    0x93afd9: b'slow abci block',
    0x605bc9: b'node handle client blocks',
    0x60f021: b'node handle client blocks',
    0x93b10e: b'node_fast',
    0x93b003: b'node_slow',
    0x44cbea: b'\xc0\x0f_block_duration',
    0x430c15: b'\xc0\x12_backlog_from_node',
    0x440603: b'\xc0\x16_begin_block_to_commit',
    0x442559: b'\xc0\x0c_block_times',
}
F64 = {0x458f50: 0.35, 0x459490: 0.5}

FIXED = {
    # builder 0x5a6cbc0: channel allocation and the returned handle
    0x5a6ccca: 'bf00020000',            # mov edi, 0x200
    0x5a6cccf: 'be07000000',            # mov esi, 7 (alignment 2^7)
    0x5a6cd5f: '48c74424580f000000',    # mov qword [rsp+0x58], 15 (name length)
    0x5a6cd68: '48c744246088130000',    # mov qword [rsp+0x60], 5000
    0x5a6ce72: '49894520',              # mov [r13+0x20], rax (5000)
    0x5a6ce80: '410f114d10',            # movups [r13+0x10], xmm1 (name)
    0x5a6ce85: '410f114500',            # movups [r13+0x0], xmm0 (channel, counter)
    # poller 0x2aeaef0: handle at state +0xaf0, moved into the task closure
    0x2aecf7e: '4c8da3f00a0000',        # lea r12, [rbx+0xaf0] (rdi of the builder)
    0x2aee2dd: 'f30f6f83f00a0000',      # movdqu xmm0, [rbx+0xaf0]
    0x2aee2e5: 'f30f6f8b000b0000',      # movdqu xmm1, [rbx+0xb00]
    0x2aee2ff: '488b83100b0000',        # mov rax, [rbx+0xb10]
    0x2aee31d: 'bf18070000',            # mov edi, 0x718 (closure size)
    0x2aee358: 'be19000000',            # mov esi, 25 (name length)
    # poller 0x2cb6500: the same move
    0x2cb980d: 'f30f6f83f00a0000',
    0x2cb9815: 'f30f6f8b000b0000',
    0x2cb982f: '488b83100b0000',
    0x2cb9888: 'be19000000',
    # task body 0x2a92960
    0x2a92994: '0f1087e0060000',        # movups xmm0, [rdi+0x6e0] (handle)
    0x2a929b7: '4889e1',                # mov rcx, rsp (&handle copy)
    # sender 0x5a6e1e0
    0x5a6e1f4: '4989cd',                # mov r13, rcx
    0x5a6e293: '498b5d00',              # mov rbx, [r13+0x0] (channel)
    0x5a6e297: '498b4508',              # mov rax, [r13+0x8] (counter)
    0x5a6e2a3: '488d8380000000',        # lea rax, [rbx+0x80]
    0x5a6e2eb: '48899c2410010000',      # mov [rsp+0x110], rbx
    0x5a6fd83: '488b842410020000',      # mov rax, [rsp+0x210] (counter)
    0x5a6fd8b: 'f048ff4010',            # lock inc qword [rax+0x10]
    0x5a6fd90: '488b86c0010000',        # mov rax, [rsi+0x1c0]
    0x5a6fda0: 'a801',                  # test al, 1 (closed)
    0x5a6fda8: '4883f8fe',              # cmp rax, -2 (overflow)
    0x5a6fdb2: '488d5002',              # lea rdx, [rax+2]
    0x5a6fdb6: 'f0480fb196c0010000',    # lock cmpxchg [rsi+0x1c0], rdx
    0x5a6fe12: '488bbc2498030000',      # mov rdi, [rsp+0x398] (chan+0x80)
    0x5a6fe43: '4883c902',              # or rcx, 2
    0x5a6fe47: 'f0480fb18a10010000',    # lock cmpxchg [rdx+0x110], rcx (wake)
    0x5a6ff16: '488b842410020000',      # mov rax, [rsp+0x210]
    0x5a6ff1e: 'f048ff4810',            # lock dec qword [rax+0x10] (closed: drop)
    # driver 0x5a34440: its own send on closure +0x28 / +0x30
    0x5a34554: '488b4830',              # mov rcx, [rax+0x30] (counter)
    0x5a34558: 'f048ff4110',            # lock inc qword [rcx+0x10]
    0x5a3455d: '488b5828',              # mov rbx, [rax+0x28] (channel)
    0x5a34561: '488b83c0010000',        # mov rax, [rbx+0x1c0]
    0x5a3457e: '488d5002',              # lea rdx, [rax+2]
    0x5a3458d: '488dbb80000000',        # lea rdi, [rbx+0x80]
    0x5a345f3: 'f048ff4910',            # lock dec qword [rcx+0x10]
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a6cd53, b'\x48\x8d\x0d', 7, 0x93afd9),
    (0x2aed2f5, b'\xff\x15', 6, 0x64e7458),
    (0x2aee34a, b'\x48\x8d\x3d', 7, 0x605bc9),
    (0x2aee351, b'\x48\x8d\x0d', 7, 0x64471a0),
    (0x2aee360, b'\xff\x15', 6, 0x64e1750),
    (0x2cb987a, b'\x48\x8d\x3d', 7, 0x60f021),
    (0x2cb9881, b'\x48\x8d\x0d', 7, 0x64471a0),
    (0x2a929ba, b'\xff\x15', 6, 0x64e71d0),
    (0x5a6e20e, b'\x48\x8d\x35', 7, 0x93b10e),
    (0x5a6e21d, b'\xf2\x0f\x10\x05', 8, 0x458f50),
    (0x5a6e22a, b'\xff\x15', 6, 0x64ebbc8),
    (0x5a6fe24, b'\xe8', 5, PUSH),
    (0x5a3466e, b'\x48\x8d\x35', 7, 0x93b003),
    (0x5a3467d, b'\xf2\x0f\x10\x05', 8, 0x459490),
    (0x5a3468a, b'\xff\x15', 6, 0x64ebbc8),
    (0x5a3459c, b'\xe8', 5, DRIVER_PUSH),
)


def slot_calls(data, slot):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(rb'\xff\x15', code)
            if m.start() + 6 <= len(code) and base + m.start() + 6 + struct.unpack_from('<i', code, m.start() + 2)[0] == slot]


def extent(fdes, va):
    for f in fdes:
        if f['start'] <= va < f['end']:
            return f['start'], f['end']
    raise ValueError(f'{va:#x} has no FDE')


def r13_disp8_reads(data, lo, hi, disp):
    """mov r64, [r13+disp8] (REX.WB 49/4d 8b, mod=01, rm=101) inside [lo, hi)."""
    code = read_va(data, lo, hi - lo)
    out = []
    for m in re.finditer(rb'[\x49\x4d]\x8b', code):
        i = m.start()
        if i + 4 <= len(code) and code[i + 2] & 0xc7 == 0x45 and code[i + 3] == disp:
            out.append(lo + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, raw in STRINGS.items():
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'string at {va:#x} changed')
    for va, value in F64.items():
        if struct.unpack('<d', read_va(data, va, 8))[0] != value:
            raise ValueError(f'constant at {va:#x} changed')

    push_calls = direct_calls(data, PUSH)
    if push_calls != [0x5a6fe24]:
        raise ValueError('push census changed')
    builder_calls = slot_calls(data, 0x64e7458)
    sender_calls = slot_calls(data, 0x64e71d0)
    group_calls = slot_calls(data, 0x64ebbc8)
    if builder_calls != [0x2aed2f5, 0x2cb8915] or sender_calls != [0x2a92960 + 0x5a] \
            or group_calls != [0x5a3468a, 0x5a6e22a]:
        raise ValueError('slot census changed')
    sender = extent(fdes, SENDER)
    capacity_reads = r13_disp8_reads(data, sender[0], sender[1], 0x20)
    if capacity_reads:
        raise ValueError('sender now reads handle +0x20')
    if read_va(data, sender[0], sender[1] - sender[0]).find(struct.pack('<I', 5000)) != -1:
        raise ValueError('sender now holds the immediate 5000')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'handle': {
            'builder': hex(BUILDER) + ' (slot 0x64e7458), called at ' + ', '.join(hex(v) for v in builder_calls),
            '+0x0': 'channel Arc: allocation 0x200 bytes, alignment 2^7 (0x5a6ccca, 0x5a6cccf)',
            '+0x8': 'counter Arc {1, 1, 0}; +0x10 counts queued messages',
            '+0x10': 'name %r (0x93afd9, 15 bytes)' % STRINGS[0x93afd9].decode(),
            '+0x20': '5000 (0x5a6cd68 -> 0x5a6ce72)',
        },
        'pollers': {
            'state_offset': '+0xaf0..+0xb18 (lea r12, [rbx+0xaf0] at 0x2aecf7e is the builder rdi)',
            'move': '0x28 bytes into a 0x718-byte closure at +0x6e0 (0x2aee2dd..0x2aee306; 0x2cb980d..0x2cb982f)',
            'task': '%r, vtable 0x64471a0 (+0x18 -> %s), spawned through slot 0x64e1750'
                    % (STRINGS[0x605bc9].decode(), hex(TASK_BODY)),
            'task_body': hex(TASK_BODY) + ': rcx = &handle copy, call slot 0x64e71d0 -> ' + hex(SENDER),
        },
        'send': {
            'function': hex(SENDER) + ' %s..%s' % tuple(hex(v) for v in sender),
            'site': '0x5a6fd83..0x5a6fe24 (reached from two paths)',
            'steps': [
                'counter +0x10 += 1 (0x5a6fd8b)',
                'permit word chan+0x1c0: bit 0 set -> closed path; value -2 -> overflow path; else cmpxchg +2',
                'push 0x581a2d0(rdi = chan+0x80, rsi = message) — the only direct call of 0x581a2d0',
                'wake: or 2 into chan+0x110, then call the stored waker at chan+0x100/+0x108',
                'closed: drop the message, counter +0x10 -= 1 (0x5a6ff1e)',
            ],
            'capacity_check': 'none: no [r13+0x20] read and no immediate 5000 in the sender',
            'message': 'Vec of 0x28-byte elements (cap, ptr, len) followed by 0x40 bytes, at [rsp+0x60]',
        },
        'observer_groups': {
            'builder': hex(GROUPS) + ' (slot 0x64ebbc8; #5872): {name}_block_duration, {name}_backlog_from_node, '
                                     '{name}_begin_block_to_commit, writer {name}_block_times',
            'sender': "'node_fast', 0.35 (0x5a6e22a)",
            'driver': "'node_slow', 0.5 (0x5a3468a)",
        },
        'driver_send': '0x5a34554..0x5a3459c: closure +0x30 counter, +0x28 channel, same permit shape, push 0x581a4f0',
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
    generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('slow abci block: one send site 0x5a6fd83, push 0x581a2d0 x1')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
