#!/usr/bin/env python3
"""Bind the node #115 slow abci driver's receive loop (42nd stage).

Continues #6011 (the driver closure 0x5a34440 started as `node slow
abci_state driver`) and #6014 (the single unbounded send into the `slow abci
block` channel). This tool binds, inside the closure 0x5a34440:

1. start-up: `hardfork_hashes` (15 bytes) is read through 0x5647720; on the
   start, when byte [closure] == 0, the result is sent on a second channel ([closure+0x28]) via
   0x581a4f0, with the counter at [[closure+0x30]+0x10] incremented;
2. a `node_slow` group (9 bytes, 0.5) is built through slot 0x64ebbc8 ->
   0x51c9cb0 at rsp+0x2b8 (the three-observer builder of #5872);
3. the receive: [closure+0x80] is the channel Arc; the list pop 0x58189f0 runs
   on chan+0x1a0 / chan+0x80; an empty result (0x8000000000000001) registers
   the waker at chan+0x100 (slot 0x64e0518) and pops again; a closed channel
   is rx_closed byte chan+0x1b8 == 1 with the message word chan+0x1c0 < 2;
   a taken message subtracts 2 from chan+0x1c0;
4. the wait: the thread parks on [r14+0x18] with timeout 1e9 ns through slot
   0x64e73b8 (a blocking thread, not a task);
5. per message (0x58 bytes; first word 0x8000000000000000 ends the loop):
   - `lock dec [[closure+0x88]+0x10]` -- the counter the sender increments;
   - the wall clock 0x1629690 (slot 0x64e0990) is read; from the second message
     on, the gap since the last one (0x162a290, slot 0x64e0fc0) is turned into
     seconds, clamped to [0, 60.0] (+inf -> 0), and recorded with count 1 into
     the node_slow group through 0x1547530 (slot 0x64e1010), Location
     node/src/abci_latency_sampler.rs:60:41;
   - `get` through 0x4f19fa0 (node.rs:652:42), apply through 0x59edc50,
     `spawn_slow_abci_driver_apply_block` through 0x4e47900 (edx = 1),
     and on a result `spawn_slow_abci_driver_write_greeting` through 0x4f18bd0
     (node.rs:732:40);
   - the message's Vec of 0x28-byte items (an Arc at +0x20 each) is dropped.
6. no 5000 immediate and no read of the counter other than the decrement
   occurs in the closure.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-slow-abci-driver-recv-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DRIVER = (0x5a34440, 0x5a3539f)
POP = 0x58189f0
SEND2 = 0x581a4f0
SENDER_PUSH = 0x581a2d0
EMPTY = 0x8000000000000001
CLOSED = 0x8000000000000000

FIXED = {
    # start-up: hardfork_hashes read, one send on the second channel
    0x5a3446d: 'b90f000000',                    # mov ecx, 15
    0x5a34517: '803800',                        # cmp byte [rax], 0
    0x5a34554: '488b4830',                      # mov rcx, [rax+0x30]
    0x5a34558: 'f048ff4110',                    # lock inc [rcx+0x10]
    0x5a3455d: '488b5828',                      # mov rbx, [rax+0x28]
    0x5a3457e: '488d5002',                      # lea rdx, [rax+2]
    0x5a3458d: '488dbb80000000',                # lea rdi, [rbx+0x80]
    # node_slow group
    0x5a34685: 'ba09000000',                    # mov edx, 9
    # receive: pop, empty sentinel, waker, closed check, take
    0x5a34899: '4c8b7500',                      # mov r14, [rbp]          (chan Arc)
    0x5a3489d: '498daea0010000',                # lea rbp, [r14+0x1a0]
    0x5a348a4: '498d9e80000000',                # lea rbx, [r14+0x80]
    0x5a348d1: '48b80100000000000080',          # movabs rax, 0x8000000000000001
    0x5a348e4: '498dbe00010000',                # lea rdi, [r14+0x100]    (rx waker)
    0x5a34935: '4180beb801000001',              # cmp byte [r14+0x1b8], 1 (rx closed)
    0x5a3495b: '4883f802',                      # cmp rax, 2
    0x5a34a10: 'f04983aec001000002',            # lock sub [r14+0x1c0], 2
    0x5a34a24: 'f04983aec001000002',            # lock sub [r14+0x1c0], 2
    # park with a 1 s timeout
    0x5a34b56: 'b900ca9a3b',                    # mov ecx, 1000000000
    # per message: end sentinel, counter decrement
    0x5a34c9e: '48b80000000000000080',          # movabs rax, 0x8000000000000000
    0x5a34cb6: '488b8088000000',                # mov rax, [rax+0x88]
    0x5a34cbd: 'f048ff4810',                    # lock dec [rax+0x10]
    # gap: seconds, clamp [0, 60], record count 1
    0x5a34d1c: '83bc24880a000000',              # cmp dword [rsp+0xa88], 0 (first message)
    0x5a34d7d: 'f20f5fc1',                      # maxsd xmm0, xmm1
    0x5a34d89: '7404',                          # je (inf -> 0)
    0x5a34d97: 'f20f5dc1',                      # minsd xmm0, xmm1
    0x5a34d9b: 'be01000000',                    # mov esi, 1
    0x5a34de8: '48c744245003000000',            # mov qword [rsp+0x50], 3 (len "get")
    0x5a34e83: '48c78424f000000022000000',      # len 34
    0x5a34f08: 'ba01000000',                    # mov edx, 1 (blocking)
    0x5a34f74: '48c78424f800000025000000',      # len 37
}
REFERENCES = (
    # (va, prefix, length, target)
    (0x5a3445e, b'\x48\x8d\x15', 7, 0x93b070),   # "hardfork_hashes"
    (0x5a34472, b'\xe8', 5, 0x5647720),
    (0x5a3459c, b'\xe8', 5, SEND2),
    (0x5a3466e, b'\x48\x8d\x35', 7, 0x93b003),   # "node_slow"
    (0x5a3467d, b'\xf2\x0f\x10\x05', 8, 0x459490),
    (0x5a3468a, b'\xff\x15', 6, 0x64ebbc8),
    (0x5a348b6, b'\xe8', 5, POP),
    (0x5a34904, b'\xe8', 5, POP),
    (0x5a348f3, b'\xff\x15', 6, 0x64e0518),
    (0x5a34b5b, b'\xff\x15', 6, 0x64e73b8),
    (0x5a34d16, b'\xff\x15', 6, 0x64e0990),
    (0x5a34d37, b'\xff\x15', 6, 0x64e0fc0),
    (0x5a34d6d, b'\xf2\x0f\x5e\x05', 8, 0x458d50),
    (0x5a34d81, b'\x66\x0f\x2e\x05', 8, 0x459010),
    (0x5a34d8f, b'\xf2\x0f\x10\x05', 8, 0x459718),
    (0x5a34da8, b'\x48\x8d\x15', 7, 0x64a3648),
    (0x5a34daf, b'\xff\x15', 6, 0x64e1010),
    (0x5a34ddc, b'\x48\x8d\x05', 7, 0x93b00c),   # "get"
    (0x5a34e11, b'\x4c\x8d\x0d', 7, 0x64b8a20),
    (0x5a34e18, b'\xe8', 5, 0x4f19fa0),
    (0x5a34e49, b'\xe8', 5, 0x59edc50),
    (0x5a34e74, b'\x48\x8d\x0d', 7, 0x93b00f),
    (0x5a34f0d, b'\xe8', 5, 0x4e47900),
    (0x5a34f65, b'\x48\x8d\x0d', 7, 0x93b031),
    (0x5a34fac, b'\x48\x8d\x0d', 7, 0x64b8a38),
    (0x5a34fb3, b'\xe8', 5, 0x4f18bd0),
)
STRINGS = {
    0x93b070: b'hardfork_hashes',
    0x93b003: b'node_slow',
    0x93b00c: b'get',
    0x93b00f: b'spawn_slow_abci_driver_apply_block',
    0x93b031: b'spawn_slow_abci_driver_write_greeting',
}
SLOTS = {0x64ebbc8: 0x51c9cb0, 0x64e0518: 0x5ce91b0, 0x64e73b8: 0x5bb4670,
         0x64e0990: 0x1629690, 0x64e0fc0: 0x162a290, 0x64e1010: 0x1547530}
CONSTANTS = {0x459490: 0.5, 0x458d50: 1e9, 0x459010: float('inf'), 0x459718: 60.0}
LOCATIONS = {0x64a3648: ('node/src/abci_latency_sampler.rs', 60, 41),
             0x64b8a20: ('node/src/node.rs', 652, 42),
             0x64b8a38: ('node/src/node.rs', 732, 40)}


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def location(data, rel, va):
    ptr = rel.get(va)
    if ptr is None:
        raise ValueError(f'Location {va:#x} lost its relocation')
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, ptr, length).decode(), line, col


def gap_seconds(secs, nanos):
    """Model of 0x5a34d3d..0x5a34d97: seconds from the duration, clamped."""
    x = max(float(secs) + float(nanos) / 1e9, 0.0)
    x = 0.0 if x == float('inf') else x
    return min(60.0, x)


def driver_scan(data):
    """Inside the closure: 0x1388 immediates and every [reg+0x10] counter access."""
    base, code = text(data)
    body = code[DRIVER[0] - base:DRIVER[1] - base]
    imm5000 = [hex(DRIVER[0] + m.start()) for m in re.finditer(rb'\x88\x13\x00\x00', body)]
    incdec = [hex(DRIVER[0] + m.start()) for m in re.finditer(rb'\xf0\x48\xff[\x41\x48]\x10', body)]
    return imm5000, incdec


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')
    for va, value in CONSTANTS.items():
        if struct.unpack('<d', read_va(data, va, 8))[0] != value:
            raise ValueError(f'constant at {va:#x} changed')
    locs = {}
    for va, expect in LOCATIONS.items():
        got = location(data, rel, va)
        if got != expect:
            raise ValueError(f'Location {va:#x} changed')
        locs[hex(va)] = '%s:%d:%d' % got
    if not any(f['start'] == DRIVER[0] and f['end'] == DRIVER[1] for f in fdes):
        raise ValueError('driver FDE changed')
    pops = direct_calls(data, POP)
    if [v for v in pops if DRIVER[0] <= v < DRIVER[1]] != [0x5a348b6, 0x5a34904]:
        raise ValueError('pop census changed')
    if direct_calls(data, SENDER_PUSH) != [0x5a6fe24]:
        raise ValueError('sender push census changed')
    imm5000, incdec = driver_scan(data)
    samples = {'-1s': gap_seconds(-1, 0), '0.25s': gap_seconds(0, 250000000),
               '59.5s': gap_seconds(59, 500000000), '3600s': gap_seconds(3600, 0)}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'driver': {'fde': [hex(v) for v in DRIVER]},
        'startup': {
            'read': 'hardfork_hashes (15) via 0x5647720 -> rsp+0x2b8',
            'second_channel_send': 'at start, when byte [closure] == 0 (0x5a34517): [[closure+0x30]+0x10] += 1; chan [closure+0x28]; '
                                   'message word +0x1c0 += 2; push 0x581a4f0 on chan+0x80; wake chan+0x110',
            'group': 'node_slow (9), 0.5 via slot 0x64ebbc8 -> 0x51c9cb0 at rsp+0x2b8',
        },
        'receive': {
            'channel': '[closure+0x80]',
            'pop': '0x58189f0(chan+0x1a0, chan+0x80) at 0x5a348b6 and 0x5a34904 (after the waker)',
            'empty': hex(EMPTY) + ' -> register waker chan+0x100 via slot 0x64e0518 -> 0x5ce91b0, pop again',
            'closed': 'byte chan+0x1b8 == 1 and word chan+0x1c0 < 2 -> end',
            'taken': 'lock sub chan+0x1c0, 2',
            'wait': 'park on [r14+0x18] with 1e9 ns timeout via slot 0x64e73b8 -> 0x5bb4670',
            'pop_callers_outside_driver': [hex(v) for v in pops if not DRIVER[0] <= v < DRIVER[1]],
        },
        'per_message': {
            'size': '0x58 bytes; first word 0x8000000000000000 ends the loop (0x5a34cab -> 0x5a350c5)',
            'counter': 'lock dec [[closure+0x88]+0x10] at 0x5a34cbd',
            'gap': 'wall clock 0x1629690; from the 2nd message, duration 0x162a290 -> secs + nanos/1e9, '
                   'max 0, +inf -> 0, min 60.0; recorded count 1 via 0x1547530 into rsp+0x2b8',
            'gap_samples': samples,
            'apply': 'get (3) via 0x4f19fa0; 0x59edc50; spawn_slow_abci_driver_apply_block (34) via 0x4e47900 edx=1; '
                     'on a result spawn_slow_abci_driver_write_greeting (37) via 0x4f18bd0',
            'drop': 'Vec of 0x28-byte items, Arc at +0x20 each',
        },
        'locations': locs,
        'driver_scan': {'imm_5000': imm5000, 'lock_inc_dec_plus_0x10': incdec},
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
    print('scan', result['driver_scan'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
