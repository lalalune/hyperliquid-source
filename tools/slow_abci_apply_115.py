#!/usr/bin/env python3
"""Bind the node #115 slow abci driver's thread-pool step 0x59edc50 (43rd stage).

The 42nd stage found that the slow driver (closure 0x5a34440) pops one
0x58-byte message per block, then calls 0x59edc50 and runs
`spawn_slow_abci_driver_apply_block` through the blocking helper 0x4e47900.
This tool binds:

1. the one call of 0x59edc50 (0x5a34e49): the pool is the slow runner's
   `+0xb48` (loaded as `[[closure+0x78]+0xb58]`, runner data at Arc +0x10) plus
   0x80; the input is the message at driver `rsp+0x100`; the fourth argument
   points at closure byte `+0xb0`;
2. 0x59edc50 itself: a thread-local worker check (fs:-0x488) selects one of
   three paths: no worker -> 0x4f0c910 with job vtable 0x64b7070; a worker of
   another pool (worker `+0x110` + 0x80 != pool) -> 0x59e9610; a worker of
   this pool -> inline: copy the closure byte, start an empty Vec
   {0, 8, 0}, take the message's slice (`+0x8` pointer, `+0x10` length) and
   call 0x3d9ce60, which tail-jumps to the vendored rayon collect 0x4301e90;
3. the outer parallel map: 0x3ec1b80 walks 0x28-byte items
   (`lea rsi,[r14+r14*4]; lea rsi,[r9+rsi*8]`); the fold 0x3713530 reads
   item `+0x20` as a pointer p, takes p's slice at `+0x18`/`+0x20`, and calls
   0x3d9d160 (tail jump to the second collect 0x4301ce0) with the same byte;
   each item yields a 0x18-byte Vec;
4. the inner parallel map: 0x4301ce0 allocates 0x70-byte outputs, its
   bridge 0x3ebdd10 walks 0x168-byte inputs, and the fold 0x3713300 calls
   0x36c2050 once per input; a returned word 0x1a3 stops the fold;
5. the driver passes the result with the name
   `spawn_slow_abci_driver_apply_block` (0x22 bytes) to 0x4e47900, edx = 1;
6. a census over the ten functions on this path: no RIP-relative f64 load
   and no direct call to the map inserts 0x51d4530 / 0x51d4df0 (#6010).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-slow-abci-apply-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

INSTALL = 0x59edc50
DRIVER = 0x5a34440
COLLECT_OUTER = (0x3d9ce60, 0x4301e90)
BRIDGE_OUTER = 0x3ec1b80
FOLD_OUTER = 0x3713530
COLLECT_INNER = (0x3d9d160, 0x4301ce0)
BRIDGE_INNER = 0x3ebdd10
FOLD_INNER = 0x3713300
ACTION_MAP = 0x36c2050
BLOCKING = 0x4e47900
COLD, CROSS, COLD_JOB = 0x4f0c910, 0x59e9610, 0x64b7070
MAP_INSERTS = (0x51d4530, 0x51d4df0)
NAME = (0x93b00f, b'spawn_slow_abci_driver_apply_block')
LOC_COLLECT = 0x6484208
LOC_CONSUMER = 0x6468dd0
LOC_TOO_MANY = 0x6467920

FIXED = {
    # driver: pop, closure byte pointer, pool, message, call
    0x5a34a24: 'f04983aec001000002',      # lock sub [r14+0x1c0], 2      (one message taken)
    0x5a346ad: '488b542410',              # mov rdx, [rsp+0x10]          (closure)
    0x5a346d9: '488d8ab0000000',          # lea rcx, [rdx+0xb0]
    0x5a346e0: '48898c2460010000',        # mov [rsp+0x160], rcx
    0x5a34e22: '488b4378',                # mov rax, [rbx+0x78]          (slow runner Arc)
    0x5a34e26: '488bb0580b0000',          # mov rsi, [rax+0xb58]         (runner +0xb48)
    0x5a34e2d: '4883ee80',                # sub rsi, -0x80
    0x5a34e39: '488d942400010000',        # lea rdx, [rsp+0x100]         (message)
    0x5a34e41: '488b8c2460010000',        # mov rcx, [rsp+0x160]
    0x5a34e83: '48c78424f000000022000000',  # name length 0x22
    0x5a34f08: 'ba01000000',              # mov edx, 1
    # 0x59edc50: three paths
    0x59edc60: '48c7c078fbffff',          # mov rax, -0x488
    0x59edc67: '64488b10',                # mov rdx, fs:[rax]            (worker)
    0x59edc6b: '4885d2',                  # test rdx, rdx
    0x59edc6e: '747a',                    # je cold
    0x59edc70: '488b8210010000',          # mov rax, [rdx+0x110]
    0x59edc77: '4883e880',                # sub rax, -0x80
    0x59edc7b: '4839f0',                  # cmp rax, rsi
    0x59edc7e: '0f858b000000',            # jne cross
    0x59edc84: '410fb600',                # movzx eax, byte [r8]
    0x59edc8c: '410f104608',              # movups xmm0, [r14+0x8]       (slice)
    0x59edc9a: '48c744241008000000',      # Vec ptr = 8 (empty)
    # collect entries
    0x3d9ce60: '4889f2488b7608',
    0x3d9d160: '4889f2488b7608',
    # outer bridge: 0x28-byte items
    0x3ec1bd3: '4b8d34b6',                # lea rsi, [r14+r14*4]
    0x3ec1bd7: '498d34f1',                # lea rsi, [r9+rsi*8]
    # outer fold
    0x3713570: '4b8d0476',                # lea rax, [r14+r14*2]         (0x18-byte outputs)
    0x3713579: '488d2cc1',                # lea rbp, [rcx+rax*8]
    0x3713594: '488b4b20',                # mov rcx, [rbx+0x20]          (item +0x20)
    0x3713598: '0fb600',                  # movzx eax, byte [rax]
    0x371359f: '0f104118',                # movups xmm0, [rcx+0x18]      (p slice)
    # inner
    0x4301d21: '496bef70',                # imul rbp, r15, 0x70
    0x3ebdd63: '4969f668010000',          # imul rsi, r14, 0x168
    0x371334d: '4d6bee70',                # imul r13, r14, 0x70
    0x37133b8: '66817c2420a301',          # cmp word [rsp+0x20], 0x1a3
    0x37133bf: '0f84ce000000',            # je end
}
CALLS = (
    # (call site, target)
    (0x5a34e49, INSTALL),
    (0x59edcc5, COLLECT_OUTER[0]),
    (0x59edd08, COLD),
    (0x59edd15, CROSS),
    (0x3ec1c0c, FOLD_OUTER),
    (0x37135da, COLLECT_INNER[0]),
    (0x3ebdd9e, FOLD_INNER),
    (0x37133b3, ACTION_MAP),
    (0x5a34f0d, BLOCKING),
)
JUMPS = ((0x3d9ce67, COLLECT_OUTER[1]), (0x3d9d167, COLLECT_INNER[1]))
LEAS = ((0x59edcf9, COLD_JOB), (0x5a34e74, NAME[0]),
        (0x4301fea, LOC_CONSUMER), (0x4302027, LOC_COLLECT), (0x3713667, LOC_TOO_MANY))


def rel32(data, va, opcode):
    raw = read_va(data, va, 5)
    if raw[0] != opcode:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def lea_rip(data, va):
    raw = read_va(data, va, 7)
    if raw[1] != 0x8d or raw[0] not in (0x48, 0x4c):
        raise ValueError(f'instruction at {va:#x} changed')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def location(data, rel, va):
    target = rel.get(va)
    if not target:
        raise ValueError(f'Location {va:#x} has no relocation')
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, target, length).decode(), line, col


def extent(fdes, va):
    hits = [f for f in fdes if f['start'] <= va < f['end']]
    if len(hits) != 1:
        raise ValueError(f'{va:#x} is not in exactly one FDE')
    return hits[0]['start'], hits[0]['end']


def census(data, fdes, starts):
    """RIP-relative movsd loads and direct calls to the #6010 map inserts, per function."""
    base, code = text(data)
    out = {}
    for start in starts:
        lo, hi = extent(fdes, start)
        seg = code[lo - base:hi - base]
        f64 = [m.start() for m in re.finditer(rb'\xf2[\x40-\x4f]?\x0f\x10[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', seg)]
        inserts = [i for i in range(len(seg) - 4) if seg[i] == 0xe8
                   and lo + i + 5 + struct.unpack_from('<i', seg, i + 1)[0] in MAP_INSERTS]
        out[hex(start)] = {'extent': [hex(lo), hex(hi)], 'f64_rip_loads': len(f64), 'map_insert_calls': len(inserts)}
    return out


def slot_calls_in(data, fdes, start):
    base, code = text(data)
    lo, hi = extent(fdes, start)
    seg = code[lo - base:hi - base]
    return sorted({lo + m.start() + 6 + struct.unpack_from('<i', seg, m.start() + 2)[0]
                   for m in re.finditer(rb'\xff\x15', seg) if m.start() + 6 <= len(seg)})


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if rel32(data, va, 0xe8) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, target in JUMPS:
        if rel32(data, va, 0xe9) != target:
            raise ValueError(f'jump at {va:#x} changed')
    for va, target in LEAS:
        if lea_rip(data, va) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, NAME[0], len(NAME[1])) != NAME[1]:
        raise ValueError('step name changed')
    if direct_calls(data, INSTALL) != [0x5a34e49]:
        raise ValueError('0x59edc50 caller census changed')
    if extent(fdes, 0x5a34e49)[0] != DRIVER:
        raise ValueError('driver extent changed')
    rel = relative_relocations(data)
    locs = {hex(va): location(data, rel, va) for va in (LOC_COLLECT, LOC_CONSUMER, LOC_TOO_MANY)}
    if not all(path.endswith(('rayon/src/iter/collect/mod.rs', 'rayon/src/iter/collect/consumer.rs'))
               for path, _, _ in locs.values()):
        raise ValueError('collect Locations changed')
    slots = slot_calls_in(data, fdes, ACTION_MAP)
    path = (INSTALL, COLLECT_OUTER[0], COLLECT_OUTER[1], BRIDGE_OUTER, FOLD_OUTER,
            COLLECT_INNER[0], COLLECT_INNER[1], BRIDGE_INNER, FOLD_INNER, BLOCKING)
    counts = census(data, fdes, path)
    if any(v['f64_rip_loads'] or v['map_insert_calls'] for v in counts.values()):
        raise ValueError('threshold census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'call': {
            'site': '0x5a34e49 in driver 0x5a34440 (only direct call of 0x59edc50)',
            'pool': 'rsi = [[closure+0x78]+0xb58] + 0x80 (slow runner +0xb48, runner at Arc +0x10)',
            'input': 'rdx = driver rsp+0x100, filled from the popped message (lock sub [chan+0x1c0], 2 at 0x5a34a24)',
            'byte': 'rcx -> closure +0xb0 (0x5a346d9)',
        },
        'install': {
            'no_worker': 'fs:-0x488 == 0 -> 0x4f0c910 with job 0x64b7070',
            'other_pool': '[worker+0x110] + 0x80 != pool -> 0x59e9610',
            'this_pool': 'Vec {0, 8, 0}; slice [msg+0x8]/[msg+0x10]; call 0x3d9ce60 -> jmp 0x4301e90',
            'returns': '[out+0x0..0x18] Vec, [out+0x18] = message pointer',
        },
        'outer_map': {
            'item_size': '0x28 (0x3ec1bd3)',
            'per_item': 'p = [item+0x20]; slice [p+0x18]/[p+0x20]; 0x3d9d160 -> jmp 0x4301ce0',
            'output_size': '0x18 per item (0x3713570)',
        },
        'inner_map': {
            'input_size': '0x168 (0x3ebdd63)',
            'output_size': '0x70 (0x4301d21, 0x371334d)',
            'per_input': '0x36c2050; word 0x1a3 ends the fold (0x37133b8)',
            'action_map_slot_calls': len(slots),
        },
        'apply': 'name %s (%d bytes) -> 0x4e47900, edx = 1' % (NAME[1].decode(), len(NAME[1])),
        'locations': {k: '%s:%d:%d' % v for k, v in locs.items()},
        'threshold_census': counts,
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
    print(f"action_map_slot_calls={result['inner_map']['action_map_slot_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
