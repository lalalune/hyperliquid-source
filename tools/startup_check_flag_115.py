#!/usr/bin/env python3
"""Bind the node #115 startup check flag source, the .lz4 line-count branch and the
second line-count caller (seventy-fifth RE-008 stage).

Continues #6071. The startup state machine 0x2b41b70 runs the replica_cmds height
check only when bit 0 of its future byte +0x0 is clear and byte +0x1 is 1. This
tool binds where those two bytes come from:

1. the parents 0x2ae41e0 / 0x2cde430 store a mode byte at +0x248 (2 for subcommand
   tag 2, 1 for tag 3; #5902/#5908) right after the 0x28-byte flag struct they copy
   to +0x220, and pass +0x220 as the poller state;
2. poller 0x2aeaef0 copies its state +0x28..+0x38 to +0x38 on entry, folds +0x38..
   into the setter argument at +0x90 (+0x28 = mode, +0x29 = next byte), carries the
   0x40-byte argument +0x90 -> +0xd8 -> +0x118 -> +0xae8, and copies +0xb10 (16
   bytes, i.e. argument +0x28) to the startup caller state at +0x1728;
3. the startup caller 0x2af0660 returns early when its byte +0x0 is 2, otherwise
   builds the startup future with +0x0 = that byte and +0x1.. = its bytes +0x1..;
4. 0x2b41b70 takes the join path when bit 0 of +0x0 is set and tests +0x1 == 1
   for the replica_cmds check only on the other path.

It also binds the .lz4 suffix branch of the line count 0x1500e50 (it forces the
shared lazy cell 0x64f01c0 and re-enters the same 'wc -l' path) and the second
line-count caller 0x1563bc0 (base/src/u.rs:388, then a '{}.tolerance' path).

The captured binary is not executed. Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
from freeze_snapshot_115 import read_va

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-startup-check-flag-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LAZY_CELL, LAZY_STATE, LAZY_INIT = 0x64f01c0, 0x64f01d8, 0x1568de0
LINE_COUNT_SLOT, LINE_COUNT = 0x64e0958, 0x1500e50
SECOND_SLOT, SECOND = 0x64e1218, 0x1563bc0
TOLERANCE_SLOT, TOLERANCE_FN = 0x64e09d8, 0x1502320
CHECK_SLOT = 0x64e7720
LOC_388, LOC_391 = 0x63fe4b0, 0x63fe4c8

FIXED = {
    # parents: mode byte after the 0x28-byte flag copy, poller state = +0x220
    0x2ae4604: 'c6834802000002',        # mov byte [rbx+0x248], 2   (tag 2)
    0x2ae461d: '4c8db320020000',        # lea r14, [rbx+0x220]
    0x2ae5469: 'c6834802000001',        # mov byte [rbx+0x248], 1   (tag 3)
    0x2cde6d0: '41c6854802000002',      # mov byte [r13+0x248], 2
    0x2cdf567: '41c6854802000001',      # mov byte [r13+0x248], 1
    # poller 0x2aeaef0: +0x28.. -> +0x38.. on entry
    0x2aeaf65: '0f104328',
    0x2aeaf69: '0f114338',
    # state +0x38.. -> setter argument +0x28.. (rsp+0x3e3 -> rsp+0x180 -> +0xb5)
    0x2aebb0a: '488d4338',
    0x2aebb16: '0f1000',
    0x2aebb19: '0f118424e3030000',
    0x2aebb2f: '0f108424e0030000',
    0x2aebb37: '0f298424800100',
    0x2aebb3f: '4c8dab90000000',        # lea r13, [rbx+0x90]  (setter argument)
    0x2aebb73: '0f288424800100',
    0x2aebb7b: '0f1183b5000000',        # movups [rbx+0xb5], xmm0
    # argument +0x90 -> +0xd8 -> +0x118 -> +0xae8
    0x2aebbaa: '488d83d8000000',
    0x2aebc05: 'f30f6f00',
    0x2aebc1d: 'f30f7f8318010000',
    0x2aebde4: '4c8dabe80a0000',        # lea r13, [rbx+0xae8]
    0x2aebe97: 'f30f6f8318010000',
    0x2aebf45: '410f114500',
    # +0xb10 (argument +0x28) -> startup caller state +0x1728
    0x2aebfb3: 'f30f6f83100b0000',
    0x2aebfbb: '660f7f842420030000',
    0x2aec10d: '660f6f842420030000',
    0x2aec116: 'f30f7f8328170000',
    0x2aec13a: '4c8db328170000',
    # second poller 0x2cb6500 same copy
    0x2cb75d3: 'f30f6f83100b0000',
    0x2cb7736: 'f30f7f8328170000',
    # startup caller 0x2af0660: mode 2 returns early; else future +0x0 / +0x1..
    0x2af06c2: '0fb613',
    0x2af06d9: '80fa02',
    0x2af07ef: '488b7b01',
    0x2af0818: '4c8d6328',
    0x2af081c: '885328',
    0x2af082f: '48895329',
    0x2af087d: '410f100c24',
    0x2af09e7: '660f6f8424a0050000',
    0x2af09f0: '660f7f8424f0050000',
    0x2af0a30: 'ba58110000',
    # second caller 0x2cbbbe0 same mode test
    0x2cbbc47: '0fb60b',
    0x2cbbc5e: '80f902',
    # 0x2b41b70: bit 0 of +0x0 picks the join path; +0x1 == 1 gates the check
    0x2b41bae: '440fb66301',
    0x2b41bcd: 'f60301',
    0x2b41bd0: '0f8454010000',
    0x2b41d32: '4180fc01',
    0x2b41d36: '0f8593010000',
    # line count: '.lz4' suffix forces the lazy cell, then re-enters the wc path
    0x1500e71: '817c37fc2e6c7a34',
    0x1500e79: '750e',
    0x1501268: 'e91cfcffff',
}
REFERENCES = (
    (0x2ae4627, b'\xe8', 5, 0x2aeaef0),
    (0x2cde6f4, b'\xe8', 5, 0x2cb6500),
    (0x2af0a5f, b'\xe8', 5, 0x2b41b70),
    (0x2b41d3c, b'\xff\x15', 6, CHECK_SLOT),
    (0x1500e7b, b'\x8b\x05', 6, LAZY_STATE),
    (0x150121e, b'\x48\x8d\x05', 7, LAZY_CELL),
    (0x150125c, b'\xff\x15', 6, 0x64df9f0),
    (0x1500e89, b'\x48\x8d\x05', 7, 0x4659f2),
    (0x1500f1a, b'\xff\x15', 6, 0x64e0960),
    (0x1563bd2, b'\x8b\x05', 6, LAZY_STATE),
    (0x1563be9, b'\x48\x8d\x15', 7, LOC_388),
    (0x1563bf0, b'\xff\x15', 6, LINE_COUNT_SLOT),
    (0x1563c1d, b'\x48\x8d\x35', 7, 0x4388e5),
    (0x1563c3e, b'\x48\x8d\x0d', 7, LOC_391),
    (0x1563c4d, b'\xff\x15', 6, TOLERANCE_SLOT),
    (0x2c7da78, b'\xff\x15', 6, SECOND_SLOT),
)


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def location(data, va):
    _, length, line, col = struct.unpack('<QQII', read_va(data, va, 24))
    return length, line, col


def scan(data):
    """One pass over .text: slot calls, and RIP-relative refs into the lazy cell."""
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, code = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    slots = {LINE_COUNT_SLOT: [], SECOND_SLOT: [], TOLERANCE_SLOT: []}
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code):
            tgt = base + i + 6 + struct.unpack_from('<i', code, i + 2)[0]
            if tgt in slots:
                slots[tgt].append(base + i)
    state_reads = 0
    for m in re.finditer(rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == LAZY_STATE:
            state_reads += 1
    return slots, state_reads


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in ((LINE_COUNT_SLOT, LINE_COUNT), (SECOND_SLOT, SECOND), (TOLERANCE_SLOT, TOLERANCE_FN),
                         (LAZY_CELL, LAZY_INIT)):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if read_va(data, 0x4659f2, 4) != b'wc-l' or read_va(data, 0x4388e5, 12) != b'\xc0\n.tolerance':
        raise ValueError('strings changed')
    if struct.pack('<I', 0x347a6c2e) != b'.lz4':
        raise ValueError('suffix constant changed')
    loc388, loc391 = location(data, LOC_388), location(data, LOC_391)
    if loc388 != (13, 388, 11) or loc391 != (13, 391, 29) or read_va(data, 0x442e9e, 13) != b'base/src/u.rs':
        raise ValueError('Location records changed')
    slots, state_reads = scan(data)
    starts = sorted(f['start'] for f in fdes)
    ends = {f['start']: f['end'] for f in fdes}

    def frame(va):
        s = starts[bisect.bisect_right(starts, va) - 1]
        if not s <= va < ends[s]:
            raise ValueError(f'{va:#x} has no FDE')
        return s
    second_callers = [[hex(v), hex(frame(v))] for v in slots[SECOND_SLOT]]
    line_callers = [[hex(v), hex(frame(v))] for v in slots[LINE_COUNT_SLOT]]
    if second_callers != [['0x2c7da78', '0x2c7d950']] or [c[1] for c in line_callers] != ['0x1563bc0', '0x595b520']:
        raise ValueError('call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'flag_chain': [
            'parents 0x2ae41e0 / 0x2cde430: flag struct -> +0x220, mode byte +0x248 = 2 (tag 2) or 1 (tag 3); '
            'poller state = +0x220',
            'poller 0x2aeaef0 entry: state +0x28..+0x38 -> +0x38..+0x48 (0x2aeaf65)',
            'setter argument +0x90: +0x25..+0x35 from rsp+0x3e0, whose +0x3 is state +0x38 -> argument +0x28 = mode, '
            '+0x29 = state +0x39 (= parent +0x249)',
            'argument +0x90 -> +0xd8 -> +0x118 -> +0xae8; +0xb10 (16 bytes) -> rsp+0x320 -> +0x1728 '
            '(startup caller state); same +0xb10 -> +0x1728 copy in poller 0x2cb6500',
            'startup caller 0x2af0660 (and 0x2cbbbe0): byte +0x0 == 2 skips the startup future; else future '
            '+0x0 = byte +0x0, +0x1.. = bytes +0x1.. (0x1158-byte box passed to 0x2b41b70)',
            '0x2b41b70: bit 0 of +0x0 set -> join path; clear -> replica_cmds check iff +0x1 == 1',
        ],
        'mode_writers': {'0x2ae4604': 2, '0x2ae5469': 1, '0x2cde6d0': 2, '0x2cdf567': 1},
        'lz4_branch': {
            'suffix': '.lz4 (dword 0x347a6c2e at path end, 0x1500e71)',
            'action': 'if state dword 0x64f01d8 != 0: Once::call (slot 0x64df9f0) on cell 0x64f01c0, then jmp '
                      '0x1500e89 (same wc -l build)',
            'cell_initializer': hex(LAZY_INIT),
            'state_dword_reads_in_text': state_reads,
        },
        'second_line_count_caller': {
            'fn': hex(SECOND), 'slot': hex(SECOND_SLOT), 'slot_calls': second_callers,
            'line_count_call': '0x1563bf0 with Location base/src/u.rs:388:11',
            'then': "format '{}.tolerance' (0x4388e5) and call slot 0x64e09d8 -> 0x1502320 "
                    '(Location base/src/u.rs:391:29)',
        },
        'line_count_slot_calls': line_callers,
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
    print(f"state_reads={result['lz4_branch']['state_dword_reads_in_text']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
