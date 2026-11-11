#!/usr/bin/env python3
"""Bind the node #115 block-step sampler state and its 15-second gate (17th stage).

Continues #5925, which found that the output setter's first optional value
(setter +0xae0, box +0x12a0) is the state the five block-step sampler sites
(0x5b2a130, #4718) test against 0x8000000000000001 before they call the
sampler. This tool binds:

1. the setter's two optional values (0x38 bytes each, at its stack +0x218 and
   +0x250, later +0xae0 and +0xb18): when byte +0x18 is set, +0x0 = 0,
   +0x8 = 8, +0x10 = +0x18 = 0, +0x20 = f64 15.0, +0x28 = dword 0; when it is
   clear, +0x0 = 0x8000000000000001;
2. both group_and_seq_sampler specialisations (0x5b298d0 and 0x5b2a130):
   each records into the shared value observer (slot 0x64e1010 -> 0x1547530)
   with Location node/src/group_and_seq_sampler.rs:169:10, reads the clock
   (slot 0x64e0990 -> 0x1629690), and calls the time gate (slot 0x64e0008 ->
   0x154ce40, the gate #5861 mapped) with rdi = state +0x20; 0x5b2a130 skips
   to its exit when the gate returns 0, and otherwise walks the ring at state
   +0x0..+0x18 in 0x268-byte steps;
3. the second optional value (box +0x12d8): 0x54ab437 takes rbx+0x12d8, and
   0x54ab455 / 0x54ab49b compare it with 0x8000000000000001 before calling
   0x5b298d0 with tags 0 and 1; a census of direct calls to both samplers.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
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

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-block-step-sampler-state-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SAMPLER_A, SAMPLER_B = 0x5b298d0, 0x5b2a130
GATE_SLOT, GATE = 0x64e0008, 0x154ce40
CLOCK_SLOT, CLOCK = 0x64e0990, 0x1629690
OBSERVER_SLOT, OBSERVER = 0x64e1010, 0x1547530
LOCATION = 0x64bca88
SOURCE = (0x431e32, b'node/src/group_and_seq_sampler.rs')
NONE = 0x8000000000000001
STATE_SIZE = 0x38

FIXED = {
    # output setter 0x51cf360: byte +0x18 (copied to rsp+0x13) builds both values
    0x51d0856: '807c241300',                    # cmp byte [rsp+0x13], 0
    0x51d085b: '745f',                          # je 0x51d08bc                (clear -> None)
    0x51d085d: '48c784242002000008000000',      # mov qword [rsp+0x220], 8    (+0x8)
    0x51d086c: '0f11842428020000',              # movups [rsp+0x228], xmm0    (+0x10, +0x18)
    0x51d0874: '48b8000000000000 2e40'.replace(' ', ''),  # movabs rax, 15.0
    0x51d087e: '4889842438020000',              # mov [rsp+0x238], rax        (+0x20)
    0x51d0886: 'c784244002000000000000',        # mov dword [rsp+0x240], 0    (+0x28)
    0x51d0891: '48c784245802000008000000',      # mov qword [rsp+0x258], 8
    0x51d089d: '0f11842460020000',              # movups [rsp+0x260], xmm0
    0x51d08a5: '4889842470020000',              # mov [rsp+0x270], rax
    0x51d08ad: 'c784247802000000000000',        # mov dword [rsp+0x278], 0
    0x51d08b8: '31c0',                          # xor eax, eax                (set: +0x0 = 0)
    0x51d08bc: '488d4501',                      # lea rax, [rbp+1]            (clear: None)
    0x51d08c5: '4889842418020000',              # mov [rsp+0x218], rax        (+0x0)
    0x51d08cd: '4889842450020000',              # mov [rsp+0x250], rax
    # sampler A 0x5b298d0
    0x5b299de: 'be01000000',                    # mov esi, 1
    0x5b29a03: '488d7b20',                      # lea rdi, [rbx+0x20]         (interval)
    0x5b29a07: '4c89f6',                        # mov rsi, r14                (now)
    0x5b29a10: '84c0',                          # test al, al
    # sampler B 0x5b2a130
    0x5b2a23e: 'be01000000',                    # mov esi, 1
    0x5b2a263: '488d7b20',                      # lea rdi, [rbx+0x20]
    0x5b2a267: '4c89f6',                        # mov rsi, r14
    0x5b2a270: '84c0',                          # test al, al
    0x5b2a272: '0f846a070000',                  # je 0x5b2a9e2                (gate closed -> exit)
    0x5b2a292: '488b03',                        # mov rax, [rbx]              (ring capacity)
    0x5b2a3b7: '488d8868020000',                # lea rcx, [rax+0x268]        (next item)
    # second optional value: box +0x12d8
    0x54ab437: '488d83d8120000',                # lea rax, [rbx+0x12d8]
    0x54ab443: '48b80000000000000080',          # movabs rax, 0x8000000000000000
    0x54ab44d: '48ffc0',                        # inc rax                     (None)
    0x54ab455: '483983d8120000',                # cmp [rbx+0x12d8], rax
    0x54ab45c: '7414',                          # je 0x54ab472                (None -> skip)
    0x54ab46b: '31f6',                          # xor esi, esi                (tag 0)
    0x54ab49b: '483983d8120000',                # cmp [rbx+0x12d8], rax
    0x54ab4a2: '7417',                          # je 0x54ab4bb
    0x54ab4ac: 'be01000000',                    # mov esi, 1                  (tag 1)
    0x54ab4b1: '488b7c2450',                    # mov rdi, [rsp+0x50]         (rbx+0x12d8)
}
REFERENCES = (
    (0x5b299d7, b'\x48\x8d\x15', 7, LOCATION),
    (0x5b299ec, b'\xff\x15', 6, OBSERVER_SLOT),
    (0x5b299fd, b'\xff\x15', 6, CLOCK_SLOT),
    (0x5b29a0a, b'\xff\x15', 6, GATE_SLOT),
    (0x5b2a237, b'\x48\x8d\x15', 7, LOCATION),
    (0x5b2a24c, b'\xff\x15', 6, OBSERVER_SLOT),
    (0x5b2a25d, b'\xff\x15', 6, CLOCK_SLOT),
    (0x5b2a26a, b'\xff\x15', 6, GATE_SLOT),
    (0x54ab46d, b'\xe8', 5, SAMPLER_A),
    (0x54ab4b6, b'\xe8', 5, SAMPLER_A),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


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
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def frame_starts(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start'], ordered[i]['end']
    return frame




def direct_calls(data, target):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in ((GATE_SLOT, GATE), (CLOCK_SLOT, CLOCK), (OBSERVER_SLOT, OBSERVER), (LOCATION, SOURCE[0])):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if read_va(data, SOURCE[0], len(SOURCE[1])) != SOURCE[1]:
        raise ValueError('source path changed')
    length, line, column = struct.unpack('<QII', read_va(data, LOCATION + 8, 16))
    if (length, line, column) != (len(SOURCE[1]), 169, 10):
        raise ValueError('Location changed')
    if struct.unpack('<d', bytes.fromhex(FIXED[0x51d0874])[2:])[0] != 15.0:
        raise ValueError('interval constant changed')

    frame = frame_starts(fdes)
    calls_a, calls_b = direct_calls(data, SAMPLER_A), direct_calls(data, SAMPLER_B)
    frames_a = sorted({frame(v)[0] for v in calls_a})
    frames_b = sorted({frame(v)[0] for v in calls_b})
    for va in (0x54ab46d, 0x54ab4b6):
        if va not in calls_a:
            raise ValueError('sampler A census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'setter_values': {
            'size': hex(STATE_SIZE),
            'set': {'+0x0': '0 (ring capacity)', '+0x8': '8 (ring buffer, empty)', '+0x10': '0', '+0x18': '0',
                    '+0x20': 'f64 15.0 (gate interval)', '+0x28': 'dword 0 (gate stored date: empty)'},
            'clear': {'+0x0': hex(NONE) + ' (None)'},
            'branch': hex(0x51d0856) + ' cmp byte [rsp+0x13], 0',
        },
        'samplers': {
            hex(SAMPLER_A): {'direct_calls': len(calls_a), 'caller_frames': [hex(v) for v in frames_a],
                             'gate_call': hex(0x5b29a0a)},
            hex(SAMPLER_B): {'direct_calls': len(calls_b), 'caller_frames': [hex(v) for v in frames_b],
                             'gate_call': hex(0x5b2a26a), 'gate_closed_exit': hex(0x5b2a9e2),
                             'ring_item_stride': '0x268'},
            'shared': {
                'observer': 'slot %s -> %s, Location %s:%d:%d' % (hex(OBSERVER_SLOT), hex(OBSERVER),
                                                                  SOURCE[1].decode(), line, column),
                'clock': 'slot %s -> %s' % (hex(CLOCK_SLOT), hex(CLOCK)),
                'gate': 'slot %s -> %s with rdi = state +0x20, rsi = now' % (hex(GATE_SLOT), hex(GATE)),
            },
        },
        'second_value': {
            'box_offset': '0x12d8',
            'none_checks': [hex(0x54ab455), hex(0x54ab49b)],
            'guarded_calls': {hex(0x54ab46d): 0, hex(0x54ab4b6): 1},
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
    s = result['samplers']
    print(f"sampler_a_calls={s[hex(SAMPLER_A)]['direct_calls']} sampler_b_calls={s[hex(SAMPLER_B)]['direct_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
