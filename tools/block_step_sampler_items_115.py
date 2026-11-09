#!/usr/bin/env python3
"""Bind the node #115 block-step sampler items and the per-item walk (18th stage).

Continues #5931, which found that the sampler state is 0x38 bytes (a list at
+0x0..+0x18, a 15.0 s gate interval at +0x20) and that an open gate walks the
list in 0x268-byte steps. This tool binds, in sampler 0x5b2a130:

1. where items enter the list: before the gate, the sampler calls 0x4dc50c0
   with the state and its u8 tag argument, then 0x4da7e20 (the #4460 host)
   with that result and the tag byte; the returned pointer is the observer the
   sampler records into (0x1547530 via slot 0x64e1010, #5045);
2. the list lookup 0x4dc50c0: stores the tag byte, tests the state's first
   word against the 0x8000000000000000 niche, searches through 0x57f4db0, and
   frees vec-mode storage as len * 0x268 bytes;
3. the walk: each 0x268-byte item gives a key byte (item +0x0), a dword at
   item +0x248 and a qword at item +0x208; the dword keys 0x4dc2420/0x4da4e80
   into a local map at rsp+0x50, and (qword, key byte) is pushed as a
   16-byte element (grow: slot 0x64ebf88 -> 0x5962620);
4. after the walk: a local map with at least 3 entries goes to 0x5b926e0; one
   with at least 2 entries goes there again when floor(seconds of day / 60)
   is at least 6; each call's 8-byte-element result is freed right after.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
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
PACKET = ROOT / 'research/work-items/RE-008-block-step-sampler-items-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SAMPLER = 0x5b2a130
LOOKUP, HOST = 0x4dc50c0, 0x4da7e20
GROUP_ENTRY, GROUP_VEC, COLLECT = 0x4dc2420, 0x4da4e80, 0x5b926e0
GROW_SLOT, GROW = 0x64ebf88, 0x5962620
ITEM = 0x268

FIXED = {
    # sampler head: tag byte, lookup, host, record
    0x5b2a1fd: '4088ac24e0000000',      # mov [rsp+0xe0], bpl          (tag byte)
    0x5b2a205: 'c684249800000000',      # mov byte [rsp+0x98], 0
    0x5b2a215: '4889de',                # mov rsi, rbx                 (state)
    0x5b2a218: '89ea',                  # mov edx, ebp                 (tag)
    0x5b2a21f: '488db424e0000000',      # lea rsi, [rsp+0xe0]
    0x5b2a243: '4889c7',                # mov rdi, rax                 (host result -> record)
    0x5b2a252: '4c8db4242c010000',      # lea r14, [rsp+0x12c]         (clock result)
    # local map at rsp+0x50: cap 0, ptr 8, 0, 0
    0x5b2a278: '48c744245000000000',    # mov qword [rsp+0x50], 0
    0x5b2a281: '48c744245808000000',    # mov qword [rsp+0x58], 8
    0x5b2a28d: '0f11442460',            # movups [rsp+0x60], xmm0
    # walk: stride, payload pointer, key byte, dword key, qword value
    0x5b2a3b7: '488d8868020000',        # lea rcx, [rax+0x268]
    0x5b2a3c3: '4c8d6008',              # lea r12, [rax+8]
    0x5b2a3e2: '0fb628',                # movzx ebp, byte [rax]        (key byte)
    0x5b2a3e5: '418b942440020000',      # mov edx, [r12+0x240]         (item +0x248)
    0x5b2a3f0: '4c89f6',                # mov rsi, r14                 (local map)
    0x5b2a403: '4d8bbc2400020000',      # mov r15, [r12+0x200]         (item +0x208)
    0x5b2a40b: '4c8b6010',              # mov r12, [rax+0x10]          (vec len)
    0x5b2a40f: '4c3b20',                # cmp r12, [rax]               (vec cap)
    # push (qword, byte) as a 16-byte element
    0x5b2a367: '48c1e104',              # shl rcx, 4
    0x5b2a36b: '4c893c08',              # mov [rax+rcx], r15
    0x5b2a36f: '40886c0808',            # mov [rax+rcx+8], bpl
    0x5b2a377: '4d896510',              # mov [r13+0x10], r12
    # after the walk
    0x5b2a431: '488b442468',            # mov rax, [rsp+0x68]          (local map len)
    0x5b2a436: '4883f803',              # cmp rax, 3
    0x5b2a43a: '0f82ff000000',          # jb 0x5b2a53f
    0x5b2a51f: '488b742408',            # mov rsi, [rsp+8]             (result cap)
    0x5b2a52e: '48c1e603',              # shl rsi, 3                   (8-byte elements)
    0x5b2a53f: '4883f801',              # cmp rax, 1
    0x5b2a543: '0f863e010000',          # jbe 0x5b2a687
    0x5b2a549: '8b8c2430010000',        # mov ecx, [rsp+0x130]         (seconds of day)
    0x5b2a550: 'bac5b3a291',            # mov edx, 0x91a2b3c5          (/3600)
    0x5b2a559: '48c1ea2b',              # shr rdx, 0x2b
    0x5b2a55d: '6bd23c',                # imul edx, edx, 60
    0x5b2a560: 'be89888888',            # mov esi, 0x88888889          (/60)
    0x5b2a569: '48c1ee25',              # shr rsi, 0x25
    0x5b2a56d: '4869ce89888808',        # imul rcx, rsi, 0x8888889     (/60)
    0x5b2a574: '48c1e921',              # shr rcx, 0x21
    0x5b2a578: '6bc93c',                # imul ecx, ecx, 60
    0x5b2a57b: '29ce',                  # sub esi, ecx
    0x5b2a57d: '01d6',                  # add esi, edx
    0x5b2a57f: '83fe06',                # cmp esi, 6
    0x5b2a582: '0f82ff000000',          # jb 0x5b2a687
    0x5b2a667: '488b742408',            # mov rsi, [rsp+8]
    0x5b2a676: '48c1e603',              # shl rsi, 3
    # lookup 0x4dc50c0
    0x4dc50d4: '40886c2407',            # mov [rsp+7], bpl             (tag byte)
    0x4dc50d9: '31c0',                  # xor eax, eax
    0x4dc50db: '483b06',                # cmp rax, [rsi]
    0x4dc50de: '0f80bc000000',          # jo 0x4dc51a0                 (first word == i64::MIN)
    0x4dc50e4: '49bc0000000000000080',  # movabs r12, 0x8000000000000000
    0x4dc517c: '4869f068020000',        # imul rsi, rax, 0x268         (free len * 0x268)
}
DIRECT = (
    # (call va, target)
    (0x5b2a21a, LOOKUP),
    (0x5b2a232, HOST),
    (0x5b2a3f3, GROUP_ENTRY),
    (0x5b2a3fb, GROUP_VEC),
    (0x5b2a51a, COLLECT),
    (0x5b2a662, COLLECT),
    (0x4dc50f6, 0x57f4db0),
)
SLOT_CALLS = (
    # (call va, slot)
    (0x5b2a24c, 0x64e1010),             # record -> 0x1547530
    (0x5b2a41b, GROW_SLOT),
    (0x5b2a534, 0x64df4a0),             # free
    (0x5b2a67c, 0x64df4a0),
)
RELOCS = {GROW_SLOT: GROW, 0x64e1010: 0x1547530}


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


def call_target(data, va):
    raw = read_va(data, va, 6)
    if raw[0] == 0xe8:
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if raw[:2] == b'\xff\x15':
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError(f'instruction at {va:#x} changed')


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
        return ordered[i]['start']
    return frame


def direct_calls(data, target):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    return out


def minute_of_day(seconds):
    """The arithmetic at 0x5b2a549..0x5b2a57d, from its constants."""
    hours_x60 = ((seconds * 0x91a2b3c5) >> 0x2b) * 60
    minutes = (seconds * 0x88888889) >> 0x25
    return minutes - ((minutes * 0x8888889) >> 0x21) * 60 + hours_x60


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in DIRECT:
        if read_va(data, va, 1) != b'\xe8' or call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, slot in SLOT_CALLS:
        if read_va(data, va, 2) != b'\xff\x15' or call_target(data, va) != slot:
            raise ValueError(f'slot call at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')

    samples = {s: minute_of_day(s) for s in (0, 359, 360, 3599, 3600, 86399)}
    if any(v != s // 60 for s, v in samples.items()):
        raise ValueError('minute arithmetic changed')

    frame = frame_starts(fdes)
    census = {}
    for target in (LOOKUP, GROUP_ENTRY, GROUP_VEC, COLLECT):
        calls = direct_calls(data, target)
        census[hex(target)] = {'direct_calls': len(calls),
                               'caller_frames': sorted({hex(frame(v)) for v in calls})}
    for target in (LOOKUP, GROUP_ENTRY, GROUP_VEC, COLLECT):
        if census[hex(target)]['caller_frames'] != [hex(SAMPLER)]:
            raise ValueError('callee census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'sampler': hex(SAMPLER),
        'insert': {
            'tag': '%s stores the tag byte at rsp+0xe0' % hex(0x5b2a1fd),
            'lookup': '%s call %s (rdi out, rsi = state, edx = tag)' % (hex(0x5b2a21a), hex(LOOKUP)),
            'host': '%s call %s (rdi = lookup result, rsi = &tag, rdx = &0); result -> rdi of the record'
                    % (hex(0x5b2a232), hex(HOST)),
            'record': '%s slot %s -> %s' % (hex(0x5b2a24c), hex(0x64e1010), hex(0x1547530)),
        },
        'lookup': {
            'fn': hex(LOOKUP),
            'key': 'tag byte at rsp+7 (%s)' % hex(0x4dc50d4),
            'mode_test': '%s cmp 0, [state]; jo (first word == 0x8000000000000000)' % hex(0x4dc50db),
            'search': '%s call %s' % (hex(0x4dc50f6), hex(0x57f4db0)),
            'free_size': '%s len * 0x268' % hex(0x4dc517c),
        },
        'item': {
            'size': hex(ITEM),
            '+0x0': 'u8 key (%s movzx ebp, byte [rax])' % hex(0x5b2a3e2),
            '+0x8': 'payload pointer r12 (%s)' % hex(0x5b2a3c3),
            '+0x208': 'qword pushed with the key (%s)' % hex(0x5b2a403),
            '+0x248': 'dword grouping key (%s)' % hex(0x5b2a3e5),
        },
        'walk': {
            'local_map': 'rsp+0x50 = {0, 8, 0, 0}; length at rsp+0x68',
            'entry': '%s call %s (rdi = rsp+0x98, rsi = local map, edx = item +0x248)'
                     % (hex(0x5b2a3f3), hex(GROUP_ENTRY)),
            'vec': '%s call %s -> {cap, ptr, len}' % (hex(0x5b2a3fb), hex(GROUP_VEC)),
            'push': '16-byte element: qword item +0x208 at +0, key byte at +8 (%s, %s)'
                    % (hex(0x5b2a36b), hex(0x5b2a36f)),
            'grow': 'slot %s -> %s' % (hex(GROW_SLOT), hex(GROW)),
        },
        'after_walk': {
            'len_ge_3': '%s call %s; 8-byte-element result freed at %s' % (hex(0x5b2a51a), hex(COLLECT), hex(0x5b2a534)),
            'len_ge_2_and_minute_ge_6': '%s call %s; result freed at %s' % (hex(0x5b2a662), hex(COLLECT), hex(0x5b2a67c)),
            'minute_of_day': 'floor(seconds of day / 60) from [rsp+0x130] (clock result at rsp+0x12c)',
            'minute_samples': {str(k): v for k, v in samples.items()},
        },
        'census': census,
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
    c = result['census']
    print(' '.join(f"{k}={v['direct_calls']}" for k, v in sorted(c.items())))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
