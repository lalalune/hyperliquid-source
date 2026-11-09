#!/usr/bin/env python3
"""Bind the node #115 channel.rs:16:9 forwarders and the lu.rs unfold stream's poll sites (27th stage).

Continues the 26th stage, which found four users of the lu.rs sleep helper
0x2d4f790: an unfold stream poll 0x2cf08b0 and two futures 0x2e071c0 and
0x2e075f0 that reference node/src/channel.rs:16:9. This tool binds:

1. the two futures are the poll entries of two boxed-future vtables
   (drop, size, align, poll): 0x6451ad8 (size 0x118, poll 0x2e071c0) and
   0x6451ab8 (size 0x108, poll 0x2e075f0); each poll entry has no other
   relocation and each vtable one RIP-relative reference;
2. the builders 0x2e06e40 (0x118) and 0x2e06ac0 (0x108): each builds two
   channels with capacity 0x1388 (5000), formats an optional task name from
   template 0x434b16 (argument, "_forwarder") when its fourth argument is
   set, boxes the future and passes it with its vtable to slot 0x64e1758
   (the spawn wrapper 0x15d6ef0 of the 9th stage);
3. the four builder calls and their name arguments: "client block or tx"
   (18 bytes, name flag 1) twice into 0x2e06e40, "node_stream_connection"
   (22 bytes, name flag 0) twice into 0x2e06ac0;
4. the forwarder loop: receive an item, store its 12-byte time, sleep
   max(0, time - now), then send the payload with Location channel.rs:20:33;
   a received zero first dword ends the loop (channel closed);
5. the unfold poll 0x2cf08b0 is called directly from four sites in two
   functions; at 0x2ce0de0 it is one branch of a two-branch select with a
   random start (0x5ce2080 with bound 2), the other branch being a channel
   receive 0x2ced6b0.

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
PACKET = ROOT / 'research/work-items/RE-008-lu-unfold-channel-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

BUILD_118, BUILD_108 = 0x2e06e40, 0x2e06ac0
POLL_118, POLL_108 = 0x2e071c0, 0x2e075f0
VT_118, VT_108 = 0x6451ad8, 0x6451ab8
DROP_118, DROP_108 = 0x2ddfd00, 0x2de04b0
SPAWN_SLOT, SPAWN = 0x64e1758, 0x15d6ef0
CLOCK_SLOT, DIFF_SLOT = 0x64e0990, 0x64e0fc0
UNFOLD, SLEEP = 0x2cf08b0, 0x2d4f790
LOC_16, LOC_20, CHANNEL_FILE = 0x6451af8, 0x6451b10, 0x430aa0
TEMPLATE = (0x434b16, b'\xc0\x0a_forwarder')
NAMES = {0x605f60: b'client block or tx', 0x60f345: b'client block or tx',
         0x6056b2: b'node_stream_connection'}

FIXED = {
    # builder 0x118
    0x2e06e6e: 'b988130000',              # mov ecx, 5000
    0x2e06ec7: 'b988130000',              # mov ecx, 5000
    0x2e06f27: '4084ed',                  # test bpl, bpl      (name flag)
    0x2e06ffd: 'bf18010000',              # mov edi, 0x118     (box size)
    # builder 0x108
    0x2e06aee: 'b988130000',              # mov ecx, 5000
    0x2e06b47: 'b988130000',              # mov ecx, 5000
    0x2e06ba7: '4084ed',                  # test bpl, bpl
    0x2e06c7d: 'bf08010000',              # mov edi, 0x108
    # builder calls: name length and name flag
    0x2af0b4d: 'ba12000000', 0x2af0b52: 'b901000000',
    0x2cbc152: 'ba12000000', 0x2cbc157: 'b901000000',
    0x2ace0fb: 'ba16000000', 0x2ace100: '31c9',
    0x2ad2117: 'ba16000000', 0x2ad211c: '31c9',
    # forwarder 0x118 loop
    0x2e07329: '660f1083080100',          # movupd xmm0, [rbx+0x108]   (payload to send)
    0x2e0734f: '3c05',                    # cmp al, 5                  (send result)
    0x2e073cf: '85c0',                    # test eax, eax              (received first dword 0 -> closed)
    0x2e0742b: '660f1183080100',          # movupd [rbx+0x108], xmm0   (store payload)
    0x2e074ba: 'f20f5fc8',                # maxsd xmm1, xmm0           (max(0, time - now))
    # forwarder 0x108 loop
    0x2e07753: '488b7368',                # mov rsi, [rbx+0x68]        (payload to send)
    0x2e0776a: '3c05',                    # cmp al, 5
    0x2e077e4: '85c0',                    # test eax, eax
    0x2e0783a: '488b4330',                # mov rax, [rbx+0x30]        (item +0x10)
    0x2e0783e: '48894368',                # mov [rbx+0x68], rax
    # select site
    0x2ce0e53: 'c7442404020000',          # mov dword [rsp+4], 2       (branch count)
    0x2ce0e91: '3c02',                    # cmp al, 2                  (unfold not ready)
}
REFERENCES = (
    # (instruction va, kind, target): kind lea7 = 7-byte RIP lea, ff15 = call [rip], e8 = call rel32
    (0x2e06f42, 'lea7', TEMPLATE[0]), (0x2e0702a, 'lea7', VT_118), (0x2e0703a, 'ff15', SPAWN_SLOT),
    (0x2e07002, 'ff15', 0x64df480),
    (0x2e06e73, 'e8', 0x2cef4d0), (0x2e06ed2, 'e8', 0x2cef6e0),
    (0x2e06bc2, 'lea7', TEMPLATE[0]), (0x2e06caa, 'lea7', VT_108), (0x2e06cba, 'ff15', SPAWN_SLOT),
    (0x2e06c82, 'ff15', 0x64df480),
    (0x2e06af3, 'e8', 0x2cef2c0), (0x2e06b52, 'e8', 0x2cef0b0),
    (0x2af0b3e, 'lea7', 0x605f60), (0x2af0b57, 'e8', BUILD_118),
    (0x2cbc143, 'lea7', 0x60f345), (0x2cbc15c, 'e8', BUILD_118),
    (0x2ace0ec, 'lea7', 0x6056b2), (0x2ace102, 'e8', BUILD_108),
    (0x2ad2108, 'lea7', 0x6056b2), (0x2ad211e, 'e8', BUILD_108),
    (0x2e07337, 'lea7', LOC_20), (0x2e07346, 'e8', 0x2ced920), (0x2e0739c, 'e8', 0x2ce0f40),
    (0x2e07438, 'ff15', CLOCK_SLOT), (0x2e07477, 'ff15', DIFF_SLOT), (0x2e072c6, 'e8', SLEEP),
    (0x2e07757, 'lea7', LOC_20), (0x2e07761, 'e8', 0x2cee110), (0x2e077b3, 'e8', 0x2cddeb0),
    (0x2e07847, 'ff15', CLOCK_SLOT), (0x2e07886, 'ff15', DIFF_SLOT), (0x2e076f0, 'e8', SLEEP),
    (0x2e07242, 'lea7', LOC_16),
    (0x2ce0e67, 'e8', 0x5ce2080), (0x2ce0e84, 'e8', UNFOLD), (0x2ce0ead, 'e8', 0x2ced6b0),
)
PREFIX = {'lea7': (7, 3), 'ff15': (6, 2), 'e8': (5, 1)}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def target(data, va, kind):
    length, disp_at = PREFIX[kind]
    raw = read_va(data, va, length)
    ok = {'lea7': raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and raw[2] & 0xc7 == 0x05,
          'ff15': raw[:2] == b'\xff\x15', 'e8': raw[0] == 0xe8}[kind]
    if not ok:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, disp_at)[0]


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


def census(data, goal, kind):
    """Every e8 call or 7-byte RIP lea in .text that reaches goal."""
    base, code = text(data)
    pattern = rb'\xe8' if kind == 'e8' else rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'
    length, disp_at = PREFIX[kind]
    out = []
    for m in re.finditer(pattern, code):
        i = m.start()
        if i + length <= len(code) and base + i + length + struct.unpack_from('<i', code, i + disp_at)[0] == goal:
            out.append(base + i)
    return out


def location(data, va):
    ptr_word = read_va(data, va, 24)
    length, line, col = struct.unpack_from('<QII', ptr_word, 8)
    return length, line, col


def frames(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start']
    return frame


def vtable(data, rel, va):
    size, align = struct.unpack('<QQ', read_va(data, va + 8, 16))
    return rel.get(va), size, align, rel.get(va + 24)


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, kind, goal in REFERENCES:
        if target(data, va, kind) != goal:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, *[TEMPLATE[0], len(TEMPLATE[1])]) != TEMPLATE[1]:
        raise ValueError('task name template changed')
    for va, name in NAMES.items():
        if read_va(data, va, len(name)) != name:
            raise ValueError(f'name at {va:#x} changed')
    if read_va(data, CHANNEL_FILE, 19) != b'node/src/channel.rs':
        raise ValueError('channel.rs path changed')
    locs = {LOC_16: (19, 16, 9), LOC_20: (19, 20, 33)}
    for va, want in locs.items():
        if location(data, va) != want:
            raise ValueError(f'Location at {va:#x} changed')

    rel = relative_relocations(data)
    if rel.get(SPAWN_SLOT) != SPAWN or rel.get(LOC_16) != CHANNEL_FILE or rel.get(LOC_20) != CHANNEL_FILE:
        raise ValueError('relocations changed')
    vt = {VT_118: (DROP_118, 0x118, 8, POLL_118), VT_108: (DROP_108, 0x108, 8, POLL_108)}
    for va, want in vt.items():
        if vtable(data, rel, va) != want:
            raise ValueError(f'vtable at {va:#x} changed')
    for poll, slot in ((POLL_118, VT_118 + 24), (POLL_108, VT_108 + 24)):
        if [k for k, v in rel.items() if v == poll] != [slot] or census(data, poll, 'e8'):
            raise ValueError(f'poll {poll:#x} reference census changed')

    frame = frames(fdes)
    builders = {hex(b): [hex(v) for v in census(data, b, 'e8')] for b in (BUILD_118, BUILD_108)}
    vt_refs = {hex(v): [hex(x) for x in census(data, v, 'lea7')] for v in (VT_118, VT_108)}
    unfold_sites = census(data, UNFOLD, 'e8')
    sleep_sites = census(data, SLEEP, 'e8')
    if builders != {hex(BUILD_118): ['0x2af0b57', '0x2cbc15c'], hex(BUILD_108): ['0x2ace102', '0x2ad211e']}:
        raise ValueError('builder census changed')
    if vt_refs != {hex(VT_118): ['0x2e0702a'], hex(VT_108): ['0x2e06caa']}:
        raise ValueError('vtable reference census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'forwarders': {
            hex(POLL_118): {
                'vtable': hex(VT_118), 'drop': hex(DROP_118), 'box_size': '0x118',
                'builder': hex(BUILD_118), 'builder_calls': builders[hex(BUILD_118)],
                'name': 'client block or tx (name flag 1 -> task name "client block or tx_forwarder")',
                'channels': 'two, capacity 5000 (0x2cef4d0, 0x2cef6e0)',
                'receive': '0x2ce0f40; item first dword 0 -> loop ends',
                'deadline': 'item +0x0..+0xc (date, seconds, fraction) stored at future +0x0',
                'payload': 'item +0x10..+0x20 (16 bytes) stored at +0x108, sent by 0x2ced920 at channel.rs:20:33',
            },
            hex(POLL_108): {
                'vtable': hex(VT_108), 'drop': hex(DROP_108), 'box_size': '0x108',
                'builder': hex(BUILD_108), 'builder_calls': builders[hex(BUILD_108)],
                'name': 'node_stream_connection (name flag 0 -> no task name)',
                'channels': 'two, capacity 5000 (0x2cef2c0, 0x2cef0b0)',
                'receive': '0x2cddeb0; item first dword 0 -> loop ends',
                'deadline': 'item +0x0..+0xc stored at future +0x20',
                'payload': 'item +0x10 (8 bytes) stored at +0x68, sent by 0x2cee110 at channel.rs:20:33',
            },
            'sleep': 'max(0, deadline - now): wall clock slot %s, difference slot %s, sleep %s'
                     % (hex(CLOCK_SLOT), hex(DIFF_SLOT), hex(SLEEP)),
            'task_name_template': hex(TEMPLATE[0]) + ' ' + TEMPLATE[1].hex() + ' = {}_forwarder',
            'spawn': 'slot %s -> %s' % (hex(SPAWN_SLOT), hex(SPAWN)),
            'send_ok_value': 5,
        },
        'unfold': {
            'poll': hex(UNFOLD),
            'direct_calls': [[hex(v), hex(frame(v))] for v in unfold_sites],
            'select_site': '0x2ce0de0: random start over 2 branches (0x5ce2080), branch 1 = unfold poll '
                           '(state pointer [[rsi+0x8]+0x30]), result 2 = not ready; branch 2 = receive 0x2ced6b0',
        },
        'sleep_calls': [[hex(v), hex(frame(v))] for v in sleep_sites],
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
    print(f"unfold_calls={len(result['unfold']['direct_calls'])} sleep_calls={len(result['sleep_calls'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
