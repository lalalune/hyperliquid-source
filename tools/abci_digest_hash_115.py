#!/usr/bin/env python3
"""Bind which hash the node #115 abci digest uses and what feeds it (47th stage).

Continues #6023 (stage 46), which found that the layout-A step stores
(height, digest) pairs computed by 0x548dad0 and that the wrappers compare
them with quorum values. This tool binds:

1. 0x548dad0 (one direct caller, the A step at 0x5a07fce): reads the clock,
   calls 0x4e46090(out, box, 1), passes that result to slot 0x64e7820 ->
   0x41c5140, records the elapsed seconds through slot 0x64e1010 -> 0x1547530
   into the observer the caller passes (engine value +0x20) with Location
   l1/src/abci/abci_hash.rs:28:37, then passes height box +0x28 and the
   32-byte digest to 0x4e3a7a0;
2. 0x41c5140: serialises its argument into a Vec (cap 0, ptr 1, len 0;
   config dword 0x400, byte 0) and hashes the bytes with BLAKE3: the
   platform probe 0x160bee0 (slot 0x64df488) returns 1..4 from cached CPU
   feature bits; the 32-byte IV at 0x457ae0 is loaded as both key and chaining
   value; chunk counter 0; update 0x160b3a0 (slot 0x64df510) holds 13
   references to Location records naming z_vendor/blake3/src/lib.rs; finalize
   0x160bcd0 (slot 0x64df518) writes 32 bytes to the output;
3. 0x4e34ce0 (reached from the blocking wrapper 0x4e46090): builds a table of
   73 references into the box, allocates 59 (0x3b) 0x18-byte slots preset to
   0x8000000000000001, calls 0x54423c0(table, slots), and on result 4 folds
   the slots through slot 0x64df500 -> 0x141a250; it then logs
   "computed exchange abci hash" with the height and elapsed time.

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
from freeze_snapshot_115 import direct_calls, fixed, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-digest-hash-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DIGEST, HASH, BUILD, BUILD_WRAP = 0x548dad0, 0x41c5140, 0x4e34ce0, 0x4e46090
DETECT, UPDATE, FINALIZE, FOLD, PARTS = 0x160bee0, 0x160b3a0, 0x160bcd0, 0x141a250, 0x54423c0
IV = 0x457ae0
BLAKE3_IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
BLAKE3_LIB = (0x444a84, b'/home/ubuntu/hl/code_Mainnet/z_vendor/blake3/src/lib.rs')
SLOTS = {0x64e7820: HASH, 0x64df488: DETECT, 0x64df510: UPDATE, 0x64df518: FINALIZE,
         0x64df500: FOLD, 0x64e1010: 0x1547530}
ABCI_HASH_LOC = 0x64aa290
LOG = (0x918740, b'computed exchange abci hash')

FIXED = {
    # 0x548dad0: build (blocking, flag 1), hash, time, record, height
    0x548db07: '4c89fe',                # mov rsi, r15                 (box)
    0x548db0a: 'ba01000000',            # mov edx, 1
    0x548db14: '4889df',                # mov rdi, rbx                 (32-byte out)
    0x548db17: '4c89e6',                # mov rsi, r12                 (built value)
    0x548dbae: 'be01000000',            # mov esi, 1                   (count)
    0x548dbb3: '4c89ef',                # mov rdi, r13                 (caller's observer)
    0x548dbc7: '498b4728',              # mov rax, [r15+0x28]          (height)
    # A step call site: observer = engine +0x20, third arg = engine +0x330
    0x5a07f85: '488b8ec8390000',        # mov rcx, [rsi+0x39c8]        (divisor, #6023)
    0x5a07fbb: '498d9630030000',        # lea rdx, [r14+0x330]
    0x5a07fc2: '498d4e20',              # lea rcx, [r14+0x20]
    # 0x41c5140: serializer Vec + config, then BLAKE3 state
    0x41c5160: '48c744240800000000',    # cap 0
    0x41c5169: '48c744241001000000',    # ptr 1 (dangling)
    0x41c5172: '48c744241800000000',    # len 0
    0x41c5185: 'c744242800040000',      # mov dword [rsp+0x28], 0x400  (config)
    0x41c518d: 'c644242c00',            # mov byte [rsp+0x2c], 0
    0x41c5192: '803e01',                # cmp byte [rsi], 1
    0x41c51f6: 'be42000000',            # mov esi, 0x42
    0x41c51fb: 'b920000000',            # mov ecx, 0x20
    0x41c5350: 'c78424f700000000000000',  # flags/len bytes 0
    0x41c535b: '48c78424f000000000000000',  # chunk counter 0
    0x41c5367: '888424fb000000',        # mov [rsp+0xfb], al           (platform)
    0x41c5381: '4c89fe',                # mov rsi, r15                 (bytes ptr)
    0x41c5384: '4c89e2',                # mov rdx, r12                 (bytes len)
    # 0x160bee0: platform probe returns 4 / 3 / 2 / 1
    0x160bef0: 'a900000800',            # test eax, 0x80000
    0x160beff: 'b004',                  # mov al, 4
    0x160bf01: 'f7c100000002',          # test ecx, 0x2000000
    0x160bf11: 'b003',                  # mov al, 3
    0x160bf20: 'c1e80a',                # shr eax, 10
    0x160bf23: '83e001',                # and eax, 1
    0x160bf26: 'fec0',                  # inc al
    # 0x4e34ce0: field table, 59 slots, parts call, fold on 4
    0x4e34d06: '498d87c0070000',        # lea rax, [r15+0x7c0]         (first table entry)
    0x4e35155: 'bf88050000',            # mov edi, 0x588
    0x4e35169: '49bc0100000000000080',  # movabs r12, 0x8000000000000001
    0x4e352fd: '48c74424183b000000',    # cap 0x3b
    0x4e3530b: '48c74424283b000000',    # len 0x3b
    0x4e35329: '3c04',                  # cmp al, 4
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x548db0f, b'\xe8', 5, BUILD_WRAP),
    (0x548db1a, b'\xff\x15', 6, 0x64e7820),
    (0x548dba7, b'\x48\x8d\x15', 7, ABCI_HASH_LOC),
    (0x548dbb6, b'\xff\x15', 6, 0x64e1010),
    (0x548dbf9, b'\xe8', 5, 0x4e3a7a0),
    (0x5a07fce, b'\xe8', 5, DIGEST),
    (0x41c5203, b'\xff\x15', 6, 0x64e4d08),
    (0x41c52d8, b'\xff\x15', 6, 0x64df488),
    (0x41c52f5, b'\x0f\x10\x0d', 7, IV),
    (0x41c5301, b'\x0f\x10\x15', 7, IV + 0x10),
    (0x41c5387, b'\xff\x15', 6, 0x64df510),
    (0x41c539a, b'\xff\x15', 6, 0x64df518),
    (0x4e35324, b'\xe8', 5, PARTS),
    (0x4e35359, b'\xff\x15', 6, 0x64df500),
    (0x4e354e2, b'\x48\x8d\x05', 7, LOG[0]),
)


def lea_refs(data, start, end, targets):
    """Count RIP-relative lea instructions in [start, end) whose target is in targets."""
    base, code = text(data)
    seg = code[start - base:end - base]
    n = 0
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', seg):
        i = m.start()
        if i + 7 <= len(seg) and start + i + 7 + struct.unpack_from('<i', seg, i + 3)[0] in targets:
            n += 1
    return n


def field_table(data):
    """`lea rax, [r15+disp32]` + `mov [rsp+disp32], rax` pairs from 0x4e34d06 to the slot allocation."""
    base, code = text(data)
    seg = code[0x4e34d06 - base:0x4e35155 - base]
    offsets = [struct.unpack_from('<i', seg, m.start() + 3)[0]
               for m in re.finditer(rb'\x49\x8d\x87', seg)]
    return offsets


def preset_slots(data):
    base, code = text(data)
    seg = code[0x4e35173 - base:0x4e352fd - base]
    return len(re.findall(rb'\x4c\x89\x60.|\x4c\x89\xa0....|\x4c\x89\x20', seg, re.S))


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
    if struct.unpack('<8I', read_va(data, IV, 32)) != BLAKE3_IV:
        raise ValueError('IV changed')
    if read_va(data, BLAKE3_LIB[0], len(BLAKE3_LIB[1])) != BLAKE3_LIB[1]:
        raise ValueError('blake3 path changed')
    if read_va(data, LOG[0], len(LOG[1])) != LOG[1]:
        raise ValueError('log text changed')
    loc_file = rel.get(ABCI_HASH_LOC)
    loc_len, loc_line, loc_col = struct.unpack('<QII', read_va(data, ABCI_HASH_LOC + 8, 16))
    loc_name = read_va(data, loc_file, loc_len).decode()
    if (loc_name, loc_line, loc_col) != ('l1/src/abci/abci_hash.rs', 28, 37):
        raise ValueError('abci_hash Location changed')

    ends = {f['start']: f['end'] for f in fdes}
    blake_locs = {va for va, a in rel.items() if a == BLAKE3_LIB[0]}
    update_refs = lea_refs(data, UPDATE, ends[UPDATE], blake_locs)
    if update_refs != 13:
        raise ValueError('blake3 Location census changed')
    callers = {name: [hex(v) for v in direct_calls(data, fn)]
               for name, fn in (('digest', DIGEST), ('build', BUILD), ('hash', HASH))}
    if callers['digest'] != ['0x5a07fce'] or callers['build'] != ['0x4e46129', '0x4e461c9']:
        raise ValueError('caller census changed')
    table = field_table(data)
    slots = preset_slots(data)
    if len(table) != 73 or slots != 59:
        raise ValueError(f'field table / slot census changed ({len(table)}, {slots})')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'digest_fn': {
            'fn': hex(DIGEST), 'direct_callers': callers['digest'],
            'call_site_args': 'rsi = box, rcx = engine value +0x20 (observer), rdx = engine value +0x330',
            'steps': ['clock', 'build 0x4e46090(out, box, 1)', 'hash slot 0x64e7820 -> 0x41c5140',
                      'record elapsed seconds, count 1, slot 0x64e1010 -> 0x1547530',
                      'call 0x4e3a7a0 with height box +0x28 and the 32-byte digest'],
            'location': '%s:%d:%d' % (loc_name, loc_line, loc_col),
        },
        'hash_fn': {
            'fn': hex(HASH), 'direct_callers': callers['hash'],
            'serializer': 'Vec {cap 0, ptr 1, len 0}, config dword 0x400, byte 0; tag 1 -> 0x41444a0 on +0x8, '
                          'else slot 0x64e4d08 (esi 0x42, ecx 0x20) then 0x41c6110',
            'blake3': {
                'iv': hex(IV) + ' = ' + ' '.join(hex(w) for w in BLAKE3_IV),
                'platform_probe': hex(DETECT) + ' returns 4, 3, 2 or 1 from cached feature bits',
                'state': 'IV copied as key and chaining value, chunk counter 0, platform byte +0x6b',
                'update': '%s (%d Location refs to %s)' % (hex(UPDATE), update_refs, BLAKE3_LIB[1].decode()),
                'finalize': hex(FINALIZE) + ' -> 32 bytes at out',
            },
        },
        'build_fn': {
            'fn': hex(BUILD), 'reached_from': hex(BUILD_WRAP) + ' (blocking wrapper, flag 1)',
            'r15_lea_rax_entries_before_alloc': len(table),
            'first_entries': [hex(o) for o in table[:6]],
            'slots': '%d x 0x18, preset 0x8000000000000001' % slots,
            'parts': hex(PARTS) + ' (table, slots); result 4 -> fold slot 0x64df500 -> ' + hex(FOLD),
            'log': LOG[1].decode(),
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
    print('blake3 update refs', result['hash_fn']['blake3']['update'].split('(')[1].split()[0],
          'slots', result['build_fn']['slots'].split()[0])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
