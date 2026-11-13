#!/usr/bin/env python3
"""Bind the node #115 abci_hashes line record (53rd stage).

Continues the abci digest packets (#6023 check, #6024 BLAKE3, #6027 slots,
#6029/#6030 tree encoding, #6031 hex callers, #6033 abci_digest_quorum log).
#6033 found that the engine builder creates an `abci_hashes` daily->hourly
writer at engine value +0x330. This tool binds what is written to it:

1. the only two calls of the line function 0x4e3a7a0 are in the digest steps
   0x548d8c0 (B, 0x548d9e9) and 0x548dad0 (A, 0x548dbf9); both build the same
   0x28-byte record at rsp+0x48: +0x0 = r12 (the hash tree that the root hash
   slot 0x64e7820 -> 0x41c5140 consumed), +0x8 = box +0x28 (height),
   +0x10..+0x30 = the 32-byte root digest just written to rdi; time = wall
   clock (slot 0x64e0990 -> 0x1629690); writer = the step's third argument;
2. the line function: rotation sink slot 0x64e0f80 (0x1546570), open slot
   0x64e0020 (0x14c3b30), serialiser 0x50e5fc0 -> record 0x537d5e0, '\\n',
   0x14c37f0; extra flush only when writer +0xaa and the byte behind slot
   0x64e0f88 are both set;
3. the record: '{', "height" (6) from +0x8, "abci_digest" (11) from +0x10,
   "exchange_abci_hash" (18) from +0x0, '}';
4. "abci_digest": 0x5073b20 -> 0x4e1c250, capacity 0x42, length 0x20;
5. "exchange_abci_hash": 0x506d4e0 reads the tree tag byte; tag 1 tail-jumps
   to the node writer 0x5025a10 (JSON '[' ... ']' with recursion at
   0x5025add), any other tag writes the 32 leaf bytes at +0x1 through
   0x4e1c250 with capacity 0x42 and length 0x20.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, frame, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-hashes-log-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STEP_A, STEP_B = 0x548dad0, 0x548d8c0
LINE = 0x4e3a7a0
SERIALISE, RECORD = 0x50e5fc0, 0x537d5e0
DIGEST_FIELD, TREE_FIELD, NODE, HEX_WRAP = 0x5073b20, 0x506d4e0, 0x5025a10, 0x4e1c250

RELOCATIONS = {
    0x64e7820: 0x41c5140,   # root hash of the tree (#6029)
    0x64e0990: 0x1629690,   # wall clock
    0x64e0f80: 0x1546570,   # rotation sink
    0x64e0020: 0x14c3b30,   # liner open
    0x64e0f88: 0x64ffe50,   # global flush byte
    0x64e4d08: 0x2eabb50,   # 0x-prefixed hex encoder
}
STRINGS = {
    0x924ed9: b'height',
    0x924edf: b'abci_digest',
    0x924eea: b'exchange_abci_hash',
}
RECORD_BUILD = (
    '498b4728'          # mov rax, [r15+0x28]   (box +0x28, height)
    '4889442450'        # mov [rsp+0x50], rax   (record +0x8)
    '660f1003'          # movupd xmm0, [rbx]    (root digest)
    '660f104b10'        # movupd xmm1, [rbx+0x10]
    '660f11442458'      # movupd [rsp+0x58], xmm0 (record +0x10)
    '660f114c2468'      # movupd [rsp+0x68], xmm1
    '4c89642448'        # mov [rsp+0x48], r12   (record +0x0 = tree)
    '488d742408'        # lea rsi, [rsp+0x8]    (time)
    '488d542448'        # lea rdx, [rsp+0x48]   (record)
    '488b7c2418'        # mov rdi, [rsp+0x18]   (writer)
)
FIXED = {
    0x548d9b7: RECORD_BUILD,
    0x548dbc7: RECORD_BUILD,
    0x4e3a8f6: '4180beaa00000000',   # cmp byte [r14+0xaa], 0
    0x4e3a8fe: '7437',               # je exit
    0x50e60bb: 'c604030a',           # '\n'
    0x537d600: 'c604017b',           # '{'
    0x537d617: '488d4b08',           # lea rcx, [rbx+0x8]   (height value)
    0x537d627: 'ba06000000',         # len 6
    0x537d641: '488d4b10',           # lea rcx, [rbx+0x10]  (digest value)
    0x537d651: 'ba0b000000',         # len 11
    0x537d673: 'ba12000000',         # len 18
    0x537d678: '4889d9',             # mov rcx, rbx         (tree value)
    0x537d6aa: 'c604307d',           # '}'
    0x506d58c: '803a01',             # cmp byte [rdx], 1    (node tag)
    0x506d58f: '751d',               # jne leaf
    0x506d5d1: 'be42000000b920000000',  # capacity 0x42, length 0x20
    0x5025a3a: 'c604305b',           # '['
    0x5025b31: 'be42000000b920000000',
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x548d90a, b'\xff\x15', 6, 0x64e7820),
    (0x548d9b1, b'\xff\x15', 6, 0x64e0990),
    (0x548d9e9, b'\xe8', 5, LINE),
    (0x548db1a, b'\xff\x15', 6, 0x64e7820),
    (0x548dbc1, b'\xff\x15', 6, 0x64e0990),
    (0x548dbf9, b'\xe8', 5, LINE),
    (0x4e3a7e0, b'\xff\x15', 6, 0x64e0f80),
    (0x4e3a863, b'\xff\x15', 6, 0x64e0020),
    (0x4e3a8dc, b'\xe8', 5, SERIALISE),
    (0x4e3a900, b'\x48\x8b\x05', 7, 0x64e0f88),
    (0x50e600e, b'\xe8', 5, RECORD),
    (0x50e60d0, b'\xe8', 5, 0x14c37f0),
    (0x537d61b, b'\x48\x8d\x35', 7, 0x924ed9),
    (0x537d645, b'\x48\x8d\x35', 7, 0x924edf),
    (0x537d667, b'\x48\x8d\x35', 7, 0x924eea),
    (0x537d67b, b'\xe8', 5, TREE_FIELD),
    (0x506d5a9, b'\xe9', 5, NODE),
    (0x506d5de, b'\xe8', 5, HEX_WRAP),
    (0x5025add, b'\xe8', 5, NODE),
    (0x5025b42, b'\xe8', 5, HEX_WRAP),
    (0x4e1c260, b'\xff\x15', 6, 0x64e4d08),
)
REFERENCES += (
    (0x537d656, b'\xe8', 5, DIGEST_FIELD),
    (0x5073bf9, b'\xe8', 5, HEX_WRAP),
)


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, raw in STRINGS.items():
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'string at {va:#x} changed')

    line_calls = direct_calls(data, LINE)
    if line_calls != [0x548d9e9, 0x548dbf9]:
        raise ValueError('line call census changed')
    if [frame(fdes, v) for v in line_calls] != [STEP_B, STEP_A]:
        raise ValueError('line callers moved')
    if direct_calls(data, SERIALISE) != [0x4e3a8dc] or direct_calls(data, RECORD) != [0x50e600e]:
        raise ValueError('serialiser census changed')
    if direct_calls(data, TREE_FIELD) != [0x537d67b]:
        raise ValueError('tree field census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'calls': {hex(v): hex(frame(fdes, v)) for v in line_calls},
        'record': {
            '+0x0': 'r12: the hash tree passed to the root hash (slot 0x64e7820 -> 0x41c5140)',
            '+0x8': 'box +0x28 (height)',
            '+0x10..+0x30': 'the 32-byte root digest returned through rdi',
            'time': 'wall clock, slot 0x64e0990 -> 0x1629690',
            'writer': 'the step third argument (engine value +0x330 per #6024 / #6033)',
        },
        'line_function': {
            'fn': hex(LINE),
            'path': 'rotation sink 0x1546570, open 0x14c3b30',
            'serialiser': '%s -> %s, then newline and 0x14c37f0' % (hex(SERIALISE), hex(RECORD)),
            'extra_flush': 'only if writer +0xaa and global byte 0x64ffe50 are both non-zero',
        },
        'line': {
            'format': '{"height":<u64>,"abci_digest":"0x<64 hex>","exchange_abci_hash":<tree>}\\n',
            'abci_digest': '%s -> %s: capacity 0x42, length 0x20' % (hex(DIGEST_FIELD), hex(HEX_WRAP)),
            'exchange_abci_hash': '%s: tag 1 -> node writer %s (JSON array, recursive); else leaf 32 bytes '
                                  'at +0x1 via %s, capacity 0x42, length 0x20' % (
                                      hex(TREE_FIELD), hex(NODE), hex(HEX_WRAP)),
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
    print('line calls=%s' % ','.join(result['calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
