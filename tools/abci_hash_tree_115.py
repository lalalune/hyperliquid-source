#!/usr/bin/env python3
"""Bind how the node #115 abci hash tree folds its slots into the root digest (49th stage).

Continues the abci hash packets (open PRs #6024, #6027). #6027 found that
the input builder 0x4e34ce0 fills 59 slots and passes them through slot
0x64df500 to 0x141a250. This tool binds:

1. 0x141a250 is the only target of slot 0x64df500 (R_X86_64_RELATIVE) and
   calls itself through that slot for each child;
2. leaf (first word 0x8000000000000000): the boxed 0x798-byte record holds a
   buffer Vec at +0x0..+0x18, a byte at +0x18 and a 0x778-byte hasher state
   at +0x20; the state is copied, the buffered bytes are fed through slot
   0x64df510 (0x160b3a0, BLAKE3 update) and slot 0x64df518 (0x160bcd0,
   finalize) gives 32 bytes; result = tag 0 + 32 bytes; the box is freed
   (0x798); a set byte at +0x18 calls slot 0x64df4b8 with a 23-byte slice
   at 0x450102 before hashing;
3. node (other first word): a Vec of 0x18-byte children; children whose first
   word is 0x8000000000000001 are skipped; each other child is recursed and
   pushed with its index as a 0x30-byte (index, child result) element into a
   Vec (first allocation 0xc0 = 4 elements, growth through 0x141b050 with
   align 8 / size 0x30); result = tag 1 + (cap, ptr, len); no hash is computed
   for a node here; 0x141c180 drops the unused child iterator;
4. the root: 0x41c5140 (slot 0x64e7820) serialises the tree with config
   0x400 - a node (tag 1) through 0x41444a0; a leaf (tag 0) is first written
   by 0x2eabb50 (slot 0x64e4d08) as "0x" plus lowercase hex (buffer 0x42,
   32 input bytes, table 0x455d40) and serialised through 0x41c6110 - then
   hashes the bytes from the BLAKE3 IV at 0x457ae0 (#6024).

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
from freeze_snapshot_115 import direct_calls, read_va, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-hash-tree-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

TREE = (0x141a250, 0x141a8bf)
GROW = (0x141b050, 0x141b0de)
DROP_ITER = (0x141c180, 0x141c240)
ROOT_HASH = (0x41c5140, 0x41c540a)
TREE_SLOT, UPDATE_SLOT, FINAL_SLOT = 0x64df500, 0x64df510, 0x64df518
ROOT_SLOT, HEX_SLOT = 0x64e7820, 0x64e4d08
HEX_FN, HEX_TABLE = 0x2eabb50, 0x455d40
IV = 0x457ae0
RELOCS = {TREE_SLOT: TREE[0], UPDATE_SLOT: 0x160b3a0, FINAL_SLOT: 0x160bcd0,
          ROOT_SLOT: ROOT_HASH[0], HEX_SLOT: HEX_FN}

FIXED = {
    # 0x141a250: leaf test (first word == 0x8000000000000000)
    0x141a264: '48b90100000000000080',  # movabs rcx, 0x8000000000000001
    0x141a275: '48ffc9',                # dec rcx
    0x141a278: '4839c8',                # cmp rax, rcx
    0x141a27b: '0f85c5000000',          # jne 0x141a346 (node)
    # leaf: byte +0x18, copy the 0x778-byte hasher, flush, finalize
    0x141a281: '410fb65f18',            # movzx ebx, byte [r15+0x18]
    0x141a292: 'ba78070000',            # mov edx, 0x778
    0x141a2a8: '80fb01',                # cmp bl, 1
    0x141a2b4: 'be17000000',            # mov esi, 0x17
    0x141a325: '0f114d11',              # movups [rbp+0x11], xmm1
    0x141a329: '0f114501',              # movups [rbp+0x1], xmm0   (32-byte digest)
    0x141a32d: 'c6450000',              # mov byte [rbp], 0        (tag leaf)
    0x141a331: 'be98070000',            # mov esi, 0x798           (free the box)
    # node: skip None children, recurse, collect 0x30-byte elements
    0x141a3c5: '48b90100000000000080',  # movabs rcx, 0x8000000000000001
    0x141a3cf: '4839c8',                # cmp rax, rcx
    0x141a3d2: '74dc',                  # je 0x141a3b0             (skip)
    0x141a3ff: '80bc24f800000002',      # cmp byte [rsp+0xf8], 2
    0x141a4ab: 'bfc0000000',            # mov edi, 0xc0            (4 x 0x30)
    0x141a6a0: 'b908000000',            # mov ecx, 8               (align)
    0x141a6a5: '41b830000000',          # mov r8d, 0x30            (element size)
    0x141a6c7: '4b8d0c76',              # lea rcx, [r14+r14*2]
    0x141a6cb: '48c1e104',              # shl rcx, 4               (index * 0x30)
    0x141a74d: 'c6450001',              # mov byte [rbp], 1        (tag node)
    # 0x41c5140: serialise the tree, then BLAKE3
    0x41c5185: 'c744242800040000',      # mov dword [rsp+0x28], 0x400
    0x41c5192: '803e01',                # cmp byte [rsi], 1        (node?)
    0x41c51f6: 'be42000000',            # mov esi, 0x42            (hex buffer)
    0x41c51fb: 'b920000000',            # mov ecx, 0x20            (32 bytes in)
    # 0x2eabb50: "0x" prefix
    0x2eabb62: '66c7073078',            # mov word [rdi], 0x7830
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x141a297, b'\xff\x15', 6, 0x64df508),       # memcpy 0x778
    (0x141a2ad, b'\x48\x8d\x3d', 7, 0x450102),
    (0x141a2b9, b'\xff\x15', 6, 0x64df4b8),
    (0x141a2d2, b'\xff\x15', 6, UPDATE_SLOT),
    (0x141a2e8, b'\xff\x15', 6, FINAL_SLOT),
    (0x141a3f1, b'\xff\x15', 6, TREE_SLOT),       # first child recursion
    (0x141a595, b'\xff\x15', 6, TREE_SLOT),       # later children
    (0x141a4b0, b'\xff\x15', 6, 0x64df480),       # alloc 0xc0
    (0x141a6b3, b'\xe8', 5, GROW[0]),
    (0x141a72d, b'\xe8', 5, DROP_ITER[0]),
    (0x4e35359, b'\xff\x15', 6, TREE_SLOT),       # builder -> tree
    (0x548db1a, b'\xff\x15', 6, ROOT_SLOT),       # digest step -> root hash
    (0x41c51a5, b'\xe8', 5, 0x41444a0),           # node serialiser
    (0x41c5203, b'\xff\x15', 6, HEX_SLOT),
    (0x41c5211, b'\xe8', 5, 0x41c6110),           # str serialiser
    (0x41c52f5, b'\x0f\x10\x0d', 7, IV),          # movups xmm1, [IV]
    (0x2eabb89, b'\x48\x8d\x05', 7, HEX_TABLE),
)


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if read_va(data, HEX_TABLE, 16) != b'0123456789abcdef':
        raise ValueError('hex table changed')
    if read_va(data, 0x450102, 10) != b'hash error':
        raise ValueError('leaf error slice changed')
    for lo, hi in (TREE, GROW, DROP_ITER, ROOT_HASH):
        if not any(f['start'] == lo and f['end'] == hi for f in fdes):
            raise ValueError(f'FDE {lo:#x} changed')

    tree_calls = slot_calls(data, TREE_SLOT)
    inside = [v for v in tree_calls if TREE[0] <= v < TREE[1]]
    outside = [v for v in tree_calls if not TREE[0] <= v < TREE[1]]
    tree_slots = sorted(s for s, t in rel.items() if t == TREE[0])
    root_calls = slot_calls(data, ROOT_SLOT)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'tree': {
            'fde': [hex(v) for v in TREE],
            'slots_relocated_to_it': [hex(v) for v in tree_slots],
            'self_calls': [hex(v) for v in inside],
            'callers_outside': [hex(v) for v in outside],
            'leaf': ('first word 0x8000000000000000: box 0x798 = {buffer Vec +0x0..+0x18, byte +0x18, '
                     'state 0x778 at +0x20}; byte == 1 -> slot 0x64df4b8 with (0x450102, 23); buffered bytes '
                     '-> 0x160b3a0 (update), 0x160bcd0 (finalize) -> tag 0 + 32 bytes; box freed'),
            'node': ('otherwise Vec of 0x18-byte children; first word 0x8000000000000001 skipped; each other '
                     'child recursed and pushed as (index, child result) in 0x30-byte elements; first alloc '
                     '0xc0, growth 0x141b050 (align 8, size 0x30) -> tag 1 + (cap, ptr, len); no hash'),
            'grow_direct_calls': [hex(v) for v in direct_calls(data, GROW[0])],
            'drop_iter_direct_calls': [hex(v) for v in direct_calls(data, DROP_ITER[0])],
        },
        'root': {
            'fde': [hex(v) for v in ROOT_HASH],
            'slot': hex(ROOT_SLOT),
            'slot_calls': [hex(v) for v in root_calls],
            'serialise_config': '0x400',
            'node': 'tag 1 -> 0x41444a0',
            'leaf': ('tag 0 -> 0x2eabb50 writes "0x" + lowercase hex (buffer 0x42, 32 bytes, table '
                     '0x455d40) -> 0x41c6110'),
            'hash': 'BLAKE3 from IV 0x457ae0 (#6024)',
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
    t = result['tree']
    print(f"self_calls={len(t['self_calls'])} outside={len(t['callers_outside'])} root_calls={len(result['root']['slot_calls'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
