#!/usr/bin/env python3
"""Bind the node #115 exchange abci hash input: 59 slots and their box fields (48th stage).

Continues #6023 and #6024 (stage 47), which found that the digest step builds
its hash input in 0x4e34ce0 and hashes it with BLAKE3. This tool binds:

1. the input builder 0x4e34ce0: a 74-pointer array at rsp+0x128 (the box base
   r15 plus 73 `lea rax, [r15+disp32]` field addresses), and a 0x588-byte
   allocation of 59 0x18-byte slots, each preset to 0x8000000000000001, passed
   with the pointer array to 0x54423c0; a result byte of 4 continues to the
   tree hasher through slot 0x64df500;
2. 0x54423c0: 59 (data, vtable) entries at rsp+0x10+0x10k; entry 0 carries the
   pointer array itself (the box base and 15 more fields), entry k>=1 carries
   pointer k+15; the slot vector length must be 59 (`cmp [rsi+0x10], 0x3b`),
   and the jobs go to 0x57c3b30 with edx = 59;
3. the per-entry vtables: size, alignment and first two methods by relocation;
4. the tree hasher 0x141a250 (slot 0x64df500): a node whose first word is
   0x8000000000000000 is a leaf, a boxed 0x798-byte record whose 0x778-byte
   state at +0x20 is updated with the buffered bytes (slot 0x64df510 ->
   0x160b3a0) and finalized (slot 0x64df518 -> 0x160bcd0); any other node is
   a vector of 0x18-byte children, children equal to 0x8000000000000001 are
   skipped and the rest are hashed by a recursive call through 0x64df500.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from freeze_snapshot_115 import fixed, read_va, relative_relocations

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-hash-slots-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

BUILDER_TABLE = (0x4e34d06, 0x4e35155)
ENTRY_TABLE = (0x54423c7, 0x5442a1e)
POINTER_BASE = 0x128
SLOTS = 59
SLOT_SIZE = 0x18
NONE_SLOT = 0x8000000000000001
LEAF_TAG = 0x8000000000000000

FIXED = {
    # builder: slot vector and the call into the entry table
    0x4e35155: 'bf88050000',                # mov edi, 0x588 (59 * 0x18)
    0x4e35169: '49bc0100000000000080',      # movabs r12, 0x8000000000000001
    0x4e35173: '4c8920',                    # mov [rax], r12
    0x4e352f6: '4c89a070050000',            # mov [rax+0x570], r12 (slot 58)
    0x4e352fd: '48c74424183b000000',        # mov qword [rsp+0x18], 59 (capacity)
    0x4e3530b: '48c74424283b000000',        # mov qword [rsp+0x28], 59 (length)
    0x4e35317: '488dbc2428010000',          # lea rdi, [rsp+0x128] (pointer array)
    0x4e3531f: '488d742418',                # lea rsi, [rsp+0x18] (slot vector)
    0x4e35324: 'e897d06000',                # call 0x54423c0
    0x4e35329: '3c04',                      # cmp al, 4
    0x4e35359: 'ff15a1a16a01',              # call [rip] -> slot 0x64df500
    # entry table and the job call
    0x54423c0: '4881ec680b0000',            # sub rsp, 0xb68
    0x5442a2d: '48837e103b',                # cmp qword [rsi+0x10], 59
    0x54435b2: 'ba3b000000',                # mov edx, 59
    0x54435b7: 'e874053800',                # call 0x57c3b30
    # tree hasher
    0x141a264: '48b90100000000000080',      # movabs rcx, 0x8000000000000001
    0x141a275: '48ffc9',                    # dec rcx (-> leaf tag)
    0x141a278: '4839c8',                    # cmp rax, rcx
    0x141a27b: '0f85c5000000',              # jne 0x141a346 (inner node)
    0x141a292: 'ba78070000',                # mov edx, 0x778 (hasher state copy)
    0x141a2d2: 'ff1538520c05',              # call [rip] -> slot 0x64df510 (update)
    0x141a2e8: 'ff152a520c05',              # call [rip] -> slot 0x64df518 (finalize)
    0x141a331: 'be98070000',                # mov esi, 0x798 (free the leaf box)
    0x141a3c5: '48b90100000000000080',      # movabs rcx, 0x8000000000000001 (skip)
    0x141a3f1: 'ff1509510c05',              # call [rip] -> slot 0x64df500 (recurse)
}
RELOCATIONS = {0x64df500: 0x141a250, 0x64df510: 0x160b3a0, 0x64df518: 0x160bcd0}

# Expected result, pinned so that a byte change shows as a table difference.
GROUP = [0x0, 0x7c0, 0x80, 0x7d8, 0x968, 0xb9a, 0xb98, 0x9f8,
         0x670, 0xb78, 0xa78, 0x9b0, 0xa18, 0xb99, 0xb90, 0xa38]
ENTRY_FIELDS = [
    0x3ac0, 0x3ad8, 0x3af0, 0x4158, 0x4168, 0x3c58, 0x41e8, 0xba0, 0x3f08, 0xd88,
    0x4200, 0x4220, 0x10e8, 0x4178, 0x4288, 0x4294, 0x4228, 0x3ce8, 0x3f88, 0x4188,
    0x3fa8, 0x3fc8, 0x42ac, 0x4230, 0x4238, 0x10f8, 0x4240, 0x3a00, 0x3a40, 0x3a80,
    0x1108, 0x3d40, 0x4198, 0x3ff8, 0x4018, 0x4038, 0x37e0, 0x42ad, 0x4058, 0x40a0,
    0x40c0, 0x41a8, 0x41d8, 0x4250, 0x42a0, 0x42ae, 0x4268, 0x37f0, 0x4138, 0x42af,
    0x3830, 0x3d78, 0x3858, 0x42b0, 0x4270, 0x3d98, 0x3e50, 0x3908,
]


def builder_pointers(data):
    """Decode the builder's pointer stores; only three instruction forms are allowed."""
    lo, hi = BUILDER_TABLE
    code = read_va(data, lo, hi - lo)
    i, rax, out = 0, None, {}
    while i < len(code):
        if code[i:i + 3] == b'\x49\x8d\x87':            # lea rax, [r15+disp32]
            rax = struct.unpack_from('<i', code, i + 3)[0]
            i += 7
        elif code[i:i + 4] in (b'\x48\x89\x84\x24', b'\x4c\x89\xbc\x24'):  # mov [rsp+d32], rax/r15
            slot = struct.unpack_from('<i', code, i + 4)[0]
            value = rax if code[i] == 0x48 else 0
            if value is None or (slot - POINTER_BASE) % 8:
                raise ValueError(f'unexpected store at {lo + i:#x}')
            out[(slot - POINTER_BASE) // 8] = value
            i += 8
        else:
            raise ValueError(f'unexpected builder instruction at {lo + i:#x}')
    if sorted(out) != list(range(74)):
        raise ValueError('pointer array changed')
    return [out[k] for k in range(74)]


def entry_table(data):
    """Decode 0x54423c0's (data, vtable) stores: lea r,[rip+d32]; mov r,[rdi+d]; mov [rsp+d],r."""
    lo, hi = ENTRY_TABLE
    code = read_va(data, lo, hi - lo)
    i, regs, stores = 0, {}, {}
    while i < len(code):
        rex, op = code[i], code[i + 1]
        if code[i:i + 5] == b'\x48\x89\x7c\x24\x10':    # mov [rsp+0x10], rdi
            stores[0x10] = ('array', None)
            i += 5
            continue
        if rex not in (0x48, 0x4c) or op not in (0x8d, 0x8b, 0x89):
            raise ValueError(f'unexpected entry-table instruction at {lo + i:#x}')
        modrm = code[i + 2]
        mod, reg, rm = modrm >> 6, ((rex >> 2) & 1) << 3 | (modrm >> 3) & 7, modrm & 7
        if op == 0x8d and mod == 0 and rm == 5:          # lea reg, [rip+d32]
            regs[reg] = ('vtable', lo + i + 7 + struct.unpack_from('<i', code, i + 3)[0])
            i += 7
        elif op == 0x8b and rm == 7 and mod in (1, 2):   # mov reg, [rdi+d8/d32]
            disp = struct.unpack_from('<i' if mod == 2 else '<b', code, i + 3)[0]
            regs[reg] = ('pointer', disp)
            i += 7 if mod == 2 else 4
        elif op == 0x89 and rm == 4 and code[i + 3] == 0x24 and mod in (1, 2):  # mov [rsp+d], reg
            disp = struct.unpack_from('<i' if mod == 2 else '<b', code, i + 4)[0]
            stores[disp] = regs[reg]
            i += 8 if mod == 2 else 5
        else:
            raise ValueError(f'unexpected entry-table form at {lo + i:#x}')
    entries = []
    for k in range(SLOTS):
        data_ref, vtable = stores[0x10 + 0x10 * k], stores[0x18 + 0x10 * k]
        if vtable[0] != 'vtable':
            raise ValueError(f'entry {k} has no vtable')
        if k == 0:
            if data_ref != ('array', None):
                raise ValueError('entry 0 no longer carries the pointer array')
            index = None
        else:
            if data_ref[0] != 'pointer' or data_ref[1] % 8:
                raise ValueError(f'entry {k} data changed')
            index = data_ref[1] // 8
        entries.append((index, vtable[1]))
    return entries


def bind(data):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    pointers = builder_pointers(data)
    if pointers[:16] != GROUP:
        raise ValueError('grouped pointers changed')
    entries = entry_table(data)
    rows = []
    for k, (index, vtable) in enumerate(entries):
        if k and index != k + 15:
            raise ValueError(f'entry {k} no longer takes pointer {k + 15}')
        size, align = struct.unpack('<QQ', read_va(data, vtable + 8, 16))
        methods = [rel.get(vtable + off) for off in (0, 0x18, 0x20)]
        if None in methods[1:]:
            raise ValueError(f'vtable {vtable:#x} lost a relocation')
        if methods[0] is None and read_va(data, vtable, 8) != bytes(8):
            raise ValueError(f'vtable {vtable:#x} drop slot changed')
        rows.append({
            'slot': k,
            'box_field': 'group: base + 15 fields' if k == 0 else hex(pointers[index]),
            'pointer_index': index,
            'vtable': hex(vtable),
            'type_size': size,
            'type_align': align,
            'drop': hex(methods[0]) if methods[0] else 'none (null)',
            'method_0': hex(methods[1]),
            'method_1': hex(methods[2]),
        })
    if [int(r['box_field'], 16) for r in rows[1:]] != ENTRY_FIELDS:
        raise ValueError('slot to box-field table changed')
    vtables = [r['vtable'] for r in rows]
    shared = {v: [r['slot'] for r in rows if r['vtable'] == v] for v in sorted(set(vtables))
              if vtables.count(v) > 1}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'builder': {
            'fn': '0x4e34ce0',
            'pointer_array': 'rsp+0x128, 74 pointers: [0] box base r15, [1..73] lea rax,[r15+disp32]',
            'slot_vector': '0x588 bytes = 59 slots of 0x18, each preset %s, cap/len 59' % hex(NONE_SLOT),
            'entry_call': '0x4e35324 call 0x54423c0 (rdi pointer array, rsi slot vector); al == 4 continues',
            'tree_call': '0x4e35359 call [0x64df500] -> 0x141a250 with the slot vector',
        },
        'entry_table': {
            'fn': '0x54423c0',
            'layout': 'entry k at rsp+0x10+0x10k: data, then vtable; entry 0 data = the pointer array',
            'length_check': '0x5442a2d cmp qword [rsi+0x10], 59',
            'job_call': '0x54435b7 call 0x57c3b30 with edx = 59',
            'distinct_vtables': len(set(vtables)),
            'shared_vtables': shared,
        },
        'group_fields': [hex(v) for v in GROUP],
        'slots': rows,
        'tree_hasher': {
            'fn': '0x141a250 (slot 0x64df500)',
            'leaf': 'first word %s: boxed 0x798-byte record; 0x778-byte state at +0x20 copied, '
                    'buffer (+0x8 ptr, +0x10 len) fed to slot 0x64df510 -> 0x160b3a0, finalized by '
                    'slot 0x64df518 -> 0x160bcd0; output byte 0 then 32 bytes; record freed' % hex(LEAF_TAG),
            'inner': 'vector of 0x18-byte children; %s skipped (0x141a3c5); others hashed by a '
                     'recursive call through 0x64df500 (0x141a3f1)' % hex(NONE_SLOT),
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
    result = bind(binary.read_bytes())
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
    print(f"slots={len(result['slots'])} vtables={result['entry_table']['distinct_vtables']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
