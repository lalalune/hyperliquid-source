#!/usr/bin/env python3
"""Bind the node #115 freeze height, the snapshot divisor and the periodic path (31st stage).

Continues the fast_abci_engine packet (open PR #5925), which found that the
step 0x5a08720 picks the label 'freeze' from box +0x1c58/+0x1c60 and
'periodic' from height % 10000, and tests a second divisor at box +0x4538.
This tool binds:

1. the only stores to box +0x1c58/+0x1c60: the setter 0x54c9b80, reached
   only from case 31 of the action dispatcher 0x5397b50 (jump table
   0x9226b4); the case rejects a height >= 0x0ccccccccccccccc (tag 0x154);
   the setter returns 0x77 when a freeze height is set and the new one is
   not lower, 0x76 when the new one is below the height (+0x28) or above
   height + 50000 (saturating), else stores Some(new) and returns 0x1a2;
2. the only store to box +0x4538 (0x539e19c), reached from case 108: the
   value is rejected when >= 0x0ccccccccccccccc (0x154) or when 10000 is
   not a multiple of it (0x155);
3. the freeze file path: lazy cell 0x64fdd00 (initializer 0x5620340) built
   from the root cell 0x64f06c0 +0x18 and template 0x445085
   ("{}/hyperliquid_data/freeze_abci_height"); its slot 0x64ebc88 is loaded
   only in 0x5443930 and 0x59ec200, each of which later calls the string
   writer 0x15024a0 (slot 0x64e09e8; template "fu_write_string_to_file_tmp/");
4. the step after the label: calls 0x5485f80 and 0x452aab0; when the hour
   from 0x1567ad0 is >= 2 it formats {root}/data/periodic_abci_states, adds
   -1 day with 0x16290d0, formats {}/{} and calls slot 0x64e1220 (0x1563fc0)
   with that path and box byte +0x170a; later it calls 0x5a046f0.

The body of 0x1563fc0 is not read. The captured binary is not executed.
objdump and readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-freeze-snapshot-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SETTER = 0x54c9b80
DISPATCHER = 0x5397b50
JUMP_TABLE = 0x9226b4
FREEZE_CELL, FREEZE_INIT, FREEZE_SLOT = 0x64fdd00, 0x5620340, 0x64ebc88
WRITER, WRITER_SLOT = 0x15024a0, 0x64e09e8
CLEANUP, CLEANUP_SLOT = 0x1563fc0, 0x64e1220
ROOT_SLOT, ROOT_CELL = 0x64e0918, 0x64f06c0
HOUR_SLOT, DATE_ADD_SLOT = 0x64e0f58, 0x64e0aa0
PERIODIC_STR = 0x646e9f0
LIMIT = 0x0ccccccccccccccc

FIXED = {
    # dispatcher case 31: bound check then the setter
    0x5399631: '498b5708',              # mov rdx, [r15+8]
    0x5399635: '48b8cccccccccccccc0c',  # movabs rax, 0x0ccccccccccccccc
    0x539963f: '4839c2',                # cmp rdx, rax
    0x5399642: '0f83c8690000',          # jae 0x53a0010
    0x53a0015: '66c745005401',          # mov word [rbp], 0x154
    # setter 0x54c9b80
    0x54c9b8d: '83be581c000001',        # cmp dword [rsi+0x1c58], 1     (Some)
    0x54c9b96: '488b8e601c0000',        # mov rcx, [rsi+0x1c60]
    0x54c9b9d: '4839ca',                # cmp rdx, rcx
    0x54c9ba0: '7336',                  # jae -> 0x77
    0x54c9ba2: '488b4e28',              # mov rcx, [rsi+0x28]           (height)
    0x54c9ba6: '4839ca',                # cmp rdx, rcx
    0x54c9ba9: '7223',                  # jb -> 0x76
    0x54c9bae: '4881efb03cffff',        # sub rdi, -50000
    0x54c9bb7: '4881c150c30000',        # add rcx, 50000
    0x54c9bbe: '48c7c7ffffffff',        # mov rdi, -1
    0x54c9bc5: '480f43f9',              # cmovae rdi, rcx               (saturate)
    0x54c9bc9: '4839fa',                # cmp rdx, rdi
    0x54c9bcc: '7614',                  # jbe -> store
    0x54c9bce: '66c7007600',            # mov word [rax], 0x76
    0x54c9bd8: '66c7007700',            # mov word [rax], 0x77
    0x54c9be2: '48c786581c000001000000',  # mov qword [rsi+0x1c58], 1
    0x54c9bed: '488996601c0000',        # mov [rsi+0x1c60], rdx
    0x54c9bf4: '66c700a201',            # mov word [rax], 0x1a2
    # dispatcher case 108: divisor checks and the store
    0x53982f3: '498b4f08',              # mov rcx, [r15+8]
    0x53982f7: '48b8cccccccccccccc0c',  # movabs rax, 0x0ccccccccccccccc
    0x5398304: '0f831a7d0000',          # jae 0x53a0024
    0x53a0029: '66c745005401',          # mov word [rbp], 0x154
    0x539830a: 'ba10270000',            # mov edx, 10000
    0x539830f: '4881f910270000',        # cmp rcx, 10000
    0x5398316: '7709',                  # ja (remainder stays 10000)
    0x5398318: 'b810270000',            # mov eax, 10000
    0x539831d: '31d2',                  # xor edx, edx
    0x539831f: 'f7f1',                  # div ecx
    0x5398321: '4885d2',                # test rdx, rdx
    0x5398324: '0f84725e0000',          # je 0x539e19c
    0x539832f: '66c745005501',          # mov word [rbp], 0x155
    0x539e19c: '49898d38450000',        # mov [r13+0x4538], rcx
    # freeze path initializer
    0x5620351: '418b4650',              # mov eax, [r14+0x50]           (root Once state)
    0x5620359: '4983c618',              # add r14, 0x18
    # the two slot users: digit-count compare before the writer call
    0x5443b44: '4881f97f969800',        # cmp rcx, 9999999
    0x59ec444: '4881f97f969800',        # cmp rcx, 9999999
    # step after the label
    0x5a08930: '3c02',                  # cmp al, 2                     (hour)
    0x5a08932: '0f8208010000',          # jb 0x5a08a40                  (skip)
    0x5a089ba: 'beffffffff',            # mov esi, -1                   (days)
    0x5a08a2b: '0fb6b80a170000',        # movzx edi, byte [rax+0x170a]
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5399650, b'\xe8', 5, SETTER),
    (0x562034a, b'\x4c\x8b\x35', 7, ROOT_SLOT),
    (0x562036d, b'\x48\x8d\x35', 7, 0x445085),
    (0x5443ab7, b'\x4c\x8b\x3d', 7, FREEZE_SLOT),
    (0x59ec3b5, b'\x4c\x8b\x35', 7, FREEZE_SLOT),
    (0x5443beb, b'\xff\x15', 6, WRITER_SLOT),
    (0x59ec4ef, b'\xff\x15', 6, WRITER_SLOT),
    (0x15024e6, b'\x48\x8d\x35', 7, 0x44b7f0),
    (0x5a0887e, b'\xe8', 5, 0x5485f80),
    (0x5a08919, b'\xe8', 5, 0x452aab0),
    (0x5a0892a, b'\xff\x15', 6, HOUR_SLOT),
    (0x5a08938, b'\x4c\x8b\x2d', 7, ROOT_SLOT),
    (0x5a0895f, b'\x48\x8d\x05', 7, PERIODIC_STR),
    (0x5a08977, b'\x48\x8d\x35', 7, 0x448b77),
    (0x5a089bf, b'\xff\x15', 6, DATE_ADD_SLOT),
    (0x5a089f2, b'\x48\x8d\x35', 7, 0x43aa84),
    (0x5a08a3a, b'\xff\x15', 6, CLEANUP_SLOT),
    (0x5a08ac7, b'\xe8', 5, 0x5a046f0),
)
RELOCATIONS = {
    FREEZE_CELL: FREEZE_INIT, FREEZE_SLOT: FREEZE_CELL, WRITER_SLOT: WRITER,
    CLEANUP_SLOT: CLEANUP, ROOT_SLOT: ROOT_CELL, HOUR_SLOT: 0x1567ad0,
    DATE_ADD_SLOT: 0x16290d0, PERIODIC_STR: 0x7a1572,
}
STRINGS = {
    0x445085: b'\xc0\x24/hyperliquid_data/freeze_abci_height',
    0x7a1572: b'periodic_abci_states',
    0x448b77: b'\xc0\x06/data/\xc0\x00',
    0x43aa84: b'\xc0\x01/\xc0\x00',
    0x44b7f0: b'\x1cfu_write_string_to_file_tmp/',
}


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


def frame(fdes, va):
    hits = [f for f in fdes if f['start'] <= va < f['end']]
    if len(hits) != 1:
        raise ValueError(f'{va:#x} is not in exactly one FDE')
    return hits[0]['start']


def direct_calls(data, target):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    return out


def disp32_stores(data, disp):
    """mov/movb [reg+disp32], src|imm without SIB, with or without REX. One entry per instruction."""
    base, code = text(data)
    found = set()
    for m in re.finditer(re.escape(struct.pack('<I', disp)), code):
        i = m.start()
        for j in (i - 2, i - 3):
            if j < 0:
                continue
            k = j + (1 if j == i - 3 else 0)
            if j == i - 3 and not 0x40 <= code[j] <= 0x4f:
                continue
            op, modrm = code[k], code[k + 1]
            if op in (0x88, 0x89, 0xc6, 0xc7) and modrm >> 6 == 2 and modrm & 7 != 4:
                found.add(base + (j if j == i - 3 else j))
    starts = sorted(found)
    # a REX-prefixed instruction also matches one byte later without its prefix
    return [v for v in starts if v - 1 not in found]


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
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    length = struct.unpack('<Q', read_va(data, PERIODIC_STR + 8, 8))[0]
    if length != len(STRINGS[0x7a1572]):
        raise ValueError('periodic directory name length changed')

    table = read_va(data, JUMP_TABLE, 4 * 109)
    cases = {k: JUMP_TABLE + struct.unpack_from('<i', table, 4 * k)[0] for k in (31, 108)}
    if cases != {31: 0x5399631, 108: 0x53982f3}:
        raise ValueError('dispatcher cases changed')

    stores = {hex(d): [hex(v) for v in disp32_stores(data, d)] for d in (0x1c58, 0x1c60, 0x4538)}
    if stores != {'0x1c58': ['0x54c9be2'], '0x1c60': ['0x54c9bed'], '0x4538': ['0x539e19c']}:
        raise ValueError('store census changed')
    setter_calls = direct_calls(data, SETTER)
    if setter_calls != [0x5399650] or frame(fdes, 0x5399650) != DISPATCHER:
        raise ValueError('setter call census changed')
    users = sorted({frame(fdes, va) for va in (0x5443ab7, 0x59ec3b5)})

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'freeze_height': {
            'stores': {'+0x1c58': stores['0x1c58'], '+0x1c60': stores['0x1c60']},
            'setter': hex(SETTER),
            'setter_direct_calls': [hex(v) for v in setter_calls],
            'dispatcher_case': 'case 31 of %s (table %s) -> %s' % (hex(DISPATCHER), hex(JUMP_TABLE), hex(cases[31])),
            'bound': 'value >= %s -> tag 0x154' % hex(LIMIT),
            'rules': ['Some(old) and new >= old -> 0x77',
                      'new < height (+0x28) -> 0x76',
                      'new > height + 50000 (saturating) -> 0x76',
                      'else store Some(new) -> 0x1a2'],
        },
        'snapshot_divisor': {
            'store': stores['0x4538'],
            'dispatcher_case': 'case 108 -> %s' % hex(cases[108]),
            'bound': 'value >= %s -> tag 0x154' % hex(LIMIT),
            'rule': 'value > 10000 or 10000 % value != 0 -> tag 0x155 (div ecx at 0x539831f)',
        },
        'freeze_file': {
            'cell': '%s (initializer %s)' % (hex(FREEZE_CELL), hex(FREEZE_INIT)),
            'template': '0x445085 = {root}/hyperliquid_data/freeze_abci_height (root = cell %s +0x18)' % hex(ROOT_CELL),
            'slot': hex(FREEZE_SLOT),
            'slot_users': [hex(v) for v in users],
            'writer': '%s via slot %s (template 0x44b7f0 fu_write_string_to_file_tmp/)' % (hex(WRITER), hex(WRITER_SLOT)),
        },
        'periodic_cleanup_call': {
            'hour_gate': 'slot %s (0x1567ad0) result >= 2' % hex(HOUR_SLOT),
            'directory': '{root}/data/periodic_abci_states (template 0x448b77, name 0x7a1572 len 20)',
            'day_shift': 'slot %s (0x16290d0) with -1' % hex(DATE_ADD_SLOT),
            'path': '{dir}/{date} (template 0x43aa84)',
            'call': '%s via slot %s at 0x5a08a3a with the path and box byte +0x170a; body not read'
                    % (hex(CLEANUP), hex(CLEANUP_SLOT)),
            'other_calls': ['0x5a0887e -> 0x5485f80', '0x5a08919 -> 0x452aab0', '0x5a08ac7 -> 0x5a046f0'],
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
    print('freeze stores=%s divisor store=%s' % (result['freeze_height']['stores'], result['snapshot_divisor']['store']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
