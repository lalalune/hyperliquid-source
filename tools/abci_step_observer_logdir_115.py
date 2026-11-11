#!/usr/bin/env python3
"""Bind who builds node #115 line writers and where they are stored (seventh stage).

Continues the observer packets for 0x1547530. The sixth stage found that the
observer constructor 0x1548bb0 stores both writer states (+0x98, +0x148) as
None and that the observer skips its path check and write while a state is
None. This tool binds:

1. the two writer constructors: daily 0x1546700 (slot 0x64e0f98) and hourly
   0x1546000 (slot 0x64e0fa0), with their call census;
2. the daily constructor: a name that ends or starts with '/' branches away
   from the build path; the directory is formatted from template 0x448b77
   ("{}/data/{}") with the root at lazy cell 0x64f06c0 +0x18 (slot 0x64e0918)
   and the name; the constant name "daily_liner" (11 bytes) is passed on;
3. the hourly constructor: stores 1 to writer +0xa8 (the hourly byte);
4. the root cell 0x64f06c0: its value word is relocated to the initializer
   0x17785f0, which formats template 0x43de2f ("{}/code");
5. where writers go in the four functions that call both a writer constructor
   and the observer constructor (slot 0x64e1020): in 0x51c9cb0 and 0x5a6bfb0
   the 0xb0-byte writers are copied next to the 0x260-byte observers, not
   into them;
6. a census of every `mov edx, 0xb0` preceded by `lea rdi, [reg+disp]`: the
   only non-stack destinations at an offset congruent to 0x98 or 0x148 modulo
   0x260 are the constructor's two None copies.

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
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-logdir-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DAILY_SLOT, DAILY = 0x64e0f98, 0x1546700
HOURLY_SLOT, HOURLY = 0x64e0fa0, 0x1546000
CTOR_SLOT, CTOR = 0x64e1020, 0x1548bb0
ROOT_SLOT, ROOT_CELL, ROOT_INIT = 0x64e0918, 0x64f06c0, 0x17785f0
OBSERVER_SIZE, WRITER_SIZE = 0x260, 0xb0
STATE_OFFSETS = (0x98, 0x148)

STRINGS = {
    0x448b77: '{}/data/{}',
    0x43de2f: '{}/code',
}
DAILY_NAME = (0x466d9c, b'daily_liner')

FIXED = {
    # daily constructor: '/' checks on the last and first name byte
    0x154673b: '43807c3eff2f',          # cmp byte [r14+r15-1], '/'
    0x1546741: '0f8443020000',          # je 0x154698a
    0x1546747: '41803e2f',              # cmp byte [r14], '/'
    0x154674b: '0f8439020000',          # je 0x154698a
    0x154675f: '418b4650',              # mov eax, [r14+0x50]          (root Once state)
    0x154676b: '4983c618',              # add r14, 0x18                (root +0x18)
    0x15467c9: 'ba0b000000',            # mov edx, 11                  (len "daily_liner")
    # hourly constructor: hourly byte
    0x1546046: 'c683a800000001',        # mov byte [rbx+0xa8], 1
    # 0x51c9cb0: three observers then one writer into the parent r12
    0x51c9e58: '4c89e7',                # mov rdi, r12                 (+0x0)
    0x51c9e5e: '498dbc2460020000',      # lea rdi, [r12+0x260]
    0x51c9e6e: 'ba60020000',            # mov edx, 0x260
    0x51c9e76: '498dbc24c0040000',      # lea rdi, [r12+0x4c0]
    0x51c9e86: 'ba60020000',            # mov edx, 0x260
    0x51c9e9a: '498dbc2420070000',      # lea rdi, [r12+0x720]         (writer)
    0x51c9ea2: '488d742458',            # lea rsi, [rsp+0x58]          (writer built here)
    0x51c9ea7: 'bab0000000',            # mov edx, 0xb0
    # 0x5a6bfb0: one observer then two writers on the stack
    0x5a6c547: '488dbc2460120000',      # lea rdi, [rsp+0x1260]
    0x5a6c557: 'ba60020000',            # mov edx, 0x260
    0x5a6c55f: '488dbc24c0140000',      # lea rdi, [rsp+0x14c0]
    0x5a6c56f: 'bab0000000',            # mov edx, 0xb0
    0x5a6c577: '488dbc2470150000',      # lea rdi, [rsp+0x1570]
    0x5a6c587: 'bab0000000',            # mov edx, 0xb0
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x1546758, b'\x4c\x8b\x35', 7, ROOT_SLOT),
    (0x1546774, b'\x48\x8d\x05', 7, 0x15433a0),    # root display fn
    (0x1546799, b'\x48\x8d\x35', 7, 0x448b77),
    (0x15467ba, b'\x48\x8d\x35', 7, DAILY_NAME[0]),
    (0x177866c, b'\x48\x8d\x35', 7, 0x43de2f),
    (0x51c9d22, b'\xff\x15', 6, CTOR_SLOT),
    (0x51c9d82, b'\xff\x15', 6, CTOR_SLOT),
    (0x51c9dd3, b'\xff\x15', 6, CTOR_SLOT),
    (0x51c9e3e, b'\xff\x15', 6, DAILY_SLOT),
    (0x51c9e4c, b'\x4c\x8b\x3d', 7, 0x64df508),    # memcpy slot
    (0x5a6c42c, b'\xff\x15', 6, DAILY_SLOT),
    (0x5a6c442, b'\xff\x15', 6, HOURLY_SLOT),
    (0x5a6c45c, b'\xff\x15', 6, DAILY_SLOT),
    (0x5a6c472, b'\xff\x15', 6, HOURLY_SLOT),
    (0x5a6c496, b'\xff\x15', 6, CTOR_SLOT),
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


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def frame_starts(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start'], ordered[i]['end']
    return frame


def lea_rdi(window, j):
    """Decode `lea rdi, [base+disp8/disp32]` at window[j]; return (disp, base is rsp) or None."""
    rex, op, modrm = window[j], window[j + 1], window[j + 2]
    if rex not in (0x48, 0x49, 0x4c, 0x4d) or op != 0x8d:
        return None
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | ((rex & 4) << 1), modrm & 7
    if reg != 7 or mod not in (1, 2):
        return None
    k = j + 3 + (1 if rm == 4 else 0)
    width = 4 if mod == 2 else 1
    if k + width > len(window):
        return None
    disp = struct.unpack_from('<i' if width == 4 else '<b', window, k)[0]
    on_stack = rm == 4 and (window[j + 3] & 7) == 4 and not rex & 1
    return disp, on_stack


def writer_copies(data):
    """Every `mov edx, 0xb0` with a `lea rdi, [base+disp]` in the 24 bytes before it."""
    base, code = text(data)
    total, decoded, state_like = 0, 0, []
    for m in re.finditer(rb'\xba\xb0\x00\x00\x00', code):
        total += 1
        i = m.start()
        window = code[max(0, i - 24):i]
        found = None
        for j in range(len(window) - 3):
            found = lea_rdi(window, j) or found
        if found is None:
            continue
        decoded += 1
        disp, on_stack = found
        if not on_stack and disp % OBSERVER_SIZE in STATE_OFFSETS:
            state_like.append((base + i, disp))
    return total, decoded, state_like


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')

    rel = relative_relocations(data)
    slots = {DAILY_SLOT: DAILY, HOURLY_SLOT: HOURLY, CTOR_SLOT: CTOR, ROOT_SLOT: ROOT_CELL, ROOT_CELL: ROOT_INIT}
    for slot, target in slots.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if read_va(data, DAILY_NAME[0], len(DAILY_NAME[1])) != DAILY_NAME[1]:
        raise ValueError('writer name changed')
    data_template = read_va(data, 0x448b77, 10)
    code_template = read_va(data, 0x43de2f, 7)
    if data_template != b'\xc0\x06/data/\xc0\x00' or code_template != b'\xc0\x05/code':
        raise ValueError('path templates changed')

    frame = frame_starts(fdes)
    daily, hourly, ctor = (slot_calls(data, s) for s in (DAILY_SLOT, HOURLY_SLOT, CTOR_SLOT))
    writer_fns = {frame(v) for v in daily + hourly}
    ctor_fns = {frame(v) for v in ctor}
    shared = sorted(writer_fns & ctor_fns)
    for va in (0x51c9e3e, 0x5a6c42c, 0x5a6c496):
        if frame(va) not in shared:
            raise ValueError('shared function census changed')
    total, decoded, state_like = writer_copies(data)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'writer_constructors': {
            'daily': {'fn': hex(DAILY), 'slot': hex(DAILY_SLOT), 'calls': len(daily)},
            'hourly': {'fn': hex(HOURLY), 'slot': hex(HOURLY_SLOT), 'calls': len(hourly),
                       'hourly_byte': hex(0x1546046) + ' mov byte [rbx+0xa8], 1'},
            'functions_calling_either': len(writer_fns),
        },
        'daily_constructor': {
            'name_slash_checks': [hex(0x154673b) + ' last byte', hex(0x1546747) + ' first byte'],
            'slash_branch': hex(0x154698a),
            'directory_template': hex(0x448b77) + ' ' + data_template.hex() + ' = {}/data/{}',
            'root_argument': 'slot %s -> cell %s, Once state +0x50, value +0x18, display %s'
                             % (hex(ROOT_SLOT), hex(ROOT_CELL), hex(0x15433a0)),
            'constant_name': '%s %r (len %d)' % (hex(DAILY_NAME[0]), DAILY_NAME[1].decode(), len(DAILY_NAME[1])),
        },
        'root_cell': {
            'cell': hex(ROOT_CELL),
            'initializer': hex(ROOT_INIT) + ' (R_X86_64_RELATIVE value word)',
            'code_template': hex(0x43de2f) + ' ' + code_template.hex() + ' = {}/code, used at ' + hex(0x177866c),
        },
        'observer_constructor': {'fn': hex(CTOR), 'slot': hex(CTOR_SLOT), 'calls': len(ctor),
                                 'functions': len(ctor_fns)},
        'functions_calling_both': [hex(a) for a, _ in shared],
        'placement': {
            '0x51c9cb0': 'observers (0x260) -> parent +0x0, +0x260, +0x4c0; daily writer (0xb0) -> parent +0x720',
            '0x5a6bfb0': 'observer (0x260) -> rsp+0x1260; two writers (0xb0) -> rsp+0x14c0, rsp+0x1570',
        },
        'writer_copy_census': {
            'mov_edx_0xb0': total,
            'with_lea_rdi_base_disp': decoded,
            'non_stack_state_offset_mod_0x260': [[hex(v), hex(d)] for v, d in state_like],
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
    w = result['writer_constructors']
    print(f"daily={w['daily']['calls']} hourly={w['hourly']['calls']} shared={len(result['functions_calling_both'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
