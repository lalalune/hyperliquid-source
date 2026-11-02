#!/usr/bin/env python3
"""Extract the node 94 binary configuration pair-map path from ELF bytes.

The x86 length reader below is adapted from the repository's MIT-licensed
``tools/nv_stream_inventory.py``. It recognizes only explicitly admitted byte
forms; semantic claims below use additional fixed-byte witnesses. No captured
executable or external program is run.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
TARGET = ROOT / 'artifacts/node/94/hl-node'


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def verify_identity(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == DIGEST,
            'node 94 size or SHA-256 mismatch')


class View:
    def __init__(self, data, section_rows=None):
        self.data = data
        self.sections = sections(data) if section_rows is None else section_rows

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0
                and va + size <= 1 << 64, 'invalid VA range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'VA range lacks a unique allocated file-backed section')
        s = matches[0]
        pos = s['offset'] + va - s['address']
        require(0 <= pos <= len(self.data) - size, 'mapped range extends beyond input')
        return pos

    def read(self, va, size):
        pos = self.offset(va, size)
        return self.data[pos:pos + size]

    def section(self, name):
        rows = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing or ambiguous file-backed section ' + name)
        return rows[0]


def decode_instruction(code, offset=0, base=0):
    """Restricted legacy x86-64 length decoder, not a general disassembler.

    Decode sequentially from FDE entry; never resynchronize after an unknown
    opcode. ModRM/SIB/displacements and immediates are consumed, so opcode-like
    bytes inside operands cannot become anchors. Only enumerated forms pass.
    Operand semantics used for claims get a second exact decoder below.
    """
    require(0 <= offset < len(code), 'instruction offset outside input')
    start = offset
    def take(n):
        nonlocal offset
        require(offset + n <= len(code), 'truncated instruction')
        value = code[offset:offset+n]
        offset += n
        require(offset - start <= 15, 'overlong instruction')
        return value
    def byte():
        return take(1)[0]
    prefixes = []
    while offset < len(code) and code[offset] in (0x66, 0xf2, 0xf3, 0xf0, 0x2e, 0x64):
        p = byte()
        require(p not in prefixes or p == 0x66, 'duplicate legacy prefix')
        prefixes.append(p)
    require(not (0xf2 in prefixes and 0xf3 in prefixes), 'conflicting repeat prefixes')
    rex = 0
    if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
        rex = byte()
    op = byte()
    operand = 2 if 0x66 in prefixes and not rex & 8 else 4
    kind, imm, modrm, group = 'other', 0, False, None
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        require(not prefixes and not rex, 'unsupported branch prefixes')
        kind = 'call_rel32' if op == 0xe8 else 'jmp_rel32' if op == 0xe9 else 'branch'
        imm = 4 if op in (0xe8, 0xe9) else 1
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else operand
        kind = 'mov_imm'
    elif 0xb0 <= op <= 0xb7:
        imm = 1
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc3, 0xcc, 0xc9, 0xfc):
        pass
    elif op in (0x68, 0x6a, 0xa8, 0xa9, 0xc2):
        imm = 2 if op == 0xc2 else 1 if op in (0x6a, 0xa8) else operand
    elif op in tuple(x + y for x in range(0, 0x40, 8) for y in range(4)) + (
            0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7,
            0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff):
        modrm = True
        if op in (0x69, 0x81, 0xc7): imm = operand
        if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6): imm = 1
        if op in (0x8f, 0xc6, 0xc7): group = {0}
        if op == 0xfe: group = {0, 1}
        if op == 0xff: group = {0, 1, 2, 4, 6}  # excludes far forms and reserved /7
        if op in (0xf6, 0xf7): group = {0, 2, 3, 4, 5, 6, 7}
        if op == 0x8d: kind = 'lea'
        if op == 0xc7: kind = 'mov_imm'
    elif op < 0x40 and op % 8 in (4, 5):
        imm = 1 if op % 8 == 4 else operand
    elif op == 0x0f:
        op2 = byte()
        if 0x80 <= op2 <= 0x8f:
            require(not prefixes and not rex, 'unsupported conditional branch prefixes')
            imm, kind = 4, 'branch'
        elif op2 == 0x0b:
            kind = 'ud2'
        elif 0xc8 <= op2 <= 0xcf:  # BSWAP registers
            pass
        elif op2 in (0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29,
                     0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x50, 0x51, 0x54, 0x55,
                     0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
                     0x5f, 0x60, 0x61, 0x62, 0x66, 0x6c, 0x6d, 0x6e, 0x6f,
                     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7e, 0x7f,
                     0xa3, 0xab, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xba,
                     0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc6,
                     0xd4, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef, 0xf3,
                     0xf4, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
            modrm = True
            if op2 in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc6): imm = 1
            if op2 == 0x1f: group = {0}
            if op2 in (0x71, 0x72): group = {2, 4, 6}
            if op2 == 0x73: group = {2, 3, 6, 7}
            if op2 == 0xba: group = {4, 5, 6, 7}
        else:
            raise EvidenceError(f'unsupported 0f opcode {op2:02x}')
    else:
        raise EvidenceError(f'unsupported opcode {op:02x}')
    if modrm:
        m = byte()
        mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
        require(group is None or reg in group, 'unsupported ModRM group')
        require(op != 0x8d or mod != 3, 'register-source LEA is invalid')
        if op in (0xf6, 0xf7) and reg == 0: imm = 1 if op == 0xf6 else operand
        if mod != 3:
            if rm == 4:
                sib = byte()
                if mod == 0 and sib & 7 == 5: take(4)
            elif mod == 0 and rm == 5:
                take(4)
            if mod == 1: take(1)
            if mod == 2: take(4)
        if 0xf0 in prefixes:
            require(mod != 3 and (op in (0x01, 0x09, 0x21, 0x29, 0x31, 0x80, 0x81, 0x83, 0xff)
                    or op == 0x0f and op2 in (0xb0, 0xb1, 0xc0, 0xc1)), 'unsupported LOCK form')
    else:
        require(0xf0 not in prefixes, 'LOCK without memory operand')
    if 0xf0 in prefixes and op in (0x80, 0x81, 0x83):
        require(reg != 7, 'LOCK CMP is invalid')
    if 0xf0 in prefixes and op == 0xff:
        require(reg in (0, 1), 'unsupported LOCK FF group')
    if prefixes.count(0x66) > 1 or 0x2e in prefixes:
        require(op == 0x0f and op2 == 0x1f and all(p in (0x66, 0x2e) for p in prefixes),
                'redundant prefixes only supported on NOP')
    if 0x64 in prefixes:
        require(prefixes == [0x64] and modrm and mod != 3 and op in (0x8b, 0x89, 0x80, 0x83, 0x88, 0xc6, 0x0f, 0xff, 0x22),
                'unsupported FS form')
    take(imm)
    return {'site': base + start, 'raw': bytes(code[start:offset]), 'kind': kind}


# Each start names an FDE selected for its role in this one field's binary path.
SELECTED = (
    ('binary_field_map', 0x13bffa0),
    ('optional_second_value', 0x13aa5f0),
    ('discard_pair', 0x13b2f30),
    ('insert_or_replace', 0x14cbfa0),
    ('split_insert', 0x13a3440),
    ('split_cleanup', 0x1396c80),
    ('drop_map', 0x14daa70),
    ('drain_map', 0x14cd630),
    ('unexpected_slice', 0x14d0eb0),
    ('map_value_type_error', 0x14d4c60),
)

# These adjacent signed-rel32 tables are read as data, not disassembly output.
# Outer and value tables are independently indexed; their ext sub-tables are
# indexed by tag - 0xc7 and their raw-byte tables by byte - 0xc0.
TABLES = (
    ('outer_cached_tag', 0x215184, 225, 0),
    ('outer_extended', 0x215508, 18, 0xc7),
    ('outer_raw_marker', 0x215550, 32, 0xc0),
    ('value_cached_tag', 0x2155d0, 225, 0),
    ('value_extended', 0x215954, 18, 0xc7),
    ('value_raw_marker', 0x21599c, 32, 0xc0),
)


def selected_fdes(view):
    _, all_fdes = eh_frame_records(view.data, view.sections)
    rows = []
    for role, start in SELECTED:
        matches = [f for f in all_fdes if f['start'] == start]
        require(len(matches) == 1, 'selected FDE missing or ambiguous')
        fde = dict(matches[0], role=role)
        require(fde['end'] > start, 'empty selected FDE')
        view.offset(start, fde['end'] - start)
        code_sections = [s for s in view.sections if s['type'] != 8 and s['flags'] & 4
                         and s['address'] <= start and fde['end'] <= s['address'] + s['size']]
        require(len(code_sections) == 1, 'selected FDE is not uniquely file-backed executable code')
        rows.append(fde)
    return rows, all_fdes


def decode_body(view, fde):
    start, end = fde['start'], fde['end']
    code = view.read(start, end - start)
    out = []
    off = 0
    while off < len(code):
        try:
            item = decode_instruction(code, off, start)
        except EvidenceError as exc:
            raise EvidenceError(f"unsupported instruction in {fde['role']} at {start + off:#x}: {exc}") from exc
        raw = item['raw']
        op = raw[0]
        kind = item['kind']
        target = None
        if op in (0xe8, 0xe9):
            target = item['site'] + len(raw) + int.from_bytes(raw[-4:], 'little', signed=True)
            kind = 'call' if op == 0xe8 else 'jump'
        elif op == 0xeb or 0x70 <= op <= 0x7f:
            target = item['site'] + len(raw) + int.from_bytes(raw[-1:], 'little', signed=True)
            kind = 'jump' if op == 0xeb else 'conditional'
        elif op == 0x0f and len(raw) == 6 and 0x80 <= raw[1] <= 0x8f:
            target = item['site'] + len(raw) + int.from_bytes(raw[-4:], 'little', signed=True)
            kind = 'conditional'
        elif raw[:1] in (b'\xc3', b'\xc2'):
            kind = 'return'
        elif raw[:2] == b'\x0f\x0b' or raw[:1] == b'\xcc':
            kind = 'trap'
        else:
            prefix = 1 if raw and 0x40 <= raw[0] <= 0x4f else 0
            if len(raw) >= prefix + 2 and raw[prefix] == 0xff:
                modrm = raw[prefix + 1]
                group = (modrm >> 3) & 7
                if group in (2, 4):
                    kind = 'indirect_call' if group == 2 else 'indirect_jump'
                    if modrm in (0x15, 0x25) and len(raw) == prefix + 6:
                        target = item['site'] + len(raw) + int.from_bytes(raw[-4:], 'little', signed=True)
        out.append(dict(role=fde['role'], site=item['site'], raw=raw, kind=kind, target=target))
        off += len(raw)
    require(off == len(code), 'instruction partition does not end at FDE end')
    starts = {r['site'] for r in out}
    for row in out:
        target = row['target']
        if row['kind'] in ('conditional', 'jump', 'call') and target is not None and start <= target < end:
            require(target in starts, 'local transfer points inside an instruction')
    return out


def table_rows(view, instruction_starts):
    result = []
    for label, base, count, index_base in TABLES:
        require(0 < count <= 256, 'invalid selected table size')
        for n in range(count):
            slot = base + n * 4
            raw = view.read(slot, 4)
            dest = base + struct.unpack('<i', raw)[0]
            require(dest in instruction_starts, 'dispatch target is not a selected instruction start')
            result.append((label, n + index_base, slot, view.offset(slot, 4), raw.hex(), dest))
    return result


def relocation_rows(view, slots):
    rela = view.section('.rela.dyn')
    require(rela['size'] % 24 == 0, 'unexpected RELA size')
    dynsym, dynstr = view.section('.dynsym'), view.section('.dynstr')
    found = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        dest, info, addend = struct.unpack_from('<QQq', view.data, off)
        if dest not in slots:
            continue
        require(dest not in found, 'duplicate selected relocation')
        kind, sym = info & 0xffffffff, info >> 32
        symbol = ''
        if sym:
            require(sym * 24 + 24 <= dynsym['size'], 'dynamic symbol outside table')
            name = struct.unpack_from('<I', view.data, dynsym['offset'] + sym * 24)[0]
            require(name < dynstr['size'], 'dynamic symbol name outside table')
            first = dynstr['offset'] + name
            last = view.data.find(b'\0', first, dynstr['offset'] + dynstr['size'])
            require(last >= 0, 'unterminated dynamic symbol name')
            symbol = view.data[first:last].decode('ascii')
        found[dest] = (dest, off, kind, sym, addend, symbol, view.data[off:off + 24].hex())
    require(set(found) == set(slots), 'selected relocation is missing')
    return [found[s] for s in sorted(slots)]


def lsda_rows(view, selected, all_fdes, instructions):
    """Decode supported ULEB call-site records, leaving action/type semantics open."""
    sec = view.section('.gcc_except_table')
    all_starts = sorted({f['lsda'] for f in all_fdes if f['lsda'] is not None})
    starts = {r['site'] for r in instructions}
    calls = [r for r in instructions if r['kind'] in ('call', 'indirect_call')]
    rows = []
    for f in selected:
        va = f['lsda']
        if va is None:
            continue
        upper = min([s for s in all_starts if s > va] + [sec['address'] + sec['size']])
        require(sec['address'] <= va < upper <= sec['address'] + sec['size'], 'LSDA range outside section')
        raw = view.read(va, upper - va)
        require(len(raw) >= 4 and raw[0] == 0xff and raw[1] in (0xff, 0x9b), 'unsupported LSDA header')
        pos = 2
        type_end = None
        if raw[1] != 0xff:
            displacement, pos = uleb(raw, pos, len(raw))
            type_end = pos + displacement
            require(type_end <= len(raw), 'LSDA type base outside range')
        require(pos < len(raw) and raw[pos] == 1, 'unsupported LSDA call-site encoding')
        pos += 1
        size, pos = uleb(raw, pos, len(raw))
        end = pos + size
        require(end <= len(raw) and (type_end is None or end <= type_end), 'invalid LSDA table size')
        last_end = 0
        while pos < end:
            entry = pos
            vals = []
            for _ in range(4):
                n, pos = uleb(raw, pos, end)
                vals.append(n)
            first, length, landing, action = vals
            require(length > 0 and first >= last_end and first + length <= f['end'] - f['start'],
                    'LSDA call-site range outside FDE or overlaps')
            lo, hi = f['start'] + first, f['start'] + first + length
            dest = f['start'] + landing if landing else None
            require(lo in starts and (hi in starts or hi == f['end']), 'LSDA range is not instruction-aligned')
            require(dest is None or (f['start'] <= dest < f['end'] and dest in starts), 'invalid landing site')
            inside = [r['site'] for r in calls if r['role'] == f['role'] and lo <= r['site'] < hi]
            rows.append((f['role'], va, va + entry, raw[entry:pos].hex(), lo, hi, dest, action, inside))
            last_end = first + length
        require(pos == end, 'truncated LSDA entry')
    return rows

WITNESSES = (
    ('reader_consume_cached', 0x13bffc3, '41c6462001'),
    ('outer_table', 0x13bffc8, '488d0db551e5fe'),
    ('outer_indirect_jump', 0x13bffd6, '41ffe0'),
    ('outer_map_low_nibble', 0x13c0336, '240f'),
    ('outer_map_count', 0x13c0338, '440fb6e0'),
    ('outer_depth_load', 0x13c033c, '410fb74622'),
    ('outer_depth_zero', 0x13c0344, '0f8420120000'),
    ('outer_depth_decrement', 0x13c034a, '66ffc8'),
    ('outer_depth_store', 0x13c034d, '6641894622'),
    ('outer_depth_exhausted', 0x13c0352, '0f84ca0e0000'),
    ('outer_empty_count', 0x13c0370, '4585e4'),
    ('outer_empty_branch', 0x13c0373, '0f84890b0000'),
    ('outer_key_call', 0x13c03c0, 'e80bd9ffff'),
    ('outer_key_tag', 0x13c03cb, '4180fc09'),
    ('outer_key_error', 0x13c03cf, '0f85a50b0000'),
    ('value_cached_tag', 0x13c0405, '410fb65620'),
    ('value_reset_cached', 0x13c0412, '41c6462001'),
    ('value_dispatch_table', 0x13c0417, '488d3db251e5fe'),
    ('value_indirect_jump', 0x13c042d, 'ffe0'),
    ('value_raw_unsigned', 0x13c0915, '4080fedf'),
    ('value_raw_above', 0x13c0919, '0f8712fbffff'),
    ('value_raw_array', 0x13c091f, '4080fe90'),
    ('value_raw_array_branch', 0x13c0923, '0f8327010000'),
    ('value_raw_size_mask', 0x13c0a5a, '4080e60f'),
    ('value_size_load', 0x13c0a5e, '400fb6ee'),
    ('value_depth_load', 0x13c0a62, '410fb74622'),
    ('value_depth_zero', 0x13c0a6a, '0f845c0b0000'),
    ('value_depth_decrement', 0x13c0a70, '66ffc8'),
    ('value_depth_store', 0x13c0a73, '6641894622'),
    ('value_depth_exhausted', 0x13c0a78, '0f8442060000'),
    ('value_length_zero', 0x13c0a7e, '85ed'),
    ('value_length_zero_branch', 0x13c0a80, '0f8417080000'),
    ('first_value_call', 0x13c0a96, 'e835d2ffff'),
    ('first_value_success_tag', 0x13c0aa3, '3c09'),
    ('first_value_error', 0x13c0aa5, '0f850f080000'),
    ('first_value_absent', 0x13c0ab3, '4d39fd'),
    ('first_value_absent_branch', 0x13c0ab6, '0f84e1070000'),
    ('value_length_one', 0x13c0acc, '83fd01'),
    ('value_length_one_branch', 0x13c0acf, '0f841e080000'),
    ('second_value_call', 0x13c0ae8, 'e8039bfeff'),
    ('second_value_success_tag', 0x13c0af5, '3c09'),
    ('second_value_error', 0x13c0af7, '0f8532080000'),
    ('special_slot_min', 0x13c0b18, '48b90000000000000080'),
    ('special_slot_increment', 0x13c0b22, '48ffc1'),
    ('special_slot_cmp', 0x13c0b25, '4839c8'),
    ('special_slot_branch', 0x13c0b28, '0f84c5070000'),
    ('value_length_two', 0x13c0b97, '83fd02'),
    ('value_length_other_branch', 0x13c0b9a, '755c'),
    ('extra_item_status', 0x13c0bf8, 'c68424b800000004'),
    ('extra_item_expected_count', 0x13c0c00, 'c78424bc00000002000000'),
    ('extra_item_cleanup_call', 0x13c0c25, 'e80623ffff'),
    ('value_depth_restore', 0x13c0c3b, '6641894622'),
    ('map_insert_call', 0x13c0e46, 'e855b11000'),
    ('map_old_sentinel', 0x13c0e4b, '49bf0000000000000080'),
    ('map_old_compare', 0x13c0e5a, '4c39fe'),
    ('map_old_no_value_branch', 0x13c0e5d, '0f8447f5ffff'),
    ('missing_first_boundary', 0x13c12b0, 'e83b3dffff'),
    ('missing_second_boundary', 0x13c130c, 'e8df3cffff'),
    ('map_error_drop', 0x13c144f, 'e81c961100'),
    ('map_final_depth_restore', 0x13c14ff, '6641894622'),
    ('map_publish_success_tag', 0x13c14e6, 'c684248001000009'),
    ('optional_cached_tag', 0x13aa5f8, '0fb64620'),
    ('optional_reset_tag', 0x13aa600, 'c6462001'),
    ('optional_null_compare', 0x13aa604, '3dc0000000'),
    ('optional_null_branch', 0x13aa609, '7474'),
    ('optional_fresh_compare', 0x13aa60b, '83f801'),
    ('optional_fresh_missing', 0x13aa617, '741f'),
    ('optional_marker_c0', 0x13aa671, '3cc0'),
    ('optional_marker_c0_branch', 0x13aa673, '7308'),
    ('optional_none_value', 0x13aa67f, '48b80000000000000080'),
    ('optional_none_store', 0x13aa689, '48894308'),
    ('optional_some_delegate', 0x13aa69d, 'e82e360100'),
    ('optional_some_tag', 0x13aa6a2, '803c2409'),
    ('optional_success', 0x13aa6ba, 'c60309'),
    ('insert_key_count', 0x14cbff0, '0fb78a22030000'),
    ('insert_key_base', 0x14cbfe4, '488d8218020000'),
    ('insert_key_compare', 0x14cc02e, 'ff1554242a04'),
    ('insert_match_branch', 0x14cc05b, '742e'),
    ('insert_incoming_key_free', 0x14cc0a2, 'ff15681f2a04'),
    ('insert_old_value_copy0', 0x14cc0d2, '0f100403'),
    ('insert_old_value_copy2', 0x14cc0e0, '0f115720'),
    ('insert_new_value_copy0', 0x14cc0eb, '0f1001'),
    ('insert_new_value_store0', 0x14cc0f6, '0f110403'),
    ('insert_replace_return', 0x14cc104, '4889f8'),
    ('insert_allocate_leaf', 0x14cc1ce, 'bf28030000'),
    ('insert_allocate_call', 0x14cc1d3, 'ff15ff1d2a04'),
    ('insert_allocate_fail', 0x14cc1dc, '0f84c4000000'),
    ('insert_init_leaf', 0x14cc1e2, '48c7801002000000000000'),
    ('insert_init_count', 0x14cc1ed, '66c780220300000000'),
    ('insert_publish_root', 0x14cc1f6, '49890424'),
    ('insert_capacity_check', 0x14cc22d, '4883f90b'),
    ('insert_capacity_failure', 0x14cc231, '0f8384000000'),
    ('insert_update_node_count', 0x14cc23d, '66899022030000'),
    ('insert_key_store', 0x14cc248, '4889acc818020000'),
    ('insert_value_store', 0x14cc27b, '0f110408'),
    ('insert_collection_increment', 0x14cc27f, '49ff442410'),
    ('insert_new_sentinel', 0x14cc284, '48b80000000000000080'),
    ('insert_oom_boundary', 0x14cc2b3, 'ff15671d2a04'),
    ('insert_cap_failure_boundary', 0x14cc2ce, 'ff15341e2a04'),
    ('split_capacity_check', 0x13a345f, '4983fe0b'),
    ('split_room_branch', 0x13a3463, '7233'),
    ('split_insertion_index_five', 0x13a346e, '4983fc05'),
    ('split_insertion_index_six', 0x13a34f3, '4983fc06'),
    ('split_leaf_alloc_size', 0x13a3642, 'bf28030000'),
    ('split_leaf_alloc', 0x13a3647, 'ff158ba93c04'),
    ('split_leaf_alloc_fail', 0x13a3650, '0f84450d0000'),
    ('split_new_node_count', 0x13a368b, '664489ab22030000'),
    ('split_original_node_count', 0x13a3745, '664589bc2422030000'),
    ('split_internal_alloc_size', 0x13a3a20, 'bf88030000'),
    ('split_internal_alloc', 0x13a3a25, 'ff15ada53c04'),
    ('split_internal_fail', 0x13a3a2e, '0f841b090000'),
    ('split_child_slot', 0x13a421a, '4d8984d430030000'),
    ('split_parent_count', 0x13a4222, '6641898c2422030000'),
    ('split_failure_trap', 0x13a440b, '0f0b'),
    ('split_cleanup_call', 0x13a4441, 'e83a28ffff'),
    ('drop_first_iterator', 0x14daad5, 'e8562bffff'),
    ('drop_key_capacity', 0x14dab1d, '4b8bb4ec18020000'),
    ('drop_key_free', 0x14dab3a, '41ffd7'),
    ('drop_first_capacity', 0x14dab44, '498b3424'),
    ('drop_first_free', 0x14dab54, '41ffd7'),
    ('drop_second_capacity', 0x14dab57, '498b742418'),
    ('drop_second_niche', 0x14dab5f, '48f7d8'),
    ('drop_second_overflow', 0x14dab62, '709c'),
    ('drop_second_zero', 0x14dab64, '739a'),
    ('drop_second_free', 0x14dab6d, '41ffd7'),
    ('drain_remaining', 0x14cd63e, '488b4640'),
    ('drain_decrement', 0x14cd64b, '48ffc8'),
    ('drain_store_remaining', 0x14cd64e, '48894640'),
    ('drain_node_count', 0x14cd70b, '0fb78f22030000'),
    ('drain_leaf_bytes', 0x14cd7b1, '41bf28030000'),
    ('drain_internal_bytes', 0x14cd7ca, 'be88030000'),
    ('error_formatter', 0x14d0f19, 'e84244eeff'),
    ('error_sentinel', 0x14d0f1e, '48b80000000000000080'),
)

EXTRA_WITNESSES = (
    ('outer_extension_table_lea', 0x13c0002, '488d15ff54e5fe'),
    ('outer_raw_table_lea', 0x13c11cf, '4c8d057a43e5fe'),
    ('value_extension_table_lea', 0x13c045d, '488d3df054e5fe'),
    ('value_raw_table_lea', 0x13c0c76, '4c8d0d1f4de5fe'),
    ('optional_high_cmp', 0x13aa64f, '3cdf'),
    ('optional_map_end', 0x13aa659, '3c90'),
    ('optional_nibble_mask', 0x13aa65d, '240f'),
    ('optional_array_end', 0x13aa665, '3ca0'),
    ('optional_string_mask', 0x13aa675, '241f'),
    ('optional_map_class', 0x13aa661, 'b080'),
    ('optional_array_class', 0x13aa66d, 'b090'),
    ('optional_string_class', 0x13aa679, 'b0a0'),
    ('optional_negative_class', 0x13aa655, 'b0e0'),
    ('raw_array_upper', 0x13c0a50, '4080fea0'),
    ('raw_string_upper', 0x13c0c5d, '4080fec0'),
    ('outer_fresh_scalar_jump', 0x13c018e, 'e946feffff'),
    ('outer_fresh_negative_branch', 0x13c0328, '0f87abfcffff'),
    ('outer_fresh_array_mask', 0x13c100d, '240f'),
    ('outer_fresh_string_jump', 0x13c1136, 'e989f0ffff'),
    ('value_fresh_scalar_jump', 0x13c0522, 'e90affffff'),
    ('value_fresh_map_mask', 0x13c0929, '4080e60f'),
    ('value_fresh_string_jump', 0x13c0c67, 'e924f8ffff'),
)


EXTRA_WITNESSES += (
    ('outer_extended_jump', 0x13c0010, 'ffe6'),
    ('outer_raw_jump', 0x13c11df, '41ffe1'),
    ('value_extended_jump', 0x13c046b, 'ffe1'),
    ('value_raw_jump', 0x13c0c86, '41ffe0'),
    ('split_ge_five', 0x13a3484, '7367'),
    ('split_pivot_before_five', 0x13a348b, '41bf04000000'),
    ('split_left_flag', 0x13a3491, '31ed'),
    ('split_equal_five', 0x13a34ed, '0f8418010000'),
    ('split_not_six', 0x13a34f7, '0f851a010000'),
    ('split_pivot_at_six', 0x13a34fd, '41bf05000000'),
    ('split_right_flag', 0x13a3503, '40b501'),
    ('split_equal_five_flag', 0x13a360b, '31ed'),
    ('split_equal_five_pivot', 0x13a3612, '4d89e7'),
    ('split_right_index_bias', 0x13a3617, '4983c4f9'),
    ('split_pivot_after_six', 0x13a3620, '41bf06000000'),
    ('split_select_old_if_zero', 0x13a3780, '807c243000'),
    ('split_choose_sibling', 0x13a3788, '4d0f44f4'),
    ('split_selected_node_count', 0x13a38ce, '664589be22030000'),
    ('map_value_depth_load', 0x13c0931, '410fb74622'),
    ('map_value_depth_zero', 0x13c0939, '0f84840c0000'),
    ('map_value_depth_decrement', 0x13c093f, '66ffc8'),
    ('map_value_depth_store', 0x13c0942, '6641894622'),
    ('map_value_depth_exhausted', 0x13c0947, '0f8473070000'),
    ('map_value_error_call', 0x13c095a, 'e801431100'),
    ('map_value_error_compare', 0x13c0980, '4c39f8'),
    ('map_value_error_branch', 0x13c0983, '0f84ff080000'),
    ('map_value_error_template', 0x14d4cb3, '488d3584ccd2fe'),
    ('map_value_error_format_call', 0x14d4cbf, 'e89c06eeff'),
    ('map_value_error_sentinel', 0x14d4cc4, '48b80000000000000080'),
    ('map_value_error_return_store', 0x14d4cce, '488903'),
    ('map_value_error_return', 0x14d4cd9, 'c3'),
    ('key_order_incoming_length', 0x14cbfe0, '4d8b7810'),
    ('key_order_stored_length', 0x14cc01d, '488b5010'),
    ('key_order_difference_init', 0x14cc021, '4d89fe'),
    ('key_order_difference_subtract', 0x14cc024, '4929d6'),
    ('key_order_min_length', 0x14cc027, '490f42d7'),
    ('key_order_sign_extend', 0x14cc034, '4898'),
    ('key_order_test_memcmp', 0x14cc036, '85c0'),
    ('key_order_nonzero_memcmp', 0x14cc038, '4c0f45f0'),
    ('key_order_test_sign', 0x14cc03c, '4d85f6'),
    ('key_order_negative', 0x14cc03f, '0f98c0'),
    ('key_order_positive', 0x14cc042, '0f9fc1'),
    ('key_order_normalize', 0x14cc045, '28c1'),
    ('replaced_first_test', 0x13c0e63, '4885f6'),
    ('replaced_first_empty_branch', 0x13c0e66, '740d'),
    ('replaced_first_release', 0x13c0e6f, 'ff159bd13a04'),
    ('replaced_second_load', 0x13c0e75, '488b742428'),
    ('replaced_second_none_cmp', 0x13c0e7a, '4c39fe'),
    ('replaced_second_none_branch', 0x13c0e7d, '0f8427f5ffff'),
    ('replaced_second_zero_test', 0x13c0e83, '4885f6'),
    ('replaced_second_zero_branch', 0x13c0e86, '0f841ef5ffff'),
    ('replaced_second_release', 0x13c0e93, 'ff1577d13a04'),
    ('discard_first_load', 0x13b2f34, '488b37'),
    ('discard_first_test', 0x13b2f37, '4885f6'),
    ('discard_first_zero_branch', 0x13b2f3a, '740c'),
    ('discard_second_load', 0x13b2f48, '488b7318'),
    ('discard_second_negate', 0x13b2f4f, '48f7d8'),
    ('discard_second_none_branch', 0x13b2f52, '700f'),
    ('discard_second_zero_branch', 0x13b2f54, '730d'),
    ('discard_second_release', 0x13b2f5d, 'ff25adb03b04'),
    ('value_depth_error_tag', 0x13c10c0, 'c644244808'),
    ('value_depth_zero_failure_call', 0x13c15e3, 'ff1567cb3a04'),
    ('value_depth_zero_trap', 0x13c1616, '0f0b'),
    ('outer_empty_zero_first', 0x13c0f02, '31ed'),
    ('outer_empty_zero_second', 0x13c0f04, '31c0'),
    ('outer_empty_zero_count', 0x13c0f06, 'c744247c00000000'),
    ('outer_empty_finish_jump', 0x13c0f0e, 'e95b050000'),
    ('map_error_to_common', 0x13c1298, 'e909010000'),
    ('map_error_common_to_drop', 0x13c13b2, 'eb3e'),
    ('map_output_high', 0x13c1514, '0f114b10'),
    ('map_output_low', 0x13c1518, '0f1103'),
    ('map_output_exit', 0x13c151b, 'e905fdffff'),
    ('array32_remaining_check', 0x13c04a1, '4883f804'),
    ('array32_short_header', 0x13c04a5, '0f82900c0000'),
    ('array32_load', 0x13c04ab, '8b29'),
    ('array32_reduce_remaining', 0x13c04ad, '4883c0fc'),
    ('array32_advance_pointer', 0x13c04b1, '4883c104'),
    ('array32_big_endian', 0x13c04b5, '0fcd'),
    ('array32_store_pointer', 0x13c04b7, '49894e10'),
    ('array32_store_remaining', 0x13c04bb, '49894618'),
    ('array32_join', 0x13c04bf, 'e99e050000'),
    ('array16_remaining_check', 0x13c07eb, '4883f802'),
    ('array16_short_header', 0x13c07ef, '0f8246090000'),
    ('array16_load', 0x13c07f5, '0fb711'),
    ('array16_reduce_remaining', 0x13c07f8, '4883c0fe'),
    ('array16_big_endian', 0x13c07fc, '66c1c208'),
    ('array16_advance_pointer', 0x13c0800, '4883c102'),
    ('array16_store_pointer', 0x13c0804, '49894e10'),
    ('array16_store_remaining', 0x13c0808, '49894618'),
    ('array16_count', 0x13c080c, '0fb7ea'),
    ('array16_join', 0x13c080f, 'e94e020000'),
    ('map16_remaining_check', 0x13c081c, '4883f802'),
    ('map16_short_header', 0x13c0820, '0f8215090000'),
    ('map16_load', 0x13c0826, '0fb711'),
    ('map16_big_endian', 0x13c082d, '66c1c208'),
    ('map16_join', 0x13c0840, 'e9ec000000'),
    ('map32_remaining_check', 0x13c0573, '4883f804'),
    ('map32_short_header', 0x13c0577, '0f82be0b0000'),
    ('map32_load', 0x13c057d, '8b29'),
    ('map32_big_endian', 0x13c0587, '0fcd'),
    ('map32_join', 0x13c0591, 'e99b030000'),
    ('short_header_consume_remaining', 0x13c113b, '4801c1'),
    ('short_header_store_pointer', 0x13c113e, '49894e10'),
    ('short_header_zero_remaining', 0x13c1142, '49c7461800000000'),
    ('short_header_error_tag', 0x13c114a, 'c644244801'),
    ('short_header_to_cleanup', 0x13c115b, 'e992020000'),
    ('unwind_missing_second_landing', 0x13c1618, 'eb3b'),
    ('unwind_second_reader_landing', 0x13c1655, '4889c3'),
    ('unwind_first_value_test', 0x13c1658, '4d85ed'),
    ('unwind_first_value_skip', 0x13c165b, '747a'),
    ('unwind_first_value_release', 0x13c166a, 'ff15a0c93a04'),
    ('unwind_first_reader_landing', 0x13c16d4, '4889c3'),
    ('unwind_key_test', 0x13c16d7, '4883bc240801000000'),
    ('unwind_key_skip', 0x13c16e0, '741d'),
    ('unwind_key_release', 0x13c16f4, 'ff1516c93a04'),
    ('unwind_insert_landing', 0x13c16fc, '4889c3'),
    ('unwind_map_drop', 0x13c1707, 'e864931100'),
    ('unwind_resume_call', 0x13c170f, 'e8fce92904'),
    ('unwind_split_failure_landing', 0x13a447c, '4989c7'),
    ('unwind_split_failure_jump', 0x13a447f, 'eb38'),
    ('unwind_split_value_cleanup', 0x13a44be, 'e8bd27ffff'),
    ('unwind_split_release_skip', 0x13a44c6, '0f8482000000'),
    ('unwind_split_resume_call', 0x13a44df, 'e82cbc2b04'),
    ('outer_map32_remaining_check', 0x13c00e0, '4883f904'),
    ('outer_map32_short_header', 0x13c00e4, '0f822f010000'),
    ('outer_map32_load', 0x13c00ee, '448b26'),
    ('outer_map32_big_endian', 0x13c00f5, '410fcc'),
    ('outer_map32_join', 0x13c0100, 'e937020000'),
    ('outer_map16_remaining_check', 0x13c0138, '4883f902'),
    ('outer_map16_short_header', 0x13c013c, '0f82d7000000'),
    ('outer_map16_load', 0x13c0146, '0fb706'),
    ('outer_map16_big_endian', 0x13c0149, '66c1c008'),
    ('outer_map16_join', 0x13c015d, 'e9da010000'),
    ('outer_short_header_consume', 0x13c0219, '4801ce'),
    ('outer_short_header_pointer', 0x13c021c, '49897610'),
    ('outer_short_header_remaining', 0x13c0220, '49c7461800000000'),
    ('outer_short_header_status', 0x13c0228, 'c60301'),
    ('outer_short_header_return', 0x13c0236, 'e9ea0f0000'),
    ('outer_key_missing_sentinel', 0x13c0379, '49bf0000000000000080'),
    ('outer_initial_remaining_count', 0x13c0383, '418d4424ff'),
    ('outer_store_remaining_count', 0x13c0388, '8944247c'),
    ('outer_remaining_count_decrement', 0x13c03aa, '8344247cff'),
    ('outer_remaining_count_finish', 0x13c03af, '0f830e0c0000'),
    ('outer_finish_clear_count', 0x13c0fc3, 'c744247c00000000'),
    ('outer_depth_exhausted_status', 0x13c1222, 'c60308'),
)


def witnesses(view, instructions):
    by_va = {r['site']: r for r in instructions}
    out = []
    for label, site, hexdump in WITNESSES + EXTRA_WITNESSES:
        require(site in by_va, 'witness is not at an instruction boundary: ' + label)
        row = by_va[site]
        require(row['raw'] == bytes.fromhex(hexdump), 'witness bytes changed: ' + label)
        require(view.read(site, len(row['raw'])) == row['raw'], 'witness differs from input')
        out.append((label, row['role'], site, view.offset(site, len(row['raw'])),
                    row['raw'].hex(), row['kind'], row['target']))
    return out


def relative_target(view, site, expected_prefix):
    raw = view.read(site, 7)
    require(raw[:3] == bytes.fromhex(expected_prefix), 'unexpected RIP-relative LEA')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def direct_call(view, site, target):
    raw = view.read(site, 5)
    require(raw[0] == 0xe8 and site + 5 + struct.unpack_from('<i', raw, 1)[0] == target,
            'context call does not resolve to expected target')
    return raw


def context_rows(view):
    """Keep older field-classifier/visitor bodies as attribution boundaries only."""
    literal = view.read(0x21bb8d, 26)
    require(literal == b'chain_to_etherscan_ws_urls', 'field literal changed')
    literal_ref = view.read(0x14a8022, 7)
    require(relative_target(view, 0x14a8022, '488d05') == 0x21bb8d,
            'field diagnostic points outside selected literal')
    literal_len = view.read(0x14a8031, 12)
    require(literal_len[:8] == bytes.fromhex('48c78424e8000000') and
            struct.unpack_from('<I', literal_len, 8)[0] == len(literal),
            'field diagnostic length disagrees with literal')
    length_bias = view.read(0x13c75e3, 4)
    length_range = view.read(0x13c75e7, 4)
    require(length_bias == bytes.fromhex('488d4afa') and
            length_range == bytes.fromhex('4883f91b'), 'prior length dispatch changed')
    length_base = relative_target(view, 0x13c75f1, '488d3d')
    length_index = len(literal) - 6
    length_slot = length_base + 4 * length_index
    length_bytes = view.read(length_slot, 4)
    length_target = length_base + struct.unpack('<i', length_bytes)[0]
    require(length_index <= 0x1b and length_target == 0x13c792a,
            'field length selects unexpected prior classifier arm')
    tag_store = view.read(0x13c7a39, 4)
    require(tag_store[:3] == bytes.fromhex('c64008'), 'unexpected classifier tag store')
    tag = tag_store[3]
    bias = view.read(0x13aca29, 3)
    require(bias[:2] == bytes.fromhex('8d42'), 'unexpected visitor table bias')
    first_tag = -struct.unpack('<b', bias[2:])[0]
    base = relative_target(view, 0x13aca3d, '488d0d')
    require(first_tag <= tag < first_tag + 24, 'field tag outside previously bounded visitor dispatch')
    slot = base + 4 * (tag - first_tag)
    raw = view.read(slot, 4)
    branch = base + struct.unpack('<i', raw)[0]
    require(branch == 0x13ad5da, 'field tag selects unexpected arm')
    call = direct_call(view, 0x13ad609, 0x13bffa0)
    checks = [
        ('field_literal', 0x21bb8d, literal, ''),
        ('prior_field_literal_reference', 0x14a8022, literal_ref, 0x21bb8d),
        ('prior_field_literal_length', 0x14a8031, literal_len, len(literal)),
        ('prior_classifier_length_bias', 0x13c75e3, length_bias, 6),
        ('prior_classifier_length_range', 0x13c75e7, length_range, 0x1b),
        ('prior_classifier_length_table', 0x13c75f1, view.read(0x13c75f1, 7), length_base),
        ('prior_classifier_length_slot', length_slot, length_bytes, length_target),
        ('prior_classifier_tag_store', 0x13c7a39, tag_store, tag),
        ('prior_visitor_index_bias', 0x13aca29, bias, first_tag),
        ('prior_visitor_table_lea', 0x13aca3d, view.read(0x13aca3d, 7), base),
        ('prior_visitor_table_slot', slot, raw, branch),
        ('prior_visitor_call', 0x13ad609, call, 0x13bffa0),
    ]
    return checks


def validate_relocations(rows):
    by_slot = {r[0]: r for r in rows}
    expected_relative = {
        0x576e928: 0x577b288, 0x576eb70: 0x577a898,
        0x577a898: 0x13d28e0, 0x5668488: 0x2180ff,
        0x576dfd8: 0x54c06b0, 0x576e010: 0x54c8cb0,
        0x576e020: 0x1345e2a, 0x576e108: 0x157b7f0,
        0x576e828: 0x13c22d0, 0x576e830: 0x13c5d90,
    }
    for slot, addend in expected_relative.items():
        r = by_slot[slot]
        require(r[2] == 8 and r[3] == 0 and r[4] == addend, 'RELATIVE relocation changed')
    require(by_slot[0x576e488][2] == 6 and by_slot[0x576e488][5] == 'memcmp',
            'comparison relocation is not GLOB_DAT memcmp')
    require(by_slot[0x576e0e0][2] == 6 and by_slot[0x576e0e0][5] == 'memmove',
            'move relocation is not GLOB_DAT memmove')


def marker_class(byte, limits):
    """Classify one fresh byte according to the locked scalar comparison sites."""
    require(type(byte) is int and 0 <= byte <= 255, 'marker must be a byte')
    map_class, array_class, string_class, null_class, high_class, nibble, low5 = limits
    if byte < map_class:
        return 0, byte
    if byte < array_class:
        return map_class, byte & nibble
    if byte < string_class:
        return array_class, byte & nibble
    if byte < null_class:
        return string_class, byte & low5
    if byte < high_class:
        return byte, None  # prior cached payload is not overwritten on this branch
    return high_class, byte


def model_array_pair(arity, first_status, second_status, depth, expected_arity):
    """Selected array route; external reader outcomes are abstract inputs.

    ``depth`` is the u16 value at the local value-depth load, not the initial
    depth at the outer map entry. Missing-sentinel outcomes are modeled even
    when their generation in an external reader has not been established.
    """
    require(type(arity) is int and 0 <= arity <= 0xffffffff, 'array count outside u32')
    require(first_status in ('value', 'error', 'missing') and
            second_status in ('value', 'null', 'error', 'missing'), 'invalid external result')
    require(type(depth) is int and 0 <= depth <= 0xffff, 'depth outside u16')
    if depth == 0:
        return 'depth_zero_failure_call'
    if depth == 1:
        return 'depth_exhausted'
    if arity == 0:
        return 'missing_first'
    if first_status == 'error':
        return 'first_reader_error'
    if first_status == 'missing':
        return 'missing_first'
    if arity == 1:
        return 'missing_second'
    if second_status == 'error':
        return 'second_reader_error'
    if second_status == 'missing':
        return 'missing_second'
    if arity != expected_arity:
        return 'extra_item_cleanup'
    return 'pair_with_null_second' if second_status == 'null' else 'pair_with_second_value'


def model_bad_value_map(count, depth):
    """Selected map value marker path, assuming the error formatter returns."""
    require(type(count) is int and 0 <= count <= 0xffffffff, 'map count outside u32')
    require(type(depth) is int and 0 <= depth <= 0xffff, 'depth outside u16')
    if depth == 0:
        return 'depth_zero_failure_call'
    if depth == 1:
        return 'depth_exhausted'
    return 'invalid_type_then_map_cleanup'


def model_value_header(marker, payload):
    """Read fixed, 16-bit and 32-bit value-container counts from abstract input.

    Consumption is for bytes *after* the marker. Unsupported marker classes
    and downstream parser semantics are outside this model.
    """
    require(type(marker) is int and 0 <= marker <= 255 and type(payload) is bytes,
            'invalid marker or payload')
    if 0x80 <= marker <= 0x8f:
        return 'map', marker & 0x0f, 0, 'ok'
    if 0x90 <= marker <= 0x9f:
        return 'array', marker & 0x0f, 0, 'ok'
    require(marker in (0xdc, 0xdd, 0xde, 0xdf), 'unsupported value container marker')
    kind = 'array' if marker in (0xdc, 0xdd) else 'map'
    width = 2 if marker in (0xdc, 0xde) else 4
    if len(payload) < width:
        return kind, None, len(payload), 'truncated'
    return kind, int.from_bytes(payload[:width], 'big'), width, 'ok'


def model_key_order(incoming, stored):
    """Sign of the compared byte prefixes, with length as the equality tie-break."""
    require(type(incoming) is bytes and type(stored) is bytes, 'keys must be bytes')
    require(len(incoming) < 1 << 63 and len(stored) < 1 << 63, 'key length outside isize')
    common = min(len(incoming), len(stored))
    left, right = incoming[:common], stored[:common]
    if left != right:
        return -1 if left < right else 1
    return (len(incoming) > len(stored)) - (len(incoming) < len(stored))


def hx(value):
    return '' if value is None else hex(value)


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


TABLE_JUMPS = {
    0x13bffd6: 'outer_cached_tag', 0x13c0010: 'outer_extended',
    0x13c11df: 'outer_raw_marker', 0x13c042d: 'value_cached_tag',
    0x13c046b: 'value_extended', 0x13c0c86: 'value_raw_marker',
}


def build_graph(fdes, instructions, tables):
    """Local normal-flow overapproximation; calls are assumed to return."""
    by_site = {r['site']: r for r in instructions}
    ends = {f['role']: f['end'] for f in fdes}
    groups = collections.defaultdict(set)
    for label, _, _, _, _, target in tables:
        groups[label].add(target)
    edges = {}
    for row in instructions:
        site, raw, kind, target, role = (row['site'], row['raw'], row['kind'], row['target'], row['role'])
        following = site + len(raw)
        require(following <= ends[role], 'instruction crosses FDE end')
        nexts = set()
        if kind == 'conditional':
            if target in by_site and by_site[target]['role'] == role:
                nexts.add(target)
            if following < ends[role]:
                nexts.add(following)
        elif kind == 'jump':
            if target in by_site and by_site[target]['role'] == role:
                nexts.add(target)
        elif kind == 'indirect_jump':
            if site in TABLE_JUMPS:
                nexts.update(groups[TABLE_JUMPS[site]])
        elif kind not in ('return', 'trap') and following < ends[role]:
            nexts.add(following)
        for dest in nexts:
            require(dest in by_site and by_site[dest]['role'] == role, 'graph edge leaves selected FDE')
        edges[site] = nexts
    for site in TABLE_JUMPS:
        require(site in by_site and by_site[site]['kind'] == 'indirect_jump', 'missing dispatch instruction')
    return edges


def reaches(edges, start, target):
    require(start in edges and target in edges, 'graph query outside selected instructions')
    todo, seen = [start], set()
    while todo:
        site = todo.pop()
        if site == target:
            return True
        if site not in seen:
            seen.add(site)
            todo.extend(sorted(edges[site] - seen, reverse=True))
    return False


def split_model(index, cap, pivot_a, pivot_b, pivot_c, shift):
    """Full-node split decisions for a well-formed insertion position."""
    require(type(index) is int and 0 <= index <= cap, 'insertion position outside full node')
    if index < pivot_b:
        pivot, side, local = pivot_a, 'old', index
    elif index == pivot_b:
        pivot, side, local = pivot_b, 'old', index
    elif index == pivot_c:
        pivot, side, local = pivot_b, 'new', 0
    else:
        pivot, side, local = pivot_c, 'new', index - shift
    old_before, new_before = pivot, cap - pivot - 1
    old_after = old_before + (side == 'old')
    new_after = new_before + (side == 'new')
    return pivot, side, local, old_before, new_before, old_after, new_after


def unwind_routes(lsda, graph, by_site):
    """Connect selected LSDA call ranges to local landing-pad observations."""
    specs = (
        ('first_value_reader', 0x13c0a96, 0x13c16d4,
         (0x13c16f4, 0x13c1707), 0x13c170f),
        ('second_value_reader', 0x13c0ae8, 0x13c1655,
         (0x13c166a, 0x13c16f4, 0x13c1707), 0x13c170f),
        ('insert_call', 0x13c0e46, 0x13c16fc,
         (0x13c1707,), 0x13c170f),
        ('missing_second_error', 0x13c130c, 0x13c1618,
         (0x13c166a, 0x13c1707), 0x13c170f),
        ('split_leaf_alloc_failure_handler', 0x13a43a5, 0x13a447c,
         (0x13a44be,), 0x13a44df),
    )
    out = []
    for label, call, expected_landing, cleanup, tail in specs:
        matches = [row for row in lsda if call in row[-1]]
        require(len(matches) == 1, 'unwind call lacks unique selected LSDA entry: ' + label)
        row = matches[0]
        landing, action = row[6:8]
        require(landing == expected_landing and action == 0, 'unwind landing/action changed: ' + label)
        require(all(reaches(graph, landing, site) for site in (*cleanup, tail)),
                'unwind landing cannot reach selected cleanup: ' + label)
        require(by_site[tail]['kind'] == 'call' and by_site[tail]['target'] == 0x5660110,
                'unwind continuation call changed: ' + label)
        out.append((label, call, row[1], row[2], landing, action, cleanup, tail))
    return out


def collect(data):
    """Collect only after authenticating the entire target."""
    verify_identity(data)
    view = View(data)
    fdes, all_fdes = selected_fdes(view)
    instructions = [item for f in fdes for item in decode_body(view, f)]
    by_va = {item['site']: item for item in instructions}
    require(len(by_va) == len(instructions), 'overlapping selected FDEs')
    fixed = witnesses(view, instructions)
    contexts = context_rows(view)
    table = table_rows(view, set(by_va))
    for label, base, _, _ in TABLES:
        sites = {
            'outer_cached_tag': (0x13bffc8, '488d0d'),
            'outer_extended': (0x13c0002, '488d15'),
            'outer_raw_marker': (0x13c11cf, '4c8d05'),
            'value_cached_tag': (0x13c0417, '488d3d'),
            'value_extended': (0x13c045d, '488d3d'),
            'value_raw_marker': (0x13c0c76, '4c8d0d'),
        }
        site, prefix = sites[label]
        require(relative_target(view, site, prefix) == base, 'dispatch table LEA changed')
    for left, right in zip(TABLES, TABLES[1:]):
        require(left[1] + 4 * left[2] == right[1], 'unexpected gap between selected dispatch tables')
    slots = (0x5668488, 0x576dfd8, 0x576e010, 0x576e020, 0x576e0e0,
             0x576e108, 0x576e488, 0x576e828, 0x576e830, 0x576e928,
             0x576eb70, 0x577a898)
    reloc = relocation_rows(view, slots)
    validate_relocations(reloc)
    require(view.read(0x2180ff, 9) == b'NvTestnet', 'prior name bytes changed')
    require(struct.unpack('<Q', view.read(0x5668490, 8))[0] == 9, 'prior descriptor length changed')
    require(view.read(0x1fc0ec, 8) == bytes.fromhex('c0052f6368616d00'), 'prior directory template changed')
    require(view.read(0x1ef5f5, 17) == bytes.fromhex('c00e2f7374617469635f636f6e66696700'),
            'prior static config template changed')
    contexts += [
        ('prior_cham_template', 0x1fc0ec, view.read(0x1fc0ec, 8), ''),
        ('prior_static_config_template', 0x1ef5f5, view.read(0x1ef5f5, 17), ''),
        ('prior_default_name_bytes', 0x2180ff, view.read(0x2180ff, 9), ''),
        ('prior_default_descriptor_length', 0x5668490, view.read(0x5668490, 8), 9),
    ]
    template = view.read(0x20193e, 30)
    require(template == b'\x0einvalid type: \xc0\x0b, expected \xc0\x00', 'type-error template changed')
    require(relative_target(view, 0x14d4cb3, '488d35') == 0x20193e,
            'type-error template reference changed')
    contexts.append(('type_error_template', 0x20193e, template, ''))
    exc = lsda_rows(view, fdes, all_fdes, instructions)
    by_label = {r[0]: r for r in fixed}
    get_last = lambda label: bytes.fromhex(by_label[label][4])[-1]
    map_tag = get_last('optional_map_class')
    array_tag = get_last('optional_array_class')
    string_tag = get_last('optional_string_class')
    null_tag = get_last('optional_marker_c0')
    high_tag = get_last('optional_negative_class')
    nibble = get_last('optional_nibble_mask')
    low5 = get_last('optional_string_mask')
    require(get_last('optional_map_end') == array_tag and get_last('optional_array_end') == string_tag
            and get_last('optional_high_cmp') + 1 == high_tag, 'marker boundaries disagree')
    limits = (map_tag, array_tag, string_tag, null_tag, high_tag, nibble, low5)
    arity = get_last('value_length_two')
    require(get_last('value_length_one') == 1 and arity == 2, 'fixed array checks changed')
    lookup = {(label, index): target for label, index, _, _, _, target in table}
    cases = []
    for raw in range(256):
        tag, payload = marker_class(raw, limits)
        outer_cached = lookup['outer_cached_tag', tag]
        value_cached = lookup['value_cached_tag', tag]
        if null_tag <= raw < high_tag:
            outer_fresh = lookup['outer_raw_marker', raw]
            value_fresh = lookup['value_raw_marker', raw]
        elif raw < map_tag or raw >= high_tag:
            outer_fresh = by_va[0x13c018e]['target'] if raw < map_tag else by_va[0x13c0328]['target']
            value_fresh = by_va[0x13c0522]['target'] if raw < map_tag else by_va[0x13c0919]['target']
        elif raw < array_tag:
            outer_fresh = by_va[0x13c0336]['site'] + len(by_va[0x13c0336]['raw'])
            value_fresh = by_va[0x13c0929]['site'] + len(by_va[0x13c0929]['raw'])
        elif raw < string_tag:
            outer_fresh = by_va[0x13c100d]['site'] + len(by_va[0x13c100d]['raw'])
            value_fresh = by_va[0x13c0a5a]['site'] + len(by_va[0x13c0a5a]['raw'])
        else:
            outer_fresh = by_va[0x13c1136]['target']
            value_fresh = by_va[0x13c0c67]['target']
        require(outer_fresh in by_va and value_fresh in by_va, 'fresh marker join is not an instruction')
        cases.append((raw, tag, payload, outer_cached, outer_fresh, value_cached, value_fresh))
    probes = []
    for count in range(nibble + 1):
        for depth in (0, 1, 2):
            for first_status in ('value', 'error', 'missing'):
                for second_status in ('value', 'null', 'error', 'missing'):
                    probes.append((count, depth, first_status, second_status,
                                   model_array_pair(count, first_status, second_status, depth, arity)))
    bad_maps = [(count, depth, model_bad_value_map(count, depth))
                for count in range(nibble + 1) for depth in (0, 1, 2)]
    extended_targets = {0xdc: 0x13c07eb, 0xdd: 0x13c04a1,
                        0xde: 0x13c081c, 0xdf: 0x13c0573}
    for marker, target in extended_targets.items():
        require(lookup['value_raw_marker', marker] == target, 'extended marker dispatch changed')
    require(lookup['outer_raw_marker', 0xde] == 0x13c0138 and
            lookup['outer_raw_marker', 0xdf] == 0x13c00e0,
            'outer extended map marker dispatch changed')
    header_inputs = [(b, b'') for b in (0x80, 0x81, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x9f)]
    for marker in (0xdc, 0xdd, 0xde, 0xdf):
        width = 2 if marker in (0xdc, 0xde) else 4
        for n in (0, 1, 2, 3, 15, 16, 65535, 65536, 0xffffffff):
            if n < 1 << (8 * width):
                header_inputs.append((marker, n.to_bytes(width, 'big')))
        header_inputs.extend((marker, b'\xff' * n) for n in range(width))
    header_inputs += [(0xdc, b'\x00\x02\xff'), (0xdd, b'\x00\x00\x00\x02\xff')]
    headers = []
    for marker, payload in header_inputs:
        kind, count, consumed, status = model_value_header(marker, payload)
        if status == 'truncated':
            route = 'short_header_then_map_cleanup'
        elif kind == 'array':
            route = model_array_pair(count, 'value', 'null', 2, arity)
        else:
            route = model_bad_value_map(count, 2)
        headers.append((marker, payload.hex(), kind, count, consumed, status, route))
    key_pairs = ((b'', b''), (b'', b'\0'), (b'a', b''), (b'ab', b'a'),
                 (b'a', b'ab'), (b'a', b'b'), (b'\x80', b'\x7f'),
                 (b'ab\0', b'ab\xff'), (b'ABC', b'abc'), (b'same', b'same'),
                 (b'\xff', b'\0'))
    key_order = [(left.hex(), right.hex(), model_key_order(left, right))
                 for left, right in key_pairs]
    graph = build_graph(fdes, instructions, table)
    unwinds = unwind_routes(exc, graph, by_va)
    queries = (
        ('entry_to_key_reader', 0x13bffa0, 0x13c03c0, True),
        ('outer_empty_to_success', 0x13c0f02, 0x13c14e6, True),
        ('outer_empty_bypasses_key_reader', 0x13c0f02, 0x13c03c0, False),
        ('outer_map16_to_depth', 0x13c0138, 0x13c033c, True),
        ('outer_map32_to_depth', 0x13c00e0, 0x13c033c, True),
        ('outer_short_header_to_return', 0x13c0219, 0x13c1225, True),
        ('outer_remaining_to_finish', 0x13c03aa, 0x13c0fc3, True),
        ('outer_finish_to_success', 0x13c0fc3, 0x13c14e6, True),
        ('key_reader_to_pair_dispatch', 0x13c03c0, 0x13c0a96, True),
        ('pair_dispatch_to_optional_reader', 0x13c0a96, 0x13c0ae8, True),
        ('array16_to_pair_depth', 0x13c07eb, 0x13c0a62, True),
        ('array32_to_pair_depth', 0x13c04a1, 0x13c0a62, True),
        ('map16_to_value_depth', 0x13c081c, 0x13c0931, True),
        ('map32_to_value_depth', 0x13c0573, 0x13c0931, True),
        ('short_header_to_map_drop', 0x13c113b, 0x13c144f, True),
        ('map_value_to_type_error', 0x13c092d, 0x13c095a, True),
        ('map_type_error_to_map_drop', 0x13c1288, 0x13c144f, True),
        ('map_type_error_bypasses_insert', 0x13c1288, 0x13c0e46, False),
        ('optional_reader_to_map_insert', 0x13c0ae8, 0x13c0e46, True),
        ('insert_to_success_tag', 0x13c0e46, 0x13c14e6, True),
        ('success_tag_to_output_copy', 0x13c14e6, 0x13c1514, True),
        ('extra_item_to_pair_cleanup', 0x13c0bf8, 0x13c0c25, True),
        ('parse_error_to_map_drop', 0x13c13f2, 0x13c144f, True),
        ('exhausted_depth_to_map_drop', 0x13c10c0, 0x13c144f, True),
        ('zero_depth_failure_call_to_trap', 0x13c15e3, 0x13c1616, True),
        ('replace_to_return', 0x14cc08b, 0x14cc104, True),
        ('replace_to_length_increment', 0x14cc08b, 0x14cc27f, False),
        ('empty_root_to_allocation', 0x14cc0b6, 0x14cc1ce, True),
        ('empty_root_to_length_increment', 0x14cc0b6, 0x14cc27f, True),
        ('split_to_leaf_allocation', 0x13a3440, 0x13a3642, True),
        ('split_to_internal_allocation', 0x13a3440, 0x13a3a20, True),
        ('split_to_trap', 0x13a3440, 0x13a440b, True),
        ('map_drop_to_drain_call', 0x14daa70, 0x14daad5, True),
    )
    for name, start, dest, expected in queries:
        require(reaches(graph, start, dest) == expected, 'unexpected local CFG result: ' + name)
    cap = get_last('split_capacity_check')
    pivot_a = int.from_bytes(bytes.fromhex(by_label['split_pivot_before_five'][4])[-4:], 'little')
    pivot_b = int.from_bytes(bytes.fromhex(by_label['split_pivot_at_six'][4])[-4:], 'little')
    pivot_c = int.from_bytes(bytes.fromhex(by_label['split_pivot_after_six'][4])[-4:], 'little')
    shift = -int.from_bytes(bytes.fromhex(by_label['split_right_index_bias'][4])[-1:], 'little', signed=True)
    require((cap, pivot_a, pivot_b, pivot_c, shift) == (11, 4, 5, 6, 7),
            'full-node split constants changed')
    require(get_last('split_insertion_index_five') == pivot_b and
            get_last('split_insertion_index_six') == pivot_c, 'split branch thresholds disagree')
    splits = [(i, *split_model(i, cap, pivot_a, pivot_b, pivot_c, shift))
              for i in range(cap + 1)]
    return dict(view=view, fdes=fdes, instructions=instructions, witnesses=fixed,
                contexts=contexts, tables=table, relocs=reloc, lsda=exc,
                markers=cases, models=probes, limits=limits, arity=arity,
                bad_maps=bad_maps, headers=headers, key_order=key_order, graph=graph,
                queries=queries, splits=splits, unwinds=unwinds)


def emit(data, out_dir):
    result = collect(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    view = result['view']
    fdes = result['fdes']
    instructions = result['instructions']
    fde_rows = []
    for f in fdes:
        raw = view.read(f['start'], f['end'] - f['start'])
        fde_rows.append((f['role'], hx(f['start']), hx(f['end']), hx(view.offset(f['start'], len(raw))),
                         hx(f['fde']), hx(f['cie']), hx(f['lsda']), len(raw), hashlib.sha256(raw).hexdigest()))
    write_tsv(out_dir / 'functions.tsv',
              ('role', 'start_va', 'end_exclusive_va', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'bytes', 'sha256'), fde_rows)
    write_tsv(out_dir / 'instructions.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'form', 'target_va_or_slot'),
              ((r['role'], hx(r['site']), hx(view.offset(r['site'], len(r['raw']))),
                r['raw'].hex(), r['kind'], hx(r['target'])) for r in instructions))
    transfers = [r for r in instructions if r['kind'] in ('call', 'jump', 'conditional', 'indirect_call', 'indirect_jump')]
    fde_by_role = {f['role']: f for f in fdes}
    fde_by_start = {f['start']: f['role'] for f in fdes}
    write_tsv(out_dir / 'transfers.tsv', ('role', 'site_va', 'bytes', 'form', 'target_va_or_slot', 'within_same_fde'),
              ((r['role'], hx(r['site']), r['raw'].hex(), r['kind'], hx(r['target']),
                '' if r['target'] is None else str(fde_by_role[r['role']]['start'] <= r['target'] < fde_by_role[r['role']]['end']).lower())
               for r in transfers))
    calls = [r for r in transfers if r['kind'] in ('call', 'indirect_call')]
    write_tsv(out_dir / 'calls.tsv', ('caller_role', 'site_va', 'bytes', 'form',
              'target_va_or_slot', 'selected_callee_role_or_boundary'),
              ((r['role'], hx(r['site']), r['raw'].hex(), r['kind'], hx(r['target']),
                fde_by_start.get(r['target'], 'boundary')) for r in calls))
    write_tsv(out_dir / 'dispatch.tsv', ('table', 'index_or_tag', 'slot_va', 'file_offset', 'signed_rel32_bytes', 'target_va'),
              ((label, hx(index), hx(slot), hx(file_off), raw, hx(target))
               for label, index, slot, file_off, raw, target in result['tables']))
    write_tsv(out_dir / 'marker-model.tsv', ('raw_byte', 'normalized_tag', 'payload_or_preserved',
              'outer_cached_target_va', 'outer_fresh_join_va', 'value_cached_target_va', 'value_fresh_join_va'),
              ((hx(raw), hx(tag), 'preserved' if payload is None else hx(payload), hx(oc), hx(of), hx(vc), hx(vf))
               for raw, tag, payload, oc, of, vc, vf in result['markers']))
    write_tsv(out_dir / 'arity-model.tsv', ('fixed_array_length', 'local_depth', 'first_reader_result',
              'second_reader_result', 'modeled_route'), result['models'])
    write_tsv(out_dir / 'map-value-model.tsv', ('fixed_map_count', 'local_depth', 'modeled_route'),
              result['bad_maps'])
    write_tsv(out_dir / 'header-model.tsv', ('marker', 'payload_bytes', 'kind', 'count',
              'payload_bytes_consumed', 'header_status', 'modeled_route_at_depth_2'),
              ((hx(marker), payload, kind, '' if count is None else count, consumed, status, route)
               for marker, payload, kind, count, consumed, status, route in result['headers']))
    write_tsv(out_dir / 'key-order-model.tsv', ('incoming_key_bytes', 'stored_key_bytes', 'comparison_sign'),
              result['key_order'])
    write_tsv(out_dir / 'split-model.tsv', ('insertion_index', 'promoted_old_key_index', 'destination_node',
              'destination_local_index', 'old_count_before_insert', 'new_count_before_insert',
              'old_count_after_insert', 'new_count_after_insert'), result['splits'])
    write_tsv(out_dir / 'cfg.tsv', ('query', 'start_va', 'target_va', 'reachable_in_normal_flow_overapproximation'),
              ((name, hx(start), hx(dest), str(expected).lower())
               for name, start, dest, expected in result['queries']))
    write_tsv(out_dir / 'witnesses.tsv', ('label', 'role', 'site_va', 'file_offset', 'bytes', 'form', 'target_va_or_slot'),
              ((name, role, hx(site), hx(off), raw, form, hx(target))
               for name, role, site, off, raw, form, target in result['witnesses']))
    write_tsv(out_dir / 'context.tsv', ('label', 'site_va', 'file_offset', 'bytes', 'decoded_value'),
              ((name, hx(site), hx(view.offset(site, len(raw))), raw.hex(), hx(value) if type(value) is int else value)
               for name, site, raw, value in result['contexts']))
    write_tsv(out_dir / 'relocations.tsv', ('slot_va', 'record_file_offset', 'type', 'symbol_index', 'addend', 'symbol', 'record_bytes'),
              ((hx(slot), hx(off), typ, sym, hx(addend), symbol, raw)
               for slot, off, typ, sym, addend, symbol, raw in result['relocs']))
    write_tsv(out_dir / 'exception-sites.tsv', ('role', 'lsda_va', 'entry_va', 'entry_bytes',
              'start_va', 'end_exclusive_va', 'landing_va', 'action', 'selected_calls'),
              ((role, hx(lsda), hx(entry), raw, hx(lo), hx(hi), hx(landing), action,
                ','.join(hx(c) for c in calls)) for role, lsda, entry, raw, lo, hi, landing, action, calls in result['lsda']))
    write_tsv(out_dir / 'unwind-paths.tsv', ('case', 'call_va', 'lsda_va', 'entry_va', 'landing_va',
              'action', 'locally_reachable_cleanup_calls', 'locally_reachable_continuation_call'),
              ((name, hx(call), hx(lsda), hx(entry), hx(landing), action,
                ','.join(hx(c) for c in cleanup), hx(tail))
               for name, call, lsda, entry, landing, action, cleanup, tail in result['unwinds']))
    summary = {
        'target': 'node94', 'target_sha256': DIGEST, 'target_size': len(data),
        'coordinate_system': 'linked ELF virtual address; file offset separately reported',
        'selected_fdes': len(fdes), 'selected_fde_bytes': sum(f['end'] - f['start'] for f in fdes),
        'admitted_instruction_encodings': len(instructions), 'selected_transfers': len(transfers),
        'selected_call_sites': len(calls), 'normal_flow_cfg_queries': len(result['queries']),
        'full_node_split_model_cases': len(result['splits']),
        'selected_witnesses': len(result['witnesses']), 'selected_rel32_table_slots': len(result['tables']),
        'fresh_marker_model_cases': len(result['markers']), 'fixed_array_model_cases': len(result['models']),
        'fixed_map_value_model_cases': len(result['bad_maps']),
        'container_header_model_cases': len(result['headers']),
        'key_order_model_cases': len(result['key_order']),
        'selected_lsda_call_site_records': len(result['lsda']), 'selected_relocations': len(result['relocs']),
        'selected_unwind_path_cases': len(result['unwinds']),
        'marker_class_immediates': [hx(n) for n in result['limits']],
        'fixed_array_required_arity': result['arity'],
        'limitations': ['models are static predicates, not execution of the captured target',
                        'FDE extents are unwind ranges, not a function census',
                        'indirect calls and common previously researched helpers are boundaries',
                        'local CFG includes all table targets and both conditional edges and omits unwinding',
                        'field attribution relies on the prior classifier path and checked handoff',
                        'runtime state, full malformed input behavior, type identity and whole-ELF comparison remain open'],
    }
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, help='directory for generated evidence')
    args = parser.parse_args()
    try:
        summary = emit(TARGET.read_bytes(), args.out)
    except (OSError, ValueError, struct.error) as exc:
        parser.exit(2, f'evidence collection failed: {exc}\n')
    print(f"node94: {summary['selected_fdes']} selected FDEs; {summary['selected_rel32_table_slots']} dispatch slots")


if __name__ == '__main__':
    main()
