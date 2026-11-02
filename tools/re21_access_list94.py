#!/usr/bin/env python3
"""Static, digest-bound node #94 access-list preparation evidence (MIT).

The bounded instruction-length decoder is adapted from the repository's MIT
``tools/evm_kvs_inventory.py``. No captured instruction is executed.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import fde_extents, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1
FUNCTIONS = {
    0x276fa70: 'revision-9 descriptor method at offset 0x28',
    0x27712d0: 'revision-9 descriptor method at offset 0x20',
    0x2776950: 'revision-9 descriptor method at offset 0x18',
    0x278ed50: 'access-list-shaped account and slot preparation',
    0x4e742e0: '104-byte slot-table reserve and rehash',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data, expected=DIGEST):
    require(hashlib.sha256(data).hexdigest() == expected, 'node #94 digest mismatch')


def offset_for(sec, address, size, executable=False):
    require(type(address) is int and type(size) is int and address >= 0 and size > 0,
            'invalid read range')
    require(address + size <= 1 << 64, 'address overflow')
    matches = [s for s in sec if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= address and address + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'missing, ambiguous, crossing or NOBITS read')
    return matches[0]['offset'] + address - matches[0]['address']


def read_va(data, sec, va, size, executable=False):
    off = offset_for(sec, va, size, executable)
    require(off + size <= len(data), 'read exceeds file')
    return bytes(data[off:off + size])


def exact(data, sec, va, expected, executable=True):
    raw = bytes.fromhex(expected) if isinstance(expected, str) else expected
    require(read_va(data, sec, va, len(raw), executable) == raw,
            f'byte pin mismatch at {va:#x}')
    return raw

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
        kind = ('call_rel32' if op == 0xe8 else 'jmp_rel32' if op == 0xe9
                else 'jmp_rel8' if op == 0xeb else 'branch')
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
        elif 0xc8 <= op2 <= 0xcf:
            require(not prefixes, 'unsupported BSWAP prefixes')
        elif op2 in (0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29,
                     0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x50, 0x51, 0x54, 0x55,
                     0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
                     0x5f, 0x60, 0x61, 0x62, 0x64, 0x66, 0x6c, 0x6d, 0x6e, 0x6f,
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
            raise ValueError(f'unsupported 0f opcode {op2:02x}')
    else:
        raise ValueError(f'unsupported opcode {op:02x}')
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




def selected_fdes(data, sec):
    summary, rows, _ = fde_extents(data)
    for name in ('unwind_start_differs_from_fde_start', 'duplicate_start',
                 'zero_length', 'starts_inside_earlier_extent',
                 'extent_crosses_section_end', 'fde_records_not_in_unwind_table',
                 'lsda_outside_gcc_except_table'):
        require(summary[name] == 0, f'inconsistent FDE inventory: {name}')
    rows.sort(key=lambda row: row['start'])
    starts = [row['start'] for row in rows]
    text_sections = [s for s in sec if s['name'] == '.text' and s['type'] != 8]
    require(len(text_sections) == 1, 'missing or duplicate text section')
    text_section = text_sections[0]
    code = bytes(data[text_section['offset']:text_section['offset'] + text_section['size']])
    require(len(code) == text_section['size'], 'truncated text section')
    candidates = {}
    pos = -1
    # A byte search finds candidates, not functions. Every candidate is then
    # matched to a real FDE and checked against its decoded instruction starts.
    while True:
        pos = code.find(b'\xe8', pos + 1)
        if pos < 0 or pos + 5 > len(code):
            break
        site = text_section['address'] + pos
        target = site + 5 + struct.unpack_from('<i', code, pos + 1)[0]
        if target != 0x278ed50:
            continue
        index = bisect.bisect_right(starts, site) - 1
        if index >= 0 and site < rows[index]['end']:
            candidates[rows[index]['start']] = rows[index]
    methods = {}
    for start, row in sorted(candidates.items()):
        body = read_va(data, sec, start, row['end'] - start, True)
        decoded = decode_stream(body, start)
        calls = [(instruction, transfer(instruction)) for instruction in decoded
                 if transfer(instruction)[0] == 'call_rel32']
        to_walker = [instruction for instruction, (_, target, _) in calls if target == 0x278ed50]
        if not to_walker:
            continue  # an E8-like byte inside an operand is not a call
        require(len(to_walker) == 1, 'multiple calls to selected walker')
        revisions = [instruction for instruction in decoded
                     if instruction['raw'].startswith(bytes.fromhex('c682b0000000'))]
        require(len(revisions) == 1, 'wrapper revision store not unique')
        require(revisions[0]['site'] < to_walker[0]['site'], 'revision store follows walker')
        revision = revisions[0]['raw'][-1]
        prior = [instruction for instruction, (_, target, _) in calls if target == 0x27c7e10]
        require(all(instruction['site'] < to_walker[0]['site'] for instruction in prior),
                'set-insertion call is not before walker')
        require(len(calls) == len(prior) + 1 and len(prior) in (0, 1, 2),
                'unexpected wrapper call shape')
        if prior:
            shapes = {instruction['raw'] for instruction in decoded
                      if instruction['site'] < prior[0]['site']}
            require({bytes.fromhex(x) for x in ('488b82d8000000', '8b88e0000000',
                                               '0f1080d0000000')} <= shapes,
                    'wrapper environment key load changed')
            require(bool(shapes & {bytes.fromhex('488dba80000000'),
                                   bytes.fromhex('4c8dba80000000')}),
                    'wrapper set argument changed')
        fixed = [instruction for instruction in decoded if instruction['raw'][:3] == b'\x48\x8d\x35'
                 and len(instruction['raw']) == 7]
        require(len(fixed) == (1 if len(prior) == 2 else 0), 'unexpected fixed-key reference')
        fixed_va = (fixed[0]['site'] + len(fixed[0]['raw']) +
                    struct.unpack_from('<i', fixed[0]['raw'], 3)[0]) if fixed else None
        if fixed:
            require(prior[0]['site'] < fixed[0]['site'] < prior[1]['site'],
                    'fixed key not between the two set calls')
        # Compare each three-method family after masking only PC-relative
        # displacements. All other bytes, including the context byte, stay.
        signature = []
        for instruction in decoded:
            raw = instruction['raw']
            if instruction['kind'] == 'call_rel32' or raw[:3] == b'\x48\x8d\x35' and len(raw) == 7:
                raw = raw[:-4] + b'\0' * 4
            signature.append(raw)
        methods[start] = {'fde': row, 'revision': revision, 'revision_site': revisions[0]['site'],
                          'walker_site': to_walker[0]['site'], 'prior_calls': prior,
                          'fixed_va': fixed_va,
                          'fixed_bytes': read_va(data, sec, fixed_va, 20).hex() if fixed else '',
                          'signature': signature, 'raw_sha256': hashlib.sha256(body).hexdigest(),
                          'shape_sha256': hashlib.sha256(b''.join(signature)).hexdigest()}
    by_target = {start: [] for start in methods}
    for s in sec:
        if s['type'] != 4:
            continue
        require(s['size'] % 24 == 0, 'truncated RELA section')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if addend in by_target and info == 8:
                by_target[addend].append((slot, pos))
    groups = {}
    for start, method in methods.items():
        require(len(by_target[start]) == 1, 'wrapper relocation is not unique')
        method['slot'], method['rela_file_offset'] = by_target[start][0]
        require(read_va(data, sec, method['slot'], 8) == b'\0' * 8,
                'descriptor slot is not zero before relocation')
        groups.setdefault(method['revision'], []).append((method['slot'], start))
    fork_rows, method_rows, roles = [], [], dict(FUNCTIONS)
    for revision, members in sorted(groups.items()):
        members.sort()
        require(len(members) == 3, 'descriptor does not have three methods')
        base = members[0][0] - 0x18
        require([slot - base for slot, _ in members] == [0x18, 0x20, 0x28],
                'descriptor method offsets changed')
        expected_count = len(methods[members[0][1]]['prior_calls'])
        expected_fixed = methods[members[0][1]]['fixed_va']
        for slot, start in members:
            method = methods[start]
            require(len(method['prior_calls']) == expected_count and method['fixed_va'] == expected_fixed,
                    'descriptor method family disagrees')
            require(method['signature'] == methods[members[0][1]]['signature'],
                    'descriptor method byte shapes differ')
            method['descriptor'] = base
            roles[start] = f'descriptor method byte {revision} at offset {slot - base:#x}'
            method_rows.append((revision, hex(base), hex(slot - base), hex(slot), hex(start),
                                hex(method['revision_site']), hex(method['walker_site']),
                                len(method['prior_calls']),
                                ','.join(hex(x['site']) for x in method['prior_calls']),
                                hex(method['rela_file_offset']), method['raw_sha256'],
                                method['shape_sha256']))
        sample = methods[members[0][1]]
        fork_rows.append((revision, hex(base), *(hex(start) for _, start in members),
                          expected_count, hex(expected_fixed) if expected_fixed is not None else '',
                          sample['fixed_bytes']))
    require(0x276fa70 in methods and len(methods) == 45 and len(groups) == 15,
            'unexpected authenticated descriptor family')
    by_start = {}
    for row in rows:
        if row['start'] in roles:
            require(row['start'] not in by_start, 'duplicate selected FDE')
            by_start[row['start']] = row
    require(set(by_start) == set(roles), 'missing selected FDE')
    return by_start, roles, methods, fork_rows, method_rows


def decode_stream(code, start):
    rows = []
    cursor = 0
    while cursor < len(code):
        try:
            insn = decode_instruction(code, cursor, start)
        except ValueError as error:
            raise ValueError(f'cannot decode {start + cursor:#x}: {error}') from error
        require(insn['raw'], 'empty instruction')
        rows.append(insn)
        cursor += len(insn['raw'])
    require(cursor == len(code), 'truncated function')
    starts = {r['site'] for r in rows}
    for row in rows:
        if row['kind'] in ('branch', 'jmp_rel32', 'jmp_rel8'):
            raw = row['raw']
            n = 1 if raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f else 4
            dst = row['site'] + len(raw) + int.from_bytes(raw[-n:], 'little', signed=True)
            if start <= dst < start + len(code):
                require(dst in starts, f'branch into instruction at {dst:#x}')
    return rows


def transfer(row):
    raw, va = row['raw'], row['site']
    kind = row['kind']
    if kind in ('call_rel32', 'jmp_rel32', 'jmp_rel8', 'branch'):
        n = 1 if raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f else 4
        return kind, va + len(raw) + int.from_bytes(raw[-n:], 'little', signed=True), None
    if raw == b'\xc3':
        return 'return', None, None
    if raw == b'\x0f\x0b':
        return 'trap', None, None
    prefix = 1 if raw and 0x40 <= raw[0] <= 0x4f else 0
    if len(raw) >= prefix + 2 and raw[prefix] == 0xff:
        modrm = raw[prefix + 1]
        group = (modrm >> 3) & 7
        if group in (2, 4):
            name = 'call_indirect' if group == 2 else 'jump_indirect'
            if modrm & 0xc7 == 0x05 and len(raw) == prefix + 6:
                return name, None, va + len(raw) + struct.unpack_from('<i', raw, prefix + 2)[0]
            return name, None, None
    return None, None, None


def scan_relocations(data, sec, wanted):
    found = {}
    for s in sec:
        if s['type'] != 4:
            continue
        require(s['size'] % 24 == 0, 'truncated RELA section')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot not in wanted:
                continue
            require(slot not in found, f'duplicate selected relocation {slot:#x}')
            found[slot] = {'slot': slot, 'type': info & 0xffffffff,
                           'symbol': info >> 32, 'addend': addend,
                           'file_offset': pos, 'raw': bytes(data[pos:pos+24])}
    require(set(found) == set(wanted), 'missing selected relocation')
    return found


def validate_relative(row, expected):
    require(row['type'] == 8 and row['symbol'] == 0, 'not a symbol-free relative relocation')
    require(row['addend'] == expected, 'relative relocation addend mismatch')
    return row


def dyn_symbol(data, sec, index):
    dynsym = [s for s in sec if s['name'] == '.dynsym' and s['type'] == 11]
    dynstr = [s for s in sec if s['name'] == '.dynstr' and s['type'] == 3]
    require(len(dynsym) == len(dynstr) == 1 and index >= 0, 'missing dynamic tables')
    sym, strings = dynsym[0], dynstr[0]
    require((index + 1) * 24 <= sym['size'], 'dynamic symbol index outside table')
    name = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    require(name < strings['size'], 'dynamic name outside strings')
    begin = strings['offset'] + name
    end = data.find(b'\x00', begin, strings['offset'] + strings['size'])
    require(end >= begin, 'unterminated dynamic name')
    return bytes(data[begin:end]).decode('ascii')


def read_lsda(data, sec, fde, starts):
    require(fde['lsda'] is not None, 'missing exception table')
    table = [s for s in sec if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(table) == 1, 'missing or duplicate exception section')
    start = offset_for(sec, fde['lsda'], 1)
    end = table[0]['offset'] + table[0]['size']
    require(start + 2 <= end and data[start] == 0xff, 'unsupported LSDA base')
    pos = start + 2
    type_encoding = data[start + 1]
    type_table = None
    if type_encoding == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_table = pos + delta
        require(type_table <= end, 'LSDA type pointer outside section')
    else:
        require(type_encoding == 0xff, 'unsupported LSDA type encoding')
    require(pos < end and data[pos] == 1, 'unsupported LSDA call-site encoding')
    length, pos = uleb(data, pos + 1, end)
    table_start, limit = pos, pos + length
    require(limit <= end and (type_table is None or limit <= type_table), 'bad LSDA extent')
    entries, last = [], 0
    while pos < limit:
        before = pos
        relative, pos = uleb(data, pos, limit)
        span, pos = uleb(data, pos, limit)
        landing, pos = uleb(data, pos, limit)
        action, pos = uleb(data, pos, limit)
        require(relative >= last and fde['start'] + relative + span <= fde['end'],
                'LSDA call-site outside FDE or overlaps')
        if landing:
            require(fde['start'] + landing < fde['end'] and
                    fde['start'] + landing in starts, 'LSDA landing is not an instruction')
        last = relative + span
        entries.append({'start_va': hex(fde['start'] + relative), 'length': span,
                        'landing_va': hex(fde['start'] + landing) if landing else None,
                        'action': action, 'raw': bytes(data[before:pos]).hex()})
    return {'function_va': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
            'file_offset': hex(start), 'header': bytes(data[start:table_start]).hex(),
            'table': bytes(data[table_start:limit]).hex(), 'entries': entries}


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')

# Windows are bounded by decoded instruction starts. The labels are review
# questions; the emitted bytes and their coordinates are read from the ELF.
WINDOWS = (
    ('mode9_adapter', 0x276fa70, 0x276fa90),
    ('mode9_error_copy', 0x276fa9c, 0x276fab5),
    ('second_method', 0x27712d0, 0x27712f0),
    ('first_method', 0x2776950, 0x2776970),
    ('environment_list', 0x278ed6e, 0x278ed97),
    ('entry_loop', 0x278edd0, 0x278edf7),
    ('address_slot_fields', 0x278edf7, 0x278ee14),
    ('account_probe', 0x278ee34, 0x278ee4f),
    ('backing_account', 0x278ee8e, 0x278eec7),
    ('account_hit_slot_count', 0x278f1a0, 0x278f1be),
    ('account_result_copy', 0x278f27c, 0x278f293),
    ('account_cleanup', 0x278f2a0, 0x278f302),
    ('account_control_and_208_byte_bucket', 0x278f35a, 0x278f3cb),
    ('slot_range_and_process_words', 0x278f3d0, 0x278f407),
    ('slot_probe_full_32_bytes', 0x278f410, 0x278f4a2),
    ('slot_duplicate_and_capacity', 0x278f4b0, 0x278f4de),
    ('slot_backing_account_gate', 0x278f4e3, 0x278f53a),
    ('slot_backing_read', 0x278f53a, 0x278f5ad),
    ('slot_default', 0x278f5ad, 0x278f635),
    ('slot_control_and_bucket_writes', 0x278f667, 0x278f72a),
    ('slot_endian_and_hash', 0x278f735, 0x278f7b8),
    ('slot_reserve_call', 0x278f808, 0x278f82e),
    ('normal_return', 0x278f88e, 0x278f8ab),
    ('unwind_cleanup', 0x278f8ab, 0x278f91f),
    ('reserve_size_and_rehash_gate', 0x4e742f4, 0x4e74335),
    ('reserve_small_sizes', 0x4e74335, 0x4e7435d),
    ('reserve_large_sizes', 0x4e7438f, 0x4e743d8),
    ('reserve_allocation_limits', 0x4e743d8, 0x4e74425),
    ('reserve_allocate', 0x4e7443b, 0x4e7444d),
    ('reserve_move_104_byte_rows', 0x4e745a1, 0x4e745ee),
    ('reserve_control_reclassification', 0x4e7463b, 0x4e746b3),
    ('reserve_swap_104_byte_rows', 0x4e747bb, 0x4e74887),
    ('reserve_capacity_publish', 0x4e74977, 0x4e749a2),
    ('reserve_null_allocation', 0x4e749bb, 0x4e749c8),
    ('reserve_table_publish_cleanup', 0x4e749c8, 0x4e74a1f),
    ('reserve_failure_calls', 0x4e74a1f, 0x4e74a46),
)

# A small set of exact, independently reviewed instruction shapes. The digest
# authenticates the entire image; these pins additionally fail close if this
# module is invoked on altered bytes during its mutation controls.
PINS = (
    (0x276fa78, 'c682b000000009'),
    (0x27712d8, 'c682b000000009'),
    (0x2776958, 'c682b000000009'),
    (0x278ed6e, '488b86d8000000'),
    (0x278ed75, '488b88f8010000'),
    (0x278ed85, '488bb0f0010000'),
    (0x278ed8c, '488d0449'),
    (0x278ed90, '48c1e004'),
    (0x278edf7, '8b4628'),
    (0x278edfe, '0f104618'),
    (0x278ee07, '488b5e08'),
    (0x278ee0b, '488b4610'),
    (0x278f37c, '4869ced0000000'),
    (0x278f439, '4d6bdb68'),
    (0x278f66b, '498b4bd8'),
    (0x278f6ae, '486bca68'),
    (0x278f6be, '4c894c0898'),
    (0x278f6c8, '0f114408a0'),
    (0x278f6d2, '48895408b0'),
    (0x278f6fb, 'f30f7f4408b8'),
    (0x278f701, 'f30f7f4c08c8'),
    (0x278f707, 'f30f7f5408d8'),
    (0x278f70d, 'f30f7f5c08e8'),
    (0x278f713, 'c64408f800'),
    (0x278f718, '49ff43e8'),
    (0x278f747, '480fcb'),
    (0x278f74a, '490fcd'),
    (0x278f74d, '480fcd'),
    (0x278f750, '490fce'),
    (0x278f792, '4983c120'),
    (0x278f7a4, '4883f004'),
    (0x278f896, 'c60005'),
    (0x4e743d8, 'b968000000'),
    (0x4e743a5, '48ba9324499224499224'),
    (0x4e7443e, 'ff15949b8f00'),
    (0x4e749d2, '48892b'),
    (0x4e749d5, '4c896308'),
    (0x4e749d9, '48894310'),
    # Flag-setting instructions for the annotated decisions below.
    (0x278ed7c, '4885c9'),
    (0x278eddc, '483bb42440010000'),
    (0x278ee46, '4d85e4'),
    (0x278eec1, '4883f801'),
    (0x278ef8f, '84c0'),
    (0x278f1a5, '48837c241800'),
    (0x278f27c, '83bc24a002000005'),
    (0x278f2b2, '837c247004'),
    (0x278f3d0, '48837c241800'),
    (0x278f426, '4585d2'),
    (0x278f466, '4181fbffff0000'),
    (0x278f473, '664521d3'),
    (0x278f48d, '4585d2'),
    (0x278f4c0, '483b5c2418'),
    (0x278f4d0, '49837be000'),
    (0x278f532, '48837c247000'),
    (0x278f588, '80bc24a002000000'),
    (0x278f67c, '85d2'),
    (0x278f692, '4084f6'),
    (0x278f72a, '483b5c2418'),
    (0x4e742f8, '4801fe'),
    (0x4e7432b, '4839c6'),
    (0x4e7433f, '4883f90f'),
    (0x4e7439c, '4839c1'),
    (0x4e743e0, '48f7e1'),
    (0x4e74411, '08c1'),
    (0x4e74415, '4584c9'),
    (0x4e74444, '4885c0'),
    (0x4e749bb, '803c2400'),
)

# Site, expected target, interpretation of the condition. Destinations and raw
# encodings in the published table are decoded from the actual instruction.
DECISIONS = (
    (0x278ed7f, 0x278f88e, 'zero outer count: normal return'),
    (0x278edf1, 0x278f88e, 'outer cursor reaches end: normal return'),
    (0x278ee49, 0x278f1a0, 'account probe result word zero: existing entry'),
    (0x278eec5, 0x278ef0c, 'account getter result word differs from one'),
    (0x278ef91, 0x278f1c0, 'account getter low byte zero: default representation'),
    (0x278f1b3, 0x278f3e4, 'existing account and nonzero slot count'),
    (0x278f284, 0x278f2a0, 'temporary account tag differs from five'),
    (0x278f2b7, 0x278f310, 'temporary tag four: skip selected destructor'),
    (0x278f3de, 0x278edd0, 'new account and zero slot count: next account'),
    (0x278f429, 0x278f480, 'no matching fingerprint in current group'),
    (0x278f46d, 0x278f4b0, 'both 16-byte key halves match'),
    (0x278f47e, 0x278f42b, 'remaining fingerprint candidates'),
    (0x278f490, 0x278f4d0, 'empty control found: slot absent'),
    (0x278f4c5, 0x278f735, 'duplicate slot found and input has next slot'),
    (0x278f4d8, 0x278f808, 'zero growth budget: reserve one slot'),
    (0x278f538, 0x278f5ad, 'backing account result zero: skip storage getter'),
    (0x278f590, 0x278f5e4, 'backing storage result zero: use zero value'),
    (0x278f67e, 0x278f7e5, 'no available control byte in initial group'),
    (0x278f695, 0x278f82e, 'selected control is nonnegative: alternate scan'),
    (0x278f72f, 0x278edd0, 'last slot inserted: advance outer record'),
    (0x4e742fb, 0x4e74415, 'additional plus count carries'),
    (0x4e74333, 0x4e7435d, 'needed is at most half current capacity'),
    (0x4e74343, 0x4e7438f, 'requested capacity at least fifteen'),
    (0x4e7439f, 0x4e74415, 'large requested capacity exceeds bound'),
    (0x4e743e3, 0x4e74415, '104-byte bucket multiplication overflows'),
    (0x4e74413, 0x4e74425, 'combined allocation size is admissible'),
    (0x4e74418, 0x4e74a1f, 'overflow with fatal mode byte nonzero'),
    (0x4e74447, 0x4e749bb, 'allocator returns null'),
    (0x4e749bf, 0x4e74a38, 'allocator null with fatal mode byte nonzero'),
)

# Reviewed x86 condition-code nibbles in the same order as DECISIONS. Check
# the opcode as well as the destination: swapping JE for JNE without moving
# the branch must not retain the old interpretation.
DECISION_CODES = (
    4, 4, 4, 5, 4, 5, 5, 4, 4, 4, 4, 5, 5, 5, 4,
    4, 4, 4, 9, 4, 2, 6, 3, 7, 0, 4, 5, 4, 5,
)


def check_pins(data, sec):
    for site, raw in PINS:
        exact(data, sec, site, raw)


def inspect_decisions(instructions):
    result = []
    require(len(DECISIONS) == len(DECISION_CODES), 'decision metadata mismatch')
    for (site, expected_target, description), expected_code in zip(DECISIONS, DECISION_CODES):
        require(site in instructions, f'no instruction at {site:#x}')
        row = instructions[site]
        kind, target, _ = transfer(row)
        require(kind == 'branch' and target == expected_target,
                f'branch shape/target mismatch at {site:#x}')
        raw = row['raw']
        require((raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f and
                 (raw[1] & 0x0f) == expected_code) or
                (0x70 <= raw[0] <= 0x7f and (raw[0] & 0x0f) == expected_code),
                f'branch condition mismatch at {site:#x}')
        result.append((hex(site), row['raw'].hex(), hex(target), description))
    return result


def fold64(a, b):
    product = (a & MASK64) * (b & MASK64)
    return ((product & MASK64) ^ (product >> 64)) & MASK64


def normalized_slot(raw):
    require(isinstance(raw, bytes) and len(raw) == 32, 'slot must have exactly 32 bytes')
    return raw[::-1]


def slot_hash(raw, seed, secret0, secret1):
    """Synthetic projection of the selected slot-hash inputs; no code runs."""
    for x in (seed, secret0, secret1):
        require(type(x) is int and 0 <= x <= MASK64, 'invalid hash word')
    key = normalized_slot(raw)
    a, b, c, d = struct.unpack('<QQQQ', key)
    return fold64(fold64(d ^ secret0, b ^ secret1) ^
                  fold64(a ^ seed, c ^ secret0) ^ 4, secret0)


def probe(controls, keys, key, hash_value):
    """Synthetic full-key probe with explicit controls; valid tables only."""
    require(isinstance(controls, bytes) and len(controls) >= 16 and
            len(controls) & (len(controls)-1) == 0, 'invalid control count')
    require(len(keys) == len(controls), 'invalid key count')
    require(isinstance(key, bytes) and len(key) == 32, 'invalid probe key')
    require(type(hash_value) is int and 0 <= hash_value <= MASK64, 'invalid hash')
    require(all(k is None or isinstance(k, bytes) and len(k) == 32 for k in keys),
            'invalid stored key')
    mask, step = len(controls) - 1, 0
    index, tag = hash_value & mask, hash_value >> 57
    for _ in range(len(controls) // 16):
        group = [(index + i) & mask for i in range(16)]
        for i in group:
            if controls[i] == tag and keys[i] == key:
                return i
        if any(controls[i] == 0xff for i in group):
            return None
        step += 16
        index = (index + step) & mask
    raise ValueError('probe requires a terminating empty control')


def reserve_plan(mask, count, additional):
    """Bounded arithmetic projection on a well-formed power-of-two table."""
    for x in (mask, count, additional):
        require(type(x) is int and 0 <= x <= MASK64, 'invalid reserve input')
    require(mask < MASK64 and (mask + 1) & mask == 0, 'invalid bucket mask')
    need = count + additional
    if need > MASK64:
        return {'branch': 'overflow'}
    capacity = mask if mask < 8 else (mask + 1) - ((mask + 1) >> 3)
    require(count <= capacity, 'count exceeds capacity')
    if need <= capacity // 2:
        return {'branch': 'in_place', 'capacity': capacity}
    request = max(capacity + 1, need)
    if request < 15:
        buckets = 4 if request < 4 else 8 if request < 8 else 16
    else:
        if request > 0x1fffffffffffffff:
            return {'branch': 'overflow'}
        quotient = (request * 8) // 7
        buckets = 1 << (quotient - 1).bit_length()
    if buckets * 104 > MASK64:
        return {'branch': 'overflow'}
    allocated = ((buckets * 104 + 15) & ~15) + buckets + 16
    if allocated > 0x7ffffffffffffff0:
        return {'branch': 'overflow'}
    return {'branch': 'allocate', 'buckets': buckets, 'allocation_bytes': allocated}


def record_bytes(data, sec, va):
    head = read_va(data, sec, va, 4)
    length = struct.unpack('<I', head)[0]
    require(4 <= length < 0xffffffff, 'unsupported unwind record')
    return read_va(data, sec, va, length + 4)


def collect(data):
    authenticate(data)
    require(struct.unpack_from('<HH', data, 16) == (3, 62), 'expected x86-64 ET_DYN')
    sec = sections(data)
    require(len({s['name'] for s in sec}) == len(sec), 'duplicate section name')
    fdes, roles, methods, fork_rows, method_rows = selected_fdes(data, sec)
    check_pins(data, sec)
    decoded, by_site, body_records, function_rows, unwind = {}, {}, {}, [], []
    hdr = next(s for s in sec if s['name'] == '.eh_frame_hdr')
    for start in sorted(roles):
        fde = fdes[start]
        code = read_va(data, sec, start, fde['end'] - start, True)
        rows = decode_stream(code, start)
        decoded[start] = rows
        for row in rows:
            require(row['site'] not in by_site, 'duplicate instruction address')
            by_site[row['site']] = row
        sha = hashlib.sha256(code).hexdigest()
        body_records[hex(start)] = code.hex()
        function_rows.append((hex(start), hex(fde['end']), len(code),
                              hex(offset_for(sec, start, len(code), True)), hex(fde['fde']),
                              hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] else '',
                              sha, len(rows), roles[start]))
        hdr_va = hdr['address'] + 12 + 8 * fde['index']
        unwind.append({'start_va': hex(start), 'end_exclusive_va': hex(fde['end']),
                       'fde_va': hex(fde['fde']), 'fde_raw': record_bytes(data, sec, fde['fde']).hex(),
                       'cie_va': hex(fde['cie']), 'cie_raw': record_bytes(data, sec, fde['cie']).hex(),
                       'index_entry_va': hex(hdr_va), 'index_entry_raw': read_va(data, sec, hdr_va, 8).hex(),
                       'lsda_va': hex(fde['lsda']) if fde['lsda'] else None})
    decision_rows = inspect_decisions(by_site)
    ins_rows, transfer_rows, indirect_slots = [], [], set()
    for start in sorted(decoded):
        for row in decoded[start]:
            site, raw = row['site'], row['raw']
            kind, target, slot = transfer(row)
            ins_rows.append((hex(start), hex(site), hex(offset_for(sec, site, len(raw), True)),
                             raw.hex(), kind or 'other', hex(target) if target is not None else '',
                             hex(slot) if slot is not None else ''))
            if kind is not None:
                transfer_rows.append((hex(start), hex(site), kind, raw.hex(),
                                      hex(target) if target is not None else '',
                                      hex(slot) if slot is not None else ''))
            if slot is not None:
                indirect_slots.add(slot)
    window_rows = []
    for name, start, end in WINDOWS:
        owners = [f for f in fdes.values() if f['start'] <= start < end <= f['end']]
        require(len(owners) == 1 and start in by_site and
                (end in by_site or end == owners[0]['end']), 'window not on instruction boundaries')
        raw = read_va(data, sec, start, end - start, True)
        window_rows.append((name, hex(owners[0]['start']), hex(start), hex(end),
                            hex(offset_for(sec, start, len(raw), True)), raw.hex()))
    required_relocations = {
        0x56bed08: 0x2776950,
        0x56bed10: 0x27712d0,
        0x56bed18: 0x276fa70,
        0x5773780: 0x4e742e0,
        0x5773268: 0x4ea53c0,
        0x576e3e0: 0x5788348,
    }
    required_relocations.update({method['slot']: start for start, method in methods.items()})
    wanted = set(required_relocations) | indirect_slots | {0x576dfe0}
    relocs = scan_relocations(data, sec, wanted)
    for slot, target in required_relocations.items():
        validate_relative(relocs[slot], target)
    memcpy = relocs[0x576dfe0]
    require(memcpy['type'] == 6 and memcpy['symbol'] != 0 and memcpy['addend'] == 0,
            'memcpy slot is not GLOB_DAT')
    require(dyn_symbol(data, sec, memcpy['symbol']) == 'memcpy', 'wrong dynamic copy symbol')
    relocation_rows = []
    for slot in sorted(relocs):
        row = relocs[slot]
        name = dyn_symbol(data, sec, row['symbol']) if row['symbol'] else ''
        relocation_rows.append((hex(slot), row['type'], row['symbol'], name,
                                hex(row['addend']) if row['addend'] >= 0 else str(row['addend']),
                                hex(row['file_offset']), row['raw'].hex()))
    calls = []
    for start in sorted(decoded):
        for instruction in decoded[start]:
            kind, target, slot = transfer(instruction)
            if kind not in ('call_rel32', 'call_indirect'):
                continue
            resolved, symbol = target, ''
            if slot is not None:
                relocation = relocs[slot]
                if relocation['type'] == 8 and relocation['symbol'] == 0:
                    resolved = relocation['addend']
                elif relocation['symbol']:
                    symbol = dyn_symbol(data, sec, relocation['symbol'])
            calls.append((hex(start), hex(instruction['site']), instruction['raw'].hex(),
                          kind, hex(slot) if slot is not None else '',
                          hex(resolved) if resolved is not None else '', symbol,
                          roles.get(resolved, 'outside selected extents') if resolved is not None else 'unresolved'))
    slots = []
    for offset, expected in ((0x18, 0x2776950), (0x20, 0x27712d0), (0x28, 0x276fa70)):
        va = 0x56becf0 + offset
        raw = read_va(data, sec, va, 8)
        require(raw == b'\x00' * 8, 'unexpected unrelocated callback slot bytes')
        row = validate_relative(relocs[va], expected)
        slots.append((hex(0x56becf0), hex(offset), hex(va), raw.hex(),
                      hex(row['addend']), hex(row['file_offset'])))
    key = read_va(data, sec, 0x574f0c0, 20)
    require(key == b'\0' * 19 + b'\x09', 'prior address-09 object key changed')
    layout = [
        ('context environment pointer', hex(0x278ed6e), struct.unpack('<I', by_site[0x278ed6e]['raw'][-4:])[0]),
        ('environment outer pointer', hex(0x278ed85), struct.unpack('<I', by_site[0x278ed85]['raw'][-4:])[0]),
        ('environment outer count', hex(0x278ed75), struct.unpack('<I', by_site[0x278ed75]['raw'][-4:])[0]),
        ('outer entry stride', hex(0x278ed8c), (1 + (1 << (by_site[0x278ed8c]['raw'][-1] >> 6))) << by_site[0x278ed90]['raw'][-1]),
        ('outer address offset', hex(0x278edfe), by_site[0x278edfe]['raw'][-1]),
        ('outer slot pointer offset', hex(0x278ee07), by_site[0x278ee07]['raw'][-1]),
        ('outer slot count offset', hex(0x278ee0b), by_site[0x278ee0b]['raw'][-1]),
        ('account bucket stride', hex(0x278f37c), struct.unpack('<I', by_site[0x278f37c]['raw'][-4:])[0]),
        ('slot bucket stride', hex(0x278f6ae), by_site[0x278f6ae]['raw'][-1]),
        ('slot input advance', hex(0x278f792), by_site[0x278f792]['raw'][-1]),
        ('slot state offset', hex(0x278f713), by_site[0x278f6ae]['raw'][-1] + struct.unpack('b', by_site[0x278f713]['raw'][-2:-1])[0]),
        ('normal result byte', hex(0x278f896), by_site[0x278f896]['raw'][-1]),
        ('revision byte', hex(0x276fa78), by_site[0x276fa78]['raw'][-1]),
    ]
    require(dict((k, v) for k, _, v in layout)['outer entry stride'] == 48, 'unexpected entry stride')
    exceptions = read_lsda(data, sec, fdes[0x278ed50], set(by_site))
    summary = {
        'target': 'node94', 'target_sha256': DIGEST,
        'function_count': len(function_rows), 'selected_code_bytes': sum(f['end']-f['start'] for f in fdes.values()),
        'decoded_instruction_count': len(ins_rows), 'transfer_count': len(transfer_rows),
        'annotated_branch_count': len(decision_rows), 'semantic_window_count': len(window_rows),
        'descriptor_method_count': len(slots), 'relocation_count': len(relocation_rows),
        'revision_descriptor_count': len(fork_rows), 'revision_method_count': len(method_rows),
        'lsda_call_site_count': len(exceptions['entries']),
        'lsda_landing_count': sum(e['landing_va'] is not None for e in exceptions['entries']),
        'call_site_count': len(calls),
        'call_sites_to_selected_extents': sum(row[-1] not in ('outside selected extents', 'unresolved') for row in calls),
        'unresolved_call_sites': sum(row[-1] == 'unresolved' for row in calls),
        'prior_key_va': hex(0x574f0c0), 'prior_key_file_offset': hex(offset_for(sec, 0x574f0c0, 20)),
        'prior_key_hex': key.hex(),
        'interpretation': 'Selected static records only; no captured execution or component coverage claim.',
    }
    return {
        'functions.tsv': tsv(['start_va','end_va','size','file_offset','fde_va','cie_va','lsda_va','sha256','instruction_count','role_inferred'], function_rows),
        'bodies.json': json_bytes(body_records),
        'unwind.json': json_bytes(unwind),
        'instructions.tsv': tsv(['fde_start','site_va','file_offset','bytes','kind','target_va','slot_va'], ins_rows),
        'control-flow.tsv': tsv(['fde_start','site_va','kind','bytes','target_va','slot_va'], transfer_rows),
        'calls.tsv': tsv(['fde_start','site_va','bytes','kind','slot_va','resolved_target_va','symbol_name','target_role_inferred'], calls),
        'revision-descriptors.tsv': tsv(['context_byte','descriptor_va','method_0x18_va','method_0x20_va','method_0x28_va','prior_set_calls','fixed_key_va','fixed_key_hex'], fork_rows),
        'revision-methods.tsv': tsv(['context_byte','descriptor_va','offset','slot_va','method_va','revision_store_va','walker_call_va','prior_set_calls','set_call_sites','rela_file_offset','raw_sha256','masked_shape_sha256'], method_rows),
        'semantic-windows.tsv': tsv(['purpose','fde_start','start_va','end_va','file_offset','bytes'], window_rows),
        'decisions.tsv': tsv(['site_va','bytes','taken_va','condition'], decision_rows),
        'descriptor.tsv': tsv(['descriptor_va','method_offset','slot_va','file_bytes','rela_addend_va','rela_file_offset'], slots),
        'relocations.tsv': tsv(['slot_va','type','symbol_index','symbol_name','addend','rela_file_offset','raw'], relocation_rows),
        'layout.tsv': tsv(['field','source_instruction_va','value'], layout),
        'exceptions.json': json_bytes(exceptions),
        'summary.json': json_bytes(summary),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    records = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(records.items()):
        (args.out / name).write_bytes(content)
    print('Generated', len(records), 'digest-bound evidence files.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('re21_access_list94:', error, file=sys.stderr)
        raise SystemExit(1)
