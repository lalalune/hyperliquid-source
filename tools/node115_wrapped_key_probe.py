#!/usr/bin/env python3
"""Bind one node #115 circular key search, statically and without native tools.

The decoder is deliberately a rejecting subset, not a general x86 disassembler.
The equations below model values, never execute captured code or advance a PC.
New code is independently authored under the repository MIT license.
"""
import argparse
import bisect
import hashlib
import itertools
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-wrapped-key-probe'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE_COMMIT = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x2ee0640, 0x2ee0761
BODY_SHA = '1efd73cd0cb516ac291a6d28230f91c441e5953af233dd06c3d4f176560b91fa'
CALLER, CALLER_END, CALL_SITE = 0x2eedb70, 0x2eedff0, 0x2eedcf9
CALLER_SHA = '16e424775c946f87fe8fc596f7879426b08c465f87bc341074d21c3bd9462334'
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
U64 = (1 << 64) - 1
REGS = {
    64: 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(),
    32: 'eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d'.split(),
    16: 'ax cx dx bx sp bp si di r8w r9w r10w r11w r12w r13w r14w r15w'.split(),
    8: 'al cl dl bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b'.split(),
    128: [f'xmm{i}' for i in range(16)],
}
CONDITIONS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
              's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def reg(number, width, rex):
    if width == 8 and not rex and 4 <= number < 8:
        return ('ah', 'ch', 'dh', 'bh')[number - 4]
    return REGS[width][number]


def decode(code, start):
    """Decode every byte, including ModRM/SIB, signed displacements and branches.

    Unknown opcodes, prefixes, group extensions and truncated operands reject.
    Operand strings use explicit memory widths; targets are original ELF VAs.
    """
    rows, pos = [], 0
    while pos < len(code):
        begin = pos

        def integer(size, signed=False):
            nonlocal pos
            demand(pos + size <= len(code), 'truncated instruction')
            value = int.from_bytes(code[pos:pos + size], 'little', signed=signed)
            pos += size
            return value

        prefixes = []
        while pos < len(code) and code[pos] in (0x66, 0x2e):
            prefixes.append(integer(1))
        rex = integer(1) if pos < len(code) and 0x40 <= code[pos] <= 0x4f else 0
        width = 64 if rex & 8 else 32
        opcode = integer(1)

        def modrm(bits=width, regbits=None):
            value = integer(1)
            mode, extension, low = value >> 6, (value >> 3) & 7, value & 7
            register = reg(extension + (8 if rex & 4 else 0), regbits or bits, rex)
            if mode == 3:
                return reg(low + (8 if rex & 1 else 0), bits, rex), register, extension
            terms, disp = [], 0
            if low == 4:
                sib = integer(1)
                scale, index, base = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
                if base == 5 and mode == 0:
                    disp = integer(4, True)
                else:
                    terms.append(reg(base + (8 if rex & 1 else 0), 64, rex))
                if index != 4 or rex & 2:
                    terms.append(f'{reg(index + (8 if rex & 2 else 0), 64, rex)}*{scale}')
            elif low == 5 and mode == 0:
                terms.append('rip')
                disp = integer(4, True)
            else:
                terms.append(reg(low + (8 if rex & 1 else 0), 64, rex))
            if mode == 1:
                disp = integer(1, True)
            elif mode == 2:
                disp = integer(4, True)
            expression = '+'.join(terms)
            if disp:
                expression += ('+' if disp > 0 and expression else '') + str(disp)
            return f'm{bits}[{expression or "0"}]', register, extension

        target = None
        if opcode == 0x0f:
            second = integer(1)
            if 0x80 <= second <= 0x8f:
                displacement = integer(4, True)
                target = start + pos + displacement
                op, args = 'j' + CONDITIONS[second & 15], [hex(target)]
            elif 0x90 <= second <= 0x9f:
                operand, _, ext = modrm(8)
                demand(ext == 0 and not rex & 4, 'unsupported SETcc extension')
                op, args = 'set' + CONDITIONS[second & 15], [operand]
            elif 0x40 <= second <= 0x4f:
                operand, register, _ = modrm()
                op, args = 'cmov' + CONDITIONS[second & 15], [register, operand]
            elif second in (0xb6, 0xb7):
                operand, register, _ = modrm(8 if second == 0xb6 else 16, width)
                op, args = 'movzx', [register, operand]
            elif second == 0x1f:
                operand, _, ext = modrm(16 if 0x66 in prefixes else width)
                demand(ext == 0 and not rex & 4, 'unsupported NOP extension')
                op, args = 'nop', [operand]
            elif second in (0x10, 0x11, 0x29, 0x57):
                operand, register, _ = modrm(128)
                op = {0x10: 'movups', 0x11: 'movups', 0x29: 'movaps', 0x57: 'xorps'}[second]
                args = [operand, register] if second in (0x11, 0x29) else [register, operand]
            else:
                raise ValueError(f'unsupported 0f opcode {second:#x}')
        elif 0x70 <= opcode <= 0x7f or opcode in (0xe8, 0xe9, 0xeb):
            displacement = integer(4 if opcode in (0xe8, 0xe9) else 1, True)
            target = start + pos + displacement
            op = ('call' if opcode == 0xe8 else 'jmp') if opcode >= 0xe8 else 'j' + CONDITIONS[opcode & 15]
            args = [hex(target)]
        elif opcode in (0x89, 0x8b, 0x8d, 0x39, 0x3b, 0x85, 0x31,
                        0x29, 0x01, 0x03, 0x20, 0x84):
            bits = 8 if opcode in (0x20, 0x84) else width
            operand, register, _ = modrm(bits)
            op = {0x89: 'mov', 0x8b: 'mov', 0x8d: 'lea', 0x39: 'cmp', 0x3b: 'cmp',
                  0x85: 'test', 0x31: 'xor', 0x29: 'sub', 0x01: 'add', 0x03: 'add',
                  0x20: 'and', 0x84: 'test'}[opcode]
            if opcode == 0x8d:
                demand(operand.startswith('m'), 'LEA requires memory addressing')
            args = [register, operand] if opcode in (0x8b, 0x8d, 0x3b, 0x03) else [operand, register]
        elif opcode in (0x80, 0x81, 0x83):
            operand, _, ext = modrm(8 if opcode == 0x80 else width)
            demand(ext in (0, 2, 3, 5, 7) and not rex & 4, 'unsupported arithmetic extension')
            op = {0: 'add', 2: 'adc', 3: 'sbb', 5: 'sub', 7: 'cmp'}[ext]
            args = [operand, integer(4 if opcode == 0x81 else 1, opcode != 0x80)]
        elif opcode in (0xc1, 0xd1):
            operand, _, ext = modrm()
            demand(ext in (4, 5) and not rex & 4, 'unsupported shift extension')
            op, args = ('shl' if ext == 4 else 'shr'), [operand, integer(1) if opcode == 0xc1 else 1]
        elif opcode == 0xf7:
            operand, _, ext = modrm()
            demand(ext == 3 and not rex & 4, 'unsupported F7 extension')
            op, args = 'neg', [operand]
        elif opcode == 0xff:
            operand, _, ext = modrm(64)
            demand(ext in (0, 2, 4) and not rex & 4, 'unsupported FF extension')
            op, args = {0: 'inc', 2: 'call_indirect', 4: 'jmp_indirect'}[ext], [operand]
        elif opcode == 0xc7:
            operand, _, ext = modrm()
            demand(ext == 0 and not rex & 4, 'unsupported C7 extension')
            op, args = 'mov', [operand, integer(4, width == 64)]
        elif 0xb8 <= opcode <= 0xbf:
            op, args = 'mov', [reg(opcode - 0xb8 + (8 if rex & 1 else 0), width, rex), integer(8 if width == 64 else 4)]
        elif 0x50 <= opcode <= 0x5f:
            op = 'push' if opcode < 0x58 else 'pop'
            args = [reg((opcode & 7) + (8 if rex & 1 else 0), 64, rex)]
        elif opcode in (0x1c, 0x3d, 0xa8):
            op, args = {0x1c: ('sbb', ['al']), 0x3d: ('cmp', ['eax']), 0xa8: ('test', ['al'])}[opcode]
            args.append(integer(4 if opcode == 0x3d else 1))
        elif opcode in (0x90, 0xc3):
            op, args = ('nop' if opcode == 0x90 else 'ret'), []
        else:
            raise ValueError(f'unsupported opcode {opcode:#x} at {start + begin:#x}')
        demand(not prefixes or op == 'nop', 'unsupported instruction prefixes')
        demand(pos - begin <= 15, 'instruction exceeds x86 length limit')
        row = {'va': start + begin, 'size': pos - begin, 'bytes': code[begin:pos].hex(), 'op': op, 'args': args}
        if target is not None:
            row['target'] = target
        rows.append(row)
    return rows


def check_semantics(rows):
    """Check operative facts separately from the public whole-ELF hash gate."""
    by_va = {r['va']: r for r in rows}
    anchors = {
        0x2ee0640: ('mov', ['rax', 'm64[rdi+24]']),
        0x2ee064d: ('mov', ['rdx', 'm64[rdi]']),
        0x2ee0650: ('mov', ['rcx', 'm64[rdi+16]']),
        0x2ee065a: ('cmovae', ['r8', 'rdx']),
        0x2ee066a: ('jbe', ['0x2ee06ea']),
        0x2ee0679: ('seta', ['al']),
        0x2ee067c: ('sbb', ['al', 0]),
        0x2ee0683: ('je', ['0x2ee074c']),
        0x2ee0689: ('cmp', ['eax', 255]),
        0x2ee068e: ('jne', ['0x2ee074d']),
        0x2ee06a6: ('shr', ['rsi', 1]),
        0x2ee06af: ('shl', ['r10', 5]),
        0x2ee06b3: ('cmp', ['m64[r8+r10*1]', 'rdi']),
        0x2ee06b7: ('cmova', ['rcx', 'rax']),
        0x2ee06c2: ('ja', ['0x2ee06a0']),
        0x2ee06d4: ('adc', ['rcx', 0]),
        0x2ee06dd: ('setne', ['al']),
        0x2ee06e0: ('add', ['rdx', 'rcx']),
        0x2ee06fb: ('mov', ['eax', 1]),
        0x2ee0716: ('shr', ['r9', 1]),
        0x2ee071f: ('shl', ['r10', 5]),
        0x2ee0723: ('cmp', ['m64[rcx+r10*1]', 'rsi']),
        0x2ee0727: ('cmova', ['rdi', 'r8']),
        0x2ee0732: ('ja', ['0x2ee0710']),
        0x2ee0745: ('adc', ['rdi', 0]),
        0x2ee0754: ('mov', ['eax', 1]),
    }
    for va, (op, args) in anchors.items():
        demand(va in by_va and (by_va[va]['op'], by_va[va]['args']) == (op, args),
               f'semantic anchor changed at {va:#x}')
    demand(rows[0]['va'] == START and rows[-1]['va'] + rows[-1]['size'] == END,
           'function decode extent changed')
    demand(not any(r['op'] in ('call', 'call_indirect', 'jmp_indirect', 'push', 'pop') for r in rows),
           'leaf closure changed')
    demand(not any(r['op'] in ('mov', 'add', 'sub', 'adc', 'sbb', 'xor') and
                   r['args'][0].startswith('m') for r in rows), 'unexpected memory store')
    for row in rows:
        if 'target' in row:
            demand(row['target'] in by_va, 'branch is not an internal instruction boundary')
    return {'record_stride': 1 << by_va[0x2ee06af]['args'][1],
            'key_width_bits': 64, 'found_status': 0, 'missing_status': 1,
            'seam_equality': 'return first record of the wrapped second span immediately',
            'span_search': 'last key <= sought (or first record); equal returns found, otherwise insertion position',
            'comparison': 'unsigned', 'explicit_memory_writes': 0, 'callees': []}


def selected_section(secs, name):
    found = [s for s in secs if s['name'] == name and s['type'] != 8]
    demand(len(found) == 1, 'missing or duplicate section ' + name)
    return found[0]


def offset(secs, va, size):
    found = [s['offset'] + va - s['address'] for s in secs if s['type'] != 8 and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    demand(len(found) == 1, 'ambiguous or unmapped VA')
    return found[0]


def read_va(data, secs, va, size):
    off = offset(secs, va, size)
    return data[off:off + size]


def frame_record(data, secs, cies, fdes, index, start, end, fde_va, cie_va):
    matches = [f for f in fdes if f['start'] == start]
    demand(len(matches) == 1 and matches[0]['end'] == end and matches[0]['fde'] == fde_va
           and matches[0]['cie'] == cie_va, 'exact FDE binding changed')
    row = dict(matches[0])
    indexed = [r for r in index if r['start'] == start]
    demand(len(indexed) == 1 and indexed[0]['fde'] == fde_va, 'FDE/index binding changed')
    row['header_index'] = indexed[0]['index']
    row['cie_decoded'] = cies[cie_va]
    for name, va in [('fde', fde_va), ('cie', cie_va)]:
        size = struct.unpack('<I', read_va(data, secs, va, 4))[0] + 4
        row[name + '_file_offset'] = offset(secs, va, size)
        row[name + '_bytes'] = read_va(data, secs, va, size).hex()
    row['file_offset'] = offset(secs, start, end - start)
    row['body_sha256'] = hashlib.sha256(read_va(data, secs, start, end - start)).hexdigest()
    row['size'] = end - start
    return row


def rel32_scan(data, text, target):
    """Every possible E8/E9 position in the complete .text, including unaligned hits."""
    hits = []
    limit = text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        pos = text['offset']
        while True:
            pos = data.find(bytes([opcode]), pos, limit - 4)
            if pos < 0:
                break
            va = text['address'] + pos - text['offset']
            destination = va + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if destination == target:
                hits.append({'va': va, 'opcode': hex(opcode), 'target': destination,
                             'file_offset': pos, 'bytes': data[pos:pos + 5].hex()})
            pos += 1
    return sorted(hits, key=lambda r: r['va'])


def source_record(data, secs, caller_rows):
    site, slot, string = 0x2eedfa1, 0x6461510, 0x4402cd
    instruction = next(r for r in caller_rows if r['va'] == site)
    demand(instruction['op'] == 'lea' and instruction['args'][0] == 'rdx', 'source LEA changed')
    raw = bytes.fromhex(instruction['bytes'])
    demand(len(raw) == 7 and raw[:3] == bytes.fromhex('488d15') and
           site + len(raw) + struct.unpack_from('<i', raw, 3)[0] == slot, 'source LEA target changed')
    rel = selected_section(secs, '.rela.dyn')
    demand(rel['size'] % 24 == 0, 'truncated RELA section')
    matches = []
    for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
        destination, info, addend = struct.unpack_from('<QQq', data, pos)
        if destination == slot:
            matches.append({'file_offset': pos, 'slot': destination, 'info': info,
                            'addend': addend, 'bytes': data[pos:pos + 24].hex()})
    demand(len(matches) == 1 and matches[0]['info'] == 8 and matches[0]['addend'] == string,
           'source relocation changed')
    location = read_va(data, secs, slot, 24)
    pointer, length, line, column = struct.unpack('<QQII', location)
    demand((pointer, length, line, column) == (0, 24, 64, 17), 'source Location changed')
    path = read_va(data, secs, string, length)
    demand(path == b'base/src/l1_map/entry.rs', 'source path changed')
    return {'caller_start': CALLER, 'lea_va': site, 'location_va': slot,
            'location_file_offset': offset(secs, slot, 24), 'location_bytes': location.hex(),
            'path_va': string, 'path': path.decode('ascii'), 'line': line, 'column': column,
            'relocation': matches[0],
            'claim': 'source-associated caller; original leaf symbol and Rust type remain unknown'}


def check_image(data):
    """Private structural/semantic checks, also used beneath the digest gate by tests."""
    secs, index = unwind_index(data)
    text = selected_section(secs, '.text')
    demand((text['address'], text['address'] + text['size']) == (TEXT_START, TEXT_END)
           and text['flags'] & 4, 'text geometry changed')
    cies, fdes = eh_frame_records(data, secs)
    function = frame_record(data, secs, cies, fdes, index, START, END, 0xda2e70, 0xca6ed8)
    demand(function['lsda'] is None and function['cie_decoded']['augmentation'] == 'zR', 'leaf unwind closure changed')
    code = read_va(data, secs, START, END - START)
    instructions = decode(code, START)
    semantics = check_semantics(instructions)
    demand(function['body_sha256'] == BODY_SHA, 'function body digest changed')
    following = min(f['start'] for f in fdes if f['start'] > START)
    demand(following == 0x2ee0770 and END <= following, 'following FDE changed')
    padding = read_va(data, secs, END, following - END)
    demand(padding == b'\xcc' * (following - END), 'padding changed')
    hits = rel32_scan(data, text, START)
    demand([(r['va'], r['opcode']) for r in hits] == [(CALL_SITE, '0xe8')], 'direct caller census changed')
    caller = frame_record(data, secs, cies, fdes, index, CALLER, CALLER_END, 0x11bd1a8, 0x103d604)
    caller_code = read_va(data, secs, CALLER, CALLER_END - CALLER)
    caller_rows = decode(caller_code, CALLER)
    by_va = {r['va']: r for r in caller_rows}
    demand(CALL_SITE in by_va and by_va[CALL_SITE]['op'] == 'call' and
           by_va[CALL_SITE]['target'] == START, 'caller instruction boundary/target changed')
    for row in caller_rows:
        if row['op'].startswith('j') and 'target' in row:
            demand(row['target'] in by_va, 'caller branch is not an instruction boundary')
    source = source_record(data, secs, caller_rows)
    demand(caller['body_sha256'] == CALLER_SHA, 'caller body digest changed')
    hits[0]['owner_start'] = CALLER
    hits[0]['boundary_validation'] = 'complete strict linear decode from unique caller FDE start; all local branch targets align'
    return {'target': {'release': 115, 'sha256': DIGEST, 'file_size': len(data)},
            'function': function, 'semantics': semantics, 'instructions': instructions,
            'padding': {'start': END, 'end': following, 'size': len(padding), 'bytes': padding.hex(),
                        'classification': 'INT3 fill outside the return-closed FDE'},
            'caller_scan': {'start': TEXT_START, 'end': TEXT_END, 'opcodes': ['e8', 'e9'],
                            'method': 'all byte positions, signed little-endian rel32, then instruction-boundary validation',
                            'hits': hits, 'indirect_references': 'not enumerated'},
            'caller_context': {'frame': caller, 'instructions': caller_rows,
                               'scope': 'extent, instruction boundaries, direct edge and source association only; no behavioral bind'},
            'source_association': source}


def authenticate(data):
    demand(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == DIGEST,
           'node #115 size/SHA-256 mismatch')


def validate_inputs(physical, raw_head, length, sought):
    demand(all(isinstance(x, int) and 0 <= x <= U64 for x in
               itertools.chain(physical, (raw_head, length, sought))), 'model requires u64 values')
    if not length:
        return 0
    capacity = len(physical)
    demand(0 < length <= capacity and raw_head < 2 * capacity, 'invalid ring geometry')
    head = raw_head - capacity if raw_head >= capacity else raw_head
    logical = [physical[(head + i) % capacity] for i in range(length)]
    demand(all(a <= b for a, b in zip(logical, logical[1:])), 'unsorted logical keys')
    return head


def instruction_relation(physical, raw_head, length, sought):
    """Value recurrence read from the decoded instructions; no CPU or pointer model."""
    head = validate_inputs(physical, raw_head, length, sought)
    if length == 0:
        return 1, 0
    capacity = len(physical)
    tail = capacity - head
    if length > tail:
        pivot = physical[0]
        if pivot == sought:
            return 0, tail
        if pivot < sought:
            base, span, bias = 0, length - tail, tail
        else:
            base, span, bias = head, tail, 0
    else:
        base, span, bias = head, length, 0
    cursor = 0
    while span > 1:
        half = span >> 1
        if physical[base + cursor + half] <= sought:
            cursor += half
        span -= half
    key = physical[base + cursor]
    return (0, bias + cursor) if key == sought else (1, bias + cursor + int(key < sought))


def rule_model(physical, raw_head, length, sought):
    """Independent declarative rule using the standard-library sorted search."""
    head = validate_inputs(physical, raw_head, length, sought)
    if length == 0:
        return 1, 0
    logical = [physical[(head + i) % len(physical)] for i in range(length)]
    seam = len(physical) - head
    if length > seam and logical[seam] == sought:
        return 0, seam
    after = bisect.bisect_right(logical, sought)
    if after and logical[after - 1] == sought:
        return 0, after - 1
    return 1, after


# Frozen from branch/comparison reasoning, not generated from rule_model.
# Tuple: label, logical keys, capacity, normalized head, add_capacity, key, (RAX,RDX).
VECTORS = [
    ('empty', [], 0, 0, False, 0, (1, 0)),
    ('singleton_equal', [7], 1, 0, False, 7, (0, 0)),
    ('singleton_before', [7], 1, 0, False, 6, (1, 0)),
    ('singleton_after', [7], 1, 0, False, 8, (1, 1)),
    ('nonwrap_gap', [2, 4, 9], 6, 1, False, 5, (1, 2)),
    ('nonwrap_last_duplicate', [2, 4, 4, 9], 6, 1, False, 4, (0, 2)),
    ('ends_at_capacity', [2, 4, 9], 6, 3, False, 9, (0, 2)),
    ('wrapped_first_span', [2, 4, 7, 9], 6, 4, False, 4, (0, 1)),
    ('wrapped_seam_equal', [2, 4, 7, 9], 6, 4, False, 7, (0, 2)),
    ('wrapped_second_span', [2, 4, 7, 9], 6, 4, False, 9, (0, 3)),
    ('wrapped_before', [2, 4, 7, 9], 6, 4, False, 0, (1, 0)),
    ('wrapped_first_gap', [2, 4, 7, 9], 6, 4, False, 5, (1, 2)),
    ('wrapped_second_gap', [2, 4, 7, 9], 6, 4, False, 8, (1, 3)),
    ('wrapped_after', [2, 4, 7, 9], 6, 4, False, 10, (1, 4)),
    ('seam_duplicate_exception', [2, 4, 4, 4], 4, 2, False, 4, (0, 2)),
    ('all_equal_seam_exception', [4, 4, 4, 4], 4, 3, False, 4, (0, 1)),
    ('second_span_later_duplicates', [1, 2, 3, 7, 7], 5, 3, False, 7, (0, 4)),
    ('normalize_head_once', [2, 4, 7, 9], 6, 4, True, 9, (0, 3)),
    ('unsigned_high_bit', [0, (1 << 63) - 1, 1 << 63, U64], 4, 3, False, 1 << 63, (0, 2)),
    ('unsigned_max_equal', [0, U64], 2, 1, False, U64, (0, 1)),
    ('unsigned_max_gap', [0, U64], 2, 1, False, U64 - 1, (1, 1)),
]


def vector_records():
    rows = []
    for label, logical, capacity, head, extra, key, expected in VECTORS:
        physical = [0] * capacity
        for i, value in enumerate(logical):
            physical[(head + i) % capacity] = value
        raw_head = head + (capacity if extra else 0)
        demand(instruction_relation(physical, raw_head, len(logical), key) == expected,
               'instruction-derived fixture mismatch: ' + label)
        demand(rule_model(physical, raw_head, len(logical), key) == expected,
               'declarative model fixture mismatch: ' + label)
        rows.append({'label': label, 'physical_keys': physical, 'raw_head': raw_head,
                     'length': len(logical), 'sought': key, 'rax': expected[0], 'rdx': expected[1]})
    return rows


def records(data):
    authenticate(data)
    result = check_image(data)
    result['vectors'] = vector_records()
    result['counts'] = {
        'bound_functions': 1,
        'body_bytes': result['function']['size'],
        'body_instructions': len(result['instructions']),
        'return_sites': sum(r['op'] == 'ret' for r in result['instructions']),
        'conditional_branches': sum(r['op'].startswith('j') and r['op'] != 'jmp' for r in result['instructions']),
        'padding_bytes': result['padding']['size'],
        'callees': len(result['semantics']['callees']),
        'direct_call_sites': len(result['caller_scan']['hits']),
        'direct_caller_functions': len({r['owner_start'] for r in result['caller_scan']['hits']}),
        'tail_jump_sites': sum(r['opcode'] == '0xe9' for r in result['caller_scan']['hits']),
        'caller_context_bytes': result['caller_context']['frame']['size'],
        'caller_context_instructions': len(result['caller_context']['instructions']),
        'frozen_vectors': len(result['vectors']),
    }
    return result


def render_walk(record):
    lines = ['node #115 SHA-256 ' + DIGEST, 'Original ELF VAs; bytes unnormalized; strict Python subset decode.']
    for title, rows in [('bound function', record['instructions']), ('caller context (no behavioral bind)', record['caller_context']['instructions'])]:
        lines.append('\n' + title)
        for row in rows:
            lines.append((f"{row['va']:08x}  {row['bytes']:<30} {row['op']} " + ', '.join(map(str, row['args']))).rstrip())
    return '\n'.join(lines) + '\n'


def generate(binary=TARGET, out=PACKET):
    with Path(binary).open('rb') as handle:
        demand(handle.seek(0, 2) == 105896032, 'node #115 size/SHA-256 mismatch')
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            result = records(data)
    payloads = {'records.json': json.dumps(result, indent=2, sort_keys=True) + '\n',
                'instructions.txt': render_walk(result), 'README.md': render_readme(result)}
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, value in payloads.items():
        (out / name).write_text(value, encoding='utf-8', newline='\n')
    return result


def render_readme(record):
    # Defined below with the evidence narrative; all measured counts come from JSON.
    return README_TEMPLATE.format(digest=DIGEST, base=BASE_COMMIT,
                                 metrics='\n'.join(f'| {key} | {value} |' for key, value in record['counts'].items()),
                                 body_sha=record['function']['body_sha256'])


README_TEMPLATE = '''# RE-001: node #115 wrapped key probe

This packet binds the complete computation at `0x2ee0640` for node #115,
SHA-256 `{digest}`. Component: foundation, first-party map-associated search.
Base/reference revision: `{base}`. New analysis, code and tests are independently
authored under the repository MIT license. No source implementation was copied.

Bounded question: given a valid circular storage descriptor and a sorted sequence
of unsigned keys, which status and logical position does this function return,
including equality at the wrap boundary?

Answer: it returns `(RAX,RDX) = (0,index)` for a matching key and `(1,index)`
for a missing key's insertion position. The search compares unsigned qword keys
at the start of each record. Empty input returns missing at the beginning.
Ordinary search paths choose the last equal key. The exception is a wrapped
sequence whose first physically stored key equals the query: the function
immediately returns that key's logical position at the seam, even if later
duplicates exist. It performs no explicit memory writes and has no callees.

## Scope, bytes and measured counts

All addresses are original ELF virtual addresses, all intervals half-open.
The function is `[0x2ee0640,0x2ee0761)`, file offset `0x2edf640`.
Its body SHA-256 is `{body_sha}`. Actual FDE `0xda2e70`, CIE `0xca6ed8`
(`zR`, no personality or LSDA) supplies the same extent. The strict decoder
covers its entire body and every branch lands on an internal instruction boundary.
All exits are local returns; the next FDE starts at `0x2ee0770`. The intervening
bytes are INT3 fill, excluded from the body. FDE/CIE raw bytes, file offsets,
header-index binding, body bytes and complete instruction walks are retained.
The FDE alone is not used to infer a boundary; the return-closed control flow
and external padding supply additional evidence.

These are local evidence counts, not node-wide coverage or accepted gates:

| JSON count key | Value |
| --- | ---: |
{metrics}

`records.json` carries the semantic facts, original operands, source association,
caller evidence and instruction-derived vectors. `instructions.txt` is the
complete strict decode of the leaf and its caller context. No instruction,
operand, relocation or raw body byte is normalized or masked.

## Instruction proof and raw layout

Let `C = qword[RDI+0]`, `P = qword[RDI+8]`, `H = qword[RDI+0x10]`,
`N = qword[RDI+0x18]`, and `K = qword[RSI]`. The observed stride is `0x20`;
only the initial qword of each record is compared. Capacity, head, length and
circular storage are descriptive inferences from these operations, not recovered
Rust field names or ABI types.

For nonempty input, assume `C>0`, `N<=C`, `H<2*C`, readable storage and query,
nonwrapping address calculations, and logical keys sorted in nondecreasing
unsigned order. Memory must remain stable during the call. Empty input skips
the key load and storage dereferences, though it still reads the descriptor's
pointer word. Invalid pointers, unsorted keys and malformed geometry have no
search-contract guarantee; the machine contains no corresponding validation.

* `0x2ee0640..0x2ee066a`: load N; empty branches to zero positions. Otherwise
  normalize `h = H - (H>=C ? C : 0)` using unsigned CMOVAE, compute
  `t=C-h`, and select wrapped storage exactly when `N>t` through SUB/JBE.
* `0x2ee066c..0x2ee068e`: load `qword[P]` and K. CMP/SETA/SBB yields the
  ordering byte: below, equal or above. MOVZX makes this an exact full-word
  value. Equality returns immediately at `0x2ee074c` with RAX zero and RDX=t.
  A smaller physical-first key selects the wrapped second span; a larger key
  selects the tail span. These comparisons are unsigned.
* `0x2ee0694..0x2ee06e3`: search the second span, with length `N-t` and a
  logical index bias t. Maintain cursor b and span s. Each iteration computes
  `half=floor(s/2)`, tentatively advances b, restores the old b only when
  `key[b+half]>K` (CMOVA), and sets `s=s-half`. Thus ties advance. SHR and
  SHL encode the midpoint and record stride. Span strictly decreases until
  its final record is tested. Equality returns found; otherwise ADC adds
  the unsigned less-than carry to produce the insertion position. SETNE
  supplies missing/found status and ADD applies the logical bias.
* `0x2ee06e4..0x2ee0703`: the empty route forms a zero-length span; the
  nonwrapped route forms `[P+h*stride, N]`. Neither wrap branch means a
  second-span search is needed. EAX is initialized to the missing status.
* `0x2ee0705..0x2ee074c`: the tail/nonwrapped loop uses the same midpoint,
  unsigned CMOVA and decreasing-span recurrence. The final equal path
  clears EAX; the unequal path uses carry-preserving JNE and ADC to produce
  insertion position. RDX receives the position without a seam bias.
* `0x2ee074d..0x2ee0760`: a wrapped query below the physical-first key
  enters the tail search; the empty route returns missing at the beginning.

For any nonempty sorted chosen span, the recurrence retains the final key
less than or equal to K, or its initial key if every key is greater. The final
comparison distinguishes equality from the insertion gap. When the ring wraps,
comparing K with the first key of the second span selects the only possible
span, except for immediate seam equality. This proves the stated duplicate
exception rather than assuming a unique-key invariant from the caller.

The independently authored `rule_model` uses `bisect_right` on logical keys
plus the seam rule. A separate `instruction_relation` implements the extracted
value recurrence. Frozen vectors cover empty/singleton inputs, both spans,
exact-end geometry, gaps, repeated keys, head normalization and unsigned
extremes. The tests also compare both formulations over exhaustive small sorted
rings. These are static model checks, not execution or emulation of the capture.

## Callees, caller census and first-party association

The leaf's callee set is empty: the complete decode contains no CALL or indirect
transfer and no branch leaves its extent. There is no helper behavior to assume.

The census scans every possible E8/E9 rel32 start in the complete `.text`
interval `[0x1419300,0x63f0a00)`, including bytes that might be inside another
instruction. The retained hit is E8 at `0x2eedcf9`, targeting this leaf, inside
the actual caller FDE `[0x2eedb70,0x2eedff0)`. The complete caller is strictly
decoded from its FDE start and its local branch targets align, so this hit is
an instruction boundary rather than an unaligned byte-pattern coincidence.
Indirect references, other executable sections and runtime reachability are
outside this direct census. Caller metadata and full decode are context only;
the caller's other callees, exception paths and whole behavior are unbound.

At `0x2eedcee` the caller passes a stack query address in RSI, and at
`0x2eedcf6` it passes its retained descriptor pointer in RDI. The source LEA at
`0x2eedfa1` addresses Location `0x6461510`. An actual R_X86_64_RELATIVE entry
at file offset `0x8cb68` binds that Location's path pointer to `0x4402cd`,
the captured relative path `base/src/l1_map/entry.rs`, line `0x40`, column `0x11`.
The path, length, line/column, LEA displacement and relocation are all checked.
This establishes association with first-party map code; it does not prove the
leaf's original symbol, concrete collection type, or a standard-library origin.

## Novelty and reproduction

Before creating this packet, the following commands each exited with status 1
and empty stdout/stderr. No function callee required a separate address check.
The slug was also absent from the research, tool/test and supplied PR lists.
These are pre-change checks; the address is expected to occur in this packet
after creation. The PR-list snapshot is supplied input, not a live upstream query.

```sh
rg -i '2ee0640' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '49153600' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'wrapped.key.probe' research/ tools/ tests/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

Run from repository root using Python 3.10+ standard library only. Development
used Python 3.13.5 on Linux x86-64; GNU objdump 2.44 was used for initial bounded
inspection (`-d -Mintel --start-address=0x2ee0640 --stop-address=0x2ee0761`).
Neither the generator, verifier nor tests invoke or import a native decoder.
No package installation, network, target execution or environment capture occurs.
Input identity is checked before decoding or creating output. The target is
memory-mapped; the tool does not create full-size binary copies.

```sh
python3 tools/node115_wrapped_key_probe.py --out research/work-items/RE-001-node115-wrapped-key-probe/
python3 -m unittest tests.test_node115_wrapped_key_probe -v
python3 research/work-items/RE-001-node115-wrapped-key-probe/verify.py
make verify
make catalogue-check
make reproduce
```

The generator rewrites only the deterministic records, instruction walk and this
README. The independently reviewed verifier and manifest are packet source files.
The manifest binds all packet payloads plus the new tool and test. Verification
requires an exact path whitelist, checks every hash and regenerates evidence
byte-identically in a temporary directory. The test suite checks README metrics
against JSON and attacks the whole-image digest, operative bytes, actual FDE
start/range, caller target, source relocation and manifest whitelist. The private
structural checks are deliberately callable beneath authentication for corruption
tests; the public generator always authenticates first.

## Results, non-claims and next step

Before this work the selected address had no retained behavioral bind. This
packet establishes its search rule, including the seam equality exception,
complete local instruction/branch closure and a source-associated direct caller.
The models are small value specifications, not reconstructed Rust or original
source. A compiler build, two-build reproducibility, binary comparison and ABI
equivalence have not been implemented or measured. No normalization masks apply.
Source-level relocation/vtable integration, whole-ELF equivalence, dynamic caller
coverage, protocol meaning and hosted CI remain unproved. All component and
full-scope RE-001 gates remain unchanged and incomplete.

Local validation passed: targeted unittests, byte-identical regeneration and
packet verification, `make verify`, `make catalogue-check`, and `make reproduce`.
The repository-wide `make test` was not run; no hosted or container result is
claimed. An initial development run caught misplaced CMOV mutation offsets and
an incorrect model-case count in the test fixtures. Those fixtures were corrected;
the operative CMOV change now demonstrably changes duplicate selection before
the semantic checker rejects it. No binary mismatch or model disagreement was
suppressed.

Next question: establish the caller's key-uniqueness and storage-transition
invariants before assigning a concrete map API or using this rule in Rust.
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, default=PACKET)
    args = parser.parse_args()
    result = generate(args.binary, args.out)
    print(json.dumps(result['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
