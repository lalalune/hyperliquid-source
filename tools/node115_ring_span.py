#!/usr/bin/env python3
"""Bind the node #115 ring-span descriptor leaf using only static stdlib parsing.

The small x86 decoder accepts only the instruction forms needed by this packet.
It never advances a captured CPU state or executes the captured program.
"""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET_REL = 'research/work-items/RE-001-node115-ring-span'
PACKET = ROOT / PACKET_REL
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
START, END = 0x2d55b30, 0x2d55bef
BODY_SHA = 'e9a031557c0d127ca9671c407e03a7df2d07c693b016d4931703504e53455df2'
SOURCE_COMMIT = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
MASK = (1 << 64) - 1
FDE = {'fde': 0xd94580, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
FRAME_BYTES = {
    'fde': '10000000acd60e00a815fc01bf00000000000000',
    'cie': '1400000000000000017a5200017810011b0c070890010000',
}
CALLER_START, CALLER_END = 0x2c47660, 0x2c4d2e9
CALL_SITES = (0x2c47db2, 0x2c47e05, 0x2c4820c)
CONTEXT_SLICES = ((0x2c47d7e, 0x2c47db7), (0x2c47dce, 0x2c47e0a),
                  (0x2c48204, 0x2c48211))
LOCATION_SITE, LOCATION_VA, PATH_VA = 0x2c4c715, 0x644d990, 0x448f4e
SOURCE_PATH = b'l1/src/asset/pdi.rs'

REGS = {
    64: 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(),
    32: 'eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d'.split(),
    8: 'al cl dl bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b'.split(),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reg(index, width, rex):
    require(width != 8 or rex or index < 4, 'unsupported high-byte register')
    return {'reg': REGS[width][index], 'width': width}


def operand_text(operand):
    if 'reg' in operand:
        return operand['reg']
    if 'target' in operand:
        return hex(operand['target'])
    if 'imm' in operand:
        return hex(operand['imm'])
    parts = []
    if operand['base']:
        parts.append(operand['base'])
    if operand['index']:
        parts.append(f"{operand['index']}*{operand['scale']}")
    address = '+'.join(parts)
    displacement = operand['disp']
    if displacement:
        address += ('+' if address and displacement > 0 else '') + hex(displacement)
    return {8: 'byte', 32: 'dword', 64: 'qword'}[operand['width']] + ' [' + (address or '0x0') + ']'


def decode(code, start):
    """Strict, bounded x86-64 subset: REX, ModRM/SIB, rel8/rel32, immediates.

    All unsupported opcodes, extensions, prefixes and truncated operands fail.
    Instruction boundaries come from parsing, never searching for opcode bytes.
    """
    rows, pos = [], 0

    def take(n, signed=False):
        nonlocal pos
        require(pos + n <= len(code), 'truncated instruction')
        value = int.from_bytes(code[pos:pos + n], 'little', signed=signed)
        pos += n
        return value

    def modrm(width, rex):
        value = take(1)
        mod, field, low = value >> 6, (value >> 3) & 7, value & 7
        rd = reg(field + (8 if rex & 4 else 0), width, rex)
        if mod == 3:
            return field, rd, reg(low + (8 if rex & 1 else 0), width, rex)
        base, index, scale, displacement = None, None, 1, 0
        if low == 4:
            sib = take(1)
            scale, ix, bas = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
            if ix != 4 or rex & 2:
                index = REGS[64][ix + (8 if rex & 2 else 0)]
            if bas == 5 and mod == 0:
                displacement = take(4, True)
            else:
                base = REGS[64][bas + (8 if rex & 1 else 0)]
        elif low == 5 and mod == 0:
            base, displacement = 'rip', take(4, True)
        else:
            base = REGS[64][low + (8 if rex & 1 else 0)]
        if mod == 1:
            displacement = take(1, True)
        elif mod == 2:
            displacement = take(4, True)
        return field, rd, {'base': base, 'index': index, 'scale': scale,
                           'disp': displacement, 'width': width}

    while pos < len(code):
        begin, rex = pos, 0
        if 0x40 <= code[pos] <= 0x4f:
            rex = take(1)
        op = take(1)
        width = 64 if rex & 8 else 32
        if op in (0x89, 0x8b, 0x88, 0x8d, 0x31, 0x85, 0x39, 0x29, 0x01):
            if op == 0x88:
                width = 8
            _, rd, rm = modrm(width, rex)
            name = {0x89: 'mov', 0x8b: 'mov', 0x88: 'mov', 0x8d: 'lea',
                    0x31: 'xor', 0x85: 'test', 0x39: 'cmp', 0x29: 'sub', 0x01: 'add'}[op]
            operands = [rd, rm] if op in (0x8b, 0x8d) else [rm, rd]
            if op == 0x8d:
                require('base' in rm and width == 64, 'unsupported LEA form')
        elif op in (0xf7, 0xc1, 0xc7):
            field, _, rm = modrm(width, rex)
            require(not rex & 4, 'unsupported group extension')
            if op == 0xf7:
                require(field == 3 and width == 64, 'unsupported F7 group')
                name, operands = 'neg', [rm]
            elif op == 0xc1:
                require(field == 4 and width == 64, 'unsupported shift group')
                name, operands = 'shl', [rm, {'imm': take(1), 'width': 8}]
            else:
                require(field == 0, 'unsupported C7 group')
                value = take(4, width == 64)
                name, operands = 'mov', [rm, {'imm': value, 'width': width}]
        elif 0xb0 <= op <= 0xbf:
            byte = op < 0xb8
            width = 8 if byte else width
            index = (op & 7) + (8 if rex & 1 else 0)
            name, operands = 'mov', [reg(index, width, rex),
                                      {'imm': take(width // 8), 'width': width}]
        elif op == 0x0f:
            ext = take(1)
            require(ext in (0x95, 0x43), 'unsupported 0F opcode')
            if ext == 0x95:
                field, _, rm = modrm(8, rex)
                require(field == 0 and not rex & 4, 'unsupported SETNE form')
                name, operands = 'setne', [rm]
            else:
                _, rd, rm = modrm(width, rex)
                require(width == 64, 'unsupported CMOVAE width')
                name, operands = 'cmovae', [rd, rm]
        elif op in (0x71, 0x74, 0x77, 0xeb, 0xe8, 0xe9):
            require(not rex, 'unsupported branch prefix')
            displacement = take(4 if op in (0xe8, 0xe9) else 1, True)
            name = {0x71: 'jno', 0x74: 'je', 0x77: 'ja', 0xeb: 'jmp',
                    0xe8: 'call', 0xe9: 'jmp'}[op]
            operands = [{'target': start + pos + displacement}]
        elif op == 0xc3:
            require(not rex, 'unsupported RET prefix')
            name, operands = 'ret', []
        else:
            raise ValueError(f'unsupported opcode at {start + begin:#x}')
        row = {'va': start + begin, 'bytes': code[begin:pos].hex(),
               'mnemonic': name, 'operands': operands}
        row['assembly'] = name + (' ' + ', '.join(map(operand_text, operands)) if operands else '')
        rows.append(row)
    return rows


# Independently transcribed instruction obligations, checked against parsed operands.
EXPECTED_ASSEMBLY = '''mov rax, rdi
mov rcx, qword [rsi]
mov rdx, rcx
neg rdx
jno 0x2d55b62
mov rcx, qword [rsi+0x8]
xor edi, edi
mov r8, rcx
test rcx, rcx
setne r9b
je 0x2d55b54
mov r8, qword [rsi+0x18]
mov rdx, qword [rsi+0x10]
mov dil, r9b
xor esi, esi
mov r9, rdi
jmp 0x2d55bc7
mov rdx, qword [rsi+0x18]
test rdx, rdx
je 0x2d55b95
mov rdi, qword [rsi+0x10]
xor r8d, r8d
cmp rdi, rcx
cmovae r8, rcx
sub rdi, r8
mov r9, rcx
sub r9, rdi
mov r8, rdx
sub r8, r9
ja 0x2d55b9c
add rdx, rdi
xor r8d, r8d
mov rcx, rdx
jmp 0x2d55b9c
xor edi, edi
xor ecx, ecx
xor r8d, r8d
mov rdx, qword [rsi+0x8]
lea rsi, qword [rdi+rdi*2]
shl rsi, 0x4
add rsi, rdx
lea rcx, qword [rcx+rcx*2]
shl rcx, 0x4
add rcx, rdx
lea rdi, qword [r8+r8*2]
shl rdi, 0x4
add rdi, rdx
mov r9d, 0x2
mov qword [rax], r9
mov qword [rax+0x8], rsi
mov qword [rax+0x10], rcx
mov qword [rax+0x18], rdx
mov qword [rax+0x20], rdi
mov qword [rax+0x28], 0x0
mov qword [rax+0x30], rcx
mov qword [rax+0x38], rdx
mov qword [rax+0x40], r8
ret'''.splitlines()


def parameters(rows):
    """Extract the constants whose instruction-derived meanings the model uses."""
    by_va = {row['va']: row for row in rows}
    neg = by_va[0x2d55b39]
    require(neg['mnemonic'] == 'neg' and neg['operands'][0]['width'] == 64,
            'sentinel must follow qword NEG overflow')
    strides = []
    for lea_va, shift_va in ((0x2d55ba0, 0x2d55ba4), (0x2d55bab, 0x2d55baf),
                             (0x2d55bb6, 0x2d55bba)):
        lea, shift = by_va[lea_va], by_va[shift_va]
        require(lea['mnemonic'] == 'lea' and shift['mnemonic'] == 'shl', 'stride sequence')
        mem = lea['operands'][1]
        require(mem['base'] == mem['index'] and mem['disp'] == 0, 'stride LEA')
        strides.append((1 + mem['scale']) << (shift['operands'][1]['imm'] & 63))
    require(len(set(strides)) == 1, 'inconsistent strides')
    return {'word_bits': 64, 'sentinel': 1 << 63, 'stride': strides[0],
            'ring_tag': by_va[0x2d55bc1]['operands'][1]['imm'],
            'zero_word': by_va[0x2d55bda]['operands'][1]['imm']}


def validate_body(body):
    rows = decode(body, START)
    require([r['assembly'] for r in rows] == EXPECTED_ASSEMBLY, 'instruction rule changed')
    require(len(body) == END - START, 'function extent changed')
    boundaries = {r['va'] for r in rows}
    edges = []
    for row in rows:
        va, name = row['va'], row['mnemonic']
        following = va + len(bytes.fromhex(row['bytes']))
        successors = []
        if name != 'ret':
            if name in ('jno', 'je', 'ja', 'jmp'):
                successors.append(row['operands'][0]['target'])
            if name != 'jmp':
                successors.append(following)
        require(all(dst in boundaries for dst in successors), 'branch leaves decoded boundary')
        require(all(dst > va for dst in successors), 'expected acyclic forward graph')
        edges.append({'va': va, 'successors': successors})
    reached, pending = set(), [START]
    graph = {r['va']: r['successors'] for r in edges}
    while pending:
        current = pending.pop()
        if current not in reached:
            reached.add(current)
            pending.extend(graph[current])
    require(reached == boundaries, 'unreachable decoded bytes')
    require(hashlib.sha256(body).hexdigest() == BODY_SHA, 'body SHA-256 mismatch')
    return rows, edges, parameters(rows)


def model(words, params=None):
    """Independent raw-word equation, not a native object API or CPU emulator."""
    require(len(words) == 4 and all(type(w) is int and 0 <= w <= MASK for w in words),
            'expected four unsigned qwords')
    p = params or {'sentinel': 1 << 63, 'stride': 48, 'ring_tag': 2, 'zero_word': 0}
    capacity, base, head, length = words
    if capacity == p['sentinel']:
        flag = int(base != 0)
        return [flag, 0, base, head, flag, p['zero_word'], base, head, length if flag else 0]
    if length == 0:
        index = first_end = second_count = 0
    else:
        index = (head - (capacity if head >= capacity else 0)) & MASK
        room = (capacity - index) & MASK
        if length > room:
            first_end, second_count = capacity, length - room
        else:
            first_end, second_count = (index + length) & MASK, 0
    address = lambda index: (base + p['stride'] * index) & MASK
    first_start, first_stop, second_stop = address(index), address(first_end), address(second_count)
    return [p['ring_tag'], first_start, first_stop, base, second_stop, p['zero_word'],
            first_stop, base, second_count]


# Expected outputs are hand-derived from the decoded paths, not computed by model().
VECTORS = [
    ('empty ignores head', [8, 4096, 7, 0], [2, 4096, 4096, 4096, 4096, 0, 4096, 4096, 0]),
    ('zero capacity empty', [0, 0, MASK, 0], [2, 0, 0, 0, 0, 0, 0, 0, 0]),
    ('contiguous', [8, 4096, 2, 3], [2, 4192, 4336, 4096, 4096, 0, 4336, 4096, 0]),
    ('exact end equality', [8, 4096, 5, 3], [2, 4336, 4480, 4096, 4096, 0, 4480, 4096, 0]),
    ('wrap by one', [8, 4096, 5, 4], [2, 4336, 4480, 4096, 4144, 0, 4480, 4096, 1]),
    ('full ring', [8, 4096, 5, 8], [2, 4336, 4480, 4096, 4336, 0, 4480, 4096, 5]),
    ('head equals capacity', [8, 4096, 8, 3], [2, 4096, 4240, 4096, 4096, 0, 4240, 4096, 0]),
    ('head reduced once', [8, 4096, 13, 4], [2, 4336, 4480, 4096, 4144, 0, 4480, 4096, 1]),
    ('not general modulo', [8, 4096, 17, 1], [2, 4528, 4576, 4096, 4096, 0, 4576, 4096, 0]),
    ('address wrap', [8, MASK - 15, 1, 2], [2, 32, 128, MASK - 15, MASK - 15, 0, 128, MASK - 15, 0]),
    ('sentinel absent', [1 << 63, 0, 85, MASK], [0, 0, 0, 85, 0, 0, 0, 85, 0]),
    ('sentinel present', [1 << 63, 7, 85, 9], [1, 0, 7, 85, 1, 0, 7, 85, 9]),
    ('sentinel high nonzero', [1 << 63, MASK, 0, MASK], [1, 0, MASK, 0, 1, 0, MASK, 0, MASK]),
    ('unsigned high capacity', [MASK, 0, 0, 1], [2, 0, 48, 0, 0, 0, 48, 0, 0]),
]


def mapping(secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or missing file mapping')
    s = matches[0]
    return s['offset'] + va - s['address']


def read(data, secs, va, size):
    off = mapping(secs, va, size)
    return bytes(data[off:off + size])


def frame_record(data, secs, row):
    result = dict(row)
    for key in ('fde', 'cie'):
        va = row[key]
        size = 4 + struct.unpack('<I', read(data, secs, va, 4))[0]
        result[key + '_record'] = {'file_offset': mapping(secs, va, size),
                                  'bytes': read(data, secs, va, size).hex()}
    return result


def scan_direct(data, text, target):
    """Scan EVERY byte for E8/E9 rel32 across full .text, including unaligned hits.

    Returned sites are syntactic candidates until instruction context is checked.
    mmap.find avoids allocating an additional full copy of .text or the ELF.
    """
    rows = []
    first, end = text['offset'], text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        pos = first - 1
        while True:
            pos = data.find(bytes([opcode]), pos + 1, end - 4)
            if pos == -1:
                break
            va = text['address'] + pos - first
            displacement = struct.unpack_from('<i', data, pos + 1)[0]
            if va + 5 + displacement == target:
                rows.append({'site': va, 'file_offset': pos, 'kind': 'call' if opcode == 0xe8 else 'jmp',
                             'target': target, 'bytes': bytes(data[pos:pos + 5]).hex()})
    return sorted(rows, key=lambda r: r['site'])


def inspect_static(data):
    """Narrow evidence checks below the public digest gate, exposed for controls."""
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text']
    require(len(text) == 1 and text[0]['address'] == TEXT_START
            and text[0]['size'] == TEXT_END - TEXT_START and text[0]['flags'] & 4,
            'text section changed')
    text = text[0]
    _, fdes = eh_frame_records(data, secs)
    matches = [r for r in fdes if r['start'] <= START < r['end'] or r['start'] == START]
    require(matches == [FDE], 'selected FDE changed')
    for key, expected in FRAME_BYTES.items():
        require(read(data, secs, FDE[key], len(bytes.fromhex(expected))).hex() == expected,
                'selected frame bytes changed')
    body = read(data, secs, START, END - START)
    instructions, edges, params = validate_body(body)
    next_start = min(r['start'] for r in fdes if r['start'] > START)
    require(next_start == 0x2d55bf0 and read(data, secs, END, next_start - END) == b'\xcc',
            'padding or following FDE changed')
    owner = [r for r in fdes if r['start'] == CALLER_START]
    require(len(owner) == 1 and owner[0] == {'fde': 0x118c3e4, 'cie': 0x103d604,
            'start': CALLER_START, 'end': CALLER_END, 'lsda': 0x26f114}, 'caller FDE changed')
    owner = owner[0]
    contexts = []
    for lo, hi in CONTEXT_SLICES:
        raw = read(data, secs, lo, hi - lo)
        decoded = decode(raw, lo)
        require(decoded[-1]['mnemonic'] == 'call'
                and decoded[-1]['operands'] == [{'target': START}], 'caller target changed')
        require(decoded[0]['mnemonic'] == 'lea' and decoded[0]['operands'][0]['reg'] == 'rdi'
                and decoded[-2]['assembly'] in ('mov rsi, r15', 'mov rsi, r13'),
                'caller argument context changed')
        contexts.append({'start': lo, 'end': hi, 'bytes': raw.hex(), 'instructions': decoded})
    callers = scan_direct(data, text, START)
    require(tuple(r['site'] for r in callers) == CALL_SITES
            and all(r['kind'] == 'call' for r in callers), 'direct caller census changed')
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]
    for row in callers:
        index = bisect.bisect_right(starts, row['site']) - 1
        containing = ordered[index] if index >= 0 else None
        require(containing == owner and row['site'] + 5 <= containing['end'], 'caller containment changed')
        row['owner_start'] = containing['start']
        # Local decoding is evidence of alignment, not a whole-caller CFG proof.
        row['local_decode_start'] = next(c['start'] for c in contexts
                                        if c['instructions'][-1]['va'] == row['site'])
    lea = decode(read(data, secs, LOCATION_SITE, 7), LOCATION_SITE)
    require(len(lea) == 1 and lea[0]['assembly'].startswith('lea rdi, qword [rip+'),
            'source Location reference changed')
    loc = LOCATION_SITE + 7 + lea[0]['operands'][1]['disp']
    require(loc == LOCATION_VA, 'source Location target changed')
    literal = read(data, secs, PATH_VA, len(SOURCE_PATH))
    require(literal == SOURCE_PATH, 'source path bytes changed')
    location = read(data, secs, loc, 24)
    require(location == struct.pack('<QQII', 0, len(SOURCE_PATH), 32, 14), 'source Location changed')
    rels = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(rels) == 1, 'relocation section changed')
    rel = rels[0]
    found = []
    for offset in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot == loc:
            found.append({'file_offset': offset, 'slot': slot, 'info': info, 'addend': addend,
                          'bytes': bytes(data[offset:offset + 24]).hex()})
    require(len(found) == 1 and found[0]['info'] == 8 and found[0]['addend'] == PATH_VA,
            'source Location relocation changed')
    vectors = [{'case': label, 'input': words, 'output': expected} for label, words, expected in VECTORS]
    require(all(model(r['input'], params) == r['output'] for r in vectors), 'target-derived vector disagreement')
    counts = {'body_bytes': len(body), 'instructions': len(instructions),
              'padding_bytes': next_start - END, 'callees': 0,
              'call_sites': len(callers), 'tail_jump_sites': sum(r['kind'] == 'jmp' for r in callers),
              'caller_owners': len({r['owner_start'] for r in callers}),
              'conditional_branches': sum(r['mnemonic'] in ('jno', 'je', 'ja') for r in instructions),
              'unconditional_branches': sum(r['mnemonic'] == 'jmp' for r in instructions),
              'returns': sum(r['mnemonic'] == 'ret' for r in instructions),
              'output_words': 9, 'vectors': len(vectors), 'text_bytes_scanned': text['size']}
    return {'task': 'RE-001', 'component_allocation': 'assets',
            'target': {'release': 115, 'sha256': SHA, 'size': SIZE},
            'question': 'How does this leaf transform four input qwords into its returned nine-qword descriptor?',
            'window': {'start': START, 'end': END, 'file_offset': mapping(secs, START, len(body)),
                       'size': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                       'body_bytes': body.hex(), 'frame': frame_record(data, secs, FDE),
                       'padding': {'start': END, 'end': next_start, 'bytes': 'cc'}},
            'instructions': instructions, 'control_flow': edges, 'parameters': params,
            'callees': [], 'caller_scan': {'start': TEXT_START, 'end': TEXT_END,
                'method': 'every-byte E8/E9 signed rel32; local decode at retained argument-setup slices',
                'sites': callers, 'owners': [frame_record(data, secs, owner)], 'contexts': contexts},
            'source_context': {'claim': 'Location in caller FDE; not original leaf symbol or exclusive ownership',
                'reference': lea[0], 'location_va': loc, 'location_bytes': location.hex(),
                'path_va': PATH_VA, 'path': literal.decode('ascii'), 'line': 32, 'column': 14,
                'relocation': found[0]},
            'rule': {'input_qwords': ['capacity_or_sentinel', 'base_or_alternate_word', 'head_or_alternate_word', 'length_or_alternate_word'],
                'output_qwords': ['tag', 'first_start_or_zero', 'first_end_or_word1', 'base_or_word2',
                                  'second_end_or_flag', 'zero', 'first_end_or_word1', 'base_or_word2', 'second_count_or_payload'],
                'arithmetic': 'unsigned qword arithmetic modulo 2^64; NEG overflow is equality to 2^63',
                'scope': 'complete local value and store transformation under readable input, writable output and valid return stack'},
            'vectors': vectors, 'counts': counts,
            'non_claims': ['original Rust symbol or type identity', 'validity of arbitrary native pointers',
                'whole-caller reachability or indirect/address-taken callers', 'runtime execution or reconstruction equivalence',
                'exclusive first-party implementation ownership', 'component acceptance gate']}


def analyze(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'node #115 digest mismatch')
    return inspect_static(data)


def load_record(binary=TARGET):
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'node #115 digest mismatch')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return analyze(data)


def walk_text(record):
    return '\n'.join(f"{r['va']:#x}  {r['bytes']:<24} {r['assembly']}" for r in record['instructions']) + '\n'


def count_lines(record):
    return '\n'.join(f'- {key}: {value}' for key, value in sorted(record['counts'].items()))


def readme_text(r):
    w, p = r['window'], r['parameters']
    return f'''# RE-001: node #115 ring-span descriptor at {START:#x}

Task: {r['task']} function bind. Component allocation: `{r['component_allocation']}`,
based on the asset/pdi caller context. This is bounded static research, not a
reconstructed Rust component or gate claim.
Target: node #115, SHA-256 `{SHA}`.
Source/reference base: `{SOURCE_COMMIT}`. New code and prose are independently
authored under the repository MIT license; no inferred proprietary source was copied.

## Question and answer

**{r['question']}**

Given input qwords `(a,b,c,d)` at RSI and output at RDI, this call-free leaf returns
the original output pointer in RAX after writing the descriptor below. For
`a != 2^63`, it forms a ring-shaped split with a {p['stride']}-byte element stride,
reduces the starting index by **at most one** subtraction of `a`, separates the
non-wrapping and wrapping portions, and writes pointer endpoints plus a residual
count with raw tag `{p['ring_tag']}`. Empty input produces empty spans at `b`.
For `a == 2^63`, it instead writes an alternate descriptor controlled by whether
`b` is zero. The sentinel is established by **NEG overflow**, not a sign test.
Every store and control-flow edge is decoded; no helper behavior is assumed.

## Rule and proof

All variables below are unsigned qwords, with addition, subtraction and address
multiplication modulo `2^64`. These equations cover raw input words; native
memory validity remains a precondition. The original types and field names are
unknown. The words “capacity”, “head” and “span” describe an inferred use of the
observed arithmetic, not recovered source identifiers.

For the ordinary arm, if `d == 0`, set `i = e = k = 0`. Otherwise:

```
i = c - (a if c >= a else 0)
room = a - i
if d > room: e = a;     k = d - room
else:        e = i + d; k = 0
P(x) = b + {p['stride']}*x
output = [{p['ring_tag']}, P(i), P(e), b, P(k), 0, P(e), b, k]
```

For the sentinel arm, let `f = int(b != 0)`:

```
output = [f, 0, b, c, f, 0, b, c, (d if f else 0)]
```

The instruction walk is retained in `instructions.txt` and in `records.json`.
At `0x2d55b39`, qword NEG sets OF only for the bit pattern `2^63`; JNO selects
the ordinary arm for all other words, including other high-bit-set words.
The sentinel arm's TEST/SETNE observes the full `b`, zero-extends the flag by
XOR EDI followed by MOV DIL, and avoids reading input `+0x18` when `b == 0`.
The ordinary arm tests `d` before loading `c`; an empty span ignores `c`.
CMP/CMOVAE at `0x2d55b72` performs unsigned `c >= a`; the subsequent subtraction
reduces `c` once. The SUB at `0x2d55b85` and JA use unsigned **strict** `d > room`;
equality takes the contiguous arm with zero residual count. Each LEA computes
three times its index and each SHL multiplies by sixteen, giving the stride.
The stores at `0x2d55bc7` onward cover every output word, with duplicate endpoint
words preserved. RET ends the FDE, with no outgoing branch, call or indirect dispatch.

For `a > 0`, `c < 2*a`, `d <= a`, and valid non-wrapping addresses, these are two
ordered contiguous spans of a circular buffer, with total element count `d`.
This useful interpretation is narrower than the raw-word equation. For example,
`c >= 2*a` is not normalized modulo `a`; raw arithmetic still follows the equation.
The model does not validate allocation geometry or dereference calculated endpoints.
Input reads precede all output stores, so the local equation also permits overlapping
input/output storage if those accesses themselves are valid. Code and the live return
slot must remain intact. It makes no concurrent mutation or hardware-fault guarantee.

## Extent, caller context and closure

Coordinates are original ELF virtual addresses; the function is
`[{START:#x}, {END:#x})`, file offset `{w['file_offset']:#x}`.
Body SHA-256: `{w['body_sha256']}`.
FDE VA/file offset `{FDE['fde']:#x}`; CIE VA/file offset `{FDE['cie']:#x}`.
Raw FDE/CIE bytes and LSDA absence are retained. The complete decoded graph is
acyclic, every instruction is reachable in its structural graph, and its only
exit is RET. This validates this particular extent beyond an unwind start alone.
Padding is `cc` at `{END:#x}`, up to the next FDE start `{w['padding']['end']:#x}`;
it is excluded from the body digest. No callee identity/extent is outstanding:
the measured leaf has no calls or external transfers and no RIP-relative data reads.

The full `.text` interval `[{TEXT_START:#x}, {TEXT_END:#x})` was scanned at every
byte for E8/E9 signed-rel32 destinations. The retained matches are E8 calls at
`0x2c47db2`, `0x2c47e05` and `0x2c4820c`, all within caller FDE
`[{CALLER_START:#x}, {CALLER_END:#x})`. Argument-setup slices are decoded from
their bytes and end at these calls; output is a stack address and input is moved
into RSI. Their owner FDE references a relocated Location at `{LOCATION_VA:#x}`
from LEA `{LOCATION_SITE:#x}`, pointing to `{SOURCE_PATH.decode()}:32:14`.
The path, length, line, column and R_X86_64_RELATIVE addend are checked.
This binds a first-party **caller context**, not an original leaf name or proof
that this potentially generic monomorphized operation was authored in that file.
No absolute build-machine path is recorded.

The census is exhaustive for raw E8/E9 destinations in the stated interval.
Local instruction slices support the matches, but the complete caller CFG is
unmeasured; indirect calls, function pointers, dynamically modified code and
callers outside `.text` are not counted. Caller behavior and its own callees
are not bound. There are no normalized code bytes or masked operands.

## Derived counts

This entire block is rendered from `records.json`; the test suite checks it and
the complete README rendering against the JSON. Counts measure only this packet.

<!-- counts:start -->
{count_lines(r)}
<!-- counts:end -->

## Novelty before analysis

Before adding this packet, these commands all returned exit status 1 with empty
stdout and stderr at the source base above:

```sh
rg -i '2d55b30' research/
rg -i '47536944' research/
rg -i '2d55b30' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '47536944' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees needing additional novelty checks. The start lies in the
assigned `[0x2800000,0x3c00000)` band and is absent from the supplied claimed-address
list. After creation, the research searches naturally match this packet. The
external title lists are preflight inputs, not a claim of a live upstream query.

## Reproduce and validation scope

From the repository root, with materialized authenticated target bytes:

```sh
python3 tools/node115_ring_span.py --out research/work-items/RE-001-node115-ring-span/
python3 -m unittest tests.test_node115_ring_span -v
python3 research/work-items/RE-001-node115-ring-span/verify.py
make verify
make catalogue-check
make reproduce
```

Local results: the targeted tests, packet verifier, `make verify`,
`make catalogue-check`, `make doctor` and `make reproduce` passed. Repository-wide
`make test` was not run, as requested. Hosted CI was not run or claimed.

The producer authenticates the whole ELF before parsing or output creation and
uses a single memory map, never a second full binary copy. Python 3.10+ stdlib
and the existing `elf_index.py`/`fde_extents.py` parsers suffice. Development
used Python 3.13.5 on Linux x86-64; exploratory GNU objdump 2.44 was used only
for manual inspection. No producer, verifier or test imports or invokes objdump.
The retained evidence is generated by the strict Python decoder. No captured
binary or emulator was run, and no network, installation or external service was used.

`verify.py` checks an exact file whitelist and manifest, regenerates all evidence
in memory, and requires byte-identical output. The manifest binds the producer,
tests, verifier and reused parsing dependencies as well as the generated packet.
Corruption controls cover the public digest gate, every byte of the local body,
truncated/unsupported instructions, shifted FDE, padding, actual caller targets,
Location references/data/relocation, and extra/duplicate/missing manifest entries.
A stride-operand counterfactual changes a model output before semantic rejection.
Frozen instruction-derived vectors cover sentinel, unsigned, empty, equality,
wrap, single-subtraction and modular-address boundaries; wider independent tests
compare valid ring spans with enumerated circular positions. Neither is target
execution. This tool only resolves the selected binary unknown; no surrounding
analysis infrastructure was changed.

## Results, limitations and next step

Before: no retained research/title-list reference to this function start. After:
its full local input/output rule, branch conditions, extent and direct-call
context are byte-bound and reproducible. Verdict: **strong for the raw-word
transformation**, with only an inferred circular-span/type interpretation.

No reconstructed Rust, Cargo graph, two-build comparison, whole-ELF equivalence,
runtime differential result, protocol meaning, memory safety, complete caller
reachability, original Rust ABI/type identity or component gate is claimed.
Source-implementation comparisons, relocation/vtable closure outside the stated
Location, and transitive caller semantics are not yet implemented/measured.
All existing progress/catalogue/gate records are unchanged. Next: bind a consumer
of this descriptor in the same caller to identify the raw tags' iteration and
ownership meaning before assigning an original collection type.
'''


GENERATED = ('README.md', 'records.json', 'instructions.txt')
DEPENDENCIES = ('tools/node115_ring_span.py', 'tests/test_node115_ring_span.py',
                'tools/elf_index.py', 'tools/fde_extents.py')


def payloads(record):
    return {'README.md': readme_text(record).encode(),
            'records.json': (json.dumps(record, indent=2, sort_keys=True) + '\n').encode(),
            'instructions.txt': walk_text(record).encode()}


def manifest_text(output):
    paths = {name: Path(output) / name for name in (*GENERATED, 'verify.py')}
    paths.update({name: ROOT / name for name in DEPENDENCIES})
    return ''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\n'
                   for name, path in sorted(paths.items()))


def generate(binary, output):
    record = load_record(binary)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, contents in payloads(record).items():
        (output / name).write_bytes(contents)
    # The verifier is a maintained source file, copied for isolated regeneration.
    if output.resolve() != PACKET.resolve():
        (output / 'verify.py').write_bytes((PACKET / 'verify.py').read_bytes())
    (output / 'MANIFEST.sha256').write_text(manifest_text(output), encoding='utf-8')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record = generate(args.binary, args.out)
    print(json.dumps({'target_sha256': SHA, 'start': hex(START), 'counts': record['counts']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        raise SystemExit(str(error))
