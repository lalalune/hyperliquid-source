#!/usr/bin/env python3
"""Statically bind node #115's consuming decimal-triplet leaf; Python stdlib only.

ELF/FDE parsers are reused from this MIT repository. The bounded decoder and
mapping/census helpers adapt the repository's ring-span packet, also MIT.
No target instructions are executed or emulated.
"""
import argparse
import ast
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET_REL = 'research/work-items/RE-001-node115-decimal-cursor'
PACKET = ROOT / PACKET_REL
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
SOURCE_COMMIT = '05bc2de303c05525b71e7e257426e741bc66a390'
START, END = 0x2e564b0, 0x2e56538
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
BODY_SHA = '1a8232ce726e9ffed03a2c18b4a551a07c2f24be62c92791b09e5304dcb90ae6'
FDE = {'fde': 0xd9aac4, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
FRAME_BYTES = {'fde': '10000000f03b0f00e4b90b028800000000000000',
               'cie': '1400000000000000017a5200017810011b0c070890010000'}
CALL_SITE = 0x2e57e92
CALLER_FDE = {'fde': 0xd9ac40, 'cie': 0xca6ed8, 'start': 0x2e57c60,
              'end': 0x2e5810f, 'lsda': None}
CONTEXT_START, CONTEXT_END = 0x2e57e7a, 0x2e57ea2
LOCATION_SITE, LOCATION_VA, PATH_VA = 0x2e57f81, 0x6453d88, 0x446fcd
PATH_SIZE = 58
PATH_SHA = 'd16979a23d4e57a0f42ddc294f588c5cc82e508f0a61aafde39e7b30bba13b4b'
PATH_SUFFIX = b'z_vendor/httparse/src/iter.rs'
REGS = {
    64: 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(),
    32: 'eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d'.split(),
    16: 'ax cx dx bx sp bp si di r8w r9w r10w r11w r12w r13w r14w r15w'.split(),
    8: 'al cl dl bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b'.split(),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def register(index, width, rex):
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
    disp = operand['disp']
    if disp:
        address += ('+' if address and disp > 0 else '') + hex(disp)
    return {8: 'byte', 16: 'word', 32: 'dword', 64: 'qword'}[operand['width']] + ' [' + (address or '0x0') + ']'


def decode(code, start):
    """Strict subset decoder: unsupported prefixes/opcodes/ModRM groups fail.

    Widths, registers, SIB addresses, immediates and branch targets are decoded
    from operands. No opcode searching, disassembler output or assembly lookup
    is used to select instruction boundaries.
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
        rd = {'reg': REGS[width][field + (8 if rex & 4 else 0)], 'width': width}
        if mod == 3:
            return field, rd, register(low + (8 if rex & 1 else 0), width, rex)
        base, index, scale, disp = None, None, 1, 0
        if low == 4:
            sib = take(1)
            scale, ix, bas = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
            if ix != 4 or rex & 2:
                index = REGS[64][ix + (8 if rex & 2 else 0)]
            if bas == 5 and mod == 0:
                disp = take(4, True)
            else:
                base = REGS[64][bas + (8 if rex & 1 else 0)]
        elif low == 5 and mod == 0:
            base, disp = 'rip', take(4, True)
        else:
            base = REGS[64][low + (8 if rex & 1 else 0)]
        if mod == 1:
            disp = take(1, True)
        elif mod == 2:
            disp = take(4, True)
        return field, rd, {'base': base, 'index': index, 'scale': scale,
                           'disp': disp, 'width': width}

    while pos < len(code):
        begin, rex, prefix16 = pos, 0, False
        if code[pos] == 0x66:
            take(1)
            prefix16 = True
        require(pos < len(code), 'truncated prefix')
        if 0x40 <= code[pos] <= 0x4f:
            rex = take(1)
        op = take(1)
        width = 64 if rex & 8 else (16 if prefix16 else 32)
        require(not prefix16 or op == 0x83 and not rex, 'unsupported operand-size prefix')
        if op in (0x8b, 0x89, 0x8d, 0x39, 0x01):
            _, rd, rm = modrm(width, rex)
            name = {0x8b: 'mov', 0x89: 'mov', 0x8d: 'lea', 0x39: 'cmp', 0x01: 'add'}[op]
            operands = [rd, rm] if op in (0x8b, 0x8d) else [rm, rd]
            if op == 0x8d:
                require('base' in rm, 'LEA requires memory form')
        elif op in (0x80, 0x83, 0xc1):
            if op == 0x80:
                width = 8
            field, _, rm = modrm(width, rex)
            require(not rex & 4, 'unsupported group REX.R')
            names = {4: 'shl', 5: 'shr'} if op == 0xc1 else {0: 'add', 7: 'cmp'}
            require(field in names, 'unsupported group extension')
            name = names[field]
            operands = [rm, {'imm': take(1, op == 0x83), 'width': 8}]
        elif op == 0x6b:
            _, rd, rm = modrm(width, rex)
            name, operands = 'imul', [rd, rm, {'imm': take(1, True), 'width': 8}]
        elif 0xb8 <= op <= 0xbf:
            name = 'mov'
            operands = [register((op & 7) + (8 if rex & 1 else 0), width, rex),
                        {'imm': take(8 if width == 64 else 4), 'width': width}]
        elif op == 0x0f:
            require(take(1) == 0xb6, 'unsupported two-byte opcode')
            # MOVZX has an independently sized byte source and full-width dest.
            at = pos
            field, _, rm = modrm(8, rex)
            rd = register(field + (8 if rex & 4 else 0), width, rex)
            require(code[at] >> 6 != 3 or 'reg' in rm, 'invalid MOVZX')
            name, operands = 'movzx', [rd, rm]
        elif op in (0x73, 0x74, 0x75, 0x77, 0xeb, 0xe8, 0xe9):
            require(not rex, 'unsupported branch prefix')
            delta = take(4 if op in (0xe8, 0xe9) else 1, True)
            name = {0x73: 'jae', 0x74: 'je', 0x75: 'jne', 0x77: 'ja',
                    0xeb: 'jmp', 0xe8: 'call', 0xe9: 'jmp'}[op]
            operands = [{'target': start + pos + delta}]
        elif op == 0xc3:
            require(not rex, 'unsupported RET prefix')
            name, operands = 'ret', []
        else:
            raise ValueError(f'unsupported opcode {op:#x} at {start + begin:#x}')
        rows.append({'va': start + begin, 'bytes': bytes(code[begin:pos]).hex(),
                     'mnemonic': name, 'operands': operands,
                     'assembly': name + (' ' + ', '.join(map(operand_text, operands)) if operands else '')})
    return rows


EXPECTED_ASSEMBLY = '''mov r8, qword [rdi+0x8]
mov rdx, qword [rdi+0x10]
mov eax, 0x30001
cmp rdx, r8
jae 0x2e56531
movzx ecx, byte [rdx]
lea rsi, qword [rdx+0x1]
mov qword [rdi+0x10], rsi
add cl, 0xd0
cmp cl, 0x9
ja 0x2e56532
cmp rsi, r8
jae 0x2e56531
movzx esi, byte [rdx+0x1]
lea r9, qword [rdx+0x2]
mov qword [rdi+0x10], r9
lea r10d, dword [rsi-0x30]
cmp r10b, 0x9
ja 0x2e56532
cmp r9, r8
jae 0x2e56531
movzx r8d, byte [rdx+0x2]
add rdx, 0x3
mov qword [rdi+0x10], rdx
add r8b, 0xd0
mov eax, 0x30002
cmp r8b, 0xa
jae 0x2e56531
movzx eax, cl
imul eax, eax, 0x64
movzx ecx, sil
add ecx, ecx
lea ecx, dword [rcx+rcx*4]
add cl, 0x20
movzx ecx, cl
add ecx, eax
movzx eax, r8b
add eax, ecx
shl eax, 0x10
ret
mov eax, 0x30002
ret'''.splitlines()
CONTEXT_ASSEMBLY = '''mov qword [rsp+0x18], rdx
mov qword [rsp+0x8], rdx
mov r12, r8
mov r15, rsi
mov r14, rcx
lea rdi, qword [rsp+0x8]
call 0x2e564b0
mov ecx, eax
shr ecx, 0x10
cmp ax, 0x2
jne 0x2e57eaf'''.splitlines()


def parameters(rows):
    by_va = {r['va']: r for r in rows}
    imm = lambda va: by_va[va]['operands'][-1]['imm']
    return {'empty_return': imm(0x2e564b8), 'invalid_return': imm(0x2e56506),
            'first_adjust': imm(0x2e564cd), 'first_max': imm(0x2e564d0),
            'second_adjust': by_va[0x2e564e6]['operands'][1]['disp'],
            'second_max': imm(0x2e564ea), 'third_adjust': imm(0x2e56502),
            'third_limit': imm(0x2e5650b), 'hundreds': imm(0x2e56514),
            'tens_scale': 2 * (1 + by_va[0x2e5651d]['operands'][1]['scale']),
            'tens_adjust': imm(0x2e56520), 'pack_shift': imm(0x2e5652e)}


def instruction_value(digits, params):
    """Algebra of the decoded arithmetic, for comparison with the decimal model.

    This is a formula over bytes, not an emulator or captured-node invocation.
    """
    a, b, c = digits
    p = params
    first = (a + p['first_adjust']) & 255
    second = (b + p['second_adjust']) & 255
    third = (c + p['third_adjust']) & 255
    if first > p['first_max'] or second > p['second_max'] or third >= p['third_limit']:
        return p['invalid_return']
    value = first * p['hundreds'] + ((b * p['tens_scale'] + p['tens_adjust']) & 255) + third
    return (value << (p['pack_shift'] & 31)) & 0xffffffff


def validate_body(body):
    rows = decode(body, START)
    require([r['assembly'] for r in rows] == EXPECTED_ASSEMBLY, 'instruction rule changed')
    require(len(body) == END - START, 'function extent changed')
    boundaries = {r['va'] for r in rows}
    edges = []
    for row in rows:
        va, name = row['va'], row['mnemonic']
        successors = []
        if name != 'ret':
            if name in ('ja', 'jae'):
                successors.append(row['operands'][0]['target'])
            successors.append(va + len(bytes.fromhex(row['bytes'])))
        require(all(dst in boundaries and dst > va for dst in successors), 'invalid forward CFG')
        edges.append({'va': va, 'successors': successors})
    graph = {r['va']: r['successors'] for r in edges}
    pending, reached = [START], set()
    while pending:
        va = pending.pop()
        if va not in reached:
            reached.add(va)
            pending.extend(graph[va])
    require(reached == boundaries, 'unreachable instruction bytes')
    require(hashlib.sha256(body).hexdigest() == BODY_SHA, 'body SHA-256 mismatch')
    return rows, edges, parameters(rows)


def model(buffer, cursor=0, end=None):
    """Independent consumption/decimal model for valid disjoint buffer storage.

    Return (full zero-extended RAX, updated cursor). Bytes beyond end are ignored.
    The initial cursor may already exceed end, reproducing the unsigned guard.
    """
    require(isinstance(buffer, bytes), 'expected bytes buffer')
    end = len(buffer) if end is None else end
    require(type(cursor) is int and type(end) is int and 0 <= end <= len(buffer)
            and 0 <= cursor < 1 << 64, 'invalid model bounds')
    value = 0
    for _ in range(3):
        if cursor >= end:
            return 0x30001, cursor
        byte = buffer[cursor]
        cursor += 1
        if not 48 <= byte <= 57:
            return 0x30002, cursor
        value = value * 10 + byte - 48
    return value << 16, cursor


# Frozen from the branch/store walk, not filled using model().
VECTORS = [
    ('empty', '', 0, 0, 0x30001, 0),
    ('cursor beyond end', '', 9, 0, 0x30001, 9),
    ('single valid digit', '37', 0, 1, 0x30001, 1),
    ('two valid digits', '3432', 0, 2, 0x30001, 2),
    ('first invalid is consumed', '2f', 0, 1, 0x30002, 1),
    ('second invalid is consumed', '303a', 0, 2, 0x30002, 2),
    ('third invalid is consumed', '30302f', 0, 3, 0x30002, 3),
    ('NUL invalid', '003132', 0, 3, 0x30002, 1),
    ('high byte invalid', '3132ff', 0, 3, 0x30002, 3),
    ('leading zero accepted', '303037', 0, 3, 0x70000, 3),
    ('all zero success distinct from incomplete', '303030', 0, 3, 0, 3),
    ('decimal hundreds', '313233', 0, 3, 0x7b0000, 3),
    ('maximum', '393939', 0, 3, 0x3e70000, 3),
    ('fourth invalid byte untouched', '323030ff', 0, 4, 0xc80000, 3),
    ('offset cursor', 'ff34303421', 1, 5, 0x1940000, 4),
    ('explicit end truncates available bytes', '313233', 0, 2, 0x30001, 2),
    ('sign rejected', '2d3132', 0, 3, 0x30002, 1),
    ('whitespace rejected', '203132', 0, 3, 0x30002, 1),
]


def mapping(secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or missing file mapping')
    s = matches[0]
    return s['offset'] + va - s['address']


def read(data, secs, va, size):
    offset = mapping(secs, va, size)
    return bytes(data[offset:offset + size])


def frame_record(data, secs, row):
    result = dict(row)
    for key in ('fde', 'cie'):
        va = row[key]
        size = 4 + struct.unpack('<I', read(data, secs, va, 4))[0]
        result[key + '_record'] = {'file_offset': mapping(secs, va, size),
                                  'bytes': read(data, secs, va, size).hex()}
    return result


def scan_direct(data, text, target):
    """Every-byte E8/E9 signed-rel32 scan, including unaligned candidates."""
    rows = []
    first, end = text['offset'], text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        pos = first - 1
        while True:
            pos = data.find(bytes([opcode]), pos + 1, end - 4)
            if pos == -1:
                break
            va = text['address'] + pos - first
            delta = struct.unpack_from('<i', data, pos + 1)[0]
            if va + 5 + delta == target:
                rows.append({'site': va, 'file_offset': pos, 'kind': 'call' if opcode == 0xe8 else 'jmp',
                             'target': target, 'bytes': bytes(data[pos:pos + 5]).hex()})
    return sorted(rows, key=lambda r: r['site'])


def test_count():
    tree = ast.parse((ROOT / 'tests/test_node115_decimal_cursor.py').read_text(encoding='utf-8'))
    return sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in ast.walk(tree))


def inspect_static(data):
    """Narrow checks below the public digest gate, exposed for corruption tests."""
    secs = sections(data)
    texts = [s for s in secs if s['name'] == '.text']
    require(len(texts) == 1 and texts[0]['address'] == TEXT_START
            and texts[0]['size'] == TEXT_END - TEXT_START and texts[0]['flags'] & 4,
            'text section changed')
    text = texts[0]
    cies, fdes = eh_frame_records(data, secs)
    matches = [r for r in fdes if r['start'] <= START < r['end'] or r['start'] == START]
    require(matches == [FDE], 'selected FDE changed')
    for key, expected in FRAME_BYTES.items():
        require(read(data, secs, FDE[key], len(bytes.fromhex(expected))).hex() == expected,
                'selected frame bytes changed')
    body = read(data, secs, START, END - START)
    rows, graph, params = validate_body(body)
    next_start = min(r['start'] for r in fdes if r['start'] > START)
    pad = read(data, secs, END, next_start - END)
    require(next_start == 0x2e56540 and pad == b'\xcc' * 8, 'padding or following FDE changed')
    owner = [r for r in fdes if r['start'] == CALLER_FDE['start']]
    require(owner == [CALLER_FDE], 'caller FDE changed')
    raw = read(data, secs, CONTEXT_START, CONTEXT_END - CONTEXT_START)
    context = decode(raw, CONTEXT_START)
    calls = [r for r in context if r['mnemonic'] == 'call']
    require(len(calls) == 1 and calls[0]['va'] == CALL_SITE
            and calls[0]['operands'] == [{'target': START}], 'caller target changed')
    require([r['assembly'] for r in context] == CONTEXT_ASSEMBLY, 'caller argument/result context changed')
    callers = scan_direct(data, text, START)
    require([(r['site'], r['kind']) for r in callers] == [(CALL_SITE, 'call')], 'caller census changed')
    for row in callers:
        owners = [f for f in fdes if f['start'] <= row['site'] and row['site'] + 5 <= f['end']]
        require(owners == [CALLER_FDE], 'caller containment changed')
        row['owner_start'] = CALLER_FDE['start']
        row['local_decode_start'] = CONTEXT_START
    lea = decode(read(data, secs, LOCATION_SITE, 7), LOCATION_SITE)
    require(len(lea) == 1 and lea[0]['mnemonic'] == 'lea'
            and lea[0]['operands'][0] == {'reg': 'rdi', 'width': 64}
            and lea[0]['operands'][1] == {'base': 'rip', 'index': None, 'scale': 1,
                                         'disp': LOCATION_VA - LOCATION_SITE - 7, 'width': 64},
            'source Location reference changed')
    location = read(data, secs, LOCATION_VA, 24)
    require(location == struct.pack('<QQII', 0, PATH_SIZE, 88, 9), 'source Location changed')
    literal = read(data, secs, PATH_VA, PATH_SIZE)
    require(hashlib.sha256(literal).hexdigest() == PATH_SHA and literal.endswith(PATH_SUFFIX),
            'source path changed')
    rels = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(rels) == 1, 'source relocation section changed')
    rel = rels[0]
    found = []
    for offset in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot == LOCATION_VA:
            found.append({'file_offset': offset, 'slot': slot, 'info': info, 'addend': addend,
                          'bytes': bytes(data[offset:offset + 24]).hex()})
    require(len(found) == 1 and found[0]['info'] == 8 and found[0]['addend'] == PATH_VA,
            'source Location relocation changed')
    vectors = [{'case': label, 'buffer_hex': data_hex, 'cursor': cur, 'end': end,
                'rax': rax, 'cursor_after': after} for label, data_hex, cur, end, rax, after in VECTORS]
    require(all(model(bytes.fromhex(r['buffer_hex']), r['cursor'], r['end']) == (r['rax'], r['cursor_after'])
                for r in vectors), 'frozen vector disagreement')
    counts = {'body_bytes': len(body), 'instructions': len(rows), 'padding_bytes': len(pad),
              'callees': sum(r['mnemonic'] == 'call' for r in rows),
              'direct_call_sites': sum(r['kind'] == 'call' for r in callers),
              'direct_caller_owners': len({r['owner_start'] for r in callers}),
              'tail_jump_sites': sum(r['kind'] == 'jmp' for r in callers),
              'conditional_branches': sum(r['mnemonic'] in ('ja', 'jae') for r in rows),
              'returns': sum(r['mnemonic'] == 'ret' for r in rows),
              'cursor_stores': sum(r['mnemonic'] == 'mov' and 'base' in r['operands'][0] for r in rows),
              'frozen_vectors': len(vectors), 'text_bytes_scanned': text['size'], 'targeted_tests': test_count()}
    return {'task': 'RE-001', 'component_allocation': 'transport; RE-012 parsing dependency lead',
            'target': {'release': 115, 'sha256': SHA, 'size': SIZE}, 'source_commit': SOURCE_COMMIT,
            'question': 'What packed result and cursor mutation does this complete leaf compute from a bounded byte stream?',
            'window': {'start': START, 'end': END, 'file_offset': mapping(secs, START, len(body)),
                       'size': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(), 'body_bytes': body.hex(),
                       'frame': frame_record(data, secs, FDE), 'cie_decoded': cies[FDE['cie']],
                       'padding': {'start': END, 'end': next_start, 'bytes': pad.hex()}},
            'instructions': rows, 'control_flow': graph, 'parameters': params, 'callees': [],
            'rule': {'inputs': 'RDI points to state: end at +8, cursor at +16; state +0 unused',
                     'output': 'RAX=decimal_value<<16 after three digits; 0x30001 on exhaustion; 0x30002 on invalid byte',
                     'mutation': 'Store incremented cursor before each digit check; no rollback',
                     'preconditions': 'Readable state/buffer, writable cursor word, disjoint state and buffer, stable memory; no address wrap',
                     'admission': 'ASCII 0..9 at every position, including a leading zero; at most three bytes consumed'},
            'caller_scan': {'start': TEXT_START, 'end': TEXT_END,
                            'method': 'Every byte E8/E9 signed rel32; local context decoding, not whole-caller CFG',
                            'sites': callers, 'owners': [frame_record(data, secs, CALLER_FDE)],
                            'contexts': [{'start': CONTEXT_START, 'end': CONTEXT_END,
                                          'bytes': raw.hex(), 'instructions': context}]},
            'source_context': {'claim': 'Caller references vendored httparse Location; original symbol/version unproved',
                               'reference': lea[0], 'location_va': LOCATION_VA, 'location_bytes': location.hex(),
                               'path_va': PATH_VA, 'path_size': len(literal), 'path_sha256': hashlib.sha256(literal).hexdigest(),
                               'retained_path_suffix': PATH_SUFFIX.decode('ascii'), 'line': 88, 'column': 9,
                               'path_redaction': 'Build-machine prefix omitted; full original bytes checked by SHA-256',
                               'relocation': found[0]},
            'vectors': vectors, 'counts': counts,
            'non_claims': ['Original Rust symbol/type/ABI or httparse revision', 'Whole caller behavior or all indirect callers',
                           'HTTP status policy, delimiter parsing, streaming rollback or node protocol compatibility',
                           'Rust reconstruction, source-build equivalence, runtime differential testing or completion gate']}


def analyze(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'node #115 digest mismatch')
    return inspect_static(data)


def load_record(binary=TARGET):
    with Path(binary).open('rb') as handle:
        require(Path(binary).stat().st_size == SIZE, 'node #115 digest mismatch')
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return analyze(data)


def count_lines(record):
    return '\n'.join(f'- {key}: {value}' for key, value in sorted(record['counts'].items()))


def walk_text(record):
    parts = [f"node #115 SHA-256 {SHA}; ELF virtual addresses; no normalization"]
    for label, rows in [('complete leaf', record['instructions']),
                        ('local caller context', record['caller_scan']['contexts'][0]['instructions']),
                        ('caller source reference', [record['source_context']['reference']])]:
        parts.append('\n' + label)
        parts.extend(f"{r['va']:#x}  {r['bytes']:<24}  {r['assembly']}" for r in rows)
    return '\n'.join(parts) + '\n'


def readme_text(r):
    w, source = r['window'], r['source_context']
    return f'''# RE-001: node #115 consuming decimal cursor

- Component/task: RE-001 function map; transport dependency parsing lead for RE-012.
- Target: Linux x86-64 node #115, SHA-256 `{SHA}`.
- Source base: `{r['source_commit']}`. New rule/model/docs are independently authored under the root MIT license. Decoder, mapping and scan helpers adapt existing MIT repository code. No upstream source implementation or inferred unlicensed source is copied; no upstream revision is attributed.
- Bounded question: {r['question']}

**Answer.** With valid, stable, disjoint state and buffer memory, RDI points to a
state whose end pointer is at `+8` and cursor at `+16`. The leaf consumes a prefix
of up to three bytes. Each consumed byte advances the stored cursor before its
ASCII digit check. Exhaustion before three valid digits returns RAX `0x30001`;
the first non-digit returns `0x30002`, including that byte in consumption. Three
valid digits, including leading zeros, return their decimal value shifted left
by sixteen bits. Bytes after that prefix are untouched. No failure rolls back
the cursor. These are raw machine results, not recovered Rust enum names.

## Window, ownership and counts

All coordinates are original ELF VAs unless explicitly marked file offsets.
The complete window is `[{w['start']:#x}, {w['end']:#x})`, size
{w['size']} bytes, file offset `{w['file_offset']:#x}`. The FDE is at
VA/file offset `{w['frame']['fde']:#x}`, CIE `{w['frame']['cie']:#x}`,
with `zR` augmentation, PC-relative signed-word encoding and no LSDA.
The body SHA-256 is `{w['body_sha256']}`. Actual FDE extent, complete
instruction coverage, all branch destinations and returning paths agree.
The following `{w['padding']['bytes']}` padding occupies
`[{w['padding']['start']:#x}, {w['padding']['end']:#x})`; it is excluded from the body.
FDE bounds alone are not used as a whole-program function census.

Every reported count below is generated from `records.json` and checked by the
targeted tests. No component/function-coverage denominator is claimed.

<!-- counts:start -->
{count_lines(r)}
<!-- counts:end -->

The leaf has no CALL, external jump, indirect dispatch, RIP-relative data load,
or helper dependency. Its callee set is empty; callee identities/extents and
callee-target controls are therefore inapplicable. Incoming call displacement
corruption is tested instead. `instructions.txt` and the JSON retain every
instruction's raw bytes, decoded operands and address. The CFG covers the entire
body with no unexplained internal padding or unreachable instructions.

## Instruction proof

- Entry loads end into R8 and cursor into RDX. EAX initially holds `0x30001`.
  Unsigned `cursor >= end` returns it without reading a buffer byte or storing
  the cursor. An already exhausted cursor is allowed by this raw rule.
- At `0x2e564c2`, `0x2e564da` and `0x2e564f5`, MOVZX loads successive bytes.
  The stores at `0x2e564c9`, `0x2e564e2` and `0x2e564fe` write initial cursor
  plus one, two and three respectively, before validating the loaded byte.
  Bounds checks before the latter loads keep the incomplete return distinct
  from an invalid byte. State `+0` is never accessed.
- The first and last bytes add `0xd0` modulo the byte width, equal to subtraction
  of ASCII `0`. The middle byte uses LEA with `-0x30`, then compares its low byte.
  Unsigned `>9` or `>=10` rejects exactly the complement of ASCII `0` through `9`,
  including bytes below `0`, high bytes, signs, whitespace and NUL.
- On the valid path, `0x2e56514` multiplies the first digit by `100`. The middle
  byte remains its original ASCII value in SIL. MOVZX, doubling and LEA multiply
  it by `10`; `add cl,0x20; movzx ecx,cl` produces
  `(10*(48+d)+32) mod 256 = d*10` for every digit d. This byte truncation is
  essential to explaining the apparent ASCII rather than digit multiplication.
  The last digit is added, and SHL by `16` packs the decimal value in EAX.
  Its maximum is `999`, so neither the sum nor packing overflows the result word.
  All exits follow a write to EAX, establishing zero in RAX's upper half.

The independent `model()` implements decimal accumulation and cursor mutation.
`instruction_value()` separately expresses the decoded byte arithmetic and its
extracted constants. Frozen vectors and exhaustive valid decimal triples agree;
byte substitutions at every position check the full admission alphabet.
Real factor, admission and packing operand mutants change this relation before
the validator rejects them. These checks are static formulas, not target
execution, an emulator or a runtime differential test.

## Caller census and source evidence

The producer scans every possible byte position in full `.text`
`[{TEXT_START:#x}, {TEXT_END:#x})` for E8/E9 signed rel32 destinations equal
to the entry. It retains unaligned hits rather than assuming opcode alignment.
The sole hit is `CALL` at `{CALL_SITE:#x}`, in actual caller FDE
`[{CALLER_FDE['start']:#x}, {CALLER_FDE['end']:#x})`, FDE
`{CALLER_FDE['fde']:#x}`, CIE `{CALLER_FDE['cie']:#x}`. The retained local decode
from `{CONTEXT_START:#x}` passes a stack-state address in RDI, calls the leaf,
shifts the returned word right by `16` and compares AX with `2`.
This corroborates a packed value/status split. It does not recover the entire
caller CFG, prove entry reachability, or rule out indirect callers or references
outside `.text`. The census is complete for the stated byte-pattern scan only.

Inside that same caller FDE, LEA at `{LOCATION_SITE:#x}` addresses Location
`{LOCATION_VA:#x}`. Its actual R_X86_64_RELATIVE relocation targets
`{PATH_VA:#x}`; the metadata gives `{source['retained_path_suffix']}` at
line {source['line']}, column {source['column']}. The complete original path
bytes are authenticated by `{source['path_sha256']}`; its build-machine prefix
is omitted from committed prose/data. The raw Location and relocation are
retained. This supports a vendored httparse association, not first-party
Hyperliquid authorship or an exact dependency revision. The leaf itself has no
source Location. Small first-party-associated leads examined during discovery
were dispatchers or close variants of existing binds; this dependency parser
instead adds an unbound consumption/error contract useful to transport work.

## Novelty

Before creating this packet, these commands produced empty stdout and exit
status 1 for each search (no matches). There are no bound callee addresses.
The snapshot checked was the recorded source base plus the supplied PR lists;
this is not a claim about later upstream submissions.

```sh
rg -i '2e564b0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg '48587952' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'decimal-cursor|decimal_cursor' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The existing three-digit-decimal packet describes a different pointer/length
leaf that rejects leading zero and has no consuming cursor. It is background,
not evidence for this function's behavior. No existing work item/tool/test is
modified and no progress/catalogue/gate record is changed.

## Reproduce and validation

From repository root, with materialized authenticated inputs, Python 3.10+
stdlib and the existing ELF/FDE parsers:

```sh
python3 tools/node115_decimal_cursor.py --out {PACKET_REL}/
python3 -m unittest tests.test_node115_decimal_cursor -v
python3 {PACKET_REL}/verify.py
make verify
make catalogue-check
```

Development environment: Linux x86-64, Python 3.13.5. GNU objdump 2.44 was used
only for bounded exploratory inspection. The producer, verifier and tests never
import or invoke it. Their evidence comes from strict Python decoding. No
network, installation, captured executable, private fixture or emulator is used.
A single memory map avoids a second full binary copy. Public generation checks
the complete digest before parsing or output creation.

`verify.py` enforces an exact file/manifest whitelist, binds the tool, tests and
parsing dependencies, and compares regenerated payloads byte for byte. Controls
cover every body byte, malformed/truncated instructions, wrong digest, shifted
FDE/extent, CIE, padding, incoming call target, caller interpretation, Location
metadata/path/relocation, and extra/duplicate/missing/symlinked manifest files.
README metrics are checked against JSON and their underlying evidence arrays.
The producer, targeted tests, packet verifier, `make verify` and `make reproduce`
passed locally. `make catalogue-check` failed on pre-existing root README
work-item inventory drift, confirmed before this packet was tracked. Generated
files are unchanged under the add-only task constraint. Repository-wide
`make test` is intentionally omitted under the task's validation limit.

## Results, non-claims and next step

Before: no retained research or supplied PR-list reference to this entry.
After: a complete local value/consumption contract, caller census, extent and
source association can be regenerated from authenticated bytes. Verdict:
**strong for this bounded raw result and cursor contract**.

No original Rust function name/type/ABI, exact httparse version, HTTP status
policy, delimiter consumption, incremental-parser rollback, whole caller,
all-caller reachability, pointer safety or protocol compatibility is claimed.
Arbitrary invalid pointers, aliasing state/buffer, concurrent mutation and
wrapping pointer arithmetic are outside the stated memory contract. The leaf
is instruction-complete, while caller/source context is explicitly range-limited.

Rust implementation, Cargo closure, build flags, two-build comparison, normalized
source comparison, runtime differential evidence and whole-ELF equivalence are
not yet implemented/measured. Normalization masks: none. There is no local
helper/vtable/relocation dependency in the leaf; only the cited caller Location
relocation is bound, with all wider data/unwind/caller closure left open.
No full-scope gate is requested; reconstruction remains incomplete.

Next: bind the caller's handling of the returned status and saved cursor to
establish when incomplete parsing resumes or rolls back and what delimiter must
follow a successful decimal prefix.
'''


GENERATED = ('README.md', 'records.json', 'instructions.txt')
DEPENDENCIES = ('tools/node115_decimal_cursor.py', 'tests/test_node115_decimal_cursor.py',
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
