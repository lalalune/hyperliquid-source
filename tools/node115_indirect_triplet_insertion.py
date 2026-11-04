#!/usr/bin/env python3
"""Static RE-001 certificate for node #115's indirect triplet insertion leaf.

Python 3.10+ standard library only. No captured code, native disassembler,
emulator, network service or subprocess is invoked. New code is MIT.
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
SLUG = 'RE-001-node115-indirect-triplet-insertion'
PACKET = ROOT / 'research/work-items' / SLUG
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
BASE_REVISION = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END, NEXT = 0x26d4280, 0x26d4376, 0x26d4380
BODY_SHA = '96b785127b56f7b4af1568aa67d397f88564ace441aff825c905cbc1cfc44531'
FDE = {'fde': 0xd44330, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
FDE_HEX = '200000005cd4090048ff9801f600000000570e10410e188303860202da0e10410e08c3c6'
CIE_HEX = '1400000000000000017a5200017810011b0c070890010000'
CALLER = {'fde': 0x11b2110, 'cie': 0x103d604, 'start': 0x2e098e0,
          'end': 0x2e11140, 'lsda': 0x2879e8}
CALL_SITE = 0x2e10682
CONTEXT_START, CONTEXT_END = 0x2e1066e, 0x2e1068c
CONTEXT_HEX = '4883fe150f836c010000488d4c2450ba01000000e8f93b8cffe998efffff'
LOCATION_LEA, LOCATION = 0x2e0ab42, 0x6451b88
LOCATION_HEX = '00000000000000001b000000000000002602000011000000'
LOCATION_RELOC, PATH_VA = 0x77f58, 0x43e0ae
SOURCE_PATH = b'node/src/consensus/state.rs'
MASK64 = (1 << 64) - 1
MANIFEST_NAMES = (
    'README.md', 'records.json', 'verify.py',
    'tools/node115_indirect_triplet_insertion.py',
    'tests/test_node115_indirect_triplet_insertion.py',
    'tools/elf_index.py', 'tools/fde_extents.py',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


REGS = {
    64: ('rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15').split(),
    32: ('eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d').split(),
    8: ('al cl dl bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b').split(),
    128: [f'xmm{i}' for i in range(16)],
}
CONDITIONS = {2: 'b', 3: 'ae', 4: 'e', 5: 'ne', 12: 'l', 13: 'ge'}


def decode(code, base):
    """Decode the selected x86-64 vocabulary; unknown/truncated forms fail closed.

    ModRM, SIB, REX, signed displacements and relative destinations are decoded
    from bytes, including memory widths. This is deliberately not a general x86
    decoder. The sole legacy-prefix form admitted is the observed inert NOP.
    """
    rows, p = [], 0

    def read(n, signed=False):
        nonlocal p
        require(p + n <= len(code), 'Truncated instruction')
        value = int.from_bytes(code[p:p + n], 'little', signed=signed)
        p += n
        return value

    while p < len(code):
        begin = p
        target = rip_disp = None
        rex = 0
        if code[p:p + 10] == bytes.fromhex('662e0f1f840000000000'):
            p += 10
            mnemonic, operands = 'nop', []
        else:
            if 0x40 <= code[p] <= 0x4f:
                rex = read(1)
            op = read(1)
            width = 64 if rex & 8 else 32

            def reg(index, bits):
                require(bits != 8 or rex or index < 4,
                        'Legacy high byte registers are outside the decoder vocabulary')
                return REGS[bits][index]

            def modrm(bits):
                nonlocal rip_disp
                raw = read(1)
                mode, group, rm = raw >> 6, (raw >> 3) & 7, raw & 7
                register = reg(group + (8 if rex & 4 else 0), bits)
                if mode == 3:
                    return register, reg(rm + (8 if rex & 1 else 0), bits), group
                terms, disp = [], 0
                if rm == 4:
                    sib = read(1)
                    scale, index, basereg = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
                    if basereg == 5 and mode == 0:
                        disp = read(4, True)
                    else:
                        terms.append(REGS[64][basereg + (8 if rex & 1 else 0)])
                    if index != 4 or rex & 2:
                        terms.append(f'{REGS[64][index + (8 if rex & 2 else 0)]}*{scale}')
                elif rm == 5 and mode == 0:
                    terms.append('rip')
                    disp = read(4, True)
                    rip_disp = disp
                else:
                    terms.append(REGS[64][rm + (8 if rex & 1 else 0)])
                if mode in (1, 2):
                    disp = read(1 if mode == 1 else 4, True)
                address = '+'.join(terms)
                if disp or not address:
                    address += ('+' if address and disp >= 0 else '') + str(disp)
                return register, f'{bits}-bit [{address}]', group

            if op in (0xc3,):
                require(not rex, 'Unexpected RET prefix')
                mnemonic, operands = 'ret', []
            elif 0x50 <= op <= 0x5f:
                require(not rex or rex == 0x41, 'Unsupported PUSH/POP prefix')
                mnemonic = 'push' if op < 0x58 else 'pop'
                operands = [REGS[64][(op & 7) + (8 if rex & 1 else 0)]]
            elif op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
                require(not rex, 'Unexpected branch prefix')
                displacement = read(1 if op == 0xeb or op < 0x80 else 4, True)
                target = base + p + displacement
                if op in (0xe8, 0xe9, 0xeb):
                    mnemonic = 'call' if op == 0xe8 else 'jmp'
                else:
                    require((op & 15) in CONDITIONS, 'Unsupported condition')
                    mnemonic = 'j' + CONDITIONS[op & 15]
                operands = [hex(target)]
            elif 0xb8 <= op <= 0xbf:
                require(not rex or not rex & 6, 'Unsupported MOV immediate prefix')
                mnemonic = 'mov'
                operands = [reg((op & 7) + (8 if rex & 1 else 0), width),
                            str(read(width // 8))]
            elif op in (0x89, 0x8b, 0x8d, 0x01, 0x39, 0x3b, 0x84):
                bits = 8 if op == 0x84 else width
                register, rm, _ = modrm(bits)
                mnemonic = {0x89: 'mov', 0x8b: 'mov', 0x8d: 'lea',
                            0x01: 'add', 0x39: 'cmp', 0x3b: 'cmp', 0x84: 'test'}[op]
                if op == 0x8d:
                    require('[' in rm, 'LEA requires memory addressing')
                    rm = rm.split(' ', 1)[1]
                operands = [register, rm] if op in (0x8b, 0x8d, 0x3b) else [rm, register]
            elif op in (0x83, 0xc1):
                _, rm, group = modrm(width)
                if op == 0xc1:
                    require(group == 4, 'Unsupported shift operation')
                    mnemonic, immediate = 'shl', read(1)
                else:
                    require(group in (0, 7), 'Unsupported immediate arithmetic')
                    mnemonic, immediate = ('add' if group == 0 else 'cmp'), read(1, True)
                operands = [rm, str(immediate)]
            elif op == 0x0f:
                second = read(1)
                if second == 0x0b:
                    require(not rex, 'Unexpected UD2 prefix')
                    mnemonic, operands = 'ud2', []
                elif 0x80 <= second <= 0x8f:
                    require(not rex and (second & 15) in CONDITIONS, 'Unsupported near condition')
                    displacement = read(4, True)
                    target = base + p + displacement
                    mnemonic, operands = 'j' + CONDITIONS[second & 15], [hex(target)]
                elif 0x90 <= second <= 0x9f:
                    require(not rex & 12 and (second & 15) in CONDITIONS, 'Unsupported SETcc form')
                    _, rm, group = modrm(8)
                    require(group == 0, 'Unsupported SETcc extension')
                    mnemonic, operands = 'set' + CONDITIONS[second & 15], [rm]
                elif second in (0x10, 0x11):
                    require(not rex & 8, 'Unexpected MOVUPS width prefix')
                    register, rm, _ = modrm(128)
                    mnemonic = 'movups'
                    operands = [register, rm] if second == 0x10 else [rm, register]
                else:
                    raise ValueError(f'Unsupported 0F opcode at {base + begin:#x}')
            else:
                raise ValueError(f'Unsupported opcode at {base + begin:#x}')
        row = {'va': base + begin, 'bytes': code[begin:p].hex(),
               'mnemonic': mnemonic, 'operands': operands}
        if target is not None:
            row['target'] = target
        if rip_disp is not None:
            row['rip_target'] = base + p + rip_disp
        rows.append(row)
    return rows


def control_flow(rows):
    by_va = {r['va']: r for r in rows}
    require(len(by_va) == len(rows) and rows[0]['va'] == START, 'Bad instruction geometry')
    successors = {}
    for row in rows:
        op, at = row['mnemonic'], row['va']
        following = at + len(bytes.fromhex(row['bytes']))
        require(op != 'call', 'Unexpected callee in leaf')
        if op in ('ret', 'ud2'):
            edges = []
        elif op == 'jmp':
            edges = [row['target']]
        elif op.startswith('j'):
            edges = [row['target'], following]
        else:
            edges = [following]
        require(all(e in by_va for e in edges), 'Branch/fallthrough outside instruction boundaries')
        successors[at] = edges
    seen, pending = set(), [START]
    while pending:
        at = pending.pop()
        if at not in seen:
            seen.add(at)
            pending.extend(successors[at])
    return {'edges': [{'from': a, 'to': successors[a]} for a in sorted(successors)],
            'unreachable': sorted(set(by_va) - seen),
            'terminals': [{'va': r['va'], 'kind': r['mnemonic']}
                          for r in rows if r['mnemonic'] in ('ret', 'ud2')]}


def comparison_conditions(rows):
    """Extract both actual comparison sites, also used by operand counterfacts."""
    indexed = {r['va']: r for r in rows}
    return [[indexed[a]['mnemonic'] for a in group] for group in (
        (0x26d42d6, 0x26d42e4, 0x26d42f2),
        (0x26d434f, 0x26d435b, 0x26d4367))]


def entry_action(length, start):
    require(type(length) is int and type(start) is int and
            0 <= length <= MASK64 and 0 <= start <= MASK64, 'Expected unsigned word arguments')
    if ((start - 1) & MASK64) >= length:
        return 'ud2'
    return 'return' if start == length else 'insert'


def key_value(words):
    require(len(words) == 3 and all(type(w) is int and 0 <= w < 1 << 32 for w in words),
            'Expected three raw u32 key words')
    first, second, third = words
    return (first - (1 << 32) if first & (1 << 31) else first, second, third)


def insertion_order(keys, start):
    """Independent value-level model; returns original record indices, not a CPU trace."""
    if entry_action(len(keys), start) == 'ud2':
        raise ValueError('UD2 entry guard')
    values = [key_value(k) for k in keys]
    order = list(range(len(keys)))
    for i in range(start, len(order)):
        current = order[i]
        hole = i
        while hole and values[current] < values[order[hole - 1]]:
            order[hole] = order[hole - 1]
            hole -= 1
        order[hole] = current
    return order


def vectors():
    # Frozen from the decoded strict/signed/unsigned decisions, never from model output.
    cases = [
        ('empty-trap', [], 0, 'ud2'),
        ('zero-start-trap', [(0, 0, 0)], 0, 'ud2'),
        ('past-end-trap', [(0, 0, 0)], 2, 'ud2'),
        ('singleton', [(0, 0, 0)], 1, [0]),
        ('end-is-noop', [(2, 0, 0), (1, 0, 0)], 2, [0, 1]),
        ('signed-min-first', [(0, 0, 0), (0x80000000, 0, 0)], 1, [1, 0]),
        ('signed-minus-one', [(0x7fffffff, 0, 0), (0xffffffff, 0, 0)], 1, [1, 0]),
        ('signed-negative-order', [(0xffffffff, 0, 0), (0x80000000, 0, 0)], 1, [1, 0]),
        ('unsigned-second', [(0, 0xffffffff, 0), (0, 0, 0)], 1, [1, 0]),
        ('unsigned-second-sign-boundary', [(0, 0x80000000, 0), (0, 0x7fffffff, 0)], 1, [1, 0]),
        ('unsigned-third', [(0, 0, 0xffffffff), (0, 0, 0)], 1, [1, 0]),
        ('unsigned-third-sign-boundary', [(0, 0, 0x80000000), (0, 0, 0x7fffffff)], 1, [1, 0]),
        ('first-dominates', [(0, 0, 0), (0xffffffff, 0xffffffff, 0xffffffff)], 1, [1, 0]),
        ('second-dominates', [(0, 1, 0), (0, 0, 0xffffffff)], 1, [1, 0]),
        ('all-equal-stable', [(7, 8, 9)] * 4, 1, [0, 1, 2, 3]),
        ('duplicates-shift-stably', [(2, 0, 0), (1, 0, 0), (2, 0, 0), (1, 0, 0)], 1, [1, 3, 0, 2]),
        ('reverse-through-left-edge', [(3, 0, 0), (2, 0, 0), (1, 0, 0), (0, 0, 0)], 1, [3, 2, 1, 0]),
        ('insert-middle', [(0, 0, 0), (2, 0, 0), (1, 0, 0)], 2, [0, 2, 1]),
        ('no-suffix-movement', [(0, 0, 0), (1, 0, 0), (2, 0, 0)], 1, [0, 1, 2]),
        ('prefix-precondition-matters', [(2, 0, 0), (1, 0, 0), (3, 0, 0)], 2, [0, 1, 2]),
        ('unsorted-prefix-insertion', [(3, 0, 0), (1, 0, 0), (0, 0, 0)], 2, [2, 0, 1]),
        ('inner-signed-comparison', [(0, 0, 0), (1, 0, 0), (0x80000000, 0, 0)], 2, [2, 0, 1]),
        ('inner-unsigned-second', [(0, 0x80000000, 0), (0, 0xffffffff, 0), (0, 1, 0)], 2, [2, 0, 1]),
        ('inner-unsigned-third', [(0, 0, 0x80000000), (0, 0, 0xffffffff), (0, 0, 1)], 2, [2, 0, 1]),
        ('inner-equality-stops', [(1, 2, 3), (2, 0, 0), (1, 2, 3)], 2, [0, 2, 1]),
    ]
    return [{'name': name, 'keys': [list(k) for k in keys], 'start_index': start,
             'expected': expected} for name, keys, start, expected in cases]


def section_map(data):
    rows = sections(data)
    require(len({s['name'] for s in rows}) == len(rows), 'Duplicate section name')
    mapped = {s['name']: s for s in rows}
    for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn', '.rodata', '.data.rel.ro'):
        require(name in mapped and mapped[name]['type'] != 8, f'Missing required section {name}')
    text = mapped['.text']
    require((text['address'], text['offset'], text['size'], text['flags']) ==
            (0x1419300, 0x1418300, 0x4fd7700, 6), 'Changed .text geometry or flags')
    return rows, mapped


def file_offset(sections_, va, size):
    matches = [s for s in sections_ if s['type'] != 8 and s['address'] <= va and
               va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'Ambiguous or missing VA mapping')
    s = matches[0]
    return s['offset'] + va - s['address']


def frame_record(data, secs, va):
    p = file_offset(secs, va, 4)
    length = struct.unpack_from('<I', data, p)[0] + 4
    require(8 <= length <= 4096, 'Unexpected selected frame size')
    file_offset(secs, va, length)
    return {'va': va, 'file_offset': p, 'bytes': data[p:p + length].hex()}


def scan_rel32(data, text_offset, text_va, text_size, target):
    """All byte positions, including overlapping encodings and the last legal start."""
    matches = []
    limit = text_offset + text_size
    for opcode, kind in ((b'\xe8', 'call'), (b'\xe9', 'jmp')):
        p = text_offset
        while p <= limit - 5:
            p = data.find(opcode, p, limit - 4)
            if p < 0:
                break
            site = text_va + p - text_offset
            destination = site + 5 + struct.unpack_from('<i', data, p + 1)[0]
            if destination == target:
                matches.append({'site': site, 'kind': kind, 'target': target,
                                'bytes': data[p:p + 5].hex()})
            p += 1
    return sorted(matches, key=lambda r: r['site'])


def _analyze(data):
    """Below-identity static obligations; private entry for corruption controls."""
    secs, by_name = section_map(data)
    cies, fdes = eh_frame_records(data, secs)
    overlaps = [f for f in fdes if f['start'] < END and f['end'] > START]
    require(overlaps == [FDE], 'Selected FDE extent/identity changed or overlaps another FDE')
    require([f for f in fdes if f['start'] == CALLER['start']] == [CALLER], 'Caller FDE changed')
    require(min(f['start'] for f in fdes if f['start'] > START) == NEXT, 'Next FDE changed')
    fde, cie = (frame_record(data, secs, FDE[k]) for k in ('fde', 'cie'))
    require(fde['bytes'] == FDE_HEX and cie['bytes'] == CIE_HEX, 'Selected FDE/CIE bytes changed')
    header = by_name['.eh_frame_hdr']
    hp = header['offset']
    require(data[hp:hp + 4] == bytes([1, 0x1b, 3, 0x3b]), 'Changed unwind-header encodings')
    count = struct.unpack_from('<I', data, hp + 8)[0]
    require(12 + 8 * count <= header['size'], 'Truncated unwind header')
    selected_index = []
    for i in range(count):
        a, f = struct.unpack_from('<ii', data, hp + 12 + 8 * i)
        if header['address'] + a == START:
            require(header['address'] + f == FDE['fde'], 'Unwind header disagrees with FDE')
            selected_index.append({'index': i, 'file_offset': hp + 12 + 8 * i,
                                   'bytes': data[hp + 12 + 8 * i:hp + 20 + 8 * i].hex()})
    require(len(selected_index) == 1, 'Missing/duplicate selected unwind index')

    offset = file_offset(secs, START, END - START)
    body = data[offset:offset + END - START]
    instructions = decode(body, START)
    graph = control_flow(instructions)
    require(comparison_conditions(instructions) ==
            [['setl', 'setb', 'jae'], ['setl', 'setb', 'jb']], 'Changed comparison conditions')
    require(digest(body) == BODY_SHA, 'Function body SHA-256 mismatch')
    require(graph['unreachable'] == [0x26d42f6], 'Unexpected unreachable instruction')
    padding_offset = file_offset(secs, END, NEXT - END)
    padding = data[padding_offset:padding_offset + NEXT - END]
    require(padding == b'\xcc' * (NEXT - END), 'Changed post-FDE padding')

    cp = file_offset(secs, CONTEXT_START, CONTEXT_END - CONTEXT_START)
    context_bytes = data[cp:cp + CONTEXT_END - CONTEXT_START]
    context = decode(context_bytes, CONTEXT_START)
    calls = [r for r in context if r['mnemonic'] == 'call']
    require(len(calls) == 1 and calls[0]['va'] == CALL_SITE and calls[0]['target'] == START,
            'Caller target changed')
    require(context_bytes.hex() == CONTEXT_HEX, 'Caller setup/continuation changed')

    lp = file_offset(secs, LOCATION_LEA, 7)
    location_instruction = decode(data[lp:lp + 7], LOCATION_LEA)
    require(location_instruction == [{'va': LOCATION_LEA, 'bytes': '488d0d3f706403',
            'mnemonic': 'lea', 'operands': ['rcx', '[rip+56913983]'], 'rip_target': LOCATION}],
            'First-party Location LEA changed')
    locp = file_offset(secs, LOCATION, 24)
    require(data[locp:locp + 24].hex() == LOCATION_HEX, 'First-party Location metadata changed')
    rela = by_name['.rela.dyn']
    require(rela['size'] % 24 == 0, 'Truncated relocations')
    bindings = []
    for p in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, p)
        if slot == LOCATION:
            bindings.append((p, info, addend))
    require(bindings == [(LOCATION_RELOC, 8, PATH_VA)], 'First-party Location relocation changed')
    pathp = file_offset(secs, PATH_VA, len(SOURCE_PATH))
    require(data[pathp:pathp + len(SOURCE_PATH)] == SOURCE_PATH, 'First-party path changed')

    text = by_name['.text']
    incoming = scan_rel32(data, text['offset'], text['address'], text['size'], START)
    require(incoming == [{'site': CALL_SITE, 'kind': 'call', 'target': START, 'bytes': 'e8f93b8cff'}],
            'Changed full .text direct-reference census')
    ordered_fdes = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered_fdes]
    for row in incoming:
        owner = ordered_fdes[bisect.bisect_right(starts, row['site']) - 1]
        require(owner == CALLER and row['site'] + 5 <= owner['end'], 'Ambiguous caller ownership')
        require([f for f in fdes if f['start'] <= row['site'] < f['end']] == [CALLER],
                'Overlapping caller FDEs')
        row['owner'] = owner
        row['instruction_boundary_evidence'] = 'decoded-caller-context'
    return {
        'target': {'release': 115, 'sha256': SHA, 'size': SIZE},
        'function': {'start': START, 'end': END, 'size': len(body), 'file_offset': offset,
                     'body_sha256': digest(body), 'bytes': body.hex(), 'fde': FDE,
                     'fde_record': fde, 'cie_record': cie, 'cie_decoded': cies[FDE['cie']],
                     'unwind_index': selected_index[0], 'instructions': instructions,
                     'control_flow': graph, 'callees': [], 'indirect_transfers': [],
                     'post_fde_padding': {'start': END, 'end': NEXT, 'bytes': padding.hex()},
                     'internal_padding': [{'start': 0x26d42f6, 'end': 0x26d4300,
                                           'bytes': body[0x76:0x80].hex(), 'reachable': False}]},
        'direct_references': {'scan': {'start': text['address'], 'end': text['address'] + text['size'],
                                     'file_offset': text['offset'], 'opcodes': ['e8', 'e9'],
                                     'stride': 1, 'normalization_masks': []}, 'matches': incoming},
        'caller_context': {'fde': CALLER, 'fde_record': frame_record(data, secs, CALLER['fde']),
                           'cie_record': frame_record(data, secs, CALLER['cie']),
                           'start': CONTEXT_START, 'end': CONTEXT_END, 'instructions': context,
                           'source_association': {
                               'instruction': location_instruction[0], 'location_va': LOCATION,
                               'location_file_offset': locp, 'location_bytes': LOCATION_HEX,
                               'relocation_file_offset': LOCATION_RELOC,
                               'relocation_bytes': data[LOCATION_RELOC:LOCATION_RELOC + 24].hex(),
                               'relocation_type': 'R_X86_64_RELATIVE', 'path_va': PATH_VA,
                               'path_file_offset': pathp, 'path': SOURCE_PATH.decode('ascii'),
                               'path_length': len(SOURCE_PATH), 'line': 550, 'column': 17}},
        'rule': {'entry_registers': {'rdi': 'record base', 'rsi': 'record count', 'rdx': 'first insertion index'},
                 'row_bytes': 16, 'payload_offset': 0, 'key_pointer_offset': 8,
                 'key_word_offsets': [0, 4, 8], 'key_word_bits': [32, 32, 32],
                 'key_order': ['signed', 'unsigned', 'unsigned'],
                 'comparison_conditions': comparison_conditions(instructions),
                 'entry_trap': '((start_index - 1) mod 2^64) >= count',
                 'early_return': 'start_index == count, after the trap check',
                 'normal_effect': 'stable insertion of suffix records into the preceding prefix',
                 'sorted_result_precondition': 'the initial prefix is sorted under the same key order',
                 'caller_start_index': 1, 'caller_count_exclusive_bound': 21,
                 'return_register_observations': {'early_return_rax': 'k - 1',
                                                  'insertion_return_rax': 'base + 16*n'},
                 'scalar_return_contract': None},
        'vectors': vectors(),
    }


def analyze(data):
    require(len(data) == SIZE and digest(data) == SHA, 'Node #115 size/SHA-256 mismatch')
    return _analyze(data)


def analyze_path(binary=TARGET):
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'Node #115 size/SHA-256 mismatch')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return analyze(data)


def metrics(record):
    f = record['function']
    return {
        'Bound function bodies': len([f]),
        'Function bytes (including internal NOP)': f['size'],
        'Decoded function instructions (including internal NOP)': len(f['instructions']),
        'Reachable function instructions': len(f['instructions']) - len(f['control_flow']['unreachable']),
        'Internal unreachable NOP bytes': sum(p['end'] - p['start'] for p in f['internal_padding']),
        'Post-FDE INT3 bytes (excluded from body)': f['post_fde_padding']['end'] - f['post_fde_padding']['start'],
        'Callees': len(f['callees']),
        'Indirect transfers': len(f['indirect_transfers']),
        'Raw full-text E8/E9 matches': len(record['direct_references']['matches']),
        'Distinct direct caller FDEs': len({r['owner']['start'] for r in record['direct_references']['matches']}),
        'Frozen semantic vectors': len(record['vectors']),
    }


def readme(record):
    f, rule = record['function'], record['rule']
    metric_rows = '\n'.join(f'| {name} | {value} |' for name, value in metrics(record).items())
    walk = '\n'.join(f"{r['va']:08x}  {r['bytes']:<22} {r['mnemonic']} {', '.join(r['operands'])}".rstrip()
                     for r in f['instructions'])
    return f'''# RE-001: indirect triplet insertion at {START:#x}

- Component: foundation function mapping, with a direct consensus-state caller (RE-008 context).
- Target: node #115, SHA-256 `{SHA}`.
- Repository/reference revision: `{BASE_REVISION}`. No external implementation source is used.
- Status: bytes, extents, transfers and key comparisons are observations; insertion-sort role and argument names are inferences proved below. Original Rust names/types remain unresolved.
- Bounded question: what does this complete leaf compute, including its entry guard, record movement, signedness and ties?

Given RDI pointing to writable records, RSI = n and RDX = k, the leaf traps with
UD2 unless `1 <= k <= n`; at `k == n` it returns without reading the records.
Otherwise it performs stable insertion of each record in the suffix beginning
at k into the preceding prefix. Each record consists of a payload word and a
key pointer. Keys compare lexicographically as `(i32, u32, u32)` loaded from
that pointer. Both words of each moved record are preserved, equal keys do not
cross, and an initially sorted prefix yields a fully sorted result. No scalar
return value is assigned a meaning. This is a complete local memory-transform
contract under the memory preconditions below, not a recovered consensus policy.

## Scope and measurements

All addresses are original ELF virtual addresses; ranges are half-open.
The selected window is `[{START:#x}, {END:#x})`, file offset `{f['file_offset']:#x}`.
Actual FDE `{FDE['fde']:#x}` (same file offset) references CIE `{FDE['cie']:#x}`;
the CIE uses zR/pcrel-sdata4 and the FDE has no LSDA. The selected unwind-header
entry independently points to that FDE. The FDE, terminal RET/UD2, internal
branch boundaries and following INT3 fill jointly support this body extent;
the start table alone is not the boundary argument.

Body SHA-256: `{f['body_sha256']}`. Raw instruction, FDE and CIE bytes are in
`records.json`. Internal `0x26d42f6..0x26d4300` is an unreachable decoded NOP;
`{END:#x}..{NEXT:#x}` is INT3 padding outside the body, up to the next FDE.

<!-- metrics derived from records.json; checked by the targeted tests -->
| Measurement | Count |
| --- | ---: |
{metric_rows}
<!-- end metrics -->

The leaf's callee list is empty: there is no call, tail transfer, indirect
dispatch, RIP data access, allocation or external arithmetic helper to close.
All branches stay within the decoded body. Stack PUSH/POP saves RBX/RBP on the
insertion route; the early return and entry trap precede those saves.

## Rule proof from the instruction walk

`0x26d4280..0x26d4296` forms `(k-1) mod 2^64`, compares it unsigned to n, and
branches to UD2 on greater-or-equal. Thus zero k traps even for maximum n;
k greater than n also traps. Equality k=n is tested only after this guard.
No object/key memory is read on either of these entry exits. On the early
return, RAX retains `k-1`; after a completed insertion route it equals the
computed end pointer `base + 16*n`. These are observed register residues,
not an inferred Rust return type.

The shifts at `0x26d4298` and `0x26d429f` multiply the count and index by the
record width `{rule['row_bytes']}`. RAX becomes the current record pointer and
RSI the end pointer; RDX is the previous-record byte offset. The initial
comparison loads the previous key pointer at current-minus-{rule['key_pointer_offset']}
and the current key pointer at current-plus-{rule['key_pointer_offset']}.
The key loads at offsets `{rule['key_word_offsets']}` have widths
`{rule['key_word_bits']}`. SETL at `0x26d42d6` and `0x26d434f` implements signed
comparison of the first word. SETB at `0x26d42e4` and `0x26d435b` implements
unsigned comparison of the second. The first unequal word decides; when both
tie, JAE at `0x26d42f2` skips movement for unsigned greater-or-equal third words,
and JB at `0x26d4367` continues shifting only for unsigned strictly smaller ones.
SETcc does not overwrite comparison flags, so the following JNE still tests
the associated CMP equality, not the SETcc result.

When a record belongs earlier, `0x26d4305..0x26d4313` saves its payload in R8
and retains its key pointer in RCX, then copies the preceding entire record
rightward using MOVUPS. R9 tracks the hole, R11 the hole's byte offset, and
R10 the eventual store address. The inner loop compares the saved key against
the record before the hole and shifts that record only when the saved key is
strictly smaller. At the left edge it stores at the base; otherwise it stores
at the first hole whose predecessor is less-or-equal. `0x26d42b0..0x26d42b7`
restores both saved words. The outer step advances the current position and
previous-record offset equally, stopping at the end pointer.

Invariant: processed records are a permutation of their initial records, with
the current record temporarily held in R8/RCX during shifts. With an initially
sorted prefix, each insertion preserves prefix order. The inner hole moves
strictly toward the base and the outer cursor moves strictly toward the end,
so valid finite input terminates. Strict comparisons preserve equal-key order.
An unsorted initial prefix is not promised to become sorted; frozen vectors
explicitly retain that distinction. The model is an independent value-level
Python implementation, not execution or emulation of captured instructions.

Required memory assumptions: the record range is writable, its keys are
readable for the complete key width, key storage stays unchanged by row
movement, stack storage is valid and disjoint, and shifted sizes/pointer
arithmetic do not wrap or leave the allocation. Key pointers may be shared
when their pointees remain immutable. Invalid addresses, concurrent mutation,
hardware exceptions during memory access and writable-key aliasing are outside
this normal-transform contract. Guard behavior itself needs no record memory.

### Complete byte-decoded walk

```text
{walk}
```

## Caller census and first-party association

The producer scans every possible byte start of E8/E9 rel32 encodings in
`.text [0x1419300, 0x63f0a00)`, including overlapping candidates. The only hit is
CALL `{CALL_SITE:#x}` in actual FDE `0x2e098e0..0x2e11140`. The selected context
`{CONTEXT_START:#x}..{CONTEXT_END:#x}` decodes the call and its immediate setup:
the fallthrough branch requires `n < {rule['caller_count_exclusive_bound']}`,
and EDX is `{rule['caller_start_index']}`. This establishes a use of the leaf
as a small-range sort, conditional on reaching that block with valid memory;
the whole caller's reachability and collection identity are not proved.

In the same caller FDE, LEA `{LOCATION_LEA:#x}` names Location `{LOCATION:#x}`.
Its checked R_X86_64_RELATIVE relocation at file offset `{LOCATION_RELOC:#x}`
names `{SOURCE_PATH.decode()}:550:17`; pointer, length, line, column and literal
bytes are regenerated. This is direct first-party caller evidence, not an
original symbol or proof that the leaf was authored in that source file.
No behavior is bound for the caller's other callees. The caller FDE/CIE bytes
are retained only to support ownership of these selected sites.

The raw scan is not a whole-text instruction decoder. Its hit is corroborated
by the strict caller-context decode and by exploratory GNU decoding from the
caller's FDE entry. No additional raw hit was discarded. Address-taken uses,
indirect callers, alternate entrypoints, short branches into the body and
references outside .text are not covered by this direct-reference census.

## Novelty before packet creation

At the repository/reference revision above, each command below produced empty
stdout and exit status 1 (no matches). The hexadecimal and decimal checks cover
the function start; there are no behavior-bound callees to check. These are
historical pre-addition observations, not commands expected to stay empty after
this packet is added. PR lists are the provided local snapshots, not live data.

```sh
rg -i '26d4280' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '40714880' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'indirect-triplet-insertion|indirect_triplet_insertion' research/work-items/ tools/ tests/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Reproduce and controls

From the repository root, with the authenticated artifact materialized:

```sh
python3 tools/node115_indirect_triplet_insertion.py --out research/work-items/{SLUG}/
python3 -m unittest tests.test_node115_indirect_triplet_insertion -v
python3 research/work-items/{SLUG}/verify.py
make verify
make catalogue-check
```

Python 3.10+ standard library is sufficient; local validation used Python 3.13.5
on Linux x86-64. The narrow instruction decoder, selected FDE checks, source
relocation and full-text scan use bytes only. Existing `elf_index.py` and
`fde_extents.py` supply section/FDE parsing and are included in the manifest.
Exploration used GNU objdump 2.44 with `-d -Mintel --insn-width=16` and bounded
`--start-address`/`--stop-address` for the selected and caller FDEs; its transient
output is under ignored work/. Producer, verifier and tests never invoke it.

The producer authenticates size and the full target digest before parsing or
creating output. It memory-maps the binary, materializing only small evidence
windows. It regenerates `records.json` and this README from authenticated bytes
and independently authored rule/proof text; it copies the verifier source and
hashes exactly its named source/evidence dependencies into MANIFEST.sha256.
The verifier rejects missing, extra, duplicate, changed or symlinked whitelist
entries, then requires byte-identical regeneration of JSON and README.

Controls exercise wrong identity, actual instruction and signedness changes,
shifted FDE, CIE corruption, wrong incoming call destination, changed padding,
source Location/relocation corruption, section geometry and scanner boundaries.
All binary mutations are private static mappings; none is executed. Frozen
vectors cover entry traps, signed/unsigned extremes, each tie-break, left-edge
and inner-loop shifts, equality stability and the sorted-prefix precondition.
Additional independent Python sorting checks exercise the model, not the node.
README measurement counts are computed from JSON and checked against that JSON.

## Results, non-claims and next step

Before this packet, the selected function had no binding in the checked research
tree or provided PR-title snapshots. This packet closes its complete local
record-movement rule, the mixed signedness and tie handling, and entry trap.
The required targeted checks are recorded in the accompanying submission body;
no repository-wide test completion, hosted CI or container result is claimed.

No Rust implementation, compiled comparison, normalization mask, original
function/type name, original crate ownership, consensus policy, whole-caller
contract, full ABI recovery, runtime differential result or whole-ELF identity
is claimed. The abstract Python model is not reconstruction credit. No progress
gate is requested or changed. Source pins and imported evidence are untouched.
The leaf has no static-data/callee closure gap; broader caller, allocation,
key-layout provenance and integration gaps remain outside its bounded contract.

Next question: trace the caller's record construction and key-pointer provenance
to assign meanings to the key words, and prove the caller's positive-length and
valid-memory conditions before using this ordering in reconstructed consensus.
'''.encode('utf-8')


def manifest_bytes(output):
    rows = []
    for name in MANIFEST_NAMES:
        path = output / name if '/' not in name else ROOT / name
        require(path.is_file() and not path.is_symlink(), f'Missing/unsafe manifest source: {name}')
        rows.append(f'{digest(path.read_bytes())}  {name}\n')
    return ''.join(rows).encode('ascii')


def generate(binary, output):
    record = analyze_path(binary)
    verifier = (PACKET / 'verify.py').read_bytes()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'records.json').write_bytes(json_bytes(record))
    (output / 'README.md').write_bytes(readme(record))
    (output / 'verify.py').write_bytes(verifier)
    (output / 'MANIFEST.sha256').write_bytes(manifest_bytes(output))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record = generate(args.binary, args.out)
    print(json.dumps(metrics(record), indent=2))


if __name__ == '__main__':
    main()
