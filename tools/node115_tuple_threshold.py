#!/usr/bin/env python3
"""Bind node #115's tuple-gated saturating threshold using static bytes only (MIT)."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-tuple-threshold'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x2c6f290, 0x2c6f2f4
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
U64 = (1 << 64) - 1
BODY_SHA = 'c7eae84020e629ae599eb400ad0d31b78d3a037651d47d2cdc3ce4a83995acf0'
CALL_SITES = (0x22e5bbb, 0x22e60d0, 0x2894df8, 0x289566d)
# These contexts are independently decoded; their containing functions are not bound.
CONTEXTS = ((0x22e5bb6, 0x22e5bc4), (0x22e60cd, 0x22e60d9),
            (0x2894df3, 0x2894e01), (0x289566a, 0x2895672))
SOURCE_CALLER = 0x28946b0
SOURCE_LEA = 0x2894cd0
LOCATION = 0x64768a8
EXPECTED_FDE = {'fde': 0xd86a0c, 'cie': 0xca6ed8,
                'start': START, 'end': END, 'lsda': None}
DEPENDENCIES = ('../../../tools/node115_tuple_threshold.py',
                '../../../tests/test_node115_tuple_threshold.py',
                '../../../tools/elf_index.py', '../../../tools/fde_extents.py')
PACKET_FILES = ('README.md', 'records.json', 'verify.py')


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_offset(secs, va, size):
    demand(size > 0, 'Empty VA read')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    demand(len(matches) == 1, 'Ambiguous or missing VA mapping')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size):
    off = file_offset(secs, va, size)
    result = data[off:off + size]
    demand(len(result) == size, 'Truncated VA read')
    return result


# A deliberately small, strict x86-64 decoder. Unsupported encodings, prefixes,
# ModRM/SIB values and truncated operands fail; no byte skipping or native tool.
# Operands are decoded from bytes, not looked up by instruction address.
def decode(code, start):
    rows, pos = [], 0
    conditions = {2: 'b', 3: 'ae', 4: 'e', 5: 'ne', 12: 'l', 13: 'ge'}
    while pos < len(code):
        p, fields = pos, {}

        def take(n):
            nonlocal pos
            demand(pos + n <= len(code), 'Truncated instruction')
            value = code[pos:pos + n]
            pos += n
            return value

        def imm(n, signed=False):
            return int.from_bytes(take(n), 'little', signed=signed)

        def mem(reg, width, displacement):
            return f'mem{width}[{reg}+{displacement:#x}]'

        op = take(1)[0]
        if op == 0x8b:
            modrm = take(1)[0]
            demand(modrm == 0x47, 'Unsupported MOV ModRM')
            d = imm(1, True)
            mnemonic, operands = 'mov', ['eax', mem('rdi', 32, d)]
            fields = {'width': 32, 'displacement': d}
        elif op == 0x3b:
            demand(take(1) == b'\x87', 'Unsupported CMP ModRM')
            d = imm(4, True)
            mnemonic, operands = 'cmp', ['eax', mem('rdi', 32, d)]
            fields = {'width': 32, 'displacement': d}
        elif op == 0x0f:
            cc = take(1)[0] - 0x90
            demand(cc in conditions and take(1) == b'\xc0', 'Unsupported SETcc')
            mnemonic, operands = 'set' + conditions[cc], ['al']
        elif 0x70 <= op <= 0x7f or op == 0xeb:
            cc = op - 0x70
            demand(op == 0xeb or cc in conditions, 'Unsupported short condition')
            d = imm(1, True)
            target = start + pos + d
            mnemonic = 'jmp' if op == 0xeb else 'j' + conditions[cc]
            operands, fields = [hex(target)], {'target': target}
        elif op in (0xe8, 0xe9):
            d = imm(4, True)
            target = start + pos + d
            mnemonic = 'call' if op == 0xe8 else 'jmp'
            operands, fields = [hex(target)], {'target': target}
        elif op == 0x84:
            demand(take(1) == b'\xc0', 'Unsupported TEST ModRM')
            mnemonic, operands = 'test', ['al', 'al']
        elif op in (0xb0, 0x3c):
            n = imm(1)
            mnemonic = 'mov' if op == 0xb0 else 'cmp'
            operands, fields = ['al', hex(n)], {'immediate': n, 'width': 8}
        elif op == 0xc3:
            mnemonic, operands = 'ret', []
        elif op == 0x4c:
            demand(take(2) == b'\x89\xef', 'Unsupported REX MOV')
            mnemonic, operands = 'mov', ['rdi', 'r13']
        elif op == 0x48:
            second = take(1)[0]
            if second == 0x8b:
                modrm = take(1)[0]
                if modrm in (0x47, 0x4f):
                    d = imm(1, True)
                    reg = 'rax' if modrm == 0x47 else 'rcx'
                    mnemonic, operands = 'mov', [reg, mem('rdi', 64, d)]
                else:
                    demand(modrm == 0x7c and take(1) == b'\x24', 'Unsupported MOV SIB')
                    d = imm(1, True)
                    mnemonic, operands = 'mov', ['rdi', mem('rsp', 64, d)]
                fields = {'width': 64, 'displacement': d}
            elif second == 0x3b:
                demand(take(1) == b'\x8f', 'Unsupported wide CMP')
                d = imm(4, True)
                mnemonic, operands = 'cmp', ['rcx', mem('rdi', 64, d)]
                fields = {'width': 64, 'displacement': d}
            elif second == 0x89:
                modrm = take(1)[0]
                demand(modrm in (0xc2, 0xdf), 'Unsupported register MOV')
                mnemonic = 'mov'
                operands = ['rdx', 'rax'] if modrm == 0xc2 else ['rdi', 'rbx']
            elif second in (0x81, 0x05, 0xc7):
                if second != 0x05:
                    demand(take(1) == (b'\xea' if second == 0x81 else b'\xc2'),
                           'Unsupported immediate ModRM')
                n = imm(4, True)
                mnemonic = {0x81: 'sub', 0x05: 'add', 0xc7: 'mov'}[second]
                operands = ['rax' if second == 0x05 else 'rdx', str(n)]
                fields = {'immediate': n, 'width': 64}
            elif second == 0x0f:
                cc = take(1)[0] - 0x40
                demand(cc in (2, 3) and take(1) == b'\xd0', 'Unsupported CMOVcc')
                mnemonic, operands = 'cmov' + conditions[cc], ['rdx', 'rax']
            elif second == 0x39:
                demand(take(1) == b'\xd1', 'Unsupported register CMP')
                mnemonic, operands = 'cmp', ['rcx', 'rdx']
            elif second == 0x8d:
                demand(take(1) == b'\x3d', 'Unsupported RIP LEA')
                d = imm(4, True)
                target = start + pos + d
                mnemonic, operands = 'lea', ['rdi', hex(target)]
                fields = {'target': target}
            else:
                raise ValueError('Unsupported REX opcode')
        else:
            raise ValueError(f'Unsupported opcode at {start + p:#x}')
        rows.append({'address': start + p, 'offset': p, 'size': pos - p,
                     'hex': code[p:pos].hex(), 'mnemonic': mnemonic,
                     'operands': operands, **fields})
    return rows


# Byte-independent expected instruction contract: opcode semantics, registers,
# memory operands, immediates and every branch destination. Full-body SHA is an
# additional check, never a replacement for this decoded contract.
CONTRACT = (
    (0, 'mov', 'eax', 'mem32[rdi+0x60]'),
    (3, 'mov', 'rcx', 'mem64[rdi+0x28]'),
    (7, 'cmp', 'eax', 'mem32[rdi+0x4294]'),
    (13, 'setl', 'al'), (16, 'jne', '0x2c6f2bd'),
    (18, 'mov', 'eax', 'mem32[rdi+0x64]'),
    (21, 'cmp', 'eax', 'mem32[rdi+0x4298]'),
    (27, 'setb', 'al'), (30, 'jne', '0x2c6f2bd'),
    (32, 'mov', 'eax', 'mem32[rdi+0x68]'),
    (35, 'cmp', 'eax', 'mem32[rdi+0x429c]'),
    (41, 'jae', '0x2c6f2c1'), (43, 'jmp', '0x2c6f2cc'),
    (45, 'test', 'al', 'al'), (47, 'jne', '0x2c6f2cc'),
    (49, 'mov', 'al', '0x2'), (51, 'cmp', 'rcx', 'mem64[rdi+0x4228]'),
    (58, 'jae', '0x2c6f2f3'), (60, 'mov', 'rax', 'mem64[rdi+0x10]'),
    (64, 'mov', 'rdx', 'rax'), (67, 'sub', 'rdx', '-5000'),
    (74, 'jb', '0x2c6f2ed'), (76, 'add', 'rax', '5000'),
    (82, 'mov', 'rdx', '-1'), (89, 'cmovae', 'rdx', 'rax'),
    (93, 'cmp', 'rcx', 'rdx'), (96, 'setae', 'al'), (99, 'ret'))


def rule_from_instructions(rows):
    """Extract operative fields before certification, including counterfactuals."""
    by = {r['offset']: r for r in rows}
    demand(all(p in by for p in (0, 3, 7, 13, 18, 21, 27, 32, 35, 49, 51,
                                 60, 67, 74, 76, 89, 96)), 'Missing semantic site')
    return {
        'input_base': 'rdi', 'output_register': 'al',
        'tuple_bits': by[0]['width'], 'word_bits': by[3]['width'],
        'left_offsets': [by[p]['displacement'] for p in (0, 18, 32)],
        'right_offsets': [by[p]['displacement'] for p in (7, 21, 35)],
        'first_less_condition': by[13]['mnemonic'],
        'second_less_condition': by[27]['mnemonic'],
        'current_offset': by[3]['displacement'],
        'reference_offset': by[51]['displacement'],
        'base_offset': by[60]['displacement'],
        'gate_value': by[49]['immediate'],
        'sub_immediate': by[67]['immediate'], 'add_immediate': by[76]['immediate'],
        'sub_branch': by[74]['mnemonic'], 'saturation_select': by[89]['mnemonic'],
        'threshold_condition': by[96]['mnemonic'],
    }


def certify_body(body):
    rows = decode(body, START)
    actual = tuple((r['offset'], r['mnemonic'], *r['operands']) for r in rows)
    demand(actual == CONTRACT, 'Decoded body contract mismatch')
    demand(len(body) == END - START and digest(body) == BODY_SHA, 'Body hash/extent mismatch')
    addresses = {r['address'] for r in rows}
    graph = []
    for r in rows:
        op, fall = r['mnemonic'], r['address'] + r['size']
        if op == 'ret':
            edges = []
        elif op == 'jmp':
            edges = [r['target']]
        elif op.startswith('j'):
            edges = [fall, r['target']]
        else:
            edges = [fall]
        demand(all(e in addresses for e in edges), 'Control edge leaves instruction boundary')
        graph.append({'address': r['address'], 'successors': edges})
    reached, pending = set(), [START]
    by = {r['address']: r['successors'] for r in graph}
    while pending:
        p = pending.pop()
        if p not in reached:
            reached.add(p)
            pending.extend(by[p])
    demand(reached == addresses, 'Unreachable bytes in body')
    demand(all(e > r['address'] for r in graph for e in r['successors']), 'Unexpected loop')
    return rows, graph, rule_from_instructions(rows)


def model(left, right, current, reference, base, *, rule=None):
    """Independent scalar rule; inputs are raw integer words, never native pointers."""
    if rule is None:
        first_signed, delta, gate, threshold_condition = True, 5000, 2, 'setae'
    else:
        demand(rule['first_less_condition'] in ('setl', 'setb'), 'Unsupported model comparison')
        demand(rule['threshold_condition'] in ('setae', 'setb'), 'Unsupported model threshold')
        demand(rule['sub_immediate'] == -rule['add_immediate'], 'Unpaired arithmetic operands')
        demand(rule['second_less_condition'] == 'setb' and rule['sub_branch'] == 'jb'
               and rule['saturation_select'] == 'cmovae' and rule['tuple_bits'] == 32
               and rule['word_bits'] == 64 and 0 < rule['add_immediate'] < 1 << 31,
               'Unsupported model instruction contract')
        first_signed = rule['first_less_condition'] == 'setl'
        delta, gate, threshold_condition = (rule['add_immediate'], rule['gate_value'],
                                             rule['threshold_condition'])
    demand(len(left) == len(right) == 3, 'Expected raw triples')
    demand(all(type(n) is int and 0 <= n < 1 << 32 for n in (*left, *right)), 'Expected u32 fields')
    demand(all(type(n) is int and 0 <= n <= U64 for n in (current, reference, base)), 'Expected u64 words')
    def key(triple):
        a, b, c = triple
        if first_signed and a >= 1 << 31:
            a -= 1 << 32
        return a, b, c
    if key(left) >= key(right) and current >= reference:
        return gate
    threshold = min(U64, base + delta)
    return int(current >= threshold if threshold_condition == 'setae' else current < threshold)


def saturation_operands(base, rule):
    """Arithmetic relation of SUB/JB then ADD/CMOVAE, not a CPU interpreter."""
    subtrahend = rule['sub_immediate'] & U64
    sub_result = (base - subtrahend) & U64
    if base < subtrahend:  # SUB's unsigned borrow makes JB take its edge.
        return sub_result
    added = base + rule['add_immediate']
    return added if added <= U64 else U64


# Frozen, instruction-grounded examples. Expected AL values are explicit;
# regeneration does not use model() to invent the oracle column.
def vectors():
    eq, lo, hi = [0, 0, 0], [0xffffffff, 0, 0], [1, 0, 0]
    cases = [
        ('equal-gate', eq, eq, 0, 0, U64, 2),
        ('greater-first-gate', hi, eq, 7, 7, U64, 2),
        ('signed-negative-first', lo, eq, 0, 0, 0, 0),
        ('signed-min-first', [0x80000000, 0xffffffff, 0xffffffff], [0x7fffffff, 0, 0], 0, 0, 0, 0),
        ('signed-max-first', [0x7fffffff, 0, 0], [0x80000000, 0xffffffff, 0xffffffff], 0, 0, U64, 2),
        ('unsigned-second-high', [0, 0x80000000, 0], [0, 0x7fffffff, 0xffffffff], 0, 0, U64, 2),
        ('unsigned-second-low', [0, 0x7fffffff, 0xffffffff], [0, 0x80000000, 0], 0, 0, 0, 0),
        ('unsigned-third-high', [0, 0, 0x80000000], [0, 0, 0x7fffffff], 0, 0, U64, 2),
        ('unsigned-third-low', [0, 0, 0x7fffffff], [0, 0, 0x80000000], 0, 0, 0, 0),
        ('first-dominates-tail', [1, 0, 0], [0, 0xffffffff, 0xffffffff], 0, 0, U64, 2),
        ('second-dominates-tail', [0, 1, 0], [0, 0, 0xffffffff], 0, 0, U64, 2),
        ('word-below-reference', eq, eq, 4, 5, 0, 0),
        ('word-high-bit-unsigned', eq, eq, 1 << 63, (1 << 63) - 1, U64, 2),
        ('word-low-vs-high-reference', eq, eq, 4999, 1 << 63, 0, 0),
        ('threshold-minus-one', lo, eq, 4999, 0, 0, 0),
        ('threshold-equal', lo, eq, 5000, 0, 0, 1),
        ('threshold-plus-one', lo, eq, 5001, 0, 0, 1),
        ('reference-failure-still-threshold', eq, eq, 5000, 5001, 0, 1),
        ('gate-takes-priority', eq, eq, 5000, 5000, 0, 2),
        ('base-one-threshold-low', lo, eq, 5000, 0, 1, 0),
        ('base-one-threshold-equal', lo, eq, 5001, 0, 1, 1),
        ('largest-nonsaturated-low', lo, eq, U64 - 1, 0, U64 - 5000, 0),
        ('largest-nonsaturated-equal', lo, eq, U64, 0, U64 - 5000, 1),
        ('first-saturated-low', lo, eq, U64 - 1, 0, U64 - 4999, 0),
        ('first-saturated-equal', lo, eq, U64, 0, U64 - 4999, 1),
        ('max-base-no-wrap', lo, eq, 4999, 0, U64, 0),
        ('max-base-equal', lo, eq, U64, 0, U64, 1),
        ('max-word-gate', eq, eq, U64, U64, U64, 2),
    ]
    return [dict(name=n, left=a, right=b, current=c, reference=r, base=t, al=out)
            for n, a, b, c, r, t, out in cases]


def metadata_record(data, secs, va):
    raw_length = read_va(data, secs, va, 4)
    size = struct.unpack('<I', raw_length)[0] + 4
    demand(4 < size <= 256, 'Unexpected metadata record size')
    raw = read_va(data, secs, va, size)
    return {'address': va, 'file_offset': file_offset(secs, va, size),
            'size': size, 'hex': raw.hex(), 'sha256': digest(raw)}


def check_window(data, secs, cies, fdes):
    selected = [f for f in fdes if f['start'] == START or f['fde'] == EXPECTED_FDE['fde']]
    demand(selected == [EXPECTED_FDE], 'FDE identity/extent mismatch')
    cie = cies[EXPECTED_FDE['cie']]
    demand(cie == {'va': 0xca6ed8, 'augmentation': 'zR', 'code_align': 1,
                   'data_align': -8, 'fde_encoding': 0x1b, 'lsda_encoding': None,
                   'personality_slot': None}, 'CIE interpretation mismatch')
    body = read_va(data, secs, START, END - START)
    rows, graph, rule = certify_body(body)
    ordered = sorted(fdes, key=lambda f: f['start'])
    k = next(i for i, f in enumerate(ordered) if f['start'] == START)
    before, after = ordered[k - 1]['end'], ordered[k + 1]['start']
    demand((before, after) == (0x2c6f283, 0x2c6f300), 'Neighbor FDE extent mismatch')
    pads = []
    for a, b in ((before, START), (END, after)):
        raw = read_va(data, secs, a, b - a)
        demand(raw == b'\xcc' * (b - a), 'Padding changed')
        pads.append({'start': a, 'end': b, 'size': b - a, 'hex': raw.hex(), 'kind': 'INT3'})
    return ({'start': START, 'end': END, 'size': len(body),
             'file_offset': file_offset(secs, START, len(body)), 'body_hex': body.hex(),
             'body_sha256': digest(body), 'fde': EXPECTED_FDE,
             'fde_record': metadata_record(data, secs, EXPECTED_FDE['fde']),
             'cie': cie, 'cie_record': metadata_record(data, secs, EXPECTED_FDE['cie']),
             'padding': pads}, rows, graph, rule)


def direct_scan(data, secs, targets):
    """Every byte offset with room for rel32, not a linear disassembly census."""
    text = next(s for s in secs if s['name'] == '.text')
    demand((text['address'], text['address'] + text['size'], text['flags']) ==
           (TEXT_START, TEXT_END, 6), 'Unexpected .text geometry/flags')
    lower, upper = text['offset'], text['offset'] + text['size']
    hits = []
    for op in (b'\xe8', b'\xe9'):
        p = lower
        while True:
            # end is exclusive for the one-byte search; last legal site is upper-5.
            p = data.find(op, p, upper - 4)
            if p < 0:
                break
            va = text['address'] + p - lower
            target = va + 5 + struct.unpack_from('<i', data, p + 1)[0]
            if target in targets:
                instruction = decode(data[p:p + 5], va)
                demand(len(instruction) == 1 and instruction[0]['target'] == target,
                       'rel32 decode mismatch')
                hits.append(instruction[0])
            p += 1
    return sorted(hits, key=lambda r: r['address'])


def check_context(data, secs, start, end, site):
    raw = read_va(data, secs, start, end - start)
    rows = decode(raw, start)
    calls = [r for r in rows if r['mnemonic'] == 'call']
    demand(len(calls) == 1 and calls[0]['address'] == site and calls[0]['target'] == START,
           'Caller target mismatch')
    demand(rows[0]['mnemonic'] == 'mov' and rows[0]['operands'][0] == 'rdi',
           'Caller input context mismatch')
    if site != CALL_SITES[-1]:
        demand(rows[-2]['mnemonic'] == 'cmp' and rows[-2]['operands'] == ['al', '0x2']
               and rows[-1]['mnemonic'] in ('je', 'jne'), 'Caller byte-result use changed')
    return {'start': start, 'end': end, 'hex': raw.hex(), 'instructions': rows}


def source_association(data, secs, fdes):
    owner = [f for f in fdes if f['start'] == SOURCE_CALLER]
    demand(len(owner) == 1 and owner[0]['end'] == 0x2894f94, 'Source caller FDE changed')
    demand(owner[0]['start'] <= SOURCE_LEA < CALL_SITES[2] < owner[0]['end'], 'Source association bounds')
    lea = decode(read_va(data, secs, SOURCE_LEA, 7), SOURCE_LEA)
    demand(len(lea) == 1 and lea[0]['mnemonic'] == 'lea'
           and lea[0]['operands'] == ['rdi', hex(LOCATION)], 'Location LEA mismatch')
    section = next(s for s in secs if s['name'] == '.rela.dyn')
    matches = []
    for p in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, p)
        if slot == LOCATION:
            matches.append({'record_file_offset': p, 'slot': slot, 'info': info,
                            'addend': addend, 'hex': data[p:p + 24].hex()})
    demand(len(matches) == 1, 'Location relocation missing/duplicate')
    relocation = matches[0]
    demand((relocation['info'], relocation['addend']) == (8, 0x437df7), 'Location relocation mismatch')
    raw = read_va(data, secs, LOCATION, 24)
    pointer, size, line, column = struct.unpack('<QQII', raw)
    demand((pointer, size, line, column) == (0, 19, 163, 38), 'Location fields mismatch')
    path = read_va(data, secs, relocation['addend'], size)
    demand(path == b'l1/src/perp_meta.rs', 'Location path mismatch')
    return {'association': 'direct callee of an FDE containing a first-party Location reference',
            'caller_fde': owner[0], 'lea': lea[0], 'location': LOCATION,
            'location_file_offset': file_offset(secs, LOCATION, 24), 'location_hex': raw.hex(),
            'relocation': relocation, 'path_hex': path.hex(), 'path_length': size,
            'path_display': path.rstrip(b'\0').decode('ascii'), 'line': line, 'column': column}


def collect(data):
    # There is no public bypass. Internal component functions exist only so tests
    # can establish checks below this identity gate without admitting a mutant.
    demand(len(data) == 105896032 and digest(data) == SHA, 'Node #115 digest mismatch')
    secs = sections(data)
    demand(len({s['name'] for s in secs}) == len(secs), 'Duplicate section names')
    cies, fdes = eh_frame_records(data, secs)
    window, rows, graph, rule = check_window(data, secs, cies, fdes)
    _, index = unwind_index(data)
    chosen = [i for i in index if i['start'] == START]
    demand(len(chosen) == 1 and chosen[0]['fde'] == EXPECTED_FDE['fde'], 'FDE/index disagreement')
    window['unwind_index'] = chosen[0]
    hits = direct_scan(data, secs, {START})
    demand(tuple(h['address'] for h in hits) == CALL_SITES
           and all(h['mnemonic'] == 'call' for h in hits), 'Direct census changed')
    starts = sorted((f['start'], i) for i, f in enumerate(fdes))
    keys = [s for s, _ in starts]
    for h, (a, b) in zip(hits, CONTEXTS):
        k = bisect.bisect_right(keys, h['address']) - 1
        owner = fdes[starts[k][1]]
        demand(owner['start'] <= h['address'] and h['address'] + h['size'] <= owner['end'],
               'Call outside FDE')
        h['containing_fde'] = owner
        h['context'] = check_context(data, secs, a, b, h['address'])
    source = source_association(data, secs, fdes)
    fixtures = vectors()
    return {
        'schema': 'node115-tuple-threshold-v1', 'task': 'RE-001',
        'component': 'l1-shared: source-associated scalar comparison, ownership not proven',
        'source_revision': BASE,
        'claim_status': {'observation': 'bytes, instructions, FDE and relocation records',
                         'proof': 'conditional scalar rule over stable valid memory',
                         'inference': 'first-party association through a caller Location',
                         'unresolved': 'original name, field types and business meaning'},
        'target': {'release': '115', 'path': 'artifacts/node/115/hl-node',
                   'sha256': SHA, 'size': len(data)},
        'window': window, 'instructions': rows, 'control_flow': graph,
        'rule': rule, 'callees': [], 'source_association': source,
        'caller_census': {'start': TEXT_START, 'end': TEXT_END,
                          'bytes_scanned': TEXT_END - TEXT_START, 'opcodes': ['e8', 'e9'],
                          'method': 'all byte offsets with a complete signed rel32 operand',
                          'boundary_limit': 'local contexts decoded; caller FDE CFGs not closed; raw hits may be embedded encodings',
                          'hits': hits},
        'vectors': fixtures,
        'counts': {'functions_bound': 1, 'body_bytes': len(bytes.fromhex(window['body_hex'])),
                   'instructions': len(rows), 'callees': 0,
                   'direct_call_candidates': sum(h['mnemonic'] == 'call' for h in hits),
                   'direct_jump_candidates': sum(h['mnemonic'] == 'jmp' for h in hits),
                   'caller_fdes': len({h['containing_fde']['fde'] for h in hits}),
                   'vectors': len(fixtures)},
    }


def collect_path(binary):
    with Path(binary).open('rb') as f:
        demand(f.seek(0, 2) == 105896032, 'Node #115 digest mismatch')
        f.seek(0)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return collect(data)


def json_bytes(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def render_readme(r):
    w, c, q = r['window'], r['counts'], r['rule']
    s, scan = r['source_association'], r['caller_census']
    walk = '\n'.join(f"| `{i['address']:#x}` | `{i['hex']}` | `{i['mnemonic']} {', '.join(i['operands'])}` |"
                     for i in r['instructions'])
    callers = '\n'.join(f"| `{h['address']:#x}` | `{h['hex']}` | `{h['containing_fde']['start']:#x}..{h['containing_fde']['end']:#x}` |"
                        for h in scan['hits'])
    metrics = '\n'.join(f'| {k} | {v} |' for k, v in c.items())
    return f'''# RE-001: node #115 tuple-gated saturating threshold

Component: {r['component']}. Target: node #{r['target']['release']}, SHA-256
`{r['target']['sha256']}`. Base/reference revision:
`{r['source_revision']}`. All results below are bound to that digest.
New code and prose are independently authored under the repository MIT license;
no inferred source, public implementation or reference source was copied.
Claim status: observed bytes and metadata; proved conditional scalar rule;
inferred first-party association; unresolved original name and field identities.

## Bounded question and answer

What does the complete function at `{w['start']:#x}` return in AL, including
mixed signedness, equality and overflow boundaries?

Given valid, stable input memory based at RDI and a valid return stack, define
tuples A and B from the
raw dwords at offsets `{q['left_offsets'][0]:#x}/{q['left_offsets'][1]:#x}/{q['left_offsets'][2]:#x}`
and `{q['right_offsets'][0]:#x}/{q['right_offsets'][1]:#x}/{q['right_offsets'][2]:#x}`.
Compare them lexicographically with a signed first `{q['tuple_bits']}`-bit field
and unsigned remaining fields. Let C, R and T be the unsigned `{q['word_bits']}`-bit
words at `{q['current_offset']:#x}`, `{q['reference_offset']:#x}` and `{q['base_offset']:#x}`.
The rule is **AL = {q['gate_value']} if A >= B and C >= R; otherwise AL =
int(C >= min(UINT64_MAX, T + {q['add_immediate']}))**. Equality passes each
non-strict gate. The saturation branch prevents wraparound; its maximum threshold
is still attainable when C is UINT64_MAX. The function reads memory and writes
registers only. All paths terminate at its RET, with no callees or indirect dispatch.
Only AL is the scalar result claimed; upper RAX bits vary by path.

## Extent and raw evidence

Addresses are linked ELF VAs, half-open ranges, without a runtime load bias.
The body is `{w['start']:#x}..{w['end']:#x}`, file offset `{w['file_offset']:#x}`,
size **{w['size']} bytes**, body SHA-256 `{w['body_sha256']}`.
Its actual FDE is at file offset/VA `{w['fde_record']['address']:#x}` and names
CIE `{w['cie_record']['address']:#x}` (`{w['cie']['augmentation']}`), with no LSDA.
Raw FDE/CIE records and the independently cross-checked unwind index row are in
`records.json`. Full entry-to-RET decoding, forward-only local control flow and
INT3 gaps support the extent beyond mere unwind-table membership. The preceding
gap is {w['padding'][0]['size']} bytes; the following gap is {w['padding'][1]['size']}
bytes. Padding is recorded separately and excluded from the body.

| Metric (derived from records.json) | Value |
| --- | ---: |
{metrics}

Every instruction is decoded by the strict Python subset decoder; unsupported
opcodes, ModRM/SIB values, prefixes, truncated operands or altered contracts fail.
No instruction bytes or operands are normalized or masked.

| VA | Raw bytes | Decoded instruction |
| --- | --- | --- |
{walk}

## Why the rule follows

The first CMP feeds SETL, which uses signed ordering. SETL leaves flags intact,
so JNE still tests the CMP's equality result. For unequal first fields, TEST AL
selects either the threshold path or the C-versus-R gate. Equal first fields
reach the next CMP/SETB/JNE, using unsigned ordering; equal second fields reach
an unsigned JAE on the last dword. Thus the gate is reached exactly when A >= B.
MOV AL,{q['gate_value']} precedes the unsigned C-versus-R comparison and its JAE
to RET. Failure of that comparison also falls through to the threshold calculation.

Put M = 2^{q['word_bits']} and d = {q['add_immediate']}. SUB uses the sign-extended
immediate -d, whose unsigned value is M-d. For T < M-d, it sets borrow, and its
result modulo M is T+d without overflow; JB selects that value directly. For
T >= M-d, ADD T,d carries. MOV RDX,-1 preserves carry, and CMOVAE cannot replace
that maximum word on this arm. Therefore RDX is min(M-1,T+d) over the full word
domain. The final unsigned CMP/SETAE gives the stated threshold predicate.
This is an algebraic proof over all input words, not an exhaustive execution test.
The independent scalar Python model and frozen target-grounded vectors exercise
signedness, lexicographic priority, equality, both gates and saturation neighbors.
They do not execute captured instructions or establish an original Rust API.

## First-party association and caller census

The direct-call site `{scan['hits'][2]['address']:#x}` lies in the FDE
`{s['caller_fde']['start']:#x}..{s['caller_fde']['end']:#x}`. That same FDE contains
LEA `{s['lea']['address']:#x}` to Location `{s['location']:#x}`. Its unique
R_X86_64_RELATIVE relocation binds the file string `{s['path_display']}`,
line {s['line']}, column {s['column']}. The encoded path length and all bytes are
preserved. This is first-party caller
association, not proof of the leaf's original name, owner or field types. The
binary uses a relative source path here; no build-machine path is invented.

The entire `.text` interval `{scan['start']:#x}..{scan['end']:#x}`
({scan['bytes_scanned']} bytes) is scanned at every possible byte offset for
complete E8/E9 signed-rel32 encodings that resolve to the leaf's entry. This yields
{c['direct_call_candidates']} E8 candidates and {c['direct_jump_candidates']} E9
candidates in {c['caller_fdes']} containing FDEs. Local argument-load/call contexts
are decoded, and the available immediate CMP AL,{q['gate_value']} uses are retained.

| Candidate site | Raw transfer | Containing FDE |
| --- | --- | --- |
{callers}

This is a complete byte-pattern census for those opcodes and that destination,
not a full caller CFG or reachability proof. Local context decoding alone cannot
exclude an encoding embedded in a longer instruction. Indirect references,
interior-entry transfers, other executable sections, data pointers and dynamic
callers remain unmeasured. No caller's complete behavior is bound here.
Callee identities/extents are an empty set: the fully decoded leaf has none.

## Novelty and scope

Before creating this packet, the following commands each produced empty stdout
and stderr with rg exit status 1 (no matches):

```sh
rg -i '{w['start']:x}' research/
rg -i '{w['start']}' research/
rg -i '{w['start']:x}' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '{w['start']}' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

These are historical pre-addition checks; this packet now contains the address.
There are no callee addresses requiring a separate novelty check. The function
is inside the assigned address band and outside the excluded band. Work is
limited to RE-001 and the new tool, targeted tests and this packet. Existing
work items, imports, submodules, catalogue and acceptance gates are unchanged.
The generator is packet-specific evidence reproduction requested by this task,
not a standalone infrastructure change.

## Reproduction and validation scope

From the repository root, with the authenticated capture materialized:

```sh
python3 tools/node115_tuple_threshold.py --out research/work-items/RE-001-node115-tuple-threshold/
python3 -m unittest tests.test_node115_tuple_threshold -v
python3 research/work-items/RE-001-node115-tuple-threshold/verify.py
make verify
make catalogue-check
```

Python 3.10+ stdlib only; developed with Python 3.13.5 on Linux x86-64.
GNU objdump 2.44 was used for initial manual reconnaissance only; no generator,
verifier or test calls it or parses its output. No REA provider was connected.
The generator authenticates the whole image before interpretation or output,
uses a read-only mmap, and regenerates records and this README byte-identically.
The static verifier is copied unchanged into an alternate output directory;
the manifest binds its exact whitelist plus the generator, tests and shared
stdlib-only ELF/FDE parsers. It rejects unknown/duplicate/missing manifest entries,
path escapes, changed files and discrepancies with regenerated evidence.
No absolute local paths, host state or generation times enter the evidence.

Negative controls cover wrong/truncated input, a one-bit corruption at every
body-byte position,
unknown/truncated decoding, altered signedness and threshold predicates, paired
arithmetic constants, shifted FDEs, duplicate FDE identity, caller retargeting,
source relocation duplication/corruption and changed Location metadata/padding.
The README equality test checks all displayed counts against JSON, and JSON
counts are separately checked against their underlying semantic arrays.
Below-digest mutations are private component tests, never alternate admitted
captures. Static generation and local targeted checks are the validation scope;
repository-wide tests and hosted CI are not claimed here.

## Non-claims, unresolved questions and next step

Before: the leaf had no retained behavioral bind. After: the complete bytes,
control flow, scalar return rule and helper-free closure are reproducible.
Rust implementation, source-build identity, compiler flags/dependency versions,
whole ELF equality, Rust type/ABI recovery and component completion remain
not yet implemented or measured. There is no source-versus-binary comparison
and no normalization mask. The source Location association does not identify
units, timestamps, business meaning or an enum/Option representation. Concurrent
mutation, invalid pointers and fault behavior are excluded by the stable valid
memory precondition; native target execution has not occurred.

No progress gate is requested. The next bounded question is to establish the
provenance of the caller's RDI object and its compared fields before assigning
protocol, time or trading meaning to the raw return values.
'''.encode('utf-8')


def manifest_bytes(folder, root=ROOT):
    rows = []
    for relative in sorted((*PACKET_FILES, *DEPENDENCIES)):
        path = root / relative.removeprefix('../../../') if relative in DEPENDENCIES else folder / relative
        rows.append(f'{digest(path.read_bytes())}  {relative}\n')
    return ''.join(rows).encode('ascii')


def generate(binary, out):
    record = collect_path(binary)  # Fail closed before creating output.
    payloads = {'records.json': json_bytes(record), 'README.md': render_readme(record),
                'verify.py': (PACKET / 'verify.py').read_bytes()}
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    demand(all(not p.is_symlink() for p in out.iterdir()), 'Refuse output symlinks')
    demand({p.name for p in out.iterdir()} <= {*PACKET_FILES, 'MANIFEST.sha256'}, 'Unexpected output file')
    for name, payload in payloads.items():
        (out / name).write_bytes(payload)
    (out / 'MANIFEST.sha256').write_bytes(manifest_bytes(out))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, default=PACKET)
    args = parser.parse_args()
    record = generate(args.binary, args.out)
    print(json.dumps({'target_sha256': SHA, **record['counts']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print(f'node115_tuple_threshold: {error}', file=sys.stderr)
        sys.exit(1)
