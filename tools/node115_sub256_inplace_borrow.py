#!/usr/bin/env python3
"""Digest-bound, static RE-001 subtraction certificate. Python 3.10+ / MIT.

The deliberately restricted x86 decoder supports only the observed leaf and
its caller, plus named semantic counterfacts. Unsupported encodings fail closed.
No captured instruction is executed. No native disassembler is required.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-sub256-inplace-borrow'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END, NEXT = 0x43be060, 0x43be091, 0x43be0a0
OWNER, OWNER_END = 0x4353990, 0x4353ec4
BODY_SHA = 'ddc8e1d31bf3e406e23cd98cc4d8f38975b0d0d0a54b4db2dedbbe9dfa7fdb91'
SOURCE_BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
U64, U256 = 1 << 64, 1 << 256


def demand(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    demand(len(data) == 105896032 and digest(data) == SHA, 'node #115 digest mismatch')


def offset(secs, va, size=1):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    demand(len(matches) == 1, 'ambiguous or absent VA mapping')
    return matches[0]['offset'] + va - matches[0]['address']


def read_va(data, secs, va, size):
    p = offset(secs, va, size)
    return data[p:p + size]


def reg(index, width):
    names = {
        64: ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'],
        32: ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'],
        8: ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil'],
    }
    if width == 128:
        return f'xmm{index}'
    if index < 8:
        return names[width][index]
    return f'r{index}' + {64: '', 32: 'd', 8: 'b'}[width]


def mem(base, displacement=0, width=64, index=None, scale=1):
    return {'base': base, 'index': index, 'scale': scale,
            'displacement': displacement, 'width': width}


def decode(body, start):
    """Decode every byte, with checked lengths, prefixes, ModRM and SIB.

    No recovery/skipping, proximity symbols, guessed instruction lengths or
    objdump output are inputs. Relative targets use the decoded instruction end.
    This is intentionally not a general x86 disassembler.
    """
    p, rows = 0, []

    def integer(n, signed=False):
        nonlocal p
        demand(p + n <= len(body), 'truncated instruction')
        value = int.from_bytes(body[p:p + n], 'little', signed=signed)
        p += n
        return value

    def modrm(width, rex, reg_width=None):
        byte = integer(1)
        mod, group, rm = byte >> 6, (byte >> 3) & 7, byte & 7
        r = reg(group + (8 if rex & 4 else 0), reg_width or width)
        if mod == 3:
            # No legacy high-byte register encodings are used in this packet.
            demand(width != 8 or rex or rm < 4, 'unsupported high-byte register')
            operand = reg(rm + (8 if rex & 1 else 0), width)
        else:
            base, index, scale, disp = None, None, 1, 0
            if rm == 4:
                sib = integer(1)
                scale = 1 << (sib >> 6)
                idx, b = (sib >> 3) & 7, sib & 7
                if idx != 4 or rex & 2:
                    index = reg(idx + (8 if rex & 2 else 0), 64)
                demand(not (mod == 0 and b == 5), 'unsupported no-base SIB')
                base = reg(b + (8 if rex & 1 else 0), 64)
            elif mod == 0 and rm == 5:
                base, disp = 'rip', integer(4, True)
            else:
                base = reg(rm + (8 if rex & 1 else 0), 64)
            if mod == 1:
                disp = integer(1, True)
            elif mod == 2:
                disp = integer(4, True)
            operand = mem(base, disp, width, index, scale)
        return operand, r, group, mod

    while p < len(body):
        begin = p
        prefix, rex = None, 0
        if body[p] in (0x66, 0xf3):
            prefix = integer(1)
        if p < len(body) and 0x40 <= body[p] <= 0x4f:
            rex = integer(1)
        op = integer(1)
        width = 64 if rex & 8 else 32
        operands, target = [], None
        if op == 0x0f:
            sub = integer(1)
            vectors = {(None, 0x10): ('movups', False), (None, 0x11): ('movups', True),
                       (None, 0x28): ('movaps', False), (None, 0x29): ('movaps', True),
                       (0x66, 0x6f): ('movdqa', False), (0x66, 0x7f): ('movdqa', True),
                       (0xf3, 0x6f): ('movdqu', False), (0xf3, 0x7f): ('movdqu', True),
                       (0x66, 0xef): ('pxor', False), (0x66, 0x6c): ('punpcklqdq', False),
                       (0x66, 0xeb): ('por', False), (0x66, 0x76): ('pcmpeqd', False),
                       (None, 0x57): ('xorps', False)}
            if (prefix, sub) in vectors:
                demand(not rex & 8, 'unsupported vector REX.W')
                name, store = vectors[prefix, sub]
                rm, r, _, _ = modrm(128, rex)
                operands = [rm, r] if store else [r, rm]
            elif prefix == 0xf3 and sub == 0x7e:
                demand(not rex, 'unsupported movq prefix')
                rm, r, _, mod = modrm(128, rex)
                if isinstance(rm, dict):
                    rm['width'] = 64
                name, operands = 'movq', [r, rm]
            else:
                demand(prefix is None, 'unsupported opcode prefix')
                if sub in (0x82, 0x83, 0x84, 0x85):
                    demand(not rex, 'unsupported branch prefix')
                    name = {0x82: 'jb', 0x83: 'jae', 0x84: 'je', 0x85: 'jne'}[sub]
                    delta = integer(4, True)
                    target = start + p + delta
                    operands = [target]
                elif sub in (0x92, 0x93):
                    rm, _, group, _ = modrm(8, rex)
                    demand(group == 0 and not rex & 12, 'unsupported SETcc encoding')
                    name, operands = ('setb' if sub == 0x92 else 'setae'), [rm]
                elif sub == 0xb6:
                    rm, r, _, _ = modrm(8, rex, width)
                    name, operands = 'movzx', [r, rm]
                elif sub == 0x44:
                    rm, r, _, _ = modrm(width, rex)
                    name, operands = 'cmove', [r, rm]
                elif sub == 0x50:
                    rm, r, _, mod = modrm(128, rex, 32)
                    demand(mod == 3 and not rex & 8, 'unsupported movmskps')
                    name, operands = 'movmskps', [r, rm]
                else:
                    raise ValueError(f'unsupported 0f opcode {sub:02x}')
        else:
            demand(prefix is None, 'unsupported legacy prefix')
            if 0x50 <= op <= 0x5f:
                demand(not rex or rex == 0x41, 'unsupported stack prefix')
                name = 'push' if op < 0x58 else 'pop'
                operands = [reg((op & 7) + (8 if rex & 1 else 0), 64)]
            elif op in (0xe8, 0xe9, 0xeb, 0x75):
                demand(not rex, 'unsupported branch prefix')
                name = {0xe8: 'call', 0xe9: 'jmp', 0xeb: 'jmp', 0x75: 'jne'}[op]
                delta = integer(4 if op in (0xe8, 0xe9) else 1, True)
                target = start + p + delta
                operands = [target]
            elif op == 0xc3:
                demand(not rex, 'unsupported RET prefix')
                name = 'ret'
            elif 0xb8 <= op <= 0xbf:
                name = 'mov'
                operands = [reg((op & 7) + (8 if rex & 1 else 0), width),
                            integer(8 if width == 64 else 4)]
            elif op in (0x80, 0x81, 0x83, 0xc6, 0xc7):
                w = 8 if op in (0x80, 0xc6) else width
                rm, _, group, _ = modrm(w, rex)
                if op in (0xc6, 0xc7):
                    demand(group == 0 and not rex & 4, 'invalid MOV group')
                    name = 'mov'
                else:
                    demand(group in (0, 1, 2, 5, 6, 7), 'unsupported ALU group')
                    name = {0: 'add', 1: 'or', 2: 'adc', 5: 'sub', 6: 'xor', 7: 'cmp'}[group]
                n = 1 if op in (0x80, 0x83, 0xc6) else 4
                operands = [rm, integer(n, op == 0x83 or (width == 64 and n == 4))]
            elif op == 0x69:
                rm, r, _, _ = modrm(width, rex)
                name, operands = 'imul', [r, rm, integer(4, True)]
            elif op == 0xff:
                rm, _, group, _ = modrm(64, rex)
                demand(group == 2 and not rex, 'unsupported FF encoding')
                name, operands = 'call', [rm]
            else:
                pairs = {0x8b: ('mov', True), 0x89: ('mov', False), 0x8d: ('lea', True),
                         0x01: ('add', False), 0x09: ('or', False), 0x11: ('adc', False),
                         0x19: ('sbb', False), 0x1b: ('sbb', True), 0x29: ('sub', False),
                         0x31: ('xor', False), 0x3b: ('cmp', True), 0x84: ('test', False)}
                demand(op in pairs, f'unsupported opcode {op:02x} at {start + begin:#x}')
                name, reverse = pairs[op]
                rm, r, _, mod = modrm(8 if op == 0x84 else width, rex)
                demand(op != 0x8d or mod != 3, 'LEA requires memory operand')
                operands = [r, rm] if reverse else [rm, r]
        row = {'va': start + begin, 'size': p - begin, 'hex': body[begin:p].hex(),
               'op': name, 'operands': operands}
        demand(row['size'] <= 15, 'oversized instruction')
        if target is not None:
            row['target'] = target
        for operand in operands:
            if isinstance(operand, dict) and operand['base'] == 'rip':
                operand['target'] = start + p + operand['displacement']
        rows.append(row)
    return rows


def derive_rule(rows):
    """Read the carry-chain operations, offsets and final condition from the walk."""
    demand(len(rows) == 14, 'leaf instruction count')
    chain = []
    for i in range(4):
        load, arithmetic = rows[2 * i:2 * i + 2]
        demand(load['op'] == 'mov' and load['operands'][0] == 'rax'
               and isinstance(load['operands'][1], dict), 'limb load')
        demand(arithmetic['op'] in ('sub', 'sbb') and arithmetic['operands'][1] == 'rax'
               and isinstance(arithmetic['operands'][0], dict), 'limb subtraction')
        chain.append({'rhs': load['operands'][1], 'lhs': arithmetic['operands'][0],
                      'consume_borrow': arithmetic['op'] == 'sbb'})
    demand(rows[12]['op'] in ('setb', 'setae'), 'borrow condition')
    return {'chain': chain, 'condition': rows[12]['op'], 'flag_destination': rows[12]['operands'][0]}


def check_leaf(body):
    rows = decode(body, START)
    rule = derive_rule(rows)
    expected = [('mov', ['rax', mem('rdx', i * 8)]) if k == 0 else
                ('sub' if i == 0 else 'sbb', [mem('rsi', i * 8), 'rax'])
                for i in range(4) for k in range(2)]
    expected += [('movups', ['xmm0', mem('rsi', 0, 128)]),
                 ('movups', [mem('rdi', 0, 128), 'xmm0']),
                 ('movups', ['xmm0', mem('rsi', 16, 128)]),
                 ('movups', [mem('rdi', 16, 128), 'xmm0']),
                 ('setb', [mem('rdi', 32, 8)]), ('ret', [])]
    demand([(r['op'], r['operands']) for r in rows] == expected, 'leaf semantic contract changed')
    demand(len(body) == END - START and digest(body) == BODY_SHA, 'leaf body bytes changed')
    return rows, rule


def model(left, right):
    """Independently authored integer rule, not captured-code execution."""
    demand(type(left) is int and type(right) is int and 0 <= left < U256 and 0 <= right < U256,
           'unsigned 256-bit inputs required')
    return {'difference': (left - right) % U256, 'borrow': int(left < right),
            'rax': right >> 192}


def limb_relation(rule, left, right):
    """Algebraic recurrence extracted from the instructions; no PC/memory emulator."""
    result, borrow = 0, 0
    for term in rule['chain']:
        a = (left >> (8 * term['lhs']['displacement'])) % U64
        b = (right >> (8 * term['rhs']['displacement'])) % U64
        d = a - b - (borrow if term['consume_borrow'] else 0)
        borrow = int(d < 0)
        result |= (d % U64) << (8 * term['lhs']['displacement'])
    flag = borrow if rule['condition'] == 'setb' else 1 - borrow
    return {'difference': result, 'borrow': flag, 'rax': right >> 192}


def frame_record(data, secs, fdes, cies, start, end):
    matches = [f for f in fdes if f['start'] < end and start < f['end']]
    demand(len(matches) == 1 and matches[0]['start'] == start and matches[0]['end'] == end,
           'exact nonoverlapping FDE extent changed')
    f = matches[0]
    demand(f['lsda'] is None, 'unexpected LSDA')
    demand(f['fde'] == {START: 0xea5568, OWNER: 0xe9e4f8}[start]
           and f['cie'] == 0xca6ed8, 'FDE/CIE identity changed')
    record = dict(f)
    for name, va in [('fde', f['fde']), ('cie', f['cie'])]:
        p = offset(secs, va, 4)
        size = 4 + struct.unpack_from('<I', data, p)[0]
        record[name + '_file_offset'] = p
        record[name + '_hex'] = read_va(data, secs, va, size).hex()
    record['cie_fields'] = cies[f['cie']]
    demand(record['cie_hex'] == '1400000000000000017a5200017810011b0c070890010000',
           'CIE bytes changed')
    return record


def scan_rel32(data, text, target):
    """Every e8/e9 byte position in all .text, including instruction interiors."""
    hits = []
    limit = text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        p = text['offset']
        while True:
            p = data.find(bytes([opcode]), p, limit - 4)
            if p < 0:
                break
            site = text['address'] + p - text['offset']
            if site + 5 + struct.unpack_from('<i', data, p + 1)[0] == target:
                hits.append({'site': site, 'opcode': opcode, 'hex': data[p:p + 5].hex(),
                             'target': target})
            p += 1
    return sorted(hits, key=lambda r: r['site'])


def source_location(data, secs, owner_rows):
    lea = next(r for r in owner_rows if r['va'] == 0x4353eb7)
    demand(lea['op'] == 'lea' and lea['operands'][0] == 'rdi'
           and lea['operands'][1].get('target') == 0x64768d8, 'source Location LEA changed')
    loc = lea['operands'][1]['target']
    p = offset(secs, loc, 24)
    pointer, length, line, column = struct.unpack_from('<QQII', data, p)
    demand((pointer, length, line, column) == (0, 19, 119, 33), 'source Location fields changed')
    rel = [s for s in secs if s['name'] == '.rela.dyn']
    demand(len(rel) == 1 and rel[0]['size'] % 24 == 0, 'relocation section')
    rel = rel[0]
    found = []
    for q in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, q)
        if slot == loc:
            found.append((q, info, addend))
    demand(len(found) == 1 and found[0][1:] == (8, 0x432b6f), 'Location relocation changed')
    q, info, path_va = found[0]
    path = read_va(data, secs, path_va, length)
    demand(path == b'l1/src/spot_meta.rs', 'source path changed')
    return {'lea': lea, 'location_va': loc, 'location_file_offset': p,
            'location_hex': data[p:p + 24].hex(), 'path_va': path_va,
            'path': path.decode('ascii'), 'line': line, 'column': column,
            'relocation_file_offset': q, 'relocation_hex': data[q:q + 24].hex(),
            'relocation_type': 'R_X86_64_RELATIVE',
            'association': 'caller references first-party Location; leaf authorship and original name unresolved'}


def vectors(rule):
    cases = [(0, 0), (0, 1), (1, 0), (1, 1), (U256 - 1, 0),
             (U256 - 1, U256 - 1), (0, U256 - 1), (U256 - 1, 1)]
    for bit in (64, 128, 192, 255):
        edge = 1 << bit
        cases += [(edge, 1), (edge - 1, edge), (edge, edge - 1),
                  (edge, edge), (edge, edge + 1), (0, edge), (edge, 0)]
    out = []
    for a, b in cases:
        expected = model(a, b)
        demand(limb_relation(rule, a, b) == expected, 'instruction-derived vector mismatch')
        out.append({'left': hex(a), 'right': hex(b),
                    'difference': hex(expected['difference']), 'borrow': expected['borrow'],
                    'rax': hex(expected['rax'])})
    return out


def collect_static(data):
    """Local obligations; intentionally below the digest gate for corruption tests.

    Public generation always authenticates first. This function is not a way to
    admit alternate targets and must not be used to make target identity claims.
    """
    secs = sections(data)
    texts = [s for s in secs if s['name'] == '.text']
    demand(len(texts) == 1, 'text section ambiguity')
    text = texts[0]
    demand(text == {'name': '.text', 'type': 1, 'flags': 6, 'address': 0x1419300,
                    'offset': 0x1418300, 'size': 0x4fd7700}, 'text geometry changed')
    body = read_va(data, secs, START, END - START)
    rows, rule = check_leaf(body)
    cies, fdes = eh_frame_records(data, secs)
    frame = frame_record(data, secs, fdes, cies, START, END)
    next_frames = [f for f in fdes if f['start'] >= END]
    demand(min(f['start'] for f in next_frames) == NEXT, 'next FDE start changed')
    padding = read_va(data, secs, END, NEXT - END)
    demand(padding == b'\xcc' * (NEXT - END), 'INT3 padding changed')
    owner_frame = frame_record(data, secs, fdes, cies, OWNER, OWNER_END)
    owner_body = read_va(data, secs, OWNER, OWNER_END - OWNER)
    owner_rows = decode(owner_body, OWNER)
    boundaries = {r['va']: r for r in owner_rows}
    for r in owner_rows:
        if r['op'] in ('je', 'jne', 'jb', 'jae', 'jmp'):
            demand(r['target'] in boundaries, 'caller branch does not target an instruction boundary')
    hits = scan_rel32(data, text, START)
    demand([r['site'] for r in hits] == [0x4353cf6, 0x4353db7], 'direct-caller census changed')
    for hit in hits:
        r = boundaries.get(hit['site'])
        demand(r is not None and r['op'] == 'call' and r.get('target') == START
               and r['hex'] == hit['hex'], 'caller is not a decoded CALL boundary')
        hit['owner_start'] = OWNER
        hit['boundary_validated'] = True
        hit['setup_and_borrow_check'] = [x for x in owner_rows
                                       if hit['site'] - 16 <= x['va'] <= hit['site'] + 10]
    decoded_calls = [r['va'] for r in owner_rows if r['op'] == 'call' and r.get('target') == START]
    demand(decoded_calls == [r['site'] for r in hits], 'decoded/census calls disagree')
    source = source_location(data, secs, owner_rows)
    # Local setup is evidence of disjoint stack buffers, not full caller semantics.
    setup = {0x4353cdb: ['rdi', mem('rsp', 0x30)],
             0x4353ce6: ['rsi', mem('rsp', 0xe0)], 0x4353cee: ['rdx', mem('rsp', 0xb0)],
             0x4353da7: ['rsi', mem('rsp', 0xb0)], 0x4353daf: ['rdx', mem('rsp', 0x160)]}
    for va, operands in setup.items():
        demand(boundaries[va]['op'] == 'lea' and boundaries[va]['operands'] == operands,
               'caller buffer setup changed')
    for cmp_va, branch_va in ((0x4353cfb, 0x4353d00), (0x4353dbc, 0x4353dc1)):
        demand(boundaries[cmp_va]['op'] == 'cmp'
               and boundaries[cmp_va]['operands'] == [mem('rsp', 0x50, 8), 0]
               and boundaries[branch_va]['op'] == 'jne'
               and boundaries[branch_va]['target'] == 0x4353d74, 'caller borrow check changed')
    demand(digest(owner_body) == '95bd0889bb9ee33ed281acee145a888e094de359fce5e5698b6ba607c51133b5',
           'caller context body changed')
    fixtures = vectors(rule)
    return {'schema_version': 1, 'task': 'RE-001', 'component': 'foundation',
            'target': {'release': 115, 'sha256': SHA, 'size': len(data)},
            'source_base': SOURCE_BASE,
            'function': {'start': START, 'end': END, 'size': len(body),
                         'file_offset': offset(secs, START), 'body_sha256': digest(body),
                         'body_hex': body.hex(), 'frame': frame, 'instructions': rows,
                         'callees': [], 'indirect_transfers': [],
                         'padding': {'start': END, 'end': NEXT, 'size': len(padding), 'hex': padding.hex()}},
            'rule': rule,
            'contract': {
                'preconditions': 'Readable right[0:32], readable/writable left[0:32], writable out[0:33]; disjoint ranges, valid return stack, no concurrent mutation.',
                'register_inputs': {'rdi': 'out', 'rsi': 'left', 'rdx': 'right'},
                'integer_representation': 'unsigned 256-bit, four little-endian 64-bit limbs',
                'left_after': '(left_before - right_before) mod 2^256, including underflow',
                'out_bytes_0_to_31': 'copy of left_after',
                'out_byte_32': '1 exactly when left_before < right_before; otherwise 0',
                'rax_after': 'right_before >> 192; incidental machine result, not a typed return claim',
                'xmm0_after': 'high 128 bits of difference',
                'flags': 'SETB and MOVUPS preserve the flags of the final SBB',
                'other_effects': 'No allocation, calls, global data references or local control-flow alternatives; RET consumes return address.',
                'aliasing_limit': 'Partial overlap and concurrent memory access are outside this integer contract; ordered instruction writes are retained.',
            },
            'caller_scan': {'text': text, 'method': 'all byte positions: e8/e9 signed rel32; full owner decode validates every hit',
                            'hits': hits, 'false_positive_hits': [],
                            'limitations': 'No indirect callers, pointers, non-.text entries or dynamic reachability census.'},
            'caller_context': {'start': OWNER, 'end': OWNER_END, 'size': len(owner_body),
                               'body_sha256': digest(owner_body), 'body_hex': owner_body.hex(),
                               'frame': owner_frame, 'decoded_instruction_count': len(owner_rows),
                               'argument_setup': [boundaries[va] for va in setup],
                               'source_location': source,
                               'scope': 'instruction boundaries, call sites, stack arguments and Location only; no caller behavior bind'},
            'vectors': fixtures,
            'counts': {'function_bytes': len(body), 'instructions': len(rows), 'callees': 0,
                       'indirect_transfers': 0, 'padding_bytes': len(padding),
                       'direct_call_sites': len(hits), 'direct_tail_sites': sum(h['opcode'] == 0xe9 for h in hits),
                       'caller_owners': len({h['owner_start'] for h in hits}),
                       'caller_context_bytes': len(owner_body), 'caller_context_instructions': len(owner_rows),
                       'scan_bytes': text['size'], 'vectors': len(fixtures)}}


def collect(data):
    authenticate(data)
    return collect_static(data)


def encoded(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def readme_counts(record):
    return '\n'.join(f'| {name} | {value} |' for name, value in sorted(record['counts'].items()))


def generate(binary, out):
    # Map one image rather than copying a 100 MB capture for each check.
    with Path(binary).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = collect(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_bytes(encoded(record))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, default=PACKET)
    args = parser.parse_args()
    record = generate(args.binary, args.out)
    print(json.dumps({'target_sha256': SHA, 'start': hex(START), 'counts': record['counts']}, sort_keys=True))


if __name__ == '__main__':
    main()
