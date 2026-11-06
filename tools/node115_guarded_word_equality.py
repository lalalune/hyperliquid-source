#!/usr/bin/env python3
"""Bind a complete node #115 equality leaf using static, stdlib-only reads.

The decoder deliberately supports only the instruction forms in the measured
leaf and its two caller excerpts. Unknown forms fail closed. No native code,
disassembler, subprocess, network or target execution is used by this tool.
New implementation: MIT, independently authored from the instruction evidence.
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
PACKET = ROOT / 'research/work-items/RE-001-node115-guarded-word-equality'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
BASE_COMMIT = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x542f290, 0x542f31b
BODY_SHA = '03cdac3c0ab0bf56c2619e06eefd37b6696bbc508c948b14d06b459d073bc39e'
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
CALLER_START, CALLER_END = 0x5378220, 0x537aa59
CALL_SITE = 0x53794cc
CONTEXT_START, CONTEXT_END = 0x53794b4, 0x53794d6
LOCATION_SITE, LOCATION = 0x53788f2, 0x64a7f08
SOURCE = 'l1/src/raw_signature_tracker.rs'
FDE_RAW = bytes.fromhex('1000000084682d00301b4b048b00000000000000')
CIE_RAW = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE_VA, CIE_VA = 0xf7d758, 0xca6ed8
WHITELIST = (
    'README.md', 'records.json', 'verify.py',
    'tools/node115_guarded_word_equality.py',
    'tests/test_node115_guarded_word_equality.py',
    'tools/elf_index.py', 'tools/fde_extents.py',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(len(data) == SIZE and digest(data) == SHA, 'Node #115 size/digest mismatch')


# Fixed register forms, including the complete opcode, ModRM and REX prefix.
# Memory displacements and immediates are decoded separately below, not hidden
# in an opaque whole-function byte string.
FIXED = {
    '488b17': ('mov', 'rdx, qword [rdi]'),
    '488b0e': ('mov', 'rcx, qword [rsi]'),
    '0f95c0': ('setne', 'al'),
    '410f95c0': ('setne', 'r8b'),
    '410f95c1': ('setne', 'r9b'),
    '4130c0': ('xor', 'r8b, al'),
    '31c0': ('xor', 'eax, eax'),
    '4584c1': ('test', 'r9b, r8b'),
    '4885c0': ('test', 'rax, rax'),
    '4c39c0': ('cmp', 'rax, r8'),
    '4d85c0': ('test', 'r8, r8'),
    '4839c8': ('cmp', 'rax, rcx'),
    '4885c9': ('test', 'rcx, rcx'),
    '0f94c0': ('sete', 'al'),
    'c3': ('ret', ''),
}
FIXED = {bytes.fromhex(k): v for k, v in FIXED.items()}
MEMORY = {
    bytes.fromhex('488b47'): ('mov', 'rax', 'rdi', 64, False),
    bytes.fromhex('4c8b46'): ('mov', 'r8', 'rsi', 64, False),
    bytes.fromhex('483b46'): ('cmp', 'rax', 'rsi', 64, False),
    bytes.fromhex('488b4e'): ('mov', 'rcx', 'rsi', 64, False),
    bytes.fromhex('410fb645'): ('movzx', 'eax', 'r13', 8, False),
    bytes.fromhex('3a4424'): ('cmp', 'al', 'rsp', 8, False),
    bytes.fromhex('498d7d'): ('lea', 'rdi', 'r13', 64, True),
    bytes.fromhex('488d7424'): ('lea', 'rsi', 'rsp', 64, True),
}
IMMEDIATE = {
    bytes.fromhex('4883fa'): ('cmp', 'rdx', 64),
    bytes.fromhex('4883f9'): ('cmp', 'rcx', 64),
    bytes.fromhex('83fa'): ('cmp', 'edx', 32),
    bytes.fromhex('83f9'): ('cmp', 'ecx', 32),
    bytes.fromhex('f6c1'): ('test', 'cl', 8),
    bytes.fromhex('b0'): ('mov', 'al', 8),
}


def decode(data, base):
    """Linear strict decoding, with signed branch/RIP displacements resolved."""
    rows, pos = [], 0
    while pos < len(data):
        start = pos
        row = {'va': base + pos}
        found = False
        for encoding, (op, operands) in FIXED.items():
            if data.startswith(encoding, pos):
                pos += len(encoding)
                row.update(op=op, operands=operands)
                found = True
                break
        if not found:
            for encoding, (op, reg, width) in IMMEDIATE.items():
                if data.startswith(encoding, pos):
                    pos += len(encoding)
                    require(pos < len(data), 'Truncated immediate')
                    imm = data[pos]
                    if op == 'cmp' and imm >= 128:
                        imm -= 256  # opcode 83 sign-extends its imm8
                    pos += 1
                    row.update(op=op, operands=f'{reg}, {imm}', width=width, immediate=imm)
                    found = True
                    break
        if not found:
            for encoding, (op, reg, source, width, address_only) in MEMORY.items():
                if data.startswith(encoding, pos):
                    pos += len(encoding)
                    require(pos < len(data), 'Truncated memory displacement')
                    disp = struct.unpack_from('<b', data, pos)[0]
                    pos += 1
                    row.update(op=op, operands=f'{reg}, [{source}{disp:+#x}]',
                               width=width, displacement=disp, base=source,
                               memory_access='address-only' if address_only else 'read')
                    found = True
                    break
        if not found and data[pos] in (0x74, 0x75, 0xeb, 0xe8, 0xe9):
            opcode = data[pos]
            n = 1 if opcode in (0x74, 0x75, 0xeb) else 4
            require(pos + 1 + n <= len(data), 'Truncated relative transfer')
            displacement = int.from_bytes(data[pos + 1:pos + 1 + n], 'little', signed=True)
            pos += 1 + n
            target = base + pos + displacement
            op = {0x74: 'je', 0x75: 'jne', 0xeb: 'jmp', 0xe8: 'call', 0xe9: 'jmp'}[opcode]
            row.update(op=op, operands=hex(target), target=target,
                       relative_displacement=displacement)
            found = True
        if not found and data.startswith(bytes.fromhex('0f85'), pos):
            require(pos + 6 <= len(data), 'Truncated near conditional transfer')
            displacement = struct.unpack_from('<i', data, pos + 2)[0]
            pos += 6
            row.update(op='jne', operands=hex(base + pos + displacement),
                       target=base + pos + displacement, relative_displacement=displacement)
            found = True
        if not found and data.startswith(bytes.fromhex('488d35'), pos):
            require(pos + 7 <= len(data), 'Truncated RIP-relative LEA')
            displacement = struct.unpack_from('<i', data, pos + 3)[0]
            pos += 7
            row.update(op='lea', operands=f'rsi, [rip{displacement:+#x}]',
                       rip_target=base + pos + displacement, displacement=displacement,
                       memory_access='address-only')
            found = True
        require(found, f'Unsupported instruction at {base + start:#x}')
        row.update(size=pos - start, bytes=data[start:pos].hex())
        rows.append(row)
    return rows


def bind_body(body):
    require(len(body) == END - START, 'Leaf extent mismatch')
    rows = decode(body, START)
    require(digest(body) == BODY_SHA, 'Leaf body SHA-256 mismatch')
    boundaries = {r['va'] for r in rows}
    for row in rows:
        require(row['op'] != 'call', 'Unexpected leaf callee')
        if 'target' in row:
            require(row['target'] in boundaries, 'Leaf branch misses instruction boundary')
    # Follow both sides of each conditional: all instruction bytes belong to
    # the entry-reachable CFG, with RET as the only terminal instruction.
    by_va = {r['va']: r for r in rows}
    pending, seen = [START], set()
    while pending:
        va = pending.pop()
        if va in seen:
            continue
        require(va in by_va, 'Leaf falls outside its complete extent')
        seen.add(va)
        row = by_va[va]
        if row['op'] != 'ret':
            if 'target' in row:
                pending.append(row['target'])
            if row['op'] != 'jmp':
                pending.append(va + row['size'])
    require(seen == boundaries, 'Unreachable instruction bytes in leaf')
    return rows


def bind_fde(raw, va, cie_raw):
    require(len(raw) >= 17, 'Truncated leaf FDE')
    length, cie_delta, displacement, extent = struct.unpack_from('<IIii', raw)
    require(length + 4 == len(raw), 'Leaf FDE record length mismatch')
    require(va + 4 - cie_delta == CIE_VA, 'Leaf FDE CIE mismatch')
    require(va + 8 + displacement == START and extent == END - START, 'Leaf FDE extent mismatch')
    require(va == FDE_VA and raw == FDE_RAW, 'Leaf FDE bytes mismatch')
    require(cie_raw == CIE_RAW, 'Leaf CIE bytes mismatch')


def bind_caller(context):
    rows = decode(context, CONTEXT_START)
    require(CONTEXT_START + len(context) == CONTEXT_END, 'Caller excerpt extent mismatch')
    calls = [r for r in rows if r['op'] == 'call']
    require(len(calls) == 1 and calls[0]['va'] == CALL_SITE
            and calls[0]['target'] == START, 'Caller target mismatch')
    require(context.hex() == '410fb645303a4424380f859d080000498d7d08488d742410e8bf5d0b00e97d080000',
            'Caller context bytes mismatch')
    return rows


def extract_rule(rows):
    """Extract the constants/offsets used by the manual dataflow theorem."""
    by_va = {row['va']: row for row in rows}
    full = [by_va[va] for va in (0x542f293, 0x542f29d)]
    low = [by_va[va] for va in (0x542f2ad, 0x542f2b4)]
    require(full[0]['immediate'] == full[1]['immediate'], 'Unequal full-width sentinels')
    require(low[0]['immediate'] == low[1]['immediate'], 'Unequal low-width sentinels')
    payload_offsets = []
    for a, b in ((0x542f2c2, 0x542f2c6), (0x542f2f6, 0x542f2fa), (0x542f30f, 0x542f313)):
        require(by_va[a]['displacement'] == by_va[b]['displacement'], 'Asymmetric payload offset')
        payload_offsets.append(by_va[a]['displacement'])
    require(by_va[0x542f2e5]['displacement'] == by_va[0x542f2e9]['displacement'],
            'Asymmetric conditional payload offset')
    require(by_va[0x542f2e0]['immediate'] == by_va[0x542f2f1]['immediate'], 'Unequal low-bit masks')
    return {
        'words_per_record': max(payload_offsets) // (full[0]['width'] // 8) + 1,
        'word_bits': full[0]['width'], 'low_tag_bits': low[0]['width'],
        'full_width_sentinel': full[0]['immediate'], 'low_width_sentinel': low[0]['immediate'],
        'left_payload_tag': by_va[0x542f2db]['immediate'],
        'right_tag_mask': by_va[0x542f2e0]['immediate'],
        'required_equal_payload_offsets_after_low_tag_gate': payload_offsets,
        'conditionally_compared_payload_offset': by_va[0x542f2e5]['displacement'],
        'domain_note': 'All raw u64 tags modeled; original Rust enum validity is not established',
        'proof_phases': [
            {'start': START, 'end': 0x542f2ad,
             'observation': 'Full-width sentinel-membership disagreement returns AL=0'},
            {'start': 0x542f2ad, 'end': 0x542f2c2,
             'observation': 'Either low-width sentinel tag returns AL=1'},
            {'start': 0x542f2c2, 'end': 0x542f2db,
             'observation': 'Word at offset 16 must be equal; zero and nonzero routes agree'},
            {'start': 0x542f2db, 'end': 0x542f2f6,
             'observation': 'Left low tag 1 requires right low bit 1 and equal offset 8; other left tags require right low bit 0'},
            {'start': 0x542f2f6, 'end': 0x542f30f,
             'observation': 'Word at offset 24 must be equal; zero and nonzero routes agree'},
            {'start': 0x542f30f, 'end': END,
             'observation': 'Compare offset 32 and return the equality condition in AL'},
        ],
    }


def model(left, right):
    """Independent value model. Only AL is a specified result, not all of RAX."""
    require(len(left) == len(right) == 5, 'Expected five raw words per record')
    require(all(type(x) is int and 0 <= x < 1 << 64 for x in (*left, *right)),
            'Words must be unsigned 64-bit values')
    a, b = left[0], right[0]
    if (a == 2) != (b == 2):
        return 0
    a32, b32 = a & 0xffffffff, b & 0xffffffff
    if a32 == 2 or b32 == 2:
        return 1
    if left[2] != right[2]:
        return 0
    if a32 == 1:
        if not b & 1 or left[1] != right[1]:
            return 0
    elif b & 1:
        return 0
    return int(left[3] == right[3] and left[4] == right[4])


def vectors():
    """Manually derived branch/boundary witnesses, not target executions."""
    maximum = (1 << 64) - 1
    cases = [
        ('both-sentinel-ignore-payload', [2, 1, 2, 3, 4], [2, 9, 8, 7, 6], 1),
        ('left-sentinel-only', [2, 0, 0, 0, 0], [0, 0, 0, 0, 0], 0),
        ('right-sentinel-only', [0, 0, 0, 0, 0], [2, 0, 0, 0, 0], 0),
        ('zero-tag-ignore-word-one', [0, 1, 0, 0, 0], [0, maximum, 0, 0, 0], 1),
        ('one-tag-equal-extremes', [1, maximum, maximum, maximum, maximum],
         [1, maximum, maximum, maximum, maximum], 1),
        ('one-tag-word-one-mismatch', [1, 0, 0, 0, 0], [1, 1, 0, 0, 0], 0),
        ('one-zero-tag', [1, 0, 0, 0, 0], [0, 0, 0, 0, 0], 0),
        ('zero-one-tag', [0, 0, 0, 0, 0], [1, 0, 0, 0, 0], 0),
        ('word-two-zero-left', [0, 0, 0, 0, 0], [0, 0, maximum, 0, 0], 0),
        ('word-two-zero-right', [0, 0, maximum, 0, 0], [0, 0, 0, 0, 0], 0),
        ('word-two-nonzero-mismatch', [0, 0, 1, 0, 0], [0, 0, maximum, 0, 0], 0),
        ('word-three-zero-left', [0, 0, 1, 0, 0], [0, 0, 1, maximum, 0], 0),
        ('word-three-zero-right', [0, 0, 1, maximum, 0], [0, 0, 1, 0, 0], 0),
        ('word-three-nonzero-mismatch', [0, 0, 1, 1, 0], [0, 0, 1, maximum, 0], 0),
        ('word-four-high-bit-mismatch', [0, 0, 1, 1, 0], [0, 0, 1, 1, 1 << 63], 0),
        ('word-four-full-width-match', [0, 0, 1, 1, maximum], [0, 0, 1, 1, maximum], 1),
        ('wide-two-vs-actual-sentinel', [(1 << 32) + 2, 0, 0, 0, 0], [2, 0, 0, 0, 0], 0),
        ('wide-two-left-bypasses-payload', [(1 << 32) + 2, 1, 2, 3, 4], [0, 9, 8, 7, 6], 1),
        ('wide-two-right-bypasses-payload', [0, 1, 2, 3, 4], [(1 << 32) + 2, 9, 8, 7, 6], 1),
        ('wide-one-compares-word-one', [(1 << 32) + 1, 7, 0, 0, 0], [3, 7, 0, 0, 0], 1),
        ('wide-one-word-one-mismatch', [(1 << 32) + 1, 7, 0, 0, 0], [3, 8, 0, 0, 0], 0),
        ('arbitrary-tags-asymmetric-forward', [3, 0, 0, 0, 0], [0, 0, 0, 0, 0], 1),
        ('arbitrary-tags-asymmetric-reverse', [0, 0, 0, 0, 0], [3, 0, 0, 0, 0], 0),
    ]
    return [{'name': n, 'left': a, 'right': b, 'al': result} for n, a, b, result in cases]


def offset(secs, va, size):
    candidates = [s for s in secs if s['type'] != 8 and s['flags'] & 2
                  and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(candidates) == 1, 'Non-unique allocated ELF mapping')
    return candidates[0]['offset'] + va - candidates[0]['address']


def bytes_at(data, secs, va, size):
    pos = offset(secs, va, size)
    require(pos + size <= len(data), 'ELF mapping exceeds file')
    return data[pos:pos + size]


def frame_record(data, secs, frame, cies):
    result = dict(frame)
    for key in ('fde', 'cie'):
        va = frame[key]
        size = struct.unpack('<I', bytes_at(data, secs, va, 4))[0] + 4
        raw = bytes_at(data, secs, va, size)
        result[key + '_record'] = {'va': va, 'file_offset': offset(secs, va, size),
                                  'size': size, 'bytes': raw.hex(), 'sha256': digest(raw)}
    result['cie_fields'] = cies[frame['cie']]
    return result


def scan_rel32(data, text, target):
    """All byte positions admitting a complete E8/E9 rel32 within .text.

    This is intentionally an encoding census, not a whole-section decoder.
    The retained hit is separately decoded in its measured caller excerpt.
    """
    rows = []
    begin, end = text['offset'], text['offset'] + text['size']
    for opcode in (b'\xe8', b'\xe9'):
        pos = begin
        while True:
            pos = data.find(opcode, pos, end - 4)
            if pos < 0:
                break
            va = text['address'] + pos - begin
            rel = struct.unpack_from('<i', data, pos + 1)[0]
            if va + 5 + rel == target:
                rows.append({'va': va, 'file_offset': pos, 'opcode': opcode.hex(),
                             'target': target, 'bytes': data[pos:pos + 5].hex()})
            pos += 1
    return sorted(rows, key=lambda row: row['va'])


def analyze(data):
    authenticate(data)  # No admitted alternate digest or bypass switch.
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text']
    require(len(text) == 1, 'Ambiguous .text')
    text = text[0]
    require(text['address'] == TEXT_START and text['address'] + text['size'] == TEXT_END
            and text['flags'] == 6, 'Unexpected .text geometry/flags')
    cies, fdes = eh_frame_records(data, secs)
    overlapping = [f for f in fdes if f['start'] < END and START < f['end']]
    require(overlapping == [{'fde': FDE_VA, 'cie': CIE_VA, 'start': START, 'end': END, 'lsda': None}],
            'Leaf FDE ownership mismatch')
    frame = frame_record(data, secs, overlapping[0], cies)
    bind_fde(bytes.fromhex(frame['fde_record']['bytes']), FDE_VA,
             bytes.fromhex(frame['cie_record']['bytes']))
    body = bytes_at(data, secs, START, END - START)
    instructions = bind_body(body)
    previous_end = max(f['end'] for f in fdes if f['end'] <= START)
    next_start = min(f['start'] for f in fdes if f['start'] >= END)
    require((previous_end, next_start) == (0x542f283, 0x542f320), 'Neighbor FDE geometry mismatch')
    padding = []
    for start, end in ((previous_end, START), (END, next_start)):
        raw = bytes_at(data, secs, start, end - start)
        require(raw == b'\xcc' * (end - start), 'INT3 padding mismatch')
        padding.append({'start': start, 'end': end, 'size': len(raw), 'bytes': raw.hex()})
    hits = scan_rel32(data, text, START)
    require([(h['va'], h['opcode']) for h in hits] == [(CALL_SITE, 'e8')], 'Direct caller census mismatch')
    owners = [f for f in fdes if f['start'] <= CALL_SITE and CALL_SITE + 5 <= f['end']]
    require(len(owners) == 1 and owners[0]['start'] == CALLER_START
            and owners[0]['end'] == CALLER_END, 'Caller FDE mismatch')
    caller_frame = frame_record(data, secs, owners[0], cies)
    context = bytes_at(data, secs, CONTEXT_START, CONTEXT_END - CONTEXT_START)
    caller_rows = bind_caller(context)
    location_code = bytes_at(data, secs, LOCATION_SITE, 7)
    location_rows = decode(location_code, LOCATION_SITE)
    require(len(location_rows) == 1 and location_rows[0].get('rip_target') == LOCATION,
            'Source Location LEA mismatch')
    require(CALLER_START <= LOCATION_SITE < CALLER_END, 'Location outside caller')
    location_raw = bytes_at(data, secs, LOCATION, 24)
    pointer, length, line, column = struct.unpack('<QQII', location_raw)
    require((pointer, length, line, column) == (0, len(SOURCE), 231, 9), 'Source Location layout mismatch')
    rela = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'Unexpected RELA layout')
    relocations, leaf_relocations = [], []
    for pos in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, pos)
        if START <= address < END:
            leaf_relocations.append({'offset_va': address, 'info': info, 'addend': addend})
        if address == LOCATION:
            relocations.append({'file_offset': pos, 'offset_va': address,
                                'info': info, 'addend': addend, 'bytes': data[pos:pos + 24].hex()})
    require(len(relocations) == 1 and relocations[0]['info'] == 8
            and relocations[0]['addend'] == 0x44e7fd, 'Source relocation mismatch')
    path_bytes = bytes_at(data, secs, relocations[0]['addend'], length)
    require(path_bytes.decode('ascii') == SOURCE, 'Source path mismatch')
    require(not leaf_relocations, 'Unexpected relocation into the leaf')
    callees = [row for row in instructions if row['op'] == 'call']
    result = {
        'task': 'RE-001', 'component': 'l1-shared', 'target_release': 115,
        'target_sha256': SHA, 'target_size': len(data), 'base_commit': BASE_COMMIT,
        'coordinates': 'Original ELF virtual addresses; half-open extents; no rebasing',
        'function': {'start': START, 'end': END, 'size': len(body),
                     'file_offset': offset(secs, START, len(body)), 'body_sha256': digest(body),
                     'body_bytes': body.hex(), 'frame': frame, 'instructions': instructions,
                     'padding': padding, 'callees': callees, 'indirect_transfers': [],
                     'relocations_into_body': leaf_relocations,
                     'static_data_references': [], 'return_contract': 'AL only; upper RAX is unspecified',
                     'writes': [], 'normalization_masks': []},
        'caller_census': {'section': text, 'method': 'Full .text E8/E9 rel32 byte-position scan',
                          'hits': hits, 'owner_frame': caller_frame,
                          'context_start': CONTEXT_START, 'context_end': CONTEXT_END,
                          'context_sha256': digest(context), 'instructions': caller_rows,
                          'limitation': 'One locally decoded CALL site; caller body and other entry edges are not bound'},
        'source_association': {'status': 'Observed caller association; leaf source ownership remains inferred',
                               'lea_instructions': location_rows, 'location_va': LOCATION,
                               'location_bytes': location_raw.hex(), 'path': SOURCE,
                               'path_va': relocations[0]['addend'], 'path_bytes': path_bytes.hex(),
                               'line': line, 'column': column, 'relocation': relocations[0]},
        'rule': extract_rule(instructions),
        'vectors': vectors(),
    }
    result['counts'] = {
        'bound_functions': 1, 'body_bytes': len(body), 'instructions': len(instructions),
        'callee_count': len(callees), 'indirect_transfer_count': 0, 'caller_sites': len(hits),
        'caller_fdes': len(owners), 'tail_call_sites': sum(h['opcode'] == 'e9' for h in hits),
        'text_bytes_scanned': text['size'], 'padding_before': padding[0]['size'],
        'padding_after': padding[1]['size'], 'return_sites': sum(r['op'] == 'ret' for r in instructions),
        'vectors': len(result['vectors']),
    }
    return result


def render_readme(r):
    f, c, a = r['function'], r['counts'], r['source_association']
    counts = '\n'.join(f'| {key} | {value} |' for key, value in c.items())
    walk = '\n'.join(f"| {i['va']:#x} | `{i['bytes']}` | `{i['op']} {i['operands']}` |"
                     for i in f['instructions'])
    return f'''# RE-001: guarded word equality in node #{r['target_release']}

- Component: `{r['component']}`; function-map work associated with the raw-signature tracker.
- Target: `artifacts/node/115/hl-node`, SHA-256 `{r['target_sha256']}`.
- Base/source revision: `{r['base_commit']}`. No external inferred source was copied.
- Bounded question: exactly which raw words determine AL at `{f['start']:#x}`, including mixed-width tag tests?
- Status: complete local instruction relation observed; source/type names remain inferred.
- Intended new files: this packet, `tools/node115_guarded_word_equality.py`, and `tests/test_node115_guarded_word_equality.py`.

For readable, stable records with raw words A and B, AL is false if exactly one
full-width tag equals the sentinel. Otherwise AL is true immediately if either
low-width tag equals the sentinel. On the remaining path, words at the required
payload offsets must match. If A's low tag equals the payload tag,
B's low tag bit must be set and the conditional payload word must also match;
otherwise B's low tag bit must be clear. The constants and offsets are extracted
below. The leaf reads memory and returns AL; it has no writes or opaque helper
effects. It does not promise a canonical boolean in the whole RAX register.

## Measured extent and counts

Original ELF VA window: `{f['start']:#x}..{f['end']:#x}`;
file offset `{f['file_offset']:#x}`; body SHA-256 `{f['body_sha256']}`.
Actual FDE at `{f['frame']['fde']:#x}` (file offset `{f['frame']['fde_record']['file_offset']:#x}`),
CIE at `{f['frame']['cie']:#x}` (file offset `{f['frame']['cie_record']['file_offset']:#x}`),
augmentation `{f['frame']['cie_fields']['augmentation']}`, no LSDA.
The neighboring gaps are all INT3. Padding is excluded from the body hash.
The FDE, complete instruction walk, internal branch destinations, entry-reachable
CFG and terminal RETs agree on the bounded extent. This is not a whole-node
function denominator. Callee identities/extents are the empty set: every
transfer in this leaf is an internal conditional/unconditional branch or RET.

All measured counts in this README come from `records.json`:

| Metric | Count |
| --- | ---: |
{counts}

## Rule and byte proof

Let `A[i]` and `B[i]` be unsigned {r['rule']['word_bits']}-bit words and
`a = A[0] & 0xffffffff`, `b = B[0] & 0xffffffff`.
The sentinel is {r['rule']['full_width_sentinel']}; the payload tag and right-tag
mask are {r['rule']['left_payload_tag']} and {r['rule']['right_tag_mask']}.
The required equal payload offsets after the low-tag gate are
`{r['rule']['required_equal_payload_offsets_after_low_tag_gate']}`;
the conditional payload offset is `{r['rule']['conditionally_compared_payload_offset']}`.

```
if (A[0] == 2) != (B[0] == 2): return AL=0
if a == 2 or b == 2: return AL=1
if A[2] != B[2]: return AL=0
if a == 1:
    if (b & 1) == 0 or A[1] != B[1]: return AL=0
else:
    if (b & 1) != 0: return AL=0
return AL = (A[3] == B[3] and A[4] == B[4])
```

The initial RDX/RCX comparisons and SETNE/XOR detect whether exactly one raw
tag is the sentinel. Later EDX/ECX comparisons truncate the tags before
SETNE/TEST. MOV AL does not change flags. At each payload word with an explicit
zero branch, the zero and nonzero routes together implement full-width equality.
The last CMP/SETE supplies AL on the surviving path. Loads of later words are
skipped on earlier failures; there is no assumption that ignored payload is
initialized or dereferenced. A valid stack for RET and memory for each actual
load, with no concurrent mutation, are preconditions. Aliasing of the records
does not add a write hazard.

On conventional tag values `0`, `1`, `2`, this is equality with an ignored
payload for tag `2`, an ignored conditional word for tag `0`, and a compared
conditional word for tag `1`. Those are a useful restricted-domain interpretation,
not recovered enum names. For arbitrary raw tags the relation can be asymmetric:
the recorded asymmetric-forward/reverse witnesses demonstrate this. High tag
bits also distinguish the full sentinel gate from the low-tag shortcut. The
independent Python model preserves these details; the retained vectors are
manually derived from these branches, not observations of target execution.

## Complete instruction walk

The strict Python decoder consumes all body bytes. It resolves signed relative
branches, decodes immediate widths and memory displacements, and rejects unknown
opcode/register forms. The body digest and frame bytes additionally pin the
accepted operands. No normalization masks are applied.

| ELF VA | Raw bytes | Decoded instruction |
| --- | --- | --- |
{walk}

## Caller census and source association

The producer scans every byte position that can hold a complete E8 or E9 rel32
in `.text` (`{TEXT_START:#x}..{TEXT_END:#x}`). It retains every hit in JSON,
including its raw bytes, then separately decodes the matching caller excerpt.
CALL at `{CALL_SITE:#x}` belongs to FDE `{CALLER_START:#x}..{CALLER_END:#x}`.
The excerpt sets RDI to `r13+0x8` and RSI to `rsp+0x10` before the call, after
a separate outer byte comparison. The subsequent jump preserves the returned
AL. The complete caller's behavior and stack/type construction are not bound.
Raw scanning is an exhaustive direct-encoding census, not a proof about indirect
calls, pointers, alternate entrypoints, or a whole-section instruction decode.
The original focused GNU disassembly agreed with this local CALL boundary;
regeneration relies only on Python and the pinned excerpt bytes.

Within that same caller FDE, RIP-relative LEA at `{LOCATION_SITE:#x}` references
Location `{a['location_va']:#x}`. Its actual R_X86_64_RELATIVE relocation resolves
the on-disk null pointer to path bytes at `{a['path_va']:#x}`. The location reads
`{a['path']}:{a['line']}:{a['column']}`. The retained path is relative in the ELF.
This associates the caller with first-party code. It does not prove the leaf's
original source name, enum type, or first-party authorship; compiler-generated
equality remains a plausible inference. No behavior of the caller's other
callees is bound or included in the leaf's empty callee set.

## Novelty, provenance and reproduction

Before packet creation, these exact searches returned empty stdout, empty
stderr and exit status `1` for each command:

```sh
rg -i '542f290' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '88273552' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'guarded-word-equality|guarded_word_equality' research/work-items tools tests ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no bound callees requiring additional address novelty searches.
These are historical pre-addition checks at the recorded base revision; running
them after adding this packet will find this packet. The selected start is in
the assigned band and outside the excluded band and claimed-address list.
Existing merged tagged-count, u8-rejection, numeric-selector and
weighted-comparison packets were reviewed; no existing packet/tool/test is edited.

From repository root, with the authenticated artifact present:

```sh
python3 tools/node115_guarded_word_equality.py --out research/work-items/RE-001-node115-guarded-word-equality/
python3 -m unittest tests.test_node115_guarded_word_equality -v
python3 research/work-items/RE-001-node115-guarded-word-equality/verify.py
make verify
make catalogue-check
```

The generator authenticates the complete input before parsing or output creation
and uses a read-only mapping rather than copying the full binary. The semantic
JSON and this README regenerate deterministically; authored verifier/code/tests
are covered by the exact manifest whitelist, including the shared ELF/FDE readers.
The generator requires Python 3.10+ stdlib only. Discovery used Linux x86-64,
Python 3.13.5 and GNU binutils 2.44. No connected REA tools were exposed;
doctor reported Ghidra and Java unavailable. Native
tools were used only for discovery and a cross-check, not by generator, verifier
or tests. The focused discovery command was:

```sh
objdump -d -M intel --start-address=0x542f290 --stop-address=0x542f31b artifacts/node/115/hl-node
```

The retained raw instruction/frame/relocation bytes preserve the evidence
without depending on native text rendering. Wrong digest, modified leaf bytes,
branch/displacement changes, shifted FDE, changed caller target, malformed
decoder inputs and manifest/record corruption are negative controls. Tests
also require README metrics to equal JSON and exact regeneration of the README.
The leaf has no callee target to mutate; the actual incoming CALL target is
corrupted instead. No captured node/visor, emulator, network or install is used.

## Results, non-claims and next step

Before: this address had no retained bind in the checked research and PR lists.
After: the complete local read/branch/AL relation and a caller association are
reproducible from the pinned target. This is a static function bind with a small
independent Python value model. It is not a recovered Rust implementation,
source-build comparison, target execution, full caller bind, or original ABI/type
recovery. No compiler/linker equivalence, Cargo graph, whole-ELF/data/vtable
closure, signature-validation policy or protocol behavior is claimed. Runtime
faults from unreadable memory, stack faults, asynchronous mutation and alternate
entry into the body are outside the normal-return theorem. No progress gate is
requested; all full-scope gates remain unchanged.

Next: establish how the caller constructs the compared records and constrains
their tags before assigning source-level type or signature-tracking meaning.
'''


def json_bytes(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode()


def generated_files(data):
    record = analyze(data)
    return {'records.json': json_bytes(record), 'README.md': render_readme(record).encode()}


def manifest_bytes(payloads):
    lines = []
    for name in WHITELIST:
        content = payloads[name] if name in payloads else (ROOT / name).read_bytes()
        lines.append(f'{digest(content)}  {name}\n')
    return ''.join(lines).encode()


def generate(binary, output):
    with Path(binary).open('rb') as stream:
        # Empty files cannot be mapped; report the same fail-closed identity error.
        require(stream.seek(0, 2) == SIZE, 'Node #115 size/digest mismatch')
        stream.seek(0)
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            payloads = generated_files(data)
    payloads['verify.py'] = (PACKET / 'verify.py').read_bytes()
    payloads['MANIFEST.sha256'] = manifest_bytes(payloads)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, content in payloads.items():
        (output / name).write_bytes(content)
    return json.loads(payloads['records.json'])['counts']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, default=PACKET)
    args = parser.parse_args()
    print(json.dumps(generate(args.binary, args.out), sort_keys=True))


if __name__ == '__main__':
    main()
