#!/usr/bin/env python3
"""Bind one node #115 subtraction leaf using static, stdlib-only decoding.

The decoders deliberately support only the operand forms used in this packet.
They reject unknown instructions, truncated operands and unconsumed bytes.
No captured code, native disassembler or instruction emulator is invoked.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
SLUG = 'RE-001-node115-sub256-borrow'
PACKET = ROOT / 'research/work-items' / SLUG
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END, NEXT = 0x2ccdd80, 0x2ccddb1, 0x2ccddc0
CALLER_START, CALLER_END = 0x2c70160, 0x2c70fd9
SITES = (0x2c70e23, 0x2c70e87, 0x2c70eca)
CONTEXT_STARTS = (0x2c70e0e, 0x2c70e72, 0x2c70eb5)
SOURCE_SITE, LOCATION = 0x2c70f64, 0x6487478
FRAME_PINS = {
    START: (END, 0xd8b2b8, 0xca6ed8, None,
            '10000000e4430e00c02af4013100000000000000',
            '1400000000000000017a5200017810011b0c070890010000'),
    CALLER_START: (CALLER_END, 0x118deec, 0x103d604, 0x27037c,
                   '50000000ec0815006c22ae01790e0000047f240eff410e10420e18420e20420e28420e30410e38470ec00683078c068d058e048f03860203eb020e38410e30420e28420e20420e18420e10410e08410ec0060000',
                   '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_offset(secs, va, size):
    require(size >= 0, 'negative read size')
    matches = [s['offset'] + va - s['address'] for s in secs
               if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'ambiguous or unmapped VA interval')
    return matches[0]


def read_va(data, secs, va, size):
    off = file_offset(secs, va, size)
    return data[off:off + size]


def operand(kind, name=None, offset=None, bits=None):
    row = {'kind': kind}
    if name is not None:
        row['name' if kind == 'reg' else 'base'] = name
    if offset is not None:
        row['offset'] = offset
    if bits is not None:
        row['bits'] = bits
    return row


def reg(name, bits):
    return operand('reg', name, bits=bits)


def mem(base, offset, bits):
    return operand('mem', base, offset, bits)


def insn(va, raw, mnemonic, operands, **extra):
    return dict(va=va, hex=raw.hex(), size=len(raw), mnemonic=mnemonic,
                operands=operands, **extra)


def decode_leaf(body, start=START):
    """Decode all bytes; ModRM is restricted to RAX/XMM0 and RSI/RDX/RDI.

    SUB is accepted as well as SBB at any arithmetic row so semantic mutation
    tests can observe the changed carry relation before the certificate rejects.
    SETAE is similarly decoded, never admitted by the subtraction certificate.
    """
    rows, p = [], 0
    while p < len(body):
        begin = p
        if body[p] == 0xc3:
            p += 1
            rows.append(insn(start + begin, body[begin:p], 'ret', []))
            continue
        require(p + 3 <= len(body), 'truncated leaf opcode')
        prefix, opcode, modrm = body[p:p + 3]
        p += 3
        mode, field, base_code = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        require(mode in (0, 1) and field == 0 and base_code in (2, 6, 7),
                'unsupported leaf ModRM')
        displacement = 0
        if mode == 1:
            require(p < len(body), 'truncated leaf displacement')
            displacement = struct.unpack_from('<b', body, p)[0]
            p += 1
        base = {2: 'rdx', 6: 'rsi', 7: 'rdi'}[base_code]
        if prefix == 0x48 and opcode in (0x8b, 0x29, 0x19):
            memory = mem(base, displacement, 64)
            mnemonic = {0x8b: 'mov', 0x29: 'sub', 0x19: 'sbb'}[opcode]
            args = [reg('rax', 64), memory] if opcode == 0x8b else [memory, reg('rax', 64)]
        elif prefix == 0x0f and opcode in (0x10, 0x11):
            mnemonic = 'movups'
            memory = mem(base, displacement, 128)
            args = [reg('xmm0', 128), memory] if opcode == 0x10 else [memory, reg('xmm0', 128)]
        elif prefix == 0x0f and opcode in (0x92, 0x93):
            mnemonic = 'setb' if opcode == 0x92 else 'setae'
            args = [mem(base, displacement, 8)]
        else:
            raise ValueError('unsupported leaf opcode')
        rows.append(insn(start + begin, body[begin:p], mnemonic, args))
    return rows


def certify_leaf(rows):
    """Check the whole load/borrow/copy/store sequence, not a byte substring."""
    expected = []
    for displacement in (0, 8, 16, 24):
        expected.append(('mov', [reg('rax', 64), mem('rdx', displacement, 64)]))
        expected.append(('sub' if displacement == 0 else 'sbb',
                         [mem('rsi', displacement, 64), reg('rax', 64)]))
    for displacement in (0, 16):
        expected.extend([
            ('movups', [reg('xmm0', 128), mem('rsi', displacement, 128)]),
            ('movups', [mem('rdi', displacement, 128), reg('xmm0', 128)]),
        ])
    expected.extend([('setb', [mem('rdi', 32, 8)]), ('ret', [])])
    require([(r['mnemonic'], r['operands']) for r in rows] == expected,
            'leaf semantic certificate changed')
    require(rows[0]['va'] == START and rows[-1]['va'] + rows[-1]['size'] == END,
            'leaf instruction extent changed')
    require(all(a['va'] + a['size'] == b['va'] for a, b in zip(rows, rows[1:])),
            'noncontiguous leaf instructions')
    arithmetic = [r for r in rows if r['mnemonic'] in ('sub', 'sbb')]
    return {
        'limb_bits': arithmetic[0]['operands'][0]['bits'],
        'limb_offsets': [r['operands'][0]['offset'] for r in arithmetic],
        'limb_count': len(arithmetic),
        'integer_bits': sum(r['operands'][0]['bits'] for r in arithmetic),
        'left_base': arithmetic[0]['operands'][0]['base'],
        'right_base': rows[0]['operands'][1]['base'],
        'output_base': rows[-2]['operands'][0]['base'],
        'output_borrow_offset': rows[-2]['operands'][0]['offset'],
        'copy_offsets': [r['operands'][0]['offset'] for r in rows
                         if r['mnemonic'] == 'movups' and r['operands'][0]['kind'] == 'mem'],
        'copy_bits': 128,
        'result_relation': 'left := (left - right) mod 2**256; output[0:32] := left; output[32] := int(original_left < original_right)',
        'assumptions': [
            'Readable right[0:32], readable/writable left[0:32], writable output[0:33], valid return stack.',
            'The three buffers are pairwise disjoint and do not overlap executable code or the return-address slot; ordinary stable memory without concurrent mutation.',
            'Little-endian limbs in increasing significance; no claim about the original Rust type or ABI.',
        ],
        'register_result': 'RAX retains the last loaded right limb; no scalar integer result in RAX is claimed.',
    }


def decode_context(body, start):
    """Strictly decode the focused stack-argument/CALL/borrow-test sequences."""
    rows, p = [], 0
    while p < len(body):
        begin = p
        if body[p:p + 2] == b'\x48\x8d':
            require(p + 4 <= len(body), 'truncated context LEA')
            modrm, sib = body[p + 2:p + 4]
            require(modrm in (0x7c, 0xb4, 0x94) and sib == 0x24,
                    'unsupported context LEA')
            width = 1 if modrm == 0x7c else 4
            require(p + 4 + width <= len(body), 'truncated context displacement')
            disp = int.from_bytes(body[p + 4:p + 4 + width], 'little', signed=True)
            p += 4 + width
            args = [reg({0x7c: 'rdi', 0xb4: 'rsi', 0x94: 'rdx'}[modrm], 64),
                    operand('address', 'rsp', disp)]
            row = insn(start + begin, body[begin:p], 'lea', args)
        elif body[p] == 0xe8:
            require(p + 5 <= len(body), 'truncated context CALL')
            p += 5
            target = start + p + struct.unpack_from('<i', body, begin + 1)[0]
            row = insn(start + begin, body[begin:p], 'call', [], target=target)
        elif body[p:p + 3] == b'\x80\x7c\x24':
            require(p + 5 <= len(body), 'truncated context CMP')
            disp = struct.unpack_from('<b', body, p + 3)[0]
            immediate = body[p + 4]
            p += 5
            row = insn(start + begin, body[begin:p], 'cmp',
                       [mem('rsp', disp, 8), {'kind': 'imm', 'value': immediate, 'bits': 8}])
        elif body[p:p + 2] == b'\x0f\x85':
            require(p + 6 <= len(body), 'truncated context JNE')
            p += 6
            target = start + p + struct.unpack_from('<i', body, begin + 2)[0]
            row = insn(start + begin, body[begin:p], 'jne', [], target=target)
        else:
            raise ValueError('unsupported context opcode')
        rows.append(row)
    return rows


def certify_context(rows, index):
    require([r['mnemonic'] for r in rows] == ['lea', 'lea', 'lea', 'call', 'cmp', 'jne'],
            'caller context instruction sequence changed')
    offsets = (0x20, (0x240, 0x280, 0x2a0)[index], (0x80, 0x80, 0x170)[index])
    for row, name, disp in zip(rows[:3], ('rdi', 'rsi', 'rdx'), offsets):
        require(row['operands'] == [reg(name, 64), operand('address', 'rsp', disp)],
                'caller argument offsets changed')
    require(rows[3]['va'] == SITES[index] and rows[3]['target'] == START,
            'wrong caller callee target')
    require(rows[4]['operands'] == [mem('rsp', 0x40, 8), {'kind': 'imm', 'value': 0, 'bits': 8}],
            'caller borrow test changed')
    require(rows[5]['target'] == 0x2c70c50, 'caller borrow edge changed')
    return {'output_stack_offset': offsets[0], 'left_stack_offset': offsets[1],
            'right_stack_offset': offsets[2], 'borrow_stack_offset': 0x40,
            'nonzero_borrow_edge': rows[5]['target']}


def check_frames(data, secs):
    cies, fdes = eh_frame_records(data, secs)
    indexed_secs, index = unwind_index(data)
    require(indexed_secs == secs, 'inconsistent ELF sections')
    selected = {}
    for start, (end, fde_va, cie_va, lsda, fde_hex, cie_hex) in FRAME_PINS.items():
        owners = [f for f in fdes if f['start'] < end and start < f['end']]
        require(owners == [dict(fde=fde_va, cie=cie_va, start=start, end=end, lsda=lsda)],
                'exact FDE extent/identity changed')
        entries = [i for i in index if i['start'] == start]
        require(len(entries) == 1 and entries[0]['fde'] == fde_va,
                'FDE/index disagreement')
        row = dict(owners[0])
        for role, va, expected in (('fde_record', fde_va, fde_hex), ('cie_record', cie_va, cie_hex)):
            off = file_offset(secs, va, 4)
            length = struct.unpack_from('<I', data, off)[0] + 4
            require(length == len(bytes.fromhex(expected)), 'frame record length changed')
            raw = read_va(data, secs, va, length)
            require(raw.hex() == expected, 'frame record bytes changed')
            row[role] = {'va': va, 'file_offset': off, 'hex': raw.hex(), 'sha256': sha(raw)}
        row['cie_fields'] = cies[cie_va]
        row['unwind_index'] = entries[0]
        selected[start] = row
    require(selected[START]['unwind_index']['next_index_upper_bound'] == NEXT,
            'next unwind start changed')
    return selected, fdes


def scan_rel32(data, section, target):
    """Every byte of .text is considered; retain CALL and JMP candidates.

    A byte-pattern census alone is not an instruction-boundary or reachability
    proof. Focused contexts are decoded separately for the retained hits.
    """
    hits = []
    lo, hi = section['offset'], section['offset'] + section['size']
    for opcode in (0xe8, 0xe9):
        pos = lo
        while True:
            pos = data.find(bytes([opcode]), pos, hi - 4)
            if pos < 0:
                break
            va = section['address'] + pos - lo
            destination = va + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if destination == target:
                hits.append({'site': va, 'file_offset': pos, 'hex': data[pos:pos + 5].hex(),
                             'mnemonic': 'call' if opcode == 0xe8 else 'jmp', 'target': destination})
            pos += 1
    return sorted(hits, key=lambda row: row['site'])


def source_context(data, secs):
    raw = read_va(data, secs, SOURCE_SITE, 7)
    require(raw[:3] == b'\x48\x8d\x35', 'source Location LEA opcode changed')
    dest = SOURCE_SITE + 7 + struct.unpack_from('<i', raw, 3)[0]
    require(dest == LOCATION, 'source Location LEA target changed')
    lea = insn(SOURCE_SITE, raw, 'lea',
               [reg('rsi', 64), operand('address', 'rip', struct.unpack_from('<i', raw, 3)[0])],
               target=dest)
    rela = [s for s in secs if s['name'] == '.rela.dyn']
    require(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'invalid relocation section')
    bindings = []
    for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == LOCATION:
            bindings.append({'file_offset': off, 'slot': slot, 'info': info, 'addend': addend,
                             'hex': data[off:off + 24].hex()})
    require(len(bindings) == 1 and bindings[0]['info'] == 8
            and bindings[0]['addend'] == 0x43f393, 'source relocation binding changed')
    location_bytes = read_va(data, secs, LOCATION, 24)
    pointer, length, line, column = struct.unpack('<QQII', location_bytes)
    require((pointer, length, line, column) == (0, 23, 6, 1), 'source Location fields changed')
    path_bytes = read_va(data, secs, bindings[0]['addend'], length)
    require(path_bytes == b'l1/src/qtys/impl_wei.rs', 'source path changed')
    return {'owner_start': CALLER_START, 'owner_end': CALLER_END, 'instruction': lea,
            'location_va': LOCATION, 'location_hex': location_bytes.hex(),
            'relocation': bindings[0], 'path_va': bindings[0]['addend'],
            'path_hex': path_bytes.hex(), 'path': path_bytes.decode('ascii'),
            'path_length': length, 'line': line, 'column': column,
            'scope': 'A first-party Location reference in the same caller FDE; not a recovered function name or proof of leaf ownership.'}


def model(left, right, bits=256):
    """Independent scalar formulation, for disjoint valid buffers only."""
    require(type(left) is int and type(right) is int and 0 <= left < 1 << bits
            and 0 <= right < 1 << bits, 'model inputs outside unsigned domain')
    return (left - right) % (1 << bits), int(left < right)


def instruction_equations(rows, left, right):
    """Evaluate the decoded limb recurrence, not machine instructions or memory.

    This exposes the consequences of real SUB/SBB and SETB/SETAE counterfacts.
    There is no PC, native state, stack, pointer or instruction execution.
    """
    result, borrow = 0, 0
    for row in rows:
        if row['mnemonic'] in ('sub', 'sbb'):
            dest = row['operands'][0]
            width, shift = dest['bits'], dest['offset'] * 8
            mask = (1 << width) - 1
            a, b = (left >> shift) & mask, (right >> shift) & mask
            difference = a - b - (borrow if row['mnemonic'] == 'sbb' else 0)
            borrow = int(difference < 0)
            result |= (difference & mask) << shift
    flag = next(r['mnemonic'] for r in rows if r['mnemonic'] in ('setb', 'setae'))
    return result, borrow if flag == 'setb' else 1 - borrow


def vectors(rows, rule):
    bits, width = rule['integer_bits'], rule['limb_bits']
    maximum = (1 << bits) - 1
    values = {0, 1, 2, maximum - 1, maximum}
    for shift in range(width, bits, width):
        values.update((2**shift - 1, 2**shift, 2**shift + 1))
    values.update((2**(bits - 1) - 1, 2**(bits - 1), 2**(bits - 1) + 1))
    output = []
    for left in sorted(values):
        for right in sorted(values):
            result, borrow = instruction_equations(rows, left, right)
            require((result, borrow) == model(left, right, bits), 'limb equations disagree with scalar rule')
            output.append({'left_hex': f'{left:064x}', 'right_hex': f'{right:064x}',
                           'result_hex': f'{result:064x}', 'borrow': borrow})
    return output


def build_records(data):
    """Authenticate before parsing; private component checks remain testable."""
    require(sha(data) == SHA, 'node #115 digest mismatch')
    secs = sections(data)
    texts = [s for s in secs if s['name'] == '.text']
    require(len(texts) == 1 and texts[0]['flags'] & 4
            and texts[0]['address'] == 0x1419300
            and texts[0]['address'] + texts[0]['size'] == 0x63f0a00,
            'target .text mapping changed')
    frames, fdes = check_frames(data, secs)
    body = read_va(data, secs, START, END - START)
    instructions = decode_leaf(body)
    rule = certify_leaf(instructions)
    padding = read_va(data, secs, END, NEXT - END)
    require(padding == b'\xcc' * (NEXT - END), 'INT3 padding changed')
    hits = scan_rel32(data, texts[0], START)
    require([(h['site'], h['mnemonic']) for h in hits] == [(s, 'call') for s in SITES],
            'direct caller candidate census changed')
    for index, hit in enumerate(hits):
        owners = [f for f in fdes if f['start'] <= hit['site'] and hit['site'] + 5 <= f['end']]
        require(len(owners) == 1 and owners[0]['start'] == CALLER_START,
                'caller FDE ownership changed')
        begin, end = CONTEXT_STARTS[index], hit['site'] + 16
        raw = read_va(data, secs, begin, end - begin)
        decoded = decode_context(raw, begin)
        args = certify_context(decoded, index)
        hit.update(owner_start=owners[0]['start'], owner_end=owners[0]['end'],
                   context={'start': begin, 'end': end, 'hex': raw.hex(),
                            'instructions': decoded, 'argument_relation': args})
    source = source_context(data, secs)
    cases = vectors(instructions, rule)
    window = {'start': START, 'end': END, 'size': len(body),
              'file_offset': file_offset(secs, START, len(body)),
              'body_hex': body.hex(), 'body_sha256': sha(body),
              'frame': frames[START], 'instructions': instructions,
              'padding': {'start': END, 'end': NEXT, 'size': len(padding),
                          'hex': padding.hex(), 'classification': 'INT3 fill outside the FDE'}}
    metrics = {'bound_functions': 1, 'body_bytes': len(body), 'decoded_instructions': len(instructions),
               'callees': 0, 'indirect_transfers': 0, 'direct_call_sites': len(hits),
               'direct_tail_sites': sum(h['mnemonic'] == 'jmp' for h in hits),
               'caller_fdes': len({h['owner_start'] for h in hits}),
               'padding_bytes': len(padding), 'vectors': len(cases),
               'text_bytes_scanned': texts[0]['size']}
    return {'target': {'release': 115, 'sha256': SHA, 'size': len(data),
                       'path': 'artifacts/node/115/hl-node'},
            'window': window, 'rule': rule, 'callees': [],
            'caller_census': {'section': texts[0], 'opcodes': ['e8', 'e9'],
                              'method': 'all byte positions with a complete rel32; focused contexts decoded separately',
                              'hits': hits, 'owner_frame': frames[CALLER_START],
                              'limitations': 'No global instruction-boundary, reachability, indirect-reference or address-taken census; the whole caller CFG is unbound.'},
            'source_context': source, 'vectors': cases, 'metrics': metrics}


def metric_table(record):
    return '\n'.join(['| Measurement | Count |', '| --- | ---: |'] +
                     [f'| {key} | {value} |' for key, value in record['metrics'].items()])


def render_readme(record):
    w, r, source = record['window'], record['rule'], record['source_context']
    m, frame = record['metrics'], w['frame']
    walk = '\n'.join(f"| `{i['va']:#x}` | `{i['hex']}` | {i['mnemonic']} {format_operands(i['operands'])} |"
                     for i in w['instructions'])
    sites = ', '.join(f"`{h['site']:#x}`" for h in record['caller_census']['hits'])
    return f'''# RE-001: node #115 unsigned subtraction with final borrow

Task/component: RE-001 function binding; foundation arithmetic used by a
quantity-associated caller. Source/reference base: `{BASE}`. New Python and
prose are independently authored under the repository MIT license. Existing
ELF/FDE parsers are reused unchanged; no inferred source implementation is copied.

**Bounded question:** what does the complete leaf at `{w['start']:#x}` compute
and write, and does its final byte mean unsigned borrow or signed overflow?

**Answer:** for valid, stable, pairwise-disjoint buffers, interpret the
{r['limb_count']} little-endian {r['limb_bits']}-bit limbs at RSI and RDX as unsigned
integers A and B. The function overwrites RSI with `(A-B) mod 2**{r['integer_bits']}`,
copies that result to RDI, and writes `int(A < B)` at RDI+{r['output_borrow_offset']}.
It wraps on underflow and reports the borrow; it neither saturates nor panics.
The {m['decoded_instructions']}-instruction body has {m['callees']} callees and
{m['indirect_transfers']} indirect transfers. The arithmetic theorem covers the
entire function under the stated memory premises, without opaque helpers.

## Target, extent and bytes

Target: `{record['target']['path']}`, {record['target']['size']} bytes, SHA-256
`{record['target']['sha256']}`. Every record belongs to this digest; public
generation rejects any mismatch before parsing or creating output.
Addresses are original linked ELF VAs, with half-open ranges. The window is
`{w['start']:#x}..{w['end']:#x}`, {w['size']} bytes, at file offset `{w['file_offset']:#x}`.
Body SHA-256: `{w['body_sha256']}`. Actual FDE VA/file offset:
`{frame['fde']:#x}` / `{frame['fde_record']['file_offset']:#x}`; CIE VA/file offset:
`{frame['cie']:#x}` / `{frame['cie_record']['file_offset']:#x}`. The CIE uses
`zR`/PC-relative signed displacement encoding; the FDE has no LSDA.
Its raw records and unwind-header link are retained and checked.
The trailing `{w['padding']['start']:#x}..{w['padding']['end']:#x}` interval is
{w['padding']['size']} INT3 bytes outside the body. A complete straight-line
decode from the indexed entry ends at RET exactly at the FDE end. This is
stronger evidence of this local extent than an unwind-start interval alone.

{metric_table(record)}

These are packet denominators, not node coverage or acceptance gates.
The vector count is the Cartesian boundary set recorded in `records.json`.

## Instruction walk and rule proof

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
{walk}

Let `W=2**{r['limb_bits']}`. For each ascending limb, the memory SUB/SBB writes
`d_i=(a_i-b_i-c_i) mod W`, with incoming borrow zero for SUB and the preceding
carry flag for SBB. The outgoing carry is `c_(i+1)=int(a_i < b_i+c_i)`.
MOV between arithmetic instructions preserves flags. Summing
`a_i-b_i-c_i=d_i-W*c_(i+1)` after multiplication by the limb place values
cancels all internal borrows. Therefore `A-B=D-W**{r['limb_count']}*c_final`.
Since D is in the unsigned range, `c_final` is exactly `int(A < B)`.
This also covers the maximal subtrahend limb with an incoming borrow;
`b_i+c_i` is a mathematical integer and must not be prematurely wrapped.

The unaligned vector moves copy the completed left buffer in ascending blocks
at offsets {', '.join(str(x) for x in r['copy_offsets'])}. They preserve flags,
so SETB stores the final arithmetic carry at output+{r['output_borrow_offset']}.
No signed-overflow test, saturation branch, data table, relocation or callee
is involved in the leaf. Incoming carry is irrelevant because SUB initializes it.
RAX retains the last loaded right limb; the integer result is in memory.
Writable left memory is essential even when only the output is wanted.

The buffer premises are readable right and readable/writable left ranges of
{r['output_borrow_offset']} bytes, a writable output range of
{r['output_borrow_offset'] + 1} bytes, valid return stack, and ordinary stable
memory. Buffers must not overlap executable code or the return-address slot.
Partial overlaps are outside the theorem: sequential source loads,
in-place writes and vector copies can change later reads. Other bytes are not
explicitly written by the leaf. This is a machine-level buffer contract, not
an assertion about Rust alias rules, type layout or the caller's public API.

`model()` uses independent whole-integer subtraction/modulo. The recorded vectors
come from the decoded limb equations, including each limb boundary, long borrow
propagation, equality, zero, high-bit and unsigned-maximum neighbors. The algebra
above proves the full domain; the fixtures check the independent formulation.
Tests additionally replace actual SBB with SUB and SETB with SETAE: the equations
change on distinguishing inputs before the semantic certificate rejects them.

## Callers and first-party context

The producer scans every eligible byte position in the complete `.text` range
`{record['caller_census']['section']['address']:#x}..{record['caller_census']['section']['address'] + record['caller_census']['section']['size']:#x}`
for E8/E9 signed rel32 targets. The raw candidates are {sites}; all are CALLs
inside FDE `{CALLER_START:#x}..{CALLER_END:#x}`. There are
{m['direct_tail_sites']} E9 candidates. Raw bytes, source file offsets, owner
FDE/CIE and focused instruction contexts are retained. Every context decodes
the stack-buffer LEAs, direct CALL, output-borrow comparison and nonzero branch.
Those stack ranges are disjoint, and the compared byte is exactly the leaf's
output borrow byte. The taken edge is recorded without assigning final caller
success/error meaning.

The same caller FDE contains a decoded RIP-relative LEA at `{SOURCE_SITE:#x}`
to Location `{LOCATION:#x}`. Its symbol-zero RELATIVE relocation, path bytes,
length and line/column bind `{source['path']}:{source['line']}:{source['column']}`.
This supplies a first-party quantity association for the direct caller. It does
not recover the leaf's original name, crate, Rust integer type or financial units.

The census is deliberately qualified: a raw E8/E9 scan is not a global
instruction-boundary proof. The focused sequences were also inspected in native
static disassembly, but the reproducible certificate only decodes these bounded
contexts, not the complete caller CFG. Indirect/address-taken references, runtime
reachability and callers outside `.text` remain unmeasured. Callee identities
and extents are an empty set because the complete leaf has no call or jump.

## Novelty preflight

Before creating this packet, at the source base above, these exact commands
each returned empty stdout, empty stderr and exit status 1 (no matches):

```sh
rg -i 2ccdd80 research/
rg -i 46980480 research/
rg -i 2ccdd80 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 46980480 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The entry lies inside the assigned address band and is absent from the supplied
claimed-address list. There are no callee behavior bindings requiring another
novelty check. The commands naturally match this packet after it is added.
The PR-list snapshots were local review inputs; no online PR check is claimed.

## Reproduce and controls

Run from the repository root with the authenticated capture materialized:

```sh
python3 tools/node115_sub256_borrow.py --out research/work-items/{SLUG}/
python3 -m unittest tests.test_node115_sub256_borrow -v
python3 research/work-items/{SLUG}/verify.py
make verify
make catalogue-check
```

Python 3.10+ standard library only; validated locally on Linux x86-64 with
Python 3.13.5. Initial exploration used GNU objdump 2.44 in a bounded static
export under ignored `work/`; it is not a generator, verifier or test dependency.
No connected REA provider was available. ELF bytes are read through one mmap;
mutant controls use private copy-on-write pages. No captured code is executed.
No network, installs, Rust build, hosted CI or container run is involved.
`records.json` and this README regenerate byte-identically; the manifest also
pins producer, verifier, tests and the unchanged ELF/FDE parser dependencies.
The verifier uses an exact manifest whitelist and compares regenerated evidence.

Controls include wrong/truncated input, actual instruction-byte mutations below
the digest gate, shifted FDE bounds, changed frame bytes, wrong CALL target,
changed argument/borrow operands, source metadata/relocation corruption, scan
end boundaries and manifest tampering. README counts are checked against JSON;
the complete README is also compared with its deterministic renderer. Static
instruction equations are not target execution or differential runtime testing.

## Status, non-claims and next step

Before: no function bind at the novelty-checked entry. After: its full bytes,
extent, carry semantics, in-place effects and output contract are bound to the
target, with a reproducible direct-call candidate census and source association.
Observation: decoded operations and bytes. Inference: the unsigned arithmetic
rule follows under the explicit buffer premises. Unresolved: original symbol,
source ownership, API, units, caller reachability and partial-alias behavior.

No Rust reconstruction, compiled-byte equivalence, full caller behavior,
whole-ELF equivalence, protocol correctness, source-built node or component gate
is claimed. There are no normalization masks, helper closure gaps or data-table
dependencies in the leaf; whole-program call/data/relocation integration remains
open. Existing evidence, source pins, progress and catalogue files are unchanged.
Next: trace the caller's operand construction and borrow branch to establish
which quantity operation uses this subtraction and what rejection it causes.
'''


def format_operands(args):
    parts = []
    for arg in args:
        if arg['kind'] == 'reg':
            parts.append(arg['name'])
        elif arg['kind'] == 'mem':
            parts.append(f"{arg['bits']}-bit [{arg['base']}+{arg['offset']}]")
    return ', '.join(parts)


def encoded_records(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def collect(binary=TARGET):
    with Path(binary).open('rb') as stream:
        require(stream.seek(0, 2) > 0, 'node #115 digest mismatch')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return build_records(data)


def generate(binary, out):
    record = collect(binary)
    # Authenticate and finish every check before mutating the requested output.
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_bytes(encoded_records(record))
    (out / 'README.md').write_text(render_readme(record), encoding='utf-8', newline='\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record = generate(args.binary, args.out)
    print(json.dumps({'target_sha256': SHA, **record['metrics']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        raise SystemExit(str(error))
