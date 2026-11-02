#!/usr/bin/env python3
"""Bind one node #115 record-insertion leaf using only static stdlib parsing."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records
from gas_auction_price import decode as context_decode

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET_REL = 'research/work-items/RE-001-node115-record-insertion'
PACKET = ROOT / PACKET_REL
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
START, END = 0x26cf370, 0x26cf42f
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
BODY_SHA = 'ea15bcdcf54fee271b20f8bfb7246bed1d6ea8c1c651c18b8ac70a7ee48081df'
CALLER_START, CALLER_END, CALL_SITE = 0x23fdb60, 0x23fea14, 0x23fe91f
CALLER_SHA = '62aed9b5e67ded3fd7f9743acc9fd3f7cf96e1852180752531ab53438508e425'
BASE_COMMIT = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
FRAME_BYTES = {
    START: ('1000000070c7090024bd9801bf00000000000000',
            '1400000000000000017a5200017810011b0c070890010000'),
    CALLER_START: ('50000000a4b00c00b4542f01b40e000004871011ff410e10420e18420e20420e28420e30410e38470ea00383078c068d058e048f038602037a0d0e38410e30420e28420e20420e18420e10410e08410ea0030000',
                   '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'),
}
FRAMES = {
    START: dict(fde=0xd43644, cie=0xca6ed8, start=START, end=END, lsda=None),
    CALLER_START: dict(fde=0x11086a4, cie=0x103d604, start=CALLER_START,
                       end=CALLER_END, lsda=2201404),
}
MANIFEST_PATHS = (
    'README.md', 'records.json', 'verify.py',
    'tools/node115_record_insertion.py', 'tests/test_node115_record_insertion.py',
    'tools/elf_index.py', 'tools/fde_extents.py', 'tools/gas_auction_price.py',
)
U64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(len(data) == SIZE and sha(data) == SHA, 'node #115 size/SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        require(len({s['name'] for s in self.sections}) == len(self.sections),
                'duplicate section names')
        self.cies, self.fdes = eh_frame_records(data, self.sections)
        self.fdes.sort(key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.fdes]
        require(len(set(self.starts)) == len(self.starts), 'duplicate FDE starts')
        self.text = self.section('.text')
        require((self.text['address'], self.text['size'], self.text['offset'], self.text['flags'])
                == (TEXT_START, TEXT_END - TEXT_START, 0x1418300, 6), 'text geometry changed')

    def section(self, name):
        rows = [s for s in self.sections if s['name'] == name]
        require(len(rows) == 1, 'missing or ambiguous section')
        return rows[0]

    def offset(self, va, size=1):
        rows = [s for s in self.sections if s['type'] != 8 and s['address'] <= va
                and va + size <= s['address'] + s['size']]
        require(len(rows) == 1, 'ambiguous or missing file-backed mapping')
        return rows[0]['offset'] + va - rows[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def owner(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        require(i >= 0 and va < self.fdes[i]['end'], 'call candidate outside FDE')
        return self.fdes[i]

    def frame(self, start):
        expected = FRAMES[start]
        rows = [f for f in self.fdes if f['start'] <= start < f['end']]
        require(rows == [expected], 'selected FDE geometry changed')
        result = dict(expected)
        for key, raw in zip(('fde', 'cie'), FRAME_BYTES[start]):
            off = self.offset(expected[key], 4)
            length = struct.unpack_from('<I', self.data, off)[0] + 4
            body = self.data[off:off + length]
            require(body.hex() == raw, f'{key} bytes changed')
            result[key + '_file_offset'] = off
            result[key + '_bytes'] = body.hex()
        result['cie_properties'] = self.cies[expected['cie']]
        return result


REGS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
NOP_ENCODINGS = (bytes.fromhex('0f1f8000000000'), bytes.fromhex('66662e0f1f840000000000'))


def decode_leaf(body, start=START):
    """Strict x86 subset: reject unknown prefixes, groups, forms and truncation.

    Decode operands, SIB, signed displacements and branch targets from bytes.
    This is a decoder, never an instruction executor or target emulator.
    """
    rows, pos = [], 0
    while pos < len(body):
        begin = pos
        row = {'va': start + begin}

        def take(n):
            nonlocal pos
            require(pos + n <= len(body), 'truncated instruction')
            value = body[pos:pos + n]
            pos += n
            return value

        def integer(n):
            return int.from_bytes(take(n), 'little', signed=True)

        def reg(number, vector=False):
            return {'register': 'xmm' + str(number) if vector else REGS[number]}

        def modrm(rex, vector=False):
            byte = take(1)[0]
            mod, field, rm = byte >> 6, (byte >> 3) & 7, byte & 7
            dest = reg(field | ((rex & 4) << 1), vector)
            if mod == 3:
                return field, dest, reg(rm | ((rex & 1) << 3), vector)
            base, index, scale = None, None, 1
            if rm == 4:
                sib = take(1)[0]
                scale = 1 << (sib >> 6)
                idx = ((sib >> 3) & 7) | ((rex & 2) << 2)
                if idx != 4:
                    index = REGS[idx]
                require(not (mod == 0 and sib & 7 == 5), 'unsupported baseless SIB')
                base = REGS[(sib & 7) | ((rex & 1) << 3)]
            else:
                require(not (mod == 0 and rm == 5), 'unexpected RIP memory in leaf')
                base = REGS[rm | ((rex & 1) << 3)]
            displacement = integer(1) if mod == 1 else integer(4) if mod == 2 else 0
            return field, dest, {'memory': {'base': base, 'index': index,
                                          'scale': scale, 'displacement': displacement}}

        nop = next((raw for raw in NOP_ENCODINGS if body.startswith(raw, pos)), None)
        if nop is not None:
            take(len(nop)); row['op'] = 'nop'
        else:
            rex = 0
            if 0x40 <= body[pos] <= 0x4f:
                rex = take(1)[0]
            opcode = take(1)[0]
            if opcode in (0x8d, 0x89, 0x8b, 0x39, 0x3b, 0x01):
                require(rex & 8, 'expected 64-bit scalar operand')
                _, dest, rm = modrm(rex)
                op = {0x8d: 'lea', 0x89: 'mov', 0x8b: 'mov', 0x39: 'cmp', 0x3b: 'cmp', 0x01: 'add'}[opcode]
                if opcode == 0x8d:
                    require('memory' in rm, 'LEA requires memory addressing')
                operands = [dest, rm] if opcode in (0x8d, 0x8b, 0x3b) else [rm, dest]
                row.update(op=op, width=8, operands=operands)
            elif opcode in (0x83, 0xc1):
                require(rex & 8 and not rex & 4, 'unsupported immediate group prefix')
                field, _, rm = modrm(rex)
                require((opcode == 0x83 and field in (0, 7)) or
                        (opcode == 0xc1 and field == 4), 'unsupported immediate group')
                imm = integer(1)
                row.update(op=('shl' if opcode == 0xc1 else 'add' if field == 0 else 'cmp'),
                           width=8, operands=[rm, {'immediate': imm}])
            elif opcode in (0x72, 0x73, 0x74, 0x75, 0xeb, 0xe9):
                require(not rex, 'unexpected branch prefix')
                displacement = integer(4 if opcode == 0xe9 else 1)
                row.update(op={0x72: 'jb', 0x73: 'jae', 0x74: 'je', 0x75: 'jne',
                               0xeb: 'jmp', 0xe9: 'jmp'}[opcode], target=start + pos + displacement)
            elif opcode == 0xc3:
                require(not rex, 'unexpected RET prefix'); row['op'] = 'ret'
            elif opcode == 0x0f:
                second = take(1)[0]
                if second in (0x10, 0x11, 0x28, 0x29):
                    require(not rex & 8, 'unexpected vector REX.W')
                    _, dest, rm = modrm(rex, True)
                    require('memory' in rm, 'expected vector memory operand')
                    row.update(op='movups' if second in (0x10, 0x11) else 'movaps', width=16,
                               operands=[dest, rm] if second in (0x10, 0x28) else [rm, dest])
                elif second == 0x83:
                    require(not rex, 'unexpected branch prefix')
                    displacement = integer(4)
                    row.update(op='jae', target=start + pos + displacement)
                elif second == 0x0b:
                    require(not rex, 'unexpected UD2 prefix'); row['op'] = 'ud2'
                else:
                    raise ValueError('unsupported two-byte opcode')
            else:
                raise ValueError('unsupported opcode or prefix')
        row.update(size=pos - begin, bytes=body[begin:pos].hex())
        rows.append(row)
    boundaries = {r['va'] for r in rows}
    require(all(r['target'] in boundaries for r in rows if 'target' in r),
            'branch target is not a local instruction boundary')
    return rows


def relation_from_decode(rows):
    by = {r['va']: r for r in rows}
    return {
        'record_bytes': by[0x26cf3ba]['operands'][1]['immediate'],
        'key_bytes': by[0x26cf3ca]['width'],
        'initial_skip_condition': by[0x26cf3ce]['op'],
        'backward_shift_condition': by[0x26cf423]['op'],
        'entry_guard_condition': by[0x26cf377]['op'],
        'entry_guard_target': by[0x26cf377]['target'],
        'entry_decrement': by[START]['operands'][1]['memory']['displacement'],
        'previous_key_displacement': by[0x26cf3ca]['operands'][1]['memory']['displacement'],
        'earlier_key_displacement': by[0x26cf41b]['operands'][1]['memory']['displacement'],
        'trap': by[0x26cf42d]['op'],
    }


def check_relation(rows):
    relation = relation_from_decode(rows)
    require(relation == dict(record_bytes=40, key_bytes=8, initial_skip_condition='jae',
                            backward_shift_condition='jb', entry_guard_condition='jae',
                            entry_guard_target=0x26cf42d, entry_decrement=-1,
                            previous_key_displacement=-40, earlier_key_displacement=-80,
                            trap='ud2'), 'insertion relation changed')
    return relation


def insertion_model(records, start_index):
    """Independent record-level model; no captured PC/register/memory execution."""
    n = len(records)
    require(type(start_index) is int and 0 <= start_index <= U64, 'invalid index word')
    if ((start_index - 1) & U64) >= n:
        raise ValueError('UD2 entry guard')
    require(all(isinstance(r, bytes) and len(r) == 40 for r in records), 'invalid record')
    result = list(records)
    for i in range(start_index, n):
        saved = result[i]
        key = int.from_bytes(saved[:8], 'little')
        j = i
        while j and int.from_bytes(result[j - 1][:8], 'little') > key:
            result[j] = result[j - 1]
            j -= 1
        result[j] = saved
    return result


def vectors():
    # Explicit expected identity order, derived from unsigned CMP/JAE/JB and
    # whole-record moves. Identity bytes distinguish equal keys and payloads.
    cases = [
        ('single', [9], 1, [0]),
        ('ascending', [0, 1, U64], 1, [0, 1, 2]),
        ('descending', [U64, 2, 1, 0], 1, [3, 2, 1, 0]),
        ('equal-stability', [7, 7, 2, 7, 2], 1, [2, 4, 0, 1, 3]),
        ('unsigned-high-bit', [U64, 0, 1 << 63, (1 << 63) - 1], 1, [1, 3, 2, 0]),
        ('sorted-prefix', [1, 5, 9, 0, 5], 3, [3, 0, 1, 4, 2]),
        ('unprocessed-prefix', [9, 1, 5], 2, [0, 1, 2]),
        ('insert-to-front', [3, 4, 1], 2, [2, 0, 1]),
        ('skip-all', [9, 1, 5], 3, [0, 1, 2]),
    ]
    result = [dict(name=name, keys=keys, start_index=k, expected_order=order)
              for name, keys, k, order in cases]
    result += [dict(name=name, keys=keys, start_index=k, expected_trap='UD2')
               for name, keys, k in [('empty-zero', [], 0), ('empty-one', [], 1),
                                     ('zero-index', [1], 0), ('past-end', [1], 2),
                                     ('max-index', [1], U64)]]
    return result


def direct_candidates(image, target=START):
    """Every byte offset in full .text is eligible for an E8/E9 rel32 hit."""
    data, sec = image.data, image.text
    begin, end = sec['offset'], sec['offset'] + sec['size']
    rows = []
    for opcode in (b'\xe8', b'\xe9'):
        pos = begin
        while True:
            pos = data.find(opcode, pos, end - 4)
            if pos < 0:
                break
            va = sec['address'] + pos - begin
            displacement = struct.unpack_from('<i', data, pos + 1)[0]
            if va + 5 + displacement == target:
                rows.append(dict(va=va, file_offset=pos, opcode=opcode.hex(),
                                 displacement=displacement, target=target,
                                 bytes=data[pos:pos + 5].hex()))
            pos += 1
    return sorted(rows, key=lambda r: r['va'])


def context_walk(image):
    body = image.read(CALLER_START, CALLER_END - CALLER_START)
    require(sha(body) == CALLER_SHA, 'caller body changed')
    pc, rows = CALLER_START, []
    while pc < CALLER_END:
        instruction = context_decode(image.read, pc)
        require(0 < instruction.size <= 15 and pc + instruction.size <= CALLER_END,
                'caller instruction crosses extent')
        rows.append(instruction)
        pc += instruction.size
    return rows


def location(image, site, slot, path, line, column, relocation_offset):
    raw = image.read(site, 7)
    require(raw[:3] in (b'\x4c\x8d\x05', b'\x48\x8d\x15'), 'Location LEA changed')
    require(site + 7 + struct.unpack_from('<i', raw, 3)[0] == slot, 'Location target changed')
    sec = image.section('.rela.dyn')
    matches = []
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        rslot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if rslot == slot:
            matches.append((off, info, addend))
    require(len(matches) == 1, 'duplicate or missing Location relocation')
    off, info, addend = matches[0]
    require(info == 8 and off == relocation_offset, 'Location relocation changed')
    raw_location = image.read(slot, 24)
    raw_pointer, length, observed_line, observed_column = struct.unpack('<QQII', raw_location)
    require(raw_pointer == 0 and (length, observed_line, observed_column)
            == (len(path), line, column), 'Location layout changed')
    require(image.read(addend, length) == path.encode('ascii'), 'Location path changed')
    return dict(lea_va=site, lea_bytes=raw.hex(), slot_va=slot,
                slot_file_offset=image.offset(slot), slot_bytes=raw_location.hex(),
                relocation_file_offset=off, relocation_bytes=image.data[off:off + 24].hex(),
                relocation_type='R_X86_64_RELATIVE', path_va=addend, path=path,
                path_length=length, line=line, column=column)


def validate_leaf(body):
    instructions = decode_leaf(body)
    relation = check_relation(instructions)
    require(sha(body) == BODY_SHA, 'leaf body changed')
    return instructions, relation


def _observe(data):
    """Private structural checker, exposed to tests below the public hash gate."""
    image = Image(data)
    frame = image.frame(START)
    body = image.read(START, END - START)
    instructions, relation = validate_leaf(body)
    padding = []
    for a, b in ((START - 5, START), (END, END + 1)):
        raw = image.read(a, b - a)
        require(raw == b'\xcc' * (b - a), 'INT3 padding changed')
        padding.append(dict(start=a, end=b, size=b-a, bytes=raw.hex()))
    require(any(f['end'] == START - 5 for f in image.fdes)
            and any(f['start'] == END + 1 for f in image.fdes), 'adjacent FDE boundary changed')
    hits = direct_candidates(image)
    require([(h['va'], h['opcode']) for h in hits] == [(CALL_SITE, 'e8')],
            'direct caller census changed')
    caller_frame = image.frame(CALLER_START)
    context = context_walk(image)
    decoded = {i.va: i for i in context}
    require(decoded[CALL_SITE].op == 'call' and decoded[CALL_SITE].target == START,
            'caller target or instruction boundary changed')
    sources = [location(image, 0x23fe967, 0x648b990,
                        'l1/src/dex_registry/clearinghouses.rs', 11, 29, 0xbc1d8),
               location(image, 0x23fe983, 0x642f7a0,
                        'l1/src/clearinghouse/oracle/oracle.rs', 433, 18, 0x4f0f8)]
    require(all(s['lea_va'] in decoded for s in sources), 'Location not an instruction boundary')
    # Selected caller operands are independently decoded by the shared subset;
    # only the immediate index and the transfer are used, not caller semantics.
    index = decoded[0x23fe917]
    require(index.op == 'mov' and index.width == 4 and index.a == ('r', 2)
            and index.b == ('i', 1), 'caller start index changed')
    for h in hits:
        require(image.owner(h['va']) == FRAMES[CALLER_START], 'caller FDE owner changed')
        h.update(instruction_boundary_verified=True, owner_start=CALLER_START,
                 owner_end=CALLER_END)
    fixture_rows = vectors()
    return dict(
        schema='node115-record-insertion-v1', task='RE-001', component='foundation',
        target=dict(release=115, sha256=SHA, size=SIZE, architecture='ELF64 x86-64 little-endian'),
        question='What does the complete leaf do to its array, and what is the entry-index guard?',
        rule=dict(name='stable unsigned-key record insertion', registers={'rdi': 'record base',
                  'rsi': 'record count n', 'rdx': 'first index k'},
                  entry_guard='UD2 iff ((k - 1) mod 2^64) >= n; otherwise 1 <= k <= n',
                  normal='For i=k..n-1, move record i left across strictly larger unsigned keys; equal keys never cross.',
                  sorting_precondition='A sorted prefix [0,k) gives a sorted whole array; k=1 sorts every admissible nonempty array.',
                  extracted=relation),
        function=dict(start=START, end=END, size=len(body), file_offset=image.offset(START),
                      body_sha256=sha(body), body_hex=body.hex(), frame=frame,
                      padding=padding, instructions=instructions,
                      direct_callees=[], indirect_transfers=[], external_branches=[]),
        caller_census=dict(scan_start=TEXT_START, scan_end=TEXT_END,
                           scan_bytes=TEXT_END - TEXT_START,
                           method='byte-exhaustive E8/E9 signed rel32, then complete owner linear decode',
                           hits=hits, rejected_hits=[],
                           limitations='No indirect references, other executable sections or whole-program reachability claim.'),
        caller_context=dict(start=CALLER_START, end=CALLER_END, size=CALLER_END-CALLER_START,
                            body_sha256=CALLER_SHA, frame=caller_frame,
                            linear_instruction_count=len(context), sources=sources,
                            first_index=dict(site=index.va, bytes=image.read(index.va, index.size).hex(), value=1),
                            claim='Caller association only; no caller behavior or original leaf symbol/type recovered.'),
        vectors=fixture_rows,
        metrics=dict(function_bytes=len(body), instructions=len(instructions),
                     padding_before_bytes=5, padding_after_bytes=1,
                     direct_callees=0, indirect_transfers=0, direct_call_sites=len(hits),
                     direct_caller_fdes=len({h['owner_start'] for h in hits}),
                     tail_jump_sites=sum(h['opcode'] == 'e9' for h in hits),
                     source_locations=len(sources), caller_instructions=len(context),
                     vectors=len(fixture_rows), trap_vectors=sum('expected_trap' in v for v in fixture_rows)),
    )


def build_records(data):
    authenticate(data)
    return _observe(data)


def json_text(record):
    return json.dumps(record, indent=2, sort_keys=True) + '\n'


def operand_text(operand):
    if 'register' in operand:
        return operand['register']
    if 'immediate' in operand:
        return str(operand['immediate'])
    m = operand['memory']
    text = m['base'] or ''
    if m['index']:
        text += '+' + m['index'] + '*' + str(m['scale'])
    if m['displacement']:
        text += f"{m['displacement']:+d}"
    return '[' + text + ']'


def instruction_text(row):
    if 'target' in row:
        return row['op'] + ' ' + hex(row['target'])
    return row['op'] + (' ' + ', '.join(map(operand_text, row['operands'])) if 'operands' in row else '')


def readme_text(record):
    f, m, c = record['function'], record['metrics'], record['caller_context']
    rule = record['rule']['extracted']
    table = '\n'.join(f"| `{i['va']:#x}` | `{i['bytes']}` | `{instruction_text(i)}` |"
                      for i in f['instructions'])
    return f'''# RE-001: node #115 stable record insertion

- Component: foundation, with a direct caller associated with clearinghouse source Locations.
- Target: node #115 Linux x86-64, SHA-256 `{record['target']['sha256']}`.
- Source/reference base: `{BASE_COMMIT}`. New code and prose are independently authored under the repository MIT license; no inferred source was copied.
- Claim status: observed instructions and an inferred record-level algorithm, proved below. Original function/type names are unresolved.
- Scope: the complete leaf and its local array effect; caller/source association only. No progress or catalogue gate requested.

## Question and answer

What does `{f['start']:#x}` do to its array, and what is the entry-index guard?

It processes contiguous **{rule['record_bytes']}-byte records**, comparing the first **{rule['key_bytes']}-byte word as unsigned**. RDI is the base, RSI is the record count n, and RDX is the first index k. The entry traps with UD2 exactly when `((k - 1) mod 2^64) >= n`; passing is equivalent to `1 <= k <= n`. For each index from k to n excluded, the function saves that record and shifts preceding records with strictly larger keys right, then inserts the saved record. Equal keys never cross, so this is stable insertion. A sorted prefix `[0,k)` yields a sorted whole array; k=1 supplies that precondition for every admissible nonempty array. k=n returns without touching the array. An unsorted longer prefix is not repaired in general.

## Evidence geometry and measured counts

All addresses are original ELF virtual addresses, with no rebase or operand normalization. The file offset differs from VA and is recorded explicitly. The extent uses the actual FDE, complete decode, closed local branches, RET/UD2 terminals and adjacent padding, rather than a next-start estimate.

| Measurement | Value |
| --- | --- |
| Leaf half-open window | `{f['start']:#x}..{f['end']:#x}` |
| Leaf file offset | `{f['file_offset']:#x}` |
| Complete leaf bytes | {m['function_bytes']} |
| Decoded leaf instructions, including in-body NOPs | {m['instructions']} |
| FDE VA / file offset | `{f['frame']['fde']:#x}` / `{f['frame']['fde_file_offset']:#x}` |
| CIE VA / file offset | `{f['frame']['cie']:#x}` / `{f['frame']['cie_file_offset']:#x}` |
| INT3 bytes before / after, outside the body | {m['padding_before_bytes']} / {m['padding_after_bytes']} |
| Direct callees / indirect transfers | {m['direct_callees']} / {m['indirect_transfers']} |
| Direct call sites / owning FDEs / tail-jump sites | {m['direct_call_sites']} / {m['direct_caller_fdes']} / {m['tail_jump_sites']} |
| Caller instructions decoded for boundary validation | {m['caller_instructions']} |
| First-party Location bindings in that caller | {m['source_locations']} |
| Instruction-grounded vectors / trap vectors | {m['vectors']} / {m['trap_vectors']} |

Body SHA-256: `{f['body_sha256']}`. Raw body, FDE/CIE bytes and properties, padding, typed decoded operands, source relocations, caller scan hits and vectors are in `records.json`. The leaf CIE has no LSDA/personality; no exception handler or helper implementation is needed to establish its local normal path. The padding is excluded from the body digest.

## Instruction walk and proof

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
{table}

The entry LEA forms k-1 with machine-word wrap. CMP/JAE sends an out-of-range value to the final UD2; CMP/JNE then returns immediately for k=n. Otherwise the LEAs and shift establish RAX=base+n*stride, RDX=base+k*stride and RCX=k*stride. Address multiplication must be representable under the memory preconditions below.

At `0x26cf3c7`, RSI holds the current key. CMP/JAE skips moving a record when its unsigned key is at least its predecessor's key, including equality. Otherwise MOVUPS saves its payload in XMM registers and MOVAPS spills it to the red zone. R9 tracks the hole offset. The backward loop copies the complete preceding record into the hole: its final word is loaded before the vector stores, and the vector loads preserve the remaining bytes before overwrite. These moves cover the entire record with no missing payload bytes.

The R9 comparison stops at the beginning; otherwise the CMP/JB at `0x26cf41b`/`0x26cf423` continues only while the saved key is unsigned-less than the earlier key. The common insertion block writes the saved key and payload to the hole. RDX and RCX advance by the decoded stride and the end-pointer test closes the outer loop. The hole moves strictly toward the beginning and the outer index strictly toward n, proving termination for valid finite arrays. If the prefix was sorted, each insertion extends that sorted prefix; strict comparisons preserve the original order of equal keys. The `unprocessed-prefix` vector prevents claiming that an arbitrary prefix is sorted automatically.

The output contract is the array mutation. No Rust return type is assigned. Incidentally, the raw RAX return is k-1 on the k=n shortcut and the end pointer after a nonempty insertion pass. No globals, constant tables, calls, tail transfers or indirect dispatch participate in this leaf.

## Direct caller and first-party association

The census examines every possible E8/E9 opcode byte in `.text` over `{TEXT_START:#x}..{TEXT_END:#x}`, a **{record['caller_census']['scan_bytes']}-byte** domain, applies signed rel32, and retains every hit to the leaf. It then checks each hit against a complete linear decode from its containing FDE entry. This avoids counting an E8/E9 embedded in another instruction as a caller.

The retained CALL is at `{CALL_SITE:#x}` inside `{c['start']:#x}..{c['end']:#x}`. The immediately preceding MOV EDX sets k to `{c['first_index']['value']}`. That FDE contains authenticated RIP-relative LEAs and R_X86_64_RELATIVE bindings for `l1/src/dex_registry/clearinghouses.rs:11:29` and `l1/src/clearinghouse/oracle/oracle.rs:433:18`. These are relative first-party paths present in this target; no source pathname is invented. The source association is an observation about the caller, not proof of the leaf's original source module or concrete collection/record type. The caller's other behavior and callees are not bound here.

The census is complete for these opcodes in the stated section, not for indirect references, other executable sections or reachable execution paths. No target callees exist to identify or bind; the wrong-callee negative control is therefore inapplicable. Tests instead corrupt the actual incoming CALL target and require the caller binding to fail.

## Novelty before investment

These commands ran against the base tree before adding this packet or its tool. Each returned exit status 1, with empty stdout/stderr (no matches):

```sh
rg -i '26cf370' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg '40694640' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callee addresses requiring additional novelty checks. The chosen start lies in the assigned band and outside the excluded crowding interval. The PR-title files are local collision hints, not proof that all unpublished work is absent.

## Reproduce and validation

From the repository root, use Python 3.10+ and only its standard library. The evidence producer uses the existing ELF/FDE parsers and the existing Python instruction decoder for caller boundaries; its new narrow decoder handles every leaf instruction and rejects unsupported forms. It authenticates the entire target before interpretation or output creation. Generation and verification use mmap and small slices, never multiple whole-file byte copies. GNU objdump 2.44 was used for initial manual inspection only; the producer, tests and verifier do not invoke or require it. Python 3.13.5 was used for the local validation.

```sh
python3 tools/node115_record_insertion.py --out research/work-items/RE-001-node115-record-insertion/
python3 -m unittest tests.test_node115_record_insertion -v
python3 research/work-items/RE-001-node115-record-insertion/verify.py
make verify
make catalogue-check
```

`make doctor` and the initial `make verify` passed before selection. The packet verifier rejects missing, extra, duplicated or traversal manifest entries and compares freshly regenerated records and README byte-for-byte. Every quantitative table entry is interpolated from JSON; a targeted test checks the complete README against that rendering. The task-specific producer closes the otherwise missing reproducible byte-to-rule check for this leaf; no surrounding infrastructure, imported evidence or existing work item was modified.

Controls cover wrong digest and truncated input before output; every leaf byte below the public hash gate; decoded unsigned-comparison/stride counterfacts; non-boundary branches; shifted FDE start/extent/CIE; padding; the incoming CALL displacement; Location bytes and relocation addend; malformed manifest entries; and payload/stability/unsigned-boundary model vectors. The model is independently authored at record level and checked against explicit instruction-grounded identity permutations and Python's stable sorting. It does not execute or emulate the captured code.

## Preconditions, non-claims and next step

Normal-array semantics require a valid writable contiguous array, representable address/stride arithmetic, ordinary readable instruction memory, a valid return stack, SysV-compatible stack alignment and red-zone storage, and no array overlap with that stack scratch space. The trap guard and k=n shortcut occur before any array dereference. Empty arrays always fail this entry guard. Invalid pointers, unaligned stack, aliased scratch memory, hardware faults, concurrent mutation and nonstandard caller ABIs are outside the normal-array theorem.

No captured executable, emulator, network, install, signing, chain action or external service is used. Rust reconstruction, source-build comparison, compiler flags/lockfiles, original symbol/type/ABI recovery, whole-caller semantics, whole-node equivalence, hosted CI and a completed component gate are not claimed. Rust implementation and binary comparison are not yet implemented/measured; there are no normalization masks or copied machine-code implementation artifacts. This packet resolves the previously unbound leaf's complete local algorithm and failure guard; it is not a whole-node reconstruction claim.

Next: establish the caller's record construction and key meaning before assigning a domain name to this stable ordering operation.
'''


def manifest_text(packet, root=ROOT):
    rows = []
    for name in MANIFEST_PATHS:
        path = packet / name if '/' not in name else root / name
        require(path.is_file() and not path.is_symlink(), 'missing or symlinked manifest input')
        rows.append(f'{sha(path.read_bytes())}  {name}\n')
    return ''.join(rows)


def generate(binary, out):
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'node #115 size/SHA-256 mismatch')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            records = build_records(data)
    # Authenticate and validate completely before creating output.
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json_text(records), encoding='utf-8')
    (out / 'README.md').write_text(readme_text(records), encoding='utf-8')
    # The verifier is source, not binary-derived evidence. Copy its reviewed
    # canonical source for out-of-tree regeneration; never manufacture it.
    if out.resolve() != PACKET.resolve():
        (out / 'verify.py').write_bytes((PACKET / 'verify.py').read_bytes())
    (out / 'MANIFEST.sha256').write_text(manifest_text(out), encoding='ascii')
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        records = generate(args.binary, args.out)
    except (ValueError, OSError) as error:
        print(f'record-insertion: {error}', file=sys.stderr)
        return 1
    print(json.dumps(records['metrics'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
