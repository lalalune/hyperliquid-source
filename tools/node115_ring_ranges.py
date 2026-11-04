#!/usr/bin/env python3
"""Bind node #115's 408-byte ring-range projection using static bytes only.

Independently authored, MIT. Python 3.10+ standard library plus the repository's
stdlib ELF/FDE readers. No target execution, disassembler subprocess or network.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

# Existing ELF/FDE modules use sibling imports when run as scripts.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-ring-ranges'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
BASE_REVISION = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x24cdad0, 0x24cdb3f
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
MASK = (1 << 64) - 1
FDE = {'fde': 0xd18a84, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
BODY_SHA256 = '3b3f546c00ba1a4b6c071c172de25d7e15f722131d4301739bd098f62702c905'
# These are selected instruction windows, not complete caller implementations.
CALLERS = (
    (0x2e0ec44, 0x2e098e0, 0x2e11140, 0x2e0ec39, 0x2e0ec69),
    (0x2e150ee, 0x2e13ea0, 0x2e153c9, 0x2e150de, 0x2e15113),
    (0x2e182a3, 0x2e157c0, 0x2e197f5, 0x2e1828f, 0x2e182c8),
    (0x2e1f344, 0x2e1da10, 0x2e1f73c, 0x2e1f33c, 0x2e1f369),
)
LOCATIONS = (
    (0x2e0ab42, 0x6451b88, 0x77f58, 0x43e0ae, 'node/src/consensus/state.rs', 550, 17),
    (0x2e179b0, 0x6451bb8, 0x77f88, 0x44f69a, 'node/src/consensus/mempool.rs', 516, 38),
    (0x2e1e901, 0x6451be8, 0x77fb8, 0x44f69a, 'node/src/consensus/mempool.rs', 809, 14),
)
REG64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
REG32 = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def mapped(path):
    with Path(path).open('rb') as handle:
        require(handle.seek(0, 2) > 0, 'Empty target')
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield data


def authenticate(data):
    require(len(data) == SIZE and digest(data) == SHA256, 'Node #115 size/SHA-256 mismatch')


def decode(code, start):
    """Strict decoder for the observed integer/branch subset, no fallback rows.

    Decode operands from ModRM, SIB, REX and signed immediates. Reject unsupported
    prefixes, addressing forms, truncated operands and opcodes. This is not a
    general x86 decoder and is never used to guess across an unknown opcode.
    """
    rows, pos = [], 0

    def take(n):
        nonlocal pos
        require(pos + n <= len(code), 'Truncated instruction')
        value = code[pos:pos + n]
        pos += n
        return value

    def signed(n):
        return int.from_bytes(take(n), 'little', signed=True)

    while pos < len(code):
        begin = pos
        rex = 0
        op = take(1)[0]
        if 0x40 <= op <= 0x4f:
            rex = op
            op = take(1)[0]
        width = 64 if rex & 8 else 32
        regs = REG64 if width == 64 else REG32
        extra = {}
        if op in (0x74, 0x77, 0xeb, 0xe8, 0xe9):
            require(not rex, 'Unexpected branch prefix')
            delta = signed(4 if op in (0xe8, 0xe9) else 1)
            target = start + pos + delta
            mnemonic = {0x74: 'je', 0x77: 'ja', 0xeb: 'jmp', 0xe8: 'call', 0xe9: 'jmp'}[op]
            operands = [hex(target)]
            extra = {'target': target, 'displacement': delta}
        elif op == 0xc3:
            require(not rex, 'Unexpected return prefix')
            mnemonic, operands = 'ret', []
        else:
            if op == 0x0f:
                require(take(1)[0] == 0x43, 'Unsupported two-byte opcode')
                mnemonic = 'cmovae'
            else:
                require(op in (0x89, 0x8b, 0x8d, 0x85, 0x39, 0x29, 0x01, 0x31, 0x69),
                        f'Unsupported opcode {op:#x}')
                mnemonic = {0x89: 'mov', 0x8b: 'mov', 0x8d: 'lea', 0x85: 'test',
                            0x39: 'cmp', 0x29: 'sub', 0x01: 'add', 0x31: 'xor', 0x69: 'imul'}[op]
            modrm = take(1)[0]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            reg += 8 if rex & 4 else 0
            require(not rex & 2, 'Unsupported extended SIB index')
            if mod == 3:
                operand = regs[rm + (8 if rex & 1 else 0)]
                require(op != 0x8d, 'LEA requires memory')
            else:
                if rm == 4:
                    sib = take(1)[0]
                    require((sib >> 3) & 7 == 4 and sib >> 6 == 0,
                            'Unsupported indexed SIB')
                    base = sib & 7
                    require(not (mod == 0 and base == 5), 'Unsupported baseless SIB')
                    name = REG64[base + (8 if rex & 1 else 0)]
                elif mod == 0 and rm == 5:
                    require(not rex & 1, 'Unsupported RIP REX.B')
                    name = 'rip'
                else:
                    name = REG64[rm + (8 if rex & 1 else 0)]
                displacement = signed(1 if mod == 1 else 4) if mod in (1, 2) or name == 'rip' else 0
                suffix = f'+{displacement:#x}' if displacement > 0 else f'-{-displacement:#x}' if displacement < 0 else ''
                operand = f'[{name}{suffix}]'
                if name == 'rip':
                    extra['rip_target'] = start + pos + displacement
            operands = ([regs[reg], operand] if op in (0x8b, 0x8d, 0x0f, 0x69)
                        else [operand, regs[reg]])
            if op == 0x69:
                immediate = signed(4)
                operands.append(str(immediate))
                extra['immediate'] = immediate
        rows.append({'address': start + begin, 'size': pos - begin,
                     'bytes': code[begin:pos].hex(), 'mnemonic': mnemonic,
                     'operands': operands, **extra})
    return rows


EXPECTED = (
    ('mov', ['rax', 'rdi']), ('mov', ['r8', '[rsi+0x18]']), ('test', ['r8', 'r8']),
    ('je', ['0x24cdb07']), ('mov', ['rdx', '[rsi]']), ('mov', ['rcx', '[rsi+0x10]']),
    ('xor', ['edi', 'edi']), ('cmp', ['rcx', 'rdx']), ('cmovae', ['rdi', 'rdx']),
    ('sub', ['rcx', 'rdi']), ('mov', ['r9', 'rdx']), ('sub', ['r9', 'rcx']),
    ('mov', ['rdi', 'r8']), ('sub', ['rdi', 'r9']), ('ja', ['0x24cdb0d']),
    ('add', ['r8', 'rcx']), ('xor', ['edi', 'edi']), ('mov', ['rdx', 'r8']),
    ('jmp', ['0x24cdb0d']), ('xor', ['ecx', 'ecx']), ('xor', ['edx', 'edx']),
    ('xor', ['edi', 'edi']), ('mov', ['rsi', '[rsi+0x8]']),
    ('imul', ['rcx', 'rcx', '408']), ('add', ['rcx', 'rsi']),
    ('imul', ['rdx', 'rdx', '408']), ('add', ['rdx', 'rsi']),
    ('imul', ['rdi', 'rdi', '408']), ('add', ['rdi', 'rsi']),
    ('mov', ['[rax]', 'rcx']), ('mov', ['[rax+0x8]', 'rdx']),
    ('mov', ['[rax+0x10]', 'rsi']), ('mov', ['[rax+0x18]', 'rdi']), ('ret', []),
)


def certify_body(code):
    rows = decode(code, START)
    require(tuple((r['mnemonic'], r['operands']) for r in rows) == EXPECTED,
            'Function instruction contract changed')
    require(len(code) == END - START and digest(code) == BODY_SHA256, 'Function body identity changed')
    starts = {r['address'] for r in rows}
    require(all(r['target'] in starts for r in rows if 'target' in r), 'Branch leaves function or splits instruction')
    require(rows[-1]['address'] + rows[-1]['size'] == END, 'Function does not end at RET')
    return rows


def project(capacity, base, head, length):
    """Independent closed-form word rule; no captured instruction execution.

    All input/output words are unsigned 64-bit. The single head reduction is
    intentional: the bytes do not implement general head % capacity.
    """
    require(all(type(x) is int and 0 <= x <= MASK for x in (capacity, base, head, length)),
            'Expected four u64 words')
    if length == 0:
        return (base, base, base, base)
    h = head - capacity if head >= capacity else head
    tail = (capacity - h) & MASK
    first_end = capacity if length > tail else (h + length) & MASK
    second_end = length - tail if length > tail else 0
    return tuple((base + 408 * i) & MASK for i in (h, first_end, 0, second_end))


# Expected words are frozen, manually calculated from the decoded branches.
# Invalid ring geometry is included to pin raw-word semantics, not memory safety.
VECTORS = (
    ('empty_ignores_geometry', (MASK, 4096, MASK, 0), (4096, 4096, 4096, 4096)),
    ('contiguous', (8, 4096, 2, 3), (4912, 6136, 4096, 4096)),
    ('ends_exactly_at_capacity', (8, 4096, 6, 2), (6544, 7360, 4096, 4096)),
    ('wraps_by_one', (8, 4096, 6, 3), (6544, 7360, 4096, 4504)),
    ('full_wrapped', (8, 4096, 6, 8), (6544, 7360, 4096, 6544)),
    ('head_equals_capacity', (8, 4096, 8, 3), (4096, 5320, 4096, 4096)),
    ('head_reduced_once', (8, 4096, 14, 3), (6544, 7360, 4096, 4504)),
    ('head_twice_capacity_not_modulo', (8, 4096, 16, 1), (7360, 7360, 4096, 4504)),
    ('unsigned_head_compare', (MASK, 0, 1, 1), (408, 816, 0, 0)),
    ('unsigned_length_compare', (8, 0, 0, 1 << 63), (0, 3264, 0, MASK - 3263)),
    ('zero_capacity_nonempty', (0, 4096, 0, 1), (4096, 4096, 4096, 4504)),
    ('wrapped_tail_subtraction', (8, 0, 17, 1), (3672, 4080, 0, 0)),
    ('base_add_wraps', (8, MASK - 100, 1, 1), (307, 715, MASK - 100, MASK - 100)),
    ('multiply_wraps', (MASK, 0, MASK - 1, 1), (MASK - 815, MASK - 407, 0, 0)),
)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        require(len({s['name'] for s in self.sections}) == len(self.sections), 'Duplicate section')
        self.cies, self.fdes = eh_frame_records(data, self.sections)

    def section(self, name):
        return next(s for s in self.sections if s['name'] == name)

    def offset(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or missing ELF mapping')
        s = matches[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        o = self.offset(va, size)
        return self.data[o:o + size]

    def frame_record(self, va):
        s = self.section('.eh_frame')
        require(s['address'] <= va < s['address'] + s['size'], 'Frame outside .eh_frame')
        n = struct.unpack('<I', self.read(va, 4))[0] + 4
        require(va + n <= s['address'] + s['size'], 'Frame crosses section')
        return {'address': va, 'file_offset': self.offset(va, n), 'bytes': self.read(va, n).hex()}

    def frame(self, start, end=None):
        hits = [r for r in self.fdes if r['start'] == start]
        require(len(hits) == 1, 'Missing or ambiguous FDE start')
        f = hits[0]
        require(end is None or f['end'] == end, 'FDE extent changed')
        return {**f, 'fde_record': self.frame_record(f['fde']),
                'cie_record': self.frame_record(f['cie']), 'cie_decoded': self.cies[f['cie']]}


def scan_calls(image, target):
    """Complete all-byte e8/e9 rel32 candidate census, bounded to .text.

    Does not mistake a byte hit for a proven global instruction boundary.
    Selected contexts are decoded separately; indirect and non-.text edges
    remain explicitly outside this scan.
    """
    s = image.section('.text')
    require((s['address'], s['address'] + s['size'], s['offset'], s['flags']) ==
            (TEXT_START, TEXT_END, TEXT_START - 0x1000, 6), '.text geometry changed')
    begin, end = s['offset'], s['offset'] + s['size']
    rows = []
    for opcode in (0xe8, 0xe9):
        pos = begin
        while True:
            pos = image.data.find(bytes([opcode]), pos, end - 4)
            if pos < 0:
                break
            va = s['address'] + pos - begin
            if va + 5 + struct.unpack_from('<i', image.data, pos + 1)[0] == target:
                rows.append(decode(image.data[pos:pos + 5], va)[0])
            pos += 1
    return sorted(rows, key=lambda r: r['address'])


def inspect(data):
    """Internal structural certificate, separated for below-digest controls.

    Public generation always authenticates first; this function alone is not
    authorization to attribute arbitrary data to the target digest.
    """
    image = Image(data)
    frame = image.frame(START, END)
    require({k: frame[k] for k in FDE} == FDE, 'Function FDE identity changed')
    require(frame['fde_record']['bytes'] == '10000000b01b070044507b016f00000000000000', 'FDE bytes changed')
    require(frame['cie_record']['bytes'] == '1400000000000000017a5200017810011b0c070890010000', 'CIE bytes changed')
    body = image.read(START, END - START)
    instructions = certify_body(body)
    padding = []
    for a, b in ((0x24cdac6, START), (END, 0x24cdb40)):
        raw = image.read(a, b - a)
        require(raw == b'\xcc' * (b - a), 'Adjacent INT3 padding changed')
        padding.append({'start': a, 'end': b, 'size': b - a, 'bytes': raw.hex()})
    require(any(r['end'] == 0x24cdac6 for r in image.fdes), 'Previous FDE boundary changed')
    require(any(r['start'] == 0x24cdb40 for r in image.fdes), 'Next FDE boundary changed')
    calls = scan_calls(image, START)
    require([(r['address'], r['mnemonic']) for r in calls] == [(c[0], 'call') for c in CALLERS],
            'Direct caller census/target changed')
    callers = []
    for call, (site, owner, end, lo, hi) in zip(calls, CALLERS):
        owner_frame = image.frame(owner, end)
        require(owner <= lo <= site < hi <= end, 'Caller context outside owner')
        context = decode(image.read(lo, hi - lo), lo)
        require(call in context, 'CALL is not at a selected context instruction boundary')
        # The return buffer's four qwords are loaded immediately after the call.
        at = next(i for i, r in enumerate(context) if r['address'] == site)
        following = context[at + 1:]
        require(len(following) == 4 and all(r['mnemonic'] == 'mov' for r in following),
                'Caller output loads changed')
        callers.append({'site': site, 'instruction': call, 'owner': owner_frame,
                        'context_start': lo, 'context_end': hi, 'instructions': context,
                        'boundary_status': 'decoded selected window; full owner CFG/reachability unproved'})
    locations = []
    relsec = image.section('.rela.dyn')
    for insn_va, slot, reloc_off, string_va, path, line, column in LOCATIONS:
        instruction = decode(image.read(insn_va, 7), insn_va)
        require(len(instruction) == 1 and instruction[0]['mnemonic'] == 'lea' and
                instruction[0].get('rip_target') == slot, 'Source Location LEA changed')
        require(relsec['offset'] <= reloc_off and reloc_off + 24 <= relsec['offset'] + relsec['size'],
                'Relocation outside .rela.dyn')
        reloc = data[reloc_off:reloc_off + 24]
        require(struct.unpack('<QQq', reloc) == (slot, 8, string_va), 'Source Location relocation changed')
        raw = image.read(slot, 24)
        require(struct.unpack('<QQII', raw) == (0, len(path), line, column), 'Source Location words changed')
        require(image.read(string_va, len(path)) == path.encode('ascii'), 'Source path changed')
        owners = [c['owner']['start'] for c in callers if c['owner']['start'] <= insn_va < c['owner']['end']]
        require(len(owners) == 1, 'Location outside selected caller FDE')
        locations.append({'caller_owner': owners[0], 'instruction': instruction[0],
                          'slot': slot, 'location_bytes': raw.hex(), 'path': path,
                          'path_address': string_va, 'path_length': len(path), 'line': line, 'column': column,
                          'relocation': {'file_offset': reloc_off, 'offset': slot, 'type': 8,
                                         'symbol': 0, 'addend': string_va, 'bytes': reloc.hex()}})
    vectors = []
    for label, args, expected in VECTORS:
        require(project(*args) == expected, f'Frozen rule vector failed: {label}')
        vectors.append({'case': label, 'input_C_P_H_L': list(args), 'output_qwords': list(expected)})
    counts = {'function_bytes': len(body), 'instructions': len(instructions),
              'callees': 0, 'direct_call_sites': len(callers),
              'caller_fdes': len({c['owner']['start'] for c in callers}),
              'direct_tail_jump_sites': sum(r['mnemonic'] == 'jmp' for r in calls),
              'source_locations': len(locations), 'vectors': len(vectors),
              'padding_before': padding[0]['size'], 'padding_after': padding[1]['size']}
    return {
        'schema': 'node115-ring-ranges-v1', 'task': 'RE-001', 'component': 'consensus',
        'target': {'release': 115, 'sha256': SHA256, 'size': len(data)},
        'question': 'Which pointer endpoints does the complete leaf compute from its four input words?',
        'function': {'start': START, 'end': END, 'size': len(body),
                     'file_offset': image.offset(START, len(body)), 'body_sha256': digest(body),
                     'body_hex': body.hex(), 'frame': frame, 'padding': padding,
                     'instructions': instructions, 'callees': [],
                     'return': 'RAX = incoming RDI; four qwords written through that pointer'},
        'rule': {'input_offsets': {'C': 0, 'P': 8, 'H': 16, 'L': 24}, 'word_bits': 64,
                 'stride': 408, 'empty': 'L == 0: output = [P,P,P,P]',
                 'nonempty': 'h = H-C if H>=C else H; t = (C-h) mod 2^64; '
                             '(a,b) = (C,L-t) if L>t else ((h+L) mod 2^64,0); '
                             'output = [P+408*h,P+408*a,P,P+408*b] mod 2^64',
                 'inference': 'two ranges over a circular allocation of 408-byte elements, under valid ring geometry'},
        'caller_scan': {'section': '.text', 'start': TEXT_START, 'end': TEXT_END,
                        'method': 'every byte offset with five bytes remaining; e8/e9 plus signed rel32 equals entry',
                        'candidates': calls, 'callers': callers,
                        'limitation': 'local instruction decoding, not full caller CFG proof; indirect and non-.text callers unmeasured'},
        'source_association': locations, 'vectors': vectors, 'counts': counts,
        'non_claims': ['original Rust symbol/type/ABI', 'caller runtime reachability',
                       'element identity or consensus policy', 'memory safety for arbitrary raw words',
                       'full indirect caller census', 'Rust reconstruction or compiled equivalence',
                       'whole-node/component gate completion'],
    }


def records_bytes(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def generate(binary, out):
    with mapped(binary) as data:
        authenticate(data)
        record = inspect(data)
    # No output directory or file is created until authentication and all checks pass.
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_bytes(records_bytes(record))
    (out / 'README.md').write_text(render_readme(record), encoding='utf-8')
    return record


def render_readme(record):
    return README_TEMPLATE.format(
        revision=BASE_REVISION, sha=SHA256,
        body_sha=record['function']['body_sha256'],
        counts='\n'.join(f'| {k} | {v} |' for k, v in record['counts'].items()),
    )


README_TEMPLATE = '''# RE-001: node #115 ring-range projection

- Component: consensus-associated container projection; RE-001 with an RE-008 lead.
- Target: Linux x86-64 node #115, SHA-256 `{sha}`.
- Source/reference base: `{revision}`. No external source implementation used.
- Claim: observed complete leaf computation; circular-buffer interpretation is inference.
- Bounded question: which pointer endpoints does this function compute from its input words?

Given unsigned words C, P, H, L at input offsets +0, +8, +16, +24, an empty
L writes [P,P,P,P]. Otherwise it reduces H by C **once** if H >= C, producing h,
and computes t = (C-h) modulo 2^64. If L > t (unsigned), the output is
[P+408*h, P+408*C, P, P+408*(L-t)]; otherwise it is
[P+408*h, P+408*(h+L), P, P]. Every output address calculation wraps modulo
2^64. The function writes these words through incoming RDI and returns that
same pointer in RAX. Incoming RSI supplies the input. It calls no helper.

## Scope and bytes

The window is ELF VA `[0x24cdad0,0x24cdb3f)`, file offset `0x24ccad0`.
Body SHA-256: `{body_sha}`. The FDE is at VA/file offset `0xd18a84`,
CIE at `0xca6ed8`, augmentation `zR`, no LSDA. Actual FDE range, complete
instruction decoding, local branch closure, terminal RET and neighboring INT3
padding agree. The FDE is corroborating metadata, not the sole boundary proof.
Neighboring bodies are not bound. No normalized byte masks are used.

Every measured count below comes from `records.json`; the targeted test checks
this table against the JSON and against the underlying arrays/ranges.

| Metric | Count |
| --- | ---: |
{counts}

`records.json` contains the unnormalized body bytes, every decoded instruction,
FDE/CIE records, padding, caller windows and source-location relocation records.
There is no hidden native-disassembler dependency. The purpose-built strict
Python decoder handles only the forms used in this packet and rejects unknown
or truncated instructions; it does not claim to decode the whole ELF.

## Instruction proof

- `0x24cdad0..0x24cdadc`: preserve the output pointer, load L, and branch on
  zero before reading C or H. The empty arm zeroes the indices.
- `0x24cdadc..0x24cdaef`: load C and H; unsigned CMP/CMOVAE chooses C or zero
  for a single subtraction. This is not a general modulo operation.
- `0x24cdaef..0x24cdafd`: compute t in R9, subtract it from L in RDI, then
  JA selects wraparound exactly when there was no borrow and the difference
  was nonzero. Equality follows the contiguous arm.
- `0x24cdafd..0x24cdb0d`: the contiguous arm sets the first end index to h+L
  and the second to zero. The wrap arm retains C and L-t. The empty arm sets
  all indices to zero. Every branch targets a decoded instruction in this body.
- `0x24cdb0d..0x24cdb3f`: load P, multiply the indices by the immediate 408,
  add P, write the endpoints and return. IMUL retains the low word; signedness
  does not change that product modulo 2^64, and its overflow flags are unused.

All input loads precede every output store. This leaf reads no element payload,
allocates nothing, changes no input word except if it aliases the output, and
contains no indirect transfer, call, panic edge, or unclosed helper. On the
empty path it reads only L and P. Normal completion assumes readable required
input bytes, writable output bytes, a valid return stack and stable memory;
invalid pointers, concurrent mutation and hardware faults are outside the rule.
Output endpoints need not be dereferenceable for the leaf to compute them.

Under the additional ring interpretation (C > 0, h < C, L <= C and an adequate
allocation without address wrap), these endpoints represent the logical items
as a first range from the head toward the allocation end and a second range
from its base. The lengths add to L, and crossing the allocation end introduces
the second range. Empty input canonicalizes all endpoints to P. The raw-word
rule also covers invalid ring geometry: H >= C is reduced only once and the
tail subtraction can wrap. The frozen vectors deliberately include these
cases, the unsigned comparison boundary, and multiplication/address overflow.

## Callers and first-party association

The complete `.text` interval `[0x1419300,0x63f0a00)` was scanned at every byte
for E8/E9 plus signed rel32 targeting this entry. The retained hits are direct
CALL encodings at `0x2e0ec44`, `0x2e150ee`, `0x2e182a3`, `0x2e1f344`.
Each decodes on an instruction boundary in its retained local setup/readback
window, and every window lies in the recorded actual caller FDE. The readback
loads all output words immediately after CALL. This establishes syntactic
local call evidence, **not** complete caller-CFG validation or runtime
reachability: an all-byte scan can in general match data/immediates. Indirect
callers, other executable sections and dynamic targets are unmeasured.

Selected RIP-relative LEAs in enclosing caller FDEs resolve to relocated
Location records naming `node/src/consensus/state.rs:550:17` and
`node/src/consensus/mempool.rs:516:38`, `:809:14`. Actual RELATIVE entries,
string bytes/lengths and Location fields are checked. These are relative paths
already embedded in the target, not workstation paths. The association applies
to the enclosing FDEs, not necessarily the call's source line. No original
symbol, concrete container type, element identity or consensus behavior is
assigned. The remaining enclosing caller has no first-party attribution here.

## Novelty and ownership

Before writing this packet or investing in the bind, from repository root:

```sh
rg -i '24cdad0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '38591184' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

Both commands produced empty stdout and exit status 1. There are no outgoing
callees whose behavior needs an additional novelty check. Repeating these
commands after adding the packet will naturally find this packet itself.
The selected entry is inside the assigned address band and outside all supplied
claimed addresses. Only this work item, its new producer and new tests are in
scope; the caller windows are association evidence, not additional function binds.

## Reproduce and controls

From repository root, with the authenticated artifact materialized:

```sh
python3 tools/node115_ring_ranges.py --out research/work-items/RE-001-node115-ring-ranges/
python3 -m unittest tests.test_node115_ring_ranges -v
python3 research/work-items/RE-001-node115-ring-ranges/verify.py
make verify
make catalogue-check
```

Python 3.13.5 on Linux was used; the producer, verifier and tests require only
Python 3.10+ stdlib and the existing stdlib ELF/FDE readers. GNU objdump 2.44 was
used for exploratory inspection; no committed result or reproduction step
requires it. Static only: no captured node/visor execution, emulator, network,
installation, chain action or GitHub action. A single memory map avoids copying
the full binary. `make doctor` and initial `make verify` passed.

The producer authenticates the complete target before parsing or creating
outputs. The verifier requires an exact manifest whitelist, verifies file
hashes, then regenerates and byte-compares the semantic JSON and README.
Tests include whole-target digest failure, a body mutation below the digest
gate, shifted/extended FDEs, branch/stride/input-offset mutations, a redirected
incoming CALL, altered Location relocation/data, padding damage and unsupported
or truncated decoder input. There is no outgoing callee to retarget: the actual
incoming call target is the meaningful negative control. Frozen vectors and an
independent ring-index oracle exercise the rule without running machine code.

## Implementation, limitations and next step

Before this packet, the novelty search found no retained bind for the entry.
After it, the complete byte-backed word relation and conditional ring-range
meaning are reproducible. The small Python model is independently authored;
no inferred source text was copied. New files use the repository MIT license.
No Rust implementation, Cargo graph, compiled comparison, two-build result,
relocation-normalized match, full unwind semantics or original ABI is claimed.
The model tests establish consistency with the decoded rule, not dynamic
behavioral equivalence. No inventory/literal catalogue or progress gate changes.
Repository-wide tests, hosted CI and container builds are not claimed.

Next step: establish the input object's producer and its ring invariants in a
consensus/mempool caller, including the identity and lifetime of its elements,
before using this projection in a reconstructed state path.
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record = generate(args.binary, args.out)
    print(json.dumps(record['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
