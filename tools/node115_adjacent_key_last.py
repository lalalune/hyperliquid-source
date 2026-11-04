#!/usr/bin/env python3
"""Static #115 adjacent-key compaction certificate; Python 3.10+ stdlib only.

Independently authored under the repository MIT license. No native target code
is executed. The decoder intentionally accepts only the encodings used by this
packet; it is not a general disassembler. Public input always authenticates first.
"""
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

ROOT = Path(__file__).resolve().parents[1]
SLUG = 'adjacent-key-last'
NAME = 'node115_adjacent_key_last'
PACKET = ROOT / 'research/work-items' / ('RE-001-node115-' + SLUG)
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x5b2d510, 0x5b2d648
BODY_SHA = 'b0da65b42a0b5f1bea941c34249f63d6cfea9f27fb6ac0cf4e6c81290af3fbe4'
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
CALL_SITE, CALLER_START, CALLER_END = 0x4dff15a, 0x4dfe6d0, 0x4dff979
LOCATION_SITE, LOCATION = 0x4dfe87d, 0x649ccf8
PATH_VA = 0x44f5d5
SOURCE_PATH = 'node/src/consensus/execution_state.rs'
PACKET_FILES = ('README.md', 'instructions.txt', 'records.json', 'verify.py')
EXTERNAL_FILES = (f'tools/{NAME}.py', f'tests/test_{NAME}.py')
REGS = {
    64: 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(),
    32: 'eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d'.split(),
    128: [f'xmm{i}' for i in range(16)],
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(code, start):
    """Decode every byte, including ModRM/SIB, REX, widths and signed rel32.

    Unsupported opcode, prefix, addressing form or partial instruction rejects.
    Callers use bounded snippets; the selected leaf uses its whole FDE body.
    """
    rows, pos = [], 0
    while pos < len(code):
        begin = pos
        def take(n):
            nonlocal pos
            require(pos + n <= len(code), 'Truncated instruction')
            value = code[pos:pos + n]
            pos += n
            return value
        def integer(n, signed=False):
            return int.from_bytes(take(n), 'little', signed=signed)
        prefixes = []
        while pos < len(code) and code[pos] in (0x66, 0xf3, 0x2e):
            prefixes.append(integer(1))
            require(len(prefixes) <= 7, 'Oversized prefix sequence')
        rex = integer(1) if pos < len(code) and 0x40 <= code[pos] <= 0x4f else 0
        width = 64 if rex & 8 else 32
        def reg(number, bits):
            return {'kind': 'reg', 'name': REGS[bits][number], 'width': bits}
        def imm(value):
            return {'kind': 'imm', 'value': value}
        def modrm(reg_width, rm_width):
            m = integer(1)
            mod, rr, rm = m >> 6, (m >> 3) & 7, m & 7
            r = reg(rr + (8 if rex & 4 else 0), reg_width)
            if mod == 3:
                return r, reg(rm + (8 if rex & 1 else 0), rm_width), rr
            mem = {'kind': 'mem', 'width': rm_width, 'base': None,
                   'index': None, 'scale': 1, 'disp': 0}
            if rm == 4:
                sib = integer(1)
                scale, index, base = sib >> 6, (sib >> 3) & 7, sib & 7
                mem['scale'] = 1 << scale
                if index != 4 or rex & 2:
                    mem['index'] = REGS[64][index + (8 if rex & 2 else 0)]
                if mod == 0 and base == 5:
                    mem['disp'] = integer(4, True)
                else:
                    mem['base'] = REGS[64][base + (8 if rex & 1 else 0)]
            elif mod == 0 and rm == 5:
                mem['base'] = 'rip'
                mem['disp'] = integer(4, True)
            else:
                mem['base'] = REGS[64][rm + (8 if rex & 1 else 0)]
            if mod in (1, 2):
                mem['disp'] = integer(1 if mod == 1 else 4, True)
            return r, mem, rr
        op = integer(1)
        mnemonic, args, target = None, [], None
        if op == 0x0f:
            second = integer(1)
            if second == 0x1f:
                require(all(p in (0x66, 0x2e) for p in prefixes) and not rex, 'Bad NOP prefix')
                _, memory, group = modrm(32, 32)
                require(group == 0 and memory['kind'] == 'mem', 'Bad NOP ModRM')
                mnemonic = 'nop'
            elif second in (0x83, 0x86):
                require(not prefixes and not rex, 'Bad branch prefix')
                delta = integer(4, True)
                mnemonic = {0x83: 'jae', 0x86: 'jbe'}[second]
                target = start + pos + delta
            elif second in (0x10, 0x11, 0x6f, 0x7f, 0x6e, 0x74, 0xdb, 0xd7):
                expected = [] if second in (0x10, 0x11) else [0xf3] if second in (0x6f, 0x7f) else [0x66]
                require(prefixes == expected and not (rex & 8), 'Unsupported SSE prefix/width')
                rw, mw = (32, 128) if second == 0xd7 else (128, 32) if second == 0x6e else (128, 128)
                r, rm, _ = modrm(rw, mw)
                if second == 0xd7:
                    require(rm['kind'] == 'reg', 'PMOVMSKB requires register source')
                mnemonic = {0x10:'movups', 0x11:'movups', 0x6f:'movdqu', 0x7f:'movdqu',
                            0x6e:'movd', 0x74:'pcmpeqb', 0xdb:'pand', 0xd7:'pmovmskb'}[second]
                args = [rm, r] if second in (0x11, 0x7f) else [r, rm]
            else:
                raise ValueError(f'Unsupported 0f opcode {second:#x}')
        else:
            require(not prefixes, 'Unsupported integer prefix')
            if op in (0x8b, 0x89, 0x8d, 0x01, 0x29, 0x31, 0x39):
                r, rm, _ = modrm(width, width)
                mnemonic = {0x8b:'mov', 0x89:'mov', 0x8d:'lea', 0x01:'add',
                            0x29:'sub', 0x31:'xor', 0x39:'cmp'}[op]
                args = [r, rm] if op in (0x8b, 0x8d) else [rm, r]
                if op == 0x8d:
                    require(rm['kind'] == 'mem', 'LEA requires memory encoding')
            elif op in (0x81, 0x83, 0xc1, 0xff):
                _, rm, group = modrm(width, width)
                require(not rex & 4, 'Unsupported group REX.R')
                table = {0:'add', 5:'sub', 7:'cmp'} if op in (0x81, 0x83) else {4:'shl'} if op == 0xc1 else {0:'inc', 1:'dec'}
                require(group in table, 'Unsupported group opcode')
                mnemonic, args = table[group], [rm]
                if op != 0xff:
                    args.append(imm(integer(4 if op == 0x81 else 1, op != 0xc1)))
            elif 0xb8 <= op <= 0xbf:
                mnemonic = 'mov'
                args = [reg(op - 0xb8 + (8 if rex & 1 else 0), width), imm(integer(8 if width == 64 else 4))]
            elif op in (0x72, 0x73, 0x74, 0x75, 0x76, 0xeb, 0xe8, 0xe9):
                require(not rex, 'Unsupported branch REX')
                delta = integer(4 if op in (0xe8, 0xe9) else 1, True)
                mnemonic = {0x72:'jb', 0x73:'jae', 0x74:'je', 0x75:'jne', 0x76:'jbe',
                            0xeb:'jmp', 0xe8:'call', 0xe9:'jmp'}[op]
                target = start + pos + delta
            elif op == 0xc3:
                require(not rex, 'Unsupported RET prefix')
                mnemonic = 'ret'
            else:
                raise ValueError(f'Unsupported opcode {op:#x}')
        require(pos - begin <= 15, 'Instruction exceeds x86 length limit')
        for arg in args:
            if arg['kind'] == 'mem' and arg['base'] == 'rip':
                arg['address'] = start + pos + arg['disp']
        row = {'address': start + begin, 'bytes': code[begin:pos].hex(),
               'mnemonic': mnemonic, 'operands': args}
        if target is not None:
            row['target'] = target
        rows.append(row)
    return rows


def compact_model(records):
    """Independent grouping specification: last complete record of each key run."""
    require(all(isinstance(r, bytes) and len(r) == 32 for r in records), 'Expected 32-byte records')
    result = []
    for record in records:
        if result and result[-1][:20] == record[:20]:
            result[-1] = record
        else:
            result.append(record)
    return result


def leaf_instructions(body):
    """Close every byte of the selected body, independently of the ELF parser."""
    require(len(body) == END - START and digest(body) == BODY_SHA, 'Changed function bytes')
    return decode(body, START)


def byte_walk_model(records):
    """Instruction-grounded copy/swap schedule, including bytes beyond new length.

    This is an authored Python algorithm, not a CPU interpreter or target run.
    The returned count is the stored length, not a native return-register claim.
    """
    require(all(isinstance(r, bytes) and len(r) == 32 for r in records), 'Expected 32-byte records')
    rows, n = list(records), len(records)
    first = next((i for i in range(n - 1) if rows[i][:20] == rows[i + 1][:20]), None)
    if first is None:
        return rows, n
    rows[first], rows[first + 1] = rows[first + 1], rows[first]
    write = first + 1
    for read in range(first + 2, n):
        if rows[read][:20] == rows[write - 1][:20]:
            rows[read], rows[write - 1] = rows[write - 1], rows[read]
        else:
            rows[write] = rows[read]
            write += 1
    return rows, write


def equality_mask(a, b):
    """MOVD zero-fill + PCMPEQB + PAND + PMOVMSKB, for the observed load offsets."""
    require(len(a) == len(b) == 32, 'Expected complete records')
    first = [0xff if x == y else 0 for x, y in zip(a[:16], b[:16])]
    tail = [0xff if x == y else 0 for x, y in zip(a[16:20], b[16:20])] + [0xff] * 12
    return sum(((x & y) >> 7) << i for i, (x, y) in enumerate(zip(first, tail)))


def fixtures():
    def row(key, payload):
        return bytes([key]) * 20 + bytes([payload]) * 12
    cases = [([], 'empty'), ([row(1, 1)], 'singleton'),
             ([row(1, 1), row(2, 2)], 'distinct'),
             ([row(1, 1), row(1, 2)], 'equal-key-last-payload'),
             ([row(1, 1), row(1, 2), row(1, 3)], 'whole-run'),
             ([row(1, 1), row(2, 2), row(1, 3)], 'nonadjacent-repeat'),
             ([row(1, 1), row(2, 2), row(2, 3)], 'duplicate-at-end'),
             ([row(1, 1), row(1, 2), row(2, 3), row(2, 4), row(1, 5)], 'multiple-runs')]
    for i in range(32):
        a = bytes(32)
        b = bytes([0] * i + [0x80] + [0] * (31 - i))
        cases.append(([a, b], f'single-different-byte-{i}'))
    result = []
    for rows, label in cases:
        memory, length = byte_walk_model(rows)
        require(memory[:length] == compact_model(rows), 'Model disagreement')
        result.append({'case': label, 'input': [r.hex() for r in rows],
                       'output_prefix': [r.hex() for r in compact_model(rows)],
                       'stored_length': length, 'entire_backing_after': [r.hex() for r in memory]})
    return result


def va_offset(secs, va, size):
    choices = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(choices) == 1, 'Ambiguous or unmapped VA')
    s = choices[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size):
    off = va_offset(secs, va, size)
    return data[off:off + size]


def frame_record(data, secs, cies, fdes, start, end, fde_va, cie_va):
    matches = [f for f in fdes if f['start'] == start]
    require(len(matches) == 1, 'Missing or duplicate FDE')
    f = matches[0]
    require((f['end'], f['fde'], f['cie']) == (end, fde_va, cie_va), 'FDE extent/identity changed')
    record = dict(f)
    record['cie_decoded'] = cies[cie_va]
    for label, va in [('fde', fde_va), ('cie', cie_va)]:
        off = va_offset(secs, va, 4)
        length = struct.unpack_from('<I', data, off)[0] + 4
        record[label + '_file_offset'] = off
        record[label + '_bytes'] = read_va(data, secs, va, length).hex()
    return record


def caller_scan(data, text, fdes):
    """All byte-aligned e8/e9 rel32 matches, without pretending to decode .text."""
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]
    lower, upper = text['offset'], text['offset'] + text['size']
    hits = []
    for opcode in (0xe8, 0xe9):
        at = lower
        while True:
            at = data.find(bytes([opcode]), at, upper - 4)
            if at < 0:
                break
            site = text['address'] + at - lower
            delta = struct.unpack_from('<i', data, at + 1)[0]
            if site + 5 + delta == START:
                k = bisect.bisect_right(starts, site) - 1
                owner = ordered[k] if k >= 0 and site + 5 <= ordered[k]['end'] else None
                hits.append({'site': site, 'bytes': data[at:at + 5].hex(), 'target': START,
                             'kind': 'call' if opcode == 0xe8 else 'tail-jump',
                             'owner_start': owner['start'] if owner else None,
                             'owner_end': owner['end'] if owner else None})
            at += 1
    return sorted(hits, key=lambda r: r['site'])


def _analyze(data):
    """Strict structural checks below the public hash gate, exposed for controls."""
    secs = sections(data)
    require(len({s['name'] for s in secs}) == len(secs), 'Duplicate ELF section')
    text = next(s for s in secs if s['name'] == '.text')
    require((text['address'], text['size'], text['flags']) == (TEXT_START, TEXT_END - TEXT_START, 6), 'Wrong .text')
    cies, fdes = eh_frame_records(data, secs)
    frame = frame_record(data, secs, cies, fdes, START, END, 0xfd1f08, 0xca6ed8)
    require(frame['lsda'] is None and frame['cie_decoded']['augmentation'] == 'zR', 'Unexpected unwind augmentation')
    body = read_va(data, secs, START, END - START)
    instructions = leaf_instructions(body)
    by_pc = {r['address']: r for r in instructions}
    for ins in instructions:
        require(ins['mnemonic'] != 'call', 'Leaf has a callee')
        if 'target' in ins:
            require(ins['target'] in by_pc, 'Branch leaves function or enters instruction interior')
    require(instructions[-1]['mnemonic'] == 'ret', 'No terminal RET')
    # Enumerate the CFG, including internal NOP padding, and reject dead bytes.
    pending, visited, edges = [START], set(), []
    while pending:
        pc = pending.pop()
        if pc in visited:
            continue
        visited.add(pc)
        ins = by_pc[pc]
        successors = [] if ins['mnemonic'] == 'ret' else [pc + len(bytes.fromhex(ins['bytes']))]
        if 'target' in ins:
            successors = ([ins['target']] if ins['mnemonic'] == 'jmp' else successors + [ins['target']])
        for nxt in successors:
            require(nxt in by_pc, 'CFG falls outside body')
            edges.append([pc, nxt])
            pending.append(nxt)
    unreachable = [r for r in instructions if r['address'] not in visited]
    require(all(r['mnemonic'] == 'nop' for r in unreachable), 'Unreachable non-padding instruction')
    next_start = min(f['start'] for f in fdes if f['start'] > START)
    require(next_start == 0x5b2d650, 'Following FDE moved')
    padding = read_va(data, secs, END, next_start - END)
    require(padding == b'\xcc' * (next_start - END), 'Changed external padding')
    hits = caller_scan(data, text, fdes)
    require([(r['site'], r['kind'], r['owner_start'], r['owner_end']) for r in hits]
            == [(CALL_SITE, 'call', CALLER_START, CALLER_END)], 'Direct caller census changed')
    caller_frame = frame_record(data, secs, cies, fdes, CALLER_START, CALLER_END, 0x130072c, 0x103d604)
    snippets = []
    for role, a, b, expected in [
        ('argument-call-result-loads', 0x4dff152, 0x4dff177,
         '488dbc2400020000e8b1e3d200488b8c2400020000488b842408020000488b942410020000'),
        ('source-location-reference', LOCATION_SITE, LOCATION_SITE + 7, '488d0d74e46901'),
        ('incoming-direct-branch', 0x4dff846, 0x4dff84b, 'e907f9ffff'),
        ('other-incoming-direct-branch', 0x4dff866, 0x4dff86b, 'e9e7f8ffff'),
    ]:
        raw = read_va(data, secs, a, b - a)
        decoded = decode(raw, a)
        require(raw.hex() == expected, 'Caller slice/target changed')
        snippets.append({'role': role, 'start': a, 'end': b, 'instructions': decoded})
    require(snippets[0]['instructions'][1]['target'] == START, 'Wrong callee target')
    require(snippets[1]['instructions'][0]['operands'][1]['address'] == LOCATION, 'Wrong Location target')
    loc = read_va(data, secs, LOCATION, 24)
    pointer, path_length, line, column = struct.unpack('<QQII', loc)
    require((pointer, path_length, line, column) == (0, len(SOURCE_PATH), 138, 29), 'Source Location changed')
    relsec = next(s for s in secs if s['name'] == '.rela.dyn')
    require(relsec['size'] % 24 == 0, 'Truncated relocation table')
    rels = []
    for off in range(relsec['offset'], relsec['offset'] + relsec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == LOCATION:
            rels.append({'file_offset': off, 'slot': slot, 'type': info & 0xffffffff,
                         'symbol': info >> 32, 'addend': addend, 'bytes': data[off:off + 24].hex()})
    require(len(rels) == 1 and (rels[0]['type'], rels[0]['symbol'], rels[0]['addend'])
            == (8, 0, PATH_VA), 'Location relocation changed')
    path = read_va(data, secs, PATH_VA, path_length)
    require(path == SOURCE_PATH.encode(), 'Source path changed')
    vectors = fixtures()
    return {
        'target': {'release': 115, 'sha256': SHA, 'size': len(data), 'coordinate_system': 'original ELF virtual addresses'},
        'base_commit': BASE,
        'question': 'Does this leaf keep the first or last complete record of each adjacent equal-key run, and which bytes form the key?',
        'function': {'start': START, 'end': END, 'size': END - START,
                     'file_offset': va_offset(secs, START, END - START), 'body_sha256': digest(body),
                     'body_hex': body.hex(), 'frame': frame, 'instructions': instructions,
                     'cfg_edges': sorted(edges), 'unreachable_padding_addresses': [r['address'] for r in unreachable],
                     'callees': [], 'indirect_transfers': [],
                     'following_padding': {'start': END, 'end': next_start, 'bytes': padding.hex()}},
        'caller_census': {'scan_start': TEXT_START, 'scan_end': TEXT_END, 'scan_bytes': TEXT_END - TEXT_START,
                         'method': 'Every byte position that can hold e8/e9 plus signed rel32; target = site + 5 + displacement.',
                         'hits': hits, 'caller_frame': caller_frame, 'decoded_slices': snippets,
                         'limitation': 'Byte-pattern census, not a full .text disassembly. The hit is corroborated by local argument/call/load instructions and incoming branches. Indirect/data references and caller reachability are not counted.'},
        'source_association': {'path': SOURCE_PATH, 'path_va': PATH_VA, 'path_bytes': path.hex(),
                               'location_va': LOCATION, 'location_bytes': loc.hex(), 'line': line, 'column': column,
                               'relocation': rels[0], 'reference_site': LOCATION_SITE,
                               'status': 'Observed Location-shaped record in the caller FDE, not an original name or function ownership proof.'},
        'rule': {'row_bytes': 32, 'key_bytes': 20, 'payload_bytes': 12,
                 'object_pointer_offset': 8, 'object_length_offset': 16,
                 'keeper': 'last complete record in each maximal adjacent equal-key run',
                 'order': 'original run order; nonadjacent equal keys are not merged',
                 'equality_mask': 65535,
                 'mask_lane_key_dependencies': [[i, i + 16] if i < 4 else [i] for i in range(16)],
                 'preconditions': 'Valid stack/return; readable object length; for n>=2 readable pointer field and writable nonwrapping n*32-byte backing range disjoint from object; no concurrent mutation.',
                 'effects': 'No writes when n<2 or no adjacent equality. Otherwise copy/swap full rows and store run count at object+16; backing tail is modified, not erased. No allocation, callee, static data or relocation is used by the leaf.',
                 'return': 'No source-level return value claimed; meaningful result is memory plus stored length.'},
        'vectors': vectors,
        'metrics': {'body_bytes': len(body), 'instructions': len(instructions),
                    'ret_sites': sum(r['mnemonic'] == 'ret' for r in instructions),
                    'branch_sites': sum('target' in r for r in instructions),
                    'internal_padding_bytes': sum(len(bytes.fromhex(r['bytes'])) for r in instructions if r['mnemonic'] == 'nop'),
                    'external_padding_bytes': len(padding), 'callees': 0, 'caller_sites': len(hits),
                    'caller_functions': len({r['owner_start'] for r in hits}),
                    'e8_sites': sum(r['kind'] == 'call' for r in hits),
                    'e9_sites': sum(r['kind'] == 'tail-jump' for r in hits), 'vectors': len(vectors)},
    }


def analyze(data):
    require(digest(data) == SHA, 'Node #115 digest mismatch')
    return _analyze(data)


def inspect(binary=TARGET):
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) > 0, 'Empty input')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return analyze(data)


def operand_text(arg):
    if arg['kind'] == 'reg':
        return arg['name']
    if arg['kind'] == 'imm':
        return str(arg['value'])
    pieces = ([arg['base']] if arg['base'] else []) + ([f"{arg['index']}*{arg['scale']}"] if arg['index'] else [])
    expr = '+'.join(pieces) + (f"{arg['disp']:+#x}" if arg['disp'] else '')
    return f"{arg['width']}bit [{expr or '0'}]"


def instruction_text(record):
    blocks = [('complete leaf', record['function']['instructions'])]
    blocks += [(s['role'], s['instructions']) for s in record['caller_census']['decoded_slices']]
    out = [f'Target node #115 SHA-256 {SHA}', 'Original ELF VAs; strict Python decoder; bytes unnormalized.', '']
    for title, rows in blocks:
        out.append(title)
        for r in rows:
            operands = ', '.join(operand_text(a) for a in r['operands'])
            if 'target' in r:
                operands = hex(r['target'])
            out.append(f"{r['address']:#x}  {r['bytes']:<30}  {r['mnemonic']} {operands}".rstrip())
        out.append('')
    return '\n'.join(out)


def readme_text(r):
    f, m, rule = r['function'], r['metrics'], r['rule']
    c = r['caller_census']
    table = '\n'.join(f'| {key} | {m[key]} |' for key in sorted(m))
    return f'''# RE-001: node #115 adjacent-key compaction keeps the last record

Component: consensus-associated collection transformation; RE-001 function bind,
preparatory evidence for RE-008. Base/reference commit: `{BASE}`.
Target: node #{r['target']['release']}, SHA-256 `{SHA}`.
All coordinates are original ELF virtual addresses unless explicitly file offsets.
New analysis, models, tests and documentation are independently authored under MIT.

## Bounded question and answer

{r['question']}

**Rule.** Given an object in RDI with backing pointer at `+{rule['object_pointer_offset']:#x}`
and unsigned length at `+{rule['object_length_offset']:#x}`, the leaf compacts
maximal adjacent runs with equal leading **{rule['key_bytes']} bytes** of each
**{rule['row_bytes']}-byte record**. It keeps the **last complete record** of each
run, including its trailing {rule['payload_bytes']} bytes, in original run order,
and stores the run count at the length field. Nonadjacent equal keys remain
separate. Short inputs and inputs without adjacent equality receive no writes.
On compaction, the backing tail can change and is not erased. The observed result
is memory and length; an original source-level return type is not recovered.

This rule assumes a valid stack/return and readable length field. For the
nontrivial route, the pointer field must be readable and the backing range must
be writable, nonwrapping, cover the original length times record size, and be
disjoint from the object. No concurrent mutation is allowed. Arbitrary invalid
pointer/length combinations are outside the theorem.

## Boundaries and instruction evidence

The complete window is `{f['start']:#x}..{f['end']:#x}` (half-open), file offset
`{f['file_offset']:#x}`, body SHA-256 `{f['body_sha256']}`.
Actual FDE `{f['frame']['fde']:#x}` (file offset `{f['frame']['fde_file_offset']:#x}`)
references CIE `{f['frame']['cie']:#x}` (file offset `{f['frame']['cie_file_offset']:#x}`),
augmentation `zR`, with no LSDA. `records.json` retains complete FDE/CIE bytes,
body bytes, strict decoded operands and CFG edges. `instructions.txt` is the
complete byte walk, including internal NOP padding. Every conditional target is
an instruction boundary inside the body; every non-padding instruction is
reachable in the structural CFG. Terminal RETs and the following INT3 fill through
`{f['following_padding']['end']:#x}` corroborate the FDE extent. This establishes
this bounded leaf, not a general rule equating FDEs with source functions.

All reported packet counts below are derived from `records.json.metrics` and
checked against this README by the targeted tests.

| Metric | Count |
| --- | ---: |
{table}

The leaf has no calls, indirect transfers, RIP-relative data accesses or external
branches, so its callee identity/extent set is empty. No callee behavior is left
conditional. Internal alignment bytes are inside the body hash; external INT3
padding is recorded separately and earns no implementation-byte credit.

## Why the key comparison and last-record rule follow from bytes

- `0x5b2d510..0x5b2d52f` loads the length, uses unsigned JB to return for short
  inputs, loads the backing pointer, computes the last comparison offset by
  shift and subtraction, and initializes the scan. The admitted memory geometry
  makes these address calculations exact, without integer wrap.
- `0x5b2d540..0x5b2d56f` compares adjacent leading SIMD blocks. MOVD loads the
  remaining key fragment and zeroes its upper lanes. PCMPEQB therefore produces
  all-one upper lanes for that fragment; PAND combines the leading-block equality
  and fragment equality. PMOVMSKB followed by comparison with
  `{rule['equality_mask']:#x}` is true exactly when the whole key matches.
  The machine-readable `mask_lane_key_dependencies` shows which key bytes
  contribute to each mask bit. Payload bytes are not compared.
- `0x5b2d571..0x5b2d57d` advances by the decoded record stride until an equal pair
  is found or the end is reached. Without an equal pair it returns without writes.
- `0x5b2d57e..0x5b2d5ad` loads and swaps both halves of the first equal pair.
  The later row now occupies the retained position. RDX becomes the write index
  after the retained prefix; RAX is the remaining unread count. JBE handles an
  equal pair at the end. The count cannot underflow under the stated geometry.
- `0x5b2d5dc..0x5b2d616` compares the next unread row with the last retained row,
  using the same key relation. On inequality, `0x5b2d5c0..0x5b2d5da` copies the
  complete row into the write position and increments the write index. On equality,
  `0x5b2d618..0x5b2d641` swaps the complete unread row with the last retained row,
  leaving the write index unchanged. Both routes advance the read pointer and
  decrease the remaining count.
- `0x5b2d643` stores the write index as the new length, then returns.

Inductive invariant: before processing an unread row, the prefix up to the write
index is the last complete representative of every run in the processed input.
The last retained key either equals the next input key, replacing its representative,
or differs, extending the prefix. Reads never revisit the already-processed tail,
and writes never reach a future unread row. The invariant proves the stated rule
for every valid finite input, including a run extending to the last row. It does
not require sorted input and does not prove global deduplication. Copying after a
duplicate can leave repeated stale rows in the backing tail; only the live prefix
has the compacted interpretation.

## Direct caller and source association

The census scans every eligible byte position in `.text`
`{c['scan_start']:#x}..{c['scan_end']:#x}` ({c['scan_bytes']} bytes) for E8/E9 rel32
whose signed displacement targets the leaf. The sole hit is CALL at
`{CALL_SITE:#x}`, in actual FDE `{CALLER_START:#x}..{CALLER_END:#x}`.
It is corroborated by the decoded LEA of `[rsp+0x200]` into RDI followed by the
CALL and reloads of the object fields, plus incoming direct jumps to that LEA.
All these relied-on instructions are decoded by the same strict Python decoder.
The census counts byte-pattern matches; it does not decode the entire text section,
prove all caller reachability, or discover indirect calls/data-held pointers.

The caller FDE also contains a RIP-relative LEA at `{LOCATION_SITE:#x}` naming
Location-shaped record `{LOCATION:#x}`. Its pointer is resolved by the retained
`R_X86_64_RELATIVE` relocation to `{PATH_VA:#x}`. Length, raw path bytes and
line/column bind it to `{SOURCE_PATH}:{r['source_association']['line']}:{r['source_association']['column']}`.
This is observed first-party source association through a direct caller, not a
recovered name, proof of exclusive ownership, or interpretation of key/payload
fields as particular consensus entities. The caller itself is not behavior-bound;
its other helpers and source-level collection type remain unresolved.

## Novelty and scope

Before creating this packet, at the base commit above, these exact searches
returned **empty stdout and exit status 1**:

```sh
rg -i '5b2d510' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '95606032' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -in 'adjacent-key-last|adjacent_key_last|run-key-compact|run_key_compact|5b2d510|95606032' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

These are historical pre-creation checks: this packet necessarily matches them
now. The callee novelty check is vacuous because the bound leaf has no callees.
Its start is within the assigned band and outside the excluded crowded interval.
Only this new packet, its generator and targeted tests are added. No imported
records, catalogue, progress gate, existing tool/test or upstream pin is changed.

## Reproduction and controls

From the repository root with the authenticated artifact present:

```sh
python3 tools/{NAME}.py --out research/work-items/RE-001-node115-{SLUG}/
python3 -m unittest tests.test_{NAME} -v
python3 research/work-items/RE-001-node115-{SLUG}/verify.py
make verify
make catalogue-check
```

The generator authenticates the entire artifact before interpretation or output
creation, uses a single read-only mmap, and writes deterministic JSON, byte walk,
README, verifier and manifest. It requires Python 3.10+ and only stdlib plus the
repository's existing stdlib ELF/FDE parsers. The local validation environment
was Linux x86-64 with Python 3.13.5. GNU objdump 2.44 was used for exploratory
cross-checking; generation, tests and verification never invoke or depend on it.
No captured node/visor, emulator, service, network request or installation is used.

`compact_model` is an independently authored grouping specification;
`byte_walk_model` expresses the decoded copy/swap schedule, including the tail.
The retained vectors cover empty/singleton/distinct runs, last-payload retention,
end-of-input duplicates, separated repeats, and a change at every byte position.
Tests additionally exhaust short key sequences and compare the SIMD-lane relation
with byte equality. These are instruction-grounded static fixtures, not outputs
captured by running the target. Corruption controls cover wrong/truncated input,
every body byte, unsupported/truncated instructions, an altered key load, flipped
branch, shifted FDE, caller target, source relocation and external padding.
Manifest checks enforce an exact path whitelist and regeneration, not merely
hashes of whatever files an altered manifest names.

## Results, non-claims and next step

Before this packet, the selected address had no bind in the checked research or
PR lists. The result closes the complete local transformation and its key width,
keeper choice and mutation schedule. The full branch walk and induction are the
semantic argument; a successful generator run alone is not equivalence evidence.

No Rust implementation or build comparison is provided. Source/compiler/dependency
closure, original ABI/types, caller sorting/admission, protocol meaning, runtime
fault/unwind behavior on invalid inputs, indirect consumers and whole-ELF identity
remain unmeasured. There are no normalization masks or transplanted implementation
bytes. All component/full-scope acceptance gates remain open; no progress update,
hosted CI result or full repository test-suite pass is claimed.

Next: recover the caller's input construction and ordering before assigning
consensus meaning or global uniqueness to the compacted records.
'''


VERIFY_SOURCE = '''#!/usr/bin/env python3
"""Verify the exact adjacent-key-last packet whitelist and regenerate its evidence."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'tools/node115_adjacent_key_last.py').is_file())
sys.path.insert(0, str(ROOT / 'tools'))
from node115_adjacent_key_last import verify_packet

if __name__ == '__main__':
    try:
        verify_packet(Path(__file__).resolve().parent)
    except (ValueError, OSError) as error:
        print(f'verification failed: {error}', file=sys.stderr)
        raise SystemExit(1)
    print('node #115 adjacent-key-last: whitelist, hashes and regeneration passed')
'''


def outputs(record):
    return {'records.json': (json.dumps(record, indent=2, sort_keys=True) + '\n').encode(),
            'instructions.txt': instruction_text(record).encode(),
            'README.md': readme_text(record).encode(), 'verify.py': VERIFY_SOURCE.encode()}


def manifest_text(payloads):
    blobs = dict(payloads)
    blobs.update({name: (ROOT / name).read_bytes() for name in EXTERNAL_FILES})
    return ''.join(f'{digest(blobs[name])}  {name}\n' for name in sorted(blobs))


def generate(binary, out):
    record = inspect(binary)
    payloads = outputs(record)
    # Build everything, including hashes, before creating any output.
    payloads['MANIFEST.sha256'] = manifest_text(payloads).encode()
    out = Path(out)
    if out.exists():
        require({p.name for p in out.iterdir()} <= set(payloads), 'Unexpected output file')
        require(not any(p.is_symlink() for p in out.iterdir()), 'Symlink output rejected')
    require(not out.is_symlink(), 'Symlink output directory rejected')
    out.mkdir(parents=True, exist_ok=True)
    for name, blob in payloads.items():
        (out / name).write_bytes(blob)
    return record


def verify_packet(packet=PACKET):
    packet = Path(packet)
    allowed = set(PACKET_FILES) | set(EXTERNAL_FILES)
    require({p.name for p in packet.iterdir()} == set(PACKET_FILES) | {'MANIFEST.sha256'}, 'Packet file whitelist mismatch')
    require(not packet.is_symlink(), 'Symlink packet rejected')
    seen = set()
    for line in (packet / 'MANIFEST.sha256').read_text().splitlines():
        fields = line.split('  ')
        require(len(fields) == 2, 'Malformed manifest row')
        sha, name = fields
        require(name in allowed and name not in seen, 'Manifest whitelist/duplicate mismatch')
        require(len(sha) == 64 and all(c in '0123456789abcdef' for c in sha), 'Invalid digest')
        path = packet / name if name in PACKET_FILES else ROOT / name
        require(path.is_file() and not path.is_symlink(), 'Missing file or symlink')
        require(digest(path.read_bytes()) == sha, 'Manifest digest mismatch')
        seen.add(name)
    require(seen == allowed, 'Manifest missing whitelisted file')
    expected = outputs(inspect())
    for name, blob in expected.items():
        require((packet / name).read_bytes() == blob, f'Regeneration mismatch: {name}')
    require((packet / 'MANIFEST.sha256').read_text() == manifest_text(expected), 'Noncanonical manifest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        r = generate(args.binary, args.out)
    except (ValueError, OSError, StopIteration, struct.error) as error:
        print(f'{NAME}: {error}', file=sys.stderr)
        return 1
    print(json.dumps({'target_sha256': SHA, 'start': hex(START), **r['metrics']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
