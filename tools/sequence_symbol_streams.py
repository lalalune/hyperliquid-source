#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RE-001: static, digest-bound decoding of node #94's packed symbol leaf.

Python 3.10+ stdlib only; never invokes a disassembler or executes target code.
The decoder is deliberately restricted to the instruction forms used here.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-sequence-symbols-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END, NEXT = 0x555f240, 0x555f319, 0x555f320
BODY_SHA = '3346eb8e78da732005e6105fb970c427edaecdea1cc407b9397ad97ac9707f83'
FDE_OFFSET, CIE_OFFSET = 0x2cfe64, 0
TABLES = ((0x8015c0, 64), (0x801540, 128))
CALL_SITES = (0x555f385, 0x55f7a07)
MASK64 = (1 << 64) - 1
REGS = {
    64: 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(),
    32: 'eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d'.split(),
    16: 'ax cx dx bx sp bp si di r8w r9w r10w r11w r12w r13w r14w r15w'.split(),
    8: 'al cl dl bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b'.split(),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def target(path=BINARY):
    with Path(path).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'target size mismatch')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            require(digest(data) == SHA256, 'target digest mismatch')
            yield data


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section name')
        self.by_name = {s['name']: s for s in self.sections}
        require(all(n in self.by_name for n in ('.text', '.rodata', '.eh_frame')),
                'missing required section')

    def read(self, va, size):
        require(size >= 0, 'negative read size')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'unmapped or ambiguous read')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


@dataclass(frozen=True)
class Instruction:
    address: int
    raw: bytes
    op: str
    args: tuple = ()
    target: int = None

    @property
    def end(self):
        return self.address + len(self.raw)

    def text(self):
        return f'{self.address:#x}: {self.raw.hex():<30} {self.op}' + (
            ' ' + ', '.join(self.args) if self.args else '')


def decode(code, start):
    """Strict structural x86-64 decoder, including ModRM/SIB and rel targets.

    Accept only the forms needed by the leaf and retained caller contexts.
    It rejects truncation, unsupported prefixes/opcodes and reserved groups.
    It is not a general x86 disassembler or a symbolic executor.
    """
    out, pos = [], 0

    def take(n):
        nonlocal pos
        require(pos + n <= len(code), 'truncated instruction')
        value = code[pos:pos + n]
        pos += n
        return value

    def integer(n, signed=False):
        return int.from_bytes(take(n), 'little', signed=signed)

    while pos < len(code):
        begin = pos
        addr = start + begin
        op, args, branch = None, (), None
        if code[pos:pos + 4] == bytes.fromhex('f30f1efa'):
            take(4)
            out.append(Instruction(addr, code[begin:pos], 'endbr64'))
            continue
        # Only the one architectural NOP form present in this body.
        if code[pos:pos + 7] == bytes.fromhex('0f1f8000000000'):
            take(7)
            out.append(Instruction(addr, code[begin:pos], 'nop'))
            continue
        segment = ''
        if code[pos] == 0x64:
            take(1)
            segment = 'fs:'
        require(pos < len(code), 'truncated prefix')
        rex = 0
        if 0x40 <= code[pos] <= 0x4f:
            rex = integer(1)
        width = 64 if rex & 8 else 32
        opcode = integer(1)

        def reg(index, bits):
            require(bits != 8 or rex or index < 4,
                    'unsupported high-byte register form')
            return REGS[bits][index]

        def modrm(bits, dest_bits=None):
            m = integer(1)
            mode, group, rm = m >> 6, (m >> 3) & 7, m & 7
            r = reg(group + (8 if rex & 4 else 0), dest_bits or bits)
            if mode == 3:
                require(not segment, 'segment on register operand')
                return r, reg(rm + (8 if rex & 1 else 0), bits), group
            base, index, scale, disp = None, None, 1, 0
            if rm == 4:
                sib = integer(1)
                scale = 1 << (sib >> 6)
                idx, b = (sib >> 3) & 7, sib & 7
                if idx != 4 or rex & 2:
                    index = REGS[64][idx + (8 if rex & 2 else 0)]
                if mode == 0 and b == 5:
                    disp = integer(4, True)
                else:
                    base = REGS[64][b + (8 if rex & 1 else 0)]
            elif mode == 0 and rm == 5:
                base, disp = 'rip', integer(4, True)
            else:
                base = REGS[64][rm + (8 if rex & 1 else 0)]
            if mode == 1:
                disp = integer(1, True)
            elif mode == 2:
                disp = integer(4, True)
            expr = base or ''
            if index:
                expr += ('+' if expr else '') + index + f'*{scale}'
            if disp or not expr:
                expr += (('+' if expr else '') + hex(disp) if disp >= 0
                         else '-' + hex(-disp))
            mem = f'{bits}-bit {segment}[{expr}]'
            return r, mem, group

        if 0x50 <= opcode <= 0x5f:
            require(not segment and rex in (0, 0x41), 'unsupported push/pop prefix')
            op = 'push' if opcode < 0x58 else 'pop'
            args = (REGS[64][(opcode & 7) + (8 if rex & 1 else 0)],)
        elif 0xb8 <= opcode <= 0xbf:
            require(not segment, 'segment on immediate move')
            op, args = 'mov', (reg((opcode & 7) + (8 if rex & 1 else 0), width),
                               hex(integer(8 if width == 64 else 4)))
        elif opcode in (0x88, 0x89, 0x8b, 0x8d, 0x31, 0x29, 0x2b, 0x39, 0x85):
            bits = 8 if opcode == 0x88 else width
            r, rm, _ = modrm(bits)
            op = {0x88: 'mov', 0x89: 'mov', 0x8b: 'mov', 0x8d: 'lea',
                  0x31: 'xor', 0x29: 'sub', 0x2b: 'sub', 0x39: 'cmp', 0x85: 'test'}[opcode]
            args = (r, rm) if opcode in (0x8b, 0x8d, 0x2b) else (rm, r)
            if opcode == 0x8d:
                require('[' in rm and not segment, 'invalid LEA')
                args = (r, rm.split(' ', 1)[1])  # LEA does not read memory.
        elif opcode in (0x83, 0xc1, 0xc6):
            bits = 8 if opcode == 0xc6 else width
            _, rm, group = modrm(bits)
            require(not rex & 4, 'extended opcode group')
            allowed = {0x83: {0: 'add', 5: 'sub', 6: 'xor', 7: 'cmp'},
                       0xc1: {7: 'sar'}, 0xc6: {0: 'mov'}}[opcode]
            require(group in allowed, 'unsupported opcode group')
            op, args = allowed[group], (rm, hex(integer(1, opcode == 0x83)))
        elif opcode == 0x0f:
            second = integer(1)
            if second in (0xb6, 0xb7, 0xbd):
                src_bits = {0xb6: 8, 0xb7: 16, 0xbd: width}[second]
                r, rm, _ = modrm(src_bits, width)
                op, args = ('bsr' if second == 0xbd else 'movzx'), (r, rm)
            else:
                require(second == 0x85 and not rex and not segment, 'unsupported 0f opcode')
                delta = integer(4, True)
                branch = start + pos + delta
                op, args = 'jne', (hex(branch),)
        elif opcode in (0x74, 0x75, 0x76, 0x77, 0xeb, 0xe8, 0xe9):
            require(not rex and not segment, 'unsupported branch prefix')
            delta = integer(4 if opcode in (0xe8, 0xe9) else 1, True)
            branch = start + pos + delta
            op = {0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'ja',
                  0xeb: 'jmp', 0xe8: 'call', 0xe9: 'jmp'}[opcode]
            args = (hex(branch),)
        elif opcode == 0xc3:
            require(not rex and not segment, 'unsupported ret prefix')
            op = 'ret'
        else:
            raise ValueError(f'unsupported opcode {opcode:#x} at {addr:#x}')
        out.append(Instruction(addr, code[begin:pos], op, args, branch))
    return out


def check_cfg(instructions, start=START, end=END):
    """Prove local control-flow closure and record unreachable alignment fill."""
    by_va = {i.address: i for i in instructions}
    require(instructions and instructions[0].address == start
            and instructions[-1].end == end, 'incomplete instruction coverage')
    require(all(a.end == b.address for a, b in zip(instructions, instructions[1:])),
            'instruction gap')
    for ins in instructions:
        require(ins.op != 'call', 'leaf has unexpected callee')
        if ins.target is not None:
            require(ins.target in by_va, 'branch leaves body or enters instruction')
    seen, pending = set(), [start]
    while pending:
        pc = pending.pop()
        if pc in seen:
            continue
        require(pc in by_va, 'reachable fallthrough outside body')
        seen.add(pc)
        ins = by_va[pc]
        if ins.op == 'ret':
            continue
        if ins.target is not None:
            pending.append(ins.target)
        if ins.op != 'jmp':
            pending.append(ins.end)
    unreachable = [i for i in instructions if i.address not in seen]
    require(all(i.op == 'nop' for i in unreachable), 'unreachable non-padding instruction')
    return unreachable


def validate_body(body):
    instructions = decode(body, START)
    check_cfg(instructions)
    require(len(body) == END - START and digest(body) == BODY_SHA, 'function body mismatch')
    return instructions


def count_from_span(begin, end):
    """Exact machine count, including subtraction wrap and low-dword truncation."""
    diff = (end - begin) & MASK64
    signed = diff - (1 << 64) if diff & (1 << 63) else diff
    return (signed >> 3) & 0xffffffff


def symbol_a(value):
    require(type(value) is int and 0 <= value <= 0xffff, 'A input must be u16')
    for upper, base, shift, bias in ((16, 0, 0, 0), (24, 16, 1, 16),
                                    (32, 24, 2, 20), (48, 32, 3, 22),
                                    (64, 48, 4, 24)):
        if value < upper:
            return ((value - base) >> shift) + bias
    return value.bit_length() - 1 + 19


def symbol_b(value):
    require(type(value) is int and 0 <= value <= 0xffff, 'B input must be u16')
    for upper, base, shift, bias in ((32, 0, 0, 0), (40, 32, 1, 32),
                                    (48, 40, 2, 36), (64, 48, 3, 38),
                                    (96, 64, 4, 40), (128, 96, 5, 42)):
        if value < upper:
            return ((value - base) >> shift) + bias
    return value.bit_length() - 1 + 36


def model(records, tag=0, position=0, capacity=None, fill=0xa5):
    """Independent mathematical model for disjoint, valid buffers.

    Each record is (u32 nonzero, u16 A, u16 B). The object and all buffers
    must be disjoint for this value model; the instruction walk retains the
    actual load/store order. Zero first fields have no specified BSR result.
    Capacity may exceed record count, notably for an override on an empty span.
    """
    require(type(tag) is int and 0 <= tag <= 0xffffffff, 'tag must be u32')
    require(type(position) is int and 0 <= position <= 0xffffffff, 'position must be u32')
    capacity = len(records) if capacity is None else capacity
    require(capacity >= len(records), 'insufficient stream capacity')
    a, b, c = [bytearray([fill]) * capacity for _ in range(3)]
    for i, (word, av, bv) in enumerate(records):
        require(type(word) is int and 0 < word <= 0xffffffff,
                'zero/invalid first field: BSR result unspecified')
        a[i], b[i], c[i] = symbol_a(av), symbol_b(bv), word.bit_length() - 1
    if tag in (1, 2):
        require(position < capacity, 'override position outside model allocation')
        (a if tag == 1 else b)[position] = 35 if tag == 1 else 52
    return {'return': 0, 'a': a.hex(), 'b': b.hex(), 'c': c.hex()}


def scan_rel32(image, destination):
    """Every byte position in the full file-backed .text, no second text copy."""
    sec = image.by_name['.text']
    require(sec['type'] != 8 and sec['flags'] & 4, 'invalid .text')
    end = sec['offset'] + sec['size']
    found = []
    for opcode in (0xe8, 0xe9):
        pos = sec['offset']
        while (pos := image.data.find(bytes([opcode]), pos, end)) >= 0:
            if pos + 5 <= end:
                va = sec['address'] + pos - sec['offset']
                disp = struct.unpack_from('<i', image.data, pos + 1)[0]
                if va + 5 + disp == destination:
                    found.append({'site': hex(va), 'opcode': hex(opcode),
                                  'target': hex(destination),
                                  'bytes': image.data[pos:pos + 5].hex()})
            pos += 1
    return sorted(found, key=lambda x: int(x['site'], 16))


def frame_record(image, rows, start):
    matches = [r for r in rows if r['start'] == start]
    require(len(matches) == 1, 'missing/duplicate FDE start')
    r = matches[0]
    eh = image.by_name['.eh_frame']
    raw_size = struct.unpack('<I', image.read(r['fde'], 4))[0] + 4
    cie_size = struct.unpack('<I', image.read(r['cie'], 4))[0] + 4
    return {'start': hex(r['start']), 'end_exclusive': hex(r['end']),
            'size': r['end'] - r['start'], 'fde_va': hex(r['fde']),
            'fde_section_offset': hex(r['fde'] - eh['address']),
            'cie_va': hex(r['cie']), 'cie_section_offset': hex(r['cie'] - eh['address']),
            'fde_record_size': raw_size, 'fde_hex': image.read(r['fde'], raw_size).hex(),
            'cie_hex': image.read(r['cie'], cie_size).hex(), 'lsda': r['lsda']}


def check_frame(frame, start=START, end=END, fde=FDE_OFFSET, cie=CIE_OFFSET):
    require((int(frame['start'], 16), int(frame['end_exclusive'], 16),
             int(frame['fde_section_offset'], 16), int(frame['cie_section_offset'], 16))
            == (start, end, fde, cie), 'FDE/CIE association mismatch')


def vectors():
    cases = [
        ('empty', [], 0, 0, 0),
        ('low edges', [(1, 0, 0), (2, 15, 31), (3, 16, 32)], 0, 0, 3),
        ('table ends and fallback', [(4, 63, 127), (8, 64, 128),
                                     (0x80000000, 65535, 65535)], 0, 0, 3),
        ('A override', [(0xffffffff, 65535, 65535)], 1, 0, 1),
        ('B override', [(0xffffffff, 65535, 65535)], 2, 0, 1),
        ('other tag', [(7, 23, 39)], 3, 0, 1),
        ('empty A override', [], 1, 1, 3),
        ('empty B override', [], 2, 1, 3),
        ('override beyond record count', [(1, 1, 1)], 1, 2, 3),
    ]
    return [{'name': name, 'records': records, 'tag': tag, 'position': pos,
             'capacity': cap, 'result': model(records, tag, pos, cap)}
            for name, records, tag, pos, cap in cases]


def analyze(data):
    """Structural analysis; CLI authenticates the entire mmap before calling.

    Exposed separately so corruption tests can reach checks behind the digest.
    """
    image = Image(data)
    _, rows = eh_frame_records(data, image.sections)
    frame = frame_record(image, rows, START)
    check_frame(frame)
    following = min(r['start'] for r in rows if r['start'] > START)
    require(following == NEXT, 'next FDE changed')
    require(not any(r['start'] < START < r['end'] or START < r['start'] < END
                    for r in rows), 'overlapping function extent')
    body = image.read(START, END - START)
    instructions = validate_body(body)
    padding = image.read(END, NEXT - END)
    require(padding == b'\xcc' * (NEXT - END), 'padding changed')
    table_rows = []
    for label, (va, size), rule in zip(('a', 'b'), TABLES, (symbol_a, symbol_b)):
        raw = image.read(va, size)
        require(raw == bytes(rule(i) for i in range(size)), 'symbol table mismatch')
        table_rows.append({'stream': label, 'address': hex(va), 'size': size,
                           'sha256': digest(raw), 'hex': raw.hex()})
    # Resolve both RIP-relative LEAs from the decoded bytes, not a prose label.
    lea = [i for i in instructions if i.op == 'lea' and 'rip' in i.args[1]]
    require(len(lea) == len(TABLES), 'unexpected table references')
    targets = [i.end + struct.unpack_from('<i', i.raw, 3)[0] for i in lea]
    require(targets == [va for va, _ in TABLES], 'table target mismatch')
    incoming = scan_rel32(image, START)
    require([(int(r['site'], 16), r['opcode']) for r in incoming]
            == [(site, '0xe8') for site in CALL_SITES], 'direct-caller census changed')
    contexts = []
    for row, lower, upper, container, boundary in zip(
            incoming, (NEXT, 0x55f79f2), (0x555f38a, 0x55f7a0c),
            (NEXT, 0x55f7570), ('decoded from FDE start', 'local decode only')):
        raw = image.read(lower, upper - lower)
        walk = decode(raw, lower)
        call = walk[-1]
        require(call.op == 'call' and call.address == int(row['site'], 16)
                and call.target == START, 'caller target mismatch')
        owner = frame_record(image, rows, container)
        require(container <= lower < upper <= int(owner['end_exclusive'], 16),
                'caller context outside FDE')
        contexts.append({'start': hex(lower), 'end_exclusive': hex(upper),
                         'sha256': digest(raw), 'boundary_status': boundary,
                         'container': owner})
    branches = [{'site': hex(i.address), 'kind': i.op, 'target': hex(i.target)}
                for i in instructions if i.target is not None]
    unreachable = check_cfg(instructions)
    text_sec = image.by_name['.text']
    records = {
        'task': 'RE-001', 'component': 'foundation; ownership unresolved',
        'target': {'path': 'artifacts/node/94/hl-node', 'release': 94,
                   'sha256': SHA256, 'size': SIZE},
        'function': {**frame, 'sha256': digest(body), 'file_offset': hex(
            text_sec['offset'] + START - text_sec['address']),
            'next_fde_start': hex(NEXT), 'padding_bytes': len(padding),
            'padding_hex': padding.hex()},
        'next_frame': frame_record(image, rows, NEXT),
        'callees': [], 'incoming': incoming, 'caller_contexts': contexts,
        'census': {'section': '.text', 'start': hex(text_sec['address']),
                   'end_exclusive': hex(text_sec['address'] + text_sec['size']),
                   'size': text_sec['size'], 'call_count': len(incoming), 'jump_count': 0,
                   'method': 'every byte position; e8/e9 signed rel32; candidates, not all xrefs'},
        'tables': table_rows, 'branches': branches,
        'control_flow': {'instruction_count': len(instructions),
                         'reachable_instruction_count': len(instructions) - len(unreachable),
                         'unreachable_nop_bytes': sum(len(i.raw) for i in unreachable),
                         'return_sites': [hex(i.address) for i in instructions if i.op == 'ret']},
        'rule': {'record_stride': 8, 'fields': {'word_u32': 0, 'a_u16': 4, 'b_u16': 6},
                 'object_offsets': {'begin': 0, 'end': 8, 'a': 32, 'b': 40,
                                    'c': 48, 'tag_u32': 72, 'position_u32': 76},
                 'a_large_bias': 19, 'b_large_bias': 36, 'a_override': 35,
                 'b_override': 52, 'return': 0,
                 'count': 'low32(asr64(wrapping_u64(end-begin), 3))',
                 'c': 'floor(log2(word_u32)); unspecified for zero',
                 'a': 'table_a[x] if x <= 63; floor(log2(x)) + 19 otherwise',
                 'b': 'table_b[x] if x <= 127; floor(log2(x)) + 36 otherwise',
                 'override': 'tag == 1: A[position]=35; tag == 2: B[position]=52',
                 'model_domain': 'valid disjoint object/input/output buffers; nonzero word; valid override allocation'},
        'vectors': vectors(),
        'non_claims': ['No recovered source name, first-party ownership or exact library version.',
                       'No native execution, Rust build, byte-equivalence or component gate.',
                       'No specified BSR destination for zero first fields.',
                       'Caller containers are not behavior-bound; second site has only a local boundary check.',
                       'No indirect/pointer/vtable or whole-ELF reference closure.'],
    }
    disasm = ['# Pure-Python restricted decoder; ELF virtual addresses; no symbol annotations.',
              '# Complete function (including unreachable NOP fill):']
    disasm.extend(i.text() for i in instructions)
    disasm.append(f'# External padding {END:#x}..{NEXT:#x}: {padding.hex()}')
    for ctx in contexts:
        lower, upper = int(ctx['start'], 16), int(ctx['end_exclusive'], 16)
        disasm.append('# Caller context: ' + ctx['boundary_status'])
        disasm.extend(i.text() for i in decode(image.read(lower, upper - lower), lower))
    frames = ['# FDE and CIE records decoded from .eh_frame; offsets are section-relative.']
    for fr in [frame, records['next_frame'], contexts[1]['container']]:
        frames.append(f"FDE {fr['fde_section_offset']} CIE {fr['cie_section_offset']} "
                      f"PC {fr['start']}..{fr['end_exclusive']} size {fr['size']}")
        frames.append('FDE bytes: ' + fr['fde_hex'])
        frames.append('CIE bytes: ' + fr['cie_hex'])
    return records, '\n'.join(disasm) + '\n', '\n'.join(frames) + '\n'

# Historical pre-write novelty snapshot; not a claim that a self-search stays empty.
NOVELTY = {'revision': 'e5c9b6436876b2a4a39daef813171f9879317699',
 'checks': [{'pattern': '555f240',
             'scope': 'research',
             'exit_code': 1,
             'stdout': '',
             'stderr': ''},
            {'pattern': '555f240',
             'scope': 'PR titles',
             'exit_code': 1,
             'stdout': '',
             'stderr': ''},
            {'pattern': '89518656',
             'scope': 'research',
             'exit_code': 1,
             'stdout': '',
             'stderr': ''},
            {'pattern': '89518656',
             'scope': 'PR titles',
             'exit_code': 1,
             'stdout': '',
             'stderr': ''}],
 'pr_lists': [{'name': 'open_prs.txt',
               'sha256': '9e6a8c69d7e6cfe350157045fbe69718186847f8a26854c4d9b79690dbb7a962'},
              {'name': 'merged_prs.txt',
               'sha256': 'c291aef81f04946a0e6594630e2a5538052c57d12bc79580150555ee0d89ac6d'},
              {'name': 'closed_unmerged_prs.txt',
               'sha256': '7ffc9b73e46cf197874fe3cc691a8c8380e5ef8139dc4d23d90ff7db86819406'}]}

VERIFY_SOURCE = '''#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whitelist and reproduce this packet using the authenticated static target."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from sequence_symbol_streams import main

if __name__ == '__main__':
    raise SystemExit(main(['--check', str(Path(__file__).resolve().parent)]))
'''
PAYLOAD_NAMES = ('README.md', 'records.json', 'disassembly.txt', 'frames.txt', 'verify.py')
PACKET_NAMES = frozenset((*PAYLOAD_NAMES, 'MANIFEST.sha256'))


def metrics(rec):
    f, cfg, census = rec['function'], rec['control_flow'], rec['census']
    return {
        'Function bytes': f['size'],
        'External INT3 padding bytes': f['padding_bytes'],
        'Decoded instructions': cfg['instruction_count'],
        'Reachable instructions': cfg['reachable_instruction_count'],
        'Unreachable internal NOP bytes': cfg['unreachable_nop_bytes'],
        'Direct or indirect callees': len(rec['callees']),
        'Full .text bytes scanned': census['size'],
        'E8 call candidates': census['call_count'],
        'E9 jump candidates': census['jump_count'],
        'Lookup tables': len(rec['tables']),
        'Table A bytes': rec['tables'][0]['size'],
        'Table B bytes': rec['tables'][1]['size'],
        'Recorded model vectors': len(rec['vectors']),
        'Focused tests passed': rec['validation']['focused_test_count'],
        'Novelty searches with empty output': len(rec['novelty']['checks']),
    }


def render_readme(rec):
    f, r, cfg = rec['function'], rec['rule'], rec['control_flow']
    o = r['object_offsets']
    summary = '\n'.join(f'| {key} | {value} |' for key, value in metrics(rec).items())
    branches = '\n'.join(f"| `{b['site']}` | {b['kind']} | `{b['target']}` |"
                         for b in rec['branches'])
    callers = '\n'.join(f"| `{call['site']}` | `{ctx['container']['start']}.."
                        f"{ctx['container']['end_exclusive']}` | {ctx['boundary_status']} |"
                        for call, ctx in zip(rec['incoming'], rec['caller_contexts']))
    validation = '\n'.join(f"- `{name}`: {rec['validation'][name]}" for name in (
        'focused_suite', 'packet_verifier', 'doctor', 'artifact_recovery', 'make_verify',
        'make_catalogue_check', 'make_reproduce', 'make_test'))
    lists = '\n'.join(f"- `{p['name']}`: `{p['sha256']}`" for p in rec['novelty']['pr_lists'])
    nonclaims = '\n'.join('- ' + item for item in rec['non_claims'])
    edges = '\n'.join(f"| {v['name']} | `{v['result']['a']}` | `{v['result']['b']}` | "
                      f"`{v['result']['c']}` |" for v in rec['vectors'])
    return f'''# RE-001: packed record to symbol streams at {f['start']} (node #{rec['target']['release']})

Task: RE-001. Component allocation: foundation; source ownership unresolved.
Bounded question: how does this leaf convert a packed record span into byte
symbol streams, including its exceptional-position override?

**Answer.** With valid, disjoint object, input and output storage, let
`n = {r['count']}` and iterate the packed records at the begin pointer with
stride {r['record_stride']}. For each record, C receives `{r['c']}` from its
first dword; A receives `{r['a']}` from its following word; B receives
`{r['b']}` from its final word. After the loop, `{r['override']}`;
other tags leave the streams as computed. The override runs even for an empty
span and is not checked against the record count. The return value is
{r['return']} whenever the function returns. It has no callee-dependent behavior.

## Binding and scope

- Target: `{rec['target']['path']}`, size {rec['target']['size']}, SHA-256
  `{rec['target']['sha256']}`; authenticated before parsing or output writes.
- ELF VA window: `{f['start']}..{f['end_exclusive']}` (exclusive end),
  file offset `{f['file_offset']}`, body SHA-256 `{f['sha256']}`.
- FDE: `.eh_frame+{f['fde_section_offset']}`, VA `{f['fde_va']}`;
  CIE: `.eh_frame+{f['cie_section_offset']}`, VA `{f['cie_va']}`.
  [frames.txt](frames.txt) retains exact records and decoded associations.
- External padding is `{f['padding_hex']}`, up to the next FDE at
  `{f['next_fde_start']}`. The internal unreachable NOP is inside the FDE
  and included in the body hash. The entry marker, complete instruction
  tiling, closed branch graph, return and padding support the function bind;
  an unwind start alone would not.
- Base repository revision: `{rec['novelty']['revision']}`.
  No inferred reference source was copied or used to supply a function name.
- Tool: `tools/sequence_symbol_streams.py`, restricted pure-Python decoder
  with ModRM/SIB, operand widths, signed branch and RIP-relative displacements;
  Python >=3.10, exercised with Python 3.13.5. The initial exploratory
  inspection used GNU binutils 2.44; regeneration and verification do not.

| Metric (derived from records.json) | Count |
| --- | ---: |
{summary}

## Instruction proof and memory layout

[disassembly.txt](disassembly.txt) is a complete byte-decoded instruction walk,
including internal fill and separately identified caller contexts. No instruction
bytes are normalized or masked. [records.json](records.json) contains semantic
records, data tables, extents and branch/caller relationships, not an instruction
inventory.

The argument is the object pointer in RDI. Its qwords at
`+{o['begin']:#x}` and `+{o['end']:#x}` are begin/end; qwords at
`+{o['a']:#x}`, `+{o['b']:#x}`, `+{o['c']:#x}` are A/B/C pointers.
Dwords at `+{o['tag_u32']:#x}` and `+{o['position_u32']:#x}` supply tag and
position. These are observed machine widths and offsets, not recovered types.

The entry saves R12/RBP/RBX and caches pointers. `sub rcx,rsi; sar rcx,3;
mov ebx,ecx` subtracts with wrapping machine arithmetic, shifts arithmetically,
then zero-extends the low dword into RBX. It does not validate ordering,
alignment or capacity. The loop compares its qword index against that narrowed
count. The early empty check enters the override code rather than returning.

At the loop head, `bsr edi,[rsi+rdx*8]` supplies a highest-set-bit index for a
nonzero first field. The XOR against the all-ones index mask followed by
subtraction from the same mask reduces back to that index. A zero operand
leaves the BSR destination architecturally unspecified; this packet does not
invent a zero code. The following word fields are zero-extended before their
unsigned threshold comparisons. Small values use the exact read-only table
bytes retained in records; larger values use BSR plus the recorded biases.
The RIP-relative LEAs resolve directly to `{rec['tables'][0]['address']}`
and `{rec['tables'][1]['address']}`. No relocation-slot dereference or helper
is needed to reach these tables.

Both paths store A, then C, then B for each record. The large-A path rejoins
the appropriate B path; both B paths advance the index and loop or enter the
override. Tag selects the output to overwrite; after the A override the tag
is loaded again. All outputs are byte stores. The epilogue restores the saved
registers, clears EAX and returns. Input buffers, table data and object fields
are only read on the stated disjoint-buffer domain; stack saves are balanced.

| Branch site | Instruction | Target |
| --- | --- | --- |
{branches}

## Callees and incoming references

`callees` is empty: full instruction decoding and CFG closure find no call,
indirect transfer or external tail jump. Callee identity/extent closure is
therefore vacuous, rather than deferred to an unbound helper.

The census examines every byte position in the entire file-backed `.text`
for `e8` and `e9`, adding signed rel32 to the end of the candidate encoding.
Raw candidate bytes and targets are retained. It does not mistake matching
operand bytes for independently established instruction boundaries.

| Candidate site | Enclosing decoded FDE range | Boundary evidence |
| --- | --- | --- |
{callers}

The first call is decoded continuously from its FDE start. The second is a
locally decoded context inside its enclosing FDE, not a complete decode from
that caller's entry. Thus the census count is a direct-transfer byte-pattern
count; the second candidate's full CFG boundary remains a limitation. Neither
caller is behavior-bound here, and no caller/callee closure beyond this leaf
is claimed. Pointer references, relocations, vtables and indirect calls remain
outside this census.

## Target-grounded model and controls

The independent Python model expresses the table steps as arithmetic intervals,
not copied implementation source. Tests compare these intervals against every
retained table entry and compare all word inputs against table-or-BSR rules.
Separate tests lock threshold neighbors, powers of two, count truncation,
ignored tags, override position and untouched allocation bytes. The following
vectors are derived from the decoded operations and data, not native executions.
All vector returns are the recorded constant return value; untouched allocation
bytes retain the synthetic fill marker.

| Vector | A hex | B hex | C hex |
| --- | --- | --- | --- |
{edges}

A zero first field is rejected by the value model because its C result is
unspecified; this is a model-domain check, not a branch in the target. The
model requires disjoint storage. Aliasing can affect subsequent reads, including
the tag reload, and only the retained instruction order describes those cases.
An empty span with an override still needs an allocated destination. Invalid
pointers, insufficient buffers and nonsensical spans have no target guard;
this is not a memory-safe parser claim.

Corruption controls cover the pinned digest, body mutations, unsupported and
truncated instructions, altered branch/caller/table targets, changed table
bytes, shifted FDE ranges and CIE links, padding, census records, packet bytes
and manifest membership. The manifest verifier uses an exact filename whitelist,
rejects symlinks/extra files, rejects duplicate or traversal entries and compares
all generated bytes again with the authenticated target.

## Novelty before writing this packet

The following commands were run at the base revision above before creating
this packet. Each returned exit code `1`, empty stdout and empty stderr.
`PR_LIST_DIR` denotes the supplied sibling title-list directory; its local
absolute spelling is deliberately not retained.

```sh
rg -i '555f240' research/
rg -i '89518656' research/
rg -i '555f240' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
rg -i '89518656' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
```

No callee is behavior-bound, so there is no additional callee address to test.
The list snapshots were:

{lists}

These are historical empty results, not a promise that searching after adding
this packet remains empty. The seed catalogue supplied no band candidate;
a bounded search for first-party panic Locations did not identify this leaf.
Its packed symbol conversion is established, while compression-library
ownership is only an inference. No first-party credit is requested.

## Reproduction and validation scope

From the repository root, without network, installs or target execution:

```sh
python3 tools/sequence_symbol_streams.py --out research/work-items/RE-001-sequence-symbols-94/
python3 -m unittest tests.test_sequence_symbol_streams -v
python3 research/work-items/RE-001-sequence-symbols-94/verify.py
make verify
make catalogue-check
```

The tool memory-maps the target and scans the text in place, keeping only small
windows and metadata. Output is deterministic and includes no machine-local
paths or timestamps. The recorded local validation outcomes are:

{validation}

These are historical outcomes from the contribution environment, not claims
that every future environment has those failures. The missing reference binary
is `references/can1357-hl/bin/hl-node-mainnet-new`; the broad suite also lacks
`references/can1357-hl/l1/abci/state.rs`. No submodule, generated catalogue or
existing evidence was changed to work around these failures. Passing model
tests is not differential validation against a running node.

## Non-claims, unknowns and next step

{nonclaims}

There is no implementation-byte comparison; helper, relocation, vtable/data
and whole-ELF equivalence are not asserted. The tables are bound as data read
by this function, not as a complete library data map. No catalogue, progress
or acceptance gate is changed. The next bounded question is to validate the
second candidate caller's entry-to-call CFG and show how its consumer uses
the symbol streams, without assuming a compression format from familiar
constants. Verdict: strong for the complete local conversion rule, limited
for source attribution and integration.
'''


def generated(data):
    records, disassembly, frames = analyze(data)
    records['novelty'] = NOVELTY
    records['validation'] = {
        'focused_test_count': 31,
        'focused_suite': 'passed',
        'packet_verifier': 'passed; byte-identical reproduction and whitelist',
        'doctor': 'analysis_ready=true; exact_rebuild_ready=false; no native REA provider available',
        'artifact_recovery': 'Initial LFS pointer failure; explicitly requested git lfs pull succeeded.',
        'make_verify': 'Artifact hashes/signatures pass; fails at missing pinned reference binary.',
        'make_catalogue_check': 'Fails: stale research/catalogue/components.json; left unchanged.',
        'make_reproduce': 'Fails at artifact verifier because pinned reference checkout is missing.',
        'make_test': 'Incomplete: interrupted after an existing missing-reference error in test_abci_state_inventory.TargetTests; subsequent files were running.',
    }
    # JSON round-trip canonicalizes tuple-valued model inputs for caller use.
    records_bytes = (json.dumps(records, indent=2, sort_keys=True) + '\n').encode()
    payload = {
        'records.json': records_bytes,
        'README.md': render_readme(records).encode(),
        'disassembly.txt': disassembly.encode(),
        'frames.txt': frames.encode(),
        'verify.py': VERIFY_SOURCE.encode(),
    }
    payload['MANIFEST.sha256'] = ''.join(
        f'{digest(payload[name])}  {name}\n' for name in sorted(payload)).encode()
    return payload


def verify_manifest(packet):
    packet = Path(packet)
    require(packet.is_dir() and not packet.is_symlink(), 'invalid packet directory')
    files = list(packet.iterdir())
    require({p.name for p in files} == PACKET_NAMES, 'packet whitelist mismatch')
    require(all(p.is_file() and not p.is_symlink() for p in files),
            'packet contains non-regular file or symlink')
    lines = (packet / 'MANIFEST.sha256').read_text().splitlines()
    names = []
    for line in lines:
        fields = line.split('  ')
        require(len(fields) == 2, 'malformed manifest entry')
        expected, name = fields
        require(name in PAYLOAD_NAMES and name not in names, 'manifest whitelist/duplicate mismatch')
        require(len(expected) == 64 and all(c in '0123456789abcdef' for c in expected),
                'malformed manifest digest')
        require(digest((packet / name).read_bytes()) == expected, 'manifest digest mismatch')
        names.append(name)
    require(set(names) == set(PAYLOAD_NAMES), 'manifest membership mismatch')


def check_packet(packet, data):
    verify_manifest(packet)
    expected = generated(data)
    for name, value in expected.items():
        require((Path(packet) / name).read_bytes() == value, 'regeneration mismatch: ' + name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--out', type=Path)
    group.add_argument('--check', type=Path)
    parser.add_argument('--binary', type=Path, default=BINARY)
    args = parser.parse_args(argv)
    try:
        with target(args.binary) as data:
            if args.check:
                check_packet(args.check, data)
                print('Packet whitelist, manifest and target-derived evidence reproduce exactly.')
            else:
                payload = generated(data)
                if args.out.exists():
                    require(args.out.is_dir() and not args.out.is_symlink(), 'invalid output directory')
                    require(all(p.name in PACKET_NAMES and p.is_file() and not p.is_symlink()
                                for p in args.out.iterdir()), 'unexpected output member')
                args.out.mkdir(parents=True, exist_ok=True)
                for name, value in payload.items():
                    (args.out / name).write_bytes(value)
                print(f'Generated {len(payload)} static evidence files for {START:#x}.')
    except (ValueError, OSError, struct.error) as error:
        print('sequence_symbol_streams: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
