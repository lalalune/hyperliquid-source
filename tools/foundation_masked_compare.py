#!/usr/bin/env python3
"""Static RE-001 bind of node94 0x1407ec0; Python 3.10+ standard library only.

The instruction decoder deliberately accepts only the opcode/operand forms in
this packet. It is not a general x86 decoder. No external disassembler or target
execution is used. The small interpreter executes decoded operations on synthetic
memory, never executable target bytes. Existing ELF/FDE readers are MIT helpers.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x1407EC0, 0x1407FB0
BODY_SHA = '76d2b7b814722c8c202960f2a5abc5b9cd7fa964545e8c141ad824da7b4d9a33'
PACKET = 'research/work-items/RE-001-masked-compare-94'
TOOL = 'tools/foundation_masked_compare.py'
TEST = 'tests/test_foundation_masked_compare.py'
CALLER = 0x1403C30
CALLS = (0x1403DEF, 0x1403FD4, 0x1404044, 0x1404097, 0x14040D2, 0x1404141)
CONTEXTS = ((0x1403DE7, 0x1403DF4), (0x1403F9D, 0x1403FD9),
            (0x140401A, 0x1404049), (0x1404079, 0x140409C),
            (0x14040C0, 0x14040D7), (0x1404130, 0x1404146),
            (0x1404565, 0x140457A), (0x140458D, 0x1404593))
MASK64 = (1 << 64) - 1
NOVELTY = {
    'baseline_revision': 'e5c9b6436876b2a4a39daef813171f9879317699',
    'queries': [{'command': command, 'exit_code': 1, 'stdout': '', 'stderr': ''} for command in (
        'rg -i 1407ec0 research/', 'rg -i 21003968 research/',
        'rg -i 1407ec0 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt',
        'rg -i 21003968 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt')],
    'list_sha256': {
        '../open_prs.txt': '392b5dc45cbf7fd4c0a56640f566edbb28f31f2d5537cb364c99ad10dc62c496',
        '../merged_prs.txt': 'efc5ab0523e72ecec68136b2c70a64c7c821829180eafe3d51be4bdc11fbe178',
        '../closed_unmerged_prs.txt': '297dcbf46c25131b07f912c7b2af552d40f26be941156362395b7b5e3352ffbb'},
    'scope': 'Historical pre-packet searches; no callee behaviors bound. Not a claim about later PRs.',
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def reg(name, width=64):
    return ('reg', name, width)


def mem(width, base, index=None, disp=0):
    return ('mem', width, base, index, disp)


# Exact opcode, prefix, ModRM/SIB and displacement forms. Each value describes
# the encoded operation, including operand widths and memory addressing. Branch
# displacements and immediate operands are decoded separately below.
FORMS = {}


def form(raw, op, *args):
    FORMS[bytes.fromhex(raw)] = (op, args)


form('85c9', 'test', reg('rcx', 32), reg('rcx', 32))
form('31c0', 'xor', reg('rax', 32), reg('rax', 32))
form('c3', 'ret')
form('488b07', 'mov', reg('rax'), mem(64, 'rdi'))
form('4c8b4710', 'mov', reg('r8'), mem(64, 'rdi', disp=16))
form('4801c6', 'add', reg('rsi'), reg('rax'))
form('48ffc6', 'inc', reg('rsi'))
form('488b7f18', 'mov', reg('rdi'), mem(64, 'rdi', disp=24))
form('8b00', 'mov', reg('rax', 32), mem(32, 'rax'))
form('413b4438fc', 'cmp', reg('rax', 32), mem(32, 'r8', 'rdi', -4))
form('66d3c0', 'rol', reg('rax', 16), reg('rcx', 8))
form('6621c2', 'and', reg('rdx', 16), reg('rax', 16))
form('f30fbcca', 'tzcnt', reg('rcx', 32), reg('rdx', 32))
form('4c8d0c0e', 'lea', reg('r9'), mem(64, 'rsi', 'rcx'))
form('4a8d040f', 'lea', reg('rax'), mem(64, 'rdi', 'r9'))
form('4939c1', 'cmp', reg('r9'), reg('rax'))
form('4d89c2', 'mov', reg('r10'), reg('r8'))
form('6666666666662e0f1f840000000000', 'nop')
form('660f1f840000000000', 'nop')
form('458b19', 'mov', reg('r11', 32), mem(32, 'r9'))
form('453b1a', 'cmp', reg('r11', 32), mem(32, 'r10'))
form('4885ff', 'test', reg('rdi'), reg('rdi'))
form('440fb60c0e', 'movzx', reg('r9', 32), mem(8, 'rsi', 'rcx'))
form('453a08', 'cmp', reg('r9', 8), mem(8, 'r8'))
form('440fb64c0e01', 'movzx', reg('r9', 32), mem(8, 'rsi', 'rcx', 1))
form('453a4801', 'cmp', reg('r9', 8), mem(8, 'r8', disp=1))
form('410f95c1', 'setne', reg('r9', 8))
form('440fb6540e02', 'movzx', reg('r10', 32), mem(8, 'rsi', 'rcx', 2))
form('453a5002', 'cmp', reg('r10', 8), mem(8, 'r8', disp=2))
form('410f95c2', 'setne', reg('r10', 8))
form('4508ca', 'or', reg('r10', 8), reg('r9', 8))

# Context-only forms establish boundaries, arguments and the Location reference;
# the caller as a whole is neither decoded nor behaviorally bound.
form('4c89ff', 'mov', reg('rdi'), reg('r15'))
form('4c89ee', 'mov', reg('rsi'), reg('r13'))
form('31c9', 'xor', reg('rcx', 32), reg('rcx', 32))
form('488dbc2490000000', 'lea', reg('rdi'), mem(64, 'rsp', disp=144))
form('4c89fe', 'mov', reg('rsi'), reg('r15'))
form('400fb6ed', 'movzx', reg('rbp', 32), reg('rbp', 8))
form('89e9', 'mov', reg('rcx', 32), reg('rbp', 32))
form('4c89e6', 'mov', reg('rsi'), reg('r12'))
for raw, displacement in [('498d7710', 16), ('498d7720', 32), ('498d7730', 48)]:
    form(raw, 'lea', reg('rsi'), mem(64, 'r15', disp=displacement))
for raw, xmm, displacement in [('660f7f442440', 'xmm0', 64),
                               ('660f7f4c2430', 'xmm1', 48),
                               ('660f7f642470', 'xmm4', 112),
                               ('660f7f6c2460', 'xmm5', 96),
                               ('660f7fb42450010000', 'xmm6', 336),
                               ('660f7fbc2440010000', 'xmm7', 320)]:
    form(raw, 'movdqa', mem(128, 'rsp', disp=displacement), reg(xmm, 128))


def decode(data, start):
    """Decode the complete bounded input; unknown/truncated forms fail closed."""
    data = bytes(data)
    result, pos = [], 0
    while pos < len(data):
        va = start + pos
        rest = data[pos:]
        op = args = size = None
        if rest[0] in (0x72, 0x73, 0x74, 0x75, 0xEB):
            need(len(rest) >= 2, 'truncated rel8')
            size = 2
            op = {0x72: 'jb', 0x73: 'jae', 0x74: 'je', 0x75: 'jne', 0xEB: 'jmp'}[rest[0]]
            args = (va + size + struct.unpack_from('<b', rest, 1)[0],)
        elif rest[:2] in (b'\x0f\x84', b'\x0f\x85'):
            need(len(rest) >= 6, 'truncated rel32 conditional')
            size, op = 6, 'je' if rest[1] == 0x84 else 'jne'
            args = (va + size + struct.unpack_from('<i', rest, 2)[0],)
        elif rest[0] in (0xE8, 0xE9):
            need(len(rest) >= 5, 'truncated rel32')
            size, op = 5, 'call' if rest[0] == 0xE8 else 'jmp'
            args = (va + size + struct.unpack_from('<i', rest, 1)[0],)
        elif rest[:2] == b'\x66\xb8':
            need(len(rest) >= 4, 'truncated mov ax immediate')
            size, op, args = 4, 'mov', (reg('rax', 16), int.from_bytes(rest[2:4], 'little'))
        elif rest[0] == 0xB0:
            need(len(rest) >= 2, 'truncated mov al immediate')
            size, op, args = 2, 'mov', (reg('rax', 8), rest[1])
        elif rest[:3] in (b'\x48\x83\xff', b'\x48\x83\xc0', b'\x49\x83\xc1', b'\x49\x83\xc2', b'\x41\x80\xfa'):
            need(len(rest) >= 4, 'truncated group immediate')
            op, dst = {b'\x48\x83\xff': ('cmp', reg('rdi')),
                       b'\x48\x83\xc0': ('add', reg('rax')),
                       b'\x49\x83\xc1': ('add', reg('r9')),
                       b'\x49\x83\xc2': ('add', reg('r10')),
                       b'\x41\x80\xfa': ('cmp', reg('r10', 8))}[rest[:3]]
            size, args = 4, (dst, struct.unpack_from('<b', rest, 3)[0])
        elif rest[:3] in (b'\x48\x8d\x15', b'\x48\x8d\x3d'):
            need(len(rest) >= 7, 'truncated RIP lea')
            size, op = 7, 'lea_rip'
            args = (reg('rdx' if rest[2] == 0x15 else 'rdi'), va + 7 + struct.unpack_from('<i', rest, 3)[0])
        elif rest[0] == 0xBE:
            need(len(rest) >= 5, 'truncated mov esi immediate')
            size, op, args = 5, 'mov', (reg('rsi', 32), struct.unpack_from('<I', rest, 1)[0])
        elif rest[:2] == b'\xff\x15':
            need(len(rest) >= 6, 'truncated RIP call')
            size, op, args = 6, 'call_slot', (va + 6 + struct.unpack_from('<i', rest, 2)[0],)
        else:
            matches = [(raw, val) for raw, val in FORMS.items() if rest.startswith(raw)]
            need(len(matches) == 1, f'unknown/ambiguous instruction at {va:#x}')
            raw, (op, args) = matches[0]
            size = len(raw)
        result.append(dict(va=va, size=size, raw=rest[:size].hex(), op=op, args=args))
        pos += size
    return result


def validate_cfg(instructions):
    """No instruction holes, external branches, calls or unexplored body bytes."""
    need(instructions[0]['va'] == START, 'wrong instruction entry')
    addresses = {i['va'] for i in instructions}
    reachable, pending = set(), [START]
    by_va = {i['va']: i for i in instructions}
    while pending:
        pc = pending.pop()
        if pc in reachable:
            continue
        need(pc in by_va, 'control flow leaves instruction boundaries')
        reachable.add(pc)
        ins = by_va[pc]
        need(ins['op'] not in ('call', 'call_slot'), 'unexpected callee')
        if ins['op'] == 'ret':
            continue
        if ins['op'].startswith('j'):
            need(ins['args'][0] in addresses, 'branch target outside decoded body')
            pending.append(ins['args'][0])
        if ins['op'] != 'jmp':
            pending.append(pc + ins['size'])
    need(all(i['va'] in reachable or i['op'] == 'nop' for i in instructions),
         'unexplored non-padding body bytes')
    need(instructions[-1]['va'] + instructions[-1]['size'] == END, 'wrong decoded extent')
    return reachable


def format_operand(arg):
    if isinstance(arg, int):
        return hex(arg) if arg >= 0 else '-' + hex(-arg)
    if arg[0] == 'reg':
        return f'{arg[1]}:{arg[2]}'
    _, width, base, index, disp = arg
    return f'[{base}' + (f'+{index}' if index else '') + (f'{disp:+d}' if disp else '') + f']:{width}'


def disassembly(instructions):
    return ''.join((f"{i['va']:#x}  {i['raw']:<32} {i['op']} " +
                    ', '.join(format_operand(a) for a in i['args'])).rstrip() + '\n'
                   for i in instructions)


def predicate(haystack, needle, offset, mask, guard=0):
    """Independent byte-string rule, including TZCNT's empty-mask case.

    Inputs describe readable non-wrapping memory. offset is the caller's RSI;
    each candidate begins one byte beyond offset plus its selected bit index.
    Only the low dword of guard and mask matters. No invalid read is padded.
    """
    if guard & 0xFFFFFFFF:
        return False
    if not needle:
        return True
    mask &= 0xFFFFFFFF
    low = mask & 0xFFFF
    indices = [i for i in range(16) if low & (1 << i)] if low else [
        (mask & -mask).bit_length() - 1 if mask else 32]
    for i in indices:
        begin = offset + 1 + i
        need(0 <= begin <= len(haystack) - len(needle), 'model input is not readable')
        if haystack[begin:begin + len(needle)] == needle:
            return True
    return False


def interpret(instructions, haystack, needle, offset, mask, guard=0):
    """Interpret the decoded leaf over disjoint synthetic memory; return AL/trace.

    This is a limited instruction semantics cross-check, not native execution or
    an independent x86 implementation. Unmapped reads fail and are never filled.
    """
    hbase, nbase, obj = 0x100000, 0x200000, 0x300000
    regions = [(hbase, haystack), (nbase, needle),
               (obj, struct.pack('<QQQQ', hbase, 0xDEADBEEF, nbase, len(needle)))]
    regs = {f'r{i}': 0 for i in range(8, 16)}
    regs.update(rax=0xABCDEF00, rcx=guard & MASK64, rdx=mask & MASK64,
                rsi=offset & MASK64, rdi=obj)
    reads, visited = [], set()
    zf = cf = False

    def address(operand):
        return (regs[operand[2]] + (regs[operand[3]] if operand[3] else 0) + operand[4]) & MASK64

    def value(operand):
        if isinstance(operand, int):
            return operand
        if operand[0] == 'reg':
            return regs[operand[1]] & ((1 << operand[2]) - 1)
        va, count = address(operand), operand[1] // 8
        for base, content in regions:
            if base <= va and va + count <= base + len(content):
                reads.append((va, count))
                return int.from_bytes(content[va-base:va-base+count], 'little')
        raise ValueError(f'unmapped synthetic read {va:#x}+{count}')

    def write(dst, val):
        need(dst[0] == 'reg', 'unexpected memory store in leaf')
        _, name, width = dst
        bits = (1 << width) - 1
        regs[name] = (val & bits) | (regs[name] & ~bits if width < 32 else 0)

    by_va = {i['va']: i for i in instructions}
    pc = START
    for _ in range(100000):
        need(pc in by_va, 'interpreter PC outside decoded body')
        ins = by_va[pc]
        visited.add(pc)
        op, args = ins['op'], ins['args']
        pc += ins['size']
        if op == 'ret':
            return {'al': regs['rax'] & 255, 'rax': regs['rax'], 'reads': reads,
                    'visited': visited}
        if op.startswith('j'):
            taken = {'jmp': True, 'je': zf, 'jne': not zf, 'jb': cf, 'jae': not cf}[op]
            if taken:
                pc = args[0]
        elif op in ('mov', 'movzx'):
            write(args[0], value(args[1]))
        elif op == 'lea':
            write(args[0], address(args[1]))
        elif op in ('cmp', 'test', 'and', 'xor', 'or', 'add', 'inc'):
            left = value(args[0])
            right = value(args[1]) if len(args) == 2 else 1
            width = args[0][2]
            bits = (1 << width) - 1
            right &= bits
            val = {'cmp': lambda: left-right, 'test': lambda: left & right,
                   'and': lambda: left & right, 'xor': lambda: left ^ right,
                   'or': lambda: left | right, 'add': lambda: left+right,
                   'inc': lambda: left+1}[op]()
            zf = (val & bits) == 0
            if op == 'cmp':
                cf = left < right
            elif op != 'inc':
                cf = val > bits if op == 'add' else False
            if op not in ('cmp', 'test'):
                write(args[0], val)
        elif op == 'rol':
            val, count = value(args[0]), value(args[1]) % 16
            write(args[0], (val << count) | (val >> ((16-count) % 16)))
            # Only CF/OF change; neither is consumed before AND resets them.
        elif op == 'tzcnt':
            val = value(args[1])
            result = (val & -val).bit_length() - 1 if val else 32
            write(args[0], result)
            cf, zf = val == 0, result == 0
        elif op == 'setne':
            write(args[0], int(not zf))
        else:
            need(op == 'nop', f'unsupported interpreted operation {op}')
    raise ValueError('synthetic interpreter step bound exceeded')


class Image:
    """Read-only mmap, a single target mapping, and strict section coordinates."""
    def __init__(self, data):
        self.data = data
        need(len(data) == 91774280 and sha(data) == DIGEST, 'target digest/size mismatch')
        self.sections = sections(data)
        _, self.frames = eh_frame_records(data, self.sections)

    def section(self, name):
        matches = [s for s in self.sections if s['name'] == name]
        need(len(matches) == 1, 'section is not unique')
        return matches[0]

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        need(size >= 0 and len(matches) == 1, 'ambiguous/unmapped VA read')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off+size]

    def frame(self, start):
        matches = [f for f in self.frames if f['start'] == start]
        need(len(matches) == 1, 'FDE start is not unique')
        f = matches[0]
        section = self.section('.eh_frame')
        raw = self.read(f['fde'], 4)
        length = struct.unpack('<I', raw)[0]
        cie_length = struct.unpack('<I', self.read(f['cie'], 4))[0]
        return {'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                'bytes': f['end']-start, 'fde_va': hex(f['fde']),
                'fde_section_offset': hex(f['fde']-section['address']),
                'fde_length_field': length, 'fde_raw': self.read(f['fde'], length+4).hex(),
                'cie_va': hex(f['cie']), 'cie_section_offset': hex(f['cie']-section['address']),
                'cie_raw': self.read(f['cie'], cie_length+4).hex(),
                'lsda_va': hex(f['lsda']) if f['lsda'] is not None else None}

    def relocation(self, slot):
        s = self.section('.rela.dyn')
        matches = []
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', self.data, off)
            if address == slot:
                need(info == 8, 'expected symbol-free R_X86_64_RELATIVE')
                matches.append({'file_offset': hex(off), 'slot_va': hex(slot),
                                'type': info, 'addend_va': hex(addend)})
        need(len(matches) == 1, 'relocation slot is not unique')
        return matches[0]


def scan_callers(data, section, target):
    """Every byte position in full .text; raw candidates, not a global decoder."""
    found = []
    lower, upper = section['offset'], section['offset'] + section['size']
    for opcode in (0xE8, 0xE9):
        pos = lower
        while True:
            pos = data.find(bytes([opcode]), pos, upper-4)
            if pos < 0:
                break
            va = section['address'] + pos-lower
            if va + 5 + struct.unpack_from('<i', data, pos+1)[0] == target:
                found.append({'site_va': hex(va), 'opcode': hex(opcode), 'target_va': hex(target)})
            pos += 1
    return sorted(found, key=lambda r: int(r['site_va'], 16))


def vectors():
    """Fixed expected results selected from the instruction paths, not the model."""
    rows = []
    for length in (0, 1, 2, 3, 4, 5, 7, 8, 9, 12):
        needle = bytes(range(1, length+1))
        for index in (0, 15):
            hay = bytearray(b'\xee' * (40+length))
            hay[1+index:1+index+length] = needle
            rows.append({'name': f'length_{length}_bit_{index}', 'haystack_hex': hay.hex(),
                         'needle_hex': needle.hex(), 'offset': 0, 'mask': 1 << index,
                         'guard': 0, 'expected_al': 1})
    for name, hay, needle, offset, mask, guard, expected in (
            ('no_match', b'x'*64, b'abcde', 0, 0xffff, 0, 0),
            ('later_candidate', b'xabcxabc'+b'x'*64, b'abc', 0, 0x13, 0, 1),
            ('offset_plus_one', b'xabc'+b'x'*64, b'abc', 1, 1, 0, 0),
            ('offset_applied', b'xxabc'+b'x'*64, b'abc', 1, 1, 0, 1),
            ('guard_prevents_reads', b'', b'abc', 0, 1, 1, 0),
            ('guard_high_dword_ignored', b'xabc'+b'x'*64, b'abc', 0, 1, 1 << 32, 1),
            ('zero_mask_tzcnt_32', b'x'*33+b'abc', b'abc', 0, 0, 0, 1),
            ('zero_mask_mismatch', b'x'*40, b'abc', 0, 0, 0, 0),
            ('upper_only_mask', b'x'*21+b'abc', b'abc', 0, 1 << 20, 0, 1),
            ('upper_mask_ignored_after_low_exhausted', b'x'*21+b'abc', b'abc', 0, (1 << 20) | 1, 0, 0),
            ('mask_high_dword_ignored', b'x'*33+b'abc', b'abc', 0, 1 << 32, 0, 1),
            ('empty_needle_empty_mask', b'', b'', 0, 0, 0, 1)):
        rows.append({'name': name, 'haystack_hex': hay.hex(), 'needle_hex': needle.hex(),
                     'offset': offset, 'mask': mask, 'guard': guard, 'expected_al': expected})
    return rows


def collect(image):
    body = image.read(START, END-START)
    need(sha(body) == BODY_SHA, 'body digest mismatch')
    instructions = decode(body, START)
    reachable = validate_cfg(instructions)
    function = image.frame(START)
    need(function['end_va_exclusive'] == hex(END), 'FDE extent mismatch')
    need(function['fde_section_offset'] == '0x7a70' and function['cie_section_offset'] == '0x0',
         'FDE/CIE association mismatch')
    following = min(f['start'] for f in image.frames if f['start'] > START)
    need(following == END, 'unexpected following FDE/padding')
    function.update(sha256=sha(body), file_offset=hex(START-image.section('.text')['address']+
                    image.section('.text')['offset']), padding_bytes=following-END,
                    padding_hex=image.read(END, following-END).hex(), next_fde=image.frame(following))
    incoming = scan_callers(image.data, image.section('.text'), START)
    need([int(r['site_va'], 16) for r in incoming] == list(CALLS) and
         all(r['opcode'] == '0xe8' for r in incoming), 'direct caller census mismatch')
    contexts, context_text, context_instructions = [], '', {}
    for start, end in CONTEXTS:
        raw = image.read(start, end-start)
        decoded = decode(raw, start)
        context_instructions[start] = decoded
        contexts.append({'start_va': hex(start), 'end_va_exclusive': hex(end), 'sha256': sha(raw)})
        context_text += f'Context {start:#x}..{end:#x}\n' + disassembly(decoded) + '\n'
        if start < 0x1404500:
            need(decoded[-1]['op'] == 'call' and decoded[-1]['args'] == (START,),
                 'caller target mismatch')
    caller = image.frame(CALLER)
    need(caller['end_va_exclusive'] == '0x14046cb', 'caller extent mismatch')
    caller['sha256'] = sha(image.read(CALLER, caller['bytes']))
    need(all(CALLER <= int(r['site_va'], 16) < int(caller['end_va_exclusive'], 16) for r in incoming),
         'caller containment mismatch')
    location_va = 0x566AE58
    need(decode(image.read(0x1404565, 7), 0x1404565)[0]['args'][1] == location_va,
         'Location reference mismatch')
    setup = context_instructions[0x1404565]
    need(setup[1]['args'] == (reg('rsi', 32), 30) and
         setup[2]['args'] == (reg('rdi'), 0x219F59) and
         setup[3]['op'] == 'jmp' and setup[3]['args'] == (0x140458D,) and
         context_instructions[0x140458D][0]['args'] == (0x576E108,),
         'assertion argument/control-flow mismatch')
    relocation = image.relocation(location_va)
    source_va = int(relocation['addend_va'], 16)
    raw_location = image.read(location_va, 24)
    pointer, size, line, column = struct.unpack('<QQII', raw_location)
    source = image.read(source_va, size)
    need(pointer == 0 and size == 49 and line == 124 and column == 13, 'Location layout mismatch')
    need(sha(source) == '58a7d840e049892ccf5e230eeb381e95a74f55306cef2478144d4c76629b64ce',
         'first-party source path mismatch')
    # Keep the binary's historical build-machine prefix out of committed prose.
    suffix = 'base/src/duration.rs'
    need(source.endswith(suffix.encode()), 'source suffix mismatch')
    message = image.read(0x219F59, 30)
    need(message == b'assertion failed: self.0 >= 0.', 'assertion message mismatch')
    rule_vectors = vectors()
    for v in rule_vectors:
        args = (bytes.fromhex(v['haystack_hex']), bytes.fromhex(v['needle_hex']),
                v['offset'], v['mask'], v['guard'])
        need(interpret(instructions, *args)['al'] == v['expected_al'] == int(predicate(*args)),
             'target-grounded vector mismatch')
    branches = [{'site_va': hex(i['va']), 'condition': i['op'], 'target_va': hex(i['args'][0])}
                for i in instructions if i['op'].startswith('j')]
    records = {
        'task': 'RE-001', 'component': 'foundation',
        'provenance': {'novelty': NOVELTY, 'python_validation_version': '3.13.5',
                       'python_minimum_version': '3.10',
                       'exploratory_disassembler': 'GNU objdump 2.44, -d -Mintel with bounded start/stop addresses; not a regeneration dependency',
                       'decoder': 'packet-specific strict Python opcode/operand whitelist',
                       'captured_binary_executed': False,
                       'instruction_completeness': 'complete leaf; selected caller contexts only'},
        'target': {'release': 'node94', 'path': TARGET, 'sha256': DIGEST, 'size': len(image.data)},
        'question': 'Does this leaf find an exact byte-string match at positions selected by an input mask?',
        'function': function, 'callees': [], 'branches': branches,
        'incoming': {'scan': 'full .text, every byte position, e8/e9 signed rel32',
                     'section_start_va': hex(image.section('.text')['address']),
                     'section_bytes': image.section('.text')['size'], 'sites': incoming,
                     'caller_fde': caller, 'decoded_contexts': contexts},
        'first_party_relationship': {'claim': 'direct callee of an FDE referencing a first-party Location; ownership inferred, not established',
            'location_va': hex(location_va), 'location_raw': raw_location.hex(),
            'location_relocation': relocation, 'source_va': hex(source_va),
            'source_bytes': size, 'source_sha256': sha(source), 'source_suffix': suffix,
            'line': line, 'column': column, 'reference_site_va': '0x1404565',
            'message_va': '0x219f59', 'message': message.decode(),
            'panic_call_site_va': '0x140458d', 'panic_slot_va': '0x576e108',
            'scope': 'Location and assertion setup only; panic implementation and enclosing caller semantics unbound'},
        'rule': {'descriptor_register': 'rdi', 'haystack_pointer_offset': 0,
                 'needle_pointer_offset': 16, 'needle_length_offset': 24,
                 'offset_register': 'rsi', 'candidate_bias': 1,
                 'mask_register': 'edx', 'mask_width': 32, 'candidate_mask_width': 16,
                 'guard_register': 'ecx', 'guard_width': 32, 'result_register': 'al',
                 'word_bytes': 4, 'tzcnt_zero': 32,
                 'rule': 'guard != 0 => false; empty needle => true; otherwise compare at haystack + offset + 1 + each low-word set-bit index in ascending order. If low word is zero, compare just once at tzcnt32(edx), with tzcnt32(0)=32.',
                 'preconditions': 'Readable descriptor and compared bytes; non-wrapping pointer arithmetic; TZCNT semantics (BMI1 for zero input). No source type or caller invariant assumed.',
                 'vectors': rule_vectors},
        'counts': {'body_bytes': len(body), 'instructions': len(instructions),
                   'reachable_instructions': len(reachable),
                   'internal_nop_instructions': sum(i['op'] == 'nop' for i in instructions),
                   'internal_nop_bytes': sum(i['size'] for i in instructions if i['op'] == 'nop'),
                   'branches': len(branches), 'returns': sum(i['op'] == 'ret' for i in instructions),
                   'callees': 0, 'direct_call_sites': len(incoming), 'direct_tail_sites': 0,
                   'caller_functions': 1, 'vectors': len(rule_vectors)},
    }
    return records, disassembly(instructions), context_text.rstrip() + '\n'


def read_records(binary=ROOT / TARGET):
    with Path(binary).open('rb') as handle:
        need(handle.seek(0, 2) > 0, 'empty target')
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return collect(Image(data))


def canonical_json(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode()


def readme(r):
    f, c, rule, inc, rel = (r[k] for k in ('function', 'counts', 'rule', 'incoming', 'first_party_relationship'))
    provenance = r['provenance']
    novelty = provenance['novelty']
    novelty_commands = '\n'.join(q['command'] for q in novelty['queries'])
    novelty_hashes = '\n'.join(f'- `{name}`: `{digest}`' for name, digest in sorted(novelty['list_sha256'].items()))
    return f'''# RE-001: masked byte-string comparison at {f['start_va']}

Task/component: {r['task']} / {r['component']}. Static function bind, not a
source implementation or a completion gate. Bounded question: {r['question']}

Answer: the leaf returns false in `{rule['result_register'].upper()}` when incoming
`{rule['guard_register'].upper()}` is nonzero. Otherwise it compares the needle
against candidate starts `haystack + RSI + {rule['candidate_bias']} + bit_index`.
When the low {rule['candidate_mask_width']} mask bits contain any set bit, it visits
those bits in ascending order and returns true on the first exact match, false
after exhaustion. An empty needle returns true. If the low mask word is empty,
the machine still tries a single candidate at `tzcnt(EDX)`, including index
{rule['tzcnt_zero']} for an entirely empty dword under TZCNT semantics. This is
a comparison leaf with {c['callees']} callees; its answer does not depend on an
unbound helper.

## Target and extent

Target `{r['target']['release']}`: `{r['target']['path']}`,
SHA-256 `{r['target']['sha256']}`, size {r['target']['size']} bytes.
All addresses are linked ELF virtual addresses, without rebasing.
Window `{f['start_va']}..{f['end_va_exclusive']}` is {c['body_bytes']} bytes,
file offset `{f['file_offset']}`, body SHA-256 `{f['sha256']}`.
FDE `.eh_frame+{f['fde_section_offset']}` has length field
{f['fde_length_field']}, CIE `.eh_frame+{f['cie_section_offset']}`.
The following FDE starts at `{f['next_fde']['start_va']}`: external padding is
{f['padding_bytes']} bytes. Inside the body are {c['internal_nop_instructions']}
NOP instructions totaling {c['internal_nop_bytes']} bytes. They are decoded
alignment fill, not skipped unknown instructions. Raw FDE/CIE records are in JSON.

The strict Python decoder accounts for {c['instructions']} instructions,
{c['reachable_instructions']} reachable from entry, {c['branches']} branches and
{c['returns']} return instructions. Every branch lands on a decoded instruction
within the FDE. All remaining body instructions are NOP fill. This combination
of decoded control flow, returns and actual FDE extent supports a complete leaf;
neither a comment seed nor the next unwind-table start alone defines its body.

## Instruction-derived observations

`instructions.txt` is the complete byte-addressed instruction walk, generated
by the strict opcode/ModRM whitelist in the tool. Operand suffixes give bit
widths. Unknown encodings, truncated operands and external branch targets fail.
The tool and tests never invoke an external disassembler.

The descriptor in RDI supplies a haystack pointer at
`+{rule['haystack_pointer_offset']}`, a needle pointer at
`+{rule['needle_pointer_offset']}` and a byte length at
`+{rule['needle_length_offset']}`. The intervening descriptor field is not read.
RSI is an offset, not an independent pointer: the leaf adds the descriptor's
haystack base and the candidate bias. The descriptor and byte strings are read;
there are no memory stores, allocation, panics, indirect dispatch or calls.

For lengths below {rule['word_bytes']} bytes, the leaf uses explicit byte tests
with early success at each length boundary. Longer strings use
{rule['word_bytes']}-byte loads from the front and a final
{rule['word_bytes']}-byte load ending exactly at the needle end. For unaligned
lengths the final load overlaps the previous comparison. These loads cover the
whole string without extending past its end. Equality does not depend on byte
order because corresponding words are compared directly.

On a failed candidate, `rol ax, cl` rotates the all-ones-except-low-bit mask,
then `and dx, ax` clears the selected low-word bit. A zero result returns false;
otherwise TZCNT selects the next bit. The high mask word is therefore ignored
once any low-word candidate was present, even when all low-word candidates fail.
Only low-dword input guard/mask bits are inspected. A true result is established
only in AL; upper RAX bits retain scratch data and are not a canonical Boolean.

An initially empty low mask word is not checked before TZCNT. The rule above
records that behavior rather than silently assuming nonempty masks. TZCNT on
zero requires BMI1 semantics; on legacy BSF decoding that case has no defined
destination. Nonzero inputs have the same index under either instruction.
Invalid pointers, overlapping descriptors modified by another thread, and
address wraparound are outside the readable, non-wrapping model domain.

## Callers and first-party relationship

The complete {inc['section_bytes']}-byte `.text` section beginning at
`{inc['section_start_va']}` was scanned at every byte position for signed rel32
e8/e9 encodings targeting the entry. It produced {c['direct_call_sites']} e8
sites, {c['direct_tail_sites']} e9 sites and {c['caller_functions']} enclosing
FDE. All hits decode as calls at the ends of retained argument-setup contexts
in `callers.txt`. This supplies local instruction-boundary support; the complete
caller CFG has not been decoded.
The sites are {', '.join('`'+x['site_va']+'`' for x in inc['sites'])}.
Their common caller extent is `{inc['caller_fde']['start_va']}..{inc['caller_fde']['end_va_exclusive']}`.
This is a direct-site census, not a census of indirect entry references or
proof that no interior entry is used. The caller's full behavior is not bound.

That caller loads Location `{rel['location_va']}` at
`{rel['reference_site_va']}` for the assertion `{rel['message']}`.
The Location's RELATIVE relocation points to the digest-bound historical
first-party source string with suffix `{rel['source_suffix']}` at
line {rel['line']}, column {rel['column']}. JSON records its bytes' hash and
length, source VA, raw Location, and relocation. The absolute historical build
prefix is deliberately not reproduced. This establishes a first-party call
relationship, not authorship: the leaf may be a monomorphized dependency helper.
The assertion call and its implementation are outside the leaf's callee closure.

## Novelty before writing this packet

Each command below returned exit status {novelty['queries'][0]['exit_code']}, empty stdout and empty stderr:

```sh
{novelty_commands}
```

The lists were the supplied sibling copies. Their SHA-256 identities were:

{novelty_hashes}

There are no callee behavior binds needing a separate novelty query. The check
is historical: rerunning it after adding this packet necessarily finds the packet.
Baseline repository revision: `{novelty['baseline_revision']}`.
The reference tree was not used as source; no imported evidence was changed.

## Reproduce and validate

Run from the repository root with Python {provenance['python_minimum_version']} or newer, standard library only:

```sh
python3 {TOOL} --out {PACKET}/
python3 -m unittest tests.test_foundation_masked_compare -v
python3 {PACKET}/verify.py
make verify
make catalogue-check
```

The generator authenticates the whole binary before analysis, maps it read-only,
and regenerates semantic JSON, the instruction walks and this README. Manifest
paths are repository-relative; the verifier enforces an exact whitelist including
the tool, tests, ELF/FDE helpers and all packet files other than the manifest.
`--check` compares regenerated files byte-for-byte and checks the manifest.
Validation used Python {provenance['python_validation_version']}. Exploratory
inspection used {provenance['exploratory_disassembler']}. The committed instruction
walks come entirely from the Python decoder, with complete leaf coverage and
selected caller-context coverage. No decompilation or normalized comparison was used.

JSON contains {c['vectors']} fixed instruction-derived vectors. Tests also compare
an independently written byte-string predicate with an interpreter of the decoded
instructions, exercising candidate order, overlapping final words, sparse masks,
early returns and noncanonical inputs. Invalid synthetic reads fail. These are
static semantic cross-checks, not observed execution results from the node.
Corruption controls attack the target digest, body bytes, FDE/CIE associations,
branch and call targets, Location relocation, census, generated text and manifest.
README counts are rendered from JSON and checked by the tests.

## Non-claims, limitations and next step

No captured binary was executed; no network or installations were used. No
normalization masks, native differential result, Rust build, source symbol,
dependency version or whole-node equivalence is claimed. No catalogue, progress
or acceptance gate changes are requested. The Python opcode semantics are
reviewable but are not an independent hardware oracle. The caller census does
not discover indirect calls, relocations to the entry or alternate interior entry.

Next step: bind the caller's descriptor construction and mask production to
identify the searched strings and prove its nonzero-mask/readability invariants.
That would connect this complete local comparison rule to a named node behavior.
'''


PACKET_FILES = ('README.md', 'records.json', 'instructions.txt', 'callers.txt', 'verify.py')
DEPENDENCIES = (TOOL, TEST, 'tools/elf_index.py', 'tools/fde_extents.py')


def manifest(packet):
    paths = {f'{PACKET}/{name}': packet / name for name in PACKET_FILES}
    paths.update({name: ROOT / name for name in DEPENDENCIES})
    return ''.join(f'{sha(path.read_bytes())}  {name}\n' for name, path in sorted(paths.items())).encode()


def rendered(binary):
    records, walk, callers = read_records(binary)
    return {'records.json': canonical_json(records), 'instructions.txt': walk.encode(),
            'callers.txt': callers.encode(), 'README.md': readme(records).encode()}


def generate(binary, out):
    files = rendered(binary)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_bytes(content)
    verifier = ROOT / PACKET / 'verify.py'
    if out.resolve() != verifier.parent:
        (out / 'verify.py').write_bytes(verifier.read_bytes())
    (out / 'MANIFEST.sha256').write_bytes(manifest(out))


def check_packet(binary, packet):
    allowed = set(PACKET_FILES) | {'MANIFEST.sha256'}
    actual = {p.name for p in packet.iterdir() if p.name != '__pycache__'}
    need(actual == allowed, 'packet file whitelist mismatch')
    need(all(not (packet / name).is_symlink() for name in allowed), 'packet symlinks forbidden')
    # Exact regeneration also refuses duplicate JSON keys, extra keys, stale
    # records, omitted caller rows, edited prose and malformed instruction text.
    for name, expected in rendered(binary).items():
        need((packet / name).read_bytes() == expected, f'regenerated {name} mismatch')
    need((packet / 'MANIFEST.sha256').read_bytes() == manifest(packet), 'manifest whitelist/hash mismatch')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / TARGET)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', type=Path)
    mode.add_argument('--check', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out:
            generate(args.binary, args.out)
        else:
            check_packet(args.binary, args.check)
    except (ValueError, OSError, KeyError, struct.error) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    print('Masked comparison evidence reproduces exactly.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
