#!/usr/bin/env python3
"""RE-001: digest-bound static bind of node #94's asset-name scanner.

Python 3.10+ standard library only. Never executes the captured artifact.
The deliberately restricted x86 decoder rejects unsupported instructions;
it is sufficient for the entire leaf and the explicitly selected caller slices.
"""
import argparse
from dataclasses import dataclass, replace
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
BINARY = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-asset-name-scan-94'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END, NEXT = 0x2786530, 0x27865fc, 0x2786600
BODY_SHA = 'b40e4a821b07be8b4c4905cc2377f7bd408287c129ff5b599832357b34e92c80'
CALLER, CALLER_END, CALLSITE = 0x273af20, 0x273b4af, 0x273b22a
LOCATION, PATH_VA = 0x56e9b28, 0x1fd569
BASELINE = 'e5c9b6436876b2a4a39daef813171f9879317699'
REFERENCE = '999556f6e0a474b8312db96ec3149e1c44e97c23'
TOOL = 'tools/asset_name_scan.py'
TEST = 'tests/test_asset_name_scan.py'
LOCAL_FILES = ('README.md', 'records.json', 'instructions.txt', 'verify.py')
WHITELIST = frozenset((*LOCAL_FILES, TOOL, TEST))
MASK64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Operand:
    kind: str
    width: int
    value: int = 0
    base: int | None = None
    index: int | None = None
    scale: int = 1
    disp: int = 0
    rip: bool = False


@dataclass(frozen=True)
class Instruction:
    va: int
    raw: bytes
    op: str
    args: tuple = ()

    @property
    def end(self):
        return self.va + len(self.raw)


REGS = {
    8: ('al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil'),
    16: ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'),
    32: ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'),
    64: ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'),
}


def reg(n, width):
    return Operand('reg', width, n)


def imm(n, width):
    return Operand('imm', width, n)


def decode(data, start):
    """Decode all bytes; ModRM/SIB, immediates and relative targets are parsed.

    This is an allowlist decoder, not a general-purpose x86 disassembler.
    Unsupported prefixes, groups, truncated operands and opcodes fail closed.
    """
    out, p = [], 0
    while p < len(data):
        begin = p

        def take(n):
            nonlocal p
            require(p + n <= len(data), 'truncated instruction')
            raw = data[p:p + n]
            p += n
            return raw

        def number(n, signed=False):
            return int.from_bytes(take(n), 'little', signed=signed)

        # Exact architectural NOP used between the UTF-8 merge and predicate.
        nop = bytes.fromhex('6666666666662e0f1f840000000000')
        if data[p:p + len(nop)] == nop:
            out.append(Instruction(start + p, nop, 'nop'))
            p += len(nop)
            continue
        prefix66 = data[p] == 0x66
        if prefix66:
            p += 1
            require(p < len(data), 'truncated prefix')
        rex = 0
        if 0x40 <= data[p] <= 0x4f:
            rex = number(1)
        width = 64 if rex & 8 else (16 if prefix66 else 32)
        opcode = number(1)
        require(not prefix66 or opcode == 0xc7, 'unsupported operand-size prefix')

        def modrm(w, rw=None, group=False):
            b = number(1)
            mod, field, low = b >> 6, (b >> 3) & 7, b & 7
            rn = field + (8 if rex & 4 else 0)
            if w == 8 and not rex and rw is None and not group:
                require(field < 4, 'unsupported high byte register')
            ro = reg(rn, w if rw is None else rw)
            if mod == 3:
                if w == 8 and not rex:
                    require(low < 4, 'unsupported high byte register')
                return field, ro, reg(low + (8 if rex & 1 else 0), w)
            base, index, scale, disp, rip = low + (8 if rex & 1 else 0), None, 1, 0, False
            if low == 4:
                sib = number(1)
                scale, ix, lowbase = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
                if ix != 4 or rex & 2:
                    index = ix + (8 if rex & 2 else 0)
                base = lowbase + (8 if rex & 1 else 0)
                if mod == 0 and lowbase == 5:
                    base, disp = None, number(4, True)
            elif mod == 0 and low == 5:
                base, rip, disp = None, True, number(4, True)
            if mod == 1:
                disp = number(1, True)
            elif mod == 2:
                disp = number(4, True)
            return field, ro, Operand('mem', w, base=base, index=index, scale=scale, disp=disp, rip=rip)

        args = ()
        if opcode in (0x8b, 0x89, 0x8d, 0x09, 0x20, 0x84, 0x85, 0x39, 0x31, 0x01):
            w = 8 if opcode in (0x20, 0x84) else width
            _, r, m = modrm(w)
            op = {0x8b: 'mov', 0x89: 'mov', 0x8d: 'lea', 0x09: 'or',
                  0x20: 'and', 0x84: 'test', 0x85: 'test', 0x39: 'cmp', 0x31: 'xor', 0x01: 'add'}[opcode]
            args = (r, m) if opcode in (0x8b, 0x8d) else (m, r)
            require(op != 'lea' or m.kind == 'mem', 'lea requires memory addressing')
        elif opcode in (0x80, 0x81, 0x83, 0xc1, 0xc7):
            w = 8 if opcode == 0x80 else width
            group, _, m = modrm(w, group=True)
            require(not rex & 4, 'unsupported extended opcode group')
            if opcode == 0xc1:
                require(group == 4, 'unsupported shift group')
                op, val = 'shl', number(1)
            elif opcode == 0xc7:
                require(group == 0, 'unsupported mov group')
                op, val = 'mov', number(2 if width == 16 else 4, width == 64)
            else:
                require(group in (0, 4, 7), 'unsupported arithmetic group')
                op = {0: 'add', 4: 'and', 7: 'cmp'}[group]
                n = 4 if opcode == 0x81 else 1
                val = number(n, opcode == 0x83 or (opcode == 0x81 and w == 64))
            args = (m, imm(val & ((1 << w) - 1), w))
        elif opcode == 0xff:
            group, _, m = modrm(64, group=True)
            require(group == 2 and m.kind == 'mem' and m.rip and not rex, 'unsupported indirect transfer')
            op, args = 'call_indirect', (m,)
        elif opcode == 0x0f:
            second = number(1)
            if second == 0xb6:
                _, r, m = modrm(8, width)
                op, args = 'movzx', (r, m)
            elif second == 0x92:
                group, _, m = modrm(8, group=True)
                require(group == 0 and not rex & 4, 'invalid setb group')
                op, args = 'setb', (m,)
            elif second in (0x84, 0x85):
                disp = number(4, True)
                op, args = ('je' if second == 0x84 else 'jne'), (start + p + disp,)
            elif second in (0x10, 0x11):
                _, r, m = modrm(128)
                require(m.kind == 'mem', 'only memory movups is supported')
                r = replace(r, kind='xmm')
                op, args = 'movups', (r, m) if second == 0x10 else (m, r)
            else:
                raise ValueError('unsupported 0f opcode')
        elif opcode in (0xe8, 0xe9, 0xeb, 0x74, 0x75, 0x79, 0x76, 0x72):
            disp = number(4 if opcode in (0xe8, 0xe9) else 1, True)
            op = {0xe8: 'call', 0xe9: 'jmp', 0xeb: 'jmp', 0x74: 'je',
                  0x75: 'jne', 0x79: 'jns', 0x76: 'jbe', 0x72: 'jb'}[opcode]
            args = (start + p + disp,)
        elif 0xb8 <= opcode <= 0xbf:
            op, args = 'mov', (reg(opcode - 0xb8 + (8 if rex & 1 else 0), width),
                               imm(number(8 if width == 64 else 4), width))
        elif opcode == 0xb0:
            require(not rex, 'unsupported byte immediate destination')
            op, args = 'mov', (reg(0, 8), imm(number(1), 8))
        elif opcode == 0xc3:
            require(not rex, 'unsupported ret prefix')
            op = 'ret'
        else:
            raise ValueError(f'unsupported opcode at {start + begin:#x}: {opcode:#x}')
        require(p - begin <= 15, 'oversized x86 instruction')
        # Resolve RIP addressing only after the entire instruction is consumed.
        args = tuple(replace(a, disp=start + p + a.disp, rip=False)
                     if isinstance(a, Operand) and a.rip else a for a in args)
        out.append(Instruction(start + begin, data[begin:p], op, args))
    return out


def operand_text(a):
    if isinstance(a, int):
        return hex(a)
    if a.kind == 'reg':
        return REGS[a.width][a.value] if a.value < 8 else f'r{a.value}' + {8:'b',16:'w',32:'d',64:''}[a.width]
    if a.kind == 'xmm':
        return f'xmm{a.value}'
    if a.kind == 'imm':
        return hex(a.value)
    pieces = []
    if a.base is not None:
        pieces.append(operand_text(reg(a.base, 64)))
    if a.index is not None:
        pieces.append(f'{operand_text(reg(a.index, 64))}*{a.scale}')
    address = '+'.join(pieces)
    if a.disp or not address:
        address += ('+' if address and a.disp >= 0 else '') + hex(a.disp)
    return f'{a.width}-bit [{address}]'


def walk_text(insns):
    return ''.join(f'{i.va:#x}  {i.raw.hex():30}  {i.op}' +
                   ((' ' + ', '.join(map(operand_text, i.args))) if i.args else '') + '\n'
                   for i in insns)


def check_leaf(body):
    require(len(body) == END - START and sha(body) == BODY_SHA, 'function body SHA-256/size mismatch')
    insns = decode(body, START)
    starts = {i.va for i in insns}
    require(insns[-1].end == END, 'incomplete leaf decoding')
    for i in insns:
        require(not i.op.startswith('call'), 'unexpected leaf callee')
        if i.op.startswith('j'):
            require(i.args[0] in starts, 'branch target is not a leaf instruction boundary')
    reachable, todo = set(), [START]
    by_va = {i.va: i for i in insns}
    while todo:
        a = todo.pop()
        if a in reachable:
            continue
        require(a in by_va, 'control flow falls outside leaf')
        reachable.add(a)
        i = by_va[a]
        if i.op.startswith('j'):
            todo.append(i.args[0])
        if i.op not in ('ret', 'jmp'):
            todo.append(i.end)
    require(reachable == starts, 'unaccounted instruction in leaf')
    return insns


def scan_model(text, cursor=0):
    """Independent rule on valid Unicode: (AL, final UTF-8 byte cursor).

    Cursor must be a scalar boundary; the returned index is relative to the
    complete string. No target code, native emulation or external process runs.
    """
    raw = text.encode('utf-8')
    require(0 <= cursor <= len(raw), 'invalid cursor')
    suffix = raw[cursor:].decode('utf-8')
    for char in suffix:
        cursor += len(char.encode('utf-8'))
        if not ('A' <= char <= 'Z' or '0' <= char <= '9'):
            return 1, cursor
    return 0, cursor


def interpret(insns, raw, cursor=0):
    """Static instruction semantics for the leaf; no machine code execution.

    Separate from scan_model: uses decoded operands, widths, flags, branches
    and memory writes. Bounds errors are analysis errors, not target panics.
    """
    text_base, object_base = 0x100000000, 0x200000000
    memory = {text_base + n: b for n, b in enumerate(raw)}
    memory.update({object_base + n: b for n, b in enumerate(
        struct.pack('<QQ', text_base + cursor, text_base + len(raw)))})
    registers = [0] * 16
    registers[7] = object_base
    flags = {'cf': False, 'zf': False, 'sf': False}
    by_va = {i.va: i for i in insns}
    pc, writes = START, []

    def address(a):
        return (a.disp + (registers[a.base] if a.base is not None else 0) +
                (registers[a.index] * a.scale if a.index is not None else 0)) & MASK64

    def get(a):
        if a.kind == 'imm':
            return a.value
        if a.kind == 'reg':
            return registers[a.value] & ((1 << a.width) - 1)
        addr = address(a)
        require(all(addr + j in memory for j in range(a.width // 8)), 'static interpreter read outside supplied memory')
        return sum(memory[addr + j] << (8 * j) for j in range(a.width // 8))

    def put(a, value):
        value &= (1 << a.width) - 1
        if a.kind == 'reg':
            if a.width in (32, 64):
                registers[a.value] = value
            else:
                mask = (1 << a.width) - 1
                registers[a.value] = (registers[a.value] & ~mask) | value
        else:
            addr = address(a)
            require(addr == object_base and a.width == 64, 'unexpected leaf write')
            for j in range(a.width // 8):
                memory[addr + j] = (value >> (8 * j)) & 255
            writes.append(value - text_base)

    for _ in range(100 + 100 * (len(raw) + 1)):
        require(pc in by_va, 'interpreter branch outside decoded leaf')
        i = by_va[pc]
        pc = i.end
        op, a = i.op, i.args
        if op in ('mov', 'movzx'):
            put(a[0], get(a[1]))
        elif op == 'lea':
            put(a[0], address(a[1]))
        elif op in ('cmp', 'test', 'add', 'and', 'or', 'xor', 'shl'):
            x, y, w = get(a[0]), get(a[1]), a[0].width
            mask = (1 << w) - 1
            if op == 'cmp':
                value, carry = (x - y) & mask, x < y
            elif op == 'add':
                value, carry = (x + y) & mask, x + y > mask
            elif op == 'shl':
                count = y & (63 if w == 64 else 31)
                value = (x << count) & mask
                carry = bool((x >> (w - count)) & 1) if count else flags['cf']
            else:
                value = {'and': x & y, 'test': x & y, 'or': x | y, 'xor': x ^ y}[op]
                carry = False
            flags.update(cf=carry, zf=value == 0, sf=bool(value & (1 << (w - 1))))
            if op not in ('cmp', 'test'):
                put(a[0], value)
        elif op == 'setb':
            put(a[0], int(flags['cf']))
        elif op.startswith('j'):
            branch = {'jmp': True, 'je': flags['zf'], 'jne': not flags['zf'],
                      'jns': not flags['sf'], 'jbe': flags['cf'] or flags['zf'], 'jb': flags['cf']}[op]
            if branch:
                pc = a[0]
        elif op == 'ret':
            final = sum(memory[object_base + j] << (8 * j) for j in range(8)) - text_base
            return {'al': registers[0] & 255, 'rax': registers[0], 'cursor': final, 'writes': writes}
        elif op != 'nop':
            raise ValueError('unsupported static interpreter instruction')
    raise ValueError('static interpreter step bound exceeded')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.cies, self.fdes = eh_frame_records(data, self.sections)

    def section(self, name):
        matches = [s for s in self.sections if s['name'] == name]
        require(len(matches) == 1, 'ambiguous/missing section')
        return matches[0]

    def offset(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(size >= 0 and len(matches) == 1, 'ambiguous/outside-file VA range')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start, end=None):
        matches = [f for f in self.fdes if f['start'] == start]
        require(len(matches) == 1, 'missing/ambiguous FDE start')
        f = matches[0]
        require(end is None or f['end'] == end, 'FDE extent mismatch')
        frame = self.section('.eh_frame')
        def raw_record(va):
            length = struct.unpack('<I', self.read(va, 4))[0]
            return self.read(va, 4 + length)
        return {'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                'fde_section_offset': hex(f['fde'] - frame['address']),
                'fde_file_offset': hex(self.offset(f['fde'], 4)),
                'fde_record_bytes': len(raw_record(f['fde'])),
                'fde_sha256': sha(raw_record(f['fde'])),
                'cie_section_offset': hex(f['cie'] - frame['address']),
                'cie_record_bytes': len(raw_record(f['cie'])),
                'cie_sha256': sha(raw_record(f['cie'])),
                'lsda_va': hex(f['lsda']) if f['lsda'] is not None else None}


def authenticate(data):
    require(len(data) == SIZE and sha(data) == DIGEST, 'node #94 digest/size mismatch')


def direct_target(raw, va):
    require(len(raw) == 5 and raw[0] in (0xe8, 0xe9), 'invalid direct rel32 encoding')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def caller_census(image):
    """Every byte position in .text, including unaligned candidates; e8/e9."""
    s = image.section('.text')
    begin, end = s['offset'], s['offset'] + s['size']
    hits = []
    for opcode in (0xe8, 0xe9):
        p = begin
        while True:
            p = image.data.find(bytes([opcode]), p, end)
            if p < 0:
                break
            if p + 5 <= end:
                va = s['address'] + p - begin
                raw = image.data[p:p + 5]
                if direct_target(raw, va) == START:
                    containing = [f for f in image.fdes if f['start'] <= va and va + 5 <= f['end']]
                    require(len(containing) == 1, 'caller candidate has ambiguous/no FDE')
                    hits.append({'site_va': hex(va), 'encoding': raw.hex(),
                                 'kind': 'call' if opcode == 0xe8 else 'tail-jump candidate',
                                 'target_va': hex(START), 'containing_fde_start': hex(containing[0]['start'])})
            p += 1
    hits.sort(key=lambda h: int(h['site_va'], 16))
    return {'section_start_va': hex(s['address']), 'section_end_va_exclusive': hex(s['address'] + s['size']),
            'section_bytes': s['size'], 'method': 'all .text byte positions: e8/e9 signed rel32',
            'hits': hits}


def vectors(insns):
    # Each boundary is taken from a compare immediate, UTF-8 width, or cursor store.
    cases = [('', 0, 'empty'), ('AZ09', 0, 'inclusive accepted endpoints'),
             ('/0', 0, 'below digit range'), (':A', 0, 'above digit range'),
             ('@A', 0, 'below uppercase range'), ('[A', 0, 'above uppercase range'),
             ('aZ', 0, 'lowercase rejected'), ('A0\x00Z', 0, 'NUL consumed, suffix unread'),
             ('AZ_09', 0, 'underscore rejected after prefix'),
             ('AéZ', 0, 'two-byte scalar'), ('A€Z', 0, 'three-byte scalar'),
             ('A😀Z', 0, 'four-byte scalar'), ('A\U0010ffffZ', 0, 'highest valid scalar'),
             ('éA9Z', 2, 'nonzero initial cursor'), ('A0', 2, 'initial cursor at end'),
             ('AZ0', 1, 'valid suffix from scalar boundary')]
    result = []
    for text, cursor, reason in cases:
        raw = text.encode('utf-8')
        actual = interpret(insns, raw, cursor)
        require((actual['al'], actual['cursor']) == scan_model(text, cursor), 'model and instruction semantics disagree')
        result.append({'input_hex': raw.hex(), 'initial_cursor': cursor,
                       'expected_al': actual['al'], 'expected_cursor': actual['cursor'],
                       'cursor_writes': actual['writes'], 'basis': reason})
    return result


def analyze(image):
    """Local checks, also exercised with corruption controls after authentication."""
    insns = check_leaf(image.read(START, END - START))
    fde = image.fde(START, END)
    require(fde['fde_section_offset'] == '0xa4cdc' and fde['cie_section_offset'] == '0x0', 'FDE/CIE association mismatch')
    require(fde['lsda_va'] is None, 'unexpected leaf LSDA')
    following = min(f['start'] for f in image.fdes if f['start'] > START)
    require(following == NEXT, 'next FDE start mismatch')
    padding = image.read(END, NEXT - END)
    require(padding == b'\xcc' * (NEXT - END), 'padding mismatch')
    census = caller_census(image)
    require([(h['site_va'], h['kind']) for h in census['hits']] == [(hex(CALLSITE), 'call')], 'direct caller census mismatch')
    caller_fde = image.fde(CALLER, CALLER_END)
    windows, walks = [], [('complete leaf', insns)]
    for label, a, b in [('caller iterator setup, result test and unbound helper return check', 0x273b215, 0x273b247),
                        ('caller error buffer stores', 0x273b247, 0x273b28e),
                        ('caller Location reference', 0x273b429, 0x273b430)]:
        body = image.read(a, b - a)
        decoded = decode(body, a)
        windows.append({'role': label, 'start_va': hex(a), 'end_va_exclusive': hex(b), 'sha256': sha(body)})
        walks.append((label, decoded))
    setup = walks[1][1]
    call = next(i for i in setup if i.va == CALLSITE)
    require(call.op == 'call' and call.args == (START,), 'wrong callee target in caller slice')
    setup_by_va = {i.va: i for i in setup}
    test, branch = setup_by_va[0x273b22f], setup_by_va[0x273b231]
    require(test.op == 'test' and test.args == (reg(0, 8), reg(0, 8))
            and branch.op == 'je' and branch.args == (0x273b2a6,), 'caller AL test mismatch')
    helper = setup_by_va[0x273b238]
    require(helper.op == 'call_indirect' and helper.args == (Operand('mem', 64, disp=0x576dfd8),), 'supporting transfer slot mismatch')
    # Reconstruct the message from the actual vector loads/stores and qword immediate.
    error_insns = walks[2][1]
    message = bytearray(56)
    xmm, regs = {}, {}
    for i in error_insns:
        dst, src = i.args
        if i.op == 'movups':
            if dst.kind == 'xmm':
                require(src.kind == 'mem' and src.base is None and src.index is None, 'unexpected message load')
                xmm[dst.value] = image.read(src.disp, 16)
            else:
                require(dst.base == 0 and dst.index is None and 0 <= dst.disp <= 32, 'unexpected vector store')
                message[dst.disp:dst.disp + 16] = xmm[src.value]
        elif i.op == 'mov' and dst.kind == 'reg' and src.kind == 'imm':
            regs[dst.value] = src.value
        elif i.op == 'mov' and dst.kind == 'mem' and dst.base == 0:
            require(dst.disp == 48 and dst.width == 64 and src.kind == 'reg', 'unexpected message tail')
            message[48:56] = regs[src.value].to_bytes(8, 'little')
        else:
            # The remaining instructions publish a tagged pointer/length object;
            # their bytes are decoded but its source type is not identified.
            require(i.op == 'mov' and dst.kind == 'mem' and dst.base == 3, 'unexpected error result store')
    require(bytes(message) == b'asset name only accepts upper case characters and digits', 'caller message mismatch')
    loc_insn = walks[3][1][0]
    require(loc_insn.op == 'lea' and loc_insn.args ==
            (reg(8, 64), Operand('mem', 64, disp=LOCATION)), 'Location reference mismatch')
    raw_location = image.read(LOCATION, 24)
    stored_pointer, path_size, line, column = struct.unpack('<QQII', raw_location)
    relocations = []
    for s in image.sections:
        if s['type'] == 4:
            require(s['size'] % 24 == 0, 'truncated ELF64 RELA section')
            for off in range(s['offset'], s['offset'] + s['size'], 24):
                target, info, addend = struct.unpack_from('<QQq', image.data, off)
                if target == LOCATION:
                    relocations.append({'file_offset': hex(off), 'slot_va': hex(target),
                                        'type': info & 0xffffffff, 'symbol_index': info >> 32,
                                        'addend_va': hex(addend)})
    require(len(relocations) == 1 and relocations[0]['type'] == 8 and
            relocations[0]['symbol_index'] == 0 and relocations[0]['addend_va'] == hex(PATH_VA), 'Location RELATIVE relocation mismatch')
    path = image.read(PATH_VA, path_size)
    suffix = path.split(b'/code_Mainnet/')[-1].decode('ascii')
    require(stored_pointer == 0 and line == 30 and column == 33 and
            b'/code_Mainnet/' in path and suffix == 'l1/src/dex_registry/perp_dex.rs', 'caller first-party Location mismatch')
    vec = vectors(insns)
    branches = [{'site_va': hex(i.va), 'condition': i.op, 'target_va': hex(i.args[0])}
                for i in insns if i.op.startswith('j')]
    counts = {'body_bytes': END - START, 'padding_bytes': len(padding),
              'decoded_instructions': len(insns), 'internal_nop_bytes': sum(len(i.raw) for i in insns if i.op == 'nop'),
              'branches': len(branches), 'returns': sum(i.op == 'ret' for i in insns),
              'callees': 0, 'direct_e8_callers': sum(h['kind'] == 'call' for h in census['hits']),
              'direct_e9_candidates': sum(h['kind'] != 'call' for h in census['hits']),
              'caller_slices': len(windows), 'vectors': len(vec), 'scanned_text_bytes': census['section_bytes']}
    records = {
        'task': 'RE-001', 'component_allocation': 'dex-registry',
        'question': 'Which characters stop the asset-name scanner, what does AL return, and where is its cursor left?',
        'target': {'release': '94', 'path': 'artifacts/node/94/hl-node', 'sha256': DIGEST, 'size': SIZE},
        'repository_baseline': BASELINE, 'reference_gitlink': REFERENCE,
        'reference_use': 'Catalogue seeds were checked for overlap; no reference implementation was consulted or copied.',
        'function': {'start_va': hex(START), 'end_va_exclusive': hex(END),
                     'file_offset': hex(image.offset(START, END - START)), 'bytes': END - START,
                     'sha256': BODY_SHA, 'fde': fde, 'next_fde': image.fde(NEXT),
                     'padding_hex': padding.hex(), 'callees': [], 'branches': branches},
        'caller_census': census,
        'caller_context': {'fde': caller_fde, 'body_sha256': sha(image.read(CALLER, CALLER_END - CALLER)),
                           'slices': windows, 'error_message': message.decode('ascii'),
                           'message_vector_data_va': '0x3efb30', 'message_vector_data_sha256': sha(image.read(0x3efb30, 48)),
                           'location': {'va': hex(LOCATION), 'record_sha256': sha(raw_location),
                                        'path_va': hex(PATH_VA), 'path_bytes': path_size,
                                        'path_sha256': sha(path), 'path_suffix': suffix,
                                        'line': line, 'column': column, 'relocation': relocations[0]},
                           'unbound_helper_call': {'site_va': '0x273b238', 'slot_va': '0x576dfd8',
                                                   'scope': 'Only its encoding and following RAX test are decoded; helper semantics are excluded.'},
                           'scope': 'Caller slices and Location association only; caller/helper behavior is not bound.'},
        'rule': {'input': 'RDI points to current u64 pointer at +0 and end u64 pointer at +8',
                 'precondition': 'Valid UTF-8 suffix; current/end are scalar boundaries in one readable range; iterator storage does not alias the bytes.',
                 'accepted_scalar_intervals_inclusive': [[48, 57], [65, 90]],
                 'predicate_u32': '((cp - 91) mod 2**32 < 2**32 - 26) and ((cp - 58) mod 2**32 < 2**32 - 10)',
                 'return': 'AL=1 after consuming first scalar outside the intervals; AL=0 on exhaustion.',
                 'writes': 'Only the current pointer at [RDI], advanced before each byte load of a scalar. End pointer unchanged.',
                 'upper_return_bits': 'Not a canonical u64 boolean: the AL=1 path retains high RAX bits from the end pointer.',
                 'unchecked_input': 'No continuation, overlong, scalar-validity or remaining-length checks. A decoded four-byte 0x110000 takes the AL=0 path early.'},
        'vectors': vec, 'counts': counts,
    }
    text = 'Strict Python decoder; ELF virtual addresses; no normalization masks.\n\n'
    for label, rows in walks:
        text += label + '\n' + walk_text(rows) + '\n'
    text += f'{END:#x}..{NEXT:#x}  {padding.hex()}  external int3 padding\n'
    return records, text


def collect(binary=BINARY):
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'node #94 digest/size mismatch')
        handle.seek(0)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            authenticate(data)
            return analyze(Image(data))


def counts_table(records):
    return '\n'.join(['| Measurement | Count |', '| --- | ---: |'] +
                     [f'| {k} | {v} |' for k, v in records['counts'].items()])


def readme(records):
    f = records['function']
    return f'''# RE-001: bind node #94 asset-name scanning at 0x2786530

Task: RE-001; research allocation: dex-registry. Claim: complete leaf behavior,
with bounded caller context. No reconstruction or completion gate is requested.

## Bounded question and answer

Which characters stop this scanner, what does AL return, and where is its
cursor left? Given an iterator holding current/end pointers to a valid UTF-8
suffix, the function consumes scalars until it finds a character outside
ASCII `A–Z` and `0–9`, then returns `AL=1` with the current pointer immediately
past that character. Exhaustion returns `AL=0` and leaves current equal to end.
Empty input therefore returns false. Only the current-pointer field is written;
the end field is preserved. This is an invalid-character search, not an
uppercasing operation. The caller's error text identifies its asset-name use.

## Target, boundaries, and scope

Target: `artifacts/node/94/hl-node`, SHA-256
`{DIGEST}` (authority: `provenance/artifacts.json`).
Repository baseline: `{BASELINE}`. Pinned reference gitlink:
`{REFERENCE}`; reference source was neither consulted nor copied.
The catalogue's unverified comment seeds were inspected only for selection and
overlap. The selected start is inside the required `[0x2000000,0x3000000)` band.

All addresses are ELF virtual addresses unless explicitly called file offsets.
The function is `[0x2786530,0x27865fc)`, file offset `{f['file_offset']}`.
Its body SHA-256 is `{BODY_SHA}`. The actual FDE is at
`.eh_frame+{f['fde']['fde_section_offset']}`, with CIE at
`.eh_frame+{f['fde']['cie_section_offset']}`. It has no LSDA. The next FDE
starts at `0x2786600`; the intervening bytes are exclusively `cc` (`int3`).
`records.json` retains the FDE/CIE hashes, record lengths, next-FDE identity,
branch edges and section mapping. Complete decoding reaches the recorded end,
all branch targets land on instruction boundaries inside the body, and all
instructions are reachable. FDE boundaries alone were not used as proof.

<!-- counts:start -->
{counts_table(records)}
<!-- counts:end -->

Counts above come exclusively from `records.json`; the tests compare this
whole table with the JSON. Sizes describe this selected leaf and the scan
scope, not a component denominator. The instruction count includes the internal
NOP and excludes external padding. Callee identities/extents form an empty
set: this function neither calls nor tail-transfers outside its own body.

## Instruction-derived rule

`instructions.txt` is generated entirely by the strict Python decoder and
contains every instruction byte in the leaf, plus the explicitly scoped caller
slices. Its body walk is:

- Entry loads current from `[RDI]` into R8 and end from `[RDI+8]` into RAX.
  Equality is tested at `0x2786572`; the empty path reaches `xor eax,eax; ret`.
- The byte at current is loaded after storing current+1. A nonnegative byte
  goes straight to the predicate. A high-bit lead takes the masked UTF-8
  assembly paths. The lead thresholds are `0xdf` and `0xf0`; continuation
  payloads are masked by `0x3f`, with shifts `6`, `12` and `18`. Each additional
  byte has a corresponding advance stored before its load.
- At `0x2786550`, ESI gets `(cp-0x5b) mod 2**32`. The unsigned comparison with
  `0xffffffe6` and `setb sil` identifies scalars outside `[0x41,0x5a]`.
  EDX similarly becomes `(cp-0x3a) mod 2**32`, and comparison with
  `0xfffffff6` identifies scalars outside `[0x30,0x39]`.
  AND of these predicates identifies characters outside both accepted ranges.
- The rejection branch at `0x278656c` reaches `mov al,1; ret`. Otherwise the
  advanced cursor becomes the next R8 and the equality/decoding loop repeats.
  The rejection path writes AL only: the remaining RAX bits retain the loaded
  end pointer. A canonical full-register boolean is not claimed.
- The `0x110000` comparison in the long decoding path returns false early for
  that decoded value. It cannot occur in valid UTF-8. Its presence does not
  turn this routine into a UTF-8 validator.

`scan_model` is independently authored Python expressing the accepted character
ranges directly. `interpret` instead applies the decoded instruction operands,
register widths, flags, branches and pointer stores to synthetic memory.
Recorded vectors compare the model with this static interpretation. Tests also
exercise ASCII exhaustively, Unicode width/range boundaries, nonzero cursors,
consumption of the first rejected scalar, and malformed-input counterexamples.
Neither mechanism executes the node or proves dynamic target equivalence.

## Caller census and first-party association

The generator scans every byte position of the entire authenticated `.text`
for both `e8` and `e9` signed-rel32 targets, without an alignment assumption.
The result is the direct call at `0x273b22a`, inside the actual FDE
`[0x273af20,0x273b4af)`. Its encoded target is independently decoded in the
caller slice. Setup at `0x273b215` forms current/end pointers in stack storage
and passes its address in RDI. At `0x273b22f` the caller tests AL; zero branches
to `0x273b2a6`. The nonzero path calls through slot `0x576dfd8`; if that
unbound helper returns a nonzero RAX, the following decoded branch falls
through to buffer stores at `0x273b247`. Those stores assemble **“asset name only accepts upper case characters and digits”** from
RIP-relative vector loads and an immediate qword. Those loads, stores and
literal bytes are decoded and rechecked; allocator semantics are excluded.

The same caller's `lea r8` at `0x273b429` refers to the Location at
`0x56e9b28`, whose `R_X86_64_RELATIVE` relocation points to the embedded
first-party path suffix `l1/src/dex_registry/perp_dex.rs`, line 30, column 33.
The record and complete path bytes are hashed; the captured build's absolute
prefix is omitted from the packet. This establishes first-party caller context,
not that the leaf was originally declared in that file. The allocation label
and descriptive function name are inferences; the instruction rule and error
message are observations.

This is an exhaustive **byte-pattern** direct-transfer census, not a whole
program xref graph. The hit agrees with the decoded local setup/call/result
sequence; the entire caller is not instruction-decoded or behavior-bound here.
Indirect calls, address-taken entries, prefixes, other sections and dynamically
constructed targets are outside the census. No unseen caller is invented.

## Novelty before packet creation

Checked at the repository baseline above, before adding this packet. With
`PR_LIST_DIR` set to the supplied directory containing the upstream title-list
copies, these exact searches all had exit status 1, empty stdout and empty
stderr:

```sh
rg -i '2786530' research/
rg -i '41444656' research/
rg -i '2786530' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
rg -i '41444656' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
```

The decimal form is the selected start address. No behavior-bound callee
requires an additional novelty search. The supplied title-list hashes are
retained in `records.json`; these are historical selection checks, not claims
about PRs opened after those snapshots. Repeating the research search after
adding this packet necessarily finds the new packet itself.

## Reproduction and validation

From the repository root, using Python 3.10+ standard library only:

```sh
python3 tools/asset_name_scan.py --out research/work-items/RE-001-asset-name-scan-94/
python3 -m unittest tests.test_asset_name_scan -v
python3 research/work-items/RE-001-asset-name-scan-94/verify.py
make verify
make catalogue-check
```

The checker fails closed on the pinned whole-file digest before analyzing
bytes. It verifies the complete leaf, FDE/CIE binding, padding, direct-caller
scan, caller slices, relocated Location, literal and model vectors. The
manifest has an exact whitelist including this packet, its tool and its tests;
extra, duplicate, missing and traversal entries are rejected. Regeneration
checks compare generated files byte for byte, including this README and the
human-readable instruction walk. No disassembler subprocess is used by the
tool, checker or tests. The implementation uses the existing stdlib ELF/FDE
parsers; the new restricted decoder is packet-specific, needed to validate
this previously unbound leaf under the no-disassembler-dependency constraint.

Analysis used Python 3.13.5. GNU objdump 2.44 was used only for initial local
inspection; no native-disassembler output is required to reproduce the packet.
No normalization mask is applied. No captured artifact was executed.

Baseline repository validation: `make doctor` reported static analysis ready.
`make verify` initially stopped on a node #115 LFS pointer. The requested
`git lfs pull` succeeded; all captured artifact digests and signatures then
passed, but verification stopped at the missing pinned reference
`references/can1357-hl/bin/hl-node-mainnet-new`. That unrelated checkout gap was
left unchanged. Final check outcomes are recorded in the uncommitted handoff.

## Non-claims, limitations, and next step

The rule requires valid UTF-8, readable pointer ranges, a current pointer at a
scalar boundary, and nonaliasing iterator/input storage. Malformed input can
be accepted after masked decoding, can reach the sentinel return, or can read
past the supplied range; there is no validity or continuation-length guard.
The static interpreter reports a missing-memory analysis error rather than
inventing a target panic. Pointer aliasing, asynchronous memory changes and
hardware faults are outside the model.

This packet does not recover the original Rust symbol, exact source type,
full asset-name policy, error enum, allocator/helper closure, entire caller,
node #115 behavior, runtime behavior equivalence, build provenance or binary
reconstruction. It adds no Rust component, coverage registration or progress
gate. Data/relocation evidence is limited to the selected caller context;
vtable, whole-ELF and other helper questions remain open.

Next bounded question: bind the caller's preceding input checks
and its error-tag contract to establish the full asset-name acceptance rule.
'''


NOVELTY = {
    'baseline': BASELINE,
    'checks': [{'term': term, 'scope': scope, 'exit_code': 1, 'stdout': '', 'stderr': ''}
               for term in ('2786530', '41444656') for scope in ('research', 'pr_titles')],
    'pr_lists': [
        {'name': 'open_prs.txt', 'sha256': '9e6a8c69d7e6cfe350157045fbe69718186847f8a26854c4d9b79690dbb7a962'},
        {'name': 'merged_prs.txt', 'sha256': 'c291aef81f04946a0e6594630e2a5538052c57d12bc79580150555ee0d89ac6d'},
        {'name': 'closed_unmerged_prs.txt', 'sha256': '7ffc9b73e46cf197874fe3cc691a8c8380e5ef8139dc4d23d90ff7db86819406'},
    ],
}


def payload(binary=BINARY):
    records, walk = collect(binary)
    records['novelty'] = NOVELTY
    return {'records.json': (json.dumps(records, indent=2) + '\n').encode(),
            'instructions.txt': walk.encode(), 'README.md': readme(records).encode()}


def manifest_paths(packet):
    return {name: (ROOT / name if name in (TOOL, TEST) else Path(packet) / name)
            for name in WHITELIST}


def manifest_text(packet):
    return ''.join(f'{sha(path.read_bytes())}  {name}\n'
                   for name, path in sorted(manifest_paths(packet).items()))


def check_manifest(packet):
    rows = (Path(packet) / 'MANIFEST.sha256').read_text().splitlines()
    seen = set()
    paths = manifest_paths(packet)
    for row in rows:
        parts = row.split('  ')
        require(len(parts) == 2, 'invalid manifest row')
        digest, name = parts
        require(name in WHITELIST and name not in seen, 'manifest whitelist/duplicate violation')
        require(not paths[name].is_symlink(), 'manifest symlink forbidden')
        require(digest == sha(paths[name].read_bytes()), 'manifest hash mismatch: ' + name)
        seen.add(name)
    require(seen == WHITELIST, 'manifest missing whitelisted file')


def check_packet(packet=PACKET, binary=BINARY):
    check_manifest(packet)
    expected = payload(binary)
    for name, data in expected.items():
        require((Path(packet) / name).read_bytes() == data, 'regenerated evidence differs: ' + name)
    return json.loads(expected['records.json'])


def generate(out, binary=BINARY):
    generated = payload(binary)  # Authenticate before touching output files.
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in generated.items():
        (out / name).write_bytes(data)
    if out.resolve() != PACKET.resolve():
        (out / 'verify.py').write_bytes((PACKET / 'verify.py').read_bytes())
    (out / 'MANIFEST.sha256').write_text(manifest_text(out))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=BINARY)
    p.add_argument('--out', type=Path)
    p.add_argument('--check', type=Path)
    args = p.parse_args()
    require(bool(args.out) != bool(args.check), 'choose exactly one of --out or --check')
    if args.out:
        generate(args.out, args.binary)
        print('Evidence regenerated for node #94 asset-name scanner 0x2786530.')
    else:
        check_packet(args.check, args.binary)
        print('ALL CHECKS PASSED')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('asset_name_scan: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
