#!/usr/bin/env python3
"""RE-004: every Wei add and sub recorder site of node #94 (static, no execution).

One Rust Location, l1/src/qtys/impl_wei.rs:6:1, is passed to an overflow recorder.  At each
site a u64 add or subtract has overflowed: the code calls the recorder, which returns, and
goes on with the saturated value.  An add goes on with u64::MAX, a subtract with 0.  Functions
named by other work items are left out and listed, so this packet shares no function with them.

The tool lists every lea of the Location, finds the branches into each site and the
instruction that set their carry flag, and classifies the operation from those.  It then runs
the real instructions of every guard on paired vectors, interpreting an objdump listing in
Python.  All registers and memory start as random marks.  At the flag-setting instruction,
each location holding the mark of an operand is rewritten with the vector value, which keeps
copies of an operand consistent.

For every overflowing vector the run is compared with a run that does not overflow and gives
the same saturated result (a+b == u64::MAX, or a == b).  Both must reach a common address, the
first run with exactly one more recorder call.  Some location there must agree between the two
runs and differ from a run with another result.  A guard with no such location must show that
its result only decides a branch: another result leaves the path, and no callee-saved register
differs at the common address.  Every site is then damaged in the listing and must fail.
Nothing from the binary runs natively.

    python3 tools/wei_saturating_ops.py --out <dir>

writes evidence.json, wei-sites.tsv and mutation-controls.tsv.  Only the Python standard
library and objdump are used.
"""

import argparse
import bisect
import concurrent.futures
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
SIGN = 1 << 63

TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1343c80, 0x1342c80, 0x431c430
HDR_VA = 0xbf4670
RELA_OFF, RELA_SIZE = 0x6bc0, 0x1d4e10
DATA_DELTA = 0x2000
RELATIVE = 8

LOCATION = 0x56dfd90
LOCATION_SUFFIX = b'/l1/src/qtys/impl_wei.rs'
SHOWN_PATH = 'l1/src/qtys/impl_wei.rs'
LOCATION_LINE, LOCATION_COLUMN = 6, 1
RECORDER_SLOT, RECORDER = 0x5773190, 0x358dcd0
RECORDER_INNER, RECORDER_CLEAR, RECORDER_CLEAR_SLOT = 0x3396b10, 0x358db60, 0x5773e18
RECORDER_CLEAR_REFERENCES = 3
RECORDER_GLOBALS = (0x5786278, 0x57862a0)
EXCLUDED_FUNCTIONS = {
    0x1e61320: 'RE-010-exchange-handlers', 0x2760040: 'RE-010-exchange-handlers',
    0x2712ce0: 'RE-004-ntl-ten-thousand-add-94', 0x4d05e10: 'RE-004-ntl-ten-thousand-add-94',
    0x4d075d0: 'RE-004-ntl-ten-thousand-add-94',
    0x2723c70: 'RE-004-wei-buffered-cap-94', 0x27240b0: 'RE-004-wei-buffered-cap-94',
    0x4d29720: 'RE-004-wei-buffered-cap-94', 0x4d29bf0: 'RE-004-wei-buffered-cap-94',
    0x4d2a0c0: 'RE-004-wei-buffered-cap-94'}
EXCLUDED_SITES_PER_FUNCTION = 1
REFERENCE_MESSAGES = (b'Wei addition overflow', b'Wei subtraction underflow')

HUNDRED_MAGIC, HUNDRED_SHIFT = 0x28f5c28f5c28f5c3, 66   # x / 100 is ((x >> 2) * magic) >> 66

REG64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
REG32 = dict(zip(('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                  'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'), REG64))
REG16 = dict(zip(('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                  'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'), REG64))
REG8 = dict(zip(('al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'), REG64))
CALLER_SAVED = ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11')
CALLEE_SAVED = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')
WIDTH = {'QWORD': 64, 'DWORD': 32, 'WORD': 16, 'BYTE': 8}
VECTOR_OPS = ('movups', 'movaps', 'movapd', 'movupd', 'movdqa', 'movdqu', 'movsd', 'movss', 'movq', 'movd')
FLAG_WRITERS = ('test', 'and', 'or', 'xor', 'dec', 'inc', 'neg', 'shl', 'shr', 'sar', 'sbb', 'adc', 'imul', 'mul')
NEGATE = {'b': 'ae', 'ae': 'b', 'a': 'be', 'be': 'a'}

OVER_ADD = ((MASK, 1), (1, MASK), (MASK, MASK), (SIGN, SIGN), (MASK - 1, 2), (SIGN + 1, SIGN - 1))
OVER_SUB = ((0, 1), (1, 2), (5, MASK), (SIGN - 1, SIGN), (MASK - 1, MASK), (0, MASK))
OTHER_RESULTS = (1, 2, 1 << 20, 1 << 40, 1 << 62)
SEEDS = (1, 2)
RETURNED = -1
COLD_WALK = 20
STEP_LIMIT = 160
BACK_LIMIT = 30


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


def as_double(value):
    return struct.unpack('<Q', struct.pack('<d', float(value)))[0]


def hundred_proof(magic=HUNDRED_MAGIC):
    """floor(y * magic / 2^66) == floor(y / 25) for every y below 2^62, and x >> 2 is such a y.

    Write magic / 2^66 = 1 / 25 + delta / (25 * 2^66).  With delta > 0 the product never falls
    below y / 25, and it stays below the next integer when y * delta < 2^66.
    """
    delta = 25 * magic - (1 << HUNDRED_SHIFT)
    return {'magic': f'{magic:#x}', 'delta': delta, 'proved': delta > 0 and (1 << 62) * delta < (1 << HUNDRED_SHIFT)}


def mark(*key):
    return int.from_bytes(hashlib.sha256(repr(key).encode()).digest()[:8], 'little')


def split_operands(text):
    return re.split(r',(?![^\[]*\])', text)


def load_binary(path):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise EvidenceError(f'binary digest {digest} is not node #94')
    return data


def fde_table(blob):
    """Return sorted [(start, end)] from .eh_frame_hdr, reading each FDE for its range."""
    version, ptr_enc, count_enc, table_enc = struct.unpack_from('<4B', blob, HDR_VA)
    if (version, ptr_enc, count_enc, table_enc) != (1, 0x1b, 0x03, 0x3b):
        raise EvidenceError('unexpected .eh_frame_hdr encoding')
    count = struct.unpack_from('<I', blob, HDR_VA + 8)[0]
    table = []
    for i in range(count):
        start, fde = struct.unpack_from('<ii', blob, HDR_VA + 12 + 8 * i)
        start += HDR_VA
        fde += HDR_VA
        rel, size = struct.unpack_from('<iI', blob, fde + 8)
        if fde + 8 + rel != start:
            raise EvidenceError(f'FDE at {fde:#x} does not begin at {start:#x}')
        table.append((start, start + size))
    table.sort()
    for (first, _), (second, _) in zip(table, table[1:]):
        if first == second:
            raise EvidenceError(f'duplicate FDE start {second:#x}')
    return table


def enclosing(table, starts, va):
    index = bisect.bisect_right(starts, va) - 1
    if index < 0 or not table[index][0] <= va < table[index][1]:
        raise EvidenceError(f'{va:#x} is outside every FDE')
    return table[index]


def relocations(blob):
    table = {}
    for pos in range(RELA_OFF, RELA_OFF + RELA_SIZE, 24):
        offset, info, addend = struct.unpack_from('<QQq', blob, pos)
        if info & 0xffffffff == RELATIVE:
            table[offset] = addend
    return table


def read_location(blob, relocs, va):
    if va not in relocs:
        raise EvidenceError(f'no RELATIVE relocation at {va:#x}')
    length, line, column = struct.unpack_from('<QII', blob, va - DATA_DELTA + 8)
    return blob[relocs[va]:relocs[va] + length], line, column


def lea_references(blob, target):
    """Every REX.W lea r64,[rip+disp32] in .text that resolves to target."""
    text = blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits = []
    for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        disp = struct.unpack_from('<i', text, pos + 3)[0]
        if TEXT_VA + pos + 7 + disp == target:
            hits.append(TEXT_VA + pos)
    return hits


def disassemble(path, start, end):
    result = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', f'--start-address={start}',
         f'--stop-address={end}', str(path)], capture_output=True, text=True, check=True)
    rows = []
    for line in result.stdout.splitlines():
        if not line.startswith(' ') or ':\t' not in line:
            continue
        address, body = line.split(':\t', 1)
        target = 0
        if '#' in body:
            target = int(body.split('#', 1)[1].split()[0], 16)
        text = re.sub(r'\s+', ' ', body.split('#', 1)[0].split('<', 1)[0]).strip()
        rows.append((int(address, 16), text, target))
    if not rows:
        raise EvidenceError(f'no instructions in {start:#x}..{end:#x}')
    return rows


def recorder_registers(rows):
    """Addresses of `call reg` rows whose nearest earlier write of reg loads the recorder slot."""
    found = set()
    for k, row in enumerate(rows):
        match = re.fullmatch(r'call (r\w+)', row[1])
        if not match:
            continue
        register = match.group(1)
        for back in range(k - 1, -1, -1):
            if rows[back][1].startswith(f'mov {register},'):
                if rows[back][2] == RECORDER_SLOT:
                    found.add(row[0])
                break
    return found


class Machine:
    """Interprets objdump rows for one function.  Unknown results become fresh marks."""

    def __init__(self, rows, index, reg_calls, seed):
        self.rows, self.index, self.reg_calls, self.seed = rows, index, reg_calls, seed
        self.regs = {name: mark(seed, 'reg', name) for name in REG64}
        self.regs['rsp'] = 0x7000000000 + (mark(seed, 'sp') & 0xfff0)
        self.ram = {}
        self.stored = {}
        self.xmm = {}
        self.compared = []
        self.flags = None
        self.records = 0
        self.fresh = 0
        self.trace = []

    def havoc(self):
        self.fresh += 1
        return mark(self.seed, 'fresh', self.fresh)

    def address(self, operand):
        inner = operand[operand.index('[') + 1:operand.rindex(']')]
        if 'rip' in inner:
            raise Halt('rip-relative memory')
        total = 0
        for sign, term in re.findall(r'([+-]?)([^+-]+)', inner):
            if '*' in term:
                register, scale = term.split('*')
                value = self.regs[register] * int(scale)
            elif term in self.regs:
                value = self.regs[term]
            else:
                value = int(term, 16)
            total += -value if sign == '-' else value
        return total & MASK

    def read(self, operand):
        if operand in self.regs:
            return self.regs[operand]
        if operand in REG32:
            return self.regs[REG32[operand]] & 0xffffffff
        if operand in REG16:
            return self.regs[REG16[operand]] & 0xffff
        if operand in REG8:
            return self.regs[REG8[operand]] & 0xff
        if operand.startswith('0x'):
            return int(operand, 16)
        match = re.match(r'(QWORD|DWORD|WORD|BYTE) PTR ', operand)
        if not match:
            raise Halt(f'operand {operand}')
        where = self.address(operand)
        if match.group(1) == 'QWORD':
            if where not in self.ram:
                self.ram[where] = mark(self.seed, 'mem', where)
            return self.ram[where]
        return mark(self.seed, 'mem', where, match.group(1)) & ((1 << WIDTH[match.group(1)]) - 1)

    def write(self, operand, value):
        value &= MASK
        if operand in self.regs:
            self.regs[operand] = value
        elif operand in REG32:
            self.regs[REG32[operand]] = value & 0xffffffff
        elif operand in REG16:
            self.regs[REG16[operand]] = (self.regs[REG16[operand]] & ~0xffff & MASK) | (value & 0xffff)
        elif operand in REG8:
            self.regs[REG8[operand]] = (self.regs[REG8[operand]] & ~0xff & MASK) | (value & 0xff)
        elif operand.startswith('xmm'):
            pass
        elif 'PTR' in operand:
            where = self.address(operand)
            self.ram[where] = value if operand.startswith('QWORD') else self.havoc()
            self.stored[where] = operand
        else:
            raise Halt(f'destination {operand}')

    def condition(self, code):
        if self.flags is None:
            raise Halt('flags unknown')
        flags = self.flags
        carry, zero, sign, over = flags['c'], flags['z'], flags['s'], flags['o']
        table = {'b': carry, 'ae': not carry, 'e': zero, 'ne': not zero, 'be': carry or zero,
                 'a': not (carry or zero), 's': sign, 'ns': not sign, 'o': over, 'no': not over,
                 'l': sign != over, 'ge': sign == over, 'le': zero or sign != over,
                 'g': not zero and sign == over}
        if code not in table:
            raise Halt(f'condition {code}')
        return table[code]

    def width(self, operand):
        if operand in REG32:
            return 32
        if operand in REG16:
            return 16
        if operand in REG8:
            return 8
        match = re.match(r'(QWORD|DWORD|WORD|BYTE) PTR ', operand)
        return WIDTH[match.group(1)] if match else 64

    def arithmetic(self, left, right, width, subtract):
        mask = (1 << width) - 1
        sign = 1 << (width - 1)
        result = (left - right if subtract else left + right) & mask
        carry = left < right if subtract else left + right > mask
        same = bool(left & sign) == bool(right & sign)
        over = (not same if subtract else same) and bool(result & sign) != bool(left & sign)
        self.flags = {'c': carry, 'z': result == 0, 's': bool(result & sign), 'o': over}
        return result

    def logic(self, result, width):
        self.flags = {'c': False, 'o': False, 'z': result == 0, 's': bool(result >> (width - 1) & 1)}

    def call(self, row):
        body = row[1]
        direct = body.startswith('call QWORD PTR [rip+') and row[2] == RECORDER_SLOT
        if not direct and row[0] not in self.reg_calls:
            raise Halt(f'call {body}')
        if self.regs['rsi'] != LOCATION or self.regs['rdi'] & 0xff:
            raise Halt('recorder called with other arguments')
        self.records += 1
        for name in CALLER_SAVED:
            self.regs[name] = self.havoc()
        self.flags = None

    def step(self, position):
        row = self.rows[position]
        body = row[1]
        parts = body.split(' ', 1)
        name = parts[0]
        ops = split_operands(parts[1]) if len(parts) > 1 else []
        following = position + 1
        if name in ('mov', 'movabs'):
            self.write(ops[0], self.havoc() if ops[1].startswith('xmm') else self.read(ops[1]))
        elif name == 'movzx':
            self.write(ops[0], self.read(ops[1]))
        elif name in ('movsx', 'movsxd'):
            self.read(ops[1])
            self.write(ops[0], self.havoc())
        elif name == 'lea':
            self.write(ops[0], row[2] if 'rip' in ops[1] else self.address(ops[1]))
        elif name in ('add', 'sub', 'cmp'):
            width = self.width(ops[0])
            self.compared.append((self.read(ops[0]), self.read(ops[1])))
            result = self.arithmetic(self.read(ops[0]), self.read(ops[1]), width, name != 'add')
            if name != 'cmp':
                self.write(ops[0], result)
        elif name in ('xor', 'and', 'or', 'test'):
            left, right = self.read(ops[0]), self.read(ops[1])
            if name == 'xor':
                result = 0 if ops[0] == ops[1] else left ^ right
            else:
                result = left | right if name == 'or' else left & right
            self.logic(result, self.width(ops[0]))
            if name == 'test':
                self.compared.append((left, right))
            else:
                self.write(ops[0], result)
        elif name in ('shr', 'shl', 'sar'):
            count = self.read(ops[1]) & 0x3f
            value = self.read(ops[0])
            if self.width(ops[0]) != 64:
                raise Halt('narrow shift')
            if name == 'shr':
                result = value >> count
            elif name == 'shl':
                result = value << count
            else:
                result = (value - (1 << 64) if value & SIGN else value) >> count
            self.write(ops[0], result)
            self.flags = None
        elif name == 'neg':
            value = self.read(ops[0])
            result = self.arithmetic(0, value, 64, True)
            self.write(ops[0], result)
        elif name == 'not':
            self.write(ops[0], ~self.read(ops[0]))
        elif name in ('xorps', 'xorpd', 'pxor') and ops[0] == ops[1]:
            self.xmm[ops[0]] = 0
        elif name == 'cvtsi2sd' and ops[1] in self.regs:
            value = self.regs[ops[1]]
            self.xmm[ops[0]] = as_double(value - (1 << 64) if value & SIGN else value)
        elif name == 'mul' and len(ops) == 1 and self.width(ops[0]) == 64:
            product = self.regs['rax'] * self.read(ops[0])
            self.regs['rax'], self.regs['rdx'] = product & MASK, product >> 64
            self.flags = None
        elif name.startswith('cmov'):
            value = self.read(ops[1])
            if self.condition(name[4:]):
                self.write(ops[0], value)
            elif ops[0] in REG32:
                self.write(ops[0], self.read(ops[0]))
        elif name.startswith('set'):
            self.write(ops[0], int(self.condition(name[3:])))
        elif name == 'jmp':
            if not re.fullmatch(r'[0-9a-f]+', ops[0]):
                raise Halt('indirect jmp')
            following = self.target(ops[0])
        elif name.startswith('j'):
            if self.condition(name[1:]):
                following = self.target(ops[0])
        elif name == 'call':
            self.call(row)
        elif name == 'push':
            self.regs['rsp'] -= 8
            self.ram[self.regs['rsp']] = self.read(ops[0])
        elif name == 'pop':
            self.write(ops[0], self.read('QWORD PTR [rsp]'))
            self.regs['rsp'] += 8
        elif name == 'ret':
            self.trace.append(RETURNED)
            raise Halt('ret')
        elif name in ('ud2', 'int3'):
            raise Halt(name)
        elif name == 'nop' or name.startswith(('nop', 'data16', 'cs')) or body == 'xchg ax,ax':
            pass
        elif name in VECTOR_OPS and ops and 'PTR' in ops[0]:
            where = self.address(ops[0])
            self.ram[where] = self.havoc()
            self.ram[where + 8] = self.havoc()
        else:
            # Anything else leaves a fresh mark, so a result that depends on it cannot match.
            if ops and ops[0].startswith('xmm'):
                self.xmm[ops[0]] = self.havoc()
            elif ops:
                self.write(ops[0], self.havoc())
            self.flags = None
        return following

    def target(self, text):
        address = int(text, 16)
        if address not in self.index:
            raise Halt('branch outside the function')
        return self.index[address]


def branch_targets(rows):
    targets = {}
    for k, row in enumerate(rows):
        match = re.fullmatch(r'(j[a-z]+) ([0-9a-f]+)', row[1])
        if match:
            targets.setdefault(int(match.group(2), 16), []).append(k)
    return targets


def block_entry(rows, targets, lea):
    """Walk back from the lea over the argument setup that leads to the recorder call."""
    entry = lea
    while entry > 0 and rows[entry][0] not in targets:
        previous = rows[entry - 1][1]
        if previous.startswith(('j', 'ret', 'ud2')) or previous.split()[0] not in ('xor', 'lea', 'mov'):
            break
        entry -= 1
    return entry


def find_guards(rows, targets, lea):
    """Return [(branch row, taken_goes_to_site)] for every conditional edge into the site."""
    entry = block_entry(rows, targets, lea)
    guards = []
    for k in range(entry, lea + 1):
        for source in targets.get(rows[k][0], ()):
            if rows[source][1].startswith('jmp'):
                if not re.match(r'j(?!mp)', rows[source - 1][1]):
                    raise EvidenceError(f'jmp at {rows[source][0]:#x} follows no conditional branch')
                guards.append((source - 1, False))
            else:
                guards.append((source, True))
    previous = rows[entry - 1][1]
    if previous.startswith('j') and not previous.startswith('jmp'):
        guards.append((entry - 1, False))
    return sorted(set(guards))


def flag_setter(rows, targets, guard):
    """Nearest add, sub or cmp before the branch, with nothing else writing flags between."""
    for k in range(guard - 1, max(0, guard - 14), -1):
        name = rows[k][1].split()[0]
        if name in ('add', 'sub', 'cmp'):
            for between in range(k + 1, guard + 1):
                if rows[between][0] in targets:
                    raise EvidenceError(f'label between {rows[k][0]:#x} and {rows[guard][0]:#x}')
            return k
        if name.startswith('j') or name in ('call', 'ret') or name in FLAG_WRITERS:
            break
    raise EvidenceError(f'no flag setter before {rows[guard][0]:#x}')


def back_start(rows, setter):
    """First row of the straight run that holds copies of the operands."""
    k = setter
    while k > 0 and setter - k < BACK_LIMIT:
        if rows[k - 1][1].startswith(('jmp', 'ret', 'ud2', 'call', 'int3')):
            break
        k -= 1
    return k


def shared_sum_partner(rows, lea, operand):
    """For `cmp sum,y`: the other input when the cold block recomputes sum as an add with y."""
    for k in range(lea + 1, min(lea + 10, len(rows))):
        match = re.fullmatch(r'add (r\w+),(r\w+)', rows[k][1])
        if match and operand in match.groups():
            return match.group(2) if match.group(1) == operand else match.group(1)
        if rows[k][1].startswith(('jmp', 'ret')) or re.match(r'j[a-z]+ ', rows[k][1]):
            return None
    return None


def classify(rows, setter, branch, taken, lea):
    """Return (kind, form, left operand, right operand, sum operand) from the guard's flags."""
    name, rest = rows[setter][1].split(' ', 1)
    first, second = split_operands(rest)
    code = rows[branch][1].split()[0][1:]
    if second.startswith('0x'):
        raise EvidenceError(f'immediate operand at {rows[setter][0]:#x}')
    if code not in NEGATE:
        raise EvidenceError(f'branch {rows[branch][1]} at {rows[branch][0]:#x} does not read carry')
    condition = code if taken else NEGATE[code]
    if name == 'add' and condition == 'b':
        return 'add', 'add-carry', first, second, None
    if name in ('sub', 'cmp') and condition == 'b':
        if name == 'cmp':
            partner = shared_sum_partner(rows, lea, second)
            if partner:
                return 'add', 'cmp-shared-sum', partner, second, first
        return 'sub', f'{name}-borrow', first, second, None
    if name in ('sub', 'cmp') and condition == 'a':
        return 'sub', f'{name}-swapped', second, first, None
    raise EvidenceError(f'unclassified guard {rows[setter][1]} / {rows[branch][1]} at {rows[branch][0]:#x}')


def saturate(kind, left, right):
    if kind == 'add':
        return min(left + right, MASK)
    return max(left - right, 0)


def overflows(kind, left, right):
    return left + right > MASK if kind == 'add' else left < right


def partners(kind, left, right, keep):
    """Return the non-overflowing pair with the saturated result, and pairs with other results.

    One operand stays the same in all of them, so only the result and the other operand move.
    Later code can compare the result with an input, so `keep` picks which input stays.
    """
    if keep == 'smaller':
        keep = 'right' if right <= left else 'left'
    if kind == 'sub' and keep == 'right':
        others = [((right + other, right), other) for other in OTHER_RESULTS if right + other <= MASK]
        return (right, right), others
    if kind == 'sub':
        others = [((left, left - other), other) for other in OTHER_RESULTS if other <= left]
        return (left, left), others
    if keep == 'right':
        others = [((MASK - other - right, right), MASK - other) for other in OTHER_RESULTS if other + right <= MASK]
        return (MASK - right, right), others
    others = [((left, MASK - other - left), MASK - other) for other in OTHER_RESULTS if other + left <= MASK]
    return (left, MASK - left), others


def probe_vector(kind):
    """A result far from the saturated one, for a result that only decides a branch."""
    return (MASK, 0) if kind == 'sub' else (0, 0)


class Runner:
    """Runs one guard of one site on vectors."""

    def __init__(self, listing, guard):
        self.rows, self.index, self.reg_calls = listing['rows'], listing['index'], listing['reg_calls']
        self.guard = guard
        self.start = back_start(self.rows, guard['setter'])

    def prepared(self, seed, left, right):
        machine = Machine(self.rows, self.index, self.reg_calls, seed)
        for k in range(self.start, self.guard['setter']):
            if self.rows[k][1].startswith('j'):
                continue
            try:
                machine.step(k)
            except Halt:
                # The flags of this straight run are unknown, so the result of this row is too.
                machine.write(split_operands(self.rows[k][1].split(' ', 1)[1])[0], machine.havoc())
        operands = [(self.guard['left'], left), (self.guard['right'], right)]
        if self.guard['sum']:
            operands.append((self.guard['sum'], (left + right) & MASK))
        swaps = {}
        for operand, value in operands:
            swaps[machine.read(operand)] = value
        if len(swaps) != len(operands):
            raise EvidenceError(f'operands alias at {self.rows[self.guard["setter"]][0]:#x}')
        for name, value in machine.regs.items():
            machine.regs[name] = swaps.get(value, value)
        for where, value in machine.ram.items():
            machine.ram[where] = swaps.get(value, value)
        return machine

    def run(self, seed, left, right, stop=None):
        """Return (machine, list of addresses after the guard branch, halted-at-stop)."""
        machine = self.prepared(seed, left, right)
        position = self.guard['setter']
        branch = self.rows[self.guard['branch']][0]
        after = None
        try:
            for _ in range(STEP_LIMIT):
                address = self.rows[position][0]
                if after is not None:
                    if address == stop:
                        return machine, after, True
                    after.append(address)
                position = machine.step(position)
                if address == branch:
                    after = []
                    machine.compared = []
        except Halt as halt:
            if str(halt) == 'ret' and after is not None:
                after.pop()
                after.append(RETURNED)
                if stop == RETURNED:
                    return machine, after, True
        return machine, after or [], False

    def join(self, seed, over, same):
        """First address after the recorder on the overflow run that the other run reaches."""
        first, trace_over, _ = self.run(seed, *over)
        second, trace_same, _ = self.run(seed, *same)
        site = self.guard['lea']
        if site not in trace_over:
            raise EvidenceError(f'overflow vector {over} misses the site at {site:#x}: {trace_over[:6]}')
        if site in trace_same:
            raise EvidenceError(f'exact vector {same} enters the site at {site:#x}')
        call = trace_over.index(site)
        reachable = set(trace_same)
        for address in trace_over[call + 1:]:
            if address in reachable:
                return address
        raise EvidenceError(f'site {site:#x}: no common address for {over}')

    def locations(self, machine):
        found = {name: value for name, value in machine.regs.items() if name != 'rsp'}
        found.update(machine.xmm)
        for where, text in machine.stored.items():
            found[text] = machine.ram[where]
        return found

    def attempt(self, keep):
        kind = self.guard['kind']
        common, agreed = None, None
        exact_everywhere = True
        hundredth_everywhere = kind == 'sub'
        branch_only = False
        joins = set()
        runs = 0
        for seed in SEEDS:
            for left, right in OVER_ADD if kind == 'add' else OVER_SUB:
                result = saturate(kind, left, right)
                same_vector, others = partners(kind, left, right, keep)
                join = self.join(seed, (left, right), same_vector)
                joins.add(join)
                over, _, reached = self.run(seed, left, right, stop=join)
                same, _, reached_same = self.run(seed, *same_vector, stop=join)
                runs += 4
                if not reached or not reached_same:
                    raise EvidenceError(f'site {self.guard["lea"]:#x}: join not reached')
                if over.records != same.records + 1:
                    raise EvidenceError(f'site {self.guard["lea"]:#x}: records {over.records}/{same.records}')
                inputs = {left, right, (left + right) & MASK, (left - right) & MASK}
                seen = set(same.compared)
                for pair in over.compared:
                    if pair in seen or set(pair) <= inputs:
                        continue
                    # A reload across the start of the window can differ from a register copy
                    # in the marks only, so the side holding the result still has to match.
                    if not any(pair[side] == result and any(item[side] == result for item in seen) for side in (0, 1)):
                        raise EvidenceError(f'site {self.guard["lea"]:#x}: overflow run alone compares {pair}')
                held = self.locations(over)
                held_same = self.locations(same)
                agree = {name for name, value in held.items() if held_same.get(name) == value}
                agreed = agree if agreed is None else agreed & agree
                moved, exact, hundredth = set(), set(), set()
                measured = False
                diverged = False
                for other_vector, wanted in others:
                    machine, _, hit = self.run(seed, *other_vector, stop=join)
                    runs += 1
                    if not hit:
                        diverged = True
                        continue
                    if machine.records != same.records:
                        continue
                    held_other = self.locations(machine)
                    moved |= {name for name in agree if held_other.get(name) != held[name]}
                    exact |= {name for name in agree if held_other.get(name) == wanted and held[name] == result}
                    if wanted >= 100:
                        measured = True
                        hundredth |= {name for name in agree if held_other.get(name) in (wanted // 100, as_double(wanted // 100))}
                if not others:
                    continue
                if moved:
                    common = moved if common is None else common & moved
                    exact_everywhere = exact_everywhere and bool(exact)
                    if measured:
                        hundredth_everywhere = hundredth_everywhere and bool(hundredth)
                    continue
                if not diverged:
                    _, _, hit = self.run(seed, *probe_vector(kind), stop=join)
                    runs += 1
                    diverged = not hit
                if not diverged:
                    raise EvidenceError(f'site {self.guard["lea"]:#x}: no location follows the result at {join:#x}')
                for name in CALLEE_SAVED:
                    if held[name] != held_same[name] and held[name] not in inputs:
                        raise EvidenceError(f'site {self.guard["lea"]:#x}: {name} differs at {join:#x}')
                branch_only = True
        if common is not None:
            common &= agreed
        if not common and not branch_only:
            raise EvidenceError(f'site {self.guard["lea"]:#x}: no common location across vectors')
        if common and not branch_only:
            form = 'value' if exact_everywhere else 'floor-100' if hundredth_everywhere else 'derived'
        elif common:
            raise EvidenceError(f'site {self.guard["lea"]:#x}: vectors disagree on the result form')
        else:
            form = 'branch'
        return {'joins': sorted(joins), 'locations': sorted(common or ()), 'result_form': form, 'runs': runs,
                'keep': keep}

    def check(self):
        """Return the facts of this guard; raise when no input policy satisfies every vector."""
        failure = None
        for keep in ('smaller', 'left', 'right'):
            try:
                return self.attempt(keep)
            except EvidenceError as error:
                failure = failure or error
        raise failure


def analyse_site(listing, lea):
    rows = listing['rows']
    targets = listing['targets']
    position = listing['index'][lea]
    facts = []
    guards = find_guards(rows, targets, position)
    if not guards:
        raise EvidenceError(f'no guard for site {lea:#x}')
    for branch, taken in guards:
        setter = flag_setter(rows, targets, branch)
        kind, form, left, right, total = classify(rows, setter, branch, taken, position)
        guard = {'lea': lea, 'branch': branch, 'taken': taken, 'setter': setter, 'kind': kind, 'form': form,
                 'left': left, 'right': right, 'sum': total}
        result = Runner(listing, guard).check()
        nearby = ' '.join(row[1] for row in rows[max(0, setter - 3):setter + 1])
        call = next(k for k in range(position, len(rows)) if rows[k][1].startswith('call'))
        result.update({'field_pair': '+0x48]' in nearby and '+0x50]' in nearby,
                       'register_call': rows[call][0] in listing['reg_calls'] and branch == guards[0][0],
                       'lea': lea, 'branch_va': rows[branch][0], 'branch_text': rows[branch][1].split()[0],
                       'setter_va': rows[setter][0], 'setter_text': rows[setter][1], 'kind': kind, 'form': form})
        facts.append(result)
    return facts


def mutation_point(rows, listing, position, kind):
    """Return (row, new text) that damages the saturated value, if the cold path has one.

    The walk follows one unconditional jump, because some sites jump to a shared `xor`.
    """
    k = block_entry(rows, listing['targets'], position)
    followed = False
    for _ in range(COLD_WALK):
        body = rows[k][1]
        if body.startswith('jmp') and not followed:
            k = listing['index'][int(body.split()[1], 16)]
            followed = True
            continue
        if body.startswith(('jmp', 'ret')) or re.match(r'j[a-z]+ ', body):
            break
        if kind == 'add' and re.fullmatch(r'mov \w+,0xffffffffffffffff', body):
            return k, body.replace('0xffffffffffffffff', '0x5')
        match = re.fullmatch(r'(?:xor|xorpd|xorps) (\w+),(\w+)', body)
        if kind == 'sub' and match and match.group(1) == match.group(2) and match.group(1) != 'edi':
            return k, 'nop' if match.group(1).startswith('xmm') else f'mov {match.group(1)},0x5'
        k += 1
    return None


def fails(rows, lea):
    try:
        analyse_site(make_listing(rows), lea)
    except EvidenceError:
        return True
    return False


def mutation_controls(listing, lea, kind):
    """Damage one site twice: drop its recorder call, then change its saturated value."""
    rows = listing['rows']
    position = listing['index'][lea]
    call = next(k for k in range(position, len(rows)) if rows[k][1].startswith('call'))
    damaged = list(rows)
    damaged[call] = (rows[call][0], 'nop', 0)
    controls = [{'lea': lea, 'control': 'drop-recorder', 'row': rows[call][0], 'was': rows[call][1],
                 'now': 'nop', 'caught': fails(damaged, lea)}]
    point = mutation_point(rows, listing, position, kind)
    if point is None:
        controls.append({'lea': lea, 'control': 'value', 'row': 0, 'was': '', 'now': '', 'caught': None})
        return controls
    k, text = point
    damaged = list(rows)
    damaged[k] = (rows[k][0], text, 0)
    controls.append({'lea': lea, 'control': 'value', 'row': rows[k][0], 'was': rows[k][1], 'now': text,
                     'caught': fails(damaged, lea)})
    return controls


def got_references(blob, slot):
    """Rip-relative calls, jumps and loads of one GOT slot in .text."""
    text = blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits = []
    for match in re.finditer(rb'\xff[\x15\x25]|\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        if TEXT_VA + pos + 6 + struct.unpack_from('<i', text, pos + 2)[0] == slot:
            hits.append(TEXT_VA + pos)
    return hits


def rip_references(blob, low, high):
    """Instructions in .text whose rip-relative operand lands in low..high.

    Each disp32 follows a ModRM byte with mod 00 and rm 101.  An immediate of 0, 1 or 4 bytes
    may follow the displacement.
    """
    text = blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits = set()
    for align in range(4):
        words = memoryview(text[align:len(text) - (len(text) - align) % 4]).cast('i')
        first = low - TEXT_VA - align - 8
        last = high - TEXT_VA - align - 4
        for k, disp in enumerate(words):
            if first <= disp + 4 * k < last:
                pos = align + 4 * k
                if pos and text[pos - 1] & 0xc7 == 0x05:
                    if any(low <= TEXT_VA + pos + 4 + tail + disp < high for tail in (0, 1, 4)):
                        hits.add(TEXT_VA + pos)
    return sorted(hits)


def recorder_facts(path, blob, relocs, table, starts):
    rows = disassemble(path, *enclosing(table, starts, RECORDER))
    inner = disassemble(path, *enclosing(table, starts, RECORDER_INNER))
    bodies = [row[1] for row in rows]
    if 'movzx edx,dil' not in bodies or f'call {RECORDER_INNER:x}' not in bodies:
        raise EvidenceError('the recorder does not pass its byte argument to the map insert')
    if 'cmp rdx,0xb' not in [row[1] for row in inner]:
        raise EvidenceError('the map insert has no node capacity test')
    if relocs.get(RECORDER_CLEAR_SLOT) != RECORDER_CLEAR:
        raise EvidenceError(f'clear slot holds {relocs.get(RECORDER_CLEAR_SLOT)}')
    clears = got_references(blob, RECORDER_CLEAR_SLOT)
    if len(clears) != RECORDER_CLEAR_REFERENCES:
        raise EvidenceError(f'{len(clears)} references to the clear slot')
    low, high = RECORDER_GLOBALS
    users = sorted({enclosing(table, starts, va)[0] for va in rip_references(blob, low, high)})
    data = sorted(offset for offset, addend in relocs.items() if low <= addend < high)
    return {'slot': f'{RECORDER_SLOT:#x}', 'target': f'{RECORDER:#x}', 'map_insert': f'{RECORDER_INNER:#x}',
            'map_clear': f'{RECORDER_CLEAR:#x}', 'map_clear_references': [f'{va:#x}' for va in clears],
            'global_range': [f'{low:#x}', f'{high:#x}'], 'functions_using_globals': [f'{va:#x}' for va in users],
            'relocations_into_globals': len(data)}


def make_listing(rows):
    return {'rows': rows, 'index': {row[0]: k for k, row in enumerate(rows)}, 'targets': branch_targets(rows),
            'reg_calls': recorder_registers(rows)}


def analyse(path):
    blob = load_binary(path)
    table = fde_table(blob)
    starts = [item[0] for item in table]
    relocs = relocations(blob)
    location = read_location(blob, relocs, LOCATION)
    if not location[0].endswith(LOCATION_SUFFIX) or location[1:] != (LOCATION_LINE, LOCATION_COLUMN):
        raise EvidenceError(f'unexpected Location {location}')
    if relocs.get(RECORDER_SLOT) != RECORDER:
        raise EvidenceError(f'recorder slot holds {relocs.get(RECORDER_SLOT)}')
    references = lea_references(blob, LOCATION)
    data_references = sorted(offset for offset, addend in relocs.items() if addend == LOCATION)
    all_functions = sorted({enclosing(table, starts, va) for va in references})
    functions = [fn for fn in all_functions if fn[0] not in EXCLUDED_FUNCTIONS]
    left_out = [fn for fn in all_functions if fn[0] in EXCLUDED_FUNCTIONS]
    if len(left_out) != len(EXCLUDED_FUNCTIONS):
        raise EvidenceError(f'{len(left_out)} of {len(EXCLUDED_FUNCTIONS)} excluded functions hold sites')
    excluded = {}
    for fn in left_out:
        held = [va for va in references if fn[0] <= va < fn[1]]
        if len(held) != EXCLUDED_SITES_PER_FUNCTION:
            raise EvidenceError(f'{fn[0]:#x} holds {len(held)} sites')
        excluded[f'{fn[0]:#x}'] = {'site': f'{held[0]:#x}', 'named_by': EXCLUDED_FUNCTIONS[fn[0]]}
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        listings = list(pool.map(lambda fn: make_listing(disassemble(path, fn[0], fn[1])), functions))
    facts, controls = [], []
    for fn, listing in zip(functions, listings):
        for lea in sorted(va for va in references if fn[0] <= va < fn[1]):
            found = analyse_site(listing, lea)
            for item in found:
                item['function'], item['function_end'] = fn
            facts.extend(found)
            controls.extend(mutation_controls(listing, lea, found[0]['kind']))
    if len({item['lea'] for item in facts}) + len(excluded) != len(references):
        raise EvidenceError('sites and references differ')
    counts = {}
    for item in facts:
        key = f'{item["kind"]}/{item["form"]}'
        counts[key] = counts.get(key, 0) + 1
    site_kinds = {}
    for item in facts:
        site_kinds.setdefault(item['lea'], set()).add(item['kind'])
    mixed = sorted(lea for lea, kinds in site_kinds.items() if len(kinds) != 1)
    proof = hundred_proof()
    if not proof['proved']:
        raise EvidenceError('the reciprocal of 100 fails its bound')
    evidence = {
        'target_sha256': SHA256,
        'location': {'va': f'{LOCATION:#x}', 'file': SHOWN_PATH, 'line': LOCATION_LINE, 'column': LOCATION_COLUMN},
        'recorder': recorder_facts(path, blob, relocs, table, starts),
        'fde_count': len(table),
        'location_references': len(references),
        'location_data_references': len(data_references),
        'location_function_count': len(all_functions),
        'excluded_functions': excluded,
        'sites_analysed': len(site_kinds),
        'functions': len(functions),
        'guards': len(facts),
        'guards_by_kind_and_form': dict(sorted(counts.items())),
        'sites_by_kind': {name: sum(1 for kinds in site_kinds.values() if kinds == {name}) for name in ('add', 'sub')},
        'sites_with_both_kinds': [f'{lea:#x}' for lea in mixed],
        'guards_reading_fields_0x48_and_0x50': sum(1 for item in facts if item['field_pair']),
        'sites_calling_through_a_register': sum(1 for item in facts if item['register_call']),
        'guards_by_result_form': {name: sum(1 for item in facts if item['result_form'] == name)
                                  for name in ('value', 'floor-100', 'derived', 'branch')},
        'floor_100_proof': proof,
        'vector_runs': sum(item['runs'] for item in facts),
        'mutation_controls': {
            'drop_recorder_caught': sum(1 for item in controls if item['control'] == 'drop-recorder' and item['caught']),
            'value_caught': sum(1 for item in controls if item['control'] == 'value' and item['caught']),
            'value_survived': sum(1 for item in controls if item['control'] == 'value' and item['caught'] is False),
            'no_value_instruction': sum(1 for item in controls if item['caught'] is None)},
        'reference_messages_in_binary': {text.decode(): blob.count(text) for text in REFERENCE_MESSAGES},
    }
    return evidence, facts, controls


def write_outputs(out, evidence, facts, controls):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    lines = ['function\tfunction_end\tlea\tkind\tform\tbranch\tbranch_op\tsetter\tsetter_text\tjoins\tresult_at_join\tkept_input\tlocations']
    for item in sorted(facts, key=lambda row: (row['lea'], row['branch_va'])):
        joins = ','.join('ret' if join == RETURNED else f'{join:#x}' for join in item['joins'])
        lines.append('\t'.join((f'{item["function"]:#x}', f'{item["function_end"]:#x}', f'{item["lea"]:#x}',
                                item['kind'], item['form'], f'{item["branch_va"]:#x}', item['branch_text'],
                                f'{item["setter_va"]:#x}', item['setter_text'], joins,
                                item['result_form'], item['keep'], ';'.join(item['locations']))))
    (out / 'wei-sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['lea\tcontrol\trow\twas\tnow\tcaught']
    for item in controls:
        caught = 'no-such-instruction' if item['caught'] is None else str(item['caught']).lower()
        lines.append('\t'.join((f'{item["lea"]:#x}', item['control'], f'{item["row"]:#x}', item['was'], item['now'], caught)))
    (out / 'mutation-controls.tsv').write_text('\n'.join(lines) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--out', required=True)
    parser.add_argument('--binary', default=str(ROOT / BINARY))
    args = parser.parse_args(argv)
    write_outputs(args.out, *analyse(args.binary))
    return 0


if __name__ == '__main__':
    sys.exit(main())
