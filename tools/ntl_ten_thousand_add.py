#!/usr/bin/env python3
"""RE-004: the /10000 saturating totals of node #94 (static, no execution).

One Rust Location, l1/src/qtys/impl_ntl.rs:665:1, is passed to an overflow recorder from a
fixed set of sites.  Every site adds a value divided by 10000 to the i64 field at +0x10 or
+0x18 of a record.  The value has one of four shapes:

    signed        i64 x, truncated toward zero: imul m; sar 11; add the sign bit
    neg-signed    i64 x / -10000, truncated:    imul -m; sar 11; add the sign bit
    unsigned      u64 x, floored:               mul m; shr 11
    neg-unsigned  u64 x, floored, then negated: mul m; shr 11; neg

On signed overflow the site calls the recorder, stores the saturated total and goes on.

The tool proves the four divisions for every 64-bit input from the exact integer bound on
the reciprocal m, then runs the real instructions of every site on boundary vectors.  An
objdump listing is interpreted by a small Python evaluator that stops on an unmodelled
mnemonic, an unset register or memory word, or an unknown call.  Nothing from the binary
runs natively.

    python3 tools/ntl_ten_thousand_add.py --out <dir>

writes evidence.json, add-sites.tsv, divide-proof.tsv and helper-runs.tsv.  Only the Python
standard library and objdump are used.
"""

import argparse
import bisect
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
IMAX, IMIN = SIGN - 1, -SIGN

TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1343c80, 0x1342c80, 0x431c430
HDR_VA = 0xbf4670
RELA_OFF, RELA_SIZE = 0x6bc0, 0x1d4e10
DATA_DELTA = 0x2000
RELATIVE = 8

LOCATION = 0x5715ef8
LOCATION_SUFFIX = b'/l1/src/qtys/impl_ntl.rs'
SHOWN_PATH = 'l1/src/qtys/impl_ntl.rs'
LOCATION_LINE, LOCATION_COLUMN = 665, 1
RECORDER_SLOT, RECORDER = 0x5773190, 0x358dcd0
MAGIC, SHIFT, DIVISOR = 0x346dc5d63886594b, 11, 10000
NEGATED_MAGIC = (1 << 64) - MAGIC   # imul by this reads as -MAGIC, so it divides by -10000
OFFSETS = ('0x10', '0x18')
HELPERS = {0x2712a00: (0x1f849b0, 0x740), 0x46f3240: (0x47d7ca0, 0x11c0), 0x46f3330: (0x47d7ca0, 0x740)}

RET_MAGIC = 0x7fff0000
RAM_BASE = 0x7000000
SELF = RAM_BASE + 0x1000
RECORD = RAM_BASE + 0x8000
STACK_TOP = RAM_BASE + 0x4000
STACK_MARK = 0x5a5a5a5a5a5a5a5a   # in site runs, unset memory reads as this xor its address

REG64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
REG32 = dict(zip(('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                  'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'), REG64))
REG8 = dict(zip(('al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'), REG64))
NARROW = ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
          'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w')
CALLER_SAVED = ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11')

SIGNED_X = (0, 1, -1, 9999, -9999, 10000, -10000, 10001, -10001, 19999, -19999, 20000, -20000,
            IMAX, IMIN, IMAX - 1, IMIN + 1, 92233720368547, -92233720368547)
UNSIGNED_X = (0, 1, 9999, 10000, 10001, 19999, 20000, SIGN - 1, SIGN, SIGN + 1, MASK - 1, MASK)
OLD_VALUES = (0, 1, -1, 123456789, -123456789, IMAX, IMIN, IMAX - 1, IMIN + 1)


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    pass


def signed(value):
    value &= MASK
    return value - (1 << 64) if value & SIGN else value


def trunc_div(x, d):
    return -(-x // d) if x < 0 else x // d


def saturating(total, delta):
    return max(IMIN, min(IMAX, total + delta))


def reciprocal_bound(magic, shift, divisor):
    """Return delta = divisor*magic - 2^(64+shift), the exact error of the reciprocal."""
    return divisor * magic - (1 << (64 + shift))


def proves_division(magic, shift, divisor, largest):
    """True when floor(x*magic / 2^(64+shift)) == floor(x/divisor) for all 0 <= x <= largest.

    Write magic/2^(64+shift) = 1/divisor + delta/(divisor * 2^(64+shift)).  With delta > 0 the
    product never falls below x/divisor.  It stays below the next integer when
    x * delta < 2^(64+shift), and the left side is largest at x = largest.  The same strict
    bound gives trunc(-a/divisor) = 1 + floor(-a*magic / 2^(64+shift)) for 1 <= a <= largest.
    """
    delta = reciprocal_bound(magic, shift, divisor)
    return delta > 0 and largest * delta < (1 << (64 + shift))


def division_rows(magic=MAGIC, shift=SHIFT, divisor=DIVISOR):
    delta = reciprocal_bound(magic, shift, divisor)
    rows = []
    for name, largest in (('signed', SIGN), ('neg-signed', SIGN), ('unsigned', MASK), ('neg-unsigned', MASK)):
        product = largest * delta
        rows.append({'shape': name, 'largest_magnitude': largest, 'delta': delta, 'product': product,
                     'limit': 1 << (64 + shift), 'proved': proves_division(magic, shift, divisor, largest)})
    return rows


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
    return table


def enclosing(table, starts, va):
    index = bisect.bisect_right(starts, va) - 1
    if index < 0 or not table[index][0] <= va < table[index][1]:
        raise EvidenceError(f'{va:#x} is outside every FDE')
    return table[index]


def read_location(blob, va):
    relocation = None
    for pos in range(RELA_OFF, RELA_OFF + RELA_SIZE, 24):
        offset, info, addend = struct.unpack_from('<QQq', blob, pos)
        if offset == va and info & 0xffffffff == RELATIVE:
            relocation = addend
            break
    if relocation is None:
        raise EvidenceError(f'no RELATIVE relocation at {va:#x}')
    length, line, column = struct.unpack_from('<QII', blob, va - DATA_DELTA + 8)
    return blob[relocation:relocation + length], line, column


def relative_target(blob, slot):
    for pos in range(RELA_OFF, RELA_OFF + RELA_SIZE, 24):
        offset, info, addend = struct.unpack_from('<QQq', blob, pos)
        if offset == slot and info & 0xffffffff == RELATIVE:
            return addend
    raise EvidenceError(f'no RELATIVE relocation at {slot:#x}')


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


def signed_division_bytes(blob):
    """Byte scan: sar r64,0xb within 24 bytes after a one-operand 64-bit imul."""
    text = blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    imul = re.compile(rb'[\x48\x49][\xf7](?:[\xe8-\xef]|\x6c\x24.)', re.DOTALL)
    hits = []
    for match in re.finditer(rb'[\x48\x49]\xc1[\xf8-\xff]\x0b', text):
        pos = match.start()
        if imul.search(text, max(0, pos - 24), pos):
            hits.append(TEXT_VA + pos)
    return hits


def direct_callers(blob, target):
    text = blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits = []
    for match in re.finditer(rb'\xe8', text):
        pos = match.start()
        if pos + 5 > len(text):
            continue
        if TEXT_VA + pos + 5 + struct.unpack_from('<i', text, pos + 1)[0] == target:
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


def writes_register(body, register):
    parts = body.split(' ', 1)
    if len(parts) < 2:
        return False
    name, operands = parts
    if name.startswith(('cmp', 'test', 'j', 'call', 'push', 'nop', 'xchg')):
        return False
    if name in ('mul', 'imul') and ',' not in operands:
        return register in ('rax', 'rdx')
    first = operands.split(',')[0]
    aliases = {register}
    aliases.update(k for k, v in REG32.items() if v == register)
    aliases.update(k for k, v in REG8.items() if v == register)
    return first in aliases


def magic_is_loaded(rows, index, register):
    """The nearest linear write to register before rows[index] must be movabs of the magic."""
    for k in range(index - 1, -1, -1):
        body = rows[k][1]
        if body.startswith('call') and register in CALLER_SAVED:
            return None
        if writes_register(body, register):
            for magic in (MAGIC, NEGATED_MAGIC):
                if body == f'movabs {register},{magic:#x}':
                    return magic
            return None
    return None


class Machine:
    """Interprets objdump rows for one function; unset state stops the run."""

    def __init__(self, rows, record_slot=RECORDER_SLOT):
        self.rows = rows
        self.index = {row[0]: i for i, row in enumerate(rows)}
        self.record_slot = record_slot
        self.regs = {}
        self.ram = {}
        self.flags = {}
        self.records = 0
        self.lookups = []
        self.lookup_target = None
        self.stop_at = None
        self.marked = False
        self.executed = set()

    def get(self, name):
        if name not in self.regs:
            raise Unmodelled(f'unset register {name}')
        return self.regs[name]

    def address(self, text):
        match = re.fullmatch(r'\[(\w+)(?:([+-])0x([0-9a-f]+))?\]', text)
        if not match:
            raise Unmodelled(f'unmodelled address {text}')
        base = self.get(match.group(1))
        disp = int(match.group(3) or '0', 16)
        return (base + disp if match.group(2) != '-' else base - disp) & MASK

    def read(self, operand):
        if operand in REG64:
            return self.get(operand)
        if operand in REG32:
            return self.get(REG32[operand]) & 0xffffffff
        if operand in REG8:
            return self.get(REG8[operand]) & 0xff
        if operand.startswith('0x'):
            return int(operand, 16)
        if operand.startswith('QWORD PTR '):
            where = self.address(operand[len('QWORD PTR '):])
            if where not in self.ram:
                if not self.marked:
                    raise Unmodelled(f'unset memory {where:#x}')
                self.ram[where] = STACK_MARK ^ where
            return self.ram[where]
        raise Unmodelled(f'unmodelled operand {operand}')

    def write(self, operand, value):
        if operand in REG64:
            self.regs[operand] = value & MASK
        elif operand in REG32:
            self.regs[REG32[operand]] = value & 0xffffffff
        elif operand.startswith('QWORD PTR '):
            where = self.address(operand[len('QWORD PTR '):])
            if not RAM_BASE <= where < RAM_BASE + 0x10000:
                if self.marked:
                    return False
                raise Unmodelled(f'write outside RAM at {where:#x}')
            self.ram[where] = value & MASK
            if where == self.stop_at:
                return True
        else:
            raise Unmodelled(f'unmodelled destination {operand}')
        return False

    def add_flags(self, left, right, result):
        self.flags = {'c': left + right > MASK, 'z': result == 0, 's': bool(result & SIGN),
                      'o': signed(left) + signed(right) != signed(result)}

    def logic_flags(self, result):
        self.flags = {'c': False, 'o': False, 'z': result == 0, 's': bool(result & SIGN)}

    def condition(self, code):
        if code in ('o', 'no'):
            value = self.flags['o']
        elif code in ('e', 'ne'):
            value = self.flags['z']
        elif code in ('s', 'ns'):
            value = self.flags['s']
        else:
            raise Unmodelled(f'unmodelled condition {code}')
        return not value if code.startswith('n') else value

    def call(self, body, row):
        if body.startswith('call QWORD PTR [rip+') and row[2] == self.record_slot:
            if self.get('rsi') != LOCATION or self.get('rdi') & 0xff != 0:
                raise Unmodelled('recorder called with other arguments')
            self.records += 1
        elif re.fullmatch(r'call [0-9a-f]+', body) and int(body.split()[1], 16) == self.lookup_target:
            self.lookups.append((self.get('rdi'), self.get('rsi')))
            self.regs['rax'] = RECORD
            for name in CALLER_SAVED[1:]:
                self.regs.pop(name, None)
            return
        else:
            raise Unmodelled(f'unknown call {body}')
        for name in CALLER_SAVED:
            self.regs.pop(name, None)

    def outside_state(self, name, ops):
        """Site runs skip narrow and vector moves; a site using one misses its expectation."""
        if name in ('movzx', 'movsx', 'movsxd', 'movups', 'movaps', 'movapd', 'movupd', 'movdqa', 'movdqu', 'movsd'):
            return True
        if name != 'mov':
            return False
        return any(op.startswith(('BYTE', 'WORD', 'DWORD', 'xmm')) or op in NARROW for op in ops)

    def run(self, start, limit=400):
        position = self.index[start]
        for _ in range(limit):
            row = self.rows[position]
            body = row[1]
            self.executed.add(row[0])
            position += 1
            parts = body.split(' ', 1)
            name = parts[0]
            ops = re.split(r',(?![^\[]*\])', parts[1]) if len(parts) > 1 else []
            if self.marked and self.outside_state(name, ops):
                continue
            if name in ('mov', 'movabs'):
                if self.write(ops[0], self.read(ops[1])):
                    return
            elif name == 'lea':
                if '[rip' not in ops[1] or not row[2]:
                    if re.fullmatch(r'\[\w+\+\w+\*1\]', ops[1]):
                        raise Unmodelled(f'unmodelled lea {body}')
                    self.write(ops[0], self.address(ops[1]))
                else:
                    self.write(ops[0], row[2])
            elif name in ('mul', 'imul') and len(ops) == 1:
                left, right = self.get('rax'), self.read(ops[0])
                if name == 'imul':
                    product = signed(left) * signed(right)
                else:
                    product = left * right
                self.regs['rax'] = product & MASK
                self.regs['rdx'] = (product >> 64) & MASK
                self.flags = {}
            elif name in ('shr', 'sar'):
                count = int(ops[1], 16)
                value = self.read(ops[0])
                result = value >> count if name == 'shr' else signed(value) >> count
                self.write(ops[0], result)
                self.logic_flags(result & MASK)
            elif name == 'add':
                left, right = self.read(ops[0]), self.read(ops[1])
                result = (left + right) & MASK
                self.add_flags(left, right, result)
                if self.write(ops[0], result):
                    return
            elif name == 'neg':
                value = self.read(ops[0])
                result = -value & MASK
                self.write(ops[0], result)
                self.flags = {'c': value != 0, 'z': result == 0, 's': bool(result & SIGN), 'o': value == SIGN}
            elif name == 'xor':
                result = 0 if ops[0] == ops[1] else self.read(ops[0]) ^ self.read(ops[1])
                self.write(ops[0], result)
                self.logic_flags(result)
            elif name == 'test':
                self.logic_flags(self.read(ops[0]) & self.read(ops[1]))
            elif name.startswith('cmov'):
                if self.condition(name[4:]):
                    self.write(ops[0], self.read(ops[1]))
            elif name == 'jmp':
                position = self.index[int(ops[0], 16)]
            elif name in ('jo', 'jno', 'je', 'jne', 'js', 'jns'):
                if self.condition(name[1:]):
                    position = self.index[int(ops[0], 16)]
            elif name == 'call':
                self.call(body, row)
            elif name == 'push':
                self.regs['rsp'] = self.get('rsp') - 8
                self.ram[self.regs['rsp']] = self.read(ops[0])
            elif name == 'pop':
                self.write(ops[0], self.ram[self.get('rsp')])
                self.regs['rsp'] += 8
            elif name == 'ret':
                value = self.ram[self.get('rsp')]
                if value != RET_MAGIC:
                    raise Unmodelled('return to an unexpected address')
                return
            elif name in ('nop', 'xchg') and (name == 'nop' or body == 'xchg ax,ax'):
                pass
            else:
                raise Unmodelled(f'unmodelled instruction {row[0]:#x}: {body}')
        raise Unmodelled('step limit')


def find_branch(rows, index):
    """Locate the overflow branch that guards the cold block holding rows[index]."""
    targets = {}
    for k, row in enumerate(rows):
        match = re.fullmatch(r'jo ([0-9a-f]+)', row[1])
        if match:
            targets.setdefault(int(match.group(1), 16), k)
    for back in range(14):
        k = index - back
        if k < 0:
            break
        if rows[k][0] in targets:
            return targets[rows[k][0]]
        if rows[k][1].startswith('jno '):
            return k
    raise EvidenceError(f'no overflow branch for {rows[index][0]:#x}')


def delta_chain(rows, multiply, add_index, delta):
    """The addend must derive from the multiply's high word and stay unwritten up to the add."""
    derived = {'rdx'}
    defined = False
    for k in range(multiply + 1, add_index):
        body = rows[k][1]
        if body.startswith('call') and delta in CALLER_SAVED:
            raise EvidenceError(f'delta {delta} crosses a call before {rows[add_index][0]:#x}')
        copy = re.fullmatch(r'mov (r\w+),(r\w+)', body)
        if copy and copy.group(2) in derived:
            derived.add(copy.group(1))
            defined = defined or copy.group(1) == delta
            continue
        chain = re.fullmatch(rf'(?:shr|sar) (r\w+),0x(?:b|3f)|add {delta},rax|neg {delta}', body)
        if chain:
            defined = True if writes_register(body, delta) else defined
            continue
        if writes_register(body, delta):
            raise EvidenceError(f'delta {delta} is rewritten at {rows[k][0]:#x}')
        derived = {name for name in derived if not writes_register(body, name)}
    if not defined or delta not in derived:
        raise EvidenceError(f'delta {delta} is not defined after {rows[multiply][0]:#x}')


def describe_site(rows, lea_index):
    """Return the static description of one recorder site, or raise."""
    branch = find_branch(rows, lea_index)
    add_index = None
    for k in range(branch - 1, max(0, branch - 6), -1):
        match = re.fullmatch(r'add (r\w+),(r\w+)', rows[k][1])
        if match:
            add_index, delta = k, match.group(2)
            break
    if add_index is None:
        raise EvidenceError(f'no add before {rows[branch][0]:#x}')
    load_index = None
    for k in range(add_index - 1, max(0, add_index - 8), -1):
        match = re.fullmatch(r'mov (r\w+),QWORD PTR \[(r\w+)\+(0x[0-9a-f]+)\]', rows[k][1])
        if match:
            load_index, base, offset = k, match.group(2), match.group(3)
            break
    if load_index is None or offset not in OFFSETS:
        raise EvidenceError(f'no record load before {rows[add_index][0]:#x}')
    negated, multiply, reused = False, None, False
    for k in range(add_index - 1, max(0, add_index - 48), -1):
        body = rows[k][1]
        if body == f'neg {delta}':
            negated = True
        if re.fullmatch(r'jo [0-9a-f]+|jno [0-9a-f]+', body):
            reused = True
        if re.fullmatch(r'(?:i?mul) r\w+', body):
            multiply = k
            break
    if multiply is None:
        raise EvidenceError(f'no multiply before {rows[add_index][0]:#x}')
    delta_chain(rows, multiply, add_index, delta)
    operand = rows[multiply][1].split()[1]
    magic = magic_is_loaded(rows, multiply, operand)
    if magic is None:
        raise EvidenceError(f'multiply at {rows[multiply][0]:#x} does not use the reciprocal')
    if rows[multiply][1].startswith('imul'):
        kind = 'signed' if magic == MAGIC else 'neg-signed'
    elif magic == MAGIC:
        kind = 'neg-unsigned' if negated else 'unsigned'
    else:
        raise EvidenceError(f'unsigned multiply at {rows[multiply][0]:#x} uses the negated reciprocal')
    return {'lea': rows[lea_index][0], 'branch': rows[branch][0], 'branch_op': rows[branch][1].split()[0],
            'add': rows[add_index][0], 'load': rows[load_index][0], 'multiply': rows[multiply][0],
            'multiplier': operand, 'magic': magic, 'base': base, 'offset': offset, 'delta': delta, 'kind': kind, 'reused': reused}


def expected_delta(kind, x):
    if kind == 'signed':
        return trunc_div(x, DIVISOR)
    if kind == 'neg-signed':
        return trunc_div(-x, DIVISOR)
    if kind == 'unsigned':
        return x // DIVISOR
    return -(x // DIVISOR)


def run_site(rows, site, x, old):
    """Run real instructions up to the store at record+offset; return (stored, records)."""
    machine = Machine(rows)
    target = RECORD + int(site['offset'], 16)
    delta = expected_delta(site['kind'], x)
    for offset in OFFSETS:
        machine.ram[RECORD + int(offset, 16)] = 0
    machine.ram[target] = old & MASK
    # Other registers hold marks, so a site that depends on one disagrees with the expectation.
    for number, name in enumerate(REG64):
        machine.regs[name] = STACK_MARK ^ number
    machine.regs['rsp'] = STACK_TOP
    machine.marked = True
    machine.regs[site['base']] = RECORD
    machine.stop_at = target
    if site['reused']:
        machine.regs[site['delta']] = delta & MASK
        machine.run(site['load'])
    else:
        machine.regs['rax'] = x & MASK
        machine.regs[site['multiplier']] = site['magic']
        machine.run(site['multiply'])
    return signed(machine.ram[target]), machine.records


def site_vectors(kind):
    return SIGNED_X if kind in ('signed', 'neg-signed') else UNSIGNED_X


def check_site(rows, site):
    """Return the run count; raise on the first mismatch."""
    runs = 0
    for x in site_vectors(site['kind']):
        delta = expected_delta(site['kind'], x)
        for old in OLD_VALUES:
            stored, records = run_site(rows, site, x, old)
            want = saturating(old, delta)
            overflow = not IMIN <= old + delta <= IMAX
            if stored != want or records != int(overflow):
                raise EvidenceError(f'site {site["lea"]:#x}: x={x} old={old} gave {stored}/{records}, '
                                    f'want {want}/{int(overflow)}')
            runs += 1
    return runs


def run_helper(rows, start, first, second, has_second, old_a, old_b):
    machine = Machine(rows)
    machine.lookup_target = HELPERS[start][0]
    machine.regs.update({'rsp': STACK_TOP, 'rdi': SELF, 'rsi': 0x1234, 'rdx': first & MASK, 'rcx': has_second,
                         'r8': second & MASK, 'rax': 7, 'rbx': 1, 'rbp': 2, 'r12': 3, 'r13': 4, 'r14': 5, 'r15': 6})
    machine.ram[STACK_TOP] = RET_MAGIC
    machine.ram[RECORD + 0x10] = old_a & MASK
    machine.ram[RECORD + 0x18] = old_b & MASK
    machine.run(start)
    return {'first_total': signed(machine.ram[RECORD + 0x10]), 'second_total': signed(machine.ram[RECORD + 0x18]),
            'records': machine.records, 'lookup': machine.lookups, 'seen': machine.executed}


def helper_vectors():
    values = (0, 9999, -9999, 10000, -10000, 123456789, -123456789, IMAX, IMIN)
    olds = ((0, 0), (5, -5), (IMAX, IMIN), (IMIN, IMAX))
    for first in values:
        for second in values:
            for has_second in (0, 1):
                for old_a, old_b in olds:
                    yield first, second, has_second, old_a, old_b


def check_helper(rows, start):
    results = []
    seen = set()
    for first, second, has_second, old_a, old_b in helper_vectors():
        got = run_helper(rows, start, first, second, has_second, old_a, old_b)
        seen |= got['seen']
        used = second if has_second else first
        delta_a, delta_b = trunc_div(first, DIVISOR), trunc_div(used, DIVISOR)
        want_a, want_b = saturating(old_a, delta_a), saturating(old_b, delta_b)
        records = int(not IMIN <= old_a + delta_a <= IMAX) + int(not IMIN <= old_b + delta_b <= IMAX)
        if (got['first_total'], got['second_total'], got['records']) != (want_a, want_b, records):
            raise EvidenceError(f'helper {start:#x}: {first} {second} {has_second} {old_a} {old_b} gave {got}')
        if got['lookup'] != [(SELF + HELPERS[start][1], 0x1234)]:
            raise EvidenceError(f'helper {start:#x}: lookup arguments {got["lookup"]}')
        results.append((first, second, has_second, old_a, old_b, want_a, want_b, records))
    return results, seen


def analyse(path):
    blob = load_binary(path)
    table = fde_table(blob)
    starts = [item[0] for item in table]
    location = read_location(blob, LOCATION)
    if not location[0].endswith(LOCATION_SUFFIX) or location[1:] != (LOCATION_LINE, LOCATION_COLUMN):
        raise EvidenceError(f'unexpected Location {location}')
    recorder = relative_target(blob, RECORDER_SLOT)
    if recorder != RECORDER:
        raise EvidenceError(f'recorder slot holds {recorder:#x}')
    references = lea_references(blob, LOCATION)
    functions = sorted({enclosing(table, starts, va) for va in references})
    listings = {fn: disassemble(path, fn[0], fn[1]) for fn in functions}
    sites = []
    runs = 0
    for fn, rows in listings.items():
        for k, row in enumerate(rows):
            if row[2] != LOCATION:
                continue
            site = describe_site(rows, k)
            site['function'], site['function_end'] = fn
            runs += check_site(rows, site)
            sites.append(site)
    if sorted(site['lea'] for site in sites) != sorted(references):
        raise EvidenceError('byte references and listing references differ')
    signed_bytes = signed_division_bytes(blob)
    outside = sorted(va for va in signed_bytes if enclosing(table, starts, va) not in listings)
    signed_multiplies = {site['multiply'] for site in sites if site['kind'] in ('signed', 'neg-signed')}
    if len(signed_multiplies) != len(signed_bytes):
        raise EvidenceError(f'{len(signed_multiplies)} signed multiplies, {len(signed_bytes)} byte hits')
    helper_rows = []
    helper_runs = 0
    callers = {}
    for start in HELPERS:
        rows = disassemble(path, *enclosing(table, starts, start))
        results, seen = check_helper(rows, start)
        helper_runs += len(results)
        helper_rows.extend((start,) + item for item in results)
        hits = direct_callers(blob, start)
        callers[f'{start:#x}'] = {'calls': len(hits), 'instructions': len(rows), 'instructions_run': len(seen),
                                  'functions': sorted({f'{enclosing(table, starts, va)[0]:#x}' for va in hits})}
    proof = division_rows()
    if not all(row['proved'] for row in proof):
        raise EvidenceError('reciprocal bound failed')
    counts = {}
    for site in sites:
        key = f'{site["kind"]}/{site["offset"]}'
        counts[key] = counts.get(key, 0) + 1
    evidence = {
        'target_sha256': SHA256,
        'location': {'va': f'{LOCATION:#x}', 'file': SHOWN_PATH, 'line': LOCATION_LINE, 'column': LOCATION_COLUMN},
        'recorder': {'slot': f'{RECORDER_SLOT:#x}', 'target': f'{recorder:#x}'},
        'reciprocal': {'magic': f'{MAGIC:#x}', 'shift': SHIFT, 'divisor': DIVISOR,
                       'delta': reciprocal_bound(MAGIC, SHIFT, DIVISOR)},
        'fde_count': len(table),
        'location_references': len(references),
        'functions': len(functions),
        'sites_by_shape_and_offset': dict(sorted(counts.items())),
        'reused_delta_sites': sum(1 for site in sites if site['reused']),
        'cold_branch_forms': {name: sum(1 for site in sites if site['branch_op'] == name) for name in ('jno', 'jo')},
        'distinct_multiplies': {name: len({site['multiply'] for site in sites if site['kind'] == name})
                                for name in ('signed', 'neg-signed', 'unsigned', 'neg-unsigned')},
        'multiplies_used_by_both_signs': len({site['multiply'] for site in sites if site['kind'] == 'unsigned'}
                                             & {site['multiply'] for site in sites if site['kind'] == 'neg-unsigned'}),
        'signed_division_byte_hits': len(signed_bytes),
        'signed_division_hits_outside_family': [f'{va:#x}' for va in outside],
        'site_runs': runs,
        'helper_runs': helper_runs,
        'helpers': callers,
    }
    return evidence, sites, proof, helper_rows


def write_outputs(out, evidence, sites, proof, helper_rows):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    lines = ['function\tfunction_end\tlea\tbranch\tbranch_op\tadd\tmultiply\tkind\toffset\treused_delta']
    for site in sorted(sites, key=lambda item: item['lea']):
        lines.append('\t'.join((f'{site["function"]:#x}', f'{site["function_end"]:#x}', f'{site["lea"]:#x}',
                                f'{site["branch"]:#x}', site['branch_op'], f'{site["add"]:#x}',
                                f'{site["multiply"]:#x}', site['kind'], site['offset'], str(site['reused']).lower())))
    (out / 'add-sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['shape\tlargest_magnitude\tdelta\tproduct\tlimit\tproved']
    for row in proof:
        lines.append('\t'.join(str(row[key]).lower() for key in
                               ('shape', 'largest_magnitude', 'delta', 'product', 'limit', 'proved')))
    (out / 'divide-proof.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['helper\tfirst\tsecond\thas_second\told_first\told_second\tnew_first\tnew_second\trecords']
    for row in helper_rows:
        lines.append('\t'.join((f'{row[0]:#x}',) + tuple(str(item) for item in row[1:])))
    (out / 'helper-runs.tsv').write_text('\n'.join(lines) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--out', required=True)
    parser.add_argument('--binary', default=str(ROOT / BINARY))
    args = parser.parse_args(argv)
    write_outputs(args.out, *analyse(args.binary))
    return 0


if __name__ == '__main__':
    sys.exit(main())
