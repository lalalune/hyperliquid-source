#!/usr/bin/env python3
"""RE-004: the two u64 constants 0x68db8bac710cb and 0x68db8bac710cc in node #94 (static).

floor((2^64-1) / 10000) is 0x68db8bac710cb.  The tool finds every copy of it and of the next
integer in the ELF file bytes.  Each copy in .text has to be a movabs immediate, and each site
is read from bytes:

    divisible-by-10000   (y * 0xd288ce703afb7e91) ror 4 <= cap, which holds exactly when
                         10000 divides y, for all u64 y (divisibility_lemma)
    cmov-zero            x <= cap ? x * 100 : 0
    branch               x <= cap reaches x * 100, the other edge leaves that path

The rows are symbolic: registers and memory start free, so the reads hold for every input and
no input is sampled.  A branch site follows both edges through calls; a call clobbers the
caller-saved registers.  Functions named by other work items or open pull requests are listed
and left out, and three more functions are listed as not read here.

    python3 tools/perp_spot_scale_gate.py --out <dir>

writes evidence.json, sites.tsv, excluded-sites.tsv, mutation-controls.tsv and message-sites.tsv.
Only the Python standard library is used; objdump is not.  Nothing from the binary runs.
"""

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1
CAP = 0x68db8bac710cb
ROUND_BOUND = CAP + 1
INVERSE_625 = 0xd288ce703afb7e91
ROTATE = 4
SCALE = 100
MESSAGE = b'could not convert perp usdc to spot'
LABELS = (b'periodic', b'freeze')
DISPLAY_TABLE = 0x59a8d0
DISPLAY_ARM = bytes.fromhex('488b3e488b4608488b4018488d35')[:14]

# Functions named by other work items or open pull requests.
EXCLUDED_FUNCTIONS = {
    0x24f7bd0: 'RE-004-decimal-scaled-u64-94 (open #94), RE-010-exchange-handlers',
    0x2711a80: 'RE-004-ntl-ten-thousand-add-94 (open #38)',
    0x2716f90: 'RE-004-ntl-ten-thousand-add-94 (open #38)',
    0x27240b0: 'RE-004-wei-buffered-cap-94, RE-004-wei-saturating-ops-94 (open #46)',
    0x274fd60: 'RE-004-decimal-scaled-u64-94 (open #94)',
    0x3736bd0: 'RE-004-wei-saturating-ops-94 (open #46)',
    0x4d03ce0: 'RE-004-ntl-ten-thousand-add-94 (open #38)',
    0x4d0dff0: 'RE-004-ntl-ten-thousand-add-94 (open #38)',
    0x4d0e820: 'RE-004-ntl-ten-thousand-add-94 (open #38)',
    0x4d29720: 'RE-004-wei-buffered-cap-94, RE-004-wei-saturating-ops-94 (open #46)',
    0x4d29bf0: 'RE-004-wei-buffered-cap-94, RE-004-wei-saturating-ops-94 (open #46)',
    0x4d72a80: 'RE-004-decimal-scaled-u64-94 (open #94)',
    0x4d73550: 'RE-004-decimal-scaled-u64-94 (open #94)'}

# Left for a separate question: only the site row is listed, nothing in them is read here.
NOT_READ_FUNCTIONS = {
    0x333a420: 'not read in this packet',
    0x4adf630: 'not read in this packet',
    0x4adfe30: 'not read in this packet'}

PERIODIC_SITES = (0x220bf11, 0x42e7411, 0x42e79c1)
GATE_WINDOW = 5
WALK_LIMIT = 6000
RSP, RAX, RCX, RDX, RSI, RDI = 4, 0, 1, 2, 6, 7
CALLER_SAVED = (0, 1, 2, 6, 7, 8, 9, 10, 11)
REG_NAMES = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')


class EvidenceError(Exception):
    pass


class Unsupported(Exception):
    """The instruction is outside the modelled subset, so the path ends here."""


def fail(message):
    raise EvidenceError(message)


# --- ELF image, from the shared repository parsers ------------------------------------------

class Image:
    def __init__(self, data, fdes=None):
        self.data = data
        table = elf_index.sections(data)
        self.sections = [s for s in table if s['type'] != 8 and s['address']]
        self.text = next(s for s in self.sections if s['name'] == '.text')
        if fdes is None:
            _, records = fde_extents.eh_frame_records(data, table)
            fdes = sorted((r['start'], r['end']) for r in records)
        self.fdes = fdes
        self.starts = [row[0] for row in fdes]

    def patched(self, edits):
        """A copy with bytes replaced, for the negative controls."""
        blob = bytearray(self.data)
        for va, raw in edits:
            off = self.file_offset(va)
            blob[off:off + len(raw)] = raw
        return Image(bytes(blob), self.fdes)

    def file_offset(self, va):
        for s in self.sections:
            if s['address'] <= va < s['address'] + s['size']:
                return va - s['address'] + s['offset']
        fail(f'address {va:#x} is outside every section with file bytes')

    def fde_of(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            fail(f'{va:#x} is outside every FDE')
        return self.fdes[i]


# --- x86-64 length decoder ------------------------------------------------------------------

def modrm_length(data, p):
    modrm = data[p]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if mod == 3:
        return length
    if rm == 4:
        length += 1
        if mod == 0 and data[p + 1] & 7 == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length


MODRM_ONE = (set(range(0x00, 0x04)) | set(range(0x08, 0x0c)) | set(range(0x10, 0x14)) | set(range(0x18, 0x1c))
             | set(range(0x20, 0x24)) | set(range(0x28, 0x2c)) | set(range(0x30, 0x34)) | set(range(0x38, 0x3c))
             | set(range(0x84, 0x90)) | set(range(0xd8, 0xe0)) | {0x63, 0xd0, 0xd1, 0xd2, 0xd3, 0xfe, 0xff})
PLAIN_ONE = (set(range(0x50, 0x60)) | set(range(0x90, 0xa0))
             | {0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xc3, 0xc9, 0xcb, 0xcc, 0xcf,
                0xf4, 0xf5, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd})
PLAIN_TWO = {0x05, 0x06, 0x08, 0x09, 0x0b, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x77, 0xa0, 0xa1, 0xa2, 0xa8,
             0xa9, 0xaa} | set(range(0xc8, 0xd0))
PREFIXES = {0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0xf0}


class Insn:
    """One decoded instruction: position, opcode key, REX byte and ModRM offset."""

    __slots__ = ('va', 'off', 'size', 'key', 'rex', 'modrm', 'target', 'body')

    def __init__(self, va, off, size, key, rex, modrm, target, body):
        self.va, self.off, self.size, self.key = va, off, size, key
        self.rex, self.modrm, self.target, self.body = rex, modrm, target, body


def decode(data, off, va):
    """Decode the length of one 64-bit instruction, or raise on an unknown form."""
    p = off
    wide16 = False
    while data[p] in PREFIXES:
        wide16 = wide16 or data[p] == 0x66
        p += 1
    rex = 0
    if 0x40 <= data[p] <= 0x4f:
        rex = data[p]
        p += 1
    body = p
    op = data[p]
    p += 1
    iz = 2 if wide16 else 4

    def done(end, key, modrm=None, rel=None):
        size = end - off
        target = None if rel is None else va + size + rel
        return Insn(va, off, size, key, rex, modrm, target, body)

    if op in (0xc4, 0xc5, 0x62):
        if op == 0xc5:
            space = 1
            p += 1
        elif op == 0xc4:
            space = data[p] & 0x1f
            p += 2
        else:
            space = data[p] & 7
            p += 3
        code = data[p]
        p += 1
        if space == 1 and code == 0x77:
            return done(p, ('vex', code))
        p += modrm_length(data, p)
        if space == 3 or (space == 1 and code in (0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6)):
            p += 1
        return done(p, ('vex', code))
    if op == 0x0f:
        two = data[p]
        p += 1
        if two in (0x38, 0x3a):
            three = data[p]
            p += 1
            modrm = p
            p += modrm_length(data, p) + (1 if two == 0x3a else 0)
            return done(p, (0x0f, two, three), modrm)
        if 0x80 <= two <= 0x8f:
            return done(p + 4, (0x0f, two), rel=struct.unpack_from('<i', data, p)[0])
        if two in PLAIN_TWO:
            return done(p, (0x0f, two))
        modrm = p
        p += modrm_length(data, p)
        if two in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            p += 1
        return done(p, (0x0f, two), modrm)
    if op in MODRM_ONE:
        modrm = p
        return done(p + modrm_length(data, p), op, modrm)
    if op in (0x69, 0x81, 0xc7):
        modrm = p
        return done(p + modrm_length(data, p) + iz, op, modrm)
    if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6):
        modrm = p
        return done(p + modrm_length(data, p) + 1, op, modrm)
    if op in (0xf6, 0xf7):
        modrm = p
        imm = 0
        if (data[p] >> 3) & 7 in (0, 1):
            imm = 1 if op == 0xf6 else iz
        return done(p + modrm_length(data, p) + imm, op, modrm)
    if (op < 0x40 and op & 7 == 4) or op in (0xa8, 0x6a, 0xcd) or 0xb0 <= op <= 0xb7:
        return done(p + 1, op)
    if (op < 0x40 and op & 7 == 5) or op in (0xa9, 0x68):
        return done(p + iz, op)
    if op in PLAIN_ONE:
        return done(p, op)
    if 0xb8 <= op <= 0xbf:
        return done(p + (8 if rex & 8 else iz), op)
    if 0x70 <= op <= 0x7f or op in (0xeb, 0xe0, 0xe1, 0xe2, 0xe3):
        return done(p + 1, op, rel=struct.unpack_from('<b', data, p)[0])
    if op in (0xe8, 0xe9):
        return done(p + 4, op, rel=struct.unpack_from('<i', data, p)[0])
    if op == 0xc2:
        return done(p + 2, op)
    if op in (0xa0, 0xa1, 0xa2, 0xa3):
        return done(p + 8, op)
    fail(f'unknown opcode {op:#x} at {va:#x}')


def sweep(image, start, end):
    """Linear sweep of one FDE range; it must stop exactly on the FDE end."""
    rows = []
    va = start
    delta = image.text['offset'] - image.text['address']
    while va < end:
        insn = decode(image.data, va + delta, va)
        rows.append(insn)
        va += insn.size
    if va != end:
        fail(f'sweep of {start:#x} ended at {va:#x}, FDE ends at {end:#x}')
    return rows


# --- symbolic values ------------------------------------------------------------------------
#
# A value is (terms, constant): a sum of (atom, coefficient) pairs plus a constant, mod 2^64.
# Atoms are tuples compared structurally, so one pure function of equal inputs is one atom.

def konst(value):
    return ((), value & U64)


def atom(*parts):
    return (((parts, 1),), 0)


def is_const(value):
    return not value[0]


def order(pair):
    return repr(pair[0])


def linear(left, right, sign):
    terms = dict(left[0])
    for key, coefficient in right[0]:
        total = (terms.get(key, 0) + sign * coefficient) & U64
        if total:
            terms[key] = total
        else:
            terms.pop(key, None)
    return tuple(sorted(terms.items(), key=order)), (left[1] + sign * right[1]) & U64


def add(left, right):
    return linear(left, right, 1)


def sub(left, right):
    return linear(left, right, -1)


def scaled(value, factor):
    return tuple(sorted(((k, (c * factor) & U64) for k, c in value[0] if (c * factor) & U64), key=order)), (value[1] * factor) & U64


def pure(name, *args):
    return atom('f', name, *args)


def ordered(left, right):
    return (left, right) if repr(left) <= repr(right) else (right, left)


def xor(left, right):
    if left == right:
        return konst(0)
    if is_const(left) and is_const(right):
        return konst(left[1] ^ right[1])
    return pure('xor', *ordered(left, right))


def low(value, bits):
    if bits == 64:
        return value
    if is_const(value):
        return konst(value[1] & ((1 << bits) - 1))
    head = value[0][0][0]
    if len(value[0]) == 1 and value[1] == 0 and value[0][0][1] == 1:
        if head[:2] == ('f', 'setlow') and bits == 8:
            return head[3]
        if head[:2] == ('f', f'low{bits}') or head[0] == 'ns':
            return value
        if head[:2] == ('f', 'partial') and head[3] == bits:
            return head[4]
    return pure(f'low{bits}', value)


def is_value(item):
    return isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], tuple) and isinstance(item[1], int)


def show(item):
    if is_value(item):
        return render(item)
    if isinstance(item, tuple):
        return '(' + ','.join(show(x) for x in item) + ')'
    return str(item)


def render(value):
    def name(key):
        if key[0] == 'r':
            return REG_NAMES[key[1]]
        if key[0] == 'm':
            return f'[{render(key[1])}]'
        if key[0] == 'h':
            return f'clobbered:{REG_NAMES[key[1]]}'
        if key[0] == 'ns':
            return f'ns({render(key[1])})'
        return key[1] + '(' + ','.join(show(x) for x in key[2:]) + ')'
    parts = []
    for key, coefficient in value[0]:
        if coefficient == 1:
            parts.append('+' + name(key))
        elif coefficient == U64:
            parts.append('-' + name(key))
        else:
            parts.append(f'+{coefficient:#x}*{name(key)}')
    if value[1] or not parts:
        parts.append(f'+{value[1]:#x}')
    return ''.join(parts).lstrip('+')


# --- symbolic machine -----------------------------------------------------------------------

class State:
    def __init__(self):
        self.regs = [atom('r', n) for n in range(16)]
        self.xmm = {}
        self.mem = {}
        self.flags = None
        self.assume = {}
        self.pc = 0

    def clone(self):
        other = State.__new__(State)
        other.regs = list(self.regs)
        other.xmm = dict(self.xmm)
        other.mem = dict(self.mem)
        other.flags = self.flags
        other.assume = dict(self.assume)
        other.pc = self.pc
        return other

    def load(self, key, size):
        slot = self.mem.get(key)
        if slot is None:
            return atom('m', key, size)
        if slot[0] == size:
            return slot[1]
        return pure('part', slot[1], size)

    def peek(self, key):
        slot = self.mem.get(key)
        return slot[1] if slot else atom('m', key, 8)


def carry_key(op, left, right):
    if op == 'add':
        return ('CF', 'add', *ordered(left, right))
    if right[0]:
        terms = dict(left[0])
        if all(terms.get(k) == c for k, c in right[0]):
            # left < right exactly when (left - right) + right overflows, for all 64-bit values.
            return carry_key('add', sub(left, right), right)
    return ('CF', 'sub', left, right)


def predicate(flags, cc):
    """Return (key, polarity): the condition holds exactly when key has that truth value."""
    if flags is None:
        raise Unsupported('condition on unknown flags')
    base, negated = cc >> 1, bool(cc & 1)
    polarity = not negated
    if flags[0] == 'a':
        op, left, right = flags[1:]
        result = add(left, right) if op == 'add' else sub(left, right)
        if base == 0:
            pair = ordered(left, right) if op == 'add' else (left, right)
            return ('OF', op, *pair), polarity
        if base == 1:
            return carry_key(op, left, right), polarity
        if base == 2:
            return ('Z', result), polarity
        if base == 3 and op == 'sub':
            return carry_key('sub', right, left), negated
        if base == 4:
            return ('S', result), polarity
    elif flags[0] == 'l':
        value = flags[1]
        if base in (0, 1):
            return ('FALSE',), polarity
        if base in (2, 3):
            return ('Z', value), polarity
        if base == 4:
            return ('S', value), polarity
    return ('cc', base, flags), polarity


def settled(state, key):
    """Truth of a key when it is known on this path, else None."""
    if key in state.assume:
        return state.assume[key]
    if key[0] == 'FALSE':
        return False
    if key[0] == 'Z' and is_const(key[1]):
        return key[1][1] == 0
    if key[0] == 'S' and is_const(key[1]):
        return bool(key[1][1] >> 63)
    return None


def operand(data, p, rex):
    """Decode ModRM at p: ('r', n), ('rip', disp) or ('m', base, index, scale, disp)."""
    modrm = data[p]
    p += 1
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | ((rex & 4) << 1), modrm & 7
    if mod == 3:
        return ('r', rm | ((rex & 1) << 3)), reg
    base, index, scale = None, None, 1
    if rm == 4:
        sib = data[p]
        p += 1
        scale = 1 << (sib >> 6)
        code = ((sib >> 3) & 7) | ((rex & 2) << 2)
        index = None if code == 4 else code
        if sib & 7 == 5 and mod == 0:
            return ('m', None, index, scale, struct.unpack_from('<i', data, p)[0]), reg
        base = (sib & 7) | ((rex & 1) << 3)
    elif mod == 0 and rm == 5:
        return ('rip', struct.unpack_from('<i', data, p)[0]), reg
    else:
        base = rm | ((rex & 1) << 3)
    disp = 0
    if mod == 1:
        disp = struct.unpack_from('<b', data, p)[0]
    elif mod == 2:
        disp = struct.unpack_from('<i', data, p)[0]
    return ('m', base, index, scale, disp), reg


class Walker:
    """Steps one instruction at a time on a symbolic state."""

    def __init__(self, image):
        self.image = image

    def address(self, state, insn, op):
        if op[0] == 'rip':
            return konst(insn.va + insn.size + op[1])
        _, base, index, scale, disp = op
        value = konst(disp)
        if base is not None:
            value = add(value, state.regs[base])
        if index is not None:
            value = add(value, scaled(state.regs[index], scale))
        return value

    def get(self, state, insn, op, bits):
        if op[0] == 'r':
            if bits == 8 and not insn.rex and 4 <= op[1] < 8:
                raise Unsupported('high byte register')
            return low(state.regs[op[1]], bits)
        return state.load(self.address(state, insn, op), bits // 8)

    def put_reg(self, state, n, bits, value):
        if bits == 64:
            state.regs[n] = value
        elif bits == 32:
            state.regs[n] = low(value, 32)
        else:
            state.regs[n] = pure('partial', state.regs[n], bits, value)

    def put(self, state, insn, op, bits, value):
        if op[0] == 'r':
            if bits == 8 and not insn.rex and 4 <= op[1] < 8:
                raise Unsupported('high byte register')
            self.put_reg(state, op[1], bits, value)
        else:
            state.mem[self.address(state, insn, op)] = (bits // 8, value)

    def alu(self, state, kind, left, right, bits):
        """Run one ALU operation; return the result, or None for a compare."""
        if bits == 64 and kind in (0, 5, 7):
            name = 'add' if kind == 0 else 'sub'
            state.flags = ('a', name, left, right)
            if kind == 7:
                return None
            return add(left, right) if kind == 0 else sub(left, right)
        if kind in (0, 5, 7):
            state.flags = ('o', kind, bits, left, right)
            if kind == 7:
                return None
            result = add(left, right) if kind == 0 else sub(left, right)
            return low(result, bits) if is_const(result) else pure('alu', kind, bits, left, right)
        if kind == 6:
            result = xor(left, right)
        elif kind in (1, 4):
            if is_const(left) and is_const(right):
                result = konst(left[1] | right[1] if kind == 1 else left[1] & right[1])
            else:
                result = pure('or' if kind == 1 else 'and', *ordered(left, right))
        else:
            result = pure('carry', kind, bits, left, right, state.flags)
            state.flags = ('o', 'carry', result)
            return result
        state.flags = ('l', result) if bits == 64 else ('o', 'logic', bits, result)
        return result

    def step(self, state, insn):
        """Execute one instruction.  Return None, or (cc, target) for a conditional branch."""
        data = self.image.data
        prefixes = data[insn.off:insn.body - (1 if insn.rex else 0)]
        if any(b in (0x64, 0x65, 0xf0, 0x67) for b in prefixes):
            raise Unsupported('segment, lock or address-size prefix')
        wide = 0x66 in prefixes
        rep = 0xf3 in prefixes
        repne = 0xf2 in prefixes
        rex = insn.rex
        bits = 64 if rex & 8 else 16 if wide else 32
        key = insn.key
        following = insn.va + insn.size
        end = insn.off + insn.size
        state.pc = following

        def signed_imm(size):
            return struct.unpack_from({1: '<b', 2: '<h', 4: '<i'}[size], data, end - size)[0]

        if key == 0x90 or key == (0x0f, 0x1f):
            return None
        if key == (0x0f, 0x1e) and rep:
            return None
        if isinstance(key, int) and key < 0x40 and key & 7 < 4:
            kind = key >> 3
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if not key & 1 else bits
            if width == 8 and not rex and reg >= 4 and reg < 8:
                raise Unsupported('high byte register')
            regop = ('r', reg)
            if key & 2:
                left, right, dest = self.get(state, insn, regop, width), self.get(state, insn, op, width), regop
            else:
                left, right, dest = self.get(state, insn, op, width), self.get(state, insn, regop, width), op
            if kind == 6 and op == regop:
                self.put(state, insn, dest, width, konst(0))
                state.flags = ('l', konst(0))
                return None
            result = self.alu(state, kind, left, right, width)
            if result is not None:
                self.put(state, insn, dest, width, result)
            return None
        if isinstance(key, int) and key < 0x40 and key & 7 == 5:
            size = 2 if wide else 4
            left = low(state.regs[RAX], bits)
            right = konst(signed_imm(size) & ((1 << bits) - 1))
            result = self.alu(state, key >> 3, left, right, bits)
            if result is not None:
                self.put_reg(state, RAX, bits, result)
            return None
        if key in (0x80, 0x81, 0x83):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x80 else bits
            size = 1 if key != 0x81 else (2 if wide else 4)
            right = konst(signed_imm(size) & ((1 << width) - 1))
            result = self.alu(state, reg & 7, self.get(state, insn, op, width), right, width)
            if result is not None:
                self.put(state, insn, op, width, result)
            return None
        if key in (0x84, 0x85):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x84 else bits
            if op == ('r', reg):
                value = self.get(state, insn, op, width)
            else:
                value = pure('and', *ordered(self.get(state, insn, op, width), self.get(state, insn, ('r', reg), width)))
            state.flags = ('l', value) if width == 64 else ('o', 'test', width, value)
            return None
        if key in (0x88, 0x89):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x88 else bits
            self.put(state, insn, op, width, self.get(state, insn, ('r', reg), width))
            return None
        if key in (0x8a, 0x8b):
            op, reg = operand(data, insn.modrm, rex)
            width = 8 if key == 0x8a else bits
            self.put(state, insn, ('r', reg), width, self.get(state, insn, op, width))
            return None
        if key == 0x8d:
            op, reg = operand(data, insn.modrm, rex)
            self.put_reg(state, reg, bits, self.address(state, insn, op))
            return None
        if key == 0x63:
            op, reg = operand(data, insn.modrm, rex)
            self.put_reg(state, reg, bits, pure('sx', self.get(state, insn, op, 32)))
            return None
        if key in (0x69, 0x6b) and bits == 64:
            op, reg = operand(data, insn.modrm, rex)
            state.flags = ('o', 'imul-immediate', insn.va)
            self.put_reg(state, reg, 64, scaled(self.get(state, insn, op, 64), signed_imm(1 if key == 0x6b else 4) & U64))
            return None
        if key == 0xa8:
            state.flags = ('o', 'test-al', low(state.regs[RAX], 8), signed_imm(1))
            return None
        if key in (0xc6, 0xc7):
            op, reg = operand(data, insn.modrm, rex)
            if reg & 7:
                raise Unsupported('group 11')
            width = 8 if key == 0xc6 else bits
            size = 1 if key == 0xc6 else (2 if wide else 4)
            self.put(state, insn, op, width, konst(signed_imm(size) & ((1 << width) - 1)))
            return None
        if isinstance(key, int) and 0xb8 <= key <= 0xbf:
            n = (key & 7) | ((rex & 1) << 3)
            if rex & 8:
                state.regs[n] = konst(struct.unpack_from('<Q', data, end - 8)[0])
            elif not wide:
                state.regs[n] = konst(struct.unpack_from('<I', data, end - 4)[0])
            else:
                self.put_reg(state, n, 16, konst(struct.unpack_from('<H', data, end - 2)[0]))
            return None
        if isinstance(key, int) and 0x50 <= key <= 0x57:
            state.regs[RSP] = add(state.regs[RSP], konst(-8))
            state.mem[state.regs[RSP]] = (8, state.regs[(key & 7) | ((rex & 1) << 3)])
            return None
        if isinstance(key, int) and 0x58 <= key <= 0x5f:
            state.regs[(key & 7) | ((rex & 1) << 3)] = state.load(state.regs[RSP], 8)
            state.regs[RSP] = add(state.regs[RSP], konst(8))
            return None
        if key in (0xc1, 0xd1):
            op, reg = operand(data, insn.modrm, rex)
            count = data[end - 1] & 63 if key == 0xc1 else 1
            name = {1: 'ror', 4: 'shl', 5: 'shr', 7: 'sar'}.get(reg & 7)
            if name is None:
                raise Unsupported('rotate')
            value = self.get(state, insn, op, bits)
            state.flags = ('o', name, bits, value, count)
            self.put(state, insn, op, bits, pure(name, value, count))
            return None
        if key == 0xff:
            op, reg = operand(data, insn.modrm, rex)
            action = reg & 7
            if action in (0, 1):
                value = self.get(state, insn, op, bits)
                state.flags = ('o', 'incdec', action, bits, value)
                self.put(state, insn, op, bits, add(value, konst(1 if action == 0 else -1)))
                return None
            raise Unsupported('call or jump through a register or slot')
        if key == 0xf7:
            op, reg = operand(data, insn.modrm, rex)
            action = reg & 7
            value = self.get(state, insn, op, bits)
            if action == 0:
                size = 2 if wide else 4
                state.flags = ('o', 'testi', bits, value, signed_imm(size))
                return None
            if action == 2:
                self.put(state, insn, op, bits, pure('not', value))
                return None
            if action == 3 and bits == 64:
                state.flags = ('a', 'sub', konst(0), value)
                self.put(state, insn, op, bits, sub(konst(0), value))
                return None
            if action == 4 and bits == 64:
                product = pure('mul', *ordered(state.regs[RAX], value))
                state.flags = ('o', 'mul', product)
                state.regs[RAX] = pure('mullow', product)
                state.regs[RDX] = pure('mulhigh', product)
                return None
            raise Unsupported('group 3')
        if key == 0xf6:
            op, reg = operand(data, insn.modrm, rex)
            if reg & 7:
                raise Unsupported('group 3 byte')
            state.flags = ('o', 'testb', self.get(state, insn, op, 8), signed_imm(1))
            return None
        if isinstance(key, int) and 0x70 <= key <= 0x7f:
            return key & 15, insn.target
        if key in (0xe9, 0xeb):
            state.pc = insn.target
            return None
        if isinstance(key, tuple) and key[0] == 0x0f:
            two = key[1]
            if 0x80 <= two <= 0x8f:
                return two & 15, insn.target
            if 0x40 <= two <= 0x4f:
                op, reg = operand(data, insn.modrm, rex)
                test, polarity = predicate(state.flags, two & 15)
                truth = settled(state, test)
                source = self.get(state, insn, op, bits)
                if truth is None:
                    self.put_reg(state, reg, bits, pure('ite', test, polarity, source, state.regs[reg]))
                elif truth == polarity:
                    self.put_reg(state, reg, bits, source)
                else:
                    self.put_reg(state, reg, bits, state.regs[reg])
                return None
            if 0x90 <= two <= 0x9f:
                op, reg = operand(data, insn.modrm, rex)
                test, polarity = predicate(state.flags, two & 15)
                truth = settled(state, test)
                if truth is not None:
                    value = konst(int(truth == polarity))
                elif test[0] == 'S' and not polarity:
                    value = atom('ns', test[1])
                else:
                    value = pure('set', test, polarity)
                if op[0] == 'r':
                    n = op[1]
                    if not rex and 4 <= n < 8:
                        raise Unsupported('high byte register')
                    old = state.regs[n]
                    state.regs[n] = value if old == konst(0) else pure('setlow', old, value)
                else:
                    state.mem[self.address(state, insn, op)] = (1, value)
                return None
            if two in (0xb6, 0xb7, 0xbe, 0xbf):
                op, reg = operand(data, insn.modrm, rex)
                source = self.get(state, insn, op, 8 if two & 1 == 0 else 16)
                value = source if two < 0xb8 else pure('sx', source)
                self.put_reg(state, reg, bits, value)
                return None
            if two == 0xaf:
                op, reg = operand(data, insn.modrm, rex)
                left, right = self.get(state, insn, ('r', reg), bits), self.get(state, insn, op, bits)
                state.flags = ('o', 'imul', bits, left, right)
                self.put_reg(state, reg, bits, pure('imul', *ordered(left, right)))
                return None
            if two in (0x28, 0x29, 0x10, 0x11, 0x6f, 0x7f) and (two in (0x28, 0x29) or not repne or two < 0x20):
                if two in (0x6f, 0x7f) and not (wide or rep):
                    raise Unsupported('mmx move')
                op, reg = operand(data, insn.modrm, rex)
                size = 8 if repne else 4 if rep and two < 0x20 else 16
                if two in (0x28, 0x10, 0x6f):
                    if op[0] == 'r':
                        state.xmm[reg] = state.xmm.get(op[1], pure('xmm', op[1]))
                    else:
                        state.xmm[reg] = state.load(self.address(state, insn, op), size)
                else:
                    value = state.xmm.get(reg, pure('xmm', reg))
                    if op[0] == 'r':
                        state.xmm[op[1]] = value
                    else:
                        state.mem[self.address(state, insn, op)] = (size, value)
                return None
            if two in (0x57, 0xef):
                op, reg = operand(data, insn.modrm, rex)
                if op == ('r', reg):
                    state.xmm[reg] = konst(0)
                    return None
        raise Unsupported(f'opcode {key}')


# --- blocks ----------------------------------------------------------------------------------

def branch_targets(rows):
    targets = {}
    for k, insn in enumerate(rows):
        if insn.target is not None and insn.key != 0xe8:
            targets.setdefault(insn.target, []).append(k)
    return targets


def is_conditional(insn):
    key = insn.key
    return (isinstance(key, int) and 0x70 <= key <= 0x7f) or (isinstance(key, tuple) and key[:1] == (0x0f,) and 0x80 <= key[1] <= 0x8f)


def is_jump(insn):
    return insn.key in (0xe9, 0xeb)


def ends_block(insn):
    return is_conditional(insn) or is_jump(insn) or insn.key in (0xc3, 0xe8, 0xff, 0xcc, (0x0f, 0x0b))


def condition_code(insn):
    return insn.key & 15 if isinstance(insn.key, int) else insn.key[1] & 15


def block_start(rows, targets, position):
    """First row of the straight block that holds position."""
    k = position
    while k > 0 and rows[k].va not in targets and not ends_block(rows[k - 1]):
        k -= 1
    return k


# --- path walks -------------------------------------------------------------------------------

class PathWalker(Walker):
    """A Walker that passes over calls, for walks along one edge of a gate."""

    def __init__(self, image):
        Walker.__init__(self, image)
        self.clobbers = 0

    def step(self, state, insn):
        key = insn.key
        is_call = key == 0xe8
        if key == 0xff:
            op, reg = operand(self.image.data, insn.modrm, insn.rex)
            is_call = reg & 7 == 2
        if not is_call:
            return Walker.step(self, state, insn)
        state.pc = insn.va + insn.size
        self.clobbers += 1
        for n in CALLER_SAVED:
            state.regs[n] = atom('h', n, self.clobbers)
        state.xmm = {}
        state.flags = None
        return None


def holders(state, value):
    """Every register and memory slot that holds value, as a hashable set."""
    if value is None:
        return frozenset(('any',))
    found = {n for n in range(16) if state.regs[n] == value}
    found.update(repr(key) for key, slot in state.mem.items() if slot[1] == value)
    return frozenset(found)


def constants_of(value):
    """The constants a value can be, through truncations and selections, or an empty set."""
    if is_const(value):
        return {value[1]}
    head = value[0][0][0]
    if value[1] or len(value[0]) != 1 or value[0][0][1] != 1 or head[0] != 'f':
        return set()
    if head[1] in ('low16', 'low32'):
        return constants_of(head[2])
    if head[1] == 'ite':
        first, second = constants_of(head[4]), constants_of(head[5])
        return first | second if first and second else set()
    return set()


def walk(image, rows, index, state, value, visit, extra=None):
    """Follow both edges of every branch from state, while some location holds value.

    A value of None walks every path whatever it holds.  visit(state, insn) sees each row first
    and returns True to end the path.  A visited pair of address and holder set, plus the result
    of extra(state) when given, is not walked again, so loops end.  Returns the rows read.
    """
    walker = PathWalker(image)
    if value is not None and len(value[0]) == 1 and value[0][0][0][0] == 'm':
        state.mem.setdefault(value[0][0][0][1], (value[0][0][0][2], value))
    pending = [state]
    seen = set()
    while pending:
        current = pending.pop()
        while len(seen) < WALK_LIMIT:
            position = index.get(current.pc)
            if position is None:
                break
            places = holders(current, value)
            mark = (current.pc, places, extra(current) if extra else None)
            if not places or mark in seen:
                break
            seen.add(mark)
            insn = rows[position]
            if insn.key in (0xc3, 0xcc, (0x0f, 0x0b)):
                break
            if visit(current, insn):
                break
            try:
                outcome = walker.step(current, insn)
            except Unsupported:
                break
            if outcome is None:
                continue
            cc, target = outcome
            try:
                test, polarity = predicate(current.flags, cc)
            except Unsupported:
                break
            truth = settled(current, test)
            if truth is not None:
                if truth == polarity:
                    current.pc = target
                continue
            other = current.clone()
            other.pc = target
            other.assume[test] = polarity
            pending.append(other)
            current.assume[test] = not polarity
    return len(seen)


def scale_rows(image, rows, index, state, value):
    """Rows of `imul reg,<location holding value>,100` reached from state."""
    walker = PathWalker(image)
    hits = set()

    def visit(current, insn):
        if insn.key not in (0x69, 0x6b):
            return False
        op, _ = operand(image.data, insn.modrm, insn.rex)
        raw = image.data[insn.off:insn.off + insn.size]
        factor = struct.unpack_from('<i', raw, len(raw) - 4)[0] if insn.key == 0x69 else raw[-1]
        if insn.rex & 8 and factor == SCALE and walker.get(current, insn, op, 64) == value:
            hits.add(insn.va)
            return True
        return False

    walk(image, rows, index, state, value, visit)
    return sorted(hits)


def first_tags(image, rows, index, state):
    """The first 16-bit constant written to memory on each path from state."""
    tags = set()

    def visit(current, insn):
        if insn.key == 0xc7 and insn.off > 0 and image.data[insn.off] == 0x66:
            raw = image.data[insn.off:insn.off + insn.size]
            tags.add((insn.va, struct.unpack_from('<H', raw, len(raw) - 2)[0]))
            return True
        if insn.key == 0x89 and image.data[insn.off] == 0x66:
            op, reg = operand(image.data, insn.modrm, insn.rex)
            held = constants_of(low(current.regs[reg], 16))
            if op[0] != 'r' and held:
                tags.update((insn.va, tag) for tag in held)
                return True
        return False

    def pending_tag(current):
        return tuple(sorted(constants_of(low(current.regs[RAX], 16))))

    walk(image, rows, index, state, None, visit, pending_tag)
    return sorted(tags)


def first_labels(image, rows, index, state):
    """The first known label loaded by a rip-relative lea on each path from state."""
    labels = set()

    def visit(current, insn):
        if insn.key != 0x8d:
            return False
        op, _ = operand(image.data, insn.modrm, insn.rex)
        if op[0] != 'rip':
            return False
        target = insn.va + insn.size + op[1]
        try:
            off = image.file_offset(target)
        except EvidenceError:
            return False
        for label in LABELS:
            if image.data[off:off + len(label)] == label:
                labels.add(label.decode('ascii'))
                return True
        return False

    walk(image, rows, index, state, None, visit)
    return sorted(labels)


# --- census ---------------------------------------------------------------------------------

def occurrences(image):
    """Every 8-byte little-endian copy of the two constants, in every section with file bytes."""
    found = {'text': [], 'data': []}
    for section in image.sections:
        blob = image.data[section['offset']:section['offset'] + section['size']]
        for value in (CAP, ROUND_BOUND):
            for match in re.finditer(re.escape(struct.pack('<Q', value)), blob):
                va = section['address'] + match.start()
                found['text' if section is image.text else 'data'].append((va, value, section['name']))
    in_file = sum(image.data.count(struct.pack('<Q', value)) for value in (CAP, ROUND_BOUND))
    if in_file != len(found['text']) + len(found['data']):
        fail(f'{in_file} copies in the file, {len(found["text"]) + len(found["data"])} in sections')
    return {key: sorted(rows) for key, rows in found.items()}


def movabs_sites(image, hits):
    """Each hit in .text has to be the immediate of a REX.W movabs at an instruction start."""
    sites = []
    delta = image.text['offset'] - image.text['address']
    for va, value, _ in hits:
        start = va - 2
        rex, opcode = image.data[start + delta], image.data[start + delta + 1]
        if rex not in (0x48, 0x49) or not 0xb8 <= opcode <= 0xbf:
            fail(f'constant at {va:#x} is not a movabs immediate')
        sites.append((start, value))
    return sites


def table_run(image, va):
    """Walk the 24-byte records around a data copy: each step of 24 bytes moves the power by 2."""
    off = image.file_offset(va)
    power = next(k for k in range(20) if U64 // 10 ** k == CAP)
    first = last = power
    while first >= 2 and struct.unpack_from('<Q', image.data, off + (first - 2 - power) * 12)[0] == U64 // 10 ** (first - 2):
        first -= 2
    while last <= 17 and struct.unpack_from('<Q', image.data, off + (last + 2 - power) * 12)[0] == U64 // 10 ** (last + 2):
        last += 2
    return {'copy': f'{va:#x}', 'power': power, 'first_power': first, 'last_power': last,
            'first_record': f'{va + (first - power) * 12:#x}', 'stride': 24}


def scale_lemma(cap=CAP):
    """x <= cap is exact for 10000 * x fitting u64, and 100 * x then fits with room for 100 more."""
    return {'cap': f'{cap:#x}', 'cap_is_floor_max_over_10000': cap == U64 // 10000,
            'times_100_fits': cap * 100 <= U64,
            'times_10000_fits': cap * 10000 <= U64,
            'next_times_10000_overflows': (cap + 1) * 10000 > U64,
            'times_100_at_most_max_over_100': cap * 100 <= U64 // 100,
            'next_times_100_above_max_over_100': (cap + 1) * 100 > U64 // 100}


def divisibility_lemma(inverse=INVERSE_625, bound=ROUND_BOUND, rotate=ROTATE):
    """(x * inverse) ror 4 < bound holds exactly for the multiples of 10000, for all u64 x.

    x -> (x * inverse) mod 2^64 and the rotate are both bijections of u64 because the inverse is
    odd.  The multiple 10000q is 16 * 625 * q, so it maps to 16q and then to q, which is below
    bound.  There are exactly bound multiples in u64 and bound values below bound, so a
    bijection leaves no room for another input.
    """
    def image_of(x):
        y = (x * inverse) & U64
        return ((y >> rotate) | (y << (64 - rotate))) & U64

    edge = []
    for q in (0, 1, 2, bound - 2, bound - 1):
        x = q * 10000
        edge.append({'x': x, 'maps_to_q': x <= U64 and image_of(x) == q})
    near = all(image_of(x) >= bound for q in (1, 2, bound - 1) for x in (q * 10000 - 1, q * 10000 + 1) if x <= U64)
    proved = (inverse & 1 == 1 and (inverse * 625) & U64 == 1 and 1 << rotate == 16 and 10000 == 625 << rotate
              and bound == U64 // 10000 + 1 and all(row['maps_to_q'] for row in edge) and near)
    return {'proved': proved, 'inverse': f'{inverse:#x}', 'rotate': rotate, 'multiples_in_u64': bound,
            'edge_multiples': len(edge), 'neighbours_rejected': near}


# --- one site -------------------------------------------------------------------------------

def gate_within(value, cc):
    """Return True when the condition means x <= CAP, False when it means x > CAP."""
    if (value, cc) in ((CAP, 6), (ROUND_BOUND, 2)):
        return True
    if (value, cc) in ((CAP, 7), (ROUND_BOUND, 3)):
        return False
    fail(f'constant {value:#x} is compared with condition {cc}')


def is_cmov(insn):
    return isinstance(insn.key, tuple) and insn.key[0] == 0x0f and 0x40 <= insn.key[1] <= 0x4f


def round_input(left):
    """Return y when left is (y * INVERSE_625) ror 4, or None."""
    if not (left[1] == 0 and len(left[0]) == 1 and left[0][0][1] == 1):
        return None
    key = left[0][0][0]
    if key[:2] != ('f', 'ror') or key[3] != ROTATE:
        return None
    inner = key[2]
    if not (inner[1] == 0 and len(inner[0]) == 1 and inner[0][0][1] == 1):
        return None
    head = inner[0][0][0]
    if head[:2] != ('f', 'imul'):
        return None
    for one, other in ((head[2], head[3]), (head[3], head[2])):
        if one == konst(INVERSE_625):
            return other
    return None


def tag_text(image, tag):
    """Plain text of an error tag, read from the arm of the Display function."""
    entry = struct.unpack_from('<i', image.data, image.file_offset(DISPLAY_TABLE + tag * 4))[0]
    arm = DISPLAY_TABLE + entry
    off = image.file_offset(arm)
    if image.data[off:off + 14] != DISPLAY_ARM:
        return f'arm {arm:#x}, not a plain text arm'
    text = arm + 18 + struct.unpack_from('<i', image.data, off + 14)[0]
    if image.data[off + 18] != 0xba:
        fail(f'text arm of tag {tag:#x} has no length')
    length = struct.unpack_from('<I', image.data, off + 19)[0]
    return image.data[image.file_offset(text):image.file_offset(text) + length].decode('ascii')


def analyse_site(image, va, value):
    """Read one movabs site from bytes.  Return its facts, or raise EvidenceError."""
    fn = image.fde_of(va)
    rows = sweep(image, *fn)
    index = {insn.va: k for k, insn in enumerate(rows)}
    if va not in index:
        fail(f'site {va:#x} is not an instruction start')
    position = index[va]
    if struct.unpack_from('<Q', image.data, rows[position].off + 2)[0] != value:
        fail(f'site {va:#x} no longer loads {value:#x}')
    targets = branch_targets(rows)
    walker = Walker(image)
    state = State()
    for k in range(block_start(rows, targets, position), position + 1):
        try:
            walker.step(state, rows[k])
        except Unsupported:
            state = State()
    if not is_const(state.regs[(rows[position].key & 7) | ((rows[position].rex & 1) << 3)]):
        fail(f'site {va:#x} did not load its constant')
    k = position + 1
    for k in range(position + 1, position + GATE_WINDOW):
        walker.step(state, rows[k])
        if state.flags and state.flags[0] == 'a' and state.flags[1] == 'sub' and state.flags[3] == konst(value):
            break
    else:
        fail(f'no compare with the constant follows {va:#x}')
    x = state.flags[2]
    gate = rows[k + 1]
    data = image.data
    facts = {'site': va, 'value': value, 'function': fn[0], 'function_end': fn[1], 'compare': rows[k].va,
             'gate': gate.va, 'gate_bytes': data[gate.off:gate.off + gate.size].hex(), 'x': render(x),
             'within': '', 'over': '', 'tags': [], 'labels': []}
    y = round_input(x)
    if y is not None:
        cc = condition_code(gate)
        if not is_conditional(gate):
            fail(f'divisibility test at {va:#x} has no branch')
        taken = gate_within(value, cc)
        edge = state.clone()
        edge.pc = gate.target if taken else gate.va + gate.size
        other = gate.va + gate.size if taken else gate.target
        divisible = edge.pc
        labels = first_labels(image, rows, index, edge)
        facts.update({'class': 'divisible-by-10000', 'x': render(y), 'read': 'x % 10000 == 0',
                      'within': f'{divisible:#x}', 'over': f'{other:#x}', 'labels': labels})
        return facts
    if is_cmov(gate):
        op, reg = operand(data, gate.modrm, gate.rex)
        if not gate.rex & 8 or gate_within(value, gate.key[1] & 15):
            fail(f'cmov at {gate.va:#x} does not act above the cap')
        old = state.regs[reg]
        source = walker.get(state, gate, op, 64)
        if old != scaled(x, SCALE):
            fail(f'cmov at {gate.va:#x} does not keep x * 100 below the cap')
        if source != konst(0):
            fail(f'cmov at {gate.va:#x} takes {render(source)} above the cap')
        facts.update({'class': 'cmov-zero', 'read': 'x <= cap ? x * 100 : 0'})
        return facts
    if not is_conditional(gate):
        fail(f'row after the compare at {rows[k].va:#x} is neither a branch nor a cmov')
    taken_within = gate_within(value, condition_code(gate))
    in_edge, out_edge = state.clone(), state.clone()
    in_edge.pc, out_edge.pc = (gate.target, gate.va + gate.size) if taken_within else (gate.va + gate.size, gate.target)
    over = out_edge.pc
    scales = scale_rows(image, rows, index, in_edge, x)
    if not scales:
        fail(f'no x * 100 is reached below the cap from {gate.va:#x}')
    tags = first_tags(image, rows, index, out_edge)
    facts.update({'class': 'branch', 'read': 'x <= cap ? x * 100 : leave', 'within': ','.join(f'{v:#x}' for v in scales),
                  'over': f'{over:#x}', 'tags': tags})
    return facts


def periodic_prefix(image, site):
    """Rows from the FDE start to the `periodic` lea: is any of them a test of a value with 0?"""
    fn = image.fde_of(site)
    rows = sweep(image, *fn)
    index = {insn.va: k for k, insn in enumerate(rows)}
    last = None
    for k in range(index[site], len(rows)):
        insn = rows[k]
        if insn.key == 0x8d:
            op, _ = operand(image.data, insn.modrm, insn.rex)
            if op[0] == 'rip' and image.data[image.file_offset(insn.va + insn.size + op[1]):][:8] == b'periodic':
                last = k
                break
    if last is None:
        fail(f'no periodic label follows {site:#x}')
    zero_tests = 0
    for insn in rows[:last]:
        if insn.key == 0x85:
            op, reg = operand(image.data, insn.modrm, insn.rex)
            zero_tests += op == ('r', reg)
        elif insn.key == 0x83 and image.data[insn.off + insn.size - 1] == 0:
            op, reg = operand(image.data, insn.modrm, insn.rex)
            zero_tests += reg & 7 == 7
    inward = [insn.va for insn in rows[last:] if insn.target is not None and insn.key != 0xe8
              and rows[0].va <= insn.target <= rows[last].va]
    if inward:
        fail(f'later rows branch into the prefix of {site:#x}: {inward}')
    return {'function': f'{fn[0]:#x}', 'label_lea': f'{rows[last].va:#x}', 'rows': last, 'zero_tests': zero_tests}


# --- negative controls -----------------------------------------------------------------------

def site_edits(image, facts):
    """Damaged copies of one site: (name, va, replacement bytes)."""
    edits = []
    gate_va = facts['gate']
    fn = (facts['function'], facts['function_end'])
    rows = sweep(image, *fn)
    index = {insn.va: k for k, insn in enumerate(rows)}
    gate = rows[index[gate_va]]
    raw = bytearray(image.data[gate.off:gate.off + gate.size])
    p = gate.body - gate.off
    raw[p + (1 if raw[p] == 0x0f else 0)] ^= 1
    edits.append(('flip-gate', gate_va, bytes(raw)))
    edits.append(('constant-low-byte', facts['site'] + 2, bytes([(facts['value'] & 255) ^ 4])))
    if facts['class'] == 'cmov-zero':
        edits.append(('cmov-source', gate_va + gate.size - 1, bytes([image.data[gate.off + gate.size - 1] ^ 3])))
    if facts['class'] == 'divisible-by-10000':
        for k in range(index[facts['site']] - 1, index[facts['site']] - 6, -1):
            insn = rows[k]
            if insn.key == 0xc1:
                edits.append(('rotate-count', insn.va, bytes([image.data[insn.off + insn.size - 1] ^ 1])))
                break
    elif facts['class'] == 'branch':
        for text in facts['within'].split(','):
            insn = rows[index[int(text, 16)]]
            edits.append(('factor', insn.va + insn.size - 1, bytes([SCALE + 1])))
    else:
        for insn in rows[index[facts['site']] - 4:index[facts['site']]]:
            if insn.key == 0x6b and image.data[insn.off + insn.size - 1] == SCALE:
                edits.append(('factor', insn.va + insn.size - 1, bytes([SCALE + 1])))
    return edits


def control_rows(image, sites):
    rows = []
    for facts in sites:
        for name, va, raw in site_edits(image, facts):
            damaged = image.patched([(va, raw)])
            try:
                caught = analyse_site(damaged, facts['site'], facts['value']) != facts
            except EvidenceError:
                caught = True
            if not caught:
                fail(f'{name} at {va:#x} survived at site {facts["site"]:#x}')
            rows.append({'site': facts['site'], 'control': name, 'va': va, 'caught': caught})
    return rows


# --- whole packet ----------------------------------------------------------------------------

def message_rows(image):
    """The LEAs of both copies of the conversion message and the gate that reaches each."""
    copies = [m.start() for m in re.finditer(re.escape(MESSAGE), image.data)]
    vas = {}
    for off in copies:
        section = next(s for s in image.sections if s['offset'] <= off < s['offset'] + s['size'])
        vas[section['address'] + off - section['offset']] = section['name']
    base, start, size = image.text['address'], image.text['offset'], image.text['size']
    text = image.data[start:start + size]
    rows = []
    for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        target = base + pos + 7 + struct.unpack_from('<i', text, pos + 3)[0]
        if target not in vas:
            continue
        va = base + pos
        fn = image.fde_of(va)
        fn_rows = sweep(image, *fn)
        index = {insn.va: k for k, insn in enumerate(fn_rows)}
        store = fn_rows[index[va] - 1]
        raw = image.data[store.off:store.off + store.size]
        if raw[:1] != b'\x66' or raw[-2:] != b'\xdf\x00':
            fail(f'message at {va:#x} does not follow a store of tag 0xdf')
        gates = [insn for insn in fn_rows if insn.target == store.va and is_conditional(insn)]
        if len(gates) != 1:
            fail(f'{len(gates)} branches reach the message block at {store.va:#x}')
        before = fn_rows[index[gates[0].va] - 3:index[gates[0].va]]
        loads = [insn for insn in before if isinstance(insn.key, int) and 0xb8 <= insn.key <= 0xbf and insn.rex & 8
                 and struct.unpack_from('<Q', image.data, insn.off + 2)[0] == CAP]
        if len(loads) != 1:
            fail(f'the gate at {gates[0].va:#x} does not follow a load of the cap')
        rows.append({'message': target, 'section': vas[target], 'lea': va, 'function': fn[0], 'store': store.va,
                     'gate': gates[0].va, 'site': loads[0].va})
    return rows, sorted(vas)


def analyse(image):
    hits = occurrences(image)
    sites = movabs_sites(image, hits['text'])
    data_copies = [row for row in hits['data'] if row[1] == CAP]
    if len(data_copies) != len(hits['data']):
        fail('the round bound has a data copy')
    tables = [table_run(image, row[0]) for row in data_copies]
    analysed, excluded = [], []
    for va, value in sites:
        fn = image.fde_of(va)
        reason = EXCLUDED_FUNCTIONS.get(fn[0]) or NOT_READ_FUNCTIONS.get(fn[0])
        if reason:
            excluded.append({'site': va, 'value': value, 'function': fn[0], 'function_end': fn[1], 'named_by': reason})
            continue
        analysed.append(analyse_site(image, va, value))
    missing = (set(EXCLUDED_FUNCTIONS) | set(NOT_READ_FUNCTIONS)) - {row['function'] for row in excluded}
    if missing:
        fail(f'excluded functions hold no site: {sorted(missing)}')
    controls = control_rows(image, analysed)
    messages, copies = message_rows(image)
    tally, tags = {}, {}
    for row in analysed:
        tally[row['class']] = tally.get(row['class'], 0) + 1
        for _, tag in row['tags']:
            tags[tag] = tags.get(tag, 0) + 1
    outcome = {}
    for row in controls:
        outcome[row['control']] = outcome.get(row['control'], 0) + 1
    if not divisibility_lemma()['proved']:
        fail('divisibility lemma failed')
    lemma = scale_lemma()
    if not all(v for k, v in lemma.items() if k != 'cap'):
        fail('scale lemma failed')
    evidence = {
        'target_sha256': SHA256,
        'cap': f'{CAP:#x}',
        'round_bound': f'{ROUND_BOUND:#x}',
        'text_sites': len(sites),
        'text_sites_by_value': {f'{v:#x}': sum(1 for _, w in sites if w == v) for v in (CAP, ROUND_BOUND)},
        'data_copies': [{'va': f'{va:#x}', 'section': name} for va, _, name in data_copies],
        'power_tables': tables,
        'analysed_sites': len(analysed),
        'analysed_functions': len({row['function'] for row in analysed}),
        'excluded_sites': sum(1 for row in excluded if row['function'] in EXCLUDED_FUNCTIONS),
        'excluded_functions': sum(1 for fn in EXCLUDED_FUNCTIONS),
        'not_read_sites': sum(1 for row in excluded if row['function'] in NOT_READ_FUNCTIONS),
        'sites_by_class': dict(sorted(tally.items())),
        'first_tag_rows': {f'{tag:#x}': {'rows': count, 'text': tag_text(image, tag)} for tag, count in sorted(tags.items())},
        'periodic_prefixes': [periodic_prefix(image, va) for va in PERIODIC_SITES],
        'scale_lemma': lemma,
        'divisibility_lemma': divisibility_lemma(),
        'controls': dict(sorted(outcome.items())),
        'controls_survived': 0,
        'message': MESSAGE.decode('ascii'),
        'message_copies': [f'{va:#x}' for va in copies],
        'message_leas': len(messages),
    }
    return evidence, analysed, excluded, controls, messages


def write_outputs(out, evidence, analysed, excluded, controls, messages):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    lines = ['site\tconstant\tfunction\tfunction_end\tcompare\tgate\tgate_bytes\tclass\tinput\tread\tscale_or_divisible_edge\tother_edge\tfirst_tags\tlabels_on_divisible_edge']
    for row in analysed:
        tags = ','.join(f'{va:#x}:{tag:#x}' for va, tag in row['tags'])
        lines.append('\t'.join((f'{row["site"]:#x}', f'{row["value"]:#x}', f'{row["function"]:#x}', f'{row["function_end"]:#x}',
                                f'{row["compare"]:#x}', f'{row["gate"]:#x}', row['gate_bytes'], row['class'], row['x'],
                                row['read'], row['within'], row['over'], tags, ','.join(row['labels']))))
    (out / 'sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['site\tconstant\tfunction\tfunction_end\tnamed_by']
    for row in excluded:
        lines.append(f'{row["site"]:#x}\t{row["value"]:#x}\t{row["function"]:#x}\t{row["function_end"]:#x}\t{row["named_by"]}')
    (out / 'excluded-sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['site\tcontrol\tva\tcaught']
    for row in controls:
        lines.append(f'{row["site"]:#x}\t{row["control"]}\t{row["va"]:#x}\t{str(row["caught"]).lower()}')
    (out / 'mutation-controls.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['message\tsection\tlea\tfunction\ttag_store\tgate\tcap_load']
    for row in messages:
        lines.append(f'{row["message"]:#x}\t{row["section"]}\t{row["lea"]:#x}\t{row["function"]:#x}\t{row["store"]:#x}\t{row["gate"]:#x}\t{row["site"]:#x}')
    (out / 'message-sites.tsv').write_text('\n'.join(lines) + '\n')


def load_target(path):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail(f'binary digest {digest} is not node #94')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--out', required=True)
    parser.add_argument('--binary', default=str(ROOT / BINARY))
    args = parser.parse_args(argv)
    write_outputs(args.out, *analyse(Image(load_target(args.binary))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
