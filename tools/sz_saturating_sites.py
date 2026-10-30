#!/usr/bin/env python3
"""RE-004: Sz and signed Sz overflow recorder sites of node #94 (static, no execution).

Two Rust Location records with the path l1/src/qtys/impl_sz.rs, lines 9 and 35, are passed to
an overflow recorder.  At each site a 64-bit add or subtract has overflowed: the code calls the
recorder, which returns, and goes on with a saturated value.

The tool finds every lea of the two Locations and the conditional branches that enter each
site.  It then reads the real bytes of both branch edges symbolically.  Registers and memory
start as free values, so no operand is sampled and each proof holds for all 2^128 operand
pairs.  A value is a sum of atoms with coefficients mod 2^64.  Flags are kept as the operation
and operands that set them, and a condition met once on a path is remembered, so a later
`cmovo` or `cmovb` on the same operands is settled by the branch that was taken.

The overflow edge has to reach the recorder exactly once with the right Location and meet the
other edge at a common address.  There some location must hold the wrapped result L on the
other edge and on the overflow edge:

    unsigned add   u64::MAX       unsigned sub   0
    signed add/sub (L >>s 63) ^ i64::MIN, or i64::MAX + (L >= 0)

`saturation_lemma` shows both signed forms are the saturated result whenever the signed
operation overflowed.  Functions named by other work items are left out and listed.

    python3 tools/sz_saturating_sites.py --out <dir>

writes evidence.json, sz-sites.tsv, excluded-functions.tsv and mutation-controls.tsv.  Only the
Python standard library is used; objdump is not.  Nothing from the binary runs.
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
I64_MIN = 1 << 63
I64_MAX = I64_MIN - 1

PATH_SUFFIX = b'/l1/src/qtys/impl_sz.rs'
SHOWN_PATH = 'l1/src/qtys/impl_sz.rs'
LINE_KIND = {9: 'unsigned', 35: 'signed'}
RECORDER_SLOT, RECORDER = 0x5773190, 0x358dcd0

# Functions named by other work items or open pull requests.
EXCLUDED_FUNCTIONS = {
    0x26e81c0: 'RE-004-px-tick-ladder-94',
    0x26ebdc0: 'RE-004-px-tick-ladder-94, RE-006-match-resting-order-94',
    0x2773d60: 'RE-004-px-tick-ladder-94',
    0x27758c0: 'RE-004-px-tick-ladder-94',
    0x36f7c40: 'RE-004-adl-shortfall-budget-94',
    0x36fff10: 'RE-004-adl-shortfall-budget-94',
    0x370afd0: 'RE-006-match-resting-order-94',
    0x42e8bf0: 'RE-006-price-level-lifecycle-94',
    0x430d610: 'RE-004-px-tick-ladder-94, RE-006-order-relation-transitions-94',
    0x4311140: 'RE-004-px-tick-ladder-94, RE-006-order-relation-transitions-94',
    0x4314da0: 'RE-004-px-tick-ladder-94, RE-006-order-relation-transitions-94',
    0x4318a00: 'RE-004-px-tick-ladder-94, RE-006-order-relation-transitions-94',
    0x4336b90: 'RE-004-px-tick-ladder-94',
    0x43377c0: 'RE-004-px-tick-ladder-94',
    0x4338210: 'RE-004-px-tick-ladder-94',
    0x4339480: 'RE-004-px-tick-ladder-94'}

STEP_LIMIT = 70
FORK_LIMIT = 24
BACK_LIMIT = 60
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
    def __init__(self, data, fdes=None, relocs=None):
        self.data = data
        table = elf_index.sections(data)
        self.sections = [s for s in table if s['type'] != 8 and s['address']]
        self.text = next(s for s in self.sections if s['name'] == '.text')
        if fdes is None:
            _, records = fde_extents.eh_frame_records(data, table)
            fdes = sorted((r['start'], r['end']) for r in records)
        self.fdes = fdes
        self.starts = [row[0] for row in fdes]
        self.relocs = relocs if relocs is not None else self.relative_relocations()

    def relative_relocations(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        relocs = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if info & 0xffffffff == 8:
                relocs[where] = addend
        return relocs

    def patched(self, edits):
        """A copy with bytes replaced, for the negative controls."""
        blob = bytearray(self.data)
        for va, raw in edits:
            off = self.file_offset(va)
            blob[off:off + len(raw)] = raw
        return Image(bytes(blob), self.fdes, self.relocs)

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


def location_records(image):
    """Every Location record whose path ends in impl_sz.rs: {record va: (line, column)}."""
    records = {}
    for where, target in image.relocs.items():
        try:
            off = image.file_offset(where)
            length, line, column = struct.unpack_from('<QII', image.data, off + 8)
            if not 0 < length < 300:
                continue
            path = image.data[image.file_offset(target):image.file_offset(target) + length]
        except (EvidenceError, struct.error):
            continue
        if path.endswith(PATH_SUFFIX):
            records[where] = (line, column)
    return records


def lea_references(image, wanted):
    """Every REX.W lea r64,[rip+disp32] in .text that resolves to a wanted record."""
    base, off, size = image.text['address'], image.text['offset'], image.text['size']
    text = image.data[off:off + size]
    hits = {}
    for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        target = base + pos + 7 + struct.unpack_from('<i', text, pos + 3)[0]
        if target in wanted:
            hits[base + pos] = target
    return hits


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


# --- the two saturated forms ----------------------------------------------------------------

def saturated_signed(value):
    """Return L when value is one of the compiled forms of a signed saturated result, or None."""
    terms, constant = value
    if len(terms) != 1 or terms[0][1] != 1:
        return None
    key = terms[0][0]
    if constant == I64_MAX and key[0] == 'ns':
        return key[1]
    if constant == 0 and key[:2] == ('f', 'xor'):
        for one, other in ((key[2], key[3]), (key[3], key[2])):
            if other == konst(I64_MIN) and len(one[0]) == 1 and one[1] == 0:
                head = one[0][0][0]
                if head[:2] == ('f', 'sar') and head[3] == 63:
                    return head[2]
    return None


def compiled_form(value):
    """Name the compiled form of a saturated value."""
    if is_const(value):
        return 'constant'
    return 'setns-add' if value[1] == I64_MAX else 'sar-xor'


def saturation_lemma(width=8):
    """Both signed forms give the saturated result whenever the signed operation overflowed.

    The check runs over all pairs at a small width, and on the edges at 64 bits.  The forms only
    read the sign of the wrapped value, so the argument is the same at every width: a true result
    above MAX wraps negative and one below MIN wraps non-negative.
    """
    def check(bits, a, b):
        mask = (1 << bits) - 1
        top = 1 << (bits - 1)
        low_bound, high_bound = -top, top - 1
        checked = 0
        for total in (a + b, a - b):
            if low_bound <= total <= high_bound:
                continue
            wrapped = total & mask
            sar = mask if wrapped & top else 0
            first = sar ^ top
            second = (high_bound + (0 if wrapped & top else 1)) & mask
            wanted = (high_bound if total > high_bound else low_bound) & mask
            if first != wanted or second != wanted:
                return None
            checked += 1
        return checked

    pairs = cases = 0
    top = 1 << (width - 1)
    for a in range(-top, top):
        for b in range(-top, top):
            result = check(width, a, b)
            if result is None:
                return {'proved': False, 'at': [a, b]}
            pairs += 1
            cases += result
    edges = (-I64_MIN, -I64_MIN + 1, -1, 0, 1, I64_MAX - 1, I64_MAX)
    for a in edges:
        for b in edges:
            result = check(64, a, b)
            if result is None:
                return {'proved': False, 'at': [a, b]}
            cases += result
    return {'proved': True, 'width': width, 'pairs': pairs, 'edge_pairs': len(edges) ** 2, 'overflow_cases': cases}


# --- symbolic machine -----------------------------------------------------------------------

class State:
    def __init__(self):
        self.regs = [atom('r', n) for n in range(16)]
        self.xmm = {}
        self.mem = {}
        self.flags = None
        self.assume = {}
        self.pc = 0
        self.records = 0
        self.clobbers = 0
        self.saturated_at_call = False

    def clone(self):
        other = State.__new__(State)
        other.regs = list(self.regs)
        other.xmm = dict(self.xmm)
        other.mem = dict(self.mem)
        other.flags = self.flags
        other.assume = dict(self.assume)
        other.pc = self.pc
        other.records = self.records
        other.clobbers = self.clobbers
        other.saturated_at_call = self.saturated_at_call
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
    """Steps one instruction at a time on the symbolic state of one guard."""

    def __init__(self, image, record, expected=None):
        self.image, self.record, self.expected = image, record, expected

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
            raise Unsupported('adc or sbb')
        state.flags = ('l', result) if bits == 64 else ('o', 'logic', bits, result)
        return result

    def call_recorder(self, state):
        if not is_const(state.regs[RSI]) or state.regs[RSI][1] != self.record:
            raise Unsupported('the recorder of another site')
        if low(state.regs[RDI], 8) != konst(0):
            fail(f'recorder byte argument {render(state.regs[RDI])} at {state.pc:#x}')
        if self.expected and held_anywhere(state, self.expected):
            state.saturated_at_call = True
        state.records += 1
        state.clobbers += 1
        for n in CALLER_SAVED:
            state.regs[n] = atom('h', n, state.clobbers)
        state.xmm = {}
        state.flags = None

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
                raise Unsupported('16-bit immediate move')
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
            name = {4: 'shl', 5: 'shr', 7: 'sar'}.get(reg & 7)
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
            if action == 2 and op[0] == 'rip' and following + op[1] == RECORDER_SLOT:
                state.pc = insn.va
                self.call_recorder(state)
                state.pc = following
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


def held_anywhere(state, expected):
    if any(expected(value) for value in state.regs):
        return True
    return any(expected(slot[1]) for slot in state.mem.values())


def explore(image, rows, index, state, walker, keep_after_record):
    """Follow every feasible edge from state.  Return a list of paths, each a list of snapshots."""
    paths = []
    pending = [(state, [])]
    forks = 0
    while pending:
        current, log = pending.pop()
        while len(log) < STEP_LIMIT:
            position = index.get(current.pc)
            if position is None:
                break
            if current.records == (1 if keep_after_record else 0):
                log.append(current.clone())
            elif current.records > 1 or not keep_after_record:
                break
            try:
                outcome = walker.step(current, rows[position])
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
            forks += 1
            if forks > FORK_LIMIT:
                break
            other = current.clone()
            other.pc = target
            other.assume[test] = polarity
            pending.append((other, list(log)))
            current.assume[test] = not polarity
        paths.append(log)
    return paths


def compatible(first, second, root):
    for key, value in first.assume.items():
        if key != root and second.assume.get(key, value) != value:
            return False
    return True


def result_locations(over, normal, wanted, result):
    found = []
    for n in range(16):
        if wanted(over.regs[n]) and normal.regs[n] == result:
            found.append(REG_NAMES[n])
    for key in sorted(set(over.mem) | set(normal.mem), key=repr):
        if wanted(over.peek(key)) and normal.peek(key) == result:
            found.append(f'[{render(key)}]')
    return found


# --- sites and guards ------------------------------------------------------------------------

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


def find_guards(rows, targets, lea):
    """Return [(branch row, edge taken into the site)] for every conditional edge into the site."""
    entry = block_start(rows, targets, lea)
    guards = []
    for source in targets.get(rows[entry].va, ()):
        if is_jump(rows[source]):
            if not is_conditional(rows[source - 1]):
                fail(f'jmp at {rows[source].va:#x} follows no conditional branch')
            guards.append((source - 1, False))
        else:
            guards.append((source, True))
    if entry and is_conditional(rows[entry - 1]):
        guards.append((entry - 1, False))
    return sorted(set(guards))


def guard_state(image, rows, targets, guard, walker):
    """Run the block that ends in the guard from free values, restarting past opaque rows."""
    start = block_start(rows, targets, guard)
    start = max(start, guard - BACK_LIMIT)
    state = State()
    for k in range(start, guard):
        insn = rows[k]
        if is_conditional(insn):
            continue
        try:
            walker.step(state, insn)
        except Unsupported:
            state = State()
    return state


def analyse_guard(image, rows, index, targets, lea, record, kind, branch, taken_in):
    walker = Walker(image, record)
    state = guard_state(image, rows, targets, branch, walker)
    insn = rows[branch]
    cc = condition_code(insn)
    if state.flags is None:
        fail(f'no flags are set in the block of the guard at {insn.va:#x}')
    test, polarity = predicate(state.flags, cc)
    if test[0] == 'S' and kind == 'unsigned':
        # The sign bit of x is the carry out of x + x, so this is a doubling.
        op, left, right = 'add', test[1], test[1]
    elif test[0] in ('CF', 'OF') and (test[0] == 'OF') == (kind == 'signed'):
        op, left, right = test[1:]
    else:
        fail(f'guard at {insn.va:#x} does not test the {kind} overflow: {test[0]}')
    overflow_edge = polarity if taken_in else not polarity
    if overflow_edge is not True:
        fail(f'site at {lea:#x} is entered when the guard at {insn.va:#x} did not overflow')
    result = add(left, right) if op == 'add' else sub(left, right)
    if kind == 'signed':
        def wanted(value):
            return saturated_signed(value) == result
    else:
        saturated = konst(U64 if op == 'add' else 0)

        def wanted(value):
            return value == saturated
    walker.expected = wanted
    target, following = insn.target, insn.va + insn.size
    over, normal = state, state.clone()
    over.pc, normal.pc = (target, following) if taken_in else (following, target)
    over.assume[test] = True
    normal.assume[test] = False
    over_paths = explore(image, rows, index, over, walker, True)
    normal_paths = explore(image, rows, index, normal, walker, False)
    seen_lea = any(snapshot.records for path in over_paths for snapshot in path)
    if not seen_lea:
        fail(f'the overflow edge of {insn.va:#x} never reaches the recorder')
    joins, places, forms, cold_first = set(), set(), set(), False
    for path in over_paths:
        if not path:
            continue
        hit = None
        for first in path:
            for other in normal_paths:
                for second in other:
                    if first.pc == second.pc and compatible(first, second, test):
                        found = result_locations(first, second, wanted, result)
                        if found:
                            hit = (first.pc, found)
                            cold_first = cold_first or first.saturated_at_call
                            forms.update(compiled_form(v) for v in first.regs if wanted(v))
                            forms.update(compiled_form(slot[1]) for slot in first.mem.values() if wanted(slot[1]))
                            break
                if hit:
                    break
            if hit:
                break
        if hit is None:
            fail(f'overflow path of {insn.va:#x} for site {lea:#x} meets no location with the saturated result')
        joins.add(hit[0])
        places.update(hit[1])
    return {'lea': lea, 'guard': insn.va, 'guard_op': f'{data_hex(image, insn)}', 'edge': 'taken' if taken_in else 'fall',
            'operation': f'{op}-{kind}', 'left': render(left), 'right': render(right), 'result': render(result),
            'joins': sorted(joins), 'locations': sorted(places), 'saturated_before_call': cold_first,
            'forms': sorted(forms),
            'paths': len(over_paths) + len(normal_paths)}


def data_hex(image, insn):
    return image.data[insn.off:insn.off + insn.size].hex()


def analyse_site(image, rows, lea, record, kind):
    index = {insn.va: k for k, insn in enumerate(rows)}
    targets = branch_targets(rows)
    if lea not in index:
        fail(f'site {lea:#x} is not an instruction start of its function')
    guards = find_guards(rows, targets, index[lea])
    if not guards:
        fail(f'no conditional edge enters site {lea:#x}')
    return [analyse_guard(image, rows, index, targets, lea, record, kind, branch, taken) for branch, taken in guards]


# --- negative controls -----------------------------------------------------------------------

def flipped_condition(image, insn):
    raw = bytearray(image.data[insn.off:insn.off + insn.size])
    p = insn.body - insn.off
    if raw[p] == 0x0f:
        raw[p + 1] ^= 1
    else:
        raw[p] ^= 1
    return bytes(raw)


def destination(image, insn):
    """Name of the register an instruction writes, '[memory]' for a store, or None."""
    data, rex = image.data, insn.rex
    key = insn.key
    if isinstance(key, int) and 0xb8 <= key <= 0xbf:
        return REG_NAMES[(key & 7) | ((rex & 1) << 3)]
    if insn.modrm is None:
        return None
    op, reg = operand(data, insn.modrm, rex)
    into_rm = key in (0x01, 0x29, 0x31, 0xc1, 0xc7) or (isinstance(key, tuple) and 0x90 <= key[1] <= 0x9f)
    if not into_rm:
        return REG_NAMES[reg]
    return REG_NAMES[op[1]] if op[0] == 'r' else '[memory]'


def cold_mutations(image, rows, index, start, stop_at):
    """Yield (name, row, bytes) for the value-making rows of the cold run from `start`."""
    position = index[start]
    followed = 0
    for _ in range(40):
        insn = rows[position]
        if insn.va in stop_at or insn.key == 0xc3:
            return
        raw = bytearray(image.data[insn.off:insn.off + insn.size])
        p = insn.body - insn.off
        key = insn.key
        if key in (0x31, 0x33):
            modrm = raw[p + 1]
            if modrm >> 6 == 3 and (modrm >> 3) & 7 == modrm & 7 and insn.rex & 5 in (0, 5) and not (modrm & 7 == 7 and not insn.rex & 1):
                raw[p] = 0x09 if key == 0x31 else 0x0b
                yield 'xor-to-or', insn, bytes(raw)
        elif key == 0xc7 or (isinstance(key, int) and 0xb8 <= key <= 0xbf):
            raw[-1] ^= 1
            yield 'immediate', insn, bytes(raw)
        elif isinstance(key, tuple) and key[0] == 0x0f and (0x40 <= key[1] <= 0x4f or 0x90 <= key[1] <= 0x9f):
            raw[p + 1] ^= 1
            yield 'condition', insn, bytes(raw)
        elif key == 0xc1:
            raw[-1] ^= 1
            yield 'shift-count', insn, bytes(raw)
        elif key in (0x01, 0x03, 0x29, 0x2b):
            raw[p] ^= 0x28
            yield 'add-sub-swap', insn, bytes(raw)
        if is_jump(insn):
            followed += 1
            if followed > 1 or insn.target not in index:
                return
            position = index[insn.target]
            continue
        if is_conditional(insn) or key == 0xc3:
            return
        position += 1
        if position >= len(rows):
            return


def fails(image, fn, lea, record, kind, edits):
    damaged = image.patched(edits)
    try:
        rows = sweep(damaged, *fn)
        analyse_site(damaged, rows, lea, record, kind)
    except EvidenceError:
        return True
    return False


def site_controls(image, rows, fn, facts, record, kind):
    """Damage one site: drop its recorder, flip its guards, change its cold value-making rows."""
    index = {insn.va: k for k, insn in enumerate(rows)}
    lea = facts[0]['lea']
    position = index[lea]
    controls = []
    call = next(insn for insn in rows[position:] if insn.key == 0xff)
    nop = bytes.fromhex('660f1f440000')[:call.size]
    if call.size != 6:
        fail(f'recorder call at {call.va:#x} is {call.size} bytes')
    controls.append(('drop-recorder', call.va, None, fails(image, fn, lea, record, kind, [(call.va, nop)])))
    for item in facts:
        insn = rows[index[item['guard']]]
        controls.append(('flip-guard', insn.va, None, fails(image, fn, lea, record, kind, [(insn.va, flipped_condition(image, insn))])))
    entry = rows[block_start(rows, branch_targets(rows), position)].va
    stops = set()
    for item in facts:
        stops.update(item['joins'])
    seen = set()
    places = {place for item in facts for place in item['locations']}
    in_memory = any(place.startswith('[') for place in places)
    for name, insn, raw in cold_mutations(image, rows, index, entry, stops):
        if insn.va in seen:
            continue
        seen.add(insn.va)
        written = destination(image, insn)
        hits = written in places or (written == '[memory]' and in_memory)
        caught = fails(image, fn, lea, record, kind, [(insn.va, raw)])
        if hits and not caught:
            fail(f'damage at {insn.va:#x} changes a result location of site {lea:#x} and was not caught')
        controls.append((name, insn.va, written, caught))
    return controls


# --- whole packet -----------------------------------------------------------------------------

def analyse(image):
    records = location_records(image)
    lines = sorted({line for line, _ in records.values()})
    if lines != sorted(LINE_KIND):
        fail(f'Location lines {lines}')
    references = lea_references(image, records)
    data_references = sum(1 for addend in image.relocs.values() if addend in records)
    if image.relocs.get(RECORDER_SLOT) != RECORDER:
        fail(f'recorder slot holds {image.relocs.get(RECORDER_SLOT)}')
    by_function = {}
    for lea in sorted(references):
        by_function.setdefault(image.fde_of(lea), []).append(lea)
    facts, controls, excluded = [], [], []
    site_rows = {}
    for fn, leas in sorted(by_function.items()):
        rows = sweep(image, *fn)
        starts = {insn.va for insn in rows}
        if not starts.issuperset(leas):
            fail(f'a lea in {fn[0]:#x} is not an instruction start')
        if fn[0] in EXCLUDED_FUNCTIONS:
            excluded.append({'function': fn[0], 'end': fn[1], 'sites': len(leas), 'named_by': EXCLUDED_FUNCTIONS[fn[0]]})
            continue
        for lea in leas:
            record = references[lea]
            kind = LINE_KIND[records[record][0]]
            found = analyse_site(image, rows, lea, record, kind)
            for item in found:
                item.update({'function': fn[0], 'function_end': fn[1], 'record': record, 'line': records[record][0]})
            facts.extend(found)
            site_rows[lea] = found
            for name, va, written, caught in site_controls(image, rows, fn, found, record, kind):
                controls.append({'lea': lea, 'control': name, 'va': va, 'writes': written or '', 'caught': caught})
    if len(excluded) != len(EXCLUDED_FUNCTIONS):
        fail(f'{len(excluded)} of {len(EXCLUDED_FUNCTIONS)} excluded functions hold sites')
    operations = {}
    for item in facts:
        operations[item['operation']] = operations.get(item['operation'], 0) + 1
    forms = {}
    for item in facts:
        name = f'{item["operation"]}/{"+".join(item["forms"])}'
        forms[name] = forms.get(name, 0) + 1
    tally = {}
    for item in controls:
        row = tally.setdefault(item['control'], {'caught': 0, 'survived': 0})
        row['caught' if item['caught'] else 'survived'] += 1
    lemma = saturation_lemma()
    if not lemma['proved']:
        fail('saturation lemma failed')
    recorder_fde = image.fde_of(RECORDER)
    recorder_rows = sweep(image, *recorder_fde)
    recorder_returns = sum(1 for insn in recorder_rows if insn.key == 0xc3)
    if recorder_fde[0] != RECORDER or not recorder_returns:
        fail('the recorder is not a returning function at its FDE start')
    evidence = {
        'target_sha256': SHA256,
        'path': SHOWN_PATH,
        'recorder': {'slot': f'{RECORDER_SLOT:#x}', 'target': f'{RECORDER:#x}', 'fde_end': f'{recorder_fde[1]:#x}',
                     'instructions': len(recorder_rows), 'ret_rows': recorder_returns},
        'location_records': {f'{va:#x}': {'line': line, 'column': column}
                             for va, (line, column) in sorted(records.items())},
        'location_data_references': data_references,
        'lea_sites': len(references),
        'lea_sites_by_line': {str(line): sum(1 for r in references.values() if records[r][0] == line) for line in lines},
        'functions_holding_sites': len(by_function),
        'excluded_functions': len(excluded),
        'excluded_sites': sum(item['sites'] for item in excluded),
        'analysed_functions': len(by_function) - len(excluded),
        'analysed_sites': len(site_rows),
        'analysed_sites_by_line': {str(line): sum(1 for lea in site_rows if records[references[lea]][0] == line) for line in lines},
        'guards': len(facts),
        'guards_by_operation': dict(sorted(operations.items())),
        'guards_by_operation_and_form': dict(sorted(forms.items())),
        'guards_saturated_before_call': sum(1 for item in facts if item['saturated_before_call']),
        'saturation_lemma': lemma,
        'controls': dict(sorted(tally.items())),
        'survivors_writing_a_result_location': 0,
        'guards_doubling': sum(1 for item in facts if item['left'] == item['right']),
    }
    return evidence, facts, controls, excluded


def write_outputs(out, evidence, facts, controls, excluded):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    lines = ['function\tfunction_end\tline\tlea\tguard\tguard_bytes\tedge\toperation\tleft\tright\tresult\tjoins\tlocations\tcompiled_form\tsaturated_before_call']
    for item in sorted(facts, key=lambda row: (row['lea'], row['guard'])):
        lines.append('\t'.join((f'{item["function"]:#x}', f'{item["function_end"]:#x}', str(item['line']), f'{item["lea"]:#x}',
                                f'{item["guard"]:#x}', item['guard_op'], item['edge'], item['operation'], item['left'],
                                item['right'], item['result'], ','.join(f'{j:#x}' for j in item['joins']),
                                ';'.join(item['locations']), ';'.join(item['forms']),
                                str(item['saturated_before_call']).lower())))
    (out / 'sz-sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['lea\tcontrol\tva\twrites\tcaught']
    for item in controls:
        lines.append(f'{item["lea"]:#x}\t{item["control"]}\t{item["va"]:#x}\t{item["writes"]}\t{str(item["caught"]).lower()}')
    (out / 'mutation-controls.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['function\tend\tsites\tnamed_by']
    for item in excluded:
        lines.append(f'{item["function"]:#x}\t{item["end"]:#x}\t{item["sites"]}\t{item["named_by"]}')
    (out / 'excluded-functions.tsv').write_text('\n'.join(lines) + '\n')


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
