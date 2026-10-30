#!/usr/bin/env python3
"""RE-004: usdc_ntl_scale, the f64 at dex record +0x2a0 in node #94 (static).

The field is named by a serde key read from bytes.  The tool checks three things:

    writer    3 copies.  With (ok, v) returned by 0x32814c0, the field becomes v / 1e9 when ok is
              set and v < 0x28f5c28f5c28f5c, else 1.0.  Branches hold for every (ok, v); the
              conversion itself is checked on vectors, see scaled_vectors().
    clamp     6 sites.  p = x * scale goes through one f64 to i64 chain.  Every one of the 2^64
              f64 bit patterns falls in a listed piece.
    gate      0x370c100 returns x unchanged above 0x28f5c28f5c28f5c, for every u64 x.

The proof method is interval refinement over the real bytes.  Inputs are 64-bit parameters u
(the f64 bit pattern, or the integer).  A piece [lo, hi] is finished when runs from both ends
give the same record of compares.  Values that depend on u are tracked as monotone in u, and each
compare has a constant on the other side, so a compare that agrees at both ends agrees on the
whole piece.  Anything outside the modelled instruction list stops the tool.

    python3 tools/usdc_ntl_scale.py --out <dir>

writes evidence.json, field-binding.tsv, field-uses.tsv, callers.tsv, writer-copies.tsv,
writer-pieces.tsv, clamp-sites.tsv, clamp-pieces.tsv, gate-pieces.tsv and mutation-controls.tsv.
Only the Python standard library is used; objdump is not.  Nothing from the binary runs.
"""

import argparse
import bisect
import hashlib
import json
import math
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
SIGN = 1 << 63
ABS_MASK = SIGN - 1
FIELD = 0x2a0
KEY = b'usdc_ntl_scale'
TOKEN_KEY = b'collateralToken'
SCALE_GATE = 0x28f5c28f5c28f5c      # floor(u64::MAX / 100)
CLAMP = 0x147ae147ae147ae           # floor(i64::MAX / 100)
ONE_BITS = 0x3ff0000000000000
INT_MIN = 1 << 63
INF_BITS = 0x7ff0000000000000
ABS_OVERFLOW_LOCATION = 0x5714da0
PATH_ROOT = '/l1/src/'
SLOT_HELPERS = {0x370c100: 0x5774cd8, 0x370c1e0: 0x5774b60}
MUL_DIV_TOKEN = 0x32814c0
DEFAULT_PRICE = 0x375fb50
DEFAULT_PRICE_SLOT = 0x5774548

# Serializers of the record: the load of the field.
SERIALIZERS = (0x26c91d8, 0x370c992, 0x4ca7b98)

# The writer copies: (function, the store, first instruction after the call, cap movabs).
WRITERS = (
    (0x26fd370, 0x26fd900, 0x26fd9d4, 0x26fd8e5),
    (0x4ce4d00, 0x4ce5290, 0x4ce5364, 0x4ce5275),
    (0x4ce5470, 0x4ce5a00, 0x4ce5ad4, 0x4ce59e5))

# Consumers: (mulsd, nonneg, seeds).  Seeds are registers that hold a constant at the site; they
# are checked by holds_constant() and the note says how.
CONSUMERS = (
    (0x370c118, True, {}),
    (0x370c1e5, False, {}),
    (0x3706eb3, False, {5: ABS_MASK}),
    (0x276896f, False, {3: ABS_MASK}),
    (0x4d9ca4f, False, {3: ABS_MASK}),
    (0x4d9d62f, False, {3: ABS_MASK}))

# Field sites in functions named by other work items or open pull requests: listed, not read.
OVERLAP = {
    0x26b93b0: 'open #131', 0x26f6110: 'open #38, #131', 0x270f6f0: 'open #38, #131',
    0x2727f30: 'open #131', 0x2732e60: 'open #38, #131', 0x2735040: 'open #38, #131',
    0x37153f0: 'open #80, #109', 0x46e8290: 'open #38, #131', 0x46e89a0: 'open #38, #131',
    0x4cda260: 'open #38, #131', 0x4cdabd0: 'open #38, #131', 0x4d2ff60: 'open #131',
    0x4d308e0: 'open #131', 0x4d41320: 'open #38, #131', 0x4d430e0: 'open #38, #131',
    0x4d45300: 'open #38, #131', 0x4d47ec0: 'open #38, #131'}

# Field-displacement sites whose owner is not established here.
NOT_READ = {0x1457070: 'not read here', 0x484c6a0: 'not read here: indexed store beside +0x288 and +0x298'}

MAX_STEPS = 400
RSP = 4
RDX = 2
RAX = 0


class EvidenceError(Exception):
    pass


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

    def read(self, va, size):
        off = self.file_offset(va)
        return self.data[off:off + size]

    def fde_of(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            fail(f'{va:#x} is outside every FDE')
        return self.fdes[i]


def location(image, va):
    """(path below the repository root, line, column) of a Rust Location record."""
    if va not in image.relocs:
        fail(f'no relocation at Location {va:#x}')
    length, line, column = struct.unpack_from('<QII', image.read(va + 8, 16))
    path = image.read(image.relocs[va], length).decode('ascii')
    if PATH_ROOT in path:
        path = 'l1/src/' + path.split(PATH_ROOT, 1)[1]
    elif path.startswith('/rustc/'):
        path = 'rustc/' + path.split('/', 3)[3]
    return path, line, column


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
    rows = {}
    va = start
    delta = image.text['offset'] - image.text['address']
    while va < end:
        insn = decode(image.data, va + delta, va)
        rows[va] = insn
        va += insn.size
    if va != end:
        fail(f'sweep of {start:#x} ended at {va:#x}, FDE ends at {end:#x}')
    return rows


# --- evaluator over real bytes --------------------------------------------------------------
#
# GPR value: (value, moving, form).  XMM value: (low, high, moving, form).  `moving` is 0 for a
# constant over the piece and 1 for a monotone function of the input parameter; 2 marks an XMM
# value that may be carried but never compared.  `form` names the value at the exit.

def to_float(bits):
    return struct.unpack('<d', struct.pack('<Q', bits))[0]


def to_bits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]


class Run:
    def __init__(self, image, rows, regs, xmm):
        self.image, self.rows = image, rows
        self.regs, self.xmm = regs, xmm
        self.trace = []
        self.flags = None
        self.exit = None

    def compare_int(self, va, a, b):
        if a[1] and b[1]:
            fail(f'two moving operands at {va:#x}')
        moving = a if a[1] else b
        left, right = a[0], b[0]
        if moving[1]:
            self.trace.append((va, (left > right) - (left < right), moving[0] >> 63))
        result = (left - right) & U64
        self.flags = {'cf': left < right, 'zf': result == 0, 'sf': result >> 63 == 1,
                      'of': ((left ^ right) & (left ^ result)) >> 63 == 1, 'pf': False}

    def compare_float(self, va, a, b, same):
        left, right = to_float(a[0]), to_float(b[0])
        if same:
            self.trace.append((va, 'nan', math.isnan(left)))
        elif a[2] == 2 or b[2] == 2 or (a[2] and b[2]):
            fail(f'unsupported float compare at {va:#x}')
        elif a[2] or b[2]:
            self.trace.append((va, 'ord', left > right, left < right, left == right))
        unordered = math.isnan(left) or math.isnan(right)
        self.flags = {'cf': unordered or left < right, 'zf': unordered or left == right,
                      'pf': unordered, 'sf': False, 'of': False}

    def condition(self, code):
        f = self.flags
        if f is None:
            fail('branch before any compare')
        base = {0: f['of'], 1: f['cf'], 2: f['zf'], 3: f['cf'] or f['zf'], 4: f['sf'], 5: f['pf'],
                6: f['sf'] != f['of'], 7: f['zf'] or f['sf'] != f['of']}[code >> 1]
        return base != bool(code & 1)

    def run(self, start, stop):
        va = start
        for _ in range(MAX_STEPS):
            if va == stop:
                self.exit = ('stop',)
                return self
            insn = self.rows.get(va)
            if insn is None:
                fail(f'execution left the sweep at {va:#x}')
            va = self.step(insn)
            if va is None:
                return self
        fail(f'step budget used from {start:#x}')

    def step(self, insn):
        d = self.image.data
        key, rex, va = insn.key, insn.rex, insn.va
        pre = d[insn.off:insn.body]
        wide = bool(rex & 8)
        following = va + insn.size
        reg = rm = mod = 0
        if insn.modrm is not None:
            byte = d[insn.modrm]
            mod, reg, rm = byte >> 6, ((byte >> 3) & 7) | ((rex & 4) << 1), (byte & 7) | ((rex & 1) << 3)

        def memory(size):
            if mod != 0 or d[insn.modrm] & 7 != 5:
                fail(f'only rip-relative memory is modelled at {va:#x}')
            disp = struct.unpack_from('<i', d, insn.modrm + 1)[0]
            return self.image.read(following + disp, size)

        def xmm_source():
            if mod == 3:
                return self.xmm[rm]
            low, high = struct.unpack('<QQ', memory(16))
            return (low, high, 0, 'const')

        if isinstance(key, int) and 0x70 <= key <= 0x7f:
            return insn.target if self.condition(key & 15) else following
        if key == 0xeb or key == 0xe9:
            return insn.target
        if isinstance(key, tuple) and len(key) == 2 and key[0] == 0x0f and 0x80 <= key[1] <= 0x8f:
            return insn.target if self.condition(key[1] & 15) else following
        if key == 0xc3:
            self.exit = ('ret',)
            return None
        if key in (0x50, 0x90):
            return following
        if key == 0x8d and mod == 0 and d[insn.modrm] & 7 == 5 and reg == 7:
            disp = struct.unpack_from('<i', d, insn.modrm + 1)[0]
            after = self.rows.get(following)
            if after is None or after.key != 0xff:
                fail(f'lea rdi at {va:#x} is not a panic call')
            self.exit = ('panic', following + disp)
            return None
        if key == 0x89 and mod == 3 and wide:
            self.regs[rm] = self.regs[reg]
            return following
        if key == 0x8b and mod == 3 and wide:
            self.regs[reg] = self.regs[rm]
            return following
        if key == 0x85 and mod == 3 and wide and reg == rm:
            self.compare_int(va, self.regs[rm], (0, 0, 'const'))
            return following
        if key == 0x39 and mod == 3 and wide:
            self.compare_int(va, self.regs[rm], self.regs[reg])
            return following
        if key == 0x3b and mod == 3 and wide:
            self.compare_int(va, self.regs[reg], self.regs[rm])
            return following
        if key == 0x31 and mod == 3 and reg == rm:
            self.regs[rm] = (0, 0, 'const')
            self.flags = None
            return following
        if key in (0x21, 0x23) and mod == 3 and wide:
            into, other = (rm, reg) if key == 0x21 else (reg, rm)
            target, mask = self.regs[into], self.regs[other]
            if mask[1] or mask[0] != ABS_MASK:
                fail(f'and at {va:#x} is not the sign mask')
            self.regs[into] = (target[0] & mask[0], target[1], target[2])
            self.flags = None
            return following
        if key == 0xf7 and mod == 3 and wide and (d[insn.modrm] >> 3) & 7 == 3:
            value, moving, form = self.regs[rm]
            result = -value & U64
            if moving:
                self.trace.append((va, 'neg', value == INT_MIN, value == 0))
            self.regs[rm] = (result, moving, f'neg({form})')
            self.flags = {'cf': value != 0, 'zf': value == 0, 'sf': result >> 63 == 1,
                          'of': value == INT_MIN, 'pf': False}
            return following
        if isinstance(key, int) and 0xb8 <= key <= 0xbf:
            number = (key - 0xb8) | ((rex & 1) << 3)
            raw = d[insn.body + 1:insn.body + 1 + (8 if wide else 4)]
            self.regs[number] = (int.from_bytes(raw, 'little'), 0, 'const')
            return following
        if key == 0xa8:
            value = self.regs[RAX]
            if value[1]:
                fail(f'test al at {va:#x} on a moving value')
            result = value[0] & d[insn.off + 1]
            self.flags = {'cf': False, 'zf': result & 0xff == 0, 'sf': False, 'of': False, 'pf': False}
            return following
        if isinstance(key, tuple) and key[0] == 0x0f and len(key) == 2:
            two = key[1]
            if 0x40 <= two <= 0x4f and mod == 3 and wide:
                if self.condition(two & 15):
                    self.regs[reg] = self.regs[rm]
                return following
            mandatory = next((b for b in pre if b in (0x66, 0xf2, 0xf3)), None)
            return self.sse(insn, two, mandatory, wide, mod, reg, rm, memory, xmm_source, following)
        fail(f'instruction outside the model at {va:#x}')

    def sse(self, insn, two, mandatory, wide, mod, reg, rm, memory, xmm_source, following):
        va = insn.va
        if mandatory == 0xf2:
            if two == 0x10 and mod != 3:
                self.xmm[reg] = (struct.unpack('<Q', memory(8))[0], 0, 0, 'const')
            elif two == 0x2c and wide and mod == 3:
                self.truncate(va, reg, self.xmm[rm])
            elif two == 0x2a and wide and mod == 3:
                value = self.regs[rm]
                bits = to_bits(float(value[0] - (1 << 64) if value[0] >> 63 else value[0]))
                self.xmm[reg] = (bits, 0, 1 if value[1] else 0, 'float(x)')
            elif two in (0x5f, 0x5d) and mod == 3:
                self.extreme(va, two, reg, rm)
            elif two in (0x58, 0x5e):
                top = self.xmm[reg]
                if mod == 3:
                    source = self.xmm[rm]
                else:
                    source = (struct.unpack('<Q', memory(8))[0], 0, 0, 'const')
                left, right = to_float(top[0]), to_float(source[0])
                value = left + right if two == 0x58 else left / right
                self.xmm[reg] = (to_bits(value), top[1], 2, 'carried')
            else:
                fail(f'sse form outside the model at {va:#x}')
            return following
        if mandatory == 0x66:
            if two == 0x7e and wide and mod == 3:
                value = self.xmm[reg]
                self.regs[rm] = (value[0], 1 if value[2] else 0, 'bits(p)')
            elif two == 0x6e and wide and mod == 3:
                value = self.regs[rm]
                self.xmm[reg] = (value[0], 0, 2 if value[1] else 0, 'carried')
            elif two == 0x2e:
                a = self.xmm[reg]
                b = xmm_source()
                self.compare_float(va, a, b, mod == 3 and reg == rm)
            elif two in (0x57, 0xef) and mod == 3 and reg == rm:
                self.xmm[reg] = (0, 0, 0, 'const')
            elif two in (0x28, 0x6f) and mod == 3:
                self.xmm[reg] = self.xmm[rm]
            elif two == 0x62:
                top, source = self.xmm[reg], xmm_source()
                low = (top[0] & 0xffffffff) | (source[0] & 0xffffffff) << 32
                high = (top[0] >> 32) | (source[0] >> 32) << 32
                self.xmm[reg] = (low, high, top[2], 'carried')
            elif two == 0x5c:
                top, source = self.xmm[reg], xmm_source()
                low = to_bits(to_float(top[0]) - to_float(source[0]))
                high = to_bits(to_float(top[1]) - to_float(source[1]))
                self.xmm[reg] = (low, high, top[2], 'carried')
            elif two == 0x15 and mod == 3:
                top, source = self.xmm[reg], self.xmm[rm]
                self.xmm[reg] = (top[1], source[1], 2 if top[2] or source[2] else 0, 'carried')
            else:
                fail(f'sse form outside the model at {va:#x}')
            return following
        fail(f'sse form outside the model at {va:#x}')

    def truncate(self, va, reg, source):
        value = to_float(source[0])
        inside = not math.isnan(value) and -9223372036854775808.0 <= value < 9223372036854775808.0
        if source[2] == 2:
            fail(f'truncate of an uncompared value at {va:#x}')
        if source[2]:
            self.trace.append((va, 'range', inside))
        if inside:
            self.regs[reg] = (int(value) & U64, source[2], 'trunc(p)' if source[2] else 'const')
        else:
            self.regs[reg] = (INT_MIN, 0, 'const')

    def extreme(self, va, two, reg, rm):
        top, source = self.xmm[reg], self.xmm[rm]
        if top[2] and source[2]:
            fail(f'two moving operands at {va:#x}')
        left, right = to_float(top[0]), to_float(source[0])
        if math.isnan(left) or math.isnan(right) or left == right:
            chosen = source
        elif two == 0x5f:
            chosen = top if left > right else source
        else:
            chosen = top if left < right else source
        if top[2] or source[2]:
            self.trace.append((va, 'pick', chosen is top))
        self.xmm[reg] = (chosen[0], top[1], chosen[2], chosen[3])


def refine(evaluate, seeds):
    """Split seeds until both ends of each piece agree.  evaluate(u) gives (trace, output)."""
    pieces = []
    stack = list(reversed(seeds))
    runs = 0
    while stack:
        lo, hi = stack.pop()
        first = evaluate(lo)
        runs += 1
        if lo == hi:
            pieces.append((lo, hi, first, first))
            continue
        last = evaluate(hi)
        runs += 1
        if first[0] == last[0] and first[1][0] == last[1][0]:
            pieces.append((lo, hi, first, last))
            continue
        middle = (lo + hi) // 2
        stack.append((middle + 1, hi))
        stack.append((lo, middle))
    return pieces, runs


def merged(pieces):
    """Join adjacent pieces of one seed with the same compare record and the same output form."""
    rows = []
    for lo, hi, first, last in pieces:
        if rows and rows[-1][1] + 1 == lo and rows[-1][2][0] == first[0] and rows[-1][2][1][0] == first[1][0]:
            rows[-1] = (rows[-1][0], hi, rows[-1][2], last)
        else:
            rows.append((lo, hi, first, last))
    return rows


# --- clamp sites ----------------------------------------------------------------------------

FLOAT_SEEDS = ((0, INF_BITS - 1), (INF_BITS, INF_BITS), (INF_BITS + 1, SIGN - 1),
               (SIGN, SIGN | (INF_BITS - 1)), (SIGN | INF_BITS, SIGN | INF_BITS), (SIGN | (INF_BITS + 1), U64))


def clamp_model(bits, nonneg):
    """Closed form of the chain: ('zero'|'panic'|'cap'|'-cap'|'trunc', value or None)."""
    p = to_float(bits)
    if math.isnan(p) or math.isinf(p):
        return ('const', 0)
    if p <= -9223372036854775808.0:
        return ('panic', ABS_OVERFLOW_LOCATION)
    t = SIGN - 1 if p >= 9223372036854775808.0 else int(p)
    if t > CLAMP:
        return ('const', CLAMP)
    if nonneg:
        return ('trunc', t) if t > 0 else ('const', 0)
    if t < -CLAMP:
        return ('const', -CLAMP & U64)
    return ('trunc', t & U64)


def inline_stop(image, rows, start):
    """Inline sites end at the join that the first jbe after the cap compare jumps to."""
    va = start
    for _ in range(64):
        insn = rows[va]
        if insn.key == 0x76:
            return insn.target
        va += insn.size
    fail(f'no join after {start:#x}')


def holds_constant(image, rows, site, reg, value):
    """The register is loaded by movabs earlier in the function; see the README for the walk."""
    want = bytes([0x49 if reg > 7 else 0x48, 0xb8 + (reg & 7)]) + struct.pack('<Q', value)
    return any(image.data[i.off:i.off + 10] == want for va, i in rows.items() if va < site)


def clamp_output(run, out):
    if run.exit[0] == 'panic':
        return ('panic', run.exit[1])
    value = run.regs[out]
    if value[1]:
        if value[2] != 'trunc(p)':
            fail(f'moving exit value {value[2]}')
        return ('trunc', value[0])
    return ('const', value[0])


def clamp_evaluator(image, mulsd, seeds):
    """The function u -> (compare record, exit value) of one site, and its FDE and join."""
    fn = image.fde_of(mulsd)
    rows = sweep(image, *fn)
    insn = rows.get(mulsd)
    if insn is None or insn.key != (0x0f, 0x59):
        fail(f'no mulsd at {mulsd:#x}')
    sib = 1 if image.data[insn.modrm] & 7 == 4 else 0
    if struct.unpack_from('<i', image.data, insn.modrm + 1 + sib)[0] != FIELD:
        fail(f'mulsd at {mulsd:#x} does not read the field')
    start = mulsd + insn.size
    helper = fn[0] in SLOT_HELPERS
    stop = None if helper else inline_stop(image, rows, start)
    for reg, value in seeds.items():
        if not holds_constant(image, rows, mulsd, reg, value):
            fail(f'no movabs of register {reg} before {mulsd:#x}')

    def evaluate(bits):
        regs = {r: (0, 0, 'const') for r in range(16)}
        regs.update({r: (v, 0, 'const') for r, v in seeds.items()})
        xmm = {x: (0, 0, 0, 'const') for x in range(16)}
        xmm[0] = (bits, 0, 1, 'p')
        run = Run(image, rows, regs, xmm)
        run.run(start, stop)
        if run.exit[0] == 'ret' and not helper:
            fail(f'inline site {mulsd:#x} returned')
        return run.trace, clamp_output(run, RAX)

    return evaluate, fn, stop


def analyse_clamp(image, mulsd, nonneg, seeds):
    """Refine one site over all 2^64 bit patterns and hold each piece to the closed form."""
    evaluate, fn, stop = clamp_evaluator(image, mulsd, seeds)
    rows_out = []
    runs = 0
    for lo, hi in FLOAT_SEEDS:
        pieces, used = refine(evaluate, [(lo, hi)])
        runs += used
        rows_out.extend(merged(pieces))
    for lo, hi, first, last in rows_out:
        for bits, out in ((lo, first[1]), (hi, last[1])):
            if clamp_model(bits, nonneg) != out:
                fail(f'site {mulsd:#x}: bits {bits:#x} gave {out}, model {clamp_model(bits, nonneg)}')
    return {'mulsd': mulsd, 'function': fn[0], 'nonneg': nonneg, 'stop': stop, 'pieces': rows_out, 'runs': runs}


def analyse_gate(image):
    """0x370c100 entry over all u64 x: x above the gate comes back, the rest reach the multiply."""
    start, end = image.fde_of(0x370c100)
    rows = sweep(image, start, end)
    mulsd = CONSUMERS[0][0]

    def evaluate(x):
        regs = {r: (0, 0, 'const') for r in range(16)}
        regs[6] = (x, 1, 'x')
        xmm = {n: (0, 0, 0, 'const') for n in range(16)}
        run = Run(image, rows, regs, xmm)
        run.run(start, mulsd)
        if run.exit[0] == 'ret':
            return run.trace, ('returned', run.regs[RAX][2], run.regs[RAX][0])
        return run.trace, ('multiplied', run.xmm[0][3], run.xmm[0][0])

    pieces, runs = refine(evaluate, [(0, U64)])
    rows_out = merged(pieces)
    for lo, hi, first, last in rows_out:
        for x, out in ((lo, first[1]), (hi, last[1])):
            if x > SCALE_GATE:
                ok = out[:2] == ('returned', 'x') and out[2] == x
            else:
                ok = out[:2] == ('multiplied', 'float(x)') and out[2] == to_bits(float(x))
            if not ok:
                fail(f'gate: x {x:#x} gave {out}')
    if len(rows_out) < 2:
        fail('gate has no split')
    return rows_out, runs


# --- writer ---------------------------------------------------------------------------------

def scaled_vectors():
    """Edges of the u64 to f64 chain plus 2048 values of a fixed generator."""
    values = [0, 1, 2, 3, 999999999, 10 ** 9, 10 ** 9 + 1, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, (1 << 52) - 1,
              1 << 52, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 53) + 3, (1 << 54) + 2, SCALE_GATE - 1]
    state = 0x9e3779b97f4a7c15
    for _ in range(2048):
        state = (state * 0xd1342543de82ef95 + 1) & U64
        values.append((state >> (state & 63)) % SCALE_GATE)
    return values


def writes_register(image, insn, number):
    """A plain write to a 64-bit register by mov, lea, movabs or a two-register ALU form."""
    key, rex = insn.key, insn.rex
    if insn.modrm is None:
        return isinstance(key, int) and 0xb8 <= key <= 0xbf and ((key - 0xb8) | ((rex & 1) << 3)) == number
    byte = image.data[insn.modrm]
    reg, rm = ((byte >> 3) & 7) | ((rex & 4) << 1), (byte & 7) | ((rex & 1) << 3)
    if key in (0x8b, 0x8d):
        return reg == number
    return key in (0x89, 0x01, 0x29, 0x31, 0x21, 0x09) and byte >> 6 == 3 and rm == number


def writer_row_facts(image, rows, store, tail, cap_row):
    """Bytes around the tail that tie it to the record loop."""
    index = sorted(rows)
    if image.read(store, 8) != bytes.fromhex('f20f1183a0020000'):
        fail(f'no field store at {store:#x}')
    call = index[index.index(tail) - 1]
    insn = rows[call]
    if insn.key != 0xe8 or insn.target != MUL_DIV_TOKEN:
        fail(f'no call of {MUL_DIV_TOKEN:#x} before {tail:#x}')
    if image.read(cap_row, 10) != bytes.fromhex('49bd') + struct.pack('<Q', SCALE_GATE):
        fail(f'no cap in r13 at {cap_row:#x}')
    back = [rows[v] for v in index[max(0, index.index(call) - 5):index.index(call)]]
    if not any(image.data[i.off:i.off + 5] == bytes.fromhex('bf00ca9a3b') for i in back):
        fail(f'no 1e9 argument before {call:#x}')
    slot_call = next((i for i in back if image.data[i.off:i.off + 2] == b'\xff\x15'), None)
    if slot_call is None:
        fail(f'no default price call before {call:#x}')
    slot = slot_call.va + 6 + struct.unpack_from('<i', image.data, slot_call.off + 2)[0]
    if slot != DEFAULT_PRICE_SLOT or image.relocs.get(slot) != DEFAULT_PRICE:
        fail(f'slot {slot:#x} is not the default price helper')
    key_load = next((v for v in index if v > cap_row and image.read(v, 4) == bytes.fromhex('4c8b6350')), None)
    if key_load is None:
        fail(f'no load of record +0x50 after {cap_row:#x}')
    for v in index:
        if store <= v < tail and writes_register(image, rows[v], 13):
            fail(f'r13 written at {v:#x}')
    return {'call': call, 'key_load': key_load, 'slot_call': slot_call.va}


def analyse_writer(image, fn, store, tail, cap_row):
    start, end = image.fde_of(store)
    if start != fn:
        fail(f'{store:#x} is not in {fn:#x}')
    rows = sweep(image, start, end)
    facts = writer_row_facts(image, rows, store, tail, cap_row)
    cap = (int.from_bytes(image.read(cap_row + 2, 8), 'little'), 0, 'const')

    def evaluator(status):
        def evaluate(v):
            regs = {r: (0, 0, 'const') for r in range(16)}
            regs[13] = cap
            regs[RDX] = (v, 1, 'v')
            regs[RAX] = (status, 0, 'const')
            xmm = {x: (0, 0, 0, 'const') for x in range(16)}
            run = Run(image, rows, regs, xmm)
            run.run(tail, store)
            value = run.xmm[0]
            return run.trace, ('scaled' if value[2] else 'const', value[0])
        return evaluate

    table = []
    runs = 0
    for status in (0, 1, 2, 3):
        pieces, used = refine(evaluator(status), [(0, U64)])
        runs += used
        for lo, hi, first, last in merged(pieces):
            table.append((status, lo, hi, first[1][0], first[1][1], last[1][1]))
    for status, lo, hi, kind, first, last in table:
        want = 'scaled' if status & 1 and hi < SCALE_GATE else 'const'
        if kind != want or (status & 1 and lo < SCALE_GATE <= hi):
            fail(f'writer {fn:#x}: status {status} [{lo:#x},{hi:#x}] is {kind}')
        if kind == 'const' and (first, last) != (ONE_BITS, ONE_BITS):
            fail(f'writer {fn:#x}: default is not 1.0')
    evaluate = evaluator(1)
    vectors = scaled_vectors()
    for v in vectors:
        out = evaluate(v)[1]
        if out[1] != to_bits(float(v) / 1e9):
            fail(f'writer {fn:#x}: v {v:#x} gave {out[1]:#x}')
    compare = next(a for a in sorted(rows) if a > tail and image.read(a, 3) == bytes.fromhex('4c39ea'))
    shape = {0x72: 'jb', 0x73: 'jae'}[image.read(compare + 3, 1)[0]]
    return {'function': fn, 'store': store, 'tail': tail, 'cap_row': cap_row, 'facts': facts, 'table': table,
            'runs': runs, 'vectors': len(vectors), 'shape': shape}


# --- field binding and census ---------------------------------------------------------------

def field_key(image, helper):
    """The key text a one-field serializer helper emits: lea rsi,[rip+d]; mov edx,len."""
    start, end = image.fde_of(helper)
    if start != helper:
        fail(f'{helper:#x} is not a function start')
    rows = sweep(image, start, end)
    order = sorted(rows)
    for here, there in zip(order, order[1:]):
        a, b = image.read(here, 3), image.read(there, 1)
        if a[:2] == b'\x48\x8d' and a[2] == 0x35 and b == b'\xba':
            target = there + struct.unpack_from('<i', image.read(here + 3, 4))[0]
            length = struct.unpack('<I', image.read(there + 1, 4))[0]
            return target, image.read(target, length)
    fail(f'no key in {helper:#x}')


def neighbour_keys(image, table, order, position, step):
    """The nearest lea r8,[r15+offset]; lea rdx,[rip+key]; ...; mov ecx,len in one direction."""
    limit = position + 12 * step
    for i in range(position, limit, step):
        here = order[i]
        if image.read(here, 3) != bytes.fromhex('4d8d87'):
            continue
        offset = struct.unpack('<I', image.read(here + 3, 4))[0]
        next_row = order[i + 1]
        if image.read(next_row, 3) != bytes.fromhex('488d15'):
            fail(f'no key lea after {here:#x}')
        target = next_row + 7 + struct.unpack('<i', image.read(next_row + 3, 4))[0]
        for v in order[i + 2:i + 5]:
            if image.read(v, 1) == b'\xb9':
                length = struct.unpack('<I', image.read(v + 1, 4))[0]
                return offset, image.read(target, length).decode('ascii')
        fail(f'no key length after {here:#x}')
    fail(f'no neighbour field near {order[position]:#x}')


def token_key(image, table, order):
    """The key emitted before mov rdx,[r15+0x50]: lea rsi,[rip+d]; mov edx,len."""
    for i, v in enumerate(order):
        if image.read(v, 4) != bytes.fromhex('498b5750'):
            continue
        for w, x in zip(order[max(0, i - 6):i], order[max(0, i - 6) + 1:i + 1]):
            if image.read(w, 3) == bytes.fromhex('488d35') and image.read(x, 1) == b'\xba':
                target = w + 7 + struct.unpack('<i', image.read(w + 3, 4))[0]
                length = struct.unpack('<I', image.read(x + 1, 4))[0]
                return v, target, image.read(target, length)
    return None


def binding_rows(image):
    rows = []
    for load in SERIALIZERS:
        if image.read(load, 8)[:4] != bytes.fromhex('f2410f10') or image.read(load + 5, 4) != struct.pack('<I', FIELD):
            fail(f'no field load at {load:#x}')
        fn = image.fde_of(load)
        table = sweep(image, *fn)
        order = sorted(table)
        pos = order.index(load)
        call = next(table[v] for v in order[pos:pos + 5] if table[v].key == 0xe8)
        address, key = field_key(image, call.target)
        if key != KEY:
            fail(f'key {key!r} at {address:#x}')
        before = neighbour_keys(image, table, order, pos, -1)
        after = neighbour_keys(image, table, order, pos, 1)
        found = token_key(image, table, order)
        if found is None:
            token_load, token_address, token = 0, 0, b'-'
        else:
            token_load, token_address, token = found
            if token != TOKEN_KEY:
                fail(f'key {token!r} at {token_address:#x}')
        rows.append((load, fn[0], call.va, call.target, address, key.decode(), before[0], before[1], after[0], after[1],
                     token_load, token_address, token.decode()))
    if not any(row[12] == TOKEN_KEY.decode() for row in rows):
        fail('no serializer names the record key')
    return rows


def field_uses(image):
    """Every scalar SSE load, store or multiply with displacement 0x2a0 in .text."""
    names = {0x59: 'mulsd', 0x10: 'load', 0x11: 'store'}
    wide_names = {0x10: 'load16', 0x11: 'store16'}
    base, off, size = image.text['address'], image.text['offset'], image.text['size']
    text = image.data[off:off + size]
    rows = []
    for match in re.finditer(re.escape(struct.pack('<I', FIELD)), text):
        p = match.start()
        for back in (4, 5, 6):
            q = p - back
            j = q
            if text[j] not in (0xf2, 0x66):
                continue
            prefix = text[j]
            j += 1
            rex = 0
            if 0x40 <= text[j] <= 0x4f:
                rex = text[j]
                j += 1
            if text[j] != 0x0f or text[j + 1] not in names:
                continue
            modrm = text[j + 2]
            sib = modrm & 7 == 4
            if modrm >> 6 != 2 or j + 3 + (1 if sib else 0) != p:
                continue
            if prefix == 0x66 and text[j + 1] not in wide_names:
                continue
            number = (modrm & 7) | ((rex & 1) << 3)
            if sib:
                number = (text[j + 3] & 7) | ((rex & 1) << 3)
            va = base + q
            fn = image.fde_of(va)
            kind = wide_names[text[j + 1]] if prefix == 0x66 else names[text[j + 1]]
            rows.append((va, kind, number, sib, fn[0]))
    return sorted(rows)


def use_class(row):
    va, kind, number, sib, fn = row
    if fn in OVERLAP:
        return 'listed, not read: ' + OVERLAP[fn]
    if fn in NOT_READ:
        return NOT_READ[fn]
    if number == RSP:
        return 'stack slot, not the field'
    if va in SERIALIZERS:
        return 'serializer load, key read'
    if any(va == c[0] for c in CONSUMERS):
        return 'clamp site, proved'
    if any(va == w[1] for w in WRITERS):
        return 'writer store, proved'
    return 'unclassified'


def slot_callers(image):
    base, off, size = image.text['address'], image.text['offset'], image.text['size']
    text = image.data[off:off + size]
    wanted = {slot: helper for helper, slot in SLOT_HELPERS.items()}
    for slot, helper in wanted.items():
        if image.relocs.get(slot) != helper:
            fail(f'slot {slot:#x} does not hold {helper:#x}')
    rows = []
    for match in re.finditer(b'\xff\x15', text):
        p = match.start()
        target = base + p + 6 + struct.unpack_from('<i', text, p + 2)[0]
        if target in wanted:
            rows.append(('indirect', base + p, wanted[target], image.fde_of(base + p)[0]))
    writers = {w[0] for w in WRITERS}
    for match in re.finditer(b'\xe8', text):
        p = match.start()
        if p + 5 > size:
            continue
        target = base + p + 5 + struct.unpack_from('<i', text, p + 1)[0]
        if target in writers:
            rows.append(('direct', base + p, target, image.fde_of(base + p)[0]))
    return sorted(rows, key=lambda r: (r[2], r[1]))


def derived_range():
    """Largest value the writer rule can store and the largest product at the gated helper."""
    scale = float(SCALE_GATE - 1) / 1e9
    product = float(SCALE_GATE) * scale
    return {'largest_written_scale': scale.hex(), 'largest_written_scale_decimal': repr(scale),
            'largest_gated_product': product.hex(), 'largest_gated_product_decimal': repr(product),
            'product_is_finite': math.isfinite(product), 'product_is_at_least_2_pow_63': product >= 2.0 ** 63}


def constant_rows(image):
    table = {'lower clamp': 0x20acb8, 'upper clamp': 0x20a7f0, 'largest f64 below 2^63': 0x20a2c8,
             'default scale': 0x20a730, 'divisor': 0x20a220}
    return {name: {'address': hex(va), 'bits': hex(struct.unpack('<Q', image.read(va, 8))[0]),
                   'value': repr(to_float(struct.unpack('<Q', image.read(va, 8))[0]))}
            for name, va in table.items()}


# --- negative controls ----------------------------------------------------------------------

def clamp_edits():
    site = CONSUMERS[0]
    inline = CONSUMERS[3]
    return (
        ('cap immediate low byte', site, [(0x370c1a0, b'\xaf')]),
        ('negative cap immediate low byte', CONSUMERS[1], [(0x370c27c, b'\x53')]),
        ('jbe becomes ja after the cap compare', site, [(0x370c1ab, b'\x77')]),
        ('jo removed after neg', site, [(0x370c19c, b'\x90\x90')]),
        ('cmovg becomes cmovle at the zero floor', site, [(0x370c1cf, b'\x4e')]),
        ('finite bound one lower', site, [(0x370c138, b'\xfe')]),
        ('non-finite branch removed', site, [(0x370c143, b'\x90\x90')]),
        ('cmova after truncate removed', site, [(0x370c180, b'\x90\x90\x90\x90')]),
        ('lower clamp constant -2^62', site, [(0x20acb8, struct.pack('<d', -2.0 ** 62))]),
        ('saturation bound 1.0', site, [(0x20a2c8, struct.pack('<d', 1.0))]),
        ('panic Location moved', site, [(0x370c1d6, b'\xc7')]),
        ('inline cap immediate second byte', inline, [(0x27689ec, b'\x48')]),
        ('inline jo removed', inline, [(0x27689e3, b'\x90' * 6)]),
        ('inline jbe becomes ja', inline, [(0x27689f6, b'\x77')]),
        ('inline final cap immediate', inline, [(0x2768a22, b'\xaf')]),
        ('inline seed movabs gone', inline, [(0x2768916, b'\x90' * 10)]))


def writer_edits():
    writer = WRITERS[0]
    return (
        ('gate compare jb becomes jae', writer, [(0x26fda00, b'\x73')]),
        ('status test uses bit 1', writer, [(0x26fda21, b'\x02')]),
        ('default 2.0', writer, [(0x20a730, struct.pack('<d', 2.0))]),
        ('divisor 1e8', writer, [(0x20a220, struct.pack('<d', 1e8))]),
        ('conversion constant high word', writer, [(0x202ea8, struct.pack('<d', 2.0 ** 83))]),
        ('cap movabs low byte', writer, [(0x26fd8e7, b'\x5d')]),
        ('1e9 argument changed', writer, [(0x26fd9c5, b'\x01')]),
        ('wrong call target', writer, [(0x26fd9d0, b'\x00')]))


def gate_edits():
    return (
        ('gate immediate low byte', [(0x370c102, b'\x5d')]),
        ('gate jbe becomes ja', [(0x370c10d, b'\x77')]),
        ('return x replaced', [(0x370c10f, bytes.fromhex('4889f8'))]))


def control_rows(image):
    rows = []

    def expect(name, action):
        try:
            action()
        except (EvidenceError, KeyError) as error:
            rows.append((name, 'rejected', str(error)[:100]))
            return
        rows.append((name, 'survived', ''))

    for name, site, edits in clamp_edits():
        expect('clamp: ' + name, lambda s=site, e=edits: analyse_clamp(image.patched(e), *s))
    for name, writer, edits in writer_edits():
        expect('writer: ' + name, lambda w=writer, e=edits: analyse_writer(image.patched(e), *w))
    for name, edits in gate_edits():
        expect('gate: ' + name, lambda e=edits: analyse_gate(image.patched(e)))
    return rows


# --- outputs --------------------------------------------------------------------------------

def analyse(image):
    binding = binding_rows(image)
    uses = field_uses(image)
    classes = [use_class(row) for row in uses]
    if 'unclassified' in classes:
        fail('a field use has no class')
    writers = [analyse_writer(image, *row) for row in WRITERS]
    clamps = [analyse_clamp(image, *row) for row in CONSUMERS]
    gate, gate_runs = analyse_gate(image)
    callers = slot_callers(image)
    panic = location(image, ABS_OVERFLOW_LOCATION)
    return {'binding': binding, 'uses': uses, 'classes': classes, 'writers': writers, 'clamps': clamps,
            'gate': gate, 'gate_runs': gate_runs, 'callers': callers, 'panic': panic,
            'constants': constant_rows(image)}


def float_text(bits):
    return to_float(bits).hex()


def write_outputs(out, result, controls):
    out.mkdir(parents=True, exist_ok=True)

    def tsv(name, header, rows):
        lines = ['\t'.join(header)] + ['\t'.join(str(c) for c in row) for row in rows]
        (out / name).write_text('\n'.join(lines) + '\n', encoding='ascii', newline='\n')

    tsv('field-binding.tsv', ('load', 'function', 'call', 'helper', 'key_address', 'key',
                              'previous_offset', 'previous_key', 'next_offset', 'next_key',
                              'token_load', 'token_key_address', 'token_key'),
        [(hex(a), hex(b), hex(c), hex(d), hex(e), f, hex(g), h, hex(i), j, hex(k), hex(m), n)
         for a, b, c, d, e, f, g, h, i, j, k, m, n in result['binding']])
    tsv('field-uses.tsv', ('address', 'kind', 'base_register', 'indexed', 'function', 'class'),
        [(hex(va), kind, reg, int(sib), hex(fn), cls)
         for (va, kind, reg, sib, fn), cls in zip(result['uses'], result['classes'])])
    tsv('callers.tsv', ('kind', 'site', 'target', 'function'),
        [(k, hex(s), hex(t), hex(f)) for k, s, t, f in result['callers']])
    tsv('writer-copies.tsv', ('function', 'store', 'tail', 'cap_movabs', 'record_key_load', 'call', 'default_price_call',
                              'compare_form', 'piece_runs', 'vectors'),
        [(hex(w['function']), hex(w['store']), hex(w['tail']), hex(w['cap_row']), hex(w['facts']['key_load']),
          hex(w['facts']['call']), hex(w['facts']['slot_call']), w['shape'], w['runs'], w['vectors'])
         for w in result['writers']])
    tsv('writer-pieces.tsv', ('function', 'status_rax', 'v_lo', 'v_hi', 'result'),
        [(hex(w['function']), status, hex(lo), hex(hi), 'v / 1e9' if kind == 'scaled' else '1.0')
         for w in result['writers'] for status, lo, hi, kind, _first, _last in w['table']])
    tsv('clamp-sites.tsv', ('mulsd', 'function', 'floor_at_zero', 'join', 'pieces', 'runs'),
        [(hex(c['mulsd']), hex(c['function']), int(c['nonneg']), 'ret' if c['stop'] is None else hex(c['stop']),
          len(c['pieces']), c['runs']) for c in result['clamps']])
    tsv('clamp-pieces.tsv', ('mulsd', 'bits_lo', 'bits_hi', 'p_at_lo', 'p_at_hi', 'kind', 'value_lo', 'value_hi'),
        [(hex(c['mulsd']), hex(lo), hex(hi), float_text(lo), float_text(hi), first[1][0],
          '' if first[1][1] is None else hex(first[1][1]), '' if last[1][1] is None else hex(last[1][1]))
         for c in result['clamps'] for lo, hi, first, last in c['pieces']])
    tsv('gate-pieces.tsv', ('x_lo', 'x_hi', 'outcome'),
        [(hex(lo), hex(hi), first[1][0]) for lo, hi, first, _last in result['gate']])
    tsv('mutation-controls.tsv', ('control', 'outcome', 'detail'), controls)
    summary = {
        'binary': BINARY, 'sha256': SHA256,
        'key': KEY.decode(), 'field_offset': hex(FIELD),
        'scale_gate': hex(SCALE_GATE), 'clamp': hex(CLAMP),
        'constants': result['constants'],
        'derived': derived_range(),
        'abs_overflow_location': {'address': hex(ABS_OVERFLOW_LOCATION), 'path': result['panic'][0],
                                  'line': result['panic'][1], 'column': result['panic'][2]},
        'field_uses': len(result['uses']),
        'field_use_classes': {c: result['classes'].count(c) for c in sorted(set(result['classes']))},
        'writer_copies': len(result['writers']),
        'clamp_sites': len(result['clamps']),
        'clamp_pieces': sum(len(c['pieces']) for c in result['clamps']),
        'clamp_runs': sum(c['runs'] for c in result['clamps']),
        'gate_pieces': len(result['gate']),
        'controls': len(controls),
        'controls_rejected': sum(1 for row in controls if row[1] == 'rejected'),
    }
    (out / 'evidence.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n', encoding='ascii',
                                       newline='\n')


def load_target(path):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail(f'{path}: sha256 {digest}, expected {SHA256}')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    image = Image(load_target(ROOT / BINARY))
    result = analyse(image)
    controls = control_rows(image)
    write_outputs(args.out, result, controls)
    print(json.dumps({'field_uses': len(result['uses']), 'clamp_sites': len(result['clamps']),
                      'controls': len(controls), 'rejected': sum(1 for r in controls if r[1] == 'rejected')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
