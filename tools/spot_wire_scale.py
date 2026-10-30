#!/usr/bin/env python3
"""RE-004: the spot order wire to raw price and size converters of node #94 (static, no execution).

Two small helpers take a u64 from the order and divide it by a power of ten chosen from the
token table.  The price helper reads the quote token's byte +0x49 (q) and the base token's byte
+0x48 (b), and the size helper reads b alone.  Neither rounds: a remainder is an error.

The tool walks the real bytes.  q and b are concrete and every one of the 65536 pairs is run (256
values of b for the size helper).  The u64 x is symbolic, so a leaf of the walk holds for every x
that takes its branches.  The only values x reaches are three facts: (x | s) < 2^32, s > x, and
x % s == 0.  Each fact forks the walk, and each leaf is held against the closed form:

    price  q < b          panic at the checked subtraction (Location spot_meta.rs:984:9)
           q - b > 8      error tag 0x65
           otherwise      s = 10^(8 - (q - b)); x < s or x % s != 0: tag 0x65; else Ok(x / s)
    size   b > 8          error tag 0x66
           otherwise      s = 10^(8 - b); x % s != 0: tag 0x66; else Ok(x / s)

Concrete vectors run through the same machine as a second check, and patched copies of the bytes
are the negative controls.

    python3 tools/spot_wire_scale.py --out <dir>

writes evidence.json, scale-table.tsv, bounds.tsv, census.tsv, call-sites.tsv and
mutation-controls.tsv.  Only the Python standard library is used; objdump is not.  Nothing from
the binary runs.
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

PRICE_COPIES = (0x4ca6940, 0x230af90)
SIZE_COPIES = (0x4ca6a90,)
# Functions in the census that this packet does not read, with the reason.
LEFT_OUT = {0x230b0e0: 'named by RE-010-exchange-handlers as an anchor'}
TAG_PRICE, TAG_SIZE, TAG_OK = 0x65, 0x66, 0x186
DISPLAY_TABLE = 0x59a8d0
DISPLAY_ARM = re.compile(rb'\x48\x8b\x3e\x48\x8b\x46\x08\x48\x8b\x40\x18\x48\x8d\x35(....)\xba(....)', re.S)
LOCATION_PREFIX = b'/l1/src/'

# Fake memory for the walk.  Any read outside these slots stops the walk.
CTX, ASSETS, TOKENS, OUT, STACK, RETURN = 0x100000, 0x200000, 0x300000, 0x400000, 0x500000, 0x777000
ASSET, BASE, QUOTE, N_ASSETS, N_TOKENS = 1, 2, 3, 2, 4
ASSET_STRIDE, TOKEN_STRIDE = 0x20, 0xe8
STEP_LIMIT = 300
RAX, RCX, RDX, RSP, RSI, RDI = 0, 1, 2, 4, 6, 7


class EvidenceError(Exception):
    pass


class Fork(Exception):
    """The walk reached a fact about x that is not yet decided."""

    def __init__(self, fact):
        super().__init__(fact)
        self.fact = fact


def fail(message):
    raise EvidenceError(message)


# --- ELF image, from the shared repository parsers ------------------------------------------

class Image:
    def __init__(self, data):
        self.data = bytearray(data)
        if hashlib.sha256(self.data).hexdigest() != SHA256:
            fail('binary digest does not match node #94')
        table = elf_index.sections(bytes(self.data))
        self.sections = [s for s in table if s['type'] != 8 and s['address']]
        self.text = next(s for s in self.sections if s['name'] == '.text')
        _, records = fde_extents.eh_frame_records(bytes(self.data), table)
        self.fdes = sorted((r['start'], r['end']) for r in records)
        self.starts = [row[0] for row in self.fdes]
        self.relocs = self.relative_relocations()
        self.cache = {}
        self.locations = {}

    def relative_relocations(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        relocs = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if info & 0xffffffff == 8:
                relocs[where] = addend
        return relocs

    def file_offset(self, va):
        for s in self.sections:
            if s['address'] <= va < s['address'] + s['size']:
                return va - s['address'] + s['offset']
        fail(f'address {va:#x} is outside every section with file bytes')

    def read(self, va, size):
        off = self.file_offset(va)
        return bytes(self.data[off:off + size])

    def fde_of(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            fail(f'{va:#x} is outside every FDE')
        return self.fdes[i]

    def patch(self, va, raw):
        """Replace bytes in place and return the old ones, for the negative controls."""
        off = self.file_offset(va)
        old = bytes(self.data[off:off + len(raw)])
        self.data[off:off + len(raw)] = raw
        self.cache.clear()
        return old

    def location(self, va):
        """The (path, line, column) of a Rust Location record, or None."""
        if va not in self.locations:
            self.locations[va] = self.read_location(va)
        return self.locations[va]

    def read_location(self, va):
        if va not in self.relocs:
            return None
        length, line, column = struct.unpack_from('<QII', self.read(va + 8, 16))
        if not 0 < length < 300:
            return None
        path = self.read(self.relocs[va], length)
        cut = path.find(LOCATION_PREFIX)
        return None if cut < 0 else (path[cut + 1:].decode('ascii'), line, column)

    def display_text(self, tag):
        """The fixed text printed by one arm of the error Display table, read from bytes."""
        arm = DISPLAY_TABLE + struct.unpack('<i', self.read(DISPLAY_TABLE + 4 * tag, 4))[0]
        found = DISPLAY_ARM.match(self.read(arm, 32))
        if not found:
            fail(f'Display arm of tag {tag:#x} has an unexpected shape')
        disp, length = struct.unpack('<iI', found.group(1) + found.group(2))
        return self.read(arm + 18 + disp, length).decode('ascii')


# --- x86-64 length decoder, for instruction starts ------------------------------------------

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


def length_of(data, off):
    """Length of one 64-bit instruction at a file offset, or raise on an unknown form."""
    p = off
    wide16 = False
    while data[p] in PREFIXES:
        wide16 = wide16 or data[p] == 0x66
        p += 1
    rex = 0
    if 0x40 <= data[p] <= 0x4f:
        rex = data[p]
        p += 1
    op = data[p]
    p += 1
    iz = 2 if wide16 else 4
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
            return p - off
        p += modrm_length(data, p)
        if space == 3 or (space == 1 and code in (0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6)):
            p += 1
        return p - off
    if op == 0x0f:
        two = data[p]
        p += 1
        if two in (0x38, 0x3a):
            p += 1
            return p + modrm_length(data, p) + (1 if two == 0x3a else 0) - off
        if 0x80 <= two <= 0x8f:
            return p + 4 - off
        if two in PLAIN_TWO:
            return p - off
        p += modrm_length(data, p)
        if two in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            p += 1
        return p - off
    if op in MODRM_ONE:
        return p + modrm_length(data, p) - off
    if op in (0x69, 0x81, 0xc7):
        return p + modrm_length(data, p) + iz - off
    if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6):
        return p + modrm_length(data, p) + 1 - off
    if op in (0xf6, 0xf7):
        imm = 0
        if (data[p] >> 3) & 7 in (0, 1):
            imm = 1 if op == 0xf6 else iz
        return p + modrm_length(data, p) + imm - off
    if (op < 0x40 and op & 7 == 4) or op in (0xa8, 0x6a, 0xcd) or 0xb0 <= op <= 0xb7:
        return p + 1 - off
    if (op < 0x40 and op & 7 == 5) or op in (0xa9, 0x68):
        return p + iz - off
    if op in PLAIN_ONE:
        return p - off
    if 0xb8 <= op <= 0xbf:
        return p + (8 if rex & 8 else iz) - off
    if 0x70 <= op <= 0x7f or op in (0xeb, 0xe0, 0xe1, 0xe2, 0xe3):
        return p + 1 - off
    if op in (0xe8, 0xe9):
        return p + 4 - off
    if op == 0xc2:
        return p + 2 - off
    if op in (0xa0, 0xa1, 0xa2, 0xa3):
        return p + 8 - off
    fail(f'unknown opcode {op:#x} at file offset {off:#x}')


def sweep(image, start, end):
    """Instruction starts of one FDE range; the sweep must stop exactly on the FDE end."""
    delta = image.text['offset'] - image.text['address']
    rows = []
    va = start
    while va < end:
        rows.append(va)
        va += length_of(image.data, va + delta)
    if va != end:
        fail(f'sweep of {start:#x} ended at {va:#x}, FDE ends at {end:#x}')
    return rows


# --- the walk -------------------------------------------------------------------------------
#
# A register holds an int, None (never written, so it may only be moved) or a symbolic value:
# X (the input), ('quot', s), ('rem', s), ('or', s) for x | s, ('hi', s) for (x | s) >> 32.

X = 'x'


def fits(value, size):
    return value & ((1 << (8 * size)) - 1)


def signed(value, size):
    value = fits(value, size)
    return value - (1 << (8 * size)) if value >> (8 * size - 1) else value


def ten_power(n):
    return 10 ** n


class World:
    """One spot table: a single asset, with its base and quote token bytes."""

    def __init__(self, q, b, asset=ASSET, base=BASE, quote=QUOTE):
        self.asset = asset
        self.memory = {
            (CTX + 0x168, 8): ASSETS, (CTX + 0x170, 8): N_ASSETS,
            (CTX + 0x180, 8): TOKENS, (CTX + 0x188, 8): N_TOKENS,
            (ASSETS + ASSET * ASSET_STRIDE, 8): base, (ASSETS + ASSET * ASSET_STRIDE + 8, 8): quote,
            (TOKENS + BASE * TOKEN_STRIDE + 0x48, 1): b, (TOKENS + QUOTE * TOKEN_STRIDE + 0x49, 1): q,
            # The other byte of each token holds a different value, so a wrong field shows.
            (TOKENS + BASE * TOKEN_STRIDE + 0x49, 1): (b + 77) & 255,
            (TOKENS + QUOTE * TOKEN_STRIDE + 0x48, 1): (q + 91) & 255}


class Walk:
    def __init__(self, image, start, world, x, decided):
        self.image, self.pc, self.world, self.decided = image, start, world, decided
        self.regs = [None] * 16
        self.regs[RDI], self.regs[RSI], self.regs[RDX], self.regs[RCX] = OUT, CTX, x, world.asset
        self.regs[RSP] = STACK
        self.stack = {STACK: RETURN}
        self.out = {}
        self.flags = None
        self.seen = set()
        self.edges = set()

    # registers and memory

    def fact(self, name):
        if name not in self.decided:
            raise Fork(name)
        return self.decided[name]

    def get(self, index, size, rex):
        value = self.regs[index]
        if size == 1 and not rex and 4 <= index < 8:
            fail(f'high byte register at {self.pc:#x}')
        if size == 8:
            return value
        if isinstance(value, int):
            return fits(value, size)
        if value == X and size == 4 and any(k[0] == 'small' and v for k, v in self.decided.items()):
            return X
        if isinstance(value, tuple) and value[0] in ('quot', 'rem') and size == 4:
            return value
        fail(f'partial read of a symbolic or unset register at {self.pc:#x}')

    def put(self, index, value, size, rex):
        if size == 1 and not rex and 4 <= index < 8:
            fail(f'high byte register at {self.pc:#x}')
        if size >= 4:
            self.regs[index] = fits(value, size) if isinstance(value, int) else value
            return
        old = self.regs[index]
        if not isinstance(old, int) or not isinstance(value, int):
            fail(f'partial write over a symbolic or unset register at {self.pc:#x}')
        mask = (1 << (8 * size)) - 1
        self.regs[index] = (old & ~mask) | fits(value, size)

    def address(self, operand):
        _, base, index, scale, disp = operand
        total = disp
        if base is not None:
            total += self.regs[base]
        if index is not None:
            total += self.regs[index] * scale
        return total & U64

    def load(self, operand, size):
        va = self.address(operand)
        if va in self.stack and size == 8:
            return self.stack[va]
        if (va, size) in self.world.memory:
            return self.world.memory[(va, size)]
        fail(f'read of {size} bytes at {va:#x} outside the model at {self.pc:#x}')

    def store(self, operand, value, size):
        va = self.address(operand)
        if not OUT <= va < OUT + 0x40:
            fail(f'write at {va:#x} outside the output record at {self.pc:#x}')
        self.out[(va - OUT, size)] = value

    def read(self, operand, size, rex):
        if operand[0] == 'r':
            return self.get(operand[1], size, rex)
        return self.load(operand, size)

    def write(self, operand, value, size, rex):
        if operand[0] == 'r':
            self.put(operand[1], value, size, rex)
        else:
            self.store(operand, value, size)

    # flags

    def compare(self, left, right, size):
        if isinstance(left, int) and isinstance(right, int):
            result = fits(left - right, size)
            self.flags = ('n', fits(left, size) < fits(right, size), result == 0, result >> (8 * size - 1),
                          (signed(left, size) - signed(right, size)) != signed(result, size))
            return result
        if isinstance(left, int) and right == X:
            self.flags = ('cmp', left)
            return None
        fail(f'compare of symbolic values at {self.pc:#x}')

    def logic(self, value, size):
        if isinstance(value, int):
            self.flags = ('n', False, fits(value, size) == 0, fits(value, size) >> (8 * size - 1), False)
        elif value[0] == 'rem':
            self.flags = ('rem', value[1])
        elif value[0] == 'hi':
            self.flags = ('hi', value[1])
        else:
            fail(f'flags from a symbolic value at {self.pc:#x}')

    def condition(self, cc):
        if self.flags is None:
            fail(f'condition on unknown flags at {self.pc:#x}')
        kind = self.flags[0]
        if kind == 'n':
            cf, zf, sf, of = self.flags[1:]
            base = {0: of, 1: cf, 2: zf, 3: cf or zf, 4: sf, 6: sf != of, 7: zf or sf != of}.get(cc >> 1)
            if base is None:
                fail(f'parity condition at {self.pc:#x}')
            return bool(base) != bool(cc & 1)
        s = self.flags[1]
        if kind == 'cmp':
            # The flags come from cmp s, x.
            if cc in (2, 3):
                return self.fact(('ge', s)) == (cc == 3)
            if cc in (6, 7):
                return self.fact(('gt', s)) == (cc == 7)
            if cc in (4, 5):
                return self.fact(('eq', s)) == (cc == 4)
        elif cc in (4, 5):
            return self.fact(('exact', s) if kind == 'rem' else ('small', s)) == (cc == 4)
        fail(f'condition {cc} on {kind} at {self.pc:#x}')

    # one instruction

    def parse_modrm(self, p, rex):
        data = self.image.data
        b = data[p]
        mod, reg, rm = b >> 6, ((b >> 3) & 7) | ((rex & 4) << 1), b & 7
        p += 1
        if mod == 3:
            return ('r', rm | ((rex & 1) << 3)), reg, p
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = data[p]
            p += 1
            scale = 1 << (sib >> 6)
            found = ((sib >> 3) & 7) | ((rex & 2) << 2)
            index = None if found == 4 else found
            if sib & 7 == 5 and mod == 0:
                disp = struct.unpack_from('<i', data, p)[0]
                return ('m', None, index, scale, disp), reg, p + 4
            base = (sib & 7) | ((rex & 1) << 3)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from('<b', data, p)[0]
            p += 1
        elif mod == 2 or rip:
            disp = struct.unpack_from('<i', data, p)[0]
            p += 4
        return ('rip' if rip else 'm', base, index, scale, disp), reg, p

    def decode(self, va):
        data = self.image.data
        start = p = self.image.file_offset(va)
        wide = False
        if data[p] == 0x66:
            wide = True
            p += 1
        rex = 0
        if 0x40 <= data[p] <= 0x4f:
            rex = data[p]
            p += 1
        op = data[p]
        p += 1
        size = 8 if rex & 8 else 2 if wide else 4
        if op == 0x0f:
            op = 0x0f00 | data[p]
            p += 1
        rm = reg = imm = target = None
        byte_ops = (0x28, 0x2a, 0x38, 0x3a, 0x80, 0xf6, 0x0fb6)
        if op in (0x50, 0x58, 0x59, 0xc3, 0x90) or 0x50 <= op <= 0x5f:
            pass
        elif op == 0xa8:
            imm = data[p]
            p += 1
        elif 0xb8 <= op <= 0xbf:
            width = 2 if wide else 4
            imm = int.from_bytes(data[p:p + width], 'little')
            p += width
            reg = (op & 7) | ((rex & 1) << 3)
        elif 0x70 <= op <= 0x7f or op == 0xeb:
            target = struct.unpack_from('<b', data, p)[0]
            p += 1
        elif 0x0f80 <= op <= 0x0f8f or op == 0xe9:
            target = struct.unpack_from('<i', data, p)[0]
            p += 4
        else:
            if op not in (0x09, 0x0b, 0x28, 0x2a, 0x31, 0x38, 0x39, 0x3a, 0x3b, 0x69, 0x6b, 0x80, 0x83, 0x85, 0x89,
                          0x8b, 0x8d, 0xc1, 0xf6, 0xf7, 0xff, 0x0fb6):
                fail(f'instruction outside the model at {va:#x}')
            rm, reg, p = self.parse_modrm(p, rex)
            if op in (0x80, 0x83, 0x6b, 0xc1):
                imm = data[p]
                if op == 0x83 and imm >= 0x80:
                    imm -= 0x100
                p += 1
            elif op == 0x69:
                imm = struct.unpack_from('<i', data, p)[0]
                p += 4
            elif op == 0xf6 and reg & 7 == 0:
                imm = data[p]
                p += 1
        end = va + p - start
        if rm is not None and rm[0] == 'rip':
            rm = ('m', None, None, 1, end + rm[4])
        if target is not None:
            target = (end + target) & U64
        return (op, 1 if op in byte_ops else size, rex, rm, reg, imm, target, end)

    def step(self):
        cache = self.image.cache
        va = self.pc
        row = cache.get(va)
        if row is None:
            row = cache[va] = self.decode(va)
        self.seen.add(va)
        op, size, rex, rm, reg, imm, target, end = row
        self.pc = end
        if 0x70 <= op <= 0x7f or 0x0f80 <= op <= 0x0f8f:
            taken = self.condition(op & 15)
            self.edges.add((va, taken))
            if taken:
                self.pc = target
        elif op in (0xe9, 0xeb):
            self.pc = target
        elif op == 0x90:
            pass
        elif 0x50 <= op <= 0x57:
            self.regs[RSP] -= 8
            self.stack[self.regs[RSP]] = self.regs[(op & 7) | ((rex & 1) << 3)]
        elif 0x58 <= op <= 0x5f:
            self.regs[(op & 7) | ((rex & 1) << 3)] = self.stack[self.regs[RSP]]
            self.regs[RSP] += 8
        elif op == 0xc3:
            if self.regs[RSP] != STACK or self.stack[STACK] != RETURN:
                fail(f'stack not balanced at ret {va:#x}')
            return self.finish()
        elif 0xb8 <= op <= 0xbf:
            self.put(reg, imm, 2 if size == 2 else size, rex)
        elif op == 0x8b:
            self.put(reg, self.read(rm, size, rex), size, rex)
        elif op == 0x89:
            self.write(rm, self.get(reg, size, rex), size, rex)
        elif op == 0x8d:
            self.put(reg, self.address(rm), size, rex)
        elif op == 0x0fb6:
            self.put(reg, self.read(rm, 1, rex), 4, rex)
        elif op in (0x38, 0x39):
            self.compare(self.read(rm, size, rex), self.get(reg, size, rex), size)
        elif op in (0x3a, 0x3b):
            self.compare(self.get(reg, size, rex), self.read(rm, size, rex), size)
        elif op in (0x28, 0x2a):
            left, right = self.read(rm, size, rex), self.get(reg, size, rex)
            if op == 0x2a:
                left, right = right, left
            value = self.compare(left, right, size)
            self.write(rm if op == 0x28 else ('r', reg), value, size, rex)
        elif op in (0x80, 0x83):
            left = self.read(rm, size, rex)
            kind = reg & 7
            if kind == 7:
                self.compare(left, imm, size)
            elif kind == 5:
                self.write(rm, self.compare(left, imm, size), size, rex)
            elif kind == 4:
                value = left & imm
                self.logic(value, size)
                self.write(rm, value, size, rex)
            else:
                fail(f'group 1 form {kind} at {va:#x}')
        elif op == 0x85:
            left, right = self.read(rm, size, rex), self.get(reg, size, rex)
            if left != right:
                fail(f'test of different registers at {va:#x}')
            self.logic(left, size)
        elif op == 0xa8:
            self.logic(self.get(RAX, 1, rex) & imm, 1)
        elif op in (0x09, 0x0b):
            left, right = self.read(rm, size, rex), self.get(reg, size, rex)
            if isinstance(left, int) and isinstance(right, int):
                value = left | right
                self.logic(value, size)
            elif X in (left, right):
                value = ('or', right if left == X else left)
                self.flags = None
            else:
                fail(f'or of symbolic values at {va:#x}')
            self.write(rm if op == 0x09 else ('r', reg), value, size, rex)
        elif op == 0x31:
            if rm != ('r', reg):
                fail(f'xor of different registers at {va:#x}')
            self.put(reg, 0, size, rex)
            self.flags = ('n', False, True, 0, False)
        elif op in (0x69, 0x6b):
            value = self.read(rm, size, rex)
            if not isinstance(value, int):
                fail(f'imul of a symbolic value at {va:#x}')
            self.put(reg, value * (imm & U64), size, rex)
            self.flags = None
        elif op == 0xc1:
            value = self.read(rm, size, rex)
            kind = reg & 7
            if isinstance(value, int) and kind == 4:
                self.write(rm, value << imm, size, rex)
                self.flags = None
            elif isinstance(value, int) and kind == 5:
                value >>= imm
                self.logic(value, size)
                self.write(rm, value, size, rex)
            elif kind == 5 and imm == 32 and size == 8 and isinstance(value, tuple) and value[0] == 'or':
                value = ('hi', value[1])
                self.logic(value, size)
                self.write(rm, value, size, rex)
            else:
                fail(f'shift form at {va:#x}')
        elif op == 0xf6:
            kind = reg & 7
            if kind == 0:
                self.logic(self.read(rm, 1, rex) & imm, 1)
            elif kind == 3:
                value = self.read(rm, 1, rex)
                self.compare(0, value, 1)
                self.write(rm, -value, 1, rex)
            else:
                fail(f'group 3 form {kind} at {va:#x}')
        elif op == 0xf7:
            kind = reg & 7
            if kind == 3:
                value = self.read(rm, size, rex)
                self.compare(0, value, size)
                self.write(rm, -value, size, rex)
            elif kind == 6:
                self.divide(self.read(rm, size, rex), size, rex)
            else:
                fail(f'group 3 form {kind} at {va:#x}')
        elif op == 0xff and reg & 7 == 2:
            return self.panic(self.address(rm))
        else:
            fail(f'instruction outside the model at {va:#x}')
        return None

    def divide(self, divisor, size, rex):
        high, low = self.get(RDX, size, rex), self.get(RAX, size, rex)
        if high != 0 or not isinstance(divisor, int) or divisor == 0:
            fail(f'divide without a clear high half or with a bad divisor at {self.pc:#x}')
        if low == X:
            quotient, remainder = ('quot', divisor), ('rem', divisor)
        elif isinstance(low, int):
            quotient, remainder = low // divisor, low % divisor
        else:
            fail(f'divide of a symbolic value at {self.pc:#x}')
        self.put(RAX, quotient, size, rex)
        self.put(RDX, remainder, size, rex)
        self.flags = None

    def finish(self):
        if self.regs[RAX] != OUT:
            fail('rax does not return the output record')
        word = self.out.get((0, 2))
        if word is None:
            fail('no status word written')
        if word != TAG_OK:
            if (8, 8) in self.out:
                fail('an error wrote a value')
            return ('err', word)
        return ('ok', self.out.get((8, 8)))

    def panic(self, slot):
        for register in (RDI, RDX):
            value = self.regs[register]
            if isinstance(value, int) and self.image.location(value):
                return ('panic', slot, value)
        fail(f'call without a Location at {self.pc:#x}')


def run(image, start, world, x, decided):
    walk = Walk(image, start, world, x, decided)
    for _ in range(STEP_LIMIT):
        result = walk.step()
        if result is not None:
            return result, walk
    fail(f'walk from {start:#x} did not end')


def leaves(image, start, world, seen, edges):
    """All leaves of the walk with x symbolic, as (decisions, outcome)."""
    pending, rows = [{}], []
    while pending:
        decided = pending.pop()
        try:
            outcome, walk = run(image, start, world, X, decided)
        except Fork as stop:
            pending.append({**decided, stop.fact: False})
            pending.append({**decided, stop.fact: True})
            continue
        seen |= walk.seen
        edges |= walk.edges
        rows.append((decided, outcome))
    return rows


# --- the closed form ------------------------------------------------------------------------

def price_class(q, b):
    """Return ('panic'), ('reject') or the divisor for one byte pair."""
    if q < b:
        return 'panic'
    return ten_power(8 - (q - b)) if q - b <= 8 else 'reject'


def size_class(b):
    return ten_power(8 - b) if b <= 8 else 'reject'


def check_leaf(decided, outcome, s, tag, zero_rejected):
    """One leaf of a divisor case against the closed form.  Returns an error text or None."""
    known = {('small', s), ('gt', s), ('exact', s)}
    if set(decided) - known:
        return f'fact outside the closed form: {sorted(set(decided) - known)}'
    if ('small', s) not in decided:
        return 'the 32-bit split was not reached'
    if zero_rejected:
        if ('gt', s) not in decided:
            return 'x < s was not tested'
        if decided[('gt', s)]:
            return None if outcome == ('err', tag) else f'x < s gave {outcome}'
    if ('exact', s) not in decided:
        return 'the remainder was not tested'
    if not decided[('exact', s)]:
        return None if outcome == ('err', tag) else f'a remainder gave {outcome}'
    return None if outcome == ('ok', ('quot', s)) else f'an exact x gave {outcome}'


def vectors_for(s):
    points = {0, 1, s - 1, s, s + 1, 2 * s - 1, 2 * s, 2 * s + 1, 7 * s, 7 * s + 1, U64}
    for top in (1 << 32, 1 << 64):
        whole = (top - 1) // s * s
        points |= {whole - s, whole - 1, whole, whole + 1, whole + s, top - 1, top, top + 1}
    return sorted(p for p in points if 0 <= p <= U64)


def concrete_vectors(image, start, world, s, tag, zero_rejected):
    """Run concrete x through the same machine.  Returns (count, first mismatch or None)."""
    points = vectors_for(s)
    for x in points:
        outcome, _ = run(image, start, world, x, {})
        rejected = (zero_rejected and x < s) or x % s != 0
        wanted = ('err', tag) if rejected else ('ok', x // s)
        if outcome != wanted:
            return len(points), f'x={x:#x} gave {outcome}'
    return len(points), None


def price_pairs():
    """Byte pairs with the divisor cases first, so a broken control stops early."""
    pairs = [(q, b) for q in range(256) for b in range(256)]
    return sorted(pairs, key=lambda p: (not 0 <= p[0] - p[1] <= 8, p))


def prove_price(image, start):
    seen, edges = set(), set()
    groups = {}
    vectors = 0
    tried = set()
    for q, b in price_pairs():
        world = World(q, b)
        rows = leaves(image, start, world, seen, edges)
        wanted = price_class(q, b)
        where = f'{start:#x} q={q} b={b}'
        if wanted == 'panic':
            if len(rows) != 1 or rows[0][0] or rows[0][1][0] != 'panic':
                return None, f'{where}: wanted a panic, got {rows}'
            location = image.location(rows[0][1][2])
            group = ('underflow', 'panic', 'none', f'{location[0]}:{location[1]}:{location[2]}', 0, 1)
        elif wanted == 'reject':
            if len(rows) != 1 or rows[0][0] or rows[0][1] != ('err', TAG_PRICE):
                return None, f'{where}: wanted tag 0x65 for every x, got {rows}'
            group = ('k>8', 'reject all x', 'none', 'tag 0x65', 0, 1)
        else:
            if len(rows) != 6:
                return None, f'{where}: {len(rows)} leaves, wanted 6'
            for decided, outcome in rows:
                error = check_leaf(decided, outcome, wanted, TAG_PRICE, True)
                if error:
                    return None, f'{where}: {error}'
            if wanted not in tried:
                tried.add(wanted)
                count, error = concrete_vectors(image, start, world, wanted, TAG_PRICE, True)
                vectors += count
                if error:
                    return None, f'{where}: {error}'
            ok = sum(1 for _, outcome in rows if outcome[0] == 'ok')
            group = (f'k={q - b}', 'x>=s and x%s==0 gives x/s', str(wanted), 'tag 0x65', ok, len(rows) - ok)
        groups.setdefault(group, 0)
        groups[group] += 1
    return {'groups': groups, 'seen': seen, 'edges': edges, 'vectors': vectors, 'cases': 65536}, None


def prove_size(image, start):
    seen, edges = set(), set()
    groups = {}
    vectors = 0
    for b in range(256):
        world = World(0, b)
        rows = leaves(image, start, world, seen, edges)
        wanted = size_class(b)
        where = f'{start:#x} b={b}'
        if wanted == 'reject':
            if len(rows) != 1 or rows[0][0] or rows[0][1] != ('err', TAG_SIZE):
                return None, f'{where}: wanted tag 0x66 for every x, got {rows}'
            group = ('b>8', 'reject all x', 'none', 'tag 0x66', 0, 1)
        else:
            if len(rows) != 4:
                return None, f'{where}: {len(rows)} leaves, wanted 4'
            for decided, outcome in rows:
                error = check_leaf(decided, outcome, wanted, TAG_SIZE, False)
                if error:
                    return None, f'{where}: {error}'
            count, error = concrete_vectors(image, start, world, wanted, TAG_SIZE, False)
            vectors += count
            if error:
                return None, f'{where}: {error}'
            ok = sum(1 for _, outcome in rows if outcome[0] == 'ok')
            group = (f'b={b}', 'x%s==0 gives x/s', str(wanted), 'tag 0x66', ok, len(rows) - ok)
        groups.setdefault(group, 0)
        groups[group] += 1
    return {'groups': groups, 'seen': seen, 'edges': edges, 'vectors': vectors, 'cases': 256}, None


def bounds_rows(image, start, kind, seen, edges):
    """The index checks, each run with one index out of range."""
    worlds = [('asset index = table length', World(8, 2, asset=N_ASSETS))]
    if kind == 'price':
        worlds.append(('quote index = token count', World(8, 2, quote=N_TOKENS)))
    worlds.append(('base index = token count', World(8, 2, base=N_TOKENS)))
    rows = []
    for name, world in worlds:
        cases = leaves(image, start, world, seen, edges)
        if len(cases) != 1 or cases[0][1][0] != 'panic':
            fail(f'{start:#x} {name}: wanted one panic, got {cases}')
        location = image.location(cases[0][1][2])
        rows.append((start, kind, name, cases[0][1][1], location))
    return rows


# --- census ---------------------------------------------------------------------------------

def census_rows(image):
    """Every `mov $tag,%cx` of the two error tags in .text."""
    base, off, size = image.text['address'], image.text['offset'], image.text['size']
    text = bytes(image.data[off:off + size])
    rows = []
    for tag in (TAG_PRICE, TAG_SIZE):
        for match in re.finditer(re.escape(b'\x66\xb9' + struct.pack('<H', tag)), text):
            va = base + match.start()
            start, end = image.fde_of(va)
            is_start = va in sweep(image, start, end)
            if not is_start:
                status = 'bytes are not an instruction start'
            elif start in PRICE_COPIES or start in SIZE_COPIES:
                status = 'analysed'
            elif start in LEFT_OUT:
                status = 'left out: ' + LEFT_OUT[start]
            else:
                status = 'inline, not read'
            rows.append((tag, va, start, end, status))
    return rows


def call_rows(image):
    """Every direct call of an analysed helper, at an instruction start of its caller."""
    base, off, size = image.text['address'], image.text['offset'], image.text['size']
    text = bytes(image.data[off:off + size])
    wanted = set(PRICE_COPIES) | set(SIZE_COPIES)
    rows = []
    for match in re.finditer(rb'[\xe8\xe9]', text):
        pos = match.start()
        if pos + 5 > len(text):
            continue
        target = base + pos + 5 + struct.unpack_from('<i', text, pos + 1)[0]
        if target not in wanted:
            continue
        va = base + pos
        start, end = image.fde_of(va)
        if va not in sweep(image, start, end):
            continue
        after = text[pos + 5:pos + 21]
        rows.append((target, va, start, 'jmp' if text[pos] == 0xe9 else 'call', b'\x86\x01' in after))
    return sorted(rows)


def pointer_count(image):
    wanted = set(PRICE_COPIES) | set(SIZE_COPIES) | set(LEFT_OUT)
    return sum(1 for target in image.relocs.values() if target in wanted)


# --- negative controls ----------------------------------------------------------------------

# name, helper, what the pattern is, the pattern, byte offset to change, new bytes
PRICE_FIRST, PRICE_SECOND = PRICE_COPIES
SIZE_ONLY = SIZE_COPIES[0]
CONTROLS = (
    ('ten', PRICE_FIRST, 'mov $10,%esi becomes 11', b'\xbe\x0a\x00\x00\x00', 1, b'\x0b'),
    ('hundred', PRICE_FIRST, 'imul 100 becomes 101', b'\x48\x6b\xf6\x64', 3, b'\x65'),
    ('ten-thousand', PRICE_FIRST, 'imul 10000 becomes 10001', b'\x48\x69\xf6\x10\x27\x00\x00', 3, b'\x11'),
    ('hundred-million', PRICE_FIRST, 'imul 1e8 becomes 1e8+1', b'\x48\x69\xf6\x00\xe1\xf5\x05', 3, b'\x01'),
    ('decimals-gate', PRICE_FIRST, 'sub $8,%r9b becomes sub $7', b'\x41\x80\xe9\x08', 3, b'\x07'),
    ('borrow-gate', PRICE_FIRST, 'jb to the panic becomes jmp', b'\x41\x28\xd2\x0f\x82', 3, b'\x90\xe9'),
    ('quote-field', PRICE_FIRST, 'quote byte +0x49 becomes +0x48', b'\x0f\xb6\x44\x02\x49', 4, b'\x48'),
    ('base-field', PRICE_FIRST, 'base byte +0x48 becomes +0x49', b'\x0f\xb6\x54\x0a\x48', 4, b'\x49'),
    ('zero-gate-64', PRICE_FIRST, '64-bit jbe becomes jb', b'\x4c\x39\xc6\x76', 3, b'\x72'),
    ('zero-gate-32', PRICE_FIRST, '32-bit ja becomes jae', b'\x4c\x39\xc6\x77', 3, b'\x73'),
    ('remainder', PRICE_FIRST, 'jne after the remainder test removed', b'\x48\x85\xd2\x75', 3, b'\x90\x90'),
    ('price-tag', PRICE_FIRST, 'tag 0x65 becomes 0x64', b'\x66\xb9\x65\x00', 2, b'\x64'),
    ('ok-tag', PRICE_FIRST, 'ok word 0x186 becomes 0x185', b'\x66\xb9\x86\x01', 2, b'\x85'),
    ('second-copy', PRICE_SECOND, 'imul 100 becomes 101 in the other copy', b'\x48\x6b\xf6\x64', 3, b'\x65'),
    ('size-gate', SIZE_ONLY, 'sub $8,%eax becomes sub $7', b'\x83\xe8\x08', 2, b'\x07'),
    ('size-field', SIZE_ONLY, 'base byte +0x48 becomes +0x49', b'\x44\x0f\xb6\x44\x01\x48', 5, b'\x49'),
    ('size-remainder-64', SIZE_ONLY, 'je after the 64-bit remainder test becomes jmp', b'\x48\x85\xd2\x74', 3, b'\xeb'),
    ('size-remainder-32', SIZE_ONLY, 'jne after the 32-bit remainder test removed', b'\x48\x85\xd2\x75', 3, b'\x90\x90'),
    ('size-hundred', SIZE_ONLY, 'imul 100 becomes 101', b'\x48\x6b\xf6\x64', 3, b'\x65'),
    ('size-tag', SIZE_ONLY, 'tag 0x66 becomes 0x64', b'\x66\xb9\x66\x00', 2, b'\x64'),
)


def control_rows(image):
    rows = []
    for name, start, what, pattern, offset, new in CONTROLS:
        _, end = image.fde_of(start)
        body = image.read(start, end - start)
        hits = [m.start() for m in re.finditer(re.escape(pattern), body)]
        if len(hits) != 1:
            fail(f'control {name}: pattern hits {len(hits)} times')
        va = start + hits[0] + offset
        old = image.patch(va, new)
        try:
            prove = prove_price if start in PRICE_COPIES else prove_size
            proof, error = prove(image, start)
            if proof is not None:
                outcome, detail = 'survived', ''
            else:
                outcome, detail = 'detected', error
        except EvidenceError as stop:
            outcome, detail = 'detected', str(stop)
        finally:
            image.patch(va, old)
        rows.append((name, start, va, old.hex(), new.hex(), what, outcome, detail))
    return rows


# --- output ---------------------------------------------------------------------------------

def tsv(header, rows):
    return ''.join('\t'.join(str(x) for x in row) + '\n' for row in [header] + rows)


def show_edges(edges):
    return [f'{va:#x}:{"taken" if taken else "not-taken"}' for va, taken in sorted(edges)]


def missing_edges(proof):
    """Conditional branch sides the proof never took."""
    return sorted((va, not taken) for va, taken in proof['edges'] if (va, not taken) not in proof['edges'])


def analyse(data):
    image = Image(data)
    table = []
    summary = {}
    bounds = []
    for start, kind, prove in ([(s, 'price', prove_price) for s in PRICE_COPIES]
                               + [(s, 'size', prove_size) for s in SIZE_COPIES]):
        proof, error = prove(image, start)
        if proof is None:
            fail(error)
        bounds.extend(bounds_rows(image, start, kind, proof['seen'], proof['edges']))
        fde = image.fde_of(start)
        instructions = sweep(image, *fde)
        unreached = [va for va in instructions if va not in proof['seen']]
        for group, count in sorted(proof['groups'].items(), key=lambda row: (row[0][0][0], len(row[0][0]), row[0][0])):
            table.append((f'{start:#x}', kind, group[0], count, group[1], group[2], group[3], group[4], group[5]))
        summary[f'{start:#x}'] = {
            'kind': kind, 'fde': [f'{fde[0]:#x}', f'{fde[1]:#x}'], 'bytes': fde[1] - fde[0],
            'instructions': len(instructions), 'instructions_reached': len(instructions) - len(unreached),
            'instructions_not_reached': [f'{va:#x}' for va in unreached],
            'cases': proof['cases'], 'concrete_vectors': proof['vectors'],
            'branch_sides_not_taken': show_edges(missing_edges(proof))}
    census = census_rows(image)
    calls = call_rows(image)
    controls = control_rows(image)
    evidence = {
        'binary': BINARY, 'sha256': SHA256,
        'sections': {s['name']: [f"{s['address']:#x}", s['size']] for s in image.sections
                     if s['name'] in ('.text', '.rodata', '.rela.dyn')},
        'fde_records': len(image.fdes),
        'helpers': summary,
        'tag_text': {f'{tag:#x}': image.display_text(tag) for tag in (TAG_PRICE, TAG_SIZE)},
        'relative_relocations_to_helpers': pointer_count(image),
        'direct_calls': {f'{t:#x}': sum(1 for row in calls if row[0] == t)
                         for t in PRICE_COPIES + SIZE_COPIES},
        'left_out': {f'{k:#x}': v for k, v in sorted(LEFT_OUT.items())},
        'controls': {'total': len(controls), 'detected': sum(1 for row in controls if row[6] == 'detected')},
    }
    if evidence['controls']['detected'] != len(controls):
        fail('a negative control survived: ' + str([row[0] for row in controls if row[6] != 'detected']))
    files = {
        'evidence.json': json.dumps(evidence, indent=1, sort_keys=True) + '\n',
        'scale-table.tsv': tsv(('helper', 'kind', 'case', 'byte_cases', 'rule', 'divisor', 'error', 'ok_leaves',
                                'error_leaves'), table),
        'bounds.tsv': tsv(('helper', 'kind', 'case', 'call_slot', 'location'),
                          [(f'{s:#x}', k, n, f'{slot:#x}', f'{loc[0]}:{loc[1]}:{loc[2]}')
                           for s, k, n, slot, loc in bounds]),
        'census.tsv': tsv(('tag', 'site', 'fde_start', 'fde_end', 'status'),
                          [(f'{t:#x}', f'{v:#x}', f'{s:#x}', f'{e:#x}', st) for t, v, s, e, st in census]),
        'call-sites.tsv': tsv(('helper', 'site', 'caller_fde_start', 'form', 'status_word_read_within_16_bytes'),
                              [(f'{t:#x}', f'{v:#x}', f'{s:#x}', f, str(c).lower()) for t, v, s, f, c in calls]),
        'mutation-controls.tsv': tsv(('control', 'helper', 'patch_va', 'old', 'new', 'patch', 'outcome', 'first_stop'),
                                     [(n, f'{s:#x}', f'{v:#x}', o, w, what, out, d)
                                      for n, s, v, o, w, what, out, d in controls]),
    }
    return files


def load_binary():
    path = ROOT / BINARY
    if not path.exists():
        fail(f'{BINARY} is missing')
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    try:
        files = analyse(load_binary())
    except EvidenceError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (out / name).write_text(text, encoding='utf-8', newline='\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
