#!/usr/bin/env python3
"""RE-004: the five-significant-figure price tick ladder of node #94 (static, no execution).

Eleven functions share one threshold ladder over a u64 x:

    step(x) = 10^max(0, digits(x) - 5), with digits(0) = 1

Two perp functions return min(step(px), 10^(6 - szDecimals)).  Three spot functions return
1000 when a per-base-token lookup hits, otherwise min(step(px), 10^(quote.+0x49 - base.+0x48)),
or step(px) alone when that power does not fit (exponent 20 or more).  Six larger functions
inline the ladder with no asset term and store floor(x / step) * step.

The ladder compares x, or x shifted right, with constants and nothing else, so its result
is constant between neighbouring thresholds.  The tool proves that shape from the
instructions, then runs the real instructions at both ends of every interval, which covers
all 2^64 inputs.  Instructions are read with objdump and interpreted by a small Python
x86-64 evaluator that stops on an unmodelled mnemonic, an unset register, flag or memory
byte, an unknown call target or a write outside its own RAM.  Nothing from the binary runs
natively.

    python3 tools/px_tick_ladder.py --out <dir>

writes evidence.json, step-intervals.tsv, ladder-copies.tsv, exponent-table.tsv and
call-sites.tsv.  Only the Python standard library and objdump are used.
"""

import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
import sys
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
SEED = b'RE-004-px-tick-ladder-94'
SIZES = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16}

SIGNIFICANT_FIGURES = 5
BREAKPOINTS = tuple(10 ** e for e in range(5, 20))
FIRST_LIMIT = 100_000
PERP = (0x230b390, 0x42c7600)
SPOT = (0x230b590, 0x36f3350, 0x4ca6b90)
FLOOR = (0x2773d60, 0x27758c0, 0x4336b90, 0x43377c0, 0x4338210, 0x4339480)
DIGIT_COUNT = 0x4eb76c0          # holds 10^15-1 too, but returns a digit count
FAMILY_A, FAMILY_B = 0x2e90edd, 0x48c27395   # 10^11 >> 11 and 10^13 >> 13
FLAG_SLOT, FLAG_FUNCTION = 0x5773d30, 0x3728550
PANIC_UNWRAP, PANIC_SUB, PANIC_BOUNDS = 0x157a9f0, 0x157b520, 0x157b64f
PANICS = {PANIC_UNWRAP, PANIC_SUB, PANIC_BOUNDS}
ROUNDING_ENTRY, ROUNDING_STOP = 0x2774197, 0x27741ed
STATUS_DISPLAY, STATUS_TABLE = 0x3a008e0, 0x5a572c
STATUS_BASE = 1 << 63
STATUS_TEXT = {0: b'Price must be divisible by tick size.', 9: b'Invalid TP/SL price.'}
FAILURE_ROWS, FAILURE_CHUNK = 24, 0x40
ERROR_TABLE, OUTER_TAG = 0x59a8d0, 0xc4
OUTER_PIECES = b'\xc0\x07 asset=\xc0\x00'
CAP_IMM = struct.pack('<Q', 10 ** 15)
CAP_WINDOW = 0x40
CALL_TAIL = 0xc0
FLOOR_SEEDS = 200
WORKED_EXAMPLES = ((123_456_000_000, 0), (12_345_600_000, 0), (12_345_000_000, 0), (123_456_789_000, 3))

# From references/can1357-hl/l1/qtys/impl_sz.rs, visible_bucket_step: (x below this, step).
REFERENCE_STEPS = ((10 ** 5, 1), (10 ** 6, 10), (10 ** 7, 100), (10 ** 8, 10 ** 3), (10 ** 9, 10 ** 4),
                   (10 ** 10, 10 ** 5), (10 ** 12, 10 ** 6), (10 ** 13, 10 ** 7), (10 ** 14, 10 ** 8),
                   (10 ** 15, 10 ** 10), (10 ** 16, 10 ** 11), (10 ** 17, 10 ** 12), (10 ** 18, 10 ** 13),
                   (10 ** 19, 10 ** 14), (1 << 64, 10 ** 9))

RET_MAGIC = 0x7fff0000
FLAG_STUB = 0x7fff0010
RAM_BASE, RAM_SIZE = 0x7000000, 0x10000
STACK_TOP = RAM_BASE + 0xf000 - 8    # entry rsp + 8 is 16-aligned, as the ABI requires
META = RAM_BASE + 0x100
TABLE = RAM_BASE + 0x800
TOKENS = RAM_BASE + 0x1000
PERP_DEX, PERP_ASSET, PERP_COUNT = 3, 30_002, 4
PERP_STRIDE, PERP_SZ_OFFSET = 48, 0x2a
SPOT_PAIR, SPOT_PAIRS, SPOT_BASE, SPOT_QUOTE, SPOT_TOKENS = 1, 3, 1, 2, 3
PAIR_STRIDE, TOKEN_STRIDE = 32, 0xe8
TOKEN_SZ_OFFSET, TOKEN_WEI_OFFSET = 0x48, 0x49

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
REGS = {name: (i, 8) for i, name in enumerate(REG64)}
for i, name in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[name] = (i, 4)
for i, name in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                          'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']):
    REGS[name] = (i, 2)
for i, name in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[name] = (i, 1)


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    pass


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


# ------------------------------------------------------------------- ELF / FDE

def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    out = {}
    for name, typ, _flags, addr, off, size, *_ in raw:
        if typ == 8:  # SHT_NOBITS occupies no file bytes; mapping its VAs would
            continue  # return unrelated file bytes as if they lived there.
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)
        self.relocs = None

    def off(self, va, size=1):
        for addr, off, sz in self.sec.values():
            if addr and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def text(self):
        addr, off, size = self.sec['.text']
        return addr, self.data[off:off + size]

    def in_rodata(self, va, size):
        addr, _, sz = self.sec['.rodata']
        return addr <= va and va + size <= addr + sz

    def slots(self):
        """GOT contents after load: RELATIVE addends."""
        got = self.sec['.got']
        return {where: addend & MASK for where, addend in self.relative_relocs_cached().items()
                if got[0] <= where < got[0] + got[2]}

    def relative_relocs_cached(self):
        if self.relocs is None:
            _, off, size = self.sec['.rela.dyn']
            out = {}
            for where, info, addend in struct.iter_unpack('<QQq', self.data[off:off + size]):
                if info & 0xffffffff == 8:
                    if where in out:
                        raise EvidenceError(f'duplicate RELATIVE relocation slot {where:#x}')
                    out[where] = addend
            self.relocs = out
        return self.relocs


def uleb(buf, i):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[enc & 0x0f]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 != 0x00:
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & MASK, size


class Fdes:
    """Binary-search table from .eh_frame_hdr; ranges from each FDE body."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr'][0]
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        if any(b <= a for a, b in zip(self.starts, self.starts[1:])):
            raise EvidenceError('.eh_frame_hdr table not strictly increasing')
        self.count = count

    def cie_r_encoding(self, cie):
        body = self.img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        begin, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return {'start': begin, 'end': begin + length, 'fde': fde}


# ------------------------------------------------------------ instruction reader

def disassemble(binary, start, end):
    cmd = ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(binary)]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
MEM_RE = re.compile(r'^(?:(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[(.*)\]$')
HEX_RE = re.compile(r'0x[0-9a-f]+')
SHIFTS = ('shl', 'shr', 'sar')


def parse_operand(text, comment):
    if text in REGS:
        idx, size = REGS[text]
        return ('r', idx, size)
    if re.fullmatch(r'xmm[0-9]+', text):
        return ('x', int(text[3:]))
    if HEX_RE.fullmatch(text):
        return ('i', int(text, 16))
    m = MEM_RE.match(text)
    if m:
        size = SIZES.get(m.group(1), 8)
        inner = m.group(2)
        if inner.startswith('rip'):
            return ('a', size, comment)
        base = index = None
        scale, disp = 1, 0
        for part in re.findall(r'[+-]?[^+-]+', inner):
            neg = part[0] == '-'
            part = part.lstrip('+-')
            if '*' in part:
                reg, mul = part.split('*')
                index, scale = REGS[reg][0], int(mul)
            elif part in REGS:
                base = REGS[part][0]
            else:
                disp = -int(part, 16) if neg else int(part, 16)
        return ('m', size, base, index, scale, disp)
    if re.fullmatch(r'[0-9a-f]+', text):
        return ('t', int(text, 16))
    raise EvidenceError(f'unparsed operand {text!r}')


def parse_listing(listing):
    """objdump text -> ordered list of (va, mnemonic, operands, next_va)."""
    rows = []
    for line in listing.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        va, body = int(m.group(1), 16), m.group(2).strip()
        comment = None
        if '#' in body:
            body, tail = body.split('#', 1)
            comment = int(tail.split()[0], 16)
        body = re.sub(r'<[^>]*>', '', body).strip()
        if 'nop' in body or body == 'xchg   ax,ax':
            rows.append((va, 'nop', ()))
            continue
        parts = body.split(None, 1)
        mn = parts[0] if parts else 'nop'
        ops = ()
        if len(parts) > 1:
            try:
                ops = tuple(parse_operand(p.strip(), comment) for p in parts[1].split(','))
            except (EvidenceError, KeyError, ValueError):
                mn, ops = 'unparsed', ()         # stops the evaluator only if reached
        if mn in SHIFTS and ops[-1:] == (('t', 1),):
            ops = ops[:-1] + (('i', 1),)
        rows.append((va, mn, ops))
    return [(va, mn, ops, rows[i + 1][0] if i + 1 < len(rows) else None)
            for i, (va, mn, ops) in enumerate(rows)]


# ------------------------------------------------------------------ evaluator

def signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) else val


class Machine:
    """Byte-accurate integer and SSE-move subset.  Unset state is tracked and never guessed."""

    CC = {'e': lambda s: s.flag('zf'), 'ne': lambda s: not s.flag('zf'),
          'b': lambda s: s.flag('cf'), 'ae': lambda s: not s.flag('cf'),
          'a': lambda s: not (s.flag('cf') or s.flag('zf')), 'be': lambda s: s.flag('cf') or s.flag('zf'),
          's': lambda s: s.flag('sf'), 'ns': lambda s: not s.flag('sf'),
          'o': lambda s: s.flag('of'), 'no': lambda s: not s.flag('of')}

    def __init__(self, insns, img, slots):
        self.img = img
        self.slots = slots
        table = {name[2:]: getattr(self, name) for name in dir(self) if name.startswith('i_')}
        for cc in self.CC:
            table['j' + cc] = partial(self.jcc, cc)
            table['cmov' + cc] = partial(self.cmov, cc)
            table['set' + cc] = partial(self.setcc, cc)
        self.code = {}
        for va, mn, ops, nxt in insns:
            handler = table.get(mn) or partial(self.unknown, mn, va)
            self.code[va] = (handler, ops, nxt)
        self.seen = set()
        self.stubs = {}
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.known = [0] * 16
        self.ram = bytearray(RAM_SIZE)
        self.valid = bytearray(RAM_SIZE)
        self.cf = self.zf = self.sf = self.of = None
        self.steps = 0
        self.pc = None

    # state access

    def setreg(self, idx, val):
        self.regs[idx] = val & MASK
        self.known[idx] = MASK

    def poison(self, *idxs):
        for idx in idxs:
            self.known[idx] = 0

    def flag(self, name):
        val = getattr(self, name)
        if val is None:
            raise Unmodelled(f'read of unset {name} at {self.pc:#x}')
        return val

    def ea(self, op):
        _, _, base, index, scale, disp = op
        val = disp
        if base is not None:
            if self.known[base] != MASK:
                raise Unmodelled(f'unset base at {self.pc:#x}')
            val += self.regs[base]
        if index is not None:
            if self.known[index] != MASK:
                raise Unmodelled(f'unset index at {self.pc:#x}')
            val += self.regs[index] * scale
        return val & MASK

    def load(self, ea, size):
        lo = ea - RAM_BASE
        if 0 <= lo and lo + size <= RAM_SIZE:
            if 0 in self.valid[lo:lo + size]:
                raise Unmodelled(f'read of unset memory {ea:#x}/{size} at {self.pc:#x}')
            return int.from_bytes(self.ram[lo:lo + size], 'little')
        if size == 8 and ea in self.slots:
            return self.slots[ea]
        if self.img.in_rodata(ea, size):
            return int.from_bytes(self.img.read(ea, size), 'little')
        raise Unmodelled(f'read outside the model {ea:#x}/{size} at {self.pc:#x}')

    def store(self, ea, size, val):
        lo = ea - RAM_BASE
        if not (0 <= lo and lo + size <= RAM_SIZE):
            raise Unmodelled(f'write outside RAM {ea:#x} at {self.pc:#x}')
        self.ram[lo:lo + size] = (val & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
        self.valid[lo:lo + size] = b'\x01' * size

    def rd(self, op):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            mask = (1 << (size * 8)) - 1
            if self.known[idx] & mask != mask:
                raise Unmodelled(f'read of unset {REG64[idx]} at {self.pc:#x}')
            return self.regs[idx] & mask
        if kind == 'i':
            return op[1]
        if kind == 'm':
            return self.load(self.ea(op), op[1])
        if kind == 'a':
            return self.load(op[2], op[1])
        raise Unmodelled(f'operand {op} at {self.pc:#x}')

    def wr(self, op, val):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            if size >= 4:
                self.regs[idx] = val & (MASK if size == 8 else 0xffffffff)
                self.known[idx] = MASK
            else:
                mask = (1 << (size * 8)) - 1
                self.regs[idx] = (self.regs[idx] & ~mask) | (val & mask)
                self.known[idx] |= mask
        elif kind == 'm':
            self.store(self.ea(op), op[1], val)
        elif kind == 'a':
            raise Unmodelled(f'write to a static address at {self.pc:#x}')
        else:
            raise Unmodelled(f'write to {op} at {self.pc:#x}')

    def size(self, op):
        return op[2] if op[0] == 'r' else op[1]

    def nz(self, res, bits):
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))

    # moves

    def i_nop(self, ops):
        pass

    def i_mov(self, ops):
        dst, src = ops
        if dst[0] == 'r' and src[0] == 'r' and dst[2] >= 4:
            self.regs[dst[1]] = self.regs[src[1]] & (MASK if dst[2] == 8 else 0xffffffff)
            self.known[dst[1]] = self.known[src[1]] if dst[2] == 8 else (self.known[src[1]] & 0xffffffff) | ~0xffffffff & MASK
            return
        self.wr(dst, self.rd(src))

    i_movabs = i_mov

    def i_movzx(self, ops):
        self.wr(ops[0], self.rd(ops[1]))

    def i_lea(self, ops):
        dst, src = ops
        self.wr(dst, src[2] if src[0] == 'a' else self.ea(src))

    def i_push(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP] - 8
        self.regs[RSP] = rsp
        lo = rsp - RAM_BASE
        self.ram[lo:lo + 8] = self.regs[idx].to_bytes(8, 'little')
        self.valid[lo:lo + 8] = bytes((self.known[idx] >> (8 * i)) & 1 for i in range(8))

    def i_pop(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP]
        lo = rsp - RAM_BASE
        self.regs[idx] = int.from_bytes(self.ram[lo:lo + 8], 'little')
        self.known[idx] = sum(0xff << (8 * i) for i in range(8) if self.valid[lo + i])
        self.regs[RSP] = rsp + 8

    # integer arithmetic

    def arith(self, ops, carry_in, subtract, store=True):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        a, b = self.rd(ops[0]), self.rd(ops[1]) & mask
        c = int(self.flag('cf')) if carry_in else 0
        if subtract:
            raw = a - b - c
            res = raw & mask
            self.cf = raw < 0
            self.of = bool((((a ^ b) & (a ^ res)) >> (bits - 1)) & 1)
        else:
            raw = a + b + c
            res = raw & mask
            self.cf = raw > mask
            self.of = bool((((a ^ res) & (b ^ res)) >> (bits - 1)) & 1)
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_add(self, ops):
        self.arith(ops, False, False)

    def i_adc(self, ops):
        self.arith(ops, True, False)

    def i_sub(self, ops):
        self.arith(ops, False, True)

    def i_sbb(self, ops):
        self.arith(ops, True, True)

    def i_cmp(self, ops):
        self.arith(ops, False, True, store=False)

    def logic(self, ops, fn, store=True):
        bits = self.size(ops[0]) * 8
        res = fn(self.rd(ops[0]), self.rd(ops[1]) & ((1 << bits) - 1))
        self.cf = self.of = False
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_and(self, ops):
        self.logic(ops, lambda a, b: a & b)

    def i_or(self, ops):
        self.logic(ops, lambda a, b: a | b)

    def i_xor(self, ops):
        if ops[0] == ops[1] and ops[0][0] == 'r':
            self.wr(ops[0], 0)
            self.cf = self.of = self.sf = False
            self.zf = True
            return
        self.logic(ops, lambda a, b: a ^ b)

    def i_test(self, ops):
        self.logic(ops, lambda a, b: a & b, store=False)

    def i_inc(self, ops):
        bits = self.size(ops[0]) * 8
        res = (self.rd(ops[0]) + 1) & ((1 << bits) - 1)
        self.of = res == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_dec(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = (a - 1) & ((1 << bits) - 1)
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_neg(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = -a & ((1 << bits) - 1)
        self.cf = a != 0
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_not(self, ops):
        bits = self.size(ops[0]) * 8
        self.wr(ops[0], ~self.rd(ops[0]) & ((1 << bits) - 1))

    def shift(self, ops, kind):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[1]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a = self.rd(ops[0])
        if kind == 'shl':
            raw = a << count
            self.cf = bool((raw >> bits) & 1)
        elif kind == 'shr':
            raw = a >> count
            self.cf = bool((a >> (count - 1)) & 1)
        else:
            sa = signed(a, bits)
            raw = sa >> count
            self.cf = bool((sa >> (count - 1)) & 1)
        res = raw & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shl(self, ops):
        self.shift(ops, 'shl')

    def i_shr(self, ops):
        self.shift(ops, 'shr')

    def i_sar(self, ops):
        self.shift(ops, 'sar')

    def i_mul(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        raw = self.rd(lo_op) * self.rd(ops[0])
        self.wr(lo_op, raw)
        self.wr(hi_op, raw >> bits)
        self.cf = self.of = raw >> bits != 0
        self.zf = self.sf = None

    def i_imul(self, ops):
        bits = self.size(ops[0]) * 8
        if len(ops) == 2:
            a, b = self.rd(ops[0]), self.rd(ops[1])
        elif len(ops) == 3:
            a, b = self.rd(ops[1]), self.rd(ops[2])
        else:
            raise Unmodelled(f'one-operand imul at {self.pc:#x}')
        b &= (1 << bits) - 1
        raw = signed(a, bits) * signed(b, bits)
        res = raw & ((1 << bits) - 1)
        self.cf = self.of = signed(res, bits) != raw
        self.zf = self.sf = None
        self.wr(ops[0], res)

    def i_div(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        num = (self.rd(hi_op) << bits) | self.rd(lo_op)
        den = self.rd(ops[0])
        if den == 0 or num // den >> bits:
            raise Unmodelled(f'divide fault at {self.pc:#x}')
        self.wr(lo_op, num // den)
        self.wr(hi_op, num % den)
        self.cf = self.of = self.zf = self.sf = None

    # control flow

    def jcc(self, cc, ops):
        if self.CC[cc](self):
            self.pc = ops[0][1]

    def cmov(self, cc, ops):
        dst, src = ops
        val = self.rd(src)
        if self.CC[cc](self):
            self.wr(dst, val)
        elif dst[2] == 4:
            self.wr(dst, self.rd(dst))

    def setcc(self, cc, ops):
        self.wr(ops[0], int(bool(self.CC[cc](self))))

    def target(self, op):
        return op[1] if op[0] == 't' else self.rd(op)

    def i_jmp(self, ops):
        self.pc = self.target(ops[0])

    def i_call(self, ops):
        dest = self.target(ops[0])
        self.regs[RSP] -= 8
        self.store(self.regs[RSP], 8, self.pc or 0)     # a panic call can end a listing
        self.pc = dest

    def i_ret(self, ops):
        self.pc = self.load(self.regs[RSP], 8)
        self.regs[RSP] += 8


    def unknown(self, mn, va, ops):
        raise Unmodelled(f'mnemonic {mn} at {va:#x}')

    # stubs

    def after_stub(self, result):
        self.setreg(RAX, result)
        self.poison(RCX, RDX, RSI, RDI, R8, R9, R10, R11)
        self.cf = self.zf = self.sf = self.of = None
        self.i_ret(())


    def run(self, entry, stop=(), limit=20000):
        self.pc = entry
        code = self.code
        seen = self.seen
        while True:
            pc = self.pc
            if pc == RET_MAGIC or pc in stop:
                return pc
            if pc in self.stubs:
                self.stubs[pc]()
                continue
            ins = code.get(pc)
            if ins is None:
                raise Unmodelled(f'no instruction at {pc:#x}')
            self.steps += 1
            if self.steps > limit:
                raise Unmodelled('step limit')
            seen.add(pc)
            self.pc = ins[2]
            ins[0](ins[1])


def intervals():
    """[lo, hi] for each constant piece of the ladder, from the breakpoints the code compares."""
    points = [0] + list(BREAKPOINTS) + [1 << 64]
    return [(points[i], points[i + 1] - 1) for i in range(len(points) - 1)]


def endpoints():
    return sorted({v for pair in intervals() for v in pair})


def step_model(x, figures=SIGNIFICANT_FIGURES):
    return 10 ** max(0, len(str(x)) - figures)


def perp_model(x, sz, figures=SIGNIFICANT_FIGURES):
    return min(step_model(x, figures), 10 ** (6 - sz))


def spot_model(x, k, figures=SIGNIFICANT_FIGURES):
    step = step_model(x, figures)
    return min(step, 10 ** k) if k < 20 else step


def next_model(x, tick):
    """The rounding-up arm: quotient + 1 saturated, product saturated, then at least 1."""
    q = min(x // tick + 1, MASK)
    return max(q * tick, 1) if q * tick <= MASK else MASK


def floor_model(x, tick):
    return max(x // tick * tick, 1)


def seeded(count):
    """Deterministic x values spread over every bit length."""
    out = []
    for i in range(count):
        raw = int.from_bytes(hashlib.sha256(SEED + i.to_bytes(4, 'little')).digest()[:8], 'little')
        out.append(raw >> (i % 64))
    return out


# ------------------------------------------------------------------------ locating

def read_rows(binary, start, end):
    return parse_listing(disassemble(binary, start, end))


def locate_window(rows):
    """The ladder inside one function: first row, join address, compared register, step register."""
    for i, (va, mn, ops, _) in enumerate(rows):
        if mn == 'cmp' and ops[1] == ('i', FIRST_LIMIT):
            prev = rows[i - 1]
            if prev[1] != 'mov' or prev[2][1] != ('i', 1) or prev[2][0][0] != 'r':
                raise EvidenceError(f'no step seed before {va:#x}')
            if rows[i + 1][1] != 'jb':
                raise EvidenceError(f'no jb after {va:#x}')
            return {'start': prev[0], 'join': rows[i + 1][2][0][1], 'x': ops[0][1],
                    'step': prev[2][0][1], 'cmp': va}
    raise EvidenceError('ladder start not found')


def window_rows(rows, window):
    """Rows between start and join that control flow reaches; cold blocks can sit in between."""
    by_va = {r[0]: r for r in rows}
    reached, todo = set(), [window['start']]
    while todo:
        va = todo.pop()
        if va in reached or va == window['join']:
            continue
        row = by_va.get(va)
        if row is None or not window['start'] <= va < window['join']:
            raise EvidenceError(f'window leaves its range at {va:#x}')
        reached.add(va)
        if row[1] in ('jb', 'jae', 'ja', 'jbe', 'jmp'):
            todo.append(row[2][0][1])
        if row[1] != 'jmp':
            todo.append(row[3])
    return [r for r in rows if r[0] in reached]


def is_spill(ops):
    """A stack slot save or restore; the only memory traffic a ladder window may have."""
    return any(op[0] == 'm' and op[2] == RSP and op[3] is None for op in ops[:2])


def breakpoints(rows, window):
    """Every threshold the window compares against, with a proof that nothing else steers it.

    Accepted: x copied to a scratch register and shifted right, immediates and constants
    moved into registers, a compare of x (or the shifted copy) with a constant consumed at
    once by an unsigned condition, stack spills.  The step register never takes a value
    derived from x, so the output is constant between two neighbouring thresholds.
    """
    x, step = window['x'], window['step']
    shifted, const = {}, {}
    found = set()
    for i, (va, mn, ops, _) in enumerate(rows):
        if mn in ('mov', 'movabs') and ops[0][0] == 'r':
            dst, src = ops[0][1], ops[1]
            if dst == x:
                raise EvidenceError(f'write to x at {va:#x}')
            shifted.pop(dst, None)
            const.pop(dst, None)
            if src[0] == 'i':
                const[dst] = src[1]
            elif src[0] == 'r' and src[1] == x and src[2] == 8:
                shifted[dst] = 0
            elif not is_spill(ops):
                raise EvidenceError(f'unexpected source at {va:#x}')
        elif mn == 'mov':
            if not is_spill(ops):
                raise EvidenceError(f'store outside the stack at {va:#x}')
        elif mn == 'shr':
            shifted[ops[0][1]] += ops[1][1]
        elif mn == 'cmp':
            left, right = ops
            if left[1] == x:
                k = 0
            elif left[1] in shifted:
                k = shifted[left[1]]
            else:
                raise EvidenceError(f'compare of a value not derived from x at {va:#x}')
            limit = right[1] if right[0] == 'i' else const[right[1]]
            cc = rows[i + 1][1]
            if cc in ('jb', 'jae', 'cmovb'):
                found.add(limit << k)
            elif cc in ('ja', 'jbe'):
                found.add((limit + 1) << k)
            else:
                raise EvidenceError(f'compare at {va:#x} is consumed by {cc}')
        elif mn == 'cmovb':
            if ops[1][1] in shifted or ops[1][1] == x:
                raise EvidenceError(f'x reaches a conditional move at {va:#x}')
        elif mn == 'inc':
            if ops[0][1] in shifted:
                raise EvidenceError(f'x reaches an increment at {va:#x}')
        elif mn not in ('jb', 'jae', 'ja', 'jbe', 'jmp'):
            raise EvidenceError(f'unexpected {mn} at {va:#x}')
        if mn in ('jb', 'jae', 'ja', 'jbe', 'jmp') and step in shifted:
            raise EvidenceError(f'step register holds x at {va:#x}')
    return sorted(found)


# --------------------------------------------------------------------- evaluation

def fresh(machine):
    """Entry state: sentinels everywhere, a stack, and a return address."""
    machine.reset()
    for idx in range(16):
        machine.setreg(idx, 0x5e5e000000000000 | idx)
    machine.setreg(RSP, STACK_TOP)
    machine.store(STACK_TOP, 8, RET_MAGIC)
    for slot in range(8, 0x200, 8):            # the caller frame holds earlier spills
        machine.store(STACK_TOP + slot, 8, 0x5f5f000000000000 | slot)


def run_window(machine, window, x):
    fresh(machine)
    machine.setreg(window['x'], x)
    machine.run(window['start'], stop={window['join']})
    if machine.regs[window['x']] != x:
        raise EvidenceError('window changed x')
    return machine.regs[window['step']]


def enter_function(machine, x):
    machine.reset()
    machine.setreg(RSP, STACK_TOP)
    machine.store(STACK_TOP, 8, RET_MAGIC)
    machine.setreg(RDI, META)
    machine.setreg(RDX, x)


def outcome(machine, stop_pc):
    """('ok', value) or ('panic', path, line, column) from where the run stopped."""
    if stop_pc == RET_MAGIC:
        if machine.regs[RSP] != STACK_TOP + 8:
            raise Unmodelled('unbalanced stack')
        return ('ok', machine.regs[RAX])
    register = RDX if stop_pc == PANIC_BOUNDS else RDI
    return ('panic',) + location(machine.img, machine.regs[register])


def run_perp(machine, fn, x, sz, asset=PERP_ASSET, dex=PERP_DEX, count=PERP_COUNT):
    enter_function(machine, x)
    machine.setreg(RSI, asset)
    machine.store(META + 0x30, 8, dex)
    machine.store(META + 0x10, 8, count)
    machine.store(META + 0x8, 8, TABLE)
    if asset % 10000 < count:
        machine.store(TABLE + asset % 10000 * PERP_STRIDE + PERP_SZ_OFFSET, 1, sz)
    return outcome(machine, machine.run(fn, stop=PANICS))


def run_spot(machine, fn, x, base_sz, quote_wei, flag=0, pair=SPOT_PAIR, tokens=SPOT_TOKENS):
    enter_function(machine, x)
    machine.setreg(RSI, pair)
    machine.flag_result = flag
    machine.store(META + 0x170, 8, SPOT_PAIRS)
    machine.store(META + 0x168, 8, TABLE)
    machine.store(META + 0x188, 8, tokens)
    machine.store(META + 0x180, 8, TOKENS)
    if pair < SPOT_PAIRS:
        machine.store(TABLE + pair * PAIR_STRIDE, 8, SPOT_BASE)
        machine.store(TABLE + pair * PAIR_STRIDE + 8, 8, SPOT_QUOTE)
    if SPOT_BASE < tokens:
        machine.store(TOKENS + SPOT_BASE * TOKEN_STRIDE + TOKEN_SZ_OFFSET, 1, base_sz)
    if SPOT_QUOTE < tokens:
        machine.store(TOKENS + SPOT_QUOTE * TOKEN_STRIDE + TOKEN_WEI_OFFSET, 1, quote_wei)
    return outcome(machine, machine.run(fn, stop=PANICS))


def flag_stub(machine):
    """The set lookup at the slot: answers from the test and records what it was asked."""
    machine.flag_calls.append((machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
    machine.after_stub(machine.flag_result)


def run_floor(machine, tail, x):
    fresh(machine)
    machine.setreg(tail['x'], x)
    pc = machine.run(tail['start'], stop={tail['stop'], tail['overflow']})
    if pc == tail['overflow']:
        return None
    return machine.regs[tail['x']]


def floor_tail(rows, window):
    """After the join: divide, multiply, overflow branch, store back into x."""
    after = [r for r in rows if r[0] >= window['join']]
    for i, (va, mn, ops, nxt) in enumerate(after):
        if mn == 'mul':
            if after[i + 1][1] != 'jo' or after[i + 2][1] != 'mov':
                raise EvidenceError(f'unexpected tail after {va:#x}')
            store = after[i + 2]
            if store[2] != (('r', window['x'], 8), ('r', RAX, 8)):
                raise EvidenceError(f'tail does not store into x at {store[0]:#x}')
            return {'start': window['start'], 'stop': store[3], 'overflow': after[i + 1][2][0][1],
                    'x': window['x'], 'mul': va}
    raise EvidenceError('no multiply after the join')


def run_rounding(machine, x, tick, round_up):
    """The real tail after the call at 0x2774192: floor or next, saturated, at least 1."""
    fresh(machine)
    machine.setreg(RAX, tick)
    machine.setreg(RBP, x)
    rsp = machine.regs[RSP]
    machine.store(rsp + 0x40, 1, int(round_up))
    machine.store(rsp + 0x28, 8, 0x1234)
    machine.run(ROUNDING_ENTRY, stop={ROUNDING_STOP})
    return machine.regs[RSI]


def location(img, record):
    """A Rust panic Location: path pointer (RELATIVE reloc), length, line, column."""
    ptr = img.relative_relocs_cached().get(record)
    if ptr is None:
        raise EvidenceError(f'no relocated path at {record:#x}')
    length, line, column = struct.unpack('<QII', img.read(record + 8, 16))
    path = img.read(ptr, length).decode()
    return (path[path.index('l1/src/'):], line, column)


# ---------------------------------------------------------------- whole-domain sweep

def sweep_windows(binary, fdes, functions):
    rows_by_fn, windows, table = {}, {}, []
    points = None
    for fn in functions:
        extent = fdes.range_of(fn)
        if extent['start'] != fn:
            raise EvidenceError(f'{fn:#x} is not an FDE start')
        rows = read_rows(binary, extent['start'], extent['end'])
        window = locate_window(rows)
        found = breakpoints(window_rows(rows, window), window)
        if points is None:
            points = found
        if found != points or tuple(found) != BREAKPOINTS:
            raise EvidenceError(f'{fn:#x} compares other thresholds: {found}')
        rows_by_fn[fn], windows[fn] = rows, window
        table.append((fn, extent['end'] - extent['start'], window))
    return rows_by_fn, windows, table


def check_windows(machine, windows):
    runs = mismatches = 0
    rows = []
    for lo, hi in intervals():
        values = set()
        for window in windows.values():
            for x in (lo, hi):
                got = run_window(machine, window, x)
                runs += 1
                values.add(got)
                mismatches += got != step_model(x)
        if len(values) != 1:
            raise EvidenceError(f'copies disagree on [{lo},{hi}]: {values}')
        rows.append((lo, hi, values.pop()))
    return runs, mismatches, rows


def check_perp(machine, functions):
    runs = mismatches = 0
    for fn in functions:
        for sz in range(7):
            for x in endpoints():
                got = run_perp(machine, fn, x, sz)
                runs += 1
                mismatches += got != ('ok', perp_model(x, sz))
    panics = {}
    for fn in functions:
        for sz in range(7, 256):
            got = run_perp(machine, fn, 1, sz)
            runs += 1
            panics[got] = panics.get(got, 0) + 1
    index = [run_perp(machine, fn, 1, 0, asset=PERP_ASSET + 10000) for fn in functions]
    index += [run_perp(machine, fn, 1, 0, asset=PERP_ASSET + PERP_COUNT) for fn in functions]
    return runs, mismatches, panics, sorted(set(index))


def check_spot(machine, functions):
    runs = mismatches = 0
    for fn in functions:
        for k in range(256):
            for x in endpoints():
                got = run_spot(machine, fn, x, 0, k)
                runs += 1
                mismatches += got != ('ok', spot_model(x, k))
    args = set()
    for call in machine.flag_calls:
        args.add(call)
    panics = {}
    for fn in functions:
        for sz in range(1, 256):
            got = run_spot(machine, fn, 1, sz, sz - 1)
            runs += 1
            panics[got] = panics.get(got, 0) + 1
    flags = {}
    for fn in functions:
        for flag in (1, 3, 0x101):
            for x in endpoints():
                got = run_spot(machine, fn, x, 0, 0, flag=flag)
                runs += 1
                flags[got] = flags.get(got, 0) + 1
        for x in endpoints():
            got = run_spot(machine, fn, x, 0, 8, flag=0xfe)
            runs += 1
            mismatches += got != ('ok', spot_model(x, 8))
    pair = [run_spot(machine, fn, 1, 0, 0, pair=SPOT_PAIRS) for fn in functions]
    token = [run_spot(machine, fn, 1, 0, 0, tokens=SPOT_QUOTE) for fn in functions]
    token += [run_spot(machine, fn, 1, 0, 0, tokens=SPOT_BASE) for fn in functions]
    return runs, mismatches, panics, flags, sorted(set(pair)), sorted(set(token)), sorted(args)


def floor_inputs():
    values = endpoints() + seeded(FLOOR_SEEDS)
    values += [step_model(x) * 7 for x in endpoints() if step_model(x) * 7 <= MASK]
    return sorted(set(values))


def check_floor(machine, tails):
    runs = mismatches = 0
    for tail in tails.values():
        for x in floor_inputs():
            got = run_floor(machine, tail, x)
            runs += 1
            mismatches += got != x // step_model(x) * step_model(x)
    return runs, mismatches


def check_rounding(machine):
    runs = mismatches = 0
    exact = []
    for x in floor_inputs():
        for tick in sorted({1, 10, 1000, step_model(x), 10 ** 15}):
            for round_up in (False, True):
                got = run_rounding(machine, x, tick, round_up)
                want = next_model(x, tick) if round_up else floor_model(x, tick)
                runs += 1
                mismatches += got != want
    for x, tick in ((1000, 10), (1005, 10), (1009, 10), (0, 10), (MASK, 1)):
        exact.append((x, tick, run_rounding(machine, x, tick, False), run_rounding(machine, x, tick, True)))
    return runs, mismatches, exact


# ---------------------------------------------------------------------- call sites

def census(img, pattern):
    """Every occurrence of a byte pattern in .text."""
    addr, text = img.text()
    return [addr + m.start() for m in re.finditer(re.escape(pattern), text)]


def call_sites(img, target):
    addr, text = img.text()
    out = []
    for m in re.finditer(b'\xe8', text):
        i = m.start()
        if i + 5 <= len(text) and addr + i + 5 + struct.unpack_from('<i', text, i + 1)[0] == target:
            out.append(addr + i)
    return out


def classify(rows):
    """What happens to the returned tick: REM (remainder test), FLOOR (product) or NEXT (q + 1).

    Walks the fall-through path, following `jmp` inside the window.  The divisor must be
    the register the return value was copied to.
    """
    index = {r[0]: i for i, r in enumerate(rows)}
    divisor = None
    divided = False
    i = 0
    seen = []
    while i < len(rows):
        va, mn, ops, _ = rows[i]
        seen.append(mn)
        if divisor is None and mn == 'mov' and ops[1] == ('r', RAX, 8) and ops[0][0] == 'r':
            divisor = ops[0][1]
        if mn == 'div':
            if ops[0][1] != divisor:
                raise EvidenceError(f'divisor at {va:#x} is not the returned tick')
            divided = True
        elif divided and mn == 'test' and ops[0] == ('r', RDX, 8) and ops[1] == ('r', RDX, 8):
            return 'REM', va
        elif divided and mn == 'inc':
            return 'NEXT', va
        elif divided and mn == 'mul':
            return 'FLOOR', va
        if mn == 'jmp' and ops[0][0] == 't' and ops[0][1] in index:
            i = index[ops[0][1]]
            continue
        i += 1
    raise EvidenceError(f'unclassified tail after {rows[0][0]:#x}: {seen}')


def gated(rows, va):
    """A NEXT arm taken only under a test: a second cmove back to the quotient, or a sign branch."""
    start = next(i for i, r in enumerate(rows) if r[0] == va)
    if any(r[1] == 'js' for r in rows[max(0, start - 3):start]):
        return True
    return any(r[1] == 'cmove' and r[2][1] == ('r', RAX, 8) for r in rows[start:start + 12])


def failure_literals(binary, va):
    """Order-status words stored on the failing path of a remainder test, in store order.

    Walks at most FAILURE_ROWS rows from the `test rdx,rdx`: a `jne` or `jmp` is followed, any
    other branch falls through, and the walk ends at a call or return.  A register counts
    when it holds a constant with the top bit set, built by movabs, add, lea or a copy.
    """
    regs, out = {}, []
    rows = read_rows(binary, va, va + FAILURE_CHUNK)
    i = walked = 0
    while walked < FAILURE_ROWS:
        if i >= len(rows) - 1:
            rows = read_rows(binary, rows[i][0], rows[i][0] + FAILURE_CHUNK)
            i = 0
        _, mn, ops, _ = rows[i]
        walked += 1
        i += 1
        if mn == 'movabs' and ops[1][0] == 'i':
            regs[ops[0][1]] = ops[1][1]
        elif mn == 'add' and ops[0][0] == 'r' and ops[0][1] in regs and ops[1][0] == 'i':
            regs[ops[0][1]] = (regs[ops[0][1]] + ops[1][1]) & MASK
        elif mn == 'lea' and ops[1][0] == 'm' and ops[1][2] in regs and ops[1][3] is None:
            regs[ops[0][1]] = (regs[ops[1][2]] + ops[1][5]) & MASK
        elif mn == 'mov' and ops[0][0] == 'r' and ops[1][0] == 'r' and ops[0][2] == 8:
            if ops[1][1] in regs:
                regs[ops[0][1]] = regs[ops[1][1]]
            else:
                regs.pop(ops[0][1], None)
        elif mn == 'mov' and ops[0][0] == 'm' and ops[1][0] == 'r' and ops[1][2] == 8:
            if regs.get(ops[1][1], 0) >> 63 and regs[ops[1][1]] not in out:
                out.append(regs[ops[1][1]])
        elif mn in ('call', 'ret'):
            break
        elif mn == 'jne' or (mn == 'jmp' and ops[0][0] == 't'):
            rows = read_rows(binary, ops[0][1], ops[0][1] + FAILURE_CHUNK)
            i = 0
    return out


def sweep_calls(binary, img, fdes, targets):
    rows = []
    for target, kind in targets.items():
        for site in call_sites(img, target):
            owner = fdes.range_of(site)
            tail = read_rows(binary, site + 5, min(site + 5 + CALL_TAIL, owner['end']))
            cls, va = classify(tail)
            cap = img.read(site - CAP_WINDOW, CAP_WINDOW).find(CAP_IMM) >= 0
            gate = cls == 'NEXT' and gated(tail, va)
            lits = failure_literals(binary, va) if cls == 'REM' else []
            rows.append((site, target, kind, owner['start'], cls, va, int(gate), lits, int(cap)))
    return rows


def status_message(binary, img, index):
    """The sentence of one index of the order-status Display jump table."""
    entry = struct.unpack('<i', img.read(STATUS_TABLE + index * 4, 4))[0]
    arm = (STATUS_TABLE + entry) & MASK
    rows = read_rows(binary, arm, arm + 0x20)
    lea = [r for r in rows if r[1] == 'lea' and r[2][1][0] == 'a']
    length = [r for r in rows if r[1] == 'mov' and r[2][0] == ('r', RDX, 4) and r[2][1][0] == 'i']
    if not lea or not length:
        raise EvidenceError(f'status arm at {arm:#x} has no message')
    return arm, lea[0][2][1][2], img.read(lea[0][2][1][2], length[0][2][1][1])


def check_status_messages(binary, img):
    """The Display at 0x3a008e0 maps word ^ 2^63 to an arm when the word has its top bit set."""
    rows = read_rows(binary, STATUS_DISPLAY, STATUS_DISPLAY + 0x30)
    lea = [r for r in rows if r[1] == 'lea']
    if len(lea) != 1 or lea[0][2][1][2] != STATUS_TABLE:
        raise EvidenceError('status table not found')
    if not any(r[1] == 'cmovs' for r in rows) or not any(r[1] == 'xor' for r in rows):
        raise EvidenceError('status decode changed')
    out = []
    for index, text in STATUS_TEXT.items():
        arm, va, got = status_message(binary, img, index)
        if got != text:
            raise EvidenceError(f'status {index} is {got!r}')
        out.append({'index': index, 'word': hex(STATUS_BASE + index), 'arm': hex(arm),
                    'message_va': hex(va), 'message': got.decode()})
    return out


def check_outer_tag(binary, img):
    """Error tag 0xc4 prints `{status} asset={n}`: status word at +8, asset at +4."""
    entry = struct.unpack('<i', img.read(ERROR_TABLE + OUTER_TAG * 4, 4))[0]
    arm = (ERROR_TABLE + entry) & MASK
    rows = read_rows(binary, arm, arm + 0x50)
    if rows[0][1] != 'lea' or rows[0][2][1][5] != 8 or rows[1][1] != 'add' or rows[1][2][1][1] != 4:
        raise EvidenceError(f'tag arm at {arm:#x} changed')
    lea = [r[2][1][2] for r in rows if r[1] == 'lea' and r[2][1][0] == 'a']
    if len(lea) != 3:
        raise EvidenceError(f'tag arm at {arm:#x} has {len(lea)} references')
    wrapper = read_rows(binary, lea[0], lea[0] + 0x10)
    if wrapper[0][1] != 'mov' or wrapper[1][1] != 'jmp' or wrapper[1][2][0][0] != 'a':
        raise EvidenceError('status wrapper changed')
    slot = wrapper[1][2][0][2]
    if img.slots().get(slot) != STATUS_DISPLAY:
        raise EvidenceError(f'wrapper reaches {img.slots().get(slot)}')
    pieces = img.read(lea[2], len(OUTER_PIECES))
    if pieces != OUTER_PIECES:
        raise EvidenceError(f'format pieces are {pieces!r}')
    return {'tag': hex(OUTER_TAG), 'arm': hex(arm), 'wrapper': hex(lea[0]), 'slot': hex(slot),
            'pieces': pieces.hex()}


def check_flag_function(binary, img, fdes):
    """The lookup behind the spot flag: reads word 0 of the pair, answers 0 when the set is empty."""
    extent = fdes.range_of(FLAG_FUNCTION)
    rows = read_rows(binary, extent['start'], extent['end'])
    want = ((('r', RAX, 8), ('m', 8, RDX, None, 1, 0x170)),
            (('r', RAX, 8), ('m', 8, RDX, None, 1, 0x168)),
            (('r', RBX, 8), ('m', 8, RAX, RSI, 1, 0)))
    got = [r[2] for r in rows if r[1] == 'mov' and len(r[2]) == 2]
    for ops in want:
        if ops not in got:
            raise EvidenceError(f'flag function lost {ops}')
    if not any(r[1] == 'cmp' and r[2] == (('m', 8, RDI, None, 1, 0x88), ('i', 0)) for r in rows):
        raise EvidenceError('flag function lost the empty test')
    return {'start': hex(extent['start']), 'fde_bytes': extent['end'] - extent['start']}


def coverage(machine, rows_by_fn, functions):
    """Instructions of whole functions the evaluator reached, with what it did not."""
    out = {}
    for fn in functions:
        rows = [r for r in rows_by_fn[fn] if r[1] not in ('nop', 'int3')]
        missed = [hex(r[0]) for r in rows if r[0] not in machine.seen]
        out[hex(fn)] = {'instructions': len(rows), 'executed': len(rows) - len(missed), 'not_executed': missed}
    return out


def worked_examples(machine):
    """Perp prices with szDecimals 0: the tick, and the remainder a caller tests."""
    rows = []
    for x, sz in WORKED_EXAMPLES:
        tick = run_perp(machine, PERP[0], x, sz)[1]
        rows.append({'x': x, 'sz': sz, 'tick': tick, 'remainder': x % tick, 'step': step_model(x)})
    return rows


def checked(cond, message):
    if not cond:
        raise EvidenceError(message)


# ------------------------------------------------------------------------- analysis

def analyse(binary, data):
    check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    for imm in (FAMILY_A, FAMILY_B):
        sites = census(img, struct.pack('<I', imm))
        owners = sorted(fdes.range_of(va)['start'] for va in sites)
        checked(owners == sorted(PERP + SPOT + FLOOR), f'census of {imm:#x} found {[hex(o) for o in owners]}')
    wide = sorted(fdes.range_of(va)['start'] for va in census(img, struct.pack('<Q', 10 ** 15 - 1)))
    checked(wide == sorted(PERP + SPOT + FLOOR + (DIGIT_COUNT,)), 'census of 10^15-1 changed')

    functions = PERP + SPOT + FLOOR
    rows_by_fn, windows, table = sweep_windows(binary, fdes, functions)
    tails = {fn: floor_tail(rows_by_fn[fn], windows[fn]) for fn in FLOOR}
    extra = read_rows(binary, ROUNDING_ENTRY, ROUNDING_STOP + 8)
    insns = [r for fn in functions for r in rows_by_fn[fn]] + extra
    slots = img.slots()
    checked(slots.get(FLAG_SLOT) == FLAG_FUNCTION, 'flag slot changed')
    slots[FLAG_SLOT] = FLAG_STUB
    machine = Machine(insns, img, slots)
    machine.flag_calls = []
    machine.flag_result = None
    machine.stubs[FLAG_STUB] = partial(flag_stub, machine)

    w_runs, w_bad, ladder = check_windows(machine, windows)
    p_runs, p_bad, p_panics, p_index = check_perp(machine, PERP)
    s_runs, s_bad, s_panics, s_flags, s_pair, s_token, flag_args = check_spot(machine, SPOT)
    f_runs, f_bad = check_floor(machine, tails)
    r_runs, r_bad, exact = check_rounding(machine)

    examples = worked_examples(machine)
    covered = coverage(machine, rows_by_fn, PERP + SPOT)
    status = check_status_messages(binary, img)
    outer = check_outer_tag(binary, img)
    flag_fn = check_flag_function(binary, img, fdes)
    calls = sweep_calls(binary, img, fdes, {fn: 'perp' for fn in PERP} | {fn: 'spot' for fn in SPOT})
    classes, forms = {}, {}
    for row in calls:
        classes[row[4]] = classes.get(row[4], 0) + 1
        if row[4] == 'REM':
            key = ','.join(hex(v) for v in row[7]) or 'none'
            forms[key] = forms.get(key, 0) + 1

    reference = []
    for lo, hi, step in ladder:
        ref = next(s for bound, s in REFERENCE_STEPS if lo < bound)
        reference.append((lo, hi, step, ref))
    result = {
        'binary_sha256': SHA256,
        'census': {'family_imm32': [hex(FAMILY_A), hex(FAMILY_B)], 'functions': len(functions),
                   'excluded_digit_count': hex(DIGIT_COUNT)},
        'breakpoints': list(BREAKPOINTS),
        'runs': {'windows': w_runs, 'perp': p_runs, 'spot': s_runs, 'floor': f_runs, 'rounding': r_runs},
        'mismatches': {'windows': w_bad, 'perp': p_bad, 'spot': s_bad, 'floor': f_bad, 'rounding': r_bad},
        'perp_panics': [{'outcome': list(k), 'count': v} for k, v in sorted(p_panics.items())],
        'perp_index_panics': [list(k) for k in p_index],
        'spot_panics': [{'outcome': list(k), 'count': v} for k, v in sorted(s_panics.items())],
        'spot_flag_outcomes': [{'outcome': list(k), 'count': v} for k, v in sorted(s_flags.items())],
        'spot_pair_panics': [list(k) for k in s_pair],
        'spot_token_panics': [list(k) for k in s_token],
        'spot_flag_arguments': [[hex(v) for v in call] for call in flag_args],
        'coverage': covered,
        'worked_examples': examples,
        'flag_function': flag_fn,
        'outer_error_tag': outer,
        'exact_multiple_probe': [{'x': x, 'tick': t, 'down': d, 'up': u} for x, t, d, u in exact],
        'status': status,
        'call_sites': {'total': len(calls), 'classes': dict(sorted(classes.items())),
                       'next_gated': sum(r[6] for r in calls),
                       'rem_failure_literals': dict(sorted(forms.items())),
                       'cap_1e15_before_call': sum(r[8] for r in calls)},
        'reference_decades_differing': sum(1 for r in reference if r[2] != r[3]),
    }
    for section in result['mismatches'].values():
        checked(section == 0, f'model mismatches: {result["mismatches"]}')
    return {'result': result, 'windows': table, 'reference': reference, 'calls': calls, 'machine': machine,
            'tails': tails, 'exponent': exponent_rows(machine)}


def exponent_rows(machine):
    x = MASK
    rows = []
    for sz in range(8):
        got = run_perp(machine, PERP[0], x, sz)
        rows.append(('perp', f'sz={sz}', got[1] if got[0] == 'ok' else ':'.join(str(v) for v in got[1:])))
    for k in list(range(0, 24)) + [31, 32, 63, 64, 127, 128, 255]:
        rows.append(('spot', f'k={k}', run_spot(machine, SPOT[1], MASK, 0, k)[1]))
    rows.append(('spot', 'k=-1', ':'.join(str(v) for v in run_spot(machine, SPOT[1], 1, 1, 0)[1:])))
    return rows


def write_outputs(out, analysis, data):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(analysis['result'], indent=1, sort_keys=True) + '\n')
    lines = ['x_low\tx_high\tstep\treference_step\tagrees']
    lines += [f'{lo}\t{hi}\t{step}\t{ref}\t{int(step == ref)}' for lo, hi, step, ref in analysis['reference']]
    (out / 'step-intervals.tsv').write_text('\n'.join(lines) + '\n')
    img = Image(data)
    lines = ['function\tfde_bytes\tgroup\twindow_start\tjoin\tx_register\tstep_register\twindow_sha256']
    for fn, size, w in analysis['windows']:
        group = 'perp' if fn in PERP else 'spot' if fn in SPOT else 'floor'
        digest = hashlib.sha256(img.read(w['start'], w['join'] - w['start'])).hexdigest()
        lines.append(f'{fn:#x}\t{size}\t{group}\t{w["start"]:#x}\t{w["join"]:#x}\t'
                     f'{REG64[w["x"]]}\t{REG64[w["step"]]}\t{digest}')
    (out / 'ladder-copies.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['site\ttarget\tkind\towner\tclass\tclass_va\tgated\tfailure_literals\tcap_1e15_before']
    for site, target, kind, owner, cls, va, gate, lits, cap in analysis['calls']:
        words = ','.join(hex(v) for v in lits) or '-'
        lines.append(f'{site:#x}\t{target:#x}\t{kind}\t{owner:#x}\t{cls}\t{va:#x}\t{gate}\t{words}\t{cap}')
    (out / 'call-sites.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['group\tinput\ttick_at_x_max_or_panic']
    lines += ['\t'.join(str(v) for v in row) for row in analysis['exponent']]
    (out / 'exponent-table.tsv').write_text('\n'.join(lines) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    binary = ROOT / BINARY
    data = binary.read_bytes()
    analysis = analyse(binary, data)
    write_outputs(args.out, analysis, data)
    r = analysis['result']
    print(f"runs {sum(r['runs'].values())}, mismatches {sum(r['mismatches'].values())}, "
          f"call sites {r['call_sites']['total']} {r['call_sites']['classes']}, "
          f"reference decades differing {r['reference_decades_differing']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
