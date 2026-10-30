#!/usr/bin/env python3
"""RE-004: the Wei cap chain around the 1.001 constant in node #94 (static, no execution).

The f64 constant 1.001 occurs once in `.rodata`, and five SSE instructions read it.
Each sits in a compact function that sums amounts, converts the sum, and ends in the
same arithmetic tail:

    factor = u32 as f64 / 1e8; require factor <= 1.01
    scaled = clamp(amount as f64 * factor)
    buffered = clamp(scaled as f64 * 1.001)
    result = buffered + 1_000_000, saturating, with a recorder call on overflow

This tool bounds each function with its FDE, reads it with objdump and interprets the
tail in a small Python evaluator.  Nothing from the binary runs natively.  The evaluator
performs binary64 arithmetic with Python floats, and it stops on any unmodelled mnemonic,
call or memory read.

    python3 tools/wei_buffered_cap.py --out <dir>

writes evidence.json, sites.tsv, boundaries.tsv and tail-bytes.txt.  Only the Python
standard library and objdump are used.
"""

import argparse
import bisect
import hashlib
import json
import math
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
SIZES = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16}
SEED = b'RE-004-wei-buffered-cap-94'
ADD_WEI = 1_000_000
MAX_FACTOR_INT = 101_000_000
WINDOW = 500
RECIPROCAL = 0x346dc5d63886594b
DROP_A, DROP_B = 0x277eba0, 0x4daf4a0      # the two local tag-drop helpers called in the tails
RECORDER_TARGET = 0x358dcd0
RECORD_LOCATION = 0x56dfd90
STACK, OUT = 0x7000000, 0x400000

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
REGS = {name: (i, 8) for i, name in enumerate(REG64)}
for i, name in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[name] = (i, 4)
for i, name in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[name] = (i, 1)


class EvidenceError(Exception):
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
    for name, _typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)

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

    def relative_relocs(self):
        _, off, size = self.sec['.rela.dyn']
        return {where: addend for where, info, addend in
                struct.iter_unpack('<QQq', self.data[off:off + size]) if info & 0xffffffff == 8}


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


def parse_operand(text, comment):
    if text in REGS:
        idx, size = REGS[text]
        return ('r', idx, size, text)
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
        base = None
        disp = 0
        for part in re.findall(r'[+-]?[^+-]+', inner):
            neg = part[0] == '-'
            part = part.lstrip('+-')
            if part in REGS:
                base = REGS[part][0]
            else:
                disp = -int(part, 16) if neg else int(part, 16)
        return ('m', size, base, disp)
    if re.fullmatch(r'[0-9a-f]+', text):
        return ('t', int(text, 16))
    raise EvidenceError(f'unparsed operand {text!r}')


def parse_listing(listing):
    """objdump text -> ordered list of (va, mnemonic, operands, text)."""
    out = []
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
        parts = body.split(None, 1)
        mn = parts[0] if parts else 'nop'
        ops = ()
        if len(parts) > 1:
            try:
                ops = tuple(parse_operand(p.strip(), comment) for p in parts[1].split(','))
            except (EvidenceError, KeyError, ValueError):
                mn, ops = 'unparsed', ()         # stops the evaluator only if reached
        out.append((va, mn, ops, body))
    return out


# ------------------------------------------------------------------ evaluator

class Unmodelled(Exception):
    pass


def d2u(val):
    return struct.unpack('<Q', struct.pack('<d', val))[0]


def u2d(val):
    return struct.unpack('<d', struct.pack('<Q', val))[0]


class Machine:
    """Integer and scalar SSE2 subset over Python values.  Python floats are IEEE binary64."""

    def __init__(self, insns, img, drop_targets=(), recorder_slot=None):
        self.insns = insns
        self.index = {ins[0]: i for i, ins in enumerate(insns)}
        self.img = img
        self.drop_targets = set(drop_targets)
        self.recorder_slot = recorder_slot
        self.reset()

    def reset(self):
        self.regs = [None] * 16
        self.xmm = [None] * 16
        self.mem = {}
        self.cf = self.zf = self.of = None
        self.records = []
        self.steps = 0

    def get(self, op):
        kind = op[0]
        if kind == 'r':
            val = self.regs[op[1]]
            if val is None:
                raise Unmodelled(f'read of poisoned {op[3]}')
            return val & ((1 << (op[2] * 8)) - 1)
        if kind == 'i':
            return op[1]
        if kind == 'm':
            ea = (self.regs[op[2]] + op[3]) & MASK
            key = (ea, op[1])
            if key not in self.mem:
                raise Unmodelled(f'read of unmodelled memory {ea:#x}/{op[1]}')
            return self.mem[key]
        if kind == 'a':
            return int.from_bytes(self.img.read(op[2], op[1]), 'little')
        raise Unmodelled(f'operand {op}')

    def put(self, op, val):
        if op[0] == 'r':
            self.regs[op[1]] = val & (MASK if op[2] == 8 else 0xffffffff)
            if op[2] not in (4, 8):
                raise Unmodelled('partial register write')
        elif op[0] == 'm':
            self.mem[((self.regs[op[2]] + op[3]) & MASK, op[1])] = val & ((1 << (op[1] * 8)) - 1)
        else:
            raise Unmodelled(f'write to {op}')

    def xget(self, op):
        """Low 64 bits of an xmm or a memory operand."""
        if op[0] == 'x':
            if self.xmm[op[1]] is None:
                raise Unmodelled('read of poisoned xmm')
            return self.xmm[op[1]] & MASK
        return self.get(op) & MASK

    def xfull(self, op):
        if op[0] == 'x':
            if self.xmm[op[1]] is None:
                raise Unmodelled('read of poisoned xmm')
            return self.xmm[op[1]]
        return self.get(op)

    def xset_low(self, idx, val):
        hi = (self.xmm[idx] or 0) >> 64
        self.xmm[idx] = (hi << 64) | val

    def cond(self, cc):
        if cc == 'e':
            return self.zf
        if cc == 'ae':
            return not self.cf
        if cc == 'b':
            return self.cf
        if cc == 'be':
            return self.cf or self.zf
        if cc == 'a':
            return not self.cf and not self.zf
        raise Unmodelled(f'condition {cc}')

    def clobber(self):
        for name in ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'):
            self.regs[REGS[name][0]] = None
        self.xmm = [None] * 16
        self.cf = self.zf = self.of = None

    def run(self, start, stops=(), limit=400):
        i = self.index[start]
        stops = set(stops)
        insns = self.insns
        while True:
            if self.steps >= limit:
                raise Unmodelled('step limit')
            va, mn, ops, text = insns[i]
            if va in stops:
                return va
            self.steps += 1
            i += 1
            if mn == 'mov':
                self.put(ops[0], self.get(ops[1]))
            elif mn == 'movq':
                if ops[0][0] == 'x':
                    self.xmm[ops[0][1]] = self.get(ops[1])
                else:
                    raise Unmodelled('movq to gpr')
            elif mn == 'movsd':
                if ops[1][0] == 'x':
                    self.xset_low(ops[0][1], self.xget(ops[1]))
                else:
                    self.xmm[ops[0][1]] = self.xget(ops[1])
            elif mn == 'movapd':
                self.xmm[ops[0][1]] = self.xfull(ops[1])
            elif mn == 'cvtsi2sd':
                self.xset_low(ops[0][1], d2u(float(to_signed(self.get(ops[1]), 64))))
            elif mn in ('addsd', 'subsd', 'mulsd', 'divsd'):
                a, b = u2d(self.xget(ops[0])), u2d(self.xget(ops[1]))
                res = {'addsd': lambda: a + b, 'subsd': lambda: a - b, 'mulsd': lambda: a * b,
                       'divsd': lambda: a / b}[mn]()
                self.xset_low(ops[0][1], d2u(res))
            elif mn == 'ucomisd':
                a, b = u2d(self.xget(ops[0])), u2d(self.xget(ops[1]))
                if a != a or b != b:
                    self.cf, self.zf = True, True
                else:
                    self.cf, self.zf = a < b, a == b
                self.of = False
            elif mn == 'xorpd':
                self.xmm[ops[0][1]] = self.xfull(ops[0]) ^ self.xfull(ops[1]) if ops[0] != ops[1] else 0
            elif mn == 'punpckldq':
                a, b = self.xfull(ops[0]), self.xfull(ops[1])
                self.xmm[ops[0][1]] = ((a & 0xffffffff) | ((b & 0xffffffff) << 32)
                                       | (((a >> 32) & 0xffffffff) << 64) | (((b >> 32) & 0xffffffff) << 96))
            elif mn == 'subpd':
                a, b = self.xfull(ops[0]), self.xfull(ops[1])
                lo = d2u(u2d(a & MASK) - u2d(b & MASK))
                hi = d2u(u2d(a >> 64) - u2d(b >> 64))
                self.xmm[ops[0][1]] = lo | (hi << 64)
            elif mn == 'unpckhpd':
                a, b = self.xfull(ops[0]), self.xfull(ops[1])
                self.xmm[ops[0][1]] = (a >> 64) | ((b >> 64) << 64)
            elif mn == 'cvttsd2si':
                self.put(ops[0], cvttsd2si(u2d(self.xget(ops[1]))))
            elif mn == 'sar':
                self.put(ops[0], to_signed(self.get(ops[0]), 64) >> ops[1][1])
            elif mn in ('and', 'or', 'xor'):
                bits = ops[0][2] * 8
                if mn == 'xor' and ops[0] == ops[1]:
                    res = 0
                else:
                    a, b = self.get(ops[0]), self.get(ops[1]) & ((1 << bits) - 1)
                    res = a & b if mn == 'and' else a | b if mn == 'or' else a ^ b
                self.put(ops[0], res)
                self.cf, self.zf = False, res == 0
            elif mn in ('cmp', 'add'):
                bits = ops[0][2] * 8
                mask = (1 << bits) - 1
                a, b = self.get(ops[0]), self.get(ops[1]) & mask
                if mn == 'cmp':
                    self.cf, self.zf = a < b, a == b
                else:
                    raw = a + b
                    self.cf, self.zf = raw > mask, raw & mask == 0
                    self.put(ops[0], raw)
            elif mn.startswith('cmov'):
                if self.cond(mn[4:]):
                    self.put(ops[0], self.get(ops[1]))
            elif mn == 'jmp':
                i = self.index[ops[0][1]]
            elif mn[0] == 'j':
                if self.cond(mn[1:]):
                    i = self.index[ops[0][1]]
            elif mn == 'lea':
                if ops[1][0] == 'a':
                    self.put(ops[0], ops[1][2])
                else:
                    self.put(ops[0], self.regs[ops[1][2]] + ops[1][3])
            elif mn == 'call':
                if ops[0][0] == 't' and ops[0][1] in self.drop_targets:
                    self.clobber()               # SysV: rbx and rsp survive; only rbx is read later
                elif ops[0][0] == 'a' and ops[0][2] == self.recorder_slot:
                    self.records.append((self.regs[REGS['rdi'][0]], self.regs[REGS['rsi'][0]]))
                    self.clobber()
                else:
                    raise Unmodelled(f'call at {va:#x}')
            else:
                raise Unmodelled(f'mnemonic {mn} at {va:#x}')


def to_signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) else val


def cvttsd2si(x):
    if x != x or x >= 2.0 ** 63 or x < -(2.0 ** 63):
        return 1 << 63
    return int(x) & MASK


# --------------------------------------------------------------------- models

ERR_FACTOR, OK_TAG = 0x13f, 0x186


def sat(x):
    """Decoded float clamp: NaN and +inf give 0, x >= 2^64 gives u64::MAX, else truncation."""
    if x != x or x == math.inf:
        return 0
    if x >= 2.0 ** 64:
        return MASK
    return int(x) if x > 0 else 0


def cap_model(amount, factor):
    """(tag, value, recorded) for one amount and one u32 factor."""
    fac = factor / 1e8
    if not fac <= 1.01:
        return (ERR_FACTOR, None, False)
    scaled = sat(float(amount) * fac)
    buffered = sat(float(scaled) * 1.001)
    if buffered >= (1 << 64) - ADD_WEI:
        return (OK_TAG, MASK, True)
    return (OK_TAG, buffered + ADD_WEI, False)


def lead_saturating(x):
    """Lead `saturating_f64_to_u64`: +inf gives u64::MAX."""
    if x != x or x <= 0.0:
        return 0
    if x >= 2.0 ** 64:
        return MASK
    return int(x)


def lead_buffered_cap(amount, factor):
    """Lead `Wei::buffered_cap`, for comparison only."""
    fac = factor / 1e8
    if not 0.0 <= fac <= 1.01:
        return None
    scaled = lead_saturating(float(amount) * fac)
    buffered = lead_saturating(float(scaled) * 1.001)
    return min(buffered + ADD_WEI, MASK)


def reciprocal_exact(multiplier, shift, divisor):
    """floor(x*multiplier / 2^shift) == floor(x/divisor) for every u64 x (Granlund-Montgomery)."""
    if multiplier != (1 << shift) // divisor + 1:
        return False
    error = multiplier * divisor - (1 << shift)
    return 0 < error <= (1 << (shift - 64))


def double_grid():
    """Every sign and exponent with four mantissas, plus both neighbours of each clamp bound."""
    out = []
    for sign in (0, 1):
        for exponent in range(2048):
            for mantissa in (0, 1, 1 << 51, (1 << 52) - 1):
                out.append((sign << 63) | (exponent << 52) | mantissa)
    for bound in (2.0 ** 63, 2.0 ** 64):
        out.extend([d2u(math.nextafter(bound, 0.0)), d2u(bound), d2u(math.nextafter(bound, math.inf))])
    return out


def amount_grid():
    base = [0, 1, 2, 999, 10 ** 6, 10 ** 8, 10 ** 8 + 1, 10 ** 12, 10 ** 15, 2 ** 32 - 1, 2 ** 32, 2 ** 52,
            2 ** 53 - 1, 2 ** 53, 2 ** 53 + 1, 2 ** 53 + 3, 2 ** 62, 2 ** 63 - 1025, 2 ** 63 - 1, 2 ** 63,
            2 ** 63 + 1, 2 ** 63 + 1025, 2 ** 64 - 4096, 2 ** 64 - 2049, 2 ** 64 - 2048, 2 ** 64 - 1025,
            2 ** 64 - 1024, 2 ** 64 - 1]
    out = list(base)
    for i in range(120):
        raw = hashlib.sha256(SEED + i.to_bytes(4, 'little')).digest()
        out.append(int.from_bytes(raw[:8], 'little') >> (raw[8] % 64))
    return out


def factor_grid():
    return [0, 1, 50_000_000, 99_999_999, 100_000_000, 100_000_001, 100_100_000, MAX_FACTOR_INT - 1, MAX_FACTOR_INT,
            MAX_FACTOR_INT + 1, MAX_FACTOR_INT + 2, 2 ** 31, 2 ** 32 - 1]


def saturation_threshold(factor):
    """Smallest u64 amount whose model output is u64::MAX (the model is monotone in amount), or None."""
    lo, hi = 0, MASK
    while lo < hi:
        mid = (lo + hi) // 2
        if cap_model(mid, factor)[1] == MASK:
            hi = mid
        else:
            lo = mid + 1
    return lo if cap_model(lo, factor)[1] == MASK else None


# ----------------------------------------------------------------- site anchors

SSE_RIP_RE = re.compile(rb'[\x66\xf2\xf3]?[\x40-\x4f]?\x0f[\x10\x28\x2e\x2f\x54\x58\x59\x5c\x5e]'
                        rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', re.S)
LEA_RIP_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', re.S)


def find_constant(img, value):
    addr, off, size = img.sec['.rodata']
    ro = img.data[off:off + size]
    needle = struct.pack('<d', value)
    hits = [m.start() for m in re.finditer(re.escape(needle), ro)]
    if len(hits) != 1:
        raise EvidenceError(f'expected one {value} in .rodata, found {len(hits)}')
    return addr + hits[0]


def rip_refs(text_va, text, target):
    sse = [text_va + m.start() for m in SSE_RIP_RE.finditer(text)
           if text_va + m.end() + struct.unpack('<i', m.group()[-4:])[0] == target]
    lea = [text_va + m.start() for m in LEA_RIP_RE.finditer(text)
           if text_va + m.end() + struct.unpack('<i', m.group()[-4:])[0] == target]
    return sse, lea


def direct_refs(text_va, text, targets):
    """Direct E8/E9 branches and RIP-relative LEAs that land on any target: {target: [(kind, va)]}."""
    out = {t: [] for t in targets}
    for m in re.finditer(rb'[\xe8\xe9]....', text, re.S):
        dest = text_va + m.end() + struct.unpack('<i', m.group()[1:])[0]
        if dest in out:
            out[dest].append(('call' if m.group()[0] == 0xe8 else 'jmp', text_va + m.start()))
    for m in LEA_RIP_RE.finditer(text):
        dest = text_va + m.end() + struct.unpack('<i', m.group()[-4:])[0]
        if dest in out:
            out[dest].append(('lea', text_va + m.start()))
    return out


def find_tail(insns):
    """Anchors of the cap arithmetic inside one function listing."""
    idx = next(i for i, ins in enumerate(insns) if ins[1] == 'cvtsi2sd')
    load = insns[idx - 1]
    if load[3] != 'mov    eax,DWORD PTR [rsp+0x14]':
        raise EvidenceError(f'unexpected factor load at {load[0]:#x}')
    ok_store = next(i for i in range(idx, len(insns)) if insns[i][3] == 'mov    WORD PTR [rdi],0x186')
    err_store = next(i for i in range(idx, len(insns)) if insns[i][3] == 'mov    WORD PTR [rdi],0x13f')
    join = insns[err_store + 1][2][0][1]
    mul_buffer = next(i for i in range(idx, ok_store) if insns[i][1] == 'mulsd' and insns[i][2][1][0] == 'a')
    stage2 = next(i for i in range(mul_buffer, ok_store) if insns[i][1] == 'ucomisd')
    stage1_end = next(i for i in range(idx, stage2) if insns[i][3] == 'movq   xmm2,rcx')
    tag_b2 = next(i for i in range(stage2, ok_store) if insns[i][1] == 'mov' and insns[i][2][1] == ('i', 0xb2))
    return {'tail_start': load[0], 'cvt': insns[idx][0], 'join': join, 'stage1_end': insns[stage1_end][0],
            'stage2': insns[stage2][0], 'stage2_end': insns[tag_b2][0], 'ok_store': insns[ok_store][0],
            'err_store': insns[err_store][0], 'indices': (idx - 1, ok_store + 1)}


def stage1_start(insns, tail):
    i = next(k for k, ins in enumerate(insns) if ins[0] == tail['cvt'])
    return next(ins[0] for ins in insns[i:] if ins[3].startswith('xorpd  xmm0,xmm0'))


def normalise(insns, lo, hi):
    """Text of insns[lo:hi] with RIP displacements replaced by their target and calls masked."""
    out = []
    for va, mn, ops, text in insns[lo:hi]:
        norm = re.sub(r'\[rip[+-]0x[0-9a-f]+\]', '[rip]', text)
        norm = re.sub(r'\[rsp\+0x(28|48)\]', '[rsp+SLOT]', norm)    # the drop-tag slot differs by frame size
        target = next((op[2] for op in ops if op[0] == 'a'), None)
        if mn == 'call' and ops and ops[0][0] == 't':
            norm = 'call DROP'
        elif mn[0] == 'j' or mn == 'jmp':
            norm = mn
        out.append(norm + (f' ->{target:#x}' if target is not None else ''))
    return out


def run_cap(machine, tail, amount, factor):
    m = machine
    m.reset()
    m.regs[4] = STACK
    m.regs[2] = amount
    m.mem[(STACK + 0x14, 4)] = factor
    m.mem[(STACK + 0x8, 8)] = OUT
    m.run(tail['tail_start'], stops=[tail['join']])
    tag = m.mem[(OUT, 2)]
    val = m.mem.get((OUT + 8, 8))
    return (tag, val, bool(m.records))


def run_clamp(machine, start, stop, reg_name, bits):
    m = machine
    m.reset()
    m.regs[4] = STACK
    m.regs[REGS['rbx'][0]] = 0
    m.regs[0] = MASK                         # set by the stage-1 `mov rax,-1`, read by stage 2
    m.xmm[0] = 0
    m.xmm[1] = bits
    m.xmm[2] = bits
    m.run(start, stops=[stop])
    return m.regs[REGS[reg_name][0]]


def check_site(machine, tail, insns):
    grid = [(a, f) for a in amount_grid() for f in factor_grid()]
    mismatch = rejected = recorded = 0
    for a, f in grid:
        got = run_cap(machine, tail, a, f)
        want = cap_model(a, f)
        if got != want:
            mismatch += 1
        rejected += want[0] == ERR_FACTOR
        recorded += want[2]
    window = 0
    for f in range(MAX_FACTOR_INT - WINDOW, MAX_FACTOR_INT + WINDOW + 1):
        window += run_cap(machine, tail, 1, f) != cap_model(1, f)
    start1 = stage1_start(insns, tail)
    clamp = 0
    for bits in double_grid():
        x = u2d(bits)
        clamp += run_clamp(machine, start1, tail['stage1_end'], 'rcx', bits) != sat(x)
        clamp += run_clamp(machine, tail['stage2'], tail['stage2_end'], 'rbx', bits) != sat(x)
    return {'grid': len(grid), 'grid_mismatch': mismatch, 'grid_rejected': rejected, 'grid_recorded': recorded,
            'factor_window': 2 * WINDOW + 1, 'factor_window_mismatch': window,
            'doubles': len(double_grid()), 'clamp_mismatch': clamp}


def extract_reciprocal_shift(insns):
    """Total right shift of the reciprocal division idiom, from the code.

    The sequence is: movabs rax, RECIPROCAL; mul <src> (unsigned, leaving
    the 128-bit product in rdx:rax); mov reg, rdx (the high half, an
    implicit shift of 64); shr reg, imm. Returns 64 + imm, or None when
    the idiom is not present in this shape.
    """
    for i, ins in enumerate(insns):
        if not re.search(r'movabs rax,0x346dc5d63886594b', ins[3]):
            continue
        window = insns[i + 1:i + 10]
        if not any(w[1] == 'mul' for w in window):
            return None
        for j, w in enumerate(window):
            m = re.search(r'mov\s+(r\w+),rdx$', w[3])
            if not m:
                continue
            for v in window[j + 1:]:
                s = re.search(rf'shr\s+{m.group(1)},0x([0-9a-f]+)$', v[3])
                if s:
                    return 64 + int(s.group(1), 16)
            return None
        return None
    return None


def scan_head(insns):
    """Decoded facts of the accumulation loop, by instruction text."""
    text = [ins[3] for ins in insns]
    has = lambda pat: any(re.search(pat, t) for t in text)                 # noqa: E731
    calls = sorted({ins[2][0][1] for ins in insns if ins[1] == 'call' and ins[2] and ins[2][0][0] == 't'})
    return {'mode_guard_fb': has(r'mov\s+WORD PTR \[rdi\],0xfb'),
            'cap_guard_28f5': has(r'movabs rcx,0x28f5c28f5c28f5c'),
            'overflow_tag_69': has(r'mov\s+WORD PTR \[rdi\],0x69'),
            'dex_reciprocal': has(r'movabs rax,0x346dc5d63886594b'),
            'amount_limit_68db': has(r'movabs rax,0x68db8bac710cb'),
            'times_100': has(r'imul\s+rbp,QWORD PTR \[rsp\+0x38\],0x64'),
            'ratio_flag_one': has(r'mov\s+ecx,0x1$'),
            'direct_calls': [hex(c) for c in calls]}


# --------------------------------------------------------------------- analysis

def analyse(binary_path, data):
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    relocs = img.relative_relocs()
    text_va, text = img.text()
    constant = find_constant(img, 1.001)
    sse, lea = rip_refs(text_va, text, constant)
    movabs = len(re.findall(rb'[\x48\x49][\xb8-\xbf]' + re.escape(struct.pack('<d', 1.001)), text))
    if not sse:
        raise EvidenceError('no reference to the 1.001 constant')

    sites, forms, details = [], {}, []
    reciprocal_shifts = set()
    agg = {'grid': 0, 'grid_mismatch': 0, 'factor_window_mismatch': 0, 'clamp_mismatch': 0, 'doubles': 0}
    recorder = None
    for ref in sse:
        r = fdes.range_of(ref)
        insns = parse_listing(disassemble(binary_path, r['start'], r['end']))
        tail = find_tail(insns)
        heads = scan_head(insns)
        if heads['dex_reciprocal']:
            shift = extract_reciprocal_shift(insns)
            if shift is None:
                raise EvidenceError('reciprocal shift not extractable at a dex site')
            reciprocal_shifts.add(shift)
        drops = {DROP_A, DROP_B} & set(int(c, 16) for c in heads['direct_calls'])
        rec_lea = next(ins for ins in insns if ins[1] == 'call' and ins[2][0][0] == 'a'
                       and ins[0] > tail['ok_store'] and relocs.get(ins[2][0][2]) == RECORDER_TARGET)
        recorder = rec_lea[2][0][2]
        machine = Machine(insns, img, drops, recorder)
        res = check_site(machine, tail, insns)
        for key in agg:
            agg[key] += res[key]
        lo, hi = tail['indices']
        form = tuple(normalise(insns, lo, hi))
        forms.setdefault(form, []).append(hex(r['start']))
        site = {'ref_va': hex(ref), 'fn_start': hex(r['start']), 'fn_end': hex(r['end']), 'fde': hex(r['fde']),
                'size': r['end'] - r['start'], 'tail_start': hex(tail['tail_start']), 'join': hex(tail['join']),
                'head': heads, 'result': res}
        sites.append(site)
        details.append((r['start'], img.read(tail['tail_start'], tail['ok_store'] - tail['tail_start'] + 5)))

    location = img.read(RECORD_LOCATION + 8, 16)
    loc_len = struct.unpack('<Q', location[:8])[0]
    line, col = struct.unpack('<II', location[8:])
    path = img.read(relocs[RECORD_LOCATION], loc_len)
    tail_form = next(iter(forms))
    max_x = float(MASK) * (MAX_FACTOR_INT / 1e8)
    max_y = float(sat(max_x)) * 1.001
    lead_mismatch = sum(1 for a in amount_grid() for f in factor_grid() if
                        (cap_model(a, f)[1] if cap_model(a, f)[0] == OK_TAG else None) != lead_buffered_cap(a, f))
    lead_clamp = [hex(bits) for bits in double_grid() if sat(u2d(bits)) != lead_saturating(u2d(bits))]
    thresholds = []
    for f in (MAX_FACTOR_INT, 100_000_000, 99_900_000, 50_000_000):
        t = saturation_threshold(f)
        thresholds.append({'factor': f, 'first_saturating_amount': t,
                           'output_at_max_amount': cap_model(MASK, f)[1]})
    boundary_rows = []
    sample = sites[0]
    insns0 = parse_listing(disassemble(binary_path, int(sample['fn_start'], 16), int(sample['fn_end'], 16)))
    tail0 = find_tail(insns0)
    machine0 = Machine(insns0, img, {DROP_A, DROP_B}, recorder)
    for a, f in ((0, 0), (0, MAX_FACTOR_INT), (1, 100_000_000), (10 ** 8, 100_000_000), (10 ** 15, 100_000_000),
                 (10 ** 15, MAX_FACTOR_INT), (2 ** 53 + 1, 100_000_000), (2 ** 63, 100_000_000),
                 (2 ** 64 - 1, 100_000_000), (2 ** 64 - 1, MAX_FACTOR_INT), (1, MAX_FACTOR_INT + 1), (1, 2 ** 32 - 1)):
        boundary_rows.append((a, f) + run_cap(machine0, tail0, a, f))
    for row in thresholds:
        t, f = row['first_saturating_amount'], row['factor']
        if t is None:
            continue
        boundary_rows.append((t - 1, f) + run_cap(machine0, tail0, t - 1, f))
        boundary_rows.append((t, f) + run_cap(machine0, tail0, t, f))

    starts = [int(site['fn_start'], 16) for site in sites]
    refs = direct_refs(text_va, text, starts)
    for site, start in zip(sites, starts):
        site['direct_refs'] = [[kind, hex(va)] for kind, va in refs[start]]
    limit_refs = rip_refs(text_va, text, find_constant(img, 1.01))[0]
    if len(reciprocal_shifts) != 1:
        raise EvidenceError(f'reciprocal shifts disagree across sites: {sorted(reciprocal_shifts)}')
    reciprocal_shift = reciprocal_shifts.pop()

    result = {
        'task': 'RE-004', 'question': 'Wei cap arithmetic: factor guard, float chain, buffered saturating add',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)}, 'fde_table_entries': fdes.count,
        'constant_1_001': {'va': hex(constant), 'hex': struct.pack('<d', 1.001).hex()},
        'recorder': {'got_slot': hex(recorder), 'target': hex(RECORDER_TARGET),
                     'location': {'va': hex(RECORD_LOCATION), 'file': path.split(b'/code_Mainnet/')[-1].decode(),
                                  'line': line, 'col': col}},
        'sites': sites, 'tail_text': list(tail_form),
        'reciprocal_10000': {'multiplier': hex(RECIPROCAL), 'shift': reciprocal_shift,
                             'exact_for_all_u64': reciprocal_exact(RECIPROCAL, reciprocal_shift, 10000)},
        'factor': {'max_admitted': MAX_FACTOR_INT,
                   'quotient_at_max': (MAX_FACTOR_INT / 1e8).hex(), 'limit': (1.01).hex(),
                   'quotient_above_max': ((MAX_FACTOR_INT + 1) / 1e8).hex()},
        'reachable_range': {'max_stage1_double': max_x.hex(), 'max_stage2_double': max_y.hex(),
                            'nan_or_inf_reachable': not (math.isfinite(max_x) and math.isfinite(max_y))},
        'lead': {'grid_mismatch': lead_mismatch, 'clamp_bits_differing': lead_clamp},
        'saturation_thresholds': thresholds,
        'summary': {
            'sse_refs': len(sse), 'lea_refs': len(lea), 'movabs_refs': movabs,
            'limit_1_01_sse_refs': len(limit_refs),
            'direct_refs_total': sum(len(v) for v in refs.values()),
            'ratio_flag_one_sites': sum(1 for site in sites if site['head']['ratio_flag_one']),
            'functions': len({s['fn_start'] for s in sites}),
            'distinct_tail_forms': len(forms), 'tail_instructions': len(tail_form),
            'grid_vectors': agg['grid'], 'grid_mismatches': agg['grid_mismatch'],
            'factor_window_mismatches': agg['factor_window_mismatch'],
            'doubles_per_site': agg['doubles'] // len(sites), 'clamp_mismatches': agg['clamp_mismatch'],
            'max_factor_int': MAX_FACTOR_INT,
            'lead_grid_mismatches': lead_mismatch, 'lead_clamp_differences': len(lead_clamp),
            'reciprocal_exact': reciprocal_exact(RECIPROCAL, reciprocal_shift, 10000),
            'nan_or_inf_reachable': not (math.isfinite(max_x) and math.isfinite(max_y)),
        },
    }
    return result, boundary_rows, details


def write(out, result, boundary_rows, details):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    rows = ['ref_va\tfn_start\tfn_end\tfde\tsize\tgrid\tgrid_mismatch\tfactor_window_mismatch\tdoubles\tclamp_mismatch'
            '\tdex_variant\tdirect_calls']
    for s in result['sites']:
        r = s['result']
        rows.append('\t'.join([s['ref_va'], s['fn_start'], s['fn_end'], s['fde'], str(s['size']), str(r['grid']),
                               str(r['grid_mismatch']), str(r['factor_window_mismatch']), str(r['doubles']),
                               str(r['clamp_mismatch']), str(int(s['head']['dex_reciprocal'])),
                               ','.join(s['head']['direct_calls'])]))
    (out / 'sites.tsv').write_text('\n'.join(rows) + '\n')
    rows = ['amount\tfactor\ttag\tvalue\trecorded']
    for a, f, tag, val, rec in boundary_rows:
        rows.append(f"{a}\t{f}\t{tag:#x}\t{'-' if val is None else val}\t{int(rec)}")
    (out / 'boundaries.tsv').write_text('\n'.join(rows) + '\n')
    lines = []
    for start, raw in details:
        lines.append(f'# tail bytes of function {start:#x}')
        lines.append(raw.hex())
        lines.append('')
    (out / 'tail-bytes.txt').write_text('\n'.join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        result, boundary_rows, details = analyse(args.binary, args.binary.read_bytes())
    except (EvidenceError, Unmodelled) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, boundary_rows, details)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
