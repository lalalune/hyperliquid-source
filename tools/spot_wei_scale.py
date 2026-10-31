#!/usr/bin/env python3
"""RE-004: the 10^(weiDecimals - szDecimals) family in node #94 (static, no execution).

Every copy of the spot token wei scale panics through one Rust Location,
`l1/src/spot_meta.rs:1199:57`.  This tool finds that Location from `.rela.dyn`,
finds every RIP-relative LEA that loads it, bounds each holding function with its
FDE and reads the instructions with objdump.  A small Python evaluator then
interprets the decoded instruction text on concrete inputs.  Nothing from the
binary runs natively: the evaluator is a table of integer operations over Python
ints, and any `call` it cannot justify stops the run.

Two claims are evaluated:

  ladder   for each holder, all 256 exponents and all 255 borrow cases, against
           10^k for k in 0..=19 and a panic otherwise (all 65536 byte pairs for the
           one helper that takes a TokenSpec pointer)
  helpers  for twelve small conversion helpers, a closed-form model on a fixed
           boundary grid plus seeded pseudo-random vectors

    python3 tools/spot_wei_scale.py --out <dir>

writes evidence.json, holders.tsv, helpers.tsv, pow10-exponents.tsv and
helper-bytes.txt.  Only the Python standard library and objdump are used.
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
SOURCE_SUFFIX = b'l1/src/spot_meta.rs'
SCALE_LOCATION = (1199, 57)
TOKEN_LOCATION = (113, 33)
UNWRAP_MESSAGE = b'called `Option::unwrap()` on a `None` value'
UDIVTI3_SLOT = 0x576e1a8
MASK = (1 << 64) - 1
SIZES = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8}
SEED = b'RE-004-spot-wei-scale-94'
RANDOM_VECTORS = 400

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
REGS = {name: (i, 8) for i, name in enumerate(REG64)}
for i, name in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[name] = (i, 4)
for i, name in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[name] = (i, 1)
CALLEE_SAVED = {'rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'}


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


# ------------------------------------------------------------- binary anchoring

def find_locations(img, relocs):
    """Rust Location records whose file pointer ends with SOURCE_SUFFIX: {(line, col): VA}."""
    addr, off, size = img.sec['.rodata']
    ro = img.data[off:off + size]
    first = ro.find(SOURCE_SUFFIX + b'\0')
    if first == -1 or ro.find(SOURCE_SUFFIX + b'\0', first + 1) != -1:
        raise EvidenceError('expected exactly one spot_meta.rs path in .rodata')
    end = addr + first + len(SOURCE_SUFFIX)
    out = {}
    drr = img.sec['.data.rel.ro']
    for where, addend in relocs.items():
        if not (drr[0] <= where < drr[0] + drr[2] - 24) or not addr <= addend < end:
            continue
        length = struct.unpack('<Q', img.read(where + 8, 8))[0]
        if addend + length == end:
            line, col = struct.unpack('<II', img.read(where + 16, 8))
            out[(line, col)] = where
    return out


def lea_rip_refs(text_va, text, target):
    """VAs of every REX.W 8D /r (mod=00, rm=101) loading exactly target."""
    out = []
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', text, re.S):
        if text_va + m.end() + struct.unpack('<i', m.group()[3:])[0] == target:
            out.append(text_va + m.start())
    return out


def ladder_signature_sites(text_va, text):
    """imul r64,r64,10^8 with imul by 10^4 in the 48 bytes before and movabs 10^16 in the 48 after."""
    sites = []
    for m in re.finditer(rb'[\x48\x4c\x49\x4d]\x69[\xc0-\xff]\x00\xe1\xf5\x05', text):
        before = text[max(0, m.start() - 48):m.start()]
        after = text[m.end():m.end() + 48]
        if re.search(rb'\x69[\xc0-\xff]\x10\x27\x00\x00', before) and b'\x00\x00\xc1\x6f\xf2\x86\x23\x00' in after:
            sites.append(text_va + m.start())
    return sites


def call_slot_target(img, relocs, call_va):
    """`call [rip+disp32]` (FF 15) at call_va -> (GOT slot VA, relocated target)."""
    raw = img.read(call_va, 6)
    if raw[:2] != b'\xff\x15':
        raise EvidenceError(f'no indirect call at {call_va:#x}')
    slot = call_va + 6 + struct.unpack('<i', raw[2:])[0]
    if slot not in relocs:
        raise EvidenceError(f'GOT slot {slot:#x} has no RELATIVE relocation')
    return slot, relocs[slot]


def panic_message(img, target):
    """Target must be `lea rdi,[rip+msg]; mov esi,len` after a frame prologue (4 bytes)."""
    raw = img.read(target, 16)
    if raw[:4] != b'\x55\x48\x89\xe5' or raw[4:7] != b'\x48\x89\xfa' or raw[7:10] != b'\x48\x8d\x3d' \
            or raw[14] != 0xbe:
        raise EvidenceError(f'unexpected panic stub at {target:#x}')
    msg = target + 14 + struct.unpack('<i', raw[10:14])[0]
    length = struct.unpack('<I', img.read(target + 15, 4))[0]
    return img.read(msg, length)


# ------------------------------------------------------------ instruction reader

def disassemble(binary, start, end):
    cmd = ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(binary)]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
MEM_RE = re.compile(r'^(?:(BYTE|WORD|DWORD|QWORD) PTR )?\[(.*)\]$')


def parse_operand(text, comment):
    if text in REGS:
        idx, size = REGS[text]
        return ('r', idx, size, text)
    if re.fullmatch(r'0x[0-9a-f]+', text):
        return ('i', int(text, 16))
    m = MEM_RE.match(text)
    if m:
        size = SIZES.get(m.group(1), 8)
        inner = m.group(2)
        if inner.startswith('rip'):
            if comment is None:
                raise EvidenceError(f'rip operand without target: {text}')
            return ('a', size, comment)
        base = index = None
        scale = 1
        disp = 0
        for part in re.findall(r'[+-]?[^+-]+', inner):
            neg = part[0] == '-'
            part = part.lstrip('+-')
            if '*' in part:
                reg, mul = part.split('*')
                index, scale = REGS[reg][0], int(mul)
            elif part in REGS:
                if base is None:
                    base = REGS[part][0]
                else:
                    index, scale = REGS[part][0], 1
            else:
                disp = -int(part, 16) if neg else int(part, 16)
        return ('m', size, base, index, scale, disp)
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
        if body.startswith('data16') or body.startswith('cs ') or body.startswith('nop'):
            out.append((va, 'nop', (), body))
            continue
        parts = body.split(None, 1)
        mn = parts[0]
        ops = ()
        if len(parts) > 1:
            try:
                ops = tuple(parse_operand(p.strip(), comment) for p in parts[1].split(','))
            except (EvidenceError, KeyError, ValueError):
                mn, ops = 'unparsed', ()         # stops the evaluator only if reached
        out.append((va, mn, ops, body))
    return out


# ------------------------------------------------------------------ evaluator

class Panic(Exception):
    def __init__(self, location):
        super().__init__(location)
        self.location = location


class Unmodelled(Exception):
    pass


class Machine:
    """Integer subset of x86-64 over Python ints.  Registers start poisoned (None)."""

    def __init__(self, insns, panics, udiv_slot=None, default_mem=None):
        self.insns = insns
        self.index = {ins[0]: i for i, ins in enumerate(insns)}
        self.panics = panics
        self.udiv_slot = udiv_slot
        self.default_mem = default_mem
        self.regs = [None] * 16
        self.mem = {}
        self.cf = self.zf = self.sf = self.of = None
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
        return self.load(self.addr(op), opsize(op))

    def addr(self, op):
        if op[0] == 'a':
            return op[2]
        _, _, base, index, scale, disp = op
        ea = disp
        if base is not None:
            if self.regs[base] is None:
                raise Unmodelled('poisoned base register')
            ea += self.regs[base]
        if index is not None:
            if self.regs[index] is None:
                raise Unmodelled('poisoned index register')
            ea += self.regs[index] * scale
        return ea & MASK

    def load(self, ea, size):
        key = (ea, size)
        if key in self.mem:
            return self.mem[key]
        if self.default_mem is not None:
            return self.default_mem
        raise Unmodelled(f'read of unmodelled memory {ea:#x}/{size}')

    def store(self, ea, size, val):
        self.mem[(ea, size)] = val & ((1 << (size * 8)) - 1)

    def put(self, op, val):
        if op[0] == 'r':
            idx, size = op[1], op[2]
            if size == 8:
                self.regs[idx] = val & MASK
            elif size == 4:
                self.regs[idx] = val & 0xffffffff
            else:
                old = self.regs[idx]
                if old is None:
                    raise Unmodelled('partial write to poisoned register')
                self.regs[idx] = (old & ~0xff) | (val & 0xff)
        else:
            self.store(self.addr(op), opsize(op), val)

    def logic_flags(self, val, bits):
        self.cf = self.of = False
        self.zf = val == 0
        self.sf = bool(val >> (bits - 1))

    def add_flags(self, a, b, carry, bits):
        mask = (1 << bits) - 1
        raw = a + b + carry
        res = raw & mask
        self.cf = raw > mask
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))
        self.of = bool(~(a ^ b) & (a ^ res) & (1 << (bits - 1)))
        return res

    def sub_flags(self, a, b, borrow, bits):
        mask = (1 << bits) - 1
        raw = a - b - borrow
        res = raw & mask
        self.cf = raw < 0
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))
        self.of = bool((a ^ b) & (a ^ res) & (1 << (bits - 1)))
        return res

    def cond(self, cc):
        if cc in ('e', 'z'):
            return self.zf
        if cc in ('ne', 'nz'):
            return not self.zf
        if cc in ('b', 'c'):
            return self.cf
        if cc in ('ae', 'nc'):
            return not self.cf
        if cc == 'a':
            return not self.cf and not self.zf
        if cc == 'be':
            return self.cf or self.zf
        if cc == 'o':
            return self.of
        if cc == 'no':
            return not self.of
        if cc == 's':
            return self.sf
        if cc == 'ns':
            return not self.sf
        raise Unmodelled(f'condition {cc}')

    def run(self, start, stops=(), limit=4000):
        i = self.index[start]
        insns = self.insns
        stops = set(stops)
        while True:
            if self.steps >= limit:
                raise Unmodelled('step limit')
            if i >= len(insns):
                raise Unmodelled('ran off the listing')
            va, mn, ops, text = insns[i]
            if va in stops:
                return ('stop', va)
            self.steps += 1
            i += 1
            if mn == 'nop':
                continue
            if mn == 'mov':
                self.put(ops[0], self.get(ops[1]))
            elif mn == 'movabs':
                self.put(ops[0], ops[1][1])
            elif mn == 'movzx':
                self.put(ops[0], self.get(ops[1]))
            elif mn == 'push':
                self.regs[4] = (self.regs[4] - 8) & MASK
                val = self.regs[ops[0][1]]
                self.mem[(self.regs[4], 8)] = 0 if val is None else val
            elif mn == 'pop':
                self.regs[ops[0][1]] = self.mem[(self.regs[4], 8)]
                self.regs[4] = (self.regs[4] + 8) & MASK
            elif mn in ('add', 'adc'):
                bits = ops[0][2] * 8 if ops[0][0] == 'r' else opsize(ops[0]) * 8
                carry = int(self.cf) if mn == 'adc' else 0
                self.put(ops[0], self.add_flags(self.get(ops[0]), self.get(ops[1]) & ((1 << bits) - 1), carry, bits))
            elif mn in ('sub', 'sbb', 'cmp'):
                bits = ops[0][2] * 8 if ops[0][0] == 'r' else opsize(ops[0]) * 8
                borrow = int(self.cf) if mn == 'sbb' else 0
                res = self.sub_flags(self.get(ops[0]), self.get(ops[1]) & ((1 << bits) - 1), borrow, bits)
                if mn != 'cmp':
                    self.put(ops[0], res)
            elif mn in ('and', 'or', 'xor', 'test'):
                bits = ops[0][2] * 8 if ops[0][0] == 'r' else opsize(ops[0]) * 8
                mask = (1 << bits) - 1
                if mn == 'xor' and ops[0] == ops[1]:
                    res = 0
                else:
                    a, b = self.get(ops[0]), self.get(ops[1]) & mask
                    res = a | b if mn == 'or' else a ^ b if mn == 'xor' else a & b
                self.logic_flags(res, bits)
                if mn != 'test':
                    self.put(ops[0], res)
            elif mn == 'dec':
                bits = ops[0][2] * 8
                cf = self.cf
                self.put(ops[0], self.sub_flags(self.get(ops[0]), 1, 0, bits))
                self.cf = cf
            elif mn == 'imul':
                if len(ops) == 3:
                    a, b = self.get(ops[1]), ops[2][1]
                else:
                    a, b = self.get(ops[0]), self.get(ops[1])
                bits = ops[0][2] * 8
                full = to_signed(a, bits) * to_signed(b, bits)
                res = full & ((1 << bits) - 1)
                self.cf = self.of = full != to_signed(res, bits)
                self.put(ops[0], res)
            elif mn == 'mul':
                bits = opsize(ops[0]) * 8 if ops[0][0] != 'r' else ops[0][2] * 8
                if bits != 64:
                    raise Unmodelled('narrow mul')
                full = self.regs[0] * self.get(ops[0])
                self.regs[0] = full & MASK
                self.regs[2] = full >> 64
                self.cf = self.of = self.regs[2] != 0
            elif mn == 'div':
                bits = ops[0][2] * 8
                d = self.get(ops[0])
                if d == 0:
                    raise Unmodelled('divide by zero')
                if bits == 64:
                    n = (self.regs[2] << 64) | self.regs[0]
                else:
                    n = ((self.regs[2] & 0xffffffff) << 32) | (self.regs[0] & 0xffffffff)
                q, r = divmod(n, d)
                if q >> bits:
                    raise Unmodelled('divide overflow')
                self.regs[0], self.regs[2] = q, r
            elif mn == 'shl':
                bits = ops[0][2] * 8
                res = (self.get(ops[0]) << ops[1][1]) & ((1 << bits) - 1)
                self.logic_flags(res, bits)
                self.put(ops[0], res)
            elif mn == 'shr':
                bits = ops[0][2] * 8
                res = self.get(ops[0]) >> ops[1][1]
                self.logic_flags(res, bits)
                self.put(ops[0], res)
            elif mn.startswith('cmov'):
                if self.cond(mn[4:]):
                    self.put(ops[0], self.get(ops[1]))
            elif mn.startswith('set'):
                self.put(ops[0], int(self.cond(mn[3:])))
            elif mn == 'jmp':
                i = self.index[ops[0][1]]
            elif mn[0] == 'j':
                if self.cond(mn[1:]):
                    i = self.index[ops[0][1]]
            elif mn == 'lea':
                ea = self.addr(ops[1])
                if ea in self.panics:
                    raise Panic(ea)
                raise Unmodelled(f'lea at {va:#x}')
            elif mn == 'ret':
                return ('ret', va)
            elif mn == 'call':
                if ops[0][0] == 'a' and ops[0][2] == self.udiv_slot:
                    n = self.regs[7] | (self.regs[6] << 64)
                    d = self.regs[2] | (self.regs[1] << 64)
                    if d == 0:
                        raise Unmodelled('u128 divide by zero')
                    q = n // d
                    self.regs[0], self.regs[2] = q & MASK, q >> 64
                    for name in ('rcx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'):
                        self.regs[REGS[name][0]] = None
                    self.cf = self.zf = self.sf = self.of = None
                else:
                    raise Unmodelled(f'call at {va:#x}')
            else:
                raise Unmodelled(f'mnemonic {mn} at {va:#x}')


def opsize(op):
    return op[1]


def to_signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) else val


# ------------------------------------------------------------------ ladder claim

def pow10_model(sz, wei):
    if wei < sz or wei - sz > 19:
        return None
    return 10 ** (wei - sz)


def is_exponent_load(ins):
    return ins[1] == 'movzx' and ins[2][1][0] == 'm' and ins[2][1][1] == 1 and ins[2][1][5] in (0x19, 0x49)


def find_ladders(insns, scale_location):
    """Each `movzx r,[..+wei]; sub r8,[..+sz]; jb panic` with the k==0 fall-through join."""
    out = []
    for i, ins in enumerate(insns):
        if not is_exponent_load(ins):
            continue
        for j in range(i + 1, min(i + 4, len(insns))):
            sub = insns[j]
            if sub[1] == 'sub' and sub[2][1][0] == 'm' and sub[2][1][1] == 1 \
                    and sub[2][1][5] == ins[2][1][5] - 1 and sub[2][0][1] == ins[2][0][1]:
                break
        else:
            continue
        if insns[j + 1][1] != 'jb':
            continue
        panic_target = insns[j + 1][2][0][1]
        k = j + 2
        while insns[k][1] != 'jne':
            if k > j + 6:
                raise EvidenceError(f'no jne after {sub[0]:#x}')
            k += 1
        # The accumulator starts at 1; it may be set before the exponent load (0x32814c0).
        results = [x for x in insns[max(0, i - 10):k] if x[1] == 'mov' and x[2][1] == ('i', 1)]
        if not results:
            raise EvidenceError(f'no accumulator set before {sub[0]:#x}')
        out.append({'load_va': ins[0], 'sub_va': sub[0], 'panic_va': panic_target, 'join_va': insns[k + 1][0],
                    'result_reg': results[-1][2][0][1], 'seed': results[-1][0] < ins[0], 'base_ops': (ins[2][1], sub[2][1]),
                    'disps': (sub[2][1][5], ins[2][1][5])})
    return out


def eval_ladder(machine, lad, sz, wei):
    """(value or None, steps) for one byte pair at one ladder."""
    base = 0x100000
    m = machine
    m.regs = [0] * 16
    m.regs[4] = 0x7000000
    for op in lad['base_ops']:
        m.regs[op[2]] = base
        if op[3] is not None:
            m.regs[op[3]] = 0
    if lad['seed']:
        m.regs[lad['result_reg']] = 1
    m.mem = {(base + lad['disps'][0], 1): sz, (base + lad['disps'][1], 1): wei}
    m.steps = 0
    try:
        m.run(lad['load_va'], stops=[lad['join_va']], limit=64)
    except Panic:
        return None
    return m.regs[lad['result_reg']]


def check_ladder(machine, lad):
    """All 256 exponents with sz=0 and all 255 borrows with wei=0."""
    bad = []
    table = []
    for k in range(256):
        got = eval_ladder(machine, lad, 0, k)
        table.append(got)
        if got != pow10_model(0, k):
            bad.append((0, k))
    for s in range(1, 256):
        if eval_ladder(machine, lad, s, 0) is not None:
            bad.append((s, 0))
    return table, bad


def check_all_pairs(machine, lad):
    return sum(1 for s in range(256) for w in range(256) if eval_ladder(machine, lad, s, w) != pow10_model(s, w))


# ----------------------------------------------------------------- helper models
# Every model returns the tuple the matching `observe` function reads back.

META, TOKENS, SPOTS, OUT, STACK = 0x100000, 0x200000, 0x300000, 0x400000, 0x7000000
TOKEN = 1
QUOTE = 2
SPOT = 1
EDGE = [0, 1, 2, 3, 7, 9, 10, 11, 99, 100, 1000, 999999, 10 ** 8, 10 ** 9 + 7, 2 ** 31, 2 ** 32 - 1, 2 ** 32,
        2 ** 32 + 1, 10 ** 10, 10 ** 15, 10 ** 18, 2 ** 53 + 1, 2 ** 62, 2 ** 63 - 1, 2 ** 63, 2 ** 64 - 2 ** 32,
        10 ** 19, 2 ** 64 - 2, 2 ** 64 - 1]
K_GRID = [0, 1, 2, 3, 5, 8, 10, 16, 18, 19]
# (k, a, b): a*b overflows u64 in all three; the last has a < 10^k.
FIXED_EXAMPLES = [(3, 10 ** 15 + 999, 10 ** 5), (2, 2 ** 63 - 1, 3), (1, 2, 2 ** 63)]
BOUNDS_HELPERS = ('sz_to_wei_checked', 'wei_to_sz_floor', 'mul_div_token', 'ratio_round', 'ratio_ceil',
                  'ntl_ratio_capped', 'mul_div_floor_one')


def checked(val):
    return (1, val) if val <= MASK else (0, val & MASK)


def m_scale(s):
    return (s['scale'],)


def m_sz_to_wei(s):
    return checked(s['a'] * s['scale'])


def m_wei_to_sz(s):
    return (s['a'] // s['scale'],)


def m_mul_div_token(s):
    d = 1 if s['token'] == 0 else s['scale']
    a, m = s['a'], s['b']
    if a * m <= MASK:
        return (1, a * m // d)
    return checked(a // d * m)


def ratio_u128(num, den, ceil):
    q, r = divmod(num, den)
    return q + (1 if ceil and r else 0)


def m_ratio_round(s):
    return tuple(checked_q(ratio_u128(s['scale'] * s['a'], s['b'], s['flag'])))


def checked_q(q):
    return (1 if q <= MASK else 0, q & MASK)


def m_ratio_ceil(s):
    q = ratio_u128(s['scale'] * s['a'], s['b'], True)
    return (q if q <= MASK else 0,)


def m_ntl_cap(s):
    q = ratio_u128(s['a'] * s['b'], s['scale'] * 100, s['flag'])
    return (1 if q < 0x28f5c28f5c28f5c else 0, q & MASK)


def m_reorder(s):
    a, m, d = s['a'], s['b'], s['scale']
    if a * m <= MASK:
        return (a * m // d,)
    if a % d == 0:
        p = a // d * m
    elif m % d == 0:
        p = m // d * a
    else:
        p = max(a, m) // d * min(a, m)
    return (p if p <= MASK else 0,)


def m_max_sz(s):
    return (min(10 ** 18 // s['b'], s['a'] // s['scale']),)


def m_side(s):
    if s['flag']:
        return (QUOTE,) + checked(s['a'] * s['b'])
    return (TOKEN,) + checked(s['b'] * s['scale'])


def m_floor_one(s):
    a, m, d = s['a'], s['b'], s['scale']
    if m == 0:
        return (0,)
    if a * d <= MASK:
        q = a * d // m
    else:
        q = a // m * d
        if q > MASK:
            return (0,)
    return (q or 1,)


def m_order_notional(s):
    q = min(10 ** 18 // s['b'], s['a'] // s['scale'])
    n = s['b'] * q
    return (q, n & MASK, 0x327f86f if n > MASK or n > 0x7ffffffffffffffe else 0x327f878)


def setup_common(m, s):
    m.regs = [None] * 16
    m.mem = {}
    m.steps = 0
    m.regs[4] = STACK
    m.mem[(STACK, 8)] = 0xdeadbeef
    for name in CALLEE_SAVED - {'rsp'}:
        m.regs[REGS[name][0]] = 0
    wei = s['k']
    mem = m.mem
    mem[(META + 0x168, 8)] = SPOTS
    mem[(META + 0x170, 8)] = 4
    mem[(META + 0x180, 8)] = TOKENS
    mem[(META + 0x188, 8)] = 4
    mem[(SPOTS + 32 * SPOT, 8)] = TOKEN
    mem[(SPOTS + 32 * SPOT + 8, 8)] = QUOTE
    for tok in (TOKEN, QUOTE, 0):
        mem[(TOKENS + tok * 0xe8 + 0x48, 1)] = 0
        mem[(TOKENS + tok * 0xe8 + 0x49, 1)] = wei


def setargs(m, **kw):
    for name, val in kw.items():
        m.regs[REGS[name][0]] = val


def s_rax(m):
    return (m.regs[0],)


def s_rax_rdx(m):
    return (m.regs[0], m.regs[2])


def a_scale(m, s):
    setargs(m, rdi=TOKENS)
    m.mem[(TOKENS + 0x18, 1)] = 0
    m.mem[(TOKENS + 0x19, 1)] = s['k']


def a_sz_to_wei(m, s):
    setargs(m, rdi=META, rsi=TOKEN, rdx=s['a'])


def a_wei_to_sz(m, s):
    setargs(m, rdi=s['a'], rsi=TOKEN, rdx=META)


def a_mul_div_token(m, s):
    setargs(m, rdi=s['a'], rsi=s['token'], rdx=s['b'], rcx=META)


def a_ratio_round(m, s):
    setargs(m, rdi=s['a'], rsi=TOKEN, rdx=s['b'], rcx=int(s['flag']), r8=META)


def a_ratio_ceil(m, s):
    setargs(m, rdi=s['a'], rsi=s['b'], rdx=TOKEN, rcx=META)


def a_reorder(m, s):
    setargs(m, rdi=s['a'], rsi=s['b'], rdx=SPOT, rcx=META)


def a_max_sz(m, s):
    setargs(m, rdi=SPOT, rsi=s['a'], rdx=s['b'], rcx=META)


def a_side(m, s):
    setargs(m, rdi=OUT, rsi=META, rdx=SPOT, rcx=int(s['flag']), r8=s['a'], r9=s['b'])


def a_floor_one(m, s):
    setargs(m, rdi=s['a'], rsi=TOKEN, rdx=s['b'], rcx=META)
    m.mem[(0x577ab98, 4)] = 0


def a_order_notional(m, s):
    setargs(m, rdi=OUT, rsi=SPOT, rdx=OUT, rcx=0, r8=s['b'], r9=s['a'])
    m.mem[(STACK + 0x10, 8)] = META


def s_side(m):
    return (m.mem[(OUT, 8)], m.mem[(OUT + 8, 8)], m.mem[(OUT + 16, 8)])


def s_order(m):
    return (m.regs[REGS['r12'][0]], m.regs[REGS['r13'][0]], m.last_stop)


# name, entry, args, observe, model, formula, divisor b must be non-zero, uses flag, stop VAs
HELPERS = [
    ('spec_scale', 0x3760790, a_scale, s_rax, m_scale, 'rax = 10^k (TokenSpec pointer)', False, False, ()),
    ('sz_to_wei_checked', 0x37606b0, a_sz_to_wei, s_rax_rdx, m_sz_to_wei,
     '(rax ok, rdx) = checked a*10^k', False, False, ()),
    ('wei_to_sz_floor', 0x32813d0, a_wei_to_sz, s_rax, m_wei_to_sz, 'rax = floor(a/10^k)', False, False, ()),
    ('mul_div_token', 0x32814c0, a_mul_div_token, s_rax_rdx, m_mul_div_token,
     'd = 1 if token==0 else 10^k; a*b fits u64: (1, floor(a*b/d)); else checked floor(a/d)*b',
     False, False, ()),
    ('ratio_round', 0x333e310, a_ratio_round, s_rax_rdx, m_ratio_round,
     'q = floor or ceil (flag) of a*10^k/b in u128; rax = q fits u64, rdx = low q', True, True, ()),
    ('ratio_ceil', 0x3594ec0, a_ratio_ceil, s_rax, m_ratio_ceil,
     'q = ceil(a*10^k/b) in u128; rax = q, or 0 if q > u64::MAX', True, False, ()),
    ('ntl_ratio_capped', 0x32815f0, a_ratio_round, s_rax_rdx, m_ntl_cap,
     'q = floor or ceil (flag) of a*b/(100*10^k) in u128; rax = q < 0x28f5c28f5c28f5c, rdx = low q',
     False, True, ()),
    ('mul_div_reorder', 0x3281190, a_reorder, s_rax, m_reorder,
     'd = 10^k of the pair quote token; a*b fits: floor(a*b/d); else a%d==0: (a/d)*b; b%d==0: (b/d)*a; '
     'else (max/d)*min; 0 if that overflows', False, False, ()),
    ('max_sz_for_px', 0x327f900, a_max_sz, s_rax, m_max_sz,
     'rax = min(floor(10^18/b), floor(a/10^k)) with k of the pair base token', True, False, ()),
    ('side_amount', 0x375e300, a_side, s_side, m_side,
     'flag: (quote token, checked a*b); else (base token, checked b*10^k)', False, True, ()),
    ('mul_div_floor_one', 0x3c09830, a_floor_one, s_rax, m_floor_one,
     'b==0: 0; a*10^k fits: q=floor(a*10^k/b); else q=checked floor(a/b)*10^k or 0; q==0 becomes 1',
     False, False, ()),
    ('order_notional', 0x327f720, a_order_notional, s_order, m_order_notional,
     'q = min(floor(10^18/b), floor(a/10^k)); n = b*q; error store if n overflows or n > i64::MAX-1',
     True, False, (0x327f86f, 0x327f878)),
]


def helper_vectors(flagged, nonzero):
    """Fixed boundary grid, then seeded pseudo-random pairs per exponent."""
    rows = []
    b_values = [v for v in EDGE if v or not nonzero]
    for k in K_GRID:
        for a in EDGE:
            for b in b_values:
                rows.append((k, a, b, False))
        rows.extend((k, a, b_values[(i * 7 + k) % len(b_values)], True) for i, a in enumerate(EDGE))
    counter = 0
    for k in range(20):
        for _ in range(RANDOM_VECTORS // 20):
            raw = hashlib.sha256(SEED + counter.to_bytes(8, 'little')).digest()
            counter += 1
            shift_a, shift_b = raw[16] % 64, raw[17] % 64
            a = int.from_bytes(raw[:8], 'little') >> shift_a
            b = int.from_bytes(raw[8:16], 'little') >> shift_b
            if nonzero and b == 0:
                b = 1
            rows.append((k, a, b, bool(raw[18] & 1)))
    if not flagged:
        rows = [r for r in rows if not r[3]]
    return rows


def run_helper(machine, helper, state):
    name, entry, args, observe, model, _f, _nz, _fl, stops = helper
    setup_common(machine, state)
    args(machine, state)
    outcome = machine.run(entry, stops=stops)
    machine.last_stop = outcome[1]
    return observe(machine)


def check_helper(machine, helper, tokens=(TOKEN,), stop_at_first=False):
    name, entry, args, observe, model, _f, nonzero, flagged, stops = helper
    vectors = helper_vectors(flagged, nonzero)
    total = mismatch = 0
    first = None
    for token in tokens:
        for k, a, b, flag in vectors:
            state = {'k': k, 'a': a, 'b': b, 'flag': flag, 'scale': 10 ** k, 'token': token}
            got = run_helper(machine, helper, state)
            want = model(state)
            total += 1
            if got != want:
                mismatch += 1
                first = first or {'k': k, 'a': a, 'b': b, 'flag': flag, 'got': list(got), 'want': list(want)}
                if stop_at_first:
                    return {'vectors': total, 'mismatch': mismatch, 'first_mismatch': first}
    return {'vectors': total, 'mismatch': mismatch, 'first_mismatch': first}


def reference_from_px_wei(a, m, d):
    """Lead `Ntl::from_px_wei_floor`: u128 product, floor, None above u64::MAX."""
    q = a * m // d
    return q if q <= MASK else None


def reference_divergence(machine, helper):
    """mul_div_token against the lead formula: the grid split by kind, then fixed examples."""
    counts = {'same': 0, 'binary_below_lead': 0, 'binary_some_lead_none': 0, 'binary_none_lead_some': 0,
              'binary_above_lead': 0}

    def binary(k, a, b):
        state = {'k': k, 'a': a, 'b': b, 'flag': False, 'scale': 10 ** k, 'token': TOKEN}
        ok, val = run_helper(machine, helper, state)
        return val if ok else None

    for k, a, b, _ in helper_vectors(False, False):
        if k == 0:
            continue
        got, ref = binary(k, a, b), reference_from_px_wei(a, b, 10 ** k)
        if got == ref:
            counts['same'] += 1
        elif ref is None:
            counts['binary_some_lead_none'] += 1
        elif got is None:
            counts['binary_none_lead_some'] += 1
        elif got < ref:
            counts['binary_below_lead'] += 1
        else:
            counts['binary_above_lead'] += 1
    examples = []
    for k, a, b in FIXED_EXAMPLES:
        examples.append({'k': k, 'a': a, 'b': b, 'a_times_b_fits_u64': a * b <= MASK, 'binary': binary(k, a, b),
                         'lead': reference_from_px_wei(a, b, 10 ** k)})
    return dict(counts, examples=examples)


def token_bounds(machine, helper, bad_token):
    """Helpers taking a token index: the first index past the 4-entry table panics at 113:33."""
    name = helper[0]
    state = {'k': 2, 'a': 5, 'b': 5, 'flag': False, 'scale': 100, 'token': bad_token}
    setup_common(machine, state)
    helper[2](machine, state)
    if name != 'mul_div_token':
        setargs(machine, **{'rdx' if name == 'ratio_ceil' else 'rsi': bad_token})
    try:
        machine.run(helper[1], stops=helper[8])
    except Panic as exc:
        return exc.location
    return None


# --------------------------------------------------------------------- analysis

def analyse(binary_path, data):
    digest = check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    relocs = img.relative_relocs()
    text_va, text = img.text()
    locations = find_locations(img, relocs)
    for need in (SCALE_LOCATION, TOKEN_LOCATION):
        if need not in locations:
            raise EvidenceError(f'Location {need} not found')
    scale_loc = locations[SCALE_LOCATION]
    token_loc = locations[TOKEN_LOCATION]

    leas = lea_rip_refs(text_va, text, scale_loc)
    holders = {}
    for lea in leas:
        r = fdes.range_of(lea)
        h = holders.setdefault(r['start'], dict(r, leas=[]))
        h['leas'].append(lea)

    signature = ladder_signature_sites(text_va, text)
    sig_fns = {fdes.range_of(v)['start'] for v in signature}
    other_fns = sorted(sig_fns - set(holders))

    slots = set()
    targets = set()
    for lea in leas:
        slot, target = call_slot_target(img, relocs, lea + 7)
        slots.add(slot)
        targets.add(target)
    if len(targets) != 1:
        raise EvidenceError('holders disagree on the panic target')
    panic_target = next(iter(targets))
    message = panic_message(img, panic_target)
    if message != UNWRAP_MESSAGE:
        raise EvidenceError(f'unexpected panic message {message!r}')
    udiv_target = relocs.get(UDIVTI3_SLOT)

    panics = {scale_loc, token_loc}
    rows = []
    pow_tables = {}
    pair_mismatch = None
    listings = {}
    for start in sorted(holders):
        h = holders[start]
        insns = parse_listing(disassemble(binary_path, start, h['end']))
        listings[start] = insns
        machine = Machine(insns, panics, UDIVTI3_SLOT, default_mem=0)
        ladders = find_ladders(insns, scale_loc)
        if not ladders:
            raise EvidenceError(f'no exponent ladder in {start:#x}')
        checked_ladders = []
        for lad in ladders:
            table, bad = check_ladder(machine, lad)
            pow_tables[(start, lad['load_va'])] = table
            checked_ladders.append({
                'load_va': hex(lad['load_va']), 'sub_va': hex(lad['sub_va']), 'panic_va': hex(lad['panic_va']),
                'join_va': hex(lad['join_va']), 'result_reg': REG64[lad['result_reg']],
                'wei_disp': lad['disps'][1], 'sz_disp': lad['disps'][0], 'mismatch': len(bad)})
            if start == 0x3760790:
                pair_mismatch = check_all_pairs(machine, lad)
        rows.append({'start': hex(start), 'end': hex(h['end']), 'fde': hex(h['fde']), 'size': h['end'] - start,
                     'lea_sites': [hex(x) for x in h['leas']], 'ladders': checked_ladders})

    helper_rows = []
    byte_dump = {}
    bounds = {}
    mul_div = None
    for helper in HELPERS:
        name, entry, *_ = helper
        if entry not in holders:
            raise EvidenceError(f'helper {name} at {entry:#x} is not a holder')
        machine = Machine(listings[entry], panics, UDIVTI3_SLOT)
        tokens = (TOKEN, 0) if name == 'mul_div_token' else (TOKEN,)
        res = check_helper(machine, helper, tokens)
        res.update({'name': name, 'entry': hex(entry), 'size': holders[entry]['end'] - entry, 'formula': helper[5],
                    'b_nonzero_only': helper[6]})
        helper_rows.append(res)
        byte_dump[entry] = img.read(entry, holders[entry]['end'] - entry)
        if name in BOUNDS_HELPERS:
            hit = token_bounds(machine, helper, 4)
            bounds[name] = hex(hit) if hit is not None else None
        if name == 'mul_div_token':
            mul_div = machine, helper

    exponents = []
    reference_table = next(iter(pow_tables.values()))
    distinct = {tuple(t) for t in pow_tables.values()}
    for k in range(256):
        val = reference_table[k]
        exponents.append({'k': k, 'value': val, 'admitted': val is not None, 'equals_pow10': val == 10 ** k})

    divergence = reference_divergence(*mul_div)
    admitted = [e['k'] for e in exponents if e['admitted']]
    result = {
        'task': 'RE-004', 'question': 'spot token wei scale 10^(wei-sz): ladder and conversion helpers',
        'binary': BINARY, 'sha256': digest, 'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)}, 'fde_table_entries': fdes.count,
        'locations': {'scale_unwrap': {'va': hex(scale_loc), 'file': SOURCE_SUFFIX.decode(),
                                       'line': SCALE_LOCATION[0], 'col': SCALE_LOCATION[1]},
                      'token_index': {'va': hex(token_loc), 'file': SOURCE_SUFFIX.decode(),
                                      'line': TOKEN_LOCATION[0], 'col': TOKEN_LOCATION[1]}},
        'panic': {'got_slots': [hex(s) for s in sorted(slots)], 'target': hex(panic_target),
                  'message': message.decode(), 'message_length': len(message)},
        'udivti3_slot': {'slot': hex(UDIVTI3_SLOT), 'target': hex(udiv_target) if udiv_target else None},
        'holders': rows, 'helpers': helper_rows,
        'ladder_signature': {'sites': len(signature), 'functions': len(sig_fns),
                             'functions_outside_this_location': [hex(x) for x in other_fns]},
        'reference_lead_divergence': divergence, 'token_index_past_end_panics_at': bounds,
        'summary': {
            'scale_location_lea_sites': len(leas), 'holder_functions': len(holders),
            'ladders_evaluated': sum(len(r['ladders']) for r in rows),
            'ladder_mismatches': sum(c['mismatch'] for r in rows for c in r['ladders']),
            'distinct_pow_tables': len(distinct),
            'exponents_admitted': len(admitted), 'exponent_max': max(admitted),
            'all_pairs_mismatch_on_spec_scale': pair_mismatch,
            'all_pairs_evaluated': 65536,
            'helpers_modelled': len(helper_rows),
            'helper_vectors': sum(h['vectors'] for h in helper_rows),
            'helper_mismatches': sum(h['mismatch'] for h in helper_rows),
            'ladder_signature_sites': len(signature),
            'ladder_signature_functions_outside': len(other_fns),
            'token_bound_helpers': len(bounds),
            'token_bound_at_location': sum(1 for v in bounds.values() if v == hex(token_loc)),
            'reference_same': divergence['same'], 'reference_binary_below': divergence['binary_below_lead'],
            'reference_binary_some_lead_none': divergence['binary_some_lead_none'],
            'reference_binary_none_lead_some': divergence['binary_none_lead_some'],
            'reference_binary_above': divergence['binary_above_lead'],
        },
    }
    return result, exponents, byte_dump


def write(out, result, exponents, byte_dump):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n',
                                       encoding='utf-8', newline='\n')
    rows = ['fn_start\tfn_end\tfde\tsize\tlea_sites\tladder_load\tladder_sub\tjoin\tresult_reg\tdisp_wei\tdisp_sz\tmismatch']
    for r in result['holders']:
        for c in r['ladders']:
            rows.append('\t'.join([r['start'], r['end'], r['fde'], str(r['size']), ','.join(r['lea_sites']),
                                   c['load_va'], c['sub_va'], c['join_va'], c['result_reg'],
                                   hex(c['wei_disp']), hex(c['sz_disp']), str(c['mismatch'])]))
    (out / 'holders.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
    rows = ['name\tentry\tsize\tvectors\tmismatch\tb_nonzero_only\tformula']
    for h in result['helpers']:
        rows.append('\t'.join([h['name'], h['entry'], str(h['size']), str(h['vectors']), str(h['mismatch']),
                               str(h['b_nonzero_only']), h['formula']]))
    (out / 'helpers.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
    rows = ['k\tvalue\tadmitted\tequals_10_pow_k']
    for e in exponents:
        rows.append(f"{e['k']}\t{e['value'] if e['value'] is not None else 'panic'}\t{int(e['admitted'])}\t{int(e['equals_pow10'])}")
    (out / 'pow10-exponents.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
    lines = []
    for entry in sorted(byte_dump):
        raw = byte_dump[entry]
        lines.append(f'# helper {entry:#x} size {len(raw)}')
        for k in range(0, len(raw), 16):
            lines.append(f'{entry + k:x}: {raw[k:k + 16].hex(" ")}')
        lines.append('')
    (out / 'helper-bytes.txt').write_text('\n'.join(lines), encoding='utf-8', newline='\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    try:
        result, exponents, byte_dump = analyse(args.binary, args.binary.read_bytes())
    except (EvidenceError, Unmodelled, Panic) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    write(args.out, result, exponents, byte_dump)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
