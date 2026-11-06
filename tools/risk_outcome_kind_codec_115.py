#!/usr/bin/env python3
"""Reconstruct the node #115 oracle outcome-kind decoder and prove it.

The clearinghouse oracle enum (name pool next to `l1/src/clearinghouse/oracle/
oracle.rs`) has the wire names StandaloneOutcome, Question and QuestionOutcome
(tags 0..2 in declaration order).  The producer authenticates the #115
capture, locates ten bodies by their unwind (FDE) extents and runs each
body's original machine code in a small interpreter for the fixed x86-64
instruction subset those bodies use:

* six exact-name visitors in three copy families: a `&str` visitor that
  gates on the length (8, 15 or 17) and compares whole qwords or an SSE2
  16+1-byte block, and a `&[u8]` visitor that converts unknown input with a
  lossy UTF-8 conversion before reporting it as an unknown variant and frees
  the converted copy when owned; both write the tagged word `0x09 | tag << 8`;
* four serde_json slice readers in the first two families: a variant-key
  reader (skip JSON whitespace, require '"', parse the string, match the
  name, skip whitespace, require ':') and a string identifier reader (skip
  whitespace, require '"', parse, match).  Each failure exit is bound to the
  error code it passes to the position-error callee, read from the bytes.

Every interpreted result is compared with an independent pure-Python
reconstruction.  Visitor literals, reader error codes, the whitespace bit
mask and the three name pools (RELATIVE relocations) are decoded from the file
bytes.  Deliberately wrong reconstructions run through the same comparison and
must be caught.

Only the standard library and the repository's shared ELF/unwind parsers are
used.  The capture is never executed; no external program is invoked.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
MASK = (1 << 64) - 1

NAMES = (b'StandaloneOutcome', b'Question', b'QuestionOutcome')
# &[&str; 3] pools passed to the unknown-variant callees, one per copy family
VARIANT_POOLS = (0x6432d68, 0x648b648, 0x64aa178)
CODEC_NAMES = {'outcome_kind': NAMES}
CODEC_POOLS = {'outcome_kind': VARIANT_POOLS}

# (entry, family, input kind, output form, codec)
VISITORS = (
    (0x25d3a80, 1, 'bytes', 'tagged', 'outcome_kind'),
    (0x25d3ca0, 1, 'str', 'tagged', 'outcome_kind'),
    (0x44647c0, 2, 'bytes', 'tagged', 'outcome_kind'),
    (0x44649e0, 2, 'str', 'tagged', 'outcome_kind'),
    (0x54797f0, 3, 'bytes', 'tagged', 'outcome_kind'),
    (0x5479a10, 3, 'str', 'tagged', 'outcome_kind'),
)
# serde_json slice readers: (entry, family, kind).  'key' reads `"name"` then
# the ':' of an externally tagged map; 'ident' reads a bare `"name"`.
READERS = (
    (0x1debf40, 1, 'key'),
    (0x1e21040, 1, 'ident'),
    (0x3f7ea60, 2, 'key'),
    (0x3fba720, 2, 'ident'),
)
FUNCTIONS = ([('outcome_kind_reader_%s' % kind, va) for va, _, kind in READERS]
             + [('%s_visitor_%s_%s' % (codec, kind, form), va) for va, _, kind, form, codec in VISITORS])

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
DATA_BASE = 0x4000_0000
OWNED_BASE = 0x5000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
ERR_SENTINEL = 0xe770_0000_0000_0001
ERR_FILL = bytes(range(0xc0, 0xe0))
DE_BASE = 0x6000_0000
ERR_BASE = 0xe000_0000_0000_0000
JSON_WS = b' \t\n\r'
BORROWED = 0x8000000000000000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c


class Reject(Exception):
    pass


def u64(x):
    return x & MASK


def sx(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = [s for s in elf_index.sections(data) if s['type'] != 8 and s['address']]
        rela = [s for s in elf_index.sections(data) if s['type'] == 4 and s['name'] == '.rela.dyn']
        if len(rela) != 1:
            raise Reject('expected one .rela.dyn')
        self.rela = rela[0]
        self.cache = {}

    def section_of(self, va):
        hits = [s for s in self.secs if s['address'] <= va < s['address'] + s['size']]
        if len(hits) != 1:
            raise Reject('VA 0x%x is not in exactly one file-backed section' % va)
        return hits[0]

    def read(self, va, n):
        s = self.section_of(va)
        if va + n > s['address'] + s['size']:
            raise Reject('read crosses section end at 0x%x' % va)
        off = s['offset'] + va - s['address']
        return self.data[off:off + n]

    def relative_addends(self, wanted):
        out = {}
        base, size = self.rela['offset'], self.rela['size']
        for pos in range(base, base + size - size % 24, 24):
            r_off, r_info, r_add = struct.unpack_from('<QQq', self.data, pos)
            if r_off in wanted and (r_info & 0xffffffff) == 8:
                if r_off in out:
                    raise Reject('duplicate relocation at 0x%x' % r_off)
                out[r_off] = (pos, r_add)
        return out


class Insn:
    __slots__ = ('va', 'length', 'raw', 'op', 'w', 'size', 'reg', 'rm', 'imm', 'target', 'ext')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


JCC8 = {0x74: 'je', 0x75: 'jne', 0x72: 'jb', 0x73: 'jae', 0x76: 'jbe', 0x77: 'ja', 0x7e: 'jle', 0x7f: 'jg',
        0xeb: 'jmp'}
JCC32 = {0x0f84: 'je', 0x0f85: 'jne', 0x0f82: 'jb', 0x0f83: 'jae', 0x0f86: 'jbe', 0x0f87: 'ja', 0x0f8e: 'jle',
         0x0f8f: 'jg'}


def decode(image, va):
    """Decode one instruction of the supported subset; raise Reject otherwise."""
    if va in image.cache:
        return image.cache[va]
    raw = image.read(va, 16)
    i = 0
    opsize16 = rep = False
    while raw[i] in (0x66, 0xf3):
        if raw[i] == 0x66:
            opsize16 = True
        else:
            rep = True
        i += 1
    rex = 0
    if 0x40 <= raw[i] <= 0x4f:
        rex = raw[i]
        i += 1
    w = bool(rex & 8)
    rex_r, rex_x, rex_b = (rex >> 2) & 1, (rex >> 1) & 1, rex & 1
    op = raw[i]
    i += 1
    two = False
    if op == 0x0f:
        op = 0x0f00 | raw[i]
        i += 1
        two = True
    size = 8 if w else (2 if opsize16 else 4)

    def modrm():
        nonlocal i
        m = raw[i]
        i += 1
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | (rex_r << 3), m & 7
        if mod == 3:
            return reg, ('reg', rm | (rex_b << 3)), (m >> 3) & 7
        base = index = None
        scale = 1
        disp = 0
        riprel = False
        if rm == 4:
            sib = raw[i]
            i += 1
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (rex_x << 3)
            index = None if idx == 4 else idx
            b = sib & 7
            if b == 5 and mod == 0:
                disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
                i += 4
            else:
                base = b | (rex_b << 3)
        elif rm == 5 and mod == 0:
            riprel = True
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        else:
            base = rm | (rex_b << 3)
        if mod == 1:
            disp = sx(raw[i], 8)
            i += 1
        elif mod == 2:
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        return reg, ('mem', base, index, scale, disp, riprel), (m >> 3) & 7

    def imm(n):
        nonlocal i
        v = int.from_bytes(raw[i:i + n], 'little')
        i += n
        return v

    kw = dict(va=va, w=w, size=size)
    if rep and not (two and op == 0x0f6f):
        raise Reject('unsupported f3 form at 0x%x' % va)
    if not two and op in (0x01, 0x03, 0x09, 0x0b, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85, 0x89, 0x8b, 0x88, 0x8d, 0x63):
        reg, rm, _ = modrm()
        names = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
                 0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov', 0x88: 'mov', 0x8d: 'lea', 0x63: 'movsxd'}
        to_reg = op in (0x03, 0x0b, 0x2b, 0x33, 0x3b, 0x8b, 0x8d, 0x63)
        if op == 0x88:
            kw['size'] = 1
            if not rex and (reg & 7) >= 4:
                raise Reject('legacy high-byte register at 0x%x' % va)
        if op == 0x63 and not w:
            raise Reject('movsxd without REX.W at 0x%x' % va)
        kw.update(op=names[op], reg=reg, rm=rm, ext='to_reg' if to_reg else 'to_rm')
    elif not two and op in (0x83, 0x81, 0x80):
        reg, rm, sub = modrm()
        names = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
        if sub not in names:
            raise Reject('unsupported group-1 form at 0x%x' % va)
        if op == 0x80:
            kw['size'] = 1
            v = imm(1)
        elif op == 0x83:
            v = sx(imm(1), 8)
        else:
            v = sx(imm(2), 16) if opsize16 else sx(imm(4), 32)
        kw.update(op=names[sub], rm=rm, imm=v, ext='imm')
    elif not two and op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        v = sx(imm(2), 16) if opsize16 else sx(imm(4), 32)
        names = {0x05: 'add', 0x0d: 'or', 0x25: 'and', 0x2d: 'sub', 0x35: 'xor', 0x3d: 'cmp'}
        kw.update(op=names[op], rm=('reg', 0), imm=v, ext='imm')
    elif not two and op == 0xf7:
        reg, rm, sub = modrm()
        if sub != 3:
            raise Reject('unsupported f7 form at 0x%x' % va)
        kw.update(op='neg', rm=rm)
    elif two and op == 0x0fa3:
        reg, rm, _ = modrm()
        if rm[0] != 'reg':
            raise Reject('bt on memory at 0x%x' % va)
        kw.update(op='bt', reg=reg, rm=rm)
    elif not two and op == 0xc0:
        reg, rm, sub = modrm()
        if sub != 4:
            raise Reject('unsupported c0 form at 0x%x' % va)
        kw.update(op='shl', rm=rm, imm=imm(1), size=1, ext='imm')
    elif not two and 0xb8 <= op <= 0xbf:
        r = (op - 0xb8) | (rex_b << 3)
        v = imm(8) if w else imm(4)
        kw.update(op='movimm', reg=r, imm=v, size=8 if w else 4)
    elif not two and 0xb0 <= op <= 0xb7:
        if not rex and op >= 0xb4:
            raise Reject('legacy high-byte register at 0x%x' % va)
        kw.update(op='movimm', reg=(op - 0xb0) | (rex_b << 3), imm=imm(1), size=1)
    elif not two and op in (0xc6, 0xc7):
        reg, rm, sub = modrm()
        if sub != 0:
            raise Reject('unsupported c6/c7 form at 0x%x' % va)
        if op == 0xc6:
            kw.update(op='mov', rm=rm, imm=imm(1), size=1, ext='imm')
        else:
            n = 2 if opsize16 else 4
            v = imm(n)
            if w:
                v = u64(sx(v, 32))
            kw.update(op='mov', rm=rm, imm=v, ext='imm')
    elif two and op in (0x0fb6, 0x0fb7):
        reg, rm, _ = modrm()
        kw.update(op='movzx8' if op == 0x0fb6 else 'movzx16', reg=reg, rm=rm)
    elif two and op in (0x0f10, 0x0f11) and not opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op == 0x0f10 else 'movups_store', reg=reg, rm=rm, size=16)
    elif two and op == 0x0f6f and rep:
        reg, rm, _ = modrm()
        kw.update(op='movups_load', reg=reg, rm=rm, size=16)
    elif two and op == 0x0f6e and opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movd', reg=reg, rm=rm, size=4)
    elif two and op in (0x0f74, 0x0fdb) and opsize16:
        reg, rm, _ = modrm()
        kw.update(op='pcmpeqb' if op == 0x0f74 else 'pand', reg=reg, rm=rm, size=16)
    elif two and op == 0x0fd7 and opsize16:
        reg, rm, _ = modrm()
        if rm[0] != 'reg':
            raise Reject('pmovmskb from memory at 0x%x' % va)
        kw.update(op='pmovmskb', reg=reg, rm=rm, size=4)
    elif not two and op in JCC8:
        rel = sx(imm(1), 8)
        kw.update(op=JCC8[op])
        kw['target'] = va + i + rel
    elif two and op in JCC32:
        rel = sx(imm(4), 32)
        kw.update(op=JCC32[op])
        kw['target'] = va + i + rel
    elif not two and op in (0xe8, 0xe9):
        rel = sx(imm(4), 32)
        kw.update(op='call' if op == 0xe8 else 'jmp')
        kw['target'] = va + i + rel
    elif not two and op == 0xff:
        reg, rm, sub = modrm()
        if sub == 4:
            kw.update(op='jmpind', rm=rm, size=8)
        elif sub == 2:
            if rm[0] != 'mem' or not rm[5]:
                raise Reject('indirect call not through a rip slot at 0x%x' % va)
            kw.update(op='callslot', rm=rm, size=8)
        elif sub == 0:
            kw.update(op='inc', rm=rm)
        elif sub == 1:
            kw.update(op='dec', rm=rm)
        else:
            raise Reject('unsupported ff form at 0x%x' % va)
    elif not two and 0x50 <= op <= 0x57:
        kw.update(op='push', reg=(op - 0x50) | (rex_b << 3))
    elif not two and 0x58 <= op <= 0x5f:
        kw.update(op='pop', reg=(op - 0x58) | (rex_b << 3))
    elif not two and op == 0xc3:
        kw.update(op='ret')
    else:
        raise Reject('unsupported opcode 0x%x at 0x%x' % (op, va))
    kw['length'] = i
    kw['raw'] = bytes(raw[:i])
    if kw.get('rm') and kw['rm'][0] == 'mem' and kw['rm'][5]:
        kw['rm'] = ('mem', None, None, 1, va + i + kw['rm'][4], True)
    ins = Insn(**kw)
    image.cache[va] = ins
    return ins


class Machine:
    """Interpreter for the decoded subset.  Flags kept: ZF, CF, SF and OF."""

    def __init__(self, image, stubs):
        self.image = image
        self.stubs = stubs
        self.regs = {n: 0 for n in range(16)}
        self.xmm = {n: 0 for n in range(16)}
        self.mem = {}
        self.zf = self.cf = self.sf = self.of = False
        self.calls = []
        self.trace = []

    def load(self, addr, n):
        out = bytearray()
        for k in range(n):
            a = addr + k
            if a in self.mem:
                out.append(self.mem[a])
            elif a < 0x1000_0000 or a >= 0x8000_0000:
                out += self.image.read(a, 1)
            else:
                raise Reject('read of unset scratch byte 0x%x' % a)
        return int.from_bytes(out, 'little')

    def store(self, addr, value, n):
        if not (0x1000_0000 <= addr and addr + n <= 0x8000_0000):
            raise Reject('store outside scratch memory at 0x%x' % addr)
        for k, b in enumerate(int(value & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')):
            self.mem[addr + k] = b

    def ea(self, rm):
        _, base, index, scale, disp, riprel = rm
        if riprel:
            return disp
        a = disp
        if base is not None:
            a += self.regs[base]
        if index is not None:
            a += self.regs[index] * scale
        return u64(a)

    def get(self, rm, size):
        if rm[0] == 'reg':
            return self.regs[rm[1]] & ((1 << (8 * size)) - 1)
        return self.load(self.ea(rm), size)

    def put(self, rm, value, size):
        value &= (1 << (8 * size)) - 1
        if rm[0] == 'reg':
            r = rm[1]
            if size >= 4:
                self.regs[r] = value  # 32-bit writes zero-extend
            else:
                keep = MASK ^ ((1 << (8 * size)) - 1)
                self.regs[r] = (self.regs[r] & keep) | value
        else:
            self.store(self.ea(rm), value, size)

    def xget(self, rm):
        if rm[0] == 'reg':
            return self.xmm[rm[1]]
        return self.load(self.ea(rm), 16)

    def setflags(self, result, size, cf=False, of=False):
        m = (1 << (8 * size)) - 1
        self.zf = (result & m) == 0
        self.sf = bool((result >> (8 * size - 1)) & 1)
        self.cf = cf
        self.of = of

    def run(self, entry, limit=600):
        self.regs[4] = STACK_TOP - 8
        self.store(self.regs[4], RETURN_SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.trace.append(pc)
            nxt = pc + ins.length
            op, size = ins.op, ins.size
            m = (1 << (8 * size)) - 1
            if op in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test'):
                if ins.ext == 'imm':
                    a, b, dst = self.get(ins.rm, size), ins.imm & m, ins.rm
                elif ins.ext == 'to_reg':
                    a, b, dst = self.regs[ins.reg] & m, self.get(ins.rm, size), ('reg', ins.reg)
                else:
                    a, b, dst = self.get(ins.rm, size), self.regs[ins.reg] & m, ins.rm
                top = 1 << (8 * size - 1)
                if op == 'add':
                    r = a + b
                    self.setflags(r, size, r > m, bool(~(a ^ b) & (a ^ r) & top))
                    self.put(dst, r, size)
                elif op in ('sub', 'cmp'):
                    r = (a - b) & m
                    self.setflags(r, size, a < b, bool((a ^ b) & (a ^ r) & top))
                    if op == 'sub':
                        self.put(dst, r, size)
                elif op == 'test':
                    self.setflags(a & b, size)
                else:
                    r = {'xor': a ^ b, 'or': a | b, 'and': a & b}[op]
                    self.setflags(r, size)
                    self.put(dst, r, size)
            elif op == 'shl':
                a = self.get(ins.rm, size)
                n = ins.imm & 0x1f
                r = (a << n) & m
                self.setflags(r, size, bool(n and (a >> (8 * size - n)) & 1))
                self.put(ins.rm, r, size)
            elif op == 'mov':
                if ins.ext == 'imm':
                    self.put(ins.rm, ins.imm, size)
                elif ins.ext == 'to_reg':
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                else:
                    self.put(ins.rm, self.regs[ins.reg], size)
            elif op == 'movimm':
                self.put(('reg', ins.reg), ins.imm, size)
            elif op == 'lea':
                self.put(('reg', ins.reg), self.ea(ins.rm), size)
            elif op == 'movsxd':
                self.regs[ins.reg] = u64(sx(self.get(ins.rm, 4), 32))
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), max(size, 4))
            elif op == 'movzx16':
                self.put(('reg', ins.reg), self.get(ins.rm, 2), max(size, 4))
            elif op == 'movups_load':
                self.xmm[ins.reg] = self.xget(ins.rm)
            elif op == 'movups_store':
                if ins.rm[0] == 'reg':
                    self.xmm[ins.rm[1]] = self.xmm[ins.reg]
                else:
                    self.store(self.ea(ins.rm), self.xmm[ins.reg], 16)
            elif op == 'movd':
                self.xmm[ins.reg] = self.get(ins.rm, 4)
            elif op == 'pcmpeqb':
                a, b = self.xmm[ins.reg], self.xget(ins.rm)
                r = 0
                for k in range(16):
                    if (a >> (8 * k)) & 0xff == (b >> (8 * k)) & 0xff:
                        r |= 0xff << (8 * k)
                self.xmm[ins.reg] = r
            elif op == 'pand':
                self.xmm[ins.reg] &= self.xget(ins.rm)
            elif op == 'pmovmskb':
                v = self.xmm[ins.rm[1]]
                self.regs[ins.reg] = sum(((v >> (8 * k + 7)) & 1) << k for k in range(16))
            elif op == 'neg':
                a = self.get(ins.rm, size)
                r = (-a) & m
                self.setflags(r, size, a != 0, a == (1 << (8 * size - 1)))
                self.put(ins.rm, r, size)
            elif op == 'bt':
                bit = self.regs[ins.reg] & (8 * size - 1)
                self.cf = bool((self.get(ins.rm, size) >> bit) & 1)
            elif op in ('inc', 'dec'):
                r = (self.get(ins.rm, size) + (1 if op == 'inc' else -1)) & m
                self.zf = r == 0
                self.sf = bool(r >> (8 * size - 1))
                self.put(ins.rm, r, size)
            elif op in ('je', 'jne', 'jb', 'jae', 'jbe', 'ja', 'jle', 'jg'):
                le = self.zf or (self.sf != self.of)
                take = {'je': self.zf, 'jne': not self.zf, 'jb': self.cf, 'jae': not self.cf,
                        'jbe': self.cf or self.zf, 'ja': not (self.cf or self.zf),
                        'jle': le, 'jg': not le}[op]
                if take:
                    nxt = ins.target
            elif op == 'jmp':
                nxt = ins.target
            elif op == 'jmpind':
                nxt = self.get(ins.rm, 8)
            elif op == 'push':
                self.regs[4] -= 8
                self.store(self.regs[4], self.regs[ins.reg], 8)
            elif op == 'pop':
                self.regs[ins.reg] = self.load(self.regs[4], 8)
                self.regs[4] += 8
            elif op in ('call', 'callslot'):
                key = ins.target if op == 'call' else ('slot', ins.rm[4])
                if key not in self.stubs:
                    raise Reject('call to unmodelled target %s at 0x%x' % (key, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, key, args))
                self.regs[0] = self.stubs[key](self, args)
                for r in (1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = CLOBBER  # caller-saved clobber
            elif op == 'ret':
                target = self.load(self.regs[4], 8)
                self.regs[4] += 8
                if target == RETURN_SENTINEL:
                    if self.regs[4] != STACK_TOP:
                        raise Reject('unbalanced stack at return 0x%x' % pc)
                    return
                raise Reject('return to unexpected address at 0x%x' % pc)
            else:
                raise Reject('no semantics for %s' % op)
            pc = nxt
        raise Reject('step limit reached')


def linear(image, entry, end):
    rows = []
    pc = entry
    while pc < end:
        if image.read(pc, 1) == b'\xcc':
            if any(b != 0xcc for b in image.read(pc, end - pc)):
                raise Reject('non-int3 bytes after the body of 0x%x' % entry)
            break
        ins = decode(image, pc)
        rows.append(ins)
        pc += ins.length
    if pc > end:
        raise Reject('decode overran the FDE of 0x%x' % entry)
    return rows


# ---------------------------------------------------------------- stubs

def lossy_stub(machine, args):
    """from_utf8_lossy-shaped callee: writes Cow<str> (cap or borrowed niche, ptr, len) at rdi."""
    out, ptr, length = args[0], args[1], args[2]
    raw = bytes(machine.load(ptr + k, 1) for k in range(length))
    try:
        raw.decode('utf-8')
        cow = (BORROWED, ptr, length)
    except UnicodeDecodeError:
        text = raw.decode('utf-8', 'replace').encode('utf-8')
        for k, b in enumerate(text):
            machine.store(OWNED_BASE + k, b, 1)
        cow = (len(text), OWNED_BASE, len(text))
    for k, v in enumerate(cow):
        machine.store(out + 8 * k, v, 8)
    return out


def free_stub(machine, args):
    return 0


def unknown_ptr_stub(machine, args):
    return ERR_SENTINEL


def unknown_fill_stub(machine, args):
    for k, b in enumerate(ERR_FILL):
        machine.store(args[0] + k, b, 1)
    return args[0]


# ---------------------------------------------------------------- reconstruction

def recon_classify(text, names=NAMES):
    """Exact byte-for-byte match against the name set; declaration order is the tag."""
    return names.index(text) if text in names else None


def lossy(text):
    try:
        text.decode('utf-8')
        return text, False
    except UnicodeDecodeError:
        return text.decode('utf-8', 'replace').encode('utf-8'), True


def recon_visitor(kind, form, text, classify=recon_classify, names=NAMES):
    """Observable outcome of one visitor: (status, value, error text, freed owned copy)."""
    tag = classify(text, names)
    if tag is not None:
        return ('ok', tag if form == 'result' else 0x09 | (tag << 8), None, False)
    if kind == 'str':
        return ('err', None, text, False)
    shown, owned = lossy(text)
    return ('err', None, shown, owned)


# Deliberately wrong reconstructions (negative controls).
def wrong_prefix(text, names):
    for k, n in enumerate(names):
        if text[:len(n)] == n:
            return k
    return None


def wrong_casefold(text, names):
    low = [n.lower() for n in names]
    return low.index(text.lower()) if text.lower() in low else None


def wrong_swap(text, names):
    t = recon_classify(text, names)
    return {0: 1, 1: 0}.get(t, t)


def wrong_first4(text, names):
    """Compares only the first dword of each name (drops the trailing word/byte compares)."""
    for k, n in enumerate(names):
        if len(text) == len(n) and text[:4] == n[:4]:
            return k
    return None


def wrong_length_only(text, names):
    """Selects a name by the length gate alone (drops every byte compare)."""
    for k, n in enumerate(names):
        if len(text) == len(n):
            return k
    return None


def wrong_first_byte(text, names):
    """Selects a name by its length and first byte alone (drops the remaining compares)."""
    for k, n in enumerate(names):
        if len(text) == len(n) and text[:1] == n[:1]:
            return k
    return None


def wrong_raw_error(kind, form, text, names):
    tag = recon_classify(text, names)
    if tag is not None:
        return recon_visitor(kind, form, text, names=names)
    return ('err', None, text, False)


# ---------------------------------------------------------------- interpretation drivers

class ReaderErrors:
    """Error values handed out by the reader stubs: each is ERR_BASE + index
    into `rows`, so the interpreted result names the error it carries."""

    def __init__(self):
        self.rows = []

    def new(self, row):
        self.rows.append(row)
        return ERR_BASE + len(self.rows) - 1

    def name(self, value):
        k = value - ERR_BASE
        if not 0 <= k < len(self.rows):
            raise Reject('reader result is not a stub error: 0x%x' % value)
        return self.rows[k]


def de_state(machine):
    ptr = machine.load(DE_BASE + 0x18, 8)
    length = machine.load(DE_BASE + 0x20, 8)
    index = machine.load(DE_BASE + 0x28, 8)
    return ptr, length, index


def reader_stubs(roles, errors):
    """Stubs for the reader callees, keyed like `roles`."""
    def parse_str(machine, args):
        # Stand-in for the string scanner after the opening quote: the
        # string runs to the next '"'; a backslash, a control byte or the end
        # of input is a scanner error.  On success the index moves past the
        # closing quote and a Borrowed (tag 0) reference is returned.
        out, read, de = args[0], args[1], args[2]
        if de != DE_BASE or read != DE_BASE + 0x18 or machine.load(DE_BASE + 0x10, 8) != 0:
            raise Reject('parse_str arguments differ')
        ptr, length, index = de_state(machine)
        text = bytes(machine.load(ptr + k, 1) for k in range(length))
        got = scan_string(text, index)
        if got[0] == 'err':
            machine.store(out, 2, 4)
            machine.store(out + 8, errors.new(('scan', got[1])), 8)
            return out
        start, end = got[1], got[2]
        machine.store(DE_BASE + 0x28, end + 1, 8)
        machine.store(out, 0, 4)
        machine.store(out + 8, ptr + start, 8)
        machine.store(out + 0x10, end - start, 8)
        return out

    def unknown(machine, args):
        ptr, ln, pool, count = args[0], args[1], args[2], args[3]
        text = bytes(machine.load(ptr + k, 1) for k in range(ln))
        return errors.new(('unknown_variant', text, pool, count))

    def fix(machine, args):
        if args[1] != DE_BASE:
            raise Reject('fix_position deserializer argument differs')
        return errors.new(('fix_position', errors.name(args[0])))

    def peek(machine, args):
        if args[0] != DE_BASE:
            raise Reject('peek_error deserializer argument differs')
        return errors.new(('peek_error', machine.load(args[1], 8), de_state(machine)[2]))

    def invalid(machine, args):
        if args[0] != DE_BASE:
            raise Reject('invalid_type deserializer argument differs')
        return errors.new(('invalid_type', de_state(machine)[2], args[2]))

    def panic(machine, args):
        raise Reject('index overflow panic reached')
    table = {'parse_str': parse_str, 'unknown_variant_ptr': unknown, 'fix_position': fix,
             'peek_error': peek, 'invalid_type': invalid, 'overflow_panic': panic}
    return {k: table[v] for k, v in roles.items()}


def scan_string(text, index):
    """Model of the stubbed string scanner shared by interpretation and reconstruction."""
    k = index
    while k < len(text):
        c = text[k]
        if c == 0x22:
            return ('ok', index, k)
        if c == 0x5c or c < 0x20:
            return ('err', k)
        k += 1
    return ('err', k)


def bind_reader_roles(image, rows, va):
    """Name each reader callee from its call-site shape."""
    roles = {}

    def bind(key, role):
        if roles.get(key, role) != role:
            raise Reject('reader callee %s has two roles' % (key,))
        roles[key] = role
    calls = [k for k, r in enumerate(rows) if r.op in ('call', 'callslot')]
    for n, k in enumerate(calls):
        r = rows[k]
        # argument set-up since the previous call only
        prev = rows[max(0, k - 4, calls[n - 1] + 1 if n else 0):k]
        if r.op == 'callslot':
            if rows[k - 1].op == 'lea' and rows[k - 1].reg == 7 and rows[k - 1].rm[5]:
                bind(('slot', r.rm[4]), 'overflow_panic')
            else:
                bind(('slot', r.rm[4]), 'parse_str')
        elif any(x.op == 'movimm' and x.reg == 1 and x.imm == len(NAMES) for x in prev):
            bind(r.target, 'unknown_variant_ptr')
            nxt = rows[calls[n + 1]]
            if nxt.op != 'call':
                raise Reject('no fix_position after the unknown-variant call in 0x%x' % va)
            bind(nxt.target, 'fix_position')
        elif any(x.op == 'lea' and x.reg == 2 and x.rm[5] for x in prev):
            bind(r.target, 'invalid_type')
    for k in calls:
        r = rows[k]
        if r.op == 'call' and r.target not in roles:
            bind(r.target, 'peek_error')
    return roles


def recon_reader(kind, text, pool, expected, codes, names=NAMES, ws=JSON_WS, fix_scan=None, colon=b':',
                 classify=None):
    """Observable effect of one reader on the JSON slice `text` (index 0).

    Returns (status, value, final index).  `value` is the tag on success and a
    nested error description otherwise.  Keyword arguments only exist for the
    negative controls."""
    fix_scan = (kind == 'key') if fix_scan is None else fix_scan
    classify = classify or (lambda t: recon_classify(t, names))
    i = 0
    n = len(text)
    while i < n and text[i] in ws:
        i += 1
    if i >= n:
        return ('err', ('peek_error', codes['eof'], i), i)
    c = text[i]
    if c != 0x22:
        if kind == 'ident':
            return ('err', ('fix_position', ('invalid_type', i, expected)), i)
        code = codes['close'] if c == 0x7d else codes['other']
        return ('err', ('peek_error', code, i), i)
    i += 1
    got = scan_string(text, i)
    if got[0] == 'err':
        err = ('scan', got[1])
        return ('err', ('fix_position', err) if fix_scan else err, i)
    start, end = got[1], got[2]
    i = end + 1
    tag = classify(text[start:end])
    if tag is None:
        return ('err', ('fix_position', ('unknown_variant', text[start:end], pool, len(names))), i)
    if kind == 'ident':
        return ('ok', tag, i)
    while i < n and text[i] in ws:
        i += 1
    if i >= n:
        return ('err', ('peek_error', codes['eof'], i), i)
    if text[i:i + 1] != colon:
        return ('err', ('peek_error', codes['colon'], i), i)
    return ('ok', tag, i + 1)


def run_reader(image, entry, roles, text):
    errors = ReaderErrors()
    m = Machine(image, reader_stubs(roles, errors))
    for k in range(16):
        m.store(OUT_BASE + k, 0xa5, 1)
    for k in range(0x40):
        m.store(STACK_TOP - 0x100 + k, 0x00, 1)
    for k, b in enumerate(text):
        m.store(DATA_BASE + k, b, 1)
    m.store(DE_BASE, 0, 8)
    m.store(DE_BASE + 8, 0, 8)
    m.store(DE_BASE + 0x10, CLOBBER, 8)
    m.store(DE_BASE + 0x18, DATA_BASE, 8)
    m.store(DE_BASE + 0x20, len(text), 8)
    m.store(DE_BASE + 0x28, 0, 8)
    m.regs[7], m.regs[6] = OUT_BASE, DE_BASE
    m.run(entry, limit=4000)
    if m.regs[0] != OUT_BASE:
        raise Reject('reader 0x%x does not return its output pointer' % entry)
    tag = m.load(OUT_BASE, 1)
    word = m.load(OUT_BASE + 8, 8)
    index = m.load(DE_BASE + 0x28, 8)
    if tag < len(NAMES):
        if word != DE_BASE:
            raise Reject('reader 0x%x Ok does not carry the deserializer' % entry)
        return ('ok', tag, index), m
    if tag != len(NAMES):
        raise Reject('reader 0x%x wrote result byte %d' % (entry, tag))
    return ('err', errors.name(word), index), m


def run_visitor(image, entry, kind, form, codec, stubs, roles, text, pool):
    m = Machine(image, stubs)
    for k in range(32):
        m.store(OUT_BASE + k, 0xa5, 1)
    # Pad past the input so that any whole-word read is defined.  Zero is not
    # a byte of any name.
    for k in range(48):
        m.store(IN_BASE + k, 0x00, 1)
    for k, b in enumerate(text):
        m.store(IN_BASE + k, b, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, len(text)
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('visitor 0x%x does not return its output pointer' % entry)
    seq = [roles[key] for _, key, _ in m.calls]
    if not m.calls:
        if form == 'result':
            if m.load(OUT_BASE, 1) != 0:
                raise Reject('result visitor 0x%x wrote a non-Ok byte without an error call' % entry)
            return ('ok', m.load(OUT_BASE + 1, 1), None, False), m
        return ('ok', m.load(OUT_BASE, 2), None, False), m
    want_seq = (['lossy'] if kind == 'bytes' else []) + ['unknown_variant_' + form]
    if seq[:len(want_seq)] != want_seq or seq[len(want_seq):] not in ([], ['free']):
        raise Reject('visitor 0x%x call sequence %s' % (entry, seq))
    freed = seq[-1] == 'free'
    idx = len(want_seq) - 1
    site, key, args = m.calls[idx]
    if form == 'result':
        ptr, ln, got_pool, count = args[0], args[1], args[2], args[3]
    else:
        ptr, ln, got_pool, count = args[1], args[2], args[3], args[4]
    if (got_pool, count) != (pool, len(CODEC_NAMES[codec])):
        raise Reject('unknown-%s call arguments differ at 0x%x' % (codec, site))
    shown = bytes(m.load(ptr + k, 1) for k in range(ln))
    if kind == 'bytes':
        cow = m.calls[0][2][0]
        if ptr != m.load(cow + 8, 8) or ln != m.load(cow + 16, 8):
            raise Reject('visitor 0x%x does not report the converted text' % entry)
        if freed:
            fa = m.calls[-1][2]
            if (fa[0], fa[1], fa[2]) != (OWNED_BASE, m.load(cow, 8), 0):
                raise Reject('visitor 0x%x frees the wrong buffer' % entry)
    if form == 'result':
        if m.load(OUT_BASE, 1) != 1 or m.load(OUT_BASE + 8, 8) != ERR_SENTINEL:
            raise Reject('result visitor 0x%x does not store Err(error)' % entry)
    else:
        if bytes(m.load(OUT_BASE + k, 1) for k in range(32)) != ERR_FILL:
            raise Reject('tagged visitor 0x%x does not carry the 32-byte error' % entry)
    return ('err', None, shown, freed), m


MUTATION_BYTES = (0x00, 0x09, 0x0a, 0x80, 0xc3, 0xe2, 0xff) + tuple(range(0x20, 0x7f, 2))


def visitor_inputs():
    seen = []
    have = set()

    def add(t):
        if t not in have:
            have.add(t)
            seen.append(t)
    add(b'')
    every = NAMES
    for n in every:
        add(n)
        for k in range(len(n) + 1):
            add(n[:k])
        add(n + b'x')
        add(n + n[-1:])
        add(n + b'\0')
        add(n.lower())
        add(n.upper())
        add(n[:-1] + b'\xff')
        add(n[:1] + b'\xc3\xa9' + n[3:])
        for v in range(0x30, 0x3a):
            add(n[:3] + bytes([v]) + n[4:])
        for pos in range(len(n)):
            for v in MUTATION_BYTES:
                add(n[:pos] + bytes([v]) + n[pos + 1:])
            add(n[:pos] + bytes([n[pos] ^ 0x20]) + n[pos + 1:])
    for a in every:
        for b in every:
            if a != b:
                add(a[:len(a) // 2] + b[len(b) // 2:])
                add(a + b)
    for ln in range(0, 20):
        add(b'A' * ln)
        add(b'\x80' * ln)
    return seen


def esc(b):
    return b.hex() if b else '-'


WS_MASK_BITS = (0x09, 0x0a, 0x0d, 0x20)
READER_EXITS = {'key': ('eof', 'close', 'other', 'colon'), 'ident': ('eof',)}


def reader_inputs():
    """JSON slices for the readers: every name and every visitor input as a
    string, with leading/trailing whitespace, colon and early-end variants."""
    seen, have = [], set()

    def add(t):
        if t not in have:
            have.add(t)
            seen.append(t)
    lead = (b'', b' ', b'\t\n\r ', b'\x0b', b'\x0c', b'}', b'{', b'[', b'!', b'#', b'x', b'\x00', b':', b"'")
    tail = (b'', b':', b' :', b'\t\n\r :1', b' ', b'x', b';', b'}', b',', b'\x0b:', b'"', b'::')
    for n in NAMES:
        for a in lead:
            for z in tail:
                add(a + b'"' + n + b'"' + z)
        add(b'"' + n)
        add(b'"' + n + b'\\"":')
        add(b'"' + n[:3] + b'\\' + n[3:] + b'":')
        add(b'"' + n[:3] + b'\n' + n[3:] + b'":')
    for a in lead:
        add(a)
        add(a + b'"')
        add(a + b'""')
        add(a + b'"":')
    for text in visitor_inputs():
        add(b'"' + text + b'":')
        add(b' "' + text + b'"')
    return seen


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows = [], []
    bodies = {}
    for role, va in FUNCTIONS:
        if va not in by_start:
            raise Reject('0x%x is not an FDE start' % va)
        rec = by_start[va]
        rows = linear(image, va, rec['end'])
        bodies[va] = rows
        body = image.read(va, rec['end'] - va)
        calls = sorted(set('0x%x' % r.target for r in rows if r.op == 'call')
                       | set('slot:0x%x' % r.rm[4] for r in rows if r.op == 'callslot'))
        functions.append(dict(role=role, entry='0x%x' % va, fde_end='0x%x' % rec['end'], fde_bytes=rec['end'] - va,
                              decoded_instructions=len(rows), decoded_bytes=sum(r.length for r in rows),
                              lsda='none' if rec['lsda'] is None else '0x%x' % rec['lsda'],
                              sha256=hashlib.sha256(body).hexdigest(), callees=','.join(calls)))
        for r in rows:
            insn_rows.append((role, '0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))

    # Visitor callee roles from the body shapes: a bytes visitor's first slot
    # call is the lossy conversion and its second the free; a visitor's
    # direct call is the unknown-variant callee.  _Unwind_Resume sits on
    # landing pads only.
    stubs, roles = {}, {}

    def bind(key, role, fn):
        if roles.get(key, role) != role:
            raise Reject('callee %s has two roles' % (key,))
        roles[key] = role
        stubs[key] = fn
    unwind = set()
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        slots = []
        for r in rows:
            if r.op == 'callslot' and r.rm[4] not in slots:
                slots.append(r.rm[4])
        if kind == 'bytes':
            if len(slots) != 2:
                raise Reject('bytes visitor 0x%x does not use two slots' % va)
            bind(('slot', slots[0]), 'lossy', lossy_stub)
            bind(('slot', slots[1]), 'free', free_stub)
        elif slots:
            raise Reject('str visitor 0x%x calls through a slot' % va)
        direct = sorted(set(r.target for r in rows if r.op == 'call'))
        last = [r for r in rows if r.op == 'call'][-1].target if kind == 'bytes' else None
        for t in direct:
            if t == last:
                unwind.add(t)
                continue
            bind(t, 'unknown_variant_' + form, unknown_ptr_stub if form == 'result' else unknown_fill_stub)
    if len(unwind) != 1:
        raise Reject('landing-pad resume target is not unique')
    callee_rows = sorted(('slot:0x%x' % k[1] if isinstance(k, tuple) else '0x%x' % k, v) for k, v in roles.items())
    callee_rows.append(('0x%x' % unwind.pop(), 'unwind_resume (landing pads only)'))

    # Reader roles, error codes, whitespace masks, pools and name literals.
    reader_roles, reader_info, code_rows, reader_lit_rows = {}, {}, [], []
    seen_reader_callees = {}
    for va, fam, kind in READERS:
        rows = bodies[va]
        rr = bind_reader_roles(image, rows, va)
        reader_roles[va] = rr
        for key, role in rr.items():
            name = 'slot:0x%x' % key[1] if isinstance(key, tuple) else '0x%x' % key
            if seen_reader_callees.get(name, role) != role:
                raise Reject('reader callee %s has two roles' % name)
            seen_reader_callees[name] = role
        # error codes: the u64 immediates stored to the stack before peek_error
        stores = [r for r in rows if r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.rm[1] == 4
                  and r.size == 8]
        if len(stores) != len(READER_EXITS[kind]):
            raise Reject('reader 0x%x has %d code stores' % (va, len(stores)))
        codes = {}
        for exit_name, r in zip(READER_EXITS[kind], stores):
            codes[exit_name] = r.imm
            code_rows.append(('0x%x' % va, fam, kind, exit_name, '0x%x' % r.va, '%d' % r.imm))
        masks = [r for r in rows if r.op == 'movimm' and r.size == 8 and r.imm == sum(1 << b for b in WS_MASK_BITS)]
        if len(masks) != 1:
            raise Reject('reader 0x%x whitespace mask is not the JSON set' % va)
        bounds = sorted(set(r.imm for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg'
                            and r.imm in (0x22, 0x3a, 0x7d)))
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]]
        pool = [x.rm[4] for x in leas if x.rm[4] in VARIANT_POOLS]
        if len(set(pool)) != 1 or pool[0] != VARIANT_POOLS[fam - 1]:
            raise Reject('reader 0x%x pool reference differs' % va)
        expected = None
        if kind == 'ident':
            inv = [r for r in rows if r.op == 'lea' and r.reg == 2 and r.rm[5] and r.rm[4] not in VARIANT_POOLS]
            if len(inv) != 1:
                raise Reject('reader 0x%x has no unique expected-type argument' % va)
            expected = inv[0].rm[4]
        reader_info[va] = dict(codes=codes, pool=pool[0], expected=expected)
        for r in rows:
            if r.op in ('movups_load', 'cmp', 'xor', 'movzx8') and r.rm[0] == 'mem' and r.rm[5] \
                    and image.section_of(r.rm[4])['name'] == '.rodata':
                n = {'movups_load': 16, 'movzx8': 1}.get(r.op, 8)
                raw = image.read(r.rm[4], n)
                reader_lit_rows.append(('0x%x' % va, '0x%x' % r.va, r.op, '0x%x' % r.rm[4], raw.hex(),
                                        raw.decode('ascii')))
        code_rows.append(('0x%x' % va, fam, kind, 'ws_mask', '0x%x' % masks[0].va, '0x%x' % masks[0].imm))
        code_rows.append(('0x%x' % va, fam, kind, 'byte_bounds', '-', ','.join('0x%x' % b for b in bounds)))
        if expected is not None:
            code_rows.append(('0x%x' % va, fam, kind, 'invalid_type_expected', '-', '0x%x' % expected))
    callee_rows += sorted((k, 'reader_' + v) for k, v in seen_reader_callees.items())
    # every reader literal must be a piece of a declared name
    for va, _, op, addr, hexraw, text in reader_lit_rows:
        if not any(text.encode() in n for n in NAMES):
            raise Reject('reader %s literal %r is not part of a name' % (va, text))

    # Visitor literals and variant-pool references.
    lit_rows, var_rows, pools = [], [], {}
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]
                and image.section_of(r.rm[4])['name'] == '.data.rel.ro']
        if len(leas) != 1:
            raise Reject('visitor 0x%x does not reference exactly one pool' % va)
        pools[va] = leas[0].rm[4]
        var_rows.append(('0x%x' % va, codec, fam, kind, form, '0x%x' % leas[0].va, '0x%x' % pools[va]))
        for r in rows:
            if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg' and r.rm[1] == 2:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'length_gate', '%d' % r.imm))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'byte+%d' % r.rm[4], chr(r.imm)))
            elif r.op == 'movimm' and r.size == 8:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'movabs_imm64', r.imm.to_bytes(8, 'little').decode('ascii')))
            elif r.op == 'pcmpeqb' and r.rm[0] == 'mem':
                raw = image.read(r.rm[4], 16)
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'pcmpeqb_rip_0x%x' % r.rm[4], raw.hex()))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.rm[1] in (0, 7):
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'result_store%d+%d' % (8 * r.size, r.rm[4]), '0x%x' % r.imm))
    for va, fam, kind in READERS:
        lea = [r for r in bodies[va] if r.op == 'lea' and r.rm[5] and r.rm[4] == reader_info[va]['pool']][0]
        var_rows.append(('0x%x' % va, 'outcome_kind', fam, 'json', 'reader_' + kind, '0x%x' % lea.va,
                         '0x%x' % reader_info[va]['pool']))
    for codec, want_pools in sorted(CODEC_POOLS.items()):
        got = tuple(sorted(set(pools[v[0]] for v in VISITORS if v[4] == codec)))
        if got != want_pools:
            raise Reject('%s pool references differ: %s' % (codec, ['0x%x' % p for p in got]))

    table_rows = []
    for codec in ('outcome_kind',):
        names = CODEC_NAMES[codec]
        for pool in CODEC_POOLS[codec]:
            relocs = image.relative_addends({pool + 16 * k for k in range(len(names))})
            texts = []
            for k in range(len(names)):
                slot = pool + 16 * k
                if slot not in relocs:
                    raise Reject('no RELATIVE relocation for %s slot 0x%x' % (codec, slot))
                pos, add = relocs[slot]
                ln = struct.unpack('<Q', image.read(slot + 8, 8))[0]
                text = image.read(add, ln)
                texts.append(text)
                table_rows.append((codec, '0x%x' % pool, k, '0x%x' % slot, '0x%x' % pos, '0x%x' % add, ln,
                                   text.decode('ascii')))
            if tuple(texts) != names:
                raise Reject('%s name pool 0x%x differs from reconstruction order' % (codec, pool))

    path_counts = {}
    # Reader comparison.
    rinputs = reader_inputs()
    rd_rows, rd_ok, rd_total = [], 0, 0
    neg_rd = {k: 0 for k in READER_NEGATIVES}
    reader_ok = {}
    for text in rinputs:
        row = [esc(text), len(text)]
        outs = []
        for va, fam, kind in READERS:
            info = reader_info[va]
            got, m = run_reader(image, va, reader_roles[va], text)
            want = recon_reader(kind, text, info['pool'], info['expected'], info['codes'])
            same = got == want
            rd_total += 1
            rd_ok += same
            key = (va, len(m.trace), got[0] if got[0] == 'ok' else 'err:' + err_kind(got[1]))
            path_counts[key] = path_counts.get(key, 0) + 1
            if got[0] == 'ok':
                reader_ok['0x%x' % va] = reader_ok.get('0x%x' % va, 0) + 1
            for name, kw in READER_NEGATIVES.items():
                args = dict(codes=info['codes'])
                args.update(kw(kind, info))
                neg_rd[name] += got != recon_reader(kind, text, info['pool'], info['expected'], **args)
            outs.append(show_reader(got) + ('' if same else '!'))
        row += outs
        row.append('match' if all(not o.endswith('!') for o in outs) else 'MISMATCH')
        rd_rows.append(tuple(row))

    # Visitor comparison.
    inputs = visitor_inputs()
    vis_rows, vis_ok, vis_total = [], 0, 0
    neg_vis = {'prefix_match': wrong_prefix, 'case_fold': wrong_casefold, 'swap_first_two': wrong_swap,
               'first4_only': wrong_first4, 'length_only': wrong_length_only,
               'first_byte_only': wrong_first_byte}
    neg_counts = {k: 0 for k in neg_vis}
    neg_counts['raw_error_text'] = 0
    lossy_inputs = owned_frees = 0
    for text in inputs:
        row = [esc(text), len(text)]
        outcomes = []
        for va, fam, kind, form, codec in VISITORS:
            names = CODEC_NAMES[codec]
            got, m = run_visitor(image, va, kind, form, codec, stubs, roles, text, pools[va])
            want = recon_visitor(kind, form, text, names=names)
            same = got == want
            vis_total += 1
            vis_ok += same
            key = (va, len(m.trace), got[0] + ('+free' if got[3] else ''))
            path_counts[key] = path_counts.get(key, 0) + 1
            owned_frees += got[3]
            for name, fn in neg_vis.items():
                neg_counts[name] += got != recon_visitor(kind, form, text, fn, names)
            neg_counts['raw_error_text'] += got != wrong_raw_error(kind, form, text, names)
            if got[0] == 'ok':
                cell = 'ok:0x%x' % got[1]
            else:
                cell = 'err' + (':lossy' if got[2] != text else '') + (':free' if got[3] else '')
            outcomes.append(cell + ('' if same else '!'))
        lossy_inputs += lossy(text)[1]
        row += outcomes
        tag = recon_classify(text, NAMES)
        row.append('-' if tag is None else NAMES[tag].decode())
        row.append('match' if all(not o.endswith('!') for o in outcomes) else 'MISMATCH')
        vis_rows.append(tuple(row))

    paths = [('0x%x' % va, steps, status, n) for (va, steps, status), n in sorted(path_counts.items())]
    negatives = ([('reader', k, v, rd_total) for k, v in sorted(neg_rd.items())]
                 + [('visitor', k, v, vis_total) for k, v in sorted(neg_counts.items())])
    accepted = sum(1 for r in vis_rows if r[-2] != '-')
    summary = dict(
        target='node115', sha256=SHA115, component='risk', task='none',
        functions=len(FUNCTIONS), decoded_instructions=len(insn_rows),
        outcome_kind_names=[n.decode() for n in NAMES], outcome_kind_pools=['0x%x' % p for p in VARIANT_POOLS],
        readers=len(READERS), reader_inputs=len(rinputs), reader_cases=rd_total, reader_matches=rd_ok,
        reader_ok_inputs=reader_ok,
        reader_error_codes={'0x%x' % va: reader_info[va]['codes'] for va, _, _ in READERS},
        visitor_inputs=len(inputs), accepted_inputs=accepted, invalid_utf8_inputs=lossy_inputs,
        visitor_cases=vis_total, visitor_matches=vis_ok, owned_copy_frees=owned_frees,
        callees={a: b for a, b in callee_rows},
        distinct_paths=len(paths),
        negative_controls={'%s/%s' % (a, b): n for a, b, n, _ in negatives},
        all_negative_controls_caught=all(n > 0 for _, _, n, _ in negatives),
        reconstruction_matches_all=(rd_ok == rd_total and vis_ok == vis_total),
    )
    return dict(functions=functions, instructions=insn_rows, literals=lit_rows, reader_literals=reader_lit_rows,
                reader_codes=code_rows, variant_refs=var_rows, variant_tables=table_rows, callees=callee_rows,
                reader=rd_rows, visitor=vis_rows, paths=paths, negatives=negatives, summary=summary)


def err_kind(err):
    out = []
    while isinstance(err, tuple):
        out.append(err[0])
        err = err[1] if err[0] == 'fix_position' else None
    return '>'.join(out)


def show_reader(got):
    status, value, index = got
    if status == 'ok':
        return 'ok:%d@%d' % (value, index)
    parts = []
    err = value
    while err[0] == 'fix_position':
        parts.append('fix')
        err = err[1]
    head = err[0]
    if head == 'peek_error':
        parts.append('peek(%d,%d)' % (err[1], err[2]))
    elif head == 'scan':
        parts.append('scan(%d)' % err[1])
    elif head == 'invalid_type':
        parts.append('invalid_type(%d)' % err[1])
    else:
        parts.append('unknown(%s)' % esc(err[1]))
    return 'err:' + '>'.join(parts) + '@%d' % index


READER_NEGATIVES = {
    'no_tab_whitespace': lambda kind, info: dict(ws=b' \n\r'),
    'form_feed_is_whitespace': lambda kind, info: dict(ws=JSON_WS + b'\x0b\x0c'),
    'scan_error_fixed_in_ident': lambda kind, info: dict(fix_scan=True),
    'scan_error_unfixed_in_key': lambda kind, info: dict(fix_scan=False),
    'eof_code_off_by_one': lambda kind, info: dict(codes=dict(info['codes'], eof=info['codes']['eof'] + 1)),
    'close_brace_as_other': lambda kind, info: dict(codes=dict(info['codes'], close=info['codes'].get('other'))),
    'semicolon_colon': lambda kind, info: dict(colon=b';'),
    'prefix_name_match': lambda kind, info: dict(classify=lambda t: wrong_prefix(t, NAMES)),
    'alphabetical_tags': lambda kind, info: dict(names=(NAMES[1], NAMES[2], NAMES[0])),
}


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('role', 'function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callees.tsv': tsv(('callee', 'role'), result['callees']),
        'visitor-literals.tsv': tsv(('visitor', 'va', 'form', 'value'), result['literals']),
        'reader-literals.tsv': tsv(('reader', 'va', 'op', 'rodata_va', 'hex', 'text'), result['reader_literals']),
        'reader-codes.tsv': tsv(('reader', 'family', 'kind', 'exit', 'va', 'value'), result['reader_codes']),
        'name-pool-refs.tsv': tsv(('function', 'codec', 'family', 'input', 'output', 'lea_va', 'pool'),
                                  result['variant_refs']),
        'name-pools.tsv': tsv(('codec', 'pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'),
                              result['variant_tables']),
        'reader-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v[0] for v in READERS) + ('verdict',),
                                result['reader']),
        'visitor-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v[0] for v in VISITORS)
                                 + ('outcome_kind', 'verdict'), result['visitor']),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'inputs'), result['paths']),
        'negative-controls.tsv': tsv(('family', 'wrong_reconstruction', 'mismatching_cases', 'cases'),
                                     result['negatives']),
        'summary.json': json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(TARGET))
    args = ap.parse_args(argv)
    data = Path(args.binary).read_bytes()
    try:
        result = build(data)
    except Reject as exc:
        print('rejected: %s' % exc, file=sys.stderr)
        return 1
    if not result['summary']['reconstruction_matches_all'] or not result['summary']['all_negative_controls_caught']:
        print('reconstruction or negative controls failed', file=sys.stderr)
        print(json.dumps(result['summary'], indent=1, sort_keys=True), file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    s = result['summary']
    print('reader %d/%d, visitor %d/%d, negatives caught: %s' % (
        s['reader_matches'], s['reader_cases'], s['visitor_matches'], s['visitor_cases'],
        s['all_negative_controls_caught']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
