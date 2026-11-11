#!/usr/bin/env python3
"""Reconstruct the node #115 EVM call-outcome codec and prove it.

The four-variant enum with the wire names Ok, OutOfGas, Error and
UnexpectedError (tags 0..3 in declaration order; Ok carries a u64 `gas_used`
and a `bytes` value, the other three are unit variants).  The producer
authenticates the #115 capture, locates the three bodies that carry the names
by their unwind (FDE) extents and runs each body's original machine code in a
small interpreter for the fixed x86-64 instruction subset those bodies use:

* two exact-name visitors that share one name pool: a `&str` visitor that
  dispatches on the input length through a 14-row jump table (lengths 2..15)
  and compares whole words/dwords/qwords, and a `&[u8]` visitor with its own
  length table that compares byte by byte, converts unknown input with a
  lossy UTF-8 conversion before reporting it as an unknown variant and frees
  the converted copy when owned; both write the tagged word `0x09 | tag << 8`;
* the msgpack serializer: an unchecked jump table on the u64 tag; unit
  variants are written as a bare fixstr name, Ok as the one-entry map
  `{"Ok": [gas_used, bytes]}` whose inner header is a two-entry map or array
  from the serializer's struct-as-map flag, with the `gas_used` key when the
  flag is non-zero and the `bytes` key when it is one; an error of the u64
  writer is re-tagged, an error of the bytes writer is returned as is.

Every interpreted result is compared with an independent pure-Python
reconstruction.  Jump-table rows, visitor literals and the name pool
(RELATIVE relocations) are decoded from the file bytes.  Deliberately wrong
reconstructions run through the same comparison and must be caught.

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

NAMES = (b'Ok', b'OutOfGas', b'Error', b'UnexpectedError')
# &[&str; 4] pool passed to the unknown-variant callee by both visitors
VARIANT_POOLS = (0x64373c8,)
CODEC_NAMES = {'outcome': NAMES}
CODEC_POOLS = {'outcome': VARIANT_POOLS}

# The msgpack serializer: (entry, family)
ENVELOPES = (
    (0x5af5570, 1),
)
# Serializer input layout: u64 tag at +0; for Ok the u64 gas_used at +8 and
# the bytes value at +0x10.
GAS_OFFSET = 0x8
BYTES_OFFSET = 0x10
# (entry, family, input kind, output form, codec)
VISITORS = (
    (0x2692850, 1, 'bytes', 'tagged', 'outcome'),
    (0x2692a20, 1, 'str', 'tagged', 'outcome'),
)
# The only other `lea` of the pool: an enum-access call inside the seq visitor
# 0x27b4150 that passes the enum's Rust name.  (FDE start, first argument
# set-up instruction, call site)
ENUM_ACCESS = (0x27b4150, 0x27b4289, 0x27b42ad)
FUNCTIONS = ([('call_outcome_msgpack_serializer', va) for va, _ in ENVELOPES]
             + [('%s_visitor_%s_%s' % (codec, kind, form), va) for va, _, kind, form, codec in VISITORS])

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VEC_BASE = 0x3000_0000
DATA_BASE = 0x4000_0000
OWNED_BASE = 0x5000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
ERR_SENTINEL = 0xe770_0000_0000_0001
ERR_FILL = bytes(range(0xc0, 0xe0))
GAS_MARK = b'\xc1G'
BYTES_MARK = b'\xc1B'
GAS_VALUE = 0x0123_4567_89ab_cdef
GAS_OK = 2
GAS_ERR = (0x47, 0x4747_4747_4747_4747)
GAS_ERR_TAG = 0x8000000000000000
BYTES_ERR = (0x6666_0000_0000_0001, 0x5353_5353_5353_5353, 0x5454_5454_5454_5454)
OK_WORD = 0x8000000000000004
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

def grow_stub(machine, args):
    vec, length, additional, align, elem = args
    if (align, elem) != (1, 1):
        raise Reject('unexpected element layout in grow call')
    cap = machine.load(vec, 8)
    machine.store(vec, grown(cap, length, additional), 8)
    return 0


def grown(cap, length, additional):
    """Capacity after the modelled grow helper (any value >= length + additional works)."""
    return max(cap * 2, length + additional, 8)


def appended_cap(cap, length, mark):
    """Capacity after a stubbed inner serializer appended `mark`."""
    return max(cap, length + len(mark))


def bytes_stub(fail):
    """Stub for the bytes writer (rdi = result, rsi = value, rdx = vector):
    append BYTES_MARK and return Ok, or write the 24-byte BYTES_ERR."""
    def stub(machine, args):
        out, vec = args[0], args[2]
        if fail:
            for k, v in enumerate(BYTES_ERR):
                machine.store(out + 8 * k, v, 8)
            return out
        append(machine, vec, BYTES_MARK)
        machine.store(out, OK_WORD, 8)
        return out
    return stub


def gas_stub(fail):
    """Stub for the u64 writer (rdi = result, rsi = vector, rdx = value):
    append GAS_MARK and the value's eight bytes and return the Ok code 2, or
    write the error pair GAS_ERR."""
    def stub(machine, args):
        out, vec, value = args[0], args[1], args[2]
        if fail:
            for k, v in enumerate(GAS_ERR):
                machine.store(out + 8 * k, v, 8)
            return out
        append(machine, vec, GAS_MARK + value.to_bytes(8, 'little'))
        machine.store(out, GAS_OK, 8)
        return out
    return stub


def append(machine, vec, mark):
    cap, ptr, ln = machine.load(vec, 8), machine.load(vec + 8, 8), machine.load(vec + 16, 8)
    machine.store(vec, appended_cap(cap, ln, mark), 8)
    for k, b in enumerate(mark):
        machine.store(ptr + ln + k, b, 1)
    machine.store(vec + 16, ln + len(mark), 8)


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

def recon_envelope(tag, flag, cap, length, fail, names=NAMES, header=None, gas_key_always=False,
                   wrap_ok=True, wrap_units=False, keep_going=False, strict=False, bytes_first=False,
                   raw_gas_error=False):
    """Observable effect of the serializer.

    Returns (appended bytes, grow calls as (length, additional), final length,
    result words, inner calls as (role, argument)).  `fail` is None, 'gas' or
    'bytes'; the keyword arguments only exist to express the negative
    controls."""
    out = bytearray()
    grows = []
    calls = []
    st = dict(cap=cap, len=length)

    def room(n):
        if (st['cap'] - st['len'] <= n) if strict else (st['cap'] - st['len'] < n):
            grows.append((st['len'], n))
            st['cap'] = grown(st['cap'], st['len'], n)

    def byte(b):
        if st['cap'] == st['len']:
            grows.append((st['len'], 1))
            st['cap'] = grown(st['cap'], st['len'], 1)
        out.append(b)
        st['len'] += 1

    def text(t):
        byte(0xa0 | len(t))
        room(len(t))
        out.extend(t)
        st['len'] += len(t)

    def inner(role, mark, arg):
        calls.append((role, arg))
        if fail == role and not keep_going:
            return True
        st['cap'] = appended_cap(st['cap'], st['len'], mark)
        out.extend(mark)
        st['len'] += len(mark)
        return False

    def done(words):
        return bytes(out), grows, st['len'], words, calls

    if tag != 0:
        if wrap_units:
            byte(0x81)
        text(names[tag])
        if wrap_units:
            byte(0xc0)
        return done((OK_WORD,))
    if wrap_ok:
        byte(0x81)
    text(names[0])
    byte(header(flag) if header else 0x82 | ((flag ^ 1) << 4))

    def gas():
        if flag != 0 or gas_key_always:
            text(b'gas_used')
        if inner('gas', GAS_MARK + GAS_VALUE.to_bytes(8, 'little'), GAS_VALUE):
            return (GAS_ERR[0], GAS_ERR[0], GAS_ERR[1]) if raw_gas_error else (GAS_ERR_TAG,) + GAS_ERR
        return None

    def value():
        if flag == 1:
            text(b'bytes')
        if inner('bytes', BYTES_MARK, BYTES_OFFSET):
            return BYTES_ERR
        return None

    for step in ((value, gas) if bytes_first else (gas, value)):
        err = step()
        if err is not None:
            return done(err)
    return done((OK_WORD,))


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
    """Selects a name by the length gate alone; the four Eip names share length 7."""
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


ENVELOPE_NEGATIVES = {
    'array_header_inverted': dict(header=lambda f: 0x82 | (f << 4)),
    'gas_key_always': dict(gas_key_always=True),
    'ok_as_bare_string': dict(wrap_ok=False),
    'units_as_map_with_nil': dict(wrap_units=True),
    'alphabetical_tags': dict(names=tuple(sorted(NAMES))),
    'error_swallowed': dict(keep_going=True),
    'reserve_on_equal': dict(strict=True),
    'bytes_first': dict(bytes_first=True),
    'gas_error_not_retagged': dict(raw_gas_error=True),
}


# ---------------------------------------------------------------- interpretation drivers

def run_envelope(image, entry, roles, tag, flag, cap, length, fail):
    stubs = {}
    for key, role in roles.items():
        if role == 'grow':
            stubs[key] = grow_stub
        elif role == 'gas':
            stubs[key] = gas_stub(fail == 'gas')
        else:
            stubs[key] = bytes_stub(fail == 'bytes')
    m = Machine(image, stubs)
    for k in range(24):
        m.store(OUT_BASE + k, 0x11, 1)
    m.store(IN_BASE, tag, 8)
    m.store(IN_BASE + GAS_OFFSET, GAS_VALUE, 8)
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, length, 8)
    m.store(VEC_BASE + 24, flag << 24, 8)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, VEC_BASE
    m.run(entry, limit=2000)
    end = m.load(VEC_BASE + 16, 8)
    if m.load(VEC_BASE + 8, 8) != DATA_BASE:
        raise Reject('serializer 0x%x moved the data pointer' % entry)
    data = bytes(m.load(DATA_BASE + k, 1) for k in range(length, end))
    grows, calls = [], []
    for site, key, args in m.calls:
        role = roles[key]
        if role == 'grow':
            if args[0] != VEC_BASE:
                raise Reject('grow call vector argument differs at 0x%x' % site)
            grows.append((args[1], args[2]))
        elif role == 'gas':
            if args[1] != VEC_BASE:
                raise Reject('gas call serializer argument differs at 0x%x' % site)
            calls.append((role, args[2]))
        else:
            if args[2] != VEC_BASE:
                raise Reject('bytes call serializer argument differs at 0x%x' % site)
            calls.append((role, args[1] - IN_BASE))
    if m.regs[0] != OUT_BASE:
        raise Reject('serializer 0x%x does not return its output pointer' % entry)
    first = m.load(OUT_BASE, 8)
    words = (first,) if first == OK_WORD else tuple(m.load(OUT_BASE + 8 * k, 8) for k in range(3))
    return data, grows, end, words, calls, m


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


def envelope_inputs():
    """(tag, flag, capacity, length, fail): every declared tag with both
    struct layouts across every reserve edge, plus both Ok failure exits."""
    rows = []
    for tag in range(len(NAMES)):
        for flag in (0, 1):
            for length in (0, 1, 7, 64):
                for spare in range(0, 60):
                    rows.append((tag, flag, length + spare, length, None))
            if tag == 0:
                for fail in ('gas', 'bytes'):
                    for length in (0, 9):
                        for spare in range(0, 24):
                            rows.append((tag, flag, length + spare, length, fail))
    return rows


def dispatch_heads(rows, va):
    """Every indirect jump of the serializer with the instructions from the
    tag load: they carry no compare or conditional branch, so the u64 tag
    indexes the table unchecked and only tags 0..3 are defined inputs."""
    heads = []
    for k, r in enumerate(rows):
        if r.op != 'jmpind':
            continue
        head = rows[k - 4:k + 1]
        ops = [x.op for x in head]
        if ops != ['mov', 'lea', 'movsxd', 'add', 'jmpind'] or not head[1].rm[5]:
            raise Reject('serializer 0x%x dispatch at 0x%x is not an unchecked table jump' % (va, r.va))
        heads.append((head, head[1].rm[4]))
    if not heads or len(set(b for _, b in heads)) != 1:
        raise Reject('serializer 0x%x has no single jump-table base' % va)
    return heads


def enum_access(image, by_start):
    """Decode the argument set-up of the enum-access call and read the name it
    passes (rdx = name, ecx = length, r8 = pool, r9d = count)."""
    fde_start, site, call_va = ENUM_ACCESS
    if fde_start not in by_start or not fde_start <= call_va < by_start[fde_start]['end']:
        raise Reject('enum-access site is not inside the FDE of 0x%x' % fde_start)
    regs, pc, setup = {}, site, []
    while pc < call_va:
        r = decode(image, pc)
        setup.append(r)
        if r.op == 'movimm':
            regs[r.reg] = ('imm', r.imm)
        elif r.op == 'lea' and r.rm[5]:
            regs[r.reg] = ('va', r.rm[4])
        pc += r.length
    call = decode(image, call_va)
    if pc != call_va or call.op != 'call':
        raise Reject('enum-access call not found at 0x%x' % call_va)
    want = {1: 'rcx', 2: 'rdx', 8: 'r8', 9: 'r9'}
    if any(k not in regs for k in want):
        raise Reject('enum-access arguments are not all constants')
    name_va, name_len = regs[2][1], regs[1][1]
    enum_name = image.read(name_va, name_len).decode('ascii')
    if regs[8] != ('va', VARIANT_POOLS[0]) or regs[9] != ('imm', len(NAMES)):
        raise Reject('enum-access call does not pass the outcome pool and count')
    enum_rows = [('0x%x' % fde_start, '0x%x' % call_va, '0x%x' % call.target, '0x%x' % name_va,
                  image.section_of(name_va)['name'], name_len, enum_name, '0x%x' % regs[8][1], regs[9][1])]
    return enum_name, enum_rows


def esc(b):
    return b.hex() if b else '-'


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

    # Callee roles from the body shapes (envelope roles are bound below): a
    # bytes visitor's first slot call is the lossy conversion and
    # its second the free; a visitor's direct call is the unknown-variant
    # callee of its output form.  _Unwind_Resume sits on landing pads only.
    stubs, roles = {}, {}

    def bind(key, role, fn):
        if roles.get(key, role) != role:
            raise Reject('callee %s has two roles' % (key,))
        roles[key] = role
        stubs[key] = fn
    unwind = set()
    env_roles = {}
    payload_rows = []
    for va, fam in ENVELOPES:
        rows = bodies[va]
        writers = []
        for k, r in enumerate(rows):
            if r.op != 'call':
                continue
            # grow helper: called with r8d = 1 (element size) loaded just before;
            # the other two direct callees are the u64 writer and then the
            # bytes writer, in body order.
            if any(x.op == 'movimm' and x.reg == 8 and x.imm == 1 for x in rows[max(0, k - 6):k]):
                role = 'grow'
            else:
                if r.target not in writers:
                    writers.append(r.target)
                role = ('gas', 'bytes')[writers.index(r.target)] if len(writers) <= 2 else 'extra'
            if env_roles.get(r.target, role) != role:
                raise Reject('serializer callee 0x%x has two roles' % r.target)
            env_roles[r.target] = role
            if role != 'grow':
                payload_rows.append(('0x%x' % va, '0x%x' % r.va, '0x%x' % r.target, role))
        if len(writers) != 2:
            raise Reject('serializer 0x%x does not call exactly two value writers' % va)
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

    # Envelope tag dispatch: unchecked jump tables and the arm each row reaches.
    jt_rows, arm_rows, unchecked_heads = [], [], []
    for va, fam in ENVELOPES:
        rows = bodies[va]
        heads = dispatch_heads(rows, va)
        base = heads[0][1]
        for head, _ in heads:
            unchecked_heads.append(('0x%x' % head[-1].va, len(head), ' '.join(r.op for r in head)))
        starts = {r.va: k for k, r in enumerate(rows)}
        for tag in range(len(NAMES)):
            rel = sx(struct.unpack('<I', image.read(base + 4 * tag, 4))[0], 32)
            tgt = base + rel
            if tgt not in starts:
                raise Reject('jump-table row %d of 0x%x is not an instruction start' % (tag, va))
            # the name bytes this arm stores: printable immediates and movabs
            # registers stored to memory, up to the length advance `add reg, imm`
            k = starts[tgt]
            stored, held = [], {}
            while not (rows[k].op == 'add' and rows[k].ext == 'imm' and rows[k].rm[0] == 'reg' and rows[k].imm >= 2):
                r = rows[k]
                if r.op == 'movimm' and r.size == 8:
                    held[r.reg] = r.imm.to_bytes(8, 'little')
                elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and (
                        r.size in (2, 4) or 0x20 <= r.imm < 0x7f):
                    stored.append((r.rm[4], (r.imm & ((1 << (8 * r.size)) - 1)).to_bytes(r.size, 'little')))
                elif r.op == 'mov' and r.ext == 'to_rm' and r.rm[0] == 'mem' and r.reg in held:
                    stored.append((r.rm[4], held[r.reg]))
                elif r.op in ('ret', 'jmp', 'call', 'jmpind'):
                    raise Reject('arm %d of 0x%x ends before its length advance' % (tag, va))
                k += 1
            buf = bytearray(16)
            top = 0
            for disp, raw in stored:
                buf[disp:disp + len(raw)] = raw
                top = max(top, disp + len(raw))
            arm_text = bytes(buf[:top]).decode('ascii')
            jt_rows.append(('0x%x' % va, fam, tag, '0x%x' % (base + 4 * tag), rel, '0x%x' % tgt,
                            '0x%x' % rows[k].va, rows[k].imm, arm_text))
            if arm_text != NAMES[tag].decode() or rows[k].imm != len(NAMES[tag]):
                raise Reject('jump-table row %d of 0x%x stores %r' % (tag, va, arm_text))
        for r in rows:
            if r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1 and r.imm >= 0x80:
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'store8', 'marker', '%02x' % r.imm, '-'))
            elif r.op == 'movimm' and r.size == 8 and all(0x20 <= c < 0x7f for c in r.imm.to_bytes(8, 'little')):
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'movabs', 'key_bytes', r.imm.to_bytes(8, 'little').hex(),
                                 r.imm.to_bytes(8, 'little').decode('ascii')))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size in (2, 4):
                raw = (r.imm & ((1 << (8 * r.size)) - 1)).to_bytes(r.size, 'little')
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'store%d' % (8 * r.size), 'name_bytes', raw.hex(),
                                 raw.decode('latin-1')))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg':
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'cmp_imm', 'reserve_bound', '%d' % r.imm, '-'))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.rm[4] == 0x1b:
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'cmp_mem8', 'struct_map_flag', '%d' % r.imm, '-'))

    # Visitor literals and variant-pool references.
    lit_rows, var_rows, pools = [], [], {}
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        # rip-relative leas into .data.rel.ro; the bytes visitors' other lea
        # is the .rodata base of the fourth-byte jump table.
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]
                and image.section_of(r.rm[4])['name'] == '.data.rel.ro']
        if len(leas) != 1:
            raise Reject('visitor 0x%x does not reference exactly one pool' % va)
        pools[va] = leas[0].rm[4]
        var_rows.append(('0x%x' % va, codec, fam, kind, form, '0x%x' % leas[0].va, '0x%x' % pools[va]))
        for r in rows:
            if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg':
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'length_table_bound', '%d' % r.imm))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'byte+%d' % r.rm[4], chr(r.imm)))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size in (2, 4):
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'imm%d+%d' % (8 * r.size, r.rm[4]),
                                 (r.imm & ((1 << (8 * r.size)) - 1)).to_bytes(r.size, 'little').decode('ascii')))
            elif r.op == 'xor' and r.ext == 'imm' and r.rm[0] == 'reg':
                n = 2 if r.imm > 0xff else 1
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'xor_imm%d' % (8 * n),
                                 (r.imm & ((1 << (8 * n)) - 1)).to_bytes(n, 'little').decode('ascii')))
            elif r.op == 'movimm' and r.size == 4 and r.imm >= 0x20202020:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'mov_imm32', r.imm.to_bytes(4, 'little').decode('ascii')))
            elif r.op == 'movimm' and r.size == 8:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'movabs_imm64', r.imm.to_bytes(8, 'little').decode('ascii')))
            elif r.op == 'pcmpeqb' and r.rm[0] == 'mem':
                raw = image.read(r.rm[4], 16)
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'pcmpeqb_rip_0x%x' % r.rm[4], raw.hex()))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.rm[1] in (0, 7):
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'result_store%d+%d' % (8 * r.size, r.rm[4]), '0x%x' % r.imm))
    for codec, want_pools in sorted(CODEC_POOLS.items()):
        got = tuple(sorted(set(pools[v[0]] for v in VISITORS if v[4] == codec)))
        if got != want_pools:
            raise Reject('%s pool references differ: %s' % (codec, ['0x%x' % p for p in got]))

    # Visitor length dispatch: `lea r, [rdx - bias]; cmp r, bound; ja reject`
    # then a .rodata table of rel32 rows; a row is a name arm exactly when
    # its length is a name length, every other row is the reject block.
    len_rows = []
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        jumps = [k for k, r in enumerate(rows) if r.op == 'jmpind']
        if len(jumps) != 1:
            raise Reject('visitor 0x%x does not have one indirect jump' % va)
        head = rows[jumps[0] - 6:jumps[0] + 1]
        ops = [r.op for r in head]
        if ops != ['lea', 'cmp', 'ja', 'lea', 'movsxd', 'add', 'jmpind'] or head[0].rm[0] != 'mem' \
                or head[0].rm[1] != 2 or not head[3].rm[5]:
            raise Reject('visitor 0x%x length dispatch is %s' % (va, ops))
        bias, bound, reject, base = -head[0].rm[4], head[1].imm, head[2].target, head[3].rm[4]
        if image.section_of(base)['name'] != '.rodata':
            raise Reject('visitor 0x%x length table is not in .rodata' % va)
        lengths = {len(n): n for n in CODEC_NAMES[codec]}
        for row in range(bound + 1):
            rel = sx(struct.unpack('<I', image.read(base + 4 * row, 4))[0], 32)
            tgt = base + rel
            ln = row + bias
            arm = lengths[ln].decode() if ln in lengths else 'reject'
            if (tgt == reject) != (arm == 'reject'):
                raise Reject('visitor 0x%x length row %d reaches 0x%x' % (va, row, tgt))
            len_rows.append(('0x%x' % va, kind, '0x%x' % base, row, ln, '0x%x' % (base + 4 * row), rel,
                             '0x%x' % tgt, arm))
        if set(lengths) - set(range(bias, bias + bound + 1)):
            raise Reject('visitor 0x%x length table misses a name length' % va)

    enum_name, enum_rows = enum_access(image, by_start)

    table_rows = []
    for codec in ('outcome',):
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

    # Envelope comparison.
    ser_rows, ser_ok, ser_total = [], 0, 0
    neg_ser = {k: 0 for k in ENVELOPE_NEGATIVES}
    path_counts = {}
    for va, fam in ENVELOPES:
        for tag, flag, cap, length, fail in envelope_inputs():
            got = run_envelope(image, va, env_roles, tag, flag, cap, length, fail)
            m = got[-1]
            got = got[:-1]
            want = recon_envelope(tag, flag, cap, length, fail)
            same = got == want
            ser_total += 1
            ser_ok += same
            key = (va, len(m.trace), 'fail:%s' % (fail or 'none'))
            path_counts[key] = path_counts.get(key, 0) + 1
            for name, kw in ENVELOPE_NEGATIVES.items():
                neg_ser[name] += got != recon_envelope(tag, flag, cap, length, fail, **kw)
            ser_rows.append(('0x%x' % va, tag, flag, cap, length, fail or '-', esc(got[0]),
                             ';'.join('%d+%d' % g for g in got[1]) or '-', got[2],
                             ':'.join('0x%016x' % w for w in got[3]),
                             ';'.join('%s@0x%x' % c for c in got[4]) or '-',
                             NAMES[tag].decode(), 'match' if same else 'MISMATCH'))

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
        for names in (NAMES,):
            tag = recon_classify(text, names)
            row.append('-' if tag is None else names[tag].decode())
        row.append('match' if all(not o.endswith('!') for o in outcomes) else 'MISMATCH')
        vis_rows.append(tuple(row))

    paths = [('0x%x' % va, steps, status, n) for (va, steps, status), n in sorted(path_counts.items())]
    negatives = ([('serializer', k, v, ser_total) for k, v in sorted(neg_ser.items())]
                 + [('visitor', k, v, vis_total) for k, v in sorted(neg_counts.items())])
    accepted = sum(1 for r in vis_rows if r[-2] != '-')
    summary = dict(
        target='node115', sha256=SHA115, component='evm', task='none',
        functions=len(FUNCTIONS), decoded_instructions=len(insn_rows),
        outcome_names=[n.decode() for n in NAMES], outcome_pools=['0x%x' % p for p in VARIANT_POOLS],
        serializers=len(ENVELOPES), serializer_cases=ser_total, serializer_matches=ser_ok,
        visitor_length_tables=len(len_rows), enum_name=enum_name,
        serializer_callees={'0x%x' % k: v for k, v in sorted(env_roles.items())},
        visitor_inputs=len(inputs), accepted_inputs=accepted, invalid_utf8_inputs=lossy_inputs,
        visitor_cases=vis_total, visitor_matches=vis_ok, owned_copy_frees=owned_frees,
        callees={a: b for a, b in callee_rows},
        distinct_paths=len(paths),
        unchecked_dispatch_heads={a: '%d: %s' % (n, ops) for a, n, ops in unchecked_heads},
        negative_controls={'%s/%s' % (a, b): n for a, b, n, _ in negatives},
        all_negative_controls_caught=all(n > 0 for _, _, n, _ in negatives),
        reconstruction_matches_all=(ser_ok == ser_total and vis_ok == vis_total),
    )
    return dict(functions=functions, instructions=insn_rows, jump_tables=jt_rows, length_tables=len_rows, enum_access=enum_rows, arms=arm_rows, literals=lit_rows,
                variant_refs=var_rows, variant_tables=table_rows, callees=callee_rows, serializer=ser_rows,
                payload_calls=payload_rows, summary_heads=unchecked_heads,
                visitor=vis_rows, paths=paths, negatives=negatives, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('role', 'function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callees.tsv': tsv(('callee', 'role'), result['callees']),
        'serializer-jump-table.tsv': tsv(('serializer', 'family', 'tag', 'row_va', 'rel32', 'arm_va', 'advance_va', 'advance', 'arm_name'), result['jump_tables']),
        'serializer-unchecked-heads.tsv': tsv(('jmp_va', 'instructions', 'ops'), [tuple(x) for x in result['summary_heads']]),
        'serializer-literals.tsv': tsv(('serializer', 'va', 'form', 'kind', 'value', 'text'), result['arms']),
        'serializer-writer-calls.tsv': tsv(('serializer', 'call_va', 'callee', 'role'), result['payload_calls']),
        'enum-access-name.tsv': tsv(('function', 'call_va', 'callee', 'name_va', 'section', 'length', 'name', 'pool', 'variants'), result['enum_access']),
        'visitor-length-tables.tsv': tsv(('visitor', 'input', 'table', 'row', 'length', 'row_va', 'rel32', 'target', 'arm'), result['length_tables']),
        'visitor-literals.tsv': tsv(('visitor', 'va', 'form', 'value'), result['literals']),
        'name-pool-refs.tsv': tsv(('visitor', 'codec', 'family', 'input', 'output', 'lea_va', 'pool'), result['variant_refs']),
        'name-pools.tsv': tsv(('codec', 'pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'), result['variant_tables']),
        'serializer-cases.tsv': tsv(('serializer', 'tag', 'struct_map_flag', 'capacity', 'length', 'fail', 'appended_hex', 'grow_calls', 'final_length', 'result_words', 'writer_calls', 'arm', 'verdict'), result['serializer']),
        'visitor-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v[0] for v in VISITORS) + ('outcome', 'verdict'), result['visitor']),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'inputs'), result['paths']),
        'negative-controls.tsv': tsv(('family', 'wrong_reconstruction', 'mismatching_cases', 'cases'), result['negatives']),
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
    files = render(result)
    for name, text in files.items():
        if any(not (0x20 <= ord(c) < 0x7f or c in '\t\n') for c in text):
            print('rejected: %s carries a control or non-ASCII character' % name, file=sys.stderr)
            return 1
    for name, text in files.items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    s = result['summary']
    print('serializer %d/%d, visitor %d/%d, negatives caught: %s' % (
        s['serializer_matches'], s['serializer_cases'], s['visitor_matches'], s['visitor_cases'],
        s['all_negative_controls_caught']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
