#!/usr/bin/env python3
"""Reconstruct the node #115 vote-record serializer and its MessagePack integer writer and prove it.

The governance vote action carries a record of a vote choice and an unsigned
64-bit weight.  Three code copies serialize the record: a msgpack fixmap
(0x82) with the keys choice and weight, or a fixarray (0x92) of the two
values, selected by one flag byte of the serializer state.  The choice is the
fixstr of its name (tag 0 yes, tag 1 no, every other tag byte abstain) and the
weight goes through an unsigned-integer writer that picks the shortest form
(positive fixint, 0xcc, 0xcd, 0xce, 0xcf with big-endian payloads).

The producer authenticates the #115 capture, locates the nine bodies by their
unwind (FDE) extents and runs each body's original machine code in a small
interpreter for the x86-64 subset those bodies use, including the three
`Vec<u8>` reserve helpers (reached through the serializer and the writer,
with the allocator's finish-grow call and the process error handler modelled
as the only stubs).  Every interpreted result is compared with an independent
pure-Python reconstruction: appended bytes, reserve calls, final capacity and
data pointer, the returned result words, and the error paths.  Deliberately
wrong reconstructions, corrupted code bytes and out-of-range inputs run
through the same comparison and must be caught.

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

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VEC_BASE = 0x3000_0000
DATA_BASE = 0x4000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c
OK_WORD = 0x8000000000000004


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


JCC_CC = {'jb': 2, 'jae': 3, 'je': 4, 'jne': 5, 'jbe': 6, 'ja': 7, 'js': 8, 'jns': 9, 'jle': 14, 'jg': 15}


class Insn:
    __slots__ = ('va', 'length', 'raw', 'op', 'w', 'size', 'reg', 'rm', 'imm', 'target', 'ext')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


JCC8 = {0x74: 'je', 0x75: 'jne', 0x72: 'jb', 0x73: 'jae', 0x76: 'jbe', 0x77: 'ja', 0x7e: 'jle', 0x7f: 'jg',
        0xeb: 'jmp', 0x78: 'js', 0x79: 'jns'}
JCC32 = {0x0f84: 'je', 0x0f85: 'jne', 0x0f82: 'jb', 0x0f83: 'jae', 0x0f86: 'jbe', 0x0f87: 'ja', 0x0f8e: 'jle',
         0x0f8f: 'jg', 0x0f88: 'js', 0x0f89: 'jns'}


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
    if not two and op in (0x01, 0x03, 0x09, 0x0b, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x84, 0x85, 0x89, 0x8b, 0x88, 0x8d, 0x63):
        reg, rm, _ = modrm()
        names = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
                 0x39: 'cmp', 0x3b: 'cmp', 0x84: 'test', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov', 0x88: 'mov', 0x8d: 'lea', 0x63: 'movsxd'}
        to_reg = op in (0x03, 0x0b, 0x2b, 0x33, 0x3b, 0x8b, 0x8d, 0x63)
        if op in (0x88, 0x84):
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
    elif not two and op in (0xc0, 0xc1):
        reg, rm, sub = modrm()
        names = {0: 'rol', 4: 'shl', 5: 'shr'}
        if sub not in names:
            raise Reject('unsupported shift form at 0x%x' % va)
        if op == 0xc0:
            kw['size'] = 1
        kw.update(op=names[sub], rm=rm, imm=imm(1), ext='imm')
    elif two and 0x0fc8 <= op <= 0x0fcf:
        kw.update(op='bswap', reg=(op - 0x0fc8) | (rex_b << 3))
    elif two and 0x0f40 <= op <= 0x0f4f:
        reg, rm, _ = modrm()
        kw.update(op='cmov', reg=reg, rm=rm, imm=op & 15)
    elif two and 0x0f90 <= op <= 0x0f9f:
        reg, rm, _ = modrm()
        kw.update(op='setcc', rm=rm, imm=op & 15, size=1)
    elif not two and op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        v = sx(imm(2), 16) if opsize16 else sx(imm(4), 32)
        names = {0x05: 'add', 0x0d: 'or', 0x25: 'and', 0x2d: 'sub', 0x35: 'xor', 0x3d: 'cmp'}
        kw.update(op=names[op], rm=('reg', 0), imm=v, ext='imm')
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
        self.stack_top = STACK_TOP

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

    def cc(self, code):
        le = self.zf or (self.sf != self.of)
        return {2: self.cf, 3: not self.cf, 4: self.zf, 5: not self.zf, 6: self.cf or self.zf,
                7: not (self.cf or self.zf), 8: self.sf, 9: not self.sf, 14: le, 15: not le}[code]

    def run(self, entry, limit=900):
        self.regs[4] = self.stack_top - 8
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
            elif op in ('shl', 'shr', 'rol'):
                a, n = self.get(ins.rm, size), ins.imm & (63 if size == 8 else 31)
                bits = 8 * size
                if op == 'shl':
                    r = (a << n) & m
                elif op == 'shr':
                    r = a >> n
                else:
                    n %= bits
                    r = ((a << n) | (a >> (bits - n))) & m
                if n:
                    self.setflags(r, size)
                self.put(ins.rm, r, size)
            elif op == 'bswap':
                self.put(('reg', ins.reg), int.from_bytes((self.regs[ins.reg] & m).to_bytes(size, 'little'), 'big'), size)
            elif op == 'cmov':
                src = self.get(ins.rm, size)
                if self.cc(ins.imm):
                    self.put(('reg', ins.reg), src, size)
                elif size == 4:
                    self.put(('reg', ins.reg), self.regs[ins.reg], 4)
            elif op == 'setcc':
                self.put(ins.rm, 1 if self.cc(ins.imm) else 0, 1)
            elif op in ('inc', 'dec'):
                r = (self.get(ins.rm, size) + (1 if op == 'inc' else -1)) & m
                self.zf = r == 0
                self.sf = bool(r >> (8 * size - 1))
                self.put(ins.rm, r, size)
            elif op in JCC_CC:
                if self.cc(JCC_CC[op]):
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
                    if self.regs[4] != self.stack_top:
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
    machine.store(vec, max(cap * 2, length + additional, 8), 8)
    return 0



# ------------------------------------------------------------ the functions

# (record serializer, unsigned-integer writer, Vec<u8> reserve helper, finish-grow callee)
FAMILIES = (
    (0x241cb90, 0x25e9f10, 0x231e050, 0x231dc90),
    (0x3c31a70, 0x3d51450, 0x43bd910, 0x43bd550),
    (0x4d974e0, 0x57cfd20, 0x5963a10, 0x5963650),
)
HANDLE_ERROR_SLOT = 0x64df498
ROLES = ('record_serializer', 'uint_writer', 'reserve_helper')
NAMES = (b'yes', b'no', b'abstain')
KEY_CHOICE, KEY_WEIGHT = b'choice', b'weight'
STEP = 0x10000          # the modelled allocator moves the buffer by this much
ERR1, ERR2 = 0x1111_1111_1111_1111, 0x2222_2222_2222_2222
BORROWED = 0x8000000000000000
OUT_BYTES = 24


class Abort(Exception):
    """The process error handler was called (it never returns)."""

    def __init__(self, rdi, rsi):
        super().__init__('abort')
        self.rdi, self.rsi = rdi, rsi


def linear_rows(image, entry, end):
    rows = []
    pc = entry
    while pc < end:
        if image.read(pc, 1) == b'\xcc':
            raise Reject('padding inside the body of 0x%x' % entry)
        ins = decode(image, pc)
        rows.append(ins)
        pc += ins.length
    if pc != end:
        raise Reject('decode does not end on the FDE end of 0x%x' % entry)
    return rows


class Env:
    """One run: the allocator and error-handler stubs of a code family."""

    def __init__(self, image, fam, fail_alloc=False, writer=None):
        self.image, self.fam, self.fail_alloc = image, fam, fail_alloc
        self.finishes = []
        self.reserves = []
        self.writer = writer

    def inner_stubs(self):
        return {self.fam[3]: self.finish, ('slot', HANDLE_ERROR_SLOT): self.error}

    def stubs(self):
        out = self.inner_stubs()
        out[self.fam[2]] = self.reserve
        out[self.fam[1]] = self.writer if self.writer is not None else self.call_writer
        return out

    def finish(self, m, args):
        out, old_cap, ptr, new_cap, align = args
        self.finishes.append((old_cap, ptr, new_cap, align))
        if self.fail_alloc:
            m.store(out, 1, 8)
            m.store(out + 8, ERR1, 8)
            m.store(out + 16, ERR2, 8)
            return 0
        new_ptr = u64(ptr + STEP)
        for a in [a for a in m.mem if ptr <= a < ptr + old_cap]:
            m.mem[new_ptr + (a - ptr)] = m.mem[a]
        m.store(out, 0, 8)
        m.store(out + 8, new_ptr, 8)
        return 0

    def error(self, m, args):
        raise Abort(args[0], args[1])

    def call_writer(self, m, args):
        sub = Machine(self.image, self.stubs())
        sub.mem = m.mem
        sub.stack_top = m.stack_top - 0x2000
        sub.regs[7], sub.regs[6], sub.regs[2] = args[:3]
        try:
            sub.run(self.fam[1])
        finally:
            m.trace.extend(sub.trace)
        return 0

    def reserve(self, m, args):
        self.reserves.append((args[1], args[2]))
        sub = Machine(self.image, self.inner_stubs())
        sub.mem = m.mem
        sub.stack_top = m.stack_top - 0x2000
        sub.regs[7], sub.regs[6], sub.regs[2], sub.regs[1], sub.regs[8] = args
        try:
            sub.run(self.fam[2])
        finally:
            m.trace.extend(sub.trace)
        return 0


def obs_of(m, env, base_len):
    ptr = m.load(VEC_BASE + 8, 8)
    end = m.load(VEC_BASE + 16, 8)
    added = bytes(m.load(ptr + k, 1) for k in range(base_len, end))
    reserves = tuple(env.reserves)
    out = bytes(m.load(OUT_BASE + k, 1) for k in range(OUT_BYTES))
    return ('ok', added.hex(), end, m.load(VEC_BASE, 8), ptr, out.hex(), reserves, tuple(env.finishes))


def new_machine(image, env, cap, length, flag=0):
    m = Machine(image, env.stubs())
    for k in range(32):
        m.store(OUT_BASE + k, 0xa5, 1)
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, length, 8)
    m.store(VEC_BASE + 0x18, 0, 8)
    m.store(VEC_BASE + 0x1b, flag, 1)
    return m


def execute(m, entry, env, base_len):
    try:
        m.run(entry)
    except Abort as exc:
        return ('abort', exc.rdi, exc.rsi)
    return obs_of(m, env, base_len)


def run_writer(image, fam, value, cap, length, fail=False):
    env = Env(image, fam, fail)
    m = new_machine(image, env, cap, length)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, VEC_BASE, value
    return execute(m, fam[1], env, length), m


def run_record(image, fam, flag, tag, weight, cap, length, fail=False, status=None):
    writer = None
    if status is not None:
        def writer(m, args):
            m.store(args[0], status[0], 8)
            m.store(args[0] + 8, status[1], 8)
            return 0
    env = Env(image, fam, fail, writer)
    m = new_machine(image, env, cap, length, flag)
    m.store(IN_BASE, weight, 8)
    m.store(IN_BASE + 8, tag, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, VEC_BASE
    return execute(m, fam[0], env, length), m


def run_reserve(image, fam, cap, ptr, length, add, align, elem, fail=False):
    env = Env(image, fam, fail)
    m = Machine(image, env.inner_stubs())
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, ptr, 8)
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = VEC_BASE, length, add, align, elem
    try:
        m.run(fam[2])
    except Abort as exc:
        return ('abort', exc.rdi, exc.rsi), m
    return ('ok', m.load(VEC_BASE, 8), m.load(VEC_BASE + 8, 8), tuple(env.finishes)), m


# ----------------------------------------------------- the reconstruction

class Vec:
    def __init__(self, cap, length, ptr=DATA_BASE):
        self.cap, self.len, self.ptr = cap, length, ptr
        self.data = bytearray()
        self.reserves, self.finishes = [], []


class Abandon(Exception):
    def __init__(self, rdi, rsi):
        super().__init__('abort')
        self.rdi, self.rsi = rdi, rsi


def recon_grow(cap, ptr, length, add, align, elem, fail, min_small=4, doubling=True, check_overflow=True,
               small_edge=0x401, min_one=8):
    """Vec::reserve's slow path: the new capacity and buffer."""
    if elem == 0:
        raise Abandon(0, length)
    need = length + add
    if check_overflow and need > MASK:
        raise Abandon(0, length)
    new = max(need & MASK, (cap * 2) & MASK if doubling else 0)
    new = max(new, min_one if elem == 1 else (min_small if elem < small_edge else 1))
    finish = (cap, ptr, new, align)
    if fail:
        raise Abandon(ERR1, ERR2)
    return new, u64(ptr + STEP), finish


def reserve(v, add, fail=False, **kw):
    if add == 1:
        need_grow = v.cap == v.len
    else:
        need_grow = v.cap - v.len < add
    if need_grow:
        v.reserves.append((v.len, add))
        v.cap, v.ptr, fin = recon_grow(v.cap, v.ptr, v.len, add, 1, 1, fail, **kw)
        v.finishes.append(fin)


def put(v, data, fail=False, skip_reserve=False, reserve_extra=0, **kw):
    if not skip_reserve:
        reserve(v, len(data) + reserve_extra, fail, **kw)
    v.data += data
    v.len += len(data)


def uint_plan(value, th=(0x80, 0x100, 0x10000, 1 << 32), marks=(0xcc, 0xcd, 0xce, 0xcf), big=True):
    """(marker, payload) of the shortest unsigned MessagePack form."""
    order = 'big' if big else 'little'
    if value < th[0]:
        return None, bytes([value])
    for limit, mark, width in zip(th[1:], marks, (1, 2, 4)):
        if value < limit:
            return mark, value.to_bytes(width, order)
    return marks[3], value.to_bytes(8, order)


def recon_uint(v, value, fail=False, plan=uint_plan, **kw):
    """Append the integer; returns the leading bytes of the 16-byte result."""
    if not 0 <= value <= MASK:
        raise ValueError('weight outside u64')
    mark, payload = plan(value)
    if mark is None:
        put(v, payload, fail, **kw)
        return (2).to_bytes(8, 'little') + bytes([0, payload[0]])
    put(v, bytes([mark]), fail, **kw)
    put(v, payload, fail, **kw)
    return (2).to_bytes(8, 'little') + bytes([mark])


def finish_obs(v, out_head):
    out = bytes(out_head) + b'\xa5' * (OUT_BYTES - len(out_head))
    return ('ok', bytes(v.data).hex(), v.len, v.cap, v.ptr, out.hex(), tuple(v.reserves), tuple(v.finishes))


def recon_writer(value, cap, length, fail=False, plan=uint_plan, **kw):
    v = Vec(cap, length)
    try:
        head = recon_uint(v, value, fail, plan, **kw)
    except Abandon as exc:
        return ('abort', exc.rdi, exc.rsi)
    return finish_obs(v, head)


def recon_record(flag, tag, weight, cap, length, fail=False, status=None, names=NAMES,
                 header=lambda f: (((f ^ 1) << 4) | 0x82) & 0xff, choice_key=lambda f: f != 0,
                 weight_key=lambda f: f == 1, strict_tag=False, plan=uint_plan, **kw):
    """The flag is a whole byte: 0 gives a fixarray header, 1 a fixmap with both keys, any other value a header
    byte of (flag ^ 1) << 4 | 0x82 with the choice key but no weight key."""
    if not 0 <= flag < 256 or not 0 <= tag < 256 or not 0 <= weight <= MASK:
        raise ValueError('record field outside its range')
    if strict_tag and tag > 2:
        raise ValueError('tag outside the enum')
    v = Vec(cap, length)
    try:
        put(v, bytes([header(flag)]), fail, **kw)
        if choice_key(flag):
            put(v, b'\xa6', fail, **kw)
            put(v, KEY_CHOICE, fail, **kw)
        name = names[min(tag, 2)]
        put(v, bytes([0xa0 | len(name)]), fail, **kw)
        put(v, name, fail, **kw)
        if weight_key(flag):
            put(v, b'\xa6', fail, **kw)
            put(v, KEY_WEIGHT, fail, **kw)
        if status is not None:
            head = BORROWED.to_bytes(8, 'little') + status[0].to_bytes(8, 'little') + status[1].to_bytes(8, 'little')
            return finish_obs(v, head)
        recon_uint(v, weight, fail, plan, **kw)
    except Abandon as exc:
        return ('abort', exc.rdi, exc.rsi)
    return finish_obs(v, OK_WORD.to_bytes(8, 'little'))


def recon_reserve_call(cap, ptr, length, add, align, elem, fail=False, **kw):
    try:
        new, new_ptr, fin = recon_grow(cap, ptr, length, add, align, elem, fail, **kw)
    except Abandon as exc:
        return ('abort', exc.rdi, exc.rsi)
    return ('ok', new, new_ptr, (fin,))


# ------------------------------------------------------------- case streams

def lcg(count, seed):
    x = seed
    for i in range(count):
        x = (x * 6364136223846793005 + 1442695040888963407) & MASK
        yield x >> ((i * 11) % 61)


WRITER_WEIGHTS = tuple(sorted(set((0, 1, 2, 0x7f, 0x80, 0x81, 0xfe, 0xff, 0x100, 0x101, 0xffff, 0x10000, 0x10001,
                                   0xffffff, 0xffffffff, 0x100000000, 0x100000001, 1 << 56, 1 << 63, MASK - 1, MASK)
                                  + tuple(lcg(10, 7)))))
RECORD_WEIGHTS = (0, 127, 128, 256, 65536, 1 << 32, 1 << 63, MASK) + tuple(lcg(1, 99))
RECORD_TAGS = (0, 1, 2, 255)
RECORD_FLAGS = (0, 1, 2, 3, 255)
RESERVE_CAPS = (0, 1, 3, 8, 100, (1 << 63) - 1, 1 << 63, (1 << 63) + 5, MASK)
RESERVE_LENS = (0, 5, MASK)
RESERVE_ADDS = (0, 1, 2, 6, 100, 1 << 63, MASK)
RESERVE_ALIGNS = (0, 1, 8)
RESERVE_ELEMS = (0, 1, 2, 0x400, 0x401, 0x1000)
STATUSES = ((0, 7), (1, 0x55), (3, MASK), (1 << 63, 1))


def writer_cases():
    for weight in WRITER_WEIGHTS:
        for length in (0, 3):
            for spare in range(10):
                for fail in ((False, True) if spare <= 1 else (False,)):
                    yield (weight, length + spare, length, fail)


def record_cases():
    for flag in RECORD_FLAGS:
        for tag in RECORD_TAGS:
            for weight in RECORD_WEIGHTS:
                for length in (0, 5):
                    for spare in range(23):
                        yield (flag, tag, weight, length + spare, length, False, None)
    for flag in (0, 1, 2):
        for tag in (0, 2):
            for weight in (0, 200, 1 << 33, MASK):
                for spare in (0, 1):
                    yield (flag, tag, weight, 4 + spare, 4, True, None)
    for flag in (0, 1, 2):
        for tag in (0, 1, 2):
            for status in STATUSES:
                for spare in (0, 12):
                    yield (flag, tag, 9, 3 + spare, 3, False, status)


def reserve_cases():
    for cap in RESERVE_CAPS:
        for length in RESERVE_LENS:
            for add in RESERVE_ADDS:
                for align in RESERVE_ALIGNS:
                    for elem in RESERVE_ELEMS:
                        for fail in (False, True):
                            yield (cap, 0x4444_0000, length, add, align, elem, fail)


KINDS = {
    'uint_writer': (writer_cases, lambda image, fam, p: run_writer(image, fam, *p), lambda p, **kw: recon_writer(*p, **kw)),
    'record_serializer': (record_cases, lambda image, fam, p: run_record(image, fam, *p),
                          lambda p, **kw: recon_record(*p, **kw)),
    'reserve_helper': (reserve_cases, lambda image, fam, p: run_reserve(image, fam, *p),
                       lambda p, **kw: recon_reserve_call(*p, **kw)),
}
STRIDES = {'uint_writer': 1, 'record_serializer': 5, 'reserve_helper': 11}


class PatchedImage(Image):
    """The same file with a few bytes changed (negative controls); own decode cache."""

    def __init__(self, base, patches):
        self.data, self.secs, self.rela, self.cache = base.data, base.secs, base.rela, {}
        self.patches = patches

    def read(self, va, n):
        raw = bytearray(super().read(va, n))
        for a, b in self.patches.items():
            if va <= a < va + n:
                raw[a - va] = b
        return bytes(raw)


def verdict(a, b):
    return 'match' if a == b else 'MISMATCH'


# ---------------------------------------------------------- negative controls

def mut(**kw):
    return kw


MUTANTS = {
    'uint_writer': (
        ('fixint edge 0x7f', mut(plan=lambda v: uint_plan(v, th=(0x7f, 0x100, 0x10000, 1 << 32)))),
        ('cc edge 0xff', mut(plan=lambda v: uint_plan(v, th=(0x80, 0xff, 0x10000, 1 << 32)))),
        ('cd edge 0xffff', mut(plan=lambda v: uint_plan(v, th=(0x80, 0x100, 0xffff, 1 << 32)))),
        ('ce edge 2^32-1', mut(plan=lambda v: uint_plan(v, th=(0x80, 0x100, 0x10000, (1 << 32) - 1)))),
        ('little-endian payload', mut(plan=lambda v: uint_plan(v, big=False))),
        ('ce and cf markers swapped', mut(plan=lambda v: uint_plan(v, marks=(0xcc, 0xcd, 0xcf, 0xce)))),
        ('no reserve before the write', mut(skip_reserve=True)),
        ('reserve one byte too many', mut(reserve_extra=1)),
        ('buffer never doubles', mut(doubling=False)),
        ('byte minimum capacity 4', mut(min_one=4)),
    ),
    'record_serializer': (
        ('map and array headers swapped', mut(header=lambda f: 0x92 if f else 0x82)),
        ('header ignores modes above 1', mut(header=lambda f: 0x82 if f else 0x92)),
        ('keys omitted in map mode', mut(choice_key=lambda f: False, weight_key=lambda f: False)),
        ('weight key for every nonzero mode', mut(weight_key=lambda f: f != 0)),
        ('choice key only in mode 1', mut(choice_key=lambda f: f == 1)),
        ('yes and no swapped', mut(names=(b'no', b'yes', b'abstain'))),
        ('tags above 2 rejected', mut(strict_tag=True)),
        ('yes spelled yep', mut(names=(b'yep', b'no', b'abstain'))),
        ('abstain never produced', mut(names=(b'yes', b'no', b'no'))),
        ('reserve one byte too many', mut(reserve_extra=1)),
        ('buffer never doubles', mut(doubling=False)),
        ('fixint edge 0x7f', mut(plan=lambda v: uint_plan(v, th=(0x7f, 0x100, 0x10000, 1 << 32)))),
        ('little-endian weight', mut(plan=lambda v: uint_plan(v, big=False))),
    ),
    'reserve_helper': (
        ('small-element minimum 8', mut(min_small=8)),
        ('buffer never doubles', mut(doubling=False)),
        ('small-element edge 0x400', mut(small_edge=0x400)),
        ('overflow unchecked', mut(check_overflow=False)),
        ('byte minimum capacity 4', mut(min_one=4)),
    ),
}

# (kind, entry va, byte index in the instruction, xor mask, expected operation, what it is)
CORRUPTIONS = (
    ('uint_writer', 0x25e9f18, 4, 0x02, 'cmp', 'cmp $0x100,%rdx immediate'),
    ('uint_writer', 0x25e9f4f, 5, 0x01, 'cmp', 'cmp $0x10000,%rdx immediate'),
    ('uint_writer', 0x25e9faa, 3, 0x01, 'shr', 'shr $0x20,%rcx count'),
    ('uint_writer', 0x25e9f6c, 3, 0x01, 'mov', 'movb $0xcd marker'),
    ('uint_writer', 0x25e9fd4, 1, 0x01, 'bswap', 'bswap %edx register'),
    ('uint_writer', 0x25e9f78, 3, 0x01, 'rol', 'rol $8,%dx count'),
    ('uint_writer', 0x25e9f7f, 3, 0x01, 'cmp', 'cmp $1,%rcx immediate'),
    ('uint_writer', 0x25ea034, 1, 0x01, 'movimm', 'mov $0xcc,%cl immediate'),
    ('record_serializer', 0x241cbad, 3, 0x10, 'or', 'or $0x82 header immediate'),
    ('record_serializer', 0x241cba5, 3, 0x01, 'xor', 'xor $1,%bpl flag inversion'),
    ('record_serializer', 0x241cbdf, 3, 0x01, 'mov', 'movb $0xa6 key marker'),
    ('record_serializer', 0x241cc42, 4, 0x01, 'mov', 'movw "no" literal'),
    ('record_serializer', 0x241cc11, 2, 0x01, 'cmp', 'cmp $1,%ebp tag immediate'),
    ('record_serializer', 0x241cbed, 3, 0x01, 'cmp', 'cmp $5,%rdi reserve edge'),
    ('record_serializer', 0x241cc7d, 3, 0x01, 'cmp', 'cmp $2,%rdi reserve edge'),
    ('record_serializer', 0x241cd43, 3, 0x01, 'cmp', 'cmp $2,%rcx writer status'),
    ('reserve_helper', 0x231e07f, 3, 0x01, 'cmp', 'cmp $0x401,%r9 element edge'),
    ('reserve_helper', 0x231e079, 2, 0x05, 'cmov', 'cmova opcode'),
    ('reserve_helper', 0x231e092, 1, 0x04, 'movimm', 'mov $8,%ebx immediate'),
    ('reserve_helper', 0x231e06a, 0, 0x01, 'jb', 'jb overflow branch'),
    ('reserve_helper', 0x231e08d, 4, 0x01, 'lea', 'lea 1(%rcx,%rcx,2) displacement'),
)


def detected(fn):
    """True when the check raises (a wrong reconstruction can also be rejected outright)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - any failure is a detection here
        return True


def build(data):
    build_guard(data)
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows, callee_rows = [], [], []
    bodies = {}
    for fi, fam in enumerate(FAMILIES):
        for role, va in zip(ROLES, (fam[0], fam[1], fam[2])):
            require_start(by_start, va)
            rec = by_start[va]
            rows = linear_rows(image, va, rec['end'])
            bodies[va] = rows
            body = image.read(va, rec['end'] - va)
            functions.append(dict(family=fi + 1, role=role, entry='0x%x' % va, fde_end='0x%x' % rec['end'],
                                  fde_bytes=rec['end'] - va, instructions=len(rows),
                                  lsda='none' if rec['lsda'] is None else '0x%x' % rec['lsda'],
                                  sha256=hashlib.sha256(body).hexdigest()))
            for r in rows if fi == 0 else ():
                insn_rows.append((fi + 1, role, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                                  '' if r.target is None else '0x%x' % r.target))
        # callee roles must follow from the body shapes
        want = {fam[0]: {fam[1], fam[2]}, fam[1]: {fam[2]}, fam[2]: {fam[3]}}
        for va, targets in want.items():
            got = {r.target for r in bodies[va] if r.op == 'call'}
            if got != targets:
                raise Reject('0x%x calls %s instead of %s' % (va, sorted(map(hex, got)), sorted(map(hex, targets))))
            for t in sorted(targets):
                callee_rows.append((fi + 1, '0x%x' % va, '0x%x' % t))
        slots = {r.rm[4] for r in bodies[fam[2]] if r.op == 'callslot'}
        if slots != {HANDLE_ERROR_SLOT}:
            raise Reject('reserve helper 0x%x does not call the error slot' % fam[2])
        callee_rows.append((fi + 1, '0x%x' % fam[2], 'slot:0x%x' % HANDLE_ERROR_SLOT))

    covered = set()
    totals = {k: [0, 0] for k in KINDS}
    sample_rows = []
    stored = {k: [] for k in KINDS}
    abort_count = {k: 0 for k in KINDS}
    for kind, (gen, run, recon) in KINDS.items():
        for fi, fam in enumerate(FAMILIES):
            for i, p in enumerate(gen()):
                got, m = run(image, fam, p)
                covered.update(m.trace)
                exp = recon(p)
                totals[kind][0] += 1
                totals[kind][1] += got == exp
                if got[0] == 'abort':
                    abort_count[kind] += 1
                if fi == 0 and i % STRIDES[kind] == 0:
                    stored[kind].append((p, got))
                if i % 397 == 0:
                    sample_rows.append((kind, fi + 1, ' '.join('%x' % x if isinstance(x, int) and x > 9 else str(x)
                                                               for x in p), got[0], got[1] if got[0] == 'ok' else '',
                                        got[2] if got[0] == 'ok' else '', verdict(got, exp)))
    cases = sum(t[0] for t in totals.values())
    matches = sum(t[1] for t in totals.values())

    negatives = []
    for kind, muts in MUTANTS.items():
        recon = KINDS[kind][2]
        for name, kw in muts:
            bad = 0
            for p, got in stored[kind]:
                try:
                    bad += recon(p, **kw) != got
                except ValueError:
                    bad += 1
            negatives.append(('wrong reconstruction', kind, name, bad, len(stored[kind])))
    fam0 = FAMILIES[0]
    for kind, va, idx, mask, op, what in CORRUPTIONS:
        ins = decode(image, va)
        if ins.op != op or idx >= ins.length:
            raise Reject('corruption site 0x%x is not the expected %s' % (va, op))
        patched = PatchedImage(image, {va + idx: image.read(va + idx, 1)[0] ^ mask})
        run = KINDS[kind][1]
        bad = 0
        for p, got in stored[kind]:
            try:
                bad += run(patched, fam0, p)[0] != got
            except Exception:  # noqa: BLE001 - a rejected or crashing run is a detection
                bad += 1
        negatives.append(('corrupted code byte', kind, '0x%x %s' % (va, what), bad, len(stored[kind])))

    def range_fail(fn):
        try:
            fn()
        except ValueError:
            return 1
        return 0
    for name, fn in (
            ('weight 2^64 outside u64', lambda: recon_record(1, 0, 1 << 64, 8, 0)),
            ('negative weight', lambda: recon_writer(-1, 8, 0)),
            ('tag 256 outside a byte', lambda: recon_record(0, 256, 1, 8, 0)),
    ):
        negatives.append(('out-of-range input', 'both', name, range_fail(fn), 1))
    flipped = bytearray(data)
    flipped[len(flipped) // 2] ^= 1
    try:
        build_guard(flipped)
        caught = 0
    except Reject:
        caught = 1
    negatives.append(('corrupted input', 'both', 'one flipped byte fails the SHA-256 check', caught, 1))
    try:
        require_start(by_start, 0x241cba5)
        caught = 0
    except Reject:
        caught = 1
    negatives.append(('out-of-range input', 'both', 'mid-function address is not an FDE start', caught, 1))

    cov_rows = []
    for fi, fam in enumerate(FAMILIES):
        for role, va in zip(ROLES, fam[:3]):
            hit = sum(1 for r in bodies[va] if r.va in covered)
            cov_rows.append((fi + 1, role, '0x%x' % va, len(bodies[va]), hit))
    caught_all = all(n[3] > 0 for n in negatives)
    summary = dict(
        cases=cases, matches=matches, per_kind={k: dict(cases=v[0], matches=v[1], aborts=abort_count[k])
                                                for k, v in totals.items()},
        negative_controls=len(negatives), negative_detected=sum(1 for n in negatives if n[3] > 0),
        all_negative_controls_caught=caught_all, reconstruction_matches_all=cases == matches,
        instructions_covered=sum(c[4] for c in cov_rows), instructions_total=sum(c[3] for c in cov_rows))
    return dict(functions=functions, instructions=insn_rows, callees=callee_rows, samples=sample_rows,
                negatives=negatives, coverage=cov_rows, summary=summary)


def require_start(by_start, va):
    if va not in by_start:
        raise Reject('0x%x is not an FDE start' % va)


def build_guard(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    s = result['summary']
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('family', 'role', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callees.tsv': tsv(('family', 'caller', 'callee'), result['callees']),
        'case-samples.tsv': tsv(('kind', 'family', 'inputs_hex', 'outcome', 'appended_or_abort_rdi',
                                 'final_length_or_rsi', 'verdict'), result['samples']),
        'coverage.tsv': tsv(('family', 'role', 'entry', 'instructions', 'executed'), result['coverage']),
        'negative-controls.tsv': tsv(('family', 'kind', 'control', 'differing_cases', 'cases'), result['negatives']),
        'summary.json': json.dumps(s, indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(dict(cases=s['cases'], negative_controls=s['negative_controls'],
                                        negative_detected=s['negative_detected']), indent=2, sort_keys=True) + '\n',
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
    s = result['summary']
    if not s['reconstruction_matches_all'] or not s['all_negative_controls_caught']:
        print('reconstruction or negative controls failed', file=sys.stderr)
        print(json.dumps(s, indent=1, sort_keys=True), file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    print('cases %d/%d, negatives %d/%d, instructions executed %d/%d' % (
        s['matches'], s['cases'], s['negative_detected'], s['negative_controls'],
        s['instructions_covered'], s['instructions_total']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
