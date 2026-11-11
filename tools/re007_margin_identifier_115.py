#!/usr/bin/env python3
"""Reconstruct the node #115 margin-mode enum-identifier deserializers and prove them.

The margin-mode enum (normal, noCross, strictIsolated) is read from a serde
`Content` buffer through an identifier-plus-value pair deserializer: it takes a
0x40-byte pair (the identifier Content at +0x00, the value Content at +0x20)
and returns the variant index together with the untouched value Content, or an
error.  The producer authenticates the #115 capture, locates five bodies by
their unwind (FDE) extents, and runs each body's original machine code in a
small interpreter for the fixed x86-64 subset those bodies use:

* three 1,002-byte bodies (three copy families) that write the result and the
  error into a tagged 32-byte record, and
* two 873-byte bodies (families 1 and 2) that return the same decisions as a
  one-byte `Result` with a boxed error pointer.

The identifier Content is dispatched through a 15-entry jump table: U8 and U64
are variant indexes 0..2, String and Str are compared byte-for-byte with the
three names, ByteBuf and Bytes are handed to the already reconstructed name
visitor (run for real as a callee), and every other tag is an invalid-type
error.  The drop, free, invalid-value, unknown-variant and invalid-type callees
are replaced by recording stubs; the order and the arguments of those calls
are part of the comparison.

Every interpreted result is compared with an independent pure-Python
reconstruction.  Deliberately wrong reconstructions, damaged code bytes and
out-of-range inputs must all be caught.

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
DATA_BASE = 0x4000_0000
OWNED_BASE = 0x5000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c
BORROWED = 0x8000000000000000


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
        self.patches = {}

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
        raw = self.data[off:off + n]
        if self.patches:
            raw = bytes(self.patches.get(va + k, b) for k, b in enumerate(raw))
        return raw

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
    elif not two and op == 0x3c:
        kw.update(op='cmp', rm=('reg', 0), imm=imm(1), size=1, ext='imm')
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
    elif two and op in (0x0f10, 0x0f11, 0x0f28, 0x0f29) and not opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op in (0x0f10, 0x0f28) else 'movups_store', reg=reg, rm=rm, size=16)
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

    def run(self, entry, limit=4000, stack_top=STACK_TOP):
        self.regs[4] = stack_top - 8
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
                    if self.regs[4] != stack_top:
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


# ---------------------------------------------------------------- bodies and callee roles

# (entry, copy family, output form).  The tagged form leaves a 32-byte record
# at out+8 on error; the result form leaves a boxed error pointer at out+8.
BODIES = (
    (0x1fa4630, 1, 'tagged'),
    (0x3945390, 2, 'tagged'),
    (0x567f110, 3, 'tagged'),
    (0x1fac540, 1, 'result'),
    (0x394a4e0, 2, 'result'),
)
# name visitors (already reconstructed by the margin-mode packet) used as callees
VISITORS = {(1, 'tagged'): 0x28687f0, (1, 'result'): 0x2868660,
            (2, 'tagged'): 0x3bcf6b0, (2, 'result'): 0x3bcf850,
            (3, 'tagged'): 0x59fdd20}
VARIANT_POOLS = {1: 0x643e188, 2: 0x6475de0, 3: 0x64b7d28}
NAMES = (b'normal', b'noCross', b'strictIsolated')
# first appearance order of the distinct callees inside every body
ROLE_ORDER = ('invalid_value', 'visit_bytes', 'unknown_variant', 'drop', 'free', 'invalid_type', 'resume', 'cleanup')
# Content tag (byte 0) -> arm.  Table index is tag - 1; the bound is index <= 14.
ARMS = {1: 'int8', 4: 'int64', 12: 'string', 13: 'str', 14: 'bytebuf', 15: 'bytes'}
NICHE_TAG = 0x16

FILL_BASE = {'invalid_value': 0xa0, 'unknown_variant': 0xc0, 'invalid_type': 0xe0}
SENTINEL = {'invalid_value': 0xe771_0000_0000_0001, 'unknown_variant': 0xe772_0000_0000_0001,
            'invalid_type': 0xe773_0000_0000_0001}


def fill_for(role):
    return bytes((FILL_BASE[role] + k) & 0xff for k in range(32))


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


def call_key(r):
    return r.target if r.op == 'call' else ('slot', r.rm[4])


def body_roles(rows):
    """Bind the eight distinct callees of a body, by first appearance, to ROLE_ORDER."""
    keys = []
    for r in rows:
        if r.op in ('call', 'callslot') and call_key(r) not in keys:
            keys.append(call_key(r))
    if len(keys) != len(ROLE_ORDER):
        raise Reject('body has %d distinct callees, expected %d' % (len(keys), len(ROLE_ORDER)))
    return dict(zip(ROLE_ORDER, keys))


def visitor_callees(rows, form):
    """(lossy slot, free slot, unknown target, unwind target) of a bytes visitor body."""
    slots = []
    for r in rows:
        if r.op == 'callslot' and r.rm[4] not in slots:
            slots.append(r.rm[4])
    if len(slots) != 2:
        raise Reject('bytes visitor does not use two slots')
    direct = [r.target for r in rows if r.op == 'call']
    if not direct:
        raise Reject('bytes visitor has no direct call')
    return slots[0], slots[1], sorted(set(direct[:-1]))[0] if len(set(direct[:-1])) == 1 else None, direct[-1]


# ---------------------------------------------------------------- recording stubs

class Recorder:
    """Callee stubs that append one event per call.  `form` selects the
    argument layout of the three error constructors."""

    def __init__(self, form, pools):
        self.form = form
        self.pools = pools
        self.events = []

    def invalid_value(self, m, args):
        if self.form == 'tagged':
            out, struct_ptr = args[0], m.load(args[2], 8)
            self.events.append(('iv', m.load(struct_ptr, 1), m.load(struct_ptr + 8, 8)))
            for k, b in enumerate(fill_for('invalid_value')):
                m.store(out + k, b, 1)
            return out
        self.events.append(('iv', m.load(args[0], 1), m.load(args[0] + 8, 8)))
        return SENTINEL['invalid_value']

    def unknown_variant(self, m, args):
        if self.form == 'tagged':
            out, ptr, ln, pool, count = args
        else:
            out, (ptr, ln, pool, count) = None, args[:4]
        text = bytes(m.load(ptr + k, 1) for k in range(ln))
        self.events.append(('uv', text, pool, count))
        if self.form == 'tagged':
            for k, b in enumerate(fill_for('unknown_variant')):
                m.store(out + k, b, 1)
            return out
        return SENTINEL['unknown_variant']

    def invalid_type(self, m, args):
        if self.form == 'tagged':
            out, content, pool = args[0], args[1], args[3]
        else:
            out, content, pool = None, args[0], args[2]
        self.events.append(('it', m.load(content, 1), pool))
        if self.form == 'tagged':
            for k, b in enumerate(fill_for('invalid_type')):
                m.store(out + k, b, 1)
            return out
        return SENTINEL['invalid_type']

    def drop(self, m, args):
        which = {IN_BASE: 'c1', IN_BASE + 0x20: 'c2'}.get(args[0])
        if which is None:
            raise Reject('drop of an unknown object 0x%x' % args[0])
        self.events.append(('drop', which, m.load(args[0], 1)))
        return 0

    def free(self, m, args):
        self.events.append(('free', args[0], args[1], args[2]))
        return 0

    def visit(self, m, args):
        """Run the name visitor body for real on a private stack below the caller's."""
        sub = Machine(m.image, m.stubs)
        sub.mem = m.mem
        sub.regs[7], sub.regs[6], sub.regs[2] = args[0], args[1], args[2]
        sub.run(self.visitor, stack_top=STACK_TOP - 0x2000)
        m.trace.extend(sub.trace)
        return sub.regs[0]

    def lossy(self, m, args):
        out, ptr, ln = args[0], args[1], args[2]
        raw = bytes(m.load(ptr + k, 1) for k in range(ln))
        self.events.append(('lossy', raw))
        try:
            raw.decode('utf-8')
            cow = (BORROWED, ptr, ln)
        except UnicodeDecodeError:
            text = raw.decode('utf-8', 'replace').encode('utf-8')
            for k, b in enumerate(text):
                m.store(OWNED_BASE + k, b, 1)
            cow = (len(text), OWNED_BASE, len(text))
        for k, v in enumerate(cow):
            m.store(out + 8 * k, v, 8)
        return out


_FDE_CACHE = {}


def fde_index(image):
    key = id(image.data)
    if key not in _FDE_CACHE:
        _, recs, _ = fde_extents.fde_extents(image.data)
        _FDE_CACHE[key] = {r['start']: r for r in recs}
    return _FDE_CACHE[key]


def bind_stubs(image, entry, family, form):
    """Return (stubs, recorder, roles) for one body.  The roles come from the
    body's own call order; the nested name visitor's callees are bound from
    its body shape."""
    by_start = fde_index(image)
    rows = linear(image, entry, by_start[entry]['end'])
    roles = body_roles(rows)
    rec = Recorder(form, VARIANT_POOLS[family])
    stubs = {roles['invalid_value']: rec.invalid_value, roles['unknown_variant']: rec.unknown_variant,
             roles['invalid_type']: rec.invalid_type, roles['drop']: rec.drop, roles['free']: rec.free}
    ventry = VISITORS[(family, form)]
    vrows = linear(image, ventry, by_start[ventry]['end'])
    lossy_slot, free_slot, unknown, _unwind = visitor_callees(vrows, form)
    stubs[('slot', lossy_slot)] = rec.lossy
    if ('slot', free_slot) != roles['free']:
        stubs[('slot', free_slot)] = rec.free
    if unknown is not None and unknown != roles['unknown_variant']:
        stubs[unknown] = rec.unknown_variant
    rec.visitor = ventry
    stubs[roles['visit_bytes']] = rec.visit
    if roles['visit_bytes'] != ventry:
        raise Reject('the visit_bytes callee is not the expected visitor 0x%x' % ventry)
    return stubs, rec, roles, rows, vrows


# ---------------------------------------------------------------- cases

class Case:
    __slots__ = ('arm', 'tag', 'value', 'data', 'cap', 'c2')

    def __init__(self, arm, tag, value=0, data=b'', cap=0, c2=NICHE_TAG):
        self.arm, self.tag, self.value, self.data, self.cap, self.c2 = arm, tag, value, data, cap, c2

    def label(self):
        v = self.data.hex() if self.data else '-'
        return '%s:t%d:v%x:d%s:c%d:n%02x' % (self.arm, self.tag, self.value, v, self.cap, self.c2)


def c2_bytes(tag):
    return bytes([tag]) + bytes((k * 7 + 3) & 0xff for k in range(31))


MUTATION_BYTES = (0x00, 0x09, 0x0a, 0x80, 0xc3, 0xe2, 0xff) + tuple(range(0x20, 0x7f, 6))


def text_inputs():
    seen, have = [], set()

    def add(t):
        if t not in have:
            have.add(t)
            seen.append(t)
    add(b'')
    for n in NAMES:
        add(n)
        for k in range(len(n) + 1):
            add(n[:k])
        add(n + b'x')
        add(n + b'\0')
        add(n.lower())
        add(n.upper())
        add(n[:-1] + b'\xff')
        for pos in range(len(n)):
            for v in MUTATION_BYTES:
                add(n[:pos] + bytes([v]) + n[pos + 1:])
            add(n[:pos] + bytes([n[pos] ^ 0x20]) + n[pos + 1:])
    for a in NAMES:
        for b in NAMES:
            if a != b:
                add(a[:len(a) // 2] + b[len(b) // 2:])
    for ln in range(0, 20):
        add(b'A' * ln)
        add(b'\x80' * ln)
    return seen


INT_VALUES = tuple(range(0, 9)) + (0x7f, 0x80, 0xff, 0x100, 0x101, 0xffff, 0x10000, 0x100000000, 0x100000001,
                                   0x8000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff,
                                   0x0100000000000000, 0x0200000000000000)
OTHER_TAGS = (0, 2, 3, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23, 0x7f, 0x80, 0xff)
C2_TAGS = (NICHE_TAG, 0x03, 0x0d)


def case_list(sample=1):
    """All cases of one body.  `sample` thins the text cases for control runs."""
    texts = text_inputs()
    out = []
    for i, v in enumerate(INT_VALUES):
        for k, c2 in enumerate(C2_TAGS):
            if v <= 0xff:
                out.append(Case('int8', 1, value=v, c2=c2))
            out.append(Case('int64', 4, value=v, c2=c2))
    for i, t in enumerate(OTHER_TAGS):
        for c2 in C2_TAGS:
            out.append(Case('other', t, c2=c2))
    for arm, tag in (('str', 13), ('bytes', 15), ('string', 12), ('bytebuf', 14)):
        for i, t in enumerate(texts):
            cap = 0
            if arm in ('string', 'bytebuf'):
                cap = 0 if i % 2 == 0 else len(t) + 3
            out.append(Case(arm, tag, data=t, cap=cap, c2=C2_TAGS[i % 3]))
    return out[::sample] if sample > 1 else out


# ---------------------------------------------------------------- reconstruction

class Flaws:
    """Switches that turn the reconstruction into a deliberately wrong one."""
    ALL = ('int_bound', 'int64_low_byte', 'prefix_match', 'case_fold', 'swap_first_two', 'length_only',
           'first4_only', 'no_drop_c1', 'free_always', 'drop_c2_always', 'string_drops_c1', 'int16_as_int8',
           'bytes_no_lossy', 'drop_c2_on_ok', 'unknown_is_last', 'bytebuf_drops_c1', 'invalid_type_drops_c1',
           'drop_before_visit')


def classify(text, flaws):
    if 'prefix_match' in flaws:
        for k, n in enumerate(NAMES):
            if text[:len(n)] == n:
                return k
        return None
    if 'case_fold' in flaws:
        low = [n.lower() for n in NAMES]
        t = low.index(text.lower()) if text.lower() in low else None
    elif 'length_only' in flaws:
        t = next((k for k, n in enumerate(NAMES) if len(n) == len(text)), None)
    elif 'first4_only' in flaws:
        t = next((k for k, n in enumerate(NAMES) if len(n) == len(text) and n[:4] == text[:4]), None)
    else:
        t = NAMES.index(text) if text in NAMES else None
    if t is not None and 'swap_first_two' in flaws:
        t = {0: 1, 1: 0}.get(t, t)
    return t


def lossy_text(text):
    try:
        text.decode('utf-8')
        return text, False
    except UnicodeDecodeError:
        return text.decode('utf-8', 'replace').encode('utf-8'), True


def recon_visitor(text, pool, flaws, events):
    """Name visitor outcome: variant index or None; appends its call events."""
    t = classify(text, flaws)
    if t is not None:
        return t
    shown, owned = lossy_text(text)
    if 'bytes_no_lossy' not in flaws:
        events.append(('lossy', text))
    events.append(('uv', shown, pool, 3))
    if owned:
        events.append(('free', OWNED_BASE, len(shown), 0))
    return None


def recon(case, family, flaws=frozenset()):
    """(outcome, events).  outcome = ('ok', index) or ('err', role)."""
    pool = VARIANT_POOLS[family]
    ev = []
    arm = ARMS.get(case.tag)
    if 'int16_as_int8' in flaws and case.tag in (2, 3):
        arm = 'int8'
    result = None
    consumed = False
    if arm in ('int8', 'int64'):
        v = case.value if arm == 'int8' else (case.value & 0xff if 'int64_low_byte' in flaws else case.value)
        limit = 3 if 'int_bound' in flaws else 2
        if v <= limit:
            result = ('ok', min(v, 2))
        else:
            ev.append(('iv', 1, v))
            result = ('err', 'invalid_value')
    elif arm in ('str', 'string'):
        t = classify(case.data, flaws)
        if t is not None:
            result = ('ok', t)
        else:
            ev.append(('uv', case.data, pool, 3))
            result = ('err', 'unknown_variant')
    elif arm in ('bytes', 'bytebuf'):
        if 'drop_before_visit' in flaws and arm == 'bytes':
            ev.append(('drop', 'c1', case.tag))
        t = recon_visitor(case.data, pool, flaws, ev)
        result = ('ok', t) if t is not None else ('err', 'unknown_variant')
    else:
        ev.append(('it', case.tag, 0))
        result = ('err', 'invalid_type')
        consumed = True
        if 'invalid_type_drops_c1' in flaws:
            ev.append(('drop', 'c1', case.tag))
    if arm in ('string', 'bytebuf'):
        if case.cap or 'free_always' in flaws:
            ev.append(('free', DATA_BASE, case.cap, 0))
        if (arm == 'string' and 'string_drops_c1' in flaws) or (arm == 'bytebuf' and 'bytebuf_drops_c1' in flaws):
            ev.append(('drop', 'c1', case.tag))
    elif arm is not None and 'no_drop_c1' not in flaws and not ('drop_before_visit' in flaws and arm == 'bytes'):
        ev.append(('drop', 'c1', case.tag))
    del consumed
    if result[0] == 'err' and (case.c2 != NICHE_TAG or 'drop_c2_always' in flaws):
        ev.append(('drop', 'c2', case.c2))
    elif result[0] == 'ok' and 'drop_c2_on_ok' in flaws:
        ev.append(('drop', 'c2', case.c2))
    if 'unknown_is_last' in flaws and result == ('err', 'unknown_variant'):
        result = ('ok', 2)
    return result, ev


def fix_it_pool(events, pool):
    return [('it', e[1], pool) if e[0] == 'it' else e for e in events]


# ---------------------------------------------------------------- interpretation driver

def load_case(m, case):
    c1 = bytearray([0x5a] * 32)
    c1[0] = case.tag
    data_ptr = DATA_BASE
    if case.arm == 'int8':
        c1[1] = case.value
    elif case.arm == 'int64':
        c1[8:16] = case.value.to_bytes(8, 'little')
    elif case.arm in ('str', 'bytes'):
        c1[8:16] = data_ptr.to_bytes(8, 'little')
        c1[16:24] = len(case.data).to_bytes(8, 'little')
    elif case.arm in ('string', 'bytebuf'):
        c1[8:16] = case.cap.to_bytes(8, 'little')
        c1[16:24] = data_ptr.to_bytes(8, 'little')
        c1[24:32] = len(case.data).to_bytes(8, 'little')
    for k, b in enumerate(c1):
        m.store(IN_BASE + k, b, 1)
    for k, b in enumerate(c2_bytes(case.c2)):
        m.store(IN_BASE + 0x20 + k, b, 1)
    for k in range(len(case.data) + 48):
        m.store(DATA_BASE + k, case.data[k] if k < len(case.data) else 0x00, 1)


def run_case(image, entry, form, stubs, rec, case):
    """Run one body.  Returns (outcome, events, steps)."""
    rec.events = []
    m = Machine(image, stubs)
    for k in range(0x400):
        m.store(STACK_TOP - 8 - k, 0xa5, 1)
    for k in range(64):
        m.store(OUT_BASE + k, 0xa5, 1)
    load_case(m, case)
    m.regs[7], m.regs[6] = OUT_BASE, IN_BASE
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('body 0x%x does not return its output pointer' % entry)
    head = m.load(OUT_BASE, 1)
    if head <= 2:
        got = m.load(OUT_BASE + 8, 8), bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(32))
        if got[1] != c2_bytes(case.c2):
            raise Reject('Ok result does not carry the value Content unchanged')
        return ('ok', head), list(rec.events), len(m.trace)
    if head != 3:
        raise Reject('unexpected result byte %d' % head)
    if form == 'tagged':
        blob = bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(32))
        role = next((r for r in FILL_BASE if blob == fill_for(r)), None)
    else:
        word = m.load(OUT_BASE + 8, 8)
        role = next((r for r, s in SENTINEL.items() if s == word), None)
    if role is None:
        raise Reject('error payload is not one of the recorded error records')
    return ('err', role), list(rec.events), len(m.trace)


def normalise(events, it_pool):
    return fix_it_pool(events, it_pool)


def gather_it_pool(rows, roles):
    """The invalid-type pool: the last rip-relative lea before the invalid-type call."""
    key = roles['invalid_type']
    for i, r in enumerate(rows):
        if r.op in ('call', 'callslot') and call_key(r) == key:
            for q in reversed(rows[max(0, i - 8):i]):
                if q.op == 'lea' and q.rm[5]:
                    return q.rm[4]
    raise Reject('no pool before the invalid-type call')


# ---------------------------------------------------------------- static derivation

def jump_table(image, rows):
    """(table va, [(tag, target va)] for tags 1..15, default target) from the body bytes."""
    idx = next(i for i, r in enumerate(rows) if r.op == 'jmpind')
    lea = next(q for q in reversed(rows[max(0, idx - 5):idx]) if q.op == 'lea' and q.rm[5])
    table = lea.rm[4]
    bound = next(q for q in rows[:idx] if q.op == 'cmp' and q.ext == 'imm' and q.imm == 0xe)
    ja = next(q for q in rows[rows.index(bound):idx] if q.op == 'ja')
    entries = []
    for k in range(15):
        off = sx(struct.unpack('<I', image.read(table + 4 * k, 4))[0], 32)
        entries.append((k + 1, table + off))
    return table, entries, ja.target


def check_arms(entries, default):
    """Every tag the model calls an arm has its own target; all others share the default."""
    seen = {}
    for tag, target in entries:
        arm = ARMS.get(tag)
        if arm is None:
            if target != default:
                raise Reject('tag %d is not an invalid-type tag' % tag)
        else:
            if target in seen.values() or target == default:
                raise Reject('arm %s shares a target' % arm)
            seen[arm] = target
    return seen


def name_literals(image, rows):
    """Rip-relative `xor` operands: the name words the byte compares use."""
    out = []
    for r in rows:
        if r.op == 'xor' and r.rm and r.rm[0] == 'mem' and r.rm[5]:
            n = r.size
            out.append((r.va, n, r.rm[4], image.read(r.rm[4], n)))
    return out


def esc(b):
    return b.hex() if b else '-'


def event_text(events):
    parts = []
    for e in events:
        if e[0] in ('uv', 'lossy'):
            parts.append('%s(%s)' % (e[0], esc(e[1])))
        else:
            parts.append('%s(%s)' % (e[0], ','.join(str(x) for x in e[1:])))
    return ';'.join(parts) or '-'


# ---------------------------------------------------------------- damage controls

def damage_sites(rows, executed):
    """Executed `cmp reg,imm` instructions: flipping bit 3 of the immediate byte."""
    sites = []
    for r in rows:
        if r.va in executed and r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg' and r.imm in (1, 2, 6, 7, 0xe, 0x16):
            sites.append((r.va + r.length - 1, 'cmp_imm_%x' % r.imm, r.raw[-1], r.raw[-1] ^ 0x08))
    return sites


def run_damage(data, entry, family, form, patches, cases):
    """First case label on which the damaged body disagrees with the reconstruction (or is rejected)."""
    image = Image(data)
    image.patches = dict(patches)
    stubs, rec, roles, rows, _ = bind_stubs(image, entry, family, form)
    it_pool = gather_it_pool(rows, roles)
    for case in cases:
        try:
            got, ev, _ = run_case(image, entry, form, stubs, rec, case)
        except Reject:
            return case.label()
        want, wev = recon(case, family)
        if (got, ev) != (want, fix_it_pool(wev, it_pool)):
            return case.label()
    return None


def table_patches(table, entries, tag_from, tag_to):
    """Patch the table entry of `tag_from` so that it points where `tag_to` points."""
    target = dict(entries)[tag_to]
    new = struct.pack('<i', target - table)
    pos = table + 4 * (tag_from - 1)
    return {pos + k: new[k] for k in range(4)}, pos


def executed_pcs(image, entry, form, stubs, rec, cases):
    seen = set()
    for case in cases:
        rec.events = []
        m = Machine(image, stubs)
        for k in range(0x400):
            m.store(STACK_TOP - 8 - k, 0xa5, 1)
        for k in range(64):
            m.store(OUT_BASE + k, 0xa5, 1)
        load_case(m, case)
        m.regs[7], m.regs[6] = OUT_BASE, IN_BASE
        m.run(entry)
        seen.update(m.trace)
    return seen


def check_sha(data):
    if hashlib.sha256(bytes(data)).hexdigest() != SHA115:
        raise Reject('input is not node #115')


# ---------------------------------------------------------------- build

def build(data, sample_rows=2800, damage_sample=9):
    check_sha(data)
    image = Image(data)
    by_start = fde_index(image)
    functions, insn_rows, table_rows, callee_rows, lit_rows = [], [], [], [], []
    case_rows, path_counts, damage_rows = [], {}, []
    flaw_counts = {f: 0 for f in Flaws.ALL}
    total = ok = 0
    all_cases = case_list()
    control_cases = all_cases
    stride = max(1, len(all_cases) * len(BODIES) // sample_rows)
    for entry, family, form in BODIES:
        if entry not in by_start:
            raise Reject('0x%x is not an FDE start' % entry)
        stubs, rec, roles, rows, vrows = bind_stubs(image, entry, family, form)
        end = by_start[entry]['end']
        functions.append(('0x%x' % entry, family, form, '0x%x' % end, end - entry, len(rows),
                          'none' if by_start[entry]['lsda'] is None else '0x%x' % by_start[entry]['lsda'],
                          hashlib.sha256(image.read(entry, end - entry)).hexdigest()))
        for r in rows:
            insn_rows.append(('0x%x' % entry, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))
        it_pool = gather_it_pool(rows, roles)
        for role in ROLE_ORDER:
            key = roles[role]
            callee_rows.append(('0x%x' % entry, role, 'slot:0x%x' % key[1] if isinstance(key, tuple) else '0x%x' % key))
        callee_rows.append(('0x%x' % entry, 'name_visitor', '0x%x' % VISITORS[(family, form)]))
        callee_rows.append(('0x%x' % entry, 'variant_pool_unknown', '0x%x' % VARIANT_POOLS[family]))
        callee_rows.append(('0x%x' % entry, 'type_pool_invalid_type', '0x%x' % it_pool))
        table, entries, default = jump_table(image, rows)
        check_arms(entries, default)
        for tag, target in entries:
            table_rows.append(('0x%x' % entry, '0x%x' % table, tag, '0x%x' % target, ARMS.get(tag, 'invalid_type')))
        for va, size, target, raw in name_literals(image, rows):
            lit_rows.append(('0x%x' % entry, '0x%x' % va, size, '0x%x' % target, raw.hex(), raw.decode('latin-1')))
        for i, case in enumerate(all_cases):
            got, ev, steps = run_case(image, entry, form, stubs, rec, case)
            want, wev = recon(case, family)
            same = (got, ev) == (want, fix_it_pool(wev, it_pool))
            total += 1
            ok += same
            key = ('0x%x' % entry, case.arm, got[0] if got[0] == 'ok' else got[1])
            lo, hi, n = path_counts.get(key, (steps, steps, 0))
            path_counts[key] = (min(lo, steps), max(hi, steps), n + 1)
            if i % stride == 0 or not same:
                case_rows.append(('0x%x' % entry, case.label(), '%s:%s' % got, event_text(ev), steps,
                                  'match' if same else 'MISMATCH'))
            for flaw in Flaws.ALL:
                fw, fev = recon(case, family, frozenset([flaw]))
                if (got, ev) != (fw, fix_it_pool(fev, it_pool)):
                    flaw_counts[flaw] += 1
        executed = executed_pcs(image, entry, form, stubs, rec, control_cases)
        for pos, kind, before, after in damage_sites(rows, executed):
            found = run_damage(data, entry, family, form, {pos: after}, control_cases)
            damage_rows.append(('0x%x' % entry, kind, '0x%x' % pos, '%02x>%02x' % (before, after),
                                'detected' if found else 'UNDETECTED', found or '-'))
        for tag_from, tag_to in ((4, 1), (13, 12), (15, 14)):
            patch, pos = table_patches(table, entries, tag_from, tag_to)
            found = run_damage(data, entry, family, form, patch, control_cases)
            damage_rows.append(('0x%x' % entry, 'table_tag%d_as_tag%d' % (tag_from, tag_to), '0x%x' % pos, '4 bytes',
                                'detected' if found else 'UNDETECTED', found or '-'))
    range_rows = []
    try:
        check_sha(bytes(data[:-1]))
        range_rows.append(('truncated_binary', 'UNDETECTED'))
    except Reject:
        range_rows.append(('truncated_binary', 'detected'))
    try:
        bind_stubs(image, 0x1fa4631, 1, 'tagged')
        range_rows.append(('entry_not_fde_start', 'UNDETECTED'))
    except (Reject, KeyError):
        range_rows.append(('entry_not_fde_start', 'detected'))
    try:
        stubs, rec, roles, rows, _ = bind_stubs(image, 0x1fa4630, 1, 'tagged')
        del stubs[roles['drop']]
        run_case(image, 0x1fa4630, 'tagged', stubs, rec, Case('str', 13, data=b'normal'))
        range_rows.append(('missing_drop_stub', 'UNDETECTED'))
    except Reject:
        range_rows.append(('missing_drop_stub', 'detected'))
    paths = [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in sorted(path_counts.items())]
    negatives = ([('model_flaw', f, n, total) for f, n in sorted(flaw_counts.items())]
                 + [('damaged_code', '%s %s@%s' % (r[0], r[1], r[2]), 1 if r[4] == 'detected' else 0, 1) for r in damage_rows]
                 + [('out_of_range', r[0], 1 if r[1] == 'detected' else 0, 1) for r in range_rows])
    detected = sum(1 for _, _, n, _ in negatives if n > 0)
    summary = dict(target='node115', sha256=SHA115, component='risk', task='RE-007', bodies=len(BODIES),
                   cases=total, matches=ok, reconstruction_matches_all=(ok == total),
                   negative_controls=len(negatives), negative_detected=detected,
                   model_flaws=len(Flaws.ALL), damaged_code_sites=len(damage_rows), range_controls=len(range_rows))
    return dict(functions=functions, instructions=insn_rows, tables=table_rows, callees=callee_rows, literals=lit_rows,
                cases=case_rows, paths=paths, negatives=negatives, damage=damage_rows, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    s = result['summary']
    return {
        'functions.tsv': tsv(('entry', 'family', 'form', 'fde_end', 'fde_bytes', 'decoded_instructions', 'lsda', 'sha256'),
                             result['functions']),
        'instructions.tsv': tsv(('function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'jump-tables.tsv': tsv(('function', 'table', 'tag', 'target', 'arm'), result['tables']),
        'callees.tsv': tsv(('function', 'role', 'value'), result['callees']),
        'name-words.tsv': tsv(('function', 'va', 'size', 'rip_target', 'word_hex', 'word_text'), result['literals']),
        'cases.tsv': tsv(('function', 'case', 'result', 'events', 'steps', 'verdict'), result['cases']),
        'paths.tsv': tsv(('function', 'arm', 'outcome', 'min_steps', 'max_steps', 'cases'), result['paths']),
        'damage-controls.tsv': tsv(('function', 'kind', 'byte_va', 'change', 'verdict', 'first_case'), result['damage']),
        'negative-controls.tsv': tsv(('family', 'control', 'detections', 'cases'), result['negatives']),
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
    if not s['reconstruction_matches_all'] or s['negative_detected'] != s['negative_controls']:
        print('reconstruction or negative controls failed', file=sys.stderr)
        print(json.dumps(s, indent=1, sort_keys=True), file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    print('cases %d/%d, negative controls %d/%d' % (s['matches'], s['cases'], s['negative_detected'], s['negative_controls']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
