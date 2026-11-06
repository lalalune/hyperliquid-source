#!/usr/bin/env python3
"""Reconstruct the node #115 IndexedArtifactContentSerde deserialize path and prove it.

The storage enum `IndexedArtifactContentSerde` (type-name literal passed to the
serde_json map-enum path; variant pool next to `db/src/owned_db_home.rs`) has
the wire names NodeMetadata, VisorMetadata, HotfixMetadata, NodeArtifact and
PublisherBinaryMetadata (variant indexes 0..4).  The producer authenticates the
#115 capture, locates eight bodies in two copy families by their unwind (FDE)
extents and runs each body's original machine code in a small interpreter for
the fixed x86-64 instruction subset they use.  Calls between the eight bodies
are executed for real (nested), so the whole chain runs on original bytes:

* `deserialize_enum` entry on a serde_json `Value` (word-0 niche dispatch:
  String -> unit-variant access, Object -> map enum access, other ->
  invalid_type error and the value is dropped);
* `visit_enum`: variant seed, a 5-entry jump table on the variant index, the
  unit-variant rejection, one struct-variant callee per arm and the result
  layout of every arm (output tags 2, 3, 5, 6, a 0xb0-byte move for the
  niche-carrying HotfixMetadata arm, 7 = error);
* the variant seed (string visitor, owned-buffer free, value drop on error);
* the exact-name `&str` visitor (length jump table 12..23, qword/dword and
  SSE2 compares, unknown_variant with the 5-name pool).

Every interpreted result is compared with an independent pure-Python
reconstruction.  Name literals, the variant pools, the per-arm field-name
pools and the jump tables are decoded from the file bytes.  Deliberately
wrong reconstructions run through the same comparison and must be caught.

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

NAMES = (b'NodeMetadata', b'VisorMetadata', b'HotfixMetadata', b'NodeArtifact', b'PublisherBinaryMetadata')
TYPE_NAME = b'IndexedArtifactContentSerde'
IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VALUE_BASE = 0x3000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c
OUT_FILL = 0x5a
OUT_SIZE = 0xb8
NONE_VALUE = 0x8000000000000005  # Option<Value>::None niche in the access
SEED_ERR = 0x8000000000000006    # Err niche of the seed result
ERR_UNKNOWN = 0xe770_0000_0000_0001
ERR_INVALID = 0xe770_0000_0000_0002
ERR_STRUCT = 0xe770_0000_0000_0003
ERR_MAP = 0xe770_0000_0000_0004
UNEXPECTED_FILL = 0x71


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
    elif not two and op in (0xc0, 0xc1):
        reg, rm, sub = modrm()
        if sub != 4:
            raise Reject('unsupported c0/c1 form at 0x%x' % va)
        kw.update(op='shl', rm=rm, imm=imm(1), ext='imm')
        if op == 0xc0:
            kw['size'] = 1
    elif two and op == 0x0f92:
        reg, rm, _ = modrm()
        kw.update(op='setb', rm=rm, size=1)
    elif not two and op == 0x6b:
        reg, rm, _ = modrm()
        kw.update(op='imul', reg=reg, rm=rm, imm=sx(imm(1), 8))
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
        # movups / movaps: alignment is not modelled (the captures only move 16 bytes)
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op in (0x0f10, 0x0f28) else 'movups_store', reg=reg, rm=rm, size=16)
    elif two and op == 0x0f48:
        reg, rm, _ = modrm()
        kw.update(op='cmovs', reg=reg, rm=rm)
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

    def __init__(self, image, stubs, inline=()):
        self.image = image
        self.stubs = stubs
        self.inline = frozenset(inline)  # direct-call targets executed for real
        self.entered = []
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
            elif STACK_TOP - 0x4000 <= a < STACK_TOP:
                out.append(STACK_FILL)  # uninitialised stack padding is copied, never interpreted
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
            elif op == 'setb':
                self.put(ins.rm, 1 if self.cf else 0, 1)
            elif op == 'imul':
                full = sx(self.get(ins.rm, size), 8 * size) * ins.imm
                r = full & m
                ovf = full != sx(r, 8 * size)
                self.setflags(r, size, ovf, ovf)
                self.put(('reg', ins.reg), r, size)
            elif op == 'cmovs':
                if self.sf:
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                elif size == 4:
                    self.regs[ins.reg] &= 0xffffffff
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
            elif op == 'call' and ins.target in self.inline:
                self.entered.append(ins.target)
                self.regs[4] -= 8
                self.store(self.regs[4], nxt, 8)
                nxt = ins.target
            elif op in ('call', 'callslot'):
                key = ins.target if op == 'call' else ('slot', ins.rm[4])
                if key not in self.stubs:
                    raise Reject('call to unmodelled target %s at 0x%x' % (key, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8, 9))
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
                nxt = target
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


# ---------------------------------------------------------------- layout
STACK_FILL = 0xa5

# Two copy families.  Arms are listed in variant-index order (NodeMetadata,
# VisorMetadata, HotfixMetadata, NodeArtifact, PublisherBinaryMetadata).
FAMILIES = {
    1: dict(entry=0x1506410, enum=0x15001f0, seed=0x1590700, ident=0x1500470,
            map=0x157ce90, entry_drop=0x150c770, seed_drop=0x158ab60, unknown=0x159abc0,
            arms=(0x14ff780, 0x14ff380, 0x14ff480, 0x14ff580, 0x14ff680),
            iter_drop=0x153e480, panic_locs=(0x63fe008, 0x63fe0b0),
            pool=0x63fbf90, type_name=0x465a39, field_pools=None),
    2: dict(entry=0x57d3a40, enum=0x57c3d80, seed=0x4ee4e90, ident=0x57c41a0,
            map=0x4e2a0f0, entry_drop=0x57e1bb0, seed_drop=0x4e50b60, unknown=0x4effa40,
            arms=(0x4d51ac0, 0x4d51cc0, 0x4d519c0, 0x4d518c0, 0x4d51bc0),
            iter_drop=0x59d3d30, panic_locs=(0x649e8b8, 0x649ea60),
            pool=0x64b0a28, type_name=0x93628c,
            field_pools=((0x64b8278, 2), (0x64b8298, 1), (0x64b82a8, 3), (0x64aa878, 3), (0x64b82d8, 2))),
}
ROLES = ('entry', 'map', 'enum', 'seed', 'ident')
SLOT_INVALID_VALUE = ('slot', 0x64e0910)
SLOT_PANIC = ('slot', 0x64df520)
UNEXPECTED_MAP = 0x0b  # serde::de::Unexpected::Map discriminant byte
BUCKET = 0x68          # IndexMap bucket: key String, Value (0x48), hash
BUCKETS_BASE = 0x3800_0000
CTRL_BASE = 0x3f00_0000
KEY_STRIDE = 0x1000
ERR_INVALID_VALUE = 0xe770_0000_0000_0005


class Panic(Exception):
    pass
SLOT_DEALLOC = ('slot', 0x64df4a0)
SLOT_MEMCPY = ('slot', 0x64df508)
SLOT_INVALID = ('slot', 0x64e0900)
SLOT_UNEXPECTED = ('slot', 0x64e0908)
UNIT_VARIANT = 0x0d  # serde::de::Unexpected::UnitVariant discriminant byte
# Arm result shapes: 'flag' callees return a bool error byte at +0, 'word'
# callees return a word where 2 is the error niche.  (shape, output tag or
# None for the full 0xb0-byte move, destination offset, source offset, length)
ARM_SHAPE = (
    ('flag', 2, 8, 8, 0x28),     # NodeMetadata
    ('flag', 3, 8, 1, 0x20),     # VisorMetadata
    ('word', None, 0, 0, 0xb0),  # HotfixMetadata (niche-carrying payload)
    ('word', 5, 8, 0, 0x38),     # NodeArtifact
    ('flag', 6, 8, 1, 0x21),     # PublisherBinaryMetadata
)
ERR_TAG = 7


def pattern(seed, n):
    return bytes(((seed * 37 + k * 11 + 3) & 0xff) for k in range(n))


def arm_result(idx, outcome):
    """Bytes a stubbed struct-variant callee writes for one outcome."""
    shape = ARM_SHAPE[idx][0]
    body = bytearray(pattern(idx + 1, 0xb0))
    if shape == 'flag':
        body[0] = 1 if outcome == 'err' else 0
    else:
        body[0:8] = struct.pack('<Q', 2 if outcome == 'err' else int(outcome[-1]))
    if outcome == 'err':
        body[8:16] = struct.pack('<Q', ERR_STRUCT)
    return bytes(body)


BORROWED_NONE = 1 << 63  # Option<(String, Value)>::None niche in the key capacity


# ---------------------------------------------------------------- stubs

class Log:
    def __init__(self, machine):
        self.m = machine
        self.rows = []

    def text(self, ptr, n):
        return bytes(self.m.load(ptr + k, 1) for k in range(n))


def make_stubs(fam, log, case):
    f = FAMILIES[fam]

    def unknown(m, a):
        log.rows.append(('unknown_variant', log.text(a[0], a[1]).hex(), '0x%x' % a[2], a[3]))
        return ERR_UNKNOWN

    def dealloc(m, a):
        log.rows.append(('dealloc', '0x%x' % a[0], a[1], a[2]))
        return 0

    def seed_drop(m, a):
        log.rows.append(('drop_value', '0x%x' % m.load(a[0], 8)))
        return 0

    def entry_drop(m, a):
        log.rows.append(('drop_input', '0x%x' % m.load(a[0], 8)))
        return 0

    def unexpected(m, a):
        log.rows.append(('unexpected', '0x%x' % m.load(a[1], 8)))
        for k in range(24):
            m.store(a[0] + k, UNEXPECTED_FILL, 1)
        return a[0]

    def invalid(m, a):
        log.rows.append(('invalid_type', '0x%02x' % m.load(a[0], 1)))
        return ERR_INVALID

    def memcpy(m, a):
        for k in range(a[2]):
            m.store(a[0] + k, m.load(a[1] + k, 1), 1)
        log.rows.append(('memcpy', a[2]))
        return a[0]

    def invalid_value(m, a):
        log.rows.append(('invalid_value', '0x%02x' % m.load(a[0], 1)))
        return ERR_INVALID_VALUE

    def iter_drop(m, a):
        cur, end = m.load(a[0] + 8, 8), m.load(a[0] + 24, 8)
        log.rows.append(('drop_iter', (end - cur) // BUCKET))
        return 0

    def panic(m, a):
        log.rows.append(('panic', 'mask_all_ones' if a[0] == f['panic_locs'][0] else
                         'mask_too_large' if a[0] == f['panic_locs'][1] else '0x%x' % a[0]))
        raise Panic()

    def arm(idx):
        def stub(m, a):
            row = ['arm', idx, '0x%x' % m.load(a[1], 8)]
            if f['field_pools'] is not None:
                row += [log.text(a[2], a[3]).decode(), '0x%x' % a[4], a[5]]
            log.rows.append(tuple(row))
            for k, b in enumerate(arm_result(idx, case.get('outcome', 'ok0'))):
                m.store(a[0] + k, b, 1)
            return a[0]
        return stub

    stubs = {f['unknown']: unknown, SLOT_DEALLOC: dealloc, f['seed_drop']: seed_drop,
             f['entry_drop']: entry_drop, SLOT_UNEXPECTED: unexpected, SLOT_INVALID: invalid,
             SLOT_MEMCPY: memcpy, SLOT_INVALID_VALUE: invalid_value, f['iter_drop']: iter_drop,
             SLOT_PANIC: panic}
    for idx, va in enumerate(f['arms']):
        stubs[va] = arm(idx)
    return stubs


# ---------------------------------------------------------------- reconstruction

def r_ident(text, fam, names=NAMES):
    """visit_str: exact byte match; Ok(index) or Err(unknown_variant(text, pool, 5))."""
    if text in names:
        return ('ok', names.index(text)), []
    return ('err', '0x%x' % ERR_UNKNOWN), [('unknown_variant', text.hex(), '0x%x' % FAMILIES[fam]['pool'], 5)]


def r_seed(text, cap, value_word, fam, ident=r_ident):
    """variant_seed: identify, free an owned name buffer, drop the value on error."""
    res, calls = ident(text, fam)
    if cap:
        calls = calls + [('dealloc', '0x%x' % IN_BASE, cap, 0)]
    if res[0] == 'err':
        if value_word != NONE_VALUE:
            calls = calls + [('drop_value', '0x%x' % value_word)]
        return ('err', res[1], '0x%x' % SEED_ERR), calls
    return ('ok', res[1], 'value'), calls


def r_enum(text, cap, value_word, outcome, fam, seed=r_seed, shapes=ARM_SHAPE):
    """visit_enum: seed, unit-variant rejection, struct arm, arm result layout."""
    res, calls = seed(text, cap, value_word, fam)
    out = bytearray([OUT_FILL]) * OUT_SIZE
    if res[0] == 'err':
        out[0:16] = struct.pack('<QQ', ERR_TAG, ERR_UNKNOWN)
        return bytes(out), calls
    idx = res[1]
    if value_word == NONE_VALUE:
        out[0:16] = struct.pack('<QQ', ERR_TAG, ERR_INVALID)
        return bytes(out), calls + [('invalid_type', '0x%02x' % UNIT_VARIANT)]
    row = ['arm', idx, '0x%x' % value_word]
    pools = FAMILIES[fam]['field_pools']
    if pools is not None:
        row += [NAMES[idx].decode(), '0x%x' % pools[idx][0], pools[idx][1]]
    calls = calls + [tuple(row)]
    body = arm_result(idx, outcome)
    shape, tag, dst, src, n = shapes[idx]
    if outcome == 'err':
        out[0:16] = struct.pack('<QQ', ERR_TAG, ERR_STRUCT)
    elif tag is None:
        out[0:n] = body[src:src + n]
        calls = calls + [('memcpy', n)]
    else:
        out[0:8] = struct.pack('<Q', tag)
        out[dst:dst + n] = body[src:src + n]
    return bytes(out), calls


def value_kind(word):
    """serde_json Value discriminant from word 0 (Object is the dataful niche)."""
    return word ^ (1 << 63) if word >> 63 else 5


def r_table_free(mask):
    """IndexMap index table (hashbrown RawTable<usize>) release before iteration."""
    if mask == 0:
        return []
    if mask == MASK:
        return [('panic', 'mask_all_ones')]
    if mask > 0xffffffffffffffee:
        return [('panic', 'mask_too_large')]
    ctrl_offset = u64(mask * 8 + 0x17) & ~0xf & MASK
    total = u64(mask + ctrl_offset + 0x11)
    if total == 0:
        return []
    return [('dealloc', '0x%x' % u64(CTRL_BASE - ctrl_offset), total, 4 if total < 0x10 else 0)]


def r_object(entries, mask, outcome, fam, enum=r_enum):
    """Value::Object: exactly one (key, value) entry selects the variant, else invalid_value(Map)."""
    out = bytearray([OUT_FILL]) * OUT_SIZE
    calls = r_table_free(mask)
    if calls and calls[-1][0] == 'panic':
        return bytes(out), calls
    live = [e for e in entries]
    if not live or live[0][1] == BORROWED_NONE:
        out[0:16] = struct.pack('<QQ', ERR_TAG, ERR_INVALID_VALUE)
        return bytes(out), calls + [('invalid_value', '0x%02x' % UNEXPECTED_MAP), ('drop_iter', max(len(live) - 1, 0))]
    text, cap, value = live[0]
    if len(live) == 1 or live[1][1] == BORROWED_NONE:
        got, inner = enum(text, cap, value, outcome, fam)
        return got, calls + inner + [('drop_iter', max(len(live) - 2, 0) if len(live) > 1 else 0)]
    text2, cap2, value2 = live[1]
    if cap2:
        calls = calls + [('dealloc', '0x%x' % (IN_BASE + KEY_STRIDE), cap2, 0)]
    calls = calls + [('drop_value', '0x%x' % value2), ('invalid_value', '0x%02x' % UNEXPECTED_MAP),
                     ('drop_value', '0x%x' % value)]
    if cap:
        calls = calls + [('dealloc', '0x%x' % IN_BASE, cap, 0)]
    out[0:16] = struct.pack('<QQ', ERR_TAG, ERR_INVALID_VALUE)
    return bytes(out), calls + [('drop_iter', len(live) - 2)]


def r_entry(word, text, fam, enum=r_enum):
    """deserialize_enum on a Value: String -> unit access, Object -> map access."""
    kind = value_kind(word)
    if kind == 3:
        return enum(text, len(text) + 5, NONE_VALUE, 'ok0', fam)
    if kind == 5:
        entries, mask, outcome = text
        return r_object(entries, mask, outcome, fam, enum=enum)
    out = bytearray([OUT_FILL]) * OUT_SIZE
    out[0:16] = struct.pack('<QQ', ERR_TAG, ERR_INVALID)
    return bytes(out), [('unexpected', '0x%x' % word), ('invalid_type', '0x%02x' % UNEXPECTED_FILL),
                        ('drop_input', '0x%x' % word)]


# ---------------------------------------------------------------- interpretation

def new_machine(image, fam, case, inline):
    m = Machine(image, None, inline)
    log = Log(m)
    m.stubs = make_stubs(fam, log, case)
    for k in range(OUT_SIZE):
        m.store(OUT_BASE + k, OUT_FILL, 1)
    return m, log


def put_text(m, text):
    for k, b in enumerate(text):
        m.store(IN_BASE + k, b, 1)


def put_access(m, base, text, cap, value_word):
    put_text(m, text)
    m.store(base, cap, 8)
    m.store(base + 8, IN_BASE, 8)
    m.store(base + 16, len(text), 8)
    m.store(base + 0x18, value_word, 8)
    for k, b in enumerate(pattern(7, 0x40)):
        m.store(base + 0x20 + k, b, 1)


def run_ident(image, fam, text):
    f = FAMILIES[fam]
    m, log = new_machine(image, fam, {}, ())
    put_text(m, text)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, len(text)
    m.run(f['ident'])
    tag = m.load(OUT_BASE, 1)
    if tag == 0:
        res = ('ok', m.load(OUT_BASE + 1, 1))
    elif tag == 1:
        res = ('err', '0x%x' % m.load(OUT_BASE + 8, 8))
    else:
        raise Reject('visit_str wrote result byte %d' % tag)
    return res, log.rows, m


def run_seed(image, fam, text, cap, value_word):
    f = FAMILIES[fam]
    m, log = new_machine(image, fam, {}, (f['ident'],))
    put_access(m, VALUE_BASE, text, cap, value_word)
    m.regs[7], m.regs[6] = OUT_BASE, VALUE_BASE
    m.run(f['seed'])
    if m.load(OUT_BASE + 8, 8) == SEED_ERR:
        res = ('err', '0x%x' % m.load(OUT_BASE, 8), '0x%x' % SEED_ERR)
    else:
        moved = bytes(m.load(OUT_BASE + 8 + k, 1) for k in range(0x48))
        want = bytes(m.load(VALUE_BASE + 0x18 + k, 1) for k in range(0x48))
        res = ('ok', m.load(OUT_BASE, 1), 'value' if moved == want else 'value-mismatch')
    return res, log.rows, m


def run_enum(image, fam, text, cap, value_word, outcome):
    f = FAMILIES[fam]
    m, log = new_machine(image, fam, {'outcome': outcome}, (f['seed'], f['ident']))
    put_access(m, VALUE_BASE, text, cap, value_word)
    m.regs[7], m.regs[6] = OUT_BASE, VALUE_BASE
    m.run(f['enum'])
    return bytes(m.load(OUT_BASE + k, 1) for k in range(OUT_SIZE)), log.rows, m


def run_entry(image, fam, word, text):
    f = FAMILIES[fam]
    outcome = text[2] if value_kind(word) == 5 else 'ok0'
    m, log = new_machine(image, fam, {'outcome': outcome}, (f['map'], f['enum'], f['seed'], f['ident']))
    m.store(VALUE_BASE, word, 8)
    if value_kind(word) == 5:
        entries, mask, _ = text
        m.store(VALUE_BASE + 8, BUCKETS_BASE, 8)
        m.store(VALUE_BASE + 16, len(entries), 8)
        m.store(VALUE_BASE + 24, CTRL_BASE, 8)
        m.store(VALUE_BASE + 32, mask, 8)
        for k, (key, cap, value) in enumerate(entries):
            b = BUCKETS_BASE + k * BUCKET
            for j, ch in enumerate(key):
                m.store(IN_BASE + k * KEY_STRIDE + j, ch, 1)
            m.store(b, cap, 8)
            m.store(b + 8, IN_BASE + k * KEY_STRIDE, 8)
            m.store(b + 16, len(key), 8)
            m.store(b + 24, value, 8)
            for j, ch in enumerate(pattern(k + 11, 0x48)):
                m.store(b + 32 + j, ch, 1)
    else:
        put_text(m, text)
        m.store(VALUE_BASE + 8, len(text) + 5, 8)
        m.store(VALUE_BASE + 16, IN_BASE, 8)
        m.store(VALUE_BASE + 24, len(text), 8)
    m.regs[7], m.regs[6] = OUT_BASE, VALUE_BASE
    try:
        m.run(f['entry'], limit=1600)
    except Panic:
        pass
    return bytes(m.load(OUT_BASE + k, 1) for k in range(OUT_SIZE)), log.rows, m


def norm(rows):
    return [tuple(r) for r in rows]


# ---------------------------------------------------------------- inputs

MUTATIONS = (0x00, 0x20, 0x41, 0x61, 0x7a, 0x80, 0xff)


def name_inputs():
    seen, out = set(), []

    def add(t):
        if t not in seen:
            seen.add(t)
            out.append(t)
    for n in NAMES:
        add(n)
    for n in NAMES:
        add(n[:-1])
        add(n + b'x')
        add(n + b'\x00')
        add(n.lower())
        add(n.upper())
        add(n[1:])
        for k in range(len(n)):
            for b in (n[k] ^ 0x20, n[k] ^ 0x01, 0x00):
                t = bytearray(n)
                t[k] = b
                add(bytes(t))
    for length in range(0, 31):
        add(b'A' * length)
        add(bytes(MUTATIONS[length % len(MUTATIONS)] for _ in range(length)))
        for n in NAMES:
            add((n * 2)[:length])
    return out


def enum_inputs():
    texts = list(NAMES) + [b'', b'Node', b'NodeMetadatA', b'visorMetadata', b'PublisherBinaryMetadat']
    out = []
    for text in texts:
        for cap in (0, 64):
            for value in (NONE_VALUE, 0x8000000000000001, 0x8000000000000003, 0x10):
                for outcome in ('ok0', 'ok1', 'err'):
                    out.append((text, cap, value, outcome))
    return out


VALUE_WORDS = (1 << 63, (1 << 63) | 1, 0x10)  # Null, Bool, Object(cap 0x10)
MASKS = (0, 1, 3, 7, 0xff, 0x0fffffffffffffff, 0x1ffffffffffffffd, 0x1ffffffffffffffe,
         0xffffffffffffffed, 0xffffffffffffffee, 0xffffffffffffffef, MASK)


def object_inputs():
    out = []
    one = ((NAMES[0], 0, VALUE_WORDS[2]),)
    for mask in MASKS:
        out.append(((), mask, 'ok0'))
        out.append((one, mask, 'ok0'))
    for name in NAMES:
        for cap in (0, len(name) + 3):
            for value in VALUE_WORDS:
                for outcome in ('ok0', 'ok1', 'err'):
                    out.append((((name, cap, value),), 0, outcome))
    for bad in (b'', b'nodeMetadata', b'NodeArtifact\x00'):
        out.append((((bad, 4, VALUE_WORDS[0]),), 1, 'ok0'))
    for k, name in enumerate(NAMES):
        other = NAMES[(k + 1) % len(NAMES)]
        for cap2 in (0, 9):
            out.append((((name, 0, VALUE_WORDS[1]), (other, cap2, VALUE_WORDS[2])), 3, 'ok0'))
            out.append((((name, 7, VALUE_WORDS[1]), (other, cap2, VALUE_WORDS[0]), (name, 0, VALUE_WORDS[0])), 7, 'ok0'))
        out.append((((name, 0, VALUE_WORDS[2]), (other, BORROWED_NONE, VALUE_WORDS[0])), 0, 'ok0'))
        out.append((((name, 0, VALUE_WORDS[2]), (other, BORROWED_NONE, VALUE_WORDS[0]), (name, 0, 0)), 0, 'ok0'))
        out.append((((name, BORROWED_NONE, VALUE_WORDS[2]),), 0, 'ok0'))
        out.append((((name, BORROWED_NONE, VALUE_WORDS[2]), (other, 0, 0)), 0, 'ok0'))
    return out


def entry_inputs():
    words = [(1 << 63) | k for k in range(8)] + [0, 1, 0x40, (1 << 63) - 1]
    texts = list(NAMES) + [b'', b'Nodemetadata', b'NodeArtifacts']
    out = []
    for w in words:
        if value_kind(w) == 3:
            out += [(w, t) for t in texts]
        elif value_kind(w) == 5:
            out += [(w, o) for o in object_inputs()]
        else:
            out.append((w, b''))
    return out


def describe(case):
    if isinstance(case, bytes):
        return esc(case)
    entries, mask, outcome = case
    keys = ','.join('%s:%s:%s' % (esc(t), 'none' if c == BORROWED_NONE else c, '0x%x' % v) for t, c, v in entries)
    return 'map[%s] mask=0x%x arm=%s' % (keys or '-', mask, outcome)


# ---------------------------------------------------------------- evidence

def esc(b):
    return b.hex() if b else '-'


def fde_map(data):
    _, fdes, _ = fde_extents.fde_extents(data)
    return {f['start']: f['end'] for f in fdes}


def decode_pool(image, pool, count):
    va = list(range(pool, pool + 16 * count, 16))
    rel = image.relative_addends(set(va))
    out = []
    for a in va:
        if a not in rel:
            raise Reject('pool slot 0x%x has no RELATIVE relocation' % a)
        n = struct.unpack('<Q', image.read(a + 8, 8))[0]
        out.append((a, rel[a][1], image.read(rel[a][1], n)))
    return out


def jump_table(image, rows):
    """(table va, entries) from the `lea; movsxd [t+i*4]; add; jmp` shape."""
    for k in range(len(rows) - 3):
        a, b, c, d = rows[k:k + 4]
        if a.op == 'lea' and a.rm[5] and b.op == 'movsxd' and c.op == 'add' and d.op == 'jmpind':
            return a.rm[4]
    raise Reject('no jump table shape')


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not the node #115 capture')
    image = Image(data)
    ends = fde_map(data)
    summary = {'target_sha256': SHA115, 'names': [n.decode() for n in NAMES], 'type_name': TYPE_NAME.decode()}
    functions, instructions, pools, tables, callees = [], [], [], [], []
    for fam, f in sorted(FAMILIES.items()):
        for role in ROLES:
            va = f[role]
            if va not in ends:
                raise Reject('0x%x is not an FDE start' % va)
            functions.append((fam, role, '0x%x' % va, ends[va] - va))
        for role in ROLES:
            va = f[role]
            rows = linear(image, va, ends[va])
            for ins in rows:
                instructions.append((fam, role, '0x%x' % ins.va, ins.raw.hex(), ins.op,
                                     '0x%x' % ins.target if ins.target is not None else '-'))
            for ins in rows:
                if ins.op in ('call', 'callslot'):
                    key = ins.target if ins.op == 'call' else ins.rm[4]
                    callees.append((fam, role, '0x%x' % ins.va, ins.op, '0x%x' % key))
            if role in ('enum', 'ident'):
                t = jump_table(image, rows)
                n = 5 if role == 'enum' else 12
                for k in range(n):
                    rel = struct.unpack('<i', image.read(t + 4 * k, 4))[0]
                    tables.append((fam, role, '0x%x' % t, k, '0x%x' % (t + rel)))
        for k, (slot, target, text) in enumerate(decode_pool(image, f['pool'], 5)):
            if text != NAMES[k]:
                raise Reject('pool 0x%x slot %d is %r' % (f['pool'], k, text))
            pools.append((fam, 'variants', '0x%x' % f['pool'], k, '0x%x' % target, text.decode()))
        if image.read(f['type_name'], len(TYPE_NAME)) != TYPE_NAME:
            raise Reject('type name literal moved')
        for idx, pf in enumerate(f['field_pools'] or ()):
            for k, (slot, target, text) in enumerate(decode_pool(image, pf[0], pf[1])):
                pools.append((fam, 'fields:%s' % NAMES[idx].decode(), '0x%x' % pf[0], k, '0x%x' % target, text.decode()))
    texts = name_inputs()
    ident_rows, seed_rows, enum_rows, entry_rows = [], [], [], []
    mismatches = []
    for fam in sorted(FAMILIES):
        for text in texts:
            got, calls, _ = run_ident(image, fam, text)
            want, wcalls = r_ident(text, fam)
            ok = (got, norm(calls)) == (want, wcalls)
            ident_rows.append((fam, esc(text), len(text), got[0], got[1], 'match' if ok else 'MISMATCH'))
            if not ok:
                mismatches.append(('ident', fam, esc(text)))
        for text in texts:
            for cap in (0, len(text) + 8):
                for value in (NONE_VALUE, 0x8000000000000002):
                    got, calls, _ = run_seed(image, fam, text, cap, value)
                    want, wcalls = r_seed(text, cap, value, fam)
                    ok = (got, norm(calls)) == (want, wcalls)
                    seed_rows.append((fam, esc(text), cap, '0x%x' % value, got[0], got[1],
                                      ';'.join(r[0] for r in calls) or '-', 'match' if ok else 'MISMATCH'))
                    if not ok:
                        mismatches.append(('seed', fam, esc(text), cap, value))
        for text, cap, value, outcome in enum_inputs():
            got, calls, _ = run_enum(image, fam, text, cap, value, outcome)
            want, wcalls = r_enum(text, cap, value, outcome, fam)
            ok = (got, norm(calls)) == (want, wcalls)
            enum_rows.append((fam, esc(text), cap, '0x%x' % value, outcome, '0x%x' % struct.unpack_from('<Q', got)[0],
                              hashlib.sha256(got).hexdigest()[:16],
                              ';'.join(str(c) for r in calls for c in r[:2]) or '-', 'match' if ok else 'MISMATCH'))
            if not ok:
                mismatches.append(('enum', fam, esc(text), cap, value, outcome))
        for word, text in entry_inputs():
            got, calls, _ = run_entry(image, fam, word, text)
            want, wcalls = r_entry(word, text, fam)
            ok = (got, norm(calls)) == (want, wcalls)
            entry_rows.append((fam, '0x%x' % word, value_kind(word), describe(text),
                               '0x%x' % struct.unpack_from('<Q', got)[0], hashlib.sha256(got).hexdigest()[:16],
                               ';'.join(r[0] for r in calls) or '-', 'match' if ok else 'MISMATCH'))
            if not ok:
                mismatches.append(('entry', fam, '0x%x' % word, describe(text), norm(calls), wcalls))
    negatives = run_negatives(image)
    summary.update({
        'functions': len(functions), 'instructions': len(instructions),
        'ident_cases': len(ident_rows), 'seed_cases': len(seed_rows),
        'enum_cases': len(enum_rows), 'entry_cases': len(entry_rows),
        'mismatches': len(mismatches),
        'negative_controls': len(negatives), 'negatives_caught': sum(1 for r in negatives if r[-1] == 'caught'),
        'arm_shapes': [dict(zip(('variant', 'shape', 'tag', 'dst', 'src', 'len'), (NAMES[k].decode(),) + s))
                       for k, s in enumerate(ARM_SHAPE)],
    })
    return dict(summary=summary, functions=functions, instructions=instructions, pools=pools, tables=tables,
                callees=callees, ident=ident_rows, seed=seed_rows, enum=enum_rows, entry=entry_rows,
                negatives=negatives, mismatches=mismatches)


# ---------------------------------------------------------------- negative controls

def wrong_ident_casefold(text, fam):
    for k, n in enumerate(NAMES):
        if text.lower() == n.lower():
            return ('ok', k), []
    return r_ident(text, fam)


def wrong_ident_prefix(text, fam):
    for k, n in enumerate(NAMES):
        if len(text) >= 4 and n.startswith(text):
            return ('ok', k), []
    return r_ident(text, fam)


def wrong_ident_order(text, fam):
    return r_ident(text, fam, names=tuple(sorted(NAMES)))


def wrong_seed_no_free(text, cap, value, fam):
    res, calls = r_seed(text, cap, value, fam)
    return res, [c for c in calls if c[0] != 'dealloc']


def wrong_seed_no_drop(text, cap, value, fam):
    res, calls = r_seed(text, cap, value, fam)
    return res, [c for c in calls if c[0] != 'drop_value']


def wrong_enum_unit_ok(text, cap, value, outcome, fam):
    return r_enum(text, cap, 0x8000000000000001 if value == NONE_VALUE else value, outcome, fam)


def wrong_enum_visor_tag(text, cap, value, outcome, fam):
    shapes = list(ARM_SHAPE)
    shapes[1] = ('flag', 4, 8, 1, 0x20)
    return r_enum(text, cap, value, outcome, fam, shapes=tuple(shapes))


def wrong_enum_publisher_len(text, cap, value, outcome, fam):
    shapes = list(ARM_SHAPE)
    shapes[4] = ('flag', 6, 8, 1, 0x20)
    return r_enum(text, cap, value, outcome, fam, shapes=tuple(shapes))


def wrong_enum_hotfix_tagged(text, cap, value, outcome, fam):
    shapes = list(ARM_SHAPE)
    shapes[2] = ('word', 4, 8, 0, 0xa8)
    return r_enum(text, cap, value, outcome, fam, shapes=tuple(shapes))


def wrong_entry_array(word, text, fam):
    if value_kind(word) == 4:
        return r_entry((1 << 63) | 3, text, fam)
    return r_entry(word, text, fam)


def wrong_entry_no_drop(word, text, fam):
    out, calls = r_entry(word, text, fam)
    return out, [c for c in calls if c[0] != 'drop_input']


def wrong_map_first_key_wins(word, text, fam):
    if value_kind(word) == 5 and len(text[0]) > 1 and text[0][1][1] != BORROWED_NONE:
        return r_entry(word, (text[0][:1], text[1], text[2]), fam)
    return r_entry(word, text, fam)


def wrong_map_unrounded_table(word, text, fam):
    if value_kind(word) == 5:
        out, calls = r_entry(word, text, fam)
        mask = text[1]
        if mask and mask < 0xffffffffffffffef and calls and calls[0][0] == 'dealloc':
            total = u64(mask * 9 + 0x11)
            calls = [('dealloc', '0x%x' % u64(CTRL_BASE - (mask * 8 + 8)), total, 4 if total < 0x10 else 0)] + calls[1:]
        return out, calls
    return r_entry(word, text, fam)


def wrong_map_no_overflow_panic(word, text, fam):
    if value_kind(word) == 5 and text[1] == 0xffffffffffffffef:
        return r_entry(word, (text[0], 0xffffffffffffffee, text[2]), fam)
    return r_entry(word, text, fam)


NEGATIVES = (
    ('ident', 'case-insensitive name match', wrong_ident_casefold),
    ('ident', 'prefix name match', wrong_ident_prefix),
    ('ident', 'sorted variant order', wrong_ident_order),
    ('seed', 'owned name buffer not freed', wrong_seed_no_free),
    ('seed', 'value kept on unknown variant', wrong_seed_no_drop),
    ('enum', 'unit variant accepted', wrong_enum_unit_ok),
    ('enum', 'VisorMetadata output tag 4', wrong_enum_visor_tag),
    ('enum', 'PublisherBinaryMetadata payload 0x20 bytes', wrong_enum_publisher_len),
    ('enum', 'HotfixMetadata given its own tag', wrong_enum_hotfix_tagged),
    ('entry', 'Array accepted as a variant name', wrong_entry_array),
    ('entry', 'rejected input not dropped', wrong_entry_no_drop),
    ('entry', 'multi-key map decoded from its first key', wrong_map_first_key_wins),
    ('entry', 'index table size without 16-byte rounding', wrong_map_unrounded_table),
    ('entry', 'bucket mask 0x...ef freed instead of panicking', wrong_map_no_overflow_panic),
)


def run_negatives(image):
    texts = name_inputs()
    out = []
    for level, label, fn in NEGATIVES:
        caught = 0
        for fam in sorted(FAMILIES):
            if level == 'ident':
                for t in texts:
                    got, calls, _ = run_ident(image, fam, t)
                    caught += (got, norm(calls)) != fn(t, fam)
            elif level == 'seed':
                for t in texts[:40]:
                    for cap in (0, len(t) + 8):
                        for value in (NONE_VALUE, 0x8000000000000002):
                            got, calls, _ = run_seed(image, fam, t, cap, value)
                            caught += (got, norm(calls)) != fn(t, cap, value, fam)
            elif level == 'enum':
                for t, cap, value, outcome in enum_inputs():
                    got, calls, _ = run_enum(image, fam, t, cap, value, outcome)
                    caught += (got, norm(calls)) != fn(t, cap, value, outcome, fam)
            else:
                for word, t in entry_inputs():
                    got, calls, _ = run_entry(image, fam, word, t)
                    caught += (got, norm(calls)) != fn(word, t, fam)
        out.append((level, label, caught, 'caught' if caught else 'MISSED'))
    return out


# ---------------------------------------------------------------- output

def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    return {
        'summary.json': json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
        'functions.tsv': tsv(('family', 'role', 'entry', 'fde_bytes'), result['functions']),
        'instructions.tsv': tsv(('family', 'role', 'va', 'bytes', 'op', 'target'), result['instructions']),
        'name-pools.tsv': tsv(('family', 'pool_kind', 'pool', 'index', 'literal', 'text'), result['pools']),
        'jump-tables.tsv': tsv(('family', 'role', 'table', 'index', 'target'), result['tables']),
        'callees.tsv': tsv(('family', 'role', 'site', 'kind', 'target'), result['callees']),
        'ident-cases.tsv': tsv(('family', 'text_hex', 'len', 'status', 'value', 'verdict'), result['ident']),
        'seed-cases.tsv': tsv(('family', 'text_hex', 'cap', 'value_word', 'status', 'value', 'calls', 'verdict'),
                              result['seed']),
        'enum-cases.tsv': tsv(('family', 'text_hex', 'cap', 'value_word', 'arm_outcome', 'out_tag', 'out_sha256_16',
                               'calls', 'verdict'), result['enum']),
        'entry-cases.tsv': tsv(('family', 'value_word', 'value_kind', 'input', 'out_tag', 'out_sha256_16', 'calls',
                                'verdict'), result['entry']),
        'negative-controls.tsv': tsv(('level', 'wrong_reconstruction', 'cases_caught', 'verdict'), result['negatives']),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(TARGET))
    args = ap.parse_args(argv)
    data = Path(args.binary).read_bytes()
    result = build(data)
    if result['mismatches']:
        for m in result['mismatches'][:20]:
            print('MISMATCH', m, file=sys.stderr)
        return 1
    if any(r[-1] != 'caught' for r in result['negatives']):
        print('negative control missed', file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(render(result).items()):
        (out / name).write_text(text, encoding='utf-8', newline='\n')
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
