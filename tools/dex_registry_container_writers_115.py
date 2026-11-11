#!/usr/bin/env python3
"""Reconstruct the node #115 msgpack container writers below the Hip3 records.

The Hip3 `schema` writer hands two containers to outlined writers that earlier
packets left stubbed: the `asset_to_oi_cap` map writer and the `sub_deployers`
sequence writer.  This producer covers the whole write path of both, in the
three copy families of the capture (loops 0x2202220/0x4151980/0x52c5a70 for
maps and 0x2205280/0x4177540/0x52b19d0 for sequences, entered through the
wrappers 0x2d562f0/0x3c6f250/0x4da9790).  It authenticates the #115 capture,
locates every body by its unwind (FDE) extent, and runs the ORIGINAL machine
code of these bodies in a small interpreter for the fixed x86-64 subset they
use:

* the loops, the array-header writer, the map entry writer, the finish routine,
  the two B-tree iterator `next` bodies, the marker normaliser and Vec reserve
  with its grow helper;
* only the leaf callees (key/value/tuple-end/element writers and the allocator
  slots) are stubs that record their arguments.

Every interpreted result (output bytes, result words, call log, allocator log)
is compared with an independent pure-Python reconstruction.  Deliberately wrong
reconstructions and byte-corrupted copies of the capture run through the same
comparison and must all be caught.

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
import elf_index  # noqa: E402,F401
import fde_extents  # noqa: E402
import hip3_subrecord_helpers_115 as eng  # noqa: E402  (shared image reader)

TARGET = eng.TARGET
SHA115 = eng.SHA115
MASK = (1 << 64) - 1
Reject = eng.Reject
Image = eng.Image
sx = eng.sx

# ------------------------------------------------------------------ decoder

CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']
ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']


class Insn:
    __slots__ = ('va', 'length', 'raw', 'mn', 'size', 'a', 'b', 'imm', 'target')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def decode(image, va):
    """Decode one instruction of the supported subset; raise Reject otherwise."""
    if va in image.cache:
        return image.cache[va]
    raw = image.read(va, 16)
    i = 0
    p66 = rep = False
    while raw[i] in (0x66, 0x2e, 0xf3):
        if raw[i] == 0x66:
            p66 = True
        elif raw[i] == 0xf3:
            rep = True
        i += 1
    rex = 0
    if 0x40 <= raw[i] <= 0x4f:
        rex = raw[i]
        i += 1
    w = bool(rex & 8)
    rr, rx, rb = (rex >> 2) & 1, (rex >> 1) & 1, rex & 1
    op = raw[i]
    i += 1
    two = False
    if op == 0x0f:
        op = 0x0f00 | raw[i]
        i += 1
        two = True
    osz = 8 if w else (2 if p66 else 4)

    def modrm():
        nonlocal i
        m = raw[i]
        i += 1
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | (rr << 3), m & 7
        if mod == 3:
            return reg, ('r', rm | (rb << 3)), (m >> 3) & 7
        base = index = None
        scale, disp, rip = 1, 0, False
        if rm == 4:
            sib = raw[i]
            i += 1
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (rx << 3)
            index = None if idx == 4 else idx
            b = sib & 7
            if b == 5 and mod == 0:
                disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
                i += 4
            else:
                base = b | (rb << 3)
        elif rm == 5 and mod == 0:
            rip = True
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        else:
            base = rm | (rb << 3)
        if mod == 1:
            disp = sx(raw[i], 8)
            i += 1
        elif mod == 2:
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        return reg, ('m', base, index, scale, disp, rip), (m >> 3) & 7

    def imm(n):
        nonlocal i
        v = int.from_bytes(raw[i:i + n], 'little')
        i += n
        return v

    def byte_reg_ok(*ops):
        for o in ops:
            if o[0] == 'r' and not rex and 4 <= o[1] <= 7:
                raise Reject('legacy high-byte register at 0x%x' % va)

    kw = dict(va=va, size=osz)
    if not two and op < 0x40 and (op & 7) < 6 and (op & 0xf8) in (0, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        name = ALU[op >> 3]
        low = op & 7
        if low in (0, 1, 2, 3):
            reg, rm, _ = modrm()
            sz = 1 if low in (0, 2) else osz
            if sz == 1:
                byte_reg_ok(('r', reg), rm)
            if low in (0, 1):
                kw.update(mn=name, size=sz, a=rm, b=('r', reg))
            else:
                kw.update(mn=name, size=sz, a=('r', reg), b=rm)
        elif low == 4:
            kw.update(mn=name, size=1, a=('r', 0), b=('i', imm(1)))
        else:
            kw.update(mn=name, size=osz, a=('r', 0), b=('i', sx(imm(4), 32) if w else imm(4)))
    elif not two and op in (0x80, 0x81, 0x83):
        _, rm, sub = modrm()
        if sub == 2 or sub == 1 and False:
            raise Reject('unsupported group-1 form at 0x%x' % va)
        if op == 0x80:
            byte_reg_ok(rm)
            kw.update(mn=ALU[sub], size=1, a=rm, b=('i', imm(1)))
        else:
            v = sx(imm(1), 8) if op == 0x83 else (sx(imm(4), 32) if w else imm(4))
            kw.update(mn=ALU[sub], a=rm, b=('i', v & MASK if w else v & 0xffffffff))
    elif not two and op in (0x84, 0x85):
        reg, rm, _ = modrm()
        if op == 0x84:
            byte_reg_ok(('r', reg), rm)
        kw.update(mn='test', size=1 if op == 0x84 else osz, a=rm, b=('r', reg))
    elif not two and op in (0x88, 0x89, 0x8a, 0x8b):
        reg, rm, _ = modrm()
        sz = 1 if op in (0x88, 0x8a) else osz
        if sz == 1:
            byte_reg_ok(('r', reg), rm)
        if op in (0x88, 0x89):
            kw.update(mn='mov', size=sz, a=rm, b=('r', reg))
        else:
            kw.update(mn='mov', size=sz, a=('r', reg), b=rm)
    elif not two and op == 0x8d:
        reg, rm, _ = modrm()
        if rm[0] != 'm':
            raise Reject('lea of a register at 0x%x' % va)
        kw.update(mn='lea', a=('r', reg), b=rm)
    elif not two and op == 0x63 and w:
        reg, rm, _ = modrm()
        kw.update(mn='movsxd', a=('r', reg), b=rm)
    elif not two and 0xb8 <= op <= 0xbf:
        r = (op - 0xb8) | (rb << 3)
        kw.update(mn='mov', a=('r', r), b=('i', imm(8) if w else imm(4)))
    elif not two and op in (0xc6, 0xc7):
        _, rm, sub = modrm()
        if sub != 0:
            raise Reject('unsupported c6/c7 form at 0x%x' % va)
        if op == 0xc6:
            byte_reg_ok(rm)
            kw.update(mn='mov', size=1, a=rm, b=('i', imm(1)))
        else:
            v = imm(2 if p66 else 4)
            kw.update(mn='mov', a=rm, b=('i', (sx(v, 32) & MASK) if w else v))
    elif not two and op == 0xc1:
        _, rm, sub = modrm()
        if sub not in (0, 4, 5):
            raise Reject('unsupported c1 form at 0x%x' % va)
        kw.update(mn={0: 'rol', 4: 'shl', 5: 'shr'}[sub], a=rm, b=('i', imm(1)))
    elif not two and op == 0xf7:
        _, rm, sub = modrm()
        if sub not in (3, 4):
            raise Reject('unsupported f7 form at 0x%x' % va)
        kw.update(mn={3: 'neg', 4: 'mul'}[sub], a=rm)
    elif not two and op == 0xff:
        _, rm, sub = modrm()
        if sub in (0, 1):
            kw.update(mn=('inc', 'dec')[sub], a=rm)
        elif sub == 2 and rm[0] == 'm':
            kw.update(mn='call_mem', a=rm)
        elif sub == 4 and rm[0] == 'm':
            kw.update(mn='jmp_mem', a=rm)
        else:
            raise Reject('unsupported ff form at 0x%x' % va)
    elif not two and 0x50 <= op <= 0x57:
        kw.update(mn='push', a=('r', (op - 0x50) | (rb << 3)))
    elif not two and 0x58 <= op <= 0x5f:
        kw.update(mn='pop', a=('r', (op - 0x58) | (rb << 3)))
    elif not two and 0x70 <= op <= 0x7f:
        rel = sx(imm(1), 8)
        kw.update(mn='j' + CC[op - 0x70], target=va + i + rel)
    elif two and 0x0f80 <= op <= 0x0f8f:
        rel = sx(imm(4), 32)
        kw.update(mn='j' + CC[op - 0x0f80], target=va + i + rel)
    elif two and 0x0f90 <= op <= 0x0f9f:
        _, rm, _ = modrm()
        byte_reg_ok(rm)
        kw.update(mn='set' + CC[op - 0x0f90], size=1, a=rm)
    elif two and 0x0f40 <= op <= 0x0f4f:
        reg, rm, _ = modrm()
        kw.update(mn='cmov' + CC[op - 0x0f40], a=('r', reg), b=rm)
    elif not two and op in (0xe8, 0xe9):
        kw.update(mn='call' if op == 0xe8 else 'jmp', target=va + 5 + sx(imm(4), 32))
    elif not two and op == 0xeb:
        kw.update(mn='jmp', target=va + 2 + sx(imm(1), 8))
    elif not two and op == 0xc3:
        kw.update(mn='ret')
    elif not two and op == 0x90:
        kw.update(mn='nop')
    elif two and op == 0x0f1f:
        modrm()
        kw.update(mn='nop')
    elif two and op == 0x0f0b:
        kw.update(mn='ud2')
    elif two and op in (0x0fb6, 0x0fb7):
        reg, rm, _ = modrm()
        if op == 0x0fb6:
            byte_reg_ok(rm)
        kw.update(mn='movzx', a=('r', reg), b=rm, imm=1 if op == 0x0fb6 else 2)
    elif two and op in (0x0f10, 0x0f11, 0x0f28, 0x0f29):
        reg, rm, _ = modrm()
        kw.update(mn='movaps' if op in (0x0f28, 0x0f29) else 'movups', size=16,
                  a=('x', reg) if op in (0x0f10, 0x0f28) else rm, b=rm if op in (0x0f10, 0x0f28) else ('x', reg))
    elif two and op == 0x0f57:
        reg, rm, _ = modrm()
        if rm != ('r', reg):
            raise Reject('unsupported xorps form at 0x%x' % va)
        kw.update(mn='xorps', size=16, a=('x', reg))
    elif two and 0x0fc8 <= op <= 0x0fcf:
        kw.update(mn='bswap', a=('r', (op - 0x0fc8) | (rb << 3)))
    elif two and op == 0x0fbc and rep:
        reg, rm, _ = modrm()
        kw.update(mn='tzcnt', a=('r', reg), b=rm)
    else:
        raise Reject('unsupported opcode 0x%x at 0x%x' % (op, va))
    kw['length'] = i
    kw['raw'] = bytes(raw[:i])
    for k in ('a', 'b'):
        o = kw.get(k)
        if o and o[0] == 'm' and o[5]:
            kw[k] = ('m', None, None, 1, va + i + o[4], True)
    ins = Insn(**kw)
    image.cache[va] = ins
    return ins


def linear(image, entry, end):
    rows, pc = [], entry
    while pc < end:
        ins = decode(image, pc)
        rows.append(ins)
        pc += ins.length
    if pc != end:
        raise Reject('decode did not land on the FDE end of 0x%x' % entry)
    return rows


# ------------------------------------------------------------------ machine

STACK_TOP = 0x7f00_0000
SENTINEL = 0xdead_0000
HEAP_BASE = 0x3000_0000
NICHE = 1 << 63
OK_WORD = NICHE + 4
SCRATCH_LO, SCRATCH_HI = 0x1000_0000, 0x8000_0000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c


class Panic(Exception):
    pass


def mask(size):
    return (1 << (8 * size)) - 1


class Machine:
    """Interpreter for the decoded subset with ZF CF SF OF.

    `real` is the set of body entries that run as original code; `stubs`
    maps a call target (or allocator/panic slot) to a Python callable that
    records its arguments.  Anything else is refused."""

    def __init__(self, image, real, stubs, slots, cover):
        self.image, self.real, self.stubs, self.slots, self.cover = image, real, stubs, slots, cover
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.mem = {}
        self.zf = self.cf = self.sf = self.of = False
        self.log = []
        self.steps = 0
        self.heap = HEAP_BASE
        self.sizes = {}
        # stack garbage: padding bytes of spilled words are never written by the code
        for a in range(STACK_TOP - 0x600, STACK_TOP):
            self.mem[a] = 0xa5

    # memory
    def load(self, addr, n):
        if n == 8 and addr in self.image.reloc:
            return self.image.reloc[addr]
        if addr < SCRATCH_LO:
            if any((addr + k) in self.mem for k in range(n)):
                raise Reject('mixed image/scratch read at 0x%x' % addr)
            return int.from_bytes(self.image.read(addr, n), 'little')
        out = bytearray()
        for k in range(n):
            b = self.mem.get(addr + k)
            if b is None:
                raise Reject('read of unset scratch byte 0x%x' % (addr + k))
            out.append(b)
        return int.from_bytes(out, 'little')

    def store(self, addr, value, n):
        if not (SCRATCH_LO <= addr and addr + n <= SCRATCH_HI):
            raise Reject('store outside scratch memory at 0x%x' % addr)
        data = (value & mask(n)).to_bytes(n, 'little')
        for k in range(n):
            self.mem[addr + k] = data[k]

    def poke(self, addr, data):
        for k, b in enumerate(data):
            self.mem[addr + k] = b

    def peek(self, addr, n):
        return bytes(self.mem[addr + k] for k in range(n))

    def w64(self, addr, v):
        self.store(addr, v, 8)

    def r64(self, addr):
        return self.load(addr, 8)

    def ea(self, o):
        _, base, index, scale, disp, rip = o
        if rip:
            return disp
        a = disp
        if base is not None:
            a += self.regs[base]
        if index is not None:
            a += self.regs[index] * scale
        return a & MASK

    def get(self, o, size):
        k = o[0]
        if k == 'i':
            return o[1] & mask(size)
        if k == 'r':
            return self.regs[o[1]] & mask(size)
        if k == 'x':
            return self.xmm[o[1]]
        return self.load(self.ea(o), size)

    def put(self, o, v, size):
        v &= mask(size)
        k = o[0]
        if k == 'x':
            self.xmm[o[1]] = v
        elif k == 'r':
            r = o[1]
            if size >= 4:
                self.regs[r] = v
            else:
                self.regs[r] = (self.regs[r] & (MASK ^ mask(size))) | v
        else:
            self.store(self.ea(o), v, size)

    def flags(self, r, size, cf, of):
        m = mask(size)
        self.zf = (r & m) == 0
        self.sf = bool((r >> (8 * size - 1)) & 1)
        self.cf, self.of = cf, of

    def cond(self, c):
        z, cf, sf, of = self.zf, self.cf, self.sf, self.of
        if None in (z, cf, sf, of) and c in (0, 1, 12, 13, 14, 15):
            if of is None:
                raise Reject('use of undefined overflow flag')
        if z is None or sf is None:
            if c in (4, 5, 6, 7, 8, 9, 12, 13, 14, 15):
                raise Reject('use of undefined zero/sign flag')
        return [of, not of, cf, not cf, z, not z, cf or z, not (cf or z), sf, not sf, False, True,
                sf != of, sf == of, z or sf != of, (not z) and sf == of][c]

    def alu(self, mn, a, b, size):
        m = mask(size)
        sign = 1 << (8 * size - 1)
        a &= m
        b &= m
        if mn == 'add':
            r = a + b
            self.flags(r, size, r > m, bool((a ^ r) & (b ^ r) & sign))
        elif mn in ('sub', 'cmp', 'sbb'):
            c = int(self.cf) if mn == 'sbb' else 0
            r = (a - b - c) & m
            self.flags(r, size, a < b + c, bool((a ^ b) & (a ^ r) & sign))
        else:
            r = {'and': a & b, 'or': a | b, 'xor': a ^ b, 'test': a & b}[mn]
            self.flags(r, size, False, False)
        return r & m

    def push(self, v):
        self.regs[4] -= 8
        self.store(self.regs[4], v, 8)

    def pop(self):
        v = self.load(self.regs[4], 8)
        self.regs[4] += 8
        return v

    def call_stub(self, fn):
        args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8, 9))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.regs[r] = CLOBBER
        fn(self, args)

    def run(self, entry, limit=60000):
        self.regs[4] = STACK_TOP - 8
        self.store(self.regs[4], SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.cover.add(pc)
            self.steps += 1
            nxt = pc + ins.length
            mn, size = ins.mn, ins.size
            if mn in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test', 'sbb'):
                a, b = self.get(ins.a, size), self.get(ins.b, size)
                r = self.alu(mn, a, b, size)
                if mn not in ('cmp', 'test'):
                    self.put(ins.a, r, size)
            elif mn == 'adc':
                raise Reject('adc is not modelled')
            elif mn == 'mov':
                self.put(ins.a, self.get(ins.b, size), size)
            elif mn == 'lea':
                self.put(ins.a, self.ea(ins.b), size)
            elif mn == 'movzx':
                self.put(ins.a, self.get(ins.b, ins.imm), size)
            elif mn == 'movsxd':
                self.put(ins.a, sx(self.get(ins.b, 4), 32), 8)
            elif mn in ('movups', 'movaps'):
                if mn == 'movaps':
                    o = ins.a if ins.a[0] == 'm' else ins.b
                    if o[0] == 'm' and self.ea(o) % 16:
                        raise Reject('misaligned movaps at 0x%x' % pc)
                self.put(ins.a, self.get(ins.b, 16), 16)
            elif mn == 'xorps':
                self.xmm[ins.a[1]] = 0
            elif mn == 'push':
                self.push(self.regs[ins.a[1]])
            elif mn == 'pop':
                self.regs[ins.a[1]] = self.pop()
            elif mn == 'neg':
                a = self.get(ins.a, size)
                r = (-a) & mask(size)
                self.flags(r, size, a != 0, a == 1 << (8 * size - 1))
                self.put(ins.a, r, size)
            elif mn == 'mul':
                r = self.regs[0] * self.get(ins.a, 8)
                self.regs[0], self.regs[2] = r & MASK, r >> 64
                self.cf = self.of = bool(r >> 64)
                self.zf = self.sf = None
            elif mn in ('inc', 'dec'):
                a = self.get(ins.a, size)
                r = (a + (1 if mn == 'inc' else -1)) & mask(size)
                sign = 1 << (8 * size - 1)
                cf = self.cf
                self.flags(r, size, cf, (a == sign - 1) if mn == 'inc' else (a == sign))
                self.put(ins.a, r, size)
            elif mn in ('shl', 'shr', 'rol'):
                bits = 8 * size
                cnt = self.get(ins.b, 1) & (63 if size == 8 else 31)
                a = self.get(ins.a, size)
                if mn == 'rol':
                    cnt %= bits
                    r = ((a << cnt) | (a >> (bits - cnt))) & mask(size) if cnt else a
                    if cnt:
                        self.cf = bool(r & 1)
                        self.of = bool(((r >> (bits - 1)) & 1) ^ (r & 1)) if cnt == 1 else None
                elif cnt:
                    if mn == 'shl':
                        r = (a << cnt) & mask(size)
                        cf = bool((a >> (bits - cnt)) & 1)
                        of = bool(((r >> (bits - 1)) & 1) ^ cf) if cnt == 1 else None
                    else:
                        r = a >> cnt
                        cf = bool((a >> (cnt - 1)) & 1)
                        of = bool((a >> (bits - 1)) & 1) if cnt == 1 else None
                    self.flags(r, size, cf, of)
                else:
                    r = a
                self.put(ins.a, r, size)
            elif mn == 'bswap':
                self.put(ins.a, int.from_bytes(self.get(ins.a, size).to_bytes(size, 'little'), 'big'), size)
            elif mn == 'tzcnt':
                v = self.get(ins.b, size)
                r = (v & -v).bit_length() - 1 if v else 8 * size
                self.flags(r, size, v == 0, None)
                self.put(ins.a, r, size)
            elif mn.startswith('set'):
                self.put(ins.a, int(self.cond(CC.index(mn[3:]))), 1)
            elif mn.startswith('cmov'):
                if size not in (4, 8):
                    raise Reject('16-bit cmov is not modelled')
                if self.cond(CC.index(mn[4:])):
                    self.put(ins.a, self.get(ins.b, size), size)
                elif size == 4:
                    self.put(ins.a, self.get(ins.a, 4), 4)
            elif mn.startswith('j') and mn not in ('jmp', 'jmp_mem') and ins.target is not None:
                if self.cond(CC.index(mn[1:])):
                    nxt = ins.target
            elif mn == 'jmp':
                nxt = ins.target
            elif mn == 'call':
                t = ins.target
                if t in self.stubs:
                    self.call_stub(self.stubs[t])
                elif t in self.real:
                    self.push(nxt)
                    nxt = t
                else:
                    raise Reject('call to unmodelled target 0x%x at 0x%x' % (t, pc))
            elif mn in ('call_mem', 'jmp_mem'):
                slot = self.ea(ins.a)
                if slot not in self.stubs:
                    raise Reject('call through unmodelled slot 0x%x at 0x%x' % (slot, pc))
                self.call_stub(self.stubs[slot])
                if mn == 'jmp_mem':
                    nxt = self.pop()
            elif mn == 'ret':
                nxt = self.pop()
                if nxt == SENTINEL:
                    if self.regs[4] != STACK_TOP:
                        raise Reject('unbalanced stack at return 0x%x' % pc)
                    return
            elif mn == 'ud2':
                raise Reject('reached ud2 at 0x%x' % pc)
            elif mn == 'nop':
                pass
            else:
                raise Reject('no semantics for %s at 0x%x' % (mn, pc))
            pc = nxt
        raise Reject('step limit reached')


# ------------------------------------------------------------------ targets

SLOT = dict(alloc=0x64df480, alloc_err=0x64df498, dealloc=0x64df4a0, memcpy=0x64df508, panic=0x64df520,
            realloc_al=0x64df580, realloc=0x64df588, alloc_al=0x64df590, panic_loc=0x64df830)

# one row per copy family: copy 1, 2, 3
COPIES = (
    dict(copy=1, map=0x2202220, seq=0x2205280, wrap=0x2d562f0, head=0x25e7c10, fin=0x227e1b0, ent=0x22877f0,
         nmap=0x2388170, nseq=0x23896a0, mark=0x25eab50, res=0x231e050, grow=0x231dc90,
         key=0x2296160, val=0x2296fa0, end=0x22999e0, elem=0x22927f0),
    dict(copy=2, map=0x4151980, seq=0x4177540, wrap=0x3c6f250, head=0x3d50540, fin=0x41acd70, ent=0x41bf660,
         nmap=0x37c3750, nseq=0x37cd990, mark=0x3d52310, res=0x43bd910, grow=0x43bd550,
         key=0x41cfc10, val=0x41d06f0, end=0x41d4150, elem=0x41c2c30),
    dict(copy=3, map=0x52c5a70, seq=0x52b19d0, wrap=0x4da9790, head=0x57cee80, fin=0x5306d60, ent=0x5315e20,
         nmap=0x51347f0, nseq=0x5134a00, mark=0x57d0b20, res=0x5963a10, grow=0x5963650,
         key=0x5320130, val=0x53206b0, end=0x5325140, elem=0x5312380),
)
# the second-copy and third-copy map loop of the seq family use their own wrappers' callees
SEQ_NEXT = {1: 0x23896a0, 2: 0x37cd990, 3: 0x5134a00}
REAL_KEYS = ('map', 'seq', 'wrap', 'head', 'fin', 'ent', 'nmap', 'nseq', 'mark', 'res', 'grow')
STUB_KEYS = ('key', 'val', 'end', 'elem')
# The seq loop of copy 2 and 3 call the seq iterator of the same family; the wrapper calls the seq loop of
# its own family.  `wrap` of copy 2 reaches 0x4177540 and of copy 3 reaches 0x52b19d0 (checked from the bytes).
IT, OUT, WR, VB, CT, EL1, EL2, TREE = 0x1000_0000, 0x2000_0000, 0x2100_0000, 0x2200_0000, 0x2300_0000, \
    0x2400_0000, 0x2500_0000, 0x3800_0000
MAP_ELEM, SEQ_ELEM = 16, 32

# B-tree node layouts read from the two iterator bodies: (key_off, key_stride, val_off, val_stride, pidx_off,
# len_off, edge_off, leaf_size, internal_size)
LAYOUT = dict(map=(8, 8, 0x60, 8, 0xb8, 0xba, 0xc0, 0xc0, 0x120), seq=(0x114, 1, 8, 24, 0x110, 0x112, 0x120, 0x120, 0x180))


class PatchedImage(Image):
    """Capture image with byte overrides (used only for byte-corruption controls)."""

    def __init__(self, data, patches):
        super().__init__(data)
        self.patches = dict(patches)

    def read(self, va, n):
        b = bytearray(super().read(va, n))
        for p, v in self.patches.items():
            if va <= p < va + n:
                b[p - va] = v
        return bytes(b)


class Rng:
    def __init__(self, seed):
        self.s = (seed * 0x9E3779B97F4A7C15 + 1) & MASK

    def next(self):
        x = self.s
        x ^= (x << 13) & MASK
        x ^= x >> 7
        x ^= (x << 17) & MASK
        self.s = x
        return x

    def below(self, n):
        return self.next() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


def bsl_reserve(cap, ln, add, bad=None):
    """Vec<u8>::reserve growth: max(2*cap, len+add, 8)."""
    if bad == 'reserve_min4':
        return max(2 * cap, ln + add, 4)
    if bad == 'reserve_nodouble':
        return max(ln + add, 8)
    return max(2 * cap, ln + add, 8)


# ------------------------------------------------------------------ reconstruction (independent model)

class Vec:
    def __init__(self, cap, data):
        self.cap, self.buf = cap, bytearray(data)

    def room(self):
        return self.cap - len(self.buf)


def m_push(vec, data, log, bad=None):
    n = len(data)
    if vec.room() < n:
        grow = bsl_reserve(vec.cap, len(vec.buf), n, bad)
        log.append(('alloc' if vec.cap == 0 else 'realloc', grow))
        vec.cap = grow
    vec.buf += data


def m_header(vec, n, log, bad=None):
    if n < 16:
        kind = 0x90
    elif n < 0x10000:
        kind = 0xdc
    else:
        kind = 0xdd
    if bad == 'hdr_limit':
        kind = 0x90 if n < 15 else (0xdc if n < 0x10000 else 0xdd)
    if bad == 'hdr_marker' and kind == 0xdc:
        kind = 0xdd
    m_push(vec, bytes([0x90 | n if kind == 0x90 else kind]), log, bad)
    if kind == 0xdc:
        m_push(vec, (n & 0xffff).to_bytes(2, 'big' if bad != 'hdr_endian' else 'little'), log, bad)
    elif kind == 0xdd:
        m_push(vec, (n & 0xffffffff).to_bytes(4, 'big'), log, bad)
    return (2, kind, n & 0xff)


def state_tuple(cfg, target):
    return (0 if cfg[2] == 2 else NICHE, 1, 0, target, 2, cfg)


def m_entry(vec, cfg, target, item, plan, counters, log, bad=None):
    """Map entry: array-of-two marker unless the struct flag is 2, then key, value, end.  Returns error or None."""
    if cfg[2] != 2 or bad == 'flag_skip':
        m_push(vec, b'\x92', log, bad)
    st = state_tuple(cfg, target)
    for stage in ('key', 'val', 'end'):
        log.append((stage, st, None if stage == 'end' else item))
        k = counters[stage]
        counters[stage] += 1
        if plan and plan[0] == stage and plan[1] == k:
            return err_words(stage, k)
    return None


def err_words(stage, k):
    sid = ('key', 'val', 'end', 'elem').index(stage)
    return (0x0e10_0000_0000_0000 | (sid << 40) | k, 0x0e20_0000_0000_0000 | sid, 0x0e30_0000_0000_0000 | k)


def m_elem(cfg, target, item, plan, counters, log, bad=None):
    log.append(('elem', target, cfg, item))
    k = counters['elem']
    counters['elem'] += 1
    if plan and plan[0] == 'elem' and plan[1] == k:
        return err_words('elem', k)
    return None


def m_loop(kind, words, vec, cfg, items, plan, alloc_fail, bad=None):
    """Whole-loop reconstruction.  Returns (out words, log, panic)."""
    log = []
    elem = MAP_ELEM if kind == 'map' else SEQ_ELEM
    allocs = [0]

    def vec_alloc_fail_check(before):
        pass

    if words[0] == 2:
        n = ((words[2] - words[1]) & MASK) // elem + ((words[4] - words[3]) & MASK) // elem
    else:
        n = words[8]
    counters = dict(key=0, val=0, end=0, elem=0)
    buffered = (n >> 32) != 0
    if bad == 'buffered_limit':
        buffered = (n >> 32) != 0 or n > 18
    if not buffered:
        m_header(vec, n, log, bad)
        target, tvec = 'W', vec
    else:
        log.append(('alloc', 0x80))
        target, tvec = 'B', Vec(0x80, b'')
        cfg_b = (cfg[0], cfg[1] & 0x101, cfg[2])
    cnt = 0
    tcfg = cfg if not buffered else cfg_b
    seq_items = items if words[0] == 2 else items
    take = list(seq_items[:n]) if n < (1 << 40) else list(seq_items)
    if bad == 'tree_reverse' and words[0] != 2:
        take.reverse()
    exhausted_panic = n > len(seq_items) and words[0] != 2
    out = None
    for idx, item in enumerate(take):
        if kind == 'map':
            err = m_entry(tvec, tcfg, target, item, plan, counters, log, bad)
        else:
            err = m_elem(tcfg, target, item, plan, counters, log, bad)
        if err:
            out = err
            break
        cnt += 1
    if out is None and exhausted_panic:
        return None, log, 'next_exhausted'
    if out is not None:
        if buffered and bad != 'error_no_dealloc':
            log.append(('dealloc', tvec.cap))
        return out, log, None
    if not buffered:
        return (OK_WORD, None, None), log, None
    m_finish_tail(vec, tvec.cap, bytes(tvec.buf), cnt, log, bad)
    return (OK_WORD, None, None), log, None


def m_wrapper(repr_words):
    """The seq wrapper: container words (cap, ptr, head, len) -> nine iterator words."""
    cap, ptr, head, ln = repr_words
    if cap == NICHE:
        root, height, ln2 = ptr, head, ln
        p = int(root != 0)
        r8 = ln2 if root else 0
        return (p, 0, root, height, p, 0, root, height, r8)
    if ln == 0:
        s1, e1, base, c2, r8 = ptr, ptr, ptr, ptr, 0
        return (2, s1, e1, base, c2, 0, e1, base, r8)
    h = head - cap if head >= cap else head
    first = cap - h
    if ln > first:
        end1, second = cap, ln - first
        r8 = ln
    else:
        end1, second = h + ln, 0
        r8 = ln + h
    return (2, ptr + h * SEQ_ELEM, ptr + end1 * SEQ_ELEM, ptr, ptr + second * SEQ_ELEM, 0,
            ptr + end1 * SEQ_ELEM, ptr, r8)


def calls_in_order(image, by_start, entry):
    """Distinct direct-call targets that are unwind-table entries, in first-call order."""
    out = []
    for i in linear(image, entry, by_start[entry]['end']):
        if i.mn == 'call' and i.target in by_start and i.target not in out:
            out.append(i.target)
    return out


def derive_copies(image, by_start):
    """Stage roles come from call order inside the original bodies (first, second and third callee of the
    entry writer; the one non-iterator, non-header, non-finish callee of the sequence loop)."""
    for c in COPIES:
        ec = [t for t in calls_in_order(image, by_start, c['ent']) if t != c['res']]
        if len(ec) != 3:
            raise Reject('entry writer 0x%x does not call three stage writers' % c['ent'])
        c['key'], c['val'], c['end'] = ec
        sc = [t for t in calls_in_order(image, by_start, c['seq']) if t not in (c['head'], c['fin'], c['nseq'])]
        if len(sc) != 1:
            raise Reject('sequence loop 0x%x has no unique element writer' % c['seq'])
        c['elem'] = sc[0]
        wc = calls_in_order(image, by_start, c['wrap'])
        if wc != [c['seq']]:
            raise Reject('wrapper 0x%x does not call its sequence loop' % c['wrap'])
        mc = [t for t in calls_in_order(image, by_start, c['map']) if t not in (c['head'], c['fin'], c['nmap'], c['ent'])]
        if mc:
            raise Reject('map loop 0x%x has an unexpected callee' % c['map'])


def m_finish_tail(vec, tcap, tbuf, cnt, log, bad=None):
    """Finish of a buffered writer: array header with the count, the buffered bytes, then the buffer is freed."""
    m_header(vec, cnt + (1 if bad == 'count_plus1' else 0), log, bad)
    nb = len(tbuf)
    if nb > vec.room():
        grow = bsl_reserve(vec.cap, len(vec.buf), nb, bad)
        log.append(('alloc' if vec.cap == 0 else 'realloc', grow))
        vec.cap = grow
    if nb or bad == 'memcpy_empty':
        log.append(('memcpy', nb))
        vec.buf += tbuf
    if tcap and bad != 'finish_no_dealloc':
        log.append(('dealloc', tcap))


# ------------------------------------------------------------------ fixtures and runner

class World:
    def __init__(self, plan, alloc_fail, names):
        self.plan, self.alloc_fail, self.names = plan, alloc_fail, names
        self.counters = dict(key=0, val=0, end=0, elem=0)
        self.nalloc = 0

    def item(self, key, val):
        idx = self.names.get(key)
        if idx is None or self.names.get(('vk', val)) != idx:
            return ('?', key, val)
        return idx

    def key_only(self, key):
        return self.names.get(key, ('?', key))

    def val_only(self, val):
        return self.names.get(('vk', val), ('?', val))

    def tgt(self, ptr):
        return 'W' if ptr == WR else ('B' if ptr >= STACK_TOP - 0x10000 else ('?', ptr))


def cfg_of(m, p):
    return (m.load(p + 0x18, 2), m.load(p + 0x1a, 2), m.load(p + 0x1c, 1))


def make_stubs(world, cp):
    st = {}

    def do_alloc(m, a):
        size = a[0]
        n = world.nalloc
        world.nalloc += 1
        m.log.append(('alloc', size))
        if world.alloc_fail == n:
            m.regs[0] = 0
            return
        ptr = m.heap
        m.heap += ((size + 15) & ~15) + 16
        m.sizes[ptr] = size
        m.regs[0] = ptr

    def do_realloc(m, a):
        ptr, size = a[0], a[1]
        n = world.nalloc
        world.nalloc += 1
        m.log.append(('realloc', size))
        if world.alloc_fail == n:
            m.regs[0] = 0
            return
        new = m.heap
        m.heap += ((size + 15) & ~15) + 16
        old = m.sizes.get(ptr, 0)
        for k in range(min(old, size)):
            if ptr + k in m.mem:
                m.mem[new + k] = m.mem[ptr + k]
        m.sizes[new] = size
        m.regs[0] = new

    def do_alloc_err(m, a):
        raise Panic(('alloc_error', a[0], a[1]))

    def do_dealloc(m, a):
        m.log.append(('dealloc', a[1]))

    def do_memcpy(m, a):
        dst, src, n = a[0], a[1], a[2]
        m.log.append(('memcpy', n))
        for k in range(n):
            m.mem[dst + k] = m.mem[src + k]
        m.regs[0] = dst

    def do_panic(m, a):
        raise Panic(('panic', 'loc'))

    st[SLOT['alloc']] = do_alloc
    st[SLOT['alloc_al']] = do_alloc
    st[SLOT['realloc']] = do_realloc
    st[SLOT['realloc_al']] = do_realloc
    st[SLOT['alloc_err']] = do_alloc_err
    st[SLOT['dealloc']] = do_dealloc
    st[SLOT['memcpy']] = do_memcpy
    st[SLOT['panic']] = do_panic
    st[SLOT['panic_loc']] = do_panic

    def leaf(stage, nargs_state):
        def fn(m, a):
            out = a[0]
            k = world.counters[stage]
            world.counters[stage] += 1
            if stage == 'elem':
                m.log.append(('elem', world.tgt(a[3]), cfg_of(m, a[3]), world.item(a[1], a[2])))
            else:
                state = tuple(m.r64(a[1] + 8 * j) for j in range(4)) + (m.load(a[1] + 0x20, 4),)
                tgt = world.tgt(state[3])
                row = (state[0], state[1], state[2], tgt, state[4], cfg_of(m, state[3]))
                if stage == 'end':
                    m.log.append(('end', row, None))
                elif stage == 'key':
                    m.log.append(('key', row, world.key_only(a[2])))
                else:
                    m.log.append(('val', row, world.val_only(a[2])))
            plan = world.plan
            words = err_words(stage, k) if plan and plan[0] == stage and plan[1] == k else (OK_WORD, 0, 0)
            for j, wv in enumerate(words):
                m.w64(out + 8 * j, wv)
        return fn

    st[cp['key']] = leaf('key', 5)
    st[cp['val']] = leaf('val', 5)
    st[cp['end']] = leaf('end', 5)
    st[cp['elem']] = leaf('elem', 0)
    return st


def write_writer(m, cap, data, flag, w18, w1a):
    m.w64(WR, cap)
    if cap == 0:
        m.w64(WR + 8, 1)
    else:
        m.w64(WR + 8, VB)
        m.poke(VB, bytes(data))
        m.sizes[VB] = cap
    m.w64(WR + 0x10, len(data))
    m.store(WR + 0x18, w18, 2)
    m.store(WR + 0x1a, w1a, 2)
    m.store(WR + 0x1c, flag, 1)
    m.poke(WR + 0x1d, bytes(0x13))


class TreeBuilder:
    def __init__(self, m, kind):
        self.m, self.kind = m, kind
        self.lay = LAYOUT[kind]
        self.next_addr = TREE

    def node(self, internal):
        a = self.next_addr
        self.next_addr += 0x400
        return a

    def build(self, rng, height, maxlen):
        """Returns (root, items) with items the in-order (key ptr, val ptr) pairs."""
        ko, ks, vo, vs, po, lo, eo, _, _ = self.lay
        m = self.m
        items = []

        def gen(h, parent, pidx):
            a = self.node(h > 0)
            n = 1 + rng.below(maxlen)
            m.w64(a, parent)
            m.store(a + po, pidx, 2)
            m.store(a + lo, n, 2)
            if h == 0:
                for i in range(n):
                    items.append((a + ko + ks * i, a + vo + vs * i))
                return a
            for i in range(n + 1):
                c = gen(h - 1, a, i)
                m.w64(a + eo + 8 * i, c)
                if i < n:
                    items.append((a + ko + ks * i, a + vo + vs * i))
            return a

        root = gen(height, 0, 0)
        return root, items


def prepare_names(items):
    names = {}
    for idx, (k, v) in enumerate(items):
        names[k] = idx
        names[('vk', v)] = idx
    return names


def run_machine(image, cover, cp, case, kind):
    """Build the fixture of one case and run the original code; return (m, world, items, words, panic)."""
    rng = Rng(case['seed'])
    items = []
    m_holder = {}
    world = World(case.get('plan'), case.get('alloc_fail'), {})
    real = set()
    for c in COPIES:
        real.update(c[k] for k in REAL_KEYS)
    m = Machine(image, real, make_stubs(world, cp), SLOT, cover)
    elem = MAP_ELEM if kind == 'map' else SEQ_ELEM
    spec = case['iter']
    if spec[0] == 'slices':
        _, n1, n2 = spec
        words = (2, EL1, EL1 + n1 * elem, EL2, EL2 + n2 * elem, 0x7777, 0x7777, 0x7777, 0x7777)
        items = [(EL1 + elem * k, EL1 + elem * k + 8) for k in range(n1)] + \
                [(EL2 + elem * k, EL2 + elem * k + 8) for k in range(n2)]
    elif spec[0] == 'tree':
        _, height, maxlen, lenmod = spec
        tb = TreeBuilder(m, kind)
        root, items = tb.build(rng, height, maxlen)
        words = (1, 0, root, height, 1, 0, root, height, len(items) + lenmod)
    else:
        words = (0,) * 9
    world.names = prepare_names(items)
    for j, wv in enumerate(words):
        m.w64(IT + 8 * j, wv)
    write_writer(m, *case['writer'])
    m.w64(OUT, 0x1111)
    m.w64(OUT + 8, 0x2222)
    m.w64(OUT + 0x10, 0x3333)
    m.regs[7], m.regs[6], m.regs[2] = OUT, WR, IT
    panic = None
    try:
        m.run(cp[kind])
    except Panic as p:
        panic = p.args[0]
    return m, world, items, words, panic


def observe(m, panic):
    cap = m.r64(WR)
    ln = m.r64(WR + 0x10)
    ptr = m.r64(WR + 8)
    data = m.peek(ptr, ln) if ln else b''
    out = tuple(m.r64(OUT + 8 * j) for j in range(3))
    return dict(out=out, cap=cap, data=data, log=list(m.log), panic=panic)


def expect(kind, case, items, words, bad=None):
    cap, data, flag, w18, w1a = case['writer']
    vec = Vec(cap, data)
    out, log, panic = m_loop(kind, words, vec, (w18, w1a, flag), [k for k in range(len(items))], case.get('plan'),
                             case.get('alloc_fail'), bad)
    exp = dict(out=out, cap=vec.cap, data=bytes(vec.buf), log=log, panic=None)
    af = case.get('alloc_fail')
    if af is not None:
        seen = -1
        for pos, ev in enumerate(log):
            if ev[0] in ('alloc', 'realloc'):
                seen += 1
                if seen == af:
                    exp.update(log=log[:pos + 1], panic='alloc')
                    break
    if panic and exp['panic'] is None:
        exp['panic'] = 'next'
    return exp


def norm_log(log, items_n):
    out = []
    for ev in log:
        if ev[0] in ('key', 'val') and isinstance(ev[2], int):
            out.append((ev[0], ev[1], ev[2]))
        else:
            out.append(ev)
    return out


def compare(kind, got, exp):
    """None when equal, else a short reason (no raw bytes in the text)."""
    gp = got['panic']
    ep = exp['panic']
    gk = None if gp is None else ('alloc' if gp[0] == 'alloc_error' else 'next')
    if gk != ep:
        return 'panic kind %s vs %s' % (gk, ep)
    if got['log'] != exp['log']:
        for k, (a, b) in enumerate(zip(got['log'], exp['log'])):
            if a != b:
                return 'log row %d differs' % k
        return 'log length %d vs %d' % (len(got['log']), len(exp['log']))
    if ep is None:
        if any(e is not None and g != e for g, e in zip(got['out'], exp['out'])):
            return 'result words differ'
        if got['cap'] != exp['cap']:
            return 'capacity %d vs %d' % (got['cap'], exp['cap'])
        if got['data'] != exp['data']:
            return 'output bytes differ'
        if 'hdr' in got and got['hdr'] != exp['hdr']:
            return 'header bytes differ'
    return None


# ------------------------------------------------------------------ direct entry families

BUFP = 0x2600_0000


def run_direct(image, cover, cp, case):
    """Header, finish and wrapper entries run on their own; returns (got, exp, steps)."""
    fam = case['family']
    rng = Rng(case['seed'])
    world = World(None, case.get('alloc_fail'), {})
    real = set()
    for c in COPIES:
        real.update(c[k] for k in REAL_KEYS)
    m = Machine(image, real, make_stubs(world, cp), SLOT, cover)
    cap, data, flag, w18, w1a = case['writer']
    write_writer(m, cap, data, flag, w18, w1a)
    vec = Vec(cap, data)
    m.w64(OUT, 0x1111)
    m.w64(OUT + 8, 0x2222)
    m.w64(OUT + 0x10, 0x3333)
    panic = None
    exp_log = []
    exp_out = None
    if fam == 'header':
        n = case['n']
        m.regs[7], m.regs[6], m.regs[2] = OUT, WR, n
        entry = cp['head']
        hdr = m_header(vec, n, exp_log, case.get('bad'))
        exp_out = (hdr[0], None, None)
    elif fam == 'finish':
        scap, buf, cnt = case['state']
        m.w64(CT, scap)
        m.w64(CT + 8, BUFP if buf else 1)
        m.w64(CT + 0x10, len(buf))
        m.store(CT + 0x20, cnt, 4)
        m.w64(CT + 0x28, WR)
        m.poke(BUFP, bytes(buf))
        m.sizes[BUFP] = scap if scap != NICHE else 0
        m.regs[7], m.regs[6] = OUT, CT
        entry = cp['fin']
        exp_out = (OK_WORD, None, None)
        if scap != NICHE:
            m_finish_tail(vec, scap, bytes(buf), cnt, exp_log, case.get('bad'))
    else:
        c = case['container']
        words = c['words']
        for j, wv in enumerate(words):
            m.w64(CT + 8 * j, wv)
        items = []
        if words[0] == NICHE:
            tb = TreeBuilder(m, 'seq')
            root, items = tb.build(rng, c['height'], c['maxlen'])
            m.w64(CT + 8, root)
            m.w64(CT + 0x10, c['height'])
            m.w64(CT + 0x18, len(items) + c['lenmod'] if root else c['lenmod'])
            if c.get('empty'):
                m.w64(CT + 8, 0)
                items = []
            cwords = (NICHE, m.r64(CT + 8), m.r64(CT + 0x10), m.r64(CT + 0x18))
        else:
            cwords = tuple(words)
        it = m_wrapper(cwords)
        if it[0] == 2:
            items = [(it[1] + SEQ_ELEM * k, it[1] + SEQ_ELEM * k + 8) for k in range((it[2] - it[1]) // SEQ_ELEM)] + \
                    [(it[3] + SEQ_ELEM * k, it[3] + SEQ_ELEM * k + 8) for k in range((it[4] - it[3]) // SEQ_ELEM)]
        world.names = prepare_names(items)
        m.regs[7], m.regs[6], m.regs[2] = OUT, CT, WR
        entry = cp['wrap']
        out, exp_log, p = m_loop('seq', it, vec, (w18, w1a, flag), list(range(len(items))), None, case.get('alloc_fail'),
                                 case.get('bad'))
        exp_out = out
        if p:
            exp_out = None
    try:
        m.run(entry)
    except Panic as p:
        panic = p.args[0]
    got = dict(out=tuple(m.r64(OUT + 8 * j) for j in range(3)), cap=m.r64(WR), log=list(m.log), panic=panic)
    ln = m.r64(WR + 0x10)
    got['data'] = m.peek(m.r64(WR + 8), ln) if ln else b''
    exp = dict(out=exp_out, cap=vec.cap, data=bytes(vec.buf), log=exp_log, panic=None)
    af = case.get('alloc_fail')
    if af is not None:
        seen = -1
        for pos, ev in enumerate(exp_log):
            if ev[0] in ('alloc', 'realloc'):
                seen += 1
                if seen == af:
                    exp.update(log=exp_log[:pos + 1], panic='alloc')
                    break
    if exp_out is None and exp['panic'] is None:
        exp['panic'] = 'next'
    if fam == 'header':
        got['hdr'] = (m.mem.get(OUT + 8), m.mem.get(OUT + 9))
        exp['hdr'] = (hdr[1], hdr[2])
    return got, exp, m.steps


def compare_direct(got, exp):
    r = compare('direct', got, exp) if exp['out'] is None or True else None
    return r


# ------------------------------------------------------------------ cases

WRITER_CAPS = (0, 1, 2, 3, 4, 5, 8, 16, 64)
FLAGS = (0, 1, 2, 3, 0x80, 0xff)
W18 = (0, 1, 0x101, 0xffff)
W1A = (0, 1, 0x100, 0x101, 0xffff)


def rand_writer(rng):
    cap = rng.pick(WRITER_CAPS)
    ln = rng.below(min(cap, 6) + 1)
    data = bytes(0x41 + (rng.below(26)) for _ in range(ln))
    return (cap, data, rng.pick(FLAGS), rng.pick(W18), rng.pick(W1A))


def rand_loop_case(rng, kind, seed, buffered_ok=True):
    sel = rng.below(12)
    if sel < 5:
        it = ('slices', rng.pick((0, 0, 1, 2, 3, 5, 9, 17, 18)), rng.pick((0, 0, 1, 2, 4, 16, 17)))
        n = it[1] + it[2]
    elif sel < 10:
        it = ('tree', rng.below(3), 1 + rng.below(4), rng.pick((0, 0, 0, -1)))
        n = 0
    elif sel == 10:
        it = ('tree', rng.below(2), 1 + rng.below(3), (1 << 32) + rng.below(3))
        n = 0
    else:
        it = ('empty',)
        n = 0
    case = dict(seed=seed, iter=it, writer=rand_writer(rng))
    cnt = n if it[0] == 'slices' else 6
    r = rng.below(8)
    if r == 1 and cnt:
        case['plan'] = ('elem' if kind == 'seq' else rng.pick(('key', 'val', 'end')), rng.below(cnt))
    elif r == 2:
        case['alloc_fail'] = rng.below(3)
    return case


def gen_cases():
    """Deterministic case stream: (family, kind, copy index, case)."""
    seed = 1
    for ci in range(3):
        for kind, count in (('map', 1750), ('seq', 1150)):
            rng = Rng(100 * ci + (7 if kind == 'map' else 9))
            for _ in range(count):
                seed += 1
                c = rand_loop_case(rng, kind, seed)
                if c['iter'][0] == 'tree' and c['iter'][3] < 0:
                    c['iter'] = c['iter'][:3] + (-1,)
                yield 'loop', kind, ci, c
        rng = Rng(500 + ci)
        for k in range(330):
            seed += 1
            n = (0, 1, 2, 15, 16, 17, 255, 256, 0xfffe, 0xffff, 0x10000, 0x10001, 0xfffffffe, 0xffffffff)[k % 14] \
                if k < 280 else rng.below(70000)
            c = dict(seed=seed, family='header', n=n, writer=rand_writer(rng))
            if rng.below(6) == 0:
                c['alloc_fail'] = 0
            yield 'direct', 'header', ci, c
        for k in range(160):
            seed += 1
            scap = rng.pick((NICHE, NICHE, 0, 3, 8, 0x80, 0x100))
            bl = rng.pick((0, 0, 1, 2, 5, 9, 20))
            cnt = rng.pick((0, 1, 15, 16, 17, 300, 65535, 65536, 70000))
            buf = bytes(0x61 + rng.below(26) for _ in range(bl))
            c = dict(seed=seed, family='finish', state=(scap, buf, cnt), writer=rand_writer(rng))
            if rng.below(7) == 0:
                c['alloc_fail'] = rng.below(2)
            yield 'direct', 'finish', ci, c
        for k in range(520):
            seed += 1
            sel = rng.below(10)
            if sel < 3:
                words = (NICHE, 0, 0, 0)
                cont = dict(words=words, height=rng.below(3), maxlen=1 + rng.below(3), lenmod=rng.pick((0, 0, 1)),
                            empty=rng.below(3) == 0)
            else:
                cap = 1 + rng.below(8)
                head = rng.below(cap + 2)
                ln = rng.below(cap + 1)
                words = (cap, EL1, head, ln)
                cont = dict(words=words)
            c = dict(seed=seed, family='wrapper', container=cont, writer=rand_writer(rng))
            if rng.below(8) == 0:
                c['alloc_fail'] = rng.below(2)
            yield 'direct', 'wrapper', ci, c


def run_any(image, cover, fam, kind, ci, case, bad=None):
    cp = COPIES[ci]
    if bad:
        case = dict(case, bad=bad)
    if fam == 'loop':
        m, world, items, words, panic = run_machine(image, cover, cp, case, kind)
        got = observe(m, panic)
        exp = expect(kind, case, items, words, bad)
        return got, exp, m.steps
    return run_direct(image, cover, cp, case)


# ------------------------------------------------------------------ negative controls

MODEL_MUTANTS = ('hdr_limit', 'hdr_endian', 'hdr_marker', 'flag_skip', 'reserve_min4', 'reserve_nodouble',
                 'error_no_dealloc', 'count_plus1', 'memcpy_empty', 'finish_no_dealloc', 'tree_reverse',
                 'buffered_limit')


def mem_disp(o):
    return o[4] if o and o[0] == 'm' else None


# (name, copy index, body key, insn, predicate, bytes from the instruction end, new byte)
BYTE_CONTROLS = (
    ('head cmp n,0x10000', 0, 'head', 'cmp', lambda i: i.b == ('i', 0x10000), 2, 0x02),
    ('head cmp n,0x10', 0, 'head', 'cmp', lambda i: i.b == ('i', 0x10) and i.size == 4, 1, 0x11),
    ('head mov kind,0x90', 0, 'head', 'mov', lambda i: i.b == ('i', 0x90), 4, 0x91),
    ('head xor al,0xdd', 0, 'head', 'xor', lambda i: i.b == ('i', 0xdd), 1, 0xde),
    ('head room test 1', 0, 'head', 'cmp', lambda i: i.a == ('r', 0) and i.b == ('i', 1), 1, 0x02),
    ('map loop shr 4', 0, 'map', 'shr', lambda i: i.b == ('i', 4), 1, 0x03),
    ('map loop buffer size', 0, 'map', 'mov', lambda i: i.a == ('r', 7) and i.b == ('i', 0x80), 4, 0x90),
    ('map loop slice stride', 0, 'map', 'lea', lambda i: mem_disp(i.b) == 0x10 and i.a == ('r', 1), 1, 0x20),
    ('map loop config mask', 0, 'map', 'and', lambda i: i.b == ('i', 0xff0101), 2, 0x7f),
    ('map loop copy 2 shr 4', 1, 'map', 'shr', lambda i: i.b == ('i', 4), 1, 0x03),
    ('seq loop copy 3 shr 5', 2, 'seq', 'shr', lambda i: i.b == ('i', 5), 1, 0x04),
    ('finish ok word', 0, 'fin', 'add', lambda i: i.a == ('r', 14) and i.b == ('i', 4), 1, 0x05),
    ('entry array marker', 0, 'ent', 'mov', lambda i: i.size == 1 and i.b == ('i', 0x92), 1, 0x93),
    ('entry flag compare', 0, 'ent', 'cmp', lambda i: i.size == 1 and i.b == ('i', 2), 1, 0x03),
    ('entry state word 4', 0, 'ent', 'mov', lambda i: i.size == 4 and i.b == ('i', 2), 4, 0x03),
    ('marker low bits', 0, 'mark', 'or', lambda i: i.b == ('i', 0x90), 1, 0x91),
    ('reserve minimum', 0, 'res', 'mov', lambda i: i.a == ('r', 3) and i.b == ('i', 8), 4, 0x04),
    ('map next edge offset', 0, 'nmap', 'add', lambda i: i.b == ('i', 0xc8), 4, 0xc0),
    ('wrapper slice scale', 0, 'wrap', 'shl', lambda i: i.a == ('r', 7) and i.b == ('i', 5), 1, 0x04),
    ('seq next copy 2 length', 1, 'nseq', 'movzx', lambda i: mem_disp(i.b) == 0x112, 4, 0x13),
    ('grow minimum align', 1, 'grow', 'mov', lambda i: i.a == ('r', 12) and i.b == ('i', 1), 4, 0x00),
)


def find_patch(image, by_start, cp, key, mn, pred, from_end, new):
    ent = cp[key]
    hits = [i for i in linear(image, ent, by_start[ent]['end']) if i.mn == mn and pred(i)]
    if not hits:
        raise Reject('no instruction for the control at 0x%x' % ent)
    ins = hits[0]
    return {ins.va + ins.length - from_end: new}


def control_cases():
    """A fixed, small, family-spanning subset used by every control (the first case of each stride)."""
    out = []
    for n, row in enumerate(gen_cases()):
        fam, kind, ci, case = row
        cap, data = case['writer'][:2]
        special = (fam == 'loop' and case['iter'][0] == 'tree' and case['iter'][3] >= (1 << 32)) or \
            (kind == 'header' and (case['n'] in (15, 16, 0xffff, 0x10000) or cap - len(data) in (1, 2, 3, 4))) or \
            (kind == 'finish' and case['state'][0] != NICHE)
        if n % 29 == 0 or special:
            out.append(row)
    return out


def run_control(image, cover, subset, patches=None, bad=None):
    """True when a mismatch (or a refusal) is seen: the wrong reconstruction or corrupted bytes are caught."""
    img = image if not patches else PatchedImage(image.data, patches)
    for fam, kind, ci, case in subset:
        try:
            got, exp, _ = run_any(img, cover, fam, kind, ci, case, bad)
            r = compare(kind, got, exp)
        except (Reject, Panic, KeyError, IndexError, ValueError) as e:
            return 'refused: %s' % str(e)[:60]
        if r:
            return r
    return None


def range_controls(image, by_start, data_sha_input):
    rows = []
    try:
        check_input(b'not the capture')
        rows.append(('input digest', 0, 'accepted a wrong input'))
    except Reject as e:
        rows.append(('input digest', 1, str(e)))
    try:
        image.read(0x1, 4)
        rows.append(('address outside sections', 0, 'read succeeded'))
    except Reject as e:
        rows.append(('address outside sections', 1, str(e)))
    ent = COPIES[0]['head']
    try:
        linear(image, ent, by_start[ent]['end'] - 1)
        rows.append(('short unwind extent', 0, 'decoded'))
    except Reject as e:
        rows.append(('short unwind extent', 1, str(e)))
    try:
        m = Machine(image, {ent}, {}, SLOT, set())
        m.regs[7], m.regs[6], m.regs[2] = OUT, WR, 3
        write_writer(m, 8, b'', 0, 0, 0)
        m.run(ent)
        rows.append(('unmodelled callee', 0, 'ran'))
    except Reject as e:
        rows.append(('unmodelled callee', 1, str(e)))
    return rows


def check_input(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


# ------------------------------------------------------------------ evidence

BODY_KEYS = ('map', 'seq', 'wrap', 'head', 'fin', 'ent', 'nmap', 'nseq', 'mark', 'res', 'grow')
NAMES = dict(map='map loop', seq='sequence loop', wrap='sequence wrapper', head='array header', fin='finish',
             ent='map entry writer', nmap='map iterator next', nseq='sequence iterator next',
             mark='marker normaliser', res='vec reserve', grow='grow helper')
SLOT_NAMES = {SLOT['alloc']: 'alloc', SLOT['alloc_err']: 'alloc_error', SLOT['dealloc']: 'dealloc',
              SLOT['memcpy']: 'memcpy', SLOT['panic']: 'panic', SLOT['realloc_al']: 'realloc_aligned',
              SLOT['realloc']: 'realloc', SLOT['alloc_al']: 'alloc_aligned', SLOT['panic_loc']: 'panic_location'}


def tsv(header, rows):
    return '\n'.join(['\t'.join(header)] + ['\t'.join(str(c) for c in r) for r in rows]) + '\n'


def build(data, out):
    check_input(data)
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = dict((r['start'], r) for r in recs)
    derive_copies(image, by_start)
    cover = set()
    bodies, ins_rows, fun_rows = [], [], []
    for cp in COPIES:
        for key in BODY_KEYS:
            ent = cp[key]
            if ent not in by_start:
                raise Reject('0x%x is not an FDE start' % ent)
            rows = linear(image, ent, by_start[ent]['end'])
            bodies.append((cp['copy'], key, ent, rows))
            for r in rows:
                ins_rows.append((NAMES[key], cp['copy'], '0x%x' % ent, '0x%x' % r.va, r.length, r.raw.hex(), r.mn,
                                 '' if r.target is None else '0x%x' % r.target))
    # B-tree layout check: every node offset used by the fixtures is a displacement of the iterator bodies
    layout_rows = []
    for kind, key in (('map', 'nmap'), ('seq', 'nseq')):
        lay = LAYOUT[kind]
        for cp in COPIES:
            disps = set()
            for i in linear(image, cp[key], by_start[cp[key]]['end']):
                for o in (i.a, i.b):
                    if o and o[0] == 'm' and not o[5]:
                        disps.add(o[4])
            names = ('key', 'key stride', 'val', 'val stride', 'parent index', 'length', 'edges', 'leaf', 'internal')
            for nm, v in zip(names, lay):
                if nm in ('key', 'val', 'parent index', 'length', 'edges'):
                    if nm in ('parent index', 'length', 'edges') and v not in disps:
                        raise Reject('layout offset 0x%x not read by 0x%x' % (v, cp[key]))
                    layout_rows.append((kind, cp['copy'], '0x%x' % cp[key], nm, '0x%x' % v))
    slot_sites = {}
    for cp_, key, ent, rows in bodies:
        for r in rows:
            if r.mn in ('call_mem', 'jmp_mem'):
                s = r.a[4]
                slot_sites[s] = slot_sites.get(s, 0) + 1
    if sorted(slot_sites) != sorted(SLOT.values()):
        raise Reject('slot set differs from the modelled slots')
    rel = image.relative_addends(set(slot_sites))
    slot_rows = [('0x%x' % s, SLOT_NAMES[s], slot_sites[s], '0x%x' % rel[s][1] if s in rel else 'none')
                 for s in sorted(slot_sites)]
    role_rows = []
    for cp in COPIES:
        for role in ('key', 'val', 'end', 'elem'):
            role_rows.append((cp['copy'], role, '0x%x' % cp[role],
                              'first callee of the entry writer' if role == 'key' else
                              'second callee of the entry writer' if role == 'val' else
                              'third callee of the entry writer' if role == 'end' else
                              'only non-iterator callee of the sequence loop'))
    # whole case stream
    digest = hashlib.sha256()
    case_rows, counts, steps_total = [], {}, 0
    total = mism = 0
    for n, (fam, kind, ci, case) in enumerate(gen_cases()):
        got, exp, steps = run_any(image, cover, fam, kind, ci, case)
        r = compare(kind, got, exp)
        total += 1
        steps_total += steps
        if r:
            mism += 1
        counts[(fam, kind)] = counts.get((fam, kind), 0) + 1
        summary = '%d|%s|%s|%d|%d|%x|%d|%d|%d|%s' % (n, fam, kind, ci + 1, steps, got['out'][0], got['cap'],
                                                     len(got['data']), len(got['log']), got['panic'] is not None)
        digest.update(summary.encode())
        if n % 8 == 0:
            spec = case.get('iter') or case.get('container') or case.get('state') or case.get('n')
            case_rows.append((n, fam, kind, ci + 1, json.dumps(spec if not isinstance(spec, dict) else
                                                                  dict((k, v) for k, v in spec.items()), default=str),
                              json.dumps(case['writer'][:1] + (len(case['writer'][1]),) + case['writer'][2:]),
                              json.dumps(case.get('plan')), case.get('alloc_fail', ''), steps,
                              '%x' % got['out'][0], got['cap'], len(got['data']), len(got['log']),
                              'ok' if not r else 'MISMATCH'))
    if mism:
        raise Reject('%d of %d cases differ from the reconstruction' % (mism, total))
    # coverage
    fun_rows, unexec = [], []
    for cp_, key, ent, rows in bodies:
        ex = sum(1 for r in rows if r.va in cover)
        fun_rows.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % by_start[ent]['end'], by_start[ent]['end'] - ent,
                         len(rows), ex, hashlib.sha256(image.read(ent, by_start[ent]['end'] - ent)).hexdigest()))
        for r in rows:
            if r.va not in cover and r.mn != 'nop':
                unexec.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % r.va, r.mn))
    # controls
    subset = control_cases()
    control_rows = []
    for name in MODEL_MUTANTS:
        r = run_control(image, set(), subset, None, name)
        control_rows.append(('wrong reconstruction', name, int(r is not None), r or 'NOT DETECTED'))
    for name, ci, key, mn, pred, from_end, new in BYTE_CONTROLS:
        patch = find_patch(image, by_start, COPIES[ci], key, mn, pred, from_end, new)
        r = run_control(image, set(), subset, patch)
        control_rows.append(('byte corruption', '%s (copy %d)' % (name, ci + 1), int(r is not None), r or 'NOT DETECTED'))
    for name, ok, why in range_controls(image, by_start, None):
        control_rows.append(('out of range input', name, ok, why))
    detected = sum(r[2] for r in control_rows)
    summary = dict(
        cases=total, case_families=dict(('%s/%s' % k, v) for k, v in sorted(counts.items())),
        negative_controls=len(control_rows), negative_detected=detected, mismatches=mism,
        interpreted_steps=steps_total, all_cases_sha256=digest.hexdigest(),
        bodies=len(bodies), instructions=len(ins_rows), executed_instructions=len(cover),
        unexecuted_instructions=len(unexec))
    files = {
        'functions.tsv': tsv(('role', 'copy', 'entry', 'end', 'bytes', 'instructions', 'executed', 'body_sha256'), fun_rows),
        'instructions.tsv': tsv(('role', 'copy', 'entry', 'va', 'length', 'raw', 'insn', 'target'), ins_rows),
        'stage-roles.tsv': tsv(('copy', 'stage', 'entry', 'derivation'), role_rows),
        'slots.tsv': tsv(('slot', 'role', 'sites', 'relative_target'), slot_rows),
        'btree-layout.tsv': tsv(('kind', 'copy', 'iterator', 'field', 'offset'), layout_rows),
        'unexecuted.tsv': tsv(('role', 'copy', 'entry', 'va', 'insn'), unexec),
        'cases.tsv': tsv(('id', 'family', 'kind', 'copy', 'input', 'writer', 'plan', 'alloc_fail', 'steps', 'result0', 'cap',
                          'len', 'log_rows', 'verdict'), case_rows),
        'controls.tsv': tsv(('class', 'control', 'detected', 'first_reason'), control_rows),
        'summary.json': json.dumps(summary, indent=1, sort_keys=True) + '\n',
        'measure.json': json.dumps(dict(cases=total, negative_controls=len(control_rows), negative_detected=detected),
                                   indent=1, sort_keys=True) + '\n',
    }
    if detected != len(control_rows):
        raise Reject('a negative control was not detected: %s' % [r for r in control_rows if not r[2]])
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_text(files[name])
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, help='work-item folder that receives the generated evidence')
    args = ap.parse_args(argv)
    summary = build(TARGET.read_bytes(), args.out)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
