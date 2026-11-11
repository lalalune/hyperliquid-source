#!/usr/bin/env python3
"""Reconstruct the node #115 map entry stage writers (key, value, end) below the container loops.

The previous container packet left the three stage writers of the map entry writer stubbed.  This producer
runs them, the entry writer that calls them, and their leaf writers (array header, unsigned integer writer,
bin header writer, Vec reserve and grow, marker normaliser) as ORIGINAL machine code in a small interpreter for
the fixed x86-64 subset they use, in all three copy families of the capture.  It authenticates the #115
capture, locates every body by its unwind (FDE) extent, derives the stage order from the call order of the
entry writer, and compares every interpreted result (output bytes, result word, state word, capacity, call
and allocator log) with an independent pure-Python reconstruction.  Deliberately wrong reconstructions,
byte-corrupted copies of the capture and out-of-range inputs run through the same comparison and must all be
caught.

Only the standard library and the repository's shared ELF/unwind parsers are used.  The capture is never
executed; no external program is invoked.
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
    elif not two and 0xb0 <= op <= 0xb7:
        r = (op - 0xb0) | (rb << 3)
        byte_reg_ok(('r', r))
        kw.update(mn='mov', size=1, a=('r', r), b=('i', imm(1)))
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



SLOT = dict(alloc=0x64df480, alloc_err=0x64df498, dealloc=0x64df4a0, memcpy=0x64df508, panic=0x64df520,
            realloc_al=0x64df580, realloc=0x64df588, alloc_al=0x64df590, panic_loc=0x64df830)

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


# ------------------------------------------------------------------ targets

# one row per copy family: copy 1, 2, 3.  `ent` is the map entry writer, `key`/`val`/`end` are the three stage
# writers it calls in this order, the others are the callees the stage writers reach.
COPIES = (
    dict(copy=1, ent=0x22877f0, key=0x2296160, val=0x2296fa0, end=0x22999e0, head=0x25e7c10, wu=0x25e9f10,
         bin=0x25e80c0, res=0x231e050, grow=0x231dc90, mark=0x25eab50),
    dict(copy=2, ent=0x41bf660, key=0x41cfc10, val=0x41d06f0, end=0x41d4150, head=0x3d50540, wu=0x3d51450,
         bin=0x41c5b90, res=0x43bd910, grow=0x43bd550, mark=0x3d52310),
    dict(copy=3, ent=0x5315e20, key=0x53206b0, val=0x5320130, end=0x5325140, head=0x57cee80, wu=0x57cfd20,
         bin=0x57cf350, res=0x5963a10, grow=0x5963650, mark=0x57d0b20),
)
BODY_KEYS = ('ent', 'key', 'val', 'end', 'head', 'wu', 'bin', 'res', 'grow', 'mark')
NAMES = dict(ent='map entry writer', key='key stage writer', val='value stage writer', end='end stage writer',
             head='array header', wu='unsigned integer writer', bin='bin header writer', res='vec reserve',
             grow='grow helper', mark='marker normaliser')
SLOT_NAMES = {SLOT['alloc']: 'alloc', SLOT['alloc_err']: 'alloc_error', SLOT['dealloc']: 'dealloc',
              SLOT['memcpy']: 'memcpy', SLOT['panic']: 'panic', SLOT['realloc_al']: 'realloc_aligned',
              SLOT['realloc']: 'realloc', SLOT['alloc_al']: 'alloc_aligned', SLOT['panic_loc']: 'panic_location'}
LEAF = dict(uint='wu', bin='bin', head='head')
OUT, WR, ST, BUFP, ITEM, KEYP = 0x2000_0000, 0x2100_0000, 0x2300_0000, 0x2600_0000, 0x2700_0000, 0x2710_0000
VB = 0x2200_0000


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
    """Array header of n elements: fixarray below 16, array16 below 65536, else array32."""
    if n < (15 if bad == 'hdr_limit' else 16):
        m_push(vec, bytes([0x90 | n]), log, bad)
    elif n < 0x10000:
        m_push(vec, bytes([0xdd if bad == 'hdr_marker' else 0xdc]), log, bad)
        m_push(vec, (n & 0xffff).to_bytes(2, 'little' if bad == 'hdr_endian' else 'big'), log, bad)
    else:
        m_push(vec, b'\xdd', log, bad)
        m_push(vec, (n & 0xffffffff).to_bytes(4, 'big'), log, bad)


def m_uint(vec, v, log, bad=None):
    """Unsigned integer: positive fixint, then uint8/16/32/64 with the marker pushed before the payload."""
    lim = 0x7f if bad == 'uint_fix_limit' else 0x80
    if v < lim:
        m_push(vec, bytes([v]), log, bad)
    elif v < 0x100:
        m_push(vec, bytes([0xcd if bad == 'uint_u8_marker' else 0xcc]), log, bad)
        m_push(vec, bytes([v]), log, bad)
    elif v < 0x10000:
        m_push(vec, b'\xcd', log, bad)
        m_push(vec, v.to_bytes(2, 'little' if bad == 'uint_be16_little' else 'big'), log, bad)
    elif v < 1 << 32:
        m_push(vec, b'\xce', log, bad)
        m_push(vec, v.to_bytes(4, 'big'), log, bad)
    else:
        m_push(vec, b'\xcf', log, bad)
        m_push(vec, v.to_bytes(8, 'big'), log, bad)


def m_bin_header(vec, n, log, bad=None):
    """bin8 / bin16 / bin32 header of the 32-bit length n."""
    n &= 0xffffffff
    if n < 0x100:
        m_push(vec, b'\xc4', log, bad)
        m_push(vec, bytes([n]), log, bad)
    elif n < 0x10000:
        m_push(vec, b'\xc5', log, bad)
        m_push(vec, n.to_bytes(2, 'big'), log, bad)
    else:
        m_push(vec, b'\xc6', log, bad)
        m_push(vec, n.to_bytes(4, 'big'), log, bad)


def m_leaf(kind, value, vec, log, bad=None):
    """Leaf writers called directly: bytes plus the two result bytes they leave in the result record."""
    if kind == 'uint':
        m_uint(vec, value, log, bad)
        if value < 0x80:
            return (0, value)
        return ((0xcc, 0xcd, 0xce, 0xcf)[0 if value < 0x100 else 1 if value < 0x10000 else 2 if value < 1 << 32 else 3], 0x22)
    if kind == 'bin':
        m_bin_header(vec, value, log, bad)
        return ((0xc4 if value < 0x100 else 0xc5 if value < 0x10000 else 0xc6), 0x22)
    m_header(vec, value, log, bad)
    return ((0x90 if value < 16 else 0xdc if value < 0x10000 else 0xdd), value & 0xff)


def m_stage_uint(state, item, vec, log, bad=None):
    """Key and value stage writers: while the pending prefix is live (state word != NICHE) write an array header
    of `count` elements, the prefix bytes as integers and release the prefix; then write the 64-bit item."""
    cap, buf, count = state
    if cap != NICHE:
        m_header(vec, count, log, bad)
        for b in buf:
            m_uint(vec, b, log, bad)
        if cap != 0 and bad != 'stage_no_dealloc':
            log.append(('dealloc', cap))
        if bad == 'stage_dealloc_zero' and cap == 0:
            log.append(('dealloc', cap))
        cap = NICHE if bad != 'state_keep' else cap
    m_uint(vec, item, log, bad)
    return (cap, buf, count)


def m_stage_end(state, vec, log, bad=None):
    """End stage writer: a live prefix is written as an array of its bytes when the count is below 16 and every
    byte is below 0x80, otherwise as a bin whose length is the count; then the bytes are copied in one block."""
    cap, buf, count = state
    if cap == NICHE:
        return state
    lim = 0x11 if bad == 'end_array_limit' else 0x10
    positive = all(b < (0x81 if bad == 'end_signed' else 0x80) for b in buf)
    if count < lim and positive:
        m_header(vec, count, log, bad)
    else:
        m_bin_header(vec, len(buf) if bad == 'end_bin_len' else count, log, bad)
    n = len(buf)
    if n > vec.room():
        grow = bsl_reserve(vec.cap, len(vec.buf), n, bad)
        log.append(('alloc' if vec.cap == 0 else 'realloc', grow))
        vec.cap = grow
    if n and bad != 'end_no_memcpy':
        log.append(('memcpy', n))
    vec.buf += buf
    if cap != 0:
        log.append(('dealloc', cap))
    return state


def m_entry(flag, key, val, vec, log, bad=None):
    """Map entry: the entry writer pushes the array-of-two marker unless the struct flag is 2; the three stage
    writers then share one pending-prefix state (empty prefix, count 2) that the first live stage consumes."""
    if flag != 2 or bad == 'entry_flag_skip':
        m_push(vec, b'\x93' if bad == 'entry_marker' else b'\x92', log, bad)
    state = (0 if flag == 2 else NICHE, b'', 2)
    state = m_stage_uint(state, key, vec, log, bad)
    state = m_stage_uint(state, val, vec, log, bad)
    m_stage_end(state, vec, log, bad)
    return state


# ------------------------------------------------------------------ fixtures and runner

class World:
    def __init__(self, alloc_fail):
        self.alloc_fail = alloc_fail
        self.nalloc = 0


def make_stubs(world):
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


def write_state(m, cap, buf, count):
    m.w64(ST, cap)
    m.w64(ST + 8, BUFP if buf else 1)
    m.w64(ST + 0x10, len(buf))
    m.w64(ST + 0x18, WR)
    m.store(ST + 0x20, count, 4)
    m.poke(BUFP, bytes(buf))
    m.sizes[BUFP] = cap if cap != NICHE else 0


def run_case(image, cover, case, bad=None, patches=None):
    """Run one case on the ORIGINAL code; return (got, exp, steps)."""
    cp = COPIES[case['copy']]
    img = image if not patches else PatchedImage(image.data, patches)
    world = World(case.get('alloc_fail'))
    real = set()
    for c in COPIES:
        real.update(c[k] for k in BODY_KEYS)
    m = Machine(img, real, make_stubs(world), SLOT, cover)
    cap, data, flag, w18, w1a = case['writer']
    write_writer(m, cap, data, flag, w18, w1a)
    vec = Vec(cap, data)
    m.w64(OUT, 0x1111)
    m.w64(OUT + 8, 0x2222)
    m.w64(OUT + 0x10, 0x3333)
    log = []
    kind = case['kind']
    state_after = None
    marker = None
    if kind in LEAF:
        m.regs[7], m.regs[6], m.regs[2] = OUT, WR, case['value']
        entry = cp[LEAF[kind]]
        marker = m_leaf(kind, case['value'], vec, log, bad)
    elif kind == 'entry':
        m.w64(KEYP, case['key'])
        m.w64(ITEM, case['val'])
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT, KEYP, ITEM, WR
        entry = cp['ent']
        m_entry(flag, case['key'], case['val'], vec, log, bad)
    else:
        scap, buf, count = case['state']
        write_state(m, scap, buf, count)
        m.w64(ITEM, case.get('item', 0))
        m.regs[7], m.regs[6], m.regs[2] = OUT, ST, ITEM
        entry = cp[kind]
        if kind == 'end':
            state_after = m_stage_end(case['state'], vec, log, bad)
        else:
            state_after = m_stage_uint(case['state'], case['item'], vec, log, bad)
    panic = None
    try:
        m.run(entry)
    except Panic as p:
        panic = p.args[0]
    got = dict(out=m.r64(OUT), cap=m.r64(WR), log=list(m.log), panic=panic,
               state=m.r64(ST) if kind in ('key', 'val', 'end') else None,
               marker=(m.mem.get(OUT + 8), m.mem.get(OUT + 9)) if marker else None)
    ln = m.r64(WR + 0x10)
    got['data'] = m.peek(m.r64(WR + 8), ln) if ln and panic is None else b''
    exp = dict(out=2 if marker else OK_WORD, cap=vec.cap, data=bytes(vec.buf), log=log, panic=None,
               state=None if state_after is None else state_after[0], marker=marker)
    af = case.get('alloc_fail')
    if af is not None:
        seen = -1
        for pos, ev in enumerate(log):
            if ev[0] in ('alloc', 'realloc'):
                seen += 1
                if seen == af:
                    exp.update(log=log[:pos + 1], panic='alloc')
                    break
    return got, exp, m.steps


def compare(got, exp):
    gp, ep = got['panic'], exp['panic']
    gk = None if gp is None else ('alloc' if gp[0] == 'alloc_error' else 'other')
    if gk != ep:
        return 'panic kind %s vs %s' % (gk, ep)
    if got['log'] != exp['log']:
        for k, (a, b) in enumerate(zip(got['log'], exp['log'])):
            if a != b:
                return 'log row %d differs' % k
        return 'log length %d vs %d' % (len(got['log']), len(exp['log']))
    if ep is None:
        if got['out'] != exp['out']:
            return 'result word differs'
        if got['cap'] != exp['cap']:
            return 'capacity %d vs %d' % (got['cap'], exp['cap'])
        if got['data'] != exp['data']:
            return 'output bytes differ'
        if got['state'] != exp['state']:
            return 'state word differs'
        if got['marker'] != exp['marker']:
            return 'result marker bytes differ'
    return None


# ------------------------------------------------------------------ cases

WRITER_CAPS = (0, 1, 2, 3, 4, 5, 8, 16, 64)
FLAGS = (0, 1, 2, 3, 0x80, 0xff)
ITEMS = (0, 1, 0x7f, 0x80, 0xff, 0x100, 0x101, 0xffff, 0x10000, 0xffffff, 0xffffffff, 0x100000000, 1 << 40,
         (1 << 63) - 1, 1 << 63, MASK)
COUNTS = (0, 1, 2, 3, 15, 16, 17, 255, 256, 0xfffe, 0xffff, 0x10000, 0x10001, 0xffffffff)
CAPS = (NICHE, NICHE, 0, 1, 3, 8, 0x80, 0x100)


def rand_writer(rng):
    cap = rng.pick(WRITER_CAPS)
    ln = rng.below(min(cap, 6) + 1)
    data = bytes(0x41 + (rng.below(26)) for _ in range(ln))
    return (cap, data, rng.pick(FLAGS), 0, 0)


def rand_buf(rng, high):
    n = rng.pick((0, 0, 1, 2, 3, 5, 9, 20))
    if high == 0:
        return bytes(rng.below(0x80) for _ in range(n))
    if high == 1:
        return bytes(rng.below(256) for _ in range(n))
    return bytes(rng.pick((0, 0x7f, 0x80, 0xff)) for _ in range(n))


def gen_cases():
    """Deterministic case stream."""
    seed = 1
    for ci in range(3):
        for kind, count in (('key', 1000), ('val', 1000), ('end', 1100), ('entry', 700), ('uint', 700), ('bin', 500),
                            ('head', 500)):
            rng = Rng(100 * ci + 11 * len(kind) + count % 7)
            for k in range(count):
                seed += 1
                c = dict(seed=seed, copy=ci, kind=kind, writer=rand_writer(rng))
                if kind in LEAF:
                    if kind == 'uint':
                        c['value'] = rng.pick(ITEMS) if k % 3 else rng.next() >> rng.below(64)
                    else:
                        c['value'] = rng.pick(COUNTS) if k % 3 else rng.next() >> (32 + rng.below(32))
                elif kind == 'entry':
                    c['key'], c['val'] = rng.pick(ITEMS), rng.pick(ITEMS)
                    if k % 5 == 0:
                        c['key'] = rng.next() >> rng.below(64)
                        c['val'] = rng.next() >> rng.below(64)
                else:
                    scap = rng.pick(CAPS)
                    buf = rand_buf(rng, k % 3)
                    cnt = rng.pick(COUNTS) if k % 4 else len(buf)
                    c['state'] = (scap, buf, cnt)
                    c['item'] = rng.pick(ITEMS) if k % 3 else rng.next() >> rng.below(64)
                if rng.below(7) == 0:
                    c['alloc_fail'] = rng.below(3)
                yield c


# ------------------------------------------------------------------ negative controls

MODEL_MUTANTS = ('hdr_limit', 'hdr_endian', 'hdr_marker', 'uint_fix_limit', 'uint_u8_marker', 'uint_be16_little',
                 'reserve_min4', 'reserve_nodouble', 'stage_no_dealloc', 'stage_dealloc_zero', 'state_keep',
                 'end_array_limit', 'end_signed', 'end_bin_len', 'end_no_memcpy', 'entry_marker', 'entry_flag_skip')


def mem_disp(o):
    return o[4] if o and o[0] == 'm' else None


# (name, copy index, body key, insn, predicate, bytes from the instruction end, new byte)
BYTE_CONTROLS = (
    ('uint cmp 0x100', 0, 'wu', 'cmp', lambda i: i.b == ('i', 0x100), 3, 0x02),
    ('uint cmp 0x10000', 0, 'wu', 'cmp', lambda i: i.b == ('i', 0x10000), 2, 0x02),
    ('uint u32 marker', 0, 'wu', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xce), 1, 0xcf),
    ('uint shr 0x20', 0, 'wu', 'shr', lambda i: i.b == ('i', 0x20), 1, 0x21),
    ('uint u16 marker copy 2', 1, 'wu', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xcd), 1, 0xce),
    ('uint u8 marker copy 3', 2, 'wu', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xcc), 1, 0xcb),
    ('key result compare', 0, 'key', 'cmp', lambda i: i.b == ('i', 2), 1, 0x03),
    ('key ok word', 0, 'key', 'add', lambda i: i.b == ('i', 4), 1, 0x05),
    ('val result compare copy 2', 1, 'val', 'cmp', lambda i: i.b == ('i', 2), 1, 0x03),
    ('end count limit', 0, 'end', 'cmp', lambda i: i.b == ('i', 0x10), 1, 0x11),
    ('end sign scan', 0, 'end', 'cmp', lambda i: i.size == 1 and i.b == ('i', 0), 1, 0x01),
    ('end ok word', 0, 'end', 'add', lambda i: i.b == ('i', 4), 1, 0x05),
    ('end count limit copy 3', 2, 'end', 'cmp', lambda i: i.b == ('i', 0x10), 1, 0x0f),
    ('bin marker base', 0, 'bin', 'mov', lambda i: i.size == 4 and i.b == ('i', 0xc4), 4, 0xc3),
    ('bin 16-bit limit', 0, 'bin', 'cmp', lambda i: i.b == ('i', 0x10000), 2, 0x02),
    ('bin 8-bit limit copy 2', 1, 'bin', 'cmp', lambda i: i.b == ('i', 0x100), 3, 0x02),
    ('entry array marker', 0, 'ent', 'mov', lambda i: i.size == 1 and i.b == ('i', 0x92), 1, 0x93),
    ('entry state count', 0, 'ent', 'mov', lambda i: i.size == 4 and i.b == ('i', 2), 4, 0x03),
    ('entry array marker copy 3', 2, 'ent', 'mov', lambda i: i.size == 1 and i.b == ('i', 0x92), 1, 0x91),
    ('header count limit', 0, 'head', 'cmp', lambda i: i.b == ('i', 0x10) and i.size == 4, 1, 0x11),
    ('reserve minimum', 0, 'res', 'mov', lambda i: i.a == ('r', 3) and i.b == ('i', 8), 4, 0x04),
)


def find_patch(image, by_start, cp, key, mn, pred, from_end, new):
    ent = cp[key]
    hits = [i for i in linear(image, ent, by_start[ent]['end']) if i.mn == mn and pred(i)]
    if not hits:
        raise Reject('no instruction for the control at 0x%x' % ent)
    ins = hits[0]
    return {ins.va + ins.length - from_end: new}


def control_cases():
    """A fixed, family-spanning subset used by every control: every 31st case plus the boundary specials."""
    out = []
    for n, c in enumerate(gen_cases()):
        cap, data = c['writer'][:2]
        sc = c.get('state')
        special = (sc is not None and c['kind'] != 'entry' and sc[0] != NICHE and sc[2] in (15, 16, 0xffff, 0x10000)
                   and n % 3 == 0) or (c['kind'] == 'entry' and c['writer'][2] == 2 and n % 7 == 0)
        if n % 31 == 0 or special:
            out.append(c)
    return out


def run_control(image, subset, patches=None, bad=None):
    for c in subset:
        try:
            got, exp, _ = run_case(image, set(), c, bad, patches)
            r = compare(got, exp)
        except (Reject, Panic, KeyError, IndexError, ValueError) as e:
            return 'refused: %s' % str(e)[:60]
        if r:
            return r
    return None


def range_controls(image, by_start):
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
    ent = COPIES[0]['val']
    try:
        linear(image, ent, by_start[ent]['end'] + 1)
        rows.append(('overlong unwind extent', 0, 'decoded'))
    except Reject as e:
        rows.append(('overlong unwind extent', 1, str(e)))
    try:
        m = Machine(image, {ent}, {}, SLOT, set())
        m.regs[7], m.regs[6], m.regs[2] = OUT, ST, ITEM
        write_writer(m, 8, b'', 0, 0, 0)
        write_state(m, 0, b'', 2)
        m.w64(ITEM, 5)
        m.run(ent)
        rows.append(('unmodelled callee', 0, 'ran'))
    except Reject as e:
        rows.append(('unmodelled callee', 1, str(e)))
    return rows


def check_input(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


# ------------------------------------------------------------------ evidence

def tsv(header, rows):
    return '\n'.join(['\t'.join(header)] + ['\t'.join(str(c) for c in r) for r in rows]) + '\n'


def calls_in_order(image, by_start, entry):
    out = []
    for i in linear(image, entry, by_start[entry]['end']):
        if i.mn == 'call' and i.target in by_start and i.target not in out:
            out.append(i.target)
    return out


def shape(image, by_start, ent):
    """Instruction sequence of a body with call targets and rip displacements dropped (copy-independent)."""
    return tuple((i.mn, i.size, i.a, i.b, None if i.mn in ('call', 'jmp') else i.imm)
                 for i in linear(image, ent, by_start[ent]['end']))


def build(data, out):
    check_input(data)
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = dict((r['start'], r) for r in recs)
    role_rows = []
    for cp in COPIES:
        order = [t for t in calls_in_order(image, by_start, cp['ent']) if t != cp['res']]
        if order != [cp['key'], cp['val'], cp['end']]:
            raise Reject('entry writer 0x%x does not call key, value, end in this order' % cp['ent'])
        for role in ('key', 'val', 'end'):
            callees = [t for t in calls_in_order(image, by_start, cp[role])]
            role_rows.append((cp['copy'], role, '0x%x' % cp[role],
                              ' '.join('0x%x' % t for t in callees)))
        if shape(image, by_start, cp['key']) != shape(image, by_start, cp['val']):
            raise Reject('key and value stage writers differ in shape')
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
    slot_sites = {}
    for cp_, key, ent, rows in bodies:
        for r in rows:
            if r.mn in ('call_mem', 'jmp_mem'):
                s = r.a[4]
                slot_sites[s] = slot_sites.get(s, 0) + 1
    if not set(slot_sites) <= set(SLOT.values()):
        raise Reject('a slot outside the modelled set is called')
    rel = image.relative_addends(set(slot_sites))
    slot_rows = [('0x%x' % s, SLOT_NAMES[s], slot_sites[s], '0x%x' % rel[s][1] if s in rel else 'none')
                 for s in sorted(slot_sites)]
    digest = hashlib.sha256()
    case_rows, counts = [], {}
    total = mism = steps_total = 0
    for n, case in enumerate(gen_cases()):
        got, exp, steps = run_case(image, cover, case)
        r = compare(got, exp)
        total += 1
        steps_total += steps
        if r:
            mism += 1
        counts[(case['copy'], case['kind'])] = counts.get((case['copy'], case['kind']), 0) + 1
        summary = '%d|%d|%s|%d|%x|%d|%d|%d|%s' % (n, case['copy'] + 1, case['kind'], steps, got['out'], got['cap'],
                                                  len(got['data']), len(got['log']), got['panic'] is not None)
        digest.update(summary.encode())
        if n % 10 == 0:
            spec = (case['value'],) if case['kind'] in LEAF else (case['key'], case['val']) \
                if case['kind'] == 'entry' else case['state'][:1] + (len(case['state'][1]), case['state'][2]) + (case['item'],)
            case_rows.append((n, case['copy'] + 1, case['kind'], json.dumps(spec),
                              json.dumps(case['writer'][:1] + (len(case['writer'][1]),) + case['writer'][2:3]),
                              case.get('alloc_fail', ''), steps, '%x' % got['out'], got['cap'], len(got['data']),
                              len(got['log']), 'ok' if not r else 'MISMATCH'))
    if mism:
        raise Reject('%d of %d cases differ from the reconstruction' % (mism, total))
    unexec = []
    for cp_, key, ent, rows in bodies:
        ex = sum(1 for r in rows if r.va in cover)
        fun_rows.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % by_start[ent]['end'], by_start[ent]['end'] - ent,
                         len(rows), ex, hashlib.sha256(image.read(ent, by_start[ent]['end'] - ent)).hexdigest()))
        for r in rows:
            if r.va not in cover and r.mn != 'nop':
                unexec.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % r.va, r.mn))
    subset = control_cases()
    control_rows = []
    for name in MODEL_MUTANTS:
        r = run_control(image, subset, None, name)
        control_rows.append(('wrong reconstruction', name, int(r is not None), r or 'NOT DETECTED'))
    for name, ci, key, mn, pred, from_end, new in BYTE_CONTROLS:
        if new is None:
            continue
        patch = find_patch(image, by_start, COPIES[ci], key, mn, pred, from_end, new)
        r = run_control(image, subset, patch)
        control_rows.append(('byte corruption', '%s (copy %d)' % (name, ci + 1), int(r is not None), r or 'NOT DETECTED'))
    for name, ok, why in range_controls(image, by_start):
        control_rows.append(('out of range input', name, ok, why))
    detected = sum(r[2] for r in control_rows)
    summary = dict(
        cases=total, case_families=dict(('copy%d/%s' % (k[0] + 1, k[1]), v) for k, v in sorted(counts.items())),
        negative_controls=len(control_rows), negative_detected=detected, mismatches=mism,
        interpreted_steps=steps_total, all_cases_sha256=digest.hexdigest(),
        bodies=len(bodies), instructions=len(ins_rows), executed_instructions=len(cover),
        unexecuted_instructions=len(unexec), control_subset_cases=len(subset))
    files = {
        'functions.tsv': tsv(('role', 'copy', 'entry', 'end', 'bytes', 'instructions', 'executed', 'body_sha256'), fun_rows),
        'instructions.tsv': tsv(('role', 'copy', 'entry', 'va', 'length', 'raw', 'insn', 'target'), ins_rows),
        'stage-roles.tsv': tsv(('copy', 'stage', 'entry', 'callees_in_first_call_order'), role_rows),
        'slots.tsv': tsv(('slot', 'role', 'sites', 'relative_target'), slot_rows),
        'unexecuted.tsv': tsv(('role', 'copy', 'entry', 'va', 'insn'), unexec),
        'cases.tsv': tsv(('id', 'copy', 'kind', 'input', 'writer', 'alloc_fail', 'steps', 'result0', 'cap', 'len',
                          'log_rows', 'verdict'), case_rows),
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
