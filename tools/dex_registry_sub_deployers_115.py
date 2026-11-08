#!/usr/bin/env python3
"""Reconstruct the node #115 Hip3 `sub_deployers` element writer and prove it against the capture.

The container packet of this series left the element writer of the `sub_deployers`
sequence stubbed.  This producer covers the whole element path in the three copy
families of the capture (element writers 0x22927f0 / 0x41c2c30 / 0x5312380):

* the element writer: an array-of-two marker, the deploy action name, the address array,
  and the tuple end;
* the action name writer (a 16-entry jump table over the action tag; 15 plain names for
  tags 8..22) and its second jump table for the eight `hip3Star` actions (tags 0..7), which
  are written as a one-entry map `{"hip3Star": name}`;
* the address array writer: a streaming check, a buffered flush branch, and a tail call into
  the address loop, which walks a B-tree set of 20-byte keys with a set iterator and writes
  every key as a 42-character `0x` + lowercase hex msgpack string through the hex formatter
  behind GOT slot 0x64e4d08.

It authenticates the #115 capture, locates every body by its unwind (FDE) extent, and runs the
ORIGINAL machine code of these bodies, and of the writers they call (str, uint, array header, tuple
end, buffered finish, reserve and grow), in a small interpreter for the fixed x86-64 subset they
use.  Only the allocator, copy and panic slots are stubs.  Every interpreted result (output bytes,
capacity, result word, allocator and copy log, panic kind) is compared with an independent
pure-Python reconstruction.  Deliberately wrong reconstructions, byte-corrupted copies of the
capture and out-of-range inputs run through the same comparison and must all be caught.

Only the standard library and the repository's shared ELF/unwind parsers are used.  The capture
is never executed; no external program is invoked.
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
        elif sub == 4 and rm[0] == 'r':
            kw.update(mn='jmp_reg', a=rm)
        elif sub == 2 and rm[0] == 'r':
            kw.update(mn='call_reg', a=rm)
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
            elif mn == 'jmp_reg':
                nxt = self.regs[ins.a[1]]
            elif mn == 'call_reg':
                t = self.regs[ins.a[1]]
                if t in self.stubs:
                    self.call_stub(self.stubs[t])
                elif t in self.real:
                    self.push(nxt)
                    nxt = t
                else:
                    raise Reject('indirect call to unmodelled target 0x%x at 0x%x' % (t, pc))
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

IT, OUT, WR, VB, CT, EL1, EL2, TREE = 0x1000_0000, 0x2000_0000, 0x2100_0000, 0x2200_0000, 0x2300_0000, \
    0x2400_0000, 0x2500_0000, 0x3800_0000


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

HEX_SLOT = 0x64e4d08
HEXF = 0x2eabb50
TABLE_OUTER = ('registerAsset', 'setOracle', 'insertMarginTable', 'setFeeRecipient', 'haltTrading',
               'setMarginTableIds', 'setOpenInterestCaps', 'setFundingMultipliers', 'setMarginModes',
               'setDeployerFees', 'setFundingInterestRates', 'disableDex', 'setPerpAnnotation',
               'migrateDexQuoteToken', 'setFundingClamps')
TABLE_INNER = ('modifyApproval', 'modifyBackstopLiquidatorApproval', 'setReduceOnly', 'cancel', 'cancelAll',
               'order', 'sendAsset', 'setOracle')
WRAP_KEY = 'hip3Star'
OUTER_FIRST = 8
TAGS = tuple(range(OUTER_FIRST + len(TABLE_OUTER)))

# one row per copy family (copy 1 / 2 / 3); roles are checked against call order in derive_copies
COPIES = (
    dict(copy=1, elem=0x22927f0, name=0x2bc7610, inner=0x2bc6150, vaddr=0x2299050, loop=0x2228ba0, iter=0x2387b20,
         wstr=0x25e8bf0, uint=0x25e9f10, end=0x22999e0, end2=0x25e80c0, fin=0x227e1b0, hdr=0x25e7c10,
         mark=0x25eab50, res=0x231e050, grow=0x231dc90),
    dict(copy=2, elem=0x41c2c30, name=0x44a3da0, inner=0x44a2980, vaddr=0x41d3d00, loop=0x4152580, iter=0x37c5980,
         wstr=0x41c6610, uint=0x3d51450, end=0x41d4150, end2=0x41c5b90, fin=0x41acd70, hdr=0x3d50540,
         mark=0x3d52310, res=0x43bd910, grow=0x43bd550),
    dict(copy=3, elem=0x5312380, name=0x54a20a0, inner=0x54a0ae0, vaddr=0x53207f0, loop=0x52808c0, iter=0x5138730,
         wstr=0x57cf5d0, uint=0x57cfd20, end=0x5325140, end2=0x57cf350, fin=0x5306d60, hdr=0x57cee80,
         mark=0x57d0b20, res=0x5963a10, grow=0x5963650),
)
NEW_KEYS = ('elem', 'name', 'inner', 'vaddr', 'loop', 'iter')
DEP_KEYS = ('wstr', 'uint', 'end', 'end2', 'fin', 'hdr', 'mark', 'res', 'grow')
ROLE_TEXT = dict(
    elem='sub_deployers element writer (action name, address array, end)',
    name='deploy action name writer (jump table over the action tag)',
    inner='hip3Star wrapped action name writer (second jump table)',
    vaddr='address array writer entry (streaming check, buffered flush, tail call)',
    loop='address array loop (header, iterator, hex text, finish)',
    iter='B-tree set iterator next (20-byte keys)',
    wstr='dependency: msgpack str writer', uint='dependency: msgpack uint writer',
    end='dependency: tuple end', end2='dependency: tuple end helper', fin='dependency: buffered finish',
    hdr='dependency: array header writer', mark='dependency: marker normaliser',
    res='dependency: Vec reserve', grow='dependency: grow helper')
SLOT_NAMES = {SLOT['alloc']: 'alloc', SLOT['alloc_err']: 'alloc_error', SLOT['dealloc']: 'dealloc',
              SLOT['memcpy']: 'memcpy', SLOT['panic']: 'panic', SLOT['realloc_al']: 'realloc_aligned',
              SLOT['realloc']: 'realloc', SLOT['alloc_al']: 'alloc_aligned', SLOT['panic_loc']: 'panic_location',
              HEX_SLOT: 'hex_text', 0x64df570: 'bounds_panic'}

# B-tree set node layout read from the iterator body: keys at +8 (20 bytes), parent index u16 at +0xe4, length
# u16 at +0xe6, edges at +0xe8
KEY_OFF, KEY_LEN, PIDX_OFF, LEN_OFF, EDGE_OFF = 8, 20, 0xe4, 0xe6, 0xe8
ITEM, SETP, BUFP = 0x2400_0000, 0x2500_0000, 0x2600_0000


def calls_in_order(image, by_start, entry):
    """Distinct direct call or tail-jump targets that are unwind-table entries, in first-use order."""
    out = []
    end = by_start[entry]['end']
    for i in linear(image, entry, end):
        if i.mn in ('call', 'jmp') and i.target in by_start and i.target != entry and i.target not in out \
                and not entry <= i.target < end:
            out.append(i.target)
    return out


def derive_copies(image, by_start):
    """Check every role address of COPIES against the call order inside the original bodies."""
    for c in COPIES:
        res = c['res']
        el = [t for t in calls_in_order(image, by_start, c['elem']) if t != res]
        if el != [c['hdr'], c['name'], c['vaddr'], c['end']]:
            raise Reject('element writer 0x%x has unexpected callees' % c['elem'])
        nm = [t for t in calls_in_order(image, by_start, c['name']) if t != res]
        if nm != [c['inner']]:
            raise Reject('name writer 0x%x has unexpected callees' % c['name'])
        iw = [t for t in calls_in_order(image, by_start, c['inner']) if t != res]
        if iw != [c['wstr']]:
            raise Reject('inner name writer 0x%x has unexpected callees' % c['inner'])
        va = [t for t in calls_in_order(image, by_start, c['vaddr']) if t != res]
        if va != [c['hdr'], c['uint'], c['loop']]:
            raise Reject('address writer 0x%x has unexpected callees' % c['vaddr'])
        lp = [t for t in calls_in_order(image, by_start, c['loop']) if t != res]
        if lp != [c['hdr'], c['iter'], c['wstr'], c['fin']]:
            raise Reject('address loop 0x%x has unexpected callees' % c['loop'])
        en = [t for t in calls_in_order(image, by_start, c['end']) if t != res]
        if en != [c['end2'], c['hdr']]:
            raise Reject('tuple end 0x%x has unexpected callees' % c['end'])


# ------------------------------------------------------------------ reconstruction (independent model)

class Vec:
    def __init__(self, cap, data):
        self.cap, self.buf = cap, bytearray(data)

    def room(self):
        return self.cap - len(self.buf)


class AllocFail(Exception):
    pass


class Exhausted(Exception):
    pass


class Model:
    """Writer state of the reconstruction: output vector, allocator events and the call log."""

    def __init__(self, cap, data, alloc_fail, bad):
        self.main = Vec(cap, data)
        self.log = []
        self.nalloc = 0
        self.alloc_fail = alloc_fail
        self.bad = bad

    def event(self, kind, size):
        self.log.append((kind, size))
        n = self.nalloc
        self.nalloc += 1
        if self.alloc_fail is not None and self.alloc_fail + (1 if self.bad == 'fail_index' else 0) == n:
            raise AllocFail()

    def push(self, vec, data, copy=False):
        n = len(data)
        if vec.room() < n:
            grow = bsl_reserve(vec.cap, len(vec.buf), n, self.bad)
            self.event('alloc' if vec.cap == 0 else 'realloc', grow)
            vec.cap = grow
        if copy and self.bad != 'no_memcpy_log':
            self.log.append(('memcpy', n))
        vec.buf += data

    def header(self, vec, n):
        lim = 15 if self.bad == 'hdr_limit' else 16
        if n < lim:
            self.push(vec, bytes([0x90 | n]))
        elif n < 0x10000:
            self.push(vec, b'\xdc')
            self.push(vec, (n & 0xffff).to_bytes(2, 'big'))
        else:
            self.push(vec, b'\xdd')
            self.push(vec, (n & 0xffffffff).to_bytes(4, 'big'))

    def string(self, vec, s, copy=False):
        n = len(s)
        lim = 33 if self.bad == 'str8_limit' else 32
        if n < lim:
            self.push(vec, bytes([0xa0 | n]))
        else:
            self.push(vec, b'\xd9')
            self.push(vec, bytes([n]))
        self.push(vec, s, n >= 32)

    def uint(self, vec, v):
        if v < 128:
            self.push(vec, bytes([v]))
        else:
            self.push(vec, b'\xcc')
            self.push(vec, bytes([v]))

    def name(self, tag):
        v = self.main
        outer = list(TABLE_OUTER)
        inner = list(TABLE_INNER)
        if self.bad == 'name_swap':
            outer[1], outer[2] = outer[2], outer[1]
        if self.bad == 'inner_shift':
            inner = inner[1:] + inner[:1]
        if tag < OUTER_FIRST:
            self.push(v, b'\x81')
            self.string(v, (b'hip3Stat' if self.bad == 'wrap_key' else WRAP_KEY.encode()))
            self.string(v, inner[tag].encode())
        else:
            self.string(v, outer[tag - OUTER_FIRST].encode())

    def hexline(self, key):
        text = key.hex()
        if self.bad == 'hex_upper':
            text = text.upper()
        text = ('' if self.bad == 'hex_no_prefix' else '0x') + text
        return text.encode()

    def array(self, vec_dst, keys, root, lenword):
        n = lenword if root else 0
        buffered = (n >> 32) != 0
        if buffered:
            self.event('alloc', 0x80)
            dst = Vec(0x80, b'')
        else:
            dst = vec_dst
            self.header(dst, n - 1 if self.bad == 'count_minus1' and n else n)
        seq = list(keys)
        if self.bad == 'addr_reverse':
            seq.reverse()
        for k in range(n):
            if k >= len(seq):
                raise Exhausted()
            self.string(dst, self.hexline(seq[k]), True)

    def buffered_flush(self, state):
        cap, buf, count = state
        self.header(self.main, count)
        for b in buf:
            self.uint(self.main, b)
        if cap:
            self.log.append(('dealloc', cap))


def model_run(case, keys, root, lenword, bad=None):
    """Expected observation of one case."""
    cap, data, _flag, _w18, _w1a = case['writer']
    st = Model(cap, data, case.get('alloc_fail'), bad)
    panic = None
    try:
        fam = case['family']
        if fam == 'elem':
            st.push(st.main, b'\x92' if bad != 'no_pair_marker' else b'')
            st.name(case['tag'])
            st.array(st.main, keys, root, lenword)
        elif fam == 'name':
            st.name(case['tag'])
        else:
            if case['state'][0] != NICHE:
                st.buffered_flush(case['state'])
            st.array(st.main, keys, root, lenword)
    except AllocFail:
        panic = 'alloc'
    except Exhausted:
        panic = 'next'
    return dict(out=(OK_WORD,) if panic is None else None, cap=st.main.cap, data=bytes(st.main.buf), log=st.log,
                panic=panic)


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
            m.mem[dst + k] = m.image.read(src + k, 1)[0] if src < SCRATCH_LO else m.mem[src + k]
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


def build_set(m, rng, height, maxlen, sizes=None):
    """Random B-tree set of 20-byte keys; returns (root, keys in order).  `sizes` fixes the node lengths."""
    nxt = [TREE]
    keys = []
    sizes = list(sizes) if sizes else None

    def gen(h, parent, pidx):
        a = nxt[0]
        nxt[0] += 0x400
        n = sizes.pop(0) if sizes else 1 + rng.below(maxlen)
        m.w64(a, parent)
        m.store(a + PIDX_OFF, pidx, 2)
        m.store(a + LEN_OFF, n, 2)

        def key(i):
            k = bytes(rng.below(256) for _ in range(KEY_LEN))
            m.poke(a + KEY_OFF + KEY_LEN * i, k)
            return k

        if h == 0:
            for i in range(n):
                keys.append(key(i))
            return a
        for i in range(n + 1):
            c = gen(h - 1, a, i)
            m.w64(a + EDGE_OFF + 8 * i, c)
            if i < n:
                keys.append(key(i))
        return a

    return gen(height, 0, 0), keys


def observe(m, panic):
    cap = m.r64(WR)
    ln = m.r64(WR + 0x10)
    ptr = m.r64(WR + 8)
    return dict(out=(m.r64(OUT),), cap=cap, data=m.peek(ptr, ln) if ln else b'', log=list(m.log), panic=panic)


def run_case(image, cover, cp, case, bad=None, real=None):
    """Run the original bodies of copy `cp` for one case; return (observed, expected, steps)."""
    rng = Rng(case['seed'])
    world = World(case.get('alloc_fail'))
    keep = set(v for k, v in cp.items() if k != 'copy')
    keep.add(HEXF)
    if real is not None:
        keep = real
    m = Machine(image, keep, make_stubs(world), SLOT, cover)
    write_writer(m, *case['writer'])
    keys, root, lenword = [], 0, 0
    fam = case['family']
    if fam in ('elem', 'vaddr'):
        spec = case['set']
        if spec[0] == 'tree':
            root, keys = build_set(m, rng, spec[1], spec[2], spec[4] if len(spec) > 4 else None)
            lenword = len(keys) + spec[3]
            height = spec[1]
        else:
            root, height, lenword = 0, 0, 5
        m.w64(SETP, root)
        m.w64(SETP + 8, height)
        m.w64(SETP + 0x10, lenword)
    m.w64(OUT, 0x1111)
    m.w64(OUT + 8, 0x2222)
    m.w64(OUT + 0x10, 0x3333)
    if fam == 'vaddr':
        cap, buf, count = case['state']
        m.w64(BUFP - 0x100, cap)
        m.w64(BUFP - 0x100 + 8, BUFP if cap else 1)
        m.w64(BUFP - 0x100 + 0x10, len(buf))
        m.w64(BUFP - 0x100 + 0x18, WR)
        m.store(BUFP - 0x100 + 0x20, count, 4)
        m.poke(BUFP, bytes(buf))
        m.sizes[BUFP] = cap if cap != NICHE else 0
        m.regs[7], m.regs[6], m.regs[2] = OUT, BUFP - 0x100, SETP
        entry = cp['vaddr']
    elif fam == 'name':
        m.poke(ITEM, bytes([case['tag']]) + bytes(63))
        m.regs[7], m.regs[6], m.regs[2] = OUT, ITEM, WR
        entry = cp['name']
    else:
        m.poke(ITEM, bytes([case['tag']]) + bytes(63))
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT, ITEM, SETP, WR
        entry = cp['elem']
    panic = None
    try:
        m.run(entry, 600000)
    except Panic as p:
        panic = p.args[0]
    got = observe(m, panic)
    exp = model_run(case, keys, root, lenword, bad)
    return got, exp, m.steps


def compare(got, exp):
    """None when equal, else a short reason (no raw bytes in the text)."""
    gp = got['panic']
    gk = None if gp is None else ('alloc' if gp[0] == 'alloc_error' else 'next')
    if gk != exp['panic']:
        return 'panic kind %s vs %s' % (gk, exp['panic'])
    if got['log'] != exp['log']:
        for k, (a, b) in enumerate(zip(got['log'], exp['log'])):
            if a != b:
                return 'log row %d differs' % k
        return 'log length %d vs %d' % (len(got['log']), len(exp['log']))
    if exp['panic'] is None:
        if got['out'][0] != exp['out'][0]:
            return 'result word differs'
        if got['cap'] != exp['cap']:
            return 'capacity %d vs %d' % (got['cap'], exp['cap'])
        if got['data'] != exp['data']:
            return 'output bytes differ'
    return None


# ------------------------------------------------------------------ cases

ROOMS = (0, 1, 2, 3, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 31, 32, 33, 34, 35, 40, 44, 64, 4096)
FLAGS = (0, 1, 2, 3, 0x80, 0xff)
W18 = (0, 1, 0x101, 0xffff)
W1A = (0, 1, 0x100, 0x101, 0xffff)


def rand_writer(rng, tight=False):
    pre = rng.pick((0, 0, 1, 2, 5))
    room = rng.pick(ROOMS) if tight else rng.pick(ROOMS + (4096, 4096))
    cap = 0 if (pre == 0 and room == 0 and rng.below(2)) else pre + room
    data = bytes(0x41 + rng.below(26) for _ in range(pre)) if cap else b''
    return (cap, data, rng.pick(FLAGS), rng.pick(W18), rng.pick(W1A))


def gen_cases():
    """Deterministic case stream: (family, copy index, case)."""
    seed = 1
    for ci in range(3):
        rng = Rng(900 + ci)
        for k in range(2600):
            seed += 1
            sel = rng.below(10)
            if sel < 3:
                sset = ('empty',)
            else:
                hh = rng.below(3)
                sset = ('tree', hh, 1 + rng.below(4 if (sel < 8 or hh == 2) else 11), rng.pick((0, 0, 0, 0, -1, 1)))
            c = dict(seed=seed, family='elem', tag=TAGS[k % len(TAGS)], set=sset, writer=rand_writer(rng, k % 2 == 0))
            if sset[0] == 'tree' and rng.below(40) == 0:
                c['set'] = ('tree', rng.below(2), 1 + rng.below(3), (1 << 32) + rng.below(3))
            if rng.below(7) == 0:
                c['alloc_fail'] = rng.below(5)
            yield 'elem', ci, c
        for k, sizes in enumerate(((2, 5, 4, 4), (2, 5, 5, 4), (2, 5, 5, 5), (1, 11, 3), (1, 11, 4), (1, 11, 5),
                                   (2, 11, 3, 1), (2, 1, 1, 11))):
            seed += 1
            c = dict(seed=seed, family='elem', tag=TAGS[(k * 5 + ci) % len(TAGS)], forced=True,
                     set=('tree', 1, 11, 0, sizes), writer=(0 if k % 2 else 4096, b'', 0, 0, 0))
            yield 'elem', ci, c
        for tag in TAGS:
            for room in ROOMS:
                for pre in (0, 2):
                    seed += 1
                    cap = pre + room
                    data = b'AB'[:pre]
                    c = dict(seed=seed, family='name', tag=tag, writer=(0 if cap == 0 else cap, data if cap else b'', 0, 0, 0))
                    yield 'name', ci, c
        for k in range(300):
            seed += 1
            cap = rng.pick((NICHE, NICHE, 0, 3, 8, 0x40))
            buf = bytes(rng.pick((0, 1, 0x7f, 0x80, 0xa5, 0xff)) for _ in range(rng.pick((0, 0, 1, 2, 5))))
            buf = buf if cap == NICHE else buf[:cap]
            cnt = rng.pick((0, 1, 2, 15, 16, 17, 300))
            sset = ('empty',) if rng.below(3) == 0 else ('tree', rng.below(2), 1 + rng.below(4), 0)
            c = dict(seed=seed, family='vaddr', state=(cap, buf, cnt), set=sset, writer=rand_writer(rng, True))
            if rng.below(8) == 0:
                c['alloc_fail'] = rng.below(4)
            yield 'vaddr', ci, c


def control_cases():
    """A fixed, family-spanning subset used by every control."""
    out = []
    seen = {}
    for fam, ci, case in gen_cases():
        k = seen[(fam, ci)] = seen.get((fam, ci), -1) + 1
        cap, data = case['writer'][:2]
        if fam == 'name':
            take = case['tag'] in (0, 1, 8, 9, 22) and len(data) == 0 and cap in (0, 1, 12, 13, 14, 15, 33, 64)
        elif fam == 'elem':
            take = case.get('forced') or k % 40 == 0 or (case['set'][0] == 'tree' and case['set'][3] >= (1 << 32))
        else:
            take = k % 12 == 0
        if take:
            out.append((fam, ci, case))
    return out


# ------------------------------------------------------------------ negative controls

MODEL_MUTANTS = ('name_swap', 'inner_shift', 'wrap_key', 'str8_limit', 'hdr_limit', 'hex_upper', 'hex_no_prefix',
                 'addr_reverse', 'count_minus1', 'no_pair_marker', 'reserve_min4', 'reserve_nodouble',
                 'no_memcpy_log', 'fail_index')


def mem_disp(o):
    return o[4] if o and o[0] == 'm' else None


# (name, copy index, body key, insn, predicate, bytes from the instruction end, new byte)
BYTE_CONTROLS = (
    ('elem pair marker', 0, 'elem', 'mov', lambda i: i.size == 1 and i.b == ('i', 0x92), 1, 0x93),
    ('name tag bias', 0, 'name', 'sub', lambda i: i.b == ('i', 8), 1, 0x07),
    ('name default index', 0, 'name', 'mov', lambda i: i.b == ('i', 0xf) and i.size == 4, 4, 0x0e),
    ('name registerAsset marker', 0, 'name', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xad), 1, 0xae),
    ('name room test', 0, 'name', 'cmp', lambda i: i.b == ('i', 0xc), 1, 0x0d),
    ('name string bytes', 0, 'name', 'mov', lambda i: i.b == ('i', 0x7465737341726574), 5, 0x61),
    ('name copy 2 string bytes', 1, 'name', 'mov', lambda i: i.b == ('i', 0x7465737341726574), 5, 0x61),
    ('name copy 3 marker', 2, 'name', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xad), 1, 0xae),
    ('inner key bytes', 0, 'inner', 'mov', lambda i: i.b is not None and i.b[0] == 'i' and i.b[1] > 1 << 40, 8, 0x01),
    ('address jno', 0, 'vaddr', 'jno', lambda i: True, 1, 0x70),
    ('address copy 2 jno', 1, 'vaddr', 'jno', lambda i: True, 1, 0x70),
    ('loop hex length', 0, 'loop', 'mov', lambda i: i.b == ('i', 0x2a) and i.a == ('r', 6), 4, 0x29),
    ('loop key length', 0, 'loop', 'mov', lambda i: i.b == ('i', 0x14) and i.a == ('r', 1), 4, 0x13),
    ('loop buffer size', 0, 'loop', 'mov', lambda i: i.b == ('i', 0x80) and i.a == ('r', 7), 4, 0x90),
    ('loop count shift', 0, 'loop', 'shr', lambda i: i.b == ('i', 0x20), 1, 0x21),
    ('loop copy 3 hex length', 2, 'loop', 'mov', lambda i: i.b == ('i', 0x2a) and i.a == ('r', 6), 4, 0x29),
    ('iter length offset', 0, 'iter', 'movzx', lambda i: mem_disp(i.b) == 0xe6, 4, 0xe4),
    ('iter edge base', 0, 'iter', 'add', lambda i: i.b == ('i', 0xf0), 4, 0xe8),
    ('iter key stride', 0, 'iter', 'lea', lambda i: i.b[2] is not None and i.b[3] == 4 and i.b[1] == 0, 1, 0x04),
    ('iter copy 2 remaining', 1, 'iter', 'dec', lambda i: True, 1, 0xc0),
    ('wstr str8 marker', 0, 'wstr', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xd9), 1, 0xda),
    ('header limit', 0, 'hdr', 'cmp', lambda i: i.b == ('i', 0x10) and i.size == 4, 1, 0x11),
    ('reserve minimum', 0, 'res', 'mov', lambda i: i.a == ('r', 3) and i.b == ('i', 8), 4, 0x04),
)


def find_patch(image, by_start, cp, key, mn, pred, from_end, new):
    ent = cp[key]
    hits = [i for i in linear(image, ent, by_start[ent]['end']) if i.mn == mn and pred(i)]
    if not hits:
        raise Reject('no instruction for the control at 0x%x' % ent)
    ins = hits[0]
    return {ins.va + ins.length - from_end: new}


def table_patches(image, by_start):
    """Hex digit table byte and outer jump table entries as data corruptions."""
    out = []
    hx = [i for i in linear(image, HEXF, by_start[HEXF]['end']) if i.mn == 'lea' and i.b[5]]
    if not hx:
        raise Reject('hex formatter has no table reference')
    out.append(('hex digit table', {hx[0].b[4] + 10: 0x41}))
    c = COPIES[0]
    base, entries = jump_table(image, by_start, c['name'], 16)
    out.append(('outer jump table entry', {base + 4 * 3: image.read(base + 4 * 3, 1)[0] ^ 0x10}))
    out.append(('outer jump table copy 1 last entry', {base + 4 * (len(entries) - 2): image.read(base + 4 * (len(entries) - 2), 1)[0] ^ 0x20}))
    return out


def jump_table(image, by_start, entry, count=64):
    """(table base, [target VAs]) of the first jump through a register in the body."""
    end = by_start[entry]['end']
    rows = linear(image, entry, end)
    j = [k for k, r in enumerate(rows) if r.mn == 'jmp_reg']
    if not j:
        raise Reject('no register jump in 0x%x' % entry)
    lea = [r for r in rows[:j[0]] if r.mn == 'lea' and r.b[5]][-1]
    base = lea.b[4]
    targets = []
    for k in range(count):
        off = sx(struct.unpack('<I', image.read(base + 4 * k, 4))[0], 32)
        t = base + off
        if not entry <= t < end:
            break
        targets.append(t)
    return base, targets


def run_control(image, cover, subset, patches=None, bad=None, real_drop=None):
    """A reason string when a mismatch (or a refusal) is seen: the wrong reconstruction or corrupted bytes are caught."""
    img = image if not patches else PatchedImage(image.data, patches)
    if patches:
        img.reloc = image.reloc
    for fam, ci, case in subset:
        try:
            real = None
            if real_drop:
                cp = COPIES[ci]
                real = set(v for k, v in cp.items() if k != 'copy' and k != real_drop) | {HEXF}
            got, exp, _ = run_case(img, cover, COPIES[ci], case, bad, real)
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
    ent = COPIES[0]['name']
    try:
        linear(image, ent, by_start[ent]['end'] - 1)
        rows.append(('short unwind extent', 0, 'decode landed'))
    except Reject as e:
        rows.append(('short unwind extent', 1, str(e)))
    case = dict(seed=1, family='name', tag=len(TAGS), writer=(64, b'', 0, 0, 0))
    try:
        got, exp, _ = run_case(image, set(), COPIES[0], case)
        r = compare(got, exp)
        rows.append(('tag outside the enum', int(r is not None), r or 'accepted'))
    except (Reject, Panic, KeyError, IndexError, ValueError) as e:
        rows.append(('tag outside the enum', 1, 'refused: %s' % str(e)[:60]))
    sub = [x for x in control_cases() if x[0] == 'elem'][:3]
    r = run_control(image, set(), sub, None, None, 'inner')
    rows.append(('call to an unmodelled target', int(r is not None), r or 'accepted'))
    return rows


def check_input(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


# ------------------------------------------------------------------ evidence

def tsv(header, rows):
    return '\n'.join(['\t'.join(header)] + ['\t'.join(str(c) for c in r) for r in rows]) + '\n'


def decode_name(raw):
    """Read one msgpack str (and the optional one-entry map around it) back from written bytes."""
    def one(b):
        if b[0] & 0xe0 == 0xa0:
            n = b[0] & 0x1f
            return b[1:1 + n].decode(), b[1 + n:]
        if b[0] == 0xd9:
            return b[2:2 + b[1]].decode(), b[2 + b[1]:]
        raise Reject('not a str marker')
    if raw[0] == 0x81:
        key, rest = one(raw[1:])
        val, rest = one(rest)
        return '%s.%s' % (key, val), rest
    return one(raw)


def build(data, out):
    check_input(data)
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = dict((r['start'], r) for r in recs)
    rel = image.relative_addends({HEX_SLOT})
    if HEX_SLOT not in rel or rel[HEX_SLOT][1] != HEXF:
        raise Reject('hex slot does not point at the hex formatter')
    image.reloc[HEX_SLOT] = rel[HEX_SLOT][1]
    derive_copies(image, by_start)
    cover = set()
    ins_rows, shapes, bodies = [], {}, []
    for cp in COPIES:
        for key in NEW_KEYS + DEP_KEYS:
            ent = cp[key]
            if ent not in by_start:
                raise Reject('0x%x is not an FDE start' % ent)
            rows = linear(image, ent, by_start[ent]['end'])
            bodies.append((cp['copy'], key, ent, rows))
            shapes.setdefault(key, []).append(tuple((r.mn, r.length, r.size) for r in rows))
            if key in NEW_KEYS and cp['copy'] == 1:
                for r in rows:
                    ins_rows.append((key, '0x%x' % ent, '0x%x' % r.va, r.length, r.raw.hex(), r.mn,
                                     '' if r.target is None else '0x%x' % r.target))
    rows = linear(image, HEXF, by_start[HEXF]['end'])
    bodies.append((0, 'hexf', HEXF, rows))
    for r in rows:
        ins_rows.append(('hexf', '0x%x' % HEXF, '0x%x' % r.va, r.length, r.raw.hex(), r.mn,
                         '' if r.target is None else '0x%x' % r.target))
    shape_rows = []
    for key in NEW_KEYS + DEP_KEYS:
        s = shapes[key]
        shape_rows.append((key, ROLE_TEXT[key], len(s[0]), int(s[0] == s[1]), int(s[0] == s[2])))
    # jump tables read from the bytes
    jt_rows = []
    for cp in COPIES:
        for key in ('name', 'inner'):
            base, targets = jump_table(image, by_start, cp[key], 16 if key == 'name' else 8)
            for k, tg in enumerate(targets):
                jt_rows.append((cp['copy'], key, '0x%x' % base, k, '0x%x' % tg))
    # slots used
    sites = {}
    for cp_, key, ent, rows_ in bodies:
        for r in rows_:
            if r.mn in ('call_mem', 'jmp_mem'):
                sites[r.a[4]] = sites.get(r.a[4], 0) + 1
    slot_rows = [('0x%x' % s, SLOT_NAMES.get(s, 'unmodelled (a call would be refused)'), sites[s])
                 for s in sorted(sites)]
    # name table by running the original bodies for every tag
    name_rows = []
    for cp in COPIES:
        for tag in TAGS:
            case = dict(seed=tag, family='name', tag=tag, writer=(256, b'', 0, 0, 0))
            got, exp, steps = run_case(image, cover, cp, case)
            if compare(got, exp):
                raise Reject('name table differs for tag %d' % tag)
            text, rest = decode_name(got['data'])
            if rest:
                raise Reject('trailing bytes after the name')
            name_rows.append((cp['copy'], tag, text, got['data'].hex(), steps))
    # whole case stream
    digest = hashlib.sha256()
    case_rows, counts, steps_total, total, mism = [], {}, 0, 0, 0
    for n, (fam, ci, case) in enumerate(gen_cases()):
        got, exp, steps = run_case(image, cover, COPIES[ci], case)
        r = compare(got, exp)
        total += 1
        steps_total += steps
        mism += 1 if r else 0
        counts[fam] = counts.get(fam, 0) + 1
        digest.update(('%d|%s|%d|%d|%d|%d|%d|%s' % (n, fam, ci + 1, steps, got['cap'], len(got['data']),
                                                    len(got['log']), got['panic'] is not None)).encode())
        if n % 6 == 0:
            spec = case.get('tag', case.get('state'))
            case_rows.append((n, fam, ci + 1, json.dumps(spec, default=str), json.dumps(case.get('set')),
                              json.dumps(case['writer'][:1] + (len(case['writer'][1]),) + case['writer'][2:]),
                              case.get('alloc_fail', ''), steps, len(got['data']), got['cap'], len(got['log']),
                              'ok' if not r else 'MISMATCH'))
    if mism:
        raise Reject('%d of %d cases differ from the reconstruction' % (mism, total))
    fun_rows, unexec = [], []
    for cp_, key, ent, rows_ in bodies:
        ex = sum(1 for r in rows_ if r.va in cover)
        fun_rows.append((key, cp_, '0x%x' % ent, '0x%x' % by_start[ent]['end'], by_start[ent]['end'] - ent, len(rows_), ex,
                         hashlib.sha256(image.read(ent, by_start[ent]['end'] - ent)).hexdigest()))
        if key in NEW_KEYS or key == 'hexf':
            for r in rows_:
                if r.va not in cover and r.mn != 'nop':
                    unexec.append((key, cp_, '0x%x' % ent, '0x%x' % r.va, r.mn))
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
    for name, patch in table_patches(image, by_start):
        r = run_control(image, set(), subset, patch)
        control_rows.append(('byte corruption', name, int(r is not None), r or 'NOT DETECTED'))
    for name, ok, why in range_controls(image, by_start):
        control_rows.append(('out of range input', name, ok, why))
    detected = sum(r[2] for r in control_rows)
    summary = dict(
        cases=total, case_families=dict(sorted(counts.items())), negative_controls=len(control_rows),
        negative_detected=detected, mismatches=mism, interpreted_steps=steps_total,
        all_cases_sha256=digest.hexdigest(), bodies=len(bodies), instructions=sum(len(b[3]) for b in bodies),
        executed_instructions=len(cover), unexecuted_new_instructions=len(unexec),
        outer_tags=len(TABLE_OUTER), inner_tags=len(TABLE_INNER))
    files = {
        'functions.tsv': tsv(('role', 'copy', 'entry', 'end', 'bytes', 'instructions', 'executed', 'body_sha256'), fun_rows),
        'instructions.tsv': tsv(('role', 'entry', 'va', 'length', 'raw', 'insn', 'target'), ins_rows),
        'copy-shapes.tsv': tsv(('role', 'meaning', 'instructions', 'copy2_same_shape', 'copy3_same_shape'), shape_rows),
        'jump-tables.tsv': tsv(('copy', 'table', 'base', 'index', 'target'), jt_rows),
        'name-table.tsv': tsv(('copy', 'tag', 'text', 'written_hex', 'steps'), name_rows),
        'slots.tsv': tsv(('slot', 'role', 'sites'), slot_rows),
        'unexecuted.tsv': tsv(('role', 'copy', 'entry', 'va', 'insn'), unexec),
        'cases.tsv': tsv(('id', 'family', 'copy', 'tag_or_state', 'set', 'writer', 'alloc_fail', 'steps', 'bytes', 'cap',
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
