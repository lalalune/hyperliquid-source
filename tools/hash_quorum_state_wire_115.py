#!/usr/bin/env python3
"""Reconstruct and prove the node #115 serializers of the six-field quorum record.

The record has six fields: `tracker`, `qrs`, `highest_quorum_height`, `htm`, `adu`
(an f64) and a sixth field whose key its own helper writes.  Seven struct
bodies write it: five MessagePack bodies in three copy families and two JSON
bodies.  The tool authenticates the #115 capture, finds every body by its unwind
(FDE) extent, reads the key strings and the field count from the code bytes,
and runs the original machine code in a small interpreter for the instruction
subset these bodies use (the decoder refuses anything else).  Helpers are
stubbed with recorded arguments, so the claim covers the bodies themselves:
the header choice, the key gate, field order, field offsets, argument shapes,
every error-propagation exit, the JSON depth counter, the writer reserve
checks, the separator bytes and the three panic exits.  Every interpreted
result is compared with an independent pure-Python reconstruction, and
deliberately wrong reconstructions, corrupted code bytes and out-of-range inputs
must all be caught.

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
    __slots__ = ('va', 'length', 'raw', 'op', 'w', 'size', 'reg', 'rm', 'mem', 'imm', 'target', 'ext')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


GROUP1 = {0: 'add', 1: 'or', 3: 'sbb', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}


def decode(image, va):
    """Decode one instruction of the supported subset; raise Reject otherwise."""
    if va in image.cache:
        return image.cache[va]
    raw = image.read(va, 16)
    i = 0
    opsize16 = False
    rep_f2 = False
    if raw[i] == 0x66:
        opsize16 = True
        i += 1
    elif raw[i] == 0xf2:
        rep_f2 = True
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
    if not two and op in (0x01, 0x03, 0x09, 0x0b, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85, 0x89, 0x8b, 0x88, 0x8d):
        reg, rm, _ = modrm()
        names = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
                 0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov', 0x88: 'mov', 0x8d: 'lea'}
        to_reg = op in (0x03, 0x0b, 0x2b, 0x33, 0x3b, 0x8b, 0x8d)
        if op == 0x88:
            kw['size'] = 1
            if not rex and 4 <= reg <= 7:
                raise Reject('legacy high-byte register at 0x%x' % va)
        kw.update(op=names[op], reg=reg, rm=rm, ext='to_reg' if to_reg else 'to_rm')
    elif not two and op in (0x83, 0x81, 0x80):
        reg, rm, sub = modrm()
        if sub not in GROUP1:
            raise Reject('unsupported group-1 form at 0x%x' % va)
        if op == 0x80:
            kw['size'] = 1
            if not rex and rm[0] == 'reg' and 4 <= rm[1] <= 7:
                raise Reject('legacy high-byte register at 0x%x' % va)
            v = imm(1)
        else:
            v = sx(imm(1), 8) if op == 0x83 else sx(imm(4), 32)
        kw.update(op=GROUP1[sub], rm=rm, imm=v, ext='imm')
    elif not two and op == 0xc0:
        reg, rm, sub = modrm()
        if sub != 4 or (not rex and rm[0] == 'reg' and 4 <= rm[1] <= 7):
            raise Reject('unsupported c0 form at 0x%x' % va)
        kw.update(op='shl', rm=rm, imm=imm(1), size=1)
    elif not two and 0xb8 <= op <= 0xbf:
        r = (op - 0xb8) | (rex_b << 3)
        v = imm(8) if w else imm(4)
        kw.update(op='movimm', reg=r, imm=v, size=8 if w else 4)
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
    elif not two and op == 0x63 and w:
        reg, rm, _ = modrm()
        kw.update(op='movsxd', reg=reg, rm=rm)
    elif two and op == 0x0fb6:
        reg, rm, _ = modrm()
        kw.update(op='movzx8', reg=reg, rm=rm)
    elif two and op == 0x0f95:
        reg, rm, _ = modrm()
        if not rex and rm[0] == 'reg' and 4 <= rm[1] <= 7:
            raise Reject('legacy high-byte register at 0x%x' % va)
        kw.update(op='setne', rm=rm, size=1)
    elif two and op == 0x0f57 and not opsize16:
        reg, rm, _ = modrm()
        if rm[0] != 'reg' or rm[1] != reg:
            raise Reject('unsupported xorps form at 0x%x' % va)
        kw.update(op='xorps', reg=reg, size=16)
    elif two and op in (0x0f28, 0x0f29) and not opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op == 0x0f28 else 'movups_store', reg=reg, rm=rm, size=16, ext='aligned')
    elif two and op in (0x0f10, 0x0f11) and rep_f2:
        reg, rm, _ = modrm()
        if rm[0] != 'mem':
            raise Reject('register movsd at 0x%x' % va)
        kw.update(op='movsd_load' if op == 0x0f10 else 'movsd_store', reg=reg, rm=rm, size=8)
    elif two and op in (0x0f10, 0x0f11) and not opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op == 0x0f10 else 'movups_store', reg=reg, rm=rm, size=16)
    elif not two and op == 0xf6:
        reg, rm, sub_ = modrm()
        if sub_ != 0:
            raise Reject('unsupported f6 form at 0x%x' % va)
        kw.update(op='test', rm=rm, imm=imm(1), size=1, ext='imm')
    elif not two and op in (0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0xeb):
        rel = sx(imm(1), 8)
        kw.update(op={0x74: 'je', 0x75: 'jne', 0x72: 'jb', 0x73: 'jae', 0x76: 'jbe', 0x77: 'ja', 0xeb: 'jmp'}[op])
        kw['target'] = va + i + rel
    elif two and op in (0x0f84, 0x0f85, 0x0f82, 0x0f83, 0x0f86, 0x0f87):
        rel = sx(imm(4), 32)
        kw.update(op={0x0f84: 'je', 0x0f85: 'jne', 0x0f82: 'jb', 0x0f83: 'jae', 0x0f86: 'jbe', 0x0f87: 'ja'}[op])
        kw['target'] = va + i + rel
    elif not two and op in (0xe8, 0xe9):
        rel = sx(imm(4), 32)
        kw.update(op='call' if op == 0xe8 else 'jmp')
        kw['target'] = va + i + rel
    elif not two and op == 0xff:
        reg, rm, sub = modrm()
        if sub == 0:
            kw.update(op='inc', rm=rm)
        elif sub == 2 and rm[0] == 'mem' and rm[5]:
            kw.update(op='call_ind', rm=rm)
        elif sub == 4 and rm[0] == 'reg':
            kw.update(op='jmp_reg', rm=rm)
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
        if kw['op'] == 'call_ind':
            kw['target'] = kw['rm'][4]
    ins = Insn(**kw)
    image.cache[va] = ins
    return ins


class Machine:
    """Interpreter for the decoded subset.  Flags kept: ZF and CF."""

    def __init__(self, image, stubs):
        self.image = image
        self.stubs = stubs
        self.regs = {n: 0 for n in range(16)}
        self.xmm = {n: 0 for n in range(16)}
        self.mem = {}
        self.zf = self.cf = False
        self.calls = []
        self.jumps = []
        self.log = []
        self.steps = 0

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

    def setflags(self, result, size, cf=False):
        m = (1 << (8 * size)) - 1
        self.zf = (result & m) == 0
        self.cf = cf

    def run(self, entry, limit=2000):
        self.regs[4] = STACK_TOP
        self.regs[4] -= 8
        self.store(self.regs[4], RETURN_SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.steps += 1
            nxt = pc + ins.length
            op, size = ins.op, ins.size
            m = (1 << (8 * size)) - 1
            if op in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test', 'sbb'):
                if ins.ext == 'imm':
                    a, b, dst = self.get(ins.rm, size), ins.imm & m, ins.rm
                elif ins.ext == 'to_reg':
                    a, b, dst = self.regs[ins.reg] & m, self.get(ins.rm, size), ('reg', ins.reg)
                else:
                    a, b, dst = self.get(ins.rm, size), self.regs[ins.reg] & m, ins.rm
                if op == 'add':
                    r = a + b
                    self.setflags(r, size, r > m)
                    self.put(dst, r, size)
                elif op in ('sub', 'cmp'):
                    r = (a - b) & m
                    self.setflags(r, size, a < b)
                    if op == 'sub':
                        self.put(dst, r, size)
                elif op == 'sbb':
                    c = int(self.cf)
                    r = (a - b - c) & m
                    self.setflags(r, size, a < b + c)
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
                self.put(('reg', ins.reg), u64(sx(self.get(ins.rm, 4), 32)), 8)
            elif op == 'jmp_reg':
                nxt = self.regs[ins.rm[1]]
                self.jumps.append((pc, nxt))
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), size)
            elif op == 'shl':
                r = (self.get(ins.rm, 1) << (ins.imm & 31)) & 0xff
                self.zf = r == 0
                self.put(ins.rm, r, 1)
            elif op == 'setne':
                self.put(ins.rm, 0 if self.zf else 1, 1)
            elif op == 'xorps':
                self.xmm[ins.reg] = 0
            elif op == 'movsd_load':
                self.xmm[ins.reg] = self.get(ins.rm, 8)
            elif op == 'movsd_store':
                self.store(self.ea(ins.rm), self.xmm[ins.reg] & MASK, 8)
            elif op == 'movups_load':
                self.xmm[ins.reg] = self.get(ins.rm, 16) if ins.rm[0] == 'mem' else self.xmm[ins.rm[1]]
            elif op == 'movups_store':
                if ins.rm[0] != 'mem':
                    raise Reject('register movups store at 0x%x' % pc)
                addr = self.ea(ins.rm)
                if ins.ext == 'aligned' and addr % 16:
                    raise Reject('misaligned movaps at 0x%x' % pc)
                self.store(addr, self.xmm[ins.reg], 16)
            elif op == 'inc':
                r = (self.get(ins.rm, size) + 1) & m
                self.zf = r == 0
                self.put(ins.rm, r, size)
            elif op in ('je', 'jne', 'jb', 'jae', 'jbe', 'ja'):
                take = {'je': self.zf, 'jne': not self.zf, 'jb': self.cf, 'jae': not self.cf,
                        'jbe': self.cf or self.zf, 'ja': not (self.cf or self.zf)}[op]
                if take:
                    nxt = ins.target
            elif op == 'jmp':
                nxt = ins.target
            elif op == 'push':
                self.regs[4] -= 8
                self.store(self.regs[4], self.regs[ins.reg], 8)
            elif op == 'pop':
                self.regs[ins.reg] = self.load(self.regs[4], 8)
                self.regs[4] += 8
            elif op in ('call', 'call_ind'):
                if ins.target not in self.stubs:
                    raise Reject('call to unmodelled target 0x%x at 0x%x' % (ins.target, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, ins.target, args))
                ret = self.stubs[ins.target](self, args)
                for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = 0x5c5c_5c5c_5c5c_5c5c  # caller-saved clobber
                rax, rdx = ret if isinstance(ret, tuple) else (ret, None)
                if rax is not None:
                    self.regs[0] = rax
                if rdx is not None:
                    self.regs[2] = rdx
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



# ---------------------------------------------------------------- scratch layout
IN_BASE = 0x1000_0000      # the value being serialized: words tagged with their own offset
OUT_BASE = 0x2000_0000     # three-word result slot
VEC_BASE = 0x3000_0000     # JSON writer Vec<u8>: capacity, pointer, length
SER_BASE = 0x3100_0000     # serializer object
DATA_BASE = 0x4000_0000    # bytes behind the Vec
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
WORD_TAG = 0x7777_0000_0000_0000
PATTERN = 0x1111_1111_1111_1111
NICHE = 0x8000000000000000
OK_WORD = NICHE + 4
OK2 = 2
DEPTH_INIT, FLAG_INIT = 3, 0xaa
STACK_FILL = 0x5a5a_5a5a_5a5a_5a5a
SLOT_OVERFLOW, SLOT_FMT, SLOT_ERRCTOR = 0x64df520, 0x64df730, 0x64e0b08
ERRCTOR_TOKEN = 0x0e0b_0800
FIELD_COUNT = 6
ADDITIONAL_FIELD_KEYS = (b'tracker', b'qrs', b'highest_quorum_height', b'htm', b'adu')


class Halt(Exception):
    """A stubbed panic slot was reached; the run stops there."""

    def __init__(self, slot):
        super().__init__(slot)
        self.slot = slot


class PImage(Image):
    """Image with a byte overlay, so a corrupted copy never copies the 100 MB capture."""

    def __init__(self, data, overlay=None):
        super().__init__(data)
        self.overlay = dict(overlay or {})

    def read(self, va, n):
        raw = bytearray(super().read(va, n))
        for k in range(n):
            if va + k in self.overlay:
                raw[k] = self.overlay[va + k]
        return bytes(raw)


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


def err_words(seed):
    base = 0x0e10_0000_0000_0000 + (seed << 16)
    return (base + 0xa1, base + 0xa2, base + 0xa3), (base + 0xb1, base + 0xb2)


# ---------------------------------------------------------------- bodies
# Struct with six fields: tracker, qrs, highest_quorum_height, htm, adu (f64) and a
# sixth field whose key the callee writes.  Five MessagePack bodies and two JSON bodies.
RMP_RAW = (
    dict(name='rmp-a1', entry=0x275f130, f64='ret',
         roles=dict(hdr_map=0x25e7670, hdr_arr=0x25e7940, str=0x25e8750, tracker=0x28a8c20, qrs=0x22188a0,
                    u64=0x25e9c70, htm=0x2d56af0, f64=0x25e85a0, tail=0x282e8a0)),
    dict(name='rmp-a2', entry=0x275f560, f64='ret',
         roles=dict(hdr_map=0x25e7670, hdr_arr=0x25e7940, str=0x25e8750, tracker=0x28a90f0, qrs=0x2260260,
                    u64=0x25e9c70, htm=0x2d56af0, f64=0x25e85a0, tail=0x282e8a0)),
    dict(name='rmp-b1', entry=0x4214250, f64='out',
         roles=dict(hdr_map=0x3d4f6d0, hdr_arr=0x3d50270, str=0x41c6110, tracker=0x3686090, qrs=0x41903c0,
                    u64=0x3d517e0, htm=0x3c6e8a0, f64=0x4199450, tail=0x4308e50)),
    dict(name='rmp-b2', entry=0x4214480, f64='out',
         roles=dict(hdr_map=0x3d4f6d0, hdr_arr=0x3d50270, str=0x41c6110, tracker=0x3685130, qrs=0x418f3c0,
                    u64=0x3d517e0, htm=0x3c6e8a0, f64=0x4199450, tail=0x4308e50)),
    dict(name='rmp-c1', entry=0x5af9430, f64='ret',
         roles=dict(hdr_map=0x57ce100, hdr_arr=0x57ceba0, str=0x57cf860, tracker=0x5371910, qrs=0x52e7ff0,
                    u64=0x57d00b0, htm=0x4da9220, f64=0x4e380c0, tail=0x5b6a7a0)),
)
JSON_RAW = (
    dict(name='json-a1', entry=0x275ef30, grow=0x231e050,
         roles=dict(key=0x26077c0, tracker=0x28a77d0, qrs=0x258e910, u64=0x2590810, htm=0x25b84c0,
                    adu=0x282d550, tail=0x282ccc0, end=0x282d950)),
    dict(name='json-a2', entry=0x275f360, grow=0x231e050,
         roles=dict(key=0x26077c0, tracker=0x28a9600, qrs=0x25b2340, u64=0x2590810, htm=0x25b84c0,
                    adu=0x282d550, tail=0x282c930, end=0x282d950)),
)
JSONC_RAW = (
    dict(name='json-c1', entry=0x5af9660, grow=0x5963a10,
         roles=dict(key=0x510d230, tracker=0x5371160, qrs=0x508bb70, u64=0x507d670, htm=0x509f630,
                    adu=0x5091d50, tail=0x5b67ad0, end=0x5b56530)),
)
BODIES = (tuple(dict(b, style='rmp') for b in RMP_RAW) + tuple(dict(b, style='json') for b in JSON_RAW)
          + tuple(dict(b, style='jsonc') for b in JSONC_RAW))
RMP = tuple(b for b in BODIES if b['style'] == 'rmp')
JSON = tuple(b for b in BODIES if b['style'] == 'json')
JSONC = tuple(b for b in BODIES if b['style'] == 'jsonc')
RMP_KINDS = dict(hdr_map='u64', hdr_arr='u64', str='str', tracker='rec', qrs='rec', u64='u64', htm='rec',
                 tail='rec')
# (role, key, value description) in the order the bodies serialize them.
FIELDS = (
    ('tracker', b'tracker', 'v+0x0'),
    ('qrs', b'qrs', 'v+0x48'),
    ('u64', b'highest_quorum_height', 'w+0x80'),
    ('htm', b'htm', 'v+0x60'),
    ('f64', b'adu', 'x=w+0x88'),
)
TAIL_DESC = 'v+0x90'
JSON_DESC = dict(tracker='v+0x0', qrs='v+0x48', u64='v+0x80', htm='v+0x60', adu='v+0x88', tail='v+0x90')
JSON_KEYS = dict(tracker=b'tracker', qrs=b'qrs', u64=b'highest_quorum_height', htm=b'htm')


def on_stack(x):
    return STACK_TOP - 0x1000 <= x < STACK_TOP


class Script:
    """Which counted helper call (0-based) fails, and how."""

    def __init__(self, fail_at=None, mode='rax'):
        self.fail_at, self.mode, self.counted = fail_at, mode, 0

    def next(self):
        k = self.counted
        self.counted += 1
        return self.mode if k == self.fail_at else None


def desc_value(p):
    if not IN_BASE <= p < IN_BASE + 0x200:
        raise Reject('value pointer 0x%x is outside the input block' % p)
    return 'v+0x%x' % (p - IN_BASE)


def desc_word(x):
    if x >> 48 != WORD_TAG >> 48:
        raise Reject('word 0x%x is not a tagged input word' % x)
    return 'w+0x%x' % (x & 0xffff)


# ---------------------------------------------------------------- stubs: MessagePack bodies
def rmp_stubs(body, script, seed):
    err3, err2 = err_words(seed)
    f64form = body['f64']

    def mk(role):
        kind = RMP_KINDS.get(role, 'f64')

        def stub(m, args):
            if role in ('hdr_map', 'hdr_arr'):
                out, ser, n = args[0], args[1], args[2]
                if ser != SER_BASE or not on_stack(out):
                    raise Reject('header helper argument shape differs')
                desc = ('n=%d' % n,)
            elif role == 'str':
                ser, key, n = args[0], args[1], args[2]
                if ser != SER_BASE:
                    raise Reject('str helper does not receive the serializer first')
                desc = ('key:' + image_of(m).read(key, n).decode('ascii'),)
            elif role in ('tracker', 'htm'):
                out, value, ser = args[0], args[1], args[2]
                if ser != SER_BASE or not on_stack(out):
                    raise Reject('%s helper argument shape differs' % role)
                desc = (desc_value(value),)
            elif role in ('qrs', 'tail'):
                out, ser, value = args[0], args[1], args[2]
                if ser != SER_BASE or not on_stack(out):
                    raise Reject('%s helper argument shape differs' % role)
                desc = (desc_value(value),)
            elif role == 'u64':
                out, ser, value = args[0], args[1], args[2]
                if ser != SER_BASE or not on_stack(out):
                    raise Reject('u64 helper argument shape differs')
                desc = (desc_word(value),)
            else:  # f64
                if f64form == 'ret':
                    ser = args[0]
                    out = None
                else:
                    out, ser = args[0], args[1]
                    if not on_stack(out):
                        raise Reject('f64 helper output is not on the stack')
                if ser != SER_BASE:
                    raise Reject('f64 helper does not receive the serializer')
                desc = ('x=' + desc_word(m.xmm[0]),)
            m.log.append(('call', role, desc))
            fail = script.next()
            if kind == 'str' or (role == 'f64' and f64form == 'ret'):
                return err2 if fail else (OK2, None)
            if kind == 'u64':
                if fail:
                    m.store(out, err3[0], 8)
                    m.store(out + 8, err3[1], 8)
                else:
                    m.store(out, OK2, 8)
                return 0
            if fail:
                for k in range(3):
                    m.store(out + 8 * k, err3[k], 8)
            else:
                m.store(out, OK_WORD, 8)
            return 0
        return stub

    stubs = {}
    for role, target in body['roles'].items():
        stubs[target] = mk(role if role != 'f64' else 'f64')
    return stubs


def image_of(m):
    return m.image


# ---------------------------------------------------------------- stubs: JSON bodies
def json_stubs(body, script):
    k_key = [0]

    def grow(m, args):
        vec, length, additional, align, elem = args
        if vec != VEC_BASE or (align, elem) != (1, 1):
            raise Reject('unexpected grow call arguments')
        cap = m.load(vec, 8)
        if length != m.load(vec + 16, 8):
            raise Reject('grow length differs from the writer length')
        m.store(vec, max(cap * 2, length + additional, 8), 8)
        m.log.append(('grow', length, additional))
        return 0

    def state_byte(m, state, mode):
        if not on_stack(state):
            raise Reject('compound state is not on the stack')
        m.store(state, 1 if mode == 'state' else 0, 1)
        if mode == 'closed':
            m.store(state + 1, 0, 1)

    def key_stub(m, args):
        state, key, n = args[0], args[1], args[2]
        text = m.image.read(key, n).decode('ascii')
        m.log.append(('call', 'key', ('key:' + text,)))
        state_byte(m, state, script.next())
        return 0

    def value_first(role):  # (value, serializer) -> error pointer
        def stub(m, args):
            if args[1] != SER_BASE:
                raise Reject('%s helper does not receive the serializer second' % role)
            m.log.append(('call', role, (desc_value(args[0]),)))
            return 0x0e77_0000 + m.steps if script.next() == 'rax' else 0
        return stub

    def keyed(role):  # (state, key, len, value) -> error pointer, state byte
        def stub(m, args):
            state, key, n, value = args[0], args[1], args[2], args[3]
            text = m.image.read(key, n).decode('ascii')
            m.log.append(('call', role, ('key:' + text, desc_value(value))))
            mode = script.next()
            state_byte(m, state, mode)
            return 0x0e77_0000 + m.steps if mode == 'rax' else 0
        return stub

    def plain(role, sets_state=False):  # (state, value) -> error pointer
        def stub(m, args):
            state, value = args[0], args[1]
            if not on_stack(state):
                raise Reject('compound state is not on the stack')
            m.log.append(('call', role, (desc_value(value),)))
            mode = script.next()
            if sets_state:
                state_byte(m, state, mode)
            return 0x0e77_0000 + m.steps if mode == 'rax' else 0
        return stub

    def end_stub(m, args):
        if body['style'] == 'jsonc':
            if (args[0], args[1]) != (SER_BASE + 8, VEC_BASE):
                raise Reject('end helper arguments differ')
            m.log.append(('call', 'end', ('ser+8', 'vec')))
            return 0
        if not on_stack(args[0]):
            raise Reject('end state is not on the stack')
        m.log.append(('call', 'end', ()))
        return 0

    def panic(slot):
        def stub(m, args):
            raise Halt(slot)
        return stub

    def errctor(m, args):
        m.log.append(('call', 'errctor', ()))
        return ERRCTOR_TOKEN

    r = body['roles']
    adu = keyed('adu') if body['style'] == 'jsonc' else plain('adu')
    return {body['grow']: grow, r['key']: key_stub, r['tracker']: value_first('tracker'),
            r['qrs']: keyed('qrs'), r['u64']: keyed('u64'), r['htm']: keyed('htm'), r['adu']: adu,
            r['tail']: plain('tail', body['style'] == 'jsonc'), r['end']: end_stub, SLOT_OVERFLOW: panic(SLOT_OVERFLOW),
            SLOT_FMT: panic(SLOT_FMT), SLOT_ERRCTOR: errctor}


# ---------------------------------------------------------------- reconstruction
def recon_rmp(body, flag, fail_at, seed, v=None):
    """Pure model of one MessagePack struct body: (call log, three result words)."""
    v = v or {}
    err3, err2 = err_words(seed)
    log, counter = [], [0]
    f64form = body['f64']

    def call(role, desc, kind):
        log.append(('call', role, desc))
        k = counter[0]
        counter[0] += 1
        if k != fail_at:
            return None
        if kind == 'str':
            return (NICHE,) + err2
        if kind == 'u64':
            return v.get('err_u64', (NICHE, err3[0], err3[1]))
        return err3

    keys_when = v.get('keys_when', lambda f: f == 1)
    count = v.get('count', FIELD_COUNT)
    use_map = v.get('use_map', lambda f: f != 0)
    err = call('hdr_map' if use_map(flag) else 'hdr_arr', ('n=%d' % count,), 'u64')
    if err:
        return log, err
    fields = list(v.get('fields', FIELDS))
    for role, key, desc in fields:
        kind = {'tracker': 'rec', 'qrs': 'rec', 'u64': 'u64', 'htm': 'rec'}.get(role)
        if role == 'f64':
            kind = 'str' if f64form == 'ret' else 'rec'
            if v.get('f64_rec_error') and kind == 'str':
                kind = 'rec'
        if keys_when(flag):
            err = call('str', ('key:' + key.decode(),), 'str')
            if err:
                return log, err
        err = call(role, (desc,), kind)
        if err:
            return log, err
    if v.get('tail_key') and keys_when(flag):
        err = call('str', ('key:tail',), 'str')
        if err:
            return log, err
    err = call('tail', (v.get('tail_desc', TAIL_DESC),), 'rec')
    if err:
        return log, err
    return log, v.get('ok', (OK_WORD, PATTERN, PATTERN))


def recon_json(body, depth, cap, length, fail_at, mode, v=None):
    """Pure model of one JSON struct body.

    Returns (result tag, call log, appended bytes, end length, depth word, flag byte)."""
    v = v or {}
    log = []
    counter = [0]
    appended = bytearray()
    state = dict(cap=cap, len=length, depth=depth, flag=FLAG_INIT)

    def count():
        k = counter[0]
        counter[0] += 1
        return mode if k == fail_at else None

    def final(tag):
        return (tag, log, bytes(appended), state['len'], state['depth'], state['flag'])

    def reserve(n, short):
        if short:
            log.append(('grow', state['len'], n))
            state['cap'] = max(state['cap'] * 2, state['len'] + n, 8)

    if depth == MASK and not v.get('no_overflow_check'):
        return final(('panic', SLOT_OVERFLOW))
    if not v.get('depth_not_stored'):
        state['depth'] = (depth + 1) & MASK
    if not v.get('flag_kept'):
        state['flag'] = 0
    reserve(1, state['cap'] == state['len'])
    appended.append(v.get('open_byte', 0x7b))
    state['len'] += 1
    log.append(('call', 'key', ('key:tracker',)))
    m0 = count()
    if m0 == 'state' and not v.get('first_key_state_ignored'):
        return final(('panic', SLOT_FMT))
    sep = v.get('separator', b': ')
    reserve(len(sep), state['cap'] - state['len'] <= v.get('reserve_slack', 1))
    appended += sep
    state['len'] += len(sep)
    log.append(('call', 'tracker', ('v+0x0',)))
    if count() == 'rax':
        return final(('rax', 'call'))
    state['flag'] = 1
    for role in ('qrs', 'u64', 'htm'):
        log.append(('call', role, ('key:' + JSON_KEYS[role].decode(), JSON_DESC[role])))
        m = count()
        if m == 'rax':
            return final(('rax', 'call'))
        if m == 'state' and (role in ('qrs', 'u64') or (role == 'htm' and v.get('htm_state_checked'))) and not (role == 'qrs' and v.get('qrs_state_ignored')):
            log.append(('call', 'errctor', ()))
            return final(('rax', 'errctor'))
    log.append(('call', 'adu', (JSON_DESC['adu'],)))
    if count() == 'rax':
        return final(('rax', 'call'))
    log.append(('call', 'tail', (JSON_DESC['tail'],)))
    if count() == 'rax':
        return final(('rax', 'call'))
    if not v.get('end_missing'):
        log.append(('call', 'end', ()))
    return final(('ok', 0))


def recon_jsonc(body, depth, cap, length, fail_at, mode, v=None):
    """Pure model of the third-family JSON body (keyed adu helper, state bytes, conditional end call)."""
    v = v or {}
    log = []
    counter = [0]
    appended = bytearray()
    state = dict(cap=cap, len=length, depth=depth, flag=FLAG_INIT)

    def count():
        k = counter[0]
        counter[0] += 1
        return mode if k == fail_at else None

    def final(tag):
        return (tag, log, bytes(appended), state['len'], state['depth'], state['flag'])

    def reserve(n, short):
        if short:
            log.append(('grow', state['len'], n))
            state['cap'] = max(state['cap'] * 2, state['len'] + n, 8)

    if depth == MASK:
        return final(('panic', SLOT_OVERFLOW))
    state['depth'] = (depth + 1) & MASK
    state['flag'] = 0
    reserve(1, state['cap'] == state['len'])
    appended.append(0x7b)
    state['len'] += 1
    log.append(('call', 'key', ('key:tracker',)))
    m0 = count()
    if m0 == 'state':
        return final(('panic', SLOT_FMT))
    reserve(2, state['cap'] - state['len'] <= 1)
    appended += b': '
    state['len'] += 2
    log.append(('call', 'tracker', ('v+0x0',)))
    if count() == 'rax':
        return final(('rax', 'call'))
    state['flag'] = 1
    st0, st1 = 0, 1
    for role, key in (('qrs', b'qrs'), ('u64', b'highest_quorum_height'), ('htm', b'htm'), ('adu', b'adu')):
        log.append(('call', role, ('key:' + key.decode(), JSON_DESC[role])))
        m = count()
        if m == 'rax':
            return final(('rax', 'call'))
        st0 = 1 if m == 'state' else 0
        if role != 'adu' and st0 or (role == 'adu' and v.get('adu_state_checked') and st0):
            log.append(('call', 'errctor', ()))
            return final(('rax', 'errctor'))
    log.append(('call', 'tail', (JSON_DESC['tail'],)))
    m = count()
    if m == 'rax':
        return final(('rax', 'call'))
    st0 = 1 if m == 'state' else 0
    st1 = 0 if m == 'closed' else 1
    call_end = (not st0) and st1
    if v.get('end_always'):
        call_end = True
    if v.get('end_never'):
        call_end = False
    if v.get('end_ignores_closed'):
        call_end = not st0
    if call_end:
        log.append(('call', 'end', ('ser+8', 'vec')))
    return final(('ok', 0))


def recon_j(body, depth, cap, length, fail_at, mode, v=None):
    if body['style'] == 'jsonc':
        return recon_jsonc(body, depth, cap, length, fail_at, mode, v)
    return recon_json(body, depth, cap, length, fail_at, mode, v)


def run_j(image, body, depth, cap, length, fail_at, mode):
    return run_json(image, body, depth, cap, length, fail_at, mode)


# Deliberately wrong reconstructions (negative controls).
WRONG_RMP = {
    'keys_when_flag_nonzero': dict(keys_when=lambda f: f != 0),
    'keys_when_flag_zero': dict(keys_when=lambda f: f == 0),
    'array_header_for_flag_one': dict(use_map=lambda f: f == 0),
    'map_header_only_for_flag_one': dict(use_map=lambda f: f == 1),
    'field_count_five': dict(count=5),
    'field_count_seven': dict(count=7),
    'u64_error_copies_three_words': dict(err_u64=err_words(0)[0]),
    'success_writes_zero_tail': dict(ok=(OK_WORD, 0, 0)),
    'tail_key_written': dict(tail_key=True),
    'tail_offset_0x88': dict(tail_desc='v+0x88'),
    'tracker_qrs_swapped': dict(fields=(FIELDS[1], FIELDS[0]) + FIELDS[2:]),
    'htm_before_u64': dict(fields=FIELDS[:2] + (FIELDS[3], FIELDS[2]) + FIELDS[4:]),
    'u64_value_offset_0x88': dict(fields=FIELDS[:2] + (('u64', b'highest_quorum_height', 'w+0x88'),) + FIELDS[3:]),
    'htm_key_is_qrs': dict(fields=FIELDS[:3] + (('htm', b'qrs', 'v+0x60'),) + FIELDS[4:]),
    'f64_without_key': dict(fields=FIELDS[:4] + (('f64', b'ad', 'x=w+0x88'),)),
    'adu_reads_0x80': dict(fields=FIELDS[:4] + (('f64', b'adu', 'x=w+0x80'),)),
}
WRONG_JSON = {
    'open_bracket': dict(open_byte=0x5b),
    'separator_comma': dict(separator=b', '),
    'separator_colon_only': dict(separator=b':'),
    'depth_not_stored': dict(depth_not_stored=True),
    'flag_kept': dict(flag_kept=True),
    'no_overflow_check': dict(no_overflow_check=True),
    'reserve_slack_zero': dict(reserve_slack=0),
    'reserve_slack_two': dict(reserve_slack=2),
    'end_missing': dict(end_missing=True),
    'first_key_state_ignored': dict(first_key_state_ignored=True),
    'qrs_state_ignored': dict(qrs_state_ignored=True),
    'htm_state_checked': dict(htm_state_checked=True),
}

WRONG_JSONC = {
    'adu_state_checked': dict(adu_state_checked=True),
    'end_always': dict(end_always=True),
    'end_never': dict(end_never=True),
    'end_ignores_closed_byte': dict(end_ignores_closed=True),
}


# ---------------------------------------------------------------- drivers
SEEDS = 40
RMP_FLAGS = (0, 1, 2, 0xff)
JSON_DEPTHS = (0, 3, MASK - 1, MASK)
JSON_LENGTHS = (0, 7, 300)
JSON_SLACKS = tuple(range(10))
JSON_FAILS = ((None, 'rax'), (0, 'state')) + tuple((k, 'rax') for k in range(1, 7)) + ((2, 'state'), (3, 'state'), (4, 'state'))


JSONC_FAILS = ((None, 'rax'), (0, 'state')) + tuple((k, 'rax') for k in range(1, 7)) + tuple(
    (k, 'state') for k in range(2, 7)) + ((6, 'closed'),)


def rmp_inputs(seeds=SEEDS):
    for seed in range(seeds):
        for flag in RMP_FLAGS:
            n = len(recon_rmp(RMP[0], flag, None, seed)[0])
            for fail_at in [None] + list(range(n)):
                yield flag, fail_at, seed


def json_inputs(style='json'):
    fails = JSONC_FAILS if style == 'jsonc' else JSON_FAILS
    for depth in JSON_DEPTHS:
        for length in JSON_LENGTHS:
            for slack in JSON_SLACKS:
                for fail_at, mode in fails:
                    yield depth, length + slack, length, fail_at, mode


def run_rmp(image, body, flag, fail_at, seed):
    script = Script(fail_at)
    m = Machine(image, rmp_stubs(body, script, seed))
    for k in range(3):
        m.store(OUT_BASE + 8 * k, PATTERN, 8)
    for off in range(0, 0x140, 8):
        m.store(IN_BASE + off, WORD_TAG | off, 8)
    m.store(SER_BASE + 0xb, flag, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, SER_BASE
    m.xmm[0] = 0
    m.run(body['entry'])
    if m.regs[0] != OUT_BASE:
        raise Reject('body 0x%x does not return its output pointer' % body['entry'])
    return m.log, tuple(m.load(OUT_BASE + 8 * k, 8) for k in range(3))


def run_json(image, body, depth, cap, length, fail_at, mode):
    script = Script(fail_at, mode)
    m = Machine(image, json_stubs(body, script))
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, length, 8)
    m.store(SER_BASE, VEC_BASE, 8)
    m.store(SER_BASE + 0x18, depth, 8)
    m.store(SER_BASE + 0x20, FLAG_INIT, 1)
    m.regs[7], m.regs[6] = IN_BASE, SER_BASE
    for off in range(0x200, 8, -8):  # padding bytes of the 16-byte state copy are never defined by the body
        m.store(STACK_TOP - off, STACK_FILL, 8)
    tag = None
    try:
        m.run(body['entry'])
        rax = m.regs[0]
        if rax == 0:
            tag = ('ok', 0)
        elif rax == ERRCTOR_TOKEN:
            tag = ('rax', 'errctor')
        elif 0x0e77_0000 <= rax < 0x0e78_0000:
            tag = ('rax', 'call')
        else:
            raise Reject('unexpected return value 0x%x' % rax)
    except Halt as h:
        tag = ('panic', h.slot)
    end = m.load(VEC_BASE + 16, 8)
    data = bytes(m.load(DATA_BASE + k, 1) for k in range(length, end))
    return tag, m.log, data, end, m.load(SER_BASE + 0x18, 8), m.load(SER_BASE + 0x20, 1)


def fmt_log(log):
    parts = []
    for e in log:
        if e[0] == 'grow':
            parts.append('grow(%d,+%d)' % (e[1], e[2]))
        else:
            parts.append('%s(%s)' % (e[1], ','.join(e[2])))
    return ' '.join(parts)


def fmt_tag(tag):
    return ':'.join(str(x) if not isinstance(x, int) else '0x%x' % x for x in tag)


# ---------------------------------------------------------------- static facts from the bytes
def body_rows(image, by_start, body):
    va = body['entry']
    if va not in by_start:
        raise Reject('0x%x is not an FDE start' % va)
    return linear(image, va, by_start[va]['end'])


def static_checks(image, body, rows):
    """Cross-check the declared role table and constants against the decoded body."""
    r = body['roles']
    declared = set(r.values())
    if body['style'] in ('json', 'jsonc'):
        declared |= {body['grow'], SLOT_OVERFLOW, SLOT_FMT, SLOT_ERRCTOR}
    targets = set(x.target for x in rows if x.op in ('call', 'call_ind'))
    if targets != declared:
        raise Reject('call targets of 0x%x differ from the role table' % body['entry'])
    keys = [x[5].encode() for x in key_rows(image, body, rows)]
    if body['style'] in ('rmp', 'jsonc'):
        want = list(ADDITIONAL_FIELD_KEYS)
    else:
        want = list(ADDITIONAL_FIELD_KEYS[:4])
    if keys != want:
        raise Reject('key table of 0x%x differs: %r' % (body['entry'], keys))
    if body['style'] == 'rmp':
        counts = [x.imm for k, x in enumerate(rows) if x.op == 'movimm' and x.reg == 2 and x.imm == FIELD_COUNT
                  and k + 3 < len(rows) and rows[k + 1].op == 'call']
        if len(counts) != 2:
            raise Reject('expected two header calls with the field count in 0x%x' % body['entry'])
    return keys


def key_rows(image, body, rows):
    out = []
    for k, ins in enumerate(rows):
        if ins.op == 'lea' and ins.rm[5] and ins.reg == 6:
            for nxt in rows[k + 1:k + 4]:
                if nxt.op == 'movimm' and nxt.reg == 2:
                    out.append((body['name'], '0x%x' % body['entry'], '0x%x' % ins.va, '0x%x' % ins.rm[4], nxt.imm,
                                image.read(ins.rm[4], nxt.imm).decode('ascii')))
                    break
    return out


HELPER_KEYS = (
    ('rmp-tail', 0x282e8a0, b'h'), ('rmp-tail', 0x4308e50, b'h'), ('rmp-tail', 0x5b6a7a0, b'h'),
    ('json-tail', 0x282ccc0, b'h'), ('json-tail', 0x282c930, b'h'), ('json-adu', 0x282d550, b'adu'),
)


def first_key(image, by_start, entry):
    """First `lea rsi,[rip+disp]` followed by `mov edx,imm32` in the body of a helper, found by byte pattern."""
    if entry not in by_start:
        raise Reject('0x%x is not an FDE start' % entry)
    end = by_start[entry]['end']
    code = image.read(entry, end - entry)
    pos = 0
    while True:
        pos = code.find(b'\x48\x8d\x35', pos)
        if pos < 0 or pos + 7 > len(code):
            raise Reject('no key load in the helper at 0x%x' % entry)
        disp = struct.unpack_from('<i', code, pos + 3)[0]
        va = entry + pos + 7 + disp
        rest = code[pos + 7:pos + 7 + 14]
        for k in range(len(rest) - 4):
            if rest[k] == 0xba:
                n = struct.unpack_from('<I', rest, k + 1)[0]
                if 0 < n < 64:
                    return entry + pos, va, image.read(va, n)
        pos += 1


# ---------------------------------------------------------------- byte-corruption controls
def corruption_sites(rows, style):
    """Fixed-pattern sites: (kind, va, offset in instruction, new byte)."""
    sites = []
    for ins in rows:
        raw = ins.raw
        if ins.op == 'movimm' and ins.reg == 2 and len(raw) == 5 and ins.imm in (3, 6, 7, 0x15):
            sites.append(('key-length-immediate', ins.va, 1, (raw[1] + 1) & 0xff))
        elif ins.op == 'lea' and not ins.rm[5] and ins.rm[1] in (14, 3) and ins.rm[4] in (0x48, 0x60, 0x80, 0x88, 0x90):
            at = len(raw) - 1 if -128 <= ins.rm[4] < 128 else len(raw) - 4
            sites.append(('field-offset-displacement', ins.va, at, (raw[at] + 8) & 0xff))
        elif ins.op == 'movsd_load':
            at = len(raw) - 1 if -128 <= ins.rm[4] < 128 else len(raw) - 4
            sites.append(('f64-offset-displacement', ins.va, at, (raw[at] ^ 0x08) & 0xff))
        elif ins.op == 'cmp' and ins.ext == 'imm' and ins.size == 1 and ins.imm in (0, 1):
            sites.append(('flag-compare-immediate', ins.va, len(raw) - 1, ins.imm ^ 1))
        elif ins.op in ('je', 'jne') and len(raw) == 2:
            sites.append(('branch-polarity', ins.va, 0, raw[0] ^ 1))
        elif ins.op == 'mov' and ins.ext == 'imm' and ins.size == 1 and ins.imm == 0x7b:
            sites.append(('open-brace-byte', ins.va, len(raw) - 1, 0x5b))
        elif ins.op == 'mov' and ins.ext == 'imm' and ins.size == 2 and ins.imm == 0x203a:
            sites.append(('separator-bytes', ins.va, len(raw) - 2, 0x2c))
        elif ins.op == 'call':
            sites.append(('call-target', ins.va, 1, (raw[1] + 0x10) & 0xff))
    return sites


def pick_sites(rows, style, per_kind=1):
    seen, out = {}, []
    for s in corruption_sites(rows, style):
        if seen.get(s[0], 0) < per_kind:
            seen[s[0]] = seen.get(s[0], 0) + 1
            out.append(s)
    return out


def control_inputs(style):
    if style == 'rmp':
        return [(f, k, s) for f, k, s in rmp_inputs(3)]
    return [x for i, x in enumerate(json_inputs(style)) if i % 7 == 0]


def corrupted_detected(data, body, site):
    kind, va, off, new = site
    image = PImage(data, {va + off: new})
    try:
        for inp in control_inputs(body['style']):
            if body['style'] == 'rmp':
                flag, fail_at, seed = inp
                got = run_rmp(image, body, flag, fail_at, seed)
                if got != recon_rmp(body, flag, fail_at, seed):
                    return True
            else:
                depth, cap, length, fail_at, mode = inp
                got = run_json(image, body, depth, cap, length, fail_at, mode)
                if got != recon_j(body, depth, cap, length, fail_at, mode):
                    return True
    except (Reject, Halt, IndexError, KeyError, ValueError):
        return True
    return False


def range_controls(data, image, by_start):
    """Inputs outside the claimed range must be refused."""
    rows = []

    def refuses(fn):
        try:
            fn()
        except Reject:
            return True
        return False

    bad = bytearray(data[:4096])
    bad[100] ^= 1
    rows.append(('digest-of-a-tampered-input', refuses(lambda: check_digest(bytes(bad)))))
    rows.append(('digest-of-an-empty-input', refuses(lambda: check_digest(b''))))
    rows.append(('entry-one-byte-inside-a-body', refuses(lambda: body_rows(image, by_start, dict(entry=RMP[0]['entry'] + 1)))))
    rows.append(('entry-not-an-fde', refuses(lambda: body_rows(image, by_start, dict(entry=0x10)))))
    rows.append(('read-below-first-section', refuses(lambda: image.read(0x10, 4))))
    rows.append(('read-beyond-last-section', refuses(lambda: image.read(0x7000_0000_0000, 4))))
    m = Machine(image, {})
    rows.append(('store-outside-scratch', refuses(lambda: m.store(0x10, 1, 8))))
    rows.append(('load-of-unset-scratch-byte', refuses(lambda: m.load(0x5000_0000, 1))))
    body = RMP[0]
    def unmodelled():
        mm = Machine(image, {})
        mm.store(SER_BASE + 0xb, 1, 1)
        mm.regs[7], mm.regs[6], mm.regs[2] = OUT_BASE, IN_BASE, SER_BASE
        mm.run(body['entry'])

    rows.append(('call-to-unmodelled-target', refuses(unmodelled)))
    rows.append(('step-limit-reached', refuses(lambda: Machine(image, rmp_stubs(body, Script(None), 0)).run(
        body['entry'], limit=5))))
    return rows


# ---------------------------------------------------------------- build
def build(data, seeds=SEEDS):
    check_digest(data)
    image = PImage(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows, role_rows, keyrows = [], [], [], []
    bodies = {}
    for body in BODIES:
        rows = body_rows(image, by_start, body)
        bodies[body['entry']] = rows
        static_checks(image, body, rows)
        raw = image.read(body['entry'], by_start[body['entry']]['end'] - body['entry'])
        functions.append((body['name'], body['style'], '0x%x' % body['entry'], '0x%x' % by_start[body['entry']]['end'],
                          len(raw), len(rows), hashlib.sha256(raw).hexdigest(),
                          sum(1 for x in rows if x.op in ('call', 'call_ind'))))
        for x in rows:
            insn_rows.append((body['name'], '0x%x' % body['entry'], '0x%x' % x.va, x.length, x.raw.hex(), x.op,
                              '' if x.target is None else '0x%x' % x.target))
        sites = {}
        for x in rows:
            if x.op in ('call', 'call_ind'):
                sites[x.target] = sites.get(x.target, 0) + 1
        extra = {}
        if body['style'] in ('json', 'jsonc'):
            extra = dict(grow=body['grow'], overflow_panic=SLOT_OVERFLOW, fmt_panic=SLOT_FMT, error_ctor=SLOT_ERRCTOR)
        for role, target in sorted(list(body['roles'].items()) + list(extra.items())):
            role_rows.append((body['name'], '0x%x' % body['entry'], role, '0x%x' % target, sites[target]))
        keyrows += key_rows(image, body, rows)

    helper_rows = []
    for role, entry, want in HELPER_KEYS:
        lea_va, pool_va, key = first_key(image, by_start, entry)
        if key != want:
            raise Reject('helper 0x%x key is %r' % (entry, key))
        helper_rows.append((role, '0x%x' % entry, '0x%x' % lea_va, '0x%x' % pool_va, len(key), key.decode('ascii')))

    cases, mismatches, paths = [], 0, {}
    digest = hashlib.sha256()
    total = 0
    for i, row in enumerate(collect(image, seeds)):
        total += 1
        digest.update(('\t'.join(str(x) for x in row) + '\n').encode())
        mismatches += row[-1] != 'match'
        if i % SAMPLE == 0 or row[-1] != 'match':
            cases.append(row)
        p = paths.setdefault((row[0], row[3].split('/')[0]), [0, set()])
        p[0] += 1
        p[1].add(row[1])

    negatives = []
    for name in sorted(WRONG_RMP):
        caught, first = 0, ''
        for body in RMP:
            for flag, fail_at, seed in rmp_inputs(3):
                if recon_rmp(body, flag, fail_at, seed) != recon_rmp(body, flag, fail_at, seed, WRONG_RMP[name]):
                    caught += 1
                    first = first or '%s flag=%d fail=%s' % (body['name'], flag, fail_at)
        negatives.append(('reconstruction', name, caught, first))
    for name in sorted(WRONG_JSON):
        caught, first = 0, ''
        for body in JSON:
            for depth, cap, length, fail_at, mode in json_inputs():
                if recon_json(body, depth, cap, length, fail_at, mode) != recon_json(body, depth, cap, length, fail_at, mode, WRONG_JSON[name]):
                    caught += 1
                    first = first or '%s depth=0x%x cap=%d len=%d fail=%s' % (body['name'], depth, cap, length, fail_at)
        negatives.append(('reconstruction', name, caught, first))
    for name in sorted(WRONG_JSONC):
        caught, first = 0, ''
        for body in JSONC:
            for depth, cap, length, fail_at, mode in json_inputs('jsonc'):
                if recon_jsonc(body, depth, cap, length, fail_at, mode) != recon_jsonc(body, depth, cap, length, fail_at, mode, WRONG_JSONC[name]):
                    caught += 1
                    first = first or '%s depth=0x%x cap=%d len=%d fail=%s' % (body['name'], depth, cap, length, fail_at)
        negatives.append(('reconstruction', name, caught, first))
    for body in BODIES:
        for site in pick_sites(bodies[body['entry']], body['style']):
            det = corrupted_detected(data, body, site)
            negatives.append(('corrupted-byte', '%s %s at 0x%x+%d' % (body['name'], site[0], site[1], site[2]),
                              int(det), ''))
    for name, ok in range_controls(data, image, by_start):
        negatives.append(('out-of-range', name, int(ok), ''))

    detected = sum(1 for n in negatives if n[2])
    summary = dict(
        target='artifacts/node/115/hl-node', sha256=SHA115, bodies=len(BODIES),
        msgpack_bodies=len(RMP), json_bodies=len(JSON) + len(JSONC), cases=total, mismatches=mismatches,
        case_stream_sha256=digest.hexdigest(), case_rows_listed=len(cases),
        negative_controls=len(negatives), negative_detected=detected,
        decoded_instructions=len(insn_rows), field_count=FIELD_COUNT,
        keys=[k.decode() for k in ADDITIONAL_FIELD_KEYS], sixth_field_key='h')
    path_rows = [(k[0], k[1], v[0], ','.join(str(x) for x in sorted(v[1], key=str))) for k, v in sorted(paths.items())]
    return dict(summary=summary, functions=functions, instructions=insn_rows, roles=role_rows, keys=keyrows,
                helper_keys=helper_rows,
                cases=cases, negatives=negatives, paths=path_rows)


SAMPLE = 3


def collect(image, seeds):
    """The full case stream, one row at a time."""
    for body in BODIES:
        if body['style'] == 'rmp':
            for flag, fail_at, seed in rmp_inputs(seeds):
                log, res = run_rmp(image, body, flag, fail_at, seed)
                exp = recon_rmp(body, flag, fail_at, seed)
                yield (body['name'], flag, seed, 'ok' if fail_at is None else 'fail=%d' % fail_at, fmt_log(log),
                       ','.join('0x%x' % x for x in res), 'match' if (log, res) == exp else 'MISMATCH')
        else:
            for depth, cap, length, fail_at, mode in json_inputs(body['style']):
                got = run_json(image, body, depth, cap, length, fail_at, mode)
                exp = recon_j(body, depth, cap, length, fail_at, mode)
                outcome = fmt_tag(got[0]) + ('' if fail_at is None else '/fail=%d-%s' % (fail_at, mode))
                yield (body['name'], '0x%x' % depth, '%d+%d' % (length, cap - length), outcome, fmt_log(got[1]),
                       '%s,end=%d,depth=0x%x,flag=%d' % (got[2].hex(), got[3], got[4], got[5]),
                       'match' if got == exp else 'MISMATCH')


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(x) for x in r) + '\n' for r in rows)


def render(result):
    s = result['summary']
    measure = dict(cases=s['cases'], negative_controls=s['negative_controls'],
                   negative_detected=s['negative_detected'], mismatches=s['mismatches'])
    return {
        'summary.json': json.dumps(s, indent=2, sort_keys=True) + '\n',
        'measure.json': json.dumps(measure, indent=2, sort_keys=True) + '\n',
        'functions.tsv': tsv(('body', 'style', 'entry', 'fde_end', 'fde_bytes', 'decoded_instructions', 'sha256',
                              'call_sites'), result['functions']),
        'instructions.tsv': tsv(('body', 'entry', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callee-roles.tsv': tsv(('body', 'entry', 'role', 'target', 'call_sites'), result['roles']),
        'helper-keys.tsv': tsv(('role', 'helper', 'lea_va', 'pool_va', 'length', 'key'), result['helper_keys']),
        'field-keys.tsv': tsv(('body', 'entry', 'lea_va', 'pool_va', 'length', 'key'), result['keys']),
        'cases.tsv': tsv(('body', 'flag_or_depth', 'seed_or_start', 'outcome', 'calls', 'result', 'verdict'),
                         result['cases']),
        'paths.tsv': tsv(('body', 'outcome', 'cases', 'flags_or_depths'), result['paths']),
        'negative-controls.tsv': tsv(('family', 'control', 'detected_cases', 'first_case'), result['negatives']),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True, help='output folder for the generated evidence')
    ap.add_argument('--binary', default=str(TARGET))
    args = ap.parse_args(argv)
    data = Path(args.binary).read_bytes()
    result = build(data)
    files = render(result)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_text(files[name], encoding='utf-8')
    s = result['summary']
    print('cases %d mismatches %d negative controls detected %d/%d' % (
        s['cases'], s['mismatches'], s['negative_detected'], s['negative_controls']))
    return 0 if s['mismatches'] == 0 and s['negative_detected'] == s['negative_controls'] else 1


if __name__ == '__main__':
    sys.exit(main())
