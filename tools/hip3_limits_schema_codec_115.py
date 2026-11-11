#!/usr/bin/env python3
"""Reconstruct the node #115 Hip3 limits, schema and state struct serializers and prove it.

The `Hip3` arm of the per-DEX state enum serializes three records: limits,
schema and state.  This producer covers all three in all three copy
families (nine bodies).  It authenticates the #115 capture, locates every body
by its unwind (FDE) extent and runs the original machine code in a small
interpreter for the fixed x86-64 instruction subset the bodies use:

* limits: a six-field record of u64 values.  Three keys are written inline as
  msgpack fixstr bytes; two longer keys go through the str writer; a trailing
  outlined field helper writes the sixth.
* schema: a seven-field record.  Two strings, a 20-byte deployer address
  (hex-rendered through a GOT-slot callee in two copies and through a newtype
  helper named `Address` in the third), two optional addresses with keys gated
  on a non-zero struct-as-map byte, and two outlined sub-record helpers.
* state: a five-field record.  Two `Time` newtypes (passed by reference in
  one copy), a u64, the unit enum `disabled_state` dispatched through a
  four-entry jump table, and a byte field `m`.

Covered for each body: the map/array header byte derived from the
struct-as-map byte, every inline key and its capacity-reserve branch, the key
gate of each field, the option-tag test, the jump-table dispatch, the call order and argument
selection of each helper, and every error-propagation exit.  Every interpreted
result is compared with an independent pure-Python reconstruction; helper
internals are stubbed and outside the claim.  Deliberately wrong
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
    if raw[i] == 0x66:
        opsize16 = True
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
    elif two and op in (0x0f10, 0x0f11) and not opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op == 0x0f10 else 'movups_store', reg=reg, rm=rm, size=16)
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



# ---------------------------------------------------------------- targets

# Kinds of stubbed callees and how each signals success to its caller:
#   str  (writer, ptr, len)        -> rax == 2 on success, (rax, rdx) error pair otherwise
#   u64  (out, writer, value)      -> out[0] == 2 on success, out[0..1] error pair otherwise
#   rec  (out, writer, ...)        -> out[0] == 0x8000000000000004 on success, out[0..2] error otherwise
#   hex  (buf, 42, src, 20, 0)     -> (ptr, len) of the rendered text; never fails
KINDS = dict(str='str', u64='u64', tail='rec', some='rec', none='rec', addr='rec', r30='rec', r50='rec',
             hex='hex', time='rec', byte='rec')
HEX_SLOT = 0x64e4d08

COPIES = (
    dict(struct='state', entry=0x2bc0900, grow=0x231e050,
         roles=dict(time=0x226cf70, u64=0x25e9f10, str=0x25e8bf0, byte=0x226a340)),
    dict(struct='state', entry=0x449dbc0, grow=0x43bd910, time_by_ref=True,
         roles=dict(time=0x41b0e20, u64=0x3d51450, str=0x41c6610, byte=0x4199740)),
    dict(struct='state', entry=0x549b950, grow=0x5963a10,
         roles=dict(time=0x52f9680, u64=0x57cfd20, str=0x57cf5d0, byte=0x52f0010)),
    dict(struct='limits', entry=0x2bc1190, grow=0x231e050,
         roles=dict(u64=0x25e9f10, str=0x25e8bf0, tail=0x2cea920)),
    dict(struct='limits', entry=0x449e700, grow=0x43bd910,
         roles=dict(u64=0x3d51450, str=0x41c6610, tail=0x44fbf10)),
    dict(struct='limits', entry=0x549be00, grow=0x5963a10,
         roles=dict(u64=0x57cfd20, str=0x57cf5d0, tail=0x5676b40)),
    dict(struct='schema', entry=0x2bc17c0, grow=0x231e050, address='hex',
         roles=dict(str=0x25e8bf0, hex=HEX_SLOT, some=0x226a510, none=0x226a3b0, r30=0x2ce96a0, r50=0x2ce6f90)),
    dict(struct='schema', entry=0x449ef90, grow=0x43bd910, address='hex',
         roles=dict(str=0x41c6610, hex=HEX_SLOT, some=0x4199dc0, none=0x41997b0, r30=0x44f7950, r50=0x44f8ed0)),
    dict(struct='schema', entry=0x549c580, grow=0x5963a10, address='newtype',
         roles=dict(str=0x57cf5d0, addr=0x52f15d0, none=0x52f0170, r30=0x5676d60, r50=0x56746c0)),
)

# Reconstructed field tables.  ('inline', key) keys are written inline when
# the writer's struct-as-map byte is exactly 1; ('keyed', key, gate) keys go
# through the str writer, gated on `== 1` or `!= 0`.
LIMITS_FIELDS = (
    ('inline', b'total_oi_cap2'), ('call', 'u64', ('w+0x8',)),
    ('inline', b'oi_sz_cap_per_perp'), ('call', 'u64', ('w+0x10',)),
    ('inline', b'max_transfer_ntl2'), ('call', 'u64', ('w+0x18',)),
    ('keyed', b'max_under_initial_margin_transfer_ntl2', 'eq1'), ('call', 'u64', ('w+0x20',)),
    ('keyed', b'daily_px_range', 'eq1'), ('call', 'u64', ('w+0x0',)),
    ('tail',),
)
SCHEMA_FIELDS = (
    ('inline', b'name'), ('call', 'str', ('w+0x8', 'w+0x10')),
    ('inline', b'full_name'), ('call', 'str', ('w+0x20', 'w+0x28')),
    ('inline', b'deployer'), ('address', 'v+0x70'),
    ('keyed', b'oracle_updater', 'ne0'), ('option', 0x84, 'v+0x85'),
    ('keyed', b'fee_recipient', 'ne0'), ('option', 0x99, 'v+0x9a'),
    ('call', 'r30', ('v+0x30',)),
    ('call', 'r50', ('v+0x50',)),
)
STATE_FIELDS = (
    ('inline', b'last_settlement_time'), ('call', 'time', ('key:Time', 'v+0x8')),
    ('inline', b'deploy_time'), ('call', 'time', ('key:Time', 'v+0x14')),
    ('inline', b'n_reserve_deployments_used'), ('call', 'u64', ('w+0x0',)),
    ('keyed', b'disabled_state', 'ne0'), ('variant', 0x20),
    ('keyed', b'm', 'eq1'), ('byte', 0x21),
)
# Unit variant names of the byte at +0x20, in jump-table order.
DISABLED_STATE = (b'Na', b'UserDisabled', b'ValidatorDisabled', b'm')
FIELDS = dict(limits=LIMITS_FIELDS, schema=SCHEMA_FIELDS, state=STATE_FIELDS)
FIELD_COUNT = dict(limits=6, schema=7, state=5)
NEWTYPE_NAME = b'Address'
# The sixth limits field.  Copies 0x2bc1190/0x449e700 call a helper that
# writes this key itself (outside the claim); copy 0x549be00 passes it.
TAIL_KEY = b'max_n_users_with_positions'
TAIL_KEY_PASSED = (0x549be00,)

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VEC_BASE = 0x3000_0000
DATA_BASE = 0x4000_0000
HEX_PTR = 0x6000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
WORD_TAG = 0x7777_0000_0000_0000
PATTERN = 0x1111_1111_1111_1111
NICHE = 0x8000000000000000
OK_WORD = 0x8000000000000004
OK2 = 2
ERR = (0x0e10_0000_0000_00a1, 0x0e20_0000_0000_00a2, 0x0e30_0000_0000_00a3)
ERR_KEY = (0x0e40_0000_0000_00b1, 0x0e50_0000_0000_00b2)
HEX_LEN, HEX_SRC_LEN = 42, 20


class Script:
    """Which counted helper call (0-based) fails."""

    def __init__(self, fail_at):
        self.fail_at = fail_at
        self.counted = 0

    def fails(self):
        k = self.counted
        self.counted += 1
        return k == self.fail_at


def describe_args(image, args, m=None):
    """Semantic description of a stub's argument registers (rdi..r8).

    A stack pointer in any position but the first is a by-reference local:
    its first two words are described in place (`ref[...]`).
    """
    out = []
    for k, x in enumerate(args):
        if x == VEC_BASE:
            continue
        if STACK_TOP - 0x1000 <= x < STACK_TOP:
            if k and m is not None:
                inner = describe_args(image, (m.load(x, 8), m.load(x + 8, 8)))
                out.append('ref[%s]' % ','.join(inner))
            continue
        if IN_BASE <= x < IN_BASE + 0x200:
            out.append('v+0x%x' % (x - IN_BASE))
        elif x >> 48 == WORD_TAG >> 48:
            out.append('w+0x%x' % (x & 0xffff))
        elif x == HEX_PTR:
            out.append('hexbuf')
        elif 0x400000 <= x < 0x1000_0000 and k + 1 < len(args) and 0 < args[k + 1] < 0x100:
            out.append('key:' + image.read(x, args[k + 1]).decode('ascii'))
    return tuple(out)


def make_stubs(image, copy, script):
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

    def helper(role):
        kind = KINDS[role]

        def stub(m, args):
            out = args[0]
            if kind == 'hex':
                if (args[1], args[3]) != (HEX_LEN, HEX_SRC_LEN):
                    raise Reject('hex call lengths differ')
                if not STACK_TOP - 0x1000 <= out < STACK_TOP:
                    raise Reject('hex buffer is not on the stack')
                m.log.append(('call', role, describe_args(image, (args[2],))))
                return (HEX_PTR, HEX_LEN)
            if kind == 'str':
                if out != VEC_BASE:
                    raise Reject('str writer does not receive the writer first')
            elif args[1] != VEC_BASE:
                raise Reject('%s helper does not receive the writer second' % role)
            desc = describe_args(image, args, m)
            if role == 'byte':
                desc = ('b=%d' % args[2],)
            m.log.append(('call', role, desc))
            fail = script.fails()
            if kind == 'str':
                return ERR_KEY if fail else (OK2, None)
            if kind == 'u64':
                if fail:
                    m.store(out, ERR[0], 8)
                    m.store(out + 8, ERR[1], 8)
                else:
                    m.store(out, OK2, 8)
                return 0
            if fail:
                for k in range(3):
                    m.store(out + 8 * k, ERR[k], 8)
            else:
                m.store(out, OK_WORD, 8)
            return 0
        return stub

    stubs = {copy['grow']: grow}
    for role, target in copy['roles'].items():
        stubs[target] = helper(role)
    return stubs


# ---------------------------------------------------------------- reconstruction

class Writer:
    """Vec<u8> append model: one reserve check per inline store."""

    def __init__(self, cap, length, log, inclusive=False):
        self.cap, self.len, self.log, self.data = cap, length, log, bytearray()
        self.inclusive = inclusive

    def put(self, raw):
        n = len(raw)
        short = self.cap - self.len <= n if self.inclusive else self.cap - self.len < n
        if (n == 1 and self.cap == self.len) or (n > 1 and short):
            self.log.append(('grow', self.len, n))
            self.cap = max(self.cap * 2, self.len + n, 8)
        self.len += n
        self.data += raw

    def fixstr(self, text):
        self.put(bytes([0xa0 | len(text)]))
        self.put(text)


def recon_serialize(copy, flag, tags, cap, length, fail_at, variant=None):
    """Pure reconstruction of one struct serializer call.

    Returns (appended bytes, call log, final length, three result words).
    `variant` overrides decision rules for negative controls.
    """
    v = variant or {}
    log = []
    w = Writer(cap, length, log, v.get('reserve_inclusive', False))
    counter = [0]

    def fails():
        k = counter[0]
        counter[0] += 1
        return k == fail_at

    def done(result):
        return bytes(w.data), log, w.len, result

    struct_name = copy['struct']
    fields = v.get('fields', {}).get(struct_name, FIELDS[struct_name])
    count = v.get('count', FIELD_COUNT)[struct_name]
    header = v.get('header', lambda f, n: (((f ^ 1) << 4) | 0x80 | n) & 0xff)
    w.put(bytes([header(flag, count)]))
    gate = dict(eq1=lambda f: f == 1, ne0=lambda f: f != 0)
    gate.update(v.get('gates', {}))
    some = v.get('some', lambda tag: tag == 1)
    err_u64 = v.get('err_u64', (NICHE, ERR[0], ERR[1]))

    def call(role, desc):
        log.append(('call', role, desc))
        if fails():
            kind = KINDS[role]
            if kind == 'str':
                return (NICHE,) + ERR_KEY
            if kind == 'u64':
                return err_u64
            return ERR
        return None

    for field in fields:
        what = field[0]
        if what == 'inline':
            if gate['eq1'](flag):
                w.fixstr(field[1])
        elif what == 'keyed':
            if gate[field[2]](flag):
                err = call('str', ('key:' + field[1].decode(),))
                if err:
                    return done(err)
        elif what == 'call':
            desc = field[2]
            if field[1] == 'time' and copy.get('time_by_ref') and not v.get('time_direct'):
                # This copy passes a stack local holding the field pointer
                # instead of (newtype name, field pointer).
                desc = ('ref[%s]' % desc[1],)
            err = call(field[1], desc)
            if err:
                return done(err)
        elif what == 'tail':
            desc = ('w+0x28',)
            if copy['entry'] in TAIL_KEY_PASSED and not v.get('tail_key_absent'):
                desc = ('key:' + TAIL_KEY.decode(),) + desc
            err = call('tail', desc)
            if err:
                return done(err)
        elif what == 'address':
            if copy['address'] == 'hex':
                log.append(('call', 'hex', (field[1],)))
                err = call('str', ('hexbuf',))
            else:
                err = call('addr', ('key:' + NEWTYPE_NAME.decode(), field[1]))
            if err:
                return done(err)
        elif what == 'variant':
            names = v.get('variants', DISABLED_STATE)
            err = call('str', ('key:' + names[tags[field[1]]].decode(),))
            if err:
                return done(err)
        elif what == 'byte':
            err = call('byte', ('b=%d' % tags[field[1]],))
            if err:
                return done(err)
        elif what == 'option':
            if some(tags[field[1]]):
                if copy['address'] == 'hex':
                    err = call('some', (field[2],))
                else:
                    err = call('addr', ('key:' + NEWTYPE_NAME.decode(), field[2]))
            else:
                err = call('none', ())
            if err:
                return done(err)
    return done((OK_WORD, PATTERN, PATTERN) if v.get('ok') is None else v['ok'])


# Deliberately wrong reconstructions (negative controls).
def _swap_first_two(fields):
    return fields[2:4] + fields[0:2] + fields[4:]


WRONG = {
    'keyed_keys_gate_ne0': dict(gates=dict(eq1=lambda f: f != 0)),
    'option_keys_gate_eq1': dict(gates=dict(ne0=lambda f: f == 1)),
    'header_without_flag': dict(header=lambda f, n: 0x80 | n),
    'field_count_off_by_one': dict(count=dict(limits=5, schema=8, state=4)),
    'option_some_when_nonzero': dict(some=lambda tag: tag != 0),
    'reserve_inclusive': dict(reserve_inclusive=True),
    'limits_first_fields_swapped': dict(fields=dict(limits=_swap_first_two(LIMITS_FIELDS))),
    'schema_first_fields_swapped': dict(fields=dict(schema=_swap_first_two(SCHEMA_FIELDS))),
    'u64_error_copies_three_words': dict(err_u64=ERR),
    'success_writes_three_words': dict(ok=(OK_WORD, 0, 0)),
    'tail_key_not_passed': dict(tail_key_absent=True),
    'disabled_state_names_rotated': dict(variants=DISABLED_STATE[1:] + DISABLED_STATE[:1]),
    'time_passed_directly_everywhere': dict(time_direct=True),
    'state_fields_swapped': dict(fields=dict(state=_swap_first_two(STATE_FIELDS))),
}

# ---------------------------------------------------------------- drivers

FLAGS = (0, 1, 2, 0xff)
TAGS = (0, 1, 2)
SLACKS = tuple(range(0, 48))
START_LEN = 5


def tag_cases(copy):
    if copy['struct'] == 'limits':
        return [{}]
    if copy['struct'] == 'state':
        return [{0x20: a, 0x21: b} for a in range(len(DISABLED_STATE)) for b in (0, 1, 0xff)]
    return [{0x84: a, 0x99: b} for a in TAGS for b in TAGS]


def fmt_tags(tags):
    return ','.join('+0x%x=%d' % kv for kv in sorted(tags.items())) or '-'


def run_serializer(image, copy, stubs, flag, tags, cap, length):
    m = Machine(image, stubs)
    for k in range(3):
        m.store(OUT_BASE + 8 * k, PATTERN, 8)
    for off in range(0, 0x140, 8):
        m.store(IN_BASE + off, WORD_TAG | off, 8)
    if True:
        for off, tag in tags.items():
            m.store(IN_BASE + off, tag, 1)
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, length, 8)
    m.store(VEC_BASE + 24, flag << 24, 8)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, VEC_BASE
    m.run(copy['entry'])
    if m.regs[0] != OUT_BASE:
        raise Reject('serializer 0x%x does not return its output pointer' % copy['entry'])
    end = m.load(VEC_BASE + 16, 8)
    data = bytes(m.load(DATA_BASE + k, 1) for k in range(length, end))
    result = tuple(m.load(OUT_BASE + 8 * k, 8) for k in range(3))
    return data, m.log, end, result, m


def counted_calls(log):
    return sum(1 for e in log if e[0] == 'call' and KINDS[e[1]] != 'hex')


def fmt_log(log):
    parts = []
    for e in log:
        if e[0] == 'grow':
            parts.append('grow(%d,+%d)' % (e[1], e[2]))
        else:
            parts.append('%s(%s)' % (e[1], ','.join(e[2])))
    return ' '.join(parts)


def case_inputs(copy):
    """(flag, tags, cap, length, fail_at) for one copy."""
    rows = []
    for flag in FLAGS:
        for tags in tag_cases(copy):
            # Inline keys are written only when the struct-as-map byte is 1;
            # other flags write just the header byte, so two slacks cover them.
            for slack in (SLACKS if flag == 1 else (0, 1)):
                rows.append((flag, tags, START_LEN + slack, START_LEN, None))
            _, log, _, _ = recon_serialize(copy, flag, tags, 4096, START_LEN, None)
            for fail_at in range(counted_calls(log)):
                for slack in ((0, 4096) if flag == 1 else (4096,)):
                    rows.append((flag, tags, START_LEN + slack, START_LEN, fail_at))
    return rows


def literal_rows(image, copy, body):
    """Inline literal stores and rip-relative key references of a body."""
    rows = []
    for ins in body:
        if ins.op == 'mov' and ins.ext == 'imm' and ins.rm[0] == 'mem' and ins.size >= 2:
            raw = ins.imm.to_bytes(8, 'little')[:ins.size]
            if all(0x20 <= b < 0x7f for b in raw):
                rows.append(('imm%d' % (8 * ins.size), '0x%x' % ins.va, raw.decode('ascii')))
        if ins.op == 'movimm' and ins.size == 8:
            raw = ins.imm.to_bytes(8, 'little')
            if all(0x20 <= b < 0x7f for b in raw):
                rows.append(('imm64', '0x%x' % ins.va, raw.decode('ascii')))
        if ins.op == 'movups_load' and ins.rm[0] == 'mem' and ins.rm[5]:
            raw = image.read(ins.rm[4], 16)
            rows.append(('rodata16@0x%x' % ins.rm[4], '0x%x' % ins.va, raw.decode('ascii')))
    return rows


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows, lit_rows, role_rows = [], [], [], []
    bodies = {}
    for copy in COPIES:
        va = copy['entry']
        if va not in by_start:
            raise Reject('0x%x is not an FDE start' % va)
        rec = by_start[va]
        rows = linear(image, va, rec['end'])
        bodies[va] = rows
        body = image.read(va, rec['end'] - va)
        calls = sorted(set(r.target for r in rows if r.op in ('call', 'call_ind')))
        declared = set(copy['roles'].values()) | {copy['grow']}
        if set(calls) != declared:
            raise Reject('call targets of 0x%x differ from the role table' % va)
        functions.append(dict(struct=copy['struct'], entry='0x%x' % va, fde_end='0x%x' % rec['end'],
                              fde_bytes=rec['end'] - va, decoded_instructions=len(rows),
                              decoded_bytes=sum(r.length for r in rows),
                              sha256=hashlib.sha256(body).hexdigest(),
                              call_sites=sum(1 for r in rows if r.op in ('call', 'call_ind'))))
        for r in rows:
            insn_rows.append((copy['struct'], '0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))
        for row in literal_rows(image, copy, rows):
            lit_rows.append((copy['struct'], '0x%x' % va) + row)
        sites = {}
        for r in rows:
            if r.op in ('call', 'call_ind'):
                sites[r.target] = sites.get(r.target, 0) + 1
        for role, target in sorted(list(copy['roles'].items()) + [('grow', copy['grow'])], key=lambda x: x[0]):
            how = 'got slot' if role == 'hex' else 'direct'
            role_rows.append((copy['struct'], '0x%x' % va, role, KINDS.get(role, 'grow'), how, '0x%x' % target,
                              sites[target]))

    # Jump tables: the rip-relative lea right before each movsxd is the table
    # base; entries are signed 32-bit offsets from that base.
    table_rows, table_targets = [], {}
    for copy in COPIES:
        rows = bodies[copy['entry']]
        end = by_start[copy['entry']]['end']
        for k, ins in enumerate(rows):
            if ins.op != 'movsxd':
                continue
            leas = [r for r in rows[max(0, k - 3):k] if r.op == 'lea' and r.rm[5]]
            if len(leas) != 1:
                raise Reject('no table base before movsxd at 0x%x' % ins.va)
            base = leas[0].rm[4]
            targets = []
            for n in range(len(DISABLED_STATE)):
                off = struct.unpack('<i', image.read(base + 4 * n, 4))[0]
                target = base + off
                if not copy['entry'] <= target < end:
                    raise Reject('jump-table entry %d of 0x%x leaves the body' % (n, base))
                targets.append(target)
                table_rows.append((copy['struct'], '0x%x' % copy['entry'], '0x%x' % ins.va, '0x%x' % base, n,
                                   off, '0x%x' % target, DISABLED_STATE[n].decode()))
            table_targets[copy['entry']] = targets
    if sorted(table_targets) != sorted(c['entry'] for c in COPIES if c['struct'] == 'state'):
        raise Reject('expected one jump table per state body')

    slot = image.relative_addends({HEX_SLOT})
    if HEX_SLOT not in slot:
        raise Reject('hex slot 0x%x has no R_X86_64_RELATIVE relocation' % HEX_SLOT)
    hex_target = slot[HEX_SLOT][1]
    if hex_target not in by_start:
        raise Reject('hex slot target 0x%x is not an FDE start' % hex_target)

    # Key strings read through rip-relative lea by the str writer.
    key_rows = []
    for copy in COPIES:
        for f in FIELDS[copy['struct']]:
            if f[0] in ('inline', 'keyed'):
                key_rows.append((copy['struct'], '0x%x' % copy['entry'], f[0],
                                 'flag==1' if f[0] == 'inline' else ('flag==1' if f[2] == 'eq1' else 'flag!=0'),
                                 f[1].decode(), len(f[1]),
                                 '0x%02x' % (0xa0 | len(f[1])) if f[0] == 'inline' else 'str writer'))

    cases, mismatches, by_path = [], 0, {}
    for copy in COPIES:
        for flag, tags, cap, length, fail_at in case_inputs(copy):
            stubs = make_stubs(image, copy, Script(fail_at))
            got_data, got_log, got_end, got_res, m = run_serializer(image, copy, stubs, flag, tags, cap, length)
            for _, target in m.jumps:
                if target != table_targets[copy['entry']][tags[0x20]]:
                    raise Reject('indirect jump of 0x%x misses the table entry' % copy['entry'])
            exp = recon_serialize(copy, flag, tags, cap, length, fail_at)
            ok = (got_data, got_log, got_end, got_res) == exp
            mismatches += not ok
            path = (copy['struct'], '0x%x' % copy['entry'], 'ok' if fail_at is None else 'fail@%d' % fail_at)
            seen = by_path.setdefault(path, [0, set(), set()])
            seen[0] += 1
            seen[1].add(flag)
            seen[2].add(fmt_tags(tags))
            cases.append((copy['struct'], '0x%x' % copy['entry'], flag, fmt_tags(tags), cap, length,
                          '' if fail_at is None else fail_at, got_data.hex(), fmt_log(got_log), got_end,
                          ','.join('0x%x' % x for x in got_res), 'match' if ok else 'MISMATCH'))

    negatives = []
    for name in sorted(WRONG):
        caught = 0
        first = ''
        for copy in COPIES:
            for flag, tags, cap, length, fail_at in case_inputs(copy):
                good = recon_serialize(copy, flag, tags, cap, length, fail_at)
                bad = recon_serialize(copy, flag, tags, cap, length, fail_at, WRONG[name])
                if good != bad:
                    caught += 1
                    if not first:
                        first = '0x%x flag=%d tags=%s cap=%d fail=%s' % (
                            copy['entry'], flag, fmt_tags(tags), cap, fail_at)
        negatives.append((name, caught, 'caught' if caught else 'MISSED', first))

    summary = dict(
        target='artifacts/node/115/hl-node', sha256=SHA115,
        bodies=len(COPIES), structs=sorted(set(c['struct'] for c in COPIES)),
        cases=len(cases), mismatches=mismatches,
        paths=len(by_path),
        negative_controls=len(negatives), negative_controls_caught=sum(1 for n in negatives if n[1]),
        hex_slot='0x%x' % HEX_SLOT, hex_slot_target='0x%x' % hex_target,
        hex_slot_rela_offset=slot[HEX_SLOT][0],
        decoded_instructions=len(insn_rows),
        field_counts=FIELD_COUNT,
    )
    path_rows = [k + (v[0], ','.join(str(f) for f in sorted(v[1])), len(v[2]))
                 for k, v in sorted(by_path.items(), key=lambda kv: (kv[0][0], kv[0][1], len(kv[0][2]), kv[0][2]))]
    summary['jump_table_entries'] = len(table_rows)
    return dict(summary=summary, tables=table_rows, functions=functions, instructions=insn_rows, literals=lit_rows,
                roles=role_rows, keys=key_rows, cases=cases, negatives=negatives, paths=path_rows)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(x) for x in r) + '\n' for r in rows)


def render(result):
    fn_header = ('struct', 'entry', 'fde_end', 'fde_bytes', 'decoded_instructions', 'decoded_bytes', 'sha256',
                 'call_sites')
    return {
        'summary.json': json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
        'functions.tsv': tsv(fn_header, [tuple(f[h] for h in fn_header) for f in result['functions']]),
        'instructions.tsv': tsv(('struct', 'entry', 'va', 'length', 'bytes', 'op', 'target'),
                                result['instructions']),
        'literals.tsv': tsv(('struct', 'entry', 'source', 'va', 'text'), result['literals']),
        'callee-roles.tsv': tsv(('struct', 'entry', 'role', 'kind', 'call', 'target', 'call_sites'),
                                result['roles']),
        'field-keys.tsv': tsv(('struct', 'entry', 'mode', 'written_when', 'key', 'length', 'fixstr_marker'),
                              result['keys']),
        'cases.tsv': tsv(('struct', 'entry', 'flag', 'tag_bytes', 'capacity', 'length', 'fail_at',
                          'appended_hex', 'calls', 'end_length', 'result', 'verdict'), result['cases']),
        'jump-tables.tsv': tsv(('struct', 'entry', 'movsxd_va', 'table', 'index', 'offset', 'target', 'variant'),
                               result['tables']),
        'paths.tsv': tsv(('struct', 'entry', 'outcome', 'cases', 'flags', 'tag_combinations'), result['paths']),
        'negative-controls.tsv': tsv(('wrong_reconstruction', 'cases_caught', 'verdict', 'first_case'),
                                     result['negatives']),
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
    print('cases %d mismatches %d negative controls caught %d/%d' % (
        s['cases'], s['mismatches'], s['negative_controls_caught'], s['negative_controls']))
    return 0 if s['mismatches'] == 0 and s['negative_controls_caught'] == s['negative_controls'] else 1


if __name__ == '__main__':
    sys.exit(main())
