#!/usr/bin/env python3
"""Reconstruct the node #115 Hip3 sub-record field helpers and prove it.

The Hip3 `limits`, `schema` and `state` struct serializers call outlined
field helpers.  This producer covers 21 of those helper bodies across the
three copy families.  It authenticates the #115 capture, locates every body
by its unwind (FDE) extent and runs the original machine code in a small
interpreter for the fixed x86-64 instruction subset the bodies use:

* oi_map (`asset_to_oi_cap`): a fixstr key gated on a non-zero struct-as-map
  byte, then a nine-word iterator built from a niche-tagged container.  One
  representation is a ring buffer of 16-byte entries split into two slices;
  the other is a root/height/length triple.
* sub_deployers: a fixstr key gated on struct-as-map == 1, then a tail call
  with the value and the writer swapped into argument order (out, value, writer).
* users_cap (`max_n_users_with_positions`): an inline key in two copies; the
  third receives the key from its caller and goes through the str writer.  The
  u64 result is remapped to the record result.
* bool: rmp marker `0xc2 | b` through Marker::to_u8, then one byte.
* nil: the msgpack nil byte `0xc0`.
* some_hex and address_newtype: a 20-byte value rendered as 42 hex characters
  and written as a string.  The newtype copy rejects the rmp `_ExtStruct` magic
  name with `expected tuple`.
* time_newtype: a newtype call, or the ext path when the name is `_ExtStruct`;
  a successful ext write becomes the `expected tuple` error.
* time_text (copy 2): Time is rendered as text (date, `'T'`, time) into a
  String through two GOT-slot formatters and a write_char reached through the
  String fmt::Write vtable.  The text is written as a msgpack str and the
  buffer freed.  A formatter error panics with the Display message.

Every interpreted result (appended bytes, call log with arguments, final
length, result words) is compared with an independent pure-Python
reconstruction.  Callee internals are stubbed and outside the claim.
Deliberately wrong reconstructions run through the same comparison and must
be caught.

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
        self.reloc = {}  # slot VA -> R_X86_64_RELATIVE addend, for loads of relocated words

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
    elif not two and op == 0x84:
        reg, rm, _ = modrm()
        if not rex and (4 <= reg <= 7 or (rm[0] == 'reg' and 4 <= rm[1] <= 7)):
            raise Reject('legacy high-byte register at 0x%x' % va)
        kw.update(op='test', reg=reg, rm=rm, size=1, ext='to_rm')
    elif two and op == 0x0f0b:
        kw.update(op='ud2')
    elif not two and op == 0xc1:
        reg, rm, sub = modrm()
        if sub != 4 or rm[0] != 'reg' or not w:
            raise Reject('unsupported c1 form at 0x%x' % va)
        kw.update(op='shl64', rm=rm, imm=imm(1))
    elif not two and op == 0xf7:
        reg, rm, sub = modrm()
        if sub != 3 or rm[0] != 'reg' or not w:
            raise Reject('unsupported f7 form at 0x%x' % va)
        kw.update(op='neg', rm=rm)
    elif two and op == 0x0f43:
        reg, rm, _ = modrm()
        kw.update(op='cmovae', reg=reg, rm=rm)
    elif two and op == 0x0fb7:
        reg, rm, _ = modrm()
        kw.update(op='movzx16', reg=reg, rm=rm)
    elif not two and op == 0x71:
        rel = sx(imm(1), 8)
        kw.update(op='jno')
        kw['target'] = va + i + rel
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
        elif sub == 2 and rm[0] == 'mem':
            kw.update(op='call_mem', rm=rm)
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
        self.of = None
        self.calls = []
        self.jumps = []
        self.log = []
        self.steps = 0

    def load(self, addr, n):
        if n == 8 and addr in self.image.reloc:
            return self.image.reloc[addr]
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
        self.of = None  # only `neg` defines OF in this model; `jno` elsewhere is rejected

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
            elif op == 'movzx16':
                self.put(('reg', ins.reg), self.get(ins.rm, 2), size)
            elif op == 'neg':
                a = self.get(ins.rm, 8)
                r = (-a) & MASK
                self.zf, self.cf, self.of = r == 0, a != 0, a == 1 << 63
                self.put(ins.rm, r, 8)
            elif op == 'jno':
                if self.of is None:
                    raise Reject('jno without a defined overflow flag at 0x%x' % pc)
                if not self.of:
                    nxt = ins.target
            elif op == 'cmovae':
                if not self.cf:
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
            elif op == 'shl64':
                count = ins.imm & 63
                a = self.get(ins.rm, 8)
                r = (a << count) & MASK
                self.zf, self.cf, self.of = r == 0, bool(count and (a >> (64 - count)) & 1), None
                self.put(ins.rm, r, 8)
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
            elif op == 'jmp' and ins.target in self.stubs:
                # Tail call: run the stub, then return to our caller.
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, ins.target, args))
                self.stubs[ins.target](self, args)
                target = self.load(self.regs[4], 8)
                self.regs[4] += 8
                if target != RETURN_SENTINEL or self.regs[4] != STACK_TOP:
                    raise Reject('tail call with unbalanced stack at 0x%x' % pc)
                return
            elif op == 'jmp':
                nxt = ins.target
            elif op == 'push':
                self.regs[4] -= 8
                self.store(self.regs[4], self.regs[ins.reg], 8)
            elif op == 'pop':
                self.regs[ins.reg] = self.load(self.regs[4], 8)
                self.regs[4] += 8
            elif op == 'ud2':
                raise Reject('reached ud2 at 0x%x' % pc)
            elif op == 'call_mem':
                slot = self.ea(ins.rm)
                target = self.load(slot, 8)
                if target not in self.stubs:
                    raise Reject('call through slot 0x%x to unmodelled 0x%x at 0x%x' % (slot, target, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, target, args))
                ret = self.stubs[target](self, args)
                for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = 0x5c5c_5c5c_5c5c_5c5c
                rax, rdx = ret if isinstance(ret, tuple) else (ret, None)
                if rax is not None:
                    self.regs[0] = rax
                if rdx is not None:
                    self.regs[2] = rdx
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

# Callee roles and how each signals success:
#   str     (writer, ptr, len)          -> rax == 2 on success, (rax, rdx) error pair otherwise
#   u64     (out, writer, value)        -> out[0] == 2 on success, out[0..1] error pair otherwise
#   map/seq/newtype/ext (out, ...)      -> out[0] == 0x8000000000000004 on success, out[0..2] error otherwise
#   hex     (buf, 42, src, 20, 0)       -> (ptr, len) of the rendered text; never fails
#   marker  (marker byte)               -> rmp Marker::to_u8 of the argument (identity for 0xc0..0xdf)
#   date_fmt/time_fmt/write_char (x, fmt) -> al == 0 on success; append text to the formatter's String
#   dealloc (ptr, cap, 0)               -> frees the String buffer
#   panic   (msg, len, ...)             -> never returns
ROLE_KIND = dict(str='str', u64='u64', map='rec', seq='rec', newtype='rec', ext='rec', hex='hex', marker='marker',
                 date_fmt='fmt', time_fmt='fmt', write_char='fmt', dealloc='dealloc', panic='panic',
                 unwind='unreached')
# Argument registers recorded per role (rdi, rsi, rdx, rcx, r8 order) and the
# stack-reference depth/width read behind the third argument.
ROLE_ARGS = dict(str=3, u64=3, map=3, seq=3, newtype=3, ext=3, hex=5, marker=1, date_fmt=2, time_fmt=2,
                 write_char=2, dealloc=3, panic=2)
# Copy 2 renders Time as text: two GOT-slot formatters around a write_char
# reached through the String fmt::Write vtable, then frees the String.
DATE_SLOT, TIME_SLOT, DEALLOC_SLOT, PANIC_SLOT = 0x64e1158, 0x64e1160, 0x64df4a0, 0x64df6a0
STRING_VTABLE = 0x64820f8
WRITE_CHAR_SLOT = STRING_VTABLE + 0x20
FMT_TEXT = dict(date_fmt=b'2026-11-06', time_fmt=b'00:37:43.250')
STRBUF = 0x5c00_0000
STRBUF_CAP = 64
PANIC_TEXT_LEN = 0x37
ROLE_DEREF = dict(map=('words', 9), newtype=('chain', 2), ext=('chain', 2))
HEX_SLOT = 0x64e4d08

KEY_OI = b'asset_to_oi_cap'
KEY_SUB = b'sub_deployers'
KEY_TAIL = b'max_n_users_with_positions'
EXT_NAME = b'_ExtStruct'
NEWTYPE_NAMES = (b'Time', b'Address', EXT_NAME, b'_ExtStrucT', b'_ExtStruc', b'_ExtStructs', b'XExtStruct')

HELPERS = (
    dict(kind='oi_map', copy=1, entry=0x2ce96a0, grow=0x231e050, roles=dict(map=0x2202220)),
    dict(kind='oi_map', copy=2, entry=0x44f7950, grow=0x43bd910, roles=dict(map=None)),
    dict(kind='oi_map', copy=3, entry=0x5676d60, grow=0x5963a10, roles=dict(map=None)),
    dict(kind='sub_deployers', copy=1, entry=0x2ce6f90, grow=0x231e050, roles=dict(seq=0x2d562f0)),
    dict(kind='sub_deployers', copy=2, entry=0x44f8ed0, grow=0x43bd910, roles=dict(seq=0x3c6f250)),
    dict(kind='sub_deployers', copy=3, entry=0x56746c0, grow=0x5963a10, roles=dict(seq=0x4da9790)),
    dict(kind='users_cap', copy=1, entry=0x2cea920, grow=0x231e050, roles=dict(u64=0x25e9f10)),
    dict(kind='users_cap', copy=2, entry=0x44fbf10, grow=0x43bd910, roles=dict(u64=0x3d51450)),
    dict(kind='users_cap_keyed', copy=3, entry=0x5676b40, grow=None, roles=dict(str=0x57cf5d0, u64=0x57cfd20)),
    dict(kind='bool', copy=1, entry=0x226a340, grow=0x231e050, roles=dict(marker=0x25eab50)),
    dict(kind='bool', copy=2, entry=0x4199740, grow=0x43bd910, roles=dict(marker=0x3d52310)),
    dict(kind='bool', copy=3, entry=0x52f0010, grow=0x5963a10, roles=dict(marker=0x57d0b20)),
    dict(kind='nil', copy=1, entry=0x226a3b0, grow=0x231e050, roles=dict()),
    dict(kind='nil', copy=2, entry=0x41997b0, grow=0x43bd910, roles=dict()),
    dict(kind='nil', copy=3, entry=0x52f0170, grow=0x5963a10, roles=dict()),
    dict(kind='some_hex', copy=1, entry=0x226a510, grow=None, roles=dict(hex=HEX_SLOT, str=0x25e8bf0)),
    dict(kind='some_hex', copy=2, entry=0x4199dc0, grow=None, roles=dict(hex=HEX_SLOT, str=0x41c6610)),
    dict(kind='address_newtype', copy=3, entry=0x52f15d0, grow=None, roles=dict(hex=HEX_SLOT, str=0x57cf5d0)),
    dict(kind='time_newtype', copy=1, entry=0x226cf70, grow=None, roles=dict(newtype=0x227e5c0, ext=0x227e720)),
    dict(kind='time_newtype', copy=3, entry=0x52f9680, grow=None, roles=dict(newtype=None, ext=None)),
    dict(kind='time_text', copy=2, entry=0x41b0e20, grow=None,
         roles=dict(date_fmt=DATE_SLOT, time_fmt=TIME_SLOT, dealloc=DEALLOC_SLOT, panic=PANIC_SLOT,
                    str=0x41c6610, unwind=0x63f0a50)),
)


class Panic(Exception):
    pass

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VEC_BASE = 0x3000_0000
DATA_BASE = 0x4000_0000
NAME_BASE = 0x5000_0000
BUF = 0x0000_5800_0000_0000
HEX_PTR = 0x6000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
PATTERN = 0x1111_1111_1111_1111
VALUE = 0x7777_0000_0000_0042
NICHE = 0x8000000000000000
OK_WORD = 0x8000000000000004
OK2 = 2
ERR = (0x0e10_0000_0000_00a1, 0x0e20_0000_0000_00a2, 0x0e30_0000_0000_00a3)
ERR_KEY = (0x0e40_0000_0000_00b1, 0x0e50_0000_0000_00b2)
HEX_LEN, HEX_SRC_LEN = 42, 20
STK = 'S'


class Script:
    """Which counted helper call (0-based) fails."""

    def __init__(self, fail_at):
        self.fail_at = fail_at
        self.counted = 0

    def fails(self):
        k = self.counted
        self.counted += 1
        return k == self.fail_at


def on_stack(x):
    return STACK_TOP - 0x1000 <= x < STACK_TOP


def norm(x):
    return STK if on_stack(x) else x


def record_args(m, role, args):
    out = [norm(a) for a in args[:ROLE_ARGS[role]]]
    if role == 'marker':
        out = [args[0] & 0xff]
    deref = ROLE_DEREF.get(role)
    if deref:
        p = args[2]
        if not on_stack(p):
            raise Reject('%s argument is not a stack reference' % role)
        if deref[0] == 'words':
            out.append(tuple(m.load(p + 8 * k, 8) for k in range(deref[1])))
        else:
            x = p
            for _ in range(deref[1]):
                if not on_stack(x):
                    raise Reject('%s reference chain leaves the stack' % role)
                x = m.load(x, 8)
            out.append(('ref2', x))
    return tuple(out)


def make_stubs(helper, script):
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

    def helper_stub(role):
        kind = ROLE_KIND[role]

        def stub(m, args):
            rec = record_args(m, role, args)
            m.log.append(('call', role, rec))
            if kind == 'hex':
                if (args[1], args[3], args[4]) != (HEX_LEN, HEX_SRC_LEN, 0) or not on_stack(args[0]):
                    raise Reject('hex call arguments differ')
                return (HEX_PTR, HEX_LEN)
            if kind == 'marker':
                return args[0] & 0xff
            if kind == 'dealloc':
                return 0
            if kind == 'panic':
                raise Panic()
            if kind == 'unreached':
                raise Reject('unwind resume reached')
            fail = script.fails()
            if kind == 'fmt':
                if fail:
                    return 1
                if role == 'write_char':
                    string, text = args[0], bytes([args[1] & 0xff])
                else:
                    string, text = m.load(args[1], 8), FMT_TEXT[role]
                cap, ptr, length = (m.load(string + 8 * k, 8) for k in range(3))
                if cap - length < len(text):
                    if cap:
                        raise Reject('String regrowth is outside the model')
                    cap, ptr = STRBUF_CAP, STRBUF
                for k, b in enumerate(text):
                    m.store(ptr + length + k, b, 1)
                for k, word in enumerate((cap, ptr, length + len(text))):
                    m.store(string + 8 * k, word, 8)
                return 0
            out = args[0]
            if kind == 'str':
                return ERR_KEY if fail else (OK2, None)
            if kind == 'u64':
                m.store(out, ERR[0] if fail else OK2, 8)
                if fail:
                    m.store(out + 8, ERR[1], 8)
                return 0
            if fail:
                for k in range(3):
                    m.store(out + 8 * k, ERR[k], 8)
            else:
                m.store(out, OK_WORD, 8)
            return 0
        return stub

    stubs = {}
    if helper['grow'] is not None:
        stubs[helper['grow']] = grow
    for role, target in helper['roles'].items():
        stubs[target] = helper_stub(role)
    return stubs


# ---------------------------------------------------------------- reconstruction

class Writer:
    """Vec<u8> append model: one reserve check per inline store."""

    def __init__(self, cap, length, log, inclusive=False):
        self.cap, self.len, self.log, self.data = cap, length, log, bytearray()
        self.inclusive = inclusive

    def reserve(self, n):
        short = self.cap - self.len <= n if self.inclusive else self.cap - self.len < n
        if (n == 1 and self.cap == self.len) or (n > 1 and short):
            self.log.append(('grow', self.len, n))
            self.cap = max(self.cap * 2, self.len + n, 8)

    def put(self, raw):
        self.reserve(len(raw))
        self.len += len(raw)
        self.data += raw

    def fixstr(self, text):
        self.put(bytes([0xa0 | len(text)]))
        self.put(text)


def oi_iterator(words, v):
    """The nine-word iterator handed to the map writer.

    `words` are the four container words (+0, +8, +0x10, +0x18).  A first
    word of i64::MIN is the niche of the second representation (root, height,
    length); otherwise the words are a ring buffer (capacity, buffer, head,
    length) of 16-byte entries split into its two contiguous slices.
    """
    w0, w1, w2, w3 = words
    if w0 == NICHE and not v.get('niche_ignored'):
        root = w1
        present = int(root != 0) if not v.get('present_inverted') else int(root == 0)
        length = w3 if root else root
        return (present, 0, root, w2, present, 0, root, w2, length)
    cap, buf, head, length = words
    if length == 0:
        phys = end = wrap = 0
        last = 0
    else:
        phys = u64(head - (cap if head >= cap else 0))
        room = u64(cap - phys)
        wrapped = length > room if not v.get('wrap_inclusive') else length >= room
        if wrapped:
            end, wrap, last = cap, u64(length - room), length
        else:
            end, wrap = u64(phys + length), 0
            last = length if v.get('last_is_length') else end
    a = lambda k: u64(buf + (k << 4))  # noqa: E731
    return (2, a(phys), a(end), buf, a(wrap), 0, a(end), buf, last)


def recon(helper, inp, fail_at, variant=None):
    """Pure reconstruction of one helper call.

    Returns (appended bytes, call log, final length, three result words).
    """
    v = variant or {}
    log = []
    w = Writer(inp['cap'], inp['len'], log, v.get('reserve_inclusive', False))
    counter = [0]
    out = [PATTERN, PATTERN, PATTERN]
    flag = inp['flag']
    gate = dict(ne0=lambda f: f != 0, eq1=lambda f: f == 1)
    gate.update(v.get('gates', {}))
    kind = helper['kind']

    def call(role, args):
        log.append(('call', role, args))
        if ROLE_KIND[role] in ('hex', 'marker'):
            return None
        k = counter[0]
        counter[0] += 1
        if k != fail_at:
            return None
        return {'str': ERR_KEY, 'u64': ERR[:2]}.get(ROLE_KIND[role], ERR)

    def done():
        return bytes(w.data), log, w.len, tuple(out)

    def set_rec(err):
        out[:] = list(err) if err else [OK_WORD] + out[1:]

    if kind == 'oi_map':
        if gate[v.get('oi_gate', 'ne0')](flag):
            w.fixstr(KEY_OI)
        set_rec(call('map', (OUT_BASE, VEC_BASE, STK, oi_iterator(inp['words'], v))))
    elif kind == 'sub_deployers':
        if gate[v.get('sub_gate', 'eq1')](flag):
            w.fixstr(KEY_SUB)
        set_rec(call('seq', (OUT_BASE, IN_BASE, VEC_BASE)))
    elif kind in ('users_cap', 'users_cap_keyed'):
        if kind == 'users_cap_keyed' and not v.get('copy3_inline'):
            if gate['ne0'](flag):
                err = call('str', (VEC_BASE, NAME_BASE, len(KEY_TAIL)))
                if err:
                    out[:] = [NICHE, err[0], err[1]]
                    return done()
            value = inp['r8']
        else:
            if gate[v.get('tail_gate', 'ne0')](flag):
                w.fixstr(KEY_TAIL)
            value = VALUE
        err = call('u64', (STK, VEC_BASE, value))
        if err:
            out[:] = [NICHE, err[0], err[1]] if not v.get('u64_err_three') else list(ERR)
        else:
            out[0] = OK_WORD
    elif kind == 'bool':
        marker = (v.get('bool_base', 0xc2) | inp['b']) & 0xff
        if v.get('marker_before_grow'):
            call('marker', (marker,))
            w.reserve(1)
        else:
            w.reserve(1)
            call('marker', (marker,))
        w.len += 1
        w.data.append(marker)
        out[0] = OK_WORD
    elif kind == 'nil':
        w.put(b'\xc0')
        out[0] = OK_WORD
    elif kind in ('some_hex', 'address_newtype'):
        is_ext = kind == 'address_newtype' and name_is_ext(inp['name'], v)
        src = IN_BASE if kind == 'some_hex' else inp['r8']
        call('hex', (STK, HEX_LEN, src, HEX_SRC_LEN, 0))
        if is_ext:
            out[:] = [NICHE + 2, ADDRESS_EXT_TEXT[0], ADDRESS_EXT_TEXT[1]]
            return done()
        err = call('str', (VEC_BASE, HEX_PTR, HEX_LEN))
        if err:
            out[:] = [NICHE, err[0], err[1]]
        else:
            out[0] = OK_WORD
    elif kind == 'time_text':
        text = bytearray()
        steps = [('date_fmt', (TIME_VALUE, STK), FMT_TEXT['date_fmt']),
                 ('write_char', (STK, v.get('separator', 0x54)), bytes([v.get('separator', 0x54)])),
                 ('time_fmt', (TIME_VALUE + 4, STK), FMT_TEXT['time_fmt'])]
        if v.get('time_before_date'):
            steps = steps[::-1]
        for role, args, piece in steps:
            if v.get('fmt_errors_return') and counter[0] == fail_at:
                call(role, args)
                out[:] = [NICHE] + list(ERR_KEY)
                return done()
            if call(role, args):
                log.append(('call', 'panic', (PANIC_TEXT[0], PANIC_TEXT_LEN)))
                return done()
            text += piece
        err = call('str', (VEC_BASE, STRBUF, len(text)))
        if err:
            out[:] = [NICHE, err[0], err[1]]
        else:
            out[0] = OK_WORD
        if not v.get('string_leaked'):
            log.append(('call', 'dealloc', (STRBUF, STRBUF_CAP, 0)))
    elif kind == 'time_newtype':
        if name_is_ext(inp['name'], v):
            err = call('ext', (STK, VEC_BASE, STK, ('ref2', inp['r8'])))
            if err:
                out[:] = list(err)
            elif v.get('ext_ok_passes'):
                out[0] = OK_WORD
            else:
                out[:] = [NICHE + 2, TIME_EXT_TEXT[helper['copy']][0], TIME_EXT_TEXT[helper['copy']][1]]
        else:
            set_rec(call('newtype', (OUT_BASE, VEC_BASE, STK, ('ref2', inp['r8']))))
    else:
        raise Reject('unknown helper kind %s' % kind)
    return done()


def name_is_ext(name, v):
    if v.get('ext_prefix9'):
        return len(name) == len(EXT_NAME) and name[:9] == EXT_NAME[:9]
    return name == EXT_NAME


# Filled in by build() from the rip-relative lea of each ext-error exit.
ADDRESS_EXT_TEXT = [0, 0]
TIME_EXT_TEXT = {}
PANIC_TEXT = [0]
TIME_VALUE = IN_BASE + 0x40

WRONG = {
    'oi_key_gate_eq1': dict(oi_gate='eq1'),
    'sub_deployers_key_gate_ne0': dict(sub_gate='ne0'),
    'users_cap_key_gate_eq1': dict(tail_gate='eq1'),
    'reserve_inclusive': dict(reserve_inclusive=True),
    'ring_wrap_inclusive': dict(wrap_inclusive=True),
    'ring_last_word_is_length': dict(last_is_length=True),
    'niche_ignored': dict(niche_ignored=True),
    'niche_present_inverted': dict(present_inverted=True),
    'bool_marker_base_c0': dict(bool_base=0xc0),
    'marker_before_grow': dict(marker_before_grow=True),
    'ext_success_passes_through': dict(ext_ok_passes=True),
    'ext_name_prefix9': dict(ext_prefix9=True),
    'u64_error_three_words': dict(u64_err_three=True),
    'copy3_users_cap_inline_key': dict(copy3_inline=True),
    'time_text_separator_space': dict(separator=0x20),
    'time_text_time_before_date': dict(time_before_date=True),
    'time_text_fmt_error_returned': dict(fmt_errors_return=True),
    'time_text_string_leaked': dict(string_leaked=True),
}

# ---------------------------------------------------------------- drivers

FLAGS = (0, 1, 2, 0xff)
SLACKS = tuple(range(0, 40))
START_LEN = 5
RING_CAPS = (0, 1, 2, 3, 4, 5, 8, 16)
BIG = (0x7fff_ffff_ffff_ffff, NICHE - 1, NICHE + 1, MASK)


def ring_words():
    rows = []
    for cap in RING_CAPS:
        for head in range(0, 2 * cap + 2):
            for length in range(0, cap + 2):
                rows.append((cap, BUF, head, length))
    for big in BIG:
        rows += [(big, BUF, big - 1, 2), (big, BUF, 1, big), (4, BUF, big, 3), (big, BUF, 0, 0)]
    for root in (0, BUF, 1):
        for height in (0, 3):
            for length in (0, 7, MASK):
                rows.append((NICHE, root, height, length))
    return rows


def case_inputs(helper):
    """(input dict, fail_at) pairs for one helper."""
    kind = helper['kind']
    rows = []
    base = dict(flag=1, cap=START_LEN + 4096, len=START_LEN)

    def add(fails=(None,), **kw):
        for f in fails:
            d = dict(base)
            d.update(kw)
            rows.append((d, f))
    if kind == 'oi_map':
        words = (8, BUF, 3, 4)
        for flag in FLAGS:
            for slack in (SLACKS if flag == 1 else (0, 1)):
                add(fails=(None, 0), flag=flag, cap=START_LEN + slack, words=words)
        for words in ring_words():
            add(fails=(None,), flag=0, words=words)
    elif kind == 'sub_deployers':
        for flag in FLAGS:
            for slack in (SLACKS if flag == 1 else (0, 1)):
                add(fails=(None, 0), flag=flag, cap=START_LEN + slack)
    elif kind == 'users_cap':
        for flag in FLAGS:
            for slack in (SLACKS if flag == 1 else (0, 1)):
                add(fails=(None, 0), flag=flag, cap=START_LEN + slack)
    elif kind == 'users_cap_keyed':
        for flag in FLAGS:
            add(fails=(None, 0, 1) if flag else (None, 0), flag=flag, r8=VALUE)
    elif kind == 'bool':
        for b in range(256):
            for slack in (0, 1):
                add(b=b, cap=START_LEN + slack)
    elif kind == 'nil':
        for slack in (0, 1, 2):
            add(cap=START_LEN + slack)
    elif kind == 'some_hex':
        add(fails=(None, 0))
    elif kind == 'address_newtype':
        for name in NEWTYPE_NAMES:
            add(fails=(None, 0), name=name, r8=IN_BASE + 0x70)
    elif kind == 'time_newtype':
        for name in NEWTYPE_NAMES:
            add(fails=(None, 0), name=name, r8=IN_BASE + 0x8)
    elif kind == 'time_text':
        for flag in FLAGS:
            add(fails=(None, 0, 1, 2, 3), flag=flag)
    return rows


def run_helper(image, helper, stubs, inp):
    m = Machine(image, stubs)
    for k in range(3):
        m.store(OUT_BASE + 8 * k, PATTERN, 8)
    m.store(VEC_BASE, inp['cap'], 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, inp['len'], 8)
    m.store(VEC_BASE + 24, inp['flag'] << 24, 8)
    m.regs[7], m.regs[6] = OUT_BASE, VEC_BASE
    kind = helper['kind']
    if kind == 'oi_map':
        for k, word in enumerate(inp['words']):
            m.store(IN_BASE + 8 * k, word, 8)
        m.regs[2] = IN_BASE
    elif kind in ('sub_deployers', 'some_hex'):
        m.regs[2] = IN_BASE
    elif kind == 'users_cap':
        m.regs[2] = VALUE
    elif kind == 'users_cap_keyed':
        m.regs[2], m.regs[1], m.regs[8] = NAME_BASE, len(KEY_TAIL), inp['r8']
        for k, b in enumerate(KEY_TAIL):
            m.store(NAME_BASE + k, b, 1)
    elif kind == 'bool':
        m.regs[2] = 0x5a5a_5a5a_5a5a_5a00 | inp['b']
    elif kind in ('address_newtype', 'time_newtype'):
        name = inp['name']
        for k, b in enumerate(name + b'\0' * 16):
            m.store(NAME_BASE + k, b, 1)
        m.regs[2], m.regs[1], m.regs[8] = NAME_BASE, len(name), inp['r8']
    elif kind == 'time_text':
        # rdx -> slot holding P; [P] is the Time value pointer.
        m.store(IN_BASE + 0x100, IN_BASE + 0x8, 8)
        m.store(IN_BASE + 0x8, TIME_VALUE, 8)
        m.regs[2] = IN_BASE + 0x100
    try:
        m.run(helper['entry'])
    except Panic:
        m.regs[0] = OUT_BASE  # the panic never returns; the result words stay untouched
    if m.regs[0] != OUT_BASE and kind not in ('oi_map', 'sub_deployers', 'users_cap', 'users_cap_keyed'):
        raise Reject('helper 0x%x does not return its output pointer' % helper['entry'])
    end = m.load(VEC_BASE + 16, 8)
    data = bytes(m.load(DATA_BASE + k, 1) for k in range(inp['len'], end))
    result = tuple(m.load(OUT_BASE + 8 * k, 8) for k in range(3))
    return data, m.log, end, result


def fmt_arg(a):
    if isinstance(a, tuple):
        if a and a[0] == 'ref2':
            return '**%s' % fmt_arg(a[1])
        return '[' + ','.join(fmt_arg(x) for x in a) + ']'
    if a == STK:
        return 'stk'
    names = {OUT_BASE: 'out', VEC_BASE: 'W', IN_BASE: 'v', NAME_BASE: 'name', HEX_PTR: 'hexbuf', VALUE: 'value'}
    if a in names:
        return names[a]
    if IN_BASE < a < IN_BASE + 0x200:
        return 'v+0x%x' % (a - IN_BASE)
    if BUF <= a < BUF + 0x1_0000_0000:
        return 'buf+0x%x' % (a - BUF)
    return '0x%x' % a if a > 0xffff else str(a)


def fmt_log(log):
    parts = []
    for e in log:
        if e[0] == 'grow':
            parts.append('grow(%d,+%d)' % (e[1], e[2]))
        else:
            parts.append('%s(%s)' % (e[1], ','.join(fmt_arg(a) for a in e[2])))
    return ' '.join(parts)


def fmt_input(helper, inp):
    parts = ['flag=%d' % inp['flag'], 'cap=%d' % inp['cap']]
    if 'words' in inp:
        parts.append('words=' + ','.join(fmt_arg(x) for x in inp['words']))
    if 'b' in inp:
        parts.append('b=%d' % inp['b'])
    if 'name' in inp:
        parts.append('name=' + inp['name'].decode())
    return ' '.join(parts)


def literal_rows(image, body):
    rows = []
    for ins in body:
        if ins.op == 'movimm' and ins.size == 8:
            raw = ins.imm.to_bytes(8, 'little')
            if all(0x20 <= b < 0x7f for b in raw):
                rows.append(('imm64', '0x%x' % ins.va, raw.decode('ascii')))
        if ins.op == 'mov' and ins.ext == 'imm' and ins.rm[0] == 'mem' and ins.size == 1 and ins.imm >= 0xa0:
            rows.append(('marker', '0x%x' % ins.va, '0x%02x' % ins.imm))
        if ins.op == 'movups_load' and ins.rm[0] == 'mem' and ins.rm[5]:
            raw = image.read(ins.rm[4], 16)
            rows.append(('rodata16@0x%x' % ins.rm[4], '0x%x' % ins.va, raw.decode('ascii')))
        if ins.op == 'lea' and ins.rm[5]:
            raw = image.read(ins.rm[4], 14)
            text = raw.decode('ascii') if all(0x20 <= b < 0x7f for b in raw) else 'hex:' + raw.hex()
            rows.append(('lea@0x%x' % ins.rm[4], '0x%x' % ins.va, text))
    return rows


def resolve_roles(image, helper, rows, slot_target):
    """Fill unknown role targets from the body's call order; check the rest."""
    calls = []
    for r in rows:
        if r.op in ('call', 'call_ind') or (r.op == 'jmp' and not helper['entry'] <= r.target < helper['end']):
            if r.target not in calls:
                calls.append(r.target)
    roles = dict(helper['roles'])
    if any(r.op == 'call_mem' for r in rows):
        # The only register-based call is write_char through the String
        # fmt::Write vtable built at [rsp+0x28]; its slot is relocated.
        leas = [r.rm[4] for r in rows if r.op == 'lea' and r.rm[5]]
        if STRING_VTABLE not in leas or WRITE_CHAR_SLOT not in image.reloc:
            raise Reject('write_char vtable of 0x%x is not resolved' % helper['entry'])
        roles['write_char'] = image.reloc[WRITE_CHAR_SLOT]
        calls.append(roles['write_char'])
    known = set(t for t in roles.values() if t is not None) | ({helper['grow']} if helper['grow'] else set())
    unknown = [t for t in calls if t not in known]
    missing = [r for r, t in sorted(roles.items()) if t is None]
    order = {'oi_map': ['map'], 'time_newtype': ['newtype', 'ext']}.get(helper['kind'], [])
    missing = [r for r in order if r in missing]
    if len(unknown) != len(missing):
        raise Reject('call targets of 0x%x do not match the role table' % helper['entry'])
    roles.update(zip(missing, unknown))
    if set(calls) != set(roles.values()) | ({helper['grow']} if helper['grow'] else set()):
        raise Reject('call targets of 0x%x differ from the role table' % helper['entry'])
    return roles


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    slot = image.relative_addends({HEX_SLOT})
    if HEX_SLOT not in slot:
        raise Reject('hex slot 0x%x has no R_X86_64_RELATIVE relocation' % HEX_SLOT)
    hex_target = slot[HEX_SLOT][1]
    if hex_target not in by_start:
        raise Reject('hex slot target 0x%x is not an FDE start' % hex_target)
    text_slots = (DATE_SLOT, TIME_SLOT, DEALLOC_SLOT, PANIC_SLOT, WRITE_CHAR_SLOT)
    reloc = image.relative_addends(set(text_slots))
    if sorted(reloc) != sorted(text_slots):
        raise Reject('a Time-text slot has no R_X86_64_RELATIVE relocation')
    image.reloc = {WRITE_CHAR_SLOT: reloc[WRITE_CHAR_SLOT][1]}
    slot_rows = [('0x%x' % s, name, reloc[s][0], '0x%x' % reloc[s][1]) for s, name in (
        (DATE_SLOT, 'date_fmt'), (TIME_SLOT, 'time_fmt'), (WRITE_CHAR_SLOT, 'write_char (vtable+0x20)'),
        (DEALLOC_SLOT, 'dealloc'), (PANIC_SLOT, 'panic'))]
    slot_rows.insert(0, ('0x%x' % HEX_SLOT, 'hex', slot[HEX_SLOT][0], '0x%x' % hex_target))

    functions, insn_rows, lit_rows, role_rows, helpers = [], [], [], [], []
    for h in HELPERS:
        va = h['entry']
        if va not in by_start:
            raise Reject('0x%x is not an FDE start' % va)
        h = dict(h, end=by_start[va]['end'])
        rows = linear(image, va, h['end'])
        h['roles'] = resolve_roles(image, h, rows, hex_target)
        helpers.append(h)
        body = image.read(va, h['end'] - va)
        functions.append((h['kind'], h['copy'], '0x%x' % va, '0x%x' % h['end'], h['end'] - va, len(rows),
                          sum(r.length for r in rows), hashlib.sha256(body).hexdigest()))
        for r in rows:
            insn_rows.append((h['kind'], '0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))
        lits = literal_rows(image, rows)
        for row in lits:
            lit_rows.append((h['kind'], '0x%x' % va) + row)
        leas = [ins for ins in rows if ins.op == 'lea' and ins.rm[5]]
        if h['kind'] in ('time_newtype', 'address_newtype'):
            if len(leas) != 1:
                raise Reject('expected one error-text lea in 0x%x' % va)
            text = (leas[0].rm[4], 14)
            if h['kind'] == 'time_newtype':
                TIME_EXT_TEXT[h['copy']] = text
            else:
                ADDRESS_EXT_TEXT[:] = list(text)
        if h['kind'] == 'time_text':
            msgs = [x.rm[4] for x in leas
                    if image.read(x.rm[4], PANIC_TEXT_LEN).startswith(b'a Display implementation')]
            if len(msgs) != 1:
                raise Reject('expected one panic message lea in 0x%x' % va)
            PANIC_TEXT[0] = msgs[0]
        sites = {}
        for r in rows:
            if r.op in ('call', 'call_ind', 'jmp') and r.target not in (None,) and not va <= r.target < h['end']:
                sites[r.target] = sites.get(r.target, 0) + 1
            if r.op == 'call_mem':
                sites[h['roles']['write_char']] = sites.get(h['roles']['write_char'], 0) + 1
        for role, target in sorted(list(h['roles'].items()) + ([('grow', h['grow'])] if h['grow'] else [])):
            how = 'got slot' if any(r.op == 'call_ind' and r.target == target for r in rows) else (
                'vtable slot' if role == 'write_char' else ('tail jmp' if any(
                    r.op == 'jmp' and r.target == target for r in rows) else 'direct'))
            role_rows.append((h['kind'], h['copy'], '0x%x' % va, role, ROLE_KIND.get(role, 'grow'), how,
                              '0x%x' % target, sites[target]))

    # Key and error texts: inline imm64 pairs and rip-relative rodata are
    # read back from the bytes and must spell the reconstructed constants.
    text_rows = []
    for name, text in (('oi_key', KEY_OI), ('sub_deployers_key', KEY_SUB), ('users_cap_key', KEY_TAIL)):
        text_rows.append((name, text.decode(), len(text), '0x%02x' % (0xa0 | len(text))))
    text_rows.append(('ext_newtype_name', EXT_NAME.decode(), len(EXT_NAME), 'compared, not written'))
    for name, (va, n) in [('address_ext_error', ADDRESS_EXT_TEXT)] + [
            ('time_ext_error_copy%d' % c, TIME_EXT_TEXT[c]) for c in sorted(TIME_EXT_TEXT)] + [
            ('time_text_panic', (PANIC_TEXT[0], PANIC_TEXT_LEN))]:
        text_rows.append((name, image.read(va, n).decode('ascii'), n, '0x%x' % va))

    cases, mismatches, by_path = [], 0, {}
    for h in helpers:
        for inp, fail_at in case_inputs(h):
            stubs = make_stubs(h, Script(fail_at))
            got = run_helper(image, h, stubs, inp)
            exp = recon(h, inp, fail_at)
            ok = got == exp
            mismatches += not ok
            outcome = 'ok' if got[3][0] == OK_WORD else 'err'
            if got[1] and got[1][-1][1] == 'panic':
                outcome = 'panic'
            path = (h['kind'], '0x%x' % h['entry'], outcome, 'fail@-' if fail_at is None else 'fail@%d' % fail_at)
            by_path[path] = by_path.get(path, 0) + 1
            cases.append((h['kind'], '0x%x' % h['entry'], fmt_input(h, inp), '' if fail_at is None else fail_at,
                          got[0].hex(), fmt_log(got[1]), got[2], ','.join('0x%x' % x for x in got[3]),
                          'match' if ok else 'MISMATCH'))

    negatives = []
    for name in sorted(WRONG):
        caught, first = 0, ''
        for h in helpers:
            for inp, fail_at in case_inputs(h):
                if recon(h, inp, fail_at) != recon(h, inp, fail_at, WRONG[name]):
                    caught += 1
                    if not first:
                        first = '0x%x %s fail=%s' % (h['entry'], fmt_input(h, inp), fail_at)
        negatives.append((name, caught, 'caught' if caught else 'MISSED', first))

    summary = dict(
        target='artifacts/node/115/hl-node', sha256=SHA115,
        bodies=len(helpers), kinds=sorted(set(h['kind'] for h in helpers)),
        cases=len(cases), mismatches=mismatches, paths=len(by_path),
        negative_controls=len(negatives), negative_controls_caught=sum(1 for n in negatives if n[1]),
        hex_slot='0x%x' % HEX_SLOT, hex_slot_target='0x%x' % hex_target,
        hex_slot_rela_offset=slot[HEX_SLOT][0], decoded_instructions=len(insn_rows),
    )
    path_rows = [k + (n,) for k, n in sorted(by_path.items())]
    return dict(summary=summary, functions=functions, instructions=insn_rows, literals=lit_rows, roles=role_rows,
                texts=text_rows, cases=cases, negatives=negatives, paths=path_rows, slots=slot_rows)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(x) for x in r) + '\n' for r in rows)


def render(result):
    return {
        'summary.json': json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
        'functions.tsv': tsv(('kind', 'copy', 'entry', 'fde_end', 'fde_bytes', 'decoded_instructions',
                              'decoded_bytes', 'sha256'), result['functions']),
        'instructions.tsv': tsv(('kind', 'entry', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'literals.tsv': tsv(('kind', 'entry', 'source', 'va', 'text'), result['literals']),
        'callee-roles.tsv': tsv(('kind', 'copy', 'entry', 'role', 'role_kind', 'call', 'target', 'call_sites'),
                                result['roles']),
        'texts.tsv': tsv(('name', 'text', 'length', 'marker_or_va'), result['texts']),
        'relocated-slots.tsv': tsv(('slot', 'role', 'rela_file_offset', 'relative_addend'), result['slots']),
        'cases.tsv': tsv(('kind', 'entry', 'input', 'fail_at', 'appended_hex', 'calls', 'end_length', 'result',
                          'verdict'), result['cases']),
        'paths.tsv': tsv(('kind', 'entry', 'outcome', 'failing_call', 'cases'), result['paths']),
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
