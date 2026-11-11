#!/usr/bin/env python3
"""Reconstruct the node #115 Main/Hip3 per-DEX state codec and prove it.

Node #115 carries an externally tagged two-variant enum whose variant names are
`Main` and `Hip3`.  `Main` holds an open-interest-cap record (four fields) and
`Hip3` holds a limits/schema/state record with three optional fields.  This
producer authenticates the #115 capture, locates nine selected bodies by their
unwind (FDE) extents and runs each body's original machine code in a small
interpreter for the fixed x86-64 instruction subset the bodies use:

* three msgpack serializers of the whole enum value (two copies take
  (out, value, writer); one copy takes (out, writer, value) and first writes
  its own map key `moh`), including the struct-as-map flag, every inline
  key/marker write with its capacity-reserve branch, the optional-field count,
  the call order of the field helpers and every error-propagation exit;
* three exact-name visitors (`Main` -> 0, `Hip3` -> 1, otherwise the
  unknown-variant callee with the two-entry name pool).

Every interpreted result is compared with an independent pure-Python
reconstruction.  Field helpers are stubbed; their internals are outside the
claim.  Deliberately wrong reconstructions run through the same comparison
and must be caught.

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

NAMES = (b'Main', b'Hip3')
VARIANT_POOLS = (0x644cbb0, 0x648a408, 0x64a9c20)
VISITORS = (0x2b94d80, 0x4440220, 0x5469f10)

# Serializer copies.  Every role names the direct callee used for that step;
# the producer checks that the body's call targets are exactly these plus one
# capacity-grow callee.
SERIALIZERS = (
    dict(entry=0x2bc2700, order='value_writer', prefix=False,
         f1=0x21f4f80, f2=0x21f3d10, f3=0x2c7dea0, keyw=0x25e8bf0, f4=0x2246990, drop=0x26b45b0,
         maph=0x25e7540, arrh=0x25e7c10, limits=0x2bc1190, schema=0x2bc17c0, state=0x2bc0900,
         o30=0x21f4640, o90=0x21f5d30, o78=0x21f5ec0),
    dict(entry=0x44f6f40, order='writer_value', prefix=True,
         f1=0x4125e20, f2=0x4126a10, f3=0x4229cc0, keyw=0x41c6610, f4=0x4177e10, drop=None,
         maph=0x3d4f9a0, arrh=0x3d50540, limits=0x449e700, schema=0x449ef90, state=0x449dbc0,
         o30=0x4128630, o90=0x41277b0, o78=0x4129010),
    dict(entry=0x549d760, order='value_writer', prefix=False,
         f1=0x526fb90, f2=0x5270c20, f3=0x5616e10, keyw=0x57cf5d0, f4=0x52b7b50, drop=0x4e51e10,
         maph=0x57cdfd0, arrh=0x57cee80, limits=0x549be00, schema=0x549c580, state=0x549b950,
         o30=0x52706f0, o90=0x526e940, o78=0x5270100),
)
ROLES = ('f1', 'f2', 'f3', 'keyw', 'f4', 'drop', 'maph', 'arrh', 'limits', 'schema', 'state', 'o30', 'o90', 'o78')
KEYED = ('f1', 'f2', 'o30', 'o90', 'o78')            # (out, &compound, key, key_len, value)
VALUE_FIRST = ('f3', 'limits', 'schema', 'state')    # (out, value, writer)

# Reconstructed field keys (checked against the bytes the bodies reference).
MAIN_KEYS = dict(f1=b'asset_to_recent_oi', f2=b'override_max_oi_per_second',
                 f3=b'reset_recent_oi_bucket_guard', f4=b'assets_at_open_interest_cap')
HIP3_KEYS = dict(limits=b'limits', schema=b'schema', state=b'state',
                 o30=b'hip3_backstop_liquidator_state', o90=b'ss', o78=b'df')
PREFIX_KEY = b'moh'

NICHE_MAIN = 0x8000000000000000   # first word of the value selects Main
NONE_90 = 0x8000000000000001      # "absent" value of the word at +0x90
OK_WORD = 0x8000000000000004
HDR_OK = 2

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VEC_BASE = 0x3000_0000
DATA_BASE = 0x4000_0000
SCHEMA_PTR = 0x5000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
ERR_SENTINEL = 0xe770_0000_0000_0001
PATTERN = 0x1111_1111_1111_1111
ERR = (0x0e10_0000_0000_00a1, 0x0e20_0000_0000_00a2, 0x0e30_0000_0000_00a3)
ERR_KEY = (0x0e40_0000_0000_00b1, 0x0e50_0000_0000_00b2)


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
    elif two and op == 0x0fb6:
        reg, rm, _ = modrm()
        kw.update(op='movzx8', reg=reg, rm=rm)
    elif two and op == 0x0f95:
        reg, rm, _ = modrm()
        if not rex and rm[0] == 'reg' and 4 <= rm[1] <= 7:
            raise Reject('legacy high-byte register at 0x%x' % va)
        kw.update(op='setne', rm=rm, size=1)
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
    """Interpreter for the decoded subset.  Flags kept: ZF and CF."""

    def __init__(self, image, stubs):
        self.image = image
        self.stubs = stubs
        self.regs = {n: 0 for n in range(16)}
        self.xmm = {n: 0 for n in range(16)}
        self.mem = {}
        self.zf = self.cf = False
        self.calls = []
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
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), size)
            elif op == 'shl':
                r = (self.get(ins.rm, 1) << (ins.imm & 31)) & 0xff
                self.zf = r == 0
                self.put(ins.rm, r, 1)
            elif op == 'setne':
                self.put(ins.rm, 0 if self.zf else 1, 1)
            elif op == 'movups_load':
                self.xmm[ins.reg] = self.get(ins.rm, 16) if ins.rm[0] == 'mem' else self.xmm[ins.rm[1]]
            elif op == 'movups_store':
                if ins.rm[0] != 'mem':
                    raise Reject('register movups store at 0x%x' % pc)
                self.store(self.ea(ins.rm), self.xmm[ins.reg], 16)
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
            elif op == 'call':
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


# ---------------------------------------------------------------- stubs

class Script:
    """Per-run stub behaviour: which counted helper call (0-based) fails."""

    def __init__(self, copy, fail_at):
        self.copy = copy
        self.fail_at = fail_at
        self.counted = 0

    def fails(self):
        k = self.counted
        self.counted += 1
        return k == self.fail_at


def describe_value(ptr):
    if ptr == SCHEMA_PTR:
        return 'schema_ptr'
    if IN_BASE <= ptr < IN_BASE + 0x200:
        return 'value+0x%x' % (ptr - IN_BASE)
    raise Reject('helper value pointer 0x%x is outside the value' % ptr)


def make_stubs(image, copy, script, grow_target):
    roles = {copy[r]: r for r in ROLES if copy[r] is not None}

    def grow(m, args):
        vec, length, additional, align, elem = args
        if vec != VEC_BASE or (align, elem) != (1, 1):
            raise Reject('unexpected grow call arguments')
        cap = m.load(vec, 8)
        m.store(vec, max(cap * 2, length + additional, 8), 8)
        m.log.append(('grow', length, additional))
        return 0

    def helper(role):
        def stub(m, args):
            out, a1, a2, a3, a4 = args
            if role == 'drop':
                m.log.append(('drop', '0x%x' % m.load(out, 8)))
                return 0
            if role == 'keyw':
                if out != VEC_BASE:
                    raise Reject('key writer does not receive the writer')
                m.log.append(('key', image.read(a1, a2).decode('ascii')))
                if script.fails():
                    return ERR_KEY
                return HDR_OK
            if role in ('maph', 'arrh'):
                if a1 != VEC_BASE:
                    raise Reject('header writer does not receive the writer')
                m.log.append(('map_header' if role == 'maph' else 'array_header', a2 & 0xffffffff))
                if script.fails():
                    m.store(out, ERR[0], 8)
                    m.store(out + 8, ERR[1], 8)
                else:
                    m.store(out, HDR_OK, 8)
                return 0
            if role in KEYED:
                if m.load(a1, 8) != VEC_BASE:
                    raise Reject('keyed helper compound does not hold the writer')
                m.log.append(('field', image.read(a2, a3).decode('ascii'), describe_value(a4)))
            elif role in VALUE_FIRST:
                if a2 != VEC_BASE:
                    raise Reject('value helper does not receive the writer as third argument')
                m.log.append(('value', role, describe_value(a1)))
            else:  # f4: (out, writer, value)
                if a1 != VEC_BASE:
                    raise Reject('f4 does not receive the writer as second argument')
                m.log.append(('value', role, describe_value(a2)))
            if script.fails():
                for k in range(3):
                    m.store(out + 8 * k, ERR[k], 8)
            else:
                m.store(out, OK_WORD, 8)
            return 0
        return stub

    stubs = {grow_target: grow}
    for target, role in roles.items():
        stubs[target] = helper(role)
    return stubs


def error_stub(machine, args):
    return ERR_SENTINEL


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


def recon_serialize(copy, flag, value, cap, length, fail_at, variant=None):
    """Pure reconstruction of one serializer call.

    `value` maps word offsets of the enum value to their contents.  Returns
    (appended bytes, call log, final length, three result words).
    `variant` overrides the decision rules for negative controls.
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

    err3 = ERR
    keys_on = v.get('keys_on', lambda f: f == 1)(flag)
    if copy['prefix'] and flag != 0:
        w.fixstr(PREFIX_KEY)
    is_main = v.get('is_main', lambda head: head == NICHE_MAIN)(value[0])
    if is_main:
        w.put(b'\x81')
        w.fixstr(b'Main')
        w.put(bytes([v.get('main_header', lambda f: (((f ^ 1) << 4) | 0x84) & 0xff)(flag)]))
        order = v.get('main_order', ('f1', 'f2'))
        offs = dict(f1=0x8, f2=0x28)
        for role in order:
            log.append(('field', MAIN_KEYS[role].decode(), 'value+0x%x' % offs[role]))
            if fails():
                return done(err3)
        if keys_on:
            w.fixstr(MAIN_KEYS['f3'])
        log.append(('value', 'f3', 'value+0x48'))
        if fails():
            return done(err3)
        if keys_on:
            log.append(('key', MAIN_KEYS['f4'].decode()))
            if fails():
                return done((NICHE_MAIN,) + ERR_KEY)
        log.append(('value', 'f4', 'value+0x58'))
        if fails():
            return done(err3)
        return done((OK_WORD, PATTERN, PATTERN))
    present30 = value[0x30] != 0
    present90 = value[0x90] != NONE_90
    present78 = value[0x78] != 0
    drops = copy['drop'] is not None and not v.get('no_drop')
    if drops:
        log.append(('drop', '0x%x' % NONE_90))
    w.put(b'\x81')
    w.fixstr(b'Hip3')
    count = v.get('count', lambda a, b, c: 3 + a + b + c)(present30, present90, present78)
    as_map = v.get('as_map', lambda f: f != 0)(flag)
    log.append(('map_header' if as_map else 'array_header', count))
    if fails():
        return done((NICHE_MAIN,) + ERR[:2])
    for role, where in (('limits', 'value+0xf8'), ('schema', 'schema_ptr'), ('state', 'value+0xd0')):
        if keys_on:
            w.fixstr(HIP3_KEYS[role])
        log.append(('value', role, where))
        if fails():
            return done(err3)
    if present30:
        log.append(('field', HIP3_KEYS['o30'].decode(), 'value+0x0'))
        if fails():
            return done(err3)
    if drops:
        log.append(('drop', '0x%x' % NONE_90))
    if present90:
        log.append(('field', HIP3_KEYS['o90'].decode(), 'value+0x90'))
        if fails():
            return done(err3)
    if present78:
        log.append(('field', HIP3_KEYS['o78'].decode(), 'value+0x48'))
        if fails():
            return done(err3)
    return done((OK_WORD, PATTERN, PATTERN))


def recon_classify(text):
    return NAMES.index(text) if text in NAMES else None


def recon_visitor(text):
    tag = recon_classify(text)
    return ('err', None) if tag is None else ('ok', 0x09 | (tag << 8))


# Deliberately wrong reconstructions (negative controls).
WRONG_SERIALIZERS = {
    'header_always_map': dict(as_map=lambda f: True),
    'keys_when_flag_nonzero': dict(keys_on=lambda f: f != 0),
    'count_ignores_options': dict(count=lambda a, b, c: 6),
    'count_ignores_ss': dict(count=lambda a, b, c: 3 + a + c),
    'main_fields_swapped': dict(main_order=('f2', 'f1')),
    'main_header_always_map': dict(main_header=lambda f: 0x84),
    'niche_range_main': dict(is_main=lambda head: head >= NICHE_MAIN),
    'drops_omitted': dict(no_drop=True),
    'reserve_inclusive': dict(reserve_inclusive=True),
}


def wrong_prefix(text):
    for k, n in enumerate(NAMES):
        if text[:len(n)] == n:
            return k
    return None


def wrong_casefold(text):
    low = [n.lower() for n in NAMES]
    return low.index(text.lower()) if text.lower() in low else None


def wrong_swap(text):
    t = recon_classify(text)
    return {0: 1, 1: 0}.get(t, t)


def wrong_three_bytes(text):
    for k, n in enumerate(NAMES):
        if len(text) == 4 and text[:3] == n[:3]:
            return k
    return None


# ---------------------------------------------------------------- drivers

def value_cases():
    """(label, word map) for the enum value; offsets read by the serializers."""
    rows = [('Main', {0: NICHE_MAIN, 0x30: 0, 0x78: 0, 0x90: NONE_90})]
    for p30 in (0, 1):
        for p90 in (0, 1):
            for p78 in (0, 1):
                rows.append(('Hip3/o30=%d,ss=%d,df=%d' % (p30, p90, p78),
                             {0: 0, 0x30: 7 * p30, 0x78: 3 * p78, 0x90: 0x55 if p90 else NONE_90}))
    for head in (NICHE_MAIN + 1, NICHE_MAIN - 1, MASK):
        rows.append(('Hip3/head=0x%x' % head, {0: head, 0x30: 1, 0x78: 1, 0x90: 0}))
    return rows


def run_serializer(image, copy, stubs, flag, value, cap, length):
    m = Machine(image, stubs)
    for k in range(3):
        m.store(OUT_BASE + 8 * k, PATTERN, 8)
    for off in range(0, 0x140, 8):
        m.store(IN_BASE + off, 0x7777_0000_0000_0000 | off, 8)
    for off, word in value.items():
        m.store(IN_BASE + off, word, 8)
    m.store(IN_BASE + 0x128, SCHEMA_PTR, 8)
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, length, 8)
    m.store(VEC_BASE + 24, 0x0000_0000_0000_0000 | (flag << 24), 8)
    if copy['order'] == 'value_writer':
        m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, VEC_BASE
    else:
        m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, VEC_BASE, IN_BASE
    m.run(copy['entry'])
    # Copies taking (out, value, writer) return the out pointer; the
    # (out, writer, value) copy returns through out only.
    if copy['order'] == 'value_writer' and m.regs[0] != OUT_BASE:
        raise Reject('serializer 0x%x does not return its output pointer' % copy['entry'])
    end = m.load(VEC_BASE + 16, 8)
    data = bytes(m.load(DATA_BASE + k, 1) for k in range(length, end))
    result = tuple(m.load(OUT_BASE + 8 * k, 8) for k in range(3))
    return data, m.log, end, result, m


def run_visitor(image, entry, stubs, text, pool):
    m = Machine(image, stubs)
    m.store(OUT_BASE, 0xa5a5_a5a5_a5a5_a5a5, 8)
    for k in range(32):
        m.store(IN_BASE + k, 0x00, 1)
    for k, b in enumerate(text):
        m.store(IN_BASE + k, b, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, len(text)
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('visitor 0x%x does not return its output pointer' % entry)
    if m.calls:
        (site, target, args), = m.calls
        if args != (OUT_BASE, IN_BASE, len(text), pool, len(NAMES)):
            raise Reject('error call arguments differ at 0x%x' % site)
        return ('err', None), m
    return ('ok', m.load(OUT_BASE, 2)), m


def visitor_inputs():
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
        for extra in (b'x', n[-1:], b'\0', b' '):
            add(n + extra)
            add(extra + n)
        add(n.lower())
        add(n.upper())
        for pos in range(len(n)):
            for val in range(256):
                add(n[:pos] + bytes([val]) + n[pos + 1:])
    add(NAMES[0] + NAMES[1])
    add(b'Hain')
    add(b'Mip3')
    for ln in range(0, 9):
        add(b'A' * ln)
    return seen


def esc(b):
    return b.hex() if b else '-'


def fmt_log(log):
    parts = []
    for e in log:
        if e[0] == 'grow':
            parts.append('grow(%d+%d)' % (e[1], e[2]))
        else:
            parts.append('%s(%s)' % (e[0], ','.join(str(x) for x in e[1:])))
    return ' '.join(parts) or '-'


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows, bodies = [], [], {}
    entries = [('serializer', c['entry']) for c in SERIALIZERS] + [('visitor', va) for va in VISITORS]
    for role, va in entries:
        if va not in by_start:
            raise Reject('0x%x is not an FDE start' % va)
        rec = by_start[va]
        rows = linear(image, va, rec['end'])
        bodies[va] = rows
        body = image.read(va, rec['end'] - va)
        calls = sorted(set(r.target for r in rows if r.op == 'call'))
        functions.append(dict(role=role, entry='0x%x' % va, fde_end='0x%x' % rec['end'], fde_bytes=rec['end'] - va,
                              decoded_instructions=len(rows), decoded_bytes=sum(r.length for r in rows),
                              sha256=hashlib.sha256(body).hexdigest(),
                              callees=','.join('0x%x' % t for t in calls)))
        for r in rows:
            insn_rows.append((role, '0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))

    # Callee roles: every call target of a serializer body is a declared role
    # or the single capacity-grow callee.
    role_rows, grow_of = [], {}
    for c in SERIALIZERS:
        targets = sorted(set(r.target for r in bodies[c['entry']] if r.op == 'call'))
        declared = set(c[r] for r in ROLES if c[r] is not None)
        extra = [t for t in targets if t not in declared]
        if len(extra) != 1 or not declared <= set(targets):
            raise Reject('callee set of 0x%x differs from the role table' % c['entry'])
        grow_of[c['entry']] = extra[0]
        sites = {}
        for r in bodies[c['entry']]:
            if r.op == 'call':
                sites.setdefault(r.target, []).append(r.va)
        for role in ROLES + ('grow',):
            t = extra[0] if role == 'grow' else c[role]
            if t is None:
                role_rows.append(('0x%x' % c['entry'], role, '-', 0, '-'))
            else:
                role_rows.append(('0x%x' % c['entry'], role, '0x%x' % t, len(sites[t]),
                                  ','.join('0x%x' % s for s in sites[t])))

    # Key literals: every rip-relative key pointer with its length immediate
    # and every inline immediate store into the writer, in body order.
    lit_rows = []
    for c in SERIALIZERS:
        rows = bodies[c['entry']]
        for k, r in enumerate(rows):
            if r.op == 'lea' and r.rm[5] and r.reg in (2, 6):
                ln = [x for x in rows[k + 1:k + 6] if x.op == 'movimm' and x.reg in (1, 2)]
                if not ln:
                    raise Reject('key pointer without length at 0x%x' % r.va)
                text = image.read(r.rm[4], ln[0].imm)
                lit_rows.append(('0x%x' % c['entry'], '0x%x' % r.va, 'key_ref', '0x%x' % r.rm[4], ln[0].imm,
                                 text.decode('ascii')))
            elif r.op == 'movups_load' and r.rm[0] == 'mem' and r.rm[5]:
                lit_rows.append(('0x%x' % c['entry'], '0x%x' % r.va, 'key_vector16', '0x%x' % r.rm[4], 16,
                                 image.read(r.rm[4], 16).decode('ascii')))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.rm[2] is not None:
                raw = (r.imm & ((1 << (8 * r.size)) - 1)).to_bytes(r.size, 'little')
                text = raw.decode('ascii') if all(0x20 <= b < 0x7f for b in raw) and r.size > 1 else '-'
                lit_rows.append(('0x%x' % c['entry'], '0x%x' % r.va, 'store%d' % (8 * r.size), raw.hex(), r.size, text))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1:
                lit_rows.append(('0x%x' % c['entry'], '0x%x' % r.va, 'flag_cmp', '0x%x' % r.rm[4], 1, '%d' % r.imm))
    want_keys = set(MAIN_KEYS.values()) | set(HIP3_KEYS[k] for k in ('o30', 'o90', 'o78'))
    for c in SERIALIZERS:
        got = set(r[5].encode() for r in lit_rows if r[0] == '0x%x' % c['entry'] and r[2] == 'key_ref')
        if not (got | {MAIN_KEYS['f3']}) >= want_keys:
            raise Reject('serializer 0x%x does not reference every reconstructed key' % c['entry'])
        pieces = [r for r in lit_rows if r[0] == '0x%x' % c['entry'] and r[2] == 'key_vector16']
        if len(pieces) != 2 or (pieces[1][5] + pieces[0][5][4:]).encode() != MAIN_KEYS['f3']:
            raise Reject('28-byte key of 0x%x differs' % c['entry'])

    # Visitor pools and literals.
    vis_lits, pools = [], {}
    for va in VISITORS:
        rows = bodies[va]
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]]
        if len(leas) != 1:
            raise Reject('visitor 0x%x does not reference exactly one pool' % va)
        pools[va] = leas[0].rm[4]
        for r in rows:
            if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg':
                vis_lits.append(('0x%x' % va, '0x%x' % r.va, 'length_gate', '%d' % r.imm))
            elif r.op == 'cmp' and r.ext == 'imm':
                vis_lits.append(('0x%x' % va, '0x%x' % r.va, 'cmp_imm32',
                                 (r.imm & 0xffffffff).to_bytes(4, 'little').decode('ascii')))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem':
                vis_lits.append(('0x%x' % va, '0x%x' % r.va, 'result_store%d' % (8 * r.size), '0x%x' % r.imm))
            elif r.op == 'movimm' and r.reg == 8:
                vis_lits.append(('0x%x' % va, '0x%x' % r.va, 'variant_count', '%d' % r.imm))
            elif r.op == 'lea' and r.rm[5]:
                vis_lits.append(('0x%x' % va, '0x%x' % r.va, 'variant_pool', '0x%x' % r.rm[4]))
    if tuple(pools[va] for va in VISITORS) != VARIANT_POOLS:
        raise Reject('variant pool references differ')
    table_rows = []
    for pool in VARIANT_POOLS:
        relocs = image.relative_addends({pool + 16 * k for k in range(len(NAMES))})
        texts = []
        for k in range(len(NAMES)):
            slot = pool + 16 * k
            if slot not in relocs:
                raise Reject('no RELATIVE relocation for variant slot 0x%x' % slot)
            pos, add = relocs[slot]
            ln = struct.unpack('<Q', image.read(slot + 8, 8))[0]
            text = image.read(add, ln)
            texts.append(text)
            table_rows.append(('0x%x' % pool, k, '0x%x' % slot, '0x%x' % pos, '0x%x' % add, ln, text.decode('ascii')))
        if tuple(texts) != NAMES:
            raise Reject('variant name pool 0x%x differs from reconstruction order' % pool)

    # Serializer comparison: capacity sweep (no failure) and failure injection.
    values = value_cases()
    ser_rows, fail_rows = [], []
    ser_ok = ser_total = 0
    neg = {k: 0 for k in WRONG_SERIALIZERS}
    path_counts = {}

    def compare(c, flag, label, value, cap, length, fail_at, sink):
        nonlocal ser_ok, ser_total
        script = Script(c, fail_at)
        stubs = make_stubs(image, c, script, grow_of[c['entry']])
        got = run_serializer(image, c, stubs, flag, value, cap, length)
        got4 = got[:4]
        want = recon_serialize(c, flag, value, cap, length, fail_at)
        same = (got4[0], got4[1], got4[2], got4[3]) == want
        ser_total += 1
        ser_ok += same
        for name, variant in WRONG_SERIALIZERS.items():
            neg[name] += got4 != recon_serialize(c, flag, value, cap, length, fail_at, variant)
        key = ('0x%x' % c['entry'], got[4].steps, 'ok' if got4[3][0] == OK_WORD else 'err')
        path_counts[key] = path_counts.get(key, 0) + 1
        sink.append(('0x%x' % c['entry'], flag, label, cap, length, '-' if fail_at is None else fail_at,
                     esc(got4[0]), fmt_log(got4[1]), got4[2], ':'.join('%016x' % x for x in got4[3]),
                     'match' if same else 'MISMATCH'))
        return got4

    for c in SERIALIZERS:
        for flag in (0, 1, 2):
            for label, value in values:
                for spare in range(0, 40):
                    compare(c, flag, label, value, spare, 0, None, ser_rows)
                for length in (5, 100):
                    compare(c, flag, label, value, length + 64, length, None, ser_rows)
                # failure injection: every counted helper call in turn
                base = recon_serialize(c, flag, value, 256, 0, None)
                counted = sum(1 for e in base[1] if e[0] in ('field', 'value', 'key', 'map_header', 'array_header'))
                for k in range(counted):
                    compare(c, flag, label, value, 256, 0, k, fail_rows)

    # Visitor comparison.
    inputs = visitor_inputs()
    vstubs = {}
    for va in VISITORS:
        for r in bodies[va]:
            if r.op == 'call':
                vstubs[r.target] = error_stub
    vis_rows, vis_ok, vis_total = [], 0, 0
    neg_vis = {'prefix_match': [wrong_prefix, 0], 'case_fold': [wrong_casefold, 0],
               'swap_main_hip3': [wrong_swap, 0], 'first_three_bytes': [wrong_three_bytes, 0]}
    for text in inputs:
        row = [esc(text), len(text)]
        outcomes = []
        for va in VISITORS:
            (status, value), m = run_visitor(image, va, vstubs, text, pools[va])
            want = recon_visitor(text)
            same = (status, value) == want
            vis_total += 1
            vis_ok += same
            key = ('0x%x' % va, m.steps, status)
            path_counts[key] = path_counts.get(key, 0) + 1
            outcomes.append('%s:%s%s' % (status, '-' if value is None else '0x%x' % value, '' if same else '!'))
            got_tag = None if status == 'err' else value >> 8
            for item in neg_vis.values():
                item[1] += item[0](text) != got_tag
        row += outcomes
        tag = recon_classify(text)
        row.append('-' if tag is None else NAMES[tag].decode())
        row.append('match' if all(not o.endswith('!') for o in outcomes) else 'MISMATCH')
        vis_rows.append(tuple(row))

    paths = [(f, s, o, n) for (f, s, o), n in sorted(path_counts.items())]
    total_cases = ser_total
    negatives = ([('serializer', k, v, total_cases) for k, v in sorted(neg.items())]
                 + [('visitor', k, v[1], vis_total) for k, v in sorted(neg_vis.items())])
    summary = dict(
        target='node115', sha256=SHA115, component='dex-registry',
        functions=len(entries), decoded_instructions=len(insn_rows),
        names=[n.decode() for n in NAMES], variant_pools=['0x%x' % p for p in VARIANT_POOLS],
        serializer_cases=ser_total, serializer_matches=ser_ok,
        capacity_cases=len(ser_rows), failure_cases=len(fail_rows),
        visitor_inputs=len(inputs), visitor_cases=vis_total, visitor_matches=vis_ok,
        grow_callees=['0x%x' % grow_of[c['entry']] for c in SERIALIZERS],
        distinct_paths=len(paths),
        negative_controls={'%s/%s' % (a, b): n for a, b, n, _ in negatives},
        all_negative_controls_caught=all(n > 0 for _, _, n, _ in negatives),
        reconstruction_matches_all=(ser_ok == ser_total and vis_ok == vis_total),
    )
    return dict(functions=functions, instructions=insn_rows, roles=role_rows, literals=lit_rows,
                visitor_literals=vis_lits, variant_tables=table_rows, serializer=ser_rows, failures=fail_rows,
                visitor=vis_rows, paths=paths, negatives=negatives, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


CASE_HEADER = ('serializer', 'flag', 'value', 'capacity', 'length', 'fail_at', 'appended_hex', 'calls',
               'final_length', 'result', 'verdict')


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('role', 'function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callee-roles.tsv': tsv(('serializer', 'role', 'callee', 'call_sites', 'sites'), result['roles']),
        'serializer-literals.tsv': tsv(('serializer', 'va', 'form', 'value', 'size', 'text'), result['literals']),
        'visitor-literals.tsv': tsv(('visitor', 'va', 'form', 'value'), result['visitor_literals']),
        'variant-pool.tsv': tsv(('pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'), result['variant_tables']),
        'serializer-cases.tsv': tsv(CASE_HEADER, result['serializer']),
        'failure-cases.tsv': tsv(CASE_HEADER, result['failures']),
        'visitor-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v for v in VISITORS) + ('reconstruction', 'verdict'), result['visitor']),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'cases'), result['paths']),
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
    print('serializer %d/%d, visitor %d/%d, negatives caught: %s' % (
        s['serializer_matches'], s['serializer_cases'], s['visitor_matches'], s['visitor_cases'],
        s['all_negative_controls_caught']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
