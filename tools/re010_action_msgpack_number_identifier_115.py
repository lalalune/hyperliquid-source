#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack numeric identifier path and prove it.

When an rmp_serde `deserialize_any` sees a nil/bool/int/float marker it hands
(out, deserializer, marker, data byte) to a 653-byte number dispatcher. node
#115 has five copies of it (0x14b7dc0, 0x33fc5f0, 0x3408270, 0x3408ab0,
0x3486dd0), one per serde-derived variant-identifier visitor. Each copy reads
the big-endian payload, then calls the visitor: unsigned values go to a
`visit_u64` that maps an integer to a variant index through a jump table and
rejects out-of-range values with `invalid_value(Unsigned(v), "variant index
0 <= i < N")`; nil, bool, signed and float values reach small visitor methods
that return `invalid_type(Unit | Bool | Signed | Float)`. The copy reached
from the `Action` identifier decoder (0x1af3b70 GOT slot 0x64e3f30) is the
N = 92 copy. This tool:

1. checks the input digest, takes each function's extent from its FDE,
   decodes every instruction with a fixed-pattern x86-64 subset decoder and
   proves the five dispatcher copies are the same shape (rel32/disp32 aside);
2. reads every jump table (marker -> arm, integer -> variant index) and the
   rodata operands (error texts, expected strings) from the bytes;
3. interprets the original bytes of the dispatcher and all nine callees of
   every copy (the binary is never run; only the shared error formatter is a
   contract stub) over inputs built from the tables;
4. compares each outcome with a pure reconstruction (`reconstructed`):
   result, Unexpected kind and payload bits, expected text, input cursor;
5. proves full instruction coverage and that wrong reconstructions and
   corrupted images are rejected.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
DISPATCH_SIZE = 653

# (label, dispatcher start, GOT slot holding it as an R_X86_64_RELATIVE target)
COPIES = (
    ('N1', 0x14b7dc0, 0x64dff80),
    ('N2', 0x33fc5f0, 0x64e3f30),
    ('N3', 0x3408270, 0x64e2ef0),
    ('N4', 0x3408ab0, 0x64e4998),
    ('N5', 0x3486dd0, 0x64e4b20),
)
# Direct callees in order of first appearance. Role names are inferences that
# the case comparison below checks (a wrong role gives a mismatch).
ROLES = ('visit_f32', 'visit_f64', 'visit_i8', 'visit_u64', 'visit_i32', 'visit_i16',
         'visit_bool', 'visit_unit', 'visit_i64')
# serde::de::Unexpected discriminants written by the callees.
UNEXPECTED = {0: 'Bool', 1: 'Unsigned', 2: 'Signed', 3: 'Float', 7: 'Unit'}
MARKER_LO, MARKER_N = 0xc0, 33

IN_BASE, OUT_BASE, DES_BASE = 0x7000_0000_0000, 0x7100_0000_0000, 0x7180_0000_0000
STACK_TOP = 0x7200_0000_0000
MASK64 = (1 << 64) - 1
STEP_LIMIT = 200
OUT_FILL, STACK_FILL, DES_FILL = 0xaa, 0x5c, 0x3d


class Fault(Exception):
    pass


class Image:
    def __init__(self, data, check=True):
        if check and hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('input binary SHA-256 mismatch')
        self.data = data
        # NOBITS sections carry no file bytes and are excluded from VA reads.
        self.secs = [s for s in sections(data) if s['type'] != 8 and s['address'] and s['size']]
        self.by_name = {s['name']: s for s in self.secs}
        self.relative = {}
        rd = self.by_name['.rela.dyn']
        for i in range(rd['size'] // 24):
            off, info, add = struct.unpack_from('<QQq', data, rd['offset'] + i * 24)
            if info & 0xffffffff == 8:
                self.relative[off] = add
        _, fdes = eh_frame_records(data)
        self.fde = {}
        for f in fdes:
            self.fde.setdefault(f['start'], []).append(f)

    def off(self, va, n=1):
        for s in self.secs:
            if s['address'] <= va and va + n <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise Fault(f'unmapped static read {va:#x}+{n}')

    def read(self, va, n):
        o = self.off(va, n)
        return self.data[o:o + n]

    def extent(self, start):
        rows = self.fde.get(start, [])
        if len(rows) != 1:
            raise Fault(f'{start:#x} is not the start of exactly one FDE')
        return rows[0]['end']

    def table(self, va, n):
        return [va + struct.unpack('<i', self.read(va + 4 * i, 4))[0] for i in range(n)]

    def str_at(self, va, n):
        return self.read(va, n).decode()


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw', 'rel')


ALU_NAMES = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')


def decode(img, va):
    """Decode one instruction of the fixed subset used by these functions."""
    b = img.read(va, 16)
    p, opsz, rep, repne, rex = 0, None, False, False, 0
    while b[p] in (0x66, 0xf3, 0xf2):
        opsz = 16 if b[p] == 0x66 else opsz
        rep = rep or b[p] == 0xf3
        repne = repne or b[p] == 0xf2
        p += 1
    if 0x40 <= b[p] <= 0x4f:
        rex = b[p]
        p += 1
    W, R, X, B = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    width = 64 if W else (opsz or 32)
    ins = Insn()
    ins.va, ins.w, ins.a, ins.b, ins.rel = va, width, None, None, None

    def modrm():
        nonlocal p
        m = b[p]
        p += 1
        mod, reg, rm = m >> 6, (m >> 3 & 7) | R << 3, m & 7
        if mod == 3:
            return reg, ('r', rm | B << 3)
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = b[p]
            p += 1
            scale, idx, bs = 1 << (sib >> 6), (sib >> 3 & 7) | X << 3, sib & 7
            index = None if idx == 4 else idx
            if bs == 5 and mod == 0:
                raise Fault(f'absolute SIB address at {va:#x}')
            base = bs | B << 3
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | B << 3
        if rip:
            ins.rel = p
            disp = struct.unpack_from('<i', b, p)[0]
            p += 4
        elif mod == 1:
            disp = sx(b[p], 8)
            p += 1
        elif mod == 2:
            disp = struct.unpack_from('<i', b, p)[0]
            p += 4
        else:
            disp = 0
        return reg, ('m', base, index, scale, disp, rip)

    def reg8(n):
        # Without REX, byte registers 4..7 are ah/ch/dh/bh; the subset rejects them.
        if not rex and 4 <= n <= 7:
            raise Fault(f'high byte register at {va:#x}')
        return ('r', n)

    def low8(opnd):
        if opnd[0] == 'r':
            reg8(opnd[1])
        return opnd

    def imm(n):
        nonlocal p
        v = int.from_bytes(b[p:p + n], 'little')
        p += n
        return v

    op = b[p]
    p += 1
    if repne and op != 0x0f:
        raise Fault(f'f2 prefix on {op:02x} at {va:#x}')
    if op < 0x40 and op & 7 < 4:
        reg, rm = modrm()
        ins.op = ALU_NAMES[op >> 3]
        if ins.op in ('adc', 'sbb'):
            raise Fault(f'carry ALU at {va:#x}')
        if not op & 1:
            ins.w = 8
            rm, reg_o = low8(rm), reg8(reg)
        else:
            reg_o = ('r', reg)
        ins.a, ins.b = (rm, reg_o) if not op & 2 else (reg_o, rm)
    elif op < 0x40 and op & 7 in (4, 5):
        ins.op = ALU_NAMES[op >> 3]
        if op & 7 == 4:
            ins.w, ins.a, ins.b = 8, ('r', 0), ('i', imm(1))
        else:
            n = 2 if width == 16 else 4
            ins.a, ins.b = ('r', 0), ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif op in (0x84, 0x85, 0x88, 0x89, 0x8a, 0x8b):
        reg, rm = modrm()
        ins.op = 'test' if op < 0x88 else 'mov'
        if not op & 1:
            ins.w = 8
            rm, reg_o = low8(rm), reg8(reg)
        else:
            reg_o = ('r', reg)
        ins.a, ins.b = (reg_o, rm) if op in (0x8a, 0x8b) else (rm, reg_o)
    elif op in (0x81, 0x83, 0x80):
        reg, rm = modrm()
        ins.op = ALU_NAMES[reg & 7]
        if ins.op in ('adc', 'sbb'):
            raise Fault(f'carry ALU at {va:#x}')
        if op == 0x80:
            ins.w = 8
            rm = low8(rm)
            ins.b = ('i', imm(1))
        elif op == 0x83:
            ins.b = ('i', sx(imm(1), 8) & ((1 << width) - 1))
        else:
            n = 2 if width == 16 else 4
            ins.b = ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
        ins.a = rm
    elif op == 0xc1:
        reg, rm = modrm()
        if reg & 7 != 0 or rm[0] != 'r':
            raise Fault(f'unsupported shift form at {va:#x}')
        ins.op, ins.a, ins.b = 'rol', rm, imm(1)
    elif op in (0xfe, 0xff):
        reg, rm = modrm()
        k = reg & 7
        if op == 0xfe:
            if k > 1:
                raise Fault(f'unsupported fe form at {va:#x}')
            ins.op, ins.a, ins.w = ('inc', 'dec')[k], low8(rm), 8
        elif k in (0, 1):
            ins.op, ins.a = ('inc', 'dec')[k], rm
        elif k == 4:
            ins.op, ins.a, ins.w = 'jmpr', rm, 64
        else:
            raise Fault(f'unsupported ff form at {va:#x}')
    elif op == 0x8d:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'lea', ('r', reg), rm
    elif op == 0x63:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'movsxd', ('r', reg), rm
    elif op == 0xc7:
        reg, rm = modrm()
        n = 2 if width == 16 else 4
        ins.op, ins.a, ins.b = 'mov', rm, ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif op == 0xc6:
        reg, rm = modrm()
        ins.op, ins.a, ins.b, ins.w = 'mov', low8(rm), ('i', imm(1)), 8
    elif 0xb0 <= op <= 0xb7:
        ins.op, ins.a, ins.w = 'mov', reg8((op - 0xb0) | B << 3), 8
        ins.b = ('i', imm(1))
    elif 0xb8 <= op <= 0xbf:
        ins.op, ins.a = 'mov', ('r', (op - 0xb8) | B << 3)
        ins.b = ('i', imm(8 if W else 4))
    elif 0x50 <= op <= 0x57:
        ins.op, ins.a, ins.w = 'push', ('r', (op - 0x50) | B << 3), 64
    elif 0x58 <= op <= 0x5f:
        ins.op, ins.a, ins.w = 'pop', ('r', (op - 0x58) | B << 3), 64
    elif 0x70 <= op <= 0x7f:
        ins.op, ins.a = 'j', op & 15
        ins.b = sx(imm(1), 8)
    elif op == 0xeb:
        ins.op, ins.b = 'jmp', sx(imm(1), 8)
    elif op in (0xe8, 0xe9):
        ins.rel = p
        ins.op, ins.b = ('call' if op == 0xe8 else 'jmp'), sx(imm(4), 32)
    elif op == 0xc3:
        ins.op = 'ret'
    elif op == 0x0f:
        op2 = b[p]
        p += 1
        if 0x80 <= op2 <= 0x8f:
            ins.rel = p
            ins.op, ins.a, ins.b = 'j', op2 & 15, sx(imm(4), 32)
        elif op2 in (0xb6, 0xb7, 0xbe, 0xbf):
            reg, rm = modrm()
            ins.op = 'movzx' if op2 < 0xb8 else 'movsx'
            ins.a, ins.b = ('r', reg), rm
            ins.w = 8 if op2 & 1 == 0 else 16
            if ins.w == 8:
                low8(rm)
            ins.raw = width
        elif op2 == 0x10 and not rep and not repne and opsz is None:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xload', reg, rm
        elif op2 == 0x11 and not rep and not repne and opsz is None:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xstore', rm, reg
        elif op2 == 0x11 and repne:
            reg, rm = modrm()
            if rm[0] != 'm':
                raise Fault(f'register movsd at {va:#x}')
            ins.op, ins.a, ins.b = 'movsd_st', rm, reg
        elif op2 == 0x6e and opsz == 16:
            reg, rm = modrm()
            if rm[0] != 'r':
                raise Fault(f'memory movd at {va:#x}')
            # 66 is the mandatory SSE prefix here, not an operand-size override
            ins.op, ins.a, ins.b, ins.w = 'movdx', reg, rm, 64 if W else 32
        elif op2 == 0x5a and rep:
            reg, rm = modrm()
            if rm[0] != 'r':
                raise Fault(f'memory cvtss2sd at {va:#x}')
            ins.op, ins.a, ins.b = 'cvtss2sd', reg, rm[1]
        elif 0xc8 <= op2 <= 0xcf:
            ins.op, ins.a = 'bswap', ('r', (op2 - 0xc8) | B << 3)
        elif op2 == 0x0b:
            ins.op = 'ud2'
        else:
            raise Fault(f'unsupported 0f {op2:02x} at {va:#x}')
    else:
        raise Fault(f'unsupported opcode {op:02x} at {va:#x}')
    dst = ins.raw if ins.op in ('movzx', 'movsx') else None
    ins.size = p
    ins.raw = bytes(b[:p])
    if dst is not None:
        ins.b = (ins.b, dst)  # (source operand, destination width)
    return ins


def sweep(img, start, end):
    """Linear decode of [start, end); every byte must belong to a decoded instruction."""
    out, va = [], start
    while va < end:
        ins = decode(img, va)
        out.append(ins)
        va += ins.size
    if va != end:
        raise Fault('instruction sweep overruns the FDE end')
    return out


def shape(ins):
    """Instruction bytes with the rel32/disp32 field zeroed (copies differ only there)."""
    raw = bytearray(ins.raw)
    if ins.rel is not None:
        raw[ins.rel:ins.rel + 4] = bytes(4)
    return bytes(raw)


def target(ins):
    return ins.va + ins.size + ins.b


def rip_operand(ins):
    for o in (ins.a, ins.b):
        if isinstance(o, tuple) and o and o[0] == 'm' and o[5]:
            return ins.va + ins.size + o[4]
    return None


class Copy:
    """Static facts of one dispatcher copy and its callees, all read from the bytes."""

    def __init__(self, img, label, start, slot):
        self.label, self.start, self.slot = label, start, slot
        self.end = img.extent(start)
        if self.end - start != DISPATCH_SIZE:
            raise Fault(f'{label}: FDE extent is {self.end - start} bytes')
        if img.relative.get(slot) != start:
            raise Fault(f'{label}: GOT slot {slot:#x} does not hold the dispatcher')
        self.insns = sweep(img, start, self.end)
        self.callees = []
        for ins in self.insns:
            if ins.op == 'call' and target(ins) not in self.callees:
                self.callees.append(target(ins))
        if len(self.callees) != len(ROLES):
            raise Fault(f'{label}: {len(self.callees)} direct callees')
        self.role = dict(zip(self.callees, ROLES))
        self.by_role = dict(zip(ROLES, self.callees))
        leas = [rip_operand(i) for i in self.insns if i.op == 'lea' and rip_operand(i)]
        self.marker_va, self.eof_err = leas[0], leas[1]
        self.marker_arms = img.table(self.marker_va, MARKER_N)
        # Callee bodies and the one formatter they share.
        self.funcs = {start: self.insns}
        self.fmt = set()
        for c in self.callees:
            body = sweep(img, c, img.extent(c))
            self.funcs[c] = body
            for ins in body:
                if ins.op == 'call':
                    self.fmt.add(target(ins))
        if len(self.fmt) != 1:
            raise Fault(f'{label}: callees call {len(self.fmt)} distinct formatters')
        self.fmt = self.fmt.pop()
        u64 = self.funcs[self.by_role['visit_u64']]
        if not (u64[1].op == 'cmp' and u64[1].b[0] == 'i' and u64[2].op == 'j' and u64[2].a == 7):
            raise Fault(f'{label}: visit_u64 does not open with cmp imm / ja')
        self.n_variants = u64[1].b[1] + 1
        self.index_va = rip_operand(u64[3])
        arms = img.table(self.index_va, self.n_variants)
        self.index = []
        for a in arms:
            ins = decode(img, a)
            nxt = decode(img, a + ins.size)
            if ins.op != 'mov' or ins.w != 16 or ins.b[1] & 0xff != 9 or nxt.op != 'ret':
                raise Fault(f'{label}: index arm {a:#x} is not `movw $(i<<8|9), (%rax); ret`')
            self.index.append(ins.b[1] >> 8)
        u64_leas = [rip_operand(i) for i in u64 if i.op == 'lea' and rip_operand(i)]
        # lea expected (&str), lea its vtable, lea Display fn, lea message pieces
        exp = u64_leas[1]
        ptr = img.relative.get(exp)
        n = struct.unpack('<Q', img.read(exp + 8, 8))[0]
        self.expected_text = img.str_at(ptr, n)
        self.consts = {'expected_str': exp, 'expected_vtable': u64_leas[2], 'value_msg': u64_leas[-1]}
        small = self.funcs[self.by_role['visit_unit']]
        sl = [rip_operand(i) for i in small if i.op == 'lea' and rip_operand(i)]
        self.consts['visitor_vtable'], self.consts['type_msg'] = sl[0], sl[-1]
        eptr = img.relative.get(self.eof_err)
        en = struct.unpack('<Q', img.read(self.eof_err + 8, 8))[0]
        self.eof_text = img.str_at(eptr, en)
        self.eof_kind = img.read(self.eof_err + 16, 1)[0]

    def all_insns(self):
        for f in sorted(self.funcs):
            yield from self.funcs[f]


def slot_call_sites(img, slots):
    """`call *slot(%rip)` (ff 15 rel32) sites in .text for each GOT slot, with the FDE holding each."""
    t = img.by_name['.text']
    tb = img.data[t['offset']:t['offset'] + t['size']]
    fdes = sorted((f['start'], f['end']) for rows in img.fde.values() for f in rows)
    starts = [s for s, _ in fdes]
    out = {s: [] for s in slots}
    i = tb.find(b'\xff\x15')
    while i >= 0:
        va = t['address'] + i
        tg = va + 6 + struct.unpack_from('<i', tb, i + 2)[0]
        if tg in out:
            k = max(0, bisect.bisect_right(starts, va) - 1)
            s, e = fdes[k]
            out[tg].append((va, s if s <= va < e else None))
        i = tb.find(b'\xff\x15', i + 1)
    return out


def f32_to_f64_bits(b32):
    """cvtss2sd on bits: exact widening; NaNs are quieted (payload shifted, bit 51 set)."""
    s, e, m = b32 >> 31, b32 >> 23 & 0xff, b32 & 0x7fffff
    if e == 0xff:
        if m == 0:
            return s << 63 | 0x7ff << 52
        return s << 63 | 0x7ff << 52 | 1 << 51 | m << 29
    if e == 0:
        if m == 0:
            return s << 63
        e = 1
        while not m & 0x800000:
            m <<= 1
            e -= 1
        m &= 0x7fffff
    return s << 63 | (e - 127 + 1023) << 52 | m << 29


class Machine:
    def __init__(self, img, copy):
        self.img, self.c = img, copy
        self.cache = {}
        for body in copy.funcs.values():
            for i in body:
                self.cache[i.va] = i
        self.covered = set()

    def run(self, marker, data, inp):
        self.inp = bytes(inp)
        self.out = bytearray([OUT_FILL]) * 32
        self.stack = bytearray([STACK_FILL]) * 0x200
        des = bytearray([DES_FILL]) * 0x28
        struct.pack_into('<QQ', des, 0x10, IN_BASE, len(inp))
        self.des, self.des0 = des, bytes(des)
        self.r = [0x1111_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6] = OUT_BASE, DES_BASE
        # Only dl / cl are arguments; high bits carry junk to prove they are ignored.
        self.r[2] = 0x5a5a_5a5a_5a5a_5a00 | marker
        self.r[1] = 0xa5a5_a5a5_a5a5_a500 | data
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.calls, self.entered = [], []
        pc = self.c.start
        for _ in range(STEP_LIMIT):
            ins = self.cache.get(pc)
            if ins is None:
                raise Fault(f'execution left the decoded functions at {pc:#x}')
            self.covered.add(pc)
            nxt = pc + ins.size
            res = self.step(ins, nxt)
            if res == 'ret':
                if self.r[4] == STACK_TOP:
                    if self.r[0] != OUT_BASE:
                        raise Fault('rax does not return the out pointer')
                    return self.outcome()
                pc = int.from_bytes(self.load(self.r[4] - 8, 8), 'little')
                continue
            pc = nxt if res is None else res
        raise Fault('step limit')

    def outcome(self):
        des = self.des
        if des[:0x10] != self.des0[:0x10] or des[0x20:] != self.des0[0x20:]:
            raise Fault('deserializer bytes outside ptr/len changed')
        ptr, rem = struct.unpack_from('<QQ', des, 0x10)
        pos = ptr - IN_BASE
        if not 0 <= pos <= len(self.inp) or pos + rem != len(self.inp):
            raise Fault('input cursor is not a suffix of the input')
        out = bytes(self.out)
        if self.calls:
            if len(self.calls) != 1 or out != fmt_mark(self.calls[0]):
                raise Fault('formatter result not passed through to out')
            res = self.calls[0]
        elif out[0] == 9 and out[2:] == bytes([OUT_FILL]) * 30:
            res = ('ok', out[1])
        elif out[0] == 1 and out[1:8] == bytes([OUT_FILL]) * 7 and out[16:] == bytes([OUT_FILL]) * 16:
            res = ('eof', struct.unpack_from('<Q', out, 8)[0])
        elif out[0] == 2 and out[3:] == bytes([OUT_FILL]) * 29:
            res = ('passthrough', out[1], out[2])
        else:
            raise Fault(f'unclassified out bytes {out.hex()}')
        return res, pos

    # memory -------------------------------------------------------------
    def addr(self, m, nxt):
        _, base, index, scale, disp, rip = m
        a = nxt + disp if rip else disp
        if base is not None:
            a += self.r[base]
        if index is not None:
            a += self.r[index] * scale
        return a & MASK64

    def region(self, a, n):
        for base, buf in ((IN_BASE, self.inp), (OUT_BASE, self.out), (DES_BASE, self.des),
                          (STACK_TOP - len(self.stack), self.stack)):
            if base <= a < base + len(buf) + 64:
                if a + n > base + len(buf):
                    raise Fault(f'access past buffer {a:#x}+{n}')
                return buf, a - base
        return None, None

    def load(self, a, n):
        buf, o = self.region(a, n)
        if buf is None:
            return self.img.read(a, n)
        return bytes(buf[o:o + n])

    def store(self, a, data):
        buf, o = self.region(a, len(data))
        if buf is None or buf is self.inp:
            raise Fault(f'store outside writable buffers {a:#x}')
        buf[o:o + len(data)] = data

    def get(self, opnd, w, nxt):
        if opnd[0] == 'r':
            return self.r[opnd[1]] & ((1 << w) - 1)
        if opnd[0] == 'i':
            return opnd[1]
        return int.from_bytes(self.load(self.addr(opnd, nxt), w // 8), 'little')

    def put(self, opnd, w, v, nxt):
        v &= (1 << w) - 1
        if opnd[0] == 'r':
            n = opnd[1]
            if w in (64, 32):
                self.r[n] = v
            else:
                self.r[n] = (self.r[n] & ~((1 << w) - 1) & MASK64) | v
        else:
            self.store(self.addr(opnd, nxt), v.to_bytes(w // 8, 'little'))

    def setf(self, w, res, a=None, b=None, kind='logic'):
        m = (1 << w) - 1
        r = res & m
        self.flags['z'] = int(r == 0)
        self.flags['s'] = r >> (w - 1) & 1
        if kind == 'logic':
            self.flags['c'] = self.flags['o'] = 0
        elif kind == 'sub':
            self.flags['c'] = int(a < b)
            self.flags['o'] = int(sx(a, w) - sx(b, w) != sx(r, w))
        elif kind == 'add':
            self.flags['c'] = int(a + b > m)
            self.flags['o'] = int(sx(a, w) + sx(b, w) != sx(r, w))
        return r

    def cond(self, cc):
        f = self.flags
        v = [f['o'], f['c'], f['z'], f['c'] | f['z'], f['s'], None,
             int(f['s'] != f['o']), int(f['z'] or f['s'] != f['o'])][cc >> 1]
        if v is None:
            raise Fault('parity flag not modelled')
        return bool(v) ^ bool(cc & 1)

    def step(self, ins, nxt):
        op, w = ins.op, ins.w
        if op in ('add', 'or', 'xor', 'and', 'sub', 'cmp', 'test'):
            a, b = self.get(ins.a, w, nxt), self.get(ins.b, w, nxt)
            if op == 'add':
                r = self.setf(w, a + b, a, b, 'add')
            elif op in ('sub', 'cmp'):
                r = self.setf(w, a - b, a, b, 'sub')
            else:
                r = self.setf(w, {'or': a | b, 'xor': a ^ b, 'and': a & b, 'test': a & b}[op])
            if op not in ('cmp', 'test'):
                self.put(ins.a, w, r, nxt)
        elif op in ('inc', 'dec'):
            a, c = self.get(ins.a, w, nxt), self.flags['c']
            r = self.setf(w, a + 1, a, 1, 'add') if op == 'inc' else self.setf(w, a - 1, a, 1, 'sub')
            self.flags['c'] = c  # inc/dec leave CF unchanged
            self.put(ins.a, w, r, nxt)
        elif op == 'rol':
            v, n = self.get(ins.a, w, nxt), ins.b % w
            r = ((v << n) | (v >> (w - n))) & ((1 << w) - 1)
            self.flags['c'] = r & 1
            self.put(ins.a, w, r, nxt)
        elif op == 'bswap':
            v = self.get(ins.a, w, nxt)
            self.put(ins.a, w, int.from_bytes(v.to_bytes(w // 8, 'little'), 'big'), nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'movsxd':
            self.put(ins.a, 64, sx(self.get(ins.b, 32, nxt), 32) & MASK64, nxt)
        elif op in ('movzx', 'movsx'):
            src, dw = ins.b
            v = self.get(src, w, nxt)
            if op == 'movsx':
                v = sx(v, w) & ((1 << dw) - 1)
            self.put(ins.a, dw, v, nxt)
        elif op == 'movdx':
            v = self.get(ins.b, w, nxt)
            self.x[ins.a] = v.to_bytes(w // 8, 'little') + bytes(16 - w // 8)
        elif op == 'cvtss2sd':
            b32 = int.from_bytes(self.x[ins.b][:4], 'little')
            self.x[ins.a] = f32_to_f64_bits(b32).to_bytes(8, 'little') + self.x[ins.a][8:]
        elif op == 'movsd_st':
            self.store(self.addr(ins.a, nxt), self.x[ins.b][:8])
        elif op == 'push':
            self.r[4] -= 8
            self.store(self.r[4], self.r[ins.a[1]].to_bytes(8, 'little'))
        elif op == 'pop':
            self.r[ins.a[1]] = int.from_bytes(self.load(self.r[4], 8), 'little')
            self.r[4] += 8
        elif op == 'j':
            return nxt + ins.b if self.cond(ins.a) else None
        elif op == 'jmp':
            return nxt + ins.b
        elif op == 'jmpr':
            return self.get(ins.a, 64, nxt)
        elif op == 'ret':
            self.r[4] += 8
            return 'ret'
        elif op == 'call':
            return self.call(ins, nxt)
        elif op == 'xload':
            self.x[ins.a] = self.load(self.addr(ins.b, nxt), 16) if ins.b[0] == 'm' else self.x[ins.b[1]]
        elif op == 'xstore':
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op == 'ud2':
            raise Fault(f'ud2 reached at {ins.va:#x}')
        else:
            raise Fault(f'no semantics for {op}')
        return None

    def call(self, ins, nxt):
        t = target(ins)
        r = self.r
        if t in self.c.funcs:
            self.entered.append(t)
            r[4] -= 8
            self.store(r[4], nxt.to_bytes(8, 'little'))
            return t
        if t != self.c.fmt:
            raise Fault(f'unexpected call {t:#x}')
        # Formatter contract: (out, message pieces, &[unexpected arg, expected arg]).
        args = self.load(r[2], 32)
        un_p, un_fmt, ex_p, ex_fmt = struct.unpack('<QQQQ', args)
        un = self.load(un_p, 16)
        tag = un[0]
        if tag not in UNEXPECTED:
            raise Fault(f'unexpected Unexpected tag {tag}')
        if tag == 0:
            payload = un[1]
        elif tag == 7:
            payload = None
        else:
            payload = struct.unpack_from('<Q', un, 8)[0]
        exp_data, exp_vt = struct.unpack('<QQ', self.load(ex_p, 16))
        msg = r[6]
        # The two Display fn pointers (un_fmt, ex_fmt) are not interpreted; only the data is.
        del un_fmt, ex_fmt
        kind = 'invalid_value' if msg == self.c.consts['value_msg'] else (
            'invalid_type' if msg == self.c.consts['type_msg'] else None)
        if kind is None:
            raise Fault(f'unknown message pieces {msg:#x}')
        if exp_vt == self.c.consts['expected_vtable'] and exp_data == self.c.consts['expected_str']:
            expected = 'variant_index_text'
        elif exp_vt == self.c.consts['visitor_vtable'] and self.region(exp_data, 1)[0] is self.stack:
            expected = 'visitor'
        else:
            raise Fault('expected argument is neither the index text nor the visitor')
        rec = (kind, UNEXPECTED[tag], payload, expected)
        self.calls.append(rec)
        self.store(r[7], fmt_mark(rec))
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            r[n] = 0xdead_0000 + n
        return None


def fmt_mark(rec):
    return hashlib.sha256(repr(rec).encode()).digest()


# --- the reconstruction ----------------------------------------------------
# Marker byte (rmp Marker repr) -> (payload kind, payload length). 0x00 is
# FixPos (value in the data byte); 0xe0 is FixNeg (value in the data byte).
SCALARS = {
    0xc0: ('unit', 0), 0xc2: ('false', 0), 0xc3: ('true', 0),
    0xca: ('f32', 4), 0xcb: ('f64', 8),
    0xcc: ('u', 1), 0xcd: ('u', 2), 0xce: ('u', 4), 0xcf: ('u', 8),
    0xd0: ('i', 1), 0xd1: ('i', 2), 0xd2: ('i', 4), 0xd3: ('i', 8),
    0xe0: ('fixneg', 0),
}


def visit_u64(v, n_variants, model=None):
    """Integer v names variant v (the index table is the identity in all five copies)."""
    if v < n_variants:
        if model == 'index_reversed':
            return ('ok', n_variants - 1 - v)
        return ('ok', v)
    return ('invalid_value', 'Unsigned', v, 'variant_index_text')


def reconstructed(marker, data, inp, n_variants, eof_ptr, model=None):
    """(result, input bytes consumed) for one dispatcher call."""
    if marker == 0:
        return visit_u64(data, n_variants, model), 0
    spec = SCALARS.get(marker)
    if model == 'u8_as_i8' and marker in (0xcc, 0xd0):
        spec = SCALARS[0xd0 if marker == 0xcc else 0xcc]
    if spec is None or (model == 'no_fixneg' and marker == 0xe0):
        if model == 'passthrough_drops_data':
            return ('passthrough', marker, 0), 0
        return ('passthrough', marker, data), 0
    kind, n = spec
    if len(inp) < n:
        return ('eof', eof_ptr), (0 if model == 'eof_keeps_cursor' else len(inp))
    v = int.from_bytes(inp[:n], 'little' if model == 'little_endian' else 'big')
    if kind == 'unit':
        return ('invalid_type', 'Unit', None, 'visitor'), 0
    if kind in ('false', 'true'):
        return ('invalid_type', 'Bool', int(kind == 'true'), 'visitor'), 0
    if kind == 'u':
        if model == 'bound_off_by_one':
            n_variants += 1
        return visit_u64(v, n_variants, model), n
    if kind == 'i':
        s = v if model == 'signed_zero_extend' else sx(v, 8 * n) & MASK64
        return ('invalid_type', 'Signed', s, 'visitor'), n
    if kind == 'fixneg':
        return ('invalid_type', 'Signed', sx(data, 8) & MASK64, 'visitor'), 0
    if kind == 'f32':
        bits = v if model == 'f32_raw_bits' else f32_to_f64_bits(v)
        return ('invalid_type', 'Float', bits, 'visitor'), n
    return ('invalid_type', 'Float', v, 'visitor'), n


MODEL_MUTANTS = ('u8_as_i8', 'no_fixneg', 'passthrough_drops_data', 'eof_keeps_cursor', 'little_endian',
                 'bound_off_by_one', 'signed_zero_extend', 'f32_raw_bits', 'index_reversed')


# --- cases -------------------------------------------------------------------
F32_SPECIAL = (0x00000000, 0x80000000, 0x3f800000, 0x7f800000, 0xff800000, 0x7fc00000, 0x7f800001,
               0xffbfffff, 0x00000001, 0x007fffff, 0x00400000, 0x80000001, 0x7f7fffff, 0x0b800000)
F64_SPECIAL = (0, 1 << 63, 0x3ff0000000000000, 0x7ff0000000000000, 0x7ff0000000000001,
               0xfff8000000000000, 1, 0x000fffffffffffff)


def payloads(kind, n, bound):
    vals = set()
    if kind == 'u':
        vals.update(((1 << 8 * n) - 1, 1 << (8 * n - 1), (1 << (8 * n - 1)) - 1))
        if n == 1:
            vals.update(range(0, bound + 3))
        else:
            vals.update((0, 1, bound - 1, bound, bound + 1))
            vals.update((0x100, 0x0100 | (bound - 1), (bound - 1) << 8 * (n - 1)))
    elif kind == 'i':
        vals.update((0, 1, 0x7f, 0x80, 0xff, (1 << 8 * n) - 1, 1 << (8 * n - 1), (1 << (8 * n - 1)) - 1,
                     bound - 1, bound, 0x5a & ((1 << 8 * n) - 1)))
    elif kind == 'f32':
        vals.update(F32_SPECIAL)
    elif kind == 'f64':
        vals.update(F64_SPECIAL)
    out = [v.to_bytes(n, 'big') for v in sorted(vals) if v < 1 << 8 * n]
    for k in range(n):  # short payloads -> EOF
        out.append(bytes(range(0x11, 0x11 + k)))
    out = out + [p + b'\x99' for p in out[:2]]  # trailing byte stays unread
    return out


def build_cases(bound):
    cases = []
    for marker in range(256):
        spec = SCALARS.get(marker)
        if marker == 0:
            for d in range(256):
                cases.append((marker, d, b''))
        elif marker == 0xe0:
            for d in range(256):
                cases.append((marker, d, b''))
        elif spec is None:
            for d in (0x00, 0x7f, 0xff):
                cases.append((marker, d, b''))
            cases.append((marker, 0x33, b'\xcc\x01'))
        else:
            kind, n = spec
            if n == 0:
                for d in (0x00, 0xff):
                    cases.append((marker, d, b''))
                    cases.append((marker, d, b'\x01'))
            else:
                for p in payloads(kind, n, bound):
                    cases.append((marker, 0x42, p))
    return cases


def fmt_res(res):
    out = []
    for v in res:
        if v is None:
            out.append('-')
        elif isinstance(v, int):
            out.append(f'{v:#x}')
        else:
            out.append(str(v))
    return ':'.join(out)


def compare(img, copy, cases, model=None, machine=None):
    m = machine or Machine(img, copy)
    rows, bad = [], 0
    for marker, data, inp in cases:
        try:
            got = m.run(marker, data, inp)
        except Fault as e:
            got = ('fault', str(e)), -1
        want = reconstructed(marker, data, inp, copy.n_variants, copy.eof_err, model)
        ok = got == want
        bad += not ok
        rows.append((marker, data, inp, got, ok))
    return rows, bad, m


def image_mutants(img, copy):
    """Single-byte corruptions of the original; each must change some outcome."""
    d = copy.insns
    u64 = copy.funcs[copy.by_role['visit_u64']]

    def at(ins, k):
        return img.off(ins.va) + k

    first_ja = next(i for i in d if i.op == 'j' and i.a == 7)
    cmp20 = next(i for i in d if i.op == 'cmp' and i.b == ('i', 0x20))
    test = next(i for i in d if i.op == 'test')
    bsw = [i for i in d if i.op == 'bswap']
    rol = next(i for i in d if i.op == 'rol')
    small_tag = [next(i for i in copy.funcs[copy.by_role[r]] if i.op == 'mov' and i.w == 8 and i.b[0] == 'i')
                 for r in ('visit_i8', 'visit_f64', 'visit_unit', 'visit_bool')]
    sxi = next(i for i in copy.funcs[copy.by_role['visit_i8']] if i.op == 'movsx')
    eof_tag = next(i for i in d if i.op == 'mov' and i.w == 8 and i.b == ('i', 1))
    pass_tag = next(i for i in d if i.op == 'mov' and i.w == 8 and i.b == ('i', 2))
    cvt = next(i for i in copy.funcs[copy.by_role['visit_f32']] if i.op == 'cvtss2sd')
    tab0 = img.off(copy.marker_va + 4 * (0xcc - MARKER_LO))
    tab1 = img.off(copy.marker_va + 4 * (0xd0 - MARKER_LO))
    idx0 = img.off(copy.index_va + 4 * 1)
    idx1 = img.off(copy.index_va + 4 * 2)
    muts = [
        ('range_ja_to_jae', [(at(first_ja, 0), 0x73)]),
        ('range_cmp_0x1f', [(at(cmp20, cmp20.size - 1), 0x1f)]),
        ('fixpos_jne_to_je', None),
        ('u64_bound_plus_1', [(at(u64[1], u64[1].size - 1), copy.n_variants)]),
        ('u64_ja_to_jae', [(at(u64[2], 0), 0x73)] if u64[2].size == 2 else [(at(u64[2], 1), 0x83)]),
        ('bswap32_dropped', [(at(bsw[0], 0) + k, 0x90) for k in range(bsw[0].size)]),
        ('rol16_by_0', [(at(rol, rol.size - 1), 0)]),
        ('i8_signed_tag_to_unsigned', [(at(small_tag[0], small_tag[0].size - 1), 1)]),
        ('f64_tag_to_signed', [(at(small_tag[1], small_tag[1].size - 1), 2)]),
        ('unit_tag_to_bool', [(at(small_tag[2], small_tag[2].size - 1), 0)]),
        ('bool_tag_to_unit', [(at(small_tag[3], small_tag[3].size - 1), 7)]),
        ('i8_movsx_to_movzx', [(at(sxi, sxi.raw.index(b'\x0f\xbe') + 1), 0xb6)]),
        ('eof_tag_2', [(at(eof_tag, eof_tag.size - 1), 2)]),
        ('passthrough_tag_3', [(at(pass_tag, pass_tag.size - 1), 3)]),
        ('cvtss2sd_to_nop', [(at(cvt, 0) + k, 0x90) for k in range(cvt.size)]),
        ('swap_u8_i8_arms', 'swap', tab0, tab1),
        ('swap_index_1_2', 'swap', idx0, idx1),
    ]
    out = []
    for m in muts:
        if m[1] is None:
            # the jne after `test r8d,r8d` (FixPos vs other non-scalar markers) becomes je
            jcc = d[d.index(test) + 1]
            out.append((m[0], [(at(jcc, 0), 0x74 if jcc.size == 2 else None)]))
        elif m[1] == 'swap':
            # Entries are offsets from the table base, so swapping two words swaps two targets.
            a, b = m[2], m[3]
            out.append((m[0], [('i32', a, struct.unpack_from('<i', img.data, b)[0]),
                               ('i32', b, struct.unpack_from('<i', img.data, a)[0])]))
        else:
            out.append(m)
    return out


def apply(data, edits):
    buf = bytearray(data)
    for e in edits:
        if e[0] == 'i32':
            struct.pack_into('<i', buf, e[1], e[2])
        else:
            if e[1] is None:
                raise Fault('mutant edit not applicable')
            buf[e[0]] = e[1]
    return bytes(buf)


def generate(out_dir, data=None):
    if data is None:
        data = BINARY.read_bytes()
    img = Image(data)
    copies = [Copy(img, *c) for c in COPIES]
    base = copies[0]
    for c in copies[1:]:
        if [shape(i) for i in c.insns] != [shape(i) for i in base.insns]:
            raise Fault(f'{c.label} is not the same shape as {base.label}')
        if [a - c.start for a in c.marker_arms] != [a - base.start for a in base.marker_arms]:
            raise Fault(f'{c.label} marker table differs')
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {}

    # copies.tsv
    lines = ['copy\tdispatcher\tend\tgot_slot\tmarker_table\tn_variants\tindex_table\texpected_text\t'
             'formatter\t' + '\t'.join(ROLES) + '\tslot_call_sites']
    sites = slot_call_sites(img, [c.slot for c in copies])
    for c in copies:
        if not sites[c.slot] or any(f is None for _, f in sites[c.slot]):
            raise Fault(f'{c.label}: slot has no call site inside an FDE')
        lines.append('\t'.join([c.label, f'{c.start:#x}', f'{c.end:#x}', f'{c.slot:#x}', f'{c.marker_va:#x}',
                                str(c.n_variants), f'{c.index_va:#x}', c.expected_text, f'{c.fmt:#x}']
                               + [f'{c.by_role[r]:#x}+{img.extent(c.by_role[r]) - c.by_role[r]}'
                                  for r in ROLES]
                               + [','.join(f'{v:#x}@{f:#x}' for v, f in sites[c.slot])]))
    files['copies.tsv'] = lines

    # tables.tsv: marker arms (shared offsets) and every integer -> index row
    lines = ['table\tcopy\tkey\tvalue']
    starts = {i.va for i in base.insns}
    probe = Machine(img, base)
    for k, a in enumerate(base.marker_arms):
        if a not in starts:
            raise Fault('marker arm is not an instruction start')
        # callee entered when the arm runs with a full 8-byte payload ('-' = no callee)
        probe.run(MARKER_LO + k, 0, bytes(8))
        role = base.role[probe.entered[0]] if probe.entered else '-'
        lines.append(f'marker_arm\tall\t{MARKER_LO + k:#04x}\t+{a - base.start:#05x}\t{role}')
    for c in copies:
        for v, idx in enumerate(c.index):
            lines.append(f'u64_index\t{c.label}\t{v}\t{idx}')
    files['tables.tsv'] = lines

    # constants.tsv
    lines = ['copy\tname\tva\tvalue']
    for c in copies:
        lines.append(f'{c.label}\teof_error\t{c.eof_err:#x}\tkind={c.eof_kind} {c.eof_text}')
        for k in sorted(c.consts):
            v = c.consts[k]
            text = ''
            if k in ('value_msg', 'type_msg'):
                n = img.read(v, 1)[0]
                text = img.read(v + 1, n).decode()
            lines.append(f'{c.label}\t{k}\t{v:#x}\t{text}')
    files['constants.tsv'] = lines

    # cases
    summary = {'binary_sha256': SHA256, 'copies': [], 'model_mutants': {}, 'image_mutants': {}}
    case_lines = ['copy\tmarker\tdata\tinput\tresult\tconsumed\tmatch']
    cov_lines = ['copy\tfunction\tinstructions\tcovered\tuncovered']
    total_cases = total_bad = 0
    for c in copies:
        cases = build_cases(c.n_variants)
        rows, bad, m = compare(img, c, cases)
        total_cases += len(rows)
        total_bad += bad
        for marker, d, inp, got, ok in rows:
            case_lines.append(f'{c.label}\t{marker:#04x}\t{d:#04x}\t{inp.hex() or "-"}\t{fmt_res(got[0])}\t'
                              f'{got[1]}\t{"yes" if ok else "NO"}')
        unc_all = 0
        for fstart in sorted(c.funcs):
            body = c.funcs[fstart]
            unc = [i.va for i in body if i.va not in m.covered]
            unc_all += len(unc)
            name = 'dispatcher' if fstart == c.start else c.role[fstart]
            cov_lines.append(f'{c.label}\t{name}@{fstart:#x}\t{len(body)}\t{len(body) - len(unc)}\t'
                             + (','.join(f'{u:#x}' for u in unc) or '-'))
        summary['copies'].append({'copy': c.label, 'cases': len(rows), 'mismatches': bad,
                                  'instructions': sum(len(b) for b in c.funcs.values()),
                                  'uncovered': unc_all, 'n_variants': c.n_variants,
                                  'index_is_identity': c.index == list(range(c.n_variants))})
    files['cases.tsv'] = case_lines
    files['coverage.tsv'] = cov_lines

    # mutants (on the Action copy N2 and the first copy N1)
    mut_lines = ['kind\tcopy\tmutant\tcases_differing\tkilled']
    for c in (copies[0], copies[1]):
        cases = build_cases(c.n_variants)
        for model in MODEL_MUTANTS:
            _, bad, _ = compare(img, c, cases, model)
            mut_lines.append(f'model\t{c.label}\t{model}\t{bad}\t{"yes" if bad else "NO"}')
            summary['model_mutants'][f'{c.label}:{model}'] = bad
        for name, edits in image_mutants(img, c):
            mdata = apply(data, edits)
            mimg = Image(mdata, check=False)
            try:
                mc = Copy(mimg, c.label, c.start, c.slot)
                mc.n_variants, mc.index = c.n_variants, c.index  # judge against the original facts
                mc.eof_err = c.eof_err
                _, bad, _ = compare(mimg, mc, cases)
                result = bad
            except Fault:
                result = 'static_fault'
            killed = result == 'static_fault' or result > 0
            mut_lines.append(f'image\t{c.label}\t{name}\t{result}\t{"yes" if killed else "NO"}')
            summary['image_mutants'][f'{c.label}:{name}'] = result
    files['mutants.tsv'] = mut_lines

    # insns.tsv: byte-decoded listing of the Action copy (dispatcher + callees)
    c = copies[1]
    lines = ['function\tva\tbytes\top\tshape_hex']
    for fstart in sorted(c.funcs):
        name = 'dispatcher' if fstart == c.start else c.role[fstart]
        for i in c.funcs[fstart]:
            lines.append(f'{name}\t{i.va:#x}\t{i.raw.hex()}\t{i.op}\t{shape(i).hex()}')
    files['insns.tsv'] = lines

    summary['total_cases'] = total_cases
    summary['total_mismatches'] = total_bad
    summary['model_mutants_killed'] = sum(1 for v in summary['model_mutants'].values() if v)
    summary['model_mutants_total'] = len(summary['model_mutants'])
    summary['image_mutants_killed'] = sum(1 for v in summary['image_mutants'].values()
                                          if v == 'static_fault' or v)
    summary['image_mutants_total'] = len(summary['image_mutants'])
    for name, lines in files.items():
        (out_dir / name).write_text('\n'.join(lines) + '\n')
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(BINARY))
    a = ap.parse_args()
    s = generate(a.out, Path(a.binary).read_bytes())
    print(json.dumps({k: s[k] for k in ('total_cases', 'total_mismatches', 'model_mutants_killed',
                                        'model_mutants_total', 'image_mutants_killed', 'image_mutants_total')}))
    ok = (s['total_mismatches'] == 0 and s['model_mutants_killed'] == s['model_mutants_total']
          and s['image_mutants_killed'] == s['image_mutants_total']
          and all(c['uncovered'] == 0 for c in s['copies']))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
