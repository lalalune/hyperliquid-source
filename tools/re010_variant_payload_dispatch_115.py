#!/usr/bin/env python3
"""Reconstruct the node #115 variant payload dispatch of two serde enums and prove it.

The serde identifier decoders 0x1c2d2c0 (18 variant tags) and 0x1bfca70 (114
short variant codes) each have exactly two `visit_enum` callers in node #115.
Each caller asks the identifier decoder for the variant index (call with
edx = 1), and on success jumps through a 32-bit relative jump table indexed by
that variant to an arm that deserializes the variant payload and writes the
enum value (a qword discriminant at +0 and the payload at +8...) into the
caller's out pointer:

  F18   0x286c690  (831 B)  18 arms, generic payload helpers
  F18R  0x286ac90  (1747 B) 18 arms, same discriminants, a second deserializer
                            type: seven u8 payloads read the MessagePack marker
                            inline (peek slot or input byte) and call the u8
                            helper 0x3482410 with the decomposed marker
  E114A 0x2870370  (5016 B) 114 arms, generic payload helpers + memcpy
  E114B 0x2871710  (5114 B) 114 arms, 72 type-specific payload helpers

This tool:
1. checks the input digest, finds each function's FDE extent, decodes every
   instruction with a fixed-pattern x86-64 subset decoder, reads the frame
   size, the identifier call, the jump table and its entries from the bytes
   and checks every entry lands on an instruction start inside the function;
2. interprets the original bytes (the binary is never run; callees are
   contract stubs that write a seeded pattern with a chosen head value,
   memcpy is executed, the identifier result is supplied by the case);
3. compares every outcome with a pure reconstruction (`reconstructed`) driven
   by the literal variant table SPEC: out bytes, call sequence with arguments,
   and the deserializer bytes after the call;
4. proves 100% instruction coverage and that wrong reconstructions and
   corrupted images are rejected.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402,F401

BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# label, start, FDE size, frame size (sub rsp), identifier decoder, variants, error discriminant
FUNCS = (
    ('F18', 0x286c690, 831, 0x28, 0x1c2d2c0, 18, 0x14),
    ('F18R', 0x286ac90, 1747, 0x28, 0x1c2d2c0, 18, 0x14),
    ('E114A', 0x2870370, 5016, 0xf8, 0x1bfca70, 114, 0x86),
    ('E114B', 0x2871710, 5114, 0xf0, 0x1bfca70, 114, 0x86),
)
MEMCPY_SLOT = 0x64df508       # R_X86_64_GLOB_DAT memcpy
MARKER_U8_SLOT = 0x64e2590    # R_X86_64_RELATIVE -> 0x3482410
MARKER_U8_TARGET = 0x3482410
EOF_STATIC = 0x641ccb0        # &'static SimpleMessage of io::ErrorKind::UnexpectedEof
IDENT_OK = 9                  # Result<Field, Error> Ok niche tag written by the identifier decoder

IN_BASE, OUT_BASE, DES_BASE = 0x7000_0000_0000, 0x7100_0000_0000, 0x7180_0000_0000
STACK_TOP = 0x7200_0000_0000
MASK64 = (1 << 64) - 1
STEP_LIMIT = 600
OUT_FILL, STACK_FILL, DES_FILL = 0xaa, 0x5c, 0x3d
OUT_SIZE = 0x100
IDENT_LEN = 32
MISS = (0xf5, 1)              # a stub head value no compare in the four functions tests for


def pattern(seed, ordinal, callee, n):
    """Deterministic bytes a stub writes: sha256 stream keyed by seed, call ordinal and callee."""
    h, k = b'', 0
    while len(h) < n:
        h += hashlib.sha256(f'{seed}:{ordinal}:{callee}:{k}'.encode()).digest()
        k += 1
    return h[:n]


def stub_bytes(seed, ordinal, callee, n, knob):
    p = bytearray(pattern(seed, ordinal, callee, n))
    v, w = knob
    p[:w] = v.to_bytes(w, 'little')
    return bytes(p)


def ident_bytes(seed, tag, index):
    return bytes([tag, index]) + pattern(seed, 0, 'ident', IDENT_LEN - 2)


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

    def off(self, va, n=1):
        for s in self.secs:
            if s['address'] <= va and va + n <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise Fault(f'unmapped static read {va:#x}+{n}')

    def read(self, va, n):
        o = self.off(va, n)
        return self.data[o:o + n]

    def plt_symbol(self, va):
        stub = self.read(va, 6)
        if stub[:2] != b'\xff\x25':
            raise Fault(f'{va:#x} is not a PLT jmp stub')
        slot = va + 6 + struct.unpack('<i', stub[2:])[0]
        rp = self.by_name['.rela.plt']
        for i in range(rp['size'] // 24):
            off, info, _ = struct.unpack_from('<QQq', self.data, rp['offset'] + i * 24)
            if off == slot and info & 0xffffffff == 7:
                dynsym, dynstr = self.by_name['.dynsym'], self.by_name['.dynstr']
                name = struct.unpack_from('<I', self.data, dynsym['offset'] + 24 * (info >> 32))[0]
                start = dynstr['offset'] + name
                return self.data[start:self.data.index(b'\0', start)].decode()
        raise Fault(f'no JUMP_SLOT relocation for {slot:#x}')

    def call_sites(self, lsda, func_start):
        """LSDA call-site table rows (start, end, landing pad or 0, action) as VAs."""
        o = self.off(lsda, 4)
        if self.data[o] != 0xff:
            raise Fault('LSDA has a landing-pad base')
        p = o + 2
        if self.data[o + 1] != 0xff:
            _, p = uleb(self.data, p, o + 4096)  # type table offset (catch-all terminate entry)
        if self.data[p] != 0x01:
            raise Fault('LSDA call sites are not uleb128')
        length, p = uleb(self.data, p + 1, o + 4096)
        rows, stop = [], p + length
        while p < stop:
            start, p = uleb(self.data, p, stop)
            size, p = uleb(self.data, p, stop)
            lp, p = uleb(self.data, p, stop)
            action, p = uleb(self.data, p, stop)
            rows.append((func_start + start, func_start + start + size, func_start + lp if lp else 0, action))
        return rows

    def table(self, va, n):
        return [va + struct.unpack('<i', self.read(va + 4 * i, 4))[0] for i in range(n)]


def fde_of(data, start):
    _, fdes = eh_frame_records(data)
    rows = [f for f in fdes if f['start'] == start]
    if len(rows) != 1:
        raise Fault(f'{start:#x} is not the start of exactly one FDE')
    return rows[0]


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw', 'rel', 'immlen', 'cc')


ALU_NAMES = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')


def decode(img, va):
    """Decode one instruction of the fixed subset used by the decoder copies."""
    b = img.read(va, 16)
    p, opsz, rep, rex = 0, None, False, 0
    while b[p] in (0x66, 0xf3):
        opsz = 16 if b[p] == 0x66 else opsz
        rep = rep or b[p] == 0xf3
        p += 1
    if 0x40 <= b[p] <= 0x4f:
        rex = b[p]
        p += 1
    W, R, X, B = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    width = 64 if W else (opsz or 32)
    ins = Insn()
    ins.va, ins.w, ins.a, ins.b, ins.rel, ins.immlen = va, width, None, None, None, 0

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
        ins.immlen = n
        return v

    op = b[p]
    p += 1
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
        ins.a, ins.b = (reg_o, rm) if op == 0x8a or op == 0x8b else (rm, reg_o)
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
        elif k in (2, 4):
            ins.op, ins.a, ins.w = ('callr' if k == 2 else 'jmpr'), rm, 64
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
        elif op2 in (0xb6, 0xb7):
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movzx', ('r', reg), rm
            ins.w = 8 if op2 == 0xb6 else 16
            if op2 == 0xb6:
                low8(rm)
        elif op2 in (0x10, 0x28) and not rep and opsz is None:
            reg, rm = modrm()  # movups / movaps load (alignment is not modelled)
            ins.op, ins.a, ins.b = 'xload', reg, rm
        elif op2 in (0x11, 0x29) and not rep and opsz is None:
            reg, rm = modrm()  # movups / movaps store
            ins.op, ins.a, ins.b = 'xstore', rm, reg
        elif 0xc8 <= op2 <= 0xcf and not W:
            ins.op, ins.a = 'bswap', ('r', (op2 - 0xc8) | B << 3)
        elif op2 == 0x0b:
            ins.op = 'ud2'
        elif 0x40 <= op2 <= 0x4f:
            reg, rm = modrm()
            ins.op, ins.a, ins.b, ins.cc = 'cmov', ('r', reg), rm, op2 & 15
        else:
            raise Fault(f'unsupported 0f {op2:02x} at {va:#x}')
    else:
        raise Fault(f'unsupported opcode {op:02x} at {va:#x}')
    ins.size = p
    ins.raw = bytes(b[:p])
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




def reloc_name(img, slot):
    """('glob_dat', symbol) or ('relative', target) for a GOT slot, from .rela.dyn bytes."""
    rd = img.by_name['.rela.dyn']
    for i in range(rd['size'] // 24):
        off, info, add = struct.unpack_from('<QQq', img.data, rd['offset'] + i * 24)
        if off != slot:
            continue
        if info & 0xffffffff == 8:
            return ('relative', add)
        if info & 0xffffffff == 6:
            dynsym, dynstr = img.by_name['.dynsym'], img.by_name['.dynstr']
            name = struct.unpack_from('<I', img.data, dynsym['offset'] + 24 * (info >> 32))[0]
            start = dynstr['offset'] + name
            return ('glob_dat', img.data[start:img.data.index(b'\0', start)].decode())
    return None


class Fn:
    """Static facts of one visit_enum caller, all read from the bytes."""

    def __init__(self, img, row):
        self.label, self.start, size, self.frame, self.ident, self.n, self.err = row
        fde = fde_of(img.data, self.start)
        self.end = fde['end']
        if self.end - self.start != size:
            raise Fault(f'{self.label}: FDE extent is {self.end - self.start} bytes')
        self.insns = sweep(img, self.start, self.end)
        self.cache = {i.va: i for i in self.insns}
        subs = [i for i in self.insns if i.op == 'sub' and i.a == ('r', 4) and i.b[0] == 'i']
        if not subs or subs[0].b[1] != self.frame:
            raise Fault(f'{self.label}: frame size is not {self.frame:#x}')
        calls = [i for i in self.insns if i.op == 'call']
        if calls[0].va + calls[0].size + calls[0].b != self.ident:
            raise Fault(f'{self.label}: first call is not the identifier decoder')
        self.ident_call = calls[0].va
        jt = [i for i in self.insns if i.op == 'lea' and i.b[0] == 'm' and i.b[5] and i.va > self.ident_call]
        nxt = self.insns[self.insns.index(jt[0]) + 1:self.insns.index(jt[0]) + 4]
        if [i.op for i in nxt] != ['movsxd', 'add', 'jmpr']:
            raise Fault(f'{self.label}: no table dispatch after the identifier call')
        self.table_va = jt[0].va + jt[0].size + jt[0].b[4]
        self.arms = img.table(self.table_va, self.n)
        for a in self.arms:
            if a not in self.cache:
                raise Fault(f'{self.label}: table entry {a:#x} is not an instruction start')
        self.callees = []
        for i in calls:
            t = i.va + i.size + i.b
            if t not in self.callees:
                self.callees.append(t)
        self.slots = []
        for i in self.insns:
            if i.op == 'callr':
                slot = i.va + i.size + i.a[4]
                if slot not in self.slots:
                    self.slots.append(slot)
        for slot in self.slots:
            r = reloc_name(img, slot)
            if slot == MEMCPY_SLOT and r == ('glob_dat', 'memcpy'):
                continue
            if slot == MARKER_U8_SLOT and r == ('relative', MARKER_U8_TARGET):
                continue
            raise Fault(f'{self.label}: GOT slot {slot:#x} is not memcpy or the u8 marker helper')


class Machine:
    def __init__(self, img, fn):
        self.img, self.f = img, fn
        self.cache = fn.cache

    def run(self, case):
        label, ident, knob, seed, inp, peek = case
        self.inp = bytes(inp)
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.stack = bytearray([STACK_FILL]) * 0x200
        self.des = initial_des(inp, peek)
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6] = OUT_BASE, DES_BASE
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.calls, self.trace, self.edges = [], [], set()
        self.ident_res, self.knob, self.seed = ident, knob, seed
        self.frame_hi = None
        pc = self.f.start
        for _ in range(STEP_LIMIT):
            if not self.f.start <= pc < self.f.end:
                raise Fault(f'left function at {pc:#x}')
            ins = self.cache.get(pc)
            if ins is None:
                raise Fault(f'jump into the middle of an instruction at {pc:#x}')
            self.trace.append(pc)
            nxt = pc + ins.size
            if self.frame_hi is None and ins.op == 'sub' and ins.a == ('r', 4):
                self.frame_hi = self.r[4]
            res = self.step(ins, nxt)
            if ins.op == 'j':
                self.edges.add((pc, res is not None))
            if res == 'ret':
                if self.r[0] != OUT_BASE:
                    raise Fault('rax does not return the out pointer')
                return bytes(self.out), tuple(self.calls), bytes(self.des)
            pc = nxt if res is None else res
        raise Fault('step limit')

    # memory -------------------------------------------------------------
    def addr(self, m, nxt):
        _, base, index, scale, disp, rip = m
        a = nxt + disp if rip else disp
        if base is not None:
            a += self.r[base]
        if index is not None:
            a += self.r[index] * scale
        return a & MASK64

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
            v = self.get(ins.a, 32, nxt)
            self.put(ins.a, 32, int.from_bytes(v.to_bytes(4, 'little'), 'big'), nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'cmov':
            v = self.get(ins.b, w, nxt)
            self.put(ins.a, w, v if self.cond(ins.cc) else self.get(ins.a, w, nxt), nxt)
        elif op == 'movsxd':
            self.put(ins.a, 64, sx(self.get(ins.b, 32, nxt), 32) & MASK64, nxt)
        elif op == 'movzx':
            self.put(ins.a, 32, self.get(ins.b, w, nxt), nxt)
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
            if self.r[4] != STACK_TOP - 8:
                raise Fault('unbalanced stack at ret')
            return 'ret'
        elif op in ('call', 'callr'):
            return self.call(ins, nxt)
        elif op == 'xload':
            self.x[ins.a] = self.load(self.addr(ins.b, nxt), 16) if ins.b[0] == 'm' else self.x[ins.b[1]]
        elif op == 'xstore':
            if ins.a[0] != 'm':
                raise Fault('register-to-register xmm move not modelled')
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op == 'ud2':
            raise Fault(f'ud2 reached at {ins.va:#x}')
        else:
            raise Fault(f'no semantics for {op}')
        return None

    def region(self, a, n):
        for base, buf in ((IN_BASE, self.inp), (OUT_BASE, self.out), (DES_BASE, self.des),
                          (STACK_TOP - len(self.stack), self.stack)):
            if base <= a < base + len(buf) + 64:
                if a + n > base + len(buf):
                    raise Fault(f'access past buffer {a:#x}+{n}')
                return buf, a - base
        return None, None

    def where(self, a):
        """Name a pointer/argument value: out, deserializer, frame slot, static VA, or a plain value."""
        if a == OUT_BASE:
            return 'out'
        if a == DES_BASE:
            return 'des'
        if OUT_BASE < a < OUT_BASE + OUT_SIZE:
            return 'out+%x' % (a - OUT_BASE)
        if self.frame_hi is not None and STACK_TOP - len(self.stack) <= a < STACK_TOP:
            return 'sp+%x' % (a - (self.frame_hi - self.f.frame))
        if 0x200000 <= a < 0x7000000:
            return 'va:%x' % a
        if a & ~0xff == 0xdead_0000:
            return '-'
        return 'v:%x' % a

    def clobber(self):
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered

    def call(self, ins, nxt):
        r = self.r
        if ins.op == 'callr':
            slot = self.addr(ins.a, nxt)
            if slot == MEMCPY_SLOT:
                self.store(r[7], self.load(r[6], r[2]))
                self.calls.append(('memcpy', self.where(r[7]), self.where(r[6]), r[2]))
            elif slot == MARKER_U8_SLOT:
                if self.where(r[6]) != 'des':
                    raise Fault('u8 marker helper is not given the deserializer')
                self.calls.append(('marker_u8', self.where(r[7]), 'des', r[2] & 0xff, r[1] & 0xff))
                self.store(r[7], stub_bytes(self.seed, len(self.calls) - 1, 'marker_u8',
                                            self.frame_hi - r[7], self.knob))
            else:
                raise Fault(f'indirect call through {slot:#x}')
            self.clobber()
            return None
        t = nxt + ins.b
        rdx = self.where(r[2])
        r8 = self.where(r[8])
        rec = ('%x' % t, self.where(r[7]), self.where(r[6]), rdx,
               (r[1] & 0xffffffff) if rdx.startswith('va') else None,
               r8, (r[9] & 0xffffffff) if r8.startswith('va') else None)
        if rec[2] != 'des':
            raise Fault(f'callee {t:#x} is not given the deserializer')
        self.calls.append(rec)
        if len(self.calls) == 1:
            if t != self.f.ident:
                raise Fault('first call is not the identifier decoder')
            self.store(r[7], self.ident_res)
        else:
            n = OUT_SIZE if r[7] == OUT_BASE else self.frame_hi - r[7]
            self.store(r[7], stub_bytes(self.seed, len(self.calls) - 1, '%x' % t, n, self.knob))
        self.clobber()
        return None


def initial_des(inp, peek):
    des = bytearray([DES_FILL]) * 0x28
    struct.pack_into('<QQ', des, 0x10, IN_BASE, len(inp))
    des[0x20], des[0x21] = (1, DES_FILL) if peek is None else peek
    return des



def knobs(fn):
    """Stub head values: every value the function compares a stub result head against, from the bytes."""
    ks = {(0, 8), (1, 8)}
    for n, i in enumerate(fn.insns):
        if i.op == 'cmp' and i.a[0] == 'm' and i.a[1] == 4 and i.b[0] == 'i':
            ks.add((i.b[1], i.w // 8))
        if i.op == 'mov' and i.w == 64 and i.b[0] == 'i' and i.immlen == 8:
            ks.add((i.b[1], 8))
            nx = fn.insns[n + 1]
            if nx.op == 'or' and nx.a == i.a and nx.b[0] == 'i':
                ks.add((i.b[1] | nx.b[1], 8))
    if any(v & 0xff == MISS[0] for v, w in ks):
        raise Fault('MISS head collides with a compared value')
    return sorted(ks) + [MISS]


# reconstruction ------------------------------------------------------------------
def decompose_marker(b):
    """rmp Marker::from_u8 as the inline arms of F18R split it: (kind byte in edx, data byte in ecx)."""
    if b < 0x80:
        return 0x00, b             # FixPos(b)
    if b < 0x90:
        return 0x80, b & 0x0f      # FixMap(n)
    if b < 0xa0:
        return 0x90, b & 0x0f      # FixArray(n)
    if b < 0xc0:
        return 0xa0, b & 0x1f      # FixStr(n)
    if b < 0xe0:
        return b, b & 0x1f         # Nil..Map32: kind is the marker byte, data is unused
    return 0xe0, b                 # FixNeg(b as i8)


def parse_spec(text):
    """SPEC text -> {label: [arm, ...]}; arm = [(key, calls, segments), ...] tried in order."""
    spec = {}
    for line in text.strip().split('\n'):
        head, *rules = [p.strip() for p in line.split('|')]
        label, idx = head.split()
        arm = []
        for rule in rules:
            key, calls, toks = rule.split(' ; ')
            k = key.strip()
            if '/' in k:
                v, w = k.split('/')
                k = (int(v, 16), int(w))
            cs = []
            for c in calls.split(','):
                c = c.strip()
                if not c:
                    continue
                f = c.split('~')
                if f[0] == 'memcpy':
                    cs.append(('memcpy', f[1], f[2], int(f[3], 16)))
                elif f[0] == 'marker_u8':
                    cs.append(('marker_u8', f[1], 'des', 'M', 'M'))
                else:
                    cs.append((f[0], f[1], 'des', f[2], None if f[3] == '-' else int(f[3], 16),
                               f[4], None if f[5] == '-' else int(f[5], 16)))
            arm.append((k, tuple(cs), parse_segs(toks.split())))
        spec.setdefault(label, []).append(arm)
        if int(idx) != len(spec[label]) - 1:
            raise ValueError(f'SPEC {label} index {idx} out of order')
    return spec


def parse_segs(toks):
    segs = []
    for t in toks:
        if t == 'E':
            segs += [(0, 'q', 'err'), (8, 's', 1, 0, 32)]
        elif t == 'X':
            segs.append((0, 's', 1, 0, OUT_SIZE))
        elif t[0] == 'D':
            segs.append((0, 'q', int(t[1:], 16)))
        elif t[0] == 'P':
            o, rest = t[1:].split('=')
            src, n = rest.split('+')
            k, i = src.split('.')
            segs.append((int(o, 16), 's', int(k), int(i, 16), int(n, 16)))
        elif t[0] == 'C':
            o, hx = t[1:].split('=')
            segs.append((int(o, 16), 'c', bytes.fromhex(hx)))
        elif t[0] == 'A':
            o, rest = t[1:].split('=')
            src, ma = rest.split('*')
            k, i = src.split('.')
            m, a = ma.split('+')
            segs.append((int(o, 16), 'a', int(k), int(i, 16), int(m), int(a, 16)))
        else:
            raise ValueError('bad segment token ' + t)
    return tuple(segs)


def head_matches(buf, key):
    if key in ('*', 'eof'):
        return key == '*'
    v, w = key
    return buf[:w] == v.to_bytes(w, 'little')


def reconstructed(spec, row, case, variant=None):
    """Pure model of one visit_enum caller: (out bytes, call records, deserializer bytes)."""
    label, start, size, frame, ident_fn, n, err = row
    _, ident, knob, seed, inp, peek = case
    out = bytearray([OUT_FILL]) * OUT_SIZE
    des = initial_des(inp, peek)
    calls = [('%x' % ident_fn, 'sp+%x' % (8 if label != 'E114B' else 0), 'des', 'v:1', None, '-', None)]
    bufs = {0: ident}
    if ident[0] != IDENT_OK:
        segs = parse_segs(['E'])
        bufs[1] = ident  # the identifier error is moved out unchanged
        return apply(out, segs, bufs, err, variant), tuple(calls), bytes(des)
    arm = spec[label][ident[1]]
    marker = None
    if any(c[0] == 'marker_u8' for r in arm for c in r[1]):
        des[0x20] = 1  # the peek slot is always taken
        if peek is not None and peek[0] != 1 and variant != 'peek_ignored':
            marker = peek
        elif inp:
            marker = decompose_marker(inp[0])
            struct.pack_into('<QQ', des, 0x10, IN_BASE + 1, len(inp) - 1)
        else:
            if variant == 'eof_keeps_peek':
                des[0x20] = DES_FILL if peek is None else peek[0]
            rule = [r for r in arm if r[0] == 'eof'][0]
            return apply(out, rule[2], bufs, err, variant), tuple(calls), bytes(des)
    for rule in arm:
        key, cs, segs = rule
        if key == 'eof':
            continue
        rec, bufs2 = [], dict(bufs)
        for c in cs:
            if c[0] == 'marker_u8':
                kind, data = marker
                if variant == 'fixstr_mask_0f' and kind == 0xa0:
                    data &= 0x0f
                rec.append(('marker_u8', c[1], 'des', kind, data))
            else:
                rec.append(c)
            k = len(calls) + len(rec) - 1
            if c[0] == 'memcpy':
                continue
            dst = c[1]
            nbytes = OUT_SIZE if dst == 'out' else frame - int(dst[3:], 16)
            bufs2[k] = stub_bytes(seed, k, c[0], nbytes, knob)
        first = bufs2.get(1)
        if key == '*' or (first is not None and head_matches(first, key)):
            return apply(out, segs, bufs2, err, variant), tuple(calls + rec), bytes(des)
    raise ValueError('no rule matched')


def apply(out, segs, bufs, err, variant=None):
    for seg in segs:
        o, kind = seg[0], seg[1]
        if kind == 'q':
            v = err if seg[2] == 'err' else seg[2]
            if variant == 'err_disc_plus1' and seg[2] == 'err':
                v += 1
            out[o:o + 8] = v.to_bytes(8, 'little')
        elif kind == 'c':
            out[o:o + len(seg[2])] = seg[2]
        elif kind == 's':
            _, _, k, i, n = seg
            if variant == 'payload_shift' and k and n < 32 and o == 8:
                i += 1
            out[o:o + n] = bufs[k][i:i + n]
        elif kind == 'a':
            _, _, k, i, m, a = seg
            q = int.from_bytes(bufs[k][i:i + 8], 'little')
            out[o:o + 8] = ((q * m + a) & MASK64).to_bytes(8, 'little')
    return bytes(out)


# The reconstruction: one line per variant, rules tried in order (see README for the grammar).
SPEC = '''
F18 0 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D2 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 1 | * ; 18befa0~out~va:643e308~9~-~- ; X
F18 2 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D4 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 3 | * ; 18befa0~out~va:643e398~4~-~- ; X
F18 4 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D6 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 5 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D7 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 6 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D8 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 7 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D9 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 8 | * ; 18befa0~out~va:643e3d8~2~-~- ; X
F18 9 | 9/1 ; 18bf310~sp+8~-~-~-~- ; Db P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 10 | 9/1 ; 18bf310~sp+8~-~-~-~- ; Dc P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 11 | 9/1 ; 18bf310~sp+8~-~-~-~- ; Dd P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 12 | 9/1 ; 18bf310~sp+8~-~-~-~- ; De P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 13 | 9/1 ; 18bf220~sp+8~-~-~-~- ; Df P8=1.8+8 | * ; 18bf220~sp+8~-~-~-~- ; E
F18 14 | * ; 18befa0~out~va:643e3f8~7~-~- ; X
F18 15 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D11 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
F18 16 | * ; 18befa0~out~va:643e468~2~-~- ; X
F18 17 | * ; 18befa0~out~va:643e488~2~-~- ; X
F18R 0 | 9/1 ; marker_u8~sp+8 ; D2 P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc410600000000 P18=0.10+10 | * ; marker_u8~sp+8 ; E
F18R 1 | * ; 1954560~out~v:0~-~-~- ; X
F18R 2 | 9/1 ; 17bc510~sp+8~-~-~-~- ; D4 P8=1.8+18 | * ; 17bc510~sp+8~-~-~-~- ; E
F18R 3 | * ; 1ab2bc0~out~v:0~-~-~- ; X
F18R 4 | 9/1 ; marker_u8~sp+8 ; D6 P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc410600000000 P18=0.10+10 | * ; marker_u8~sp+8 ; E
F18R 5 | 9/1 ; marker_u8~sp+8 ; D7 P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc410600000000 P18=0.10+10 | * ; marker_u8~sp+8 ; E
F18R 6 | 9/1 ; marker_u8~sp+8 ; D8 P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc410600000000 P18=0.10+10 | * ; marker_u8~sp+8 ; E
F18R 7 | 9/1 ; 17d0110~sp+8~va:5f174d~b~-~- ; D9 P8=1.8+18 | * ; 17d0110~sp+8~va:5f174d~b~-~- ; E
F18R 8 | * ; 1a29e50~out~v:0~-~-~- ; X
F18R 9 | 9/1 ; marker_u8~sp+8 ; Db P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc410600000000 P18=0.10+10 | * ; marker_u8~sp+8 ; E
F18R 10 | 9/1 ; marker_u8~sp+8 ; Dc P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc410600000000 P18=0.10+10 | * ; marker_u8~sp+8 ; E
F18R 11 | 9/1 ; 17d5750~sp+8~va:5f174d~b~-~- ; Dd P8=1.8+8 | * ; 17d5750~sp+8~va:5f174d~b~-~- ; E
F18R 12 | 9/1 ; 17d5750~sp+8~va:5f174d~b~-~- ; De P8=1.8+8 | * ; 17d5750~sp+8~va:5f174d~b~-~- ; E
F18R 13 | 9/1 ; 17d7800~sp+8~va:5f174d~b~-~- ; Df P8=1.8+8 | * ; 17d7800~sp+8~va:5f174d~b~-~- ; E
F18R 14 | * ; 1bb1240~out~v:0~-~-~- ; X
F18R 15 | 9/1 ; 17d5750~sp+8~va:5f174d~b~-~- ; D11 P8=1.8+8 | * ; 17d5750~sp+8~va:5f174d~b~-~- ; E
F18R 16 | * ; 1b99ea0~out~v:0~-~-~- ; X
F18R 17 | * ; 193e520~out~v:0~-~-~- ; X
E114A 0 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D14 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 1 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D15 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 2 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D16 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 3 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D17 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 4 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D18 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 5 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D19 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 6 | 8000000000000000/8 ; 18bfe80~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bfe80~sp+8~-~-~-~- ; D1a P8=1.0+30
E114A 7 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D1b P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 8 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D1c P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 9 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D1d P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 10 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D1e P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 11 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D1f P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 12 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D20 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 13 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D21 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 14 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D22 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 15 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D23 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 16 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D24 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 17 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D25 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 18 | * ;  ; D26
E114A 19 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D27 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 20 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D28 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 21 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D29 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 22 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D2a P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 23 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D2b P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 24 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D2c P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 25 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 26 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 27 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 28 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 29 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D31 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 30 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 31 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D33 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 32 | 2/4 ; 18c0000~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18c0000~sp+8~-~-~-~- ; D34 P8=1.0+68
E114A 33 | * ; 18bec30~out~va:643e9f8~2~-~- ; X
E114A 34 | 8000000000000000/8 ; 18bf480~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bf480~sp+8~-~-~-~- ; D36 P8=1.0+38
E114A 35 | * ; 18bec30~out~va:643ea18~3~-~- ; X
E114A 36 | * ; 18bec30~out~va:643ea48~3~-~- ; X
E114A 37 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 38 | * ; 18bec30~out~va:643ea78~2~-~- ; X
E114A 39 | * ; 18bec30~out~va:643ea98~2~-~- ; X
E114A 40 | * ;  ; D3c
E114A 41 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D3d P8=1.8+10 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 42 | * ; 18bec30~out~va:643eab8~3~-~- ; X
E114A 43 | * ; 18bec30~out~va:643eae8~1~-~- ; X
E114A 44 | 9/1 ; 18bf220~sp+8~-~-~-~- ; D40 P8=1.8+8 | * ; 18bf220~sp+8~-~-~-~- ; E
E114A 45 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D41 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 46 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D42 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 47 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D43 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 48 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 49 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 50 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D46 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 51 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D47 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 52 | * ; 18beac0~out~v:2~-~-~- ; X
E114A 53 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D49 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 54 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D4a P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 55 | * ; 18bec30~out~va:643eaf8~2~-~- ; X
E114A 56 | * ; 18bec30~out~va:643eb18~2~-~- ; X
E114A 57 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D4d P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 58 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D4e P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 59 | 9/1 ; 18bf220~sp+8~-~-~-~- ; D4f P8=1.8+8 | * ; 18bf220~sp+8~-~-~-~- ; E
E114A 60 | 9/1 ; 18bf220~sp+8~-~-~-~- ; D50 P8=1.8+8 | * ; 18bf220~sp+8~-~-~-~- ; E
E114A 61 | * ; 18bec30~out~va:643eb38~2~-~- ; X
E114A 62 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D52 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 63 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D53 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 64 | * ; 18bec30~out~va:643eb58~3~-~- ; X
E114A 65 | * ; 18bec30~out~va:643eb88~2~-~- ; X
E114A 66 | * ; 18bec30~out~va:643eb88~2~-~- ; X
E114A 67 | * ; 18bec30~out~va:643eba8~2~-~- ; X
E114A 68 | * ; 18bec30~out~va:643ebc8~2~-~- ; X
E114A 69 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D59 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 70 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D5a P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 71 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D5b P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 72 | * ; 18bec30~out~va:643ebe8~3~-~- ; X
E114A 73 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D5d P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 74 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D5e P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 75 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D5f P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 76 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D60 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 77 | 14/4 ; 18bfa00~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bfa00~sp+8~-~-~-~-,memcpy~out~sp+8~f0 ; P0=1.0+f0
E114A 78 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D62 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 79 | * ;  ; D63
E114A 80 | * ; 18bec30~out~va:643ec18~4~-~- ; X
E114A 81 | * ; 18bec30~out~va:643ec58~1~-~- ; X
E114A 82 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D66 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 83 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D67 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 84 | 800000000000000d/8 ; 18bff80~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bff80~sp+8~-~-~-~-,memcpy~out+8~sp+8~b0 ; D68 P8=1.0+b0
E114A 85 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D69 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 86 | 4/4 ; 18bf600~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bf600~sp+8~-~-~-~- ; D6a P8=1.0+30
E114A 87 | 2/4 ; 18bf400~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bf400~sp+8~-~-~-~-,memcpy~out+8~sp+8~a8 ; D6b P8=1.0+a8
E114A 88 | 9/1 ; 18bf220~sp+8~-~-~-~- ; D6c P8=1.8+8 | * ; 18bf220~sp+8~-~-~-~- ; E
E114A 89 | * ; 18bec30~out~va:643ec68~3~-~- ; X
E114A 90 | * ; 18bec30~out~va:643ec98~8~-~- ; X
E114A 91 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D6f P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 92 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D70 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 93 | * ; 18bec30~out~va:643ed18~3~-~- ; X
E114A 94 | 8000000000000015/8 ; 18bfc80~sp+8~-~-~-~- ; D86 P8=1.8+20 | * ; 18bfc80~sp+8~-~-~-~-,memcpy~out+8~sp+8~b0 ; D72 P8=1.0+b0
E114A 95 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D73 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 96 | * ; 18bec30~out~va:643ed48~2~-~- ; X
E114A 97 | * ; 18bec30~out~va:643ed68~1~-~- ; X
E114A 98 | * ; 18bec30~out~va:643ed68~1~-~- ; X
E114A 99 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D77 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 100 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D78 P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 101 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D79 P8=1.8+18 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 102 | 0/1 ; 18bf680~sp+8~-~-~-~- ; D7a P8=1.8+20 | * ; 18bf680~sp+8~-~-~-~- ; D86 P8=1.8+20
E114A 103 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D7b P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 104 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D7c P8=1.8+10 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 105 | * ; 18bec30~out~va:643ed78~2~-~- ; X
E114A 106 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D7e P8=1.8+10 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 107 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D7f P8=1.8+10 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 108 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D80 P8=1.8+8 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 109 | * ; 18bf680~sp+8~-~-~-~- ; A0=1.0*5+81 P8=1.8+20
E114A 110 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D82 P8=1.8+10 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 111 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D83 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 112 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D84 P8=1.1+1 | * ; 18bf310~sp+8~-~-~-~- ; E
E114A 113 | * ;  ; D85
E114B 0 | 9/1 ; 17c14f0~sp+0~va:5ef0d5~11~-~- ; D14 P8=1.8+18 | * ; 17c14f0~sp+0~va:5ef0d5~11~-~- ; E
E114B 1 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D15 P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 2 | 0/1 ; 17ca410~sp+0~va:5ef102~e~-~- ; D16 P8=1.8+20 | * ; 17ca410~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 3 | 9/1 ; 17d0110~sp+0~va:5f174d~b~-~- ; D17 P8=1.8+18 | * ; 17d0110~sp+0~va:5f174d~b~-~- ; E
E114B 4 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D18 P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 5 | 9/1 ; 17d0110~sp+0~va:5f174d~b~-~- ; D19 P8=1.8+18 | * ; 17d0110~sp+0~va:5f174d~b~-~- ; E
E114B 6 | 8000000000000000/8 ; 1a7a660~sp+0~v:0~-~-~- ; D86 P8=1.8+20 | * ; 1a7a660~sp+0~v:0~-~-~- ; D1a P8=1.0+30
E114B 7 | 0/1 ; 17d5140~sp+0~va:5ef102~e~-~- ; D1b P8=1.8+20 | * ; 17d5140~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 8 | 0/1 ; 17e82e0~sp+0~va:5ef102~e~-~- ; D1c P8=1.8+20 | * ; 17e82e0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 9 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D1d P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 10 | 9/1 ; 17d3a90~sp+0~va:5ef0e6~e~-~- ; D1e P8=1.8+18 | * ; 17d3a90~sp+0~va:5ef0e6~e~-~- ; E
E114B 11 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D1f P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 12 | 0/1 ; 17f8cc0~sp+0~va:5ef102~e~-~- ; D20 P8=1.8+20 | * ; 17f8cc0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 13 | 9/1 ; 17ded20~sp+0~va:5f174d~b~-~- ; D21 P8=1.8+8 | * ; 17ded20~sp+0~va:5f174d~b~-~- ; E
E114B 14 | 0/1 ; 17f8cc0~sp+0~va:5ef102~e~-~- ; D22 P8=1.8+20 | * ; 17f8cc0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 15 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D23 P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 16 | 0/1 ; 17c0ee0~sp+0~va:5ef102~e~-~- ; D24 P8=1.8+20 | * ; 17c0ee0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 17 | 0/1 ; 17d2db0~sp+0~va:5ef102~e~-~- ; D25 P8=1.8+20 | * ; 17d2db0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 18 | 9/1 ; 29413d0~sp+0~-~-~-~- ; D26 | * ; 29413d0~sp+0~-~-~-~- ; E
E114B 19 | 0/1 ; 17c4320~sp+0~va:5ef102~e~-~- ; D27 P8=1.8+20 | * ; 17c4320~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 20 | 0/1 ; 17c4320~sp+0~va:5ef102~e~-~- ; D28 P8=1.8+20 | * ; 17c4320~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 21 | 0/1 ; 17c4320~sp+0~va:5ef102~e~-~- ; D29 P8=1.8+20 | * ; 17c4320~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 22 | 9/1 ; 17d0a30~sp+0~va:5ef0f4~e~-~- ; D2a P8=1.8+18 | * ; 17d0a30~sp+0~va:5ef0f4~e~-~- ; E
E114B 23 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D2b P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 24 | 9/1 ; 17d0110~sp+0~va:5f174d~b~-~- ; D2c P8=1.8+18 | * ; 17d0110~sp+0~va:5f174d~b~-~- ; E
E114B 25 | * ; 1b37cf0~out~v:0~-~-~- ; X
E114B 26 | * ; 1c52b00~out~v:0~-~-~- ; X
E114B 27 | * ; 1bb4a20~out~v:0~-~-~- ; X
E114B 28 | * ; 18c6390~out~v:0~-~-~- ; X
E114B 29 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D31 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 30 | * ; 19c2bd0~out~v:0~-~-~- ; X
E114B 31 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D33 P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 32 | 2/4 ; 19e7110~sp+0~v:0~-~-~- ; D86 P8=1.8+20 | * ; 19e7110~sp+0~v:0~-~-~- ; D34 P8=1.0+68
E114B 33 | * ; 1a95fa0~out~v:0~-~-~- ; X
E114B 34 | 8000000000000000/8 ; 1a34f80~sp+0~v:0~-~-~- ; D86 P8=1.8+20 | * ; 1a34f80~sp+0~v:0~-~-~- ; D36 P8=1.0+38
E114B 35 | * ; 1c4d220~out~v:0~-~-~- ; X
E114B 36 | * ; 19a2810~out~v:0~-~-~- ; X
E114B 37 | * ; 1b58e50~out~v:0~-~-~- ; X
E114B 38 | * ; 18fc810~out~v:0~-~-~- ; X
E114B 39 | * ; 19a9040~out~v:0~-~-~- ; X
E114B 40 | 9/1 ; 29413d0~sp+0~-~-~-~- ; D3c | * ; 29413d0~sp+0~-~-~-~- ; E
E114B 41 | 9/1 ; 17bb570~sp+0~-~-~-~- ; D3d P8=1.8+10 | * ; 17bb570~sp+0~-~-~-~- ; E
E114B 42 | * ; 18db750~out~v:0~-~-~- ; X
E114B 43 | * ; 1c51440~out~v:0~-~-~- ; X
E114B 44 | 9/1 ; 17d7800~sp+0~va:5f174d~b~-~- ; D40 P8=1.8+8 | * ; 17d7800~sp+0~va:5f174d~b~-~- ; E
E114B 45 | 9/1 ; 17c76f0~sp+0~va:5f174d~b~-~- ; D41 P8=1.8+8 | * ; 17c76f0~sp+0~va:5f174d~b~-~- ; E
E114B 46 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D42 P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 47 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D43 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 48 | * ; 1b8f070~out~v:0~-~-~- ; X
E114B 49 | * ; 1920740~out~v:0~-~-~- ; X
E114B 50 | 9/1 ; 17ded20~sp+0~va:5f174d~b~-~- ; D46 P8=1.8+8 | * ; 17ded20~sp+0~va:5f174d~b~-~- ; E
E114B 51 | 9/1 ; 17d5750~sp+0~va:5f174d~b~-~- ; D47 P8=1.8+8 | * ; 17d5750~sp+0~va:5f174d~b~-~- ; E
E114B 52 | * ; 18e7470~out~v:0~-~-~- ; X
E114B 53 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D49 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 54 | 9/1 ; 17bc510~sp+0~-~-~-~- ; D4a P8=1.8+18 | * ; 17bc510~sp+0~-~-~-~- ; E
E114B 55 | * ; 18cb8a0~out~v:0~-~-~- ; X
E114B 56 | * ; 1b54550~out~v:0~-~-~- ; X
E114B 57 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D4d P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 58 | 9/1 ; 17db620~sp+0~va:5f174d~b~-~- ; D4e P8=1.1+1 | * ; 17db620~sp+0~va:5f174d~b~-~- ; E
E114B 59 | 9/1 ; 17d7800~sp+0~va:5f174d~b~-~- ; D4f P8=1.8+8 | * ; 17d7800~sp+0~va:5f174d~b~-~- ; E
E114B 60 | 9/1 ; 17d7800~sp+0~va:5f174d~b~-~- ; D50 P8=1.8+8 | * ; 17d7800~sp+0~va:5f174d~b~-~- ; E
E114B 61 | * ; 1a3e0a0~out~v:0~-~-~- ; X
E114B 62 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D52 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 63 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D53 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 64 | * ; 1ba6e70~out~v:0~-~-~- ; X
E114B 65 | * ; 1a97400~out~v:0~-~-~- ; X
E114B 66 | * ; 1a6ee60~out~v:0~-~-~- ; X
E114B 67 | * ; 1ab9c70~out~v:0~-~-~- ; X
E114B 68 | * ; 1bc14f0~out~v:0~-~-~- ; X
E114B 69 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D59 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 70 | 0/1 ; 17cbeb0~sp+0~va:5ef102~e~-~- ; D5a P8=1.8+20 | * ; 17cbeb0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 71 | 0/1 ; 17cbeb0~sp+0~va:5ef102~e~-~- ; D5b P8=1.8+20 | * ; 17cbeb0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 72 | * ; 1bcfb40~out~v:0~-~-~- ; X
E114B 73 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D5d P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 74 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D5e P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 75 | 0/1 ; 17b6700~sp+0~va:5ff8af~12~va:643f948~6 ; D5f P8=1.8+20 | * ; 17b6700~sp+0~va:5ff8af~12~va:643f948~6 ; D86 P8=1.8+20
E114B 76 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D60 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 77 | 14/4 ; 17ba4c0~sp+0~va:5ff986~7~va:643e4a8~12 ; D86 P8=1.8+20 | * ; 17ba4c0~sp+0~va:5ff986~7~va:643e4a8~12,memcpy~out~sp+0~f0 ; P0=1.0+f0
E114B 78 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D62 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 79 | 9/1 ; 29413d0~sp+0~-~-~-~- ; D63 | * ; 29413d0~sp+0~-~-~-~- ; E
E114B 80 | * ; 1b4e7f0~out~v:0~-~-~- ; X
E114B 81 | * ; 1ae7580~out~v:0~-~-~- ; X
E114B 82 | 9/1 ; 17b64e0~sp+0~va:60d3e2~1a~va:644d270~3 ; D66 P8=1.1+1 | * ; 17b64e0~sp+0~va:60d3e2~1a~va:644d270~3 ; E
E114B 83 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D67 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 84 | 800000000000000d/8 ; 17b1340~sp+0~va:5ffa97~16~va:643fe38~d ; D86 P8=1.8+20 | * ; 17b1340~sp+0~va:5ffa97~16~va:643fe38~d,memcpy~out+8~sp+0~b0 ; D68 P8=1.0+b0
E114B 85 | 9/1 ; 17d0110~sp+0~va:5f174d~b~-~- ; D69 P8=1.8+18 | * ; 17d0110~sp+0~va:5f174d~b~-~- ; E
E114B 86 | 4/4 ; 17b8d10~sp+0~va:5ff89e~11~va:643f928~2 ; D86 P8=1.8+20 | * ; 17b8d10~sp+0~va:5ff89e~11~va:643f928~2 ; D6a P8=1.0+30
E114B 87 | 2/4 ; 1981140~sp+0~v:0~-~-~- ; D86 P8=1.8+20 | * ; 1981140~sp+0~v:0~-~-~-,memcpy~out+8~sp+0~a8 ; D6b P8=1.0+a8
E114B 88 | 9/1 ; 17d7800~sp+0~va:5f174d~b~-~- ; D6c P8=1.8+8 | * ; 17d7800~sp+0~va:5f174d~b~-~- ; E
E114B 89 | * ; 1a46510~out~v:0~-~-~- ; X
E114B 90 | * ; 1c132f0~out~v:0~-~-~- ; X
E114B 91 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D6f P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 92 | 0/1 ; 17d2db0~sp+0~va:5ef102~e~-~- ; D70 P8=1.8+20 | * ; 17d2db0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 93 | * ; 1b609f0~out~v:0~-~-~- ; X
E114B 94 | 8000000000000015/8 ; 17bbed0~sp+0~-~-~-~- ; D86 P8=1.8+20 | * ; 17bbed0~sp+0~-~-~-~-,memcpy~out+8~sp+0~b0 ; D72 P8=1.0+b0
E114B 95 | 9/1 ; 17d0110~sp+0~va:5f174d~b~-~- ; D73 P8=1.8+18 | * ; 17d0110~sp+0~va:5f174d~b~-~- ; E
E114B 96 | * ; 1ae1810~out~v:0~-~-~- ; X
E114B 97 | * ; 1b6fc50~out~v:0~-~-~- ; X
E114B 98 | * ; 199ba30~out~v:0~-~-~- ; X
E114B 99 | 9/1 ; 17b1130~sp+0~va:5ff9a7~e~va:643e128~2 ; D77 P8=1.8+18 | * ; 17b1130~sp+0~va:5ff9a7~e~va:643e128~2 ; E
E114B 100 | 0/1 ; 17d2aa0~sp+0~va:5ef102~e~-~- ; D78 P8=1.8+20 | * ; 17d2aa0~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 101 | 9/1 ; 17bc510~sp+0~-~-~-~- ; D79 P8=1.8+18 | * ; 17bc510~sp+0~-~-~-~- ; E
E114B 102 | 0/1 ; 17c8b10~sp+0~va:5ef102~e~-~- ; D7a P8=1.8+20 | * ; 17c8b10~sp+0~va:5ef102~e~-~- ; D86 P8=1.8+20
E114B 103 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D7b P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 104 | 9/1 ; 17b9d50~sp+0~va:5ff98d~c~va:643eda8~4 ; D7c P8=1.8+10 | * ; 17b9d50~sp+0~va:5ff98d~c~va:643eda8~4 ; E
E114B 105 | * ; 1c34ac0~out~v:0~-~-~- ; X
E114B 106 | 9/1 ; 17b5c20~sp+0~va:5ff8e9~14~va:643eda8~4 ; D7e P8=1.8+10 | * ; 17b5c20~sp+0~va:5ff8e9~14~va:643eda8~4 ; E
E114B 107 | 9/1 ; 17bb750~sp+0~-~-~-~- ; D7f P8=1.8+10 | * ; 17bb750~sp+0~-~-~-~- ; E
E114B 108 | 9/1 ; 17ded20~sp+0~va:5f174d~b~-~- ; D80 P8=1.8+8 | * ; 17ded20~sp+0~va:5f174d~b~-~- ; E
E114B 109 | * ; 17c8b10~sp+0~va:5ef102~e~-~- ; A0=1.0*5+81 P8=1.8+20
E114B 110 | 9/1 ; 17bb670~sp+0~-~-~-~- ; D82 P8=1.8+10 | * ; 17bb670~sp+0~-~-~-~- ; E
E114B 111 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D83 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 112 | 9/1 ; 26328c0~sp+0~-~-~-~- ; D84 P8=1.1+1 | * ; 26328c0~sp+0~-~-~-~- ; E
E114B 113 | 9/1 ; 29413d0~sp+0~-~-~-~- ; D85 | * ; 29413d0~sp+0~-~-~-~- ; E
'''


# cases -----------------------------------------------------------------------------
SEEDS = ('s0', 's1', 's2')
ERR_TAGS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0xff)
PEEKED = (0x00, 0x05, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xa3, 0xbf, 0xc0, 0xc2, 0xcc, 0xcd, 0xd0, 0xdf,
          0xe0, 0xf0, 0xff)


def marker_arms(spec, label):
    return [i for i, arm in enumerate(spec[label]) if any(c[0] == 'marker_u8' for r in arm for c in r[1])]


def build_cases(spec, fn):
    cases = []
    for idx in range(fn.n):
        for knob in knobs(fn):
            for seed in SEEDS:
                cases.append((fn.label, ident_bytes(seed, IDENT_OK, idx), knob, seed, b'\x07\x00', None))
    for n, tag in enumerate(ERR_TAGS):
        for seed in ('e0', 'e1'):
            cases.append((fn.label, ident_bytes(seed, tag, (n * 7) % fn.n), MISS, seed, b'', None))
    for idx in marker_arms(spec, fn.label):
        for b in range(256):
            knob = (IDENT_OK, 1) if b % 2 else MISS
            cases.append((fn.label, ident_bytes('mk', IDENT_OK, idx), knob, 'mk', bytes([b, 0x11]), None))
        for b in PEEKED:
            cases.append((fn.label, ident_bytes('pk', IDENT_OK, idx), (IDENT_OK, 1), 'pk', b'\x22',
                          decompose_marker(b)))
        cases.append((fn.label, ident_bytes('ef', IDENT_OK, idx), MISS, 'ef', b'', None))
        cases.append((fn.label, ident_bytes('ef', IDENT_OK, idx), MISS, 'ef', b'', (1, 0x44)))
        cases.append((fn.label, ident_bytes('np', IDENT_OK, idx), (IDENT_OK, 1), 'np', b'\x33', (1, 0x44)))
    return cases


def run_machine(m, case):
    try:
        return m.run(case)
    except Fault as e:
        return ('fault', str(e))


def compare(spec, img, fn, cases, variant=None):
    m = Machine(img, fn)
    rows, bad, cover, edges = [], 0, set(), set()
    for i, case in enumerate(cases):
        got = run_machine(m, case)
        cover.update(m.trace)
        edges.update(m.edges)
        want = reconstructed(spec, (fn.label, fn.start, 0, fn.frame, fn.ident, fn.n, fn.err), case, variant)
        ok = got == want
        bad += not ok
        rows.append((i, case, got, ok))
    return rows, bad, cover, edges


# mutants ---------------------------------------------------------------------------
MODEL_VARIANTS = ('peek_ignored', 'eof_keeps_peek', 'fixstr_mask_0f', 'err_disc_plus1', 'payload_shift')
SPEC_EDITS = (
    ('F18', 'swap_disc_F18_0_2', 'F18 0 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D2 ', 'F18 0 | 9/1 ; 18bf310~sp+8~-~-~-~- ; D4 '),
    ('F18', 'struct_field_count_F18_1', 'F18 1 | * ; 18befa0~out~va:643e308~9~-~- ;', 'F18 1 | * ; 18befa0~out~va:643e308~8~-~- ;'),
    ('E114A', 'affine_mul4_E114A_109', 'E114A 109 | * ; 18bf680~sp+8~-~-~-~- ; A0=1.0*5+81', 'E114A 109 | * ; 18bf680~sp+8~-~-~-~- ; A0=1.0*4+81'),
    ('E114A', 'niche_rule_dropped_E114A_6', 'E114A 6 | 8000000000000000/8 ; 18bfe80~sp+8~-~-~-~- ; D86 P8=1.8+20 | ', 'E114A 6 | '),
    ('E114B', 'memcpy_len_E114B_84', 'memcpy~out+8~sp+0~b0 ; D68 P8=1.0+b0', 'memcpy~out+8~sp+0~a8 ; D68 P8=1.0+a8'),
    ('E114B', 'ok_tag_byte_E114B_2', 'E114B 2 | 0/1 ;', 'E114B 2 | 1/1 ;'),
    ('F18R', 'eof_static_F18R_0', 'F18R 0 | 9/1 ; marker_u8~sp+8 ; D2 P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b0cc41',
     'F18R 0 | 9/1 ; marker_u8~sp+8 ; D2 P8=1.1+1 | eof ;  ; D14 C8=00 P9=0.1+7 C10=b8cc41'),
)


def image_sites(img, fn):
    """(kind, file offsets, description) corruptions of one function's bytes.

    Neighbouring jump table entries whose arms have the same SPEC rules (duplicated
    arm bodies, e.g. E114A 25/26) are skipped: swapping them is an equivalent mutant.
    """
    spec_rules = [ln.split('|', 1)[1] for ln in SPEC.strip().split('\n') if ln.split()[0] == fn.label]
    sites = []
    for i in range(0, fn.n - 1, 5):
        a, b = fn.table_va + 4 * i, fn.table_va + 4 * (i + 1)
        if fn.arms[i] != fn.arms[i + 1] and spec_rules[i] != spec_rules[i + 1]:
            sites.append(('swap', img.off(a), img.off(b), f'jump table entries {i} and {i + 1} swapped'))
    imms = [i for i in fn.insns if i.op == 'mov' and i.b and i.b[0] == 'i' and i.immlen == 4 and i.w in (32, 64)
            and (i.a[0] == 'r' or i.a[1] == 3)]
    for ins in imms[::max(1, len(imms) // 12)]:
        sites.append(('xor', img.off(ins.va + ins.size - ins.immlen), 0x01,
                      f'mov imm {ins.b[1]:#x} at {ins.va:#x}'))
    seen = set()
    for ins in fn.insns:
        if ins.op in ('cmp', 'and') and ins.b and ins.b[0] == 'i' and ins.immlen:
            key = (ins.op, ins.b[1], ins.w)
            if key in seen:
                continue
            seen.add(key)
            sites.append(('xor', img.off(ins.va + ins.size - ins.immlen), 0x01,
                          f'{ins.op} imm {ins.b[1]:#x} at {ins.va:#x}'))
    return sites


def run_image_mutant(spec, data, img, fn, row, site, cases, wants):
    mut = bytearray(data)
    if site[0] == 'swap':
        a, b = site[1], site[2]
        mut[a:a + 4], mut[b:b + 4] = mut[b:b + 4], mut[a:a + 4]
    else:
        mut[site[1]] ^= site[2]
    mimg = Image(bytes(mut), check=False)
    try:
        mfn = Fn(mimg, row)
    except Fault:
        return 'static'
    m = Machine(mimg, mfn)
    for i, case in enumerate(cases):
        if run_machine(m, case) != wants[i]:
            return i
    return None


# output ----------------------------------------------------------------------------
def hx(v):
    return '-' if v is None else (v.hex() if isinstance(v, bytes) else str(v))


def generate(out_dir, data=None):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = BINARY.read_bytes() if data is None else data
    img = Image(data)
    spec = parse_spec(SPEC)
    fns = [Fn(img, row) for row in FUNCS]
    for fn in fns:
        if len(spec[fn.label]) != fn.n:
            raise Fault(f'SPEC has {len(spec[fn.label])} arms for {fn.label}')
    summary = {'binary_sha256': SHA256, 'functions': {}, 'cases': 0, 'mismatches': 0}
    case_lines = ['id\tfunction\tident_tag\tvariant\tknob\tseed\tinput\tpeek\tout_sha256_16\tcalls\tmatch']
    cov_lines = ['function\tinstructions\tcovered\tcond_jumps\tedges_taken\tedges_fallthrough']
    fn_lines = ['function\tstart\tend\tsize\tframe\tidentifier\tjump_table\tvariants\terror_disc\tinstructions'
                '\tdirect_callees\tgot_slots\tknobs']
    arm_lines = ['function\tvariant\tarm_va\trules']
    mut_lines = ['kind\tfunction\tmutant\tresult']
    all_rows = {}
    cid = 0
    for fn in fns:
        cases = build_cases(spec, fn)
        rows, bad, cover, edges = compare(spec, img, fn, cases)
        all_rows[fn.label] = (cases, rows)
        conds = [i.va for i in fn.insns if i.op == 'j']
        taken = sum((v, True) in edges for v in conds)
        fall = sum((v, False) in edges for v in conds)
        summary['functions'][fn.label] = {
            'start': hex(fn.start), 'size': fn.end - fn.start, 'variants': fn.n, 'cases': len(cases),
            'mismatches': bad, 'instructions': len(fn.insns), 'covered': len(cover & set(fn.cache)),
            'cond_jumps': len(conds), 'edges_taken': taken, 'edges_fallthrough': fall,
            'direct_callees': len(fn.callees)}
        summary['cases'] += len(cases)
        summary['mismatches'] += bad
        cov_lines.append(f'{fn.label}\t{len(fn.insns)}\t{len(cover & set(fn.cache))}\t{len(conds)}\t{taken}\t{fall}')
        fn_lines.append('\t'.join([fn.label, hex(fn.start), hex(fn.end), str(fn.end - fn.start), hex(fn.frame),
                                   hex(fn.ident), hex(fn.table_va), str(fn.n), hex(fn.err), str(len(fn.insns)),
                                   ','.join('%x' % c for c in fn.callees), ','.join('%x' % s for s in fn.slots),
                                   ','.join('%x/%d' % k for k in knobs(fn))]))
        lines = [ln for ln in SPEC.strip().split('\n') if ln.split()[0] == fn.label]
        for idx, ln in enumerate(lines):
            arm_lines.append(f'{fn.label}\t{idx}\t{fn.arms[idx]:#x}\t{ln.split("|", 1)[1].strip()}')
        for i, case, got, ok in rows:
            label, ident, knob, seed, inp, peek = case
            if isinstance(got, tuple) and got and got[0] == 'fault':
                dig, nc = 'fault', '-'
            else:
                dig, nc = hashlib.sha256(got[0]).hexdigest()[:16], str(len(got[1]))
            case_lines.append('\t'.join([str(cid), label, str(ident[0]), str(ident[1]), '%x/%d' % knob, seed,
                                         inp.hex() or '-', '-' if peek is None else '%x/%x' % peek, dig, nc,
                                         'ok' if ok else 'MISMATCH']))
            cid += 1
    # model mutants: every wrong reconstruction must disagree with the bytes somewhere
    killed = 0
    for variant in MODEL_VARIANTS:
        hit = None
        for fn in fns:
            cases, rows = all_rows[fn.label]
            for i, case, got, ok in rows:
                if reconstructed(spec, (fn.label, fn.start, 0, fn.frame, fn.ident, fn.n, fn.err), case,
                                 variant) != got:
                    hit = f'{fn.label}#{i}'
                    break
            if hit:
                break
        killed += hit is not None
        mut_lines.append(f'model\t*\t{variant}\t{"killed " + hit if hit else "SURVIVED"}')
    for label, name, old, new in SPEC_EDITS:
        if SPEC.count(old) != 1:
            raise Fault(f'spec edit {name} does not apply exactly once')
        mspec = parse_spec(SPEC.replace(old, new))
        fn = [f for f in fns if f.label == label][0]
        cases, rows = all_rows[label]
        hit = None
        for i, case, got, ok in rows:
            if reconstructed(mspec, (fn.label, fn.start, 0, fn.frame, fn.ident, fn.n, fn.err), case) != got:
                hit = i
                break
        killed += hit is not None
        mut_lines.append(f'spec\t{label}\t{name}\t{"killed case " + str(hit) if hit is not None else "SURVIVED"}')
    n_model = len(MODEL_VARIANTS) + len(SPEC_EDITS)
    ikilled = istatic = itotal = 0
    for fn, row in zip(fns, FUNCS):
        cases, rows = all_rows[fn.label]
        wants = [got for _, _, got, _ in rows]
        for site in image_sites(img, fn):
            r = run_image_mutant(spec, data, img, fn, row, site, cases, wants)
            itotal += 1
            if r == 'static':
                istatic += 1
                res = 'rejected by static checks'
            elif r is None:
                res = 'SURVIVED'
            else:
                ikilled += 1
                res = f'killed case {r}'
            mut_lines.append(f'image\t{fn.label}\t{site[-1]}\t{res}')
    summary['model_mutants'] = {'total': n_model, 'killed': killed}
    summary['image_mutants'] = {'total': itotal, 'killed_by_cases': ikilled, 'rejected_static': istatic,
                                'survived': itotal - ikilled - istatic}
    files = {
        'functions.tsv': fn_lines, 'arms.tsv': arm_lines, 'cases.tsv': case_lines,
        'coverage.tsv': cov_lines, 'mutants.tsv': mut_lines,
    }
    for name, lines in files.items():
        (out_dir / name).write_text('\n'.join(lines) + '\n')
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True, help='evidence folder to (re)generate')
    args = ap.parse_args()
    s = generate(args.out)
    print(json.dumps({k: s[k] for k in ('cases', 'mismatches', 'model_mutants', 'image_mutants')}, sort_keys=True))
    bad = s['mismatches'] or s['model_mutants']['killed'] != s['model_mutants']['total'] \
        or s['image_mutants']['survived']
    for f in s['functions'].values():
        bad = bad or f['covered'] != f['instructions']
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
