#!/usr/bin/env python3
"""Reconstruct the node #115 internally tagged Action content visitor and prove it.

The MessagePack `Action` decoder buffers a map or a sequence before it knows the
variant: serde's internally tagged enum support reads the `type` tag with the
Action identifier decoder and keeps every other (key, value) pair as `Content`.
Node #115 has three copies of each visitor body, one per deserializer type:

  visit_map  0x1fb1750 0x3952ed0 0x5687260   (1230 B each)
  visit_seq  0x1fb1d20 0x39535e0 0x5687730   (294 B each)

This tool:
1. checks the input digest, finds each function's FDE extent, decodes every
   instruction with a fixed-pattern x86-64 subset decoder, and binds every call
   site to a role by its offset (the copies share one layout; the roles' targets
   are read from each copy's bytes and must agree with the anchor copy's GOT slots);
2. interprets the original bytes (the binary is never run; callees are contract
   stubs scripted by the case: key reader, value reader, identifier decoder,
   error formatter, allocator, vec growth, drops, and exceptions for the
   landing pads);
3. compares every outcome with a pure reconstruction (`visit_map` /
   `visit_seq` below): result bytes, the callee sequence with semantic
   arguments, the remaining-count write-back and the buffered pairs;
4. proves instruction and branch coverage and that wrong reconstructions and
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

# form, start, FDE size, frame size (sub rsp), <str as Display>::fmt copy passed to the error formatter
FUNCS = (
    ('map', 0x1fb1750, 1230, 0x108, 0x24a7c50),
    ('map', 0x3952ed0, 1230, 0x108, 0x46dd7f0),
    ('map', 0x5687260, 1230, 0x108, 0x5616320),
    ('seq', 0x1fb1d20, 294, 0x58, 0x24a7c50),
    ('seq', 0x39535e0, 294, 0x58, 0x46dd7f0),
    ('seq', 0x5687730, 294, 0x58, 0x5616320),
)
# call-site offset -> role, read for the anchor copy and required in every copy
MAP_ROLES = {
    0x43: 'alloc', 0xfd: 'key_read', 0x16c: 'value_read', 0x1bc: 'grow', 0x1e7: 'ident',
    0x270: 'fmt_error', 0x296: 'drop_pairs', 0x359: 'drop_key', 0x39f: 'fmt_error',
    0x3df: 'drop_content', 0x3ec: 'drop_content', 0x40c: 'dealloc', 0x42f: 'alloc_error',
    0x43f: 'drop_result', 0x446: 'terminate', 0x454: 'drop_key', 0x461: 'drop_pairs',
    0x468: 'terminate', 0x475: 'drop_content', 0x47c: 'terminate', 0x49c: 'drop_pair',
    0x4ba: 'dealloc', 0x4c3: 'resume', 0x4c8: 'terminate',
}
SEQ_ROLES = {0x30: 'ident', 0x58: 'rest_read', 0x118: 'fmt_error'}
SLOTS = {'alloc': 0x6355830, 'alloc_error': 0x141e264, 'dealloc': 0x635de30,
         'terminate': 0x1680cab, 'grow': 0x16a06c0}
RESUME_SYMBOL = '_Unwind_Resume'
MISSING_FIELD = 0x4325c4      # format pieces passed by the missing-field error path
DUPLICATE_FIELD = 0x43351a    # format pieces passed by the duplicate-field error path
CAUTIOUS_CAP = 0x4000         # serde size_hint::cautious: 1 MiB / 64-byte pair
PAIR = 64
NO_TAG = 0x5c                 # Option<variant index> None niche (92 variants)
KEY_TAG, KEY_END = 0x16, 0x17  # TagOrContent::Tag, Option::None niche of the key result
CONTENT_MAP = 0x15            # Content::Map discriminant
IDENT_OK = 9

OUT_BASE, VIS_BASE, ACC_BASE, DES_BASE = 0x7100_0000_0000, 0x7140_0000_0000, 0x7160_0000_0000, 0x7180_0000_0000
HEAP_BASE, NAME_PTR = 0x7400_0000_0000, 0x7300_0000_0000
STACK_TOP = 0x7200_0000_0000
MASK64 = (1 << 64) - 1
OUT_FILL, STACK_FILL, ACC_FILL = 0xaa, 0x5c, 0x3d
OUT_SIZE = 0x40
EXC = 0xe0c0_0000_0001        # exception object token handed to landing pads


def pattern(*key, n=32):
    """Deterministic stub bytes: sha256 stream keyed by the case words."""
    h, k = b'', 0
    while len(h) < n:
        h += hashlib.sha256((':'.join(map(str, key)) + f':{k}').encode()).digest()
        k += 1
    return h[:n]


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
        if reg & 7 not in (0, 4) or rm[0] != 'r':
            raise Fault(f'unsupported shift form at {va:#x}')
        ins.op, ins.a, ins.b = ('rol' if reg & 7 == 0 else 'shl'), rm, imm(1)
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
        elif op2 == 0x1f:
            modrm()  # multi-byte nop
            ins.op = 'nop'
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



def h16(b):
    return hashlib.sha256(bytes(b)).hexdigest()[:16]


class Fn:
    """Static facts of one visitor copy, all read from the bytes."""

    def __init__(self, img, row, anchor=None):
        self.form, self.start, size, self.frame, self.display = row
        fde = fde_of(img.data, self.start)
        self.end = fde['end']
        if self.end - self.start != size:
            raise Fault(f'{self.start:#x}: FDE extent is {self.end - self.start} bytes')
        self.lsda = fde.get('lsda') or 0
        self.sites = img.call_sites(self.lsda, self.start) if self.lsda else []
        self.insns = sweep(img, self.start, self.end)
        self.cache = {i.va: i for i in self.insns}
        subs = [i for i in self.insns if i.op == 'sub' and i.a == ('r', 4) and i.b[0] == 'i']
        if not subs or subs[0].b[1] != self.frame:
            raise Fault(f'{self.start:#x}: frame size is not {self.frame:#x}')
        roles = MAP_ROLES if self.form == 'map' else SEQ_ROLES
        self.role, self.targets = {}, {}
        for i in self.insns:
            if i.op not in ('call', 'callr'):
                continue
            o = i.va - self.start
            if o not in roles:
                raise Fault(f'{self.start:#x}: call at +{o:#x} has no role')
            role = roles[o]
            if i.op == 'callr':
                slot = i.va + i.size + i.a[4]
                r = reloc_name(img, slot)
                if r is None or r[0] != 'relative' or SLOTS.get(role) != r[1]:
                    raise Fault(f'{self.start:#x}: GOT slot {slot:#x} is not the {role} target')
                t = r[1]
            else:
                t = i.va + i.size + i.b
                if role == 'resume' and img.plt_symbol(t) != RESUME_SYMBOL:
                    raise Fault('resume call is not _Unwind_Resume')
            if self.targets.setdefault(role, t) != t and role not in ('fmt_error',):
                raise Fault(f'{self.start:#x}: role {role} has two targets')
            self.role[i.va] = role
        leas = {i.va + i.size + i.b[4] for i in self.insns if i.op == 'lea' and i.b[0] == 'm' and i.b[5]}
        want = {self.display, MISSING_FIELD} | ({DUPLICATE_FIELD} if self.form == 'map' else set())
        if not want <= leas:
            raise Fault(f'{self.start:#x}: formatter arguments {sorted(want - leas)} are not loaded')
        missing = set(roles) - {va - self.start for va in self.role}
        if missing:
            raise Fault(f'{self.start:#x}: role offsets without a call {sorted(missing)}')
        if anchor is not None:
            same = [a.raw == b.raw for a, b in zip(anchor.insns, self.insns) if a.op not in ('call', 'lea', 'callr')]
            if len(anchor.insns) != len(self.insns) or not all(same):
                raise Fault(f'{self.start:#x}: not a layout copy of {anchor.start:#x}')
            if self.sites != [(s - anchor.start + self.start, e - anchor.start + self.start,
                               lp - anchor.start + self.start if lp else 0, a) for s, e, lp, a in anchor.sites]:
                raise Fault(f'{self.start:#x}: call-site table differs from the anchor copy')

    def site_of(self, call_va):
        for s, e, lp, a in self.sites:
            if s <= call_va < e:
                return lp, a
        return None


class Stop(Exception):
    pass


class Machine:
    def __init__(self, img, fn):
        self.img, self.f = img, fn

    def run(self, case):
        self.case = case
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.vis = bytearray(struct.pack('<QQ', NAME_PTR, case['name_len']))
        self.acc = bytearray([ACC_FILL]) * 16
        struct.pack_into('<QI', self.acc, 0, DES_BASE, case['n'])
        self.stack = bytearray([STACK_FILL]) * 0x200
        self.heap = []
        self.events = list(case['events'])
        self.cur = None
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6], self.r[2] = OUT_BASE, VIS_BASE, ACC_BASE
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.calls, self.trace, self.edges = [], [], set()
        self.frame_lo = None
        pc = self.f.start
        try:
            for _ in range(case.get('steps', 4000)):
                if not self.f.start <= pc < self.f.end:
                    raise Fault(f'left function at {pc:#x}')
                ins = self.f.cache.get(pc)
                if ins is None:
                    raise Fault(f'jump into the middle of an instruction at {pc:#x}')
                self.trace.append(pc)
                nxt = pc + ins.size
                res = self.step(ins, nxt)
                if self.frame_lo is None and ins.op == 'sub' and ins.a == ('r', 4):
                    self.frame_lo = self.r[4]
                if ins.op == 'j':
                    self.edges.add((pc, res is not None))
                if res == 'ret':
                    if self.r[0] != OUT_BASE:
                        raise Fault('rax does not return the out pointer')
                    return self.result('ret')
                pc = nxt if res is None else res
            raise Fault('step limit')
        except Stop as s:
            return self.result(s.args[0])

    def result(self, kind):
        pairs = ''
        if kind == 'ret' and self.f.form == 'map' and self.out[0:8] == bytes(8):
            cap, ptr, ln = struct.unpack_from('<QQQ', self.out, 0x18)
            pairs = h16(self.load(ptr, ln * PAIR)) if ln else ''
        return (kind, self.out.hex(), tuple(self.calls), struct.unpack_from('<I', self.acc, 8)[0], pairs)

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
        if buf is None:
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
        elif op == 'shl':
            v, n = self.get(ins.a, w, nxt), ins.b % w
            self.put(ins.a, w, self.setf(w, v << n), nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'cmov':
            v = self.get(ins.b, w, nxt)
            self.put(ins.a, w, v if self.cond(ins.cc) else self.get(ins.a, w, nxt), nxt)
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
        elif op == 'nop':
            pass
        else:
            raise Fault(f'no semantics for {op} at {ins.va:#x}')
        return None

    def region(self, a, n):
        for base, buf in [(OUT_BASE, self.out), (VIS_BASE, self.vis), (ACC_BASE, self.acc),
                          (STACK_TOP - len(self.stack), self.stack)] + self.heap:
            if base <= a < base + len(buf) + 64:
                if a + n > base + len(buf):
                    raise Fault(f'access past buffer {a:#x}+{n}')
                return buf, a - base
        return None, None

    def where(self, a):
        """Name a pointer: out, deserializer, map access, frame slot, heap block, or a plain value."""
        if a == DES_BASE:
            return 'des'
        if a == ACC_BASE:
            return 'acc'
        if a == NAME_PTR:
            return 'name'
        if OUT_BASE <= a < OUT_BASE + OUT_SIZE:
            return 'out+%x' % (a - OUT_BASE)
        if self.frame_lo is not None and self.frame_lo <= a < STACK_TOP:
            return 'sp+%x' % (a - self.frame_lo)
        for k, (base, buf) in enumerate(self.heap):
            if base <= a <= base + len(buf):
                return 'h%d+%x' % (k, a - base)
        return 'v:%x' % a

    def new_block(self, n):
        base = HEAP_BASE + len(self.heap) * 0x1000_0000
        self.heap.append((base, bytearray([0xee]) * n))
        return base

    def clobber(self):
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered

    def call(self, ins, nxt):
        r, role = self.r, self.f.role[ins.va]
        throws = len(self.calls) in self.case.get('throws', ())
        saved = (bytes(self.out), bytes(self.stack))
        try:
            rec, ret = self.stub(role, r)
        except (IndexError, TypeError, ValueError, struct.error) as e:
            raise Fault(f'callee contract violated by {role}: {e}')
        if throws:  # a callee that unwinds leaves no result behind
            self.out[:], self.stack[:] = saved
        self.calls.append(rec + ('!',) if throws else rec)
        if throws:
            site = self.f.site_of(ins.va) if self.f.lsda else ('none',)
            if site is None:
                raise Stop('no_call_site')
            if site[0] in (0, 'none'):
                raise Stop('escape')
            self.clobber()
            r[0], r[2] = EXC, site[1]
            return site[0]
        if role in ('alloc_error', 'terminate'):
            raise Stop(role)
        if role == 'resume':
            if r[7] != EXC:
                raise Fault('_Unwind_Resume is not given the exception object')
            raise Stop('resume')
        self.clobber()
        if ret is not None:
            r[0] = ret
        return None

    def stub(self, role, r):
        c, w = self.case, self.where
        if role == 'alloc':
            if not c.get('alloc_ok', True):
                return ('alloc', r[7]), 0
            return ('alloc', r[7]), self.new_block(r[7])
        if role == 'alloc_error':
            return ('alloc_error', r[7], r[6]), None
        if role == 'key_read' or (role == 'ident' and self.f.form == 'seq'):
            self.cur = self.events.pop(0) if self.events else ('end',)
        ev = self.cur
        if role == 'key_read':
            rec = ('key_read', w(r[6]), w(r[2]), r[1], r[8] & 0xffffffff)
            if ev[0] == 'kerr':
                body = struct.pack('<IIQ', 1, 0, 0)[:8] + ev[1]
            elif ev[0] == 'content':
                body = struct.pack('<II', c['ok_word'], 0) + ev[1]
            else:
                tag = KEY_TAG if ev[0] == 'tag' else KEY_END
                body = struct.pack('<II', c['ok_word'], 0) + bytes([tag]) + pattern('key', tag, n=31)
            self.store(r[7], body)
            return rec, None
        if role == 'value_read':
            ok, val = ev[2]
            self.store(r[7], struct.pack('<II', 0 if ok else 1, 0) + val)
            return ('value_read', w(r[6])), None
        if role == 'ident':
            res = ev[1] if self.f.form == 'map' else ev[0]
            body = bytes([IDENT_OK, res[1]]) + pattern('ident', res[1], n=30) if res[0] else res[1]
            self.store(r[7], body)
            return ('ident', w(r[6]), r[2] & 0xffffffff), None
        if role == 'rest_read':
            ok, val = ev[1]
            self.store(r[7], bytes([ok]) + bytes(7) + val)
            return ('rest_read', w(r[6])), None
        if role == 'fmt_error':
            argp = int.from_bytes(self.load(r[2], 8), 'little')
            fn = int.from_bytes(self.load(r[2] + 8, 8), 'little')
            sp, sl = struct.unpack('<QQ', self.load(argp, 16))
            self.store(r[7], pattern('fmt', r[6], n=32))
            return ('fmt_error', '%x' % r[6], '%x' % fn, w(sp), sl), None
        if role == 'grow':
            cap, ptr, ln = struct.unpack('<QQQ', self.load(r[7], 24))
            new = max(2 * cap, 4)
            base = self.new_block(new * PAIR)
            self.store(base, self.load(ptr, ln * PAIR))
            self.store(r[7], struct.pack('<QQ', new, base))
            return ('grow', cap, w(ptr), ln), None
        if role == 'drop_pairs':
            cap, ptr, ln = struct.unpack('<QQQ', self.load(r[7], 24))
            return ('drop_pairs', cap, w(ptr), ln, h16(self.load(ptr, ln * PAIR)) if ln else ''), None
        if role in ('drop_content', 'drop_key'):
            return (role, self.load(r[7], 32).hex()), None
        if role in ('drop_result', 'drop_pair'):
            return (role, w(r[7]), h16(self.load(r[7], PAIR))), None
        if role == 'dealloc':
            return ('dealloc', w(r[7]), r[6], r[2] & MASK64), None
        if role in ('terminate', 'resume'):
            return (role,), None
        raise Fault(f'no stub for {role}')


# reconstruction ------------------------------------------------------------------
class Model:
    """Pure reconstruction of the two visitors; `variant` names a deliberately wrong model."""

    def __init__(self, case, form, display, variant=None):
        self.c, self.form, self.v, self.display = case, form, variant, display
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.calls, self.acc8 = [], case['n']
        self.blocks = 0

    def call(self, *rec):
        throws = len(self.calls) in self.c.get('throws', ())
        self.calls.append(rec + ('!',) if throws else rec)
        return throws

    def done(self, kind, pairs=''):
        return (kind, self.out.hex(), tuple(self.calls), self.acc8, pairs)

    def err(self, body):
        self.out[0:8] = (1).to_bytes(8, 'little')
        self.out[8:40] = body

    def unwind(self, pad, vec, extra=None):
        """Landing pads of visit_map: drop the live locals, then resume."""
        if pad == 'none':
            return self.done('escape')
        if pad == 'key':
            if self.call('drop_key', extra.hex()):
                self.call('terminate')
                return self.done('terminate')
        if pad == 'pair':
            if self.call('drop_result', 'sp+50', h16(extra)):
                self.call('terminate')
                return self.done('terminate')
        if self.v != 'pad_skips_vec':
            if self.call('drop_pairs', vec['cap'], vec['name'], len(vec['pairs']), vec['h']()):
                self.call('terminate')
                return self.done('terminate')
        if self.call('resume'):
            return self.done('escape')
        return self.done('resume')

    def drop_inline(self, vec, kind='ret'):
        """Error exit of visit_map: drop each pair in place, then free the buffer."""
        ps = vec['pairs']
        if self.v != 'err_keeps_pairs':
            for i, (k, v) in enumerate(ps):
                if self.call('drop_content', k.hex()):
                    if self.call('drop_content', v.hex()):
                        self.call('terminate')
                        return self.done('terminate')
                    return self.drop_rest(vec, i)
                if self.call('drop_content', v.hex()):
                    return self.drop_rest(vec, i)
        if vec['cap']:
            if self.call('dealloc', vec['name'], vec['cap'] * PAIR, 0):
                return self.done('escape')
        return self.done(kind)

    def drop_rest(self, vec, i):
        for j in range(i + 1, len(vec['pairs'])):
            if self.call('drop_pair', '%s+%x' % (vec['block'], j * PAIR), h16(b''.join(vec['pairs'][j]))):
                self.call('terminate')
                return self.done('terminate')
        if vec['cap']:
            if self.call('dealloc', vec['name'], vec['cap'] * PAIR, 0):
                return self.done('escape')
        if self.call('resume'):
            return self.done('escape')
        return self.done('resume')

    def missing(self, vec=None):
        name = self.c['name_len']
        if self.call('fmt_error', '%x' % MISSING_FIELD, '%x' % self.display, 'name', name):
            if self.form == 'seq':
                return self.done('escape')
            return self.unwind('vec', vec)
        self.err(pattern('fmt', MISSING_FIELD, n=32))
        if self.form == 'seq':
            return self.done('ret')
        if self.call('drop_pairs', vec['cap'], vec['name'], len(vec['pairs']), vec['h']()):
            return self.done('escape')
        return self.done('ret')

    # visit_seq --------------------------------------------------------------
    def visit_seq(self):
        n, evs = self.c['n'], list(self.c['events'])
        if n == 0:
            return self.missing()
        self.acc8 = n - 1
        ev = evs.pop(0)
        if self.call('ident', 'des', 1):
            return self.done('escape')
        res = ev[0]
        if not res[0]:
            self.err(res[1])
            return self.done('ret')
        idx = res[1]
        if idx == NO_TAG and self.v != 'seq_none_is_variant':
            return self.missing()
        if self.call('rest_read', 'acc'):
            return self.done('escape')
        flag, val = ev[1]
        if flag:
            self.err(val)
            return self.done('ret')
        self.out[0:8] = bytes(8)
        self.out[8] = idx
        self.out[9:16] = bytes([0 if self.v == 'pad_zero' else STACK_FILL]) * 7
        self.out[16:48] = val
        return self.done('ret')

    # visit_map --------------------------------------------------------------
    def visit_map(self):
        c = self.c
        n, evs = c['n'], list(c['events'])
        limit = 0x8000 if self.v == 'cap_8000' else CAUTIOUS_CAP
        vec = {'cap': 0, 'name': 'v:8', 'block': None, 'pairs': []}
        vec['h'] = lambda: h16(b''.join(a + b for a, b in vec['pairs'])) if vec['pairs'] else ''
        if n == 0 and self.v != 'empty_reads':
            return self.missing(vec)
        cap = min(n, limit)
        if self.call('alloc', cap * PAIR):
            return self.done('no_call_site')
        if not c.get('alloc_ok', True):
            if self.call('alloc_error', 8, cap * PAIR):
                return self.done('escape')
            return self.done('alloc_error')
        vec.update(cap=cap, name='h0+0', block='h0')
        self.blocks = 1
        tag = NO_TAG
        remaining = n - 1
        while True:
            if self.v != 'no_writeback':
                self.acc8 = remaining & 0xffffffff
            ev = evs.pop(0) if evs else ('end',)
            if self.call('key_read', 'des', 'name', c['name_len'], 1):
                return self.unwind('vec', vec)
            if ev[0] == 'kerr':
                self.err(ev[1])
                return self.drop_inline(vec)
            if ev[0] == 'end':
                break
            if ev[0] == 'tag':
                if tag != NO_TAG and self.v != 'dup_allowed':
                    if self.call('fmt_error', '%x' % DUPLICATE_FIELD, '%x' % self.display, 'name', c['name_len']):
                        return self.unwind('vec', vec)
                    self.err(pattern('fmt', DUPLICATE_FIELD, n=32))
                    return self.drop_inline(vec)
                if self.call('ident', 'des', 1):
                    return self.unwind('vec', vec)
                res = ev[1]
                if not res[0]:
                    self.err(res[1])
                    return self.drop_inline(vec)
                tag = res[1]
            else:
                key, (ok, val) = ev[1], ev[2]
                if self.call('value_read', 'des'):
                    return self.unwind('key', vec, key)
                if not ok:
                    self.err(val)
                    if self.v != 'value_err_keeps_key':
                        if self.call('drop_key', key.hex()):
                            return self.unwind('vec', vec)
                    return self.drop_inline(vec)
                if len(vec['pairs']) == vec['cap']:
                    if self.call('grow', vec['cap'], vec['name'], len(vec['pairs'])):
                        return self.unwind('pair', vec, key + val)
                    vec['cap'] = max(2 * vec['cap'], 4)
                    vec['block'] = 'h%d' % self.blocks
                    vec['name'] = vec['block'] + '+0'
                    self.blocks += 1
                vec['pairs'].append((key, val))
            if remaining == 0:
                break
            remaining -= 1
        if tag == NO_TAG:
            return self.missing(vec)
        self.out[0:8] = bytes(8)
        self.out[8] = tag
        self.out[16] = CONTENT_MAP
        self.out[17:24] = bytes([0 if self.v == 'pad_zero' else STACK_FILL]) * 7
        self.out[24:48] = struct.pack('<QQQ', vec['cap'], HEAP_BASE + (self.blocks - 1) * 0x1000_0000,
                                      len(vec['pairs']))
        return self.done('ret', vec['h']())


def reconstructed(case, form, variant=None, display=FUNCS[0][4]):
    m = Model(case, form, display, variant)
    return m.visit_map() if form == 'map' else m.visit_seq()


# cases ---------------------------------------------------------------------------
import random  # noqa: E402

KEY_HEADS = tuple(range(0x16)) + (0x18, 0x1f, 0x80, 0xff)
IDX = (0, 1, 2, 45, 90, 91, NO_TAG)
NS = (1, 2, 3, 4, 5, 6, 8, CAUTIOUS_CAP, CAUTIOUS_CAP + 1, 0x80000000, 0xffffffff)
MODEL_VARIANTS = ('cap_8000', 'no_writeback', 'dup_allowed', 'empty_reads', 'err_keeps_pairs',
                  'value_err_keeps_key', 'pad_skips_vec', 'seq_none_is_variant', 'pad_zero')


def blob(rng, head=None, n=32):
    b = bytes(rng.randrange(256) for _ in range(n))
    return b if head is None else bytes([head]) + b[1:]


def err_blob(rng):
    return blob(rng, rng.choice([0, 1, 2, 8, 10, 0x7f, 0xff]))


def map_event(rng):
    k = rng.randrange(10)
    if k < 5:
        ok = rng.randrange(5) != 0
        return ('content', blob(rng, rng.choice(KEY_HEADS)), (ok, blob(rng) if ok else err_blob(rng)))
    if k < 8:
        return ('tag', (True, rng.choice(IDX)) if rng.randrange(5) else (False, err_blob(rng)))
    return ('kerr', err_blob(rng)) if k == 8 else ('end',)


def base_cases():
    rng = random.Random('re010-tagged-content-115')
    out = []
    for i in range(1100):
        evs = [map_event(rng) for _ in range(rng.randrange(7))]
        if rng.randrange(3):
            evs.insert(rng.randrange(len(evs) + 1), ('tag', (True, rng.choice(IDX[:-1]))))
        out.append(dict(form='map', n=0 if i % 50 == 0 else rng.choice(NS), events=tuple(evs),
                        name_len=rng.choice((4, 4, 0, 9)), ok_word=rng.choice((0, 0, 2)),
                        alloc_ok=i % 61 != 7))
    for i in range(240):
        evs = []
        for _ in range(2):
            ident = (True, rng.choice(IDX + (0x5d, 0xff))) if rng.randrange(4) else (False, err_blob(rng))
            evs.append((ident, (rng.choice((0, 0, 0, 1, 0x80, 0xff)), blob(rng))))
        out.append(dict(form='seq', n=rng.choice((0, 1, 1, 2, 7, 0xffffffff)), events=tuple(evs),
                        name_len=rng.choice((4, 0, 9)), ok_word=0))
    return out


def throw_cases(base):
    """Exceptions raised by every callee ordinal of a subset of runs, and second exceptions in the pads."""
    out = []
    for c in base[::6]:
        calls = reconstructed(c, c['form'])[2]
        for k, rec in enumerate(calls):
            if rec[0] in ('terminate', 'resume'):
                continue
            t = dict(c, throws=(k,))
            out.append(t)
            after = reconstructed(t, t['form'])[2]
            seconds = [j for j in range(k + 1, len(after)) if after[j][0] not in ('terminate',)]
            for j in seconds[:2]:
                out.append(dict(c, throws=(k, j)))
    return out


def huge_cases():
    """Over 16384 buffered pairs: the cautious capacity is exhausted and the vec grows once."""
    rng = random.Random('re010-tagged-content-115-huge')
    evs = [('tag', (True, 7))] + [('content', blob(rng, 0x0c), (True, blob(rng))) for _ in range(CAUTIOUS_CAP + 1)]
    c = dict(form='map', n=CAUTIOUS_CAP + 2, events=tuple(evs), name_len=4, ok_word=0, steps=2000000)
    k = [i for i, r in enumerate(reconstructed(c, 'map')[2]) if r[0] == 'grow'][0]
    return [c, dict(c, throws=(k,)), dict(c, throws=(k, k + 1))]


def all_cases(huge=True):
    base = base_cases()
    cs = base + throw_cases(base) + (huge_cases() if huge else [])
    for i, c in enumerate(cs):
        c['id'] = i
    return cs


def compare(img, fn, cases, variant=None):
    m = Machine(img, fn)
    bad, edges, insns = [], set(), set()
    for c in cases:
        if c['form'] != fn.form:
            continue
        try:
            got = m.run(c)
        except Fault as e:
            got = ('fault', str(e))
        if got != reconstructed(c, fn.form, variant, fn.display):
            bad.append(c['id'])
            if variant is not None:
                return bad, edges, insns
        edges |= m.edges
        insns |= set(m.trace)
    return bad, edges, insns


def image_sites(fn):
    """Byte mutants: one immediate bit of every immediate operand and the condition of every jcc."""
    sites = []
    for i in fn.insns:
        if i.op == 'j':
            k = 0 if i.raw[0] in range(0x70, 0x80) else len(i.raw) - 5
            sites.append((i.va + k, 0x01, f'jcc {i.va:#x}'))
        elif i.immlen and i.op not in ('call', 'jmp') and i.b is not None and isinstance(i.b, tuple) and i.b[0] == 'i':
            v = i.b[1]
            bit = 0x100 if v >= 0x100 and i.immlen >= 2 and v & 0xffff not in (0xffff,) else 0x01
            k = i.size - i.immlen + (1 if bit == 0x100 else 0)
            sites.append((i.va + k, 0x01, f'imm {i.op} {i.va:#x} {v:#x}'))
    return sites


def run_image_mutant(data, img, fn, site, cases):
    va, x, _ = site
    o = img.off(va)
    mut = bytearray(data)
    mut[o] ^= x
    try:
        mimg = Image(bytes(mut), check=False)
        mfn = Fn(mimg, (fn.form, fn.start, fn.end - fn.start, fn.frame, fn.display))
    except Fault:
        return 'rejected_static'
    m = Machine(mimg, mfn)
    for c in cases:
        if c['form'] != fn.form:
            continue
        try:
            got = m.run(c)
        except Fault:
            return 'rejected_fault'
        if got != reconstructed(c, fn.form, None, fn.display):
            return 'killed'
    return 'survived'


def hx(v):
    return '%x' % v


def generate(out_dir, data=None, huge=True):
    data = BINARY.read_bytes() if data is None else data
    img = Image(data)
    fns, anchors = [], {}
    for row in FUNCS:
        f = Fn(img, row, anchors.get(row[0]))
        anchors.setdefault(row[0], f)
        fns.append(f)
    cases = all_cases(huge)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = {'binary_sha256': SHA256, 'functions': [], 'cases': len(cases)}
    rows = ['copy\tform\tstart\tend\tbytes\tinsns\tlsda\tcall_sites\troles']
    cov = ['copy\tinsn_va\tbytes\tcovered']
    total_bad = 0
    per = {}
    for f in fns:
        bad, edges, insns = compare(img, f, cases)
        total_bad += len(bad)
        js = [i.va for i in f.insns if i.op == 'j']
        both = sum(1 for j in js if (j, True) in edges and (j, False) in edges)
        per[f.start] = dict(form=f.form, mismatches=len(bad), insns=len(f.insns),
                            insns_covered=len(insns), jcc=len(js), jcc_both_ways=both)
        roles = ','.join('%s=%x' % (k, v) for k, v in sorted(f.targets.items()))
        rows.append('\t'.join([hx(f.start), f.form, hx(f.start), hx(f.end), str(f.end - f.start), str(len(f.insns)),
                               hx(f.lsda), str(len(f.sites)), roles]))
        if True:
            for i in f.insns:
                cov.append('\t'.join([hx(f.start), hx(i.va), i.raw.hex(), 'yes' if i.va in insns else 'no']))
    summary['functions'] = [dict(start=hx(k), **v) for k, v in per.items()]
    summary['mismatches'] = total_bad
    # call-site table of the anchor map copy
    sites = ['copy\tstart\tend\tlanding_pad\taction']
    for f in fns:
        for s, e, lp, a in f.sites:
            sites.append('\t'.join([hx(f.start), hx(s), hx(e), hx(lp) if lp else '-', str(a)]))
    # case outcomes (anchor copies; every copy is compared above)
    cl = ['case\tform\tn\tname_len\tok_word\talloc_ok\tthrows\tevents\toutcome\tout_hex\tcalls\tacc_count\tpairs']
    for c in cases:
        r = reconstructed(c, c['form'])
        ev = ' '.join(e[0] if c['form'] == 'map' else ('i%x' % e[0][1] if e[0][0] else 'ierr') + '/r%x' % e[1][0]
                      for e in c['events'])
        if len(ev) > 120:
            ev = ev[:60] + f'..({len(c["events"])} events)'
        calls = ' '.join(x[0] + ('!' if x[-1] == '!' else '') for x in r[2])
        if len(calls) > 200:
            calls = calls[:100] + f'..({len(r[2])} calls, {h16(repr(r[2]).encode())})'
        cl.append('\t'.join([str(c['id']), c['form'], hx(c['n']), str(c['name_len']), str(c['ok_word']),
                             str(int(c.get('alloc_ok', True))), ','.join(map(str, c.get('throws', ()))) or '-',
                             ev or '-', r[0], r[1], calls or '-', hx(r[3]), r[4] or '-']))
    # wrong reconstructions
    mt = ['kind\tname\tresult']
    small = [c for c in cases if c.get('steps') is None]
    killed = 0
    for v in MODEL_VARIANTS:
        hits = []
        for f in (anchors['map'], anchors['seq']):
            b, _, _ = compare(img, f, small, v)
            hits += b
        res = 'killed' if hits else 'survived'
        killed += res == 'killed'
        mt.append(f'model\t{v}\t{res}')
    summary['model_mutants'] = [killed, len(MODEL_VARIANTS)]
    ik, total = {}, 0
    for f in (anchors['map'], anchors['seq']):
        for site in image_sites(f):
            res = run_image_mutant(data, img, f, site, small)
            ik[res] = ik.get(res, 0) + 1
            total += 1
            mt.append(f'image\t{f.form} {site[2]} byte {site[0]:#x} xor {site[1]:#x}\t{res}')
    summary['image_mutants'] = dict(sorted(ik.items()), total=total)
    files = {
        'functions.tsv': rows, 'call_sites.tsv': sites, 'cases.tsv': cl,
        'coverage.tsv': cov, 'mutants.tsv': mt,
    }
    for name, lines in files.items():
        (out / name).write_text('\n'.join(lines) + '\n')
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    s = generate(a.out)
    print(json.dumps(s, sort_keys=True))
    bad = s['mismatches'] or s['model_mutants'][0] != s['model_mutants'][1] or s['image_mutants'].get('survived')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
