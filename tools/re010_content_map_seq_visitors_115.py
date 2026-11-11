#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack Content map / seq visitors and prove them.

serde's `ContentVisitor` collects a self-describing value into `Content`.  For
rmp_serde map and array markers the TagOrContent key reader (0x1a7e1a0 /
0x30fb4f0 / 0x48cd3a0, calls at +0x13f and +0x203) hands a `MapAccess` /
`SeqAccess { de, left: u32 }` to one visitor body per deserializer copy:

  visit_map  0x21e0380  0x3b68660  0x57af090   (1191 B, Vec<(Content, Content)>)
  visit_seq  0x21e1c10  0x3b69610  0x57af540   (666 B,  Vec<Content>)

Each body clamps the size hint (0x4000 pairs / 0x8000 items, so the first
allocation is at most 1 MiB), allocates, then for `left` rounds writes the
decremented count back into the access, reads one element (two for a map)
through the generic value reader, stops early on the Option::None niche
(tag 0x16), grows the vector when full and pushes.  An Err from the reader
(map: also the Result::Err niche tag 0x17 in the key slot) drops what was
collected, frees the buffer and is returned; the Ok value is Content::Map
(0x15) or Content::Seq (0x14) with (cap, ptr, len).

This tool:
1. checks the input digest, finds each copy's FDE extent and LSDA, decodes every
   instruction with a fixed-pattern x86-64 subset decoder, binds every call site
   to a role by its offset (copies must share the anchor layout byte for byte
   outside call targets) and checks the key reader copies call each body;
2. interprets the original bytes (the binary is never run) with contract stubs
   for the callees (value reader, allocator, RawVec grow, drops, free);
3. compares every outcome with a pure reconstruction (`reconstructed` below):
   result bytes, the callee sequence with semantic arguments, the access state
   written back and every heap block;
4. lets every callee call unwind (and a second unwind inside the landing pad),
   so the LSDA picks each cleanup pad, and proves instruction and branch
   coverage and that wrong reconstructions and corrupted images are rejected.
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

KEY_READERS = (0x1a7e1a0, 0x30fb4f0, 0x48cd3a0)   # TagOrContent key reader copies (the callers)
KINDS = {
    'map': {'funcs': (0x21e0380, 0x3b68660, 0x57af090), 'size': 1191, 'frame': 0x168, 'elem': 64,
            'clamp': 0x4000, 'ok_tag': 0x15, 'caller_call': 0x13f},
    'seq': {'funcs': (0x21e1c10, 0x3b69610, 0x57af540), 'size': 666, 'frame': 0x98, 'elem': 32,
            'clamp': 0x8000, 'ok_tag': 0x14, 'caller_call': 0x203},
}
# anchor-copy call targets -> role; other copies bind roles by call offset
ANCHOR_DIRECT = {0x17fb290: 'read', 0x21d8eb0: 'drop_content', 0x230ce30: 'drop_elem', 0x21d6020: 'drop_entry',
                 0x21d66b0: 'drop_vec', 0x21dbd40: 'drop_vec', 0x22faae0: 'drop_pair'}
GOT_ROLES = {0x64df480: 'alloc', 0x64df498: 'alloc_error', 0x64df4a0: 'free', 0x64e13b8: 'grow',
             0x64e13c0: 'grow', 0x64df4c0: 'terminate'}
RESUME_SYMBOL = '_Unwind_Resume'

NONE_TAG, ERR_NICHE = 0x16, 0x17   # Option<Content>::None and Result<(K, V)>::Err niches
DANGLING = 8                       # NonNull::dangling() for align 8

OUT_BASE, ACC_BASE, DES_BASE = 0x7100_0000_0000, 0x7180_0000_0000, 0x7190_0000_0000
HEAP_BASE = 0x7400_0000_0000
STACK_TOP = 0x7200_0000_0000
MASK64 = (1 << 64) - 1
OUT_FILL, STACK_FILL, ACC_FILL, HEAP_FILL = 0xaa, 0x5c, 0x3d, 0xee
OUT_SIZE, ACC_SIZE, DES_SIZE = 0x28, 0x10, 0x10
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
    """Decode one instruction of the fixed subset used by the visitor copies."""
    b = img.read(va, 16)
    p, opsz, rep, rex = 0, None, False, 0
    while b[p] in (0x66, 0xf3, 0x2e):  # 0x2e only pads multi-byte nops
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
    elif op == 0x90:
        ins.op = 'nop'
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



def lea_target(ins):
    return ins.va + ins.size + ins.b[4]



class Fn:
    """Static facts of one visitor copy, all read from the bytes."""

    def __init__(self, img, kind, start, anchor=None):
        k = KINDS[kind]
        self.kind, self.start = kind, start
        fde = fde_of(img.data, start)
        self.end = fde['end']
        if self.end - start != k['size']:
            raise Fault(f'{start:#x}: FDE extent is {self.end - start} bytes')
        self.lsda = fde.get('lsda') or 0
        if not self.lsda:
            raise Fault(f'{start:#x}: no LSDA')
        self.sites = img.call_sites(self.lsda, start)
        self.insns = sweep(img, start, self.end)
        self.cache = {i.va: i for i in self.insns}
        subs = [i for i in self.insns if i.op == 'sub' and i.a == ('r', 4) and i.b[0] == 'i']
        if not subs or subs[0].b[1] != k['frame']:
            raise Fault(f'{start:#x}: frame size is not {k["frame"]:#x}')
        self.role, self.targets = {}, {}
        for i in self.insns:
            if i.op == 'lea' and i.b[0] == 'm' and i.b[5]:
                raise Fault(f'{i.va:#x}: unexpected rip-relative lea')
            if i.op not in ('call', 'callr'):
                continue
            o = i.va - start
            if i.op == 'callr':
                if i.a[0] != 'm' or not i.a[5]:
                    raise Fault(f'{i.va:#x}: indirect call is not through a GOT slot')
                t = i.va + i.size + i.a[4]
                if anchor is None:
                    if t not in GOT_ROLES:
                        raise Fault(f'{i.va:#x}: GOT slot {t:#x} has no role')
                    role = GOT_ROLES[t]
                else:
                    role = anchor.role.get(anchor.start + o)
            else:
                t = i.va + i.size + i.b
                if img.read(t, 2) == b'\xff\x25' and img.plt_symbol(t) == RESUME_SYMBOL:
                    role = 'resume'
                elif anchor is None:
                    if t not in ANCHOR_DIRECT:
                        raise Fault(f'{i.va:#x}: direct call target {t:#x} has no role')
                    role = ANCHOR_DIRECT[t]
                else:
                    role = anchor.role.get(anchor.start + o)
            if role is None:
                raise Fault(f'{i.va:#x}: call offset +{o:#x} is not a call in the anchor copy')
            if self.targets.setdefault(role, t) != t:
                raise Fault(f'{start:#x}: role {role} has two targets')
            self.role[i.va] = role
        if anchor is not None:
            same = [a.raw == b.raw for a, b in zip(anchor.insns, self.insns) if a.op not in ('call', 'callr')]
            if len(anchor.insns) != len(self.insns) or not all(same):
                raise Fault(f'{start:#x}: not a layout copy of {anchor.start:#x}')
            if {self.start + va - anchor.start: r for va, r in anchor.role.items()} != self.role:
                raise Fault(f'{start:#x}: call roles differ from the anchor copy')
            if self.sites != [(s - anchor.start + start, e - anchor.start + start,
                               lp - anchor.start + start if lp else 0, a) for s, e, lp, a in anchor.sites]:
                raise Fault(f'{start:#x}: call-site table differs from the anchor copy')

    def site_of(self, call_va):
        for s, e, lp, a in self.sites:
            if s <= call_va < e:
                return lp, a
        return None


class Stop(Exception):
    pass


def read_bytes(ordinal, ev):
    """The value reader stub's 0x28-byte result for one scripted event (int tag or 'E')."""
    head = struct.pack('<I', 1 if ev == 'E' else 0) + pattern('pad', ordinal, n=4)
    if ev == 'E':
        return head + pattern('err', ordinal, n=32)
    return head + bytes([ev]) + pattern('content', ordinal, n=31)


class Machine:
    def __init__(self, img, fn):
        self.img, self.f = img, fn
        self.elem = KINDS[fn.kind]['elem']

    def run(self, case):
        self.case = case
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.acc = bytearray(struct.pack('<QI', DES_BASE, case['left'])) + bytearray([ACC_FILL]) * 4
        self.des = bytearray([ACC_FILL]) * DES_SIZE
        self.stack = bytearray([STACK_FILL]) * 0x200
        self.heap = []
        self.nread = 0
        self.calls, self.trace, self.edges = [], [], set()
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6] = OUT_BASE, ACC_BASE
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.frame_lo = None
        pc = self.f.start
        try:
            for _ in range(4000 + 120 * len(case['reads'])):
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
        return (kind, self.out.hex(), tuple(self.calls), self.acc.hex(),
                tuple(h16(buf) for _, buf in self.heap))

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
        for base, buf in [(OUT_BASE, self.out), (ACC_BASE, self.acc), (DES_BASE, self.des),
                          (STACK_TOP - len(self.stack), self.stack)] + self.heap:
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
        if buf is None or buf is self.des:
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
            self.put(ins.a, w, v << n, nxt)
            self.flags['c'] = self.flags['o'] = None  # shift flags are never read here
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
        elif op == 'ud2':
            raise Stop('ud2')
        elif op == 'nop':
            pass
        else:
            raise Fault(f'no semantics for {op} at {ins.va:#x}')
        return None

    def where(self, a):
        """Name a pointer: out, access, deserializer, frame slot, heap block or value."""
        if a == ACC_BASE:
            return 'acc'
        if a == DES_BASE:
            return 'des'
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
        self.heap.append((base, bytearray([HEAP_FILL]) * n))
        return base

    def clobber(self):
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered

    def call(self, ins, nxt):
        r, role = self.r, self.f.role[ins.va]
        throws = len(self.calls) in self.case.get('throws', ()) or role in UNWINDS
        saved = (bytes(self.out), bytes(self.stack), bytes(self.acc))
        try:
            rec, ret = self.stub(role, r, throws)
        except (IndexError, TypeError, ValueError, KeyError, struct.error) as e:
            raise Fault(f'callee contract violated by {role}: {e}')
        if throws:  # a callee that unwinds leaves no result behind
            self.out[:], self.stack[:], self.acc[:] = saved
        self.calls.append(rec + ('!',) if throws else rec)
        if throws:
            site = self.f.site_of(ins.va)
            if site is None:
                raise Stop('no_call_site')
            if site[0] == 0:
                raise Stop('escape')
            self.clobber()
            r[0], r[2] = EXC, site[1]
            return site[0]
        if role == 'terminate':
            raise Stop(role)
        if role == 'resume':
            if r[7] != EXC:
                raise Fault('_Unwind_Resume is not given the exception object')
            raise Stop('resume')
        self.clobber()
        if ret is not None:
            r[0] = ret
        return None

    def vec_rec(self, a):
        cap, ptr, n = struct.unpack('<QQQ', self.load(a, 24))
        body = self.load(ptr, n * self.elem) if n else b''
        return cap, self.where(ptr), n, h16(body)

    def stub(self, role, r, throws):
        c, w = self.case, self.where
        if role == 'read':
            k = self.nread
            self.nread += 1
            if k >= len(c['reads']):
                raise Fault('value reader called more often than scripted')
            left = struct.unpack_from('<I', self.acc, 8)[0]
            self.store(r[7], read_bytes(k, c['reads'][k]))
            return ('read', w(r[7]), w(r[6]), left), None
        if role == 'alloc':
            if not c.get('alloc_ok', True) or throws:
                return ('alloc', r[7]), 0
            return ('alloc', r[7]), self.new_block(r[7])
        if role == 'alloc_error':
            return ('alloc_error', r[7] & 0xffffffff, r[6]), None
        if role == 'grow':
            cap, ptr, n = struct.unpack('<QQQ', self.load(r[7], 24))
            rec = ('grow', w(r[7]), cap, n)
            if not throws:
                new = max(2 * cap, 4)
                base = self.new_block(new * self.elem)
                self.store(base, self.load(ptr, n * self.elem))
                self.store(r[7], struct.pack('<QQ', new, base))
            return rec, None
        if role == 'free':
            return ('free', w(r[7]), r[6], r[2] & 0xffffffff), None
        if role in ('drop_content', 'drop_elem'):
            return (role, w(r[7]), self.load(r[7], 32).hex()), None
        if role in ('drop_entry', 'drop_pair'):
            return (role, w(r[7]), self.load(r[7], 64).hex()), None
        if role == 'drop_vec':
            return ('drop_vec', w(r[7])) + self.vec_rec(r[7]), None
        if role in ('terminate', 'resume'):
            return (role,), None
        raise Fault(f'no stub for {role}')


# reconstruction ------------------------------------------------------------------
UNWINDS = ('alloc_error',)   # never returns; it unwinds
COMMON_VARIANTS = ('cap_unclamped', 'clamp_half', 'left_after_read', 'no_left_writeback', 'cleanup_reverse',
                   'free_on_ok', 'no_free_on_err', 'ok_tag_swapped', 'pad_zero', 'grow_one_early',
                   'pad_drop_skips_staged', 'unwind_frees_twice', 'empty_ptr_null')
MODEL_VARIANTS = {'map': COMMON_VARIANTS + ('map_value_none_stops', 'map_niche_is_entry', 'map_err_keeps_key'),
                  'seq': COMMON_VARIANTS + ('seq_niche_stops',)}


class Throw(Exception):
    pass


class Model:
    """Pure reconstruction of one visitor; `variant` names a deliberately wrong model."""

    def __init__(self, kind, case, variant=None):
        self.kind, self.c, self.v = kind, case, variant
        self.k = KINDS[kind]
        self.E = self.k['elem']
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.acc = bytearray(struct.pack('<QI', DES_BASE, case['left'])) + bytearray([ACC_FILL]) * 4
        self.calls, self.heap = [], []
        self.nread = 0
        self.throws = set(case.get('throws', ()))

    def call(self, rec, unwinds=False):
        """Record a callee call; raise Throw if this call unwinds."""
        thr = len(self.calls) in self.throws or unwinds
        self.calls.append(rec + ('!',) if thr else rec)
        if thr:
            raise Throw()

    def hname(self, k, off=0):
        return 'h%d+%x' % (k, off)

    # the vector: (cap, block index or None, items)
    def vec_rec(self, at):
        body = b''.join(self.items)
        ptr = self.hname(self.blk) if self.blk is not None else 'v:%x' % DANGLING
        return ('drop_vec', at, self.cap, ptr, len(self.items), h16(body))

    def read(self, buf):
        k = self.nread
        self.nread += 1
        left = struct.unpack_from('<I', self.acc, 8)[0]
        if self.v == 'left_after_read':
            left = (left + 1) & 0xffffffff if k else left
        self.call(('read', buf, 'des', left))
        if k >= len(self.c['reads']):
            raise Stop('overread')   # only a wrong model asks for more reads than scripted
        ev = self.c['reads'][k]
        return read_bytes(k, ev)

    def sync_heap(self):
        if self.blk is not None:
            body = b''.join(self.items)
            self.heap[self.blk][:len(body)] = body

    def drop_vec(self):
        self.sync_heap()
        self.call(self.vec_rec('sp+8'))

    def free(self):
        if self.cap and self.v != 'no_free_on_err':
            try:
                self.call(('free', self.hname(self.blk), self.cap * self.E, 0))
            except Throw:
                raise Stop('escape')   # LSDA range without a landing pad

    def cleanup(self):
        """Err return: drop every collected element in order, then free the buffer."""
        self.sync_heap()
        items = list(enumerate(self.items))
        if self.v == 'cleanup_reverse':
            items.reverse()
        for i, it in items:
            if self.kind == 'map':
                try:
                    self.call(('drop_elem', self.hname(self.blk, i * 64), it[:32].hex()))
                except Throw:
                    self.unwind_tail(i, half=0x20)
                    return
                try:
                    self.call(('drop_elem', self.hname(self.blk, i * 64 + 0x20), it[32:].hex()))
                except Throw:
                    self.unwind_tail(i + 1)
                    return
            else:
                try:
                    self.call(('drop_elem', self.hname(self.blk, i * 32), it.hex()))
                except Throw:
                    self.unwind_tail(i + 1)
                    return
        self.free()

    def unwind_tail(self, i, half=None):
        """Landing pad of a drop in the Err cleanup: drop the rest, free, resume."""
        try:
            if half is not None:
                self.call(('drop_elem', self.hname(self.blk, i * 64 + half), self.items[i][32:].hex()))
                i += 1
            for j in range(i, len(self.items)):
                if self.kind == 'map':
                    self.call(('drop_pair', self.hname(self.blk, j * 64), self.items[j].hex()))
                else:
                    self.call(('drop_elem', self.hname(self.blk, j * 32), self.items[j].hex()))
        except Throw:
            self.call(('terminate',))
            raise Stop('terminate')
        if self.cap:
            try:
                self.call(('free', self.hname(self.blk), self.cap * self.E, 0))
            except Throw:
                raise Stop('escape')
        self.call(('resume',))
        raise Stop('resume')

    def pad(self, *steps):
        """Landing pad: run the drop steps, then _Unwind_Resume; a second unwind terminates."""
        try:
            for s in steps:
                s()
        except Throw:
            self.call(('terminate',))
            raise Stop('terminate')
        self.call(('resume',))
        raise Stop('resume')

    def err(self, payload):
        self.out[0:8] = struct.pack('<Q', 1)
        self.out[8:0x28] = payload

    def run(self):
        try:
            self.body()
            kind = 'ret'
        except Stop as s:
            kind = s.args[0]
        except Throw:
            kind = 'model_unwound'   # only a wrong model lets a scripted unwind escape its pads
        return (kind, self.out.hex(), tuple(self.calls), self.acc.hex(), tuple(h16(b) for b in self.heap))

    def body(self):
        c, v, E = self.c, self.v, self.E
        left = c['left']
        self.cap, self.blk, self.items = 0, None, []
        pad_bytes = bytes([STACK_FILL]) * 7
        if left:
            clamp = self.k['clamp'] // (2 if v == 'clamp_half' else 1)
            self.cap = min(left, 4 * clamp) if v == 'cap_unclamped' else min(left, clamp)
            try:
                self.call(('alloc', self.cap * E))
            except Throw:
                raise Stop('no_call_site')   # the allocation call is outside every LSDA range
            if not c.get('alloc_ok', True):
                try:
                    self.call(('alloc_error', 8, self.cap * E), unwinds=True)
                except Throw:
                    raise Stop('escape')
            self.heap.append(bytearray([HEAP_FILL]) * (self.cap * E))
            self.blk = 0
            n = left - 1
            while True:
                if v != 'no_left_writeback':
                    self.acc[8:12] = struct.pack('<I', n)
                if self.kind == 'map':
                    try:
                        key = self.read('sp+c8')
                    except Throw:
                        self.pad(self.drop_vec)
                    if key[0] == 1:
                        self.err(key[8:0x28])
                        self.cleanup()
                        return
                    if key[8] == NONE_TAG:
                        break
                    try:
                        val = self.read('sp+c8')
                    except Throw:
                        self.pad(lambda: self.call(('drop_content', 'sp+108', key[8:40].hex())), self.drop_vec)
                    if val[0] == 1:
                        if v != 'map_err_keeps_key':
                            try:
                                self.call(('drop_content', 'sp+108', key[8:40].hex()))
                            except Throw:
                                self.pad(self.drop_vec)
                        self.err(val[8:0x28])
                        self.cleanup()
                        return
                    if v == 'map_value_none_stops' and val[8] == NONE_TAG:
                        break
                    pad_bytes = key[17:24] if v != 'pad_zero' else bytes(7)
                    if key[8] == ERR_NICHE and v != 'map_niche_is_entry':
                        self.err(key[16:40] + val[8:16])
                        self.cleanup()
                        return
                    item = key[8:40] + val[8:40]
                else:
                    try:
                        res = self.read('sp+28')
                    except Throw:
                        self.pad(self.drop_vec)
                    if res[0] != 0:
                        self.err(res[8:0x28])
                        self.cleanup()
                        return
                    pad_bytes = res[0:7] if v != 'pad_zero' else bytes(7)
                    if res[8] == NONE_TAG or (v == 'seq_niche_stops' and res[8] == ERR_NICHE):
                        break
                    item = res[8:40]
                full = len(self.items) == self.cap or (v == 'grow_one_early' and len(self.items) + 1 == self.cap)
                if full:
                    try:
                        self.call(('grow', 'sp+8', self.cap, len(self.items)))
                    except Throw:
                        staged = ('drop_entry', 'sp+128', item.hex()) if self.kind == 'map' else \
                                 ('drop_content', 'sp+78', item.hex())
                        steps = [self.drop_vec] if v == 'pad_drop_skips_staged' else \
                            [lambda: self.call(staged), self.drop_vec]
                        if v == 'unwind_frees_twice':
                            steps.append(lambda: self.call(('free', self.hname(self.blk), self.cap * E, 0)))
                        self.pad(*steps)
                    self.sync_heap()
                    new = max(2 * self.cap, 4)
                    self.heap.append(bytearray([HEAP_FILL]) * (new * E))
                    self.blk, self.cap = len(self.heap) - 1, new
                at = len(self.items) * E
                self.heap[self.blk][at:at + E] = item   # the push writes straight into the buffer
                self.items.append(item)
                if n == 0:
                    break
                n -= 1
            self.sync_heap()
        self.out[0:8] = bytes(8)
        tag = self.k['ok_tag'] ^ (1 if v == 'ok_tag_swapped' else 0)
        self.out[8] = tag
        self.out[9:16] = pad_bytes
        ptr = HEAP_BASE + self.blk * 0x1000_0000 if self.blk is not None else (0 if v == 'empty_ptr_null' else DANGLING)
        self.out[16:40] = struct.pack('<QQQ', self.cap, ptr, len(self.items))
        if v == 'free_on_ok' and self.cap:
            self.call(('free', self.hname(self.blk), self.cap * E, 0))


def reconstructed(kind, case, variant=None):
    return Model(kind, case, variant).run()


# cases ---------------------------------------------------------------------------
MAP_KEYS_GO, MAP_VALS_GO = (0x00, 0x0c, 0x15), (0x05, 0x16, 0x17)
SEQ_GO = (0x00, 0x0c, 0x14, 0x15, 0x17)


def map_entries(depth):
    """Every read script of `depth` map entries: (events, finished) pairs."""
    stops = [('E',), (NONE_TAG,)] + [(ERR_NICHE, v) for v in ('E', 0x05, 0x16, ERR_NICHE)] + \
            [(k, 'E') for k in MAP_KEYS_GO]
    go = [(k, v) for k in MAP_KEYS_GO for v in MAP_VALS_GO]
    if depth == 1:
        return [(s, True) for s in stops] + [(g, False) for g in go]
    out = [(s, True) for s in stops]
    for g in go:
        for rest, fin in map_entries(depth - 1):
            out.append((g + rest, fin))
    return out


def seq_entries(depth):
    stops = [('E',), (NONE_TAG,)]
    if depth == 1:
        return [(s, True) for s in stops] + [((g,), False) for g in SEQ_GO]
    out = [(s, True) for s in stops]
    for g in SEQ_GO:
        for rest, fin in seq_entries(depth - 1):
            out.append(((g,) + rest, fin))
    return out


def case(left, reads, **kw):
    d = {'left': left, 'reads': tuple(reads)}
    d.update(kw)
    return d


def base_cases(kind, huge=True):
    out = [case(0, ()), case(1, (), alloc_ok=False), case(0x5000, (), alloc_ok=False)]
    entries = map_entries if kind == 'map' else seq_entries
    full = 2 if kind == 'map' else 3
    for left in range(1, full + 1):
        for ev, _ in entries(left):
            out.append(case(left, ev))
    go = (0x00, 0x05) if kind == 'map' else (0x0c,)
    for left in (full + 1, full + 2, 7):
        for k in range(left + 1):
            ev = go * k
            if k < left:
                ev += ('E',) if k % 2 else (NONE_TAG,)
            out.append(case(left, ev))
    clamp = KINDS[kind]['clamp']
    for left in (clamp - 1, clamp, clamp + 1, 0x3000, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff):
        out.append(case(left, (NONE_TAG,)))
        out.append(case(left, ('E',)))
        out.append(case(left, go + (NONE_TAG,)))
    if huge:
        out.extend(huge_cases(kind))
    return out


def huge_cases(kind):
    """The only inputs that reach RawVec::grow: more than `clamp` elements."""
    clamp = KINDS[kind]['clamp']
    go = (0x00, 0x05) if kind == 'map' else (0x0c,)
    per = len(go)
    n = clamp + 1
    rows = [case(n, go * n), case(n + 1, go * n + (NONE_TAG,)), case(n + 1, go * n + ('E',))]
    reads = clamp * per   # the grow call follows the (clamp+1)-th element's reads and allocation
    rows.append(case(n, go * n, throws=(1 + reads + per,)))
    rows.append(case(n, go * n, throws=(1 + reads + per, 1 + reads + per + 1)))
    return rows


def throw_cases(img, fn, base):
    """For each base case, let every callee call unwind once, and once more inside its pad."""
    out = []
    m = Machine(img, fn)
    for c in base:
        if c['left'] > 64 and len(c['reads']) > 64:
            continue
        calls = m.run(c)[2]
        for k, rec in enumerate(calls):
            if rec[0] in ('terminate', 'resume') or rec[-1] == '!':
                continue
            d = dict(c)
            d['throws'] = (k,)
            out.append(d)
            r2 = m.run(d)[2]
            for j in range(k + 1, len(r2)):
                if r2[j][0] not in ('terminate', 'resume'):
                    e = dict(c)
                    e['throws'] = (k, j)
                    out.append(e)
    return out


def all_cases(img, fn, huge=True):
    base = base_cases(fn.kind, huge)
    seen, out = set(), []
    for c in base + throw_cases(img, fn, base):
        key = repr(sorted(c.items()))
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def compare(img, fn, cases, variant=None, gots=None):
    """Indices of cases where the bytes and the reconstruction disagree, plus coverage.

    `gots` collects the byte outcomes (or replays them when it already holds them)."""
    m = Machine(img, fn)
    bad, insns, edges = [], set(), set()
    replay = gots is not None and len(gots) == len(cases)
    for i, c in enumerate(cases):
        if replay:
            got = gots[i]
        else:
            try:
                got = m.run(c)
            except Fault as e:
                got = ('fault', str(e))
            insns.update(m.trace)
            edges.update(m.edges)
            if gots is not None:
                gots.append(got)
        want = reconstructed(fn.kind, c, variant)
        if got != want:
            bad.append(i)
    return bad, insns, edges


# mutants -------------------------------------------------------------------------
# (anchor VA, kind, value, name): 'imm' sets immediate byte value[0] to value[1], 'jcc' inverts the condition
IMAGE_MUTANTS = {
    'map': (
        (0x21e0399, 'imm', (1, 0x20), 'size-hint clamp compare 0x4000 -> 0x2000'),
        (0x21e039f, 'imm', (1, 0x20), 'size-hint clamp value 0x4000 -> 0x2000'),
        (0x21e03b7, 'imm', (0, 0x05), 'allocation size shift 6 -> 5'),
        (0x21e03c7, 'jcc', None, 'allocation null test inverted'),
        (0x21e044a, 'jcc', None, 'remaining-count loop exit inverted'),
        (0x21e0492, 'imm', (0, 0x02), 'key Err discriminant 1 -> 2'),
        (0x21e049b, 'imm', (0, 0x15), 'key None niche 0x16 -> 0x15'),
        (0x21e04d7, 'imm', (0, 0x02), 'value Err discriminant 1 -> 2'),
        (0x21e056f, 'imm', (0, 0x18), 'entry Err niche 0x17 -> 0x18'),
        (0x21e05d3, 'jcc', None, 'full-vector grow test inverted'),
        (0x21e05f2, 'imm', (0, 0x10), 'empty dangling pointer 8 -> 0x10'),
        (0x21e0627, 'imm', (0, 0x14), 'Content::Map 0x15 -> 0x14'),
        (0x21e06f1, 'imm', (0, 0x02), 'Err discriminant store 1 -> 2'),
        (0x21e0717, 'jcc', None, 'Err cleanup loop exit inverted'),
        (0x21e073b, 'jcc', None, 'free-if-capacity test inverted'),
        (0x21e0742, 'imm', (0, 0x05), 'free size shift 6 -> 5'),
        (0x21e07e3, 'jcc', None, 'unwind cleanup loop exit inverted'),
        (0x21e07fe, 'jcc', None, 'unwind free-if-capacity test inverted'),
    ),
    'seq': (
        (0x21e1c24, 'imm', (1, 0x40), 'size-hint clamp compare 0x8000 -> 0x4000'),
        (0x21e1c2a, 'imm', (1, 0x40), 'size-hint clamp value 0x8000 -> 0x4000'),
        (0x21e1c45, 'imm', (0, 0x04), 'allocation size shift 5 -> 4'),
        (0x21e1c55, 'jcc', None, 'allocation null test inverted'),
        (0x21e1cad, 'jcc', None, 'remaining-count loop exit inverted'),
        (0x21e1cdd, 'imm', (0, 0x01), 'element Err flag 0 -> 1'),
        (0x21e1ce8, 'imm', (0, 0x15), 'None niche 0x16 -> 0x15'),
        (0x21e1d0f, 'jcc', None, 'full-vector grow test inverted'),
        (0x21e1d2e, 'imm', (0, 0x10), 'empty dangling pointer 8 -> 0x10'),
        (0x21e1d63, 'imm', (0, 0x15), 'Content::Seq 0x14 -> 0x15'),
        (0x21e1dd9, 'imm', (0, 0x02), 'Err discriminant store 1 -> 2'),
        (0x21e1df0, 'imm', (0, 0x02), 'Err cleanup loop bound 1 -> 2'),
        (0x21e1e0f, 'jcc', None, 'free-if-capacity test inverted'),
        (0x21e1e16, 'imm', (0, 0x04), 'free size shift 5 -> 4'),
        (0x21e1e53, 'jcc', None, 'unwind cleanup loop exit inverted'),
        (0x21e1e6e, 'jcc', None, 'unwind free-if-capacity test inverted'),
    ),
}


def mutate(img, fn, m):
    va, kind, val, _ = m
    data = bytearray(img.data)
    va = va - KINDS[fn.kind]['funcs'][0] + fn.start
    ins = fn.cache[va]
    if kind == 'imm':
        if not ins.immlen or val[0] >= ins.immlen:
            raise Fault(f'{va:#x} has no immediate byte {val[0]}')
        at = va + ins.size - ins.immlen + val[0]
        if img.data[img.off(at)] == val[1]:
            raise Fault(f'{va:#x}: mutant byte equals the original')
        data[img.off(at)] = val[1]
    else:
        if ins.op != 'j':
            raise Fault(f'{va:#x} is not a conditional jump')
        at = va + (1 if ins.raw[0] == 0x0f else 0)
        data[img.off(at)] ^= 1
    return bytes(data), img.off(at)


class Patched(Image):
    def __init__(self, img, data):
        self.__dict__.update(img.__dict__)
        self.data = data


def run_mutant(img, fn, m, cases):
    data, _ = mutate(img, fn, m)
    pimg = Patched(img, data)
    pf = Fn.__new__(Fn)
    pf.__dict__.update(fn.__dict__)
    pf.insns = sweep(pimg, fn.start, fn.end)
    pf.cache = {i.va: i for i in pf.insns}
    bad, _, _ = compare(pimg, pf, cases)
    return len(bad)


# outputs -------------------------------------------------------------------------
def hx(v):
    return '%#x' % v


def reads_text(reads):
    if len(reads) > 16:
        return '%d events, sha %s' % (len(reads), h16(repr(reads).encode()))
    return ','.join(e if e == 'E' else '%02x' % e for e in reads) or '-'


def case_row(c):
    return [hx(c['left']), reads_text(c['reads']), 'alloc_ok' if c.get('alloc_ok', True) else 'alloc_fail',
            ','.join(map(str, c.get('throws', ()))) or '-']


def calls_text(calls):
    if len(calls) > 24:
        return '%d calls, first %s, sha %s' % (len(calls), '/'.join(str(x) for x in calls[0]),
                                                h16(repr(calls).encode()))
    return ' '.join('/'.join(str(x) for x in rec) for rec in calls) or '-'


def load_fns(img):
    fns = {}
    for kind, k in KINDS.items():
        anchor = Fn(img, kind, k['funcs'][0])
        fns[kind] = [anchor] + [Fn(img, kind, s, anchor) for s in k['funcs'][1:]]
        for caller, f in zip(KEY_READERS, fns[kind]):
            ins = decode(img, caller + k['caller_call'])
            if ins.op != 'call' or ins.va + ins.size + ins.b != f.start:
                raise Fault(f'{caller:#x}+{k["caller_call"]:#x} does not call {f.start:#x}')
    return fns


def generate(out_dir, data=None):
    data = data if data is not None else BINARY.read_bytes()
    img = Image(data)
    fns = load_fns(img)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {'binary_sha256': SHA256, 'callers': [hx(a) for a in KEY_READERS], 'kinds': {}}
    lines_f = ['kind\tcopy\tstart\tend\tbytes\tlsda\tcaller_site\tinsns\tcalls\tframe']
    lines_c = ['kind\toffset\trole\t' + '\t'.join('target_%d' % k for k in range(3)) + '\tlanding_pad\taction']
    lines_l = ['kind\tstart\tend\tlanding_pad\taction']
    lines_v = ['kind\toffset\tbytes\top\tcovered\tjcc_taken\tjcc_not_taken']
    lines_k = ['kind\tid\tleft\treads\talloc\tthrows\toutcome\tresult\tcalls\taccess_after\theap']
    lines_m = ['kind\tmutant\tname\tchanged_cases']
    killed = total = 0
    for kind, fl in fns.items():
        anchor = fl[0]
        k = KINDS[kind]
        cases = all_cases(img, anchor)
        base = base_cases(kind)
        per = []
        cover, gots = None, []
        for n, f in enumerate(fl):
            bad, insns, edges = compare(img, f, cases, gots=gots if n == 0 else None)
            if bad:
                raise Fault(f'{f.start:#x}: {len(bad)} cases disagree with the reconstruction (first {bad[0]})')
            jcc = {i.va for i in f.insns if i.op == 'j'}
            both = {va for va in jcc if (va, True) in edges and (va, False) in edges}
            per.append({'start': hx(f.start), 'mismatches': 0, 'insns': len(f.insns),
                        'insns_covered': len(insns), 'jcc': len(jcc), 'jcc_both_ways': len(both)})
            if n == 0:
                cover = (insns, edges)
            lines_f.append('\t'.join([kind, str(n), hx(f.start), hx(f.end), str(f.end - f.start), hx(f.lsda),
                                      hx(KEY_READERS[n] + k['caller_call']), str(len(f.insns)), str(len(f.role)),
                                      hx(k['frame'])]))
        for va in sorted(anchor.role):
            o = va - anchor.start
            site = anchor.site_of(va)
            ts = [hx(f.targets[anchor.role[va]]) for f in fl]
            lines_c.append('\t'.join([kind, hx(o), anchor.role[va]] + ts +
                                     [hx(site[0] - anchor.start) if site and site[0] else '-',
                                      str(site[1]) if site else '-']))
        for s, e, lp, a in anchor.sites:
            lines_l.append('\t'.join([kind, hx(s - anchor.start), hx(e - anchor.start),
                                      hx(lp - anchor.start) if lp else '-', str(a)]))
        insns, edges = cover
        for i in anchor.insns:
            j = i.op == 'j'
            lines_v.append('\t'.join([kind, hx(i.va - anchor.start), i.raw.hex(), i.op,
                                      'yes' if i.va in insns else 'no',
                                      ('yes' if (i.va, True) in edges else 'no') if j else '-',
                                      ('yes' if (i.va, False) in edges else 'no') if j else '-']))
        counts = {}
        for n, c in enumerate(cases):
            r = gots[n]
            key = r[0] + ':' + (r[2][-1][0] if r[2] else '-')
            counts[key] = counts.get(key, 0) + 1
            lines_k.append('\t'.join([kind, str(n)] + case_row(c) +
                                     [r[0], r[1], calls_text(r[2]), r[3], ','.join(r[4]) or '-']))
        mbase = base_cases(kind, huge=False)
        mk = 0
        for v in MODEL_VARIANTS[kind]:
            bad, _, _ = compare(img, anchor, cases, v, gots=gots)
            mk += bool(bad)
            lines_m.append('\t'.join([kind, 'model', v, str(len(bad))]))
        for mt in IMAGE_MUTANTS[kind]:
            nb = run_mutant(img, anchor, mt, mbase + throw_cases(img, anchor, mbase[::7]))
            mk += bool(nb)
            lines_m.append('\t'.join([kind, hx(mt[0]), mt[3], str(nb)]))
        killed += mk
        total += len(MODEL_VARIANTS[kind]) + len(IMAGE_MUTANTS[kind])
        summary['kinds'][kind] = {'cases': len(cases), 'base_cases': len(base),
                                  'throw_cases': len(cases) - len(base), 'copies': per,
                                  'outcomes': {x: counts[x] for x in sorted(counts)},
                                  'mutants': {'model': len(MODEL_VARIANTS[kind]), 'image': len(IMAGE_MUTANTS[kind]),
                                              'killed': mk}}
    for name, lines in (('functions.tsv', lines_f), ('call_sites.tsv', lines_c), ('lsda.tsv', lines_l),
                        ('coverage.tsv', lines_v), ('cases.tsv', lines_k), ('mutants.tsv', lines_m)):
        (out_dir / name).write_text('\n'.join(lines) + '\n')
    summary['mutants'] = {'total': total, 'killed': killed}
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, help='directory for the generated evidence files')
    ap.add_argument('--binary', default=str(BINARY))
    a = ap.parse_args()
    s = generate(a.out, Path(a.binary).read_bytes())
    print(json.dumps({k: {'cases': v['cases'], 'copies': v['copies'], 'mutants': v['mutants']}
                      for k, v in s['kinds'].items()}, sort_keys=True))
    return 0 if s['mutants']['killed'] == s['mutants']['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
