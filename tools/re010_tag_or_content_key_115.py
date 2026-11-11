#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack TagOrContent key reader and prove it.

serde's internally tagged `Action` visitor (visit_map 0x1fb1750 / 0x3952ed0 /
0x5687260) reads every map key through `deserialize_any` with a
`TagOrContentVisitor { name: "type" }`.  The rmp_serde body of that call is
inlined into one 2378-byte function per deserializer copy:

  0x1a7e1a0   0x30fb4f0   0x48cd3a0   (called at visit_map +0xfd)

It reads (or takes the peeked) MessagePack marker, dispatches on it through a
225-entry relative jump table plus an 18-entry ext table, decodes length
prefixes, borrows str/bin payloads from the input slice, decides
Tag / Content::Str / Content::Bytes by comparing with the tag name, recurses
into map / array / ext visitors under the u16 depth budget, checks the
remaining-length after a map or array visit, and forwards every other marker
to the generic deserialize_any.

This tool:
1. checks the input digest, finds each copy's FDE extent and LSDA, decodes every
   instruction with a fixed-pattern x86-64 subset decoder and binds every call
   site to a role by its offset (the three copies share one layout, which is
   checked byte for byte outside rip-relative operands and call targets);
2. interprets the original bytes (the binary is never run) with contract stubs
   for the callees (map/array/ext/bytes visitors, generic deserialize_any,
   bcmp, from_utf8 on real bytes, allocator, panics, drops);
3. compares every outcome with a pure reconstruction (`reconstructed` below):
   result bytes, the callee sequence with semantic arguments and the
   deserializer state written back (input position, remaining length, peek
   slot, depth);
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

FUNCS = (0x1a7e1a0, 0x30fb4f0, 0x48cd3a0)   # visit_map +0xfd callees of the three copies
SIZE, FRAME = 2378, 0xc8
CALLERS = (0x1fb1750, 0x3952ed0, 0x5687260)  # TaggedContentVisitor::visit_map copies
KEY_CALL = 0xfd
# anchor-copy call targets -> role; other copies bind roles by call offset
ANCHOR_DIRECT = {0x21e0380: 'map_visit', 0x21e1c10: 'seq_visit', 0x21e1930: 'ext_visit',
                 0x21e2670: 'bytes_visit', 0x18a33d0: 'drop_content', 0x187e680: 'drop_result',
                 0x21d8eb0: 'drop_ext'}
GOT_ROLES = {0x64e3a90: 'any_other', 0x64df9f8: 'bcmp', 0x64dfca8: 'from_utf8', 0x64df480: 'alloc',
             0x64df490: 'alloc_error', 0x64df848: 'panic_sub', 0x64df520: 'panic_add',
             0x64df4c0: 'terminate'}
RESUME_SYMBOL = '_Unwind_Resume'
# rip-relative operands bound per copy by the lea's offset in the function
LEA_ROLES = {0x51: 'eof', 0x4bd: 'eof', 0x695: 'L_map', 0x875: 'L_ext', 0x882: 'L_map', 0x88f: 'L_ext',
             0x89e: 'L_seq', 0x8ab: 'L_seq', 0x8ba: 'L_map_len', 0x8c9: 'L_seq_len'}
TABLE_LEAS = {0x96: ('marker', 0xe1), 0xd4: ('ext', 18)}

EOF_KIND, DATA_KIND = 0, 1        # rmp Error::InvalidMarkerRead / InvalidDataRead (first byte)
TYPE_MISMATCH, LEN_MISMATCH, DEPTH = 2, 4, 8
UNEXPECTED_EOF = 0x2500000003     # io::Error simple-kind repr stored for a short payload
NO_PEEK = 1                       # Option<Marker>::None niche in the peek slot
TAG, STR, BYTES, NEWTYPE = 0x16, 0x0d, 0x0f, 0x13

OUT_BASE, DES_BASE, IN_BASE, NAME_PTR = 0x7100_0000_0000, 0x7180_0000_0000, 0x7500_0000_0000, 0x7300_0000_0000
HEAP_BASE = 0x7400_0000_0000
STACK_TOP = 0x7200_0000_0000
MASK64 = (1 << 64) - 1
OUT_FILL, STACK_FILL, DES_FILL = 0xaa, 0x5c, 0x3d
OUT_SIZE, DES_SIZE = 0x30, 0x28
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



def lea_target(ins):
    return ins.va + ins.size + ins.b[4]


class Fn:
    """Static facts of one key-reader copy, all read from the bytes."""

    def __init__(self, img, start, anchor=None):
        self.start = start
        fde = fde_of(img.data, start)
        self.end = fde['end']
        if self.end - start != SIZE:
            raise Fault(f'{start:#x}: FDE extent is {self.end - start} bytes')
        self.lsda = fde.get('lsda') or 0
        if not self.lsda:
            raise Fault(f'{start:#x}: no LSDA')
        self.sites = img.call_sites(self.lsda, start)
        self.insns = sweep(img, start, self.end)
        self.cache = {i.va: i for i in self.insns}
        subs = [i for i in self.insns if i.op == 'sub' and i.a == ('r', 4) and i.b[0] == 'i']
        if not subs or subs[0].b[1] != FRAME:
            raise Fault(f'{start:#x}: frame size is not {FRAME:#x}')
        self.role, self.targets = {}, {}
        for i in self.insns:
            if i.op not in ('call', 'callr'):
                continue
            o = i.va - start
            if i.op == 'callr':
                if i.a[0] != 'm' or not i.a[5]:
                    raise Fault(f'{i.va:#x}: indirect call is not through a GOT slot')
                slot = i.va + i.size + i.a[4]
                if slot not in GOT_ROLES:
                    raise Fault(f'{i.va:#x}: GOT slot {slot:#x} has no role')
                role, t = GOT_ROLES[slot], slot
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
        self.consts, self.tables = {}, {}
        for i in self.insns:
            if i.op != 'lea' or i.b[0] != 'm' or not i.b[5]:
                continue
            o = i.va - start
            t = lea_target(i)
            if o in LEA_ROLES:
                if self.consts.setdefault(LEA_ROLES[o], t) != t:
                    raise Fault(f'{start:#x}: {LEA_ROLES[o]} loaded with two values')
            elif o in TABLE_LEAS:
                self.tables[TABLE_LEAS[o][0]] = (t, TABLE_LEAS[o][1])
            else:
                raise Fault(f'{i.va:#x}: rip-relative lea without a role')
        if set(self.consts) != set(LEA_ROLES.values()) or set(self.tables) != {'marker', 'ext'}:
            raise Fault(f'{start:#x}: missing rip-relative operands')
        if anchor is not None:
            same = [a.raw == b.raw for a, b in zip(anchor.insns, self.insns)
                    if a.op not in ('call', 'lea', 'callr')]
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

    def table_rows(self, img):
        """(table, index, arm offset) for both relative jump tables."""
        rows = []
        for name in ('marker', 'ext'):
            t, n = self.tables[name]
            for k, va in enumerate(img.table(t, n)):
                rows.append((name, k, va - self.start))
        return rows


class Stop(Exception):
    pass


class Machine:
    def __init__(self, img, fn):
        self.img, self.f = img, fn

    def run(self, case):
        self.case = case
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.des = bytearray([DES_FILL]) * DES_SIZE
        peek = case['peek']
        struct.pack_into('<QQBBH', self.des, 0x10, IN_BASE, len(case['buf']),
                         NO_PEEK if peek is None else peek[0], 0x77 if peek is None else peek[1], case['depth'])
        self.inp = bytearray(case['buf'])
        self.name = bytearray(case['name'])
        self.stack = bytearray([STACK_FILL]) * 0x200
        self.heap = []
        self.calls, self.trace, self.edges = [], [], set()
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6], self.r[2], self.r[1] = OUT_BASE, DES_BASE, NAME_PTR, len(case['name'])
        self.r[8] = 0x4000_0000_0000_0000 | case['flag']   # only r8b is an argument
        self.r[9] = 0x5000_0000_0000_0000
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.frame_lo = None
        pc = self.f.start
        try:
            for _ in range(4000):
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
        return (kind, self.out.hex(), tuple(self.calls), self.des.hex())

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
        for base, buf in [(OUT_BASE, self.out), (DES_BASE, self.des), (IN_BASE, self.inp),
                          (NAME_PTR, self.name), (STACK_TOP - len(self.stack), self.stack)] + self.heap:
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
        if buf is None or buf is self.inp or buf is self.name:
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
            self.put(ins.a, w, (v << n | v >> (w - n)) if n else v, nxt)
            self.flags['c'] = self.flags['o'] = None  # rotate flags are never read here
        elif op == 'bswap':
            v = self.get(ins.a, 32, nxt)
            self.put(ins.a, 32, int.from_bytes(v.to_bytes(4, 'little'), 'big'), nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'movsxd':
            self.put(ins.a, 64, sx(self.get(ins.b, 32, nxt), 32), nxt)
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
            raise Stop('ud2')
        elif op == 'nop':
            pass
        else:
            raise Fault(f'no semantics for {op} at {ins.va:#x}')
        return None

    def where(self, a):
        """Name a pointer: out, deserializer, input offset, tag name, frame slot, heap block or value."""
        if a == DES_BASE:
            return 'des'
        if a == NAME_PTR:
            return 'name'
        if OUT_BASE <= a < OUT_BASE + OUT_SIZE:
            return 'out+%x' % (a - OUT_BASE)
        if IN_BASE <= a <= IN_BASE + len(self.inp):
            return 'in+%x' % (a - IN_BASE)
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
        throws = len(self.calls) in self.case.get('throws', ()) or role in UNWINDS
        saved = (bytes(self.out), bytes(self.stack), bytes(self.des))
        try:
            rec, ret = self.stub(role, r)
        except (IndexError, TypeError, ValueError, KeyError, struct.error) as e:
            raise Fault(f'callee contract violated by {role}: {e}')
        if throws:  # a callee that unwinds leaves no result behind
            self.out[:], self.stack[:], self.des[:] = saved
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

    def loc(self, a):
        names = [k for k, v in self.f.consts.items() if v == a]
        return names[0] if names else 'v:%x' % a

    def stub(self, role, r):
        c, w = self.case, self.where
        v = c.get('visit', ('ok', 0, 0x15))
        if role == 'any_other':
            self.store(r[7], pattern('any', r[8], r[9], n=0x28))
            return ('any_other', w(r[7]), w(r[6]), w(r[2]), r[1], r[8], r[9]), None
        if role in ('map_visit', 'seq_visit'):
            de, n = struct.unpack('<QI', self.load(r[6], 12))
            rec = (role, w(r[7]), w(r[6]), w(de), n)
            if v[0] == 'err':
                self.store(r[7], struct.pack('<II', 1, 0) + pattern('verr', n=32))
            else:
                self.store(r[7], struct.pack('<II', 0, 0) + bytes([v[2]]) + pattern('vok', n=31))
                self.store(r[6] + 8, struct.pack('<I', v[1]))
            if len(v) > 3:
                self.store(DES_BASE + 0x22, struct.pack('<H', v[3]))
            return rec, None
        if role == 'ext_visit':
            de, n, b = struct.unpack('<QIB', self.load(r[6], 13))
            rec = ('ext_visit', w(r[7]), w(de), n, b)
            if v[0] == 'err':
                self.store(r[7], bytes([1]) + pattern('xpad', n=7) + pattern('xerr', n=32))
            else:
                self.store(r[7], bytes([0]) + pattern('xpad', n=7) + pattern('xok', n=32))
            if len(v) > 3:
                self.store(DES_BASE + 0x22, struct.pack('<H', v[3]))
            return rec, None
        if role == 'bytes_visit':
            p, e, k = struct.unpack('<QQQ', self.load(r[6], 24))
            self.store(r[7], pattern('bytes', e - p, n=0x28))
            return ('bytes_visit', w(r[7]), w(p), e - p, k), None
        if role == 'bcmp':
            n = r[2]
            eq = self.load(r[7], n) == self.load(r[6], n) if n else True
            return ('bcmp', w(r[7]), w(r[6]), n), 0 if eq else 1
        if role == 'from_utf8':
            raw = self.load(r[6], r[2]) if r[2] else b''
            try:
                raw.decode('utf-8')
                self.store(r[7], struct.pack('<QQQ', 0, r[6], r[2]))
            except UnicodeDecodeError as e:
                self.store(r[7], struct.pack('<QQQ', 1, e.start, 0x0101))
            return ('from_utf8', w(r[7]), w(r[6]), r[2]), None
        if role == 'alloc':
            if not c.get('alloc_ok', True):
                return ('alloc', r[7]), 0
            return ('alloc', r[7]), self.new_block(r[7])
        if role == 'alloc_error':
            return ('alloc_error', r[7], r[6]), None
        if role in ('panic_sub', 'panic_add'):
            return (role, self.loc(r[7])), None
        if role == 'drop_content':
            return ('drop_content', w(r[7]), self.load(r[7], 32).hex()), None
        if role in ('drop_result', 'drop_ext'):
            return (role, w(r[7])), None
        if role in ('terminate', 'resume'):
            return (role,), None
        raise Fault(f'no stub for {role}')


# reconstruction ------------------------------------------------------------------
FRAME_LO = STACK_TOP - 8 - 6 * 8 - FRAME
UNWINDS = ('panic_sub', 'panic_add', 'alloc_error')   # these never return; they unwind
MODEL_VARIANTS = ('fresh_data_full', 'map_err_restores_depth', 'ext_err_keeps_depth', 'bin_ignores_flag',
                  'str_err_is_str', 'no_len_check', 'depth_le1', 'no_consume_short_len',
                  'tag_keeps_slice', 'mismatch_left', 'skip_drop_any', 'nil_is_unit')


class Throw(Exception):
    pass


class Model:
    """Pure reconstruction of the key reader; `variant` names a deliberately wrong model."""

    def __init__(self, case, consts, variant=None):
        self.c, self.k, self.v = case, consts, variant
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.calls = []
        self.buf = case['buf']
        self.pos, self.rem = 0, len(case['buf'])
        self.peek = case['peek']
        self.depth = case['depth']
        self.throws = set(case.get('throws', ()))

    # callees ------------------------------------------------------------------
    def call(self, *rec, unwinds=False):
        k = len(self.calls)
        if unwinds or k in self.throws:
            self.calls.append(rec + ('!',))
            raise Throw(rec[0])
        self.calls.append(rec)

    def pad(self, *recs):
        """Run landing-pad cleanups; a cleanup that unwinds terminates."""
        for rec in recs:
            k = len(self.calls)
            if k in self.throws:
                self.calls.append(rec + ('!',))
                self.calls.append(('terminate',))
                return 'terminate'
            self.calls.append(rec)
        self.calls.append(('resume',))
        return 'resume'

    def finish(self, kind):
        des = bytearray([DES_FILL]) * DES_SIZE
        struct.pack_into('<QQBBH', des, 0x10, (IN_BASE + self.pos) & MASK64, self.rem & MASK64, NO_PEEK,
                         0x77 if self.peek is None else self.peek[1], self.depth & 0xffff)
        return (kind, self.out.hex(), tuple(self.calls), des.hex())

    def err(self, code, payload=None):
        self.out[8] = code
        if payload is not None:
            self.out[0x10:0x18] = struct.pack('<Q', payload)
        self.out[0:8] = struct.pack('<Q', 1)

    def ok(self, body):
        self.out[0:8] = struct.pack('<Q', 0)
        self.out[8:8 + len(body)] = body

    def take(self, n):
        """Read n big-endian length bytes; a short read consumes what is left."""
        if self.rem < n:
            if not (self.v == 'no_consume_short_len'):
                self.pos, self.rem = self.pos + self.rem, 0
            return None
        v = int.from_bytes(self.buf[self.pos:self.pos + n], 'big')
        self.pos, self.rem = self.pos + n, self.rem - n
        return v

    # body ---------------------------------------------------------------------
    def run(self):
        try:
            return self.body()
        except Throw as t:
            return self.unwind(t.args[0])

    def unwind(self, role):
        last = self.calls[-1]
        if role in ('panic_add',):
            return self.finish(self.pad(('drop_result', 'sp+0')))
        if role == 'panic_sub' and last[1] in ('L_map_len', 'L_seq_len'):
            if self.content[0] == TAG and self.v != 'skip_drop_any':
                return self.finish(self.pad())
            return self.finish(self.pad(('drop_content', 'sp+50', self.content.hex())))
        if role == 'alloc_error':
            return self.finish(self.pad(('drop_ext', 'sp+0')))
        return self.finish('escape')

    def body(self):
        c = self.c
        if self.peek is None:
            if self.rem == 0:
                self.err(EOF_KIND, self.k['eof'])
                return self.finish('ret')
            b = self.buf[self.pos]
            self.pos, self.rem = self.pos + 1, self.rem - 1
            if b < 0x80:
                return self.other(0, b)
            if b >= 0xe0:
                return self.other(0xe0, b)
            if b < 0x90:
                return self.nested('map', b & 0xf)
            if b < 0xa0:
                return self.nested('seq', b & 0xf)
            if b < 0xc0:
                return self.text(b & 0x1f)
            kind, data = b, (b if self.v == 'fresh_data_full' else b & 0x1f)
        else:
            kind, data = self.peek
            if kind == 0:
                return self.other(0, data)
            if kind == 0x80:
                return self.nested('map', data)
            if kind == 0x90:
                return self.nested('seq', data)
            if kind == 0xa0:
                return self.text(data)
            if kind < 0xc0:
                return self.finish('ud2')   # not a Marker discriminant: unreachable arm
        if kind in (0xc0, 0xc2, 0xc3, 0xe0) or 0xca <= kind <= 0xd3:
            if kind == 0xc0 and self.v == 'nil_is_unit':
                self.ok(bytes([0x12]))
                return self.finish('ret')
            return self.other(kind, data)
        if kind == 0xc1:
            self.out[8:10] = bytes([TYPE_MISMATCH, 0xc1])
            self.out[0:8] = struct.pack('<Q', 1)
            return self.finish('ret')
        if kind in (0xc4, 0xc5, 0xc6):
            n = self.take({0xc4: 1, 0xc5: 2, 0xc6: 4}[kind])
            if n is None:
                self.err(DATA_KIND, self.k['eof'])
                return self.finish('ret')
            return self.binary(n)
        if kind in (0xd9, 0xda, 0xdb):
            n = self.take({0xd9: 1, 0xda: 2, 0xdb: 4}[kind])
            if n is None:
                self.err(DATA_KIND, self.k['eof'])
                return self.finish('ret')
            return self.text(n)
        if kind in (0xdc, 0xdd, 0xde, 0xdf):
            n = self.take(2 if kind in (0xdc, 0xde) else 4)
            if n is None:
                self.err(DATA_KIND, self.k['eof'])
                return self.finish('ret')
            return self.nested('seq' if kind < 0xde else 'map', n)
        # ext family: c7/c8/c9 carry a length, d4..d8 are fixext 1/2/4/8/16
        if kind in (0xc7, 0xc8, 0xc9):
            n = self.take({0xc7: 1, 0xc8: 2, 0xc9: 4}[kind])
            if n is None:
                self.out[9:11] = bytes([kind, data])
                self.err(DATA_KIND, self.k['eof'])
                return self.finish('ret')
        else:
            n = {0xd4: 1, 0xd5: 2, 0xd6: 4, 0xd7: 8, 0xd8: 16}[kind]
        return self.ext(n)

    def other(self, kind, data):
        self.call('any_other', 'out+0', 'des', 'name', len(self.c['name']), kind, data)
        self.out[0:0x28] = pattern('any', kind, data, n=0x28)
        return self.finish('ret')

    def payload(self, n):
        if self.rem < n and self.v != 'no_len_check':
            self.err(DATA_KIND, UNEXPECTED_EOF)
            return None
        p = self.pos
        self.pos, self.rem = self.pos + n, self.rem - n
        return p

    def is_tag(self, p, n):
        name = self.c['name']
        if n != len(name):
            return False
        self.call('bcmp', 'in+%x' % p, 'name', n)
        return bytes(self.buf[p:p + n]) == bytes(name)

    def binary(self, n):
        p = self.payload(n)
        if p is None:
            return self.finish('ret')
        if not self.c['flag'] and self.v != 'bin_ignores_flag':
            self.call('bytes_visit', 'sp+28', 'in+%x' % p, n, 0)
            self.out[0:0x28] = pattern('bytes', n, n=0x28)
            return self.finish('ret')
        if self.is_tag(p, n):
            self.ok(bytes([TAG]))
        else:
            self.ok(bytes([BYTES]) + bytes(self.out[9:0x10]) + struct.pack('<QQ', IN_BASE + p, n))
        return self.finish('ret')

    def text(self, n):
        p = self.payload(n)
        if p is None:
            return self.finish('ret')
        self.call('from_utf8', 'sp+28', 'in+%x' % p, n)
        try:
            bytes(self.buf[p:p + n]).decode('utf-8')
            valid = True
        except UnicodeDecodeError:
            valid = False
        tag = self.is_tag(p, n)
        if not valid and self.v != 'str_err_is_str':
            # invalid UTF-8 is kept as borrowed bytes; the tag test still runs on the bytes
            self.ok(bytes([TAG if tag else BYTES]) + bytes(self.out[9:0x10]) + struct.pack('<QQ', IN_BASE + p, n))
        elif tag and self.v != 'tag_keeps_slice':
            self.ok(bytes([TAG]))
        else:
            self.ok(bytes([TAG if tag else STR]) + bytes(self.out[9:0x10]) + struct.pack('<QQ', IN_BASE + p, n))
        return self.finish('ret')

    def enter(self, loc):
        if self.depth == 0:
            self.call('panic_sub', loc, unwinds=True)
        self.depth -= 1
        lim = 1 if self.v == 'depth_le1' else 0
        if self.depth <= lim:
            self.out[8] = DEPTH
            self.out[0:8] = struct.pack('<Q', 1)
            return False
        return True

    def leave(self, loc):
        if self.depth == 0xffff:
            self.call('panic_add', loc, unwinds=True)
        self.depth += 1

    def nested(self, form, n):
        loc = 'L_' + form
        if not self.enter(loc):
            return self.finish('ret')
        v = self.c.get('visit', ('ok', 0, 0x15))
        self.call(form + '_visit', 'sp+28', 'sp+70', 'des', n)
        if len(v) > 3:
            self.depth = v[3]
        if v[0] == 'err':
            self.out[8:0x28] = pattern('verr', n=32)
            self.out[0:8] = struct.pack('<Q', 1)
            if self.v == 'map_err_restores_depth':
                self.depth += 1
            return self.finish('ret')
        self.content = bytes([v[2]]) + pattern('vok', n=31)
        left = v[1]
        if left == 0:
            res = struct.pack('<Q', 0) + self.content
        else:
            if left > n:
                self.call('panic_sub', loc + '_len', unwinds=True)
            got = left if self.v == 'mismatch_left' else n - left
            res = (struct.pack('<Q', 1) + bytes([LEN_MISMATCH]) + bytes([STACK_FILL]) * 3
                   + struct.pack('<I', got) + bytes([STACK_FILL]) * 0x18)
            if self.content[0] != TAG or self.v == 'skip_drop_any':
                self.call('drop_content', 'sp+50', self.content.hex())
        self.leave(loc)
        self.out[0:0x28] = res
        return self.finish('ret')

    def ext(self, n):
        if not self.enter('L_ext'):
            return self.finish('ret')
        v = self.c.get('visit', ('ok', 0, 0x15))
        self.call('ext_visit', 'sp+28', 'des', n, 0)
        if len(v) > 3:
            self.depth = v[3]
        if v[0] == 'err':
            res = struct.pack('<Q', 1) + pattern('xerr', n=32)
            if self.v == 'ext_err_keeps_depth':
                self.out[0:0x28] = res
                return self.finish('ret')
        else:
            self.call('alloc', 0x20)
            if not self.c.get('alloc_ok', True):
                self.call('alloc_error', 8, 0x20, unwinds=True)
            inner = pattern('xok', n=32)
            res = struct.pack('<Q', 0) + bytes([NEWTYPE]) + inner[1:8] + struct.pack('<Q', HEAP_BASE) + inner[16:32]
        self.leave('L_ext')
        self.out[0:0x28] = res
        return self.finish('ret')


def reconstructed(case, consts, variant=None):
    return Model(case, consts, variant).run()


# cases ---------------------------------------------------------------------------
NAMES = (b'type', b'', b't', b'typ', b'types', b'\xff\xfe\xfd\xfc')
PAYLOADS = (b'type', b'', b't', b'typ', b'types', b'tYpe', b'\xff\xfe\xfd\xfc', b'\xc3\xa9t\xe2',
            b'\xed\xa0\x80\x00', b'\xf0\x9f\x98\x80', b'\x00\x01\x02\x03' * 9)
VISITS = (('ok', 0, 0x15), ('ok', 0, 0x14), ('ok', 1, 0x15), ('ok', 2, TAG), ('ok', 3, 0x00), ('ok', 0xffffffff, 0x15),
          ('ok', 1, 0x15, 0xffff), ('ok', 0, 0x15, 0xffff), ('err',), ('err', 0, 0, 0xffff))
DEPTHS = (0, 1, 2, 3, 0x400, 0xfffe, 0xffff)
LEN_BYTES = {0xc4: 1, 0xc5: 2, 0xc6: 4, 0xd9: 1, 0xda: 2, 0xdb: 4, 0xc7: 1, 0xc8: 2, 0xc9: 4,
             0xdc: 2, 0xdd: 4, 0xde: 2, 0xdf: 4}


def case(buf, peek=None, name=b'type', flag=1, depth=0x400, **kw):
    d = dict(buf=bytes(buf), peek=peek, name=name, flag=flag, depth=depth)
    d.update(kw)
    return d


def base_cases():
    out = []
    # every first byte with an empty tail and with a generic tail
    for b in range(256):
        out.append(case([b]))
        out.append(case([b, 0x00, 0x04] + list(b'type') + [0x00] * 4))
        out.append(case([b, 0xff, 0xff, 0xff, 0xff], flag=0))
    out.append(case(b''))
    # length-prefixed str / bin: exact, short payload, short length, every payload and name
    for m in (0xc4, 0xc5, 0xc6, 0xd9, 0xda, 0xdb):
        lb = LEN_BYTES[m]
        for pl in PAYLOADS:
            for name in NAMES:
                for flag in ((0, 1) if m < 0xd0 else (1,)):
                    hdr = [m] + list(len(pl).to_bytes(lb, 'big'))
                    out.append(case(hdr + list(pl) + [0x99], name=name, flag=flag))
            hdr = [m] + list(len(pl).to_bytes(lb, 'big'))
            out.append(case(hdr + list(pl)[:-1] if pl else hdr[:-1]))
        for k in range(lb):
            out.append(case([m] + [0] * k))
    for pl in PAYLOADS:
        if len(pl) < 32:
            for name in NAMES:
                out.append(case([0xa0 | len(pl)] + list(pl), name=name))
            out.append(case([0xa0 | len(pl)] + list(pl)[:-1]))
    # map / array / ext: depth budget x visitor outcome
    heads = [[0x80], [0x83], [0x8f], [0x90], [0x92], [0x9f], [0xdc, 0, 3], [0xdd, 0, 0, 0, 2], [0xde, 1, 0],
             [0xdf, 0, 0, 0, 1], [0xc7, 5], [0xc8, 0, 9], [0xc9, 0, 0, 1, 0], [0xd4], [0xd5], [0xd6], [0xd7], [0xd8],
             [0xc7], [0xc8, 1], [0xc9, 0, 0]]
    for h in heads:
        for depth in DEPTHS:
            for vis in VISITS:
                for alloc_ok in ((True, False) if h[0] in (0xc7, 0xc8, 0xc9, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8) else (True,)):
                    out.append(case(h + [0x55] * 3, depth=depth, visit=vis, alloc_ok=alloc_ok))
    # peeked markers: every Marker discriminant 0x00..0xe0 with a few data bytes
    for kind in range(0xe1):
        if kind == NO_PEEK:
            continue  # the None niche: the same as no peeked marker (covered by the fresh cases)
        for data in (0, 3, 0x1f, 0xff):
            out.append(case([0x00, 0x04] + list(b'type') + [0x00, 0x00, 0x00, 0x02], peek=(kind, data)))
        out.append(case([], peek=(kind, 4)))
    for data in range(256):
        out.append(case(list(b'type') + [0x41] * 8, peek=(0xa0, data)))
        out.append(case([], peek=(0x80, data), visit=('ok', data // 2, 0x15)))
        out.append(case([], peek=(0x90, data), visit=('ok', 0, 0x14)))
    return out


def throw_cases(img, fn, base):
    """For each base case, let every non-unwinding callee call (ordinal) unwind once."""
    out = []
    m = Machine(img, fn)
    for c in base:
        calls = m.run(c)[2]
        for k, rec in enumerate(calls):
            if rec[0] in ('terminate', 'resume') or rec[-1] == '!':
                continue
            d = dict(c)
            d['throws'] = (k,)
            out.append(d)
        # cleanup pads: unwind inside the pad after a panic
        for k, rec in enumerate(calls):
            if rec[0] in ('drop_result', 'drop_ext', 'drop_content') and calls[-1] == ('resume',):
                d = dict(c)
                d['throws'] = (k,)
                out.append(d)
    return out


def all_cases(img, fn):
    base = base_cases()
    seen, out = set(), []
    for c in base + throw_cases(img, fn, base):
        key = repr(sorted(c.items()))
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def run_machine(m, c):
    m.case_unwinds = UNWINDS
    return m.run(c)


def compare(img, fn, cases, variant=None):
    m = Machine(img, fn)
    bad, insns, edges = [], set(), set()
    for i, c in enumerate(cases):
        try:
            got = m.run(c)
        except Fault as e:
            got = ('fault', str(e))
        want = reconstructed(c, fn.consts, variant)
        if got != want:
            bad.append(i)
        insns.update(m.trace)
        edges.update(m.edges)
    return bad, insns, edges


# mutants -------------------------------------------------------------------------
# (anchor VA, kind, new value): 'imm' sets the low immediate byte, 'jcc' inverts the condition,
# 'swap' exchanges two entries (indices) of a jump table
IMAGE_MUTANTS = (
    (0x1a7e1c1, 'imm', 0x02, 'no-peek niche 1 -> 2'),
    (0x1a7e1e6, 'jcc', None, 'positive fixint sign test inverted'),
    (0x1a7e204, 'imm', 0xde, 'negative fixint lower bound 0xe0 -> 0xdf'),
    (0x1a7e208, 'imm', 0x91, 'fixmap upper bound 0x90 -> 0x91'),
    (0x1a7e20c, 'imm', 0x07, 'fixmap length mask 0x0f -> 0x07'),
    (0x1a7e216, 'imm', 0x9f, 'fixarray upper bound 0xa0 -> 0x9f'),
    (0x1a7e227, 'imm', 0x0f, 'fixstr length mask 0x1f -> 0x0f'),
    (0x1a7e22b, 'imm', 0xbf, 'fixstr upper bound 0xc0 -> 0xbf'),
    (0x1a7e265, 'imm', 0x38, 'ext table base 0xc7 -> 0xc8'),
    (0x1a7e26b, 'imm', 0x10, 'ext table bound 0x11 -> 0x10'),
    (0x1a7e2c3, 'jcc', None, 'map depth exhausted test inverted'),
    (0x1a7e333, 'jcc', None, 'map remaining == 0 test inverted'),
    (0x1a7e33b, 'jcc', None, 'map remaining underflow test inverted'),
    (0x1a7e344, 'imm', 0x05, 'length-mismatch error code 4 -> 5'),
    (0x1a7e355, 'imm', 0x15, 'content drop skip tag 0x16 -> 0x15'),
    (0x1a7e3fc, 'imm', 0x03, 'bin32 length width 4 -> 3'),
    (0x1a7e41c, 'imm', 0x01, 'bin16 length width 2 -> 1'),
    (0x1a7e49a, 'imm', 0x03, 'reserved-marker error code 2 -> 3'),
    (0x1a7e5e8, 'imm', 0x05, 'fixext4 length 4 -> 5'),
    (0x1a7e629, 'imm', 0x11, 'fixext16 length 16 -> 17'),
    (0x1a7e6ae, 'jcc', None, 'bin payload length check inverted'),
    (0x1a7e6c3, 'jcc', None, 'bin borrow flag test inverted'),
    (0x1a7e6e5, 'imm', 0x0e, 'Content::Bytes 0x0f -> 0x0e'),
    (0x1a7e747, 'jcc', None, 'str payload length check inverted'),
    (0x1a7e74d, 'imm', 0x04, 'UnexpectedEof repr low byte 3 -> 4'),
    (0x1a7e7a6, 'imm', 0x15, 'invalid-UTF-8 tag value 0x16 -> 0x15'),
    (0x1a7e7f0, 'imm', 0x0c, 'Content::Str 0x0d -> 0x0c'),
    (0x1a7e82b, 'imm', 0xfe, 'map depth restore bound 0xffff -> 0xfffe'),
    (0x1a7e8a2, 'jcc', None, 'ext visitor Ok test inverted'),
    (0x1a7e8b0, 'imm', 0x09, 'depth-limit error code 8 -> 9'),
    (0x1a7e8e3, 'imm', 0x21, 'Newtype box size 0x20 -> 0x21'),
    (0x1a7e90a, 'imm', 0x12, 'Content::Newtype 0x13 -> 0x12'),
    (0x1a7e9cd, 'jcc', None, 'seq depth restore overflow test inverted'),
    (0x1a7e9f3, 'imm', 0x15, 'Tag discriminant 0x16 -> 0x15'),
    ('marker', 'swap', (0xd9, 0xda), 'str8 / str16 arms swapped'),
    ('marker', 'swap', (0xc4, 0xc5), 'bin8 / bin16 arms swapped'),
    ('marker', 'swap', (0xdc, 0xde), 'array16 / map16 arms swapped'),
    ('marker', 'swap', (0xc1, 0xc0), 'reserved / nil arms swapped'),
    ('ext', 'swap', (0xd4 - 0xc7, 0xd5 - 0xc7), 'fixext1 / fixext2 arms swapped'),
    ('ext', 'swap', (0xc8 - 0xc7, 0xc9 - 0xc7), 'ext16 / ext32 arms swapped'),
)


def mutate(img, fn, m):
    va, kind, val, _ = m
    data = bytearray(img.data)
    if kind == 'swap':
        t, _n = fn.tables[va]
        a, b = (t + 4 * i for i in val)
        oa, ob = img.off(a, 4), img.off(b, 4)   # entries are relative to the table base
        data[oa:oa + 4], data[ob:ob + 4] = data[ob:ob + 4], data[oa:oa + 4]
        return bytes(data), oa
    va = va - FUNCS[0] + fn.start
    ins = fn.cache[va]
    if kind == 'imm':
        if not ins.immlen:
            raise Fault(f'{va:#x} has no immediate')
        at = va + ins.size - ins.immlen
        data[img.off(at)] = val
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


def case_row(c):
    vis = c.get('visit', ('ok', 0, 0x15))
    return [c['buf'].hex() or '-', '-' if c['peek'] is None else '%02x:%02x' % c['peek'],
            c['name'].hex() or '-', str(c['flag']), '%#x' % c['depth'],
            ':'.join(str(x) for x in vis), 'alloc_ok' if c.get('alloc_ok', True) else 'alloc_fail',
            ','.join(map(str, c.get('throws', ()))) or '-']


def calls_text(calls):
    return ' '.join('/'.join(str(x) for x in rec) for rec in calls) or '-'


def generate(out_dir, data=None):
    data = data if data is not None else BINARY.read_bytes()
    img = Image(data)
    anchor = Fn(img, FUNCS[0])
    fns = [anchor] + [Fn(img, s, anchor) for s in FUNCS[1:]]
    rows_a = [(t, k, o) for t, k, o in anchor.table_rows(img)]
    for f in fns[1:]:
        if f.table_rows(img) != rows_a:
            raise Fault(f'{f.start:#x}: jump tables differ from the anchor copy')
    for caller, f in zip(CALLERS, fns):
        ins = decode(img, caller + KEY_CALL)
        if ins.op != 'call' or ins.va + ins.size + ins.b != f.start:
            raise Fault(f'{caller:#x}+{KEY_CALL:#x} does not call {f.start:#x}')
    base = base_cases()
    cases = all_cases(img, anchor)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {'binary_sha256': SHA256, 'functions': [hx(f.start) for f in fns], 'size': SIZE,
               'cases': len(cases), 'base_cases': len(base), 'throw_cases': len(cases) - len(base)}
    per = []
    cover = {}
    for f in fns:
        bad, insns, edges = compare(img, f, cases)
        if bad:
            raise Fault(f'{f.start:#x}: {len(bad)} cases disagree with the reconstruction (first {bad[0]})')
        jcc = {i.va for i in f.insns if i.op == 'j'}
        both = {va for va in jcc if (va, True) in edges and (va, False) in edges}
        per.append({'start': hx(f.start), 'mismatches': 0, 'insns': len(f.insns),
                    'insns_covered': len(insns), 'jcc': len(jcc), 'jcc_both_ways': len(both)})
        cover[f.start] = (insns, edges)
    summary['copies'] = per
    # functions.tsv
    lines = ['copy\tstart\tend\tbytes\tlsda\tcaller_site\tinsns\tcalls\t' + '\t'.join(sorted(anchor.consts)) +
             '\tmarker_table\text_table']
    for caller, f in zip(CALLERS, fns):
        lines.append('\t'.join([str(fns.index(f)), hx(f.start), hx(f.end), str(f.end - f.start), hx(f.lsda),
                                hx(caller + KEY_CALL), str(len(f.insns)), str(len(f.role))]
                               + [hx(f.consts[k]) for k in sorted(anchor.consts)]
                               + [hx(f.tables['marker'][0]), hx(f.tables['ext'][0])]))
    (out_dir / 'functions.tsv').write_text('\n'.join(lines) + '\n')
    # call_sites.tsv
    lines = ['offset\trole\t' + '\t'.join('target_%d' % k for k in range(len(fns))) + '\tlanding_pad\taction']
    for va in sorted(anchor.role):
        o = va - anchor.start
        site = anchor.site_of(va)
        ts = [hx(f.targets[anchor.role[va]]) for f in fns]
        lines.append('\t'.join([hx(o), anchor.role[va]] + ts +
                               [hx(site[0] - anchor.start) if site and site[0] else '-', str(site[1]) if site else '-']))
    (out_dir / 'call_sites.tsv').write_text('\n'.join(lines) + '\n')
    # dispatch.tsv: every jump-table entry, its arm and the class the reconstruction gives it
    lines = ['table\tindex\tmarker\tarm_offset\tarm_covered']
    ins_a = cover[anchor.start][0]
    for t, k, o in rows_a:
        mk = k if t == 'marker' else k + 0xc7
        if not 0 <= o < SIZE:
            raise Fault(f'{t} table entry {k} leaves the function')
        lines.append('\t'.join([t, str(k), '%02x' % mk, hx(o),
                                'yes' if anchor.start + o in ins_a else 'no']))
    (out_dir / 'dispatch.tsv').write_text('\n'.join(lines) + '\n')
    # lsda.tsv
    lines = ['start\tend\tlanding_pad\taction']
    for s, e, lp, a in anchor.sites:
        lines.append('\t'.join([hx(s - anchor.start), hx(e - anchor.start), hx(lp - anchor.start) if lp else '-', str(a)]))
    (out_dir / 'lsda.tsv').write_text('\n'.join(lines) + '\n')
    # coverage.tsv (anchor copy; the other copies' totals are in summary.json)
    insns, edges = cover[anchor.start]
    lines = ['offset\tbytes\top\tcovered\tjcc_taken\tjcc_not_taken']
    for i in anchor.insns:
        j = i.op == 'j'
        lines.append('\t'.join([hx(i.va - anchor.start), i.raw.hex(), i.op, 'yes' if i.va in insns else 'no',
                                ('yes' if (i.va, True) in edges else 'no') if j else '-',
                                ('yes' if (i.va, False) in edges else 'no') if j else '-']))
    (out_dir / 'coverage.tsv').write_text('\n'.join(lines) + '\n')
    # cases.tsv: base cases with the agreed outcome (anchor constants)
    m = Machine(img, anchor)
    lines = ['id\tinput\tpeek\tname\tflag\tdepth\tvisit\talloc\tthrows\toutcome\tresult\tcalls\tdes_after']
    for n, c in enumerate(base):
        r = m.run(c)
        lines.append('\t'.join([str(n)] + case_row(c) + [r[0], r[1], calls_text(r[2]), r[3]]))
    (out_dir / 'cases.tsv').write_text('\n'.join(lines) + '\n')
    # outcomes by class, all cases
    counts = {}
    for c in cases:
        r = m.run(c)
        key = r[0] + ':' + (r[2][0][0] if r[2] else '-')
        counts[key] = counts.get(key, 0) + 1
    summary['outcomes'] = {k: counts[k] for k in sorted(counts)}
    # mutants.tsv
    lines = ['kind\tname\tchanged_cases']
    killed = 0
    for v in MODEL_VARIANTS:
        bad, _, _ = compare(img, anchor, cases, v)
        killed += bool(bad)
        lines.append('\t'.join(['model', v, str(len(bad))]))
    mbase = base
    for mt in IMAGE_MUTANTS:
        n = run_mutant(img, anchor, mt, mbase)
        killed += bool(n)
        lines.append('\t'.join(['image', '%s %s' % (hx(mt[0]) if isinstance(mt[0], int) else mt[0], mt[3]), str(n)]))
    (out_dir / 'mutants.tsv').write_text('\n'.join(lines) + '\n')
    summary['mutants'] = {'model': len(MODEL_VARIANTS), 'image': len(IMAGE_MUTANTS), 'killed': killed}
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, help='directory for the generated evidence files')
    ap.add_argument('--binary', default=str(BINARY))
    a = ap.parse_args()
    s = generate(a.out, Path(a.binary).read_bytes())
    print(json.dumps({'cases': s['cases'], 'copies': s['copies'], 'mutants': s['mutants']}, sort_keys=True))
    total = s['mutants']['model'] + s['mutants']['image']
    return 0 if s['mutants']['killed'] == total else 1


if __name__ == '__main__':
    sys.exit(main())
