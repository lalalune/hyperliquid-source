#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack `deserialize_any` value reader and its ext / bytes visitors.

serde's `ContentVisitor` path turns one rmp_serde marker into a `Content` value.  The
inlined body of that call is one 2,074-byte function per deserializer copy
(value reader, called by the visit_map / visit_seq collectors and by the
TagOrContent key reader):

  value reader  0x17fb290  0x2f7f5e0  0x47d2470   (frame 0xb0)
  ext visitor   0x21e1930  0x3b69ad0  0x57afa00   (727 B, `{tag: i8, data: bytes}` as Content::Seq)
  bytes visitor 0x21e2670  0x57afce0              (413 B, a byte slice as Content::Seq of U8)
  primitive     0x14b9940                         (665 B, shared leaf that builds the scalar Contents)

The value reader consumes the peek slot or one marker byte, dispatches through a
225-entry relative jump table (disc 0..0xe0) and an 18-entry ext table, hands scalars
to the primitive leaf, borrows str / bin payloads, validates UTF-8, runs the
depth budget around map / array / ext collectors, checks the remaining element
count after a collector and boxes the ext Seq as Content::Newtype.

This tool:
1. checks the input digest, finds every copy's FDE extent and LSDA, decodes each
   instruction with a fixed-pattern x86-64 subset decoder, binds every call site
   to a role by its offset (copies must share the anchor layout byte for byte
   outside call targets and rip-relative operands) and dumps both jump tables;
2. interprets the original bytes (the binary is never run) with contract stubs for
   the collectors, allocator, grow, drops and UTF-8 validation; the primitive leaf
   runs as real code inside the value reader;
3. compares every outcome with a pure reconstruction (`Model*` below): result
   bytes, the callee sequence with semantic arguments, the deserializer and access
   state written back, and the heap blocks;
4. proves that wrong reconstructions, corrupted images and out-of-range inputs
   are rejected.
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

PRIM, PRIM_SIZE = 0x14b9940, 665
KINDS = {
    'vr': {'funcs': (0x17fb290, 0x2f7f5e0, 0x47d2470), 'size': 2074, 'frame': 0xb0,
           'direct': {0x21e0380: 'map', 0x21e1c10: 'seq', 0x21e1930: 'ext', 0x18a33d0: 'drop_content',
                      0x187d4e0: 'drop_result', 0x21d8eb0: 'drop_ext'},
           'tables': ((0x7e, 'marker', 0xe1), (0xbf, 'ext', 18))},
    'ext': {'funcs': (0x21e1930, 0x3b69ad0, 0x57afa00), 'size': 727, 'frame': 0x78,
            'direct': {0x230ce30: 'drop_elem', 0x21d8eb0: 'drop_content', 0x21dbd40: 'drop_vec'}, 'tables': ()},
    'bytes': {'funcs': (0x21e2670, 0x57afce0), 'size': 413, 'frame': 0x58,
              'direct': {0x21d8eb0: 'drop_content', 0x21dbd40: 'drop_vec'}, 'tables': ()},
}
GOT_ROLES = {0x64dffb0: 'prim', 0x64dfca8: 'from_utf8', 0x64df520: 'panic_add', 0x64df848: 'panic_sub',
             0x64df480: 'alloc', 0x64df490: 'alloc_error', 0x64df498: 'alloc_error', 0x64df4a0: 'free',
             0x64e13c0: 'grow', 0x64e13b8: 'grow', 0x64df4c0: 'terminate'}
RESUME_SYMBOL = '_Unwind_Resume'
EOF_LEAS = {'vr': (0x3ce, 0x4dd), 'ext': (0x1eb,)}   # rip-relative loads of the static EOF io::Error
UNWINDS = ('panic_add', 'panic_sub', 'alloc_error')   # never return; they unwind

NO_PEEK = 1                      # Option<Marker>::None niche in the peek slot
EOF_PRIM, EOF_VR, EOF_SHORT = 0x63f8470, 0x641ccb0, 0x2500000003
OUT_BASE, ACC_BASE, DES_BASE, IN_BASE = 0x7100_0000_0000, 0x7180_0000_0000, 0x7190_0000_0000, 0x7500_0000_0000
HEAP_BASE, STACK_TOP = 0x7400_0000_0000, 0x7200_0000_0000
MASK64 = (1 << 64) - 1
OUT_FILL, STACK_FILL, DES_FILL, ACC_FILL, HEAP_FILL = 0xaa, 0x5c, 0x3d, 0x2b, 0xee
OUT_SIZE, DES_SIZE, ACC_SIZE = 0x30, 0x28, 0x20
EXC = 0xe0c0_0000_0001           # exception object token handed to landing pads
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
    elif op == 0xf7:
        reg, rm = modrm()
        if reg & 7 != 2 or rm[0] != 'r':
            raise Fault(f'unsupported f7 form at {va:#x}')
        ins.op, ins.a = 'not', rm
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
        elif 0xc8 <= op2 <= 0xcf:
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




class Stop(Exception):
    pass


class Throw(Exception):
    pass


def fde_info(img, start):
    f = fde_of(img.data, start)
    return f['end'], f.get('lsda') or 0


class Fn:
    """Static facts of one body copy, all read from the bytes."""

    def __init__(self, img, kind, start, anchor=None):
        k = KINDS[kind]
        self.kind, self.start = kind, start
        self.end, self.lsda = fde_info(img, start)
        if self.end - start != k['size']:
            raise Fault(f'{start:#x}: FDE extent is {self.end - start} bytes')
        self.sites = img.call_sites(self.lsda, start) if self.lsda else []
        self.insns = sweep(img, start, self.end)
        self.cache = {i.va: i for i in self.insns}
        subs = [i for i in self.insns if i.op == 'sub' and i.a == ('r', 4) and i.b[0] == 'i']
        if not subs or subs[0].b[1] != k['frame']:
            raise Fault(f'{start:#x}: frame size is not {k["frame"]:#x}')
        self.role, self.targets, self.tables = {}, {}, {}
        self.eof = None
        for off in EOF_LEAS.get(kind, ()):
            ins = self.cache[start + off]
            if ins.op != 'lea':
                raise Fault(f'{start:#x}+{off:#x} is not the EOF lea')
            if self.eof not in (None, lea_target(ins)):
                raise Fault(f'{start:#x}: two different EOF constants')
            self.eof = lea_target(ins)
        for i in self.insns:
            if i.op not in ('call', 'callr'):
                continue
            o = i.va - start
            if i.op == 'callr':
                slot = i.va + i.size + i.a[4]
                if i.a[0] != 'm' or not i.a[5] or slot not in GOT_ROLES:
                    raise Fault(f'{i.va:#x}: indirect call is not through a known GOT slot')
                role, t = GOT_ROLES[slot], img.relative.get(slot, slot)
            else:
                t = i.va + i.size + i.b
                if img.read(t, 2) == b'\xff\x25' and img.plt_symbol(t) == RESUME_SYMBOL:
                    role = 'resume'
                elif anchor is None:
                    if t not in k['direct']:
                        raise Fault(f'{i.va:#x}: direct call target {t:#x} has no role')
                    role = k['direct'][t]
                else:
                    role = anchor.role.get(anchor.start + o)
                    if role is None:
                        raise Fault(f'{i.va:#x}: call offset +{o:#x} is not a call in the anchor copy')
            self.role[i.va] = role
            self.targets.setdefault(role, set()).add(t)
        for off, name, n in k['tables']:
            ins = self.cache[start + off]
            if ins.op != 'lea':
                raise Fault(f'{start:#x}+{off:#x} is not the table lea')
            self.tables[name] = (lea_target(ins), n)
        if anchor is not None:
            same = [a.raw == b.raw for a, b in zip(anchor.insns, self.insns) if a.op not in ('call', 'lea', 'callr')]
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
        rows = []
        for name, (t, n) in sorted(self.tables.items()):
            for idx, va in enumerate(img.table(t, n)):
                rows.append((name, idx, va - self.start))
        return rows


class Prim:
    """The shared primitive leaf: decoded and run as real code inside the value reader."""

    def __init__(self, img):
        self.start = PRIM
        self.end, lsda = fde_info(img, PRIM)
        if self.end - PRIM != PRIM_SIZE or lsda:
            raise Fault('primitive leaf extent or LSDA differs')
        self.insns = sweep(img, PRIM, self.end)
        self.cache = {i.va: i for i in self.insns}
        if any(i.op in ('call', 'callr') for i in self.insns):
            raise Fault('primitive leaf is not a leaf')


def load_fns(img):
    fns = {}
    for kind, k in KINDS.items():
        anchor = Fn(img, kind, k['funcs'][0])
        fns[kind] = [anchor] + [Fn(img, kind, s, anchor) for s in k['funcs'][1:]]
    return fns


class Machine:
    def __init__(self, img, fn, prim):
        self.img, self.f, self.prim = img, fn, prim
        self.cache = dict(fn.cache)
        self.cache.update(prim.cache)
        self.kind = fn.kind

    def setup(self, c):
        self.case = c
        buf = c['buf']
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.des = bytearray([DES_FILL]) * DES_SIZE
        self.acc = bytearray([ACC_FILL]) * ACC_SIZE
        self.inp = bytearray(buf)
        self.stack = bytearray([STACK_FILL]) * 0x200
        self.heap = []
        self.calls, self.edges, self.trace = [], set(), []
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[4] = OUT_BASE, STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.frame_lo = None
        self.r[8], self.r[9] = 0x4000_0000_0000_0000, 0x5000_0000_0000_0000
        if self.kind == 'bytes':
            p, e, n = c['slice']
            struct.pack_into('<QQQ', self.acc, 0, p, e, n)
            self.r[6] = ACC_BASE
        else:
            peek = c['peek']
            struct.pack_into('<QQBBH', self.des, 0x10, IN_BASE, len(buf),
                             NO_PEEK if peek is None else peek[0], 0x77 if peek is None else peek[1], c['depth'])
            if self.kind == 'ext':
                struct.pack_into('<QIB', self.acc, 0, DES_BASE, c['n'], c['state'])
                self.r[6] = ACC_BASE
            else:
                self.r[6] = DES_BASE

    def run(self, c):
        self.setup(c)
        pc = self.f.start
        try:
            for _ in range(3_000_000 if self.kind == 'bytes' else 60000):
                ins = self.cache.get(pc)
                if ins is None:
                    raise Fault(f'left the function or jumped into an instruction at {pc:#x}')
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

    def state(self):
        d = struct.unpack_from('<QQBBH', self.des, 0x10)
        st = (d[0] - IN_BASE, d[1], d[2], d[3], d[4])
        if self.kind == 'ext':
            st += struct.unpack_from('<QIB', self.acc, 0)[1:]
        if self.kind == 'bytes':
            st = ('-',)
        return st

    def result(self, kind):
        return (kind, bytes(self.out), tuple(self.calls), self.state(), tuple(h16(b) for _, b in self.heap))

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
        for base, buf in [(OUT_BASE, self.out), (DES_BASE, self.des), (ACC_BASE, self.acc), (IN_BASE, self.inp),
                          (STACK_TOP - len(self.stack), self.stack)] + self.heap:
            if base <= a <= base + len(buf):
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
            self.flags['c'] = c
            self.put(ins.a, w, r, nxt)
        elif op == 'rol':
            v, n = self.get(ins.a, w, nxt), ins.b % w
            self.put(ins.a, w, (v << n | v >> (w - n)) if n else v, nxt)
            self.flags['c'] = self.flags['o'] = None
        elif op == 'shl':
            v = self.get(ins.a, w, nxt)
            r = self.setf(w, v << ins.b)
            self.put(ins.a, w, r, nxt)
            self.flags['c'] = self.flags['o'] = None
        elif op == 'not':
            self.put(ins.a, w, ~self.get(ins.a, w, nxt), nxt)
        elif op == 'bswap':
            v = self.get(ins.a, w, nxt)
            self.put(ins.a, w, int.from_bytes(v.to_bytes(w // 8, 'little'), 'big'), nxt)
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
            if self.r[4] == STACK_TOP - 8:
                return 'ret'
            ret = int.from_bytes(self.load(self.r[4], 8), 'little')
            self.r[4] += 8
            return ret
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
        if a == DES_BASE:
            return 'des'
        if a == ACC_BASE:
            return 'acc'
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
        self.heap.append((base, bytearray([HEAP_FILL]) * n))
        return base

    def clobber(self):
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n

    def call(self, ins, nxt):
        r, role = self.r, self.f.role[ins.va]
        if role == 'prim':
            r[4] -= 8
            self.store(r[4], nxt.to_bytes(8, 'little'))
            return PRIM
        off = ins.va - self.f.start
        throws = (len(self.calls) in self.case.get('throws', ()) and role not in ('resume', 'terminate')) or role in UNWINDS
        saved = (bytes(self.out), bytes(self.stack), bytes(self.acc), bytes(self.des))
        try:
            rec, ret = self.stub(role, r, off, throws)
        except (IndexError, TypeError, ValueError, KeyError, struct.error) as e:
            raise Fault(f'callee contract violated by {role}: {e}')
        if throws:
            self.out[:], self.stack[:], self.acc[:], self.des[:] = saved
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
        body = self.load(ptr, n * 32) if n else b''
        return cap, self.where(ptr), n, h16(body)

    def stub(self, role, r, off, throws):
        c, w = self.case, self.where
        v = c.get('visit', ('ok', 0, 0x15))
        if role in ('map', 'seq'):
            de, n = struct.unpack('<QI', self.load(r[6], 12))
            rec = (role, w(r[7]), w(r[6]), w(de), n, struct.unpack_from('<H', self.des, 0x22)[0])
            if v[0] == 'err':
                self.store(r[7], struct.pack('<Q', 1) + pattern('verr', n=32))
            else:
                self.store(r[7], struct.pack('<Q', 0) + bytes([v[2]]) + pattern('vok', n=31))
                self.store(r[6] + 8, struct.pack('<I', v[1]))
            if c.get('vdepth') is not None:
                self.store(DES_BASE + 0x22, struct.pack('<H', c['vdepth']))
            return rec, None
        if role == 'ext':
            de, n, st = struct.unpack('<QIB', self.load(r[6], 13))
            rec = ('ext', w(r[7]), w(r[6]), n, st, struct.unpack_from('<H', self.des, 0x22)[0])
            if v[0] == 'err':
                self.store(r[7], struct.pack('<Q', 1) + pattern('xerr', n=32))
            else:
                self.store(r[7], struct.pack('<Q', 0) + bytes([v[2]]) + pattern('xok', n=31))
            if c.get('vdepth') is not None:
                self.store(DES_BASE + 0x22, struct.pack('<H', c['vdepth']))
            return rec, None
        if role == 'from_utf8':
            raw = self.load(r[6], r[2]) if r[2] else b''
            rec = ('from_utf8', w(r[7]), w(r[6]), r[2])
            try:
                raw.decode('utf-8')
                self.store(r[7], struct.pack('<QQQ', 0, r[6] + c.get('utf8_shift', 0), r[2] - c.get('utf8_trim', 0)))
            except UnicodeDecodeError as e:
                self.store(r[7], struct.pack('<QQQ', 1, e.start, 0x0101))
            return rec, None
        if role == 'alloc':
            if not c.get('alloc_ok', True) or throws:
                return ('alloc', r[7]), 0
            return ('alloc', r[7]), self.new_block(r[7])
        if role == 'alloc_error':
            return ('alloc_error', r[7] & 0xffffffff, r[6]), None
        if role in ('panic_add', 'panic_sub'):
            return (role, off), None
        if role == 'grow':
            cap, ptr, n = struct.unpack('<QQQ', self.load(r[7], 24))
            rec = ('grow', w(r[7]), cap, n)
            if not throws:
                new = max(2 * cap, 4)
                base = self.new_block(new * 32)
                self.store(base, self.load(ptr, n * 32) if n else b'')
                self.store(r[7], struct.pack('<QQ', new, base))
            return rec, None
        if role == 'free':
            return ('free', w(r[7]), r[6], r[2] & 0xffffffff), None
        if role in ('drop_content', 'drop_ext'):
            return (role, w(r[7]), self.load(r[7], 1)[0]), None
        if role == 'drop_elem':
            return ('drop_elem', w(r[7]), self.load(r[7], 32).hex()), None
        if role == 'drop_result':
            return ('drop_result', w(r[7]), self.load(r[7], 1)[0]), None
        if role == 'drop_vec':
            return ('drop_vec', w(r[7])) + self.vec_rec(r[7]), None
        if role in ('terminate', 'resume'):
            return (role,), None
        raise Fault(f'no stub for {role}')


# reconstruction ------------------------------------------------------------------
VR_VARIANTS = ('depth_off_by_one', 'no_depth_restore_ok', 'depth_restore_on_err', 'left_check_off',
               'bad_utf8_is_str', 'ext_len_is_u16', 'newtype_tag_14', 'prim_i8_unsigned',
               'fixext_len_2x', 'peek_not_consumed', 'str_eof_advances', 'ext_eof_no_advance', 'map16_is_seq',
               'out_ptr_not_utf8_result', 'mismatch_count_total')
EXT_VARIANTS = ('state0_no_next', 'bytes_tag_5', 'bad_state_tag', 'no_free_on_err')
BYTES_VARIANTS = ('cap_unclamped', 'tag_u16', 'no_overflow_panic', 'grow_early', 'off_by_one_len')


def be(buf, pos, n):
    return int.from_bytes(buf[pos:pos + n], 'big')


class Sim:
    """State shared by the three reconstructions: input cursor, calls, heap, frame."""

    def __init__(self, c, variant, fsize, eof=EOF_VR):
        self.c, self.v, self.eof_ptr = c, variant, eof
        self.buf = c['buf']
        self.pos, self.rem = 0, len(self.buf)
        self.calls, self.heap = [], []
        self.throws = set(c.get('throws', ()))
        self.fr = bytearray([STACK_FILL]) * fsize
        self.out = bytearray([OUT_FILL]) * OUT_SIZE

    def site(self, rec, pad=None, unwinds=False):
        """Record a callee call; a call that unwinds runs its landing pad or escapes."""
        thr = unwinds or len(self.calls) in self.throws
        self.calls.append(rec + ('!',) if thr else rec)
        if not thr:
            return
        if pad is None:
            raise Stop('escape')
        self.run_pad(pad)

    def run_pad(self, steps):
        for s in steps:
            thr = len(self.calls) in self.throws
            self.calls.append(s + ('!',) if thr else s)
            if thr:
                self.calls.append(('terminate',))
                raise Stop('terminate')
        self.calls.append(('resume',))
        raise Stop('resume')

    def alloc(self, n):
        self.heap.append(bytearray([HEAP_FILL]) * n)
        return len(self.heap) - 1

    def finish(self, kind, state):
        return (kind, bytes(self.out), tuple(self.calls), state, tuple(h16(b) for b in self.heap))


class ModelVR(Sim):
    """The value reader (0x17fb290 and its copies)."""

    def __init__(self, c, variant=None, eof=EOF_VR):
        super().__init__(c, variant, 0xb8, eof)
        peek = c['peek']
        self.flag, self.data = (NO_PEEK, 0x77) if peek is None else peek
        self.depth = c['depth']

    def run(self):
        try:
            self.body()
            kind = 'ret'
        except Stop as s:
            kind = s.args[0]
        return self.finish(kind, (self.pos, self.rem, self.flag, self.data, self.depth))

    def err(self, tag, payload=None, b9=None, ba=None):
        self.out[0:8] = struct.pack('<Q', 1)
        self.out[8] = tag
        if b9 is not None:
            self.out[9] = b9
        if ba is not None:
            self.out[10] = ba
        if payload is not None:
            self.out[0x10:0x18] = struct.pack('<Q', payload)
        raise Stop('ret')

    def eof(self, k=None):
        self.err(1, self.eof_ptr)

    def body(self):
        flag, data = self.flag, self.data
        if self.v != 'peek_not_consumed':
            self.flag = 1
        if flag != NO_PEEK:
            return self.dispatch(flag, flag, data)
        if self.rem == 0:
            self.err(0, self.eof_ptr)
        b = self.buf[self.pos]
        self.pos += 1
        self.rem -= 1
        if b < 0x80:
            return self.prim(0, b)
        if b >= 0xe0:
            return self.prim(0xe0, b)
        if b < 0x90:
            return self.collect('map', b & 0xf)
        if b < 0xa0:
            return self.collect('seq', b & 0xf)
        if b < 0xc0:
            return self.string(b & 0x1f)
        return self.dispatch(b, b, b & 0x1f)

    # table arms -----------------------------------------------------------------
    def dispatch(self, disc, al, dl):
        v = self.v
        if disc in (0, 0xc0, 0xc2, 0xc3, 0xe0) or 0xca <= disc <= 0xd3:
            return self.prim(disc, dl)
        if disc == 0x80:
            return self.collect('map', dl)
        if disc == 0x90:
            return self.collect('seq', dl)
        if disc == 0xa0:
            return self.string(dl)
        if disc == 0xc1:
            self.err(2, None, 0xc1)
        if disc in (0xc4, 0xc5, 0xc6):
            return self.binary(self.length({0xc4: 1, 0xc5: 2, 0xc6: 4}[disc]))
        if disc in (0xd9, 0xda, 0xdb):
            return self.string(self.length({0xd9: 1, 0xda: 2, 0xdb: 4}[disc]))
        if disc in (0xdc, 0xdd):
            return self.collect('seq', self.length({0xdc: 2, 0xdd: 4}[disc]))
        if disc in (0xde, 0xdf):
            return self.collect('seq' if v == 'map16_is_seq' else 'map', self.length({0xde: 2, 0xdf: 4}[disc]))
        if disc in (0xc7, 0xc8, 0xc9):
            n = self.length({0xc7: 1, 0xc8: 2, 0xc9: 4}[disc], ext=(al, dl))
            return self.ext(n)
        if 0xd4 <= disc <= 0xd8:
            return self.ext(2 * (1 << (disc - 0xd4)) if v == 'fixext_len_2x' else 1 << (disc - 0xd4))
        raise Stop('ud2')

    def length(self, size, ext=None):
        if self.rem < size:
            left = self.rem
            if size > 1 and self.v != 'ext_eof_no_advance':
                self.pos += self.rem
                self.rem = 0
            if ext is not None:
                self.err(1, self.eof_ptr, ext[0], ext[1] if size == 1 else left & 0xff)
            self.eof()
        if self.v == 'ext_len_is_u16' and size == 4:
            size = 2
        n = be(self.buf, self.pos, size)
        self.pos += size
        self.rem -= size
        return n

    def prim(self, disc, cl):
        o = self.out
        o[0:8] = bytes(8)
        if disc == 0 or disc == 0xe0:
            o[8], o[9] = (1, cl) if disc == 0 else (5, cl)
            return
        if disc == 0xc0:
            o[8] = 0x12
            return
        if disc in (0xc2, 0xc3):
            o[8], o[9] = 0, disc - 0xc2
            return
        kind = {0xca: (4, 9, 0xc), 0xcb: (8, 0xa, 0x10), 0xcc: (1, 1, 9), 0xcd: (2, 2, 0xa), 0xce: (4, 3, 0xc),
                0xcf: (8, 4, 0x10), 0xd0: (1, 5, 9), 0xd1: (2, 6, 0xa), 0xd2: (4, 7, 0xc), 0xd3: (8, 8, 0x10)}[disc]
        n, tag, at = kind
        if self.rem < n:
            if n > 1:
                self.pos += self.rem
                self.rem = 0
            o[0:8] = struct.pack('<Q', 1)
            o[8] = 1
            o[0x10:0x18] = struct.pack('<Q', EOF_PRIM)
            return
        val = be(self.buf, self.pos, n)
        if self.v == 'prim_i8_unsigned' and disc == 0xd0:
            tag = 1
        self.pos += n
        self.rem -= n
        o[8] = tag
        o[at:at + n] = val.to_bytes(n, 'little')

    def string(self, n):
        if n > self.rem:
            if self.v == 'str_eof_advances':
                self.pos += self.rem
                self.rem = 0
            self.err(1, EOF_SHORT)
        ptr = self.pos
        self.pos += n
        self.rem -= n
        self.site(('from_utf8', 'sp+8', 'in+%x' % ptr, n))
        raw = self.buf[ptr:ptr + n]
        shift, trim = self.c.get('utf8_shift', 0), self.c.get('utf8_trim', 0)
        try:
            raw.decode('utf-8')
            tag, p, ln = 0xd, ptr + shift, n - trim
            if self.v == 'out_ptr_not_utf8_result':
                p, ln = ptr, n
        except UnicodeDecodeError:
            tag, p, ln = (0xd if self.v == 'bad_utf8_is_str' else 0xf), ptr, n
        self.out[0:8] = bytes(8)
        self.out[8] = tag
        self.out[0x10:0x20] = struct.pack('<QQ', IN_BASE + p, ln)
        raise Stop('ret')

    def binary(self, n):
        if n > self.rem:
            self.err(1, EOF_SHORT)
        ptr = self.pos
        self.pos += n
        self.rem -= n
        self.out[0:8] = bytes(8)
        self.out[8] = 0xf
        self.out[0x10:0x20] = struct.pack('<QQ', IN_BASE + ptr, n)
        raise Stop('ret')

    # collectors ------------------------------------------------------------------
    def depth_enter(self, panic_off):
        if self.depth == 0:
            self.site(('panic_sub', panic_off), None, unwinds=True)
        self.depth -= 1
        if self.v == 'depth_off_by_one':
            self.depth -= 1
        if self.depth == 0:
            self.err(8)

    def depth_leave(self, off, pad):
        if self.depth == 0xffff:
            self.site(('panic_add', off), pad, unwinds=True)
        self.depth += 1

    def collect(self, kind, n):
        fr = self.fr
        poff, soff, doff, fin = (0x759, 0x136, 0x1a7, 0x5e5) if kind == 'map' else (0x775, 0x1f0, 0x45f, 0x782)
        self.depth_enter(poff)
        struct.pack_into('<I', fr, 0x88, n)
        c = self.c
        self.site((kind, 'sp+8', 'sp+80', 'des', n, self.depth))
        v = c.get('visit', ('ok', 0, 0x15))
        if v[0] == 'err':
            fr[8:0x30] = struct.pack('<Q', 1) + pattern('verr', n=32)
        else:
            fr[8:0x30] = struct.pack('<Q', 0) + bytes([v[2]]) + pattern('vok', n=31)
            struct.pack_into('<I', fr, 0x88, v[1])
        if c.get('vdepth') is not None:
            self.depth = c['vdepth']
        fr[0x60:0x80] = fr[0x10:0x30]
        if struct.unpack_from('<I', fr, 8)[0] == 1:
            self.out[0:8] = struct.pack('<Q', 1)
            self.out[8:0x28] = fr[0x60:0x80]
            if self.v == 'depth_restore_on_err':
                self.depth += 1
            raise Stop('ret')
        fr[0x90:0xb0] = fr[0x60:0x80]
        left = struct.unpack_from('<I', fr, 0x88)[0]
        if left == 0 and self.v != 'left_check_off':
            fr[0x38:0x58] = fr[0x90:0xb0]
            fr[0x30:0x38] = bytes(8)
        else:
            if self.v == 'left_check_off':
                left = 0
            diff = n - left
            if diff < 0:
                self.site(('panic_sub', 0x791 if kind == 'map' else 0x7a0), [('drop_content', 'sp+90', fr[0x90])],
                          unwinds=True)
            fr[0x38] = 4
            struct.pack_into('<I', fr, 0x3c, diff if self.v != 'mismatch_count_total' else n)
            fr[0x30:0x38] = struct.pack('<Q', 1)
            self.site(('drop_content', 'sp+90', fr[0x90]))
        if self.v != 'no_depth_restore_ok':
            self.depth_leave(fin, [('drop_result', 'sp+30', fr[0x30])])
        self.out[:0x28] = fr[0x30:0x58]
        raise Stop('ret')

    def ext(self, n):
        fr = self.fr
        self.depth_enter(0x74c)
        struct.pack_into('<IB', fr, 0x68, n, 0)
        c = self.c
        self.site(('ext', 'sp+8', 'sp+60', n, 0, self.depth))
        v = c.get('visit', ('ok', 0, 0x15))
        if v[0] == 'err':
            fr[8:0x30] = struct.pack('<Q', 1) + pattern('xerr', n=32)
        else:
            fr[8:0x30] = struct.pack('<Q', 0) + bytes([v[2]]) + pattern('xok', n=31)
        if c.get('vdepth') is not None:
            self.depth = c['vdepth']
        if fr[8] == 0:
            fr[0x30:0x50] = fr[0x10:0x30]
            self.site(('alloc', 32))
            if not c.get('alloc_ok', True):
                self.site(('alloc_error', 8, 32), [('drop_ext', 'sp+30', fr[0x30])], unwinds=True)
            blk = self.alloc(32)
            self.heap[blk][:] = fr[0x10:0x30]
            fr[0x10] = 0x14 if self.v == 'newtype_tag_14' else 0x13
            fr[0x18:0x20] = struct.pack('<Q', HEAP_BASE + blk * 0x1000_0000)
            fr[8:0x10] = bytes(8)
        if self.v != 'no_depth_restore_ok':
            self.depth_leave(0x766, [('drop_result', 'sp+8', fr[8])])
        self.out[:0x28] = fr[8:0x30]
        raise Stop('ret')


class ModelExt(Sim):
    """The ext visitor (0x21e1930 and copies): `{tag: i8, data: bytes}` collected as a Vec<Content>."""

    def __init__(self, c, variant=None, eof=EOF_VR):
        super().__init__(c, variant, 0x80, eof)
        self.n, self.state, self.depth = c['n'], c['state'], c['depth']

    def run(self):
        try:
            self.body()
            kind = 'ret'
        except Stop as s:
            kind = s.args[0]
        return self.finish(kind, (self.pos, self.rem, 1, 0x77, self.depth, self.n, self.state))

    def push(self, item):
        if self.k == self.cap or (self.v == 'grow_early' and self.k + 1 == self.cap):
            self.sync()
            self.site(('grow', 'sp+8', self.cap, self.k), [('drop_content', 'sp+58', item[0]),
                                                         self.drop_vec_rec()])
            new = max(2 * self.cap, 4)
            self.heap.append(bytearray([HEAP_FILL]) * (new * 32))
            self.blk, self.cap = len(self.heap) - 1, new
        self.heap[self.blk][self.k * 32:self.k * 32 + 32] = item
        self.items.append(bytes(item))
        self.k += 1

    def sync(self):
        if self.blk is not None:
            body = b''.join(self.items)
            self.heap[self.blk][:len(body)] = body

    def drop_vec_rec(self):
        self.sync()
        ptr = 'h%d+0' % self.blk if self.blk is not None else 'v:8'
        return ('drop_vec', 'sp+8', self.cap, ptr, self.k, h16(b''.join(self.items)))

    def err(self, tag, al, rcx):
        self.out[0:8] = struct.pack('<Q', 1)
        self.out[8], self.out[9] = tag, al
        self.out[0x10:0x20] = struct.pack('<QQ', rcx, self.n)
        self.cleanup()

    def cleanup(self):
        self.sync()
        items = list(enumerate(self.items))
        if self.v == 'cleanup_reverse':
            items.reverse()
        for j, it in items:
            rec = ('drop_elem', 'h%d+%x' % (self.blk, j * 32), it.hex())
            thr = len(self.calls) in self.throws
            self.calls.append(rec + ('!',) if thr else rec)
            if thr:
                self.pad_rest(j + 1)
        if self.cap and self.v != 'no_free_on_err':
            self.site_free(('free', 'h%d+0' % self.blk, self.cap * 32, 0), 0x24c)
        raise Stop('ret')

    def site_free(self, rec, off):
        thr = len(self.calls) in self.throws
        self.calls.append(rec + ('!',) if thr else rec)
        if thr:
            raise Stop('no_call_site' if off == 0x24c else 'escape')

    def pad_rest(self, j):
        """A drop in the Err cleanup unwound: drop the rest, free, resume (pad 0x289)."""
        for i in range(j, self.k):
            rec = ('drop_elem', 'h%d+%x' % (self.blk, i * 32), self.items[i].hex())
            thr = len(self.calls) in self.throws
            self.calls.append(rec + ('!',) if thr else rec)
            if thr:
                self.calls.append(('terminate',))
                raise Stop('terminate')
        if self.cap:
            self.site_free(('free', 'h%d+0' % self.blk, self.cap * 32, 0), 0x2c3)
        self.calls.append(('resume',))
        raise Stop('resume')

    def body(self):
        self.cap, self.blk, self.items, self.k = 0, None, [], 0
        st = self.state
        self.sil = STACK_FILL      # [rsp+7]
        self.r8 = 0x5c5c5c5c5c5c5c5c   # [rsp+0x30]
        n = self.n
        if st == 2:
            return self.done()
        while True:
            if st == 0:
                if self.rem == 0:
                    self.err(1, self.sil, self.eof_ptr)
                b = self.buf[self.pos]
                self.pos += 1
                self.rem -= 1
                self.state = 1 if self.v != 'state0_no_next' else 2
                self.last = False
                tag = 5
                sil = b
                rdx, r8 = n, self.r8
                st = 1
            elif st == 1:
                if n > self.rem:
                    if self.v == 'data_len_unchecked':
                        pass
                    self.err(1, self.sil, EOF_SHORT)
                ptr = self.pos
                self.pos += n
                self.rem -= n
                self.state = 2
                tag = 0xf if self.v != 'bytes_tag_5' else 5
                st = 2
                self.last = True
                sil = self.sil
                rdx, r8 = n, IN_BASE + ptr
            else:
                self.err(st if self.v != 'bad_state_tag' else 3, 0xc1, self.r8)
            item = bytearray([STACK_FILL]) * 32
            item[0], item[1] = tag, sil
            self.sil = sil
            item[8:16] = struct.pack('<Q', r8)
            item[0x10:0x18] = struct.pack('<Q', rdx)
            self.r8 = r8
            self.push(item)
            if self.last:
                return self.done()

    def done(self):
        self.sync()
        self.out[0:8] = bytes(8)
        self.out[8] = 0x14
        ptr = HEAP_BASE + self.blk * 0x1000_0000 if self.blk is not None else 8
        self.out[9:0x10] = bytes([STACK_FILL]) * 7
        self.out[0x10:0x28] = struct.pack('<QQQ', self.cap, ptr, self.k)
        raise Stop('ret')


class ModelBytes(Sim):
    """The bytes visitor (0x21e2670, 0x57afce0): every byte becomes Content::U8 in a Vec<Content>."""

    def __init__(self, c, variant=None, eof=EOF_VR):
        super().__init__(c, variant, 0x60, eof)
        self.p, self.e, self.count = c['slice']

    def run(self):
        try:
            self.body()
            kind = 'ret'
        except Stop as s:
            kind = s.args[0]
        return self.finish(kind, ('-',))

    def sync(self):
        if self.blk is not None:
            body = b''.join(self.items)
            self.heap[self.blk][:len(body)] = body

    def body(self):
        p, e, count = self.p, self.e, self.count
        n = (e - p) & MASK64
        clamp = 0x8000 * (4 if self.v == 'cap_unclamped' else 1)
        cap = min(n, clamp)
        if p == 0 and self.v != 'null_start_allocs':
            cap = 0
        self.cap, self.blk, self.items = 0, None, []
        if cap:
            size = (cap << 5) & 0xffffffff
            self.site(('alloc', size))
            if not self.c.get('alloc_ok', True):
                self.site(('alloc_error', 8, size), None, unwinds=True)
            self.heap.append(bytearray([HEAP_FILL]) * size)
            self.blk, self.cap = 0, cap
        else:
            self.cap = 0
        i = 0
        if p != 0 and p != e:
            not_count = (~count) & MASK64
            while True:
                if not_count == i and self.v != 'no_overflow_panic':
                    self.sync()
                    self.site(('panic_add', 0x167), [self.drop_vec()], unwinds=True)
                b = self.buf[p - IN_BASE + i]
                item = bytearray([STACK_FILL]) * 32
                item[0], item[1] = (2 if self.v == 'tag_u16' else 1), b
                if i == self.cap or (self.v == 'grow_early' and i + 1 == self.cap):
                    self.sync()
                    self.site(('grow', 'sp+0', self.cap, i), [('drop_content', 'sp+38', 1), self.drop_vec()])
                    new = max(2 * self.cap, 4)
                    self.heap.append(bytearray([HEAP_FILL]) * (new * 32))
                    self.blk, self.cap = len(self.heap) - 1, new
                self.heap[self.blk][i * 32:i * 32 + 32] = item
                self.items.append(bytes(item))
                i += 1
                if p + i + (1 if self.v == 'off_by_one_len' else 0) == e:
                    break
        self.sync()
        self.out[0:8] = bytes(8)
        self.out[8] = 0x14
        self.out[9:0x10] = bytes([STACK_FILL]) * 7
        ptr = HEAP_BASE + self.blk * 0x1000_0000 if self.blk is not None else 8
        self.out[0x10:0x28] = struct.pack('<QQQ', self.cap, ptr, len(self.items))
        raise Stop('ret')

    def drop_vec(self):
        self.sync()
        ptr = 'h%d+0' % self.blk if self.blk is not None else 'v:8'
        return ('drop_vec', 'sp+0', self.cap, ptr, len(self.items), h16(b''.join(self.items)))


MODELS = {'vr': ModelVR, 'ext': ModelExt, 'bytes': ModelBytes}


def reconstructed(kind, case, variant=None, eof=EOF_VR):
    return MODELS[kind](case, variant, eof).run()


# cases ---------------------------------------------------------------------------
TAILS = (b'', b'\x00', b'\x03abc', b'\x02\x01\x02\x03\x04', b'\x00\x03xyz', b'\x00\x00\x00\x02hi', bytes(range(1, 18)),
         b'\xff' * 17, b'\x00\x05ab', b'\x80\xfe\xc3\x28\xa0\xa1\x00\x00\x01', b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')
DEPTHS = (1, 2, 9, 0, 0x400, 0xfffe)
VISITS = (('ok', 0, 0x15), ('ok', 0, 0x14), ('ok', 1, 0x15), ('err',), ('ok', 3, 0x00), ('ok', 0xffffffff, 0x14),
          ('ok', 0, 0x16), ('ok', 2, 0x17))
THROWS = ((), (), (), (0,), (1,), (2,))


def case(buf, peek=None, depth=0x400, **kw):
    c = {'buf': bytes(buf), 'peek': peek, 'depth': depth, 'n': 0, 'state': 0}
    c.update(kw)
    return c


def vr_cases(copy):
    k = 0
    for b in range(256):
        for j, t in enumerate(TAILS):
            k += 1
            kw = {'visit': VISITS[(k + copy) % len(VISITS)], 'throws': THROWS[(k * 7 + b) % len(THROWS)]}
            if k % 29 == 0:
                kw['alloc_ok'] = False
            if k % 31 == 0:
                kw['vdepth'] = 0xffff
            if k % 37 == 0:
                kw['utf8_shift'], kw['utf8_trim'] = 1, 1
            yield case(bytes([b]) + t, None, DEPTHS[(k + b) % len(DEPTHS)], **kw)
    for disc in range(0xe1):
        for d in (0, 1, 0x1f, 0x80, 0xff):
            for j, t in enumerate(TAILS[:7]):
                k += 1
                kw = {'visit': VISITS[(k + copy) % len(VISITS)], 'throws': THROWS[(k * 5 + disc) % len(THROWS)]}
                if k % 23 == 0:
                    kw['alloc_ok'] = False
                if k % 41 == 0:
                    kw['vdepth'] = 0xffff
                yield case(t, (disc, d), DEPTHS[(k + disc) % len(DEPTHS)], **kw)
    for n in (0, 1, 2, 3, 5):
        for left in (0, 1, 2, 3, 4, 6, 0xffffffff):
            for tag in (0x14, 0x15):
                for disc in (0x80, 0x90, 0xde, 0xdc):
                    yield case(b'\x00\x05' + b'x' * 8, (disc, n), 5, visit=('ok', left, tag))
    for dep in (0, 1, 2, 3, 0xfffe, 0xffff):
        for first in (0x91, 0x81, 0xd4, 0xc7, 0xdc, 0xde):
            for vd in (None, 0xffff, 0):
                kw = {} if vd is None else {'vdepth': vd}
                yield case(bytes([first]) + b'\x00\x01\x02\x03\x04\x05\x06', None, dep, **kw)


def ext_cases(copy):
    k = 0
    for state in (0, 1, 2, 3, 7):
        for n in (0, 1, 2, 5, 9):
            for t in TAILS[:9]:
                for thr in ((), (0,), (1,), (2,), (3,), (4,), (5,)):
                    k += 1
                    yield case(t, None, 0x400, n=n, state=state, throws=thr)
    for n in (0, 3, 70):
        yield case(bytes(range(1, 80)), None, 1, n=n, state=0)
        yield case(bytes(range(1, 80)), None, 1, n=n, state=1)


def bytes_cases(copy):
    data = bytes((7 * i + 3) & 0xff for i in range(70000))
    for n in (0, 1, 2, 3, 4, 5, 8, 9, 31, 33):
        for count in (0, 7, 0xfffffffffffffff0, 0xfffffffffffffffd, 0xfffffffffffffffe, 0xffffffffffffffff):
            for thr in ((), (0,), (1,), (2,), (3,)):
                if n == 0 and thr:
                    continue
                yield case(data[:n], None, 0, slice=(IN_BASE, IN_BASE + n, count), throws=thr,
                           alloc_ok=not (thr == (0,) and n % 2))
    yield case(b'', None, 0, slice=(0, 0, 0))
    yield case(b'', None, 0, slice=(0, 0, 5))
    for n in (0x8000, 0x8001, 0xc000):
        yield case(data[:n], None, 0, slice=(IN_BASE, IN_BASE + n, 0))
    for thr in ((1,), (2,)):   # the grow call and the pad's first drop unwind
        yield case(data[:0x8001], None, 0, slice=(IN_BASE, IN_BASE + 0x8001, 0), throws=thr)
    for n in (1, 5):
        yield case(data[:n], None, 0, slice=(IN_BASE, IN_BASE + n, 0), alloc_ok=False)
    yield case(b'abc', None, 0, slice=(IN_BASE, IN_BASE, 0))
    yield case(b'abc', None, 0, slice=(IN_BASE, IN_BASE, 0), alloc_ok=False)


GENS = {'vr': vr_cases, 'ext': ext_cases, 'bytes': bytes_cases}


class Patched(Image):
    def __init__(self, img, data):
        self.__dict__.update(img.__dict__)
        self.data = data


def hx(v):
    return v if isinstance(v, str) else '%#x' % v


def case_row(kind, ci, c):
    parts = [c['buf'].hex() or '-', '-' if c['peek'] is None else '%x:%x' % c['peek'], '%x' % c['depth']]
    if kind == 'ext':
        parts += ['%x' % c['n'], '%x' % c['state']]
    if kind == 'bytes':
        parts += ['%x:%x:%x' % tuple(x - (IN_BASE if i < 2 and x else 0) if i < 2 else x
                                     for i, x in enumerate(c['slice']))]
    v = c.get('visit')
    parts += ['-' if v is None else ':'.join('%x' % x for x in v[1:]) + ('E' if v[0] == 'err' else ''),
              ','.join(map(str, c.get('throws', ()))) or '-',
              ''.join(k[0] for k in ('alloc_ok',) if k in c) or '-']
    return parts


def calls_text(calls):
    return ';'.join(','.join(hx(x) if isinstance(x, int) and not isinstance(x, bool) else str(x) for x in rec)
                    for rec in calls) or '-'


def compare(img, fn, prim, cases, variant=None, limit=None):
    """Run the original bytes and the model over `cases`; returns (n, mismatches, machine, results)."""
    m = Machine(img, fn, prim)
    bad = 0
    for c in cases:
        try:
            got = m.run(c)
        except (Fault, Stop, IndexError, ValueError, MemoryError, struct.error) as e:
            got = ('fault', str(e))
        try:
            want = reconstructed(fn.kind, c, variant, fn.eof)
        except (IndexError, KeyError, ValueError, struct.error, OverflowError):
            want = ('model_fault',)   # only a wrong model leaves its own domain
        if got != want:
            bad += 1
            if limit and bad >= limit:
                break
    return bad


def mutate(img, kind, off, xor):
    data = bytearray(img.data)
    fo = img.off(KINDS[kind]['funcs'][0] + off)
    data[fo] ^= xor
    return Patched(img, bytes(data))


IMAGE_MUTANTS = (
    ('vr', (26, 35, 60, 81, 85, 98, 117, 186, 216, 258, 271, 343, 384, 392, 444, 457, 529, 582, 617, 666, 715, 781,
            819, 851, 904, 950, 997, 1030, 1080, 1088, 1151, 1217, 1337, 1410, 1497, 1548, 1561, 1606, 1643, 1696,
            1806)),
    ('ext', (60, 245, 253, 263, 276, 344, 438, 548, 575, 659, 686)),
    ('bytes', (61, 79, 123, 128, 192, 198, 221)),
)   # conditional-jump condition bits (xor 1) in the anchor copy; the run proves each one changes a result


def run_mutant(img, fn, prim, kind, off, cases):
    """Flip one conditional-jump condition in the anchor copy and report whether any case differs."""
    m = mutate(img, kind, off, 1)
    fm = Fn.__new__(Fn)
    fm.__dict__.update(fn.__dict__)
    try:
        fm.insns = sweep(m, fn.start, fn.end)
        fm.cache = {x.va: x for x in fm.insns}
        return compare(m, fm, prim, cases, limit=1)
    except (Fault, Stop, IndexError, KeyError, ValueError):
        return 1


def range_controls(img, fns, prim):
    """Corrupted digest, wrong boundaries and out-of-range inputs; each must be rejected."""
    res = []
    bad = bytearray(img.data)
    bad[len(bad) // 2] ^= 1
    try:
        Image(bytes(bad))
        res.append(('digest_flip', False))
    except ValueError:
        res.append(('digest_flip', True))
    for name, thunk in (
            ('start_not_fde', lambda: Fn(img, 'vr', KINDS['vr']['funcs'][0] + 1)),
            ('wrong_size_kind', lambda: Fn(img, 'bytes', KINDS['ext']['funcs'][0])),
            ('wrong_anchor', lambda: Fn(img, 'ext', KINDS['ext']['funcs'][1], fns['vr'][0])),
            ('anchor_is_other_copy', lambda: Fn(img, 'bytes', KINDS['bytes']['funcs'][1], fns['ext'][0])),
            ('sweep_overrun', lambda: sweep(img, fns['vr'][0].start, fns['vr'][0].end - 3)),
            ('unmapped_read', lambda: img.read(0x7fff_0000_0000, 4)),
            ('prim_wrong_extent', lambda: sweep(img, PRIM, PRIM + PRIM_SIZE - 2)),
    ):
        try:
            thunk()
            res.append((name, False))
        except (Fault, ValueError):
            res.append((name, True))
    m = Machine(img, fns['vr'][0], prim)
    try:
        got = m.run(case(b'', (0xe1, 0), 5))   # disc past the 225-entry table
        res.append(('disc_past_table', got[0] != 'ret'))
    except (Fault, Stop, IndexError, ValueError):
        res.append(('disc_past_table', True))
    try:
        got = m.run(case(b'\xa5ab', None, 5))   # str longer than the input
        res.append(('str_past_input', got[0] == 'ret' and got[1][0] == 1))
    except Fault:
        res.append(('str_past_input', False))
    return res


def table_rows(fns, img):
    for kind in ('vr',):
        for fn in fns[kind]:
            for name, idx, arm in fn.table_rows(img):
                yield kind, fn.start, name, idx, arm


def generate(out_dir, data=None):
    data = data if data is not None else Path(BINARY).read_bytes()
    img = Image(data)
    fns = load_fns(img)
    prim = Prim(img)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    tsv = {n: [] for n in ('functions', 'call_sites', 'lsda', 'tables', 'coverage', 'cases', 'mutants')}
    tsv['functions'].append('kind\tstart\tsize\tlsda\tinsns\tcalls\tframe\teof_constant')
    tsv['call_sites'].append('kind\toffset\trole\ttargets_per_copy\tpad\taction')
    tsv['lsda'].append('kind\tstart\tend\tlanding_pad\taction')
    tsv['tables'].append('kind\tcopy\ttable\tindex\tarm_offset')
    tsv['coverage'].append('kind\toffset\top\tsize\tcovered\tedges')
    tsv['cases'].append('kind\tcopy\tindex\tbuf\tpeek\tdepth\tparams\tvisit\tthrows\tflags\toutcome\tout\tcalls\tstate')
    tsv['mutants'].append('kind\tcontrol\tdetected')
    total, mismatches, outcomes, controls = 0, 0, {}, []
    for kind, k in KINDS.items():
        for ci, fn in enumerate(fns[kind]):
            calls = sum(1 for i in fn.insns if i.op in ('call', 'callr'))
            tsv['functions'].append('\t'.join(map(str, (kind, hx(fn.start), k['size'], hx(fn.lsda), len(fn.insns), calls,
                                                        hx(k['frame']), hx(fn.eof) if fn.eof else '-'))))
            for s, e, lp, a in fn.sites:
                tsv['lsda'].append('%s\t%s\t%s\t%s\t%s' % (kind, hx(s - fn.start), hx(e - fn.start),
                                                           hx(lp - fn.start) if lp else '-', a))
        anchor = fns[kind][0]
        for i in anchor.insns:
            if i.va in anchor.role:
                o = i.va - anchor.start
                tg = ','.join(hx(sorted(f.targets[anchor.role[i.va]])[0]) if len(f.targets[anchor.role[i.va]]) == 1
                              else '*' for f in fns[kind])
                site = anchor.site_of(i.va)
                tsv['call_sites'].append('%s\t%s\t%s\t%s\t%s\t%s' % (
                    kind, hx(o), anchor.role[i.va], tg, hx(site[0] - anchor.start) if site and site[0] else '-',
                    site[1] if site else 'none'))
    for kind, fn_start, name, idx, arm in table_rows(fns, img):
        tsv['tables'].append('%s\t%s\t%s\t%d\t%s' % (kind, hx(fn_start), name, idx, hx(arm)))
    rowrule = {'vr': 24, 'ext': 8, 'bytes': 1}
    covered = {kind: (set(), set()) for kind in KINDS}
    for kind, k in KINDS.items():
        for ci, fn in enumerate(fns[kind]):
            m = Machine(img, fn, prim)
            for idx, c in enumerate(GENS[kind](ci)):
                got = m.run(c)
                want = reconstructed(kind, c, None, fn.eof)
                total += 1
                if got != want:
                    mismatches += 1
                outcomes[(kind, got[0])] = outcomes.get((kind, got[0]), 0) + 1
                if ci == 0:
                    covered[kind][0].update(m.trace)
                    covered[kind][1].update(m.edges)
                if idx % rowrule[kind] == ci % rowrule[kind]:
                    row = case_row(kind, idx, c)
                    tsv['cases'].append('\t'.join([kind, hx(fn.start), str(idx)] + row + [
                        got[0], got[1][:0x28].hex(), calls_text(got[2]),
                        ','.join(hx(x) for x in got[3])]))
    for kind in KINDS:
        anchor = fns[kind][0]
        hit, edges = covered[kind]
        for i in anchor.insns:
            e = ''
            if i.op == 'j':
                e = ('T' if (i.va, True) in edges else '') + ('N' if (i.va, False) in edges else '')
            tsv['coverage'].append('%s\t%s\t%s\t%d\t%d\t%s' % (kind, hx(i.va - anchor.start), i.op, i.size,
                                                               int(i.va in hit), e or '-'))
    # negative controls: wrong models, corrupted images, out-of-range inputs
    for kind, variants in (('vr', VR_VARIANTS), ('ext', EXT_VARIANTS), ('bytes', BYTES_VARIANTS)):
        fn = fns[kind][0]
        sample = [c for j, c in enumerate(GENS[kind](0)) if j % 5 == 0]
        for v in variants:
            controls.append((kind, 'model:' + v, bool(compare(img, fn, prim, sample, variant=v, limit=1))))
    for kind, offs in IMAGE_MUTANTS:
        fn = fns[kind][0]
        sample = [c for j, c in enumerate(GENS[kind](0)) if j % 3 == 0][:2000]
        for off in offs:
            controls.append((kind, 'image:+%#x' % off, bool(run_mutant(img, fn, prim, kind, off, sample))))
    for name, ok in range_controls(img, fns, prim):
        controls.append(('range', name, ok))
    for kind, name, ok in controls:
        tsv['mutants'].append('%s\t%s\t%d' % (kind, name, int(ok)))
    for name, rows in tsv.items():
        (out / f'{name}.tsv').write_text('\n'.join(rows) + '\n')
    cov = {kind: (sum(1 for i in fns[kind][0].insns if i.va in covered[kind][0]), len(fns[kind][0].insns))
           for kind in KINDS}
    summary = {'sha256': SHA256, 'cases': total, 'mismatches': mismatches, 'negative_controls': len(controls),
               'negative_detected': sum(1 for c in controls if c[2]),
               'outcomes': {f'{k}:{o}': n for (k, o), n in sorted(outcomes.items())},
               'instructions_covered': {k: f'{a}/{b}' for k, (a, b) in cov.items()},
               'case_rows': len(tsv['cases']) - 1}
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    measure = {'cases': total, 'negative_controls': len(controls),
               'negative_detected': summary['negative_detected'], 'mismatches': mismatches}
    (out / 'measure.json').write_text(json.dumps(measure, indent=1, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    s = generate(a.out)
    print(json.dumps(s, sort_keys=True))
    return 0 if s['mismatches'] == 0 and s['negative_controls'] == s['negative_detected'] else 1


if __name__ == '__main__':
    sys.exit(main())
