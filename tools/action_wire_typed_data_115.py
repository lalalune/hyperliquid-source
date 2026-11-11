#!/usr/bin/env python3
"""Reconstruct the node #115 user-signed action typed-data struct builders and prove it.

Every user-signed action of the exchange (usdSend, withdraw3, spotSend, cDeposit ...)
is signed over an EIP-712 struct whose primary type name is `HyperliquidTransaction:`
followed by the action name.  The binary builds that struct description in dozens of
small straight-line functions (one per action; the format pieces slice
`HyperliquidTransaction:` is the only shared literal).  Each function:

* formats the primary type name through the format-pieces slice,
* allocates a 16-byte buffer holding the field name `hyperliquidChain`,
* turns every further field name into an owned String through one shared helper
  (`&str` to `String`),
* lays the fields out as 48-byte records (name String, type word, type payload),
* calls the struct constructor with (type name, record array, record count),
* stores a zero tag byte plus the 32-byte constructor result into the return slot,
* drops its temporaries.

The producer authenticates the #115 capture, finds the functions as the unwind (FDE)
extents that load the pieces slice, and runs each function's original machine code in
a small interpreter for the fixed x86-64 subset those bodies use.  Calls are modelled
by recording their arguments (the modelled callees are named in the README).  The
record array handed to the constructor is read back from interpreter memory and
compared with an independent reconstruction built from the decoded field tables only.
Initial stack garbage, return-slot placement and allocation failures are varied; wrong
reconstructions and corrupted code bytes must be caught.

Only the standard library and the shared ELF/unwind parsers are used.  The capture is
never executed.
"""
import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
EXPECTED_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PIECES_SLOTS = (0x6475948, 0x6488038)   # &str "HyperliquidTransaction:" (len 23) in the data.rel.ro slices
WORK_NAME = 'action-wire-typed-data-structs-115'
PREFIX = b'HyperliquidTransaction:'
SEEDS = 64
VARIANTS = ('ok', 'ok-shifted', 'alloc-fail-0', 'alloc-fail-1')

# modelled callee addresses (direct targets or GOT slots called indirectly)
CALLEE_STR_TO_STRING = 0x41c5490
CALLEE_FORMAT = 0x64df6e8
CALLEE_ALLOC = 0x64df480
CALLEE_ALLOC_ERROR = 0x64df498
CALLEE_DEALLOC = 0x64df4a0
CALLEE_BUILD = 0x64e0158
CALLEE_DROP_FIELD = 0x44e4de0
CALLEE_DROP_TYPE = 0x44e1fd0
CALLEE_DROP_FORMATTED = 0x44ddd50
CALLEE_UNWIND_RESUME_PLT = None
CALLEE_PANIC = 0x64df4c0
CALLEE_DROP_TYPE_A = 0x3d0f570
CALLEE_NAMES = {
    CALLEE_STR_TO_STRING: 'str_to_string', CALLEE_FORMAT: 'format_type_name', CALLEE_ALLOC: 'alloc',
    CALLEE_ALLOC_ERROR: 'alloc_error', CALLEE_DEALLOC: 'dealloc', CALLEE_BUILD: 'struct_new',
    CALLEE_DROP_FIELD: 'drop_field', CALLEE_DROP_TYPE: 'drop_type', CALLEE_DROP_TYPE_A: 'drop_type', CALLEE_DROP_FORMATTED: 'drop_formatted',
    CALLEE_PANIC: 'panic_unwind',
}

STACK_TOP = 0x7ffc00100000
STACK_FILL_BASE = 0x7ffc00000000
HEAP_BASE = 0x5555aa000000
RET_SENTINEL = 0x7eeeee000000
MASK64 = (1 << 64) - 1
TAG_BASE = 0x8000000000000000
TYPE_TAG_NAMES = {TAG_BASE + 3: 'uint', TAG_BASE + 5: 'string'}


def normal_fields(fields):
    """Drop the payload word of types that carry none (it is stack padding in the record)."""
    return tuple((n, tag, payload if tag in (TAG_BASE + 3, TAG_BASE + 7) else 0) for n, cap, tag, payload in fields)


def struct_digest(tname, fields):
    return hashlib.sha256(tname + b'|' + repr(normal_fields(fields)).encode()).digest()


class Reject(Exception):
    pass


class Unsupported(Exception):
    pass


class Halt(Exception):
    def __init__(self, kind):
        Exception.__init__(self, kind)
        self.kind = kind


# ----------------------------------------------------------------------------- keccak

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
       0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
       0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data):
    """Original Keccak-256 (0x01 padding), the hash the EIP-712 type hash uses."""
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= struct.unpack_from('<Q', msg, off + 8 * i)[0]
        _keccak_f(a)
    out = b''
    for i in range(4):
        out += struct.pack('<Q', a[i % 5][i // 5])
    return out


# ----------------------------------------------------------------------------- image

class Image:
    """Read-only view of the file-backed sections, with optional byte patches."""

    def __init__(self, data):
        self.data = data
        self.secs = [s for s in elf_index.sections(data) if s['type'] != 8 and s['address'] and s['flags'] & 2]
        self.patch = {}
        self.got = [(g['address'], g['address'] + g['size']) for g in elf_index.sections(data) if g['name'] == '.got']

    def read(self, va, n):
        out = bytearray()
        for i in range(n):
            a = va + i
            if a in self.patch:
                out.append(self.patch[a])
                continue
            for s in self.secs:
                if s['address'] <= a < s['address'] + s['size']:
                    out.append(self.data[s['offset'] + a - s['address']])
                    break
            else:
                raise Unsupported('read outside image %#x' % a)
        return bytes(out)


# ----------------------------------------------------------------------------- machine

def _fill_byte(seed, addr):
    return ((addr * 2654435761 + seed * 40503 + (addr >> 7)) >> 3) & 0xff


class Machine:
    """x86-64 subset interpreter: only the instruction forms the typed-data builders use."""

    def __init__(self, image, seed, rdi_shift=0, fail_alloc=None):
        self.img = image
        self.seed = seed
        self.mem = {}
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.zf = 0
        self.sf = 0
        self.cf = 0
        self.events = []
        self.heap = HEAP_BASE
        self.allocs = 0
        self.fail_alloc = fail_alloc
        self.steps = 0
        self.visited = {}
        self.regs[4] = STACK_TOP - 8 - 16 * (seed % 4)
        self.write(self.regs[4], 8, RET_SENTINEL)
        self.sret = STACK_TOP - 0x4000 + rdi_shift
        self.regs[7] = self.sret
        for i in range(0x40):
            self.mem[self.sret + i] = 0xa5 ^ (seed & 0xff)
        self.initial_sp = self.regs[4]
        # callee-saved registers get seed-dependent junk that the function must preserve
        for r in (3, 12, 13, 14, 15):
            self.regs[r] = (0x1111111111111111 * (r + seed)) & MASK64
        self.saved = [self.regs[r] for r in (3, 12, 13, 14, 15)]

    # memory ------------------------------------------------------------
    def read(self, addr, n):
        out = bytearray()
        for i in range(n):
            a = addr + i
            if a in self.mem:
                out.append(self.mem[a])
            elif STACK_FILL_BASE <= a < STACK_TOP + 0x1000:
                out.append(_fill_byte(self.seed, a))
            elif HEAP_BASE <= a < HEAP_BASE + (1 << 24):
                out.append(0xee)
            elif any(lo <= a < hi for lo, hi in self.img.got):
                # a GOT slot reads back as its own address, which names the modelled callee
                out.append(((a & ~7) >> (8 * (a & 7))) & 0xff)
            else:
                out.extend(self.img.read(a, 1))
        return bytes(out)

    def write(self, addr, n, value):
        for i in range(n):
            self.mem[addr + i] = (value >> (8 * i)) & 0xff

    def read_int(self, addr, n):
        return int.from_bytes(self.read(addr, n), 'little')

    # decoding helpers ----------------------------------------------------
    def fetch(self, va, n):
        return self.img.read(va, n)

    def run(self, start, limit=4000):
        rip = start
        while True:
            if rip == RET_SENTINEL:
                return
            self.steps += 1
            if self.steps > limit:
                raise Unsupported('step limit')
            rip = self.step(rip)

    def modrm(self, rip, p, rex, imm_size):
        """Decode a ModRM operand at rip+p.  Returns (reg, kind, loc, newp)."""
        m = self.fetch(rip + p, 1)[0]
        p += 1
        mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
        reg |= (rex & 4) << 1
        if mod == 3:
            return reg, 'reg', rm | ((rex & 1) << 3), p
        base_expr = None
        if rm == 4:
            sib = self.fetch(rip + p, 1)[0]
            p += 1
            scale, idx, base = sib >> 6, ((sib >> 3) & 7) | ((rex & 2) << 2), (sib & 7) | ((rex & 1) << 3)
            if idx != 4:
                raise Unsupported('sib index')
            if mod == 0 and (sib & 7) == 5:
                raise Unsupported('sib disp-only')
            addr_base = ('r', base)
        elif rm == 5 and mod == 0:
            disp = struct.unpack('<i', self.fetch(rip + p, 4))[0]
            p += 4
            return reg, 'mem', ('rip', rip + p + imm_size + disp), p
        else:
            addr_base = ('r', rm | ((rex & 1) << 3))
        disp = 0
        if mod == 1:
            disp = struct.unpack('<b', self.fetch(rip + p, 1))[0]
            p += 1
        elif mod == 2:
            disp = struct.unpack('<i', self.fetch(rip + p, 4))[0]
            p += 4
        return reg, 'mem', ('rb', addr_base[1], disp), p

    def ea(self, loc):
        if loc[0] == 'rip':
            return loc[1]
        return (self.regs[loc[1]] + loc[2]) & MASK64

    def get_rm(self, kind, loc, size):
        if kind == 'reg':
            return self.regs[loc] & ((1 << (8 * size)) - 1)
        return self.read_int(self.ea(loc), size)

    def set_rm(self, kind, loc, size, value):
        if kind == 'reg':
            if size == 8:
                self.regs[loc] = value & MASK64
            elif size == 4:
                self.regs[loc] = value & 0xffffffff
            else:
                raise Unsupported('partial register write')
        else:
            self.write(self.ea(loc), size, value)

    def flags(self, result, size, carry=0):
        bits = 8 * size
        result &= (1 << bits) - 1
        self.zf = int(result == 0)
        self.sf = result >> (bits - 1)
        self.cf = carry

    def alu(self, op, a, b, size):
        bits = 8 * size
        mask = (1 << bits) - 1
        if op == 'add':
            r = a + b
            self.flags(r, size, int(r > mask))
        elif op in ('sub', 'cmp'):
            r = a - b
            self.flags(r, size, int(a < b))
        elif op == 'xor':
            r = a ^ b
            self.flags(r, size)
        elif op == 'and':
            r = a & b
            self.flags(r, size)
        elif op == 'or':
            r = a | b
            self.flags(r, size)
        else:
            raise Unsupported(op)
        return r & mask

    def push(self, v):
        self.regs[4] = (self.regs[4] - 8) & MASK64
        self.write(self.regs[4], 8, v)

    def pop(self):
        v = self.read_int(self.regs[4], 8)
        self.regs[4] = (self.regs[4] + 8) & MASK64
        return v

    def cond(self, cc):
        if cc == 4:
            return self.zf == 1
        if cc == 5:
            return self.zf == 0
        raise Unsupported('condition %d' % cc)

    # one instruction ------------------------------------------------------
    def step(self, rip):
        self.visited[rip] = self.visited.get(rip, 0) + 1
        p = 0
        rex = 0
        b = self.fetch(rip, 1)[0]
        if b == 0x66:
            raise Unsupported('operand-size prefix')
        if 0x40 <= b <= 0x4f:
            rex = b
            p = 1
            b = self.fetch(rip + 1, 1)[0]
            p = 2
        else:
            p = 1
        w = 8 if rex & 8 else 4
        # push / pop
        if 0x50 <= b <= 0x57:
            self.push(self.regs[(b - 0x50) | ((rex & 1) << 3)])
            return rip + p
        if 0x58 <= b <= 0x5f:
            self.regs[(b - 0x58) | ((rex & 1) << 3)] = self.pop()
            return rip + p
        # mov imm to register
        if 0xb8 <= b <= 0xbf:
            r = (b - 0xb8) | ((rex & 1) << 3)
            n = 8 if rex & 8 else 4
            self.regs[r] = int.from_bytes(self.fetch(rip + p, n), 'little')
            return rip + p + n
        if b in (0x89, 0x8b, 0x8d, 0x01, 0x03, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85, 0x21, 0x23, 0x09, 0x0b):
            reg, kind, loc, q = self.modrm(rip, p, rex, 0)
            if b == 0x89:
                self.set_rm(kind, loc, w, self.regs[reg] & ((1 << (8 * w)) - 1))
            elif b == 0x8b:
                self.regs[reg] = self.get_rm(kind, loc, w) & (MASK64 if w == 8 else 0xffffffff)
            elif b == 0x8d:
                if kind != 'mem':
                    raise Unsupported('lea reg')
                self.regs[reg] = self.ea(loc) & (MASK64 if w == 8 else 0xffffffff)
            else:
                names = {0x01: 'add', 0x03: 'add', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor', 0x39: 'cmp',
                         0x3b: 'cmp', 0x85: 'test', 0x21: 'and', 0x23: 'and', 0x09: 'or', 0x0b: 'or'}
                op = names[b]
                mem_dst = b in (0x01, 0x29, 0x31, 0x39, 0x85, 0x21, 0x09)
                rv = self.regs[reg] & ((1 << (8 * w)) - 1)
                mv = self.get_rm(kind, loc, w)
                if op == 'test':
                    self.flags(rv & mv, w)
                elif mem_dst:
                    res = self.alu('cmp' if op == 'cmp' else op, mv, rv, w)
                    if op != 'cmp':
                        self.set_rm(kind, loc, w, res)
                else:
                    res = self.alu('cmp' if op == 'cmp' else op, rv, mv, w)
                    if op != 'cmp':
                        self.regs[reg] = res
            return rip + q
        if b in (0x81, 0x83):
            isz = 4 if b == 0x81 else 1
            reg, kind, loc, q = self.modrm(rip, p, rex, isz)
            imm = int.from_bytes(self.fetch(rip + q, isz), 'little', signed=True) & ((1 << (8 * w)) - 1)
            ops = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
            op = ops.get(reg & 7)
            if op is None:
                raise Unsupported('group1 %d' % (reg & 7))
            res = self.alu(op, self.get_rm(kind, loc, w), imm, w)
            if op != 'cmp':
                self.set_rm(kind, loc, w, res)
            return rip + q + isz
        if b == 0xc7:
            reg, kind, loc, q = self.modrm(rip, p, rex, 4)
            if reg & 7:
                raise Unsupported('c7 /%d' % (reg & 7))
            imm = int.from_bytes(self.fetch(rip + q, 4), 'little', signed=True) & ((1 << (8 * w)) - 1)
            self.set_rm(kind, loc, w, imm)
            return rip + q + 4
        if b == 0xc6:
            reg, kind, loc, q = self.modrm(rip, p, rex, 1)
            if reg & 7 or kind != 'mem':
                raise Unsupported('c6')
            self.set_rm(kind, loc, 1, self.fetch(rip + q, 1)[0])
            return rip + q + 1
        if b == 0xff:
            reg, kind, loc, q = self.modrm(rip, p, rex, 0)
            sub = reg & 7
            if sub in (0, 1):
                v = self.get_rm(kind, loc, w)
                res = (v + (1 if sub == 0 else -1)) & ((1 << (8 * w)) - 1)
                cf = self.cf
                self.flags(res, w, cf)
                self.set_rm(kind, loc, w, res)
                return rip + q
            if sub == 2:
                if kind == 'mem':
                    slot = self.ea(loc)
                    target = slot
                else:
                    target = self.regs[loc]
                    slot = None
                self.call(target, slot is not None, rip + q)
                return rip + q
            raise Unsupported('ff /%d' % sub)
        if b == 0xe8:
            rel = struct.unpack('<i', self.fetch(rip + p, 4))[0]
            self.call(rip + p + 4 + rel, False, rip + p + 4)
            return rip + p + 4
        if b == 0xe9:
            return rip + p + 4 + struct.unpack('<i', self.fetch(rip + p, 4))[0]
        if b == 0xeb:
            return rip + p + 1 + struct.unpack('<b', self.fetch(rip + p, 1))[0]
        if 0x70 <= b <= 0x7f:
            rel = struct.unpack('<b', self.fetch(rip + p, 1))[0]
            return rip + p + 1 + (rel if self.cond(b & 15) else 0)
        if b == 0xc3:
            self.regs[4] = (self.regs[4] + 8) & MASK64
            return RET_SENTINEL
        if b == 0x0f:
            b2 = self.fetch(rip + p, 1)[0]
            p += 1
            if 0x80 <= b2 <= 0x8f:
                rel = struct.unpack('<i', self.fetch(rip + p, 4))[0]
                return rip + p + 4 + (rel if self.cond(b2 & 15) else 0)
            if b2 in (0x10, 0x11, 0x28, 0x29):
                reg, kind, loc, q = self.modrm(rip, p, rex, 0)
                if b2 in (0x10, 0x28):
                    self.xmm[reg] = self.get_rm(kind, loc, 16) if kind == 'mem' else self.xmm[loc]
                else:
                    if kind == 'mem':
                        self.write(self.ea(loc), 16, self.xmm[reg])
                    else:
                        self.xmm[loc] = self.xmm[reg]
                return rip + q
            raise Unsupported('0f %02x' % b2)
        raise Unsupported('opcode %02x at %#x' % (b, rip))

    # modelled calls -------------------------------------------------------
    def call(self, target, indirect, ret):
        a = self.regs
        if indirect:
            slot = target
            target = slot
        name = CALLEE_NAMES.get(target)
        if name is None:
            raise Unsupported('call to %#x' % target)
        self.model(target, name)

    def model(self, target, name):
        a = self.regs
        if name == 'alloc':
            size = a[7]
            idx = self.allocs
            self.allocs += 1
            if self.fail_alloc is not None and idx == self.fail_alloc:
                self.events.append(('alloc', size, 'null'))
                a[0] = 0
                return
            self.events.append(('alloc', size, 'ok'))
            a[0] = self.heap
            self.heap += (size + 15) & ~15
        elif name == 'alloc_error':
            self.events.append(('alloc_error', a[7], a[6]))
            raise Halt('alloc_error')
        elif name == 'str_to_string':
            data = self.img.read(a[6], a[2])
            ptr = self.heap
            self.heap += (a[2] + 15) & ~15
            self.write(a[7], 8, a[2])
            self.write(a[7] + 8, 8, ptr)
            self.write(a[7] + 16, 8, a[2])
            for i, c in enumerate(data):
                self.mem[ptr + i] = c
            self.events.append(('str_to_string', data))
        elif name == 'format_type_name':
            rec = self.img.read(a[6], 2)
            n = rec[1]
            pieces = self.read_int(a[2], 8)
            fmtfn = self.read_int(a[2] + 8, 8)
            text = self.img.read(a[6] + 2, n)
            full = PREFIX + text
            ptr = self.heap
            self.heap += (len(full) + 15) & ~15
            for i, c in enumerate(full):
                self.mem[ptr + i] = c
            self.write(a[7], 8, len(full))
            self.write(a[7] + 8, 8, ptr)
            self.write(a[7] + 16, 8, len(full))
            self.events.append(('format_type_name', rec[0], text, pieces in PIECES_SLOTS, fmtfn))
        elif name == 'struct_new':
            sptr = self.read_int(a[6] + 8, 8)
            slen = self.read_int(a[6] + 16, 8)
            tname = self.read(sptr, slen)
            count = a[1]
            fields = []
            for i in range(count):
                rec = a[2] + 48 * i
                cap, ptr, ln = self.read_int(rec, 8), self.read_int(rec + 8, 8), self.read_int(rec + 16, 8)
                tag, payload = self.read_int(rec + 24, 8), self.read_int(rec + 32, 8)
                fields.append((self.read(ptr, ln), cap, tag, payload))
            digest = struct_digest(tname, fields)
            self.write(a[7] + 0, 8, 0)
            self.mem.update((a[7] + i, c) for i, c in enumerate(digest))
            self.events.append(('struct_new', tname, count, tuple(fields), digest))
            a[0] = a[7]
        elif name in ('drop_field', 'drop_type', 'drop_formatted'):
            self.events.append((name,))
        elif name == 'dealloc':
            self.events.append(('dealloc', a[6], a[2]))
        elif name == 'panic_unwind':
            raise Halt('unwind')
        else:
            raise Unsupported(name)


# ----------------------------------------------------------------------------- discovery

def find_functions(data):
    secs = elf_index.sections(data)
    text = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
    if len(text) != 1:
        raise Reject('expected one .text')
    text = text[0]
    t = data[text['offset']:text['offset'] + text['size']]
    rows = fde_extents.fde_extents(data)[1]
    starts = [r['start'] for r in rows]
    found = {}
    for i in range(len(t) - 7):
        if t[i] in (0x48, 0x4c) and t[i + 1] == 0x8d and (t[i + 2] & 0xc7) == 5:
            tgt = text['address'] + i + 7 + struct.unpack_from('<i', t, i + 3)[0]
            if tgt in PIECES_SLOTS:
                va = text['address'] + i
                r = rows[bisect.bisect_right(starts, va) - 1]
                found.setdefault(r['start'], (r['end'], tgt, va))
    return sorted((s, e, slot, site) for s, (e, slot, site) in found.items())


# ----------------------------------------------------------------------------- spec from the bytes

def solidity_type(tag, payload):
    """Observed type words 0/3/4/5/7 read as address/uintN/bool/string/bytesN (inference, see README)."""
    if tag == TAG_BASE + 0:
        return 'address'
    if tag == TAG_BASE + 1:
        return 'bytes'
    if tag == TAG_BASE + 3:
        return 'uint%d' % payload
    if tag == TAG_BASE + 4:
        return 'bool'
    if tag == TAG_BASE + 5:
        return 'string'
    if tag == TAG_BASE + 7:
        return 'bytes%d' % payload
    raise Reject('unmapped type word %#x' % tag)


def encode_type(tname, fields):
    return tname + b'(' + b','.join(solidity_type(tag, payload).encode() + b' ' + n for n, tag, payload in fields) + b')'


def run_clean(image, start, seed=0, shift=0, fail=None):
    m = Machine(image, seed, shift, fail)
    outcome = 'ok'
    try:
        m.run(start)
    except Halt as h:
        outcome = h.kind
    return m, outcome


def spec_of(image, start):
    """Observation: the straight-line run of a function, reduced to its type name and record table."""
    m, outcome = run_clean(image, start)
    if outcome != 'ok':
        raise Reject('clean run of %#x did not return' % start)
    ev = [e for e in m.events if e[0] == 'struct_new']
    fmt = [e for e in m.events if e[0] == 'format_type_name']
    if len(ev) != 1 or len(fmt) != 1:
        raise Reject('unexpected call profile at %#x' % start)
    fields = tuple((n, tag, payload if tag in (TAG_BASE + 3, TAG_BASE + 7) else 0) for n, cap, tag, payload in ev[0][3])
    return dict(start=start, name=fmt[0][2], record_flag=fmt[0][1], fields=fields, tname=ev[0][1],
                steps=m.steps, insns=len(m.visited))


def static_literals(data, start, end, text_sec):
    """Fixed byte patterns: lea disp(%rip),%rsi ; ... mov $len,%edx ; ... call str_to_string.  Returns (ptr, len) per call."""
    base = text_sec['offset'] - text_sec['address']
    code = data[base + start:base + end]
    out = []
    i = 0
    while i < len(code) - 5:
        if code[i] == 0xe8:
            tgt = start + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if tgt == CALLEE_STR_TO_STRING:
                window = code[max(0, i - 40):i]
                lea = window.rfind(b'\x48\x8d\x35')
                mov = window.rfind(b'\xba')
                if lea < 0 or mov < 0 or lea + 7 > len(window) or mov + 5 > len(window):
                    raise Reject('call site without literal setup at %#x' % (start + i))
                disp = struct.unpack_from('<i', window, lea + 3)[0]
                pos = i - len(window) + lea
                ptr = start + pos + 7 + disp
                ln = struct.unpack_from('<I', window, mov + 1)[0]
                out.append((ptr, ln))
                i += 5
                continue
        i += 1
    return out


# ----------------------------------------------------------------------------- reconstruction

def reconstruct(spec, variant, mut=None):
    """Pure model: predicted (outcome, events, sret) of one builder under one run variant."""
    mut = mut or ''
    prefix = b'HyperliquidTransactions:' if mut == 'prefix' else PREFIX
    tname = prefix + spec['name']
    ev = [('format_type_name', spec['record_flag'], spec['name'])]
    fail0 = variant == 'alloc-fail-0'
    ev.append(('alloc', 8 if mut == 'alloc-size' else 16, 'null' if fail0 else 'ok'))
    if fail0:
        if mut != 'no-alloc-error':
            ev.append(('alloc_error', 1, 16))
        return 'alloc_error', ev, None
    fields = list(spec['fields'])
    if mut == 'reverse':
        fields = fields[::-1]
    if mut == 'drop-last':
        fields = fields[:-1]
    if mut == 'bits':
        fields = [(n, t, 32 if t == TAG_BASE + 3 else p) for n, t, p in fields]
    if mut == 'bool-as-string':
        fields = [(n, TAG_BASE + 5 if t == TAG_BASE + 4 else t, p) for n, t, p in fields]
    if mut == 'first-name':
        fields[0] = (b'hyperliquidChains',) + fields[0][1:]
    literals = [f[0] for f in fields[1:]]
    if mut == 'swap-literals' and len(literals) > 1:
        literals[0], literals[1] = literals[1], literals[0]
    for n in literals:
        ev.append(('str_to_string', n))
    count = len(fields) + (1 if mut == 'count' else 0)
    rows = tuple((n, 16 if i == 0 else len(n), t, p) for i, (n, t, p) in enumerate(fields))
    if mut == 'hash':
        digest = hashlib.sha1(tname).digest() + b'\0' * 12
    else:
        digest = hashlib.sha256(tname + b'|' + repr(tuple((n, t, p) for n, t, p in fields)).encode()).digest()
    ev.append(('struct_new', tname, count, rows, digest))
    if mut != 'no-drops':
        for n, c, t, p in rows:
            ev.append(('dealloc', c, 0))
            ev.append(('drop_type',))
    sret = (b'\x01' if mut == 'sret-tag' else b'\x00') + digest
    return 'ok', ev, sret


def normalise_events(events):
    out = []
    for e in events:
        if e[0] == 'format_type_name':
            out.append(('format_type_name', e[1], e[2]))
        elif e[0] == 'struct_new':
            rows = tuple((n, cap, tag, payload if tag in (TAG_BASE + 3, TAG_BASE + 7) else 0) for n, cap, tag, payload in e[3])
            out.append(('struct_new', e[1], e[2], rows, e[4]))
        elif e[0] == 'dealloc':
            out.append(('dealloc', e[1], e[2]))
        else:
            out.append(e)
    return out


def observe(image, start, seed, variant):
    shift = 0x40 if variant == 'ok-shifted' else 0
    fail = dict([('alloc-fail-0', 0), ('alloc-fail-1', 1)]).get(variant)
    m = Machine(image, seed, shift, fail)
    outcome = 'ok'
    try:
        m.run(start)
    except Halt as h:
        outcome = h.kind
    sret = None
    if outcome == 'ok':
        sret = m.read(m.sret, 33)
        if m.regs[4] != m.initial_sp + 8 or m.regs[0] != m.sret:
            raise Reject('stack or return value not restored at %#x' % start)
        if [m.regs[r] for r in (3, 12, 13, 14, 15)] != m.saved:
            raise Reject('callee-saved register clobbered at %#x' % start)
    return outcome, normalise_events(m.events), sret, m


def model_variant(variant):
    return 'ok' if variant in ('ok', 'ok-shifted', 'alloc-fail-1') else variant


def agree(image, spec, seed, variant, mut=None):
    try:
        outcome, events, sret, m = observe(image, spec['start'], seed, variant)
    except (Unsupported, Reject, Halt):
        return False, None
    want = reconstruct(spec, model_variant(variant), mut)
    return (outcome, events, sret) == (want[0], normalise_events(want[1]), want[2]), m


# ----------------------------------------------------------------------------- negatives

MUTANTS = ('prefix', 'alloc-size', 'no-alloc-error', 'reverse', 'drop-last', 'bits', 'bool-as-string', 'first-name',
           'swap-literals', 'count', 'hash', 'no-drops', 'sret-tag')


def caught(image, spec, mut=None):
    """True when some run of the (possibly patched) function disagrees with the model."""
    for variant in VARIANTS:
        for seed in (0, 1, 2):
            ok, _ = agree(image, spec, seed, variant, mut)
            if not ok:
                return True
    return False


def patch_sites(image, spec):
    """Instruction bytes of four fixed kinds inside the executed path of a function."""
    m, _ = run_clean(image, spec['start'])
    sites = dict()
    for va in sorted(m.visited):
        b = image.read(va, 9)
        if b[0] == 0xba and 'len' not in sites:
            sites['len'] = va + 1
        elif b[0] == 0xbf and b[1:5] == b'\x10\x00\x00\x00':
            sites['alloc'] = va + 1
        elif b[0] == 0xb9:
            sites['count'] = va + 1
        elif b[:3] == b'\x48\xc7\x84' or b[:4] == b'\x48\xc7\x44\x24':
            ln = 8 if b[:3] == b'\x48\xc7\x84' else 5
            imm = struct.unpack_from('<I', image.read(va + ln, 4))[0]
            if imm in (32, 64):
                sites.setdefault('bits', va + ln)
    return sites


def run_negatives(image, specs):
    rows = []
    bool_spec = [s for s in specs if any(t == TAG_BASE + 4 for _, t, _ in s['fields'])][0]
    for mut in MUTANTS:
        if mut in ('swap-literals', 'drop-last', 'reverse'):
            spec = [s for s in specs if len(s['fields']) >= 4][0]
        elif mut == 'bool-as-string':
            spec = bool_spec
        else:
            spec = specs[0]
        rows.append(('mutant', mut, '%#x' % spec['start'], caught(image, spec, mut)))
    bits_spec = [s for s in specs if any(t == TAG_BASE + 3 for _, t, _ in s['fields'])][-1]
    rows.append(('mutant', 'bits@last-uint-bearing', '%#x' % bits_spec['start'], caught(image, bits_spec, 'bits')))
    rows.append(('mutant', 'first-name@bool-bearing', '%#x' % bool_spec['start'], caught(image, bool_spec, 'first-name')))
    n = len(specs)
    picks = [specs[1], specs[n // 4], specs[n // 2], specs[3 * n // 4], specs[-1]]
    for spec in picks:
        sites = patch_sites(image, spec)
        for kind in ('len', 'alloc', 'count', 'bits'):
            if kind not in sites:
                continue
            va = sites[kind]
            old = image.read(va, 1)[0]
            image.patch[va] = old ^ 0x04
            try:
                rows.append(('byte', '%s@%#x' % (kind, va), '%#x' % spec['start'], caught(image, spec)))
            finally:
                del image.patch[va]
    for label, addr in (('mid-function', specs[0]['start'] + 1), ('string-helper', CALLEE_STR_TO_STRING),
                        ('unmapped', 0x10), ('rodata', 0x7b97b8), ('past-text', 0x7fffffff), ('null', 0)):
        fake = dict(specs[0])
        fake['start'] = addr
        rows.append(('range', label, '%#x' % addr, caught(image, fake)))
    return rows


# ----------------------------------------------------------------------------- build

def build(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise Reject('input is not the node #115 capture')
    image = Image(data)
    secs = elf_index.sections(data)
    text_sec = [s for s in secs if s['name'] == '.text' and s['type'] != 8][0]
    specs = []
    lit_ok = 0
    lit_total = 0
    for start, end, slot, site in find_functions(data):
        spec = spec_of(image, start)
        spec['end'] = end
        spec['slot'] = slot
        spec['site'] = site
        lits = static_literals(data, start, end, text_sec)
        names = [image.read(p, n) for p, n in lits]
        spec['static_names'] = names
        spec['static_lits'] = lits
        m, _ = run_clean(image, start)
        called = [e[1] for e in m.events if e[0] == 'str_to_string']
        want = [f[0] for f in spec['fields'][1:]]
        spec['call_order_ok'] = (names == called) and (sorted(called) == sorted(want))
        lit_total += len(names)
        lit_ok += sum(1 for a, b in zip(names, called) if a == b)
        specs.append(spec)
    cases = []
    matched = 0
    total = 0
    cov = dict()
    per_variant = dict()
    for spec in specs:
        seen = set()
        for variant in VARIANTS:
            for seed in range(SEEDS):
                ok, m = agree(image, spec, seed, variant)
                total += 1
                matched += int(ok)
                per_variant[variant] = per_variant.get(variant, 0) + int(ok)
                if m is not None:
                    seen.update(m.visited)
                if seed < 2:
                    cases.append((spec['start'], variant, seed, ok))
        cov[spec['start']] = len(seen)
    total += lit_total + len(specs)
    matched += lit_ok + sum(1 for s in specs if s['call_order_ok'])
    negatives = run_negatives(image, specs)
    return dict(specs=specs, total=total, matched=matched, cases=cases, cov=cov, per_variant=per_variant,
                lit_total=lit_total, lit_ok=lit_ok, negatives=negatives)


# ----------------------------------------------------------------------------- output

def ascii_name(b):
    return b.decode('ascii')


def render(result, work_name):
    specs = result['specs']
    out = dict()
    rows = ['start\tend\tbytes\tpieces_slot\ttype_name\ttype_record_flag\tfields\tsteps\tdistinct_insns\tinsns_all_runs\tliteral_order_ok']
    for s in specs:
        rows.append('\t'.join([
            '%#x' % s['start'], '%#x' % s['end'], str(s['end'] - s['start']), '%#x' % s['slot'], ascii_name(s['name']),
            '%#x' % s['record_flag'], str(len(s['fields'])), str(s['steps']), str(s['insns']),
            str(result['cov'][s['start']]), 'yes' if s['call_order_ok'] else 'no']))
    out['functions.tsv'] = '\n'.join(rows) + '\n'
    rows = ['start\tindex\tfield\ttype_word\tpayload\tsolidity_type']
    for s in specs:
        for i, (n, tag, payload) in enumerate(s['fields']):
            rows.append('\t'.join(['%#x' % s['start'], str(i), ascii_name(n), '%#x' % tag, str(payload), solidity_type(tag, payload)]))
    out['fields.tsv'] = '\n'.join(rows) + '\n'
    rows = ['start\tencode_type\ttype_hash_keccak256']
    for s in specs:
        text = encode_type(PREFIX + s['name'], s['fields'])
        rows.append('\t'.join(['%#x' % s['start'], ascii_name(text), keccak256(text).hex()]))
    out['eip712.tsv'] = '\n'.join(rows) + '\n'
    rows = ['start\tcall_index\tliteral_va\tlength\tliteral\tmatches_call_order']
    for s in specs:
        for i, n in enumerate(s['static_names']):
            rows.append('\t'.join(['%#x' % s['start'], str(i), '%#x' % s['static_lits'][i][0], str(len(n)), ascii_name(n), 'yes' if s['call_order_ok'] else 'no']))
    out['literals.tsv'] = '\n'.join(rows) + '\n'
    rows = ['start\tvariant\tseed\tmatches']
    for start, variant, seed, ok in result['cases']:
        rows.append('\t'.join(['%#x' % start, variant, str(seed), 'yes' if ok else 'no']))
    out['cases-sample.tsv'] = '\n'.join(rows) + '\n'
    rows = ['kind\tlabel\tfunction\tdetected']
    for kind, label, fn, det in result['negatives']:
        rows.append('\t'.join([kind, label, fn, 'yes' if det else 'no']))
    out['negatives.tsv'] = '\n'.join(rows) + '\n'
    words = dict()
    for s in specs:
        for n, tag, payload in s['fields']:
            words[tag] = words.get(tag, 0) + 1
    names_seen = sorted(set(ascii_name(s['name']) for s in specs))
    neg_total = len(result['negatives'])
    neg_ok = sum(1 for r in result['negatives'] if r[3])
    summary = dict(
        work_item=work_name, binary_sha256=EXPECTED_SHA256, functions=len(specs), distinct_action_names=len(names_seen),
        action_names=names_seen, fields_total=sum(len(s['fields']) for s in specs),
        type_words=dict(('%#x' % k, v) for k, v in sorted(words.items())),
        seeds=SEEDS, variants=list(VARIANTS), cases=result['total'], cases_matched=result['matched'],
        per_variant_matched=result['per_variant'], literal_sites=result['lit_total'], literal_sites_matched=result['lit_ok'],
        negative_controls=neg_total, negative_detected=neg_ok,
        all_cases_match=result['total'] == result['matched'], all_negatives_detected=neg_total == neg_ok)
    out['summary.json'] = json.dumps(summary, indent=1, sort_keys=True) + '\n'
    out['measure.json'] = json.dumps(dict(cases=result['total'], negative_controls=neg_total, negative_detected=neg_ok),
                                     indent=1, sort_keys=True) + '\n'
    return out


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
    if result['total'] != result['matched'] or not all(r[3] for r in result['negatives']):
        print('reconstruction or negative controls failed', file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result, WORK_NAME).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    print('cases %d/%d, negatives %d/%d' % (result['matched'], result['total'],
                                           sum(1 for r in result['negatives'] if r[3]), len(result['negatives'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
