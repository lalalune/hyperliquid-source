#!/usr/bin/env python3
"""Reconstruct the node 115 action-tag selector (0x2bdb5b0) and classifier (0x36c30f0).

Both functions switch on the action discriminant stored in the first word of an
action object: ``index = tag - 0x86`` for ``tag >= 0x86`` and ``0x14`` otherwise,
then jump through a 92-entry relative table.  This tool

* reads the function bytes and both jump tables straight from the ELF image,
* runs the real arm bytes in a tiny x86-64 subset interpreter (no binary is
  executed; only these bytes are decoded) over generated action objects, and
* checks an independent, hand-written Python model of each function against it.

The interpreter supports only the opcode forms these two functions use and
raises on anything else, so a byte change is detected instead of ignored.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SELECTOR = (0x2bdb5b0, 0x2bdb911, 0x60a080)
CLASSIFIER = (0x36c30f0, 0x36c3175, 0x79afb0)
TAG_BASE = 0x86
TAG_COUNT = 92
DEFAULT_INDEX = 0x14
GOT_SLOT = 0x64e8e28
EMPTY_WORD = 0x1a2

OBJ_BASE = 0x10000000
OBJ_SIZE = 0x80
OUT_BASE = 0x70000000
STK_TOP = 0x7ff00000
STK_SIZE = 0x200
POISON = 0xAA
MASK = (1 << 64) - 1
POISON_HIGH = int.from_bytes(bytes([POISON]) * 4, 'little')
EXT_RET = 0xE000000000000000


class Image:
    """File-backed section bytes keyed by linked virtual address."""

    def __init__(self, path=TARGET):
        digest = hashlib.sha256()
        with open(path, 'rb') as fh:
            for block in iter(lambda: fh.read(1 << 20), b''):
                digest.update(block)
        if digest.hexdigest() != DIGEST:
            raise ValueError('input is not node #115')
        with open(path, 'rb') as fh:
            data = fh.read()
        self.chunks = []
        for sec in sections(data):
            if sec['type'] != 8 and sec['address'] and sec['flags'] & 2:
                if sec['name'] in ('.text', '.rodata'):
                    self.chunks.append((sec['address'], data[sec['offset']:sec['offset'] + sec['size']]))
        self.patches = {}

    def read(self, va, n):
        out = bytearray()
        for i in range(n):
            if va + i in self.patches:
                out.append(self.patches[va + i])
                continue
            for base, blob in self.chunks:
                if base <= va + i < base + len(blob):
                    out.append(blob[va + i - base])
                    break
            else:
                raise ValueError('read outside mapped sections: %#x' % (va + i))
        return bytes(out)

    def table(self, spec):
        start, end, tab = spec
        rows = []
        for i in range(TAG_COUNT):
            rel = struct.unpack('<i', self.read(tab + 4 * i, 4))[0]
            target = tab + rel
            if not start <= target < end:
                raise ValueError('jump target outside function')
            rows.append(target)
        return rows


class Fault(Exception):
    pass


class Mem:
    def __init__(self, image):
        self.image = image
        self.regions = {}

    def add(self, base, size, fill=0):
        self.regions[base] = bytearray([fill]) * size

    def _find(self, va, n):
        for base, buf in self.regions.items():
            if base <= va and va + n <= base + len(buf):
                return buf, va - base
        return None, 0

    def read(self, va, n):
        buf, off = self._find(va, n)
        if buf is not None:
            return bytes(buf[off:off + n])
        return self.image.read(va, n)

    def write(self, va, data):
        buf, off = self._find(va, len(data))
        if buf is None:
            raise Fault('write outside regions %#x' % va)
        buf[off:off + len(data)] = data

    def u(self, va, n):
        return int.from_bytes(self.read(va, n), 'little')

    def w(self, va, n, val):
        self.write(va, (val & ((1 << (8 * n)) - 1)).to_bytes(n, 'little'))


class Emu:
    """Interpreter for the opcode forms found in the two functions."""

    def __init__(self, mem):
        self.mem = mem
        self.r = [0] * 16
        self.cf = 0
        self.zf = 0
        self.calls = []
        self.rip = 0
        self.done = False
        self.steps = 0

    def ea(self, d, i, rex, size_imm=0):
        modrm = d[i]
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        i += 1
        reg |= 8 if rex & 4 else 0
        if mod == 3:
            return reg, ('r', rm | (8 if rex & 1 else 0)), i
        if rm == 4:
            sib = d[i]
            i += 1
            scale, idx, base = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
            idx |= 8 if rex & 2 else 0
            base |= 8 if rex & 1 else 0
            if base & 7 == 5 and mod == 0:
                raise Fault('sib disp32 base unsupported')
            addr = self.r[base] + (0 if idx == 4 else self.r[idx] * scale)
        elif rm == 5 and mod == 0:
            disp = struct.unpack_from('<i', d, i)[0]
            i += 4
            return reg, ('m', (self.rip + i + size_imm + disp) & MASK), i
        else:
            addr = self.r[rm | (8 if rex & 1 else 0)]
        if mod == 1:
            addr += struct.unpack_from('<b', d, i)[0]
            i += 1
        elif mod == 2:
            addr += struct.unpack_from('<i', d, i)[0]
            i += 4
        return reg, ('m', addr & MASK), i

    def get(self, loc, size):
        if loc[0] == 'r':
            return self.r[loc[1]] & ((1 << (8 * size)) - 1)
        return self.mem.u(loc[1], size)

    def put(self, loc, size, val):
        if loc[0] == 'r':
            if size == 8:
                self.r[loc[1]] = val & MASK
            elif size == 4:
                self.r[loc[1]] = val & 0xFFFFFFFF
            else:
                mask = (1 << (8 * size)) - 1
                self.r[loc[1]] = (self.r[loc[1]] & ~mask & MASK) | (val & mask)
        else:
            self.mem.w(loc[1], size, val)

    def push(self, val):
        self.r[4] -= 8
        self.mem.w(self.r[4], 8, val)

    def pop(self):
        val = self.mem.u(self.r[4], 8)
        self.r[4] += 8
        return val

    def flags_sub(self, a, b, size):
        mask = (1 << (8 * size)) - 1
        a &= mask
        b &= mask
        self.cf = 1 if a < b else 0
        self.zf = 1 if a == b else 0
        return (a - b) & mask

    def record(self, kind, target):
        stack = tuple(self.mem.u(self.r[4] + 8 * k, 8) for k in range(6)) if self.mem._find(self.r[4], 0x30)[0] is not None else ()
        self.calls.append((kind, target, self.r[7], self.r[6], self.r[2], stack))

    def run(self, entry, limit=400):
        self.rip = entry
        while not self.done:
            self.steps += 1
            if self.steps > limit:
                raise Fault('step limit')
            self.step()

    def step(self):
        d = self.mem.image.read(self.rip, 16)
        i = 0
        opsz = 4
        rex = 0
        if d[i] == 0x66:
            opsz = 2
            i += 1
        if 0x40 <= d[i] <= 0x4F:
            rex = d[i]
            i += 1
            if rex & 8:
                opsz = 8
        op = d[i]
        i += 1
        start = self.rip
        r = self.r

        def fin(n):
            self.rip = start + n

        if 0x50 <= op <= 0x57:
            self.push(r[(op - 0x50) | (8 if rex & 1 else 0)])
            return fin(i)
        if 0x58 <= op <= 0x5F:
            r[(op - 0x58) | (8 if rex & 1 else 0)] = self.pop()
            return fin(i)
        if op == 0xC3:
            self.done = True
            return None
        if op in (0x89, 0x8B, 0x85, 0x31, 0x01):
            reg, loc, i = self.ea(d, i, rex)
            if op == 0x89:
                self.put(loc, opsz, r[reg])
            elif op == 0x8B:
                self.put(('r', reg), opsz, self.get(loc, opsz))
            elif op == 0x85:
                v = self.get(loc, opsz) & r[reg] & ((1 << (8 * opsz)) - 1)
                self.zf = 1 if v == 0 else 0
                self.cf = 0
            elif op == 0x01:
                self.put(loc, opsz, self.get(loc, opsz) + r[reg])
            else:
                v = self.get(loc, opsz) ^ r[reg]
                self.put(loc, opsz, v)
            return fin(i)
        if op == 0x8D:
            reg, loc, i = self.ea(d, i, rex)
            if loc[0] != 'm':
                raise Fault('lea register')
            self.put(('r', reg), opsz, loc[1])
            return fin(i)
        if op == 0x63:
            reg, loc, i = self.ea(d, i, rex)
            v = self.get(loc, 4)
            v = v - (1 << 32) if v & 0x80000000 else v
            self.put(('r', reg), 8, v & MASK)
            return fin(i)
        if op in (0x83, 0x81, 0x80, 0xC7):
            size_imm = 1 if op in (0x83, 0x80) else (2 if opsz == 2 else 4)
            reg, loc, i = self.ea(d, i, rex, size_imm)
            ext = reg & 7
            if op == 0x83:
                imm = struct.unpack_from('<b', d, i)[0]
            elif op == 0x80:
                imm = d[i]
            elif opsz == 2:
                imm = struct.unpack_from('<H', d, i)[0]
            else:
                imm = struct.unpack_from('<i', d, i)[0]
            i += size_imm
            size = 1 if op == 0x80 else opsz
            if op == 0xC7:
                if ext != 0:
                    raise Fault('c7 ext')
                self.put(loc, size, imm & MASK)
            elif ext == 0:
                self.put(loc, size, self.get(loc, size) + imm)
            elif ext == 5:
                self.put(loc, size, self.flags_sub(self.get(loc, size), imm & MASK, size))
            elif ext == 7:
                self.flags_sub(self.get(loc, size), imm & MASK, size)
            else:
                raise Fault('group1 ext %d' % ext)
            return fin(i)
        if op == 0x6B:
            reg, loc, i = self.ea(d, i, rex, 1)
            imm = struct.unpack_from('<b', d, i)[0]
            i += 1
            self.put(('r', reg), opsz, self.get(loc, opsz) * imm)
            return fin(i)
        if 0xB8 <= op <= 0xBF:
            self.put(('r', (op - 0xB8) | (8 if rex & 1 else 0)), 4, struct.unpack_from('<I', d, i)[0])
            return fin(i + 4)
        if 0xB0 <= op <= 0xB7:
            self.put(('r', (op - 0xB0) | (8 if rex & 1 else 0)), 1, d[i])
            return fin(i + 1)
        if op == 0xFF:
            reg, loc, i = self.ea(d, i, rex)
            ext = reg & 7
            if ext == 4:
                if loc[0] == 'm' and self.mem.image.read(start, 2) == b'\xff\x25':
                    self.rip = start + i
                    self.record('slot', loc[1])
                    r[0] = EXT_RET ^ loc[1]
                    self.done = True
                    return None
                self.rip = self.get(loc, 8)
                return None
            raise Fault('ff ext %d' % ext)
        if op == 0xE8:
            rel = struct.unpack_from('<i', d, i)[0]
            self.record('call', (start + i + 4 + rel) & MASK)
            r[0] = 0
            return fin(i + 4)
        if op in (0xE9, 0xEB):
            if op == 0xE9:
                rel, n = struct.unpack_from('<i', d, i)[0], 4
            else:
                rel, n = struct.unpack_from('<b', d, i)[0], 1
            self.rip = (start + i + n + rel) & MASK
            return None
        if op in (0x74, 0x75):
            rel = struct.unpack_from('<b', d, i)[0]
            take = self.zf if op == 0x74 else not self.zf
            self.rip = (start + i + 1 + (rel if take else 0)) & MASK
            return None
        if op == 0x0F:
            op2 = d[i]
            i += 1
            if op2 == 0x42:
                reg, loc, i = self.ea(d, i, rex)
                if self.cf:
                    self.put(('r', reg), opsz, self.get(loc, opsz))
                return fin(i)
            if op2 == 0x94:
                reg, loc, i = self.ea(d, i, rex)
                self.put(loc, 1, self.zf)
                return fin(i)
            if op2 == 0xB6:
                reg, loc, i = self.ea(d, i, rex)
                self.put(('r', reg), opsz, self.get(loc, 1))
                return fin(i)
        raise Fault('unsupported opcode at %#x' % start)


def tag_index(tag):
    """Index used by both functions for a first-word discriminant."""
    return tag - TAG_BASE if tag >= TAG_BASE else DEFAULT_INDEX


# --- generated action objects ---------------------------------------------

class Rng:
    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFFFFFFFFFF

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.s >> 11

    def below(self, n):
        return self.next() % n


def make_chain(rng, tags, mem):
    """Lay out one object per tag; field +0x20 links to the next, +0x10/+0x18 describe a vector."""
    addrs = [OBJ_BASE + k * OBJ_SIZE for k in range(len(tags))]
    vec_base = OBJ_BASE + len(tags) * OBJ_SIZE
    count = rng.below(5)
    mem.add(OBJ_BASE, len(tags) * OBJ_SIZE + 0x38 * 4 + 0x40)
    for k, tag in enumerate(tags):
        for off in range(8, OBJ_SIZE, 8):
            mem.w(addrs[k] + off, 8, rng.next() << 7 ^ rng.next())
        mem.w(addrs[k], 8, tag)
        mem.w(addrs[k] + 0x10, 8, vec_base)
        mem.w(addrs[k] + 0x18, 8, count)
        mem.w(addrs[k] + 0x20, 8, addrs[k + 1] if k + 1 < len(tags) else addrs[k])
        for off in (0x55, 0x56):
            mem.w(addrs[k] + off, 1, rng.below(2))
    for e in range(4):
        mem.w(vec_base + 0x38 * e + 0x36, 1, 1 if rng.below(4) else 0)
    return addrs


def case_tags(rng, n):
    """Tag chains: the first tag walks every valid index and the default region in order."""
    pool = list(range(TAG_BASE, TAG_BASE + TAG_COUNT)) + [0, 1, 0x85, 0x20, 0x7f]
    first = TAG_BASE + 52 if n % 7 == 3 else pool[n % len(pool)]
    chain = [first]
    for _ in range(rng.below(4)):
        chain.append(pool[rng.below(len(pool))])
    if chain[-1] == TAG_BASE + 52:
        chain[-1] = TAG_BASE - 1
    return chain


def fresh(image, rng, tags):
    mem = Mem(image)
    addrs = make_chain(rng, tags, mem)
    mem.add(OUT_BASE, 0x40, 0x5C)
    mem.add(STK_TOP - STK_SIZE, STK_SIZE, POISON)
    return mem, addrs


# --- the hand-written reconstruction --------------------------------------

SEL_NEST, SEL_FWD, SEL_SCALAR, SEL_VEC, SEL_SPECIAL = 'nest', 'fwd8', 'scalar', 'vec', 'special'
CLS_NEST, CLS_TRUE, CLS_SLOT, CLS_BYTE, CLS_ALL = 'nest', 'true', 'slot', 'byte', 'all'

SCALAR_CALL = 0x2785b80
VEC_CALL = 0x27848b0
SPECIAL_CALL = 0x451e890
VEC_STRIDE = 0x38
NEST_FIELD = 0x20

# Every index not listed selects the empty result (selector) or false (classifier).
SELECTOR_ARMS = {
    2: (SEL_FWD, 0x2cf0440), 3: (SEL_FWD, 0x2608ee0), 4: (SEL_FWD, 0x250f370), 7: (SEL_FWD, 0x283b490),
    10: (SEL_FWD, 0x262bb70), 12: (SEL_SCALAR, 0x40), 13: (SEL_FWD, 0x273fd20), 14: (SEL_VEC, None),
    29: (SEL_FWD, 0x245b8c0), 32: (SEL_FWD, 0x23995b0), 35: (SEL_SCALAR, 0x10), 36: (SEL_SCALAR, 0x50),
    37: (SEL_SCALAR, 0x10), 38: (SEL_SCALAR, 0x20), 39: (SEL_SCALAR, 0xc), 40: (SEL_SPECIAL, None),
    42: (SEL_FWD, 0x283c770), 43: (SEL_FWD, 0x283c020), 44: (SEL_FWD, 0x283c770), 48: (SEL_FWD, 0x246cdd0),
    51: (SEL_FWD, 0x2398c40), 52: (SEL_NEST, None), 57: (SEL_FWD, 0x283cbf0), 59: (SEL_FWD, 0x239da20),
    62: (SEL_FWD, 0x245b670), 68: (SEL_FWD, 0x2947ff0), 69: (SEL_FWD, 0x246d020), 71: (SEL_FWD, 0x285c210),
    75: (SEL_FWD, 0x23992e0), 79: (SEL_FWD, 0x283bfa0), 81: (SEL_FWD, 0x2392180), 82: (SEL_FWD, 0x285e480),
    88: (SEL_FWD, 0x26683f0), 89: (SEL_SCALAR, 0x58), 90: (SEL_FWD, 0x283c630), 91: (SEL_FWD, 0x2a1eb80),
}
CLASSIFIER_ARMS = {
    2: (CLS_SLOT, GOT_SLOT), 3: (CLS_TRUE, None), 4: (CLS_TRUE, None), 12: (CLS_BYTE, 0x56),
    14: (CLS_ALL, None), 18: (CLS_TRUE, None), 35: (CLS_TRUE, None), 36: (CLS_BYTE, 0x55),
    52: (CLS_NEST, None),
}


def stack_view(words):
    """Six stack qwords at the body stack pointer; unwritten words keep the poison byte."""
    poison = int.from_bytes(bytes([POISON]) * 8, 'little')
    return tuple(words.get(8 * k, poison) for k in range(6))


class Knobs:
    """Constants of the reconstruction; controls perturb one at a time."""

    def __init__(self, **kw):
        self.base = TAG_BASE
        self.default = DEFAULT_INDEX
        self.empty = EMPTY_WORD
        self.stride = VEC_STRIDE
        self.nest = NEST_FIELD
        self.count = TAG_COUNT
        self.__dict__.update(kw)


def model_selector(mem, obj, rdx, arms=None, k=None):
    """Reconstruction of 0x2bdb5b0: (calls, first 0x20 output bytes, rax)."""
    arms = SELECTOR_ARMS if arms is None else arms
    k = k or Knobs()
    out = bytearray([0x5C]) * 0x20
    sp = STK_TOP - 8 - 8 - 0x30
    for _ in range(64):
        tag = mem.u(obj, 8)
        idx = tag - k.base if tag >= k.base else k.default
        if idx >= k.count:
            raise ValueError('tag outside the 92-entry table')
        kind, par = arms.get(idx, (None, None))
        if kind == SEL_NEST:
            obj = mem.u(obj + k.nest, 8)
            continue
        calls = ()
        if kind is None:
            out[0x08:0x10] = bytes(8)
            out[0x18:0x20] = bytes(8)
            out[0:2] = k.empty.to_bytes(2, 'little')
        elif kind == SEL_FWD:
            calls = (('call', par, OUT_BASE, obj + 8, rdx, stack_view({})),)
        elif kind == SEL_SCALAR:
            calls = (('call', SCALAR_CALL, OUT_BASE, sp, rdx,
                      stack_view({0: rdx, 8: 0, 0x10: 1, 0x18: (POISON_HIGH << 32) | mem.u(obj + par, 4)})),)
        elif kind == SEL_VEC:
            ptr = mem.u(obj + 0x10, 8)
            end = (ptr + mem.u(obj + 0x18, 8) * k.stride) & MASK
            calls = (('call', VEC_CALL, OUT_BASE, sp, rdx, stack_view({0: ptr, 8: end, 0x10: rdx})),)
        else:
            words = {0x20: 4, 0x28: 0, 0: 1, 8: 0, 0x10: 1, 0x18: 0}
            calls = (('call', SPECIAL_CALL, OUT_BASE + 8, sp, rdx, stack_view(words)),)
            out[0:2] = k.empty.to_bytes(2, 'little')
        return (calls, bytes(out), OUT_BASE)
    raise ValueError('nest depth')


def model_classifier(mem, obj, arms=None, k=None):
    """Reconstruction of 0x36c30f0: (rax, calls as (kind, target, rdi))."""
    arms = CLASSIFIER_ARMS if arms is None else arms
    k = k or Knobs()
    for _ in range(64):
        tag = mem.u(obj, 8)
        idx = tag - k.base if tag >= k.base else k.default
        if idx >= k.count:
            raise ValueError('tag outside the 92-entry table')
        kind, par = arms.get(idx, (None, None))
        if kind == CLS_NEST:
            obj = mem.u(obj + k.nest, 8)
            continue
        if kind is None:
            return (0, ())
        if kind == CLS_TRUE:
            return (1, ())
        if kind == CLS_BYTE:
            return (mem.u(obj + par, 1), ())
        if kind == CLS_SLOT:
            return (EXT_RET ^ par, (('slot', par, obj + 8),))
        ptr = mem.u(obj + 0x10, 8)
        for e in range(mem.u(obj + 0x18, 8)):
            if mem.u(ptr + k.stride * e + 0x36, 1) == 0:
                return (0, ())
        return (1, ())
    raise ValueError('nest depth')


def run_bytes(image, spec, tags, seed, rdx):
    """Run the real function bytes; same observation shape as the model."""
    rng = Rng(seed)
    mem, addrs = fresh(image, rng, tags)
    emu = Emu(mem)
    emu.r[4] = STK_TOP - 8
    emu.r[6] = addrs[0]
    emu.r[2] = rdx
    if spec is SELECTOR:
        emu.r[7] = OUT_BASE
    else:
        emu.r[7] = addrs[0]
    emu.run(spec[0])
    if spec is SELECTOR:
        return mem, addrs, (tuple(emu.calls), bytes(mem.regions[OUT_BASE][:0x20]), emu.r[0])
    return mem, addrs, (emu.r[0], tuple((c[0], c[1], c[2]) for c in emu.calls))


def run_model(spec, mem, addrs, rdx, arms=None, knobs=None):
    if spec is SELECTOR:
        return model_selector(mem, addrs[0], rdx, arms, knobs)
    return model_classifier(mem, addrs[0], arms, knobs)


def compare(image, spec, n, seed0, arms=None, knobs=None, stop_at_first=False):
    """Compare model and bytes over n generated cases; returns (cases, mismatches)."""
    bad = 0
    for c in range(n):
        rng = Rng(seed0 + 977 * c)
        tags = case_tags(rng, c)
        rdx = rng.next()
        try:
            mem, addrs, want = run_bytes(image, spec, tags, seed0 + c, rdx)
            got = run_model(spec, mem, addrs, rdx, arms, knobs)
        except (Fault, ValueError):
            bad += 1
        else:
            bad += got != want
        if bad and stop_at_first:
            break
    return n, bad


# --- negative controls ------------------------------------------------------

def with_arm(arms, idx, entry):
    new = dict(arms)
    if entry is None:
        new.pop(idx, None)
    else:
        new[idx] = entry
    return new


def model_controls():
    """(label, spec, arms, knobs) — deliberately wrong reconstructions."""
    rows = []
    for idx, (kind, par) in sorted(SELECTOR_ARMS.items()):
        if kind == SEL_FWD:
            rows.append(('selector idx %d wrong callee' % idx, SELECTOR, with_arm(SELECTOR_ARMS, idx, (kind, par + 0x10)), None))
        elif kind == SEL_SCALAR:
            rows.append(('selector idx %d wrong field offset' % idx, SELECTOR, with_arm(SELECTOR_ARMS, idx, (kind, par + 4)), None))
        elif idx in (14, 40, 52):
            rows.append(('selector idx %d arm dropped' % idx, SELECTOR, with_arm(SELECTOR_ARMS, idx, None), None))
    rows.append(('selector idx 20 given an arm', SELECTOR, with_arm(SELECTOR_ARMS, 20, (SEL_FWD, 0x2cf0440)), None))
    rows.append(('selector idx 41 given an arm', SELECTOR, with_arm(SELECTOR_ARMS, 41, (SEL_FWD, 0x2cf0440)), None))
    rows.append(('selector tag base 0x87', SELECTOR, None, Knobs(base=TAG_BASE + 1)))
    rows.append(('selector default index 0x0e', SELECTOR, None, Knobs(default=14)))
    rows.append(('selector empty word 0x1a3', SELECTOR, None, Knobs(empty=EMPTY_WORD + 1)))
    rows.append(('selector vector stride 0x30', SELECTOR, None, Knobs(stride=0x30)))
    rows.append(('selector nest field 0x28', SELECTOR, None, Knobs(nest=0x28)))
    for idx, (kind, par) in sorted(CLASSIFIER_ARMS.items()):
        if kind == CLS_TRUE:
            rows.append(('classifier idx %d true -> false' % idx, CLASSIFIER, with_arm(CLASSIFIER_ARMS, idx, None), None))
        elif kind == CLS_BYTE:
            rows.append(('classifier idx %d byte offset swapped' % idx, CLASSIFIER, with_arm(CLASSIFIER_ARMS, idx, (kind, 0x55 + 0x56 - par)), None))
        elif kind == CLS_ALL:
            rows.append(('classifier idx 14 all -> true', CLASSIFIER, with_arm(CLASSIFIER_ARMS, idx, (CLS_TRUE, None)), None))
        elif kind == CLS_NEST:
            rows.append(('classifier idx 52 nest dropped', CLASSIFIER, with_arm(CLASSIFIER_ARMS, idx, None), None))
        elif kind == CLS_SLOT:
            rows.append(('classifier idx 2 slot -> false', CLASSIFIER, with_arm(CLASSIFIER_ARMS, idx, None), None))
    rows.append(('classifier idx 5 given true', CLASSIFIER, with_arm(CLASSIFIER_ARMS, 5, (CLS_TRUE, None)), None))
    rows.append(('classifier default idx 0x0c', CLASSIFIER, None, Knobs(default=12)))
    rows.append(('classifier tag base 0x85', CLASSIFIER, None, Knobs(base=TAG_BASE - 1)))
    rows.append(('classifier stride 0x40', CLASSIFIER, None, Knobs(stride=0x40)))
    return rows


# byte flips applied to the real code: (label, spec, address, new byte)
BYTE_CONTROLS = (
    ('selector: tag base 0x86 -> 0x87', SELECTOR, 0x2bdb5bb, 0x87),
    ('selector: default index 0x14 -> 0x0e', SELECTOR, 0x2bdb5c0, 0x0e),
    ('selector: empty word 0x1a2 -> 0x1a3', SELECTOR, 0x2bdb608, 0xa3),
    ('selector: vector stride 0x38 -> 0x30', SELECTOR, 0x2bdb78c, 0x30),
    ('selector: scalar offset 0x10 -> 0x14', SELECTOR, 0x2bdb615, 0x14),
    ('selector: nested field 0x20 -> 0x28', SELECTOR, 0x2bdb5dc, 0x28),
    ('classifier: tag base 0x86 -> 0x87', CLASSIFIER, 0x36c30f6, 0x87),
    ('classifier: flag byte 0x56 -> 0x57', CLASSIFIER, 0x36c314d, 0x57),
    ('classifier: element flag 0x36 -> 0x37', CLASSIFIER, 0x36c316b, 0x37),
    ('classifier: return true -> false', CLASSIFIER, 0x36c313e, 0x00),
)

DOMAIN_CONTROLS = ((0xe2, 'first tag past the table'), (0xff, 'byte limit'), (0x1000, 'large tag'),
                   (0x2000000000000000, 'huge tag'))


def run_controls(image):
    rows = []
    for label, spec, arms, knobs in model_controls():
        _, bad = compare(image, spec, 1500, 4001, arms, knobs, stop_at_first=True)
        rows.append((label, 'model', bad > 0))
    for label, spec, va, value in BYTE_CONTROLS:
        old = image.patches.get(va)
        image.patches[va] = value
        try:
            _, bad = compare(image, spec, 1500, 5003, stop_at_first=True)
        finally:
            if old is None:
                del image.patches[va]
            else:
                image.patches[va] = old
        rows.append((label, 'bytes', bad > 0))
    for tag, label in DOMAIN_CONTROLS:
        for spec, name in ((SELECTOR, 'selector'), (CLASSIFIER, 'classifier')):
            mem, addrs = fresh(image, Rng(7), [tag])
            try:
                run_model(spec, mem, addrs, 0)
                caught = False
            except ValueError:
                caught = True
            rows.append(('%s: %s (%#x)' % (name, label, tag), 'domain', caught))
    try:
        Image(Path(__file__))
        caught = False
    except ValueError:
        caught = True
    rows.append(('image: wrong digest refused', 'digest', caught))
    return rows


# --- evidence ---------------------------------------------------------------

def arm_rows(image):
    sel, cls = image.table(SELECTOR), image.table(CLASSIFIER)
    yield 'function\tindex\ttag\ttable_target\tkind\tparameter'
    for name, tab, arms, dflt in (('selector', sel, SELECTOR_ARMS, None), ('classifier', cls, CLASSIFIER_ARMS, None)):
        for i, target in enumerate(tab):
            kind, par = arms.get(i, ('empty' if name == 'selector' else 'false', None))
            yield '%s\t%d\t%#x\t%#x\t%s\t%s' % (name, i, TAG_BASE + i, target, kind, '' if par is None else hex(par))


def generate(out, cases_per_function=6000, sample_every=12):
    image = Image()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'arms.tsv').write_text('\n'.join(arm_rows(image)) + '\n')
    total = bad_total = 0
    per = {}
    with open(out / 'cases-sample.tsv', 'w') as fh:
        fh.write('function\tcase\ttags\trdx\tbytes_result\tmodel_result\tmatch\n')
        for spec, name in ((SELECTOR, 'selector'), (CLASSIFIER, 'classifier')):
            bad = 0
            for c in range(cases_per_function):
                rng = Rng(11 + 977 * c)
                tags = case_tags(rng, c)
                rdx = rng.next()
                mem, addrs, want = run_bytes(image, spec, tags, 11 + c, rdx)
                got = run_model(spec, mem, addrs, rdx)
                bad += got != want
                if c % sample_every == 0:
                    fh.write('%s\t%d\t%s\t%#x\t%s\t%s\t%d\n' % (
                        name, c, ','.join('%#x' % t for t in tags), rdx, digest(want), digest(got), got == want))
            per[name] = {'cases': cases_per_function, 'mismatches': bad}
            total += cases_per_function
            bad_total += bad
    rows = run_controls(image)
    with open(out / 'controls.tsv', 'w') as fh:
        fh.write('control\tkind\tdetected\n')
        for label, kind, ok in rows:
            fh.write('%s\t%s\t%d\n' % (label, kind, ok))
    detected = sum(1 for r in rows if r[2])
    summary = {
        'binary_sha256': DIGEST,
        'selector': {'start': hex(SELECTOR[0]), 'end': hex(SELECTOR[1]), 'table': hex(SELECTOR[2])},
        'classifier': {'start': hex(CLASSIFIER[0]), 'end': hex(CLASSIFIER[1]), 'table': hex(CLASSIFIER[2])},
        'table_entries': TAG_COUNT,
        'selector_distinct_arm_targets': len(set(image.table(SELECTOR))),
        'classifier_distinct_arm_targets': len(set(image.table(CLASSIFIER))),
        'per_function': per,
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    (out / 'measure.json').write_text(json.dumps(
        {'cases': total, 'negative_controls': len(rows), 'negative_detected': detected, 'mismatches': bad_total},
        indent=2, sort_keys=True) + '\n')
    return total, bad_total, len(rows), detected


def digest(obs):
    return hashlib.sha256(repr(obs).encode()).hexdigest()[:16]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args(argv)
    total, bad, controls, detected = generate(args.out)
    print('cases %d mismatches %d controls %d detected %d' % (total, bad, controls, detected))
    return 0 if bad == 0 and controls == detected else 1


if __name__ == '__main__':
    sys.exit(main())
