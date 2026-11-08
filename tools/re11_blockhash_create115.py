#!/usr/bin/env python3
"""Reconstruct and validate node #115 EVM BLOCKHASH (cache probe/insert) and CREATE/CREATE2 frame setup.

Two RE-011 opcode families share one ELF reader, one x86-64 evaluator, one deterministic case stream
and one output tail.  Both families use the RELATIVE opcode tables 0x6441210 / 0x6441f00
(index = opcode); a shared check proves that both families read the same two tables.

BLOCKHASH (opcode 0x40): 0x2995350 (table 0x6441210, inlined hashbrown cache) and 0x29951e0 (table
0x6441f00, direct provider call).  Each returns 0x2c on an empty stack.  Otherwise the stack top is
a requested block number and the current number is the u256 at host +0x30..+0x50.  A request that is
not strictly below the current number, or more than 256 blocks below it (cmp $0x101 on the
distance), yields zero.  A request in the window is handed on as a u64 (u64::MAX when limbs 1..3
are nonzero).  The direct copy calls the provider behind GOT 0x64e6450 with the object at host
+0x398.  The cached copy probes a hashbrown table at that object (ctrl +0x68, mask +0x70,
growth_left +0x78, items +0x80, secret +0x88, 0x40-byte buckets keyed by a 32-byte key whose first
u64 is the number and the only hashed part).  On a miss it calls hashbrown reserve (GOT 0x64e6df0)
when growth_left is zero, then calls the provider with the value at +0x90, inserts the answer and
decrements growth_left only for an EMPTY slot.  The 32 answer bytes become the stack word
big-endian.

CREATE (slot 0xf0, body 0x299bea0) and CREATE2 (slot 0xf5, body 0x299b760): each body checks the
static flag and the spec gate, pops value / offset / length (and the CREATE2 salt, popped late),
applies the spec-gated initcode size limit (host override, configured code size times two, or
0xc000 / 0x10000 by host spec) and per-word initcode charge, grows memory through the
memory-growth callee, copies the init code into a fresh buffer that becomes a Bytes value (vtable
chosen by the pointer parity), charges the base price (CREATE2 adds a per-word hashing price), runs
the optional reservoir step, keeps gas/divisor in the parent, boxes a 0xc8-byte create-inputs
record, drops the old pending action and stores the new one.

The tool reads every relocation, FDE extent and code byte from the ELF file and pins the
displacements and constants that the reconstructions rely on.  It evaluates the real machine code
with a small concrete x86-64 evaluator (no external programs; the binary is never executed;
callees are contract stubs that check or record their arguments).  It compares every case with
the pure-Python reconstructions, and negative controls show that wrong reconstructions and
corrupted code bytes are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
M64 = (1 << 64) - 1
M128 = (1 << 128) - 1
M256 = (1 << 256) - 1


STACK_TOP = 0x7ff0_0000_0000
RETURN_MARK = 0x7e00_dead_0000
SENTINEL = 0xa5a5a5a5a5a5a5a5
IMPORT_BASE = 0x7c00_0000_0000

class ToolError(Exception):
    pass


class Boundary(Exception):
    def __init__(self, kind, regs):
        super().__init__(kind)
        self.kind, self.regs = kind, list(regs)


def fail(message):
    raise ToolError(message)


# ---------------------------------------------------------------- ELF image
class Image:
    def __init__(self, data, check=True):
        if check and hashlib.sha256(data).hexdigest() != SHA256:
            fail("input binary SHA-256 does not match node #115")
        self.data = data
        self.secs = elf_index.sections(data)
        # SHT_NOBITS sections have no file bytes and are never used for VA reads.
        self.mapped = [(s["address"], s["offset"], s["size"], s["name"]) for s in self.secs
                       if s["type"] != 8 and s["address"] and s["size"]]
        rela = next(s for s in self.secs if s["name"] == ".rela.dyn")
        self.relative, self.imports = {}, {}
        for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
            where, info, addend = struct.unpack_from("<QQq", data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend & M64
            elif info & 0xffffffff == 6:  # GLOB_DAT import: a synthetic, distinct target per symbol
                self.relative[where] = IMPORT_BASE + 16 * (info >> 32)
                self.imports[where] = info >> 32
        self.text = next(s for s in self.secs if s["name"] == ".text")

    def import_name(self, slot):
        dynsym = next(s for s in self.secs if s["name"] == ".dynsym")
        dynstr = next(s for s in self.secs if s["name"] == ".dynstr")
        name_off = struct.unpack_from("<I", self.data, dynsym["offset"] + 24 * self.imports[slot])[0]
        end = self.data.index(b"\0", dynstr["offset"] + name_off)
        return self.data[dynstr["offset"] + name_off:end].decode("ascii")

    def section_of(self, va):
        for addr, off, size, name in self.mapped:
            if addr <= va < addr + size:
                return name, va - addr + off
        return None, None

    def read(self, va, size):
        name, off = self.section_of(va)
        if name is None:
            fail(f"read outside file-backed sections at {va:#x}")
        return self.data[off:off + size]

    def word(self, va):
        """A relocated 8-byte word: the RELATIVE addend if present, else file bytes."""
        if va in self.relative:
            return self.relative[va]
        return struct.unpack("<Q", self.read(va, 8))[0]

    def code(self, va, size):
        t = self.text
        if not (t["address"] <= va and va + size <= t["address"] + t["size"]):
            fail(f"code outside .text at {va:#x}")
        return self.data[va - t["address"] + t["offset"]:va - t["address"] + t["offset"] + size]


def fde_rows(image, starts):
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    rows = {}
    for fde in fdes:
        if fde["start"] in starts:
            rows[fde["start"]] = (fde["start"], fde["end"])
    for start in starts:
        if start not in rows:
            fail(f"no FDE starts at {start:#x}")
    return rows


# ---------------------------------------------------------------- decoder
def decode(code, va):
    """Decode one instruction of the forms used on this path; raise on others."""
    p, opsize, rex, rep, fs, f2, p66 = 0, 32, 0, False, False, False, False
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64, 0xf0):  # operand size, segments, rep/repne, lock
        if code[p] == 0x66:
            opsize, p66 = 16, True
        if code[p] == 0xf3:
            rep = True
        if code[p] == 0xf2:
            f2 = True
        if code[p] == 0x64:
            fs = True
        p += 1
    if 0x40 <= code[p] <= 0x4f:
        rex, p = code[p], p + 1
    if rex & 8:
        opsize = 64
    op = code[p]
    p += 1
    if op == 0x0f:
        op = 0x0f00 | code[p]
        p += 1
    form = {"op": op, "rex": rex, "size": opsize, "rep": rep, "fs": fs, "f2": f2, "p66": p66}

    def modrm(q):
        m = code[q]
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1), m & 7
        q += 1
        form["reg"] = reg
        if mod == 3:
            form["rm"] = ("r", rm | ((rex & 1) << 3))
            return q
        base, index, scale, disp = None, None, 1, 0
        if rm == 4:
            sib = code[q]
            q += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            index = None if index == 4 else index
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", code, q)[0]
                q += 4
        elif rm == 5 and mod == 0:
            base = "rip"
            disp = struct.unpack_from("<i", code, q)[0]
            q += 4
        else:
            base = rm | ((rex & 1) << 3)
        if mod == 1:
            disp = struct.unpack_from("<b", code, q)[0]
            q += 1
        elif mod == 2:
            disp = struct.unpack_from("<i", code, q)[0]
            q += 4
        form["rm"] = ("m", base, index, scale, disp)
        return q

    if 0x50 <= op <= 0x5f:
        form["r"] = (op & 7) | ((rex & 1) << 3)
    elif op in (0xc3, 0x90, 0x0f0b, 0xcc):
        pass
    elif op in (0x11, 0x13, 0x38, 0x88, 0x0f57, 0x01, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x29, 0x2b, 0x31, 0x33,
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x87, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f1e, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5, 0x0fad, 0x0fbd, 0x0fa3, 0x0feb, 0x0f50, 0x0f54, 0x0f56) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
    elif op in (0x0f70, 0x0fc6, 0x0fa4, 0x0fac):
        p = modrm(p)
        form["imm"] = code[p]
        p += 1
    elif op == 0x69:
        p = modrm(p)
        form["imm"] = struct.unpack_from("<i", code, p)[0]
        p += 4
    elif op == 0x6b:
        p = modrm(p)
        form["imm"] = struct.unpack_from("<b", code, p)[0]
        p += 1
    elif op in (0x3d, 0x05):
        form["imm"] = struct.unpack_from("<i", code, p)[0]
        p += 4
    elif op in (0x0c, 0x1c, 0x3c, 0x24):
        form["imm"] = code[p]
        p += 1
    elif op == 0xc6:
        p = modrm(p)
        form["imm"] = code[p]
        p += 1
    elif op == 0xf6:
        p = modrm(p)
        if form["reg"] & 7 != 0:
            fail(f"unsupported f6 form at {va:#x}")
        form["imm"] = code[p]
        p += 1
    elif 0xb0 <= op <= 0xb7:
        form["r"] = (op & 7) | ((rex & 1) << 3)
        form["imm"] = code[p]
        p += 1
    elif op in (0x83, 0xc1, 0x80):
        p = modrm(p)
        form["imm"] = struct.unpack_from("<b", code, p)[0] if op != 0xc1 else code[p]
        p += 1
    elif op in (0x81, 0xc7):
        p = modrm(p)
        form["imm"] = struct.unpack_from("<i", code, p)[0]
        p += 4
    elif op == 0xf7:
        p = modrm(p)
        if form["reg"] & 7 in (0, 1):
            form["imm"] = struct.unpack_from("<i", code, p)[0]
            p += 4
    elif op == 0xa8:
        form["imm"] = code[p]
        p += 1
    elif 0xb8 <= op <= 0xbf:
        form["r"] = (op & 7) | ((rex & 1) << 3)
        n = 8 if rex & 8 else 4
        form["imm"] = int.from_bytes(code[p:p + n], "little")
        p += n
    elif 0x70 <= op <= 0x7f or op == 0xeb:
        form["rel"] = struct.unpack_from("<b", code, p)[0]
        p += 1
    elif 0x0f80 <= op <= 0x0f8f or op in (0xe8, 0xe9):
        form["rel"] = struct.unpack_from("<i", code, p)[0]
        p += 4
    elif 0x0fc8 <= op <= 0x0fcf:
        form["r"] = (op & 7) | ((rex & 1) << 3)
    else:
        fail(f"unsupported opcode {op:#x} at {va:#x}")
    form["len"] = p
    form["bytes"] = bytes(code[:p])
    if "rel" in form:
        form["target"] = (va + p + form["rel"]) & M64
    return form


def sweep(image, start, end):
    """Linear decode of [start, end); every byte must belong to a decoded form."""
    rows, va = [], start
    while va < end:
        form = decode(image.code(va, min(16, end - va + 16)), va)
        rows.append((va, form))
        va += form["len"]
    if va != end:
        fail(f"linear decode overruns {end:#x}")
    return rows


# ---------------------------------------------------------------- evaluator
class Machine:
    def __init__(self, image, code_override=None):
        self.image = image
        self.override = code_override or {}
        self.cache = {}
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.zf = self.sf = self.cf = False
        self.regions = []
        self.stubs = {}
        self.words = {}
        self.steps = 0
        self.writes = set()
        self.stops = {}
        self.add_region(STACK_TOP - 0x10000, 0x10000)
        self.regs[4] = STACK_TOP - 0x100

    def add_region(self, base, size, content=b""):
        buf = bytearray(size)
        buf[:len(content)] = content
        self.regions.append((base, base + size, buf))
        return buf

    def load(self, at, size):
        at &= M64
        if size == 8 and at in self.words:
            return self.words[at]
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                return int.from_bytes(buf[at - lo:at - lo + size], "little")
        if size == 16 and self.image.section_of(at)[0] is not None:  # two relocated words
            return self.load(at, 8) | self.load(at + 8, 8) << 64
        if any(at <= w < at + size for w in self.words):
            fail(f"partial read of a stubbed word at {at:#x}")
        if size == 8 and at in self.image.relative:
            return self.image.relative[at]
        return int.from_bytes(self.image.read(at, size), "little")

    def store(self, at, size, value):
        at &= M64
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                buf[at - lo:at - lo + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
                self.writes.add((at, size))
                return
        fail(f"write outside writable regions at {at:#x}")

    def fetch(self, va):
        form = self.cache.get(va)
        if form is None:
            code = bytearray(self.image.code(va, 16))
            for i in range(16):
                if va + i in self.override:
                    code[i] = self.override[va + i]
            form = decode(bytes(code), va)
            self.cache[va] = form
        return form

    def ea(self, rm, form, va):
        _, base, index, scale, disp = rm
        if base == "rip":
            return (va + form["len"] + disp) & M64
        if form["fs"]:
            fail(f"fs-relative operand at {va:#x}")
        at = disp
        if base is not None:
            at += self.regs[base]
        if index is not None:
            at += self.regs[index] * scale
        return at & M64

    def get(self, rm, size, form, va):
        if rm[0] == "r":
            return self.reg(rm[1], size, form)
        return self.load(self.ea(rm, form, va), size // 8)

    def put(self, rm, size, value, form, va):
        if rm[0] == "r":
            self.set_reg(rm[1], size, value, form)
        else:
            self.store(self.ea(rm, form, va), size // 8, value)

    def reg(self, r, size, form):
        if size == 8 and not form["rex"] and 4 <= r < 8:
            fail("high-byte register form is outside the supported subset")
        return self.regs[r] & ((1 << size) - 1)

    def set_reg(self, r, size, value, form):
        mask = (1 << size) - 1
        if size == 64:
            self.regs[r] = value & M64
        elif size == 32:
            self.regs[r] = value & mask
        else:
            if size == 8 and not form["rex"] and 4 <= r < 8:
                fail("high-byte register form is outside the supported subset")
            self.regs[r] = (self.regs[r] & ~mask & M64) | (value & mask)

    def flags_logic(self, res, size):
        res &= (1 << size) - 1
        self.zf, self.sf, self.cf, self.of = res == 0, bool(res >> (size - 1)), False, None
        return res

    def flags_add(self, a, b, size):
        res = a + b
        self.cf = res >> size != 0
        res &= (1 << size) - 1
        hb = size - 1
        self.of = (a >> hb) == (b >> hb) and (res >> hb) != (a >> hb)
        self.zf, self.sf = res == 0, bool(res >> (size - 1))
        return res

    def flags_adc(self, a, b, size):
        res = a + b + (1 if self.cf else 0)
        self.cf, self.of = res >> size != 0, None
        res &= (1 << size) - 1
        self.zf, self.sf = res == 0, bool(res >> (size - 1))
        return res

    def flags_sbb(self, a, b, size):
        cin = 1 if self.cf else 0
        self.cf, self.of = a < b + cin, None
        res = (a - b - cin) & ((1 << size) - 1)
        self.zf, self.sf = res == 0, bool(res >> (size - 1))
        return res

    def flags_sub(self, a, b, size):
        self.cf = a < b
        res = (a - b) & ((1 << size) - 1)
        hb = size - 1
        self.of = (a >> hb) != (b >> hb) and (res >> hb) != (a >> hb)
        self.zf, self.sf = res == 0, bool(res >> (size - 1))
        return res

    def cond(self, code, va):
        if code in (0, 1):
            if getattr(self, "of", None) is None:
                fail(f"overflow flag read without a defining mul at {va:#x}")
            return self.of if code == 0 else not self.of
        if code == 2:
            return self.cf
        if code == 3:
            return not self.cf
        if code == 4:
            return self.zf
        if code == 5:
            return not self.zf
        if code == 6:
            return self.cf or self.zf
        if code == 7:
            return not (self.cf or self.zf)
        if code == 8:
            return self.sf
        if code == 9:
            return not self.sf
        if code in (12, 13, 14, 15):
            if getattr(self, "of", None) is None:
                fail(f"signed condition without a defined overflow flag at {va:#x}")
            less = self.sf != self.of
            if code == 12:
                return less
            if code == 13:
                return not less
            if code == 14:
                return less or self.zf
            return not (less or self.zf)
        fail(f"unsupported condition {code} at {va:#x}")

    def push(self, value):
        self.regs[4] = (self.regs[4] - 8) & M64
        self.store(self.regs[4], 8, value)

    def pop(self):
        value = self.load(self.regs[4], 8)
        self.regs[4] = (self.regs[4] + 8) & M64
        return value

    def transfer(self, target, call, va):
        if target in self.stubs:
            kind = self.stubs[target]
            if callable(kind):
                kind(self)
                return self.pop() if not call else None
            raise Boundary(kind, self.regs)
        if call:
            self.push(va)
        return target

    def run(self, start, limit=200000):
        self.push(RETURN_MARK)
        pc = start
        while pc != RETURN_MARK:
            if pc in self.stops:
                raise Boundary(self.stops[pc], self.regs)
            self.steps += 1
            if self.steps > limit:
                fail("step limit")
            pc = self.step(pc)
        return self.steps

    def step(self, va):
        f = self.fetch(va)
        op, size, nxt = f["op"], f["size"], (va + f["len"]) & M64
        if 0x50 <= op <= 0x57:
            self.push(self.regs[f["r"]])
        elif 0x58 <= op <= 0x5f:
            self.regs[f["r"]] = self.pop()
        elif op == 0xc3:
            return self.pop()
        elif op == 0x90 or op == 0x0f1f or (op == 0x0f1e and f["rep"]):
            pass
        elif op in (0x01, 0x09, 0x21, 0x29, 0x31, 0x39, 0x85, 0x89):
            a, b = self.get(f["rm"], size, f, va), self.reg(f["reg"], size, f)
            if op == 0x89:
                self.put(f["rm"], size, b, f, va)
            elif op == 0x01:
                self.put(f["rm"], size, self.flags_add(a, b, size), f, va)
            elif op == 0x29:
                self.put(f["rm"], size, self.flags_sub(a, b, size), f, va)
            elif op == 0x39:
                self.flags_sub(a, b, size)
            elif op == 0x85:
                self.flags_logic(a & b, size)
            else:
                res = {0x09: a | b, 0x21: a & b, 0x31: a ^ b}[op]
                self.put(f["rm"], size, self.flags_logic(res, size), f, va)
        elif op in (0x03, 0x0b, 0x23, 0x2b, 0x33, 0x3b, 0x8b):
            a, b = self.reg(f["reg"], size, f), self.get(f["rm"], size, f, va)
            r = ("r", f["reg"])
            if op == 0x8b:
                self.put(r, size, b, f, va)
            elif op == 0x03:
                self.put(r, size, self.flags_add(a, b, size), f, va)
            elif op == 0x2b:
                self.put(r, size, self.flags_sub(a, b, size), f, va)
            elif op == 0x3b:
                self.flags_sub(a, b, size)
            else:
                res = {0x0b: a | b, 0x23: a & b, 0x33: a ^ b}[op]
                self.put(r, size, self.flags_logic(res, size), f, va)
        elif op == 0x87:  # xchg r/m, r
            a, b = self.get(f["rm"], size, f, va), self.reg(f["reg"], size, f)
            self.put(f["rm"], size, b, f, va)
            self.set_reg(f["reg"], size, a, f)
        elif op == 0x8d:
            if f["rm"][0] != "m":
                fail("lea with a register operand")
            self.set_reg(f["reg"], size, self.ea(f["rm"], f, va), f)
        elif op in (0x81, 0x83, 0x80):
            if op == 0x80:
                size = 8
            mask = (1 << size) - 1
            a, b, kind = self.get(f["rm"], size, f, va), f["imm"] & mask, f["reg"] & 7
            if kind == 0:
                self.put(f["rm"], size, self.flags_add(a, b, size), f, va)
            elif kind == 5:
                self.put(f["rm"], size, self.flags_sub(a, b, size), f, va)
            elif kind == 7:
                self.flags_sub(a, b, size)
            elif kind in (1, 4, 6):
                res = {1: a | b, 4: a & b, 6: a ^ b}[kind]
                self.put(f["rm"], size, self.flags_logic(res, size), f, va)
            elif kind == 3:
                self.put(f["rm"], size, self.flags_sbb(a, b, size), f, va)
            elif kind == 2:
                self.put(f["rm"], size, self.flags_adc(a, b, size), f, va)
            else:
                fail(f"unsupported group-1 form at {va:#x}")
        elif op in (0x08, 0x20, 0x84):
            a, b = self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f)
            res = self.flags_logic({0x08: a | b, 0x20: a & b, 0x84: a & b}[op], 8)
            if op != 0x84:
                self.put(f["rm"], 8, res, f, va)
        elif op in (0x0a, 0x22):
            a, b = self.reg(f["reg"], 8, f), self.get(f["rm"], 8, f, va)
            self.set_reg(f["reg"], 8, self.flags_logic(a | b if op == 0x0a else a & b, 8), f)
        elif op == 0x19:
            a, b = self.get(f["rm"], size, f, va), self.reg(f["reg"], size, f)
            self.put(f["rm"], size, self.flags_sbb(a, b, size), f, va)
        elif op == 0x1b:
            a, b = self.reg(f["reg"], size, f), self.get(f["rm"], size, f, va)
            self.set_reg(f["reg"], size, self.flags_sbb(a, b, size), f)
        elif op == 0x63:
            if size != 64:
                fail("movsxd without REX.W")
            v = self.get(f["rm"], 32, f, va)
            self.set_reg(f["reg"], 64, v - (1 << 32) if v >> 31 else v, f)
        elif 0x0f90 <= op <= 0x0f9f:
            self.put(f["rm"], 8, 1 if self.cond(op & 15, va) else 0, f, va)
        elif op == 0xc6:
            if f["reg"] & 7:
                fail("unsupported c6 form")
            self.put(f["rm"], 8, f["imm"], f, va)
        elif op == 0xf6:
            self.flags_logic(self.get(f["rm"], 8, f, va) & f["imm"], 8)
        elif 0xb0 <= op <= 0xb7:
            self.set_reg(f["r"], 8, f["imm"], f)
        elif op == 0xa8:
            self.flags_logic(self.regs[0] & f["imm"], 8)
        elif 0xb8 <= op <= 0xbf:
            self.set_reg(f["r"], 64 if f["rex"] & 8 else 32, f["imm"], f)
        elif op == 0xc7:
            if f["reg"] & 7:
                fail("unsupported c7 form")
            self.put(f["rm"], size, f["imm"] & ((1 << size) - 1), f, va)
        elif op in (0xc1, 0xd1):
            count = (f["imm"] if op == 0xc1 else 1) & (63 if size == 64 else 31)
            a, kind, mask = self.get(f["rm"], size, f, va), f["reg"] & 7, (1 << size) - 1
            if kind == 0:
                res = ((a << count) | (a >> (size - count))) & mask if count else a
            elif kind == 7:
                res = (a - (1 << size) if a >> (size - 1) else a) >> count & mask
                self.flags_logic(res, size)
            elif kind == 4:
                res = (a << count) & mask
                self.flags_logic(res, size)
            elif kind == 5:
                res = a >> count
                self.flags_logic(res, size)
            else:
                fail(f"unsupported shift form at {va:#x}")
            self.put(f["rm"], size, res, f, va)
        elif op == 0xf7:
            kind = f["reg"] & 7
            a = self.get(f["rm"], size, f, va)
            if kind == 0:
                self.flags_logic(a & (f["imm"] & ((1 << size) - 1)), size)
            elif kind == 2:
                self.put(f["rm"], size, ~a, f, va)
            elif kind == 3:
                res = self.flags_sub(0, a, size)
                self.cf = a != 0
                self.put(f["rm"], size, res, f, va)
            elif kind == 4:
                if size != 64:
                    fail("unsupported mul width")
                prod = self.regs[0] * a
                self.regs[0], self.regs[2] = prod & M64, prod >> 64
                self.cf = self.regs[2] != 0
                self.of = self.cf  # unsigned mul: OF == CF; mul defines OF as CF
            elif kind == 6:  # unsigned div of rdx:rax (or edx:eax) by r/m
                if a == 0:
                    fail(f"divide by zero at {va:#x}")
                mask = (1 << size) - 1
                num = (self.regs[2] & mask) << size | (self.regs[0] & mask)
                q, r = divmod(num, a)
                if q > mask:
                    fail(f"divide overflow at {va:#x}")
                self.set_reg(0, size, q, f)
                self.set_reg(2, size, r, f)
                self.cf = self.of = None
            else:
                fail(f"unsupported f7 form at {va:#x}")
        elif op == 0xff:
            kind = f["reg"] & 7
            if kind in (0, 1):
                a = self.get(f["rm"], size, f, va)
                cf = self.cf
                res = self.flags_add(a, 1, size) if kind == 0 else self.flags_sub(a, 1, size)
                self.cf = cf
                self.put(f["rm"], size, res, f, va)
            elif kind == 6:
                self.push(self.get(f["rm"], 64, f, va))
            elif kind in (2, 4):
                target = self.get(f["rm"], 64, f, va)
                nxt2 = self.transfer(target, kind == 2, nxt)
                return nxt if nxt2 is None else nxt2
            else:
                fail(f"unsupported ff form at {va:#x}")
        elif 0x70 <= op <= 0x7f:
            return f["target"] if self.cond(op & 15, va) else nxt
        elif 0x0f80 <= op <= 0x0f8f:
            return f["target"] if self.cond(op & 15, va) else nxt
        elif op in (0xeb, 0xe9):
            nxt2 = self.transfer(f["target"], False, nxt)
            return nxt2
        elif op == 0xe8:
            nxt2 = self.transfer(f["target"], True, nxt)
            return nxt if nxt2 is None else nxt2
        elif 0x0f40 <= op <= 0x0f4f:
            value = self.get(f["rm"], size, f, va)
            if self.cond(op & 15, va):
                self.set_reg(f["reg"], size, value, f)
            elif size == 32:
                self.set_reg(f["reg"], 32, self.regs[f["reg"]], f)
        elif op == 0x0fa3:  # bt r/m, r (register forms only)
            if f["rm"][0] != "r":
                fail(f"unsupported bt memory form at {va:#x}")
            self.cf = bool(self.get(f["rm"], size, f, va) >> (self.reg(f["reg"], size, f) % size) & 1)
        elif op == 0x0fb6:
            self.set_reg(f["reg"], size, self.get(f["rm"], 8, f, va), f)
        elif 0x0fc8 <= op <= 0x0fcf:
            v = self.reg(f["r"], size, f)
            self.set_reg(f["r"], size, int.from_bytes(v.to_bytes(size // 8, "little"), "big"), f)
        elif op == 0x11:
            a, b = self.get(f["rm"], size, f, va), self.reg(f["reg"], size, f)
            self.put(f["rm"], size, self.flags_adc(a, b, size), f, va)
        elif op == 0x13:
            a, b = self.reg(f["reg"], size, f), self.get(f["rm"], size, f, va)
            self.set_reg(f["reg"], size, self.flags_adc(a, b, size), f)
        elif op == 0x88:
            self.put(f["rm"], 8, self.reg(f["reg"], 8, f), f, va)
        elif op == 0x38:
            self.flags_sub(self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f), 8)
        elif op == 0x0f57:
            rm = f["rm"]
            other = self.xmm[rm[1]] if rm[0] == "r" else self.load(self.ea(rm, f, va), 16)
            self.xmm[f["reg"]] ^= other
        elif op == 0x0f0b:
            fail(f"ud2 reached at {va:#x}")
        elif op == 0x0c:
            self.set_reg(0, 8, self.flags_logic((self.regs[0] | f["imm"]) & 0xff, 8), f)
        elif op == 0x24:
            self.set_reg(0, 8, self.flags_logic(self.regs[0] & f["imm"] & 0xff, 8), f)
        elif op == 0x1c:
            self.set_reg(0, 8, self.flags_sbb(self.regs[0] & 0xff, f["imm"], 8), f)
        elif op == 0x05:
            mask = (1 << size) - 1
            self.set_reg(0, size, self.flags_add(self.regs[0] & mask, f["imm"] & mask, size), f)
        elif op == 0x3d:
            mask = (1 << size) - 1
            self.flags_sub(self.regs[0] & mask, f["imm"] & mask, size)
        elif op in (0x69, 0x6b):
            mask = (1 << size) - 1
            a = self.get(f["rm"], size, f, va)
            a = a - (1 << size) if a >> (size - 1) else a
            prod = a * f["imm"]
            self.set_reg(f["reg"], size, prod & mask, f)
            self.of = None  # flags of imul are not modelled; reading them fails
        elif op in (0x0f6f, 0x0f74, 0x0fdb):
            rm = f["rm"]
            if rm[0] == "r":
                other = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if not f["rep"] and at % 16:  # movdqa and legacy-SSE memory operands need 16-byte alignment
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                other = self.load(at, 16)
            if op == 0x0f6f:
                self.xmm[f["reg"]] = other
            elif op == 0x0fdb:
                self.xmm[f["reg"]] &= other
            else:
                a = self.xmm[f["reg"]]
                self.xmm[f["reg"]] = sum((0xff << (8 * i)) for i in range(16)
                                         if (a >> (8 * i)) & 0xff == (other >> (8 * i)) & 0xff)
        elif op == 0x0f7f:
            rm = f["rm"]
            if rm[0] == "r":
                self.xmm[rm[1]] = self.xmm[f["reg"]]
            else:
                at = self.ea(rm, f, va)
                if not f["rep"] and at % 16:
                    fail(f"movdqa to unaligned {at:#x} at {va:#x}")
                self.store(at, 16, self.xmm[f["reg"]])
        elif op == 0x0fd7:
            if f["rm"][0] != "r":
                fail("pmovmskb with a memory operand")
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(16) if (v >> (8 * i + 7)) & 1), f)
        elif op == 0x0f10 and f["rep"]:
            rm = f["rm"]
            if rm[0] == "r":
                self.xmm[f["reg"]] = (self.xmm[f["reg"]] & ~0xffffffff) | (self.xmm[rm[1]] & 0xffffffff)
            else:
                self.xmm[f["reg"]] = self.load(self.ea(rm, f, va), 4)
        elif op in (0x0f10, 0x0f28):
            rm = f["rm"]
            value = self.xmm[rm[1]] if rm[0] == "r" else self.load(self.ea(rm, f, va), 16)
            self.xmm[f["reg"]] = value
        elif op in (0x0f11, 0x0f29):
            rm = f["rm"]
            at = None if rm[0] == "r" else self.ea(rm, f, va)
            if op == 0x0f29 and at is not None and at % 16:
                fail(f"movaps to unaligned {at:#x} at {va:#x}")
            if at is None:
                self.xmm[rm[1]] = self.xmm[f["reg"]]
            else:
                self.store(at, 16, self.xmm[f["reg"]])
        elif op == 0x3c:
            self.flags_sub(self.regs[0] & 0xff, f["imm"], 8)
        elif op == 0x28:
            a, b = self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f)
            self.put(f["rm"], 8, self.flags_sub(a, b, 8), f, va)
        elif op == 0xd3:
            count = self.regs[1] & (63 if size == 64 else 31)
            a, kind, mask = self.get(f["rm"], size, f, va), f["reg"] & 7, (1 << size) - 1
            if kind == 4:
                res = (a << count) & mask
            elif kind == 5:
                res = a >> count
            elif kind == 7:
                res = (a - (1 << size) if a >> (size - 1) else a) >> count & mask
            else:
                fail(f"unsupported d3 form at {va:#x}")
            if count:
                self.flags_logic(res, size)
            self.put(f["rm"], size, res, f, va)
        elif op == 0x0fb7:
            self.set_reg(f["reg"], size, self.get(f["rm"], 16, f, va), f)
        elif op == 0x0fbc:
            if not f["rep"]:
                fail("bsf is outside the supported subset")
            a = self.get(f["rm"], size, f, va)
            res = (a & -a).bit_length() - 1 if a else size
            self.cf, self.zf = a == 0, res == 0
            self.put(("r", f["reg"]), size, res, f, va)
        elif op == 0x0fef:
            rm = f["rm"]
            if rm[0] != "r":
                fail("pxor with a memory operand")
            self.xmm[f["reg"]] ^= self.xmm[rm[1]]
        elif op == 0x0f6e:
            if not f["p66"] or f["rex"] & 8:
                fail(f"unsupported 0f6e form at {va:#x}")
            self.xmm[f["reg"]] = self.get(f["rm"], 32, f, va)
        elif op in (0x0f60, 0x0f76, 0x0ffb, 0x0f70, 0x0fc6):
            if not (f["p66"] or (op == 0x0f70 and f["f2"])):
                fail(f"unsupported SSE form {op:#x} at {va:#x}")
            rm = f["rm"]
            if rm[0] == "r":
                b = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                b = self.load(at, 16)
            a = self.xmm[f["reg"]]
            if op == 0x0f60:  # punpcklbw
                res = 0
                for i in range(8):
                    res |= ((a >> (8 * i)) & 0xff) << (16 * i) | ((b >> (8 * i)) & 0xff) << (16 * i + 8)
            elif op == 0x0f76:  # pcmpeqd
                res = sum((0xffffffff << (32 * i)) for i in range(4)
                          if (a >> (32 * i)) & 0xffffffff == (b >> (32 * i)) & 0xffffffff)
            elif op == 0x0ffb:  # psubq
                res = (((a & M64) - (b & M64)) & M64) | ((((a >> 64) - (b >> 64)) & M64) << 64)
            elif op == 0x0f70 and f["f2"]:  # pshuflw
                imm = f["imm"]
                words = [(b >> (16 * i)) & 0xffff for i in range(4)]
                res = sum(words[(imm >> (2 * i)) & 3] << (16 * i) for i in range(4)) | (b >> 64) << 64
            elif op == 0x0f70:  # pshufd
                imm = f["imm"]
                dw = [(b >> (32 * i)) & 0xffffffff for i in range(4)]
                res = sum(dw[(imm >> (2 * i)) & 3] << (32 * i) for i in range(4))
            else:  # shufpd
                imm = f["imm"]
                lo = (a >> 64) if imm & 1 else a & M64
                hi = (b >> 64) if imm & 2 else b & M64
                res = lo | hi << 64
            self.xmm[f["reg"]] = res & M128
        elif op == 0x0fa5:  # shld r/m64, r64, cl
            if size != 64:
                fail("shld width")
            count = self.regs[1] & 63
            a, b = self.get(f["rm"], 64, f, va), self.reg(f["reg"], 64, f)
            res = ((a << count) | (b >> (64 - count))) & M64 if count else a
            if count:
                self.flags_logic(res, 64)
            self.put(f["rm"], 64, res, f, va)
        elif op in (0x0fa4, 0x0fac, 0x0fad):  # shld imm / shrd imm / shrd cl
            if size != 64:
                fail("shld/shrd width")
            count = (f["imm"] if op != 0x0fad else self.regs[1]) & 63
            a, b = self.get(f["rm"], 64, f, va), self.reg(f["reg"], 64, f)
            if op == 0x0fa4:
                res = ((a << count) | (b >> (64 - count))) & M64 if count else a
            else:
                res = ((a >> count) | (b << (64 - count))) & M64 if count else a
            if count:
                self.flags_logic(res, 64)
            self.put(f["rm"], 64, res, f, va)
        elif op == 0x0fbd:  # bsr: a zero source sets ZF and leaves the destination unchanged
            if f["rep"]:
                fail("lzcnt is outside the supported subset")
            a = self.get(f["rm"], size, f, va)
            self.zf = a == 0
            self.cf = self.of = None
            if a:
                self.set_reg(f["reg"], size, a.bit_length() - 1, f)
        elif op == 0x0feb:  # por
            if not f["p66"]:
                fail(f"unsupported 0feb form at {va:#x}")
            rm = f["rm"]
            if rm[0] == "r":
                b = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                b = self.load(at, 16)
            self.xmm[f["reg"]] |= b
        elif op in (0x0f54, 0x0f56):  # andps / orps
            if f["p66"]:
                fail(f"unsupported {op:#x} form at {va:#x}")
            rm = f["rm"]
            if rm[0] == "r":
                b = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                b = self.load(at, 16)
            self.xmm[f["reg"]] = self.xmm[f["reg"]] & b if op == 0x0f54 else self.xmm[f["reg"]] | b
        elif op == 0x0f50:  # movmskps
            if f["p66"] or f["rm"][0] != "r":
                fail(f"unsupported 0f50 form at {va:#x}")
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
        elif op == 0xcc:
            fail(f"int3 reached at {va:#x}")
        else:
            fail(f"unhandled opcode {op:#x} at {va:#x}")
        return nxt

class TraceMachine(Machine):
    """Machine that also records every executed instruction address across runs."""

    def __init__(self, image, code_override=None):
        self.seen = set()
        super().__init__(image, code_override)

    def step(self, va):
        self.seen.add(va)
        return super().step(va)



# ---------------------------------------------------------------- deterministic streams
class Stream:
    def __init__(self, label):
        self.label, self.n, self.buf = label.encode(), 0, b""

    def take(self, k):
        while len(self.buf) < k:
            self.buf += hashlib.sha512(self.label + self.n.to_bytes(8, "little")).digest()
            self.n += 1
        out, self.buf = self.buf[:k], self.buf[k:]
        return out

    def below(self, n):
        return int.from_bytes(self.take(8), "little") % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


def put(buf, off, size, value):
    buf[off:off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def u(buf, off, size):
    return int.from_bytes(buf[off:off + size], "little")


_IMAGE = []


def load_image():
    """The checked #115 image, parsed once per process."""
    if not _IMAGE:
        _IMAGE.append(Image(BINARY.read_bytes()))
    return _IMAGE[0]


# ================================================================ blockhash family
# ---------------------------------------------------------------- target constants
BH_BH_CACHED = 0x2995350  # opcode 0x40 in the RELATIVE table 0x6441210 (index = opcode); inlined cache probe + insert
BH_BH_DIRECT = 0x29951e0  # opcode 0x40 in the RELATIVE table 0x6441f00; calls the provider without a cache
BH_OP_TABLES = ((0x6441210, BH_BH_CACHED), (0x6441f00, BH_BH_DIRECT))
BH_BLOCKHASH_OP, BH_SLOAD_OP = 0x40, 0x54
BH_PROVIDER_GOT = 0x64e6450  # RELATIVE slot -> provider body 0x43c8b20 (stubbed: arguments recorded)
BH_RESERVE_GOT = 0x64e6df0  # RELATIVE slot -> hashbrown reserve called when growth_left is zero (stubbed)
BH_SEED_GOT = 0x64dfa78  # RELATIVE slot -> per-process hash seed word (NOBITS, so the tool supplies it)

# interpreter offsets
BH_I_STACK_PTR, BH_I_STACK_LEN = 0x28, 0x30
# host offsets
BH_H_NUMBER, BH_H_CACHE = 0x30, 0x398  # u256 current block number (4 limbs), pointer handed to the provider / cache
# cache object offsets (copy at 0x2995350 only)
BH_C_CTRL, BH_C_MASK, BH_C_GROWTH, BH_C_ITEMS, BH_C_SECRET, BH_C_SELF = 0x68, 0x70, 0x78, 0x80, 0x88, 0x90
BH_BUCKET = 0x40  # 32-byte key (u64 number + 24 bytes compared, not hashed) + 32-byte hash
BH_WINDOW = 0x100  # cmp $0x101: a distance of 1..256 blocks is served

BH_INTERP_AT = 0x7d00_0000_0000
BH_INTERP_SIZE = 0x200
BH_HOST_AT = 0x7d00_0100_0000
BH_HOST_SIZE = 0x400
BH_STK_AT = 0x7d00_0300_0000
BH_TABLE_AT = 0x7d00_0400_0000
BH_CACHE_AT = 0x7d00_0600_0000
BH_CACHE_SIZE = 0x100
BH_PROVIDER_SELF = 0x7d00_0700_0040  # opaque value stored at cache +0x90
BH_INTERP_FILL, BH_HOST_FILL, BH_STACK_FILL, BH_TABLE_FILL, BH_CACHE_FILL = 0x33, 0x44, 0x5c, 0x66, 0x77
BH_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
BH_REGROWN = 5  # growth_left the reserve stub leaves behind

BH_R_OK, BH_R_UNDERFLOW = 0x00, 0x2c


# ---------------------------------------------------------------- reconstruction
def bh_number_hash(num, secret, seed, mut=frozenset()):
    """Hash of the u64 block number: folded multiply with the cache secret (+0x88) and the process seed."""
    p = (num ^ (secret if "hash_no_secret" not in mut else 0)) * seed
    z = (p & M64) ^ (p >> 64)
    p = z * seed
    return (p & M64) ^ (p >> 64)


def bh_window(cur, req, mut=frozenset()):
    """Block number handed on, or None when the request is not in the last 256 blocks."""
    span = BH_WINDOW if "window_255" not in mut else BH_WINDOW - 1
    if req >= cur and "allow_current" not in mut:
        return None
    if req > cur or cur - req > span:
        return None
    if req > M64:
        return req & M64 if "truncate_number" in mut else M64
    return req


def bh_provided(num):
    """The stubbed provider's answer for a block number (sometimes all zero, to show zeros are cached too)."""
    d = hashlib.sha256(b"re11-blockhash-provider" + num.to_bytes(8, "little")).digest()
    return bytes(32) if d[0] < 0x18 else d


def bh_key_bytes(num, pad=bytes(24)):
    return num.to_bytes(8, "little") + pad


def bh_ctrl_layout(nb, ctrl):
    """Control bytes of a hashbrown table: nb real bytes then 16 trailing bytes, mirrored with
    index2 = ((i - 16) & mask) + 16 (for nb < 16 the bytes nb..15 stay EMPTY)."""
    full = [0xff] * (nb + 16)
    for i, b in enumerate(ctrl):
        full[i] = b
        full[((i - 16) & (nb - 1)) + 16] = b
    return full


def bh_table_bytes(nb, ctrl, buckets):
    """Memory of a table: buckets (slot -> 64 bytes) below the control bytes."""
    mem = bytearray([BH_TABLE_FILL]) * (nb * BH_BUCKET) + bytes(bh_ctrl_layout(nb, ctrl))
    for slot, data in buckets.items():
        at = nb * BH_BUCKET - (slot + 1) * BH_BUCKET
        mem[at:at + BH_BUCKET] = data
    return mem


def bh_insert_slot(nb, ctrl, h, mut=frozenset()):
    """hashbrown find_insert_slot: first EMPTY/DELETED byte on the triangular probe from h & mask; when the
    hit lands on a full byte (only for nb < 16) take the first special byte of group 0."""
    full = bh_ctrl_layout(nb, ctrl)
    mask, pos, stride = nb - 1, h & (nb - 1), 0
    while True:
        bits = [k for k in range(16) if full[pos + k] & 0x80]
        if bits:
            slot = (pos + bits[0]) & mask
            break
        stride += 16
        pos = (pos + stride) & mask
    if not full[slot] & 0x80 and "no_small_fixup" not in mut:
        slot = next(k for k in range(16) if full[k] & 0x80)
    return slot


def bh_model(c, mut=frozenset()):
    """BLOCKHASH 0x2995350 / 0x29951e0 reconstructed: result, stack, provider/reserve calls and cache state."""
    st = {"n": c["n"], "top": c["stack"][-1] if c["stack"] else None}
    ev = []
    cache = {"ctrl": list(c["ctrl"]), "buckets": dict(c["buckets"]), "growth": c["growth"], "items": c["items"]}

    def done(code):
        return {"ret": ("ret", code), "state": st, "events": ev, "cache": cache}
    if c["n"] == 0:
        return done(BH_R_UNDERFLOW)
    num = bh_window(c["cur"], c["stack"][-1], mut)
    if num is None:
        st["top"] = 0 if "keep_top_out_of_window" not in mut else st["top"]
        return done(BH_R_OK)
    if c["entry"] == BH_BH_DIRECT:
        ev.append(("provider", "host[0x398]", num))
        raw = bh_provided(num)
    else:
        key = bh_key_bytes(num)
        if "ignore_padding" in mut:
            pool = list(c["entries"].items()) + [(k, bytes(32)) for _, _, k in c["decoys"]]
            hit = next((v for k, v in pool if k[:8] == key[:8]), None)
        else:
            hit = None if "never_hit" in mut else c["entries"].get(key)
        if hit is not None:
            raw = hit
        else:
            if cache["growth"] == 0 or "always_reserve" in mut:
                ev.append(("reserve", "cache+0x68", 1, "cache+0x88", 1))
                cache["growth"] = BH_REGROWN
            ev.append(("provider", "cache[0x90]", num))
            raw = bh_provided(num)
            h = bh_number_hash(num, c["secret"], c["seed"], mut)
            slot = bh_insert_slot(c["buckets_n"], cache["ctrl"], h, mut)
            old = cache["ctrl"][slot]
            cache["ctrl"][slot] = h >> 57
            cache["growth"] -= old & 1 if "growth_always" not in mut else 1
            cache["items"] += 1
            cache["buckets"][slot] = key + raw
    st["top"] = int.from_bytes(raw, "big" if "little_result" not in mut else "little")
    return done(BH_R_OK)


# ---------------------------------------------------------------- fixture
def bh_build_table(c):
    """Place the cache entries (and decoys) with the reconstructed hash, so a hash error shows as a miss."""
    nb = c["buckets_n"]
    ctrl = [0xff] * nb
    for i in c["tombs"]:
        ctrl[i] = 0x80
    buckets = {}
    for slot, h2, key in c["decoys"]:
        ctrl[slot] = h2
        buckets[slot] = key + bytes(32)
    for key, value in c["order"]:
        h = bh_number_hash(int.from_bytes(key[:8], "little"), c["secret"], c["seed"], c.get("fixture_mut", frozenset()))
        full = bh_ctrl_layout(nb, ctrl)
        pos, stride = h & (nb - 1), 0
        while True:
            free = [(pos + k) & (nb - 1) for k in range(16) if full[pos + k] in (0xff, 0x80)
                    and ctrl[(pos + k) & (nb - 1)] in (0xff, 0x80)]
            if free:
                slot = free[0]
                break
            stride += 16
            pos = (pos + stride) & (nb - 1)
        ctrl[slot] = h >> 57
        buckets[slot] = key + value
    if 0xff not in ctrl:
        fail("table has no EMPTY slot")
    return ctrl, buckets


def bh_setup(m, c):
    events = []
    m.regions[0][2][:] = bytes([BH_STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(BH_INTERP_AT, BH_INTERP_SIZE, bytes([BH_INTERP_FILL]) * BH_INTERP_SIZE)
    put(it, BH_I_STACK_PTR, 8, BH_STK_AT)
    put(it, BH_I_STACK_LEN, 8, c["n"])
    host = m.add_region(BH_HOST_AT, BH_HOST_SIZE, bytes([BH_HOST_FILL]) * BH_HOST_SIZE)
    put(host, BH_H_NUMBER, 32, c["cur"])
    put(host, BH_H_CACHE, 8, BH_CACHE_AT)
    nb = c["buckets_n"]
    cache = m.add_region(BH_CACHE_AT, BH_CACHE_SIZE, bytes([BH_CACHE_FILL]) * BH_CACHE_SIZE)
    put(cache, BH_C_CTRL, 8, BH_TABLE_AT + nb * BH_BUCKET)
    put(cache, BH_C_MASK, 8, nb - 1)
    put(cache, BH_C_GROWTH, 8, c["growth"])
    put(cache, BH_C_ITEMS, 8, c["items"])
    put(cache, BH_C_SECRET, 8, c["secret"])
    put(cache, BH_C_SELF, 8, BH_PROVIDER_SELF)
    m.add_region(BH_TABLE_AT, nb * BH_BUCKET + nb + 16, bytes(bh_table_bytes(nb, c["ctrl"], c["buckets"])))
    m.add_region(BH_STK_AT, 0x20 * max(1, len(c["stack"])), b"".join(w.to_bytes(32, "little") for w in c["stack"]))
    m.add_region(m.image.word(BH_SEED_GOT), 8, c["seed"].to_bytes(8, "little"))

    def clobber(mc):
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):  # the callee may clobber every caller-saved register
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1
        mc.xmm = [0xc2c2_c2c2_c2c2_c2c2_c2c2_c2c2_c2c2_c2c2] * 16

    def provider(mc):
        out, me, num = mc.regs[7], mc.regs[6], mc.regs[2]
        who = {BH_CACHE_AT: "host[0x398]", BH_PROVIDER_SELF: "cache[0x90]"}.get(me, f"{me:#x}")
        events.append(("provider", who, num))
        for i, b in enumerate(bh_provided(num)):
            mc.store(out + i, 1, b)
        clobber(mc)

    def reserve(mc):
        def rel(p):
            return f"cache+{p - BH_CACHE_AT:#x}" if BH_CACHE_AT <= p < BH_CACHE_AT + BH_CACHE_SIZE else f"{p:#x}"
        events.append(("reserve", rel(mc.regs[7]), mc.regs[6], rel(mc.regs[2]), mc.regs[1]))
        mc.store(BH_CACHE_AT + BH_C_GROWTH, 8, BH_REGROWN)
        clobber(mc)
    m.stubs = {m.image.word(BH_PROVIDER_GOT): provider, m.image.word(BH_RESERVE_GOT): reserve}
    return events


def bh_run_case(m, c):
    m.reset()
    events = bh_setup(m, c)
    keep = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in (BH_HOST_AT, m.image.word(BH_SEED_GOT))}
    before = bytes(next(buf for lo, hi, buf in m.regions if lo == BH_INTERP_AT))
    stk_before = bytes(next(buf for lo, hi, buf in m.regions if lo == BH_STK_AT))
    cache_before = bytes(next(buf for lo, hi, buf in m.regions if lo == BH_CACHE_AT))
    for k, v in zip((3, 12, 13, 14, 15, 5), BH_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = BH_INTERP_AT, BH_HOST_AT
    got = {"events": events}
    it = next(buf for lo, hi, buf in m.regions if lo == BH_INTERP_AT)
    stk = next(buf for lo, hi, buf in m.regions if lo == BH_STK_AT)
    cache = next(buf for lo, hi, buf in m.regions if lo == BH_CACHE_AT)
    table = next(buf for lo, hi, buf in m.regions if lo == BH_TABLE_AT)
    try:
        m.run(c["entry"], limit=20000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == BH_SAVED and m.regs[4] == STACK_TOP - 0x100
    n = u(it, BH_I_STACK_LEN, 8)
    got["state"] = {"n": n, "top": u(stk, 0x20 * (n - 1), 32) if 0 < n <= c["n"] else None}
    srest = bytearray(stk)
    if c["n"]:
        srest[0x20 * (c["n"] - 1):0x20 * c["n"]] = stk_before[0x20 * (c["n"] - 1):0x20 * c["n"]]
    crest = bytearray(cache)
    for off in (BH_C_GROWTH, BH_C_ITEMS):
        crest[off:off + 8] = cache_before[off:off + 8]
    got["cache_raw"] = (u(cache, BH_C_GROWTH, 8), u(cache, BH_C_ITEMS, 8), bytes(table))
    now = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in keep}
    got["rest_ok"] = now == keep and bytes(it) == before and bytes(srest) == stk_before and bytes(crest) == cache_before
    return got


def bh_compare(c, want, got):
    if want["ret"] != got["ret"] or want["events"] != got["events"] or want["state"] != got["state"]:
        return False
    w = want["cache"]
    if got["cache_raw"] != (w["growth"], w["items"], bytes(bh_table_bytes(c["buckets_n"], w["ctrl"], w["buckets"]))):
        return False
    return got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
BH_TOTAL = 4800
BH_CUR_POOL = (0, 1, 2, 0x100, 0x101, 0x102, 0x1000, M64 - 1, M64, 1 << 64, (1 << 64) + 0x80, (1 << 64) + 0x200,
            1 << 128, (1 << 192) + 5, M256)
BH_MODES = ["hit", "miss", "reserve", "pad-decoy", "h2-decoy", "edge-1", "edge-256", "too-old", "current", "future",
         "far", "small-table", "tombstone", "hit", "crowded", "underflow"]


def bh_rand_word(s):
    if s.below(10) < 4:
        return s.pick(BH_CUR_POOL)
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def bh_pick_cur(s):
    if s.below(3) == 0:
        return s.pick(BH_CUR_POOL)
    return s.pick([0x10_0000 + s.below(1 << 24), int.from_bytes(s.take(8), "little"), bh_rand_word(s)])


def bh_pick_req(s, mode, cur):
    if mode == "edge-1":
        return (cur - 1) & M256
    if mode == "edge-256":
        return (cur - 256) & M256
    if mode == "too-old":
        return (cur - 257 - s.pick([0, 0, 1, 1000])) & M256
    if mode == "current":
        return cur
    if mode == "future":
        return (cur + 1 + s.below(1000)) & M256
    if mode == "far":
        return bh_rand_word(s)
    return (cur - 1 - s.below(256)) & M256


def bh_make_case(s, mode, entry):
    cur = bh_pick_cur(s)
    if mode not in ("current", "future", "far", "too-old"):
        while cur == 0:
            cur = bh_pick_cur(s)
    req = bh_pick_req(s, mode, cur)
    n = s.pick([1, 1, 2, 3]) if mode != "underflow" else 0
    stack = [bh_rand_word(s) for _ in range(n - 1)] + ([req] if n else [])
    nb = s.pick([4, 8]) if mode == "small-table" else s.pick([32, 64]) if mode == "crowded" else s.pick([16, 16, 32, 64, 8])
    secret = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little") | 1
    num = bh_window(cur, req)
    target = bh_key_bytes(num) if num is not None else None
    room = nb - 2 if nb < 16 else nb // 2
    others = []
    for _ in range(s.below(min(room, 6) + 1)):
        k = bh_key_bytes((int.from_bytes(s.take(8), "little") if s.below(2) else (req - s.below(300)) & M64))
        if k != target and k not in others:
            others.append(k)
    order = [(k, bh_provided(int.from_bytes(k[:8], "little")) if s.below(3) else s.take(32)) for k in others]
    if target is not None and (mode in ("hit", "small-table") and s.below(4) or mode == "crowded" and s.below(2)):
        order.insert(s.below(len(order) + 1), (target, s.take(32) if s.below(2) else bytes(32)))
    tombs = sorted({s.below(nb) for _ in range(s.below(3) if mode != "tombstone" else 2 + s.below(3))})
    if len(tombs) + len(order) + 2 > nb:
        tombs = tombs[:max(0, nb - len(order) - 2)]
    decoys = []
    if target is not None and mode in ("pad-decoy", "h2-decoy", "tombstone") or s.below(5) == 0:
        h = bh_number_hash(num if num is not None else 0, secret, seed)
        for _ in range(1 + s.below(2)):
            i = ((h & (nb - 1)) + s.below(min(nb, 16))) & (nb - 1)
            if i in tombs or any(i == j for j, _, _ in decoys) or len(decoys) + len(order) + len(tombs) + 2 >= nb:
                continue
            if mode == "pad-decoy" and target is not None:
                pad = bytearray(24)
                pad[s.below(24)] = 1 << s.below(8)
                key = target[:8] + bytes(pad)
            else:
                key = bh_key_bytes(((num or 0) ^ (1 << s.below(64))) & M64)
            decoys.append((i, h >> 57, key))
    if mode == "crowded" and num is not None:
        # the first one or two probe groups are full, so both the lookup and the insert move to the next group
        h = bh_number_hash(num, secret, seed)
        tombs = []
        decoys = [(((h & (nb - 1)) + k) & (nb - 1), s.pick([h >> 57, s.below(0x80)]),
                   bh_key_bytes(((num ^ (1 << s.below(64))) & M64))) for k in range(32 if nb == 64 and s.below(2) else 16)]
    c = {"entry": entry, "mode": mode, "cur": cur, "n": n, "stack": stack, "buckets_n": nb, "secret": secret,
         "seed": seed, "order": order, "tombs": tombs, "decoys": decoys}
    ctrl, buckets = bh_build_table(c)
    used = sum(1 for b in ctrl if b < 0x80)
    if mode == "reserve":
        growth = 0
    else:
        growth = s.pick([1, 2, 3, max(1, nb * 7 // 8 - used)])
    c.update(ctrl=ctrl, buckets=buckets, growth=growth, items=used,
             entries=dict(order))
    return c


def bh_all_cases():
    s = Stream("re11-blockhash-115")
    out = []
    for k in range(BH_TOTAL):
        entry = BH_BH_DIRECT if (k // 16) % 4 == 3 else BH_BH_CACHED
        out.append(bh_make_case(s, BH_MODES[k % 16], entry))
    return out


# ---------------------------------------------------------------- static evidence
BH_FUNCS = (BH_BH_DIRECT, BH_BH_CACHED)
BH_CHECKED = (
    (0x29951ee, "4c 8b 77 30", "direct: stack length +0x30 (0 -> result 0x2c)"),
    (0x299521f, "4c 8b 4e 30", "direct: current block number limb 0 at host +0x30"),
    (0x299522b, "4c 8b 7e 48", "direct: current block number limb 3 at host +0x48"),
    (0x29952be, "49 81 fb 01 01 00 00", "direct: distance must be below 0x101"),
    (0x29952d8, "48 0f 44 d0", "direct: number = low limb when limbs 1..3 are zero, else u64::MAX"),
    (0x29952e1, "48 8b b6 98 03 00 00", "direct: provider gets the object at host +0x398"),
    (0x29952e8, "ff 15 62 11 b5 03", "direct: provider called through GOT 0x64e6450"),
    (0x2995302, "48 0f c8", "direct: hash bytes byte-swapped into the stack word"),
    (0x299533e, "b0 2c", "direct: result 0x2c (stack underflow)"),
    (0x2995394, "4c 8b 56 30", "cached: current block number limb 0 at host +0x30"),
    (0x299542e, "49 81 fb 01 01 00 00", "cached: distance must be below 0x101"),
    (0x299544a, "4c 0f 44 f0", "cached: number = low limb when limbs 1..3 are zero, else u64::MAX"),
    (0x299544e, "4c 8b ae 98 03 00 00", "cached: cache object at host +0x398"),
    (0x299546b, "48 8b 05 06 a6 b4 03", "cached: hash seed through GOT slot 0x64dfa78"),
    (0x2995475, "49 8b 95 88 00 00 00", "cached: cache secret +0x88 xored into the number"),
    (0x2995491, "48 c1 ed 39", "cached: h2 = hash >> 57"),
    (0x2995495, "49 8b 45 68", "cached: control bytes pointer +0x68"),
    (0x2995499, "49 8b 4d 70", "cached: bucket mask +0x70"),
    (0x29954dd, "49 c1 e1 06", "cached: bucket size 0x40"),
    (0x299555f, "49 83 7d 78 00", "cached: growth_left +0x78 == 0 -> reserve first"),
    (0x299556a, "49 8b b5 90 00 00 00", "cached: provider gets the value at cache +0x90"),
    (0x299557c, "ff 15 ce 0e b5 03", "cached: provider called through GOT 0x64e6450"),
    (0x29955dc, "49 29 75 78", "cached: growth_left -= old control byte & 1"),
    (0x299560f, "49 ff 85 80 00 00 00", "cached: item count +0x80 incremented"),
    (0x299565a, "b0 2c", "cached: result 0x2c (stack underflow)"),
    (0x2995695, "ff 15 55 17 b5 03", "cached: reserve called through GOT 0x64e6df0"),
    (0x29956a0, "66 0f 6f 00", "cached: small-table fix-up rescans group 0"),
)


def bh_opcode_slots(image):
    rows = {}
    for table, want in BH_OP_TABLES:
        for op in (BH_BLOCKHASH_OP, BH_SLOAD_OP):
            slot = table + 8 * op
            got = image.relative.get(slot)
            if op == BH_BLOCKHASH_OP and got != want:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}"}
    return rows


def bh_static_evidence(image):
    rows = fde_rows(image, BH_FUNCS)
    decoded, funcs = {}, {}
    for f in BH_FUNCS:
        lo, hi = rows[f]
        decoded[f] = bh_sweep_padded(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    calls = {}
    for f in BH_FUNCS:
        calls[f"{f:#x}"] = {}
        for va, fm in decoded[f]:
            if fm is None:
                continue
            if fm["op"] == 0xe8:
                calls[f"{f:#x}"][f"{va:#x}"] = f"direct {fm['target']:#x}"
            elif fm["bytes"][:2] == b"\xff\x15":
                slot = (va + fm["len"] + struct.unpack_from("<i", fm["bytes"], 2)[0]) & M64
                if slot not in image.relative or slot in image.imports:
                    fail(f"indirect call at {va:#x} through a non-RELATIVE slot {slot:#x}")
                calls[f"{f:#x}"][f"{va:#x}"] = f"got {slot:#x} -> {image.relative[slot]:#x}"
    want = {f"{BH_BH_DIRECT:#x}": {"0x29952e8": f"got {BH_PROVIDER_GOT:#x} -> {image.word(BH_PROVIDER_GOT):#x}"},
            f"{BH_BH_CACHED:#x}": {"0x299557c": f"got {BH_PROVIDER_GOT:#x} -> {image.word(BH_PROVIDER_GOT):#x}",
                                "0x2995695": f"got {BH_RESERVE_GOT:#x} -> {image.word(BH_RESERVE_GOT):#x}"}}
    if calls != want:
        fail(f"call graph changed: {calls}")
    seed = {"slot": f"{BH_SEED_GOT:#x}", "relocation": "RELATIVE", "target": f"{image.word(BH_SEED_GOT):#x}",
            "target_section_has_file_bytes": image.section_of(image.word(BH_SEED_GOT))[0] is not None}
    checks = {}
    for va, hx, what in BH_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "calls": calls, "opcode_table_slots": bh_opcode_slots(image),
           "hash_seed": seed, "checked_bytes": checks,
           "got_targets": {"provider": f"{image.word(BH_PROVIDER_GOT):#x}", "reserve": f"{image.word(BH_RESERVE_GOT):#x}"},
           "interpreter_offsets": {"stack_ptr": f"{BH_I_STACK_PTR:#x}", "stack_len": f"{BH_I_STACK_LEN:#x}"},
           "host_offsets": {"block_number_u256": f"{BH_H_NUMBER:#x}", "provider_object": f"{BH_H_CACHE:#x}"},
           "cache_offsets": {"ctrl": f"{BH_C_CTRL:#x}", "mask": f"{BH_C_MASK:#x}", "growth_left": f"{BH_C_GROWTH:#x}",
                             "items": f"{BH_C_ITEMS:#x}", "secret": f"{BH_C_SECRET:#x}", "provider_arg": f"{BH_C_SELF:#x}"},
           "bucket_bytes": BH_BUCKET, "window_blocks": BH_WINDOW,
           "results": {"ok": BH_R_OK, "underflow": BH_R_UNDERFLOW}}
    return out, decoded


def bh_sweep_padded(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        if image.code(va, 1)[0] == 0xcc:
            rows.append((va, None))
            va += 1
            continue
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


# ---------------------------------------------------------------- evaluation
def bh_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    fixture = frozenset(x for x in mut if x.startswith("hash_"))
    for i, c in enumerate(cases if cases is not None else bh_all_cases()):
        try:
            want = bh_model(c, mut)
            if fixture:
                c = dict(c, fixture_mut=fixture)
                c["ctrl"], c["buckets"] = bh_build_table(c)
            got = bh_run_case(m, c)
            ok = bh_compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


BH_MODEL_MUTANTS = ["window_255", "allow_current", "truncate_number", "keep_top_out_of_window", "never_hit",
                 "ignore_padding", "always_reserve", "no_small_fixup", "growth_always", "little_result",
                 "hash_no_secret"]
BH_BYTE_MUTANTS = [
    (0x29952c1, 0x00, "direct: window 0x101 -> 0x100"),
    (0x29952e4, 0x90, "direct: provider object host +0x398 -> +0x390"),
    (0x299533f, 0x2d, "direct: underflow result 0x2c -> 0x2d"),
    (0x2995431, 0x02, "cached: window 0x101 -> 0x201"),
    (0x299544b, 0x45, "cached: cmove -> cmovne (number saturation inverted)"),
    (0x2995478, 0x90, "cached: secret +0x88 -> +0x90"),
    (0x2995494, 0x38, "cached: h2 shift 57 -> 56"),
    (0x2995563, 0x01, "cached: reserve when growth_left == 1"),
    (0x299556d, 0x88, "cached: provider argument cache +0x90 -> +0x88"),
    (0x2995612, 0x78, "cached: increments growth_left instead of items"),
    (0x299565b, 0x2d, "cached: underflow result 0x2c -> 0x2d"),
]


def bh_controls(image, cases):
    rows = []
    for name in BH_MODEL_MUTANTS:
        _, bad, _ = bh_evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in BH_BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = bh_evaluate(image, override={va: byte}, stop_on_first=True, cases=cases)
        rows.append(("code", f"{va:#x}={byte:#04x} {what}", int(bad > 0)))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    try:
        Image(bytes(corrupt))
        rows.append(("input", "one flipped .text byte", 0))
    except ToolError:
        rows.append(("input", "one flipped .text byte", 1))
    try:
        image.code(image.text["address"] + image.text["size"] + 0x100, 4)
        rows.append(("input", "address past .text", 0))
    except ToolError:
        rows.append(("input", "address past .text", 1))
    return rows


# ---------------------------------------------------------------- output
def bh_wtag(x):
    if x is None:
        return "-"
    if x == 0:
        return "0"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def bh_outcome(c, want, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "panic":
        return "panic"
    head = "cached/" if c["entry"] == BH_BH_CACHED else "direct/"
    if code == BH_R_UNDERFLOW:
        return head + "underflow"
    if code != BH_R_OK:
        return head + f"r{code:#x}"
    num = bh_window(c["cur"], c["stack"][-1])
    if num is None:
        return head + "zero/out-of-window"
    sat = "/saturated" if num == M64 and c["stack"][-1] > M64 else ""
    if c["entry"] == BH_BH_DIRECT:
        return head + "provider" + sat
    if bh_key_bytes(num) in c["entries"]:
        return head + "cache-hit" + sat
    grow = "/reserve" if c["growth"] == 0 else ""
    return head + "miss-insert" + grow + sat


def bh_generate(out):
    image = load_image()
    out.mkdir(parents=True, exist_ok=True)
    cases = bh_all_cases()
    rows, bad, m = bh_evaluate(image, cases=cases)
    consts, decoded = bh_static_evidence(image)
    lines = ["case\tinput\toutcome\tcalls\tresult\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = bh_outcome(c, want, got)
        inp = (f"entry={c['entry']:#x},mode={c['mode']},n={c['n']},cur={bh_wtag(c['cur'])},"
               f"req={bh_wtag(c['stack'][-1] if c['stack'] else None)},buckets={c['buckets_n']},items={c['items']},"
               f"growth={c['growth']},entries={len(c['order'])},decoys={len(c['decoys'])},tombs={len(c['tombs'])}")
        ev = got.get("events", [])
        calls = ";".join(f"{e[0]}:{e[1]}" + (f":{e[2]:#x}" if e[0] == "provider" else "") for e in ev) or "-"
        if "error" in got:
            res = got["error"]
        elif got["ret"][0] == "panic":
            res = "panic"
        else:
            s = got["state"]
            res = f"ret={got['ret'][1]:#x},n={s['n']},top={bh_wtag(s['top'])}"
            if c["entry"] == BH_BH_CACHED and "cache_raw" in got:
                res += f",growth={got['cache_raw'][0]},items={got['cache_raw'][1]}"
        classes[oc] = classes.get(oc, 0) + 1
        lines.append(f"{i}\t{inp}\t{oc}\t{calls}\t{res}\t{'yes' if ok else 'NO'}")
    (out / "blockhash-cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "blockhash-outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = total = 0
        for va, f in insns:
            if f is None:
                lines.append(f"{start:#x}\t{va:#x}\t1\tcc\tpadding\t0")
                continue
            run = va in m.seen
            hit += run
            total += 1
            lines.append(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}")
        covered[f"{start:#x}"] = [hit, total]
    (out / "blockhash-decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = bh_controls(image, cases)
    (out / "blockhash-negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "blockhash-constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes,
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "blockhash-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ create-frame family
# ---------------------------------------------------------------- target constants
CR_OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode)
CR_SLOAD_OP = 0x54
CR_SLOAD_BODIES = (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 of each table holds an SLOAD handler copy
CR_CREATE, CR_CREATE2 = 0xf0, 0xf5
CR_OPS = (CR_CREATE, CR_CREATE2)
CR_NAMES = {CR_CREATE: "CREATE", CR_CREATE2: "CREATE2"}
CR_BODIES = {CR_CREATE: 0x299bea0, CR_CREATE2: 0x299b760}  # both tables name the same body for each opcode

CR_MALLOC_GOT, CR_MEMCPY_GOT, CR_SDALLOC_GOT = 0x64df480, 0x64df508, 0x64df4a0
CR_ALLOC_ERR_BOX_GOT, CR_ALLOC_ERR_BUF_GOT = 0x64df490, 0x64df498   # handle_alloc_error(align, size), noreturn
CR_PANIC_ADD_GOT, CR_PANIC_DIV_GOT = 0x64df520, 0x64df878             # panic helpers, noreturn, rdi = location
CR_RESIZE_GOT = 0x64e6de0                                          # memory growth (rdi=interp+0x170, rsi=interp, rdx=host+0x250, rcx=words)
CR_EVEN_VT_GOT, CR_ODD_VT_GOT = 0x64df8c0, 0x64df8c8                  # Bytes vtables for an even / odd buffer pointer
CR_STATIC_VT = 0x6441d98                                           # Bytes vtable of the empty static slice
CR_DROP_INPUTS = 0x29e15d0                                         # drop of a boxed call-inputs action (old action tag 1)
CR_BOX_MALLOC_RETURNS = (0x299c262, 0x299bbf7)                     # return addresses of the 0xc8-byte box allocation
CR_LOC_RANGE, CR_LOC_BASE, CR_LOC_END, CR_LOC_DIV = 0x643e110, 0x64bfc68, 0x64bfc80, 0x6443898

CR_SAVED_REGS = (3, 5, 12, 13, 14, 15)
CR_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

CR_INTERP_AT, CR_INTERP_SIZE = 0x5100_0000_0000, 0x1b0
CR_HOST_AT, CR_HOST_SIZE = 0x5200_0000_0000, 0x270
CR_PARAM_AT, CR_PARAM_SIZE = 0x5300_0000_0000, 0x170
CR_MEMRC_AT, CR_MEMRC_SIZE = 0x5400_0000_0000, 0x30
CR_MEM_AT, CR_MEM_SIZE = 0x5500_0000_0000, 0x300
CR_BUF_AT, CR_BUF_SIZE = 0x5600_0000_0000, 0x308
CR_BOX_AT, CR_BOX_SIZE = 0x5700_0000_0000, 0xc8
CR_OLDBOX_AT, CR_OLDBOX_SIZE = 0x5800_0000_0000, 0xc8
CR_FAKE_VT_AT, CR_FAKE_VT_SIZE = 0x5900_0000_0000, 0x28
CR_FAKE_DROP = 0x7d00_0000_0000
CR_STK_AT = 0x5a00_0000_0000
CR_STK_WORDS = 0x400

# interpreter fields (rdi)
CR_I_MEM, CR_I_BASE, CR_I_STACK_PTR, CR_I_STACK_LEN = 0x10, 0x18, 0x28, 0x30
CR_I_CALLER = 0x78                    # 20-byte address of the running contract
CR_I_ACT_Q, CR_I_ACT_PTR, CR_I_ACT_LEN, CR_I_ACT_DATA, CR_I_ACT_TAG = 0xb8, 0xc0, 0xc8, 0xd0, 0x110
CR_I_FLAG149 = 0x149
CR_I_MEMWORDS, CR_I_GAS, CR_I_RESERVOIR, CR_I_SPENT = 0x170, 0x188, 0x190, 0x198
CR_I_STATIC, CR_I_SPEC = 0x1a8, 0x1a9
# host fields (rsi)
CR_H_CFG_ON, CR_H_CFG_MAX, CR_H_OVR_ON, CR_H_OVR_LIMIT = 0x200, 0x208, 0x210, 0x218
CR_H_PARAMS, CR_H_RESERVOIR_ON, CR_H_SPEC = 0x250, 0x265, 0x268
# parameter block (host+0x250)
CR_P_KECCAK_WORD, CR_P_INITCODE_WORD, CR_P_CREATE, CR_P_DIVISOR, CR_P_STATE = 0x48, 0x60, 0x68, 0x70, 0x168
# memory record
CR_M_BORROW, CR_M_PTR = 0x10, 0x20

CR_R_ACTION, CR_R_OOG, CR_R_OPERAND, CR_R_STATIC, CR_R_NOT_ACTIVE, CR_R_UNDERFLOW, CR_R_INITCODE = 0x04, 0x20, 0x24, 0x28, 0x2b, 0x2c, 0x35
CR_CREATE2_GATE = 4          # spec <= 4 -> not activated
CR_INITCODE_GATE = 9         # spec > 9 -> initcode limit and word charge
CR_ALL_BUT_GATE = 1          # spec > 1 -> keep gas / divisor
CR_HOST_SPEC_BIG = 0xe       # host spec >= 0xe -> default initcode limit 0x10000 instead of 0xc000
CR_OLD_NONE = 0x38

CR_CHECKED = (
    (0x299beb1, "80 bf a8 01 00 00 00", "CREATE: static flag interp+0x1a8 != 0 gives 0x28"),
    (0x299bec5, "b0 2c", "CREATE: underflow result 0x2c"),
    (0x299bec7, "48 83 fa 03", "CREATE: needs 3 stack words"),
    (0x299bf4f, "80 bb a9 01 00 00 09", "CREATE: spec byte interp+0x1a9 > 9 enables the initcode limit and word charge"),
    (0x299bf5c, "80 be 10 02 00 00 00", "CREATE: host+0x210 override flag"),
    (0x299bf65, "48 8b 86 18 02 00 00", "CREATE: host+0x218 override limit"),
    (0x299bf81, "48 83 be 00 02 00 00 01", "CREATE: host+0x200 == 1 selects the configured code-size limit"),
    (0x299bf8f, "48 8b 86 08 02 00 00", "CREATE: host+0x208 configured code-size limit"),
    (0x299bf9b, "48 01 c0", "CREATE: initcode limit = 2 * configured code size"),
    (0x299bfc4, "48 f7 62 60", "CREATE: initcode word price at params+0x60"),
    (0x299c014, "48 3b 8b 70 01 00 00", "CREATE: memory words interp+0x170 compared with the needed words"),
    (0x299c035, "48 ff 42 10", "CREATE: memory borrow counter +0x10 incremented"),
    (0x299c0e5, "48 2b 4a 68", "CREATE: base price at params+0x68"),
    (0x299c0f6, "80 be 65 02 00 00 01", "CREATE: host+0x265 == 1 enables the reservoir step"),
    (0x299c0ff, "48 8b b2 68 01 00 00", "CREATE: reservoir amount at params+0x168"),
    (0x299c15e, "80 bb a9 01 00 00 01", "CREATE: spec > 1 keeps gas/divisor in the parent"),
    (0x299c1a9, "48 8b 72 70", "CREATE: divisor at params+0x70"),
    (0x299c218, "c6 44 24 50 00", "CREATE: scheme tag 0"),
    (0x299c257, "bf c8 00 00 00", "CREATE: boxed inputs of 0xc8 bytes"),
    (0x299c28f, "3c 38", "CREATE: old action tag 0x38 = none"),
    (0x299c2b6, "48 c7 83 b8 00 00 00 02 00 00 00", "CREATE: action word interp+0xb8 = 2 (boxed create)"),
    (0x299c2cf, "b0 04", "CREATE: result 4"),
    (0x299c307, "80 be 68 02 00 00 0e", "CREATE: host spec byte host+0x268 >= 0xe"),
    (0x299c311, "c1 e0 0e", "CREATE: 0x4000 extra when host spec >= 0xe"),
    (0x299c314, "48 05 00 c0 00 00", "CREATE: default initcode limit base 0xc000"),
    (0x299c323, "b0 35", "CREATE: initcode too large 0x35"),
    (0x299c371, "b0 28", "CREATE: static result 0x28"),
    (0x299c38d, "b0 24", "CREATE: operand too large 0x24"),
    (0x299b771, "80 bf a8 01 00 00 00", "CREATE2: static flag"),
    (0x299b789, "41 80 f9 04", "CREATE2: spec <= 4 gives 0x2b"),
    (0x299bd0b, "b0 2b", "CREATE2: not-activated result 0x2b"),
    (0x299b827, "41 80 f9 09", "CREATE2: spec > 9 enables the initcode limit"),
    (0x299b85a, "b0 2c", "CREATE2: salt underflow result 0x2c"),
    (0x299b9f4, "48 8b be 50 02 00 00", "CREATE2: params block host+0x250"),
    (0x299ba12, "48 f7 67 48", "CREATE2: hashing word price at params+0x48"),
    (0x299ba1c, "48 01 c1", "CREATE2: base + hashing cost"),
    (0x299bb83, "c6 84 24 a0 00 00 00 01", "CREATE2: scheme tag 1"),
    (0x299bc8f, "80 be 68 02 00 00 0e", "CREATE2: host spec byte host+0x268 >= 0xe"),
    (0x299bcab, "b0 35", "CREATE2: initcode too large 0x35"),
    (0x299bac5, "80 bb a9 01 00 00 01", "CREATE2: spec > 1 keeps gas/divisor in the parent"),
)

CR_BYTE_MUTANTS = [
    (0x299beb7, 0x01, "CREATE static compare 0 -> 1"),
    (0x299b78c, 0x05, "CREATE2 spec gate 4 -> 5"),
    (0x299bf55, 0x0a, "CREATE initcode gate 9 -> 10"),
    (0x299b82a, 0x08, "CREATE2 initcode gate 9 -> 8"),
    (0x299c30d, 0x0f, "CREATE host spec bound 0xe -> 0xf"),
    (0x299c317, 0xc1, "CREATE default limit 0xc000 -> 0xc100"),
    (0x299bf9c, 0x09, "CREATE limit add rax,rax -> or rax,rax"),
    (0x299bfc7, 0x58, "CREATE initcode word price +0x60 -> +0x58"),
    (0x299c0e8, 0x60, "CREATE base price +0x68 -> +0x60"),
    (0x299ba15, 0x40, "CREATE2 hashing word price +0x48 -> +0x40"),
    (0x299c0fc, 0x00, "CREATE reservoir switch 1 -> 0"),
    (0x299c164, 0x02, "CREATE keep gate 1 -> 2"),
    (0x299c1ac, 0x78, "CREATE divisor +0x70 -> +0x78"),
    (0x299bb8a, 0x02, "CREATE2 scheme tag 1 -> 2"),
    (0x299c290, 0x39, "CREATE old-action none tag 0x38 -> 0x39"),
    (0x299c2d0, 0x05, "CREATE result 4 -> 5"),
    (0x299bcac, 0x36, "CREATE2 initcode result 0x35 -> 0x36"),
]


def cr_name(op):
    return CR_NAMES[op]


def cr_words32(n):
    return (n >> 5) + (1 if n & 31 else 0)


def cr_sat_add_i64(a, b):
    sa = a - (1 << 64) if a >> 63 else a
    sb = b - (1 << 64) if b >> 63 else b
    r = max(-(1 << 63), min((1 << 63) - 1, sa + sb))
    return r & M64


class CrPanic(Exception):
    pass


def cr_model(c, vt, mut=frozenset()):
    """Pure reconstruction of one CREATE / CREATE2 step.  vt = (static_drop, even_vt, even_drop, odd_vt, odd_drop)."""
    static_drop, even_vt, even_drop, odd_vt, odd_drop = vt
    I = dict(c["I"])
    calls = []
    st = {"I": I, "calls": calls, "ret": None, "panic": None, "box": None, "buf": None, "borrow": c["borrow"],
          "src": None}
    op = c["op"]

    def done(ret):
        st["ret"] = ret
        return st

    def panic(kind, loc):
        st["panic"] = (kind, loc)
        return st

    if I["static"] and "static_ignored" not in mut:
        return done(CR_R_STATIC)
    if op == CR_CREATE2 and I["spec"] <= CR_CREATE2_GATE + (1 if "create2_gate_plus_one" in mut else 0):
        return done(CR_R_NOT_ACTIVE)
    n = I["len"]
    if n < 3:
        return done(CR_R_UNDERFLOW)
    S = c["stack"]
    value, offset, length = S[n - 1], S[n - 2], S[n - 3]
    n -= 3
    I["len"] = n
    if length >> 64:
        return done(CR_R_OPERAND)
    L = length
    by = {"vt": CR_STATIC_VT, "fn": static_drop, "ptr": 1, "len": 0, "data": 0}

    def err(code):
        calls.append(("vt-drop", by["fn"], "stack", by["data"], by["ptr"], by["len"]))
        return done(code)

    if L:
        if I["spec"] > CR_INITCODE_GATE:
            H = c["H"]
            if H["ovr_on"]:
                limit = H["ovr_limit"]
            elif H["cfg_on"] != 1:
                limit = 0x10000 if H["spec"] >= CR_HOST_SPEC_BIG and "one_limit" not in mut else 0xc000
            else:
                limit = None if H["cfg_max"] >> 63 else 2 * H["cfg_max"]
                if "cfg_max_not_doubled" in mut and limit is not None:
                    limit = H["cfg_max"]
            if limit is not None and (L > limit or ("limit_inclusive" in mut and L == limit)):
                return err(CR_R_INITCODE)
            cost = min(cr_words32(L) * c["P"]["initcode_word"], M64)
            if "initcode_floor_words" in mut:
                cost = min((L >> 5) * c["P"]["initcode_word"], M64)
            if I["gas"] < cost:
                return err(CR_R_OOG)
            I["gas"] -= cost
        if offset >> 64:
            return err(CR_R_OPERAND)
        off = offset
        end = min(off + L, M64)
        w = cr_words32(end)
        if w > I["memwords"]:
            calls.append(("resize", w))
            if c["resize"]:
                return err(c["resize"])
            I["memwords"] = w
        if off + L > M64:
            return panic("add-overflow", CR_LOC_RANGE)
        st["borrow"] = (st["borrow"] + 1) & M64
        base = I["base"]
        if off + base > M64:
            return panic("add-overflow", CR_LOC_BASE)
        if base + off + L > M64:
            return panic("add-overflow", CR_LOC_END)
        src = (c["memvec"] + off + base) & M64
        calls.append(("malloc", L))
        if c["buf_ptr"] == 0:
            calls.append(("alloc-error", 1, L))
            return panic("alloc-error", None)
        buf = c["buf_ptr"]
        calls.append(("memcpy", buf, src, L))
        st["src"] = (src, L)
        odd = buf & 1
        if "parity_swapped" in mut:
            odd ^= 1
        calls.append(("vt-drop", static_drop, "stack", 0, 1, 0))
        by = {"vt": odd_vt if odd else even_vt, "fn": odd_drop if odd else even_drop, "ptr": buf, "len": L,
              "data": buf if odd else buf | 1}
        st["borrow"] = (st["borrow"] - 1) & M64
    salt = None
    if op == CR_CREATE2:
        if n == 0:
            return err(CR_R_UNDERFLOW)
        salt = S[n - 1]
        n -= 1
        I["len"] = n
        kw = c["P"]["keccak_word"] if "no_hash_cost" not in mut else 0
        cost = min(c["P"]["create"] + min(cr_words32(L) * kw, M64), M64)
    else:
        cost = c["P"]["create"]
    if I["gas"] < cost:
        return err(CR_R_OOG)
    I["gas"] -= cost
    if c["H"]["reservoir_on"] == 1:
        s, r = c["P"]["state"], I["reservoir"]
        if r >= s:
            I["reservoir"] = r - s
        else:
            d = s - r
            if "reservoir_no_charge" not in mut:
                if I["gas"] < d:
                    return err(CR_R_OOG)
                I["gas"] -= d
            I["reservoir"] = 0
        I["spent"] = cr_sat_add_i64(I["spent"], s) if "spent_wraps" not in mut else (I["spent"] + s) & M64
    gas = I["gas"]
    st["charged"] = c["I"]["gas"] - gas
    if I["spec"] > CR_ALL_BUT_GATE + (1 if "all_but_gate_plus_one" in mut else 0):
        dv = c["P"]["divisor"]
        if dv == 0:
            return panic("div-zero", CR_LOC_DIV)
        give = gas - gas // dv
    else:
        give = gas
    if "give_all" in mut:
        give = gas
    I["gas"] = gas - give
    calls.append(("malloc", CR_BOX_SIZE))
    if c["box_ptr"] == 0:
        calls.append(("alloc-error", 8, CR_BOX_SIZE))
        return panic("alloc-error", None)
    calls.append(("memcpy", CR_BOX_AT, "stack", CR_BOX_SIZE))
    box = {0: bytes([1 if op == CR_CREATE2 else 0])}
    if salt is not None:
        box[8] = salt.to_bytes(32, "little")
    box[0x28] = struct.pack("<QQQQ", by["vt"], by["ptr"], by["len"], by["data"])
    box[0x48] = value.to_bytes(32, "little")
    box[0x68] = struct.pack("<QQ", give, I["reservoir"])
    box[0x78] = c["caller"]
    box[0x8c] = b"\0"
    box[0xa1] = b"\0"
    st["box"] = box
    I["flag149"] = 0 if "keep_flag149" not in mut else I["flag149"]
    tag, q = I["act_tag"], I["act_q"]
    if tag == CR_OLD_NONE:
        pass
    elif tag != 0:
        calls.append(("vt-drop", CR_FAKE_DROP, "interp+0xd0", I["act_data"], I["act_ptr"], I["act_len"]))
    elif q != 0:
        helper = (q == 1) if "q_full_compare" in mut else ((q & 0xffffffff) == 1)
        if helper:
            calls.append(("drop-inputs", I["act_ptr"]))
        else:
            ob = c["oldbox"]
            calls.append(("vt-drop", CR_FAKE_DROP, "oldbox+0x40", ob[2], ob[0], ob[1]))
            calls.append(("free", I["act_ptr"], CR_BOX_SIZE, 0))
    I["act_q"], I["act_ptr"], I["act_tag"] = 2, CR_BOX_AT, 0
    return done(CR_R_ACTION)


# ---------------------------------------------------------------- case image
CR_FIELDS8 = (("mem", CR_I_MEM), ("base", CR_I_BASE), ("len", CR_I_STACK_LEN), ("act_q", CR_I_ACT_Q), ("act_ptr", CR_I_ACT_PTR),
           ("act_len", CR_I_ACT_LEN), ("act_data", CR_I_ACT_DATA), ("memwords", CR_I_MEMWORDS), ("gas", CR_I_GAS),
           ("reservoir", CR_I_RESERVOIR), ("spent", CR_I_SPENT))
CR_FIELDS1 = (("act_tag", CR_I_ACT_TAG), ("flag149", CR_I_FLAG149), ("static", CR_I_STATIC), ("spec", CR_I_SPEC))


def cr_interp_bytes(c, I):
    b = bytearray(c["interp_fill"])
    put(b, CR_I_STACK_PTR, 8, CR_STK_AT)
    b[CR_I_CALLER:CR_I_CALLER + 20] = c["caller"]
    for k, off in CR_FIELDS8:
        put(b, off, 8, I[k])
    for k, off in CR_FIELDS1:
        b[off] = I[k]
    return bytes(b)


def cr_host_bytes(c):
    b = bytearray(c["host_fill"])
    H = c["H"]
    put(b, CR_H_CFG_ON, 8, H["cfg_on"])
    put(b, CR_H_CFG_MAX, 8, H["cfg_max"])
    b[CR_H_OVR_ON] = H["ovr_on"]
    put(b, CR_H_OVR_LIMIT, 8, H["ovr_limit"])
    put(b, CR_H_PARAMS, 8, CR_PARAM_AT)
    b[CR_H_RESERVOIR_ON] = H["reservoir_on"]
    b[CR_H_SPEC] = H["spec"]
    return bytes(b)


def cr_param_bytes(c):
    b = bytearray(c["param_fill"])
    P = c["P"]
    for k, off in (("keccak_word", CR_P_KECCAK_WORD), ("initcode_word", CR_P_INITCODE_WORD), ("create", CR_P_CREATE),
                   ("divisor", CR_P_DIVISOR), ("state", CR_P_STATE)):
        put(b, off, 8, P[k])
    return bytes(b)


def cr_memrc_bytes(c, borrow):
    b = bytearray(c["memrc_fill"])
    put(b, CR_M_BORROW, 8, borrow)
    put(b, CR_M_PTR, 8, c["memvec"])
    return bytes(b)


def cr_oldbox_bytes(c):
    b = bytearray(c["oldbox_fill"])
    put(b, 0x28, 8, CR_FAKE_VT_AT)
    put(b, 0x30, 8, c["oldbox"][0])
    put(b, 0x38, 8, c["oldbox"][1])
    put(b, 0x40, 8, c["oldbox"][2])
    return bytes(b)


def cr_stack_image(c):
    b = bytearray(32 * CR_STK_WORDS)
    for i, w in c["stack"].items():
        put(b, 32 * i, 32, w)
    return bytes(b)


# ---------------------------------------------------------------- contract stubs
class CrCaseMachine(TraceMachine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.calls.append(self.noreturn[target](self))
            self.panic_site = va
            raise Boundary("noreturn", self.regs)
        self.call_ret = va
        return super().transfer(target, call, va)


def cr_in_stack(m, at):
    return STACK_TOP - 0x10000 <= at < STACK_TOP


def cr_install(m, image):
    m.calls = []
    m.panic_site = None
    m.mallocs = 0
    c = m.case

    def malloc(m):
        size = m.regs[7]
        m.calls.append(("malloc", size))
        m.mallocs += 1
        m.regs[0] = c["box_ptr"] if m.call_ret in CR_BOX_MALLOC_RETURNS else c["buf_ptr"]
        if m.mallocs > 2:
            fail("more than two allocations")

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        if n > 0x400:
            fail("memcpy larger than the case bound")
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.calls.append(("memcpy", dst, "stack" if cr_in_stack(m, src) else src, n))
        m.regs[0] = dst

    def sdalloc(m):
        m.calls.append(("free", m.regs[7], m.regs[6], m.regs[2]))

    def resize(m):
        if m.regs[7] != CR_INTERP_AT + CR_I_MEMWORDS or m.regs[6] != CR_INTERP_AT or m.regs[2] != CR_HOST_AT + CR_H_PARAMS:
            fail("memory growth called outside its contract")
        m.calls.append(("resize", m.regs[1]))
        if c["resize"] == 0:
            m.store(CR_INTERP_AT + CR_I_MEMWORDS, 8, m.regs[1])
        m.regs[0] = 0x5a5a_5a5a_5a5a_5a00 | c["resize"]

    def vt_drop(fn):
        def run(m):
            at = m.regs[7]
            where = ("stack" if cr_in_stack(m, at) else "interp+0xd0" if at == CR_INTERP_AT + CR_I_ACT_DATA
                     else "oldbox+0x40" if at == CR_OLDBOX_AT + 0x40 else f"{at:#x}")
            m.calls.append(("vt-drop", fn, where, m.load(at, 8), m.regs[6], m.regs[2]))
        return run

    def drop_inputs(m):
        m.calls.append(("drop-inputs", m.regs[7]))

    m.stubs[image.word(CR_MALLOC_GOT)] = malloc
    m.stubs[image.word(CR_MEMCPY_GOT)] = memcpy
    m.stubs[image.word(CR_SDALLOC_GOT)] = sdalloc
    m.stubs[image.word(CR_RESIZE_GOT)] = resize
    m.stubs[CR_DROP_INPUTS] = drop_inputs
    for fn in cr_vtables(image)[::2] + (CR_FAKE_DROP,):
        if fn not in m.stubs:
            m.stubs[fn] = vt_drop(fn)
    m.noreturn = {
        image.word(CR_ALLOC_ERR_BOX_GOT): lambda m: ("alloc-error", m.regs[7], m.regs[6]),
        image.word(CR_ALLOC_ERR_BUF_GOT): lambda m: ("alloc-error", m.regs[7], m.regs[6]),
        image.word(CR_PANIC_ADD_GOT): lambda m: ("panic", "add-overflow", m.regs[7]),
        image.word(CR_PANIC_DIV_GOT): lambda m: ("panic", "div-zero", m.regs[7]),
    }


def cr_vtables(image):
    """(static_drop, even_vt, even_drop, odd_vt, odd_drop): drop is the vtable's fifth word (+0x20)."""
    even, odd = image.word(CR_EVEN_VT_GOT), image.word(CR_ODD_VT_GOT)
    return (image.word(CR_STATIC_VT + 0x20), even, image.word(even + 0x20), odd, image.word(odd + 0x20))


def cr_run_case(m, c):
    m.reset()
    m.case = c
    cr_install(m, m.image)
    it = m.add_region(CR_INTERP_AT, CR_INTERP_SIZE, cr_interp_bytes(c, c["I"]))
    host = m.add_region(CR_HOST_AT, CR_HOST_SIZE, cr_host_bytes(c))
    par = m.add_region(CR_PARAM_AT, CR_PARAM_SIZE, cr_param_bytes(c))
    mrc = m.add_region(CR_MEMRC_AT, CR_MEMRC_SIZE, cr_memrc_bytes(c, c["borrow"]))
    mem = m.add_region(CR_MEM_AT, CR_MEM_SIZE, c["mem_fill"])
    buf = m.add_region(CR_BUF_AT, CR_BUF_SIZE, c["buf_fill"])
    box = m.add_region(CR_BOX_AT, CR_BOX_SIZE, c["box_fill"])
    ob = m.add_region(CR_OLDBOX_AT, CR_OLDBOX_SIZE, cr_oldbox_bytes(c))
    fv = bytearray(CR_FAKE_VT_SIZE)
    put(fv, 0x20, 8, CR_FAKE_DROP)
    m.add_region(CR_FAKE_VT_AT, CR_FAKE_VT_SIZE, bytes(fv))
    stk = m.add_region(CR_STK_AT, 32 * CR_STK_WORDS, cr_stack_image(c))
    lo, hi, frame = m.regions[0]
    frame[:] = c["frame_fill"]
    fixed = [bytes(r) for r in (host, par, mem, ob, stk)]
    for k, v in zip(CR_SAVED_REGS, CR_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = CR_INTERP_AT, CR_HOST_AT
    try:
        m.run(CR_BODIES[c["op"]], limit=20000)
        ret = m.regs[0] & 0xff
    except Boundary:
        ret = None
    return {"ret": ret, "site": m.panic_site, "interp": bytes(it), "memrc": bytes(mrc), "buf": bytes(buf),
            "box": bytes(box), "fixed_ok": [bytes(r) for r in (host, par, mem, ob, stk)] == fixed,
            "regs_ok": ret is None or ([m.regs[k] for k in CR_SAVED_REGS] == CR_SAVED and m.regs[4] == STACK_TOP - 0x100),
            "calls": list(m.calls)}


def cr_expect_calls(want):
    out = list(want["calls"])
    if want["panic"] is not None and want["panic"][0] != "alloc-error":
        out.append(("panic", want["panic"][0], want["panic"][1]))
    return out


def cr_compare(c, want, got):
    if got["calls"] != cr_expect_calls(want):
        return False
    if (want["ret"] is None) != (got["ret"] is None):
        return False
    if want["ret"] is not None and (want["ret"] != got["ret"] or not got["regs_ok"]):
        return False
    if not got["fixed_ok"] or got["memrc"] != cr_memrc_bytes(c, want["borrow"]):
        return False
    if got["interp"] != cr_interp_bytes(c, want["I"]):
        return False
    buf = bytearray(c["buf_fill"])
    if want["src"] is not None:
        src, n = want["src"]
        at = c["buf_ptr"] - CR_BUF_AT
        buf[at:at + n] = c["mem_fill"][src - CR_MEM_AT:src - CR_MEM_AT + n]
    if got["buf"] != bytes(buf):
        return False
    if want["box"] is None:
        return got["box"] == c["box_fill"]
    for off, b in want["box"].items():
        if got["box"][off:off + len(b)] != b:
            return False
    return True


# ---------------------------------------------------------------- cases
CR_PER_BODY = 3000
CR_SPECS = (0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 0x11, 0xff)
CR_SPECS2 = (0, 4, 5, 6, 8, 9, 10, 10, 11, 11, 0x11, 0x11, 0xff)   # CREATE2 needs spec > 4, so most picks pass the gate
CR_LENS = (0, 1, 2, 3, 3, 4, 4, 5, 9, 0x3ff, 0x400)
CR_LENS2 = (0, 2, 3, 3, 4, 4, 4, 5, 5, 9, 0x3ff, 0x400)


def cr_rand_word(st):
    return int.from_bytes(st.take(32), "little")


def cr_r64(st):
    return int.from_bytes(st.take(8), "little")


def cr_make_case(st, op, k, vt):
    c = {"id": f"{cr_name(op).lower()}-{k:04d}", "op": op}
    I = {"mem": CR_MEMRC_AT}
    I["static"] = st.pick((0,) * 18 + (1, st.take(1)[0] | 1))
    I["spec"] = st.pick(CR_SPECS2 if op == CR_CREATE2 else CR_SPECS)
    I["len"] = st.pick(CR_LENS2 if op == CR_CREATE2 else CR_LENS)
    I["memwords"] = st.pick((0, 0, 1, 4, 8, 0x18, cr_r64(st)))
    I["base"] = st.pick((0, 0, 8, 0x20, st.below(0x40), st.below(0x40)) * 4 + (M64 - 0x10, 1 << 63))
    I["reservoir"] = st.pick((0, 0, 50, 100, 0x10000, cr_r64(st)))
    I["spent"] = st.pick((0, 7, (1 << 63) - 5, M64, cr_r64(st)))
    I["flag149"] = st.take(1)[0]
    I["act_tag"] = st.pick((CR_OLD_NONE, CR_OLD_NONE, 0, 0, 0, 1, 2, st.take(1)[0]))
    if I["act_tag"] in (0, CR_OLD_NONE):
        I["act_q"] = st.pick((0, 1, 2, 3, 1 << 32 | 1, 1 << 32))
        I["act_ptr"] = CR_OLDBOX_AT
    else:
        I["act_q"] = CR_FAKE_VT_AT
        I["act_ptr"] = cr_r64(st)
    I["act_len"], I["act_data"] = cr_r64(st), cr_r64(st)
    H = {"cfg_on": st.pick((0, 1, 1, 2, cr_r64(st))), "cfg_max": st.pick((0x6000, 0x10, 0, 1 << 63, M64, cr_r64(st))),
         "ovr_on": st.pick((0, 0, 0, 1, st.take(1)[0])), "ovr_limit": st.pick((0xc000, 0x40, 0, M64, cr_r64(st))),
         "reservoir_on": st.pick((0, 0, 1, 1, 2)), "spec": st.pick((0, 0xd, 0xe, 0xf, 0xff))}
    P = {"keccak_word": st.pick((6, 6, 0, 1 << 60, cr_r64(st))), "initcode_word": st.pick((2, 2, 0, 1 << 59, cr_r64(st))),
         "create": st.pick((32000, 32000, 0, 1, cr_r64(st), M64)),
         "divisor": st.pick((64,) * 6 + (1, 2, cr_r64(st) | 1, 0)), "state": st.pick((0, 100, 32000, cr_r64(st), M64))}
    c["I"], c["H"], c["P"] = I, H, P
    n = I["len"]
    stack = {i: cr_rand_word(st) for i in range(max(0, n - 6), n)}
    if n >= 2:
        stack[n - 2] = st.pick((st.below(0x100),) * 6 + (cr_rand_word(st), cr_r64(st), M64 - 0x20, 1 << 64))
    if n >= 3:
        lk = st.pick(("zero", "small", "small", "small", "small", "edge", "hi", "big"))
        lim = st.pick((0xc000, 0x10000, 2 * H["cfg_max"] & M64, H["ovr_limit"]))
        stack[n - 3] = {"zero": 0, "small": st.below(0x180) + 1, "edge": (lim + st.pick((0, 1))) & M64,
                        "hi": cr_rand_word(st), "big": cr_r64(st)}[lk]
    c["stack"] = stack
    c["caller"] = st.take(20)
    c["resize"] = st.pick((0,) * 8 + (0x20, 0x50, st.take(1)[0] | 1))
    c["buf_ptr"] = st.pick((CR_BUF_AT,) * 6 + (CR_BUF_AT + 1, CR_BUF_AT + 1, CR_BUF_AT + 8, 0))
    c["box_ptr"] = st.pick((CR_BOX_AT,) * 19 + (0,))
    c["borrow"] = st.below(4)
    c["memvec"] = CR_MEM_AT
    c["oldbox"] = (cr_r64(st), cr_r64(st), cr_r64(st))
    c["interp_fill"] = st.take(CR_INTERP_SIZE)
    c["host_fill"] = st.take(CR_HOST_SIZE)
    c["param_fill"] = st.take(CR_PARAM_SIZE)
    c["memrc_fill"] = st.take(CR_MEMRC_SIZE)
    c["mem_fill"] = st.take(CR_MEM_SIZE)
    c["buf_fill"] = st.take(CR_BUF_SIZE)
    c["box_fill"] = st.take(CR_BOX_SIZE)
    c["oldbox_fill"] = st.take(CR_OLDBOX_SIZE)
    c["frame_fill"] = st.take(32) * (0x10000 // 32)
    gk = st.pick(("tight", "tight", "tight", "zero", "small", "rand", "max", "big"))
    I["gas"] = M64
    want = cr_model(c, vt)
    if gk == "tight" and want.get("charged") is not None:
        I["gas"] = (want["charged"] + st.pick((-1, 0, 0, 1))) & M64
    else:
        I["gas"] = {"tight": 32000, "zero": 0, "small": st.below(40000), "rand": cr_r64(st), "max": M64,
                    "big": 1 << 40}[gk]
    # memory window guard: when the copy would leave the case regions, the growth stub fails instead
    want = cr_model(c, vt)
    if want["src"] is not None:
        src, L = want["src"]
        if not (CR_MEM_AT <= src and src + L <= CR_MEM_AT + CR_MEM_SIZE and c["buf_ptr"] - CR_BUF_AT + L <= CR_BUF_SIZE):
            c["resize"] = st.pick((0x20, 0x50, st.take(1)[0] | 1))
            I["memwords"] = 0
    return c


def cr_all_cases(vt):
    out = []
    for op in CR_OPS:
        st = Stream(f"re11-create-115/{cr_name(op)}")
        out += [cr_make_case(st, op, k, vt) for k in range(CR_PER_BODY)]
    return out


# ---------------------------------------------------------------- static evidence
def cr_hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def cr_pinned():
    return CR_CHECKED


def cr_sweep_padded(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


def cr_static_evidence(image):
    fdes = fde_rows(image, set(CR_BODIES.values()))
    for table in CR_OP_TABLES:
        if image.relative.get(table + 8 * CR_SLOAD_OP) not in CR_SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op in CR_OPS:
            if image.relative.get(table + 8 * op) != CR_BODIES[op]:
                fail(f"opcode table {table:#x} slot {op:#x} does not name {cr_name(op)}")
    for va, want, _ in CR_CHECKED:
        got = cr_hexs(image.code(va, len(bytes.fromhex(want.replace(" ", "")))))
        if got != want:
            fail(f"pinned bytes differ at {va:#x}: {got}")
    insns = {op: cr_sweep_padded(image, *fdes[CR_BODIES[op]]) for op in CR_OPS}
    return fdes, insns


def cr_noreturn_targets(image):
    return {image.word(g) for g in (CR_ALLOC_ERR_BOX_GOT, CR_ALLOC_ERR_BUF_GOT, CR_PANIC_ADD_GOT, CR_PANIC_DIV_GOT)}


CR_KNOWN_UNREACHED = {0x299bad1: "no:spec<=1-arm (CREATE2 gate needs spec > 4)"}


def cr_reach(image, rows, seen):
    """Label each decoded instruction: executed, or why not (from bytes: ud2 tail, after a noreturn GOT call)."""
    nor = cr_noreturn_targets(image)
    out, after_ud2, prev_noret = [], False, False
    for va, f in rows:
        if f["bytes"][:2] == b"\x0f\x0b":
            after_ud2 = True
        if va in seen:
            out.append("yes")
        elif after_ud2:
            out.append("no:ud2-or-landing-pad")
        elif prev_noret:
            out.append("no:after-noreturn-call")
        elif va in CR_KNOWN_UNREACHED:
            out.append(CR_KNOWN_UNREACHED[va])
        else:
            out.append("no:unreached")
        prev_noret = (f["op"] == 0xff and f["rm"][1] == "rip"
                      and image.word(va + f["len"] + f["rm"][4]) in nor)
    return out


# ---------------------------------------------------------------- evaluation and controls
def cr_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, cases=None, machine=None):
    m = machine or CrCaseMachine(image, override)
    vt = cr_vtables(image)
    rows = []
    for c in cases:
        want = cr_model(c, vt, mut)
        got = cr_run_case(m, c)
        ok = cr_compare(c, want, got)
        rows.append((c, want, got, ok))
        if stop_on_first and not ok:
            break
    return rows, m


CR_MODEL_MUTANTS = ["static_ignored", "create2_gate_plus_one", "one_limit", "cfg_max_not_doubled", "limit_inclusive",
                 "initcode_floor_words", "parity_swapped", "no_hash_cost", "reservoir_no_charge", "spent_wraps",
                 "all_but_gate_plus_one", "give_all", "keep_flag149", "q_full_compare"]


def cr_controls(image, cases):
    rows = []
    for mt in CR_MODEL_MUTANTS:
        r, _ = cr_evaluate(image, mut=frozenset([mt]), stop_on_first=True, cases=cases)
        bad = next((x[0]["id"] for x in r if not x[3]), "")
        rows.append(("model", mt, "detected" if bad else "MISSED", bad))
    for va, value, label in CR_BYTE_MUTANTS:
        if image.code(va, 1)[0] == value:
            fail(f"byte mutant at {va:#x} does not change the byte")
        try:
            r, _ = cr_evaluate(image, override={va: value}, stop_on_first=True, cases=cases)
            bad = next((x[0]["id"] for x in r if not x[3]), "")
        except ToolError as exc:
            bad = "tool-error:" + str(exc).split(" at ")[0]
        rows.append(("code", f"{va:#x}={value:#04x} {label}", "detected" if bad else "MISSED", bad))
    bad = bytearray(image.data)
    bad[0x1000] ^= 1
    try:
        Image(bytes(bad))
        rows.append(("input", "binary with one flipped byte", "MISSED", ""))
    except ToolError:
        rows.append(("input", "binary with one flipped byte", "detected", "sha256"))
    try:
        Machine(image).fetch(image.text["address"] + image.text["size"] + 0x10)
        rows.append(("input", "code fetch outside .text", "MISSED", ""))
    except ToolError:
        rows.append(("input", "code fetch outside .text", "detected", "range"))
    return rows


CR_RESULT_NAMES = {CR_R_ACTION: "create-action", CR_R_OOG: "out-of-gas", CR_R_OPERAND: "operand-too-large",
                CR_R_STATIC: "static-call", CR_R_NOT_ACTIVE: "not-activated", CR_R_UNDERFLOW: "underflow",
                CR_R_INITCODE: "initcode-too-large"}


def cr_outcome(c, want):
    if want["panic"] is not None:
        kind, loc = want["panic"]
        return f"{kind}" + (f"@{loc:#x}" if loc else ("-box" if ("malloc", CR_BOX_SIZE) == want["calls"][-2] and
                                                        len(want["calls"]) >= 2 and want["calls"][-1][1] == 8
                                                        else "-buffer"))
    if c["resize"] and want["ret"] == c["resize"] and any(k[0] == "resize" for k in want["calls"]):
        return "growth-error"
    r = CR_RESULT_NAMES[want["ret"]]
    if want["ret"] == CR_R_ACTION:
        L = c["stack"][c["I"]["len"] - 3]
        r += "+empty-init" if L == 0 else ("+odd-buffer" if c["buf_ptr"] & 1 else "+copied")
        tag, q = c["I"]["act_tag"], c["I"]["act_q"]
        r += ("+old-none" if tag == CR_OLD_NONE else "+old-bytes" if tag else "+old-empty" if q == 0 else
              "+old-inputs" if q & 0xffffffff == 1 else "+old-box")
    return r


def cr_calls_text(calls):
    out = []
    for k in calls:
        out.append(k[0] + "(" + ",".join(x if isinstance(x, str) else f"{x:#x}" for x in k[1:]) + ")")
    return ";".join(out) or "-"


def cr_generate(out):
    image = load_image()
    fdes, insns = cr_static_evidence(image)
    vt = cr_vtables(image)
    cases = cr_all_cases(vt)
    rows, m = cr_evaluate(image, cases=cases, machine=CrCaseMachine(image))
    mism = [r[0]["id"] for r in rows if not r[3]]
    if mism:
        fail(f"{len(mism)} mismatches, first {mism[:5]}")
    ctl = cr_controls(image, cases)
    if any(r[2] != "detected" for r in ctl):
        fail(f"negative control missed: {[r for r in ctl if r[2] != 'detected']}")
    seen = m.seen
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    lines = ["case\tbody\tstatic\tspec\thost_spec\tstack_len\tvalue\toffset\tlength\tsalt\tgas\tmem_words\tbase\t"
             "cfg_on\tcfg_max\tovr_on\tovr_limit\treservoir_on\tp_keccak\tp_initcode\tp_create\tp_divisor\tp_state\t"
             "reservoir\tspent\tgrowth\tbuffer\tbox\told_tag\told_q\tresult\tstack_len_after\tgas_after\t"
             "reservoir_after\tspent_after\tmem_words_after\tchild_gas\tcalls\tmatch"]
    classes = {}
    for c, want, got, ok in rows:
        I, H, P, S = c["I"], c["H"], c["P"], c["stack"]
        n = I["len"]
        oc = cr_outcome(c, want)
        classes[(cr_name(c["op"]), oc)] = classes.get((cr_name(c["op"]), oc), 0) + 1

        def sw(i):
            return f"{S[i]:#x}" if 0 <= i < n else "-"
        res = "panic:" + want["panic"][0] if want["panic"] else f"{want['ret']:#04x}"
        child = struct.unpack_from("<Q", want["box"][0x68])[0] if want["box"] else None
        W = want["I"]
        lines.append("\t".join([
            c["id"], f"{CR_BODIES[c['op']]:#x}", f"{I['static']:#x}", f"{I['spec']:#x}", f"{H['spec']:#x}", str(n),
            sw(n - 1), sw(n - 2), sw(n - 3), sw(n - 4) if c["op"] == CR_CREATE2 else "-", f"{I['gas']:#x}",
            f"{I['memwords']:#x}", f"{I['base']:#x}", f"{H['cfg_on']:#x}", f"{H['cfg_max']:#x}", f"{H['ovr_on']:#x}",
            f"{H['ovr_limit']:#x}", f"{H['reservoir_on']:#x}", f"{P['keccak_word']:#x}", f"{P['initcode_word']:#x}",
            f"{P['create']:#x}", f"{P['divisor']:#x}", f"{P['state']:#x}", f"{I['reservoir']:#x}",
            f"{I['spent']:#x}", f"{c['resize']:#x}", f"{c['buf_ptr'] - CR_BUF_AT:#x}" if c["buf_ptr"] else "null",
            "ok" if c["box_ptr"] else "null", f"{I['act_tag']:#x}", f"{I['act_q']:#x}", res, str(W["len"]),
            f"{W['gas']:#x}", f"{W['reservoir']:#x}", f"{W['spent']:#x}", f"{W['memwords']:#x}",
            "-" if child is None else f"{child:#x}", cr_calls_text(cr_expect_calls(want)), "yes" if ok else "no"]))
    (out / "create-frame-cases.tsv").write_text("\n".join(lines) + "\n")
    oc_lines = ["body\toutcome\tcases"] + [f"{a}\t{o}\t{n}" for (a, o), n in sorted(classes.items())]
    (out / "create-frame-outcome-classes.tsv").write_text("\n".join(oc_lines) + "\n")
    ins_lines = ["body\tva\tbytes\texecuted"]
    total = hit = 0
    reached = {}
    for op in CR_OPS:
        labels = cr_reach(image, insns[op], seen)
        for (va, f), r in zip(insns[op], labels):
            total += 1
            hit += r == "yes"
            reached[r] = reached.get(r, 0) + 1
            ins_lines.append(f"{cr_name(op)}\t{va:#x}\t{cr_hexs(f['bytes'])}\t{r}")
    (out / "create-frame-decoded-instructions.tsv").write_text("\n".join(ins_lines) + "\n")
    fn = ["role\tname\tstart\tend\tsize\tsha256"]
    for op in CR_OPS:
        s, e = fdes[CR_BODIES[op]]
        fn.append(f"handler\t{cr_name(op)}\t{s:#x}\t{e:#x}\t{e - s}\t{hashlib.sha256(image.code(s, e - s)).hexdigest()}")
    (out / "create-frame-functions.tsv").write_text("\n".join(fn) + "\n")
    const = {
        "binary_sha256": SHA256,
        "opcode_tables": {f"{t:#x}": {cr_name(op): f"{image.relative[t + 8 * op]:#x}" for op in CR_OPS} for t in CR_OP_TABLES},
        "pinned_bytes": [{"va": f"{va:#x}", "bytes": b, "meaning": t} for va, b, t in CR_CHECKED],
        "got_slots": {k: f"{g:#x}->{image.word(g):#x}" for k, g in (
            ("malloc", CR_MALLOC_GOT), ("memcpy", CR_MEMCPY_GOT), ("sized_free", CR_SDALLOC_GOT),
            ("alloc_error_box", CR_ALLOC_ERR_BOX_GOT), ("alloc_error_buffer", CR_ALLOC_ERR_BUF_GOT),
            ("panic_add_overflow", CR_PANIC_ADD_GOT), ("panic_div_zero", CR_PANIC_DIV_GOT), ("memory_growth", CR_RESIZE_GOT),
            ("bytes_vtable_even", CR_EVEN_VT_GOT), ("bytes_vtable_odd", CR_ODD_VT_GOT))},
        "memcpy_import": image.import_name(CR_MEMCPY_GOT),
        "bytes_vtables": {"static": f"{CR_STATIC_VT:#x}", "static_drop": f"{vt[0]:#x}", "even": f"{vt[1]:#x}",
                          "even_drop": f"{vt[2]:#x}", "odd": f"{vt[3]:#x}", "odd_drop": f"{vt[4]:#x}"},
        "direct_callees": {"drop_old_call_inputs": f"{CR_DROP_INPUTS:#x}"},
        "box_allocation_return_addresses": [f"{a:#x}" for a in CR_BOX_MALLOC_RETURNS],
        "panic_locations": {"offset_plus_length": f"{CR_LOC_RANGE:#x}", "memory_base_plus_offset": f"{CR_LOC_BASE:#x}",
                            "memory_base_plus_end": f"{CR_LOC_END:#x}", "gas_divisor_zero": f"{CR_LOC_DIV:#x}"},
        "fields": {"interp": {"memory": CR_I_MEM, "memory_base": CR_I_BASE, "stack_ptr": CR_I_STACK_PTR,
                              "stack_len": CR_I_STACK_LEN, "caller": CR_I_CALLER, "action_word": CR_I_ACT_Q,
                              "action_ptr": CR_I_ACT_PTR, "action_len": CR_I_ACT_LEN, "action_data": CR_I_ACT_DATA,
                              "action_tag": CR_I_ACT_TAG, "flag_149": CR_I_FLAG149, "memory_words": CR_I_MEMWORDS,
                              "gas_remaining": CR_I_GAS, "reservoir": CR_I_RESERVOIR, "spent_signed": CR_I_SPENT,
                              "is_static": CR_I_STATIC, "spec": CR_I_SPEC},
                   "host": {"code_size_cfg_tag": CR_H_CFG_ON, "code_size_cfg_max": CR_H_CFG_MAX,
                            "initcode_override_on": CR_H_OVR_ON, "initcode_override_limit": CR_H_OVR_LIMIT,
                            "params": CR_H_PARAMS, "reservoir_on": CR_H_RESERVOIR_ON, "host_spec": CR_H_SPEC},
                   "params": {"keccak_word": CR_P_KECCAK_WORD, "initcode_word": CR_P_INITCODE_WORD, "create": CR_P_CREATE,
                              "keep_divisor": CR_P_DIVISOR, "state_amount": CR_P_STATE},
                   "memory_record": {"borrow": CR_M_BORROW, "vec_ptr": CR_M_PTR},
                   "create_inputs_box": {"size": CR_BOX_SIZE, "scheme_tag": 0, "salt": 8, "init_code_bytes": 0x28,
                                         "value": 0x48, "gas_limit": 0x68, "reservoir": 0x70, "caller": 0x78,
                                         "zero_byte_0x8c": 0x8c, "zero_byte_0xa1": 0xa1}},
        "results": {v: f"{k:#04x}" for k, v in sorted(CR_RESULT_NAMES.items())},
        "gates": {"create2_not_active_max_spec": CR_CREATE2_GATE, "initcode_rules_min_spec_exclusive": CR_INITCODE_GATE,
                  "keep_one_part_min_spec_exclusive": CR_ALL_BUT_GATE, "host_spec_large_limit_min": CR_HOST_SPEC_BIG,
                  "default_initcode_limits": ["0xc000", "0x10000"], "old_action_none_tag": f"{CR_OLD_NONE:#x}"},
    }
    (out / "create-frame-constants.json").write_text(json.dumps(const, indent=2, sort_keys=True) + "\n")
    ctl_lines = ["kind\tcontrol\tresult\tfirst_detecting_case"] + ["\t".join(r) for r in ctl]
    (out / "create-frame-negative-controls.tsv").write_text("\n".join(ctl_lines) + "\n")
    summary = {
        "binary_sha256": SHA256,
        "cases": len(rows), "matches": sum(1 for r in rows if r[3]),
        "cases_per_body": {cr_name(op): sum(1 for r in rows if r[0]["op"] == op) for op in CR_OPS},
        "instructions": total, "instructions_executed": hit, "instruction_reach": dict(sorted(reached.items())),
        "negative_controls": len(ctl), "negative_controls_detected": sum(1 for r in ctl if r[2] == "detected"),
        "outcome_classes": len(classes),
    }
    (out / "create-frame-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ shared layout and combined output
PARTS = (("blockhash", "bh_generate"), ("create-frame", "cr_generate"))
LISTINGS = ("cases.tsv",)
SAMPLE_EVERY = 8


def shared_layout(image):
    """Both families must read the same two RELATIVE opcode tables, anchored by the same SLOAD slot."""
    bh_tables = tuple(t for t, _ in BH_OP_TABLES)
    if bh_tables != CR_OP_TABLES:
        fail(f"opcode tables differ between the families: {bh_tables} vs {CR_OP_TABLES}")
    rows = {}
    for i, table in enumerate(CR_OP_TABLES):
        sload = image.relative.get(table + 8 * CR_SLOAD_OP)
        if sload != CR_SLOAD_BODIES[i]:
            fail(f"SLOAD anchor of {table:#x} is {sload}")
        slots = {"BLOCKHASH": BH_OP_TABLES[i][1], "CREATE": CR_BODIES[CR_CREATE], "CREATE2": CR_BODIES[CR_CREATE2]}
        ops = {"BLOCKHASH": 0x40, "CREATE": CR_CREATE, "CREATE2": CR_CREATE2}
        for label, body in slots.items():
            if image.relative.get(table + 8 * ops[label]) != body:
                fail(f"slot {ops[label]:#x} of {table:#x} does not hold {body:#x}")
        rows[f"{table:#x}"] = {"SLOAD": f"{sload:#x}", **{k: f"{v:#x}" for k, v in slots.items()}}
    return rows


def part_totals(s):
    """Case, mismatch and control counts from one part summary (the parts name them differently)."""
    cases = s["cases"]
    bad = s["mismatches"] if "mismatches" in s else cases - s["matches"]
    if isinstance(s["negative_controls"], dict):
        total, found = s["negative_controls"]["total"], s["negative_controls"]["detected"]
    else:
        total, found = s["negative_controls"], s["negative_controls_detected"]
    return cases, bad, total, found


def sample_listing(path):
    """Replace a full listing by its header and every SAMPLE_EVERY-th row; return the pin of the full text."""
    text = path.read_bytes()
    rows = text.decode().split("\n")[:-1]
    pin = {"sha256": hashlib.sha256(text).hexdigest(), "rows": len(rows) - 1}
    kept = [rows[0]] + [r for i, r in enumerate(rows[1:]) if i % SAMPLE_EVERY == 0]
    path.write_text("\n".join(kept) + "\n")
    return pin


def run_part(fn_name, out):
    return globals()[fn_name](pathlib.Path(out))


def generate(out, full=False, workers=2):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    shared = shared_layout(load_image())
    if workers > 1:
        import concurrent.futures
        with concurrent.futures.ProcessPoolExecutor(workers) as pool:
            parts = [pool.submit(run_part, fn, str(out)) for _, fn in PARTS]
            results = [p.result() for p in parts]
    else:
        results = [run_part(fn, str(out)) for _, fn in PARTS]
    summary = {"binary_sha256": SHA256, "shared_opcode_tables": shared, "parts": {}, "full_listings": {},
               "listing_sample": "full" if full else f"header + every {SAMPLE_EVERY}th row"}
    totals = [0, 0, 0, 0]
    for (slug, _), part in zip(PARTS, results):
        (out / f"{slug}-summary.json").unlink()
        row = part_totals(part)
        totals = [a + b for a, b in zip(totals, row)]
        summary["parts"][slug] = dict(part, **{"mismatches": row[1],
                                               "negative_controls": {"total": row[2], "detected": row[3]}})
        summary["parts"][slug].pop("matches", None)
        summary["parts"][slug].pop("negative_controls_detected", None)
        summary["parts"][slug].pop("binary_sha256", None)
        for name_ in LISTINGS:
            path = out / f"{slug}-{name_}"
            data = path.read_bytes()
            pin = (sample_listing(path) if not full else
                   {"sha256": hashlib.sha256(data).hexdigest(), "rows": len(data.split(b"\n")) - 2})
            summary["full_listings"][path.name] = pin
    summary.update({"cases": totals[0], "mismatches": totals[1],
                    "negative_controls": {"total": totals[2], "detected": totals[3]}})
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--full", action="store_true", help="keep every case row instead of the committed sample")
    ap.add_argument("--workers", type=int, default=2, help="processes for the two families (1 = serial)")
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.full, args.workers)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: summary[k] for k in ("cases", "mismatches", "negative_controls")}, sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
