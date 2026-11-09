#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM CREATE and CREATE2 opcode handlers (both handler families).

CREATE and CREATE2 are opcode table slots 0xf0 and 0xf5.  The RELATIVE tables 0x6485ef8 and 0x6486c60 share the
pair 0x4338c10 / 0x4339270; the third table 0x649eea0 holds the second family 0x4f07ae0 / 0x4f07460, whose tail
replaces the pending-call slot through the helper 0x4f00920.  Each handler works on the host (stack +0x28/+0x30,
executing address +0x78/+0x88, memory words +0x170, memory cost +0x178, gas +0x188, refund counters +0x190/+0x198,
static byte +0x1a8, spec byte +0x1a9, pending-call slot +0xb8/+0xc0/+0x110) and the context (limits +0x200..+0x218,
gas schedule +0x250, flags +0x265/+0x268).  They refuse static calls (0x28), CREATE2 before the fork that adds it
(0x2b), fewer than three (four) stack words (0x2c) and an initcode length wider than 64 bits (0x24); from the
Shanghai spec byte on they enforce the initcode size limit (0x35) and charge the per-word initcode gas; they check
the offset width (0x24), expand memory through 0x45244c0, copy the initcode into a fresh allocation tagged as a
Bytes value, charge the create fee (plus the CREATE2 hash words), apply the refund-counter accounting, keep back
all but 1/64 of the remaining gas, build a 0xc8-byte create request, box it and replace the pending-call slot
(returning 4).  The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real
machine code with a small concrete x86-64 evaluator (no external programs, the binary is never executed) and
compares every case with one pure-Python reconstruction.  Allocator, memcpy, free, panics, Bytes drops, the raw
vector reserve and the pending-slot drop callbacks are stubbed at their call targets and every call is recorded.
Negative controls show that wrong reconstructions, corrupted code bytes and corrupted inputs are detected.
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
M32 = (1 << 32) - 1
M64 = (1 << 64) - 1
M128 = (1 << 128) - 1

STACK_TOP = 0x7ff0_0000_0000
RETURN_MARK = 0x7e00_dead_0000
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
    elif op in (0x11, 0x13, 0x38, 0x88, 0x0f57, 0x01, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x29, 0x2b,
                0x31, 0x33, 0x39, 0x3b, 0x63, 0x84, 0x85, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0fb7, 0x28, 0xd3) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
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
        self.seen = set()
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.zf = self.sf = self.cf = False
        self.of = None
        self.regions = []
        self.stubs = {}
        self.steps = 0
        self.add_region(STACK_TOP - 0x10000, 0x10000)
        self.regs[4] = STACK_TOP - 0x100

    def add_region(self, base, size, content=b""):
        buf = bytearray(size)
        buf[:len(content)] = content
        self.regions.append((base, base + size, buf))
        return buf

    def load(self, at, size):
        at &= M64
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                return int.from_bytes(buf[at - lo:at - lo + size], "little")
        if size == 16 and self.image.section_of(at)[0] is not None:  # two relocated words
            return self.load(at, 8) | self.load(at + 8, 8) << 64
        if size == 8 and at in self.image.relative:
            return self.image.relative[at]
        return int.from_bytes(self.image.read(at, size), "little")

    def store(self, at, size, value):
        at &= M64
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                buf[at - lo:at - lo + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
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
            if self.of is None:
                fail(f"overflow flag read without a defining instruction at {va:#x}")
            return self.of if code == 0 else not self.of
        table = {2: lambda: self.cf, 3: lambda: not self.cf, 4: lambda: self.zf, 5: lambda: not self.zf,
                 6: lambda: self.cf or self.zf, 7: lambda: not (self.cf or self.zf), 8: lambda: self.sf,
                 9: lambda: not self.sf}
        if code not in table:
            fail(f"unsupported condition {code} at {va:#x}")
        return table[code]()

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
            self.steps += 1
            if self.steps > limit:
                fail("step limit")
            self.seen.add(pc)
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
        elif op == 0x90 or op == 0x0f1f:
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
        elif 0xb8 <= op <= 0xbf:
            self.set_reg(f["r"], 64 if f["rex"] & 8 else 32, f["imm"], f)
        elif op == 0xc7:
            if f["reg"] & 7:
                fail("unsupported c7 form")
            self.put(f["rm"], size, f["imm"] & ((1 << size) - 1), f, va)
        elif op in (0xc1, 0xd1, 0xd3):
            count = (f["imm"] if op == 0xc1 else 1 if op == 0xd1 else self.regs[1]) & (63 if size == 64 else 31)
            a, kind, mask = self.get(f["rm"], size, f, va), f["reg"] & 7, (1 << size) - 1
            if kind == 7:
                res = (a - (1 << size) if a >> (size - 1) else a) >> count & mask
            elif kind == 4:
                res = (a << count) & mask
            elif kind == 5:
                res = a >> count
            else:
                fail(f"unsupported shift form at {va:#x}")
            if count:
                self.flags_logic(res, size)
            self.put(f["rm"], size, res, f, va)
        elif op == 0xf7:
            kind = f["reg"] & 7
            a = self.get(f["rm"], size, f, va)
            if kind == 0:
                self.flags_logic(a & (f["imm"] & ((1 << size) - 1)), size)
            elif kind == 4:
                if size != 64:
                    fail("unsupported mul width")
                prod = self.regs[0] * a
                self.regs[0], self.regs[2] = prod & M64, prod >> 64
                self.cf = self.regs[2] != 0
                self.of = self.cf  # unsigned mul: OF == CF
            elif kind == 6:  # unsigned divide of rdx:rax (or edx:eax) by the operand
                if size not in (32, 64):
                    fail("unsupported div width")
                if a == 0:
                    fail(f"divide by zero at {va:#x}")
                dividend = (self.regs[2] << size | self.regs[0]) if size == 64 else \
                    ((self.regs[2] & M32) << 32 | (self.regs[0] & M32))
                q, r = divmod(dividend, a)
                if q >> size:
                    fail(f"divide overflow at {va:#x}")
                self.set_reg(0, size, q, f)
                self.set_reg(2, size, r, f)
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
            elif kind in (2, 4):
                target = self.get(f["rm"], 64, f, va)
                nxt2 = self.transfer(target, kind == 2, nxt)
                return nxt if nxt2 is None else nxt2
            else:
                fail(f"unsupported ff form at {va:#x}")
        elif 0x70 <= op <= 0x7f or 0x0f80 <= op <= 0x0f8f:
            return f["target"] if self.cond(op & 15, va) else nxt
        elif op in (0xeb, 0xe9):
            return self.transfer(f["target"], False, nxt)
        elif op == 0xe8:
            nxt2 = self.transfer(f["target"], True, nxt)
            return nxt if nxt2 is None else nxt2
        elif 0x0f40 <= op <= 0x0f4f:
            value = self.get(f["rm"], size, f, va)
            if self.cond(op & 15, va):
                self.set_reg(f["reg"], size, value, f)
            elif size == 32:
                self.set_reg(f["reg"], 32, self.regs[f["reg"]], f)
        elif op == 0x0fb6:
            self.set_reg(f["reg"], size, self.get(f["rm"], 8, f, va), f)
        elif op == 0x0fb7:
            self.set_reg(f["reg"], size, self.get(f["rm"], 16, f, va), f)
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
        elif op == 0x3c:
            self.flags_sub(self.regs[0] & 0xff, f["imm"], 8)
        elif op == 0x28:
            a, b = self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f)
            self.put(f["rm"], 8, self.flags_sub(a, b, 8), f, va)
        elif op == 0x6b:
            mask = (1 << size) - 1
            a = self.get(f["rm"], size, f, va)
            a = a - (1 << size) if a >> (size - 1) else a
            self.set_reg(f["reg"], size, (a * f["imm"]) & mask, f)
            self.of = None  # flags of imul are not modelled; reading them fails
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
        elif op == 0xcc:
            fail(f"int3 reached at {va:#x}")
        else:
            fail(f"unhandled opcode {op:#x} at {va:#x}")
        return nxt


def put(buf, off, size, value):
    buf[off:off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def u(buf, off, size):
    return int.from_bytes(buf[off:off + size], "little")


class Stream:
    """Deterministic byte stream: SHA-512 of a label and a counter."""

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


# ---------------------------------------------------------------- target constants
# Opcode table slots 0xf0 (CREATE) and 0xf5 (CREATE2).  RELATIVE tables 0x6485ef8 and 0x6486c60 hold the same
# pair; the third table 0x649eea0 holds the second family.
TABLES = {"A": 0x6485ef8, "B": 0x6486c60, "C": 0x649eea0}
SLOTS = {"create": 0xf0, "create2": 0xf5}
HANDLERS = {"AB": {"create": 0x4338c10, "create2": 0x4339270}, "C": {"create": 0x4f07ae0, "create2": 0x4f07460}}
SIZES = {"AB": {"create": 1625, "create2": 1858}, "C": {"create": 1442, "create2": 1658}}
PENDING_HELPER = 0x4f00920  # family C: drop the old pending slot content and install the new one
STATE1_DROP = 0x4354780  # family AB: drop of pending state 1 (called directly)
RESIZE = 0x45244c0  # memory expansion body reached through GOT slot 0x64e6de0
RESERVE = 0x5be8d40  # raw Vec<u8> reserve called by the resize body (stubbed)
SLOT_ALLOC, SLOT_MEMCPY, SLOT_FREE = 0x64df480, 0x64df508, 0x64df4a0
SLOT_ALLOC_ALIGN = 0x64df490
SLOT_PANIC, SLOT_PANIC_DIV, SLOT_PANIC_SHIFT, SLOT_ALLOC_ERROR, SLOT_UNWIND = 0x64df520, 0x64df878, 0x64df870, 0x64df498, 0x64df4c0
SLOT_RESIZE, SLOT_ARC_SLOW, SLOT_MEMSET = 0x64e6de0, 0x64e4fa8, 0x64df750
SLOT_VT_EVEN, SLOT_VT_ODD = 0x64df8c0, 0x64df8c8
EMPTY_VT = {"AB": 0x6485430, "C": 0x649f6b8}  # per-family static Bytes vtable for an empty initcode slice
# panic message addresses by family: end offset+len, base+offset, base+end, 1/64 divisor of zero
MSG = {"AB": {"end": 0x648f1e8, "base1": 0x64bfc68, "base2": 0x64bfc80, "div": 0x6486af8},
       "C": {"end": 0x64af380, "base1": 0x64bfc68, "base2": 0x64bfc80, "div": 0x649f770}}
RESIZE_MSG = {"div": 0x648f230, "words": 0x648f1d0, "add": 0x64bfcf8}

HOST, CELL, MEMBUF, STK, CTX, PARAMS = 0x1000_0000, 0x1100_0000, 0x2000_0000, 0x1200_0000, 0x1300_0000, 0x1400_0000
ALLOC, FAKE = 0x1600_0000, 0x1700_0000
FAKEFN = 0x7d00_0000_0000  # pending-slot drop callback (stubbed, recorded)
FAKEVT, PBOX, ARCBOX, ARCCNT = FAKE, FAKE + 0x100, FAKE + 0x200, FAKE + 0x300
MEMSZ, STKSLOTS, ALLOCSZ = 1 << 17, 24, 1 << 17
BOXSZ = 0xc8

RET_STATIC, RET_UNDERFLOW, RET_BIG, RET_GAS, RET_MEMGAS, RET_SPEC, RET_LIMIT, RET_OK = 0x28, 0x2c, 0x24, 0x20, 0x21, 0x2b, 0x35, 4
NO_PENDING = 0x38

# record layout (offsets inside the 0xc8-byte create request): tag byte, salt, initcode Bytes, value, forwarded
# gas, refund counter, executing address; every other byte is stack padding and is not compared
DEF_COMMON = [(0x28, 32), (0x48, 32), (0x68, 8), (0x70, 8), (0x78, 20), (0x8c, 1), (0xa1, 1), (0, 1)]
DEF_SALT = [(8, 32)]


# ---------------------------------------------------------------- pure-Python reconstruction
def mem_cost(words, c50, c58):
    """Total memory gas for `words` 32-byte words: words*c50 + words*words/c58 (u64 saturating; c58 == 0 panics)."""
    lin = min(words * c50, M64)
    sq = min(words * words, M64)
    if c58 == 0:
        return None
    return min(lin + sq // c58, M64)


def resize_model(s, words, mut=frozenset()):
    """Model of 0x45244c0 on the mutable state dict `s`; returns 0, RET_MEMGAS or ('panic', msg)."""
    cost = mem_cost(words, s["c50"], s["c58"] if "no_square" not in mut else M64)
    if cost is None:
        return ("panic", RESIZE_MSG["div"])
    s["mem_words"] = words
    delta = (cost - s["mem_cost"]) & M64
    if "delta_clamp" in mut:
        delta = max(0, cost - s["mem_cost"])
    s["mem_cost"] = cost
    if "store_cost_late" in mut:
        s["mem_cost"] = s["mem_cost"] if s["gas"] >= delta else s["mem_cost"] - delta
    if s["gas"] < delta + (1 if "gas_le" in mut else 0):
        return RET_MEMGAS
    s["gas"] -= delta
    if words >> 59 and "no_words_panic" not in mut:
        return ("panic", RESIZE_MSG["words"])
    newlen = words * 32 + s["base"]
    s["flag"] = -1
    if newlen > M64:
        return ("panic", RESIZE_MSG["add"])
    grow = newlen - s["cell_len"]
    if grow > 0:
        if grow > s["cell_cap"] - s["cell_len"] and "no_reserve" not in mut:
            s["events"].append(("reserve", s["cell_len"], grow))
            s["cell_cap"] = max(2 * s["cell_cap"], s["cell_len"] + grow)
        if "no_zero_fill" not in mut:
            for i in range(s["cell_len"], newlen):
                s["membuf"][i] = 0
    s["flag"] = 0 if "flag_keep" not in mut else 1
    s["cell_len"] = newlen if "no_shrink" not in mut or grow > 0 else s["cell_len"]
    return 0


def word_count(n):
    return (n >> 5) + (1 if n & 31 else 0)


def sat_i64_add(a, b):
    """Signed 64-bit saturating add of two u64 bit patterns (the add / cmovo pair)."""
    sa, sb = a - (1 << 64) if a >> 63 else a, b - (1 << 64) if b >> 63 else b
    return max(-(1 << 63), min((1 << 63) - 1, sa + sb)) & M64


def alloc_model(s, size):
    s["alloc_count"] += 1
    s["events"].append(("alloc", size))
    if s["alloc_fail"] and s["alloc_count"] == s["alloc_fail"]:
        return 0
    odd = s["odd"]
    ptr = ALLOC + s["bump"] + odd
    s["bump"] += (size + odd + 15) & ~15
    if size == BOXSZ:
        s["box_ptr"] = ptr
    return ptr


def drop_bytes(s, vt, ptr, ln, mut):
    if "drop_missing" not in mut:
        s["events"].append((s["drop_name"][vt], ptr, ln))


def pending_replace(s, fam, box, mut):
    """Drop the old pending-call slot content and install the new boxed request (state 2)."""
    tag = s["pend_tag"]
    if tag != NO_PENDING and "no_pending_drop" not in mut:
        if tag != 0:
            s["events"].append(("pend_cb", HOST + 0xd0, s["pend_c0"], s["pend_c8"]))
        else:
            st = s["pend_b8"]
            if st == 1:
                if fam == "AB":
                    s["events"].append(("state1_drop", s["pend_c0"]))
                else:
                    if s["arc_vt"]:
                        s["events"].append(("pend_cb", ARCBOX + 0x68, s["arc_58"], s["arc_60"]))
                    s["arc_cnt"] = (s["arc_cnt"] - 1) & M64
                    if s["arc_cnt"] == 0:
                        s["events"].append(("arc_slow", ARCBOX + 0x48))
                    s["events"].append(("free", ARCBOX, 0xd0, 0))
            elif st != 0:
                s["events"].append(("pend_cb", PBOX + 0x40, s["box_30"], s["box_38"]))
                s["events"].append(("free", PBOX, BOXSZ, 0))
    s["pend_b8"], s["pend_c0"] = (2, box)
    s["pend_c8"] = s["pend_c8"]
    s["pend_tag"] = 0 if "pend_tag_keep" not in mut else tag
    s["b149"] = 0 if "b149_keep" not in mut else s["b149"]


def create_model(kind, fam, s, mut=frozenset()):
    """Reconstruct CREATE / CREATE2.  Returns 0x04 (request queued), a status byte, ('panic', msg) or ('alloc', size).

    Mutates the state dict s exactly as the handler mutates the host, the cell, the context counters and the heap.
    `mut` names deliberately wrong variants used as negative controls (empty in the reconstruction)."""
    c2 = kind == "create2"
    msg = MSG[fam]
    st = s["stack"]
    if s["static"] and "static_ignored" not in mut:
        return RET_STATIC
    if c2 and s["spec"] <= (4 if "spec_off_by_one" not in mut else 3):
        return RET_SPEC
    if len(st) < (3 if "underflow_off_by_one" not in mut else 2):
        return RET_UNDERFLOW
    value, offset, length = st.pop(), st.pop(), st.pop()
    if length >> 64 and "len_high_ignored" not in mut:
        return RET_BIG
    length &= M64
    evt = EMPTY_VT[fam]
    vt, ptr, ln, field = evt, 1, 0, 0

    def fail_with(status):
        drop_bytes(s, vt, ptr, ln, mut)
        return status

    if length == 0 and "empty_not_special" not in mut:
        if c2 and not st:
            return fail_with(RET_UNDERFLOW)
    else:
        if s["spec"] > 9 and "no_limit" not in mut:
            if s["c210"]:
                over = length > s["c218"]
            elif s["c200"] == 1:
                over = not (s["c208"] >> 63) and length > 2 * s["c208"]
            else:
                over = length > 0xc000 + (0x4000 if s["c268"] >= 0xe else 0)
            if over:
                return fail_with(RET_LIMIT)
            cost = min(word_count(length) * s["c60"], M64) if "words_floor" not in mut else min((length >> 5) * s["c60"], M64)
            if s["gas"] < cost + (1 if "gas_le" in mut else 0):
                return fail_with(RET_GAS)
            s["gas"] -= cost
        if (offset >> 64) and "offset_high_ignored" not in mut:
            return fail_with(RET_BIG)
        offset &= M64
        end = offset + length
        words = word_count(min(end, M64))
        if words > s["mem_words"]:
            r = resize_model(s, words, mut)
            if r != 0:
                return fail_with(r) if isinstance(r, int) else r
        if end > M64:
            return ("panic", msg["end"])
        s["flag"] += 1
        if offset + s["base"] > M64:
            return ("panic", msg["base1"])
        if end + s["base"] > M64:
            return ("panic", msg["base2"])
        p = alloc_model(s, length)
        if p == 0:
            return ("alloc", length)
        src = offset + (s["base"] if "base_ignored" not in mut else 0)
        s["alloc_mem"][p - ALLOC:p - ALLOC + length] = s["membuf"][src:src + length]
        odd = (p & 1) if "vt_swapped" not in mut else 1 - (p & 1)
        newvt = s["vt_odd"] if odd else s["vt_even"]
        drop_bytes(s, vt, ptr, ln, mut)
        vt, ptr, ln, field = newvt, p, length, p | (1 if "field_not_tagged" not in mut else 0)
        s["flag"] -= 1 if "flag_not_restored" not in mut else 0
        if c2 and not st:
            return fail_with(RET_UNDERFLOW)
    salt = 0
    if c2:
        salt = st.pop()
        cost = s["c68"] + min(word_count(length) * s["c48"], M64) if "hash_free" not in mut else s["c68"]
        cost = min(cost, M64)
    else:
        cost = s["c68"]
    if s["gas"] < cost + (1 if "gas_le" in mut else 0):
        return fail_with(RET_GAS)
    s["gas"] -= cost
    if s["c265"] == 1 and "no_refund_accounting" not in mut:
        thr, r = s["c168"], s["r190"]
        if r >= thr:
            s["r198"] = sat_i64_add(thr, s["r198"])
            s["r190"] = r - thr
        else:
            d = thr - r
            if s["gas"] < d:
                return fail_with(RET_GAS)
            s["r198"] = sat_i64_add(thr, s["r198"])
            s["gas"] -= d
            s["r190"] = 0
    g = s["gas"]
    s["split_gas"] = g
    if s["spec"] > 1 and "all_gas" not in mut:
        if s["c70"] == 0:
            return ("panic", msg["div"])
        fwd = g - g // s["c70"] if "keep_wrong" not in mut else g // s["c70"]
    else:
        fwd = g
    s["gas"] = g - fwd
    rec = {}
    rec[0] = bytes([1 if c2 else 0])
    if c2:
        rec[8] = salt.to_bytes(32, "little") if "salt_big_endian" not in mut else salt.to_bytes(32, "big")
    rec[0x28] = struct.pack("<4Q", vt, ptr, ln, field)
    rec[0x48] = value.to_bytes(32, "little")
    rec[0x68] = struct.pack("<Q", fwd)
    rec[0x70] = struct.pack("<Q", s["r190"])
    rec[0x78] = bytes(s["addr"]) if "addr_zero" not in mut else bytes(20)
    rec[0x8c] = b"\0"
    rec[0xa1] = b"\0"
    s["record"] = rec
    box = alloc_model(s, BOXSZ)
    if box == 0:
        return ("alloc", BOXSZ)
    pending_replace(s, fam, box, mut)
    return RET_OK


# ---------------------------------------------------------------- machine harness
class Shell:
    """Looks up the relocated words the handlers call through."""

    def __init__(self, image):
        self.image = image
        w = image.word
        self.vt_even, self.vt_odd = w(SLOT_VT_EVEN), w(SLOT_VT_ODD)
        self.fn = {k: w(v) for k, v in (("alloc", SLOT_ALLOC), ("panic", SLOT_PANIC), ("panic_div", SLOT_PANIC_DIV),
                                       ("panic_shift", SLOT_PANIC_SHIFT), ("alloc_error", SLOT_ALLOC_ERROR), ("alloc_align", SLOT_ALLOC_ALIGN),
                                       ("memcpy", SLOT_MEMCPY), ("free", SLOT_FREE), ("unwind", SLOT_UNWIND), ("memset", SLOT_MEMSET),
                                       ("arc_slow", SLOT_ARC_SLOW))}
        self.drop_fns = {w(EMPTY_VT["AB"] + 0x20): "drop_static", w(EMPTY_VT["C"] + 0x20): "drop_static_c",
                         w(self.vt_even + 0x20): "drop_even", w(self.vt_odd + 0x20): "drop_odd"}


def region(mm, base):
    for lo, hi, buf in mm.regions:
        if lo == base:
            return buf
    fail("missing region")


def read_bytes(mm, at, n):
    for lo, hi, buf in mm.regions:
        if lo <= at and at + n <= hi:
            return bytes(buf[at - lo:at - lo + n])
    fail(f"read outside regions at {at:#x}")


def write_bytes(mm, at, data):
    for lo, hi, buf in mm.regions:
        if lo <= at and at + len(data) <= hi:
            buf[at - lo:at - lo + len(data)] = data
            return
    fail(f"write outside regions at {at:#x}")


def u256_limbs(w):
    return [(w >> (64 * i)) & M64 for i in range(4)]


def install(sh, mach, c):
    """Fill the machine with the state of case `c` and register stubs.  Returns (machine, state)."""
    m = mach
    m.reset()
    m.stubs.clear()
    host = m.add_region(HOST, 0x400)
    cell = m.add_region(CELL, 0x40)
    m.add_region(MEMBUF, MEMSZ + 64, bytes(c["membuf"]) + b"\xaa" * (MEMSZ + 64 - len(c["membuf"])))
    stk = m.add_region(STK, 32 * STKSLOTS)
    ctx = m.add_region(CTX, 0x300)
    par = m.add_region(PARAMS, 0x200)
    m.add_region(ALLOC, ALLOCSZ)
    fake = m.add_region(FAKE, 0x400)
    put(host, 0x10, 8, CELL)
    put(host, 0x18, 8, c["base"])
    put(host, 0x28, 8, STK)
    put(host, 0x30, 8, len(c["stack"]))
    host[0x78:0x78 + 20] = bytes(c["addr"])
    put(host, 0x170, 8, c["mem_words"])
    put(host, 0x178, 8, c["mem_cost"])
    put(host, 0x188, 8, c["gas"])
    put(host, 0x190, 8, c["r190"])
    put(host, 0x198, 8, c["r198"])
    host[0x1a8] = c["static"]
    host[0x1a9] = c["spec"]
    host[0x110] = c["pend_tag"]
    host[0x149] = c["b149"]
    put(host, 0xb8, 8, c["pend_b8"])
    put(host, 0xc0, 8, c["pend_c0"])
    put(host, 0xc8, 8, c["pend_c8"])
    put(cell, 0x10, 8, c["flag"])
    put(cell, 0x18, 8, c["cell_cap"])
    put(cell, 0x20, 8, MEMBUF)
    put(cell, 0x28, 8, c["cell_len"])
    for i, w in enumerate(c["stack"]):
        for j, limb in enumerate(u256_limbs(w)):
            put(stk, 32 * i + 8 * j, 8, limb)
    put(ctx, 0x200, 8, c["c200"])
    put(ctx, 0x208, 8, c["c208"])
    ctx[0x210] = c["c210"]
    put(ctx, 0x218, 8, c["c218"])
    put(ctx, 0x250, 8, PARAMS)
    ctx[0x265] = c["c265"]
    ctx[0x268] = c["c268"]
    for off, key in ((0x48, "c48"), (0x50, "c50"), (0x58, "c58"), (0x60, "c60"), (0x68, "c68"), (0x70, "c70"), (0x168, "c168")):
        put(par, off, 8, c[key])
    put(fake, 0x20, 8, FAKEFN)  # vtable whose slot 0x20 is the drop callback
    put(fake, 0x100 + 0x28, 8, FAKEVT)  # boxed pending request: vtable, two callback arguments
    put(fake, 0x100 + 0x30, 8, c["box_30"])
    put(fake, 0x100 + 0x38, 8, c["box_38"])
    put(fake, 0x200 + 0x48, 8, ARCCNT)  # shared pending state: counter, optional drop vtable
    put(fake, 0x200 + 0x50, 8, FAKEVT if c["arc_vt"] else 0)
    put(fake, 0x200 + 0x58, 8, c["arc_58"])
    put(fake, 0x200 + 0x60, 8, c["arc_60"])
    put(fake, 0x300, 8, c["arc_cnt"])
    state = {"bump": 0, "count": 0, "events": [], "box": None}

    def alloc(mm):
        size = mm.regs[7]
        state["count"] += 1
        state["events"].append(("alloc", size))
        if c["alloc_fail"] and state["count"] == c["alloc_fail"]:
            mm.regs[0] = 0
            return
        ptr = ALLOC + state["bump"] + c["odd"]
        state["bump"] += (size + c["odd"] + 15) & ~15
        if size == BOXSZ:
            state["box"] = ptr
        mm.regs[0] = ptr

    def memcpy(mm):
        dst, src, n = mm.regs[7], mm.regs[6], mm.regs[2]
        write_bytes(mm, dst, read_bytes(mm, src, n))
        mm.regs[0] = dst

    def memset(mm):
        dst, val, n = mm.regs[7], mm.regs[6] & 0xff, mm.regs[2]
        write_bytes(mm, dst, bytes([val]) * n)
        mm.regs[0] = dst

    def reserve(mm):  # raw Vec<u8>::reserve: capacity becomes at least len + additional, buffer stays in place
        v, ln, add = mm.regs[7], mm.regs[6], mm.regs[2]
        cap = mm.load(v, 8)
        state["events"].append(("reserve", ln, add))
        mm.store(v, 8, max(2 * cap, ln + add))

    def logger(name, regs):
        def fn(mm):
            state["events"].append((name,) + tuple(mm.regs[r] for r in regs))
        return fn

    m.stubs[sh.fn["alloc"]] = alloc
    m.stubs[sh.fn["memcpy"]] = memcpy
    m.stubs[RESERVE] = reserve
    m.stubs[sh.fn["memset"]] = memset
    m.stubs[sh.fn["free"]] = logger("free", (7, 6, 2))
    m.stubs[FAKEFN] = logger("pend_cb", (7, 6, 2))
    m.stubs[STATE1_DROP] = logger("state1_drop", (7,))
    m.stubs[sh.fn["arc_slow"]] = logger("arc_slow", (7,))
    for fn_addr, name in sh.drop_fns.items():
        m.stubs[fn_addr] = logger(name, (6, 2))
    for key in ("panic", "panic_div", "panic_shift", "alloc_error", "alloc_align", "unwind"):
        m.stubs[sh.fn[key]] = key
    return m, state


def run_handler(sh, mach, c, addr, override=None):
    """Execute the real handler at `addr` on case c; returns the observation dict."""
    m, state = install(sh, mach, c)
    m.override = override or {}
    m.regs[7], m.regs[6] = HOST, CTX
    try:
        m.run(addr)
        status = m.regs[0] & 0xff
    except Boundary as b:
        if b.kind in ("panic", "panic_div", "panic_shift"):
            status = ("panic", b.regs[7])
        elif b.kind in ("alloc_error", "alloc_align"):
            status = ("alloc", b.regs[6])
        else:
            fail(f"unexpected boundary {b.kind}")
    return observe(m, state, status, c)


def defined(kind):
    return DEF_COMMON + (DEF_SALT if kind == "create2" else [])


def box_digest(raw, kind):
    return b"".join(raw[o:o + n] for o, n in sorted(defined(kind))).hex()


def observe(m, state, status, c):
    host, cell, fake = region(m, HOST), region(m, CELL), region(m, FAKE)
    obs = {"status": status, "stack_len": u(host, 0x30, 8), "gas": u(host, 0x188, 8), "words": u(host, 0x170, 8),
           "cost": u(host, 0x178, 8), "cell_len": u(cell, 0x28, 8), "flag": u(cell, 0x10, 8),
           "r190": u(host, 0x190, 8), "r198": u(host, 0x198, 8), "events": tuple(state["events"]),
           "pend": (u(host, 0xb8, 8), u(host, 0xc0, 8), host[0x110], host[0x149]), "arc_cnt": u(fake, 0x300, 8),
           "membuf": hashlib.sha256(bytes(region(m, MEMBUF))).hexdigest()}
    heap = bytearray(region(m, ALLOC)[:state["bump"]])
    obs["bump"] = state["bump"]
    obs["box"] = "-"
    if state["box"] is not None and status == RET_OK:
        off = state["box"] - ALLOC
        obs["box"] = box_digest(heap[off:off + BOXSZ], c["kind"])
    if state["box"] is not None:  # the request box is compared on its defined bytes only (see box)
        off = state["box"] - ALLOC
        heap[off:off + BOXSZ] = bytes(BOXSZ)
    obs["heap"] = hashlib.sha256(bytes(heap)).hexdigest()
    return obs


# ---------------------------------------------------------------- model-side observation
def fresh_state(c, sh):
    s = dict(c)
    s["stack"] = list(c["stack"])
    mem = bytearray(MEMSZ + 64)
    mem[:] = bytes(c["membuf"]) + b"\xaa" * (MEMSZ + 64 - len(c["membuf"]))
    s["membuf"] = mem
    s["alloc_mem"] = bytearray(ALLOCSZ)
    s["bump"], s["alloc_count"], s["events"], s["box_ptr"] = 0, 0, [], None
    s["vt_even"], s["vt_odd"] = sh.vt_even, sh.vt_odd
    s["drop_name"] = {EMPTY_VT["AB"]: "drop_static", EMPTY_VT["C"]: "drop_static_c", sh.vt_even: "drop_even",
                      sh.vt_odd: "drop_odd"}
    return s


def model_obs(s, status, c):
    obs = {"status": status, "stack_len": len(s["stack"]), "gas": s["gas"], "words": s["mem_words"],
           "cost": s["mem_cost"], "cell_len": s["cell_len"], "flag": s["flag"] & M64, "r190": s["r190"],
           "r198": s["r198"], "events": tuple(s["events"]),
           "pend": (s["pend_b8"], s["pend_c0"], s["pend_tag"], s["b149"]), "arc_cnt": s["arc_cnt"],
           "membuf": hashlib.sha256(bytes(s["membuf"])).hexdigest()}
    heap = bytearray(s["alloc_mem"][:s["bump"]])
    obs["bump"] = s["bump"]
    obs["box"] = "-"
    if status == RET_OK:
        raw = bytearray(BOXSZ)
        for off, data in s["record"].items():
            raw[off:off + len(data)] = data
        obs["box"] = box_digest(raw, c["kind"])
    obs["heap"] = hashlib.sha256(bytes(heap)).hexdigest()
    return obs


def model_handler(c, sh, mut=frozenset()):
    s = fresh_state(c, sh)
    s["b149"] = c["b149"]
    try:
        status = create_model(c["kind"], c["fam"], s, mut)
    except IndexError:  # only a deliberately wrong variant can run off the harness buffers
        return {"status": "model-fault", "stack_len": -1}
    return model_obs(s, status, c)


def model_resize(c, sh, words, mut=frozenset()):
    s = fresh_state(c, sh)
    s["b149"] = c["b149"]
    try:
        status = resize_model(s, words, mut)
    except IndexError:
        return {"status": "model-fault", "stack_len": -1}
    return model_obs(s, status, c)


def diff(a, b):
    return [k for k in a if a.get(k) != b.get(k)]


# ---------------------------------------------------------------- cases
WORD_BOUNDS = (0, 1, 31, 32, 33, 63, 64, 65, 1023, 1024)
MODES = 40


def rand_word(st):
    return int.from_bytes(st.take(32), "little")


def small_len(st):
    kind = st.below(10)
    if kind < 2:
        return 0
    if kind < 5:
        return st.below(100) + 1
    if kind < 8:
        return st.pick(WORD_BOUNDS) + st.below(3)
    return st.below(6000) + 1


def make_case(k):
    """Case k: a deterministic CREATE / CREATE2 scenario; the same k always yields the same case.

    Each case fixes the host (stack, gas, memory words/cost, base offset, static flag, spec byte, refund counters,
    pending-call slot), the context limits, the gas schedule (seven parameters the handlers read), the memory
    cell and the heap behaviour."""
    st = Stream(f"evm-create-{k}")
    kind = ("create", "create2")[k % 2]
    fam = ("AB", "C")[(k // 2) % 2]
    mode = st.below(MODES)
    c = {"k": k, "kind": kind, "fam": fam, "mode": mode, "odd": 0}
    c["base"] = st.pick((0, 0, 0, 32, 96, 480, st.below(512)))
    c["mem_words"] = st.pick((0, 0, 1, 2, 7, st.below(60), st.below(300)))
    c["cell_len"] = c["base"] + 32 * c["mem_words"]
    c["cell_cap"] = st.pick((MEMSZ, MEMSZ, c["cell_len"], c["cell_len"] + 16, st.below(4096) + c["cell_len"]))
    c["flag"] = st.below(4)
    c["static"] = 1 if st.below(30) == 0 else 0
    c["addr"] = st.take(20)
    c["spec"] = st.pick((5, 9, 10, 11, 12, 13, 14, 15, 16, 14, 10))
    c["c200"], c["c208"] = st.pick((0, 0, 1, 2)), st.pick((0, 24576, 40000, 1 << 62, 1 << 63, M64, 100))
    c["c210"], c["c218"] = st.pick((0, 0, 0, 1)), st.pick((0, 100, 49152, 1000, 65536, M64))
    c["c265"], c["c268"] = st.pick((0, 1, 1, 2)), st.pick((0, 8, 0xd, 0xe, 0x10, 0xff))
    c["c48"], c["c60"] = st.pick((6, 6, 6, 0, 1, st.below(50))), st.pick((2, 2, 2, 0, 1, st.below(50)))
    c["c68"] = st.pick((32000, 32000, 32000, 0, 1, st.below(100000)))
    c["c70"] = st.pick((64, 64, 64, 1, 2, st.below(1000) + 1))
    c["c168"] = st.pick((0, 2000, 4800, 1, st.below(10000)))
    c["c50"] = st.pick((3, 3, 3, 0, 1, st.below(10)))
    c["c58"] = st.pick((512, 512, 512, 1, 7, st.below(2000) + 1))
    c["r190"] = st.pick((0, c["c168"], c["c168"] + 1, max(0, c["c168"] - 1), st.below(20000), 1 << 40))
    c["r198"] = st.pick((0, 5, st.below(10000), (1 << 63) - 3, (1 << 63) + 3, M64, 1 << 63))
    c["alloc_fail"] = 0
    c["b149"] = st.pick((0, 1, 7))
    pk = st.below(9)
    c["pend_tag"], c["pend_b8"], c["pend_c0"], c["pend_c8"] = NO_PENDING, 0, 0, 0
    if pk == 1:
        c["pend_tag"] = 0
    elif pk == 2:
        c["pend_tag"], c["pend_b8"], c["pend_c0"] = 0, 1, ARCBOX
    elif pk in (3, 4):
        c["pend_tag"], c["pend_b8"], c["pend_c0"] = 0, 2, PBOX
    elif pk == 5:
        c["pend_tag"], c["pend_b8"], c["pend_c0"] = 0, st.pick((3, 9, 1 << 40)), PBOX
    elif pk == 6:
        c["pend_tag"], c["pend_b8"] = st.pick((1, 2, 0x37, 0x39, 0xff)), FAKEVT
        c["pend_c0"], c["pend_c8"] = st.below(1 << 60), st.below(1 << 60)
    c["box_30"], c["box_38"] = st.below(1 << 60), st.below(1 << 60)
    c["arc_vt"], c["arc_cnt"] = st.pick((0, 1)), st.pick((1, 1, 2, 5, 0))
    c["arc_58"], c["arc_60"] = st.below(1 << 60), st.below(1 << 60)
    offset, length = st.below(2000), small_len(st)
    if mode == 0:
        c["spec"] = st.pick((0, 1, 2, 3, 4))
    elif mode == 1:
        c["static"] = 1
    elif mode == 3:
        length = st.pick((1 << 64, 1 << 70, rand_word(st) | (1 << 64), 1 << 255))
    elif mode == 4:
        offset = st.pick((1 << 64, 1 << 130, rand_word(st) | (1 << 255)))
        length = st.below(40) + 1
    elif mode in (5, 6):  # initcode size limit: default (spec byte 0xe raises it), context limit, or doubled limit
        which = st.below(3)
        c["spec"] = st.pick((10, 12, 13, 14, 15))
        if which == 0:
            c["c210"], c["c200"] = 0, st.pick((0, 2, 3))
            lim = 0xc000 + (0x4000 if c["c268"] >= 0xe else 0)
        elif which == 1:
            c["c210"] = 1
            c["c218"] = st.pick((100, 1000, 3000, 40000))
            lim = c["c218"]
        else:
            c["c210"], c["c200"] = 0, 1
            c["c208"] = st.pick((100, 1000, 24576, 40000))
            lim = 2 * c["c208"]
        length = lim + (st.pick((0, 1, -1, 2, -2)) if mode == 6 else st.below(4000) + 1)
        length = max(1, length)
        offset = st.below(64)
    elif mode == 7:
        c["spec"], c["c210"], c["c200"], c["c208"] = 11, 0, 1, st.pick((1 << 63, M64, (1 << 63) + 77))
        length = st.pick((60000, 70000, 100000))
    elif mode == 10:  # memory already at the u64 word limit: no resize, so the end-overflow panic is reachable
        c["mem_words"], c["cell_len"] = 1 << 59, 0
        offset, length = (1 << 64) - 1 - st.below(50), st.below(200) + 60
        c["spec"] = 5
    elif mode == 11:  # base so large that the resize add (or the copy base add) overflows
        b0 = st.below(30) if st.below(2) else st.below(2000)
        c["base"] = (1 << 64) - 1 - b0
        c["cell_len"] = 0
        c["spec"] = 5
        if b0 < 30:
            c["mem_words"] = 0
            offset, length = st.below(100), st.below(100) + 1
        elif st.below(2):
            c["mem_words"] = 1 << 59
            offset, length = b0 + 1 + st.below(50), st.below(100) + 1
        else:
            c["mem_words"] = 1 << 59
            offset, length = st.below(100), st.below(100) + 60
            c["base"] = (1 << 64) - 1 - offset - 1 - st.below(50)
    elif mode == 12:
        c["alloc_fail"] = st.pick((1, 2, 2))
        length = max(length, 1) if c["alloc_fail"] == 1 else length
    elif mode == 13:
        c["odd"] = 1
    elif mode == 16:  # refund counters near the signed saturation edges
        c["c265"], c["c168"] = 1, st.pick((1 << 62, (1 << 63) - 1, 1 << 63, M64, 5))
        c["r198"] = st.pick((1 << 62, (1 << 63) - 2, 1 << 63, (1 << 63) + 5, M64 - 3, 5))
        c["r190"] = st.pick((0, c["c168"] // 2, c["c168"], M64))
    elif mode == 17:  # 1/64 divisor of zero (panics from the Berlin-or-later spec on) and the all-gas spec bytes
        c["c70"] = 0
        c["spec"] = st.pick((0, 1, 2, 5, 10, 14))
    elif mode == 18:
        c["spec"] = st.pick((0, 1, 1, 2))
        if kind == "create2":
            c["spec"] = 5
    elif mode == 19:
        length = 0
    elif mode == 20:  # cell already longer than the new memory: the resize shrink branch
        c["cell_len"] = c["base"] + st.below(MEMSZ - 600)
        c["cell_cap"] = MEMSZ
    elif mode == 21:  # the cell is exactly full: growth needs the raw-vector reserve
        need = (offset + length + 31) >> 5
        c["cell_len"] = c["base"] + 32 * need - st.pick((1, 1, 2, 33))
        c["cell_cap"] = c["cell_len"]
        c["mem_words"] = st.below(max(need, 1))
    elif mode == 22:
        c["c60"], c["c48"] = st.pick((1 << 63, M64, 1 << 40)), st.pick((1 << 63, M64, 1 << 40))
        c["spec"] = 10
        length = st.below(2000) + 33
    elif mode == 23:
        c["c68"] = st.pick((M64, M64 - 5, 1 << 63))
    elif mode == 24:
        length = st.pick((31, 32, 33, 63, 64, 65, 1, 0))
    elif mode == 25:
        c["c50"] = st.pick((1 << 63, M64))
    elif mode == 26:
        c["c58"] = 0
    elif mode == 27:
        c["spec"] = st.pick((6, 7, 8, 9))
    c["offset"], c["length"] = offset, length
    c["mem_cost"] = mem_cost(c["mem_words"], c["c50"], c["c58"]) or 0
    n = 4 if kind == "create2" else 3
    salt = rand_word(st)
    value = rand_word(st) if st.below(3) else st.below(1000)
    extra = st.pick((0, 0, 0, 1, 3))
    c["stack"] = [rand_word(st) for _ in range(extra)] + ([salt] if kind == "create2" else []) + [length, offset, value]
    if mode == 2:
        c["stack"] = c["stack"][len(c["stack"]) - st.below(n):] if kind == "create" else c["stack"][-st.below(3):] if st.below(2) else c["stack"][-3:]
    if mode == 14 and kind == "create2":  # salt missing
        c["stack"] = [length, offset, value]
    fill = min(c["cell_len"], MEMSZ)
    c["membuf"] = bytes(st.take(min(fill, 1024))) + bytes((i * 7 + 3) & 0xff for i in range(max(0, fill - 1024)))
    c["gas"] = (1 << 64) - 1 if mode == 15 else 1 << 60
    if mode in (8, 9, 28, 29, 30, 31, 32, 33, 34, 35):
        c = edge_gas(c, st)
    return bound_case(c)


_SHELL = [None]


def shell():
    if _SHELL[0] is None:
        _SHELL[0] = Shell(Image(BINARY.read_bytes()))
    return _SHELL[0]


def edge_gas(c, st):
    """Set gas to an exact edge (-2..+1) of the charges the model computes before the 1/64 split."""
    s = fresh_state(c, shell())
    s["b149"] = c["b149"]
    top = s["gas"]
    create_model(c["kind"], c["fam"], s)
    if "split_gas" in s:
        used = top - s["split_gas"]
        if c["mode"] in (30, 31):  # edge of the first charge only (the initcode words or the create fee)
            used = min(used, s.get("first_charge", used))
        c["gas"] = max(0, min(M64, used + st.pick((-1, 0, 1, -2, 0))))
    else:
        c["gas"] = st.pick((0, 1, 5000, 31999, 32000, 32001))
    return c


def bound_case(c):
    """Keep every successful expansion inside the harness buffer: when the memory the case asks for would not
    fit (and would not panic first), withhold one unit of gas so the real handler stops at the charge."""
    length, offset = c["length"], c["offset"]
    n = 4 if c["kind"] == "create2" else 3
    if length == 0 or length >> 64 or offset >> 64 or c["static"] or len(c["stack"]) < 3 or \
            (c["kind"] == "create2" and c["spec"] <= 4):
        return c
    end = min(offset + length, M64)
    words = word_count(end)
    if words <= c["mem_words"] or words >> 59:
        return c
    newlen = words * 32 + c["base"]
    if newlen > M64 or newlen <= MEMSZ - 64:
        return c
    cost = mem_cost(words, c["c50"], c["c58"])
    if cost is None:
        return c
    pre = min(M64, word_count(length) * c["c60"]) if c["spec"] > 9 else 0
    need = pre + ((cost - c["mem_cost"]) & M64)
    if c["gas"] >= need:
        c["gas"] = max(0, need - 1)
    return c


def make_resize_case(k):
    """Direct case for the memory expansion body 0x45244c0: a create-shaped state plus a requested word count."""
    st = Stream(f"evm-create-resize-{k}")
    c = make_case(k)
    mw = c["mem_words"]
    kind = st.below(10)
    words = {0: mw + 1, 1: mw, 2: max(0, mw - 1), 3: st.below(1500), 4: 1 << 59, 5: (1 << 59) - 1,
             6: st.below(1 << 62), 7: st.below(1800), 8: mw + 1, 9: mw + 1}[kind]
    c["words"] = words
    c["stack"] = []
    if kind >= 8 and c["base"] + 32 * words < MEMSZ - 64:
        c["cell_len"] = c["base"] + 32 * words - (1 if kind == 8 else 2)
        c["cell_cap"] = c["cell_len"]
        c["membuf"] = c["membuf"][:c["cell_len"]]
    newlen = words * 32 + c["base"]
    if words >> 59 == 0 and MEMSZ - 64 < newlen <= M64:
        cost = mem_cost(words, c["c50"], c["c58"])
        delta = ((cost or 0) - c["mem_cost"]) & M64
        if cost is not None and delta > 0:
            c["gas"] = delta - 1
        elif cost is not None:
            c["words"], c["base"] = 0, 0
    return c


def run_resize(sh, mach, c):
    m, state = install(sh, mach, c)
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = HOST + 0x170, HOST, CTX + 0x250, c["words"]
    try:
        m.run(RESIZE)
        status = m.regs[0] & 0xff
    except Boundary as b:
        status = ("panic", b.regs[7]) if b.kind in ("panic", "panic_div", "panic_shift") else fail(b.kind)
    return observe(m, state, status, c)


# ---------------------------------------------------------------- static evidence
STATUS_NAMES = {0: "ok", RET_OK: "queued", RET_STATIC: "static-call", RET_UNDERFLOW: "stack-underflow", RET_BIG: "value-too-big",
                RET_GAS: "out-of-gas", RET_MEMGAS: "memory-out-of-gas", RET_SPEC: "opcode-not-active", RET_LIMIT: "initcode-too-large"}
N_MAIN, N_RESIZE, CTL_MAIN, CTL_RESIZE, STRIDE = 12000, 2000, 3000, 1200, 4
ALL_FUNCS = tuple(HANDLERS[f][k] for f in ("AB", "C") for k in ("create", "create2")) + (PENDING_HELPER, RESIZE)


def extents(image):
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    return {f["start"]: f["end"] for f in fdes}


def rip_leas(image, start, end):
    """Every `lea disp32(%rip), reg` target inside [start, end): REX.W 8d with a rip-relative modrm."""
    code = image.code(start, end - start)
    out = []
    for i in range(len(code) - 7):
        if code[i] in (0x48, 0x4c) and code[i + 1] == 0x8d and code[i + 2] & 0xc7 == 0x05:
            disp = struct.unpack_from("<i", code, i + 3)[0]
            out.append((start + i, (start + i + 7 + disp) & M64, ((code[i + 2] >> 3) & 7) | ((code[i] & 4) << 1)))
    return out


def call_slots(image, start, end):
    """Every `call/jmp *disp32(%rip)` (ff 15 / ff 25) inside the function: the GOT slot it goes through."""
    code = image.code(start, end - start)
    out = []
    for i in range(len(code) - 5):
        if code[i] == 0xff and code[i + 1] in (0x15, 0x25):
            disp = struct.unpack_from("<i", code, i + 2)[0]
            out.append((start + i, (start + i + 6 + disp) & M64, "call" if code[i + 1] == 0x15 else "jmp"))
    return out


def static_checks(image, ext):
    """Table slots, extents and constants the model relies on, all read from the ELF bytes."""
    w = image.word
    for fam, tabs in (("AB", ("A", "B")), ("C", ("C",))):
        for t in tabs:
            for kind, slot in SLOTS.items():
                if w(TABLES[t] + 8 * slot) != HANDLERS[fam][kind]:
                    fail(f"table {t} slot {slot:#x} does not hold {HANDLERS[fam][kind]:#x}")
        for kind, h in HANDLERS[fam].items():
            if h not in ext or ext[h] - h != SIZES[fam][kind]:
                fail(f"extent of {h:#x} differs from the recorded size")
    if RESIZE not in ext or ext[RESIZE] - RESIZE != 414:
        fail("resize extent differs")
    if w(SLOT_RESIZE) != RESIZE:
        fail("resize slot does not point at the resize body")
    for fam in ("AB", "C"):
        for kind, h in HANDLERS[fam].items():
            leas = {t for _, t, _ in rip_leas(image, h, ext[h])}
            slots = {s for _, s, _ in call_slots(image, h, ext[h])}
            need = {MSG[fam]["end"], MSG[fam]["base1"], MSG[fam]["base2"], MSG[fam]["div"], EMPTY_VT[fam]}
            if not need <= leas:
                fail(f"handler {h:#x} lacks lea targets {sorted(need - leas)}")
            need_slots = {SLOT_ALLOC, SLOT_MEMCPY, SLOT_PANIC, SLOT_ALLOC_ERROR, SLOT_ALLOC_ALIGN, SLOT_RESIZE, SLOT_PANIC_DIV}
            if fam == "AB":
                need_slots.add(SLOT_FREE)
            if not need_slots <= slots:
                fail(f"handler {h:#x} lacks expected call slots")
    if not {SLOT_FREE, SLOT_ARC_SLOW} <= {s for _, s, _ in call_slots(image, PENDING_HELPER, ext[PENDING_HELPER])}:
        fail("pending helper lacks the free and arc-drop slots")
    if ext[PENDING_HELPER] - PENDING_HELPER != 364:
        fail("pending helper extent differs")
    leas = {t for _, t, _ in rip_leas(image, RESIZE, ext[RESIZE])}
    if not set(RESIZE_MSG.values()) <= leas:
        fail("resize panic messages not found")


def table_rows(image):
    rows = ["table\topcode\thandler\tcreate_slot"]
    for t in ("A", "B", "C"):
        for op in range(256):
            h = image.word(TABLES[t] + 8 * op)
            name = {0xf0: "CREATE", 0xf5: "CREATE2"}.get(op, "-")
            rows.append(f"{t}\t{op:#04x}\t{h:#x}\t{name}")
    return rows


def got_rows(image):
    rows = ["slot\treloc\ttarget\tused_as"]
    names = {SLOT_ALLOC: "allocator", SLOT_MEMCPY: "memcpy", SLOT_MEMSET: "memset", SLOT_FREE: "deallocator", SLOT_PANIC: "panic",
             SLOT_PANIC_DIV: "panic-divide", SLOT_ALLOC_ALIGN: "alloc-error-aligned", SLOT_PANIC_SHIFT: "panic-shift", SLOT_ALLOC_ERROR: "alloc-error",
             SLOT_RESIZE: "memory-resize", SLOT_ARC_SLOW: "arc-drop-slow", SLOT_VT_EVEN: "bytes-vtable-even",
             SLOT_VT_ODD: "bytes-vtable-odd", SLOT_UNWIND: "unwind-cleanup"}
    for slot in sorted(names):
        if slot in image.imports:
            rows.append(f"{slot:#x}\tGLOB_DAT\t{image.import_name(slot)}\t{names[slot]}")
        else:
            rows.append(f"{slot:#x}\tRELATIVE\t{image.word(slot):#x}\t{names[slot]}")
    return rows


def site_rows(image, ext):
    rows = ["function\tkind\tsite\ttarget"]
    for f in ALL_FUNCS:
        for va, t, reg in rip_leas(image, f, ext[f]):
            rows.append(f"{f:#x}\tlea-r{reg}\t{va:#x}\t{t:#x}")
        for va, s, kind in call_slots(image, f, ext[f]):
            rows.append(f"{f:#x}\t{kind}-got\t{va:#x}\t{s:#x}")
    return rows


# ---------------------------------------------------------------- evaluation
def digest(obs):
    return hashlib.sha256(json.dumps(obs, sort_keys=True, default=str).encode()).hexdigest()


def tag(x):
    return x if isinstance(x, str) else (STATUS_NAMES.get(x, f"{x:#x}") if isinstance(x, int) else f"{x[0]}@{x[1]:#x}")


def evaluate(image, ext, mach, sh, rows, resize_rows):
    """Run every case on the machine code and on the model; returns counters and per-case digests."""
    bad, real_main, real_resize, classes = 0, [], [], {}
    for k in range(N_MAIN):
        c = make_case(k)
        addr = HANDLERS[c["fam"]][c["kind"]]
        got = run_handler(sh, mach, c, addr)
        want = model_handler(c, sh)
        ok = not diff(got, want)
        bad += 0 if ok else 1
        key = f"{c['kind']}:{tag(got['status']).split('@')[0]}"
        classes[key] = classes.get(key, 0) + 1
        if k < CTL_MAIN:
            real_main.append(digest(got))
        if k % STRIDE == 0:
            rows.append("\t".join(str(x) for x in (
                k, f"{addr:#x}", c["fam"], c["kind"], c["mode"], len(c["stack"]), c["spec"], c["gas"], got["gas"], tag(got["status"]),
                got["stack_len"], got["words"], got["cost"], got["r190"], got["pend"][0], got["pend"][2],
                ",".join(e[0] for e in got["events"]) or "-", digest(got)[:12], "yes" if ok else "NO")))
    for k in range(N_RESIZE):
        c = make_resize_case(k)
        got = run_resize(sh, mach, c)
        want = model_resize(c, sh, c["words"])
        ok = not diff(got, want)
        bad += 0 if ok else 1
        key = f"resize:{tag(got['status']).split('@')[0]}"
        classes[key] = classes.get(key, 0) + 1
        if k < CTL_RESIZE:
            real_resize.append(digest(got))
        if k % STRIDE == 0:
            resize_rows.append("\t".join(str(x) for x in (
                k, f"{RESIZE:#x}", c["words"], c["mem_words"], c["base"], c["gas"], got["gas"], tag(got["status"]),
                got["words"], got["cost"], got["cell_len"], got["flag"] & M64, ",".join(e[0] for e in got["events"]) or "-",
                digest(got)[:12], "yes" if ok else "NO")))
    return bad, real_main, real_resize, classes


MODEL_MUTANTS = (
    ("main", "static_ignored", "the static-call refusal (0x28) is skipped"),
    ("main", "spec_off_by_one", "CREATE2 is accepted one spec byte too early"),
    ("main", "underflow_off_by_one", "two stack words are accepted"),
    ("main", "len_high_ignored", "length limbs above the first are ignored"),
    ("main", "offset_high_ignored", "offset limbs above the first are ignored"),
    ("main", "empty_not_special", "an empty initcode slice takes the copy path"),
    ("main", "no_limit", "the initcode size limit is not enforced"),
    ("main", "words_floor", "the initcode word count rounds down"),
    ("both", "gas_le", "charges fail when gas equals the cost"),
    ("main", "base_ignored", "the frame base offset is not added to the source"),
    ("main", "flag_not_restored", "the borrow counter is not decremented after the copy"),
    ("main", "field_not_tagged", "the Bytes data word is not tagged with bit 0"),
    ("main", "vt_swapped", "the even/odd Bytes vtables are swapped"),
    ("main", "drop_missing", "the initcode Bytes is not released on failure paths"),
    ("main", "hash_free", "CREATE2 charges no hashing words"),
    ("main", "no_refund_accounting", "the refund-counter accounting is skipped"),
    ("main", "all_gas", "all remaining gas is forwarded"),
    ("main", "keep_wrong", "the retained and forwarded gas amounts are swapped"),
    ("main", "salt_big_endian", "the CREATE2 salt is stored big-endian"),
    ("main", "addr_zero", "the executing address is not recorded"),
    ("main", "no_pending_drop", "the old pending-call content is not released"),
    ("main", "pend_tag_keep", "the pending tag byte is left untouched"),
    ("main", "b149_keep", "the pending flag byte is left untouched"),
    ("both", "no_square", "the quadratic memory term is dropped"),
    ("both", "delta_clamp", "the memory delta clamps at zero instead of wrapping"),
    ("both", "store_cost_late", "the new memory cost is only stored when the charge succeeds"),
    ("both", "no_words_panic", "the 2^59 word limit panic is dropped"),
    ("both", "no_reserve", "the raw vector reserve call is skipped"),
    ("both", "no_zero_fill", "newly exposed memory is not zeroed"),
    ("both", "flag_keep", "the cell borrow flag is left at 1"),
    ("both", "no_shrink", "the cell length is not reset when memory is shorter"),
)


def code_sites(image, ext):
    """Deterministic corruption sites: per function the first conditional jump, the first status-byte
    immediate and the last one (chosen by instruction kind, not by outcome)."""
    sites = []
    for f in ALL_FUNCS:
        rows = sweep(image, f, ext[f])
        jcc = next((va for va, fm in rows if 0x0f80 <= fm["op"] <= 0x0f8f), None)
        imm = [(va, fm) for va, fm in rows if 0xb0 <= fm["op"] <= 0xb7 and fm["imm"] in (0x2c, 0x24, 0x28, 0x20, 0x21, 0x2b, 0x35, 4)]
        if jcc is not None:
            sites.append((f, "invert-first-jcc", jcc + 1, image.code(jcc + 1, 1)[0] ^ 1))
        if imm:
            va, fm = imm[0]
            sites.append((f, f"status-imm-{fm['imm']:#x}", va + 1, fm["imm"] ^ 0x08))
            va, fm = imm[-1]
            sites.append((f, f"last-status-imm-{fm['imm']:#x}", va + 1, fm["imm"] ^ 0x04))
    return sites


def controls(image, ext, sh, real_main, real_resize):
    rows, detected, equivalent = [], 0, []
    cases = [make_case(k) for k in range(CTL_MAIN)]
    rz_cases = [make_resize_case(k) for k in range(CTL_RESIZE)]
    for scope, name, text in MODEL_MUTANTS:
        mut, hit = frozenset((name,)), None
        if scope in ("main", "both"):
            for k, c in enumerate(cases):
                if digest(model_handler(c, sh, mut)) != real_main[k]:
                    hit = f"main:{k}"
                    break
        if hit is None and scope == "both":
            for k, c in enumerate(rz_cases):
                if digest(model_resize(c, sh, c["words"], mut)) != real_resize[k]:
                    hit = f"resize:{k}"
                    break
        detected += 1 if hit else 0
        rows.append(("model-mutant", name, text, hit or "UNDETECTED"))
    for f, what, at, newbyte in code_sites(image, ext):
        mach = Machine(image)
        hit = None
        pool = rz_cases if f == RESIZE else cases
        for k, c in enumerate(pool):
            if f != RESIZE and f != PENDING_HELPER and HANDLERS[c["fam"]][c["kind"]] != f:
                continue
            if f == PENDING_HELPER and c["fam"] != "C":
                continue
            try:
                if f == RESIZE:
                    mach.override, mach.cache = {at: newbyte}, {}
                    got = run_resize(sh, mach, c)
                    base = real_resize[k]
                else:
                    mach.override, mach.cache = {at: newbyte}, {}
                    got = run_handler(sh, mach, c, HANDLERS[c["fam"]][c["kind"]], override={at: newbyte})
                    base = real_main[k]
                if digest(got) != base:
                    hit = f"{'resize' if f == RESIZE else 'main'}:{k}"
                    break
            except ToolError:
                hit = f"{'resize' if f == RESIZE else 'main'}:{k}:fault"
                break
        detected += 1 if hit else 0
        rows.append(("code-byte", f"{f:#x}:{what}@{at:#x}", f"byte -> {newbyte:#04x}", hit or "UNDETECTED"))
    for kind, thunk in (("binary-digest", lambda: Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))),
                        ("not-a-function-start", lambda: static_checks_start(image)),
                        ("misaligned-handler", lambda: run_handler(sh, Machine(image), make_case(1), HANDLERS["AB"]["create"] + 3))):
        try:
            thunk()
            res = "UNDETECTED"
        except (ToolError, IndexError, KeyError):
            res = "refused"
            detected += 1
        rows.append(("input-corruption", kind, "corrupted input", res))
    return rows, detected, equivalent


def static_checks_start(image):
    ext = extents(image)
    if HANDLERS["AB"]["create"] + 1 in ext:
        return
    fail("not a function start")


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    ext = extents(image)
    static_checks(image, ext)
    mach = Machine(image)
    sh = Shell(image)
    _SHELL[0] = sh
    rows = ["case\tfunction\tfamily\tkind\tmode\tstack_in\tspec\tgas_in\tgas_out\tresult\tstack_out\twords\tmem_cost\trefund\t"
            "pending_state\tpending_tag\tstub_events\tobservation\tmatch"]
    resize_rows = ["case\tfunction\twords\twords_before\tbase\tgas_in\tgas_out\tresult\twords_after\tmem_cost\tcell_len\t"
                   "flag\tstub_events\tobservation\tmatch"]
    bad, real_main, real_resize, classes = evaluate(image, ext, mach, sh, rows, resize_rows)
    (out / "cases.tsv").write_text("\n".join(rows) + "\n")
    (out / "resize-cases.tsv").write_text("\n".join(resize_rows) + "\n")
    (out / "opcode-tables.tsv").write_text("\n".join(table_rows(image)) + "\n")
    (out / "got-slots.tsv").write_text("\n".join(got_rows(image)) + "\n")
    (out / "sites.tsv").write_text("\n".join(site_rows(image, ext)) + "\n")
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for f in ALL_FUNCS:
        hit = total = 0
        for va, fm in sweep(image, f, ext[f]):
            run = va in mach.seen
            hit += run
            total += 1
            lines.append(f"{f:#x}\t{va:#x}\t{fm['len']}\t{fm['bytes'].hex()}\t{fm['op']:#x}\t{int(run)}")
        covered[f"{f:#x}"] = [hit, total]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl, detected, equivalent = controls(image, ext, sh, real_main, real_resize)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdescription\tfirst_detecting_case\n" + "".join("\t".join(r) + "\n" for r in ctl))
    undetected = [r for r in ctl if r[3] == "UNDETECTED"]
    (out / "equivalent-mutants.tsv").write_text("mutant\taddress\treason\n")
    (out / "outcome-classes.tsv").write_text("class\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    total = N_MAIN + N_RESIZE
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes,
               "negative_controls": {"total": len(ctl), "detected": detected, "undetected": len(undetected)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    measure = {"cases": total, "negative_controls": len(ctl), "negative_detected": detected, "equivalent": 0,
               "mismatches": bad}
    (out / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: v for k, v in summary.items() if k != "covered_instructions"}, sort_keys=True))
    nc = summary["negative_controls"]
    return 1 if summary["mismatches"] or nc["undetected"] else 0


if __name__ == "__main__":
    sys.exit(main())
