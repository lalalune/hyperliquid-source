#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM LOG0..LOG4 opcode handlers and the memory expansion body 0x45244c0.

LOG0..LOG4 are opcode table slots 0xa0..0xa4.  The RELATIVE tables 0x6485ef8 and 0x6486c60 share one set of
five handlers (0x4330700, 0x432fdf0, 0x432f9a0, 0x43309e0, 0x43301c0); the third table 0x649eea0 holds a twin
set (0x4f02c40, 0x4f03d70, 0x4f03460, 0x4f038b0, 0x4f02f20) of identical length.  Each handler works on the host
(stack +0x28/+0x30, executing address +0x78, memory words +0x170, memory cost +0x178, gas +0x188, static byte
+0x1a8, memory cell +0x10, frame base offset +0x18) and the context (gas schedule +0x250, log vector +0x270).
It refuses static calls (0x28) and fewer than two stack words (0x2c), pops offset and length, refuses a length
wider than 64 bits (0x24), charges length*c30 + topics*c38 (saturating; the topic product panics on overflow
from LOG2 up), and for a non-empty slice checks the offset width, expands memory through 0x45244c0 when the
word count exceeds the current words, copies the bytes into a fresh allocation tagged as a Bytes value, pops the
topics (releasing the Bytes value and returning 0x2c when they are missing), stores them as big-endian 32-byte
words and appends a 0x50-byte log record.  The memory expansion charges words*c50 + words*words/c58, stores the
new word count and cost before the charge can fail (0x21), panics at 2^59 words, and zero-fills the cell.
The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real machine code
with a small concrete x86-64 evaluator (no external programs, the binary is never executed) and compares
every case with one pure-Python reconstruction.  Allocator, memcpy, memset, panics, the Bytes drop functions,
the log vector grow and the raw vector reserve are stubbed at their call targets and every call is recorded.
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
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64):  # operand size, segments, rep/repne
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
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
    elif op in (0x0f70, 0x0fc6):
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



# ---------------------------------------------------------------- target constants
# Opcode table slots 0xa0..0xa4 (LOG0..LOG4).  RELATIVE tables 0x6485ef8 and 0x6486c60 hold the same five
# handlers; the third family (table 0x649eea0) holds a byte-for-byte same-length twin set.
TABLES = {"A": 0x6485ef8, "B": 0x6486c60, "C": 0x649eea0}
LOG_SLOT0 = 0xa0
HANDLERS = {
    "AB": (0x4330700, 0x432fdf0, 0x432f9a0, 0x43309e0, 0x43301c0),
    "C": (0x4f02c40, 0x4f03d70, 0x4f03460, 0x4f038b0, 0x4f02f20),
}
RESIZE = 0x45244c0  # memory expansion body reached through GOT slot 0x64e6de0
LOG_GROW = 0x1437200  # Vec<Log> grow-by-doubling reached through GOT slot 0x64dfa48 (stubbed)
RESERVE = 0x5be8d40  # raw Vec<u8> reserve called by the resize body (stubbed)
SLOT_ALLOC, SLOT_MEMCPY, SLOT_MEMSET = 0x64df480, 0x64df508, 0x64df750
SLOT_PANIC, SLOT_PANIC_DIV, SLOT_PANIC_SHIFT, SLOT_ALLOC_ERROR = 0x64df520, 0x64df878, 0x64df870, 0x64df498
SLOT_RESIZE, SLOT_GROW = 0x64e6de0, 0x64dfa48
SLOT_VT_EVEN, SLOT_VT_ODD = 0x64df8c0, 0x64df8c8
EMPTY_VT = {"AB": 0x6485430, "C": 0x649f6b8}  # per-family static Bytes vtable for an empty data slice
# panic message addresses by family: end offset+len, base+offset, base+end, topic gas multiply
MSG = {
    "AB": {"end": 0x648f1e8, "base1": 0x64bfc68, "base2": 0x64bfc80, "topic": 0x6486a98},
    "C": {"end": 0x64af380, "base1": 0x64bfc68, "base2": 0x64bfc80, "topic": 0x649f740},
}
RESIZE_MSG = {"div": 0x648f230, "words": 0x648f1d0, "add": 0x64bfcf8}
LOG_SIZES = {"AB": (725, 972, 1094, 1212, 1337), "C": (725, 972, 1094, 1212, 1337)}

HOST, CELL, MEMBUF, STK, CTX, PARAMS = 0x1000_0000, 0x1100_0000, 0x2000_0000, 0x1200_0000, 0x1300_0000, 0x1400_0000
LOGV, ALLOC = 0x1500_0000, 0x1600_0000
MEMSZ, STKSLOTS, LOGSZ, ALLOCSZ = 1 << 16, 24, 0x50 * 64, 1 << 15
REC = 0x50

RET_STATIC, RET_UNDERFLOW, RET_BIG, RET_GAS, RET_MEMGAS = 0x28, 0x2c, 0x24, 0x20, 0x21


# ---------------------------------------------------------------- pure-Python reconstruction
def mem_cost(words, c50, c58):
    """Total memory gas for `words` 32-byte words: words*c50 + words*words/c58 (u64 saturating; c58 == 0 panics)."""
    lin = words * c50
    lin = lin if lin <= M64 else M64
    sq = words * words
    sq = sq if sq <= M64 else M64
    if c58 == 0:
        return None
    total = lin + sq // c58
    return total if total <= M64 else M64


def resize_model(s, words, mut=frozenset()):
    """Model of 0x45244c0 on the mutable state dict `s`; returns a status: 0, RET_MEMGAS or ('panic', msg)."""
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


def u256_limbs(w):
    return [(w >> (64 * i)) & M64 for i in range(4)]


def log_model(n, fam, s, mut=frozenset()):
    """Reconstruct LOG<n>: returns 0 (ok), a status byte, or ('panic', msg) / ('alloc', size).

    Mutates the state dict s exactly as the handler mutates the host, the cell and the context.
    `mut` names deliberately wrong variants used as negative controls (empty in the reconstruction)."""
    msg = MSG[fam]
    if s["static"] and "static_ignored" not in mut:
        return RET_STATIC
    if len(s["stack"]) < (2 if "underflow_off_by_one" not in mut else 1):
        return RET_UNDERFLOW
    offset = s["stack"].pop()
    length = s["stack"].pop() if s["stack"] else 0
    if length >> 64 and "len_high_ignored" not in mut:
        return RET_BIG
    c30, c38 = s["c30"], s["c38"]
    prod = length * c30
    prod = prod if prod <= M64 else (M64 if "prod_wraps" not in mut else prod & M64)
    if n >= 2 and "no_topic_panic" not in mut:
        if n * c38 > M64:
            return ("panic", msg["topic"])
    cost = prod + (n if "topics_free" not in mut else 0) * c38
    cost = cost if cost <= M64 else M64
    if s["gas"] < cost + (1 if "gas_le" in mut else 0):
        return RET_GAS
    s["gas"] -= cost
    if "gas_double_topic" in mut:
        s["gas"] -= n
    if length == 0 and "empty_not_special" not in mut:
        data_ptr, data_len, field, vt = 1, 0, 0, EMPTY_VT[fam]
        if "offset_check_when_empty" in mut and offset >> 64:
            return RET_BIG
    else:
        if offset >> 64 and "offset_high_ignored" not in mut:
            return RET_BIG
        end = offset + length
        end_sat = end if end <= M64 else M64
        words = (end_sat >> 5) + (1 if end_sat & 31 and "words_floor" not in mut else 0)
        if words > s["mem_words"]:
            r = resize_model(s, words, mut)
            if r != 0:
                return r
        if end > M64:
            return ("panic", msg["end"])
        s["flag"] += 1
        if offset + s["base"] > M64:
            return ("panic", msg["base1"])
        if end + s["base"] > M64:
            return ("panic", msg["base2"])
        ptr = alloc_model(s, length)
        if ptr == 0:
            return ("alloc", length)
        src = offset + (s["base"] if "base_ignored" not in mut else 0)
        s["alloc_mem"][ptr - ALLOC:ptr - ALLOC + length] = s["membuf"][src:src + length]
        s["flag"] -= 1 if "flag_not_restored" not in mut else 0
        data_ptr, data_len, field = ptr, length, ptr | (1 if "field_not_tagged" not in mut else 0)
        odd = (ptr & 1) if "vt_swapped" not in mut else 1 - (ptr & 1)
        vt = s["vt_odd"] if odd else s["vt_even"]
    if len(s["stack"]) < n:
        if "drop_missing" not in mut:
            s["events"].append((s["drop_name"][vt], data_ptr, data_len))
        return RET_UNDERFLOW
    topics = [s["stack"].pop() for _ in range(n)]
    if "topics_reversed" in mut:
        topics = topics[::-1]
    if n:
        tptr = alloc_model(s, 32 * n)
        if tptr == 0:
            return ("alloc", 32 * n)
        for i, t in enumerate(topics):
            raw = t.to_bytes(32, "big" if "topics_little" not in mut else "little")
            s["alloc_mem"][tptr - ALLOC + 32 * i:tptr - ALLOC + 32 * i + 32] = raw
        tcap, tlen = n, n
    else:
        tptr, tcap, tlen = 1, 0, 0
    if "tcap_one" in mut and n:
        tcap = 1
    if s["log_len"] == s["log_cap"] and "no_grow" not in mut:
        s["events"].append(("grow", s["log_cap"]))
        s["log_cap"] = max(2 * s["log_cap"], 4 if "grow_min_eight" not in mut else 8)
    s["records"].append((tcap, tptr, tlen, vt, data_ptr, data_len, field,
                         bytes(s["addr"]) if "addr_zero" not in mut else bytes(20)))
    s["log_len"] += 1 if "log_len_stuck" not in mut else 0
    return 0


def alloc_model(s, size):
    s["alloc_count"] += 1
    s["events"].append(("alloc", size))
    if s["alloc_fail"] and s["alloc_count"] == s["alloc_fail"]:
        return 0
    odd = s["odd"]
    ptr = ALLOC + s["bump"] + odd
    s["bump"] += (size + odd + 15) & ~15
    return ptr


# ---------------------------------------------------------------- machine harness
class Shell:
    """Builds the host, cell, context and heap regions for one case and collects stub events."""

    def __init__(self, image, mach):
        self.image, self.m = image, mach
        w = image.word
        self.vt_even, self.vt_odd = w(SLOT_VT_EVEN), w(SLOT_VT_ODD)
        self.fn = {k: w(v) for k, v in (("alloc", SLOT_ALLOC), ("panic", SLOT_PANIC), ("panic_div", SLOT_PANIC_DIV),
                                       ("panic_shift", SLOT_PANIC_SHIFT), ("alloc_error", SLOT_ALLOC_ERROR),
                                       ("resize", SLOT_RESIZE), ("grow", SLOT_GROW), ("memcpy", SLOT_MEMCPY),
                                       ("memset", SLOT_MEMSET))}
        self.drop_fns = {w(EMPTY_VT["AB"] + 0x20): "drop_static", w(EMPTY_VT["C"] + 0x20): "drop_static_c",
                         w(self.vt_even + 0x20): "drop_even", w(self.vt_odd + 0x20): "drop_odd"}


def install(sh, c, tamper=frozenset()):
    """Fill the machine with the state of case `c` and register stubs.  Returns the machine."""
    m = sh.m
    m.reset()
    m.stubs.clear()
    m.cache_hits = 0
    host = m.add_region(HOST, 0x400)
    cell = m.add_region(CELL, 0x40)
    membuf = m.add_region(MEMBUF, MEMSZ + 64, bytes(c["membuf"]) + b"\xaa" * (MEMSZ + 64 - len(c["membuf"])))
    stk = m.add_region(STK, 32 * STKSLOTS)
    ctx = m.add_region(CTX, 0x300)
    par = m.add_region(PARAMS, 0x100)
    logv = m.add_region(LOGV, LOGSZ * 4)
    heap = m.add_region(ALLOC, ALLOCSZ)
    put(host, 0x10, 8, CELL)
    put(host, 0x18, 8, c["base"])
    put(host, 0x28, 8, STK)
    put(host, 0x30, 8, len(c["stack"]))
    host[0x78:0x78 + 20] = bytes(c["addr"])
    put(host, 0x170, 8, c["mem_words"])
    put(host, 0x178, 8, c["mem_cost"])
    put(host, 0x188, 8, c["gas"])
    host[0x1a8] = c["static"]
    put(cell, 0x10, 8, c["flag"])
    put(cell, 0x18, 8, c["cell_cap"])
    put(cell, 0x20, 8, MEMBUF)
    put(cell, 0x28, 8, c["cell_len"])
    for i, w in enumerate(c["stack"]):
        for j, limb in enumerate(u256_limbs(w)):
            put(stk, 32 * i + 8 * j, 8, limb)
    put(ctx, 0x250, 8, PARAMS)
    put(ctx, 0x270, 8, c["log_cap"])
    put(ctx, 0x278, 8, LOGV)
    put(ctx, 0x280, 8, c["log_len"])
    for off, key in ((0x30, "c30"), (0x38, "c38"), (0x50, "c50"), (0x58, "c58")):
        put(par, off, 8, c[key])
    for i in range(c["log_len"]):  # existing records are opaque markers the handlers must leave alone
        logv[REC * i:REC * i + REC] = bytes([0x5a ^ i]) * REC
    state = {"bump": 0, "count": 0, "events": [], "grows": 0, "log_ptr": LOGV}

    def alloc(mm):
        size = mm.regs[7]
        state["count"] += 1
        state["events"].append(("alloc", size))
        if c["alloc_fail"] and state["count"] == c["alloc_fail"]:
            mm.regs[0] = 0
            return
        ptr = ALLOC + state["bump"] + c["odd"]
        state["bump"] += (size + c["odd"] + 15) & ~15
        mm.regs[0] = ptr

    def memcpy(mm):
        dst, src, n = mm.regs[7], mm.regs[6], mm.regs[2]
        data = bytes(mm.load(src + i, 1) for i in range(0)) if False else read_bytes(mm, src, n)
        write_bytes(mm, dst, data)
        mm.regs[0] = dst

    def memset(mm):
        dst, val, n = mm.regs[7], mm.regs[6] & 0xff, mm.regs[2]
        write_bytes(mm, dst, bytes([val]) * n)
        mm.regs[0] = dst

    def grow(mm):  # Vec<Log>::grow_one: doubling with a minimum of 4, copying the old records
        v = mm.regs[7]
        cap = mm.load(v, 8)
        ptr = mm.load(v + 8, 8)
        new_cap = max(2 * cap, 4)
        state["grows"] += 1
        state["events"].append(("grow", cap))
        mm.store(v, 8, new_cap)
        mm.store(v + 8, 8, ptr)

    def reserve(mm):  # raw Vec<u8>::reserve: capacity becomes at least len + additional, buffer stays in place
        v, ln, add = mm.regs[7], mm.regs[6], mm.regs[2]
        cap = mm.load(v, 8)
        state["events"].append(("reserve", ln, add))
        mm.store(v, 8, max(2 * cap, ln + add))

    def drop(name):
        def fn(mm):
            state["events"].append((name, mm.regs[6], mm.regs[2]))
        return fn

    def boundary(kind):
        return kind

    m.stubs[sh.fn["alloc"]] = alloc
    m.stubs[sh.fn["memcpy"]] = memcpy
    m.stubs[sh.fn["memset"]] = memset
    m.stubs[sh.fn["grow"]] = grow
    m.stubs[RESERVE] = reserve
    for fn_addr, name in sh.drop_fns.items():
        m.stubs[fn_addr] = drop(name)
    for key in ("panic", "panic_div", "panic_shift", "alloc_error"):
        m.stubs[sh.fn[key]] = key
    return m, state


def read_bytes(mm, at, n):
    for lo, hi, buf in mm.regions:
        if lo <= at and at + n <= hi:
            return bytes(buf[at - lo:at - lo + n])
    fail(f"read outside regions at {at:#x}")


def write_bytes(mm, at, data):
    for lo, hi, buf in mm.regions:
        if lo <= at and at + len(data) <= hi:
            buf[at - lo:at - lo + len(data)] = data
            mm.writes.add((at, len(data)))
            return
    fail(f"write outside regions at {at:#x}")


def region(mm, base):
    for lo, hi, buf in mm.regions:
        if lo == base:
            return buf
    fail("missing region")


def run_handler(sh, c, addr, tamper=frozenset(), override=None):
    """Execute the real handler at `addr` on case c; returns the observation dict."""
    m, state = install(sh, c)
    m.override = override or {}
    m.regs[7], m.regs[6] = HOST, CTX
    try:
        m.run(addr)
        status = m.regs[0] & 0xff
    except Boundary as b:
        kind = b.kind
        regs = b.regs
        if kind in ("panic", "panic_div", "panic_shift"):
            status = ("panic", regs[7])
        elif kind == "alloc_error":
            status = ("alloc", regs[6])
        else:
            fail(f"unexpected boundary {kind}")
    return observe(m, state, status)


def run_resize(sh, c, words):
    m, state = install(sh, c)
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = HOST + 0x170, HOST, CTX + 0x250, words
    try:
        m.run(RESIZE)
        status = m.regs[0] & 0xff
    except Boundary as b:
        kind = b.kind
        status = ("panic", b.regs[7]) if kind in ("panic", "panic_div", "panic_shift") else fail(kind)
    return observe(m, state, status)


def observe(m, state, status):
    host, cell, par = region(m, HOST), region(m, CELL), region(m, CTX)
    obs = {"status": status, "stack_len": u(host, 0x30, 8), "gas": u(host, 0x188, 8), "words": u(host, 0x170, 8),
           "cost": u(host, 0x178, 8), "cell_len": u(cell, 0x28, 8), "flag": u(cell, 0x10, 8),
           "log_len": u(par, 0x280, 8), "log_cap": u(par, 0x270, 8), "events": tuple(state["events"])}
    mem = region(m, MEMBUF)
    obs["membuf"] = hashlib.sha256(bytes(mem)).hexdigest()
    obs["records"] = []
    logv, heap = region(m, LOGV), region(m, ALLOC)
    for i in range(obs["log_len"]):
        obs["records"].append(bytes(logv[REC * i:REC * i + REC]))
    obs["heap"] = hashlib.sha256(bytes(heap[:state["bump"]])).hexdigest()
    obs["bump"] = state["bump"]
    return obs


# ---------------------------------------------------------------- model-side observation
def fresh_state(c, sh):
    s = dict(c)
    s["stack"] = list(c["stack"])
    s["odd"] = c["odd"]
    mem = bytearray(MEMSZ + 64)
    mem[:] = bytes(c["membuf"]) + b"\xaa" * (MEMSZ + 64 - len(c["membuf"]))
    s["membuf"] = mem
    s["alloc_mem"] = bytearray(ALLOCSZ)
    s["bump"], s["alloc_count"], s["events"], s["records"] = 0, 0, [], []
    s["vt_even"], s["vt_odd"] = sh.vt_even, sh.vt_odd
    s["drop_name"] = {EMPTY_VT["AB"]: "drop_static", EMPTY_VT["C"]: "drop_static_c", sh.vt_even: "drop_even",
                      sh.vt_odd: "drop_odd"}
    return s


def pack_record(r):
    tcap, tptr, tlen, vt, dptr, dlen, field, addr = r
    return struct.pack("<7Q", tcap, tptr, tlen, vt, dptr, dlen, field) + addr


def model_obs(s, status):
    obs = {"status": status, "stack_len": len(s["stack"]), "gas": s["gas"], "words": s["mem_words"],
           "cost": s["mem_cost"], "cell_len": s["cell_len"], "flag": s["flag"] & M64, "log_len": s["log_len"],
           "log_cap": s["log_cap"], "events": tuple(s["events"])}
    obs["membuf"] = hashlib.sha256(bytes(s["membuf"])).hexdigest()
    old = s["log_len"] - len(s["records"])
    obs["records"] = [bytes([0x5a ^ i]) * REC for i in range(old)] + [pack_record(r) + b"\0\0\0\0" for r in s["records"]]
    obs["heap"] = hashlib.sha256(bytes(s["alloc_mem"][:s["bump"]])).hexdigest()
    obs["bump"] = s["bump"]
    return obs


def model_handler(c, sh, mut=frozenset()):
    s = fresh_state(c, sh)
    try:
        status = log_model(c["n"], c["fam"], s, mut)
    except IndexError:  # only a deliberately wrong variant can run off the harness buffers
        return {"status": "model-fault", "records": [], "stack_len": -1}
    return model_obs(s, status)


def model_resize(c, sh, words, mut=frozenset()):
    s = fresh_state(c, sh)
    try:
        status = resize_model(s, words, mut)
    except IndexError:
        return {"status": "model-fault", "records": [], "stack_len": -1}
    return model_obs(s, status)


def trim(obs):
    o = dict(obs)
    o["records"] = [r[:0x4c] for r in obs["records"]]
    return o


def diff(a, b):
    a, b = trim(a), trim(b)
    return [k for k in a if a[k] != b[k]]


# ---------------------------------------------------------------- cases
WORD_BOUNDS = (0, 1, 31, 32, 33, 63, 64, 65, 1023, 1024)
MODES = 32


def rand_word(st):
    return int.from_bytes(st.take(32), "little")


def small_len(st):
    kind = st.below(10)
    if kind < 3:
        return 0
    if kind < 6:
        return st.below(100) + 1
    if kind < 8:
        return st.pick(WORD_BOUNDS) + st.below(3)
    return st.below(6000) + 1


def make_case(k, sh):
    """Case k: a deterministic LOG<n> scenario; the same k always yields the same case.

    Each case fixes the host (stack, gas, memory words/cost, base offset, static flag, address), the
    gas schedule (the four parameters the handlers read), the memory cell and the log vector."""
    st = Stream(f"evm-log-{k}")
    n = k % 5
    fam = "C" if (k // 5) % 2 else "AB"
    mode = st.below(MODES)
    c = {"k": k, "n": n, "fam": fam, "mode": mode, "odd": 0}
    c["base"] = st.pick((0, 0, 0, 32, 96, 480, st.below(512)))
    c["mem_words"] = st.pick((0, 0, 1, 2, 7, st.below(60), st.below(300)))
    c["cell_len"] = c["base"] + 32 * c["mem_words"]
    c["cell_cap"] = st.pick((MEMSZ, MEMSZ, c["cell_len"], c["cell_len"] + 16, st.below(4096) + c["cell_len"]))
    c["flag"] = st.below(4)
    c["static"] = 1 if st.below(25) == 0 else 0
    c["addr"] = st.take(20)
    c["c30"] = st.pick((8, 8, 8, 8, 0, 1, 3, st.below(100)))
    c["c38"] = st.pick((375, 375, 375, 0, 1, 50, st.below(5000)))
    c["c50"] = st.pick((3, 3, 3, 0, 1, st.below(10)))
    c["c58"] = st.pick((512, 512, 512, 1, 7, st.below(2000) + 1))
    c["log_cap"] = st.pick((0, 1, 4, 4, 8))
    c["log_len"] = st.pick((0, c["log_cap"], c["log_cap"], min(c["log_cap"], 3)))
    c["alloc_fail"] = st.pick((0, 1, 2)) if 22 <= mode <= 25 else 0
    offset, length = st.below(2000), small_len(st)
    if mode == 0:
        c["c38"] = st.pick((1 << 62, (1 << 62) + 5, 1 << 61, (1 << 64) - 1, (1 << 63) // max(n, 1) + 1))
    elif mode == 1:
        c["c30"] = st.pick((1 << 63, (1 << 64) - 1, 1 << 40))
    elif mode == 2:
        c["c58"] = 0
    elif mode == 3:
        c["c50"] = st.pick((1 << 63, (1 << 64) - 1))
    elif mode == 4:
        length = 0
        offset = st.pick((1 << 64, (1 << 64) - 1, 1 << 200, rand_word(st)))
    elif mode == 5:
        length = st.pick((1 << 64, 1 << 70, rand_word(st) | (1 << 64)))
    elif mode == 6:
        offset = st.pick((1 << 64, 1 << 130, rand_word(st) | (1 << 255)))
        length = st.below(40) + 1
    elif mode == 7:
        offset, length = (1 << 64) - 1 - st.below(40), st.below(80) + 1
    elif mode == 8:
        offset, length = st.below(1 << 63), st.below(1 << 63)
    elif mode == 9:
        offset, length = (1 << 64) - 1, 1
    elif mode == 10:
        offset, length = st.below(40000), st.below(20000) + 1
    elif mode == 16:  # memory already at the u64 word limit: no resize, so the end-overflow panic is reachable
        c["mem_words"], c["cell_len"] = 1 << 59, 0
        offset, length = (1 << 64) - 1 - st.below(50), st.below(200) + 60
    elif mode == 17:  # base so large that the resize add (or the copy base add) overflows
        b0 = st.below(30) if st.below(2) else st.below(2000)
        c["base"] = (1 << 64) - 1 - b0
        c["cell_len"] = 0
        if b0 < 30:
            c["mem_words"] = 0
            offset, length = st.below(100), st.below(100) + 1
        elif st.below(2):
            c["mem_words"] = 1 << 59
            offset, length = b0 + 1 + st.below(50), st.below(100) + 1
        else:  # offset + base still fits but end + base overflows: the second base panic
            c["mem_words"] = 1 << 59
            offset, length = st.below(100), st.below(100) + 60
            c["base"] = (1 << 64) - 1 - offset - 1 - st.below(50)
    elif mode == 18:  # word count 2^59 with a cheap square term: resize must panic on the word limit
        c["c50"], c["c58"] = 0, st.pick((1 << 40, 1 << 50, (1 << 64) - 1))
        offset, length = (1 << 64) - 1 - st.below(30), st.below(25) + 1
    elif mode == 19:
        c["odd"] = 1
    elif mode == 20:  # cell already longer than the new memory: the resize shrink branch
        c["cell_len"] = c["base"] + st.below(MEMSZ - 600)
        c["cell_cap"] = MEMSZ
    elif mode == 21:  # the cell is exactly full: growth needs the raw-vector reserve
        need = (offset + length + 31) >> 5
        c["cell_len"] = c["base"] + 32 * need - st.pick((1, 1, 2, 33))
        c["cell_cap"] = c["cell_len"]
        c["mem_words"] = st.below(max(need, 1))
    c["offset"], c["length"] = offset, length
    c["mem_cost"] = mem_cost(c["mem_words"], c["c50"], c["c58"]) or 0
    topics = [rand_word(st) for _ in range(n)]
    extra = st.pick((0, 0, 0, 1, 3))
    if mode == 11:
        topics = topics[:st.below(n)] if n else []
    c["stack"] = [rand_word(st) for _ in range(extra)] + topics[::-1] + [length, offset]
    if mode == 12:
        c["stack"] = c["stack"][-1:]
    fill = min(c["cell_len"], MEMSZ)
    c["membuf"] = bytes(st.take(min(fill, 1024))) + bytes((i * 7 + 3) & 0xff for i in range(max(0, fill - 1024)))
    c["gas"] = (1 << 64) - 1 if mode == 13 else 1 << 60
    if mode in (14, 15, 26, 27):
        c = edge_gas(c, sh, st)
    return bound_case(c)


def edge_gas(c, sh, st):
    """Set gas to an exact edge of the charges the model computes for this case (-1, 0, +1 around the sum
    of the log charge and of the memory charge)."""
    s = fresh_state(c, sh)
    top = s["gas"]
    log_model(c["n"], c["fam"], s)
    used = top - s["gas"]
    c["gas"] = max(0, min(M64, used + st.pick((-1, 0, 1, -2))))
    if c["mode"] in (26, 27) and c["length"] < 1 << 64:
        log = min(M64, c["length"] * c["c30"] + c["n"] * c["c38"])
        c["gas"] = max(0, min(M64, log + st.pick((-1, 0, 1))))
    return c


def bound_case(c):
    """Keep every successful expansion inside the 64 KiB harness buffer: when the memory the case asks
    for would not fit (and would not panic first), withhold one unit of gas so the real handler stops
    at the charge."""
    length, offset = c["length"], c["offset"]
    if length == 0 or length >> 64 or offset >> 64 or c["static"] or len(c["stack"]) < 2:
        return c
    end = min(offset + length, M64)
    words = (end >> 5) + (1 if end & 31 else 0)
    if words <= c["mem_words"] or words >> 59:
        return c
    newlen = words * 32 + c["base"]
    if newlen > M64 or newlen <= MEMSZ - 64:
        return c
    cost = mem_cost(words, c["c50"], c["c58"])
    if cost is None:
        return c
    need = min(M64, length * c["c30"] + c["n"] * c["c38"]) + ((cost - c["mem_cost"]) & M64)
    if c["gas"] >= need:
        c["gas"] = max(0, need - 1)
    return c


def make_resize_case(k, sh):
    """Direct case for the memory expansion body 0x45244c0: a log-shaped state plus a requested word count."""
    st = Stream(f"evm-resize-{k}")
    c = make_case(k, sh)
    kind = st.below(10)
    mw = c["mem_words"]
    words = {0: mw + 1, 1: mw, 2: max(0, mw - 1), 3: st.below(1500), 4: 1 << 59, 5: (1 << 59) - 1,
             6: st.below(1 << 62), 7: st.below(1800), 8: mw + 1, 9: mw + 1}[kind]
    c["words"] = words
    c["stack"] = []
    if kind >= 8 and c["base"] + 32 * words < MEMSZ - 64:  # the cell is one (or two) bytes short: growth takes the reserve path with a tiny tail
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


# ---------------------------------------------------------------- static evidence
STATUS_NAMES = {0: "ok", RET_STATIC: "static-call", RET_UNDERFLOW: "stack-underflow", RET_BIG: "value-too-big",
                RET_GAS: "out-of-gas", RET_MEMGAS: "memory-out-of-gas"}
N_LOG, N_RESIZE, CTL_LOG, CTL_RESIZE, STRIDE = 10000, 2000, 2500, 1200, 4
ALL_FUNCS = tuple(a for fam in ("AB", "C") for a in HANDLERS[fam]) + (RESIZE,)


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
            for i, h in enumerate(HANDLERS[fam]):
                if w(TABLES[t] + 8 * (LOG_SLOT0 + i)) != h:
                    fail(f"table {t} slot {LOG_SLOT0 + i:#x} does not hold {h:#x}")
        for i, h in enumerate(HANDLERS[fam]):
            if h not in ext or ext[h] - h != LOG_SIZES[fam][i]:
                fail(f"extent of {h:#x} differs from the recorded size")
    if RESIZE not in ext or ext[RESIZE] - RESIZE != 414:
        fail("resize extent differs")
    for slot, target in ((SLOT_RESIZE, RESIZE), (SLOT_GROW, LOG_GROW)):
        if w(slot) != target:
            fail(f"slot {slot:#x} does not point at {target:#x}")
    for fam in ("AB", "C"):
        for i, h in enumerate(HANDLERS[fam]):
            leas = {t for _, t, _ in rip_leas(image, h, ext[h])}
            slots = {s for _, s, _ in call_slots(image, h, ext[h])}
            need = {MSG[fam]["end"], MSG[fam]["base1"], MSG[fam]["base2"], EMPTY_VT[fam]}
            if i >= 2:
                need.add(MSG[fam]["topic"])
            if not need <= leas:
                fail(f"handler {h:#x} lacks lea targets {sorted(need - leas)}")
            if not {SLOT_ALLOC, SLOT_MEMCPY, SLOT_PANIC, SLOT_ALLOC_ERROR, SLOT_RESIZE, SLOT_GROW} <= slots:
                fail(f"handler {h:#x} lacks expected call slots")
    leas = {t for _, t, _ in rip_leas(image, RESIZE, ext[RESIZE])}
    if not set(RESIZE_MSG.values()) <= leas:
        fail("resize panic messages not found")


def table_rows(image):
    rows = ["table\topcode\thandler\tlog_slot"]
    for t in ("A", "B", "C"):
        for op in range(256):
            h = image.word(TABLES[t] + 8 * op)
            rows.append(f"{t}\t{op:#04x}\t{h:#x}\t{'LOG%d' % (op - LOG_SLOT0) if LOG_SLOT0 <= op <= LOG_SLOT0 + 4 else '-'}")
    return rows


def got_rows(image):
    rows = ["slot\treloc\ttarget\tused_as"]
    names = {SLOT_ALLOC: "allocator", SLOT_MEMCPY: "memcpy", SLOT_MEMSET: "memset", SLOT_PANIC: "panic",
             SLOT_PANIC_DIV: "panic-divide", SLOT_PANIC_SHIFT: "panic-shift", SLOT_ALLOC_ERROR: "alloc-error",
             SLOT_RESIZE: "memory-resize", SLOT_GROW: "log-vector-grow", SLOT_VT_EVEN: "bytes-vtable-even",
             SLOT_VT_ODD: "bytes-vtable-odd"}
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
    o = trim(obs)
    o["records"] = [r.hex() for r in o["records"]]
    return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()


def tag(x):
    return x if isinstance(x, str) else (STATUS_NAMES.get(x, f"{x:#x}") if isinstance(x, int) else f"{x[0]}@{x[1]:#x}")


def evaluate(image, ext, tm, sh, log_rows, resize_rows):
    """Run every case on the machine code and on the model; returns counters and per-case digests."""
    bad, real_log, real_resize = 0, [], []
    classes = {}
    for k in range(N_LOG):
        c = make_case(k, sh)
        addr = HANDLERS[c["fam"]][c["n"]]
        got = run_handler(sh, c, addr)
        want = model_handler(c, sh)
        ok = not diff(got, want)
        bad += 0 if ok else 1
        key = f"LOG{c['n']}:{tag(got['status']).split('@')[0]}"
        classes[key] = classes.get(key, 0) + 1
        if k < CTL_LOG:
            real_log.append(digest(got))
        if k % STRIDE == 0:
            log_rows.append("\t".join(str(x) for x in (
                k, f"{addr:#x}", c["fam"], c["n"], c["mode"], len(c["stack"]), c["gas"], got["gas"], tag(got["status"]),
                got["stack_len"], got["words"], got["cost"], got["cell_len"], got["log_len"],
                ",".join(e[0] for e in got["events"]) or "-", digest(got)[:12], "yes" if ok else "NO")))
    for k in range(N_RESIZE):
        c = make_resize_case(k, sh)
        got = run_resize(sh, c, c["words"])
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
    return bad, real_log, real_resize, classes


MODEL_MUTANTS = (
    ("log", "static_ignored", "the static-call refusal (0x28) is skipped"),
    ("log", "underflow_off_by_one", "a single stack word is accepted"),
    ("log", "len_high_ignored", "length limbs above the first are ignored"),
    ("log", "prod_wraps", "the length charge wraps modulo 2^64 instead of saturating"),
    ("log", "no_topic_panic", "the topic charge overflow panic is dropped"),
    ("log", "topics_free", "topics cost nothing"),
    ("both", "gas_le", "charges fail when gas equals the cost"),
    ("log", "gas_double_topic", "an extra gas unit per topic is taken"),
    ("log", "empty_not_special", "an empty data slice takes the copy path"),
    ("log", "offset_check_when_empty", "the offset width check also applies to an empty slice"),
    ("log", "offset_high_ignored", "offset limbs above the first are ignored"),
    ("log", "words_floor", "the word count rounds down"),
    ("log", "base_ignored", "the frame base offset is not added to the source"),
    ("log", "flag_not_restored", "the borrow counter is not decremented after the copy"),
    ("log", "field_not_tagged", "the Bytes data word is not tagged with bit 0"),
    ("log", "vt_swapped", "the even/odd Bytes vtables are swapped"),
    ("log", "drop_missing", "the data slice is not released when topics are missing"),
    ("log", "topics_reversed", "topics are stored in reverse order"),
    ("log", "topics_little", "topics are stored little-endian"),
    ("log", "tcap_one", "the topic vector capacity is always 1"),
    ("log", "no_grow", "the log vector is never grown"),
    ("log", "grow_min_eight", "the log vector grows to a minimum of eight"),
    ("log", "addr_zero", "the emitting address is not recorded"),
    ("log", "log_len_stuck", "the log count is not incremented"),
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
    immediate and the first 0x20/0x21 status-byte immediate (chosen by instruction kind, not by outcome)."""
    sites = []
    for f in ALL_FUNCS:
        rows = sweep(image, f, ext[f])
        jcc = next((va for va, fm in rows if 0x0f80 <= fm["op"] <= 0x0f8f), None)
        imm = [(va, fm) for va, fm in rows if 0xb0 <= fm["op"] <= 0xb7 and fm["imm"] in (0x2c, 0x24, 0x28, 0x20, 0x21)]
        sites.append((f, "invert-first-jcc", jcc + 1, image.code(jcc + 1, 1)[0] ^ 1))
        if imm:
            va, fm = imm[0]
            sites.append((f, f"status-imm-{fm['imm']:#x}", va + 1, fm["imm"] ^ 0x08))
        if f != RESIZE:
            va, fm = imm[-1]
            sites.append((f, f"last-status-imm-{fm['imm']:#x}", va + 1, fm["imm"] ^ 0x04))
    return sites


def controls(image, ext, sh, real_log, real_resize):
    rows, detected, equivalent = [], 0, []
    log_cases = [make_case(k, sh) for k in range(CTL_LOG)]
    rz_cases = [make_resize_case(k, sh) for k in range(CTL_RESIZE)]
    for scope, name, text in MODEL_MUTANTS:
        mut, hit = frozenset((name,)), None
        if scope in ("log", "both"):
            for k, c in enumerate(log_cases):
                if digest(model_handler(c, sh, mut)) != real_log[k]:
                    hit = f"log:{k}"
                    break
        if hit is None and scope in ("both",):
            for k, c in enumerate(rz_cases):
                if digest(model_resize(c, sh, c["words"], mut)) != real_resize[k]:
                    hit = f"resize:{k}"
                    break
        if hit:
            detected += 1
        rows.append(("model-mutant", name, text, hit or "UNDETECTED"))
    for f, what, at, newbyte in code_sites(image, ext):
        mach = Machine(image)
        shm = Shell(image, mach)
        hit = None
        if f == RESIZE:
            for k, c in enumerate(rz_cases):
                mach.override = {at: newbyte}
                mach.cache = {}
                try:
                    got = run_resize(shm, c, c["words"])
                    if digest(got) != real_resize[k]:
                        hit = f"resize:{k}"
                        break
                except ToolError:
                    hit = f"resize:{k}:fault"
                    break
        else:
            for k, c in enumerate(log_cases):
                if HANDLERS[c["fam"]][c["n"]] != f:
                    continue
                mach.override = {at: newbyte}
                mach.cache = {}
                try:
                    got = run_handler(shm, c, f, override={at: newbyte})
                    if digest(got) != real_log[k]:
                        hit = f"log:{k}"
                        break
                except ToolError:
                    hit = f"log:{k}:fault"
                    break
        if hit:
            detected += 1
        rows.append(("code-byte", f"{f:#x}:{what}@{at:#x}", f"byte -> {newbyte:#04x}", hit or "UNDETECTED"))
    # input corruption: a changed binary digest, a non-function start and a misaligned start must all be refused
    refused = 0
    for kind, thunk in (("binary-digest", lambda: Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))),
                        ("not-a-function-start", lambda: fde_rows(image, {HANDLERS["AB"][0] + 1})),
                        ("misaligned-handler", lambda: run_handler(Shell(image, Machine(image)), make_case(1, sh), HANDLERS["AB"][1] + 3))):
        try:
            thunk()
            res = "UNDETECTED"
        except (ToolError, IndexError, KeyError):
            res = "refused"
            detected += 1
        rows.append(("input-corruption", kind, "corrupted input", res))
    return rows, detected, equivalent


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    ext = extents(image)
    static_checks(image, ext)
    tm = TraceMachine(image)
    sh = Shell(image, tm)
    log_rows = ["case\tfunction\tfamily\tlogN\tmode\tstack_in\tgas_in\tgas_out\tresult\tstack_out\twords\tmem_cost\tcell_len\t"
                "log_len\tstub_events\tobservation\tmatch"]
    resize_rows = ["case\tfunction\twords\twords_before\tbase\tgas_in\tgas_out\tresult\twords_after\tmem_cost\tcell_len\t"
                   "flag\tstub_events\tobservation\tmatch"]
    bad, real_log, real_resize, classes = evaluate(image, ext, tm, sh, log_rows, resize_rows)
    (out / "cases.tsv").write_text("\n".join(log_rows) + "\n")
    (out / "resize-cases.tsv").write_text("\n".join(resize_rows) + "\n")
    (out / "opcode-tables.tsv").write_text("\n".join(table_rows(image)) + "\n")
    (out / "got-slots.tsv").write_text("\n".join(got_rows(image)) + "\n")
    (out / "sites.tsv").write_text("\n".join(site_rows(image, ext)) + "\n")
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for f in ALL_FUNCS:
        hit = total = 0
        for va, fm in sweep(image, f, ext[f]):
            run = va in tm.seen
            hit += run
            total += 1
            lines.append(f"{f:#x}\t{va:#x}\t{fm['len']}\t{fm['bytes'].hex()}\t{fm['op']:#x}\t{int(run)}")
        covered[f"{f:#x}"] = [hit, total]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    rows, detected, equivalent = controls(image, ext, sh, real_log, real_resize)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdescription\tfirst_detecting_case\n" + "".join("\t".join(r) + "\n" for r in rows))
    undetected = [r for r in rows if r[3] == "UNDETECTED"]
    (out / "equivalent-mutants.tsv").write_text("mutant\taddress\treason\n")
    (out / "outcome-classes.tsv").write_text("class\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    summary = {"binary_sha256": SHA256, "cases": N_LOG + N_RESIZE, "mismatches": bad,
               "covered_instructions": covered, "outcome_classes": classes,
               "negative_controls": {"total": len(rows), "detected": detected, "undetected": len(undetected)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    measure = {"cases": N_LOG + N_RESIZE, "negative_controls": len(rows), "negative_detected": detected, "equivalent": 0,
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
