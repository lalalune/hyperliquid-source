#!/usr/bin/env python3
"""Reconstruct and validate the node #115 materializer 0x3c2e860 that widens a 0x27a8-byte value to 0x42c8 bytes.

0x3c2e860(out = rdi, in = rsi, a = rdx, b = rcx) is a pure layout transform with one non-import callee: it hands
in +0x1108 (the 0xbb8-byte sub-value) together with a and b to the composer 0x434b9f0, which returns a 0x26d8-byte
value (the sub-value plus a 0x1b20-byte block), and lays the output out as
  out[0x0000:0x1108] = in[0x0000:0x1108]          (unchanged prefix)
  out[0x1108:0x37e0] = composer result            (0xbb8 + 0x1b20 bytes)
  out[0x37e0:0x42c5] = in[0x1cc0:0x27a5]          (suffix shifted by exactly +0x1b20)
and returns out.  The tool reads every relocation, FDE extent and code byte from the ELF file and evaluates the real
machine code with a small concrete x86-64 evaluator (no external programs, the binary is never executed; memcpy and
the composer are stubs that scramble all caller-saved registers, and the composer stub also overwrites the input
range it consumes).  Every case is compared with the pure-Python reconstruction `model()`, including the exact
symbolic call trace; negative controls show that wrong reconstructions and corrupted code bytes are caught.
Role names (state value, hash block, materializer, composer) are inferences, not proven by any string.
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
                0x0f6e, 0x0f7e, 0x30, 0x32, 0x0f60, 0x0f76, 0x0faf, 0x0f6c, 0x0ffb, 0x0fa5, 0x0fad, 0x0fa3, 0x0fbd, 0x0feb, 0x0f50, 0x0f54, 0x0f56) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
    elif op in (0x0f70, 0x0fc6, 0x0fa4, 0x0fac, 0x0fba):
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
    elif op in (0x04, 0x0c, 0x1c, 0x3c, 0x24):
        form["imm"] = code[p]
        p += 1
    elif op == 0xc6:
        p = modrm(p)
        form["imm"] = code[p]
        p += 1
    elif op == 0xf6:
        p = modrm(p)
        if form["reg"] & 7 in (0, 1):
            form["imm"] = code[p]
            p += 1
        elif form["reg"] & 7 not in (2, 3):
            fail(f"unsupported f6 form at {va:#x}")
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
            kind = f["reg"] & 7
            a = self.get(f["rm"], 8, f, va)
            if kind in (0, 1):
                self.flags_logic(a & f["imm"], 8)
            elif kind == 2:
                self.put(f["rm"], 8, ~a, f, va)
            else:  # neg r/m8
                res = self.flags_sub(0, a, 8)
                self.cf = a != 0
                self.put(f["rm"], 8, res, f, va)
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
            elif kind == 6:  # div: rdx:rax / r/m (quotient overflow and zero raise #DE)
                mask = (1 << size) - 1
                num = (self.regs[2] & mask) << size | (self.regs[0] & mask)
                if a == 0 or num // a > mask:
                    fail(f"divide error at {va:#x}")
                self.set_reg(0, size, num // a, f)
                self.set_reg(2, size, num % a, f)
                self.zf = self.sf = self.cf = self.of = None
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
        elif op == 0x04:
            self.set_reg(0, 8, self.flags_add(self.regs[0] & 0xff, f["imm"], 8), f)
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
        elif op == 0x0f10 and f["f2"]:  # movsd load from memory: 8 bytes, upper bits cleared
            if f["rm"][0] == "r":
                fail(f"movsd register form at {va:#x}")
            self.xmm[f["reg"]] = self.load(self.ea(f["rm"], f, va), 8)
        elif op == 0x0f11 and (f["rep"] or f["f2"]):  # movss / movsd store: low 4 / 8 bytes
            if f["rm"][0] == "r":
                fail(f"movss/movsd register form at {va:#x}")
            n = 4 if f["rep"] else 8
            self.store(self.ea(f["rm"], f, va), n, self.xmm[f["reg"]] & ((1 << (8 * n)) - 1))
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
            if rm[0] == "r":
                self.xmm[f["reg"]] ^= self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                self.xmm[f["reg"]] ^= self.load(at, 16)
        elif op in (0x30, 0x32):  # xor r/m8, r8 / xor r8, r/m8
            a, b = self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f)
            res = self.flags_logic(a ^ b, 8)
            if op == 0x30:
                self.put(f["rm"], 8, res, f, va)
            else:
                self.set_reg(f["reg"], 8, res, f)
        elif op == 0x0fa3:  # bt r, r (register bit base only)
            if f["rm"][0] != "r":
                fail(f"unsupported 0fa3 memory form at {va:#x}")
            bit = self.reg(f["reg"], size, f) & (size - 1)
            self.cf = bool((self.get(f["rm"], size, f, va) >> bit) & 1)
        elif op == 0x0fba:  # bt r/m, imm8
            if f["reg"] & 7 != 4:
                fail(f"unsupported 0fba form at {va:#x}")
            self.cf = bool((self.get(f["rm"], size, f, va) >> (f["imm"] & (size - 1))) & 1)
        elif op == 0x0f7e:  # movq/movd r/m, xmm
            if not f["p66"]:
                fail(f"unsupported 0f7e form at {va:#x}")
            bits = 64 if f["rex"] & 8 else 32
            self.put(f["rm"], bits, self.xmm[f["reg"]] & ((1 << bits) - 1), f, va)
        elif op == 0x0f6e:  # movd / movq xmm, r/m (upper lanes cleared)
            if not f["p66"]:
                fail(f"unsupported 0f6e form at {va:#x}")
            self.xmm[f["reg"]] = self.get(f["rm"], 64 if f["rex"] & 8 else 32, f, va)
        elif op == 0x0faf:  # imul r, r/m: low half only; its flags are not modelled
            if f["p66"] or f["rep"]:
                fail(f"unsupported 0faf form at {va:#x}")
            self.set_reg(f["reg"], size, self.reg(f["reg"], size, f) * self.get(f["rm"], size, f, va), f)
            self.of = self.cf = None
        elif op == 0x0f6c:  # punpcklqdq
            if not f["p66"] or f["rm"][0] != "r":
                fail(f"unsupported 0f6c form at {va:#x}")
            self.xmm[f["reg"]] = (self.xmm[f["reg"]] & M64) | (self.xmm[f["rm"][1]] & M64) << 64
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
BODY = 0x3c2e860          # FDE start; the materializer reconstructed here (role names below are inferred)
CTOR_SLOT = 0x64e9630     # RELATIVE .got slot whose addend is BODY (the only reference found by the caller scan)
BOUNDARY = 0x3c13610      # function that calls through CTOR_SLOT (context only; reported by RE-017 packets)
COMPOSER = 0x434b9f0      # the only direct callee on the normal path (composer; reconstructed separately, stubbed)
COMPOSER_SITE = 0x3c2ec16
MEMCPY_SLOT = 0x64df508   # GLOB_DAT import memcpy; stubbed by its dynsym name
UNWIND_RESUME = 0x63f0a50

IN_SIZE = 0x27a8          # input value size (boundary passes it as esi = 0x27a8; 0x27a5..0x27a8 is never read)
OUT_SIZE = 0x42c8         # output value size (boundary allocates edi = 0x42c8; 0x42c5..0x42c8 is never written)
SUB_AT, SUB_SIZE = 0x1108, 0xbb8   # input sub-value handed to the composer
COMPOSED = 0x26d8         # composer result size = SUB_SIZE + BLOCK
BLOCK = 0x1b20            # growth of the value: OUT_SIZE - IN_SIZE
FRAME = 0x8 + 6 * 8 + 3 * 0x1000 + 0xc88   # return address + six pushes + three probed pages + 0xc88

# The reconstruction: output offset <- (source, source offset, length).  "composed" is the 0x26d8-byte value the
# composer writes at body-rsp +0x15b0.
LAYOUT = (
    (0x0000, "in", 0x0000, SUB_AT, "prefix kept in place"),
    (SUB_AT, "composed", 0x0000, COMPOSED, "composer result replaces the 0xbb8-byte sub-value"),
    (SUB_AT + COMPOSED, "in", SUB_AT + SUB_SIZE, 0x27a5 - (SUB_AT + SUB_SIZE), "suffix shifted by +0x1b20"),
)

IN_AT = 0x7d00_0100_0000
OUT_AT = 0x7d00_0200_0000
OUT_SLACK = 0x40
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
JUNK = 0x6b6b_6b6b_6b6b_6b6b
STACK_FILL = 0x5c
ENTRY_SP = STACK_TOP - 0x100      # rsp before the return address is pushed
S = -FRAME                        # body rsp relative to ENTRY_SP

# memcpy calls in program order: (destination, source, length).  The first six copy input pieces to the stack
# (they are read again only by the landing pad); the rest build the output.
STACK_COPIES = ((0x4c8, 0xba0, 0x1e8), (0x6b0, 0xd88, 0x360), (0x260, 0x2278, 0xb8), (0x318, 0x2330, 0xb8),
                (0x3d0, 0x1de8, 0xf8), (0xa10, 0x0000, 0xba0))
OUT_COPIES = ((0x3af0, 0x1fd0, 0x168), (0x3c58, 0x2138, 0x90), (0x0ba0, 0x0ba0, 0x1e8), (0x0d88, 0x0d88, 0x360),
              (0x3858, 0x1d38, 0xb0), (0x3d98, 0x2278, 0xb8), (0x3e50, 0x2330, 0xb8), (0x3908, 0x1de8, 0xf8),
              (0x0000, 0x0000, 0xba0))


# ---------------------------------------------------------------- reconstruction
def model(c, mut=frozenset()):
    """Pure reconstruction: output bytes, input bytes after the call, call trace (symbolic) and return value."""
    inb = c["in"]
    out = bytearray(c["out"])
    pre = SUB_AT - (0x8 if "prefix_short" in mut else 0)
    end = 0x27a5 - (1 if "suffix_short" in mut else 0)
    shift = 0x1b00 if "shift_1b00" in mut else BLOCK
    out[0:pre] = inb[0:pre]
    lo = SUB_AT + SUB_SIZE
    out[lo + shift:end + shift] = inb[lo:end]
    out[SUB_AT:SUB_AT + COMPOSED] = c["inner"] if "composer_ignored" in mut else c["composed"]
    if "tail_zeroed" in mut:
        out[0x42c5:0x42c8] = bytes(3)
    after_in = bytearray(inb)
    after_in[SUB_AT:SUB_AT + SUB_SIZE] = c["consumed"]
    calls = []
    if "no_stack_copies" not in mut:
        calls += [("memcpy", ("stack", S + d), ("in", s), n) for d, s, n in STACK_COPIES]
    a, b = (c["b"], c["a"]) if "args_swapped" in mut else (c["a"], c["b"])
    calls.append(("composer", ("stack", S + 0x15b0), ("in", SUB_AT + (8 if "composer_in_1110" in mut else 0)),
                  a, b))
    calls += [("memcpy", ("out", d), ("in", s), n) for d, s, n in OUT_COPIES]
    calls.append(("memcpy", ("out", SUB_AT), ("stack", S + 0x15b0), COMPOSED))
    return {"out": bytes(out), "in": bytes(after_in), "calls": calls, "ret": OUT_AT}


# ---------------------------------------------------------------- harness
class MaterializeMachine(Machine):
    def load_bytes(self, at, size):
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                return bytes(buf[at - lo:at - lo + size])
        fail(f"byte read outside regions at {at:#x}")

    def store_bytes(self, at, data):
        for lo, hi, buf in self.regions:
            if lo <= at and at + len(data) <= hi:
                buf[at - lo:at - lo + len(data)] = data
                self.writes.add((at, len(data)))
                return
        fail(f"byte write outside regions at {at:#x}")


class TraceMachine(MaterializeMachine):
    def __init__(self, image, code_override=None):
        self.seen = set()
        super().__init__(image, code_override)

    def step(self, va):
        self.seen.add(va)
        return super().step(va)


def sym(v):
    if IN_AT <= v < IN_AT + IN_SIZE:
        return ("in", v - IN_AT)
    if OUT_AT <= v < OUT_AT + OUT_SIZE + OUT_SLACK:
        return ("out", v - OUT_AT)
    if STACK_TOP - 0x10000 <= v < STACK_TOP:
        return ("stack", v - ENTRY_SP)
    return ("abs", v)


def clobber(mm, ret):
    """Every stub leaves the System V caller-saved state scrambled, so the body may rely only on callee-saved state."""
    for r in (1, 2, 6, 7, 8, 9, 10, 11):
        mm.regs[r] = JUNK
    mm.regs[0] = ret
    mm.xmm = [JUNK | JUNK << 64] * 16


def install(m, c, rec, pad_drops):
    img = m.image

    def memcpy(mm):
        dst, src, size = mm.regs[7], mm.regs[6], mm.regs[2]
        rec.append(("memcpy", sym(dst), sym(src), size))
        mm.store_bytes(dst, mm.load_bytes(src, size))
        clobber(mm, dst)

    def composer(mm):
        dst, src = mm.regs[7], mm.regs[6]
        rec.append(("composer", sym(dst), sym(src), mm.regs[2], mm.regs[1]))
        mm.store_bytes(dst, c["composed"])
        if sym(src)[0] == "in":   # the composer consumes (moves out of) the sub-value it is given
            mm.store_bytes(src, c["consumed"][:max(0, min(SUB_SIZE, IN_AT + IN_SIZE - src))])
        clobber(mm, dst)

    if img.import_name(MEMCPY_SLOT) != "memcpy":
        fail("memcpy slot does not name memcpy")
    m.stubs[img.relative[MEMCPY_SLOT]] = memcpy
    m.stubs[COMPOSER] = composer
    for f in pad_drops:
        m.stubs[f] = "landing"


def run_case(m, c, pad_drops):
    m.reset()
    rec = []
    install(m, c, rec, pad_drops)
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    inb = m.add_region(IN_AT, IN_SIZE, c["in"])
    out = m.add_region(OUT_AT, OUT_SIZE + OUT_SLACK, c["out"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT_AT, IN_AT, c["a"], c["b"]
    m.run(BODY, limit=5000)
    return {"calls": rec, "ret": m.regs[0], "out": bytes(out)[:OUT_SIZE], "in": bytes(inb),
            "slack_ok": bytes(out)[OUT_SIZE:] == c["out"][OUT_SIZE:],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == ENTRY_SP}


def compare(c, want, got):
    return (got["regs_ok"] and got["slack_ok"] and got["ret"] == want["ret"] and got["in"] == want["in"]
            and got["out"] == want["out"][:OUT_SIZE] and got["calls"] == want["calls"])


# ---------------------------------------------------------------- cases
CASES = 6000
MODES = ("random", "random", "in-zero", "in-ones", "byte-ramp", "composed-zero", "args-zero", "args-max",
         "random", "out-zero", "out-ones", "composed-ones", "random", "byte-ramp", "random")


def make_case(s, idx):
    mode = MODES[idx % len(MODES)]
    inb = bytearray(s.take(IN_SIZE))
    composed = bytearray(s.take(COMPOSED))
    out = bytearray(s.take(OUT_SIZE + OUT_SLACK))
    a = int.from_bytes(s.take(8), "little") >> (8 * s.below(8))
    b = int.from_bytes(s.take(8), "little")
    if mode == "in-zero":
        inb = bytearray(IN_SIZE)
    if mode == "in-ones":
        inb = bytearray([0xff]) * IN_SIZE
    if mode == "byte-ramp":  # input bytes encode their own offset, so a misplaced or shifted field is visible
        inb = bytearray((i ^ (i >> 8) * 0x3b) & 0xff for i in range(IN_SIZE))
    if mode == "composed-zero":
        composed = bytearray(COMPOSED)
    if mode == "composed-ones":
        composed = bytearray([0xff]) * COMPOSED
    if mode == "args-zero":
        a = b = 0
    if mode == "args-max":
        a = b = M64
    if mode == "out-zero":
        out = bytearray(OUT_SIZE + OUT_SLACK)
    if mode == "out-ones":
        out = bytearray([0xff]) * (OUT_SIZE + OUT_SLACK)
    inner = s.take(COMPOSED)
    return {"mode": mode, "in": bytes(inb), "composed": bytes(composed), "out": bytes(out), "a": a, "b": b,
            "consumed": s.take(SUB_SIZE), "inner": inner}


def all_cases():
    s = Stream("re16-state-materialize-115")
    return [make_case(s, k) for k in range(CASES)]


# ---------------------------------------------------------------- static evidence
CHECKED = (
    (0x3c2e86a, "48 81 ec 00 10 00 00", "first of three probed 0x1000-byte stack pages"),
    (0x3c2e897, "48 81 ec 88 0c 00 00", "last frame step 0xc88 (frame 0x3c88)"),
    (0x3c2e89e, "48 89 4c 24 08", "rcx (4th argument) saved at rsp+8, passed to the composer as rcx"),
    (0x3c2e8a3, "48 89 14 24", "rdx (3rd argument) saved at rsp+0, passed to the composer as rdx"),
    (0x3c2ebf3, "ba a0 0b 00 00", "stack copy of in +0x000, 0xba0 bytes (prefix head)"),
    (0x3c2ec06, "49 8d b6 08 11 00 00", "composer source = in +0x1108"),
    (0x3c2ec16, "e8 d5 cd 71 00", "the only direct call on the normal path: composer 0x434b9f0"),
    (0x3c2ec63, "49 8d b6 d0 1f 00 00", "out +0x3af0 <- in +0x1fd0 (first post-call copy, shift +0x1b20)"),
    (0x3c2f1ac, "48 8d bb 08 11 00 00", "composer result copied to out +0x1108"),
    (0x3c2f1bb, "ba d8 26 00 00", "composer result length 0x26d8"),
    (0x3c2f1da, "48 89 83 e0 37 00 00", "out +0x37e0 <- in +0x1cc0 (saved before the call)"),
    (0x3c2f285, "49 8b 86 9d 27 00 00", "last input read: in +0x279d, 8 bytes (input read span ends at 0x27a5)"),
    (0x3c2f28c, "48 89 83 bd 42 00 00", "last output write: out +0x42bd, 8 bytes (written span ends at 0x42c5)"),
    (0x3c2f2c0, "48 89 d8", "returns the output pointer (rdi)"),
)
BOUNDARY_CHECKED = (   # context bytes in the caller (reported by RE-017; re-read here only to pin the two sizes)
    (0x3c13665, "ff 15 c5 5f 8d 02", "boundary calls BODY through .got 0x64e9630 (out = its stack, in = its rdi)"),
    (0x3c1366b, "bf c8 42 00 00", "boundary then allocates 0x42c8 bytes = output size"),
    (0x3c1367e, "ba c8 42 00 00", "boundary copies the 0x42c8-byte output into the new allocation"),
    (0x3c1368f, "be a8 27 00 00", "boundary frees the input allocation with size 0x27a8 = input size"),
)


def sweep_padded(image, lo, hi):
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


def call_sites(decoded, lo, hi):
    out = []
    for va, fm in decoded:
        if fm is None:
            continue
        if fm["op"] == 0xe8 or fm["op"] == 0xe9 and not lo <= fm["target"] < hi:
            out.append((va, "direct", fm["target"]))
        elif fm["op"] == 0xff and fm["reg"] & 7 in (2, 3, 4, 5):
            rm = fm["rm"]
            if rm[0] == "m" and rm[1] == "rip":
                out.append((va, "got", (va + fm["len"] + rm[4]) & M64))
            else:
                out.append((va, "register", None))
    return out


def caller_scan(image, target):
    """Every .text byte offset tried as an e8 rel32 call (superset of aligned instructions); RELATIVE addends too."""
    t, d = image.text, image.data
    lo, hi = t["offset"], t["offset"] + t["size"] - 5
    base = t["address"] - t["offset"]
    sites, pos = [], d.find(b"\xe8", lo, hi)
    while pos != -1:
        disp = struct.unpack_from("<i", d, pos + 1)[0]
        if (pos + base + 5 + disp) & M64 == target:
            sites.append(pos + base)
        pos = d.find(b"\xe8", pos + 1, hi)
    relocs = sorted(k for k, v in image.relative.items() if v == target)
    return sites, relocs


def static_evidence(image):
    if image.import_name(MEMCPY_SLOT) != "memcpy":
        fail("memcpy slot does not name memcpy")
    lo, hi = fde_rows(image, [BODY])[BODY]
    decoded = sweep_padded(image, lo, hi)
    rets = [va for va, fm in decoded if fm is not None and fm["op"] == 0xc3]
    if len(rets) != 1:
        fail("expected exactly one ret")
    pad = next(va for va, fm in decoded if va > rets[0] and fm is not None)
    rows, pad_drops = [], []
    for va, kind, target in call_sites(decoded, lo, hi):
        if va < pad:
            if (kind, target) == ("direct", COMPOSER):
                role = "composer"
            elif kind == "register":
                role = "memcpy (r15/r13 = [.got 0x64df508])"
            else:
                fail(f"unexpected normal-path call at {va:#x}")
        elif kind == "direct" and target == UNWIND_RESUME:
            role = "_Unwind_Resume"
        elif kind == "direct" and image.text["address"] <= target < image.text["address"] + image.text["size"]:
            role = "landing-pad drop"
            if target not in pad_drops:
                pad_drops.append(target)
        else:
            role = "landing-pad indirect"
        rows.append({"site": f"{va:#x}", "kind": kind, "target": f"{target:#x}" if target is not None else "reg",
                     "role": role, "in_landing_pad": va >= pad})
    checks = {}
    for va, hx, what in CHECKED + BOUNDARY_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    sites, relocs = caller_scan(image, BODY)
    if sites or relocs != [CTOR_SLOT]:
        fail(f"caller set changed: {sites} {relocs}")
    slot_users = [va for va, kind, t in call_sites(sweep_padded(image, *fde_rows(image, [BOUNDARY])[BOUNDARY]),
                                                      *fde_rows(image, [BOUNDARY])[BOUNDARY])
                  if kind == "got" and t == CTOR_SLOT]
    if slot_users != [0x3c13665]:
        fail(f"boundary slot use changed: {slot_users}")
    csites, crelocs = caller_scan(image, COMPOSER)
    if csites != [COMPOSER_SITE] or crelocs:
        fail("composer caller set changed")
    out = {"binary_sha256": SHA256,
           "function": {"start": f"{lo:#x}", "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                        "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                        "instructions": sum(1 for _, fm in decoded if fm is not None),
                        "ret": f"{rets[0]:#x}", "landing_pad_start": f"{pad:#x}", "frame_bytes": FRAME - 8},
           "calls": rows, "landing_pad_drop_targets": [f"{t:#x}" for t in pad_drops], "checked_bytes": checks,
           "callers": {"e8_rel32_sites": [f"{v:#x}" for v in sites], "relative_addends": [f"{v:#x}" for v in relocs],
                       "slot_call_sites_in_boundary": [f"{v:#x}" for v in slot_users],
                       "composer_e8_rel32_sites": [f"{v:#x}" for v in csites]},
           "sizes": {"input": IN_SIZE, "input_read_span": 0x27a5, "output": OUT_SIZE, "output_written_span": 0x42c5,
                     "sub_value_at": SUB_AT, "sub_value": SUB_SIZE, "composed": COMPOSED, "growth": BLOCK}}
    return out, decoded, pad, pad_drops


# ---------------------------------------------------------------- evaluation
def evaluate(image, pad_drops, override=None, mut=frozenset(), stop_on_first=False, cases=None):
    m = TraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else all_cases()):
        want = model(c, mut)
        try:
            got = run_case(m, c, pad_drops)
            ok = compare(c, want, got)
        except (ToolError, KeyError) as exc:
            got, ok = {"error": f"{type(exc).__name__}: {exc}"}, False
        except Boundary as exc:
            got, ok = {"error": f"reached {exc.kind} stub"}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


MODEL_MUTANTS = ["prefix_short", "suffix_short", "shift_1b00", "composer_ignored", "tail_zeroed", "no_stack_copies",
                 "args_swapped", "composer_in_1110"]
BYTE_MUTANTS = [
    (0x3c2ebf4, 0x98, "stack copy of in +0x000 0xba0 -> 0xb98"),
    (0x3c2ec09, 0x10, "composer source in +0x1108 -> +0x1110"),
    (0x3c2ec61, 0x70, "out +0x3af0 copy 0x168 -> 0x170"),
    (0x3c2f1af, 0x00, "composer result to out +0x1108 -> +0x1100"),
    (0x3c2f1bc, 0xd0, "composer result length 0x26d8 -> 0x26d0"),
    (0x3c2f1dd, 0xe8, "out +0x37e0 -> +0x37e8"),
    (0x3c2f25d, 0x18, "in +0x1d10 -> +0x1d18"),
    (0x3c2f288, 0x9c, "last input read in +0x279d -> +0x279c"),
    (0x3c2f2b5, 0xd0, "out +0x4278 source stack +0xc0 (in +0x2758) -> +0xd0 (in +0x10e8)"),
    (0x3c2e8a2, 0x24, "rdx/rcx saves: rcx stored at rsp+0x24 instead of rsp+8"),
]


def controls(image, cases, pad_drops):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, pad_drops, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, pad_drops, override={va: byte}, stop_on_first=True, cases=cases)
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
def generate(out):
    image = Image(BINARY.read_bytes())
    consts, decoded, pad, pad_drops = static_evidence(image)
    out.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    rows, bad, m = evaluate(image, pad_drops, cases=cases)
    lines = ["case\tmode\ta\tb\tcalls\tout_sha256_16\tin_after_sha256_16\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = c["mode"] + ("/error" if "error" in got else "/returned")
        classes[oc] = classes.get(oc, 0) + 1
        d_out = hashlib.sha256(got["out"]).hexdigest()[:16] if "out" in got else got.get("error", "-")
        d_in = hashlib.sha256(got["in"]).hexdigest()[:16] if "in" in got else "-"
        lines.append(f"{i}\t{c['mode']}\t{c['a']:#x}\t{c['b']:#x}\t{len(got.get('calls', []))}\t{d_out}\t{d_in}\t"
                     f"{'yes' if ok else 'NO'}")
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    (out / "layout.tsv").write_text(
        "out_offset\tsource\tsource_offset\tlength\tmeaning\n"
        + "".join(f"{d:#06x}\t{s}\t{o:#06x}\t{n:#x}\t{t}\n" for d, s, o, n, t in LAYOUT))
    (out / "copies.tsv").write_text(
        "order\tdestination\tdestination_offset\tsource\tsource_offset\tlength\n"
        + "".join(f"{k}\t{dst[0]}\t{dst[1]:#x}\t{src[0]}\t{src[1]:#x}\t{n:#x}\n"
                  for k, (_, dst, src, n) in enumerate(c for c in model(cases[0])["calls"] if c[0] == "memcpy")))
    lines = ["address\tbytes\trole\texecuted"]
    hit = total = 0
    for va, f in decoded:
        if f is None:
            continue
        run = int(va in m.seen)
        if va < pad:
            hit += run
            total += 1
        lines.append(f"{va:#x}\t{f['bytes'].hex()}\t{'body' if va < pad else 'landing-pad'}\t{run}")
    (out / "instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = controls(image, cases, pad_drops)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad,
               "body_instructions_executed": [hit, total], "outcome_classes": len(classes),
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
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
    print(json.dumps(summary, sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
