#!/usr/bin/env python3
"""Reconstruct and validate the three direct callees of the node #115 composer 0x434b9f0.

0x38b3830 (out, ctx) formats a text from its 0x30-byte argument, probes it, emits a gated diagnostic, removes the
kind sub-directory when it exists and moves the argument to out; 0x44681e0 (out, vec, ares, mode) formats the same
text, creates the directory when the probe says it is missing, copies the source tree (mode 1 also the numbered
checkpoint directory and its hash file), writes the state file and moves its 0x30-byte `ares` to out; 0x38b3ad0
(state, a, b) formats and creates a directory text, collects and sorts 16-byte items into an ordered map, clones the
state's byte string and returns a 0x40-byte block.  The tool reads every relocation, FDE extent and code byte from
the ELF file and evaluates the real machine code with a small concrete x86-64 evaluator (no external programs, the
binary is never executed; every external operation is a stub that scrambles all caller-saved registers and returns
a chosen outcome).  Each case is compared with the pure-Python reconstruction `model_*()`, including the exact
symbolic call trace; negative controls show that wrong reconstructions and corrupted code bytes are caught.  Role
names are inferences, not proven by any string.
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
        if p66:
            form["imm"] = struct.unpack_from("<H", code, p)[0]
            p += 2
        else:
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
FN_A, FN_B, FN_C = 0x38b3830, 0x44681e0, 0x38b3ad0   # FDE starts; the three direct callees of 0x434b9f0
FN_D = 0x3915d30   # the second caller of the trio (mode-0 sibling of the composer)
GATE_WORD = 0x64f01d8     # 32-bit word read before every diagnostic emission (zero = silent)
GATE_ITEM = 0x64f01c0     # static item whose address travels in the diagnostic argument cell
KIND_FN_SLOT = 0x64e2078  # RELATIVE slot: Display function of the one-byte directory kind (value 2 in these bodies)
STEP_FN_SLOT = 0x64e0a98  # RELATIVE slot: Display function of the u64 in vec +0x18
KIND = 2

# role of each external operation, by the RELATIVE target of the slot (or the direct callee itself)
ROLE = {
    0x1680500: "fmt_write", 0x141e3a0: "fmt_format", 0x1680c30: "panic", 0x5c87d50: "log", 0x635de30: "dealloc",
    0x1500a60: "is_dir", 0x1500d20: "is_file", 0x5c8f4c0: "create_dir", 0x15028f0: "cp", 0x1505a50: "op_09e0",
    0x1505de0: "copy_file", 0x15020f0: "mk", 0x6355830: "alloc", 0x141e251: "alloc_error_a", 0x141e264: "alloc_error_b",
    0x36e4490: "sort_big", 0x1680cab: "landing",
    0x1561530: "remove_dir", 0x1500b90: "io_err", 0x1696b90: "join_kind", 0x422f320: "write_state",
    0x4468e30: "list", 0x38fe5f0: "drop_state", 0x44e4920: "drop_ares", 0x37befd0: "items", 0x3577e30: "bulk_tree", 0x4375ed0: "sort_small",
}
LANDING_DIRECT = (0x38ecc10, 0x38eee10, 0x3d844e0, 0x38ea850, 0x3d65110)   # drop helpers used only by the landing pad of FN_C
MEMCPY_SLOT = 0x64df508
SLOT_ROLE = {0x64e61d0: "save_records", 0x64e9528: "block_builder", 0x64df830: "expect_failed"}
LIST_FN = 0x4468e30
SLOTS = (0x64df6f0, 0x64df6e8, 0x64df6a0, 0x64df9f0, 0x64df4a0, 0x64e0928, 0x64e0950, 0x64e0940, 0x64e0a18, 0x64e09e0,
         0x64e0a58, 0x64e0028, 0x64df480, 0x64df490, 0x64df498, 0x64e8ff8, 0x64df4c0)
# pieces of the compact format texts and how many arguments each takes
PIECES = {0x43b857: 1, 0x43aa84: 2, 0x434739: 1, 0x44f3c9: 1}
PTR = 0x7d00_0000_0000    # first address of the harness regions (random stub pointers stay below 1 << 46)
CTX_AT, ARES_AT, VEC_AT, OUT_AT, STATE_AT, SDATA_AT, OBJ_AT, VT_AT, DROP_FN, D_A_AT, LIST_AT = (
    PTR + 0x100_0000 * i for i in range(1, 12))
OUT_SIZE, OUT_SLACK = 0x30, 0x40
JUNK = 0x6b6b_6b6b_6b6b_6b6b
STACK_FILL = 0x5c
ENTRY_SP = STACK_TOP - 0x100
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


def frame(pushes, sub):
    return -(8 + 8 * pushes + sub)


S_A, S_B, S_C = frame(5, 0x60), frame(6, 0xf8), frame(6, 0xa8)


class Abort(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def st(off, base=0):
    return ("stack", base + off)


def ab(v):
    return ("abs", v)


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

    def bit(self, num=1, den=2):
        return self.below(den) < num


def u(buf, off, size):
    return int.from_bytes(buf[off:off + size], "little")


def w64(*words):
    return b"".join((x & M64).to_bytes(8, "little") for x in words)


# ---------------------------------------------------------------- constants read from the image
class K:
    """Values the reconstruction needs from the image: Display function pointers and static item contents."""
    kind_fn = step_fn = 0
    static_word = 0


def load_consts(image):
    K.kind_fn = image.relative[KIND_FN_SLOT]
    K.step_fn = image.relative[STEP_FN_SLOT]
    K.static_word = image.word(0x648b880)


# ---------------------------------------------------------------- reconstruction (pure Python)
def queues(c):
    """Fresh copies of the stub outcome queues of one case (the stubs pop from the same lists in call order)."""
    return {k: list(c[k]) for k in ("strs", "fw", "isdir", "isfile", "joins", "alloc", "cp") if k in c}


def model_a(c, mut=frozenset(), q=None, base=0, ctx_at=CTX_AT, ctx=None):
    """0x38b3830(out, ctx): format the text, probe it, emit a diagnostic, remove the kind sub-directory when present."""
    S = base + S_A
    q = q if q is not None else queues(c)
    ctx = ctx if ctx is not None else c["ctx"]
    calls = []
    baset = q["strs"].pop(0)
    calls.append(("fmt_write", st(0x10, S), ab(0x646ea90), ab(0x43b857), (("stack", S + 0x30), 0x1696d50, w64(ctx_at))))
    if q["fw"].pop(0):
        calls.append(("panic", ab(0x7a15ae), 0x37, st(0xf, S), ab(0x646ead8), ab(0x646eac0), None))
        return {"calls": calls, "abort": "panic", "out": None}
    calls.append(("is_dir", ab(baset[1]), baset[2]))
    d = q["isdir"].pop(0)
    if "dir_inverted" in mut:
        d = not d
    if c["gate"] and "gate_ignored" not in mut:
        calls.append(("log", ab(GATE_WORD), 1, st(0x10, S), st(0x48, S), ab(0x63fe250), ab(0x63fe278)))
    if d:
        sub = q["strs"].pop(0)
        calls.append(("fmt_format", st(0x48, S), ab(0x43aa84), st(0x10, S),
                      ((st(0x30, S), 0x37be6f0, w64(*baset)),
                       (st(0xe, S), K.kind_fn, bytes([1 if "kind_one" in mut else KIND])))))
        calls.append(("is_dir", ab(sub[1]), sub[2]))
        if q["isdir"].pop(0):
            calls.append(("remove_dir", st(0x10, S), ab(0x4659e8), 10 if "name_len_11" not in mut else 11, 0,
                          w64(sub[1], sub[2])))
            if c["rm"]:
                calls.append(("drop_err", ("obj", 0)))
        if sub[0] and "sub_leak" not in mut:
            calls.append(("dealloc", ab(sub[1]), sub[0], 0))
    out = ctx[:0x30] if "out_short" not in mut else ctx[:0x28] + bytes(8)
    if baset[0]:
        calls.append(("dealloc", ab(baset[1]), baset[0], 0))
    return {"calls": calls, "abort": None, "out": out, "ret": ("out", 0)}


def model_b(c, mut=frozenset(), q=None, base=0, ares_at=None, ares=None, vec_words=None, vec_sym=("vec", 0),
            mode=None):
    """0x44681e0(out, vec, ares, mode): prepare the db-home directory, copy the source tree (and, in checkpoint mode,
    the numbered checkpoint directory with its hash file), write the state file; out = the 0x30-byte `ares` value."""
    S = base + S_B
    calls = []
    q = q if q is not None else queues(c)
    ares_at = ares_at if ares_at is not None else c["ares_at"]
    ares = ares if ares is not None else c["ares"]
    in_ptr, in_len, step = vec_words if vec_words is not None else (c["in_ptr"], c["in_len"], c["step"])
    mode = mode if mode is not None else c["mode"]

    def fmt_f(dst, pieces, args_at, args):
        s = q["strs"].pop(0)
        calls.append(("fmt_format", dst, ab(pieces), args_at, tuple(args)))
        return s

    def dealloc(s):
        if s[0]:
            calls.append(("dealloc", ab(s[1]), s[0], 0))

    def panic_unwrap(err, loc):
        calls.append(("panic", ab(0x7d3212), 0x2b, st(8, S) if loc != 0x648b920 else st(0x48, S), ab(0x648c5d8),
                      ab(loc), err))
        return {"calls": calls, "abort": "panic", "out": None}

    calls.append(("fmt_write", st(8, S), ab(0x648c4f0), ab(0x43b857), (st(0x60, S), 0x1696d50, w64(ares_at))))
    if q["fw"].pop(0):
        calls.append(("panic", ab(0x7d31d2), 0x37, st(0x47, S), ab(0x648c5b8), ab(0x648c520), None))
        return {"calls": calls, "abort": "panic", "out": None}
    baset = q["strs"].pop(0)
    if c["gate"]:
        calls.append(("log", ab(GATE_WORD), 1, st(8, S), st(0x28, S), ab(0x63fe250), ab(0x63fe278)))
    calls.append(("is_dir", ab(baset[1]), baset[2]))
    if not q["isdir"].pop(0):
        calls.append(("create_dir", st(0x28, S), ab(baset[1]), baset[2], (0x1ff, 1)))
        if c["mkdir"]:
            calls.append(("io_err", st(8, S), c["mkdir"]))
            calls.append(("panic", ab(0x7d3212), 0x2b, st(8, S), ab(0x648c5d8), ab(0x648b868), c["ioconv"]))
            return {"calls": calls, "abort": "panic", "out": None}
    if "mode_inverted" in mut:
        mode = 0 if mode & 0xff else 1
    src_args = ((st(0x28, S), 0x1699c10, w64(in_ptr, in_len)), (st(0x60, S), K.kind_fn, bytes([KIND])))
    src = fmt_f(st(0x78, S), 0x43aa84, st(8, S), src_args)
    cp_flag = 0 if "cp_flag_zero" in mut else 1
    calls.append(("cp", ab(src[1]), src[2], ab(baset[1]), baset[2], cp_flag, ab(0x648b8a8)))
    err = q["cp"].pop(0)
    if err:
        return panic_unwrap(err, 0x648b8c0)
    if mode & 0xff:
        cpd = fmt_f(st(0x28, S), 0x434739, st(8, S), ((st(0x60, S), 0x44dbed0, w64(ares_at)),))
        chk = fmt_f(st(0xb0, S), 0x43aa84, st(8, S),
                    ((st(0x28, S), 0x43cd590, w64(*cpd)), (st(0x48, S), K.step_fn, w64(step))))
        dealloc(cpd)
        dst = fmt_f(st(0x60, S), 0x43aa84, st(8, S),
                    ((st(0x28, S), 0x1699c10, w64(chk[1], chk[2])), (st(0x48, S), K.kind_fn, bytes([KIND]))))
        p1 = q["joins"].pop(0)
        calls.append(("join_kind", st(8, S), KIND, ab(chk[1]), chk[2]))
        calls.append(("is_file", ab(p1[1]), p1[2]))
        marker = q["isfile"].pop(0)
        dealloc(p1)
        if not marker:
            calls.append(("cp", ab(src[1]), src[2], ab(dst[1]), dst[2], 1, ab(0x648b8d8)))
            err = q["cp"].pop(0)
            if err:
                return panic_unwrap(err, 0x648b8f0)
            p2 = q["joins"].pop(0)
            calls.append(("join_kind", st(8, S), KIND, ab(chk[1]), chk[2]))
            calls.append(("op_09e0", ab(p2[1]), p2[2], ab(0x63fc108)))
            if c["op09"]:
                calls.append(("drop_err", ("obj", 0)))
            dealloc(p2)
            if c["gate"]:
                calls.append(("log", ab(GATE_WORD), 1, st(8, S), st(0x28, S), ab(0x63fe250), ab(0x63fe278)))
            lt = fmt_f(st(0x28, S), 0x44f3c9, st(8, S), ((st(0x48, S), 0x1699c10, w64(in_ptr, in_len)),))
            calls.append(("is_file", ab(lt[1]), lt[2]))
            if q["isfile"].pop(0):
                dst2 = fmt_f(st(8, S), 0x44f3c9, st(0x48, S), ((st(0xe8, S), 0x1699c10, w64(chk[1], chk[2])),))
                calls.append(("copy_file", ab(lt[1]), lt[2], ab(dst2[1]), dst2[2], ab(0x648b908)))
                if c["cpf"]:
                    return panic_unwrap(c["cpf"], 0x648b920)
                dealloc(dst2)
            dealloc(lt)
        dealloc(dst)
        dealloc(chk)
    dealloc(src)
    path = fmt_f(st(0x28, S), 0x43aa84, st(8, S),
                 ((st(0x90, S), 0x43cd590, w64(*baset)), (ab(0x648b880), 0x46dd7f0, w64(K.static_word))))
    calls.append(("write_state", vec_sym[:1] + (vec_sym[1] + 0x18,), ab(path[1]), path[2], ab(0x648b890)))
    if c["wstate"]:
        calls.append(("drop_err", ("obj", 0)))
    dealloc(path)
    if c["gate"]:
        calls.append(("log", ab(GATE_WORD), 1, st(8, S), st(0x28, S), ab(0x63fe250), ab(0x63fe278)))
    dealloc(baset)
    return {"calls": calls, "abort": None, "out": ares[:0x30], "ret": ("out", 0)}


def model_c(c, mut=frozenset(), q=None, base=0, state_at=None, state_sym=("state", 0), state_words=None):
    """0x38b3ad0(state, a, b): format and create the directory text, collect and sort the 16-byte items, build the
    ordered map, clone the state's byte string and return an Arc-like 0x40-byte block {1, 1, n, ptr, n, map}."""
    S = base + S_C
    q = q if q is not None else queues(c)
    state_at = state_at if state_at is not None else c["state_at"]
    sl, sptr = state_words if state_words is not None else (c["state_len"], c["state_ptr"])
    calls = []
    if c["gate"]:
        calls.append(("log", ab(GATE_WORD), 1, st(0x20, S), st(8, S), ab(0x63fe250), ab(0x63fe278)))
    calls.append(("fmt_write", st(0x20, S), ab(0x646ea90), ab(0x43b857), (st(0x78, S), 0x1696d50, w64(state_at))))
    if q["fw"].pop(0):
        calls.append(("panic", ab(0x7a15ae), 0x37, st(7, S), ab(0x646ead8), ab(0x646eac0), None))
        return {"calls": calls, "abort": "panic", "out": None}
    s = q["strs"].pop(0)
    calls.append(("mk", ab(s[1]), s[2]))
    if c["mk"]:
        calls.append(("panic", ab(0x7a1618), 0x2b, st(0x20, S), ab(0x646eaf8), ab(0x646e338), c["mk"]))
        return {"calls": calls, "abort": "panic", "out": None}
    allocs = q["alloc"]
    calls.append(("alloc", 0x10))
    a_vec = allocs.pop(0)
    if not a_vec:
        calls.append(("alloc_error_b", 8, 0x10))
        return {"calls": calls, "abort": "oom", "out": None}
    n = c["nitems"]
    calls.append(("items", st(0x78, S), st(0x20, S)))
    if n:
        if n != 1:
            if n >= 0x15 and "sort_always_small" not in mut:
                calls.append(("sort_big", ab(a_vec), n, st(0x20, S)))
            else:
                calls.append(("sort_small", ab(a_vec), n, 1, st(0x20, S)))
        calls.append(("alloc", 0x70 if "leaf_68" not in mut else 0x68))
        leaf = allocs.pop(0)
        if not leaf:
            calls.append(("alloc_error_a", 8, 0x70))
            return {"calls": calls, "abort": "oom", "out": None}
        calls.append(("bulk_tree", st(0x78, S), st(0x20, S), st(0x90, S), (a_vec, a_vec, 1, a_vec + 16 * n)))
        tree = c["tree"]
    else:
        calls.append(("dealloc", ab(a_vec), 16, 0))
        tree = (0, a_vec, 0)
    if sl:
        calls.append(("alloc", sl))
        clone = allocs.pop(0)
        if not clone:
            calls.append(("alloc_error_b", 1, sl))
            return {"calls": calls, "abort": "oom", "out": None}
        calls.append(("memcpy", ab(clone), ab(sptr), sl))
    else:
        clone = 1
    calls.append(("alloc", 0x40))
    box = allocs.pop(0)
    if not box:
        calls.append(("alloc_error_a", 8, 0x40))
        return {"calls": calls, "abort": "oom", "out": None}
    if s[0]:
        calls.append(("dealloc", ab(s[1]), s[0], 0))
    calls.append(("drop_state", state_sym))
    block = w64(1, 1, sl, clone, sl, tree[0], tree[1], tree[2])
    if "arc_weak_zero" in mut:
        block = w64(1, 0, sl, clone, sl, tree[0], tree[1], tree[2])
    leaf_bytes = bytes(0x70) if n else None
    clone_bytes = c["state_data"][:sl] if sl else None
    return {"calls": calls, "abort": None, "out": None, "ret": ab(box), "box": block, "leaf": leaf_bytes,
            "clone": clone_bytes, "box_at": box}


S_D = frame(6, 0xf8)
SENT = 1 << 63


def model_d(c, mut=frozenset()):
    """0x3915d30(out, a, b, ctx): the mode-0 sibling of the composer.  Fetch the list of 32-byte entries behind
    a +0x1b18, keep the entry whose key word equals b (dropping the text of every other entry), then run the three
    callees on a stack copy of ctx with mode 0 and hand the third result and the entry to the block builder."""
    S = S_D
    q = queues(c)
    calls = [("save_records", st(0x80, S), c["a"], c["b"], 0),
             ("list", st(0x10, S), (c["a_word"] + 0x10) & M64)]
    if c["lcap"] == SENT:
        calls.append(("panic", ab(0x7a1618), 0x2b, st(0x48, S), ab(0x646eaf8), ab(0x646ec68), c["lerr"]))
        return {"calls": calls, "abort": "panic", "out": None}
    ents = c["entries"]
    found = None
    for i, (cap, ptr, ln, key) in enumerate(ents):
        if key != c["b"] ^ (1 if "key_off_by_one" in mut else 0):
            if cap:
                calls.append(("dealloc", ab(ptr), cap, 0))
            continue
        if cap != SENT:
            found = i
            break
    if found is None:
        calls.append(("expect_failed", ab(0x646ec80)))
        return {"calls": calls, "abort": "panic", "out": None}
    cap, ptr, ln, key = ents[found]
    for cap2, ptr2, ln2, key2 in ents[found + 1:]:
        if cap2:
            calls.append(("dealloc", ab(ptr2), cap2, 0))
    if c["lcap"]:
        calls.append(("dealloc", ab(LIST_AT), (c["lcap"] << 5) & M64, 0))
    ctx_copy = ENTRY_SP + S + 0x10
    ares_at = ENTRY_SP + S + 0x98
    vec_at = ENTRY_SP + S + 0x48
    state_at = ENTRY_SP + S + 0xc8
    ra = model_a(c, mut, q, S, ctx_copy)
    calls += ra["calls"]
    if ra["abort"]:
        return {"calls": calls, "abort": ra["abort"], "out": None}
    rb = model_b(c, mut, q, S, ares_at, ra["out"], (ptr, ln, key), ("stack", S + 0x48), 0)
    calls += rb["calls"]
    if rb["abort"]:
        return {"calls": calls, "abort": rb["abort"], "out": None}
    sl, sptr = u(rb["out"], 0x10, 8), u(rb["out"], 8, 8)
    rc = model_c(c, mut, q, S, state_at, ("stack", S + 0xc8), (sl, sptr))
    calls += rc["calls"]
    if rc["abort"]:
        return {"calls": calls, "abort": rc["abort"], "out": None}
    calls.append(("block", ("out", 0), rc["ret"], ("stack", S + 0x48)))
    if cap:
        calls.append(("dealloc", ab(ptr), cap, 0))
    d0 = c["d0"]
    if d0[0]:
        calls.append(("dealloc", ab(d0[1]), d0[0], 0))
    return {"calls": calls, "abort": None, "out": None, "ret": ("out", 0)}


# ---------------------------------------------------------------- harness
class TraceMachine(Machine):
    def __init__(self, image, code_override=None):
        self.seen = set()
        super().__init__(image, code_override)

    def step(self, va):
        self.seen.add(va)
        return super().step(va)

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


def sym(v, frame_sp):
    for tag, at, size in (("ctx", CTX_AT, 0x30), ("ares", ARES_AT, 0x30), ("vec", VEC_AT, 0x20), ("out", OUT_AT, 0x70),
                          ("state", STATE_AT, 0x18), ("obj", OBJ_AT, 8)):
        if at <= v < at + size:
            return (tag, v - at)
    if STACK_TOP - 0x10000 <= v < STACK_TOP:
        return ("stack", v - ENTRY_SP)
    return ("abs", v)


def clobber(mm, ret):
    for r in (1, 2, 6, 7, 8, 9, 10, 11):
        mm.regs[r] = JUNK
    mm.regs[0] = ret
    mm.xmm = [JUNK | JUNK << 64] * 16


class Env:
    """Queues of stub outcomes for one case plus the call record."""

    def __init__(self, m, c):
        self.m, self.c, self.rec = m, c, []
        self.q = {k: list(c[k]) for k in ("strs", "fw", "isdir", "isfile", "joins", "alloc", "cp") if k in c}
        self.allocs = []

    def s(self, v):
        return sym(v, 0)

    def put_string(self, at, s):
        self.m.store_bytes(at, w64(*s))

    def install(self):
        m, img, c = self.m, self.m.image, self.c

        def peek(at, width):
            try:
                return bytes(m.load_bytes(at, width))
            except ToolError:
                return m.load(at, 8).to_bytes(8, "little")[:width]

        def pieces_args(p, args_at):
            n = PIECES.get(p)
            if n is None:
                fail(f"unknown format pieces {p:#x}")
            out = []
            for k in range(n):
                ptr, fn = u(m.load_bytes(args_at + 16 * k, 16), 0, 8), u(m.load_bytes(args_at + 16 * k, 16), 8, 8)
                width = {0x37be6f0: 24, 0x43cd590: 24, 0x1699c10: 16, K.kind_fn: 1, 0x1696d50: 8}.get(fn, 8)
                out.append((self.s(ptr), fn, peek(ptr, width)))
            return tuple(out)

        def fmt_write(mm):
            r = mm.regs
            self.rec.append(("fmt_write", self.s(r[7]), self.s(r[6]), self.s(r[2]), pieces_args(r[2], r[1])[0]
                             if PIECES[r[2]] == 1 else pieces_args(r[2], r[1])))
            s = self.q["strs"].pop(0)
            self.put_string(r[7], s)
            ok = self.q["fw"].pop(0)
            clobber(mm, ok)

        def fmt_format(mm):
            r = mm.regs
            self.rec.append(("fmt_format", self.s(r[7]), self.s(r[6]), self.s(r[2]), pieces_args(r[6], r[2])))
            self.put_string(r[7], self.q["strs"].pop(0))
            clobber(mm, JUNK)

        def panic(mm):
            r = mm.regs
            pointee = u(mm.load_bytes(r[2], 8), 0, 8) if r[6] == 0x2b else None
            self.rec.append(("panic", self.s(r[7]), r[6] & 0xffffffff, self.s(r[2]), self.s(r[1]), self.s(r[8]), pointee))
            raise Abort("panic")

        def log(mm):
            r = mm.regs
            cell = u(mm.load_bytes(r[2], 8), 0, 8)
            self.rec.append(("log", self.s(r[7]), r[6] & 0xffffffff, self.s(r[2]), self.s(cell), self.s(r[1]), self.s(r[8])))
            clobber(mm, JUNK)

        def dealloc(mm):
            r = mm.regs
            self.rec.append(("dealloc", self.s(r[7]), r[6], r[2]))
            clobber(mm, JUNK)

        def query(name, queue, nargs):
            def stub(mm):
                r = mm.regs
                args = [self.s(r[7]) if k == 0 else r[(6, 2, 1)[k - 1]] for k in range(nargs)]
                self.rec.append((name, args[0]) + tuple(args[1:]))
                clobber(mm, 1 if self.q[queue].pop(0) else 0)
            return stub

        def is_dir(mm):
            self.rec.append(("is_dir", self.s(mm.regs[7]), mm.regs[6]))
            clobber(mm, 1 if self.q["isdir"].pop(0) else 0)

        def is_file(mm):
            self.rec.append(("is_file", self.s(mm.regs[7]), mm.regs[6]))
            clobber(mm, 1 if self.q["isfile"].pop(0) else 0)

        def create_dir(mm):
            r = mm.regs
            opts = m.load_bytes(r[7], 5)
            self.rec.append(("create_dir", self.s(r[7]), self.s(r[6]), r[2], (u(opts, 0, 4), opts[4])))
            clobber(mm, c["mkdir"])

        def io_err(mm):
            r = mm.regs
            self.rec.append(("io_err", self.s(r[7]), r[6]))
            clobber(mm, c["ioconv"])

        def cp(mm):
            r = mm.regs
            self.rec.append(("cp", self.s(r[7]), r[6], self.s(r[2]), r[1], r[8] & 0xffffffff, self.s(r[9])))
            clobber(mm, self.q["cp"].pop(0))

        def copy_file(mm):
            r = mm.regs
            self.rec.append(("copy_file", self.s(r[7]), r[6], self.s(r[2]), r[1], self.s(r[8])))
            clobber(mm, c["cpf"])

        def err_or_none(flag):
            return OBJ_AT if flag else 0

        def remove_dir(mm):
            r = mm.regs
            self.rec.append(("remove_dir", self.s(r[7]), self.s(r[6]), r[2] & 0xffffffff, r[1] & 0xffffffff,
                             bytes(m.load_bytes(r[7], 16))))
            clobber(mm, err_or_none(c["rm"]))

        def op_09e0(mm):
            r = mm.regs
            self.rec.append(("op_09e0", self.s(r[7]), r[6], self.s(r[2])))
            clobber(mm, err_or_none(c["op09"]))

        def write_state(mm):
            r = mm.regs
            self.rec.append(("write_state", self.s(r[7]), self.s(r[6]), r[2], self.s(r[1])))
            clobber(mm, err_or_none(c["wstate"]))

        def join_kind(mm):
            r = mm.regs
            self.rec.append(("join_kind", self.s(r[7]), r[6] & 0xffffffff, self.s(r[2]), r[1]))
            self.put_string(r[7], self.q["joins"].pop(0))
            clobber(mm, JUNK)

        def drop_err(mm):
            self.rec.append(("drop_err", self.s(mm.regs[7])))
            clobber(mm, JUNK)

        def mk(mm):
            r = mm.regs
            self.rec.append(("mk", self.s(r[7]), r[6]))
            clobber(mm, c["mk"])

        def alloc(mm):
            size = mm.regs[7]
            self.rec.append(("alloc", size))
            ptr = self.q["alloc"].pop(0)
            if ptr:
                self.allocs.append((ptr, size, m.add_region(ptr, size)))
            clobber(mm, ptr)

        def oom(name):
            def stub(mm):
                self.rec.append((name, mm.regs[7], mm.regs[6]))
                raise Abort("oom")
            return stub

        def memcpy(mm):
            r = mm.regs
            self.rec.append(("memcpy", self.s(r[7]), self.s(r[6]), r[2]))
            m.store_bytes(r[7], m.load_bytes(r[6], r[2]))
            clobber(mm, r[7])

        def items(mm):
            r = mm.regs
            self.rec.append(("items", self.s(r[7]), self.s(r[6])))
            cell = u(m.load_bytes(r[6], 8), 0, 8)
            m.store_bytes(cell, w64(c["nitems"]))
            clobber(mm, JUNK)

        def sort_small(mm):
            r = mm.regs
            self.rec.append(("sort_small", self.s(r[7]), r[6], r[2] & 0xffffffff, self.s(r[1])))
            clobber(mm, JUNK)

        def sort_big(mm):
            r = mm.regs
            self.rec.append(("sort_big", self.s(r[7]), r[6], self.s(r[2])))
            clobber(mm, JUNK)

        def bulk_tree(mm):
            r = mm.regs
            it = tuple(u(m.load_bytes(r[6] + 8 * k, 8), 0, 8) for k in (2, 3, 4, 5))
            self.rec.append(("bulk_tree", self.s(r[7]), self.s(r[6]), self.s(r[2]),
                             it))
            tree = c["tree"]
            m.store_bytes(r[7], w64(tree[0], tree[1]))
            m.store_bytes(r[2], w64(tree[2]))
            clobber(mm, JUNK)

        def drop_state(mm):
            self.rec.append(("drop_state", self.s(mm.regs[7])))
            clobber(mm, JUNK)

        def drop_ares(mm):
            self.rec.append(("drop_ares", self.s(mm.regs[7])))
            clobber(mm, JUNK)

        def mkstr(mm):
            r = mm.regs
            self.rec.append(("save_records", self.s(r[7]), r[6], r[2], r[1] & 0xffffffff))
            self.put_string(r[7], c["d0"])
            clobber(mm, JUNK)

        def list_fn(mm):
            r = mm.regs
            self.rec.append(("list", self.s(r[7]), r[6]))
            word = c["lerr"] if c["lcap"] == SENT else LIST_AT
            m.store_bytes(r[7], w64(c["lcap"], word, len(c["entries"])))
            clobber(mm, JUNK)

        def block(mm):
            r = mm.regs
            self.rec.append(("block", self.s(r[7]), self.s(r[6]), self.s(r[2])))
            clobber(mm, JUNK)

        def expect_failed(mm):
            self.rec.append(("expect_failed", self.s(mm.regs[7])))
            raise Abort("panic")

        by_target = {0x1680500: fmt_write, 0x141e3a0: fmt_format, 0x1680c30: panic, 0x5c87d50: log, 0x635de30: dealloc,
                     0x1500a60: is_dir, 0x1500d20: is_file, 0x5c8f4c0: create_dir, 0x15028f0: cp, 0x1505a50: op_09e0,
                     0x1505de0: copy_file, 0x15020f0: mk, 0x6355830: alloc, 0x141e251: oom("alloc_error_a"),
                     0x141e264: oom("alloc_error_b"), 0x36e4490: sort_big}
        for slot in SLOTS:
            target = img.relative[slot]
            if target == 0x1680cab:
                m.stubs[target] = "landing"
            else:
                m.stubs[target] = by_target[target]
        if img.import_name(MEMCPY_SLOT) != "memcpy":
            fail("memcpy slot does not name memcpy")
        m.stubs[img.relative[MEMCPY_SLOT]] = memcpy
        m.stubs[img.relative[0x64e61d0]] = mkstr
        m.stubs[img.relative[0x64e9528]] = block
        m.stubs[img.relative[0x64df830]] = expect_failed
        direct = {0x1561530: remove_dir, 0x1500b90: io_err, 0x1696b90: join_kind, 0x422f320: write_state,
                  0x38fe5f0: drop_state, 0x44e4920: drop_ares, LIST_FN: list_fn, 0x37befd0: items, 0x3577e30: bulk_tree,
                  0x4375ed0: sort_small, DROP_FN: drop_err}
        m.stubs.update(direct)
        for f in LANDING_DIRECT + (0x63f0a50,):
            m.stubs[f] = "landing"


def build_case_regions(m, c, which):
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    regs = {}
    regs["out"] = m.add_region(OUT_AT, OUT_SIZE + OUT_SLACK, c["out"])
    m.add_region(VT_AT, 8, w64(DROP_FN))
    m.add_region(OBJ_AT, 8, w64(VT_AT))
    word = m.add_region(GATE_WORD, 4, c["gate"].to_bytes(4, "little"))
    if which == "a":
        regs["ctx"] = m.add_region(CTX_AT, 0x30, c["ctx"])
    elif which == "b":
        regs["ares"] = m.add_region(ARES_AT, 0x30, c["ares"])
        regs["vec"] = m.add_region(VEC_AT, 0x20, c["vec"])
    elif which == "c":
        regs["state"] = m.add_region(STATE_AT, 0x18, c["state"])
        m.add_region(SDATA_AT, 0x40, c["state_data"])
    else:
        regs["ctx"] = m.add_region(CTX_AT, 0x30, c["ctx"])
        m.add_region(SDATA_AT, 0x40, c["state_data"])
        m.add_region(D_A_AT, 0x1b20, w64(*([0] * 0x363)) + w64(c["a_word"]))
        m.add_region(LIST_AT, max(8, 0x20 * len(c["entries"])), b"".join(w64(*e) for e in c["entries"]))
    return regs


def run_case(m, c, which):
    m.reset()
    env = Env(m, c)
    env.install()
    regs = build_case_regions(m, c, which)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    if which == "a":
        m.regs[7], m.regs[6] = OUT_AT, CTX_AT
        entry = FN_A
    elif which == "b":
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT_AT, VEC_AT, ARES_AT, c["mode"]
        entry = FN_B
    elif which == "c":
        m.regs[7], m.regs[6], m.regs[2] = STATE_AT, c["a"], c["b"]
        entry = FN_C
    else:
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT_AT, D_A_AT, c["b"], CTX_AT
        entry = FN_D
    abort = None
    try:
        m.run(entry, limit=20000)
    except Abort as exc:
        abort = exc.kind
    got = {"calls": env.rec, "abort": abort}
    if abort is None:
        got["ret"] = sym(m.regs[0], 0)
        got["out"] = bytes(regs["out"][:0x30]) if which in "ab" else None
        got["regs_ok"] = [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == ENTRY_SP
        if which == "c":
            by = {p: bytes(b) for p, s, b in env.allocs}
            got["box"] = by.get(m.regs[0])
            got["leaf"] = next((bytes(b) for p, s, b in env.allocs if s == 0x70), None)
            got["clone"] = by.get(u(got["box"], 0x18, 8)) if got["box"] else None
    got["inputs_ok"] = all(bytes(regs[k]) == c[k] for k in ("ctx", "ares", "vec", "state") if k in regs)
    return got


def compare(c, want, got, which):
    if got["abort"] != want["abort"] or got["calls"] != want["calls"] or not got["inputs_ok"]:
        return False
    if want["abort"]:
        return True
    if not got["regs_ok"] or got["ret"] != want["ret"]:
        return False
    if which == "d":
        return True
    if which == "c":
        return (got["box"] == want["box"] and got["leaf"] == want["leaf"] and got["clone"] == want["clone"])
    return got["out"] == want["out"]


# ---------------------------------------------------------------- cases
CASES_PER_FUNCTION = 4200


def rstring(s, zero_cap=None):
    cap = 0 if (zero_cap if zero_cap is not None else s.bit(1, 3)) else int.from_bytes(s.take(8), "little") % 4096 + 1
    ptr = int.from_bytes(s.take(8), "little") % (1 << 46) | 0x1000
    return (cap, ptr & ~0xf if False else ptr, s.below(300))


def make_case(s, which, idx):
    gate = [0, 1, 0xffffffff, s.below(1 << 32)][s.below(4)]
    c = {"which": which, "idx": idx, "gate": gate, "out": s.take(OUT_SIZE + OUT_SLACK),
         "strs": [rstring(s) for _ in range(8)], "fw": [int(s.bit(1, 12)) for _ in range(3)],
         "isdir": [int(s.bit()) for _ in range(3)], "isfile": [int(s.bit()) for _ in range(3)],
         "joins": [rstring(s) for _ in range(2)],
         "alloc": [int.from_bytes(s.take(8), "little") % (1 << 45) | 0x10000 if not s.bit(1, 14) else 0 for _ in range(4)],
         "cp": [int(s.bit(1, 8)) and int.from_bytes(s.take(8), "little") | 1 for _ in range(2)],
         "mkdir": (int.from_bytes(s.take(8), "little") | 1) if s.bit(1, 8) else 0,
         "ioconv": int.from_bytes(s.take(8), "little"), "cpf": (int.from_bytes(s.take(8), "little") | 1) if s.bit(1, 8) else 0,
         "rm": int(s.bit()), "op09": int(s.bit()), "wstate": int(s.bit()),
         "mk": (int.from_bytes(s.take(8), "little") | 1) if s.bit(1, 8) else 0}
    c["strs"] = [(cap, ptr, ln) for cap, ptr, ln in c["strs"]]
    # keep every stub pointer distinct so a swapped argument cannot hide
    seen = set()
    for i, (cap, ptr, ln) in enumerate(c["strs"] + c["joins"]):
        while ptr in seen:
            ptr += 0x1111
        seen.add(ptr)
    c["static_word"] = int.from_bytes(s.take(8), "little")
    if which == "a":
        c["ctx"] = s.take(0x30)
        c["ctx_at"] = CTX_AT
    elif which == "b":
        in_ptr = int.from_bytes(s.take(8), "little") % (1 << 46) | 0x1000
        in_len = s.below(200)
        step = int.from_bytes(s.take(8), "little") >> (8 * s.below(8))
        c["ares"] = s.take(0x30)
        c["ares_at"] = ARES_AT
        c["vec"] = w64(int.from_bytes(s.take(8), "little"), in_ptr, in_len, step)
        c["in_ptr"], c["in_len"], c["step"] = in_ptr, in_len, step
        c["mode"] = [0, 1, 1, 1, 0x100, 0x7f, 2][s.below(7)] if idx % 4 else idx % 2
        c["mode"] = c["mode"] if c["mode"] & 0xff else 0
        c["cp"] = [int(s.bit(1, 10)) and int.from_bytes(s.take(8), "little") | 1 for _ in range(2)]
    else:
        if which == "d":
            c["a"], c["b"], c["a_word"] = D_A_AT, int.from_bytes(s.take(8), "little"), int.from_bytes(s.take(8), "little")
            ents = []
            for _ in range(s.below(6) if s.below(8) == 0 else 1 + s.below(5)):
                cap = [0, int.from_bytes(s.take(8), "little") % 4096 + 1, int.from_bytes(s.take(8), "little") % 4096 + 1,
                       int.from_bytes(s.take(8), "little") % 4096 + 1, SENT][s.below(5)]
                ents.append((cap, int.from_bytes(s.take(8), "little") % (1 << 46) | 0x1000, s.below(300),
                             c["b"] if s.bit(2, 3) else int.from_bytes(s.take(8), "little")))
            c["entries"] = ents
            c["lcap"] = [0, int.from_bytes(s.take(8), "little") % 64 + 1, int.from_bytes(s.take(8), "little") % 64 + 1,
                         SENT][s.below(4)] if s.below(10) else SENT
            c["lerr"] = int.from_bytes(s.take(8), "little")
            c["d0"] = rstring(s)
            c["ctx"] = w64(int.from_bytes(s.take(8), "little"), SDATA_AT, [0, 1, 7, 33, 64][s.below(5)]) + s.take(0x18)
            c["ctx_at"] = CTX_AT
        n_state = [0, 1, 7, 33, 64][s.below(5)]
        sdata = s.take(0x40)
        c["state_data"] = sdata
        c["state_len"] = n_state
        c["state_ptr"] = SDATA_AT
        c["state"] = w64(int.from_bytes(s.take(8), "little"), SDATA_AT, n_state)
        c["state_at"] = STATE_AT
        if which == "c":
            c["a"], c["b"] = int.from_bytes(s.take(8), "little"), int.from_bytes(s.take(8), "little")
        c["nitems"] = [0, 1, 2, 3, 5, 19, 20, 21, 22, 40][s.below(10)] if idx % 5 else [0, 1, 2, 21][idx // 5 % 4]
        c["tree"] = (int.from_bytes(s.take(8), "little"), s.below(5), s.below(100))
        c["alloc"] = [int.from_bytes(s.take(8), "little") % (1 << 40) * 0x100 + 0x100000 if not s.bit(1, 16) else 0
                      for _ in range(4)]
        c["alloc"] = [a + 0x1000 * k if a else 0 for k, a in enumerate(c["alloc"])]
        c["fw"] = [int(s.bit(1, 16)) for _ in range(3)]
    return c


def all_cases(which):
    s = Stream(f"re16-db-home-{which}-115")
    return [make_case(s, which, k) for k in range(CASES_PER_FUNCTION)]


MODELS = {"a": model_a, "b": model_b, "c": model_c, "d": model_d}
FUNCS = {"a": FN_A, "b": FN_B, "c": FN_C, "d": FN_D}


# ---------------------------------------------------------------- evaluation
def evaluate(image, which, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or TraceMachine(image, override)
    model = MODELS[which]
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else all_cases(which)):
        want = model(c, mut)
        try:
            got = run_case(m, c, which)
            ok = compare(c, want, got, which)
        except (ToolError, KeyError, IndexError) as exc:
            got, ok = {"error": f"{type(exc).__name__}", "calls": [], "abort": "error"}, False
        except Boundary as exc:
            got, ok = {"error": f"reached {exc.kind} stub", "calls": [], "abort": "boundary"}, False
        bad += not ok
        if stop_on_first and not ok:
            return None, bad, m
        rows.append((c, want, got, ok))
    return rows, bad, m


MODEL_MUTANTS = (
    ("a", "dir_inverted"), ("a", "gate_ignored"), ("a", "kind_one"), ("a", "name_len_11"), ("a", "sub_leak"),
    ("a", "out_short"),
    ("b", "mode_inverted"), ("b", "cp_flag_zero"),
    ("c", "sort_always_small"), ("c", "leaf_68"), ("c", "arc_weak_zero"), ("d", "key_off_by_one"),
)
# (function, va, old byte, new byte, what)
BYTE_MUTANTS = (
    ("a", 0x38b38db, 0x02, 0x01, "directory kind byte 2 -> 1"),
    ("a", 0x38b3950, 0x0a, 0x0b, "remove_dir name length 10 -> 11"),
    ("a", 0x38b38ca, 0x84, 0x85, "probe branch je -> jne"),
    ("b", 0x4468375, 0x01, 0x00, "first cp flag 1 -> 0"),
    ("b", 0x44682bb, 0xff, 0xfe, "create_dir mode 0x1ff -> 0x1fe"),
    ("b", 0x44682c3, 0x01, 0x00, "create_dir recursive byte 1 -> 0"),
    ("b", 0x44682ea, 0x84, 0x85, "mode branch je -> jne"),
    ("b", 0x44682f7, 0x02, 0x01, "directory kind byte 2 -> 1"),
    ("b", 0x4468478, 0x02, 0x03, "join_kind esi 2 -> 3"),
    ("c", 0x38b3b9d, 0x10, 0x18, "item vector allocation 0x10 -> 0x18"),
    ("c", 0x38b3c34, 0x70, 0x68, "leaf node allocation 0x70 -> 0x68"),
    ("c", 0x38b3d5d, 0x40, 0x38, "block allocation 0x40 -> 0x38"),
    ("c", 0x38b3c1d, 0x01, 0x02, "single-item test 1 -> 2"),
    ("c", 0x38b3e71, 0x15, 0x16, "small-sort bound 0x15 -> 0x16"),
    ("c", 0x38b3c74, 0x04, 0x03, "item stride shl 4 -> 3"),
    ("c", 0x38b3d40, 0x01, 0x02, "block strong count 1 -> 2"),
    ("c", 0x38b3d49, 0x01, 0x02, "block weak count 1 -> 2"),
    ("c", 0x38b3c06, 0x84, 0x85, "empty-items branch je -> jne"),
    ("d", 0x3915d67, 0x10, 0x18, "list argument offset 0x10 -> 0x18"),
    ("d", 0x3915d7e, 0x80, 0x81, "list error branch jo -> jno"),
    ("d", 0x3915d9d, 0x05, 0x04, "entry stride shl 5 -> 4"),
    ("d", 0x3915de3, 0x75, 0x74, "sentinel test jne -> je"),
    ("d", 0x3915dfc, 0x74, 0x75, "key test je -> jne"),
    ("d", 0x3915e7c, 0x05, 0x04, "buffer size shl 5 -> 4"),
    ("d", 0x3915ed4, 0xc9, 0xc8, "mode 0 -> stale ecx"),
)
# extra byte mutants whose bytes are flipped by one bit (the immediates and test operands of the flows)
BIT_MUTANTS = (
    ("a", 0x38b3880, "format pieces operand (lea rdx) of the first format"),
    ("b", 0x44683ad, "format pieces operand of the checkpoint text"),
    ("b", 0x4468686, "mode-0 path: pieces operand"),
    ("b", 0x44687a4, "tail free test"),
)


def controls(image, cache):
    rows = []
    for which, name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, which, mut=frozenset([name]), stop_on_first=True, cases=cache[which])
        rows.append(("model", f"{which}:{name}", int(bad > 0)))
    for which, va, old, new, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] != old:
            fail(f"byte mutant at {va:#x} expects {old:#04x}")
        _, bad, _ = evaluate(image, which, override={va: new}, stop_on_first=True, cases=cache[which])
        rows.append(("code", f"{va:#x}={new:#04x} {what}", int(bad > 0)))
    for which, va, what in BIT_MUTANTS:
        old = image.code(va, 1)[0]
        _, bad, _ = evaluate(image, which, override={va: old ^ 0x04}, stop_on_first=True, cases=cache[which])
        rows.append(("code", f"{va:#x} bit 2 flipped {what}", int(bad > 0)))
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


# ---------------------------------------------------------------- static evidence
def call_sites(decoded, lo, hi):
    out = []
    for va, fm in decoded:
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
    rows = fde_rows(image, list(FUNCS.values()))
    fns, site_rows, slot_rows = {}, [], {}
    for which, start in FUNCS.items():
        lo, hi = rows[start]
        decoded = sweep(image, lo, hi)
        rets = [va for va, fm in decoded if fm["op"] == 0xc3]
        if len(rets) != 1:
            fail("expected exactly one ret")
        pad = next(va for va, fm in decoded if va > rets[0])
        fns[which] = {"start": f"{lo:#x}", "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                      "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(), "instructions": len(decoded),
                      "ret": f"{rets[0]:#x}", "landing_pad_start": f"{pad:#x}"}
        for va, kind, target in call_sites(decoded, lo, hi):
            if kind == "got":
                tgt = image.relative.get(target)
                if target == MEMCPY_SLOT:
                    role, shown = "memcpy", "import memcpy"
                elif target in SLOT_ROLE:
                    role, shown = SLOT_ROLE[target], f"{tgt:#x}"
                    slot_rows[target] = (role, shown)
                elif target not in SLOTS:
                    fail(f"unexpected .got slot {target:#x}")
                else:
                    role, shown = ROLE[tgt], f"{tgt:#x}"
                    slot_rows[target] = (role, shown)
            elif kind == "register":
                role, shown, target = "indirect (error object drop through its vtable, or memcpy via r15)", "register", 0
            else:
                role = ROLE.get(target) or {FN_A: "trio callee a", FN_B: "trio callee b", FN_C: "trio callee c"}.get(target) \
                    or ("landing" if target in LANDING_DIRECT + (0x63f0a50,) else None)
                if role is None:
                    fail(f"unexpected direct call target {target:#x}")
                shown, target = f"{target:#x}", target
            site_rows.append((which, va, kind, target if kind == "got" else 0, shown, role, va >= pad))
    callers = {}
    for which, start in FUNCS.items():
        sites, relocs = caller_scan(image, start)
        callers[which] = {"e8_rel32_sites": [f"{v:#x}" for v in sites], "relative_addends": [f"{v:#x}" for v in relocs]}
    if [callers[k]["e8_rel32_sites"] for k in "abc"] != [["0x3915eb4", "0x434bb32"], ["0x3915ed5", "0x434bb4f"],
                                                         ["0x3915ee4", "0x434bb5e"]] or any(callers[k]["relative_addends"] for k in "abc"):
        fail("caller sets changed")
    return {"binary_sha256": SHA256, "functions": fns, "callers": callers,
            "gate_word": f"{GATE_WORD:#x}", "kind_display_slot": f"{KIND_FN_SLOT:#x}",
            "step_display_slot": f"{STEP_FN_SLOT:#x}"}, site_rows, slot_rows


# ---------------------------------------------------------------- format texts and operation plans
def parse_pieces(image, va):
    """Compact format text at va: 0xc0 = placeholder, then the length of the next literal (0 ends); a literal
    is followed by 0 (end) or 0xc0 (next placeholder).  Returns the rendered text and the placeholder count."""
    p, parts = va, []
    while True:
        if image.read(p, 1)[0] != 0xc0:
            fail(f"format text at {va:#x} does not start a placeholder at {p:#x}")
        parts.append("{}")
        n = image.read(p + 1, 1)[0]
        p += 2
        if n == 0:
            break
        parts.append(image.read(p, n).decode("ascii"))
        p += n
        if image.read(p, 1)[0] == 0:
            break
    return "".join(parts), parts.count("{}")


FS_OPS = ("is_dir", "create_dir", "cp", "join_kind", "is_file", "op_09e0", "copy_file", "write_state", "remove_dir", "mk")


def plan_of(calls):
    """The ordered file-system operations of a call trace (probes included, formats and frees dropped)."""
    return tuple(c[0] for c in calls if c[0] in FS_OPS)


def b_full_plans():
    """Every complete operation order of 0x44681e0: create_dir only after a negative probe, mode 0 copies once."""
    full = set()
    for made in ((), ("create_dir",)):
        head = ("is_dir",) + made + ("cp",)
        full.add(head + ("write_state",))
        full.add(head + ("join_kind", "is_file", "write_state"))
        for copied in ((), ("copy_file",)):
            full.add(head + ("join_kind", "is_file", "cp", "join_kind", "op_09e0", "is_file") + copied + ("write_state",))
    return full


def plan_errors(which, plan, mode_zero, aborted, mut=""):
    """Structural invariants of the operation order; an empty list means the plan is consistent."""
    errs = []
    if which == "a":
        if plan not in {(), ("is_dir",), ("is_dir", "is_dir"), ("is_dir", "is_dir", "remove_dir")}:
            errs.append("a: order")
    elif which == "b":
        full = b_full_plans()
        if aborted:
            if not any(f[:len(plan)] == plan for f in full):
                errs.append("b: aborted plan is not a prefix of a full plan")
        elif plan not in full:
            errs.append("b: complete plan is not a full plan")
        if mode_zero and ("join_kind" in plan or "copy_file" in plan or plan.count("cp") > 1):
            errs.append("b: mode 0 took the checkpoint route")
    elif which == "c":
        if plan not in {(), ("mk",)}:
            errs.append("c: order")
    elif which == "d":
        if any(op in plan for op in ("join_kind", "copy_file", "op_09e0")) or plan.count("cp") > 1:
            errs.append("d: mode 0 route left the source copy")
        if plan.count("write_state") > 1 or ("write_state" in plan and plan[-1] != "write_state" and
                                             plan[-1] != "mk"):
            errs.append("d: state write is not the last file-system operation")
    return errs


def plan_controls(rows_by_func):
    """Mutate real plans; every mutation must violate an invariant (counts how many do)."""
    out = []
    a = next(plan_of(g["calls"]) for c, w, g, ok in rows_by_func["a"] if plan_of(g["calls"]) == ("is_dir", "is_dir", "remove_dir"))
    b1 = next(plan_of(g["calls"]) for c, w, g, ok in rows_by_func["b"]
              if not g["abort"] and c["mode"] & 0xff and "op_09e0" in plan_of(g["calls"]))
    b0 = next(plan_of(g["calls"]) for c, w, g, ok in rows_by_func["b"] if not g["abort"] and not c["mode"] & 0xff)
    d = next(plan_of(g["calls"]) for c, w, g, ok in rows_by_func["d"] if not g["abort"])
    tests = (
        ("a: remove_dir before the second probe", "a", ("is_dir", "remove_dir", "is_dir"), False, False),
        ("a: remove_dir twice", "a", a + ("remove_dir",), False, False),
        ("b: write_state dropped", "b", b1[:-1], False, False),
        ("b: cp and join swapped", "b", b1[:b1.index("cp")] + ("join_kind", "cp") + b1[b1.index("cp") + 2:], False, False),
        ("b: copy_file without the marker probe", "b", b1[:-1].__class__(x for x in b1 if x != "is_file"), False, False),
        ("b: mode 0 with a join", "b", b0[:-1] + ("join_kind",) + b0[-1:], False, True),
        ("b: create_dir after cp", "b", ("is_dir", "cp", "create_dir", "write_state"), False, True),
        ("d: join in the mode-0 route", "d", d[:-1] + ("join_kind",) + d[-1:], False, True),
        ("d: two source copies", "d", d[:-1] + ("cp",) + d[-1:], False, True),
    )
    for name, which, plan, aborted, mode_zero in tests:
        out.append(("plan", name, int(bool(plan_errors(which, plan, mode_zero, aborted)))))
    return out


# ---------------------------------------------------------------- output
def generate(out):
    image = Image(BINARY.read_bytes())
    load_consts(image)
    consts, site_rows, slot_rows = static_evidence(image)
    out.mkdir(parents=True, exist_ok=True)
    pieces_rows = []
    for va, nargs in sorted(PIECES.items()):
        text, n = parse_pieces(image, va)
        if n != nargs:
            fail(f"format text {va:#x} has {n} placeholders, the harness expects {nargs}")
        pieces_rows.append((va, text, n))
    (out / "format-pieces.tsv").write_text(
        "address\ttext\tplaceholders\n" + "".join(f"{va:#x}\t{t}\t{n}\n" for va, t, n in pieces_rows))
    cache = {w: all_cases(w) for w in "abcd"}
    summary_f, lines, seen_all = {}, ["function\tcase\tmode\tgate\tabort\tcalls\tout_sha256_16\tmatch"], {}
    classes, plans, plan_bad, rows_by_func = {}, {}, 0, {}
    total_bad = total_cases = 0
    for which in "abcd":
        rows, bad, m = evaluate(image, which, cases=cache[which])
        seen_all[which] = m.seen
        rows_by_func[which] = rows
        total_bad += bad
        total_cases += len(rows)
        for c, want, got, ok in rows:
            plan = plan_of(got["calls"])
            mode_zero = which in "d" or (which == "b" and not c["mode"] & 0xff)
            errs = plan_errors(which, plan, mode_zero, bool(got.get("abort")))
            plan_bad += bool(errs)
            pkey = (which, "mode0" if mode_zero else ("-" if which != "b" else "mode1"), got.get("abort") or "ok",
                    " ".join(plan) or "-")
            plans[pkey] = plans.get(pkey, 0) + 1
            key = (which, got.get("abort") or "ok", "gate" if c["gate"] else "quiet")
            classes[key] = classes.get(key, 0) + 1
            if c["idx"] % 8 == 0:
                digest = hashlib.sha256(got.get("out") or got.get("box") or b"-").hexdigest()[:16] if not got.get("error") \
                    else got["error"]
                lines.append(f"{which}\t{c['idx']}\t{c.get('mode', '-')}\t{c['gate'] != 0:d}\t{got.get('abort') or '-'}\t"
                             f"{len(got['calls'])}\t{digest}\t{'yes' if ok else 'NO'}")
        summary_f[which] = {"cases": len(rows), "mismatches": bad}
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "operation-plans.tsv").write_text(
        "function\troute\toutcome\toperations\tcases\n"
        + "".join(f"{k[0]}\t{k[1]}\t{k[2]}\t{k[3]}\t{v}\n" for k, v in sorted(plans.items())))
    (out / "outcome-classes.tsv").write_text(
        "function\toutcome\tgate\tcases\n" + "".join(f"{k[0]}\t{k[1]}\t{k[2]}\t{v}\n" for k, v in sorted(classes.items())))
    (out / "call-sites.tsv").write_text(
        "function\tsite\tkind\tgot_slot\ttarget\trole\tlanding_pad\n"
        + "".join(f"{FUNCS[w]:#x}\t{va:#x}\t{kind}\t{slot:#x}\t{shown}\t{role}\t{int(pad)}\n"
                  for w, va, kind, slot, shown, role, pad in site_rows))
    (out / "slot-roles.tsv").write_text(
        "got_slot\ttarget\trole\n" + "".join(f"{s:#x}\t{t}\t{r}\n" for s, (r, t) in sorted(slot_rows.items())))
    lines = ["function\taddress\tbytes\tregion\texecuted"]
    for which, start in FUNCS.items():
        lo, hi = fde_rows(image, [start])[start]
        decoded = sweep(image, lo, hi)
        pad = int(consts["functions"][which]["landing_pad_start"], 16)
        hit = tot = hit2 = tot2 = 0
        for va, f in decoded:
            run = int(va in seen_all[which])
            if va < pad:
                hit += run
                tot += 1
            else:
                hit2 += run
                tot2 += 1
            lines.append(f"{start:#x}\t{va:#x}\t{f['bytes'].hex()}\t{'body' if va < pad else 'after-ret'}\t{run}")
        summary_f[which]["body_instructions_executed"] = [hit, tot]
        summary_f[which]["after_ret_instructions_executed"] = [hit2, tot2]
    (out / "instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = controls(image, cache) + plan_controls(rows_by_func)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": total_cases, "mismatches": total_bad, "plan_violations": plan_bad, "operation_plans": len(plans),
               "functions": summary_f,
               "outcome_classes": len(classes), "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    measure = {"cases": total_cases, "negative_controls": len(ctl), "negative_detected": sum(r[2] for r in ctl)}
    (out / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    bad = (summary["mismatches"] or summary["plan_violations"]
           or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
