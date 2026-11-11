#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM context, block, memory-range and log opcode bodies.

Both RELATIVE opcode tables 0x6441210 and 0x6441f00 (index = opcode) name the same body for every opcode in
three families, each a part of this tool with its own reconstruction, harness, cases and negative controls:

  context-reads  19 bodies for 0x30 0x32 0x33 0x34 0x35 0x36 0x38 0x3a 0x41 0x42 0x43 0x45 0x46 0x48 0x49 0x4a
                 0x4b 0x50 0x5a (ADDRESS .. GAS): push bound 0x400 (0x2d), empty-stack pops (0x2c), spec-byte
                 gates (0x2b), byte-swapped 20-byte addresses, GASPRICE cap, BLOBHASH, CALLDATALOAD padding;
  memory-range   KECCAK256, CODECOPY and MCOPY: memory expansion and word cost, copy / zero-fill / overlap
                 rules and the in-binary Keccak sponge run for real;
  log-emit       LOG0..LOG4: static-call refusal, length and offset limbs, data and topic cost, memory
                 expansion call, owned data copy, big-endian topics and the 0x50-byte log record.

The tool reads every relocation, FDE extent and code byte from the ELF file (shared parsers tools/elf_index.py
and tools/fde_extents.py), evaluates the real machine code with one small concrete x86-64 evaluator (no
external programs; the binary is never executed; imports, allocators and out-of-family callees are contract
stubs named in each part) and compares every case with a pure-Python reconstruction.  Negative controls show
that wrong reconstructions, corrupted code bytes and out-of-range inputs are detected.
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
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x87, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f1e, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
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


# ================================================================ context-reads
RD_OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); both name the same bodies here
RD_SLOAD_OP, RD_SLOAD_BODIES = 0x54, (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 holds an SLOAD handler copy
RD_BODIES = {  # opcode -> body named by both tables; EVM names are inferred from the opcode number and the reads
    0x30: (0x2997f50, "ADDRESS"), 0x32: (0x2999720, "ORIGIN"), 0x33: (0x2997ef0, "CALLER"),
    0x34: (0x2998290, "CALLVALUE"), 0x35: (0x2997a50, "CALLDATALOAD"), 0x36: (0x2997b70, "CALLDATASIZE"),
    0x38: (0x2998240, "CODESIZE"), 0x3a: (0x2999780, "GASPRICE"), 0x41: (0x2b95880, "COINBASE"),
    0x42: (0x2b95970, "TIMESTAMP"), 0x43: (0x2b957a0, "NUMBER"), 0x45: (0x2b958e0, "GASLIMIT"),
    0x46: (0x2b95830, "CHAINID"), 0x48: (0x2b957e0, "BASEFEE"), 0x49: (0x2999830, "BLOBHASH"),
    0x4a: (0x2b95730, "BLOBBASEFEE"), 0x4b: (0x2b95920, "OP4B"), 0x50: (0x2995df0, "POP"),
    0x5a: (0x2997eb0, "GAS"),
}
RD_EXCLUDED = {0x44: 0x2b95670}  # owned by an existing packet; slot checked only
RD_CLAIMED = tuple(sorted(v[0] for v in RD_BODIES.values()))
RD_MEMCPY_SLOT = 0x64df508  # GLOB_DAT .got slot called by CALLDATALOAD
RD_GATES = {0x46: 0x06, 0x48: 0x08, 0x49: 0x0b, 0x4a: 0x0b, 0x4b: 0x0e}  # interpreter +0x1a9 spec byte minimum
RD_REPLACE = (0x35, 0x49)  # read the top word and replace it
RD_I_STACK_PTR, RD_I_STACK_LEN, RD_I_GAS, RD_I_SPEC = 0x28, 0x30, 0x188, 0x1a9
RD_I_CD_KIND, RD_I_CD_A, RD_I_CD_B, RD_I_CD_OBJ, RD_I_CODE = 0x38, 0x40, 0x48, 0x10, 0x120
RD_STACK_LIMIT = 0x400
RD_R_OK, RD_R_NOT_ACTIVATED, RD_R_UNDERFLOW, RD_R_OVERFLOW = 0x00, 0x2b, 0x2c, 0x2d
RD_SAVED_REGS = (3, 5, 12, 13, 14, 15)

RD_INTERP_AT, RD_INTERP_SIZE = 0x7d00_0000_0000, 0x1b0
RD_CTX_AT, RD_CTX_SIZE = 0x7d00_0100_0000, 0x260
RD_STK_AT = 0x7d00_0300_0000
RD_CODE_AT, RD_CODE_SIZE = 0x7d00_0400_0000, 0x60
RD_OBJ_AT, RD_OBJ_SIZE = 0x7d00_0500_0000, 0x30
RD_CD_AT, RD_CD_SIZE = 0x7d00_0600_0000, 0x200
RD_BLOB_AT = 0x7d00_0700_0000
RD_STACK_FILL, RD_SLACK_FILL = 0x5a, 0x7c
RD_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


# ---------------------------------------------------------------- reconstruction
def rd_le(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


def rd_be(b, off, n):
    return int.from_bytes(b[off:off + n], "big")


def rd_sat64(w, mut=frozenset()):
    """A 256-bit word as a u64 index: values with any high limb set become 2^64 - 1."""
    if "index_truncates" in mut:
        return w & M64
    return w if w <= M64 else M64


def rd_calldata(c, mut=frozenset()):
    """The calldata view: kind != 0 -> (+0x40 pointer, +0x48 length); kind 0 -> shared buffer (+0x10 object,
    base at object +0x20) sliced by (+0x40 start, +0x48 end), length saturating at 0."""
    it = c["interp"]
    if rd_le(it, RD_I_CD_KIND, 8):
        start, n = rd_le(it, RD_I_CD_A, 8) - RD_CD_AT, rd_le(it, RD_I_CD_B, 8)
    else:
        a, b = rd_le(it, RD_I_CD_A, 8), rd_le(it, RD_I_CD_B, 8)
        n = (b - a) & M64 if "size_wraps" in mut else max(b - a, 0)
        start = rd_le(c["obj"], 0x20, 8) + a - RD_CD_AT
    return start, n


def rd_gas_price(x, mut=frozenset()):
    gp = rd_le(x, 0x130, 16)
    eip1559 = x[0x1f1] >= 2 or "price_any_type" in mut
    if eip1559 and x[0xe0] != 0:
        s = rd_le(x, 0x98, 8) + rd_le(x, 0xf0, 16)
        s = s & M128 if "price_wraps" in mut else min(s, M128)
        gp = max(gp, s) if "price_max" in mut else min(gp, s)
    return gp


def rd_value(c, mut=frozenset()):
    op, it, x = c["op"], c["interp"], c["ctx"]
    if op == 0x30:
        return rd_le(it, 0x78, 20) if "address_le" in mut else rd_be(it, 0x78, 20)
    if op == 0x33:
        return rd_be(it, 0x88 if "caller_off" in mut else 0x8c, 20)
    if op == 0x34:
        return rd_be(it, 0x58, 32) if "callvalue_be" in mut else rd_le(it, 0x58, 32)
    if op == 0x35:
        off = rd_sat64(c["top"][-1], mut)
        start, n = rd_calldata(c, mut)
        if off >= n:
            return 0
        k = min(32, n - off) if "load_unpadded" not in mut else 32
        chunk = c["cd"][start + off:start + off + k]
        return int.from_bytes(chunk + bytes(32 - len(chunk)), "big")
    if op == 0x36:
        return rd_calldata(c, mut)[1]
    if op == 0x38:
        return rd_le(c["code"], 0x50, 8)
    if op == 0x5a:
        return rd_le(it, RD_I_GAS, 8)
    if op == 0x32:
        return rd_be(x, 0x1c8, 20)
    if op == 0x41:
        return rd_be(x, 0xa8, 20)
    if op == 0x42:
        return rd_le(x, 0x50, 8) if "timestamp_low" in mut else rd_le(x, 0x50, 32)
    if op == 0x43:
        return rd_le(x, 0x30, 32)
    if op == 0x45:
        return rd_le(x, 0x90, 8)
    if op == 0x46:
        return rd_le(x, 0x258, 8)
    if op == 0x48:
        return rd_le(x, 0x98, 8)
    if op == 0x4b:
        return rd_le(x, 0xa0, 8)
    if op == 0x4a:
        return rd_le(x, 0x10, 16) if x[0] & 1 or "blobfee_ignores_flag" in mut else 0
    if op == 0x3a:
        return rd_gas_price(x, mut)
    if op == 0x49:
        idx = rd_sat64(c["top"][-1], mut)
        if (x[0x1f1] == 3 or "blobhash_any_type" in mut) and idx < rd_le(x, 0x198, 8):
            h = c["blobs"][32 * idx:32 * idx + 32]
            return int.from_bytes(h, "little" if "blobhash_le" in mut else "big")
        return 0
    fail(f"no value model for opcode {op:#x}")


def rd_model(c, mut=frozenset()):
    """Result code, new stack length and written stack slots after one body."""
    op, n = c["op"], c["n"]
    gate = RD_GATES.get(op)
    if "chainid_gate_7" in mut and op == 0x46:
        gate = 7
    if "basefee_ungated" in mut and op == 0x48:
        gate = None
    if gate is not None and c["interp"][RD_I_SPEC] < gate:
        return {"ret": RD_R_NOT_ACTIVATED, "n": n, "writes": {}}
    if op == 0x50:
        if n == 0 and "pop_wraps" not in mut:
            return {"ret": RD_R_UNDERFLOW, "n": n, "writes": {}}
        return {"ret": RD_R_OK, "n": (n - 1) & M64, "writes": {}}
    if op in RD_REPLACE:
        if n == 0:
            return {"ret": RD_R_UNDERFLOW, "n": n, "writes": {}}
        return {"ret": RD_R_OK, "n": n, "writes": {n - 1: rd_value(c, mut)}}
    limit = RD_STACK_LIMIT - 1 if "limit_1023" in mut else RD_STACK_LIMIT
    if n >= limit:
        return {"ret": RD_R_OVERFLOW, "n": n, "writes": {}}
    return {"ret": RD_R_OK, "n": n + 1, "writes": {n: rd_value(c, mut)}}


# ---------------------------------------------------------------- harness
def rd_regs_ok(m):
    return [m.regs[k] for k in RD_SAVED_REGS] == RD_SAVED and m.regs[4] == STACK_TOP - 0x100


def rd_window(c):
    """Mapped stack slots: the two words under the top and two free slots above it (index lo .. n + 1)."""
    lo = max(c["n"] - 2, 0)
    return lo, c["n"] + 2 - lo


def rd_stack_image(c):
    lo, slots = rd_window(c)
    raw = bytearray([RD_SLACK_FILL]) * (32 * slots)
    for i, w in enumerate(c["top"]):
        k = c["n"] - len(c["top"]) + i - lo
        raw[32 * k:32 * k + 32] = w.to_bytes(32, "little")
    return bytes(raw)


def rd_memcpy_stub(m):
    dst, src, n = m.regs[7], m.regs[6], m.regs[2]
    if n > 32:
        fail(f"memcpy of {n} bytes")
    for i in range(n):
        m.store(dst + i, 1, m.load(src + i, 1))
    m.regs[0] = dst
    m.memcpy_calls += 1


def rd_run_case(m, c):
    m.reset()
    m.memcpy_calls = 0
    m.stubs[m.image.relative[RD_MEMCPY_SLOT]] = rd_memcpy_stub
    m.regions[0][2][:] = bytes([RD_STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(RD_INTERP_AT, RD_INTERP_SIZE, c["interp"])
    x = m.add_region(RD_CTX_AT, RD_CTX_SIZE, c["ctx"])
    code = m.add_region(RD_CODE_AT, RD_CODE_SIZE, c["code"])
    obj = m.add_region(RD_OBJ_AT, RD_OBJ_SIZE, c["obj"])
    cd = m.add_region(RD_CD_AT, RD_CD_SIZE, c["cd"])
    blobs = m.add_region(RD_BLOB_AT, max(len(c["blobs"]), 32), c["blobs"])
    lo, slots = rd_window(c)
    stk = m.add_region(RD_STK_AT + 32 * lo, 32 * slots, rd_stack_image(c))
    side = bytes(x) + bytes(code) + bytes(obj) + bytes(cd) + bytes(blobs)
    for k, v in zip(RD_SAVED_REGS, RD_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = RD_INTERP_AT, RD_CTX_AT
    m.run(c["body"], limit=20000)
    rest = bytearray(it)
    rest[RD_I_STACK_LEN:RD_I_STACK_LEN + 8] = c["interp"][RD_I_STACK_LEN:RD_I_STACK_LEN + 8]
    return {"ret": m.regs[0] & 0xff, "n": u(it, RD_I_STACK_LEN, 8), "stack_raw": bytes(stk), "regs_ok": rd_regs_ok(m),
            "interp_ok": bytes(rest) == c["interp"], "side_ok": bytes(x) + bytes(code) + bytes(obj) + bytes(cd)
            + bytes(blobs) == side, "memcpy": m.memcpy_calls}


def rd_expected_raw(c, want):
    lo, _ = rd_window(c)
    raw = bytearray(rd_stack_image(c))
    for k, w in want["writes"].items():
        raw[32 * (k - lo):32 * (k - lo) + 32] = w.to_bytes(32, "little")
    return bytes(raw)


def rd_compare(c, want, got):
    return (want["ret"] == got["ret"] and want["n"] == got["n"] and got["regs_ok"] and got["interp_ok"]
            and got["side_ok"] and got["stack_raw"] == rd_expected_raw(c, want))


# ---------------------------------------------------------------- cases
RD_CASES = 6000
RD_OPS = sorted(RD_BODIES)
RD_EDGE = (0, 1, 2, 31, 32, 33, 0xff, M64 - 1, M64, 1 << 64, (1 << 64) + 1, M128, 1 << 128, M256)
RD_SPECS = (0, 5, 6, 7, 8, 0xa, 0xb, 0xd, 0xe, 0x11, 0xff)
RD_MODES = ("random", "edge", "full-stack", "empty-stack", "gate-edge", "1559", "saturate", "short-data",
         "view-kind0", "inverted-view", "blob-hit", "random", "near-full")


def rd_rand_word(s):
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def rd_make_case(s, k):
    op = RD_OPS[k % len(RD_OPS)]
    mode = RD_MODES[(k // len(RD_OPS)) % len(RD_MODES)]
    it = bytearray(s.take(RD_INTERP_SIZE))
    x = bytearray(s.take(RD_CTX_SIZE))
    obj = bytearray(s.take(RD_OBJ_SIZE))
    cd = bytes(s.take(RD_CD_SIZE))
    nb = s.below(5)
    blobs = bytes(s.take(32 * nb))
    n = s.pick((1, 2, 3, 17, 0x3fe, 0x3ff))
    if mode == "full-stack":
        n = RD_STACK_LIMIT
    elif mode == "empty-stack":
        n = 0
    elif mode == "near-full":
        n = s.pick((0x3fe, 0x3ff, RD_STACK_LIMIT))
    top = [rd_rand_word(s) for _ in range(min(n, 2))]
    it[RD_I_SPEC] = s.pick(RD_SPECS)
    if mode == "gate-edge" and op in RD_GATES:
        it[RD_I_SPEC] = RD_GATES[op] - s.pick((0, 1))
    put(it, RD_I_STACK_PTR, 8, RD_STK_AT)
    put(it, RD_I_STACK_LEN, 8, n)
    put(it, RD_I_CODE, 8, RD_CODE_AT)
    put(it, RD_I_CD_OBJ, 8, RD_OBJ_AT)
    # calldata view: a direct slice or a slice of a shared buffer; never a null data pointer
    kind0 = mode in ("view-kind0", "inverted-view") or s.below(2) == 0
    length = s.pick((0, 1, 4, 31, 32, 33, 68, 100, 0x100))
    first = s.below(RD_CD_SIZE - 0x100 - 48) + 48
    if kind0:
        put(it, RD_I_CD_KIND, 8, 0)
        base = s.below(4) * 8 + 8
        put(obj, 0x20, 8, RD_CD_AT + base)
        a = first - base
        b = a + length if mode != "inverted-view" else max(a - s.pick((1, 2, 40)), 0)
        put(it, RD_I_CD_A, 8, a)
        put(it, RD_I_CD_B, 8, b)
    else:
        put(it, RD_I_CD_KIND, 8, s.pick((1, 2, 0x8000, int.from_bytes(s.take(8), "little") | 1)))
        put(it, RD_I_CD_A, 8, RD_CD_AT + first)
        put(it, RD_I_CD_B, 8, length)
    if op == 0x35 and n:
        if mode in ("edge", "short-data"):
            top[-1] = s.pick(RD_EDGE + (length, length - 1, length - 31, length - 32, length + 1)) & M256
        elif s.below(3):
            top[-1] = s.below(length + 40)
    x[0x1f1] = s.pick((0, 1, 2, 3, 4, x[0x1f1]))
    if mode in ("1559", "saturate"):
        x[0xe0] = s.pick((0, 1, 1, 0x80))
        x[0x1f1] = s.pick((1, 2, 3, 4))
    if mode == "saturate":
        put(x, 0x98, 8, s.pick((M64, M64 - 1, int.from_bytes(s.take(8), "little"))))
        put(x, 0xf0, 16, s.pick((M128, M128 - 1, M128 - M64, M128 - (1 << 64))))
        put(x, 0x130, 16, s.pick((M128, M128 - 1, rd_rand_word(s) & M128)))
    elif mode == "1559" or s.below(2):
        bf, tip = s.below(1 << s.pick((8, 34, 64))), s.below(1 << s.pick((8, 34, 64)))
        put(x, 0x98, 8, bf)
        put(x, 0xf0, 16, tip)
        put(x, 0x130, 16, bf + tip + s.pick((-1, 0, 1, 5, -5, 1 << 40)) if bf + tip > 5 else s.below(9))
    put(x, 0x190, 8, RD_BLOB_AT)
    put(x, 0x198, 8, nb)
    if op == 0x49 and n:
        if mode == "blob-hit":
            x[0x1f1] = 3
            top[-1] = s.below(nb + 1)
        elif mode == "edge":
            top[-1] = s.pick(RD_EDGE)
        else:
            x[0x1f1] = s.pick((3, 3, x[0x1f1]))
            top[-1] = s.pick((s.below(nb + 2), s.below(nb + 1), rd_rand_word(s)))
    if op == 0x4a and mode == "edge":
        x[0] = s.pick((0, 1, 2, 3, 0xfe))
    return {"op": op, "body": RD_BODIES[op][0], "mode": mode, "n": n, "top": top, "interp": bytes(it),
            "ctx": bytes(x), "code": bytes(s.take(RD_CODE_SIZE)), "obj": bytes(obj), "cd": cd, "blobs": blobs}


def rd_all_cases():
    s = Stream("re11-context-reads-115")
    return [rd_make_case(s, k) for k in range(RD_CASES)]


# ---------------------------------------------------------------- static evidence
RD_CHECKED = (
    (0x2997f54, "48 3d 00 04 00 00", "ADDRESS: stack length 0x400 = full (push arms share this bound)"),
    (0x2997f9e, "b0 2d", "ADDRESS: result 0x2d (stack overflow)"),
    (0x2997f5c, "8b 4f 78", "ADDRESS: 20-byte address at interpreter +0x78 (bswapped dword + 2 qwords)"),
    (0x2997efc, "8b 8f 8c 00 00 00", "CALLER: 20-byte address at interpreter +0x8c"),
    (0x29982a7, "0f 10 47 68", "CALLVALUE: native 32-byte word at interpreter +0x58..+0x78"),
    (0x2997a57, "0f 84 01 01 00 00", "CALLDATALOAD: empty stack -> 0x2c"),
    (0x2997aae, "48 83 f9 20", "CALLDATALOAD: remaining length capped at 32"),
    (0x2997ab2, "ba 20 00 00 00", "CALLDATALOAD: copy length 32 when at least 32 remain"),
    (0x2997b70, "48 83 7f 38 00", "CALLDATASIZE: interpreter +0x38 selects direct slice or shared view"),
    (0x2997bb8, "48 2b 4f 40", "CALLDATASIZE: view length end - start (saturating at 0 by cmovae)"),
    (0x2998253, "48 8b 49 50", "CODESIZE: [interpreter +0x120] +0x50"),
    (0x2997ebc, "48 8b 8f 88 01 00 00", "GAS: interpreter +0x188 = remaining gas"),
    (0x2999780, "80 be f1 01 00 00 02", "GASPRICE: context +0x1f1 (transaction type) >= 2 for the fee-market arm"),
    (0x2999797, "80 be e0 00 00 00 00", "GASPRICE: context +0xe0 = priority fee present"),
    (0x29997b5, "48 83 d6 00", "GASPRICE: base fee + priority fee carry (saturated to 2^128 - 1)"),
    (0x29997c8, "48 39 c2", "GASPRICE: min(max fee, base fee + priority fee)"),
    (0x299972c, "8b 8e c8 01 00 00", "ORIGIN: 20-byte address at context +0x1c8"),
    (0x2b9588c, "8b 8e a8 00 00 00", "COINBASE: 20-byte address at context +0xa8"),
    (0x2b9597c, "48 8b 4e 68", "TIMESTAMP: 32-byte word at context +0x50 (limb 3 at +0x68)"),
    (0x2b957b7, "0f 10 46 30", "NUMBER: 32-byte word at context +0x30"),
    (0x2b958ec, "48 8b 8e 90 00 00 00", "GASLIMIT: u64 at context +0x90"),
    (0x2b95830, "80 bf a9 01 00 00 06", "CHAINID: spec byte interpreter +0x1a9 >= 6"),
    (0x2b95845, "48 8b 8e 58 02 00 00", "CHAINID: u64 at context +0x258"),
    (0x2b957e0, "80 bf a9 01 00 00 08", "BASEFEE: spec byte >= 8"),
    (0x2b957f5, "48 8b 8e 98 00 00 00", "BASEFEE: u64 at context +0x98"),
    (0x2999830, "80 bf a9 01 00 00 0b", "BLOBHASH: spec byte >= 0xb"),
    (0x2999844, "0f 84 95 00 00 00", "BLOBHASH: empty stack -> 0x2c"),
    (0x2999874, "80 be f1 01 00 00 03", "BLOBHASH: only transaction type 3 reads the hash list"),
    (0x2b95730, "80 bf a9 01 00 00 0b", "BLOBBASEFEE: spec byte >= 0xb"),
    (0x2b95739, "f6 06 01", "BLOBBASEFEE: context +0x0 bit 0 = blob fee present"),
    (0x2b95920, "80 bf a9 01 00 00 0e", "OP4B: spec byte >= 0xe"),
    (0x2b95935, "48 8b 8e a0 00 00 00", "OP4B: u64 at context +0xa0"),
    (0x2995df4, "48 85 c0", "POP: empty stack test"),
    (0x2995e03, "b0 2c", "POP: result 0x2c (stack underflow)"),
)


def rd_expected_calls(f):
    return [(0x2997b0d, "got", RD_MEMCPY_SLOT)] if f == 0x2997a50 else []


def rd_opcode_slots(image):
    rows = {}
    for table in RD_OP_TABLES:
        if image.relative.get(table + 8 * RD_SLOAD_OP) not in RD_SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op, body in sorted(list((o, b[0]) for o, b in RD_BODIES.items()) + list(RD_EXCLUDED.items())):
            got = image.relative.get(table + 8 * op)
            if got != body:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}",
                                               "claimed": op in RD_BODIES}
    return rows


def rd_sweep_padded(image, lo, hi):
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


def rd_call_sites(decoded, lo, hi):
    """Every call, indirect jump or out-of-body jmp of a decoded body: (address, kind, target)."""
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


def rd_static_evidence(image):
    if RD_MEMCPY_SLOT not in image.imports or image.import_name(RD_MEMCPY_SLOT) != "memcpy":
        fail("CALLDATALOAD .got slot does not import memcpy")
    rows = fde_rows(image, list(RD_CLAIMED))
    decoded, funcs = {}, {}
    names = {b: (op, name) for op, (b, name) in RD_BODIES.items()}
    for f in RD_CLAIMED:
        lo, hi = rows[f]
        decoded[f] = rd_sweep_padded(image, lo, hi)
        calls = rd_call_sites(decoded[f], lo, hi)
        if calls != rd_expected_calls(f):
            fail(f"body {f:#x} has unexpected calls {[(hex(a), k) for a, k, _ in calls]}")
        op, name = names[f]
        funcs[f"{f:#x}"] = {"opcode": f"{op:#x}", "inferred_name": name, "fde_end": f"{hi:#x}",
                            "fde_bytes": hi - lo, "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "calls": len(calls), "spec_gate": f"{RD_GATES[op]:#x}" if op in RD_GATES else None}
    checks = {}
    for va, hx, what in RD_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": rd_opcode_slots(image),
           "checked_bytes": checks, "memcpy_got_slot": f"{RD_MEMCPY_SLOT:#x}",
           "interpreter_offsets": {"stack_ptr": f"{RD_I_STACK_PTR:#x}", "stack_len": f"{RD_I_STACK_LEN:#x}",
                                   "gas_remaining": f"{RD_I_GAS:#x}", "spec_byte": f"{RD_I_SPEC:#x}",
                                   "calldata_kind": f"{RD_I_CD_KIND:#x}", "calldata_ptr_or_start": f"{RD_I_CD_A:#x}",
                                   "calldata_len_or_end": f"{RD_I_CD_B:#x}", "calldata_shared": f"{RD_I_CD_OBJ:#x}",
                                   "code_object": f"{RD_I_CODE:#x}", "address": "0x78", "caller": "0x8c",
                                   "call_value": "0x58"},
           "context_offsets": {"tx_type": "0x1f1", "gas_price_max_fee_u128": "0x130", "priority_fee_present": "0xe0",
                               "priority_fee_u128": "0xf0", "base_fee": "0x98", "origin": "0x1c8",
                               "coinbase": "0xa8", "timestamp": "0x50", "number": "0x30", "gas_limit": "0x90",
                               "chain_id": "0x258", "blob_hashes_ptr": "0x190", "blob_hashes_len": "0x198",
                               "blob_fee_present_bit0": "0x0", "blob_fee_u128": "0x10", "op4b_u64": "0xa0"},
           "stack_limit": RD_STACK_LIMIT,
           "results": {"ok": RD_R_OK, "not_activated": RD_R_NOT_ACTIVATED, "underflow": RD_R_UNDERFLOW,
                       "overflow": RD_R_OVERFLOW}}
    return out, decoded


# ---------------------------------------------------------------- evaluation
def rd_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else rd_all_cases()):
        try:
            want = rd_model(c, mut)
            got = rd_run_case(m, c)
            ok = rd_compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        except Boundary as exc:
            want, got, ok = None, {"error": f"reached {exc.kind} arm"}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


RD_MODEL_MUTANTS = ["address_le", "caller_off", "callvalue_be", "size_wraps", "index_truncates", "load_unpadded",
                 "price_any_type", "price_wraps", "price_max", "timestamp_low", "blobfee_ignores_flag",
                 "blobhash_any_type", "blobhash_le", "chainid_gate_7", "basefee_ungated", "pop_wraps", "limit_1023"]
RD_BYTE_MUTANTS = [
    (0x2997f57, 0x05, "ADDRESS: stack bound 0x400 -> 0x500"),
    (0x2997f5e, 0x79, "ADDRESS: address offset +0x78 -> +0x79"),
    (0x2997efe, 0x8d, "CALLER: address offset +0x8c -> +0x8d"),
    (0x2998256, 0x58, "CODESIZE: code object +0x50 -> +0x58"),
    (0x2997ab3, 0x1f, "CALLDATALOAD: full copy 32 -> 31 bytes"),
    (0x2999786, 0x03, "GASPRICE: fee-market type bound 2 -> 3"),
    (0x29997b8, 0x01, "GASPRICE: carry add 0 -> 1"),
    (0x299987a, 0x04, "BLOBHASH: transaction type 3 -> 4"),
    (0x2999836, 0x0c, "BLOBHASH: spec gate 0xb -> 0xc"),
    (0x2b95836, 0x07, "CHAINID: spec gate 6 -> 7"),
    (0x2b957e6, 0x09, "BASEFEE: spec gate 8 -> 9"),
    (0x2b95736, 0x0c, "BLOBBASEFEE: spec gate 0xb -> 0xc"),
    (0x2b9573b, 0x02, "BLOBBASEFEE: present bit 0 -> bit 1"),
    (0x2b95926, 0x0f, "OP4B: spec gate 0xe -> 0xf"),
    (0x2b9597f, 0x60, "TIMESTAMP: limb 3 offset +0x68 -> +0x60"),
    (0x2995e04, 0x2d, "POP: underflow result 0x2c -> 0x2d"),
]


def rd_controls(image, cases):
    rows = []
    for name in RD_MODEL_MUTANTS:
        _, bad, _ = rd_evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in RD_BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = rd_evaluate(image, override={va: byte}, stop_on_first=True, cases=cases)
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
def rd_wtag(x):
    if x is None:
        return "-"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(64, "little")).hexdigest()[:12]


def rd_outcome(c, want, got):
    name = RD_BODIES[c["op"]][1]
    if "error" in got:
        return name + "/error"
    tag = {RD_R_OK: "ok", RD_R_NOT_ACTIVATED: "not-activated", RD_R_UNDERFLOW: "underflow", RD_R_OVERFLOW: "overflow"}
    out = name + "/" + tag.get(got["ret"], f"r{got['ret']:#x}")
    if got["ret"] == RD_R_OK:
        x = c["ctx"]
        if c["op"] == 0x3a:
            arm = "fee-market" if x[0x1f1] >= 2 and x[0xe0] else "legacy"
            if arm == "fee-market":
                s = rd_le(x, 0x98, 8) + rd_le(x, 0xf0, 16)
                arm += "-saturated" if s > M128 else ("-capped" if rd_le(x, 0x130, 16) <= s else "-sum")
            out += "-" + arm
        elif c["op"] == 0x49:
            out += "-hit" if want and want["writes"] and x[0x1f1] == 3 and rd_sat64(c["top"][-1]) < rd_le(x, 0x198, 8) \
                else "-zero"
        elif c["op"] == 0x35:
            off, (_, n) = rd_sat64(c["top"][-1]), rd_calldata(c)
            out += "-past-end" if off >= n else ("-partial" if n - off < 32 else "-full")
            out += "-view" if not rd_le(c["interp"], RD_I_CD_KIND, 8) else "-slice"
        elif c["op"] == 0x36:
            out += "-view" if not rd_le(c["interp"], RD_I_CD_KIND, 8) else "-slice"
        elif c["op"] == 0x4a:
            out += "-present" if x[0] & 1 else "-absent"
    return out


def rd_generate(out):
    image = load_image()
    out.mkdir(parents=True, exist_ok=True)
    cases = rd_all_cases()
    rows, bad, m = rd_evaluate(image, cases=cases)
    consts, decoded = rd_static_evidence(image)
    lines = ["case\topcode\tname\tmode\tspec\tn\ttop\toutcome\tresult\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = rd_outcome(c, want, got)
        if "error" in got:
            res = got["error"]
        else:
            res = f"ret={got['ret']:#x},n={got['n']}"
            if want is not None and want["writes"]:
                res += ",word=" + rd_wtag(next(iter(want["writes"].values())))
        classes[oc] = classes.get(oc, 0) + 1
        lines.append(f"{i}\t{c['op']:#x}\t{RD_BODIES[c['op']][1]}\t{c['mode']}\t{c['interp'][RD_I_SPEC]:#x}\t{c['n']}\t"
                     f"{rd_wtag(c['top'][-1] if c['top'] else None)}\t{oc}\t{res}\t{'yes' if ok else 'NO'}")
    (out / "context-reads-cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "context-reads-outcome-classes.tsv").write_text(
        "outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tbytes\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = total = 0
        for va, f in insns:
            if f is None:
                continue
            run = int(va in m.seen)
            hit += run
            total += 1
            lines.append(f"{start:#x}\t{va:#x}\t{f['bytes'].hex()}\t{run}")
        covered[f"{start:#x}"] = [hit, total]
    (out / "context-reads-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = rd_controls(image, cases)
    (out / "context-reads-negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "context-reads-constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": len(classes),
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "context-reads-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ memory-range
MR_OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); both name the same bodies here
MR_SLOAD_OP = 0x54
MR_SLOAD_BODIES = (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 of each table holds an SLOAD handler copy
MR_MCOPY, MR_CODECOPY, MR_KECCAK = 0x5e, 0x39, 0x20
MR_BODIES = {MR_MCOPY: 0x29971e0, MR_CODECOPY: 0x2997fb0, MR_KECCAK: 0x29982d0}
MR_NAMES = {MR_MCOPY: "MCOPY", MR_CODECOPY: "CODECOPY", MR_KECCAK: "KECCAK256"}
MR_OPS = (MR_KECCAK, MR_CODECOPY, MR_MCOPY)
# Executed, not selected: the shared memory-growth routine (selected by RE-021-callframe-input-115) and the
# Keccak sponge absorb/squeeze/permutation bodies reached from KECCAK256.
MR_EXPAND_GOT, MR_EXPAND = 0x64e6de0, 0x45244c0
MR_SPONGE = {"absorb": (0x64df7c8, 0x633a380), "squeeze": (0x64df7d0, 0x633a460)}
MR_PERMUTATION = (0x633a000, 0x633a2e0)
MR_RESERVE = 0x5be8d40           # direct call from the growth routine: buffer reserve, replaced by a contract stub
MR_LIBC = ("memmove", "memcpy", "memset")
MR_PANIC_GOTS = (0x64df570, 0x64df520, 0x64df6b8, 0x64df830, 0x64df848, 0x64df878, 0x64df870)
MR_SAVED_REGS = (3, 5, 12, 13, 14, 15)
MR_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
MR_WINDOW = 4
MR_SLACK_FILL = 0x7c

# Interpreter (rdi) displacements, host (rsi) displacement and the referenced records.
MR_I_MEM, MR_I_BASE, MR_I_STACK_PTR, MR_I_STACK_LEN, MR_I_CODE = 0x10, 0x18, 0x28, 0x30, 0x120
MR_I_WORDS, MR_I_COST, MR_I_GAS, MR_I_SPEC = 0x170, 0x178, 0x188, 0x1a9
MR_H_PARAMS = 0x250
MR_P_COPY, MR_P_MCOPY, MR_P_KECCAK, MR_P_LINEAR, MR_P_QUAD = 0x28, 0x40, 0x48, 0x50, 0x58
MR_M_BORROW, MR_M_CAP, MR_M_PTR, MR_M_LEN = 0x10, 0x18, 0x20, 0x28
MR_C_PTR, MR_C_CAP, MR_C_LEN = 0x38, 0x40, 0x50
MR_MCOPY_GATE = 0xb
MR_R_OK, MR_R_OOG, MR_R_MEM_OOG, MR_R_WIDE, MR_R_NOT_ACTIVE, MR_R_UNDERFLOW = 0x00, 0x20, 0x21, 0x24, 0x2b, 0x2c
MR_RATE = 0x88

MR_INTERP_AT, MR_INTERP_SIZE = 0x7d00_0000_0000, 0x200
MR_HOST_AT, MR_HOST_SIZE = 0x7d00_0100_0000, 0x260
MR_PARAM_AT, MR_PARAM_SIZE = 0x7d00_0110_0000, 0x60
MR_MOBJ_AT, MR_MOBJ_SIZE = 0x7d00_0120_0000, 0x30
MR_MEMBUF_AT, MR_MEMBUF_SIZE = 0x7d00_0200_0000, 0x1800
MR_COBJ_AT, MR_COBJ_SIZE = 0x7d00_0130_0000, 0x58
MR_CODE_AT, MR_CODE_SIZE = 0x7d00_0140_0000, 0x400
MR_STK_AT = 0x7d00_0300_0000

# Panic call sites, named by their return address (the address after the `call`).
MR_PANIC_SITES = {
    0x29973ca: "mcopy: slice_end_index (src+len > memory)",
    0x29973e5: "mcopy: dest is out of bounds",
    0x29973f4: "mcopy: src+len overflow",
    0x29981a1: "codecopy: code length > capacity",
    0x29981fd: "codecopy: zero-fill end > memory",
    0x2998227: "codecopy: offset+len overflow",
    0x2998594: "keccak256: absorb remainder >= 0x89",
    0x29985f2: "keccak256: offset+len overflow",
    0x2998608: "keccak256: base+offset or base+end overflow",
    0x4524605: "expand: quadratic divisor is zero",
    0x4524643: "expand: word count >> 59",
    0x4524650: "expand: base+bytes overflow",
}


class MrPanic(Exception):
    pass


class MrTooBig(Exception):
    pass


def mr_name(op):
    return MR_NAMES[op]


def mr_words_of(x):
    return (x >> 5) + (1 if x & 31 else 0)


def mr_sat_mul(a, b):
    p = a * b
    return M64 if p > M64 else p


def mr_keccak_f(st):
    rc, r, x, y = [], 1, 1, 0
    for _ in range(24):
        c = 0
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                c |= 1 << ((1 << j) - 1)
        rc.append(c)
    rot = [[0] * 5 for _ in range(5)]
    for t in range(24):
        rot[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    rol = lambda v, n: ((v << n) | (v >> (64 - n))) & M64 if n else v
    for rnd in range(24):
        c = [st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20] for i in range(5)]
        d = [c[(i - 1) % 5] ^ rol(c[(i + 1) % 5], 1) for i in range(5)]
        st = [st[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for i in range(5):
            for j in range(5):
                b[j + 5 * ((2 * i + 3 * j) % 5)] = rol(st[i + 5 * j], rot[i][j])
        st = [b[i + 5 * j] ^ (~b[(i + 1) % 5 + 5 * j] & b[(i + 2) % 5 + 5 * j]) for j in range(5) for i in range(5)]
        st = [st[i + 5 * j] for j in range(5) for i in range(5)]
        st[0] ^= rc[rnd]
    return st


def mr_keccak256(data, rate=MR_RATE):
    st = [0] * 25
    padded = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    padded[-1] |= 0x80
    for k in range(0, len(padded), rate):
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(padded[k + 8 * i:k + 8 * i + 8], "little")
        st = mr_keccak_f(st)
    return b"".join(v.to_bytes(8, "little") for v in st[:4])


MR_EMPTY_HASH = mr_keccak256(b"")


# ---------------------------------------------------------------- reconstruction
def mr_expand(s, need, mut):
    """Contract of the shared growth routine 0x45244c0 (gas first, then the buffer)."""
    lin = mr_sat_mul(need, s["p"][MR_P_LINEAR])
    quad = mr_sat_mul(need, need)
    if s["p"][MR_P_QUAD] == 0:
        raise MrPanic(0x4524605)
    total = min(M64, lin + quad // s["p"][MR_P_QUAD])
    delta = (total - s["cost"]) & M64
    s["words"], s["cost"] = need, total
    if s["gas"] < delta:
        if "expand_no_state_on_oog" in mut:
            s["words"], s["cost"] = s["words0"], s["cost0"]
        return MR_R_MEM_OOG
    s["gas"] -= delta
    if need >> 59:
        raise MrPanic(0x4524643)
    newlen = need * 32 + s["base"]
    if newlen > M64:
        raise MrPanic(0x4524650)
    if newlen > MR_MEMBUF_SIZE:
        raise MrTooBig()
    s["borrow"] = M64
    if newlen > s["mlen"]:
        extra = newlen - s["mlen"]
        if extra > s["mcap"] - s["mlen"]:
            s["mcap"] = s["mlen"] + extra
            s["reserved"] = True
        s["mem"][s["mlen"]:newlen] = bytes(extra)
        s["mlen"] = newlen
    elif "expand_never_truncates" not in mut:
        s["mlen"] = newlen
    s["borrow"] = 0
    return MR_R_OK


def mr_charge(s, size, price_off, mut):
    cost = mr_sat_mul(mr_words_of(size), s["p"][price_off])
    if "cost_floor_words" in mut:
        cost = mr_sat_mul(size >> 5, s["p"][price_off])
    if s["gas"] < cost:
        return MR_R_OOG
    s["gas"] -= cost
    return None


def mr_pop3(s):
    n = s["len"]
    return s["stack"][n - 1], s["stack"][n - 2], s["stack"][n - 3]


def mr_model(c, mut=frozenset()):
    s = {k: (bytearray(v) if isinstance(v, (bytes, bytearray)) else (dict(v) if isinstance(v, dict) else v))
         for k, v in c.items()}
    s["words0"], s["cost0"], s["reserved"] = c["words"], c["cost"], False
    try:
        s["ret"] = mr_step(s, mut)
        s["panic"] = None
    except MrPanic as exc:
        s["ret"], s["panic"] = None, exc.args[0]
    return s


def mr_step(s, mut):
    op = s["op"]
    if op == MR_MCOPY:
        gate = MR_MCOPY_GATE + (1 if "mcopy_gate_plus_one" in mut else 0)
        if s["spec"] < gate:
            return MR_R_NOT_ACTIVE
    need_len = 2 if op == MR_KECCAK else 3
    if s["len"] < need_len:
        return MR_R_UNDERFLOW
    n = s["len"]
    if op == MR_KECCAK:
        off, size = s["stack"][n - 1], s["stack"][n - 2]
        s["len"] = n - 1
        if size >> 64:
            return MR_R_WIDE
        r = mr_charge(s, size, MR_P_KECCAK, mut)
        if r is not None:
            return r
        if size == 0:
            if "keccak_empty_zero" not in mut:
                s["stack"][n - 2] = int.from_bytes(MR_EMPTY_HASH, "big")
            else:
                s["stack"][n - 2] = 0
            return MR_R_OK
        if off >> 64:
            return MR_R_WIDE
        need = mr_words_of(min(M64, off + size))
        if need > s["words"]:
            r = mr_expand(s, need, mut)
            if r:
                return r
        if off + size > M64:
            raise MrPanic(0x29985f2)
        start = s["base"] + off
        if start > M64 or start + size > M64:
            raise MrPanic(0x2998608)
        data = bytes(s["mem"][start:start + size])
        if len(data) != size:
            raise MrTooBig()
        h = mr_keccak256(data, MR_RATE - 8 if "keccak_rate_128" in mut else MR_RATE)
        word = int.from_bytes(h, "little" if "keccak_little_endian" in mut else "big")
        s["stack"][n - 2] = word
        return MR_R_OK
    a, b, size = mr_pop3(s)
    if "mcopy_swap_src_dst" in mut and op == MR_MCOPY:
        a, b = b, a
    s["len"] = n - 3
    if size >> 64:
        return MR_R_WIDE
    r = mr_charge(s, size, MR_P_MCOPY if op == MR_MCOPY else MR_P_COPY, mut)
    if r is not None:
        return r
    if size == 0:
        return MR_R_OK
    if op == MR_MCOPY:
        dst, src = a, b
        if dst >> 64 or src >> 64:
            return MR_R_WIDE
        need = mr_words_of(min(M64, max(src, dst) + size))
        if need > s["words"]:
            r = mr_expand(s, need, mut)
            if r:
                return r
        s["borrow"] = M64
        if src + size > M64:
            raise MrPanic(0x29973f4)
        avail = (s["mlen"] - s["base"]) & M64
        if src + size > avail:
            raise MrPanic(0x29973ca)
        if dst > avail - size:
            raise MrPanic(0x29973e5)
        lo = s["base"]
        chunk = bytes(s["mem"][lo + src:lo + src + size])
        if "mcopy_forward_overlap" in mut:
            for i in range(size):
                s["mem"][lo + dst + i] = s["mem"][lo + src + i]
        else:
            s["mem"][lo + dst:lo + dst + size] = chunk
        s["borrow"] = 0
        return MR_R_OK
    mo, co = a, b
    if mo >> 64:
        return MR_R_WIDE
    need = mr_words_of(min(M64, mo + size))
    if need > s["words"]:
        r = mr_expand(s, need, mut)
        if r:
            return r
    if co >> 64 and "codecopy_wide_offset_truncates" not in mut:
        co = M64
    co &= M64
    cl = s["cobj"][MR_C_LEN]
    if cl > s["cobj"][MR_C_CAP]:
        raise MrPanic(0x29981a1)
    s["borrow"] = M64
    lo = s["base"]
    if co >= cl:
        if mo + size > M64:
            raise MrPanic(0x2998227)
        if mo + size > ((s["mlen"] - lo) & M64):
            raise MrPanic(0x29981fd)
        s["mem"][lo + mo:lo + mo + size] = bytes(size)
    else:
        if co + size > M64:
            raise MrPanic(0x2998227)
        k = min(cl, co + size) - co
        if "codecopy_no_zero_tail" in mut:
            s["mem"][lo + mo:lo + mo + k] = s["code"][co:co + k]
        else:
            s["mem"][lo + mo:lo + mo + size] = bytes(s["code"][co:co + k]) + bytes(size - k)
    s["borrow"] = 0
    return MR_R_OK


# ---------------------------------------------------------------- harness
def mr_stack_image(words, lo, hi):
    return b"".join(words[i].to_bytes(32, "little") if i in words else bytes([MR_SLACK_FILL]) * 32
                    for i in range(lo, hi))


def mr_window(c):
    return max(0, c["len"] - MR_WINDOW), c["len"] + 2


def mr_interp_bytes(c, s):
    it = bytearray(c["interp"])
    put(it, MR_I_MEM, 8, MR_MOBJ_AT)
    put(it, MR_I_BASE, 8, c["base"])
    put(it, MR_I_STACK_PTR, 8, MR_STK_AT)
    put(it, MR_I_STACK_LEN, 8, s["len"])
    put(it, MR_I_CODE, 8, MR_COBJ_AT)
    put(it, MR_I_WORDS, 8, s["words"])
    put(it, MR_I_COST, 8, s["cost"])
    put(it, MR_I_GAS, 8, s["gas"])
    it[MR_I_SPEC] = c["spec"]
    return bytes(it)


def mr_mobj_bytes(c, s):
    b = bytearray(c["mobj"])
    put(b, MR_M_BORROW, 8, s["borrow"])
    put(b, MR_M_CAP, 8, s["mcap"])
    put(b, MR_M_PTR, 8, MR_MEMBUF_AT)
    put(b, MR_M_LEN, 8, s["mlen"])
    return bytes(b)


def mr_host_bytes(c):
    h = bytearray(c["host"])
    put(h, MR_H_PARAMS, 8, MR_PARAM_AT)
    return bytes(h)


def mr_param_bytes(c):
    b = bytearray(c["pfill"])
    for off, v in c["p"].items():
        put(b, off, 8, v)
    return bytes(b)


def mr_cobj_bytes(c):
    b = bytearray(c["cfill"])
    put(b, MR_C_PTR, 8, MR_CODE_AT)
    for off, v in c["cobj"].items():
        put(b, off, 8, v)
    return bytes(b)


class MrCaseMachine(TraceMachine):
    def transfer(self, target, call, va):
        if target in self.panics:
            self.panic_site = va
            raise Boundary("panic", self.regs)
        return super().transfer(target, call, va)


def mr_region_of(m, at, n):
    for lo, hi, buf in m.regions:
        if lo <= at and at + n <= hi:
            return buf, at - lo
    fail(f"libc contract range {at:#x}+{n:#x} outside regions")


def mr_libc_stub(kind):
    def run(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        if n:
            dbuf, doff = mr_region_of(m, dst, n)
            if kind == "memset":
                dbuf[doff:doff + n] = bytes([src & 0xff]) * n
            else:
                sbuf, soff = mr_region_of(m, src, n)
                if kind == "memcpy" and sbuf is dbuf and abs(soff - doff) < n:
                    fail("memcpy called with overlapping ranges")
                dbuf[doff:doff + n] = bytes(sbuf[soff:soff + n])
        m.calls.append((kind, dst, src, n))
        m.regs[0] = dst
    return run


def mr_reserve_stub(m):
    vec, length, extra = m.regs[7], m.regs[6], m.regs[2]
    if (m.regs[1], m.regs[8]) != (1, 1) or vec != MR_MOBJ_AT + MR_M_CAP or length != m.load(MR_MOBJ_AT + MR_M_LEN, 8):
        fail("reserve called outside its contract")
    m.store(vec, 8, length + extra)
    m.calls.append(("reserve", vec, length, extra))


def mr_install(m, image):
    m.panics = {image.word(g) for g in MR_PANIC_GOTS}
    m.panic_site = None
    m.calls = []
    for g in (0x64df568, 0x64df508, 0x64df750):
        m.stubs[image.word(g)] = mr_libc_stub(image.import_name(g))
    m.stubs[MR_RESERVE] = mr_reserve_stub


def mr_run_case(m, c):
    m.reset()
    mr_install(m, m.image)
    it = m.add_region(MR_INTERP_AT, MR_INTERP_SIZE, mr_interp_bytes(c, c))
    host = m.add_region(MR_HOST_AT, MR_HOST_SIZE, mr_host_bytes(c))
    par = m.add_region(MR_PARAM_AT, MR_PARAM_SIZE, mr_param_bytes(c))
    mob = m.add_region(MR_MOBJ_AT, MR_MOBJ_SIZE, mr_mobj_bytes(c, c))
    mem = m.add_region(MR_MEMBUF_AT, MR_MEMBUF_SIZE, c["mem"])
    cob = m.add_region(MR_COBJ_AT, MR_COBJ_SIZE, mr_cobj_bytes(c))
    code = m.add_region(MR_CODE_AT, MR_CODE_SIZE, c["code"])
    lo, hi = mr_window(c)
    stk = m.add_region(MR_STK_AT + 32 * lo, 32 * (hi - lo), mr_stack_image(c["stack"], lo, hi))
    fixed = [bytes(r) for r in (host, par, cob, code)]
    for k, v in zip(MR_SAVED_REGS, MR_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = MR_INTERP_AT, MR_HOST_AT
    try:
        m.run(MR_BODIES[c["op"]], limit=400000)
        ret, panic = m.regs[0] & 0xff, None
    except Boundary:
        ret, panic = None, m.panic_site
    return {"ret": ret, "panic": panic, "interp": bytes(it), "mobj": bytes(mob), "mem": bytes(mem),
            "stack": bytes(stk), "fixed_ok": [bytes(r) for r in (host, par, cob, code)] == fixed,
            "regs_ok": panic is not None or ([m.regs[k] for k in MR_SAVED_REGS] == MR_SAVED
                                             and m.regs[4] == STACK_TOP - 0x100),
            "calls": list(m.calls)}


def mr_compare(c, want, got):
    if want["panic"] is not None or got["panic"] is not None:
        return want["panic"] == got["panic"] and got["fixed_ok"]
    lo, hi = mr_window(c)
    return (want["ret"] == got["ret"] and got["regs_ok"] and got["fixed_ok"]
            and got["interp"] == mr_interp_bytes(c, want) and got["mobj"] == mr_mobj_bytes(c, want)
            and got["mem"] == bytes(want["mem"]) and got["stack"] == mr_stack_image(want["stack"], lo, hi))


# ---------------------------------------------------------------- cases
MR_PER_OP = {MR_KECCAK: 900, MR_CODECOPY: 1600, MR_MCOPY: 1600}
MR_SPECS = tuple(range(0x10)) + (0x7f, 0xff)
MR_SMALL_PRICES = (0, 1, 3, 6, 0x10)


def mr_rand_word(st):
    return int.from_bytes(st.take(32), "little")


def mr_small_or_wide(st, small_hi):
    k = st.below(16)
    if k < 11:
        return st.below(small_hi)
    if k == 11:
        return st.pick((0, 1, 31, 32, 33, MR_RATE - 1, MR_RATE, MR_RATE + 1))
    if k == 12:
        return st.below(64) << 64 | st.below(small_hi)
    if k == 13:
        return st.pick((M64, M64 - 31, 1 << 63, (1 << 59) * 32, 1 << 64, M64 - 0x40))
    if k == 14:
        return mr_rand_word(st)
    return st.below(small_hi) | (1 << st.pick((64, 128, 192, 255)))


def mr_make_case(st, op, k):
    c = {"op": op, "spec": st.pick(MR_SPECS) if st.below(4) == 0 else st.pick((0xb, 0xc, 0xd, 0x11)) % 0x100}
    n = st.pick((0, 1, 2, 3, 4, 5, 9, 1024)) if st.below(8) == 0 else st.pick((3, 4, 5, 16, 100))
    c["len"] = n
    stack = {}
    lo, hi = mr_window(c)
    for i in range(lo, n):
        stack[i] = mr_rand_word(st)
    top = {MR_KECCAK: 0x500, MR_CODECOPY: 0x500, MR_MCOPY: 0x480}[op]
    if n >= 1:
        stack[n - 1] = mr_small_or_wide(st, top)
    if n >= 2:
        stack[n - 2] = mr_small_or_wide(st, 0x500 if op != MR_KECCAK else 0x2a0)
    if n >= 3:
        stack[n - 3] = mr_small_or_wide(st, 0x2c0)
    c["stack"] = stack
    c["base"] = st.pick((0, 0, 0x20, 0x40, 0x100, 0x7))
    c["words"] = st.below(24)
    slack = st.pick((0, 0, 0, 0, 0, 0, 0x20, 0x41, 0x101, 0x301, -1, -0x20, -0x61, None))  # < 0: memory shorter than the word count
    c["mlen"] = c["base"] if slack is None else max(0, c["base"] + 32 * c["words"] + slack)
    c["mcap"] = c["mlen"] + st.pick((0, 0, 0x40, 0x400, MR_MEMBUF_SIZE - c["mlen"]))
    c["borrow"] = st.pick((0, 0, 0, 2))
    c["cost"] = st.pick((3 * c["words"] + c["words"] ** 2 // 512, 0, st.below(1 << 20)))
    c["gas"] = st.pick((st.below(1 << 12), st.below(1 << 24), 30_000_000, M64, 0, st.below(64)))
    c["p"] = {MR_P_COPY: st.pick(MR_SMALL_PRICES[1:]) if st.below(6) else st.pick((0, M64, 1 << 62)),
              MR_P_MCOPY: st.pick(MR_SMALL_PRICES[1:]) if st.below(6) else st.pick((0, M64, 1 << 62)),
              MR_P_KECCAK: st.pick(MR_SMALL_PRICES[1:]) if st.below(6) else st.pick((0, M64, 1 << 62)),
              MR_P_LINEAR: st.pick((3, 3, 3, 0, 1, M64)),
              MR_P_QUAD: st.pick((512, 512, 512, 1, 0, M64, 7))}
    c["pfill"] = st.take(MR_PARAM_SIZE)
    clen = st.pick((0, 1, 31, 0x40, 0x13f, 0x200, MR_CODE_SIZE))
    c["cobj"] = {MR_C_CAP: clen + st.pick((0, 0, 0x21)) if st.below(24) else max(0, clen - 1), MR_C_LEN: clen}
    c["cfill"] = st.take(MR_COBJ_SIZE)
    c["code"] = st.take(MR_CODE_SIZE)
    c["mem"] = st.take(MR_MEMBUF_SIZE)
    c["mobj"] = st.take(MR_MOBJ_SIZE)
    c["interp"] = st.take(MR_INTERP_SIZE)
    c["host"] = st.take(MR_HOST_SIZE)
    return c


def mr_all_cases():
    out = []
    for op in MR_OPS:
        st = Stream(f"re11-memory-range/{op:#x}")
        k = 0
        while sum(1 for c in out if c["op"] == op) < MR_PER_OP[op]:
            c = mr_make_case(st, op, k)
            k += 1
            try:
                mr_model(c)
            except MrTooBig:
                continue
            c["id"] = f"{mr_name(op).lower()}-{sum(1 for x in out if x['op'] == op):04d}"
            out.append(c)
    return out


# ---------------------------------------------------------------- static evidence
MR_CHECKED = (
    (0x29971eb, "80 bf a9 01 00 00 0b", "MCOPY: spec byte at interp+0x1a9 compared with 0xb (jb -> 0x2b)"),
    (0x29971fc, "41 b0 2c", "MCOPY: underflow result 0x2c"),
    (0x29971ff, "48 83 f8 02", "MCOPY: stack length must exceed 2"),
    (0x2997261, "41 b0 24", "MCOPY: wide-operand result 0x24"),
    (0x299726a, "49 8b 91 50 02 00 00", "MCOPY: host+0x250 parameter block"),
    (0x2997285, "48 f7 62 40", "MCOPY: per-word price at params+0x40"),
    (0x299728f, "48 8b 97 88 01 00 00", "MCOPY: remaining gas at interp+0x188"),
    (0x299737e, "41 b0 20", "MCOPY: out-of-gas result 0x20"),
    (0x29972f1, "48 3b 8f 70 01 00 00", "MCOPY: word count at interp+0x170"),
    (0x2997306, "49 c7 46 10 ff ff ff ff", "MCOPY: memory borrow flag set to -1"),
    (0x2997fc5, "48 83 f8 03", "CODECOPY: stack length must be >= 3"),
    (0x299804d, "48 f7 62 28", "CODECOPY: per-word price at params+0x28"),
    (0x29980c9, "48 8b 8f 20 01 00 00", "CODECOPY: bytecode record at interp+0x120"),
    (0x29980d0, "48 8b 51 40", "CODECOPY: bytecode capacity at +0x40"),
    (0x29980d4, "48 8b 41 50", "CODECOPY: bytecode length at +0x50"),
    (0x29980c3, "4c 0f 44 64 24 10", "CODECOPY: wide code offset saturates to 2^64-1 (cmove keeps low limb only when high limbs are 0)"),
    (0x29982e5, "48 83 f8 02", "KECCAK256: stack length must be >= 2"),
    (0x299834b, "48 f7 62 48", "KECCAK256: per-word price at params+0x48"),
    (0x29983c5, "48 ff 45 10", "KECCAK256: shared borrow (+1) of the memory record"),
    (0x299843b, "49 81 fe 88 00 00 00", "KECCAK256: rate 0x88 bytes"),
    (0x29984b8, "42 c6 84 3c f0 00 00 00 01", "KECCAK256: pad byte 0x01 after the tail"),
    (0x29984c1, "80 8c 24 77 01 00 00 80", "KECCAK256: final pad bit 0x80 at block byte 0x87"),
    (0x29984e7, "ba 20 00 00 00", "KECCAK256: squeeze 0x20 bytes"),
    (0x45244ce, "49 f7 61 50", "expand: linear price at params+0x50"),
    (0x45244e7, "4d 8b 49 58", "expand: quadratic divisor at params+0x58"),
    (0x452452c, "b0 21", "expand: memory out-of-gas result 0x21"),
    (0x452453e, "48 c1 e8 3b", "expand: word count >> 59 panics"),
)


def mr_hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def mr_empty_hash_imm(image):
    """The four movabs immediates of the size-zero branch, as stored into the result word."""
    rows, va = [], 0x299851f
    while len(rows) < 4:
        f = decode(image.code(va, 16), va)
        if 0xb8 <= f["op"] <= 0xbf and f["rex"] & 8:
            rows.append((f["r"], f["imm"]))
        va += f["len"]
    regs = dict(rows)
    stores = {0x29984fe: None}
    # rsi -> [r12-0x20], rdx -> [r12-0x18], rcx -> [r12-0x10], rax -> [r12-0x8]  (decoded below)
    word = 0
    for va2 in (0x299854a, 0x299854f, 0x2998554, 0x2998559):
        f = decode(image.code(va2, 16), va2)
        if f["op"] != 0x89 or f["rm"][0] != "m":
            fail("unexpected result store")
        word |= regs[f["reg"]] << (8 * (f["rm"][4] + 0x20))
    del stores
    return word


def mr_got_rows(image):
    rows = []
    for g in (MR_EXPAND_GOT, MR_SPONGE["absorb"][0], MR_SPONGE["squeeze"][0]):
        rows.append((g, image.word(g), ""))
    for g in (0x64df568, 0x64df508, 0x64df750):
        rows.append((g, image.word(g), image.import_name(g)))
    for g in MR_PANIC_GOTS:
        rows.append((g, image.word(g), "panic"))
    return rows


def mr_static_evidence(image):
    starts = set(MR_BODIES.values()) | {MR_EXPAND, MR_SPONGE["absorb"][1], MR_SPONGE["squeeze"][1], MR_PERMUTATION[1]}
    fdes = fde_rows(image, starts)
    for table in MR_OP_TABLES:
        if image.relative.get(table + 8 * MR_SLOAD_OP) not in MR_SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op in MR_OPS:
            if image.relative.get(table + 8 * op) != MR_BODIES[op]:
                fail(f"opcode table {table:#x} slot {op:#x} does not name {mr_name(op)}")
    for va, want, _ in MR_CHECKED:
        got = mr_hexs(image.code(va, len(bytes.fromhex(want.replace(" ", "")))))
        if got != want:
            fail(f"pinned bytes differ at {va:#x}: {got}")
    if image.word(MR_EXPAND_GOT) != MR_EXPAND:
        fail("growth GOT slot does not name 0x45244c0")
    for key, (g, body) in MR_SPONGE.items():
        if image.word(g) != body:
            fail(f"{key} GOT slot moved")
    for site in MR_PANIC_SITES:
        f = decode(image.code(site - 6, 16), site - 6)
        if f["op"] != 0xff or f["rm"][1] != "rip":
            fail(f"panic site {site:#x} is not a GOT call")
        if image.word(site + f["rm"][4]) not in {image.word(g) for g in MR_PANIC_GOTS}:
            fail(f"panic site {site:#x} calls an unexpected target")
    if mr_empty_hash_imm(image) != int.from_bytes(MR_EMPTY_HASH, "big"):
        fail("size-zero immediate is not Keccak-256 of the empty string")
    insns = {}
    for op in MR_OPS:
        start, end = fdes[MR_BODIES[op]]
        insns[op] = mr_sweep_padded(image, start, end)
    return fdes, insns


def mr_sweep_padded(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


# ---------------------------------------------------------------- evaluation and controls
def mr_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, cases=None, machine=None):
    m = machine or MrCaseMachine(image, override)
    rows = []
    for c in cases:
        want = mr_model(c, mut)
        got = mr_run_case(m, c)
        ok = mr_compare(c, want, got)
        rows.append((c, want, got, ok))
        if stop_on_first and not ok:
            break
    return rows, m


MR_MODEL_MUTANTS = ["mcopy_gate_plus_one", "mcopy_swap_src_dst", "mcopy_forward_overlap", "codecopy_no_zero_tail",
                 "codecopy_wide_offset_truncates", "keccak_empty_zero", "keccak_little_endian", "keccak_rate_128",
                 "cost_floor_words", "expand_never_truncates", "expand_no_state_on_oog"]
MR_BYTE_MUTANTS = [
    (0x29971f1, 0x0c, "MCOPY gate 0xb -> 0xc"),
    (0x2997288, 0x48, "MCOPY price params+0x40 -> +0x48"),
    (0x29972cd + 2, 0x42, "MCOPY cmova -> cmovb on max(src, dst)"),
    (0x2998050, 0x40, "CODECOPY price params+0x28 -> +0x40"),
    (0x29980d7, 0x40, "CODECOPY code length +0x50 -> +0x40"),
    (0x29980c5, 0x45, "CODECOPY cmove -> cmovne on the wide code offset"),
    (0x29984c0, 0x06, "KECCAK256 pad byte 0x01 -> 0x06"),
    (0x299834e, 0x28, "KECCAK256 price params+0x48 -> +0x28"),
    (0x4524541, 0x3a, "expand word bound >> 59 -> >> 58"),
    (0x45244ce + 3, 0x58, "expand linear price +0x50 -> +0x58"),
]


def mr_mutate_byte(image, va, value):
    return {va: value}


def mr_controls(image, cases):
    rows = []
    for mt in MR_MODEL_MUTANTS:
        r, _ = mr_evaluate(image, mut=frozenset([mt]), stop_on_first=True, cases=cases)
        bad = next((x[0]["id"] for x in r if not x[3]), "")
        rows.append(("model", mt, "detected" if bad else "MISSED", bad))
    for va, value, label in MR_BYTE_MUTANTS:
        if image.code(va, 1)[0] == value:
            fail(f"byte mutant at {va:#x} does not change the byte")
        try:
            r, _ = mr_evaluate(image, override={va: value}, stop_on_first=True, cases=cases)
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


def mr_wtag(x):
    if x == 0:
        return "0"
    if x >> 64:
        return "wide"
    return "small" if x < 0x1000 else "large64"


def mr_outcome(c, want):
    if want["panic"] is not None:
        return f"panic:{MR_PANIC_SITES[want['panic']].split(':')[0]}"
    r = {MR_R_OK: "ok", MR_R_OOG: "out-of-gas", MR_R_MEM_OOG: "memory-out-of-gas", MR_R_WIDE: "wide-operand",
         MR_R_NOT_ACTIVE: "not-activated", MR_R_UNDERFLOW: "underflow"}[want["ret"]]
    if want["ret"] == MR_R_OK and want.get("reserved"):
        r += "+reserve"
    if want["ret"] == MR_R_OK and want["words"] != c["words"]:
        r += "+grow"
    return r


def mr_generate(out):
    image = load_image()
    fdes, insns = mr_static_evidence(image)
    cases = mr_all_cases()
    rows, m = mr_evaluate(image, cases=cases, machine=MrCaseMachine(image))
    mism = [r[0]["id"] for r in rows if not r[3]]
    if mism:
        fail(f"{len(mism)} mismatches, first {mism[:5]}")
    ctl = mr_controls(image, cases)
    if any(r[2] != "detected" for r in ctl):
        fail(f"negative control missed: {[r for r in ctl if r[2] != 'detected']}")
    seen = m.seen
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    lines = ["case\top\tspec\tstack_len\ttop\tsecond\tthird\tbase\twords\tmem_len\tgas\tprices\tret_or_panic\t"
             "stack_len_after\twords_after\tcost_after\tgas_after\tmem_len_after\tresult_word_sha256\tmemory_sha256\tmatch"]
    classes = {}
    for c, want, got, ok in rows:
        n = c["len"]
        g = lambda i: mr_wtag(c["stack"][i]) + (f":{c['stack'][i]:#x}" if i in c["stack"] and c["stack"][i] < 0x1000 else "") if i in c["stack"] else "-"
        res = want["stack"].get(want["len"] - 1) if c["op"] == MR_KECCAK and want["ret"] == MR_R_OK else None
        oc = mr_outcome(c, want)
        classes[(mr_name(c["op"]), oc)] = classes.get((mr_name(c["op"]), oc), 0) + 1
        lines.append("\t".join([
            c["id"], mr_name(c["op"]), f"{c['spec']:#x}", str(n), g(n - 1), g(n - 2), g(n - 3), f"{c['base']:#x}",
            str(c["words"]), f"{c['mlen']:#x}", f"{c['gas']:#x}",
            "/".join(f"{c['p'][k]:#x}" for k in (MR_P_COPY, MR_P_MCOPY, MR_P_KECCAK, MR_P_LINEAR, MR_P_QUAD)),
            f"{want['ret']:#04x}" if want["panic"] is None else f"panic@{want['panic']:#x}",
            str(want["len"]), str(want["words"]), f"{want['cost']:#x}", f"{want['gas']:#x}", f"{want['mlen']:#x}",
            "-" if res is None else f"{res:064x}",
            hashlib.sha256(bytes(want["mem"])).hexdigest()[:16], "yes" if ok else "no"]))
    (out / "memory-range-cases.tsv").write_text("\n".join(lines) + "\n")
    oc_lines = ["opcode\toutcome\tcases"] + [f"{a}\t{b}\t{n}" for (a, b), n in sorted(classes.items())]
    (out / "memory-range-outcome-classes.tsv").write_text("\n".join(oc_lines) + "\n")
    ins_lines = ["opcode\tva\tbytes\texecuted"]
    total = hit = 0
    for op in MR_OPS:
        for va, f in insns[op]:
            total += 1
            hit += va in seen
            ins_lines.append(f"{mr_name(op)}\t{va:#x}\t{mr_hexs(f['bytes'])}\t{'yes' if va in seen else 'no'}")
    (out / "memory-range-decoded-instructions.tsv").write_text("\n".join(ins_lines) + "\n")
    fn = ["role\tname\tstart\tend\tsize\tsha256\tstatus"]
    for op in MR_OPS:
        s, e = fdes[MR_BODIES[op]]
        fn.append(f"handler\t{mr_name(op)}\t{s:#x}\t{e:#x}\t{e - s}\t{hashlib.sha256(image.code(s, e - s)).hexdigest()}\tselected")
    for label, va in (("memory growth (RE-021-callframe-input-115)", MR_EXPAND), ("sponge absorb", MR_SPONGE["absorb"][1]),
                      ("sponge squeeze", MR_SPONGE["squeeze"][1]), ("permutation wrapper", MR_PERMUTATION[1])):
        s, e = fdes[va]
        fn.append(f"dependency\t{label}\t{s:#x}\t{e:#x}\t{e - s}\t{hashlib.sha256(image.code(s, e - s)).hexdigest()}\texecuted")
    perm_end = MR_PERMUTATION[1]
    fn.append(f"dependency\tpermutation core (no FDE)\t{MR_PERMUTATION[0]:#x}\t{perm_end:#x}\t{perm_end - MR_PERMUTATION[0]}\t"
              f"{hashlib.sha256(image.code(MR_PERMUTATION[0], perm_end - MR_PERMUTATION[0])).hexdigest()}\texecuted")
    (out / "memory-range-functions.tsv").write_text("\n".join(fn) + "\n")
    dep_hit = sorted(va for va in seen if not any(fdes[MR_BODIES[o]][0] <= va < fdes[MR_BODIES[o]][1] for o in MR_OPS))
    const = {
        "binary_sha256": SHA256,
        "opcode_tables": {f"{t:#x}": {mr_name(op): f"{image.relative[t + 8 * op]:#x}" for op in MR_OPS} for t in MR_OP_TABLES},
        "pinned_bytes": [{"va": f"{va:#x}", "bytes": b, "meaning": t} for va, b, t in MR_CHECKED],
        "got_slots": [{"slot": f"{g:#x}", "target": f"{t:#x}", "import": n} for g, t, n in mr_got_rows(image)],
        "panic_sites": {f"{k:#x}": v for k, v in sorted(MR_PANIC_SITES.items())},
        "empty_hash_immediate": f"{mr_empty_hash_imm(image):064x}",
        "fields": {"interp": {"memory_record": MR_I_MEM, "memory_base": MR_I_BASE, "stack_ptr": MR_I_STACK_PTR,
                              "stack_len": MR_I_STACK_LEN, "bytecode_record": MR_I_CODE, "words": MR_I_WORDS,
                              "memory_cost": MR_I_COST, "gas_remaining": MR_I_GAS, "spec": MR_I_SPEC},
                   "host": {"params": MR_H_PARAMS},
                   "params": {"copy_word": MR_P_COPY, "mcopy_word": MR_P_MCOPY, "keccak_word": MR_P_KECCAK,
                              "memory_linear": MR_P_LINEAR, "memory_quad_divisor": MR_P_QUAD},
                   "memory_record": {"borrow": MR_M_BORROW, "cap": MR_M_CAP, "ptr": MR_M_PTR, "len": MR_M_LEN},
                   "bytecode_record": {"ptr": MR_C_PTR, "cap": MR_C_CAP, "len": MR_C_LEN}},
        "results": {"ok": MR_R_OK, "out_of_gas": MR_R_OOG, "memory_out_of_gas": MR_R_MEM_OOG, "wide_operand": MR_R_WIDE,
                    "not_activated": MR_R_NOT_ACTIVE, "underflow": MR_R_UNDERFLOW},
        "mcopy_spec_gate": MR_MCOPY_GATE, "keccak_rate": MR_RATE,
    }
    (out / "memory-range-constants.json").write_text(json.dumps(const, indent=2, sort_keys=True) + "\n")
    ctl_lines = ["kind\tcontrol\tresult\tfirst_detecting_case"] + ["\t".join(r) for r in ctl]
    (out / "memory-range-negative-controls.tsv").write_text("\n".join(ctl_lines) + "\n")
    summary = {
        "binary_sha256": SHA256,
        "cases": len(rows), "matches": sum(1 for r in rows if r[3]),
        "cases_per_opcode": {mr_name(op): sum(1 for r in rows if r[0]["op"] == op) for op in MR_OPS},
        "handler_instructions": total, "handler_instructions_executed": hit,
        "dependency_instruction_addresses_executed": len(dep_hit),
        "negative_controls": len(ctl), "negative_controls_detected": sum(1 for r in ctl if r[2] == "detected"),
        "outcome_classes": len(classes),
        "panic_sites_reached": sorted(f"{p:#x}" for p in {r[1]["panic"] for r in rows if r[1]["panic"] is not None}),
    }
    (out / "memory-range-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ log-emit
LG_OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); both name the same bodies here
LG_SLOAD_OP, LG_SLOAD_BODIES = 0x54, (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 holds an SLOAD handler copy
LG_BODIES = {  # opcode -> body named by both tables; EVM names are inferred from the opcode number and the code
    0xa0: (0x29926f0, "LOG0"), 0xa1: (0x2993350, "LOG1"), 0xa2: (0x2992f00, "LOG2"),
    0xa3: (0x2993720, "LOG3"), 0xa4: (0x29929d0, "LOG4"),
}
LG_CLAIMED = tuple(sorted(v[0] for v in LG_BODIES.values()))
LG_ALLOC_SLOT = 0x64df480    # RELATIVE .got slot -> allocator entry (size in rdi); stubbed
LG_MEMCPY_SLOT = 0x64df508   # GLOB_DAT import memcpy; stubbed by its dynsym name
LG_GROW_SLOT = 0x64dfa48     # RELATIVE .got slot -> vector grow of the host log list; stubbed
LG_RESIZE_SLOT = 0x64e6de0   # RELATIVE .got slot -> shared memory-expansion path; stubbed (outside this packet)
LG_PANIC_ADD_SLOT = 0x64df520  # RELATIVE .got slot: add-overflow panic (rdi = location)
LG_PANIC_MUL_SLOT = 0x64df870  # RELATIVE .got slot: topic-cost multiply panic (rdi = location)
LG_ALLOC_ERR_SLOT = 0x64df498  # RELATIVE .got slot: allocation failure (rdi = align, rsi = size)
LG_VT_EVEN_SLOT, LG_VT_ODD_SLOT = 0x64df8c0, 0x64df8c8  # RELATIVE slots holding the two owned-bytes vtables
LG_VT_STATIC = 0x6441d98     # vtable of the empty static bytes value (zero-length data)
LG_DROP_OFF = 0x20           # vtable +0x20 = drop entry called when the topic pop fails
LG_I_MEMOBJ, LG_I_MEM_OFF, LG_I_STACK_PTR, LG_I_STACK_LEN, LG_I_ADDR = 0x10, 0x18, 0x28, 0x30, 0x78
LG_I_MEM_WORDS, LG_I_GAS, LG_I_STATIC = 0x170, 0x188, 0x1a8
LG_H_PARAMS, LG_H_LOG_CAP, LG_H_LOG_PTR, LG_H_LOG_LEN = 0x250, 0x270, 0x278, 0x280
LG_P_PER_BYTE, LG_P_PER_TOPIC = 0x30, 0x38
LG_MO_BORROW, LG_MO_BUF = 0x10, 0x20
LG_LOG_SIZE, LG_LOG_CMP = 0x50, 0x4c  # bytes 0x4c..0x4f of a log record are padding copied from the stack
LG_R_OK, LG_R_OOG, LG_R_OFFSET, LG_R_STATIC, LG_R_UNDERFLOW = 0x00, 0x20, 0x24, 0x28, 0x2c
LG_SAVED_REGS = (3, 5, 12, 13, 14, 15)

LG_INTERP_AT, LG_INTERP_SIZE = 0x7d00_0000_0000, 0x1b0
LG_HOST_AT, LG_HOST_SIZE = 0x7d00_0100_0000, 0x290
LG_PARAMS_AT, LG_PARAMS_SIZE = 0x7d00_0200_0000, 0x40
LG_STK_AT = 0x7d00_0300_0000
LG_MEMOBJ_AT, LG_MEMOBJ_SIZE = 0x7d00_0400_0000, 0x30
LG_BUF_AT, LG_BUF_SIZE = 0x7d00_0500_0000, 0x200
LG_LOGS_AT = 0x7d00_0600_0000
LG_GROWN_AT = 0x7d00_0700_0000
LG_HEAP_DATA, LG_HEAP_TOPICS, LG_HEAP_SIZE = 0x7d00_0800_0000, 0x7d00_0900_0000, 0x200
LG_STACK_FILL, LG_SLACK_FILL = 0x5a, 0x7c
LG_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
LG_PANIC_LOCS = {0x29926f0: (0x643e110, 0x64bfc68, 0x64bfc80), 0x2993350: (0x643e110, 0x64bfc68, 0x64bfc80),
              0x2992f00: (0x643e110, 0x64bfc68, 0x64bfc80), 0x2993720: (0x643e110, 0x64bfc68, 0x64bfc80),
              0x29929d0: (0x643e110, 0x64bfc68, 0x64bfc80)}


# ---------------------------------------------------------------- reconstruction
def lg_le(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


def lg_topic_bytes(w, mut=frozenset()):
    """A popped 256-bit word as a 32-byte topic: big-endian (each limb byte-swapped, limbs reversed)."""
    return w.to_bytes(32, "little") if "topic_little" in mut else w.to_bytes(32, "big")


def lg_gas_cost(k, length, per_byte, per_topic, mut=frozenset()):
    """None = the topic-cost multiply panics; else the saturated u64 charge."""
    data = length * per_byte
    if data > M64:
        data = M64
    if k == 0:
        return data
    topics = (k + 1 if "topic_count_plus1" in mut else k) * per_topic
    if topics > M64:
        return None
    total = data + topics
    if "cost_wraps" in mut:
        return total & M64
    return M64 if total > M64 else total


def lg_model(c, mut=frozenset()):
    """The handler's result: return code, stack length, gas, memory-expansion call, log record or panic."""
    k, n, w, it = c["k"], c["n"], c["words"], c["interp"]
    gas = lg_le(it, LG_I_GAS, 8)
    out = {"ret": None, "n": n, "gas": gas, "resize": False, "drop": None, "log": None, "panic": None,
           "grew": False, "allocs": []}
    if it[LG_I_STATIC] and "no_static_check" not in mut:
        out["ret"] = LG_R_STATIC
        return out
    if n < 2:
        out["ret"] = LG_R_UNDERFLOW
        return out
    off_w, len_w = w[n - 1], w[n - 2]
    out["n"] = n - 2
    if len_w > M64:
        out["ret"] = LG_R_OFFSET
        return out
    length = len_w
    cost = lg_gas_cost(k, length, c["per_byte"], c["per_topic"], mut)
    if cost is None:
        out["panic"] = ("mul", None)
        return out
    if gas < cost:
        out["ret"] = LG_R_OOG
        return out
    out["gas"] = gas - cost
    if length == 0:
        vt, ptr, data = LG_VT_STATIC, 1, 0
        if "empty_ptr_zero" in mut:
            ptr = 0
    else:
        if off_w > M64 and "offset_high_ignored" not in mut:
            out["ret"] = LG_R_OFFSET
            return out
        off = off_w & M64
        end = off + length
        need = (min(end, M64) + 31) // 32
        if "words_floor" in mut:
            need = min(end, M64) // 32
        if need > lg_le(it, LG_I_MEM_WORDS, 8):
            out["resize"] = True
            if c["resize_ret"]:
                out["ret"] = c["resize_ret"]
                return out
        ctx = lg_le(it, LG_I_MEM_OFF, 8)
        if end > M64:
            out["panic"] = ("add", 0)
            return out
        if off + ctx > M64:
            out["panic"] = ("add", 1)
            return out
        if ctx + end > M64:
            out["panic"] = ("add", 2)
            return out
        out["allocs"].append(length)
        if c["null_alloc"] == 0:
            out["panic"] = ("alloc", length)
            return out
        ptr = LG_HEAP_DATA + c["odd"]
        src = ctx + off - (1 if "copy_skips_ctx" in mut else 0) * ctx
        out["data"] = c["buf"][src:src + length]
        odd = ptr & 1
        vt = c["vt_odd"] if odd else c["vt_even"]
        data = ptr if odd else ptr | 1
        if "vt_swapped" in mut:
            vt = c["vt_even"] if odd else c["vt_odd"]
    if k and out["n"] < k - (1 if "topic_bound_off_by_one" in mut else 0):
        out["ret"] = LG_R_UNDERFLOW
        out["drop"] = (vt, ptr, length)
        return out
    topics = b"".join(lg_topic_bytes(w[n - 3 - i], mut) for i in range(k))
    out["n"] = n - 2 - k
    if k:
        out["allocs"].append(32 * k)
        if c["null_alloc"] == 1:
            out["panic"] = ("alloc", 32 * k)
            return out
    out["topics"] = topics
    tptr = LG_HEAP_TOPICS if k else 1
    rec = struct.pack("<QQQQQQQ", k, tptr, k, vt, ptr, length, data) + c["interp"][LG_I_ADDR:LG_I_ADDR + 20]
    if "address_shift" in mut:
        rec = rec[:0x38] + c["interp"][LG_I_ADDR + 1:LG_I_ADDR + 21]
    out["log"] = rec
    out["grew"] = c["log_len"] == c["log_cap"]
    out["ret"] = LG_R_OK
    return out


# ---------------------------------------------------------------- harness
def lg_regs_ok(m):
    return [m.regs[k] for k in LG_SAVED_REGS] == LG_SAVED and m.regs[4] == STACK_TOP - 0x100


def lg_window(c):
    lo = max(c["n"] - 6, 0)
    return lo, c["n"] + 2 - lo


def lg_stack_image(c):
    lo, slots = lg_window(c)
    raw = bytearray([LG_SLACK_FILL]) * (32 * slots)
    for i, w in c["words"].items():
        raw[32 * (i - lo):32 * (i - lo) + 32] = w.to_bytes(32, "little")
    return bytes(raw)


def lg_install(m, c, rec):
    img = m.image

    def alloc(mm):
        size = mm.regs[7]
        idx = len(rec["allocs"])
        rec["allocs"].append(size)
        if c["null_alloc"] == idx:
            mm.regs[0] = 0
            return
        base = LG_HEAP_DATA + c["odd"] if idx == 0 and c["len_nonzero"] else LG_HEAP_TOPICS
        if size > LG_HEAP_SIZE - 1:
            fail("allocation larger than the fixture heap")
        mm.add_region(base, LG_HEAP_SIZE - (base & 1))
        mm.regs[0] = base

    def memcpy(mm):
        dst, src, size = mm.regs[7], mm.regs[6], mm.regs[2]
        mm.store_bytes(dst, mm.load_bytes(src, size))
        mm.regs[0] = dst

    def grow(mm):
        vec = mm.regs[7]
        cap, ptr, ln = mm.load(vec, 8), mm.load(vec + 8, 8), mm.load(vec + 16, 8)
        rec["grew"] += 1
        new_cap = max(2 * cap, 4)
        mm.add_region(LG_GROWN_AT, new_cap * LG_LOG_SIZE, mm.load_bytes(ptr, ln * LG_LOG_SIZE) if ln else b"")
        mm.store(vec, 8, new_cap)
        mm.store(vec + 8, 8, LG_GROWN_AT)

    def resize(mm):
        rec["resize"].append((mm.regs[7], mm.regs[6], mm.regs[2]))
        mm.regs[0] = (mm.regs[0] & ~0xff) | c["resize_ret"]

    def drop(mm):
        rec["drop"].append((mm.regs[7], mm.regs[6], mm.regs[2], mm.drop_vt))

    if img.import_name(LG_MEMCPY_SLOT) != "memcpy":
        fail("memcpy slot does not name memcpy")
    m.stubs[img.relative[LG_ALLOC_SLOT]] = alloc
    m.stubs[img.relative[LG_MEMCPY_SLOT]] = memcpy
    m.stubs[img.relative[LG_GROW_SLOT]] = grow
    m.stubs[img.relative[LG_RESIZE_SLOT]] = resize
    m.stubs[img.relative[LG_PANIC_ADD_SLOT]] = "add"
    m.stubs[img.relative[LG_PANIC_MUL_SLOT]] = "mul"
    m.stubs[img.relative[LG_ALLOC_ERR_SLOT]] = "alloc"
    for vt in (LG_VT_STATIC, img.relative[LG_VT_EVEN_SLOT], img.relative[LG_VT_ODD_SLOT]):
        target = img.word(vt + LG_DROP_OFF)

        def tagged(mm, vt=vt):
            mm.drop_vt = vt
            drop(mm)
        m.stubs[target] = tagged


class LgLogMachine(Machine):
    drop_vt = None

    def load_bytes(self, at, size):
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                return bytes(buf[at - lo:at - lo + size])
        fail(f"byte read outside regions at {at:#x}")

    def store_bytes(self, at, data):
        for lo, hi, buf in self.regions:
            if lo <= at and at + len(data) <= hi:
                buf[at - lo:at - lo + len(data)] = data
                return
        fail(f"byte write outside regions at {at:#x}")


class LgTraceMachine(LgLogMachine):
    def __init__(self, image, code_override=None):
        self.seen = set()
        super().__init__(image, code_override)

    def step(self, va):
        self.seen.add(va)
        return super().step(va)


def lg_run_case(m, c):
    m.reset()
    rec = {"allocs": [], "resize": [], "drop": [], "grew": 0}
    lg_install(m, c, rec)
    m.regions[0][2][:] = bytes([LG_STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(LG_INTERP_AT, LG_INTERP_SIZE, c["interp"])
    host = m.add_region(LG_HOST_AT, LG_HOST_SIZE, c["host"])
    params = m.add_region(LG_PARAMS_AT, LG_PARAMS_SIZE, c["params"])
    memobj = m.add_region(LG_MEMOBJ_AT, LG_MEMOBJ_SIZE, c["memobj"])
    buf = m.add_region(LG_BUF_AT, LG_BUF_SIZE, c["buf"])
    logs = m.add_region(LG_LOGS_AT, max(c["log_cap"], 1) * LG_LOG_SIZE, c["logs"])
    lo, slots = lg_window(c)
    stk = m.add_region(LG_STK_AT + 32 * lo, 32 * slots, lg_stack_image(c))
    for k, v in zip(LG_SAVED_REGS, LG_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = LG_INTERP_AT, LG_HOST_AT
    got = {"rec": rec}
    try:
        m.run(c["body"], limit=5000)
        got["panic"] = None
        got["ret"] = m.regs[0] & 0xff
    except Boundary as exc:
        if exc.kind not in ("add", "mul", "alloc"):
            raise
        r = exc.regs
        got["ret"] = None
        got["panic"] = (exc.kind, {"add": r[7], "mul": r[7], "alloc": (r[7], r[6])}[exc.kind])
        return got
    got["regs_ok"] = lg_regs_ok(m)
    got["n"], got["gas"] = u(it, LG_I_STACK_LEN, 8), u(it, LG_I_GAS, 8)
    rest = bytearray(it)
    for off in (LG_I_STACK_LEN, LG_I_GAS):
        rest[off:off + 8] = c["interp"][off:off + 8]
    got["interp_ok"] = bytes(rest) == c["interp"]
    got["side_ok"] = (bytes(params) == c["params"] and bytes(memobj) == c["memobj"] and bytes(buf) == c["buf"]
                      and bytes(stk) == lg_stack_image(c))
    cap, ptr, ln = u(host, LG_H_LOG_CAP, 8), u(host, LG_H_LOG_PTR, 8), u(host, LG_H_LOG_LEN, 8)
    head = bytearray(host)
    head[LG_H_LOG_CAP:LG_H_LOG_LEN + 8] = c["host"][LG_H_LOG_CAP:LG_H_LOG_LEN + 8]
    got["host_ok"] = bytes(head) == c["host"]
    got["log_len"] = ln
    got["log"] = None
    if ln == c["log_len"] + 1:
        recb = m.load_bytes(ptr + LG_LOG_SIZE * c["log_len"], LG_LOG_SIZE)
        got["log"] = recb[:LG_LOG_CMP]
        old = m.load_bytes(ptr, LG_LOG_SIZE * c["log_len"]) if c["log_len"] else b""
        got["old_ok"] = old == c["logs"][:LG_LOG_SIZE * c["log_len"]]
        k = c["k"]
        got["topics"] = m.load_bytes(LG_HEAP_TOPICS, 32 * k) if k else b""
        got["data"] = m.load_bytes(LG_HEAP_DATA + c["odd"], c["len"]) if c["len_nonzero"] else b""
        got["cap_ok"] = cap == (c["log_cap"] if c["log_len"] < c["log_cap"] else max(2 * c["log_cap"], 4))
    else:
        got["unchanged"] = bytes(host) == c["host"] and bytes(logs) == c["logs"]
    return got


def lg_compare(c, want, got):
    rec = got["rec"]
    if rec["allocs"] != want["allocs"] or (len(rec["resize"]) == 1) != want["resize"] or len(rec["resize"]) > 1:
        return False
    if rec["resize"] and rec["resize"][0] != (LG_INTERP_AT + LG_I_MEM_WORDS, LG_INTERP_AT, LG_HOST_AT + LG_H_PARAMS):
        return False
    if want["panic"] or got["panic"]:
        if not (want["panic"] and got["panic"]) or want["panic"][0] != got["panic"][0]:
            return False
        kind, arg = want["panic"]
        if kind == "add":
            return got["panic"][1] == LG_PANIC_LOCS[c["body"]][arg]
        if kind == "alloc":
            return got["panic"][1] == (1, arg)
        return True
    if not (want["ret"] == got["ret"] and want["n"] == got["n"] and want["gas"] == got["gas"] and got["regs_ok"]
            and got["interp_ok"] and got["side_ok"] and got["host_ok"]):
        return False
    if [d[1:] for d in rec["drop"]] != ([want["drop"][1:] + want["drop"][:1]] if want["drop"] else []):
        return False
    if want["log"] is None:
        return got["log"] is None and got.get("unchanged", False) and rec["grew"] == 0
    return (got["log"] == want["log"] and got["old_ok"] and got["cap_ok"] and got["topics"] == want["topics"]
            and got["data"] == want.get("data", b"") and rec["grew"] == int(want["grew"]))


# ---------------------------------------------------------------- cases
LG_CASES = 6000
LG_MODES = ("ok", "ok", "static", "short", "len-high", "gas-short", "gas-exact", "len-zero", "off-high", "resize-err",
         "resize-ok", "topics-short", "grow", "odd-ptr", "byte-overflow", "topic-overflow", "alloc-null",
         "end-overflow", "ctx-overflow", "ok", "words-edge", "words-edge")


def lg_rand_word(s):
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def lg_make_case(s, idx):
    k = idx % 5
    mode = LG_MODES[(idx // 5) % len(LG_MODES)]
    body = LG_BODIES[0xa0 + k][0]
    it = bytearray(s.take(LG_INTERP_SIZE))
    host = bytearray(s.take(LG_HOST_SIZE))
    params = bytearray(s.take(LG_PARAMS_SIZE))
    memobj = bytearray(s.take(LG_MEMOBJ_SIZE))
    buf = bytes(s.take(LG_BUF_SIZE))
    it[LG_I_STATIC] = 1 if mode == "static" else 0
    n = s.pick((2 + k, 3 + k, 2 + k + s.below(8), 0x3ff, 0x400))
    if mode == "short":
        n = s.below(2)
    elif mode == "topics-short":
        n = 2 + s.below(k + 1) if k else s.pick((0, 1))
    length = s.pick((1, 2, 31, 32, 33, 0x40, 0x100 - 1, s.below(0x100) + 1))
    off = s.below(0x100 - 0x10)
    ctx = s.below(0x100 - 0x10) if s.below(2) else 0
    while ctx + off + length > LG_BUF_SIZE:
        length = max(1, length // 2)
        off //= 2
    len_w, off_w = length, off
    per_byte, per_topic = s.pick((0, 1, 8, 0x41)), s.pick((0, 1, 375, 0x2a0))
    gas = s.pick((M64, 1 << 40, 50000, int.from_bytes(s.take(5), "little")))
    mem_words = s.pick((0, 1, 8, 0x10, 0x20, M64))
    resize_ret = 0
    null_alloc = None
    odd = 0
    log_cap = s.pick((1, 2, 4, 8))
    log_len = s.below(log_cap)
    if mode == "len-high":
        len_w = length | (1 << s.pick((64, 100, 128, 192, 255)))
    elif mode == "gas-short":
        per_byte = max(per_byte, 1)
        gas = lg_gas_cost(k, length, per_byte, per_topic) - 1
    elif mode == "gas-exact":
        gas = lg_gas_cost(k, length, per_byte, per_topic)
    elif mode == "len-zero":
        len_w = length = 0
        off_w = s.pick((0, off, lg_rand_word(s), M256))
    elif mode == "off-high":
        off_w = off | (1 << s.pick((64, 128, 200, 255)))
    elif mode == "resize-err":
        mem_words = 0
        resize_ret = s.pick((0x20, 0x21, 0x50, 0x01))
    elif mode == "resize-ok":
        mem_words = s.pick((0, 1, ((ctx + off + length) // 32)))
    elif mode == "words-edge":  # memory-words threshold: end at a word boundary, +1 byte, +16 bytes
        length = len_w = s.pick((16, 17, 32, 33, 48))
        off = off_w = 32 * s.below(4) + s.pick((0, 1, 15, 16, 31))
        ctx = 0
        mem_words = (off + length) // 32 + s.pick((-1, 0, 0, 1)) if off + length >= 32 else 0
    elif mode == "grow":
        log_len = log_cap
    elif mode == "odd-ptr":
        odd = 1
    elif mode == "byte-overflow":
        per_byte = s.pick((M64, 1 << 63, 1 << 60))
        length = len_w = s.pick((0x10, 0x20, 0x40))
        gas = s.pick((M64, M64 - 1, 1 << 63))
        per_topic = s.pick((0, 1))
    elif mode == "topic-overflow":
        per_topic = min(s.pick((M64 // max(k, 1) + 1, 1 << 63, 1 << 62, (1 << 62) - 1, M64 // 3, M64)), M64)
        gas = M64
        per_byte = s.pick((0, 1))
    elif mode == "alloc-null":
        null_alloc = s.below(2) if k else 0
        gas = M64
    elif mode == "end-overflow":
        off_w = M64 - s.below(length)
        mem_words = 0
        gas = M64
    elif mode == "ctx-overflow":
        off_w = max(s.pick((M64 - 0x300, 1 << 63, 0x20, off)), 1)
        if s.below(2):  # offset + context offset carries
            ctx = M64 - s.below(0x10) - (off_w if off_w < 0x10 else 0)
            ctx = max(ctx, M64 - off_w + 1)
        else:  # only context offset + offset + length carries
            ctx = M64 - off_w - s.below(length)
        mem_words = M64
        gas = M64
    if mode in ("ok", "grow", "odd-ptr", "resize-ok", "alloc-null", "words-edge"):
        n = max(n, 2 + k)
    if mode == "words-edge":
        gas = M64
    put(it, LG_I_STACK_PTR, 8, LG_STK_AT)
    put(it, LG_I_STACK_LEN, 8, n)
    put(it, LG_I_MEMOBJ, 8, LG_MEMOBJ_AT)
    put(it, LG_I_MEM_OFF, 8, ctx)
    put(it, LG_I_MEM_WORDS, 8, mem_words)
    put(it, LG_I_GAS, 8, gas)
    put(memobj, LG_MO_BUF, 8, LG_BUF_AT)
    put(memobj, LG_MO_BORROW, 8, s.below(4))
    put(params, LG_P_PER_BYTE, 8, per_byte)
    put(params, LG_P_PER_TOPIC, 8, per_topic)
    put(host, LG_H_PARAMS, 8, LG_PARAMS_AT)
    put(host, LG_H_LOG_CAP, 8, log_cap)
    put(host, LG_H_LOG_PTR, 8, LG_LOGS_AT)
    put(host, LG_H_LOG_LEN, 8, log_len)
    logs = bytes(s.take(max(log_cap, 1) * LG_LOG_SIZE))
    lo = max(n - 6, 0)
    words = {i: lg_rand_word(s) for i in range(lo, n)}
    if n >= 1:
        words[n - 1] = off_w
    if n >= 2:
        words[n - 2] = len_w
    return {"k": k, "op": 0xa0 + k, "body": body, "mode": mode, "n": n, "words": words, "interp": bytes(it),
            "host": bytes(host), "params": bytes(params), "memobj": bytes(memobj), "buf": buf, "logs": logs,
            "per_byte": per_byte, "per_topic": per_topic, "resize_ret": resize_ret, "null_alloc": null_alloc,
            "odd": odd, "log_cap": log_cap, "log_len": log_len, "len": length,
            "len_nonzero": int(length != 0 and len_w <= M64)}


def lg_all_cases(image):
    s = Stream("re11-log-emit-115")
    vt_even, vt_odd = image.relative[LG_VT_EVEN_SLOT], image.relative[LG_VT_ODD_SLOT]
    out = []
    for k in range(LG_CASES):
        c = lg_make_case(s, k)
        c["vt_even"], c["vt_odd"] = vt_even, vt_odd
        out.append(c)
    return out


# ---------------------------------------------------------------- static evidence
LG_CHECKED = (
    (0x29926fe, "80 bf a8 01 00 00 00", "LOG0: static-call flag interpreter +0x1a8 (result 0x28 at 0x2992923)"),
    (0x2992711, "48 83 f8 02", "LOG0: two words needed (offset, length), result 0x2c below"),
    (0x299275b, "48 89 47 30", "LOG0: both words popped before any further check"),
    (0x2992767, "48 8b 93 50 02 00 00", "LOG0: gas parameter block at host +0x250"),
    (0x2992771, "48 f7 62 30", "LOG0: length * per-byte cost (params +0x30), jo saturates to 2^64 - 1"),
    (0x299277b, "48 8b 97 88 01 00 00", "LOG0: gas left at interpreter +0x188, result 0x20 on borrow"),
    (0x29927bf, "83 e2 1f", "LOG0: memory words = ceil(saturated(offset + length) / 32)"),
    (0x29927ca, "48 3b 8f 70 01 00 00", "LOG0: compared with interpreter +0x170 (expansion call above)"),
    (0x29927eb, "48 ff 45 10", "LOG0: memory object +0x10 borrow count held across the copy"),
    (0x2992833, "48 83 c8 01", "LOG0: owned bytes: even pointer -> data = ptr | 1 with vtable slot 0x64df8c0"),
    (0x2992858, "48 8d 0d 39 f5 aa 03", "LOG0: zero length uses the static empty bytes vtable 0x6441d98"),
    (0x2992871, "0f 10 47 78", "LOG0: emitting address = interpreter +0x78 (20 bytes)"),
    (0x29928a9, "4c 8b b3 80 02 00 00", "LOG0: host log list len +0x280, cap +0x270, ptr +0x278"),
    (0x29928cd, "4b 8d 0c b6", "LOG0: log record size 5 * 16 = 0x50"),
    (0x2992a59, "49 8b 52 38", "LOG4: per-topic cost at params +0x38"),
    (0x2992a60, "49 c1 ea 3e", "LOG4: topic cost * 4 overflow check (panic slot 0x64df870)"),
    (0x2992b72, "48 83 f9 04", "LOG4: four topic words needed AFTER the data copy (drop + 0x2c)"),
    (0x2992b83, "ff 50 20", "LOG4: data dropped through vtable +0x20 on a short topic stack"),
    (0x2992c6a, "bf 80 00 00 00", "LOG4: topic buffer 4 * 32 bytes"),
    (0x2992c7e, "49 0f cd", "LOG4: topics stored big-endian (bswap of each limb, limbs reversed)"),
    (0x29933dc, "49 03 42 38", "LOG1: one topic: per-topic cost added without a multiply"),
    (0x29937b1, "49 f7 63 38", "LOG3: topic cost * 3 with mulq (jo -> panic)"),
)


def lg_opcode_slots(image):
    rows = {}
    for table in LG_OP_TABLES:
        if image.relative.get(table + 8 * LG_SLOAD_OP) not in LG_SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op, (body, _) in sorted(LG_BODIES.items()):
            got = image.relative.get(table + 8 * op)
            if got != body:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}"}
    return rows


def lg_sweep_padded(image, lo, hi):
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


def lg_call_sites(decoded, lo, hi):
    """Every call, indirect jump or out-of-body jmp of a decoded body: (address, kind, target)."""
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


LG_GOT_ROLES = {LG_ALLOC_SLOT: "alloc", LG_MEMCPY_SLOT: "memcpy", LG_GROW_SLOT: "log-list-grow", LG_RESIZE_SLOT: "memory-expand",
             LG_PANIC_ADD_SLOT: "add-overflow-panic", LG_PANIC_MUL_SLOT: "topic-cost-panic",
             LG_ALLOC_ERR_SLOT: "alloc-error", 0x64df4c0: "landing-pad callee (role unresolved)"}


LG_NORETURN_SLOTS = (LG_PANIC_ADD_SLOT, LG_PANIC_MUL_SLOT, LG_ALLOC_ERR_SLOT)


def lg_after_noreturn(decoded):
    """Instructions that only follow a call into a no-return panic / allocation-failure slot, and every ud2."""
    out, prev = set(), None
    for va, fm in decoded:
        if fm is None:
            continue
        if fm["op"] == 0x0f0b:
            out.add(va)
        elif prev is not None and prev["op"] == 0xff and prev["reg"] & 7 == 2 and prev["rm"][0] == "m" \
                and prev["rm"][1] == "rip" and (prev["va"] + prev["len"] + prev["rm"][4]) & M64 in LG_NORETURN_SLOTS:
            out.add(va)
        prev = dict(fm, va=va)
    return out


def lg_unwind_body(image, f, decoded):
    """Landing-pad tail: the first instruction after the last ud2 of the body, up to its end."""
    last = max(va for va, fm in decoded if fm is not None and fm["op"] == 0x0f0b)
    return last + 2


def lg_static_evidence(image):
    for slot in LG_GOT_ROLES:
        if slot != LG_MEMCPY_SLOT and (slot in image.imports or slot not in image.relative):
            fail(f".got slot {slot:#x} is not a RELATIVE slot")
    if image.import_name(LG_MEMCPY_SLOT) != "memcpy":
        fail("memcpy slot does not name memcpy")
    rows = fde_rows(image, list(LG_CLAIMED))
    decoded, funcs = {}, {}
    names = {b: (op, name) for op, (b, name) in LG_BODIES.items()}
    for f in LG_CLAIMED:
        lo, hi = rows[f]
        decoded[f] = lg_sweep_padded(image, lo, hi)
        calls = lg_call_sites(decoded[f], lo, hi)
        roles = {}
        for va, kind, target in calls:
            if kind == "got":
                if target not in LG_GOT_ROLES:
                    fail(f"body {f:#x} calls unexpected .got slot {target:#x}")
                role = LG_GOT_ROLES[target]
            elif kind == "register":
                role = "vtable-drop"
            else:
                role = f"direct {target:#x}"
            roles[role] = roles.get(role, 0) + 1
        op, name = names[f]
        pad = lg_unwind_body(image, f, decoded[f])
        funcs[f"{f:#x}"] = {"opcode": f"{op:#x}", "inferred_name": name, "fde_end": f"{hi:#x}",
                            "fde_bytes": hi - lo, "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "landing_pad_start": f"{pad:#x}", "call_roles": roles}
    checks = {}
    for va, hx, what in LG_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": lg_opcode_slots(image),
           "checked_bytes": checks,
           "got_slots": {f"{s:#x}": {"role": r, "target": (f"{image.relative[s]:#x}" if s != LG_MEMCPY_SLOT
                                                         else "import " + image.import_name(s))}
                         for s, r in sorted(LG_GOT_ROLES.items())},
           "bytes_vtables": {"static_empty": f"{LG_VT_STATIC:#x}",
                             "even_pointer": f"{image.relative[LG_VT_EVEN_SLOT]:#x}",
                             "odd_pointer": f"{image.relative[LG_VT_ODD_SLOT]:#x}",
                             "drop_entries": {f"{vt:#x}": f"{image.word(vt + LG_DROP_OFF):#x}" for vt in
                                              (LG_VT_STATIC, image.relative[LG_VT_EVEN_SLOT], image.relative[LG_VT_ODD_SLOT])}},
           "interpreter_offsets": {"memory_object": f"{LG_I_MEMOBJ:#x}", "memory_offset": f"{LG_I_MEM_OFF:#x}",
                                   "stack_ptr": f"{LG_I_STACK_PTR:#x}", "stack_len": f"{LG_I_STACK_LEN:#x}",
                                   "address": f"{LG_I_ADDR:#x}", "memory_words": f"{LG_I_MEM_WORDS:#x}",
                                   "gas_left": f"{LG_I_GAS:#x}", "static_flag": f"{LG_I_STATIC:#x}"},
           "host_offsets": {"gas_params": f"{LG_H_PARAMS:#x}", "logs_cap": f"{LG_H_LOG_CAP:#x}",
                            "logs_ptr": f"{LG_H_LOG_PTR:#x}", "logs_len": f"{LG_H_LOG_LEN:#x}"},
           "gas_param_offsets": {"per_data_byte": f"{LG_P_PER_BYTE:#x}", "per_topic": f"{LG_P_PER_TOPIC:#x}"},
           "memory_object_offsets": {"borrow": f"{LG_MO_BORROW:#x}", "buffer": f"{LG_MO_BUF:#x}"},
           "log_record": {"size": LG_LOG_SIZE, "fields": {"topics_cap": 0, "topics_ptr": 8, "topics_len": 16,
                                                        "data_vtable": 24, "data_ptr": 32, "data_len": 40,
                                                        "data_word": 48, "address": 56, "padding": 76}},
           "results": {"ok": LG_R_OK, "out_of_gas": LG_R_OOG, "offset_or_length_too_large": LG_R_OFFSET,
                       "static_call": LG_R_STATIC, "stack_underflow": LG_R_UNDERFLOW}}
    return out, decoded


# ---------------------------------------------------------------- evaluation
def lg_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or LgTraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else lg_all_cases(image)):
        try:
            want = lg_model(c, mut)
            got = lg_run_case(m, c)
            ok = lg_compare(c, want, got)
        except (ToolError, KeyError) as exc:
            want, got, ok = None, {"error": f"{type(exc).__name__}: {exc}"}, False
        except Boundary as exc:
            want, got, ok = None, {"error": f"reached {exc.kind} arm"}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


LG_MODEL_MUTANTS = ["no_static_check", "topic_little", "topic_count_plus1", "cost_wraps", "empty_ptr_zero",
                 "offset_high_ignored", "words_floor", "copy_skips_ctx", "vt_swapped", "topic_bound_off_by_one",
                 "address_shift"]
LG_BYTE_MUTANTS = [
    (0x2992924, 0x29, "LOG0: static-call result 0x28 -> 0x29"),
    (0x2992714, 0x01, "LOG0: two-word bound 2 -> 1"),
    (0x2992774, 0x38, "LOG0: per-byte cost +0x30 -> +0x38"),
    (0x299293f, 0x21, "LOG0: out-of-gas result 0x20 -> 0x21"),
    (0x29927c1, 0x0f, "LOG0: word rounding mask 0x1f -> 0x0f"),
    (0x2992836, 0x00, "LOG0: data |= 1 -> |= 0"),
    (0x2992874, 0x70, "LOG0: emitting address +0x78 -> +0x70"),
    (0x2992a63, 0x3f, "LOG4: topic overflow shift 62 -> 63"),
    (0x2992b75, 0x03, "LOG4: topic stack bound 4 -> 3"),
    (0x2992c6b, 0x60, "LOG4: topic buffer 0x80 -> 0x60"),
    (0x2992e0b, 0x25, "LOG4: offset result 0x24 -> 0x25"),
    (0x29933df, 0x30, "LOG1: per-topic cost +0x38 -> +0x30"),
    (0x29937b4, 0x30, "LOG3: per-topic cost +0x38 -> +0x30"),
]


def lg_controls(image, cases):
    rows = []
    for name in LG_MODEL_MUTANTS:
        _, bad, _ = lg_evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in LG_BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = lg_evaluate(image, override={va: byte}, stop_on_first=True, cases=cases)
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
LG_TAGS = {LG_R_OK: "ok", LG_R_OOG: "out-of-gas", LG_R_OFFSET: "offset-too-large", LG_R_STATIC: "static-call",
        LG_R_UNDERFLOW: "underflow"}


def lg_outcome(c, want, got):
    name = LG_BODIES[c["op"]][1]
    if "error" in got:
        return name + "/error"
    if got["panic"]:
        return name + "/panic-" + got["panic"][0]
    out = name + "/" + LG_TAGS.get(got["ret"], f"expand-error-{got['ret']:#x}")
    rec = got["rec"]
    if got["ret"] == LG_R_UNDERFLOW and rec["drop"]:
        out += "-topics-dropped-data"
    if got["ret"] == LG_R_OK:
        out += "-empty" if not c["len_nonzero"] else ("-odd-ptr" if c["odd"] else "-even-ptr")
        if rec["grew"]:
            out += "-grow"
    if rec["resize"]:
        out += "-expanded"
    return out


def lg_generate(out):
    image = load_image()
    out.mkdir(parents=True, exist_ok=True)
    cases = lg_all_cases(image)
    rows, bad, m = lg_evaluate(image, cases=cases)
    consts, decoded = lg_static_evidence(image)
    lines = ["case\topcode\tname\tmode\tn\toffset\tlength\tgas\tper_byte\tper_topic\toutcome\tresult\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = lg_outcome(c, want, got)
        if "error" in got:
            res = got["error"]
        elif got["panic"]:
            arg = got["panic"][1]
            res = f"panic-{got['panic'][0]}@" + (f"{arg:#x}" if isinstance(arg, int) else f"{arg[0]},{arg[1]:#x}")
        else:
            res = f"ret={got['ret']:#x},n={got['n']},gas={got['gas']:#x}"
            if got.get("log") is not None:
                res += ",log=" + hashlib.sha256(got["log"] + got["topics"] + got["data"]).hexdigest()[:16]
        classes[oc] = classes.get(oc, 0) + 1
        n, w = c["n"], c["words"]
        off = f"{w[n - 1]:#x}" if n >= 1 and w[n - 1] <= M64 else ("-" if n < 1 else "high")
        ln = f"{w[n - 2]:#x}" if n >= 2 and w[n - 2] <= M64 else ("-" if n < 2 else "high")
        lines.append(f"{i}\t{c['op']:#x}\t{LG_BODIES[c['op']][1]}\t{c['mode']}\t{n}\t{off}\t{ln}\t"
                     f"{lg_le(c['interp'], LG_I_GAS, 8):#x}\t{c['per_byte']:#x}\t{c['per_topic']:#x}\t{oc}\t{res}\t"
                     f"{'yes' if ok else 'NO'}")
    (out / "log-emit-cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "log-emit-outcome-classes.tsv").write_text(
        "outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tbytes\trole\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = total = 0
        pad = int(consts["functions"][f"{start:#x}"]["landing_pad_start"], 16)
        dead = lg_after_noreturn(insns)
        for va, f in insns:
            if f is None:
                continue
            run = int(va in m.seen)
            if va < pad and va not in dead:
                hit += run
                total += 1
            role = "landing-pad" if va >= pad else ("after-noreturn" if va in dead else "body")
            lines.append(f"{start:#x}\t{va:#x}\t{f['bytes'].hex()}\t{role}\t{run}")
        covered[f"{start:#x}"] = [hit, total]
    (out / "log-emit-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = lg_controls(image, cases)
    (out / "log-emit-negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "log-emit-constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad,
               "covered_instructions_before_landing_pads": covered, "outcome_classes": len(classes),
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "log-emit-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ combined output
PARTS = (("context-reads", rd_generate), ("memory-range", mr_generate), ("log-emit", lg_generate))
LISTINGS = ("cases.tsv", "instructions.tsv", "decoded-instructions.tsv")
SAMPLE_EVERY = 16


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


def generate(out, full=False):
    out.mkdir(parents=True, exist_ok=True)
    summary = {"binary_sha256": SHA256, "parts": {}, "full_listings": {},
               "listing_sample": "full" if full else f"header + every {SAMPLE_EVERY}th row"}
    totals = [0, 0, 0, 0]
    for slug, gen in PARTS:
        part = gen(out)
        row = part_totals(part)
        totals = [a + b for a, b in zip(totals, row)]
        summary["parts"][slug] = {"cases": row[0], "mismatches": row[1],
                                  "negative_controls": {"total": row[2], "detected": row[3]}}
        for name_ in LISTINGS:
            path = out / f"{slug}-{name_}"
            if path.exists():
                pin = (sample_listing(path) if not full else
                       {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "rows": len(path.read_bytes().split(b"\n")) - 2})
                summary["full_listings"][path.name] = pin
    summary.update({"cases": totals[0], "mismatches": totals[1],
                    "negative_controls": {"total": totals[2], "detected": totals[3]}})
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--full", action="store_true", help="keep every listing row instead of the committed sample")
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.full)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: summary[k] for k in ("cases", "mismatches", "negative_controls")}, sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
