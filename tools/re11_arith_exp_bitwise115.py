#!/usr/bin/env python3
"""Reconstruct node #115 EVM arithmetic, EXP, comparison, bitwise and shift opcodes with their callees.

Both RELATIVE opcode tables 0x6441210 and 0x6441f00 (index = opcode, anchored by the SLOAD slot 0x54)
name one body per opcode.  Every body takes the interpreter in rdi: stack base +0x28, stack length in
32-byte little-endian words +0x30; a short stack returns 0x2c, otherwise the result replaces the deepest
consumed word and the length drops by arity - 1.  Four families share one evaluator, one case loop, one
control loop and one output writer:

  ar  MUL 0x298f7f0, SUB 0x298f9a0, SIGNEXTEND 0x298f430 (inline limb code, no callees on the result path);
  dv  SDIV 0x298fa00, MOD 0x298f8f0, SMOD 0x298fa90, the signed helpers 0x29956c0 / 0x2995880 and the
      in-place u256 div_rem 0x144dde0 (GOT 0x64dfb80: numerator slot = quotient, divisor slot = remainder);
  md  ADDMOD 0x298fb20 -> core 0x29fe430 (u256 div_rem or the 5-limb div_rem 0x43c1f50 via GOT 0x64e6f50 on a
      carry), MULMOD 0x298fbe0 -> core 0x43bfc80 (GOT 0x64e6dd8) with the limb compare 0x43be000;
  ex  EXP 0x298f6a0 (dynamic gas ((255 - lz) / 8 + 1) * (host +0x250 -> +0x18), saturated at 2^64 - 1, 0x20
      when out of gas) -> square-and-multiply helper 0x29fcfb0, and LT..SAR, CLZ (0x10..0x1e, no callees;
      0x2b when SHL/SHR/SAR see spec byte +0x1a9 below 5 or CLZ below 0xd, checked before the stack length).

The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real machine
code of all bodies with a small concrete x86-64 evaluator (only memcpy/memmove/memset are modelled by
their libc contract; panic helpers are boundaries named by the message text they load; no external
programs, the binary is never executed) and compares every case with one pure-Python reconstruction.
Negative controls show that wrong reconstructions, corrupted code bytes and bad inputs are detected.
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
                0x0f6e, 0x0f7e, 0x30, 0x32, 0x0f60, 0x0f76, 0x0faf, 0x0f6c, 0x0ffb, 0x0fa5, 0x0fad, 0x0fbd, 0x0feb, 0x0f50, 0x0f54, 0x0f56) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
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


# ---------------------------------------------------------------- shared target constants
OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); both name the same bodies here
SLOAD_OP, SLOAD_BODY = 0x54, 0x2993ff0  # anchor: slot 0x54 of table 0x6441210 holds the SLOAD handler
DIVREM_SLOT, DIVREM = 0x64dfb80, 0x144dde0  # in-place u256 div_rem (numerator = quotient, divisor = remainder)
LIBC = {0x64df508: "memcpy", 0x64df568: "memmove", 0x64df750: "memset"}  # GLOB_DAT slots on the paths
PANICS = {  # RELATIVE GOT slot -> (panic helper body, message the helper passes)
    0x64df520: (0x1681da0, "attempt to add with overflow"),
    0x64df840: (0x1681e00, "attempt to shift left with overflow"),
    0x64df848: (0x1681e40, "attempt to subtract with overflow"),
    0x64df878: (0x1681d60, "attempt to divide by zero"),
}
BOUNDS_SLOT = 0x64df620  # limb compare: index-out-of-range panic (rdi = rsi = index, rdx = location 0x6487760)
I_STACK_PTR, I_STACK_LEN = 0x28, 0x30
R_OK, R_UNDERFLOW = 0x00, 0x2c
SAVED_REGS = (3, 5, 12, 13, 14, 15)

INTERP_AT = 0x7d00_0000_0000
INTERP_SIZE = 0x200
STK_AT = 0x7d00_0300_0000
ARG_AT = 0x7d00_0500_0000
ARG_SIZE = 0x100
STACK_FILL, INTERP_FILL, SLACK_FILL = 0x5a, 0x6b, 0x7c
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
SIGN = 1 << 255
M320 = (1 << 320) - 1


def lib_copy(m, overlap):
    d, s, n = m.regs[7], m.regs[6], m.regs[2]
    if n > 0x100:
        fail(f"library copy of {n} bytes")
    buf = [m.load(s + i, 1) for i in range(n)]
    if not overlap and n and (d < s + n and s < d + n):
        fail("memcpy with overlapping ranges")
    for i in range(n):
        m.store(d + i, 1, buf[i])
    m.regs[0] = d


def lib_set(m):
    d, c, n = m.regs[7], m.regs[6], m.regs[2]
    if n > 0x100:
        fail(f"library fill of {n} bytes")
    for i in range(n):
        m.store(d + i, 1, c & 0xff)
    m.regs[0] = d


LIB_MODELS = {"memcpy": lambda m: lib_copy(m, False), "memmove": lambda m: lib_copy(m, True), "memset": lib_set}


class PathMachine(TraceMachine):
    """TraceMachine with libc contracts; reaching a panic helper is a Boundary named by its message."""

    def reset(self):
        super().reset()
        for slot, name in LIBC.items():
            self.stubs[self.image.relative[slot]] = LIB_MODELS[name]
        for slot, (body, msg) in PANICS.items():
            self.stubs[self.image.relative[slot]] = "panic: " + msg
        self.stubs[self.image.relative[BOUNDS_SLOT]] = "panic: index out of bounds"


# ---------------------------------------------------------------- shared reconstruction helpers
def signed(x):
    return x - (1 << 256) if x & SIGN else x


def stack_bytes(words, slots):
    raw = b"".join(w.to_bytes(32, "little") for w in words)
    return raw + bytes([SLACK_FILL]) * (32 * slots - len(raw))


def callee_ok(m):
    return [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == STACK_TOP - 0x100


def expected_raw(c, want):
    """Stack memory after a handler: the result word overwrites its slot, nothing else changes."""
    raw = bytearray(stack_bytes(c["stack"], len(c["stack"]) + 2))
    if want["ret"] == R_OK:
        k = len(want["stack"]) - 1
        raw[32 * k:32 * k + 32] = want["stack"][-1].to_bytes(32, "little")
    return bytes(raw)


def opcode_slots(image, handlers):
    rows = {}
    for table in OP_TABLES:
        if image.relative.get(table + 8 * SLOAD_OP) not in (SLOAD_BODY, 0x2993bd0):
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op in sorted(handlers):
            got = image.relative.get(table + 8 * op)
            if got != handlers[op][0]:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}"}
    return rows


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


def wtag(x):
    if x is None:
        return "-"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes((x.bit_length() + 7) // 8, "little")).hexdigest()[:12]


def limbs(x):
    return (x.bit_length() + 63) // 64


# ---------------------------------------------------------------- shared case generators
EDGE = (0, 1, 2, 3, 7, 10, 0xff, 0x100, M64 - 1, M64, 1 << 64, (1 << 64) + 1, M128, 1 << 128, (1 << 192) - 1,
        1 << 192, SIGN - 1, SIGN, SIGN + 1, M256 - 1, M256, (-2) & M256, (-3) & M256, (-(1 << 64)) & M256,
        (-(1 << 128)) & M256, 1 << 63, (1 << 127) | 1, (1 << 191) + 5, 0x8000_0000_0000_0001 << 128)


def rand_word(s):
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def limbs_word(s):
    """A word with exactly k significant limbs whose top limb is random, small or has its top bit set."""
    k = 1 + s.below(4)
    top = s.pick((rand_word(s) & M64 or 1, 1 + s.below(255), (1 << 63) | (rand_word(s) & M64), M64))
    return ((int.from_bytes(s.take(8 * (k - 1)), "little") if k > 1 else 0) | top << (64 * (k - 1))) & M256

# ================================================================ family ar: MUL / SUB / SIGNEXTEND (opcodes 0x02, 0x03, 0x0b)
AR_HANDLERS = {  # opcode -> (body, inferred EVM name, arity, minimum spec byte or None)
    0x02: (0x298f7f0, "MUL", 2, None),
    0x03: (0x298f9a0, "SUB", 2, None),
    0x0b: (0x298f430, "SIGNEXTEND", 2, None),
}
AR_OPS = tuple(sorted(AR_HANDLERS))
AR_PANIC_SLOT = 0x64df870  # GOT slot called by SIGNEXTEND's unreachable index > 2^61 panic arm
AR_PANIC_ARG = 0x64437d8   # its rdi (lea) argument
AR_I_SPEC = 0x1a9  # spec byte offset in the interpreter
AR_R_NOT_ACTIVATED = 0x2b
def ar_signextend(k, x, mut=frozenset()):
    """EVM SIGNEXTEND: extend the sign of byte k (0 = least significant) of x; k >= 31 leaves x unchanged."""
    bound = 30 if "signext_bound_30" in mut else 31
    if "signext_low_limb_index" in mut:
        k &= M64
    if k >= bound:
        return x
    bit = 8 * k + (0 if "signext_bit_8k" in mut else 7)
    low = (1 << (bit + 1)) - 1
    if (x >> bit) & 1 and "signext_never_ones" not in mut:
        return x | (M256 ^ low)
    return x & low


def ar_apply(op, a, b, mut=frozenset()):
    """EVM result of opcode `op`; a = stack top, b = the word below it."""
    if op == 0x02:
        if "mul_low_128" in mut:
            return (a * b) & M128
        if "mul_no_cross_limbs" in mut:
            return ((a & M128) * (b & M128) + (((a >> 128) * (b >> 128)) << 256)) & M256
        return (a * b) & M256
    if op == 0x03:
        if "sub_swapped" in mut:
            return (b - a) & M256
        if "sub_saturating" in mut:
            return max(a - b, 0)
        return (a - b) & M256
    if op == 0x0b:
        return ar_signextend(a, b, mut)
    fail(f"no reconstruction for opcode {op:#x}")


def ar_model(c, mut=frozenset()):
    """Result code and the stack after the handler (length and every word)."""
    op, stack = c["op"], list(c["stack"])
    _, _, arity, _ = AR_HANDLERS[op]
    if len(stack) < arity:
        return {"ret": AR_R_NOT_ACTIVATED if "underflow_2b" in mut else R_UNDERFLOW, "stack": stack}
    a = stack.pop()
    b = stack.pop()
    stack.append(ar_apply(op, a, b, mut))
    return {"ret": R_OK, "stack": stack}


def ar_run_case(m, c):
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    m.stops[AR_PANIC_STOP] = "panic"
    it = m.add_region(INTERP_AT, INTERP_SIZE, bytes([INTERP_FILL]) * INTERP_SIZE)
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, len(c["stack"]))
    put(it, AR_I_SPEC, 1, c["spec"])
    slots = len(c["stack"]) + 2
    stk = m.add_region(STK_AT, 32 * slots, stack_bytes(c["stack"], slots))
    before = bytes(it)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7] = INTERP_AT
    m.run(AR_HANDLERS[c["op"]][0], limit=2000)
    n = u(it, I_STACK_LEN, 8)
    rest = bytearray(it)
    rest[I_STACK_LEN:I_STACK_LEN + 8] = before[I_STACK_LEN:I_STACK_LEN + 8]
    return {"ret": m.regs[0] & 0xff, "n": n, "stack_raw": bytes(stk), "slots": slots,
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == STACK_TOP - 0x100,
            "interp_ok": bytes(rest) == before}


AR_PANIC_STOP = 0x298f596  # first instruction of the panic arm; reaching it is a Boundary, never a result


def ar_compare(c, want, got):
    return (want["ret"] == got["ret"] and len(want["stack"]) == got["n"] and got["regs_ok"] and got["interp_ok"]
            and got["stack_raw"] == expected_raw(c, want))


# ---------------------------------------------------------------- cases
AR_PER_OP = 2000
AR_EDGE = (0, 1, 2, 3, 7, 8, 15, 16, 17, 29, 30, 31, 32, 33, 0x7f, 0x80, 0xff, 0x100, 0x101, 255, 256, 257, 0x1_0000,
        M64 - 1, M64, 1 << 64, (1 << 64) + 1, M128, 1 << 128, (1 << 192) - 1, 1 << 192,
        SIGN - 1, SIGN, SIGN + 1, M256 - 1, M256, M256 ^ SIGN ^ 1, 1 << 61, (1 << 64) + 30)
AR_SPECS = tuple(range(0x16)) + (0x7f, 0xff)
AR_MODES = ("edge", "random", "near", "equal", "limb", "index", "random", "edge", "sign", "small", "underflow", "carry")


def ar_word(s, mode):
    if mode == "edge":
        return s.pick(AR_EDGE)
    if mode == "sign":
        return SIGN | rand_word(s) if s.below(2) else rand_word(s) & (M256 ^ SIGN)
    if mode == "small":
        return s.below(300)
    return rand_word(s) if s.below(3) else s.pick(AR_EDGE)


def ar_limb_ones(s):
    """A word whose limbs are each all-ones, zero or random, to drive the carry chains."""
    return sum(s.pick((0, M64, rand_word(s) & M64, 1, M64 - 1)) << (64 * i) for i in range(4))


def ar_make_case(s, op, k):
    _, _, arity, _ = AR_HANDLERS[op]
    mode = AR_MODES[(k // 3) % len(AR_MODES)] if k % 3 == 0 else AR_MODES[k % len(AR_MODES)]
    spec = s.pick(AR_SPECS)
    extra = [rand_word(s) for _ in range(s.pick((0, 0, 1, 3)))]
    if mode == "underflow":
        return {"op": op, "spec": spec, "mode": mode, "stack": [ar_word(s, "edge")] * s.below(arity)}
    b = ar_word(s, mode)
    a = ar_word(s, mode)
    if mode == "near":
        a = (b + s.pick((1, -1, 1 << 64, -(1 << 64), 1 << 128, 1 << 192, SIGN))) & M256
    elif mode == "equal":
        a = b
    elif mode == "limb":
        a = b ^ (1 << (64 * s.below(4) + s.below(64)))
    elif mode == "carry":
        a, b = ar_limb_ones(s), ar_limb_ones(s)
    if op == 0x0b and (mode == "index" or s.below(5)):
        a = s.pick((s.below(32), s.below(32), s.below(34), 30, 31, 32, 15, 16, 7, 8, 23, 24,
                    (1 << (64 * s.below(4))) + s.below(32), 1 << 61, (1 << 61) - 1, M64, M256))
        if s.below(2):  # set or clear the sign bit of the indexed byte explicitly
            bit = 8 * (a % 32) + 7
            b = b | (1 << bit) if s.below(2) else b & (M256 ^ (1 << bit))
    stack = extra + [b, a]
    return {"op": op, "spec": spec, "mode": mode, "stack": stack}


def ar_all_cases():
    s = Stream("re11-arith-115")
    return [ar_make_case(s, op, k) for op in AR_OPS for k in range(AR_PER_OP)]


# ---------------------------------------------------------------- static evidence
AR_CHECKED = (
    (0x298f7f0, "48 8b 47 30", "MUL: stack length at interpreter +0x30"),
    (0x298f7f4, "48 83 f8 02", "MUL: two operands required"),
    (0x298f808, "4c 8b 6f 28", "MUL: stack base pointer at interpreter +0x28"),
    (0x298f83b, "48 f7 e1", "MUL: first 64x64->128 limb product (low limbs)"),
    (0x298f862, "49 0f af da", "MUL: truncated product limb 3 x limb 0 (only the low half reaches result limb 3)"),
    (0x298f8e9, "b0 2c", "MUL: result 0x2c (stack underflow)"),
    (0x298f9cf, "48 2b 74 11 e0", "SUB: top minus second, limb 0 (sub)"),
    (0x298f9d4, "4c 1b 44 11 e8", "SUB: borrow chain, limb 1 (sbb)"),
    (0x298f464, "48 83 fe 1f", "SIGNEXTEND: index limb 0 compared with 31"),
    (0x298f468, "49 83 d8 00", "SIGNEXTEND: sbb chain folds the upper index limbs into the >= 31 test"),
    (0x298f47d, "48 c1 e9 3d", "SIGNEXTEND: index >> 61 non-zero goes to the panic arm (unreachable after the < 31 test)"),
    (0x298f48a, "48 8d 04 f5 07 00 00 00", "SIGNEXTEND: sign bit index 8 * k + 7"),
    (0x298f52a, "40 f6 c7 01", "SIGNEXTEND: sign bit selects the or-ones arm or the and-mask arm"),
    (0x298f596, "48 8d 3d 3b 42 ab 03", "SIGNEXTEND: panic arm loads its location argument"),
    (0x298f59d, "ff 15 cd 02 b5 03", "SIGNEXTEND: panic arm calls through a GOT slot"),
)


def ar_static_evidence(image):
    bodies = [AR_HANDLERS[op][0] for op in AR_OPS]
    rows = fde_rows(image, bodies)
    decoded, funcs = {}, {}
    for op in AR_OPS:
        f, name, arity, gate = AR_HANDLERS[op]
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        calls = [va for va, fm in decoded[f] if fm is not None and
                 (fm["op"] == 0xe8 or fm["op"] == 0xff and fm["reg"] & 7 in (2, 3, 4, 5)
                  or fm["op"] == 0xe9 and not lo <= fm["target"] < hi)]
        if calls != ([AR_PANIC_STOP + 7] if op == 0x0b else []):
            fail(f"handler {f:#x} has unexpected calls at {[hex(x) for x in calls]}")
        funcs[f"{f:#x}"] = {"opcode": f"{op:#x}", "name_inferred": name, "arity": arity,
                            "min_spec_byte": gate, "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3)}
    checks = {}
    for va, hx, what in AR_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    lea = image.code(AR_PANIC_STOP, 13)
    arg = AR_PANIC_STOP + 7 + struct.unpack_from("<i", lea, 3)[0]
    slot = AR_PANIC_STOP + 13 + struct.unpack_from("<i", lea, 9)[0]
    if (arg, slot) != (AR_PANIC_ARG, AR_PANIC_SLOT):
        fail("SIGNEXTEND panic arm operands changed")
    panic = {"arm": f"{AR_PANIC_STOP:#x}", "rdi_lea_target": f"{arg:#x}", "rdi_section": image.section_of(arg)[0],
             "got_slot": f"{slot:#x}", "got_slot_section": image.section_of(slot)[0],
             "got_slot_kind": "GLOB_DAT import " + image.import_name(slot) if slot in image.imports
             else ("RELATIVE " + f"{image.relative[slot]:#x}" if slot in image.relative else "file bytes"),
             "reachable": "no: the index >= 31 test returns first, so index >> 61 is always zero here"}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": opcode_slots(image, AR_HANDLERS),
           "checked_bytes": checks, "signextend_panic_arm": panic,
           "interpreter_offsets": {"stack_ptr": f"{I_STACK_PTR:#x}", "stack_len": f"{I_STACK_LEN:#x}",
                                   "spec_byte": f"{AR_I_SPEC:#x}"},
           "results": {"ok": R_OK, "not_activated": AR_R_NOT_ACTIVATED, "underflow": R_UNDERFLOW}}
    return out, decoded


# ---------------------------------------------------------------- evaluation
AR_MODEL_MUTANTS = ["mul_low_128", "mul_no_cross_limbs", "sub_swapped", "sub_saturating", "signext_bound_30",
                 "signext_low_limb_index", "signext_bit_8k", "signext_never_ones", "underflow_2b"]
AR_BYTE_MUTANTS = [
    (0x298f8be, 0x29, "MUL: add r10,rax -> sub (limb 2 high-product accumulation)"),
    (0x298f8b3, 0x01, "MUL: adc r11,0 -> adc r11,1 (limb 3 carry)"),
    (0x298f868, 0xd8, "MUL: second multiplicand limb 1 -> limb 0 source register (mov rax,r11)"),
    (0x298f8ea, 0x2d, "MUL: underflow result 0x2c -> 0x2d"),
    (0x298f7f7, 0x01, "MUL: operand count 2 -> 1"),
    (0x298f9d0, 0x03, "SUB: sub -> add on limb 0"),
    (0x298f9d5, 0x13, "SUB: sbb -> adc on limb 1"),
    (0x298f9df, 0x13, "SUB: sbb -> adc on limb 3"),
    (0x298f9fb, 0x2d, "SUB: underflow result 0x2c -> 0x2d"),
    (0x298f467, 0x1e, "SIGNEXTEND: index bound 31 -> 30"),
    (0x298f46f, 0x01, "SIGNEXTEND: sbb on index limb 2 subtracts 1 (upper limbs mis-folded)"),
    (0x298f48e, 0x06, "SIGNEXTEND: sign bit 8k+7 -> 8k+6"),
    (0x298f52d, 0x02, "SIGNEXTEND: sign test bit 0 -> bit 1"),
    (0x298f4df, 0x11, "SIGNEXTEND: 128-bit mask split at index 16 -> 17"),
    (0x298f556, 0x23, "SIGNEXTEND: or limb 0 -> and on the negative arm"),
]


def ar_outcome(c, want, got):
    if "error" in got:
        return "error"
    name = AR_HANDLERS[c["op"]][1]
    if got["ret"] == R_UNDERFLOW:
        return name + "/underflow"
    if got["ret"] == AR_R_NOT_ACTIVATED:
        return name + "/not-activated"
    if got["ret"] != R_OK:
        return name + f"/r{got['ret']:#x}"
    a = c["stack"][-1]
    op = c["op"]
    b = c["stack"][-2]
    if op == 0x02:
        prod = a * b
        return name + ("/zero" if prod == 0 else "/fits-256" if prod <= M256 else "/wraps")
    if op == 0x03:
        return name + ("/zero" if a == b else "/no-borrow" if a > b else "/wraps")
    if op == 0x0b:
        if a >= 31:
            return name + ("/unchanged-31" if a == 31 else "/unchanged-big")
        neg = (b >> (8 * a + 7)) & 1
        return name + ("/limb%d" % ((8 * a + 7) // 64)) + ("-neg" if neg else "-pos")
    return name + "/value"


# ================================================================ family dv: SDIV / MOD / SMOD (opcodes 0x05..0x07) down to the u256 div_rem 0x144dde0
DV_HANDLERS = {  # opcode -> (body, inferred EVM name, arity, direct callee or GOT slot)
    0x05: (0x298fa00, "SDIV", 2, 0x29956c0),
    0x06: (0x298f8f0, "MOD", 2, 0x64dfb80),
    0x07: (0x298fa90, "SMOD", 2, 0x2995880),
}
DV_OPS = tuple(sorted(DV_HANDLERS))
DV_I256_DIV, DV_I256_MOD = 0x29956c0, 0x2995880
DV_MIN_CONST = 0x455a10  # 16 bytes xored into the upper half of |a| to test a == 2^255
DV_RECIP_SLOT, DV_RECIP_TABLE = 0x64dfa58, 0x944462  # GOT slot -> u16 reciprocal table, indexed by top 9 bits
def dv_divrem(n, d, mut=frozenset()):
    """In-place unsigned 256-bit div_rem: the numerator slot gets n // d, the divisor slot n % d (d != 0)."""
    q, r = divmod(n, d)
    if "divrem_ceil" in mut and r:
        q, r = q + 1, (r - d) & M256
    if "divrem_swap" in mut:
        q, r = r, q
    return q, r


def dv_i256_div(a, b, mut=frozenset()):
    """EVM SDIV: truncating signed division, b == 0 gives 0, MIN / -1 gives MIN."""
    sa, sb = signed(a), signed(b)
    if sb == 0:
        return a if "sdiv_zero_returns_a" in mut else 0
    if "sdiv_min_saturates" in mut and sa == -SIGN and sb == -1:
        return SIGN - 1
    q = abs(sa) // abs(sb)
    if "sdiv_floor" in mut and (sa < 0) != (sb < 0) and abs(sa) % abs(sb):
        q += 1
    neg = (sa < 0 or sb < 0) if "sdiv_neg_any" in mut else (sa < 0) != (sb < 0)
    return (-q if neg else q) & M256


def dv_i256_mod(a, b, mut=frozenset()):
    """EVM SMOD: |a| % |b| with the sign of a, b == 0 gives 0."""
    sa, sb = signed(a), signed(b)
    if sb == 0:
        return 0
    r = abs(sa) % abs(sb)
    if "smod_divisor_sign" in mut:
        return (-r if sb < 0 else r) & M256
    if "smod_unsigned" in mut:
        return a % b
    return (-r if sa < 0 else r) & M256


def dv_apply(op, a, b, mut=frozenset()):
    """EVM result of opcode `op`; a = stack top, b = the word below it."""
    if op == 0x05:
        return dv_i256_div(a, b, mut)
    if op == 0x06:
        if b == 0:
            return a if "mod_zero_returns_a" in mut else 0
        return dv_divrem(a, b, mut)[1]
    if op == 0x07:
        return dv_i256_mod(a, b, mut)
    fail(f"no reconstruction for opcode {op:#x}")


def dv_model(c, mut=frozenset()):
    """Result code and the stack after the handler (length and every word)."""
    if c["op"] == "divrem":
        q, r = dv_divrem(c["n"], c["d"], mut)
        return {"q": q, "r": r}
    op, stack = c["op"], list(c["stack"])
    _, _, arity, _ = DV_HANDLERS[op]
    if len(stack) < arity:
        return {"ret": 0x2d if "underflow_2d" in mut else R_UNDERFLOW, "stack": stack}
    a = stack.pop()
    b = stack.pop()
    stack.append(dv_apply(op, a, b, mut))
    return {"ret": R_OK, "stack": stack}


def dv_run_case(m, c):
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    if c["op"] == "divrem":
        arg = m.add_region(ARG_AT, 0x60, bytes([SLACK_FILL]) * 0x60)
        arg[0x10:0x30] = c["n"].to_bytes(32, "little")
        arg[0x30:0x50] = c["d"].to_bytes(32, "little")
        m.regs[7], m.regs[6] = ARG_AT + 0x10, ARG_AT + 0x30
        m.run(DIVREM, limit=20000)
        return {"q": u(arg, 0x10, 32), "r": u(arg, 0x30, 32), "regs_ok": callee_ok(m),
                "guard_ok": bytes(arg[:0x10]) + bytes(arg[0x50:]) == bytes([SLACK_FILL]) * 0x20}
    it = m.add_region(INTERP_AT, INTERP_SIZE, bytes([INTERP_FILL]) * INTERP_SIZE)
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, len(c["stack"]))
    slots = len(c["stack"]) + 2
    stk = m.add_region(STK_AT, 32 * slots, stack_bytes(c["stack"], slots))
    before = bytes(it)
    m.regs[7] = INTERP_AT
    m.run(DV_HANDLERS[c["op"]][0], limit=20000)
    n = u(it, I_STACK_LEN, 8)
    rest = bytearray(it)
    rest[I_STACK_LEN:I_STACK_LEN + 8] = before[I_STACK_LEN:I_STACK_LEN + 8]
    return {"ret": m.regs[0] & 0xff, "n": n, "stack_raw": bytes(stk), "slots": slots,
            "regs_ok": callee_ok(m), "interp_ok": bytes(rest) == before}


def dv_compare(c, want, got):
    if c["op"] == "divrem":
        return want["q"] == got["q"] and want["r"] == got["r"] and got["regs_ok"] and got["guard_ok"]
    return (want["ret"] == got["ret"] and len(want["stack"]) == got["n"] and got["regs_ok"] and got["interp_ok"]
            and got["stack_raw"] == expected_raw(c, want))


# ---------------------------------------------------------------- cases
DV_PER_OP = 1500
DV_DIRECT = 1500
DV_MODES = ("edge", "random", "limbs", "sign", "small", "underflow", "zero", "min", "equal", "near", "pow2", "divsmall")


def dv_neg_maybe(s, x):
    return (-x) & M256 if s.below(2) else x


def dv_word(s, mode):
    if mode == "edge":
        return s.pick(EDGE)
    if mode == "limbs":
        return dv_neg_maybe(s, limbs_word(s))
    if mode == "sign":
        return SIGN | rand_word(s) if s.below(2) else rand_word(s) & (M256 ^ SIGN)
    if mode == "small":
        return dv_neg_maybe(s, s.below(300))
    return rand_word(s) if s.below(3) else s.pick(EDGE)


def dv_make_case(s, op, k):
    _, _, arity, _ = DV_HANDLERS[op]
    mode = DV_MODES[(k // 3) % len(DV_MODES)] if k % 3 == 0 else DV_MODES[k % len(DV_MODES)]
    extra = [rand_word(s) for _ in range(s.pick((0, 0, 1, 3)))]
    if mode == "underflow":
        return {"op": op, "mode": mode, "stack": [dv_word(s, "edge")] * s.below(arity)}
    b = dv_word(s, "limbs" if mode in ("limbs", "near", "equal") else mode)
    a = dv_word(s, "limbs" if mode == "limbs" else mode)
    if mode == "zero":
        b = 0
    elif mode == "min":
        a, b = SIGN, s.pick((M256, 1, M256, 2, (-2) & M256, SIGN, SIGN - 1, b))
    elif mode == "equal":
        a = s.pick((b, (-b) & M256))
    elif mode == "near":
        a = (b * (1 + s.below(5)) + s.pick((1, -1, 0, 1 << 64))) & M256
    elif mode == "pow2":
        b = dv_neg_maybe(s, 1 << s.below(256))
    elif mode == "divsmall":
        b = dv_neg_maybe(s, 1 + s.below(1 << s.pick((8, 32, 63, 64))))
    return {"op": op, "mode": mode, "stack": extra + [b, a]}


DV_DIRECT_MODES = ("limbs", "random", "edge", "smaller", "equal", "near", "top", "single")


def dv_make_direct(s, k):
    mode = DV_DIRECT_MODES[k % len(DV_DIRECT_MODES)]
    d = limbs_word(s) if mode != "edge" else (s.pick(EDGE) or 1)
    n = limbs_word(s) if s.below(2) else rand_word(s)
    if mode == "random":
        n, d = rand_word(s), rand_word(s) or 1
    elif mode == "edge":
        n = s.pick(EDGE)
    elif mode == "smaller":
        n = d - 1 - s.below(min(d, 1 << 20))
    elif mode == "equal":
        n = d
    elif mode == "near":
        n = (d * (1 + s.below(1 << s.pick((1, 8, 64)))) + s.pick((0, 1, d - 1))) & M256
    elif mode == "top":
        d |= 1 << (64 * (d.bit_length() // 64 if d.bit_length() % 64 else d.bit_length() // 64 - 1) + 63)
        d &= M256
    elif mode == "single":
        d = ((rand_word(s) & M64) >> s.below(64)) or 1
    return {"op": "divrem", "mode": mode, "n": n & M256, "d": d or 1}


def dv_all_cases():
    s = Stream("re11-sdiv-115")
    cases = [dv_make_case(s, op, k) for op in DV_OPS for k in range(DV_PER_OP)]
    return cases + [dv_make_direct(s, k) for k in range(DV_DIRECT)]


# ---------------------------------------------------------------- static evidence
DV_CHECKED = (
    (0x298fa04, "48 83 f8 02", "SDIV: two operands required"),
    (0x298fa5a, "e8 61 5c 00 00", "SDIV: call i256_div helper 0x29956c0 (out, &top, &second)"),
    (0x298fa7f, "b0 2c", "SDIV: result 0x2c (stack underflow)"),
    (0x298faea, "e8 91 5d 00 00", "SMOD: call i256_mod helper 0x2995880 (out, &top, &second)"),
    (0x298fb0f, "b0 2c", "SMOD: result 0x2c (stack underflow)"),
    (0x298f946, "74 43", "MOD: zero divisor skips the divider and leaves the zero word in place"),
    (0x298f968, "ff 15 12 02 b5 03", "MOD: call the divider through GOT slot 0x64dfb80"),
    (0x298f96e, "0f 28 04 24", "MOD: result is the divisor slot (the remainder)"),
    (0x298f993, "b0 2c", "MOD: result 0x2c (stack underflow)"),
    (0x29956d4, "78 2b", "i256_div: negative divisor is negated in place"),
    (0x29956f1, "75 38", "i256_div: zero divisor stores 0"),
    (0x2995772, "66 0f ef 0d 96 02 ac fd", "i256_div: |a| xor 2^255 (constant 0x455a10) tests a == MIN"),
    (0x29957c5, "81 ff ff ff 00 00", "i256_div: |b| == 1 together with a == MIN returns MIN"),
    (0x2995808, "ff 15 72 a3 b4 03", "i256_div: divider through GOT slot 0x64dfb80 (quotient = numerator slot)"),
    (0x299582b, "41 30 ef", "i256_div: (a >= 0) xor (b < 0) == 0 means the signs differ: negate"),
    (0x299586b, "49 ff c6", "i256_div: 0x7fff..ff + 1 builds the MIN top limb"),
    (0x2995891, "78 54", "i256_mod: negative dividend is negated in place"),
    (0x29958ae, "74 26", "i256_mod: zero dividend stores 0"),
    (0x29958d4, "75 6d", "i256_mod: zero divisor stores 0"),
    (0x299597e, "ff 15 fc a1 b4 03", "i256_mod: divider through GOT slot 0x64dfb80 (remainder = divisor slot)"),
    (0x29959ab, "0f 89 2e ff ff ff", "i256_mod: result takes the dividend's sign"),
    (0x144de4c, "0f 92 c1", "div_rem: numerator < divisor limb compare chain"),
    (0x144debc, "ff 15 46 16 09 05", "div_rem: n < d copies the numerator into the remainder (memcpy)"),
    (0x144dfdc, "48 8b 3d 75 1a 09 05", "div_rem: reciprocal table pointer from GOT slot 0x64dfa58"),
    (0x144e0f7, "49 f7 f6", "div_rem: single-limb divisor uses the hardware div"),
    (0x144ea89, "4b 19 04 ea", "div_rem: multiply-subtract borrow chain"),
)
DV_MUTANT_BYTES = ()


def dv_call_targets(image, insns, lo, hi):
    out = []
    for va, fm in insns:
        if fm is None:
            continue
        if fm["op"] == 0xe8:
            out.append((va, f"{fm['target']:#x}"))
        elif fm["op"] == 0xff and fm["reg"] & 7 in (2, 4) and fm["rm"][0] == "m" and fm["rm"][1] == "rip":
            slot = (va + fm["len"] + fm["rm"][4]) & M64
            out.append((va, f"got:{slot:#x}"))
    return out


def dv_recip_table(image):
    raw = image.read(DV_RECIP_TABLE, 512)
    vals = struct.unpack("<256H", raw)
    formula = [(0x7fd00 // (256 + i)) for i in range(256)]  # floor((2^19 - 3 * 2^8) / d9), d9 = 256..511
    return {"slot": f"{DV_RECIP_SLOT:#x}", "table": f"{DV_RECIP_TABLE:#x}", "entries": 256,
            "index": "top 9 bits of the normalised divisor limb (256..511), base table - 0x200",
            "sha256": hashlib.sha256(raw).hexdigest(), "first": vals[0], "last": vals[-1],
            "matches_floor_0x7fd00_div_d9": sum(1 for x, y in zip(vals, formula) if x == y)}


def dv_static_evidence(image):
    for slot, name in LIBC.items():
        if slot not in image.imports or image.import_name(slot) != name:
            fail(f"GOT slot {slot:#x} is not the {name} import")
    if image.relative.get(DIVREM_SLOT) != DIVREM or image.relative.get(DV_RECIP_SLOT) != DV_RECIP_TABLE:
        fail("divider or reciprocal-table GOT slot changed")
    if image.read(DV_MIN_CONST, 16) != (1 << 127).to_bytes(16, "little"):
        fail("MIN test constant changed")
    bodies = [DV_HANDLERS[op][0] for op in DV_OPS] + [DV_I256_DIV, DV_I256_MOD, DIVREM]
    rows = fde_rows(image, bodies)
    decoded, funcs = {}, {}
    names = {DV_I256_DIV: "i256_div", DV_I256_MOD: "i256_mod"}
    for op in DV_OPS:
        names[DV_HANDLERS[op][0]] = DV_HANDLERS[op][1]
    for f in bodies[:-1]:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        calls = dv_call_targets(image, decoded[f], lo, hi)
        funcs[f"{f:#x}"] = {"name_inferred": names[f], "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "calls": [{"site": f"{va:#x}", "target": t} for va, t in calls]}
    expect = {0x298fa00: ["0x29956c0"], 0x298fa90: ["0x2995880"], 0x298f8f0: ["got:0x64dfb80"],
              DV_I256_DIV: ["got:0x64dfb80"], DV_I256_MOD: ["got:0x64dfb80"]}
    for f, want in expect.items():
        if [c["target"] for c in funcs[f"{f:#x}"]["calls"]] != want:
            fail(f"{f:#x} call targets changed")
    lo, hi = rows[DIVREM]
    funcs[f"{DIVREM:#x}"] = {"name_inferred": "u256 div_rem (in place)", "fde_end": f"{hi:#x}",
                             "fde_bytes": hi - lo, "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                             "reached_via": f"RELATIVE GOT slot {DIVREM_SLOT:#x}"}
    checks = {}
    for va, hx, what in DV_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": opcode_slots(image, DV_HANDLERS),
           "checked_bytes": checks, "min_test_constant": {"va": f"{DV_MIN_CONST:#x}",
                                                          "bytes": image.read(DV_MIN_CONST, 16).hex()},
           "libc_imports": {f"{k:#x}": v for k, v in sorted(LIBC.items())},
           "reciprocal_table": dv_recip_table(image),
           "interpreter_offsets": {"stack_ptr": f"{I_STACK_PTR:#x}", "stack_len": f"{I_STACK_LEN:#x}"},
           "results": {"ok": R_OK, "underflow": R_UNDERFLOW}}
    return out, decoded, rows


# ---------------------------------------------------------------- evaluation
DV_MODEL_MUTANTS = ["divrem_ceil", "divrem_swap", "sdiv_zero_returns_a", "sdiv_min_saturates", "sdiv_floor",
                 "sdiv_neg_any", "smod_divisor_sign", "smod_unsigned", "mod_zero_returns_a", "underflow_2d"]
DV_BYTE_MUTANTS = [
    (0x298fa80, 0x2d, "SDIV: underflow result 0x2c -> 0x2d"),
    (0x298fb10, 0x2d, "SMOD: underflow result 0x2c -> 0x2d"),
    (0x298f994, 0x2d, "MOD: underflow result 0x2c -> 0x2d"),
    (0x298f946, 0x75, "MOD: zero-divisor je -> jne"),
    (0x29956d4, 0x79, "i256_div: divisor sign js -> jns"),
    (0x29956f1, 0x74, "i256_div: zero-divisor test jne -> je"),
    (0x299582e, 0x74, "i256_div: sign-combine jne -> je"),
    (0x299586d, 0xce, "i256_div: MIN top limb inc -> dec"),
    (0x29957c7, 0xfe, "i256_div: |b| == 1 mask 0xffff -> 0xfffe"),
    (0x2995891, 0x79, "i256_mod: dividend sign js -> jns"),
    (0x29959ac, 0x88, "i256_mod: result sign jns -> js"),
    (0x144de4d, 0x93, "div_rem: numerator < divisor setb -> setae"),
    (0x144e0f9, 0xf7, "div_rem: single-limb div r14 -> div r15"),
    (0x144ea8a, 0x11, "div_rem: multiply-subtract sbb -> adc"),
]


def dv_outcome(c, want, got):
    if "error" in got:
        return "error"
    if c["op"] == "divrem":
        n, d = c["n"], c["d"]
        shape = "n<d" if n < d else "n=d" if n == d else f"n{limbs(n)}/d{limbs(d)}"
        return "div_rem/" + shape + ("-normalised" if d.bit_length() % 64 == 0 else "")
    name = DV_HANDLERS[c["op"]][1]
    if got["ret"] == R_UNDERFLOW:
        return name + "/underflow"
    if got["ret"] != R_OK:
        return name + f"/r{got['ret']:#x}"
    a, b = c["stack"][-1], c["stack"][-2]
    if b == 0:
        return name + "/zero-divisor"
    if c["op"] == 0x06:
        return name + ("/a<b" if a < b else "/exact" if a % b == 0 else "/remainder")
    sa, sb = signed(a), signed(b)
    if c["op"] == 0x05 and sa == -SIGN and abs(sb) == 1:
        return name + ("/min-by-minus-one" if sb == -1 else "/min-by-one")
    if c["op"] == 0x07 and sa == 0:
        return name + "/zero-dividend"
    signs = ("-" if sa < 0 else "+") + ("-" if sb < 0 else "+")
    return name + "/" + signs + ("/exact" if abs(sa) % abs(sb) == 0 else "")


# ================================================================ family md: ADDMOD / MULMOD (opcodes 0x08, 0x09) down to the 5-limb div_rem and the mulmod core
MD_HANDLERS = {  # opcode -> (body, inferred EVM name, arity, direct callee or GOT slot)
    0x08: (0x298fb20, "ADDMOD", 3, 0x29fe430),
    0x09: (0x298fbe0, "MULMOD", 3, 0x64e6dd8),
}
MD_OPS = tuple(sorted(MD_HANDLERS))
MD_ADDMOD_CORE = 0x29fe430  # (out, &a, &b, &n): direct call from the ADDMOD handler
MD_MULMOD_SLOT, MD_MULMOD_CORE = 0x64e6dd8, 0x43bfc80  # (&a, &b, &n) -> n slot = a * b mod n
MD_REDUCE5_SLOT, MD_REDUCE5 = 0x64e6f50, 0x43c1f50  # (&num[5], &d[4]) in place: num = quotient, d = remainder
MD_LIMB_CMP = 0x43be000  # limb-slice borrow compare called by the MULMOD core at 0x43c01e2
def md_divrem(n, d):
    """u256 div_rem 0x144dde0 (d != 0): numerator slot gets n // d, divisor slot n % d."""
    return divmod(n, d)


def md_reduce5(num, d, mut=frozenset()):
    """0x43c1f50: num is a 5-limb (320-bit) numerator, d a nonzero 4-limb divisor; in place q, r."""
    if d == 0:
        return {"panic": "attempt to divide by zero"}
    if "reduce5_low4" in mut:
        num &= M256
    q, r = divmod(num, d)
    return {"q": q & M320, "r": r}


def md_addmod_core(a, b, n, mut=frozenset()):
    """0x29fe430: returns (result, n slot after).  The carry path reduces in the n slot itself."""
    if n == 0:
        return (a + b if "addmod_zero_returns_sum" in mut else 0) & M256, n
    s = a + b
    if "addmod_wrap" in mut:
        s &= M256
    if s >> 256:
        r = md_reduce5(s, n, mut)["r"]
        return r, (n if "core_keeps_n" in mut else r)
    if s < n or ("addmod_le" in mut and s == n):
        return s, n
    return md_divrem(s, n)[1], n


def md_mulmod_core(a, b, n, mut=frozenset()):
    """0x43bfc80: the n slot becomes a * b mod n (n == 0 returns at once, leaving the zero word)."""
    if n == 0:
        return (a if "mulmod_zero_returns_a" in mut else 0)
    p = a * b
    if "mulmod_trunc" in mut:
        p &= M256
    return p % n


def md_apply(op, a, b, n, mut=frozenset()):
    """EVM result of opcode `op`; a = stack top, b = second word, n = third word (modulus)."""
    if op == 0x08:
        return md_addmod_core(a, b, n, mut)[0]
    if op == 0x09:
        return md_mulmod_core(a, b, n, mut)
    fail(f"no reconstruction for opcode {op:#x}")


def md_model(c, mut=frozenset()):
    kind = c["op"]
    if kind == "addmod_core":
        r, n_after = md_addmod_core(c["a"], c["b"], c["n"], mut)
        return {"out": r, "a": c["a"], "b": c["b"], "n": n_after}
    if kind == "mulmod_core":
        return {"a": c["a"], "b": c["b"], "n": md_mulmod_core(c["a"], c["b"], c["n"], mut)}
    if kind == "reduce5":
        return md_reduce5(c["num"], c["d"], mut)
    stack = list(c["stack"])
    _, _, arity, _ = MD_HANDLERS[kind]
    if len(stack) < arity:
        return {"ret": 0x2d if "underflow_2d" in mut else R_UNDERFLOW, "stack": stack}
    a, b, n = stack.pop(), stack.pop(), stack.pop()
    stack.append(md_apply(kind, a, b, n, mut))
    return {"ret": R_OK, "stack": stack}


MD_DIRECT_LAYOUT = {  # argument -> (offset in the argument region, bytes)
    "addmod_core": {"a": (0x10, 32), "b": (0x30, 32), "n": (0x50, 32), "out": (0x70, 32)},
    "mulmod_core": {"a": (0x10, 32), "b": (0x30, 32), "n": (0x50, 32)},
    "reduce5": {"q": (0x10, 40), "r": (0x40, 32)},
}


def md_run_case(m, c):
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    kind = c["op"]
    if kind in MD_DIRECT_LAYOUT:
        arg = m.add_region(ARG_AT, ARG_SIZE, bytes([SLACK_FILL]) * ARG_SIZE)
        lay = MD_DIRECT_LAYOUT[kind]
        if kind == "reduce5":
            put(arg, 0x10, 40, c["num"])
            put(arg, 0x40, 32, c["d"])
            m.regs[7], m.regs[6] = ARG_AT + 0x10, ARG_AT + 0x40
            start = MD_REDUCE5
        else:
            for name in ("a", "b", "n"):
                put(arg, lay[name][0], 32, c[name])
            if kind == "addmod_core":
                m.regs[7], m.regs[6], m.regs[2], m.regs[1] = (ARG_AT + 0x70, ARG_AT + 0x10, ARG_AT + 0x30,
                                                              ARG_AT + 0x50)
                start = MD_ADDMOD_CORE
            else:
                m.regs[7], m.regs[6], m.regs[2] = ARG_AT + 0x10, ARG_AT + 0x30, ARG_AT + 0x50
                start = MD_MULMOD_CORE
        slot_bytes = {i for o, size in lay.values() for i in range(o, o + size)}
        outside = [i for i in range(ARG_SIZE) if i not in slot_bytes]  # every byte no argument slot owns
        try:
            m.run(start, limit=200000)
        except Boundary as exc:
            if not exc.kind.startswith("panic: "):
                raise
            return {"panic": exc.kind[len("panic: "):], "guard_ok": all(arg[i] == SLACK_FILL for i in outside)}
        got = {name: u(arg, off, size) for name, (off, size) in lay.items()}
        got["regs_ok"] = callee_ok(m)
        got["guard_ok"] = all(arg[i] == SLACK_FILL for i in outside)
        return got
    it = m.add_region(INTERP_AT, INTERP_SIZE, bytes([INTERP_FILL]) * INTERP_SIZE)
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, len(c["stack"]))
    slots = len(c["stack"]) + 2
    stk = m.add_region(STK_AT, 32 * slots, stack_bytes(c["stack"], slots))
    before = bytes(it)
    m.regs[7] = INTERP_AT
    m.run(MD_HANDLERS[kind][0], limit=200000)
    n = u(it, I_STACK_LEN, 8)
    rest = bytearray(it)
    rest[I_STACK_LEN:I_STACK_LEN + 8] = before[I_STACK_LEN:I_STACK_LEN + 8]
    return {"ret": m.regs[0] & 0xff, "n": n, "stack_raw": bytes(stk), "slots": slots,
            "regs_ok": callee_ok(m), "interp_ok": bytes(rest) == before}


def md_compare(c, want, got):
    kind = c["op"]
    if kind in MD_DIRECT_LAYOUT:
        if "panic" in want or "panic" in got:
            return want.get("panic") == got.get("panic") and got["guard_ok"]
        return all(want[k] == got[k] for k in want) and got["regs_ok"] and got["guard_ok"]
    return (want["ret"] == got["ret"] and len(want["stack"]) == got["n"] and got["regs_ok"] and got["interp_ok"]
            and got["stack_raw"] == expected_raw(c, want))


# ---------------------------------------------------------------- cases
MD_PER_OP = 1400
MD_DIRECT = 800
MD_MODES = ("edge", "random", "limbs", "carry", "small_n", "underflow", "zero_n", "one_n", "below_n", "equal_n",
         "pow2_n", "max")


def md_word(s, mode):
    if mode == "edge":
        return s.pick(EDGE)
    if mode == "limbs":
        return limbs_word(s)
    return rand_word(s) if s.below(3) else s.pick(EDGE)


def md_operands(s, op, mode):
    a, b, n = md_word(s, mode), md_word(s, mode), md_word(s, "limbs" if mode in ("limbs", "random") else mode)
    if mode == "carry":  # a + b >= 2^256 (ADDMOD) / a * b >= 2^256 (MULMOD)
        a = M256 - s.below(1 << s.pick((1, 8, 64, 255)))
        b = (M256 - a + 1 + s.below(1 << s.pick((1, 8, 64, 200)))) & M256 if op != 0x09 else limbs_word(s)
    elif mode == "small_n":
        n = 1 + s.below(1 << s.pick((2, 8, 32, 64)))
    elif mode == "zero_n":
        n = 0
    elif mode == "one_n":
        n = 1
    elif mode == "below_n":  # result needs no reduction
        n = limbs_word(s) | SIGN
        a, b = rand_word(s) >> 2, rand_word(s) >> 2
        if op == 0x09:
            a, b = rand_word(s) & M128 >> 1, rand_word(s) & M128 >> 1
    elif mode == "equal_n":  # a + b == n or a * b == n exactly
        n = limbs_word(s) or 1
        if op == 0x08:
            a = n - s.below(n + 1)
            b = n - a
        else:
            a = 1 + s.below(1 << 16)
            n = (a * (1 + s.below(1 << 64))) & M256 or a
            b = n // a
            n = a * b
    elif mode == "pow2_n":
        n = 1 << s.below(256)
    elif mode == "max":
        a, b, n = s.pick((M256, M256 - 1)), s.pick((M256, M256 - 1, 1)), s.pick((M256, M256 - 1, 2, 3, SIGN))
    return a, b, n


def md_make_case(s, op, k):
    _, _, arity, _ = MD_HANDLERS[op]
    mode = MD_MODES[(k // 3) % len(MD_MODES)] if k % 3 == 0 else MD_MODES[k % len(MD_MODES)]
    extra = [rand_word(s) for _ in range(s.pick((0, 0, 1, 3)))]
    if mode == "underflow":
        return {"op": op, "mode": mode, "stack": [md_word(s, "edge")] * s.below(arity)}
    a, b, n = md_operands(s, op, mode)
    return {"op": op, "mode": mode, "stack": extra + [n, b, a]}


def md_make_direct(s, kind, k):
    mode = MD_MODES[k % len(MD_MODES)]
    if mode == "underflow":
        mode = "carry"
    if kind == "reduce5":
        rmode = ("random", "carry", "small_n", "equal_n", "limbs", "edge", "below_n", "one_n", "zero_n", "pow2_n")
        mode = rmode[k % len(rmode)]
        d = limbs_word(s) or 1
        num = (1 << 256) | rand_word(s)  # the only shape ADDMOD passes: carry limb 1 over a 256-bit sum
        if mode == "random":
            num = int.from_bytes(s.take(40), "little") >> (8 * s.below(40))
        elif mode == "small_n":
            d = 1 + s.below(1 << s.pick((2, 8, 32, 64)))
        elif mode == "equal_n":
            num = (d * (1 + s.below(1 << s.pick((1, 8, 64))))) & M320
        elif mode == "limbs":
            num = (limbs_word(s) | (s.below(1 << 64) << 256)) & M320
        elif mode == "edge":
            num, d = s.pick(EDGE) | (s.pick((0, 1, M64)) << 256), s.pick(EDGE) or 1
        elif mode == "below_n":
            num = d - 1 - s.below(min(d, 1 << 20))
        elif mode == "one_n":
            d = 1
        elif mode == "zero_n":
            d = 0
        elif mode == "pow2_n":
            d = 1 << s.below(256)
        return {"op": kind, "mode": mode, "num": num, "d": d}
    a, b, n = md_operands(s, 0x08 if kind == "addmod_core" else 0x09, mode)
    return {"op": kind, "mode": mode, "a": a, "b": b, "n": n}


MD_DIRECT_KINDS = ("addmod_core", "mulmod_core", "reduce5")


def md_all_cases():
    s = Stream("re11-addmod-mulmod-115")
    cases = [md_make_case(s, op, k) for op in MD_OPS for k in range(MD_PER_OP)]
    return cases + [md_make_direct(s, kind, k) for kind in MD_DIRECT_KINDS for k in range(MD_DIRECT)]


# ---------------------------------------------------------------- static evidence
MD_CHECKED = (
    (0x298fb2e, "4883fb03", "ADDMOD: three operands required"),
    (0x298fba1, "e88ae80600", "ADDMOD: call core 0x29fe430 (out, &top, &second, &third)"),
    (0x298fbc9, "b02c", "ADDMOD: result 0x2c (stack underflow)"),
    (0x298fbee, "4883fb03", "MULMOD: three operands required"),
    (0x298fc5c, "ff157671b503", "MULMOD: call core through GOT slot 0x64e6dd8 (&top, &second, &third)"),
    (0x298fc8e, "b02c", "MULMOD: result 0x2c (stack underflow)"),
    (0x29fe452, "83f00f", "ADDMOD core: movmskps ^ 0xf == 0 means all four modulus dwords pairs are zero"),
    (0x29fe455, "0f84d1000000", "ADDMOD core: zero modulus stores the zero word"),
    (0x29fe47d, "4983d000", "ADDMOD core: adc carries into the top limb"),
    (0x29fe488, "0f82a5000000", "ADDMOD core: carry out of the top limb (add r10, r9) takes the 5-limb path"),
    (0x29fe491, "0f859c000000", "ADDMOD core: carry out of the adc chain takes the 5-limb path"),
    (0x29fe4cc, "7247", "ADDMOD core: sum < modulus is returned unreduced"),
    (0x29fe4fc, "ff157e16ae03", "ADDMOD core: otherwise u256 div_rem through GOT slot 0x64dfb80 (remainder)"),
    (0x29fe555, "48c744242001000000", "ADDMOD core: fifth limb = 1 (the carry)"),
    (0x29fe567, "ff15e389ae03", "ADDMOD core: 5-limb div_rem through GOT slot 0x64e6f50; n slot gets the remainder"),
    (0x43bfca9, "83f00f", "MULMOD core: zero-modulus test"),
    (0x43bfcac, "0f84ff1b0000", "MULMOD core: zero modulus returns without writing (the zero word stays)"),
    (0x43c01e2, "e819deffff", "MULMOD core: limb-slice compare helper 0x43be000"),
    (0x43be00f, "0f92c0", "limb compare: borrow of the first limb"),
    (0x43be01e, "481b4a08", "limb compare: sbb chain over the next limbs"),
    (0x43c1f69, "48837e1800", "5-limb div_rem: top divisor limb test"),
)


def md_call_targets(insns):
    out = []
    for va, fm in insns:
        if fm is None:
            continue
        if fm["op"] == 0xe8:
            out.append((va, f"{fm['target']:#x}"))
        elif fm["op"] == 0xff and fm["reg"] & 7 in (2, 4) and fm["rm"][0] == "m" and fm["rm"][1] == "rip":
            slot = (va + fm["len"] + fm["rm"][4]) & M64
            out.append((va, f"got:{slot:#x}"))
    return out


def md_panic_rows(image):
    """Each panic helper is `push rbp; mov rbp,rsp; mov rdx,rdi; lea rdi,[rip+d]; mov esi,imm32; call *GOT`."""
    rows = {}
    for slot, (body, msg) in sorted(PANICS.items()):
        if image.relative.get(slot) != body:
            fail(f"panic GOT slot {slot:#x} changed")
        code = image.code(body, 0x19)
        if code[:7] != bytes.fromhex("554889e54889fa") or code[7:10] != bytes.fromhex("488d3d") or code[14] != 0xbe:
            fail(f"panic helper {body:#x} shape changed")
        text_va = body + 14 + struct.unpack_from("<i", code, 10)[0]
        if image.read(text_va, len(msg)) != msg.encode():
            fail(f"panic text at {text_va:#x} changed")
        rows[f"{slot:#x}"] = {"helper": f"{body:#x}", "text_va": f"{text_va:#x}", "message": msg,
                              "esi_imm": struct.unpack_from("<I", code, 15)[0]}
    return rows


def md_static_evidence(image):
    for slot, name in LIBC.items():
        if slot not in image.imports or image.import_name(slot) != name:
            fail(f"GOT slot {slot:#x} is not the {name} import")
    for slot, body in ((MD_MULMOD_SLOT, MD_MULMOD_CORE), (MD_REDUCE5_SLOT, MD_REDUCE5), (DIVREM_SLOT, DIVREM)):
        if image.relative.get(slot) != body:
            fail(f"GOT slot {slot:#x} no longer points at {body:#x}")
    small = [MD_HANDLERS[op][0] for op in MD_OPS] + [MD_ADDMOD_CORE, MD_LIMB_CMP]
    big = [MD_MULMOD_CORE, MD_REDUCE5, DIVREM]
    rows = fde_rows(image, small + big)
    names = {MD_ADDMOD_CORE: "addmod core (u256 add_mod)", MD_LIMB_CMP: "limb-slice borrow compare",
             MD_MULMOD_CORE: "mulmod core (u256 mul_mod, in place on the modulus)",
             MD_REDUCE5: "5-limb by 4-limb div_rem (in place)", DIVREM: "u256 div_rem (in place)"}
    for op in MD_OPS:
        names[MD_HANDLERS[op][0]] = MD_HANDLERS[op][1]
    decoded, funcs = {}, {}
    for f in small:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        calls = md_call_targets(decoded[f])
        funcs[f"{f:#x}"] = {"name_inferred": names[f], "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "calls": [{"site": f"{va:#x}", "target": t} for va, t in calls]}
    expect = {0x298fb20: ["0x29fe430"], 0x298fbe0: [f"got:{MD_MULMOD_SLOT:#x}"],
              MD_ADDMOD_CORE: [f"got:{DIVREM_SLOT:#x}", f"got:{MD_REDUCE5_SLOT:#x}"], MD_LIMB_CMP: [f"got:{BOUNDS_SLOT:#x}"]}
    for f, want in expect.items():
        if [c["target"] for c in funcs[f"{f:#x}"]["calls"]] != want:
            fail(f"{f:#x} call targets changed")
    for f in big:
        lo, hi = rows[f]
        funcs[f"{f:#x}"] = {"name_inferred": names[f], "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest()}
    checks = {}
    for va, hx, what in MD_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": opcode_slots(image, MD_HANDLERS),
           "checked_bytes": checks, "panic_helpers": md_panic_rows(image),
           "got_slots": {f"{MD_MULMOD_SLOT:#x}": f"{MD_MULMOD_CORE:#x}", f"{MD_REDUCE5_SLOT:#x}": f"{MD_REDUCE5:#x}",
                         f"{DIVREM_SLOT:#x}": f"{DIVREM:#x}"},
           "libc_imports": {f"{k:#x}": v for k, v in sorted(LIBC.items())},
           "interpreter_offsets": {"stack_ptr": f"{I_STACK_PTR:#x}", "stack_len": f"{I_STACK_LEN:#x}"},
           "results": {"ok": R_OK, "underflow": R_UNDERFLOW}}
    return out, decoded, rows


# ---------------------------------------------------------------- evaluation
MD_MODEL_MUTANTS = ["addmod_wrap", "addmod_zero_returns_sum", "addmod_le", "core_keeps_n", "mulmod_trunc",
                 "mulmod_zero_returns_a", "reduce5_low4", "underflow_2d"]
MD_BYTE_MUTANTS = [
    (0x298fbca, 0x2d, "ADDMOD: underflow result 0x2c -> 0x2d"),
    (0x298fc8f, 0x2d, "MULMOD: underflow result 0x2c -> 0x2d"),
    (0x298fb31, 0x02, "ADDMOD: arity check cmp $3 -> cmp $2"),
    (0x29fe456, 0x85, "ADDMOD core: zero-modulus je -> jne"),
    (0x29fe489, 0x83, "ADDMOD core: top-limb carry jb -> jae"),
    (0x29fe4cc, 0x73, "ADDMOD core: sum < modulus jb -> jae"),
    (0x29fe55a, 0x00, "ADDMOD core: carry limb 1 -> 0"),
    (0x43bfcad, 0x85, "MULMOD core: zero-modulus je -> jne"),
    (0x43be010, 0x93, "limb compare: setb -> setae"),
    (0x43c1f6d, 0x01, "5-limb div_rem: top divisor limb test cmp $0 -> cmp $1"),
]


def md_outcome(c, want, got):
    if "error" in got:
        return "error"
    kind = c["op"]
    if kind == "reduce5":
        if "panic" in got:
            return "reduce5/panic-" + got["panic"].replace(" ", "-")
        num, d = c["num"], c["d"]
        return "reduce5/" + ("num<d" if num < d else f"num{limbs(num)}/d{limbs(d)}")
    if kind in ("addmod_core", "mulmod_core"):
        a, b, n = c["a"], c["b"], c["n"]
        name = kind
    else:
        name = MD_HANDLERS[kind][1]
        if got["ret"] == R_UNDERFLOW:
            return name + "/underflow"
        if got["ret"] != R_OK:
            return name + f"/r{got['ret']:#x}"
        a, b, n = c["stack"][-1], c["stack"][-2], c["stack"][-3]
    if n == 0:
        return name + "/zero-modulus"
    if n == 1:
        return name + "/modulus-one"
    if kind in (0x08, "addmod_core"):
        s = a + b
        if s >> 256:
            return name + "/carry-5-limb-div_rem"
        return name + ("/sum<n-unreduced" if s < n else "/sum=n" if s == n else "/u256-div_rem")
    p = a * b
    if p < n:
        return name + "/product<n"
    return name + f"/p{limbs(p)}/n{limbs(n)}" + ("/exact" if p % n == 0 else "")


# ================================================================ ex: EXP + comparison/bitwise/shift/CLZ
EX_EXP_OP, EX_EXP_BODY = 0x0a, 0x298f6a0
EX_POW = 0x29fcfb0  # direct callee of the EXP body: (out, &base, &exponent), square-and-multiply
EX_HANDLERS = {  # opcode -> (body, inferred EVM name, arity, minimum spec byte or None)
    0x0a: (EX_EXP_BODY, "EXP", 2, None),
    0x10: (0x2998720, "LT", 2, None),
    0x11: (0x29986b0, "GT", 2, None),
    0x12: (0x2998e00, "SLT", 2, None),
    0x13: (0x2998a90, "SGT", 2, None),
    0x14: (0x2998630, "EQ", 2, None),
    0x15: (0x2999070, "ISZERO", 1, None),
    0x16: (0x2998fd0, "AND", 2, None),
    0x17: (0x2998f80, "OR", 2, None),
    0x18: (0x2999020, "XOR", 2, None),
    0x19: (0x2998830, "NOT", 1, None),
    0x1a: (0x2998ef0, "BYTE", 2, None),
    0x1b: (0x2998b80, "SHL", 2, 5),
    0x1c: (0x2998cc0, "SHR", 2, 5),
    0x1d: (0x2998870, "SAR", 2, 5),
    0x1e: (0x2998790, "CLZ", 1, 0xd),
}
EX_OPS = tuple(sorted(EX_HANDLERS))
EX_BIT_OPS = tuple(op for op in EX_OPS if op != EX_EXP_OP)
EX_CLAIMED = tuple(EX_HANDLERS[op][0] for op in EX_OPS) + (EX_POW,)
EX_I_GAS, EX_I_SPEC = 0x188, 0x1a9  # interpreter (rdi) offsets beside the shared stack pointer / length
EX_H_PARAMS, EX_P_BYTE_COST = 0x250, 0x18  # host (rsi) +0x250 -> parameter block; +0x18 = gas per exponent byte
EX_R_OUT_OF_GAS, EX_R_NOT_ACTIVATED = 0x20, 0x2b
EX_HOST_AT = 0x7d00_0100_0000
EX_HOST_SIZE = 0x300
EX_PARAMS_AT = 0x7d00_0200_0000
EX_PARAMS_SIZE = 0x40
EX_HOST_FILL = 0x4e


# ---------------------------------------------------------------- reconstruction: EXP
def ex_exp_bytes(e, mut=frozenset()):
    """Significant bytes of the exponent: (255 - leading zeros) / 8 + 1, i.e. ceil(bits / 8)."""
    if "bytes_floor" in mut:
        return e.bit_length() // 8
    if "bytes_words" in mut:
        return (e.bit_length() + 255) // 256
    return (e.bit_length() + 7) // 8


def ex_exp_cost(e, per_byte, mut=frozenset()):
    """Dynamic gas: 0 for a zero exponent, else bytes * per_byte saturated at 2^64 - 1 (jo arm)."""
    if e == 0:  # without the je the byte formula would give 1 (255 - 256 borrows, cmovae keeps 0, 0 / 8 + 1)
        return per_byte if "zero_exp_charged" in mut else 0
    cost = ex_exp_bytes(e, mut) * per_byte
    if "cost_wraps" in mut:
        return cost & M64
    return min(cost, M64)


def ex_power(b, e, mut=frozenset()):
    """The helper: b ** e modulo 2^256 (0 ** 0 = 1)."""
    if "pow_zero_zero" in mut and b == 0 and e == 0:
        return 0
    if "pow_low_exp" in mut:
        e &= M64
    if "pow_swap" in mut:
        b, e = e, b
    return pow(b, e, 1 << 256)


def ex_apply(op, a, b, mut=frozenset()):
    """EVM result of opcode `op`; a = stack top, b = the word below it (None for unary)."""
    if op == 0x10:
        return int(b < a) if "lt_swapped" in mut else int(a < b)
    if op == 0x11:
        return int(a > b)
    if op == 0x12:
        return int(a < b) if "slt_unsigned" in mut else int(signed(a) < signed(b))
    if op == 0x13:
        return int(signed(a) > signed(b))
    if op == 0x14:
        return int(a & M64 == b & M64) if "eq_low_limb" in mut else int(a == b)
    if op == 0x15:
        return int(a & M64 == 0) if "iszero_low_limb" in mut else int(a == 0)
    if op == 0x16:
        return a & b
    if op == 0x17:
        return a | b
    if op == 0x18:
        return a ^ b
    if op == 0x19:
        return (a ^ M64) if "not_low_limb" in mut else a ^ M256
    if op == 0x1a:
        if a >= 32:
            return 0
        if "byte_little_endian" in mut:
            return (b >> (8 * a)) & 0xff
        return (b >> (8 * (31 - a))) & 0xff
    if op == 0x1b:
        return (b << a) & M256 if a < 256 else 0
    if op == 0x1c:
        limit = 255 if "shr_limit_255" in mut else 256
        return b >> a if a < limit else 0
    if op == 0x1d:
        if a >= 256:
            return 0 if "sar_big_zero" in mut else (M256 if b & SIGN else 0)
        return (signed(b) >> a) & M256
    if op == 0x1e:
        if "clz_zero_255" in mut and a == 0:
            return 255
        return 256 - a.bit_length()
    fail(f"no reconstruction for opcode {op:#x}")


# ---------------------------------------------------------------- reconstruction: one handler step
def ex_check_case(c):
    """Reject inputs outside the interpreter's types: 256-bit words, a byte spec, 64-bit gas and price."""
    if c["op"] not in EX_HANDLERS:
        fail(f"opcode {c['op']:#x} has no reconstructed handler")
    if not 0 <= c["spec"] <= 0xff or not 0 <= c["gas"] <= M64 or not 0 <= c["per_byte"] <= M64:
        fail("spec byte, gas or per-byte price out of range")
    if any(not 0 <= w <= M256 for w in c["stack"]):
        fail("stack word out of the 256-bit range")


def ex_model(c, mut=frozenset()):
    """Result code, stack words, stored length and remaining gas after the handler body."""
    op, stack, gas = c["op"], list(c["stack"]), c["gas"]
    _, _, arity, gate = EX_HANDLERS[op]
    if "shift_gate_4" in mut and gate == 5:
        gate = 4
    if "no_spec_gate" in mut:
        gate = None
    if gate is not None and c["spec"] < gate:  # the gate is checked before the stack length
        return {"ret": EX_R_NOT_ACTIVATED, "stack": stack, "n": len(stack), "gas": gas}
    if len(stack) < arity:
        ret = EX_R_NOT_ACTIVATED if "underflow_2b" in mut else R_UNDERFLOW
        return {"ret": ret, "stack": stack, "n": len(stack), "gas": gas}
    if op != EX_EXP_OP:
        a = stack.pop()
        b = stack.pop() if arity == 2 else None
        stack.append(ex_apply(op, a, b, mut))
        return {"ret": R_OK, "stack": stack, "n": len(stack), "gas": gas}
    base, e = stack[-1], stack[-2]
    n = len(stack) - 1  # the length is stored before the gas check, so out of gas leaves it popped
    cost = ex_exp_cost(e, c["per_byte"], mut)
    if gas < cost:
        if "oog_keeps_len" in mut:
            n += 1
        return {"ret": EX_R_OUT_OF_GAS, "stack": stack, "n": n, "gas": gas}
    stack.pop()
    stack[-1] = ex_power(base, e, mut)
    return {"ret": R_OK, "stack": stack, "n": n, "gas": gas - cost}


def ex_run_case(m, c):
    ex_check_case(c)
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(INTERP_AT, INTERP_SIZE, bytes([INTERP_FILL]) * INTERP_SIZE)
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, len(c["stack"]))
    put(it, EX_I_GAS, 8, c["gas"])
    put(it, EX_I_SPEC, 1, c["spec"])
    host = m.add_region(EX_HOST_AT, EX_HOST_SIZE, bytes([EX_HOST_FILL]) * EX_HOST_SIZE)
    put(host, EX_H_PARAMS, 8, EX_PARAMS_AT)
    params = m.add_region(EX_PARAMS_AT, EX_PARAMS_SIZE, bytes([EX_HOST_FILL]) * EX_PARAMS_SIZE)
    put(params, EX_P_BYTE_COST, 8, c["per_byte"])
    side = bytes(host) + bytes(params)
    slots = len(c["stack"]) + 2
    stk = m.add_region(STK_AT, 32 * slots, stack_bytes(c["stack"], slots))
    before = bytes(it)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = INTERP_AT, EX_HOST_AT
    m.run(EX_HANDLERS[c["op"]][0], limit=200000)
    rest = bytearray(it)
    for off in (I_STACK_LEN, EX_I_GAS):
        rest[off:off + 8] = before[off:off + 8]
    return {"ret": m.regs[0] & 0xff, "n": u(it, I_STACK_LEN, 8), "gas": u(it, EX_I_GAS, 8), "stack_raw": bytes(stk),
            "regs_ok": callee_ok(m), "interp_ok": bytes(rest) == before,
            "host_ok": bytes(host) + bytes(params) == side}


def ex_compare(c, want, got):
    return (want["ret"] == got["ret"] and want["n"] == got["n"] and want["gas"] == got["gas"] and got["regs_ok"]
            and got["interp_ok"] and got["host_ok"] and got["stack_raw"] == expected_raw(c, want))


# ---------------------------------------------------------------- cases
EX_EXP_CASES = 4000
EX_PER_OP = 400
EX_EDGE = (0, 1, 2, 3, 7, 8, 10, 31, 32, 33, 0x7f, 0x80, 0xff, 0x100, 0x101, 257, 0x1_0000,
        M64 - 1, M64, 1 << 64, (1 << 64) + 1, M128, 1 << 128, (1 << 192) - 1, 1 << 192,
        SIGN - 1, SIGN, SIGN + 1, M256 - 6, M256 - 1, M256, M256 ^ SIGN ^ 1)
EX_SPECS = tuple(range(0x16)) + (0x7f, 0xff)
EX_PER_BYTE = (50, 10, 0, 1, 50, 0x7fff_ffff, 1 << 59, M64 // 32, M64 // 31, M64)
EX_EXP_MODES = ("edge", "random", "small", "byte-edge", "zero-exp", "oog", "exact-gas", "random", "pow2-base",
             "underflow", "overflow-cost", "odd-base", "long-exp", "zero-base", "one-base", "neg-one")
EX_BIT_MODES = ("edge", "random", "near", "equal", "limb", "shift", "random", "edge", "sign", "small", "underflow",
             "spec")


def ex_rand_word(s):
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def ex_pick_mode(modes, k):
    return modes[(k // 2) % len(modes)] if k % 2 == 0 else modes[k % len(modes)]


def ex_byte_edge(s):
    """An exponent right at a byte-count boundary: 2^(8k), 2^(8k) - 1 or 2^(8k) + 1."""
    k = s.below(33)
    return ((1 << (8 * k)) + s.pick((0, -1, 1))) & M256


def ex_make_exp_case(s, k):
    mode = ex_pick_mode(EX_EXP_MODES, k)
    per_byte = s.pick(EX_PER_BYTE)
    gas = s.pick((M64, 1 << 40, 30_000_000, int.from_bytes(s.take(8), "little")))
    extra = [ex_rand_word(s) for _ in range(s.pick((0, 0, 1, 3)))]
    c = {"op": EX_EXP_OP, "mode": mode, "spec": EX_SPECS[k % len(EX_SPECS)], "per_byte": per_byte, "gas": gas}
    if mode == "underflow":
        return dict(c, stack=[s.pick(EX_EDGE)] * s.below(2))
    if mode == "edge":
        b, e = s.pick(EX_EDGE), s.pick(EX_EDGE)
    elif mode == "small":
        b, e = s.below(20), s.below(300)
    elif mode == "byte-edge":
        b, e = ex_rand_word(s), ex_byte_edge(s)
    elif mode == "zero-exp":
        b, e = ex_rand_word(s), 0
        c["gas"] = s.pick((0, 1, gas))
    elif mode in ("oog", "exact-gas"):
        b, e = ex_rand_word(s), s.pick((ex_rand_word(s), ex_byte_edge(s))) or 1
        c["per_byte"] = s.pick((50, 10, 1, 0x7fff_ffff))
        cost = ex_exp_cost(e, c["per_byte"])
        gas = cost - s.pick((1, 2, cost)) if mode == "oog" else cost + s.pick((0, 0, 1))
        c["gas"] = max(gas, 0)
    elif mode == "pow2-base":
        b, e = 1 << s.below(256), s.below(600)
    elif mode == "overflow-cost":
        b, e = ex_rand_word(s), ex_rand_word(s) or 3
        c["per_byte"] = s.pick((M64, M64 // 2, 1 << 62, M64 // 31, M64 // 32))
        c["gas"] = s.pick((M64, M64 - 1, gas))
    elif mode == "odd-base":
        b, e = ex_rand_word(s) | 1, ex_rand_word(s)
    elif mode == "long-exp":
        b, e = ex_rand_word(s), int.from_bytes(s.take(32), "little") | (1 << 255)
    elif mode == "zero-base":
        b, e = 0, s.pick((0, 1, ex_rand_word(s)))
    elif mode == "one-base":
        b, e = 1, ex_rand_word(s)
    elif mode == "neg-one":
        b, e = M256, s.pick((ex_rand_word(s), 2, 3, M256))
    else:
        b, e = ex_rand_word(s), ex_rand_word(s)
    return dict(c, stack=extra + [e, b])


def ex_bit_word(s, mode):
    if mode == "edge":
        return s.pick(EX_EDGE)
    if mode == "sign":
        return SIGN | ex_rand_word(s) if s.below(2) else ex_rand_word(s) & (M256 ^ SIGN)
    if mode == "small":
        return s.below(300)
    return ex_rand_word(s) if s.below(3) else s.pick(EX_EDGE)


def ex_make_bit_case(s, op, k):
    _, _, arity, gate = EX_HANDLERS[op]
    mode = EX_BIT_MODES[k % len(EX_BIT_MODES)]
    spec = s.pick(EX_SPECS)
    if gate is not None:
        spec = s.pick((gate, gate + 1, 0x14, 0x15, 0xff)) if mode != "spec" else s.pick((0, gate - 1, gate, gate - 2))
    extra = [ex_rand_word(s) for _ in range(s.pick((0, 0, 1, 3)))]
    # these bodies never touch gas or the parameter block; both are set so a stray write is caught
    c = {"op": op, "spec": spec, "mode": mode, "gas": (0x9e37_79b9_7f4a_7c15 * (k + 1)) & M64,
         "per_byte": EX_PER_BYTE[k % len(EX_PER_BYTE)]}
    if mode == "underflow":
        return dict(c, stack=[ex_bit_word(s, "edge")] * s.below(arity))
    b = ex_bit_word(s, mode)
    a = ex_bit_word(s, mode)
    if mode == "near":
        a = (b + s.pick((1, -1, 1 << 64, -(1 << 64), 1 << 128, 1 << 192, SIGN))) & M256
    elif mode == "equal":
        a = b
    elif mode == "limb":
        a = b ^ (1 << (64 * s.below(4) + s.below(64)))
    elif op == 0x1a and s.below(4):
        a = s.pick((s.below(32), s.below(40), 31, 32, 0, M256, 1 << 64))
    elif mode == "shift" or (op in (0x1b, 0x1c, 0x1d) and s.below(4)):
        a = s.pick((s.below(300), s.below(32), 255, 256, 64 * s.below(4), 64 * s.below(4) + s.below(64),
                    (1 << 64) + s.below(3), 1 << 128, M256, 0x100 | (1 << 70)))
    if op in (0x15, 0x19, 0x1e) and mode in ("near", "limb", "shift") and s.below(2):
        a = s.pick((0, 1 << s.below(256), (1 << s.below(256)) - 1))
    return dict(c, stack=extra + ([b, a] if arity == 2 else [a]))


def ex_exp_cases():
    s = Stream("re11-exp-115")
    return [ex_make_exp_case(s, k) for k in range(EX_EXP_CASES)]


def ex_bit_cases():
    s = Stream("re11-bitwise-115")
    return [ex_make_bit_case(s, op, k) for op in EX_BIT_OPS for k in range(EX_PER_OP)]


# ---------------------------------------------------------------- direct helper cases
EX_DIRECT = 2000
EX_BUF_AT = 0x7d00_0400_0000
EX_BUF_FILL = 0x3d
EX_POW_MODES = ("random", "small", "edge", "byte-edge", "zero-exp", "pow2-base", "even-base", "long-exp", "limbs",
             "square")


def ex_run_pow(m, c):
    """The helper called directly: rdi = 32-byte output, rsi = &base, rdx = &exponent (consumed in place)."""
    if not (0 <= c["b"] <= M256 and 0 <= c["e"] <= M256):
        fail("helper operand out of the 256-bit range")
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    buf = m.add_region(EX_BUF_AT, 0xa0, bytes([EX_BUF_FILL]) * 0xa0)
    put(buf, 0x40, 32, c["b"])
    put(buf, 0x70, 32, c["e"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = EX_BUF_AT + 0x10, EX_BUF_AT + 0x40, EX_BUF_AT + 0x70
    m.run(EX_POW, limit=200000)
    guard = bytes(buf[:0x10]) + bytes(buf[0x30:0x40]) + bytes(buf[0x60:0x70]) + bytes(buf[0x90:])
    return {"out": u(buf, 0x10, 32), "b": u(buf, 0x40, 32), "e": u(buf, 0x70, 32), "regs_ok": callee_ok(m),
            "guard_ok": guard == bytes([EX_BUF_FILL]) * 0x40}


def ex_make_pow(s, k):
    mode = ex_pick_mode(EX_POW_MODES, k)
    if mode == "small":
        b, e = s.below(1 << 16), s.below(1 << 12)
    elif mode == "edge":
        b, e = s.pick(EX_EDGE), s.pick(EX_EDGE)
    elif mode == "byte-edge":
        b, e = ex_rand_word(s), ex_byte_edge(s)
    elif mode == "zero-exp":
        b, e = s.pick((0, ex_rand_word(s))), 0
    elif mode == "pow2-base":
        b, e = 1 << s.below(256), s.pick((s.below(300), ex_rand_word(s)))
    elif mode == "even-base":
        b, e = ((ex_rand_word(s) | 1) << s.below(8)) & M256, s.below(1 << s.pick((4, 6, 8)))
    elif mode == "long-exp":
        b, e = ex_rand_word(s), int.from_bytes(s.take(32), "little") | (1 << 255)
    elif mode == "limbs":
        b, e = int.from_bytes(s.take(8 * (1 + s.below(4))), "little"), 1 << (64 * s.below(4) + s.below(64))
    elif mode == "square":
        b, e = ex_rand_word(s), s.pick((2, 3, 4, (1 << 64) - 1))
    else:
        b, e = ex_rand_word(s), ex_rand_word(s)
    return {"mode": mode, "b": b, "e": e}


def ex_all_pow():
    s = Stream("re11-exp-pow-helper-115")
    return [ex_make_pow(s, k) for k in range(EX_DIRECT)]


# ---------------------------------------------------------------- static evidence
EX_CHECKED = (
    (0x298f6a4, "48 83 f8 02", "EXP: two operands required"),
    (0x298f6c8, "48 89 47 30", "EXP: the new length is stored before any gas check"),
    (0x298f6ec, "0f 84 89 00 00 00", "EXP: zero exponent skips the dynamic charge"),
    (0x298f706, "bb 7f 00 00 00", "EXP: bsr default for an all-zero low half (0x7f ^ 0x3f + 0x40)"),
    (0x298f747, "ba ff 00 00 00", "EXP: 255 - leading zeros"),
    (0x298f75a, "c1 e8 03", "EXP: / 8"),
    (0x298f75d, "48 ff c0", "EXP: + 1 = significant exponent bytes"),
    (0x298f753, "48 8b 89 50 02 00 00", "EXP: host +0x250 = parameter block"),
    (0x298f760, "48 f7 61 18", "EXP: bytes * parameter +0x18 (gas per exponent byte)"),
    (0x298f764, "70 6c", "EXP: multiply overflow takes the saturating arm"),
    (0x298f7d2, "48 c7 c0 ff ff ff ff", "EXP: saturated cost 2^64 - 1"),
    (0x298f766, "48 8b 8f 88 01 00 00", "EXP: interpreter +0x188 = remaining gas"),
    (0x298f770, "72 73", "EXP: remaining < cost -> out of gas"),
    (0x298f7e5, "b0 20", "EXP: result 0x20 (out of gas)"),
    (0x298f7b1, "e8 fa d7 06 00", "EXP: call the helper 0x29fcfb0 (out, &top, &copy of second)"),
    (0x298f7cf, "b0 2c", "EXP: result 0x2c (stack underflow)"),
    (0x29fcfe8, "83 f8 04", "helper: four zero limbs = zero exponent"),
    (0x29fcfed, "b8 01 00 00 00", "helper: zero exponent returns 1"),
    (0x29fd16a, "f6 c2 01", "helper: low exponent bit selects the multiply"),
    (0x29fd123, "48 0f ac fa 01", "helper: exponent shifted right by one in place"),
    (0x29fd161, "83 ff 04", "helper: loop ends when the exponent is zero"),
    (0x2998720, "48 8b 47 30", "LT: stack length at interpreter +0x30"),
    (0x299872a, "48 8b 4f 28", "LT: stack base pointer at interpreter +0x28"),
    (0x2998763, "0f 92 c0", "LT: setb after the four-limb cmp/sbb chain (top < second)"),
    (0x2998782, "b0 2c", "LT: result 0x2c (stack underflow)"),
    (0x2998b80, "80 bf a9 01 00 00 05", "SHL: spec byte at interpreter +0x1a9 must be >= 5"),
    (0x2998bce, "48 3d 00 01 00 00", "SHL: shift limb 0 compared with 0x100"),
    (0x2998cb2, "b0 2b", "SHL: result 0x2b (not activated)"),
    (0x2998790, "80 bf a9 01 00 00 0d", "CLZ: spec byte at interpreter +0x1a9 must be >= 0xd"),
    (0x29987bd, "41 b8 7f 00 00 00", "CLZ: bsr destination preset to 0x7f so a zero low limb gives 0x40 + 0x40"),
    (0x29987e0, "49 83 e9 80", "CLZ: sub $-0x80 adds 128 when the upper half is zero"),
)
EX_EXPECTED_CALLS = {EX_EXP_BODY: [(0x298f7b1, "direct", EX_POW)]}  # every other claimed body: no call at all


def ex_role(f):
    if f == EX_POW:
        return "0xa", "256-bit wrapping square-and-multiply power, exponent consumed in place (inferred role)"
    op = next(op for op in EX_OPS if EX_HANDLERS[op][0] == f)
    return f"{op:#x}", EX_HANDLERS[op][1] + " handler (inferred name)"


def ex_call_sites(decoded, lo, hi):
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


def ex_static_evidence(image):
    rows = fde_rows(image, list(EX_CLAIMED))
    decoded, funcs = {}, {}
    for f in EX_CLAIMED:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        calls = ex_call_sites(decoded[f], lo, hi)
        if calls != EX_EXPECTED_CALLS.get(f, []):
            fail(f"body {f:#x} has unexpected calls {[(hex(a), k) for a, k, _ in calls]}")
        op, what = ex_role(f)
        gate = next((EX_HANDLERS[o][3] for o in EX_OPS if EX_HANDLERS[o][0] == f), None)
        arity = next((EX_HANDLERS[o][2] for o in EX_OPS if EX_HANDLERS[o][0] == f), None)
        funcs[f"{f:#x}"] = {"opcode": op, "role": what, "arity": arity, "min_spec_byte": gate,
                            "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "calls": len(calls)}
    checks = {}
    for va, hx, what in EX_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": opcode_slots(image, EX_HANDLERS),
           "checked_bytes": checks,
           "interpreter_offsets": {"stack_ptr": f"{I_STACK_PTR:#x}", "stack_len": f"{I_STACK_LEN:#x}",
                                   "gas_remaining": f"{EX_I_GAS:#x}", "spec_byte": f"{EX_I_SPEC:#x}"},
           "host_offsets": {"parameter_block": f"{EX_H_PARAMS:#x}", "gas_per_exponent_byte": f"{EX_P_BYTE_COST:#x}"},
           "results": {"ok": R_OK, "out_of_gas": EX_R_OUT_OF_GAS, "not_activated": EX_R_NOT_ACTIVATED,
                       "underflow": R_UNDERFLOW}}
    return out, decoded


# ---------------------------------------------------------------- negative controls
EX_EXP_MUTANTS = ["bytes_floor", "bytes_words", "zero_exp_charged", "cost_wraps", "pow_zero_zero", "pow_low_exp",
               "pow_swap", "oog_keeps_len"]
EX_BIT_MUTANTS = ["lt_swapped", "slt_unsigned", "eq_low_limb", "iszero_low_limb", "not_low_limb",
               "byte_little_endian", "shr_limit_255", "sar_big_zero", "clz_zero_255", "shift_gate_4",
               "no_spec_gate", "underflow_2b"]
EX_POW_MUTANTS = ["pow_zero_zero", "pow_low_exp", "exp_untouched"]
EX_EXP_BYTE_MUTANTS = [
    (0x298f6a7, 0x03, "EXP: operand count 2 -> 3"),
    (0x298f7d0, 0x2d, "EXP: underflow result 0x2c -> 0x2d"),
    (0x298f7e6, 0x21, "EXP: out-of-gas result 0x20 -> 0x21"),
    (0x298f75c, 0x04, "EXP: byte count shift 3 -> 4"),
    (0x298f748, 0xfe, "EXP: 255 - lz -> 254 - lz"),
    (0x298f770, 0x76, "EXP: out of gas jb -> jbe"),
    (0x298f6ed, 0x85, "EXP: zero-exponent je -> jne"),
    (0x298f764, 0x71, "EXP: overflow jo -> jno"),
]
EX_BIT_BYTE_MUTANTS = [
    (0x2998764, 0x93, "LT: setb -> setae"),
    (0x2998783, 0x2d, "LT: underflow result 0x2c -> 0x2d"),
    (0x29986fd, 0x93, "GT: setb -> setae"),
    (0x2998e97, 0x9f, "SLT: setl -> setg on differing signums"),
    (0x2998b26, 0x9c, "SGT: setg -> setl on differing signums"),
    (0x2998682, 0xfe, "EQ: pmovmskb mask 0xffff -> 0xfffe (byte 0 ignored)"),
    (0x2998ff8, 0x56, "AND: andps -> orps"),
    (0x2998fa8, 0x54, "OR: orps -> andps"),
    (0x2998853, 0xeb, "NOT: pxor with all-ones -> por"),
    (0x2998f29, 0x1f, "BYTE: index bound 0x20 -> 0x1f"),
    (0x2998b86, 0x06, "SHL: spec gate 5 -> 6"),
    (0x2998bd1, 0x00, "SHL: shift bound 0x100 -> 0 (every shift saturates)"),
    (0x2998d0f, 0x00, "SHR: shift bound 0x100 -> 0 (every shift saturates)"),
    (0x2998d41, 0xe7, "SHR: shr -> shl on the first limb pair"),
    (0x29988c3, 0x00, "SAR: shift bound 0x100 -> 0 (every shift saturates)"),
    (0x2998a39, 0xf0, "SAR: saturation sign read from limb 2 instead of limb 3"),
    (0x2998796, 0x0e, "CLZ: spec gate 0xd -> 0xe"),
    (0x29987bf, 0x7e, "CLZ: bsr preset 0x7f -> 0x7e (zero word gives 257)"),
]
EX_POW_BYTE_MUTANTS = [
    (0x29fcfee, 0x02, "helper: zero exponent returns 1 -> 2"),
    (0x29fd16c, 0x02, "helper: multiply on bit 0 -> bit 1"),
    (0x29fd163, 0x03, "helper: loop end at 4 zero limbs -> 3"),
]


def rejects(action):
    try:
        action()
    except ToolError:
        return 1
    return 0


def with_text_patch(image, va, raw):
    """A copy of the image (sections and relocations shared, digest not rechecked) with code bytes replaced."""
    data = bytearray(image.data)
    off = va - image.text["address"] + image.text["offset"]
    data[off:off + len(raw)] = raw
    patched = object.__new__(Image)
    patched.__dict__.update(image.__dict__)
    patched.data = bytes(data)
    return patched


def with_slot(image, where, target):
    patched = object.__new__(Image)
    patched.__dict__.update(image.__dict__)
    patched.relative = dict(image.relative)
    patched.relative[where] = target
    return patched


def ex_outcome(c, want, got):
    if "error" in got:
        return "error"
    op = c["op"]
    name = EX_HANDLERS[op][1]
    if got["ret"] == R_UNDERFLOW:
        return name + "/underflow"
    if got["ret"] == EX_R_NOT_ACTIVATED:
        return name + "/not-activated"
    if op == EX_EXP_OP:
        e = c["stack"][-2]
        sat = "-saturated" if ex_exp_bytes(e) * c["per_byte"] > M64 else ""
        if got["ret"] == EX_R_OUT_OF_GAS:
            return "EXP/out-of-gas" + sat
        if got["ret"] != R_OK:
            return f"EXP/r{got['ret']:#x}"
        return "EXP/zero-exponent" if e == 0 else "EXP/b%02d%s" % (ex_exp_bytes(e), sat)
    if got["ret"] != R_OK:
        return name + f"/r{got['ret']:#x}"
    a = c["stack"][-1]
    if op in (0x10, 0x11, 0x12, 0x13, 0x14, 0x15):
        return name + ("/true" if want and want["stack"][-1] else "/false")
    if op == 0x1a:
        return name + ("/index" if a < 32 else "/out-of-range")
    if op in (0x1b, 0x1c):
        return name + ("/zero-shift" if a == 0 else "/shift" if a < 256 else "/saturated")
    if op == 0x1d:
        neg = "-neg" if c["stack"][-2] & SIGN else "-pos"
        return name + ("/zero-shift" if a == 0 else "/shift" if a < 256 else "/saturated") + neg
    if op == 0x1e:
        return name + ("/zero" if a == 0 else "/limb%d" % ((a.bit_length() - 1) // 64))
    return name + "/value"


def ex_pow_outcome(c):
    e = c["e"]
    if e == 0:
        return "POW/zero-exponent"
    return "POW/e-bits%03d" % e.bit_length() if e.bit_length() <= 8 else "POW/e-limbs%d" % ((e.bit_length() + 63) // 64)


# ---------------------------------------------------------------- ex: one driver for handler and helper cases
def ex_all_cases():
    """EXP handler cases, then 0x10..0x1e handler cases, then direct calls of the power helper (op "pow")."""
    return ([dict(c, grp="exp") for c in ex_exp_cases()] + [dict(c, grp="bit") for c in ex_bit_cases()]
            + [dict(c, op="pow", grp="pow") for c in ex_all_pow()])


def ex_family_model(c, mut=frozenset()):
    if c["op"] == "pow":  # the helper consumes the exponent buffer in place (shifted right until zero)
        return {"out": ex_power(c["b"], c["e"], mut), "e": c["e"] if "exp_untouched" in mut else 0}
    return ex_model(c, mut)


def ex_family_run(m, c):
    return ex_run_pow(m, c) if c["op"] == "pow" else ex_run_case(m, c)


def ex_family_compare(c, want, got):
    if c["op"] == "pow":
        return (got["out"] == want["out"] and got["b"] == c["b"] and got["e"] == want["e"] and got["regs_ok"]
                and got["guard_ok"])
    return ex_compare(c, want, got)


def ex_family_outcome(c, want, got):
    if "error" in got:
        return "error"
    return ex_pow_outcome(c) if c["op"] == "pow" else ex_outcome(c, want, got)


def ex_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    cases = ex_exp_cases() + ex_bit_cases() if cases is None else cases
    return evaluate(FAM_EX, image, override, mut, stop_on_first, machine, cases)


def ex_evaluate_pow(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    cases = [dict(c, op="pow") for c in (ex_all_pow() if cases is None else cases)]
    return evaluate(FAM_EX, image, override, mut, stop_on_first, machine, cases)


# ================================================================ shared evaluation, controls and output
class Family:
    def __init__(self, key, title, handlers, all_cases, model, run_case, compare, outcome, static, model_mutants,
                 byte_mutants, big):
        self.key, self.title, self.handlers = key, title, handlers
        self.all_cases, self.model, self.run_case, self.compare, self.outcome = (all_cases, model, run_case,
                                                                                 compare, outcome)
        self.static, self.model_mutants, self.byte_mutants, self.big = static, model_mutants, byte_mutants, big


FAM_EX = Family(
    "ex", "EXP + power helper, LT..SAR, CLZ", EX_HANDLERS, ex_all_cases, ex_family_model, ex_family_run,
    ex_family_compare, ex_family_outcome, ex_static_evidence,
    [(n, n, "exp") for n in EX_EXP_MUTANTS] + [(n, n, "bit") for n in EX_BIT_MUTANTS]
    + [("direct " + n, n, "pow") for n in EX_POW_MUTANTS],
    [r + ("exp",) for r in EX_EXP_BYTE_MUTANTS] + [r + ("bit",) for r in EX_BIT_BYTE_MUTANTS]
    + [r + ("pow",) for r in EX_POW_BYTE_MUTANTS], ())
FAMILIES = (
    Family("ar", "MUL/SUB/SIGNEXTEND", AR_HANDLERS, ar_all_cases, ar_model, ar_run_case, ar_compare, ar_outcome,
           ar_static_evidence, AR_MODEL_MUTANTS, AR_BYTE_MUTANTS, ()),
    Family("dv", "SDIV/MOD/SMOD + u256 div_rem", DV_HANDLERS, dv_all_cases, dv_model, dv_run_case, dv_compare,
           dv_outcome, dv_static_evidence, DV_MODEL_MUTANTS, DV_BYTE_MUTANTS, (DIVREM,)),
    Family("md", "ADDMOD/MULMOD + 5-limb div_rem + mulmod core", MD_HANDLERS, md_all_cases, md_model, md_run_case,
           md_compare, md_outcome, md_static_evidence, MD_MODEL_MUTANTS, MD_BYTE_MUTANTS, (MD_MULMOD_CORE, MD_REDUCE5)),
    FAM_EX,
)
SAMPLE_EVERY = 10  # cases-sample.tsv keeps every 10th case of each family; the full table's SHA-256 is in summary.json


def evaluate(fam, image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    """Run every case of `fam` on the real machine code and compare it with the reconstruction."""
    m = machine or PathMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else fam.all_cases()):
        try:
            want = fam.model(c, mut)
            got = fam.run_case(m, c)
            ok = fam.compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        except Boundary as exc:
            want, got, ok = None, {"error": f"reached {exc.kind}"}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


def group_cases(cases, grp):
    return cases if grp is None else [c for c in cases if c.get("grp") == grp]


def controls(fam, image, cases):
    """Model mutants and one-byte code mutants of one family; each must produce a mismatch.

    A mutant entry may name a case group ("exp", "bit", "pow"); it then runs on that group only."""
    rows = []
    for entry in fam.model_mutants:
        label, name, grp = (entry, entry, None) if isinstance(entry, str) else entry
        _, bad, _ = evaluate(fam, image, mut=frozenset([name]), stop_on_first=True, cases=group_cases(cases, grp))
        rows.append((fam.key, "model", label, int(bad > 0)))
    for va, byte, what, *grp in fam.byte_mutants:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        sub = group_cases(cases, grp[0] if grp else None)
        _, bad, _ = evaluate(fam, image, override={va: byte}, stop_on_first=True, cases=sub)
        rows.append((fam.key, "code", f"{va:#x}={byte:#04x} {what}", int(bad > 0)))
    return rows


def input_controls(image):
    """Bad inputs: each must be refused with a ToolError."""
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    # .bss, not .tbss: TLS NOBITS addresses alias the file-backed sections that follow them
    bss = next(s for s in image.secs if s["type"] == 8 and s["name"] == ".bss")
    good = next(c for c in ex_exp_cases() if len(c["stack"]) >= 2)
    m = Machine(image)
    end = image.text["address"] + image.text["size"]
    checks = (
        ("one flipped .text byte (digest)", lambda: Image(bytes(corrupt))),
        ("code address past .text", lambda: image.code(end + 0x100, 4)),
        ("truncated ELF", lambda: Image(bytes(image.data[:len(image.data) // 2]))),
        ("read inside SHT_NOBITS " + bss["name"], lambda: image.read(bss["address"], 8)),
        ("no FDE at EXP body + 1", lambda: fde_rows(image, [EX_EXP_BODY + 1])),
        ("SHR slot rewired to the SHL body",
         lambda: opcode_slots(with_slot(image, 0x6441f00 + 8 * 0x1c, 0x2998b80), EX_HANDLERS)),
        ("MUL slot rewired to the SUB body",
         lambda: opcode_slots(with_slot(image, 0x6441210 + 8 * 0x02, 0x298f9a0), AR_HANDLERS)),
        ("checked byte changed (EXP shift 3 -> 4)",
         lambda: ex_static_evidence(with_text_patch(image, 0x298f75c, b"\x04"))),
        ("call planted in the EXP power helper",
         lambda: ex_static_evidence(with_text_patch(image, 0x29fcff7, bytes.fromhex("e800000000") + b"\x90" * 4))),
        ("stack word 2^256 (out of range)", lambda: ex_run_case(m, dict(good, stack=[1 << 256, 1]))),
        ("spec byte 0x100 (out of range)", lambda: ex_run_case(m, dict(good, spec=0x100))),
        ("helper exponent 2^256 (out of range)", lambda: ex_run_pow(m, {"b": 3, "e": 1 << 256})),
    )
    return [("all", "input", what, rejects(act)) for what, act in checks]


def case_row(fam, i, c, want, got, ok, oc):
    """One tab-separated case row: operands and results as hex or short SHA-256 tags."""
    kind = c["op"]
    if isinstance(kind, str):  # direct call of a callee body
        ops = [v for k, v in c.items() if k not in ("op", "mode") and isinstance(v, int)]
        if "error" in got:
            res = got["error"]
        elif "panic" in got:
            res = "panic=" + got["panic"]
        else:
            res = ",".join(f"{k}={wtag(v)}" for k, v in got.items()
                           if not k.endswith("_ok") and isinstance(v, int) and not isinstance(v, bool))
        n, mode = "-", c["mode"]
    else:
        st = c["stack"]
        ops = [st[-k] if len(st) >= k else None for k in (1, 2, 3)]
        kind = fam.handlers[kind][1]
        mode = c["mode"] + (f",spec={c['spec']:#x}" if "spec" in c else "")
        if "per_byte" in c:
            mode += f",per_byte={c['per_byte']:#x},gas={c['gas']:#x}"
        n = len(st)
        if "error" in got:
            res = got["error"]
        else:
            res = f"ret={got['ret']:#x},n={got['n']}" + (f",gas={got['gas']:#x}" if "gas" in got else "")
            if got["ret"] == R_OK and want is not None:
                res += f",word={wtag(want['stack'][-1])}"
    ops = (ops + [None, None, None])[:3]
    return (f"{i}\t{fam.key}\t{kind}\t{mode}\t{n}\t{wtag(ops[0])}\t{wtag(ops[1])}\t{wtag(ops[2])}\t{oc}\t{res}\t"
            f"{'yes' if ok else 'NO'}")


def generate(out, full=False):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    head = "case\tfamily\tkind\tmode\tn\top1\top2\top3\toutcome\tresult\tmatch"
    sample, missed, classes, ctl, consts = [head], [], [], [], {}
    full_lines, fams = [head], {}
    for fam in FAMILIES:
        res = fam.static(image)
        consts[fam.key], decoded = res[0], res[1]
        fde = res[2] if len(res) > 2 else {}
        cases = fam.all_cases()
        rows, bad, m = evaluate(fam, image, cases=cases)
        counts, fam_lines = {}, []
        for i, c, want, got, ok in rows:
            oc = fam.outcome(c, want, got)
            counts[oc] = counts.get(oc, 0) + 1
            line = case_row(fam, i, c, want, got, ok, oc)
            fam_lines.append(line)
            if i % SAMPLE_EVERY == 0 or not ok:
                sample.append(line)
        full_lines += fam_lines
        classes += [f"{fam.key}\t{k}\t{counts[k]}" for k in sorted(counts)]
        covered = {}
        for start, insns in sorted(decoded.items()):
            hit = total = 0
            for va, f in insns:
                if f is None:
                    continue
                run = va in m.seen
                hit += run
                total += 1
                if not run:
                    missed.append(f"{fam.key}\t{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}")
            covered[f"{start:#x}"] = [hit, total]
        for big in fam.big:
            lo, hi = fde[big]
            seen = sorted(va for va in m.seen if lo <= va < hi)
            covered[f"{big:#x}"] = {"executed_instructions": len(seen),
                                    "executed_bytes": sum(m.fetch(va)["len"] for va in seen), "fde_bytes": hi - lo,
                                    "executed_set_sha256": hashlib.sha256(
                                        "".join(f"{va:#x}\n" for va in seen).encode()).hexdigest()}
        fc = controls(fam, image, cases)
        ctl += fc
        fams[fam.key] = {"title": fam.title, "cases": len(rows), "mismatches": bad, "outcome_classes": len(counts),
                         "covered_instructions": covered,
                         "case_rows_sha256": hashlib.sha256("".join(x + "\n" for x in fam_lines).encode()).hexdigest(),
                         "negative_controls": {"total": len(fc), "detected": sum(r[3] for r in fc)}}
    ctl += input_controls(image)
    full_text = "\n".join(full_lines) + "\n"
    if full:
        (out / "cases-full.tsv").write_text(full_text)
    (out / "cases-sample.tsv").write_text("\n".join(sample) + "\n")
    (out / "outcome-classes.tsv").write_text("family\toutcome\tcases\n" + "".join(x + "\n" for x in classes))
    (out / "not-executed.tsv").write_text("family\tfunction\taddress\tlength\tbytes\topcode\n"
                                          + "".join(x + "\n" for x in missed))
    (out / "negative-controls.tsv").write_text(
        "family\tkind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "families": fams,
               "cases": sum(f["cases"] for f in fams.values()),
               "mismatches": sum(f["mismatches"] for f in fams.values()),
               "outcome_classes": len(classes),
               "full_case_table": {"rows": len(full_lines) - 1, "sha256": hashlib.sha256(full_text.encode()).hexdigest(),
                                   "sample_every": SAMPLE_EVERY},
               "negative_controls": {"total": len(ctl), "detected": sum(r[3] for r in ctl),
                                     "by_kind": {k: sum(1 for r in ctl if r[1] == k) for k in ("model", "code", "input")}}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--full", action="store_true", help="also write cases-full.tsv (every case row)")
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.full)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: summary[k] for k in ("cases", "mismatches", "outcome_classes", "negative_controls")},
                     sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
