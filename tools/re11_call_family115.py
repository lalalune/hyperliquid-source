#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM CALL, CALLCODE, DELEGATECALL and STATICCALL handlers with their shared range helper.

Eight handler bodies (one per opcode in each of the RELATIVE opcode tables 0x6441210 and 0x6441f00,
slots 0xf1/0xf2/0xf4/0xfa) and the range helper 0x29998f0 are evaluated as real machine code.  Each handler
gates on the spec byte (+0x1a9; DELEGATECALL needs it nonzero, STATICCALL above 3), pops its stack words
(gas, address, and for CALL/CALLCODE a value), lets the helper pop four more words and turn them into two
checked memory ranges (the input range is shifted by interpreter +0x18; each non-empty range may grow memory
through GOT 0x64e6de0 and a length with high limbs is status 0x24), calls the account host through GOT slot
0x64e6e08 (alternate table) or 0x64e6e00 (ordinary table), builds one 0xd0-byte call record, boxes it,
retires the previous pending action (+0xb8/+0xc0/+0x110) and installs the box with status 4.
The tool reads every relocation, FDE extent and code byte from the ELF file, runs the real code with a small
concrete x86-64 evaluator (no external programs, the binary is never executed), compares each case with one
pure-Python reconstruction and shows that wrong reconstructions and corrupted code bytes are detected.
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
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5, 0x0feb, 0x0f50, 0x0f7e) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
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
        elif op == 0x0f50:  # movmskps r32, xmm
            if f["rm"][0] != "r":
                fail("movmskps with a memory operand")
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
        elif op == 0x0f7e:  # movd/movq r/m, xmm (66 prefix)
            if not f["p66"]:
                fail(f"unsupported 0f7e form at {va:#x}")
            width = 64 if f["rex"] & 8 else 32
            self.put(f["rm"], width, self.xmm[f["reg"]] & ((1 << width) - 1), f, va)
        elif op == 0x0fef:
            rm = f["rm"]
            if rm[0] != "r":
                fail("pxor with a memory operand")
            self.xmm[f["reg"]] ^= self.xmm[rm[1]]
        elif op == 0x0f6e:
            if not f["p66"] or f["rex"] & 8:
                fail(f"unsupported 0f6e form at {va:#x}")
            self.xmm[f["reg"]] = self.get(f["rm"], 32, f, va)
        elif op in (0x0f60, 0x0f76, 0x0ffb, 0x0f70, 0x0fc6, 0x0feb):
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
            elif op == 0x0feb:  # por
                res = a | b
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
INTERP_AT = 0x7d00_0000_0000
INTERP_SIZE = 0x200
HOST_AT = 0x7d00_0100_0000
HOST_SIZE = 0x400
STK_AT = 0x7d00_0300_0000
BOX_AT = 0x7d00_0600_0000  # the 0xd0-byte allocation returned by the allocator stub
OBJ_AT = 0x7d00_0700_0000  # a previous boxed action with the 0xc8-byte layout
VT_AT = 0x7d00_0800_0000
DROP_STUB = 0x7c00_0000_f000
STACK_FILL = 0xa5
INTERP_FILL_SEED = "interp"
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

I_STACK_PTR, I_STACK_LEN = 0x28, 0x30
I_SHIFT = 0x18  # added to the first (input) range
I_MEMWORDS = 0x170  # current memory size in words (second argument of the grow routine)
I_ADDR = 0x78  # executing address, 20 bytes
I_CALLER = 0x8c  # caller address, 20 bytes
I_VALUE = 0x58  # executing frame's call value, 32 bytes
I_GAS_WORD = 0x190
I_PENDING = 0xb8  # pending action: +0xb8 kind/vtable, +0xc0 payload, +0xc8 extra
I_PSTATE = 0x110  # 0x38 = none, 0 = boxed owner, else vtable drop
I_FLAG149 = 0x149
I_STATIC, I_SPEC = 0x1a8, 0x1a9

EXPAND = 0x45244c0  # GOT 0x64e6de0
HOST_ALT = 0x546c330  # GOT 0x64e6e08
HOST_ORD = 0x4335cf0  # GOT 0x64e6e00
ALLOC = 0x6355830
ALLOC_ERR = 0x141e251
DEALLOC = 0x635de30
ARC_DROP = 0x29e15d0
OVERFLOW_PANIC = 0x1681da0
HELPER = 0x29998f0

ENTRIES = {
    ("CALL", "alt"): 0x299a8f0, ("CALL", "ord"): 0x299b050,
    ("CALLCODE", "alt"): 0x299aca0, ("CALLCODE", "ord"): 0x299a1d0,
    ("DELEGATECALL", "alt"): 0x299a580, ("DELEGATECALL", "ord"): 0x2999b00,
    ("STATICCALL", "alt"): 0x299b400, ("STATICCALL", "ord"): 0x2999e70,
}
EXTENTS = {
    0x299a8f0: 0x299ac93, 0x299b050: 0x299b3f3, 0x299aca0: 0x299b049, 0x299a1d0: 0x299a579,
    0x299a580: 0x299a8eb, 0x2999b00: 0x2999e6b, 0x299b400: 0x299b751, 0x2999e70: 0x299a1c1,
}
OPCODES = {"CALL": 0xf1, "CALLCODE": 0xf2, "DELEGATECALL": 0xf4, "STATICCALL": 0xfa}
TABLES = {"ord": 0x6441f00, "alt": 0x6441210}
HOSTS = {"alt": HOST_ALT, "ord": HOST_ORD}

# per family: stack words consumed by the handler itself, spec gate, struct tag, frame scheme, host flags
FAMILY = {
    "CALL": dict(pops=3, gate=None, tag=0, scheme=0, r8=1),
    "CALLCODE": dict(pops=3, gate=None, tag=0, scheme=1, r8=0),
    "DELEGATECALL": dict(pops=2, gate=("eq0", 0), tag=1, scheme=2, r8=0),
    "STATICCALL": dict(pops=2, gate=("le", 3), tag=0, scheme=3, r8=0),
}
HOLES = tuple(range(0x68, 0x70)) + (0xcf,)
FRAME = 0xd0


def word_bytes(w):
    return (w & M256).to_bytes(32, "little")


def limbs(w):
    return [(w >> (64 * i)) & M64 for i in range(4)]


def addr20(w):
    return (w & ((1 << 160) - 1)).to_bytes(20, "big")


def words_of(end):
    return (end >> 5) + (1 if end & 31 else 0)


def range_model(w, memwords, shift, expand, mut=frozenset()):
    e24 = 0x25 if "err24_25" in mut else 0x24
    wd = (lambda end: end >> 5) if "words_floor" in mut else words_of
    if "no_shift" in mut:
        shift = 0
    """Model of the range helper 0x29998f0: w = four popped words, top first.
    Returns ("err", status, events) or ("ok", (in_off, in_end, out_off, out_end), events); events are grow requests."""
    ev = []
    off1, len1, off2, len2 = w
    if any(limbs(len1)[1:]):
        return ("err", e24, ev)
    if limbs(len1)[0] == 0:
        a, b = (0, 0) if "no_zero_sentinel" in mut else (M64, M64)
    else:
        if any(limbs(off1)[1:]):
            return ("err", e24, ev)
        o, ln = limbs(off1)[0], limbs(len1)[0]
        end = o + ln if o + ln <= M64 else M64
        need = wd(end)
        if need > memwords:
            ev.append(("expand", need))
            st = expand.pop(0)
            if st:
                return ("err", st, ev)
        if o + ln > M64 and "overflow_clamp" not in mut:
            return ("panic", "overflow", ev)
        a, b = min(o + shift, M64), min(o + ln + shift, M64)
    if any(limbs(len2)[1:]):
        return ("err", e24, ev)
    if limbs(len2)[0] == 0:
        c, d = M64, M64
    else:
        if any(limbs(off2)[1:]):
            return ("err", e24, ev)
        o, ln = limbs(off2)[0], limbs(len2)[0]
        end = o + ln if o + ln <= M64 else M64
        need = wd(end)
        if need > memwords:
            ev.append(("expand", need))
            st = expand.pop(0)
            if st:
                return ("err", st, ev)
        if o + ln > M64 and "overflow_clamp" not in mut:
            return ("panic", "overflow", ev)
        c, d = o, o + ln
        if "shift_second" in mut:
            c, d = min(o + shift, M64), min(o + ln + shift, M64)
    return ("ok", (a, b, c, d), ev)



def build_frame(fam, tbl, c, it, st_words, host, helper_out, addr, mut=frozenset()):
    """The 0xd0-byte action record; None marks bytes the handler never writes."""
    f = FAMILY[fam]
    s = [None] * FRAME

    def put_at(off, data):
        s[off:off + len(data)] = list(data)

    put_at(0x00, (0 if "dg_tag0" in mut else f["tag"]).to_bytes(8, "little"))
    if "call_value_interp" in mut and fam == "CALL":
        put_at(0x08, it[I_VALUE:I_VALUE + 32])
    elif fam in ("CALL", "CALLCODE"):
        put_at(0x08, word_bytes(st_words["value"]))
    elif fam == "DELEGATECALL":
        put_at(0x08, it[I_VALUE:I_VALUE + 32])
    else:
        put_at(0x08, bytes(32))
    put_at(0x28, host["blob"])
    put_at(0x48, host["w0"].to_bytes(8, "little"))
    put_at(0x50, bytes(8))
    a, b, cc, d = helper_out
    put_at(0x58, a.to_bytes(8, "little") + b.to_bytes(8, "little"))
    put_at(0x70, cc.to_bytes(8, "little") + d.to_bytes(8, "little"))
    put_at(0x80, host["w1"].to_bytes(8, "little"))
    put_at(0x88, it[I_GAS_WORD:I_GAS_WORD + 8])
    put_at(0x90, addr)
    put_at(0xa4, addr if "dg_addr_b_target" in mut and fam == "DELEGATECALL" else it[I_ADDR:I_ADDR + 20] if fam in ("DELEGATECALL", "CALLCODE") else addr)
    put_at(0xb8, it[I_CALLER:I_CALLER + 20] if fam == "DELEGATECALL" and "dg_exec_swap" not in mut else it[I_ADDR:I_ADDR + 20])
    s[0xcc] = 1 if fam == "STATICCALL" and "sc_static_interp" not in mut else it[I_STATIC]
    s[0xcd] = host["tag"]
    s[0xce] = {1: 2, 2: 1}.get(f["scheme"], f["scheme"]) if "scheme_swap" in mut else f["scheme"]
    return s


def model(c, mut=frozenset()):
    """Pure-Python reconstruction of one handler call; returns the observation dict."""
    fam, tbl = c["fam"], c["tbl"]
    f = FAMILY[fam]
    it = bytearray(c["interp"])
    n = c["n"]
    out = {"events": [], "box": None}
    ev = out["events"]

    def done(status, **kw):
        out["ret"] = ("ret", status)
        out["interp"] = bytes(it)
        out.update(kw)
        return out

    gate = f["gate"]
    spec = it[I_SPEC]
    if gate is not None and ((gate[0] == "eq0" and spec == gate[1]) or (gate[0] == "le" and spec <= gate[1])):
        if "no_gate" not in mut:
            return done(0x2b)
    if n < f["pops"]:
        return done(0x2c)
    st = c["stack"]  # bottom first
    top = lambda k: st[n - 1 - k]
    g = limbs(top(0))
    gas = g[0] if not any(g[1:]) else M64
    if "gas_low_only" in mut:
        gas = g[0]
    addr = addr20(top(1))
    if "addr_le" in mut:
        addr = (top(1) & ((1 << 160) - 1)).to_bytes(20, "little")
    if "addr_128" in mut:
        addr = (top(1) & M128).to_bytes(20, "big")
    value = top(2) if f["pops"] == 3 else 0
    n -= f["pops"] - (1 if "pops_minus" in mut else 0)
    put(it, I_STACK_LEN, 8, n)
    vflag = 1 if value != 0 else 0
    if "value_low_only" in mut:
        vflag = 1 if value & M64 else 0
    if fam in (("CALL", "CALLCODE") if "cc_static" in mut else ("CALL",)) and (it[I_STATIC] & vflag) and "no_static" not in mut:
        return done(0x27)
    if n < 4:
        return done(0x2c)
    pop4 = [st[n - 1 - k] for k in range(4)]
    n -= 4
    put(it, I_STACK_LEN, 8, n)
    kind, payload, hev = range_model(pop4, u(it, I_MEMWORDS, 8), u(it, I_SHIFT, 8), list(c["expand"]), mut)
    ev.extend(("expand", 0x170, 0, 0x250, w) for _, w in hev)
    if kind == "panic":
        out["ret"] = ("panic", payload)
        return out
    if kind == "err":
        return done(payload)
    host = c["host"]
    ecx = vflag if fam in ("CALL", "CALLCODE") else 0
    ev.append(("host", tbl, addr.hex(), ecx, 0 if "call_r8_zero" in mut and fam == "CALL" else f["r8"], gas))
    if host["tag"] == 2:
        return done((host["w0"] >> 8 if "host_status_hi" in mut else host["w0"]) & 0xff)
    s = build_frame(fam, tbl, c, it, {"value": value}, host, payload, addr, mut)
    ev.append(("alloc", FRAME))
    if c["alloc_fail"]:
        out["ret"] = ("panic", "alloc-error")
        return out
    ev.append(("memcpy", FRAME))
    out["box"] = s
    put(it, I_FLAG149, 1, 0)
    tag = it[I_PSTATE]
    k = u(it, I_PENDING, 8)
    if tag == 0x38 or "keep_old" in mut:
        pass
    elif tag == 0:
        if k != 0:
            ptr = u(it, I_PENDING + 8, 8)
            if (k if "arc_full64" in mut else k & 0xffffffff) == 1:
                ev.append(("arc_drop", ptr))
            else:
                ev.append(("vt_drop", ptr + 0x40, u(c["obj"], 0x30, 8), u(c["obj"], 0x38, 8)))
                ev.append(("dealloc", ptr, 0xc8, 0))
    else:
        ev.append(("vt_drop", INTERP_AT + 0xd0, u(it, I_PENDING + 8, 8), u(it, I_PENDING + 16, 8)))
    put(it, I_PENDING, 8, 1)
    put(it, I_PENDING + 8, 8, BOX_AT)
    put(it, I_PSTATE, 1, 0)
    return done(4)


def new_machine(image):
    return Machine(image)


def setup(m, c, fill=STACK_FILL):
    events = []
    cap = {"box": None}
    m.regions[0][2][:] = bytes([fill]) * len(m.regions[0][2])
    m.add_region(INTERP_AT, INTERP_SIZE, c["interp"])
    m.add_region(HOST_AT, HOST_SIZE, c["hostmem"])
    m.add_region(STK_AT, 0x20 * max(1, len(c["stack"])), b"".join(word_bytes(w) for w in c["stack"]))
    m.add_region(BOX_AT, 0x100, bytes([0xee]) * 0x100)
    m.add_region(OBJ_AT, 0x100, c["obj"])
    vt = bytearray(0x40)
    put(vt, 0x20, 8, DROP_STUB)
    m.add_region(VT_AT, 0x40, bytes(vt))
    junk = 0xc1c1_c1c1_c1c1_c1c1
    expand = list(c["expand"])

    def clobber(mc):
        for r in (1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = junk

    def grow(mc):
        events.append(("expand", mc.regs[7] - INTERP_AT, mc.regs[6] - INTERP_AT, mc.regs[2] - HOST_AT, mc.regs[1]))
        mc.regs[0] = expand.pop(0)
        clobber(mc)

    def host(which):
        def fn(mc):
            out, pair, par = mc.regs[7], mc.regs[6], mc.regs[2]
            if (mc.load(pair, 8), mc.load(pair + 8, 8)) != (INTERP_AT, HOST_AT):
                fail("host call pair is not (interp, host)")
            raw = bytes(mc.load(par + i, 1) for i in range(20))
            events.append(("host", which, raw.hex(), mc.regs[1] & M32, mc.regs[8] & M32, mc.regs[9]))
            h = c["host"]
            mc.store(out, 8, h["w0"])
            mc.store(out + 8, 8, h["w1"])
            for i in range(32):
                mc.store(out + 0x10 + i, 1, h["blob"][i])
            mc.store(out + 0x30, 1, h["tag"])
            clobber(mc)
        return fn

    def alloc(mc):
        events.append(("alloc", mc.regs[7]))
        mc.regs[0] = 0 if c["alloc_fail"] else BOX_AT
        clobber(mc)

    def memcpy(mc):
        dst, src, size = mc.regs[7], mc.regs[6], mc.regs[2]
        data = bytes(mc.load(src + i, 1) for i in range(size))
        for i in range(size):
            mc.store(dst + i, 1, data[i])
        events.append(("memcpy", size))
        cap["box"] = data
        mc.regs[0] = dst
        clobber(mc)

    def dealloc(mc):
        events.append(("dealloc", mc.regs[7], mc.regs[6], mc.regs[2]))
        clobber(mc)

    def arc(mc):
        events.append(("arc_drop", mc.regs[7]))
        clobber(mc)

    def vt(mc):
        events.append(("vt_drop", mc.regs[7], mc.regs[6], mc.regs[2]))
        clobber(mc)

    memcpy_va = next(v for k, v in m.image.relative.items() if k in m.image.imports and m.image.import_name(k) == "memcpy")
    m.stubs = {EXPAND: grow, HOST_ALT: host("alt"), HOST_ORD: host("ord"), ALLOC: alloc, ALLOC_ERR: "alloc-error",
               DEALLOC: dealloc, ARC_DROP: arc, DROP_STUB: vt, OVERFLOW_PANIC: "overflow", memcpy_va: memcpy}
    return events, cap


def run_case(m, c, fill=STACK_FILL):
    m.reset()
    events, cap = setup(m, c, fill)
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = INTERP_AT, HOST_AT
    reg = lambda base: next(buf for lo, hi, buf in m.regions if lo == base)
    got = {"events": events, "box": None}
    try:
        m.run(ENTRIES[(c["fam"], c["tbl"])], limit=30000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    got["interp"] = bytes(reg(INTERP_AT))
    got["box"] = list(cap["box"]) if cap["box"] is not None else None
    got["rest_ok"] = (bytes(reg(HOST_AT)) == c["hostmem"] and bytes(reg(OBJ_AT)) == c["obj"]
                      and bytes(reg(STK_AT)) == b"".join(word_bytes(w) for w in c["stack"]).ljust(32, b"\0")[:len(reg(STK_AT))])
    return got


def compare(want, got):
    if want["ret"] != got["ret"] or want["events"] != got["events"]:
        return False
    if want["ret"][0] == "panic":
        return True
    if want["interp"] != got["interp"] or not (got["regs_ok"] and got["rest_ok"]):
        return False
    if (want["box"] is None) != (got["box"] is None):
        return False
    if want["box"] is not None:
        for i in range(FRAME):
            if want["box"][i] is not None and want["box"][i] != got["box"][i]:
                return False
    return True



# ---------------------------------------------------------------- cases
M32 = 0xffffffff
PER_BODY = 1300
BIG = (M64, M64 - 1, 1 << 64, (1 << 64) + 5, 1 << 128, 1 << 255, M256)
SMALL = (0, 1, 2, 31, 32, 33, 64, 100, 0x1000, 0x12345)
PENDING_MODES = ("none", "none", "arc", "arc-high", "empty", "obj", "vt")


def rand_word(s, kind):
    if kind == "small":
        return s.pick(SMALL)
    if kind == "big":
        return s.pick(BIG)
    if kind == "rand":
        return int.from_bytes(s.take(32), "little")
    if kind == "u64":
        return int.from_bytes(s.take(8), "little")
    return s.below(0x400)


def rand_range_word(s):
    r = s.below(10)
    if r < 5:
        return s.below(0x300)
    if r < 7:
        return s.pick(SMALL)
    if r < 8:
        return M64 - s.below(8)
    if r < 9:
        return s.pick(BIG)
    return int.from_bytes(s.take(8), "little") | (s.below(2) << (64 + s.below(190)))


def make_case(s, fam, tbl, k):
    mode = k % 12
    n = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 7, 9)[s.below(12)]
    if mode >= 4:
        n = 7 + s.below(3) if FAMILY[fam]["pops"] == 3 else 6 + s.below(4)
    stack = [rand_range_word(s) for _ in range(n)]
    if n >= 1:
        stack[n - 1] = rand_word(s, ("small", "u64", "big", "rand")[s.below(4)])  # gas word
    if n >= 2:
        w = int.from_bytes(s.take(32), "little") if s.below(3) else s.below(1 << 160)
        stack[n - 2] = w  # address word
    if n >= 3 and FAMILY[fam]["pops"] == 3:
        stack[n - 3] = (0, 1, 1 << 200, 1 << 64, 1 << 255, int.from_bytes(s.take(32), "little"))[s.below(6)]
    it = bytearray(s.take(INTERP_SIZE))
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, n)
    it[I_SPEC] = (0, 1, 3, 4, 5, 9, s.below(256))[s.below(7)]
    it[I_STATIC] = (0, 1, 1, 0, 2, 3, s.below(256))[s.below(7)]
    put(it, I_MEMWORDS, 8, (0, 1, 2, 8, 100, 1 << 40, M64)[s.below(7)])
    put(it, I_SHIFT, 8, (0, 0, 32, 0x100, M64 - 1, s.below(1 << 20))[s.below(6)])
    pend = PENDING_MODES[s.below(len(PENDING_MODES))]
    if pend == "none":
        it[I_PSTATE] = 0x38
    elif pend == "empty":
        it[I_PSTATE] = 0
        put(it, I_PENDING, 8, 0)
    elif pend == "arc":
        it[I_PSTATE] = 0
        put(it, I_PENDING, 8, 1)
    elif pend == "arc-high":
        it[I_PSTATE] = 0
        put(it, I_PENDING, 8, (s.below(1 << 31) + 1 << 32) | 1)
    elif pend == "obj":
        it[I_PSTATE] = 0
        put(it, I_PENDING, 8, (2, 3, 0x100000000, 0x7777)[s.below(4)])
        put(it, I_PENDING + 8, 8, OBJ_AT)
    else:
        it[I_PSTATE] = (1, 2, 0x37, 0x39, 0xff)[s.below(5)]
        put(it, I_PENDING, 8, VT_AT)
    obj = bytearray(s.take(0x100))
    put(obj, 0x28, 8, VT_AT)
    hm = s.take(HOST_SIZE)
    tag = (0, 0, 0, 1, 1, 2)[s.below(6)]
    host = {"tag": tag, "w0": int.from_bytes(s.take(8), "little"), "w1": int.from_bytes(s.take(8), "little"),
            "blob": s.take(32)}
    expand = [(0, 0, 0, 0, 0x21, 0x20, 0x7f)[s.below(7)] if s.below(4) == 0 else 0 for _ in range(2)]
    return {"fam": fam, "tbl": tbl, "n": n, "stack": stack, "interp": bytes(it), "hostmem": hm, "obj": bytes(obj),
            "host": host, "expand": expand, "alloc_fail": s.below(40) == 0, "mode": mode, "pend": pend}


def all_cases():
    for fam in FAMILY:
        for tbl in ("alt", "ord"):
            s = Stream(f"calls-{fam}-{tbl}")
            for k in range(PER_BODY):
                yield make_case(s, fam, tbl, k)



# ---------------------------------------------------------------- static evidence
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


def body_rows(image):
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    ext = {f["start"]: f["end"] for f in fdes}
    out = {}
    for s in list(EXTENTS) + [HELPER]:
        if s not in ext:
            fail(f"no FDE starts at {s:#x}")
        out[s] = ext[s]
    for s, e in EXTENTS.items():
        if ext[s] != e:
            fail(f"FDE end of {s:#x} is {ext[s]:#x}, expected {e:#x}")
    return out


def got_slot(va, form):
    """Target slot of an indirect call `ff 15 disp32`."""
    return va + form["len"] + struct.unpack_from("<i", form["bytes"], form["len"] - 4)[0]


def mask_form(form):
    b = bytearray(form["bytes"])
    if b[:2] == b"\xff\x15" or ("rel" in form and form["len"] >= 5):
        b[-4:] = bytes(4)
    elif "rel" in form:
        b[-1:] = bytes(1)
    return bytes(b)


def static_evidence(image):
    rows = body_rows(image)
    decoded, funcs, calls, slots = {}, {}, {}, {}
    for lo, hi in rows.items():
        dec = sweep_padded(image, lo, hi)
        decoded[lo] = dec
        body = image.code(lo, hi - lo)
        funcs[f"{lo:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                             "instructions": sum(1 for _, f in dec if f is not None)}
        calls[f"{lo:#x}"] = {}
        slots[f"{lo:#x}"] = {}
        for va, f in dec:
            if f is None:
                continue
            if f["op"] == 0xe8:
                calls[f"{lo:#x}"][f"{va:#x}"] = f"{f['target']:#x}"
            if f["bytes"][:2] == b"\xff\x15":
                slot = got_slot(va, f)
                name = image.import_name(slot) if slot in image.imports else f"{image.relative[slot]:#x}"
                slots[f"{lo:#x}"][f"{va:#x}"] = {"slot": f"{slot:#x}", "target": name}
    twins = {}
    for fam in FAMILY:
        a, b = ENTRIES[(fam, "alt")], ENTRIES[(fam, "ord")]
        la = [x for x in decoded[a] if x[1] is not None]
        lb = [x for x in decoded[b] if x[1] is not None]
        same_len = len(la) == len(lb) and all(x[1]["len"] == y[1]["len"] for x, y in zip(la, lb))
        diff = [f"{x[0] - a:#x}" for x, y in zip(la, lb) if mask_form(x[1]) != mask_form(y[1])]
        ind = [(slots[f"{a:#x}"][f"{x[0]:#x}"], slots[f"{b:#x}"][f"{y[0]:#x}"]) for x, y in zip(la, lb)
               if x[1]["bytes"][:2] == b"\xff\x15"]
        twins[fam] = {"alt": f"{a:#x}", "ord": f"{b:#x}", "same_instruction_lengths": same_len, "instructions": len(la),
                      "differing_after_masking_displacements": diff,
                      "indirect_call_slots_that_differ": [f"{p['slot']}->{q['slot']}" for p, q in ind if p["slot"] != q["slot"]]}
    table = {}
    for tbl, base in TABLES.items():
        for fam, op in OPCODES.items():
            slot = base + 8 * op
            got = image.relative.get(slot)
            if got != ENTRIES[(fam, tbl)]:
                fail(f"opcode table {base:#x} slot {op:#x} is {got}")
            table[f"{base:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "family": fam, "table": tbl, "target": f"{got:#x}"}
    if image.relative[0x64e6e08] != HOST_ALT or image.relative[0x64e6e00] != HOST_ORD or image.relative[0x64e6de0] != EXPAND:
        fail("host or grow slots changed")
    got_names = {}
    for slot in (0x64df480, 0x64df490, 0x64df4a0, 0x64df508, 0x64df520, 0x64e6de0, 0x64e6e00, 0x64e6e08):
        got_names[f"{slot:#x}"] = image.import_name(slot) if slot in image.imports else f"{image.relative[slot]:#x}"
    out = {"binary_sha256": SHA256, "functions": funcs, "direct_calls": calls, "indirect_calls": slots,
           "alt_vs_ordinary": twins, "opcode_table_slots": table, "got_slots": got_names,
           "interpreter_offsets": {"stack_ptr": I_STACK_PTR, "stack_len": I_STACK_LEN, "shift": I_SHIFT,
                                   "memory_words": I_MEMWORDS, "executing_address": I_ADDR, "caller_address": I_CALLER,
                                   "call_value": I_VALUE, "gas_word": I_GAS_WORD, "pending": I_PENDING,
                                   "pending_state": I_PSTATE, "flag_149": I_FLAG149, "static": I_STATIC, "spec": I_SPEC},
           "families": {k: dict(v) for k, v in FAMILY.items()}, "frame_bytes": FRAME,
           "frame_holes": [f"{h:#x}" for h in HOLES]}
    return out, decoded


# ---------------------------------------------------------------- evaluation
def case_stream(only=None):
    for c in all_cases():
        if only is None or (c["fam"], c["tbl"]) in only:
            yield c


def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, only=None, sink=None):
    m = machine or TraceMachine(image, override)
    total = bad = 0
    for c in case_stream(only):
        try:
            want = model(c, mut)
            got = run_case(m, c)
            ok = compare(want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        total += 1
        bad += not ok
        if sink is not None:
            sink(total - 1, c, want, got, ok)
        if stop_on_first and not ok:
            break
    return total, bad, m


MODEL_MUTANTS = [
    "no_gate", "gas_low_only", "value_low_only", "no_static", "addr_le", "addr_128", "pops_minus", "no_shift",
    "shift_second", "scheme_swap", "dg_tag0", "sc_static_interp", "call_r8_zero", "cc_static", "keep_old",
    "arc_full64", "no_zero_sentinel", "words_floor", "overflow_clamp", "err24_25", "host_status_hi",
    "dg_addr_b_target", "dg_exec_swap", "call_value_interp",
]
# (address, expected old byte, new byte, meaning, bodies it is checked on)
ALT_CALL = (("CALL", "alt"),)
HELPER_USERS = (("CALL", "alt"), ("STATICCALL", "alt"))
BYTE_MUTANTS = [
    (0x299a912, 0x2c, 0x2d, "alt CALL stack-underflow status 0x2c -> 0x2d", ALT_CALL),
    (0x299a916, 0x02, 0x03, "alt CALL needs more than 2 words -> more than 3", ALT_CALL),
    (0x299a9a0, 0x27, 0x28, "alt CALL static-with-value status 0x27 -> 0x28", ALT_CALL),
    (0x299a9a4, 0xa8, 0xa9, "alt CALL static byte +0x1a8 -> +0x1a9", ALT_CALL),
    (0x299a9dc, 0x20, 0x1f, "alt CALL address top-limb shift 32 -> 31", ALT_CALL),
    (0x299aa1f, 0x01, 0x00, "alt CALL host flag r8d 1 -> 0", ALT_CALL),
    (0x299aa35, 0x02, 0x03, "alt CALL host error tag 2 -> 3", ALT_CALL),
    (0x299aa8f, 0x88, 0x8c, "alt CALL executing-address tail +0x88 -> +0x8c", ALT_CALL),
    (0x299ab49, 0xd0, 0xc0, "alt CALL allocation size 0xd0 -> 0xc0", ALT_CALL),
    (0x299ab65, 0xd0, 0xc0, "alt CALL copy size 0xd0 -> 0xc0", ALT_CALL),
    (0x299ab76, 0x49, 0x4a, "alt CALL cleared flag +0x149 -> +0x14a", ALT_CALL),
    (0x299ab85, 0x38, 0x39, "alt CALL pending-none state 0x38 -> 0x39", ALT_CALL),
    (0x299abcd, 0x04, 0x05, "alt CALL success status 4 -> 5", ALT_CALL),
    (0x299abf7, 0x01, 0x02, "alt CALL shared-owner tag 1 -> 2", ALT_CALL),
    (0x299ac18, 0xc8, 0xc0, "alt CALL old-box size 0xc8 -> 0xc0", ALT_CALL),
    (0x2999905, 0x04, 0x05, "range helper needs 4 words -> 5", HELPER_USERS),
    (0x299998c, 0x24, 0x25, "range helper high-limb status 0x24 -> 0x25", HELPER_USERS),
    (0x29999c3, 0x1f, 0x1e, "range helper word remainder mask 0x1f -> 0x1e", HELPER_USERS),
    (0x29999c7, 0x01, 0x02, "range helper word round-up compare 1 -> 2", HELPER_USERS),
    (0x29999cf, 0x70, 0x78, "range helper memory size +0x170 -> +0x178", HELPER_USERS),
    (0x2999a3c, 0x18, 0x20, "range helper input shift +0x18 -> +0x20", HELPER_USERS),
    (0x2999a56, 0x24, 0x26, "range helper second-range status 0x24 -> 0x26", HELPER_USERS),
    (0x299a5a4, 0x00, 0x01, "alt DELEGATECALL spec gate == 0 -> == 1", (("DELEGATECALL", "alt"),)),
    (0x299b424, 0x03, 0x04, "alt STATICCALL spec gate <= 3 -> <= 4", (("STATICCALL", "alt"),)),
    (0x299a781, 0x01, 0x00, "alt DELEGATECALL record tag 1 -> 0", (("DELEGATECALL", "alt"),)),
    (0x299a78c, 0x02, 0x03, "alt DELEGATECALL frame scheme 2 -> 3", (("DELEGATECALL", "alt"),)),
    (0x299b5fa, 0x01, 0x00, "alt STATICCALL record static byte 1 -> 0", (("STATICCALL", "alt"),)),
    (0x299aeee, 0x01, 0x02, "alt CALLCODE frame scheme 1 -> 2", (("CALLCODE", "alt"),)),
]


def controls(image):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True)
        rows.append(("model", name, int(bad > 0)))
    for va, old, new, what, bodies in BYTE_MUTANTS:
        if image.code(va, 1)[0] != old:
            fail(f"byte mutant at {va:#x} expects {old:#04x}")
        _, bad, _ = evaluate(image, override={va: new}, stop_on_first=True, only=set(bodies))
        rows.append(("code", f"{va:#x}={new:#04x} {what}", int(bad > 0)))
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
    try:
        make_case(Stream("x"), "CALL", "alt", 0)["interp"][:1]
        run_case(Machine(image), dict(make_case(Stream("x"), "CALL", "alt", 0), fam="NOP"))
        rows.append(("input", "unknown family", 0))
    except (ToolError, KeyError):
        rows.append(("input", "unknown family", 1))
    return rows


# ---------------------------------------------------------------- output
STATUS = {0x2b: "not-activated", 0x2c: "stack-underflow", 0x27: "static-with-value", 0x24: "range-too-large", 4: "action-queued"}


def outcome(c, want):
    kind, code = want["ret"]
    if kind == "panic":
        return f"panic-{code}"
    if c["host"]["tag"] == 2 and any(e[0] == "host" for e in want["events"]):
        return "host-error"
    name = STATUS.get(code, f"status-{code:#x}")
    if code == 4:
        return f"{name}/{c['pend']}"
    return name


def hole_check(image, count=600):
    """Run successful cases under two stack fills; only the modelled hole bytes may differ."""
    m = Machine(image)
    seen, used = set(), 0
    for c in case_stream():
        want = model(c)
        if want["box"] is None:
            continue
        a = run_case(m, c, 0xa5)
        b = run_case(m, c, 0x5a)
        for i in range(FRAME):
            if a["box"][i] != b["box"][i]:
                seen.add(i)
        used += 1
        if used >= count:
            break
    return {"cases": used, "bytes_that_depend_on_stack_fill": sorted(f"{i:#x}" for i in seen),
            "modelled_holes": sorted(f"{i:#x}" for i in HOLES), "match": sorted(seen) == sorted(HOLES)}


def frame_layout():
    lines = ["offset\tlength\tsource"]
    rows = [
        (0x00, 8, "record tag: 1 for DELEGATECALL, 0 otherwise"),
        (0x08, 32, "call value: CALL/CALLCODE = third stack word, DELEGATECALL = interpreter +0x58, STATICCALL = 0"),
        (0x28, 32, "host result bytes +0x10..+0x2f"), (0x48, 8, "host result word 0"), (0x50, 8, "zero"),
        (0x58, 16, "range helper in_off, in_end (after the +0x18 shift)"), (0x68, 8, "never written (stack garbage)"),
        (0x70, 16, "range helper out_off, out_end"), (0x80, 8, "host result word 1"),
        (0x88, 8, "interpreter +0x190"), (0x90, 20, "target address, big-endian 160 bits of the second stack word"),
        (0xa4, 20, "CALL/STATICCALL = target address again; CALLCODE/DELEGATECALL = interpreter +0x78"),
        (0xb8, 20, "DELEGATECALL = interpreter +0x8c (caller); others = interpreter +0x78 (executing address)"),
        (0xcc, 1, "static byte: STATICCALL = 1, others = interpreter +0x1a8"),
        (0xcd, 1, "host result tag byte (0 or 1)"), (0xce, 1, "frame scheme: CALL 0, CALLCODE 1, DELEGATECALL 2, STATICCALL 3"),
        (0xcf, 1, "never written (stack garbage)"),
    ]
    for off, ln, src in rows:
        lines.append(f"{off:#x}\t{ln}\t{src}")
    return lines


def tag(x):
    return f"{x:#x}"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    consts, decoded = static_evidence(image)
    classes, sample = {}, ["case\tbody\tn\tn_after\tpending\thost_tag\toutcome\tret\trecord\tevents\tmatch"]
    totals = {"cases": 0, "bad": 0}

    def sink(i, c, want, got, ok):
        oc = outcome(c, want) if want else "error"
        key = (c["fam"], c["tbl"], oc)
        classes[key] = classes.get(key, 0) + 1
        totals["cases"] += 1
        totals["bad"] += not ok
        if i % 5 == 0:
            evs = ",".join(e[0] for e in (want["events"] if want else []))
            after = u(want["interp"], I_STACK_LEN, 8) if want and "interp" in want else "-"
            rec = "-"
            if want and want["box"] is not None:
                rec = hashlib.sha256(bytes(b or 0 for b in want["box"])).hexdigest()[:8]
            ret = f"{want['ret'][0]}:{want['ret'][1]:#x}" if want and want["ret"][0] == "ret" else (f"panic:{want['ret'][1]}" if want else "-")
            sample.append(f"{i}\t{c['fam']}/{c['tbl']}\t{c['n']}\t{after}\t{c['pend']}\t{c['host']['tag']}\t{oc}\t{ret}\t{rec}\t{evs or '-'}\t{'yes' if ok else 'NO'}")

    _, _, m = evaluate(image, sink=sink)
    (out / "cases-sample.tsv").write_text("\n".join(sample) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "family\ttable\toutcome\tcases\n" + "".join(f"{k[0]}\t{k[1]}\t{k[2]}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\tinstructions\texecuted\tunexecuted_runs"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        real = [(va, f) for va, f in insns if f is not None]
        hit = sum(1 for va, _ in real if va in m.seen)
        runs, cur = [], None
        for va, f in real:
            if va in m.seen:
                if cur:
                    runs.append(cur)
                cur = None
            elif cur is None:
                cur = [va, va + f["len"]]
            else:
                cur[1] = va + f["len"]
        if cur:
            runs.append(cur)
        covered[f"{start:#x}"] = [hit, len(real)]
        lines.append(f"{start:#x}\t{len(real)}\t{hit}\t" + (",".join(f"{a:#x}-{b:#x}" for a, b in runs) or "-"))
    (out / "coverage.tsv").write_text("\n".join(lines) + "\n")
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    for start, insns in sorted(decoded.items()):
        for va, f in insns:
            if f is None:
                lines.append(f"{start:#x}\t{va:#x}\t1\tcc\tpadding\t0")
            else:
                lines.append(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(va in m.seen)}")
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    (out / "frame-layout.tsv").write_text("\n".join(frame_layout()) + "\n")
    holes = hole_check(image)
    (out / "hole-check.json").write_text(json.dumps(holes, indent=2, sort_keys=True) + "\n")
    ctl = controls(image)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": totals["cases"], "mismatches": totals["bad"],
               "covered_instructions": covered, "hole_check_match": holes["match"],
               "negative_controls": {"total": len(ctl), "detected": detected}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": totals["cases"], "negative_controls": len(ctl), "negative_detected": detected}, sort_keys=True) + "\n")
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
    bad = (summary["mismatches"] or not summary["hole_check_match"]
           or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
