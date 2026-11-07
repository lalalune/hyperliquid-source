#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM SSTORE handler 0x2994990 with its cost 0x299f910 and refund 0x299f680.

0x2994990 is the interpreter's SSTORE instruction.  It rejects a static frame (result 0x28) and
a stack with fewer than two words (0x2c), pops key and value, applies the EIP-2200 sentry from
spec byte 6 on (gas must exceed params +0xc0, else 0x25), charges the static price params
+0x98, and calls the storage store 0x2977910 (stubbed: owned by the open warm/cold packet) with
a skip flag (spec > 6: gas < params +0xc8).  A store error returns 0x36, or 0x20 from spec 7
when the error kind bit is clear.  The cost 0x299f910 and refund 0x299f680 read prices from the
host gas-parameter table (+0x250) and are run as real code.  A host byte +0x265 enables an
extra reserve accounting for slots created from zero (params +0x150 paid from interpreter
+0x190 first, then from gas, counted in +0x198) and released again when the slot is restored
to zero.  The refund is added to the signed counter +0x1a0 (overflow panics).  The tool reads
every relocation, FDE extent and code byte from the ELF file, evaluates the real machine code
with a small concrete x86-64 evaluator (no external programs, the binary is never executed) and
compares every case with one pure-Python reconstruction.  Negative controls show that wrong
reconstructions and corrupted code bytes are detected.
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
    elif op == 0x3d:
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
        at = disp + (FS_BASE if form["fs"] else 0)
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
HANDLER = 0x2994990  # SSTORE opcode handler (interpreter, host) -> instruction result byte
COST = 0x299f910  # sstore cost (params, flag spec>=6, &result, cold byte)
REFUND = 0x299f680  # sstore refund (params, flag spec>=6, &result) -> i64
STORE = 0x2977910  # storage store (owned by the open warm/cold packet; stubbed here)
TWIN = 0x2994490  # position twin of the handler: same bytes except rel32/RIP operands, calls the fallible store
TWIN_STORE = 0x2977cd0  # fallible storage store reached by the twin (stubbed here)
STORE_OF = {HANDLER: STORE, TWIN: TWIN_STORE}
PANIC_GOTS = (0x64df520, 0x64df848)  # arithmetic-overflow panic entries (GLOB_DAT/RELATIVE slots)

# interpreter offsets read by 0x2994990
I_STACK_PTR, I_STACK_LEN, I_ADDR = 0x28, 0x30, 0x78
I_GAS, I_RESERVE, I_RESERVED, I_REFUND = 0x188, 0x190, 0x198, 0x1a0
I_STATIC, I_SPEC = 0x1a8, 0x1a9
H_PARAMS, H_FLAG = 0x250, 0x265
PARAM_OFFS = (0x98, 0xa0, 0xa8, 0xb0, 0xc0, 0xc8, 0xd0, 0x138, 0x140, 0x150)

INTERP_AT = 0x7d00_0000_0000
INTERP_SIZE = 0x200
HOST_AT = 0x7d00_0100_0000
HOST_SIZE = 0x300
PARAMS_AT = 0x7d00_0200_0000
PARAMS_SIZE = 0x200
STK_AT = 0x7d00_0300_0000
INTERP_FILL, HOST_FILL, PARAMS_FILL, STACK_FILL = 0x33, 0x44, 0x55, 0x5c
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

R_OK, R_OOG, R_SENTRY, R_STATIC, R_UNDERFLOW, R_FATAL = 0x00, 0x20, 0x25, 0x28, 0x2c, 0x36
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1


def s64(x):
    x &= M64
    return x - (1 << 64) if x >> 63 else x


def sat_add_i64(a, b):
    return max(I64_MIN, min(I64_MAX, s64(a) + s64(b))) & M64


def sat_sub_i64(a, b):
    return max(I64_MIN, min(I64_MAX, s64(a) - s64(b))) & M64


class Panic(Exception):
    pass


# ---------------------------------------------------------------- reconstruction
def sstore_cost(p, flag, o, cur, new, cold, mut=frozenset()):
    """0x299f910: before spec 6 the Istanbul-less set/reset price; from spec 6 cold surcharge plus set/reset."""
    if not flag:
        if "pre_flag_new_only" in mut:
            return p[0xa0] if new != 0 else p[0xa8]
        return p[0xa0] if (cur == 0 and new != 0) else p[0xa8]
    base = p[0xd0] if (cold and "no_cold" not in mut) else 0
    if new == cur and "noop_charges" not in mut:
        return base
    if o == cur or "dirty_charges" in mut:
        total = base + p[0xa8 if (o != 0) != ("set_reset_swap" in mut) else 0xa0]
        if total > M64:
            raise Panic("cost overflow")
        return total
    return base


def sstore_refund(p, flag, o, cur, new, mut=frozenset()):
    """0x299f680: refund counter delta (i64)."""
    clears = s64(p[0xb0])
    if not flag:
        if cur == 0:
            return 0
        return clears if new == 0 else 0
    if new == cur:
        return 0
    if o == cur and new == 0:
        return clears
    r = 0
    if o != 0:
        if cur == 0:
            if clears == I64_MIN:
                raise Panic("refund negate overflow")
            r = -clears if "no_negate" not in mut else clears
        elif new == 0:
            r = clears
    if o == new and "no_restore" not in mut:
        r += s64(p[0x138] if o == 0 else p[0x140])
        if not I64_MIN <= r <= I64_MAX:
            raise Panic("refund restore overflow")
    return r


def model(c, mut=frozenset()):
    """0x2994990 reconstructed: returns observable result and the interpreter fields it writes."""
    st = {"len": c["n"], "gas": c["gas"], "reserve": c["reserve"], "reserved": c["reserved"], "refund": c["refund"]}
    ev = []

    def done(code, kind="ret"):
        return {"ret": (kind, code), "state": st, "events": ev}
    if c["static"]:
        return done(R_STATIC)
    if c["n"] < 2:
        return done(R_UNDERFLOW)
    st["len"] = c["n"] - 2
    key, value = c["stack"][c["n"] - 1], c["stack"][c["n"] - 2]
    if "pop_swap" in mut:
        key, value = value, key
    spec, p = c["spec"], c["params"]
    gas = c["gas"]
    if spec > (5 if "sentry_ge5" not in mut else 4) and gas <= p[0xc0]:
        return done(R_SENTRY)
    if gas < p[0x98]:
        return done(R_OOG)
    gas -= p[0x98]
    st["gas"] = gas
    flag_skip = int(gas < p[0xc8]) if spec > 6 else 0
    ev.append(("store", STORE_OF[c["entry"]], I_ADDR, key.to_bytes(32, "little").hex(), value.to_bytes(32, "little").hex(), flag_skip))
    o, cur, new, tag = c["result"]
    if tag == 2:
        if spec > 6 and not (o & 1) and "err_always_fatal" not in mut:
            return done(R_OOG)
        return done(R_FATAL)
    flag = int(spec >= 6)
    try:
        cost = sstore_cost(p, flag, o, cur, new, tag, mut)
    except Panic:
        return done("cost", "panic")
    if gas < cost:
        return done(R_OOG)
    gas -= cost
    st["gas"] = gas
    if c["host_flag"] and new != cur:
        res, rsv = c["reserve"], c["reserved"]
        q = p[0x150]
        if o == cur and o == 0:
            if res >= q:
                st["reserved"] = rsv = sat_add_i64(rsv, q)
                st["reserve"] = res = res - q
            else:
                need = q - res
                if "reserve_no_gas" not in mut:
                    if gas < need:
                        return done(R_OOG)
                    gas -= need
                    st["gas"] = gas
                st["reserved"] = rsv = sat_add_i64(q, rsv)
                st["reserve"] = res = 0
        if o == new and o == 0 and q != 0 and "no_release" not in mut:
            st["reserved"] = sat_sub_i64(rsv, q)
            st["reserve"] = min(M64, res + q)
    try:
        r = sstore_refund(p, flag, o, cur, new, mut)
    except Panic:
        return done("refund", "panic")
    total = s64(c["refund"]) + r
    if not I64_MIN <= total <= I64_MAX:
        return done("refund-total", "panic")
    st["refund"] = total & M64
    return done(R_OK)


# ---------------------------------------------------------------- harness
def result_bytes(c):
    o, cur, new, tag = c["result"]
    return o.to_bytes(32, "little") + cur.to_bytes(32, "little") + new.to_bytes(32, "little") + bytes([tag]) + c["pad"]


def setup(m, c):
    image = m.image
    events = []
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(INTERP_AT, INTERP_SIZE, bytes([INTERP_FILL]) * INTERP_SIZE)
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, c["n"])
    for f, v in ((I_GAS, c["gas"]), (I_RESERVE, c["reserve"]), (I_RESERVED, c["reserved"]), (I_REFUND, c["refund"])):
        put(it, f, 8, v)
    it[I_STATIC], it[I_SPEC] = c["static"], c["spec"]
    host = m.add_region(HOST_AT, HOST_SIZE, bytes([HOST_FILL]) * HOST_SIZE)
    put(host, H_PARAMS, 8, PARAMS_AT)
    host[H_FLAG] = c["host_flag"]
    pr = m.add_region(PARAMS_AT, PARAMS_SIZE, bytes([PARAMS_FILL]) * PARAMS_SIZE)
    for off in PARAM_OFFS:
        put(pr, off, 8, c["params"][off])
    m.add_region(STK_AT, 0x20 * max(1, len(c["stack"])), b"".join(w.to_bytes(32, "little") for w in c["stack"]))

    def store(mc, target):
        out, hp, ap, kp, vp, fl = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1], mc.regs[8], mc.regs[9]
        if hp != HOST_AT:
            fail(f"store host argument {hp:#x}")
        k = bytes(mc.load(kp + i, 1) for i in range(32))
        v = bytes(mc.load(vp + i, 1) for i in range(32))
        events.append(("store", target, ap - INTERP_AT, k.hex(), v.hex(), fl & 0xff))
        for i, b in enumerate(result_bytes(c)):
            mc.store(out + i, 1, b)

    m.stubs = {STORE: lambda mc: store(mc, STORE), TWIN_STORE: lambda mc: store(mc, TWIN_STORE)}
    for slot in PANIC_GOTS:
        m.stubs[image.word(slot)] = "panic"
    return events


def run_case(m, c):
    m.reset()
    events = setup(m, c)
    keep = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in (HOST_AT, PARAMS_AT, STK_AT)}
    before = bytes(next(buf for lo, hi, buf in m.regions if lo == INTERP_AT))
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = INTERP_AT, HOST_AT
    got = {"events": events}
    it = next(buf for lo, hi, buf in m.regions if lo == INTERP_AT)
    try:
        m.run(c["entry"], limit=20000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    got["state"] = {"len": u(it, I_STACK_LEN, 8), "gas": u(it, I_GAS, 8), "reserve": u(it, I_RESERVE, 8),
                    "reserved": u(it, I_RESERVED, 8), "refund": u(it, I_REFUND, 8)}
    now = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in keep}
    rest = bytearray(it)
    for f in (I_STACK_LEN, I_GAS, I_RESERVE, I_RESERVED, I_REFUND):
        rest[f:f + 8] = before[f:f + 8]
    got["rest_ok"] = now == keep and bytes(rest) == before
    return got


def compare(c, want, got):
    if want["ret"][0] == "panic" or got["ret"][0] == "panic":
        return want["ret"][0] == got["ret"][0] and want["events"] == got["events"]
    if want["ret"] != got["ret"] or want["events"] != got["events"] or want["state"] != got["state"]:
        return False
    return got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
TOTAL = 5200
WORD_POOL = (0, 1, 2, 3, 0x100, M64, 1 << 64, M256)


def rand_word(s, pool):
    k = s.below(10)
    if k < 6:
        return s.pick(pool)
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def rand_u64(s, scale):
    k = s.below(8)
    if k == 0:
        return 0
    if k == 1:
        return M64 - s.below(4)
    if k == 2:
        return (1 << 63) + s.below(3) - 1
    return s.below(scale) + 1


def make_case(s, mode):
    params = {off: s.below(30000) + 1 for off in PARAM_OFFS}
    if s.below(4) == 0:
        params[0x150] = 0
    if mode == "edge":
        for off in s.pick([(0xb0,), (0xa0, 0xd0), (0xa8, 0xd0), (0x138,), (0x140,), (0x150,), (0x98,), (0xc0,)]):
            params[off] = s.pick([M64, M64 - 1, 1 << 63, (1 << 63) - 1, 0])
    pool = WORD_POOL
    o = rand_word(s, pool)
    cur = s.pick([o, o, 0, rand_word(s, pool)])
    new = s.pick([cur, o, 0, rand_word(s, pool), rand_word(s, pool)])
    if mode == "fresh":
        o, cur = 0, 0
        new = s.pick([0, rand_word(s, pool)])
    elif mode == "restore":
        o, new = 0, 0
        cur = s.pick([1, M256, rand_word(s, pool)])
    tag = s.pick([0, 1, 0, 1, 2]) if mode != "err" else 2
    n = s.pick([2, 2, 3, 5]) if s.below(12) else s.below(2)
    stack = [rand_word(s, pool) for _ in range(n)]
    spec = s.below(13)
    if mode in ("fresh", "restore", "edge") and s.below(3):
        spec = 6 + s.below(7)
    gas_ref = s.pick([params[0xc0], params[0x98], params[0x98] + params[0xa0], params[0x98] + params[0xd0] + params[0xa8],
                      params[0x98] + params[0xa0] + params[0x150], params[0xc8] + params[0x98]])
    gas = max(0, (gas_ref + s.below(9) - 4)) & M64 if s.below(3) else rand_u64(s, 200000)
    reserve = s.pick([0, params[0x150], params[0x150] - 1 if params[0x150] else 0, s.below(60000), M64 - s.below(3)])
    reserved = s.pick([0, s.below(60000), I64_MAX - s.below(3), (1 << 63) + s.below(3), M64])
    refund = s.pick([0, s.below(60000), I64_MAX - s.below(3), (1 << 63) + s.below(3), M64 - s.below(40000)])
    if mode == "restore_overflow":  # o != 0, cur == 0, new == o: refund = -clears + params +0x140
        params[0xb0] = s.pick([M64, M64 - 1, M64 - s.below(1000)])
        params[0x140] = s.pick([I64_MAX, I64_MAX - 1, I64_MAX - s.below(1000)])
        o = new = s.pick([1, M256, rand_word(s, pool) | 1])
        cur, n, stack = 0, 2, [rand_word(s, pool), rand_word(s, pool)]
        tag, spec, gas = s.pick([0, 1]), 6 + s.below(7), M64 - s.below(1000)
    return {"mode": mode, "params": params, "result": (o, cur, new, tag), "pad": s.take(7), "n": n, "stack": stack,
            "spec": spec, "static": int(s.below(25) == 0), "gas": gas & M64, "reserve": reserve & M64,
            "reserved": reserved & M64, "refund": refund & M64, "host_flag": s.pick([0, 1, 1, 0x80])}


def all_cases():
    s = Stream("re11-sstore-gas-refund-115")
    out = []
    for k in range(TOTAL):
        mode = ["any", "fresh", "restore", "any", "edge", "err", "any", "fresh"][k % 8]
        c = make_case(s, "restore_overflow" if k % 40 == 39 else mode)
        c["entry"] = TWIN if k % 2 else HANDLER
        out.append(c)
    return out


# ---------------------------------------------------------------- static evidence
FUNCS = (HANDLER, TWIN, COST, REFUND)
CHECKED = (
    (0x29949a1, "80 bf a8 01 00 00 00", "static flag byte +0x1a8 != 0 -> result 0x28"),
    (0x29949b5, "b0 2c", "stack length < 2 -> result 0x2c"),
    (0x2994a15, "40 80 fd 05", "spec byte +0x1a9 > 5 -> sentry check"),
    (0x2994a29, "b0 25", "sentry failure result 0x25"),
    (0x2994a2b, "4c 3b b9 c0 00 00 00", "gas must exceed params +0xc0 (sentry)"),
    (0x2994a47, "4c 2b b9 98 00 00 00", "static charge params +0x98"),
    (0x2994a54, "48 8d 53 78", "interpreter +0x78 passed to the store"),
    (0x2994a5f, "40 80 fd 06", "spec > 6 -> skip flag and error-kind arm"),
    (0x2994a68, "4c 3b b9 c8 00 00 00", "skip flag = gas < params +0xc8"),
    (0x2994aaa, "b9 36 00 00 00", "store error result 0x36"),
    (0x2994bf0, "41 80 be 65 02 00 00", "host byte +0x265 enables the reserve accounting"),
    (0x2994ce7, "4c 8b a7 50 01 00 00", "params +0x150 charged on a fresh slot"),
    (0x2994d45, "48 c7 83 90 01 00 00", "reserve +0x190 emptied when gas pays the rest"),
    (0x2994dc0, "48 8b 87 50 01 00 00", "params +0x150 released on restore to zero"),
    (0x2994e18, "48 03 83 a0 01 00 00", "refund counter +0x1a0 (signed add, overflow panics)"),
    (0x2994e72, "b0 28", "static violation result 0x28"),
    (0x299f68e, "48 8b 87 b0 00 00 00", "refund: clear amount params +0xb0"),
    (0x299f8d5, "48 03 81 38 01 00 00", "refund: restore to zero adds params +0x138"),
    (0x299f8f3, "48 03 81 40 01 00 00", "refund: restore to non-zero adds params +0x140"),
    (0x299f91b, "48 8b 87 d0 00 00 00", "cost: cold surcharge params +0xd0"),
    (0x299f947, "b8 a8 00 00 00", "cost: reset price params +0xa8"),
    (0x299f97c, "48 8d 04 c5 a0 00 00 00", "cost: set price params +0xa0"),
    (0x299fa42, "48 03 84 cf a0 00 00 00", "cost: set/reset by original != 0"),
)


def static_evidence(image):
    rows = fde_rows(image, FUNCS)
    decoded, funcs = {}, {}
    for f in FUNCS:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    calls = {}
    for f in (HANDLER, TWIN):
        calls[f"{f:#x}"] = {}
        for va, fm in decoded[f]:
            if fm is not None and fm["bytes"][:1] == b"\xe8":
                calls[f"{f:#x}"][f"{va:#x}"] = f"{(va + 5 + struct.unpack('<i', fm['bytes'][1:5])[0]) & M64:#x}"
        want = sorted(f"{x:#x}" for x in (STORE_OF[f], STORE_OF[f], COST, REFUND))
        if sorted(calls[f"{f:#x}"].values()) != want:
            fail(f"handler direct calls changed: {calls}")
    if rows[TWIN][1] - TWIN != rows[HANDLER][1] - HANDLER:
        fail("twin FDE lengths differ")
    twin = []
    for (va, fa), (vb, fb) in zip(decoded[HANDLER], decoded[TWIN]):
        if vb - TWIN != va - HANDLER or (fa is None) != (fb is None):
            fail(f"twin instruction boundaries differ at {vb:#x}")
        if fa is None or fa["bytes"] == fb["bytes"]:
            continue
        n = fa["len"]
        if fb["len"] != n or fa["bytes"][:n - 4] != fb["bytes"][:n - 4]:
            fail(f"twin difference outside a trailing rel32/disp32 at {vb:#x}")
        ta = (va + n + struct.unpack("<i", fa["bytes"][n - 4:n])[0]) & M64
        tb = (vb + n + struct.unpack("<i", fb["bytes"][n - 4:n])[0]) & M64
        if ta != tb and not (ta == STORE and tb == TWIN_STORE):
            fail(f"twin operand at {vb:#x} names {tb:#x}, handler names {ta:#x}")
        twin.append({"handler": f"{va:#x}", "twin": f"{vb:#x}", "target_handler": f"{ta:#x}", "target_twin": f"{tb:#x}"})
    slots = {}
    for slot in PANIC_GOTS:
        kind = "GLOB_DAT" if slot in image.imports else "RELATIVE"
        slots[f"{slot:#x}"] = {"relocation": kind, "target": f"{image.word(slot):#x}"}
    checks = {}
    for va, hx, what in CHECKED:
        want = bytes.fromhex(hx)
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "handler_direct_calls": calls, "panic_slots": slots,
           "twin_operands": twin,
           "checked_bytes": checks,
           "interpreter_offsets": {"stack_ptr": f"{I_STACK_PTR:#x}", "stack_len": f"{I_STACK_LEN:#x}",
                                   "address": f"{I_ADDR:#x}", "gas_remaining": f"{I_GAS:#x}",
                                   "reserve": f"{I_RESERVE:#x}", "reserved_i64": f"{I_RESERVED:#x}",
                                   "refund_i64": f"{I_REFUND:#x}", "static": f"{I_STATIC:#x}", "spec": f"{I_SPEC:#x}"},
           "host_offsets": {"gas_params": f"{H_PARAMS:#x}", "reserve_flag": f"{H_FLAG:#x}"},
           "gas_params": [f"{x:#x}" for x in PARAM_OFFS],
           "results": {"ok": R_OK, "out_of_gas": R_OOG, "sentry": R_SENTRY, "static": R_STATIC,
                       "underflow": R_UNDERFLOW, "store_error": R_FATAL}}
    return out, decoded


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


# ---------------------------------------------------------------- evaluation
def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else all_cases()):
        try:
            want = model(c, mut)
            got = run_case(m, c)
            ok = compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


MODEL_MUTANTS = ["pop_swap", "sentry_ge5", "err_always_fatal", "pre_flag_new_only", "no_cold", "noop_charges",
                 "dirty_charges", "set_reset_swap", "no_negate", "no_restore", "reserve_no_gas", "no_release"]
BYTE_MUTANTS = [
    (0x29949b6, 0x2d, "underflow result 0x2c -> 0x2d"),
    (0x2994a18, 0x04, "sentry spec threshold 5 -> 4"),
    (0x2994a4a, 0xa0, "static charge params +0x98 -> +0xa0"),
    (0x2994a6b, 0xc0, "skip-flag params +0xc8 -> +0xc0"),
    (0x2994aab, 0x37, "store error result 0x36 -> 0x37"),
    (0x2994bf3, 0x64, "reserve flag byte +0x265 -> +0x264"),
    (0x2994cea, 0x48, "fresh-slot params +0x150 -> +0x148"),
    (0x2994dc3, 0x48, "release params +0x150 -> +0x148"),
    (0x299f691, 0xa8, "refund clear params +0xb0 -> +0xa8"),
    (0x299f8d8, 0x40, "refund restore-zero +0x138 -> +0x140"),
    (0x299f91e, 0xc8, "cold surcharge +0xd0 -> +0xc8"),
    (0x299f948, 0xa0, "reset price +0xa8 -> +0xa0"),
    (0x29945ab, 0x37, "twin store error result 0x36 -> 0x37"),
    (0x29944b6, 0x2d, "twin underflow result 0x2c -> 0x2d"),
]


def controls(image, cases):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, override={va: byte}, stop_on_first=True, cases=cases)
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
def wtag(x):
    if x == 0:
        return "0"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def outcome(c, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "panic":
        return "panic"
    names = {R_OK: "ok", R_OOG: "out-of-gas", R_SENTRY: "sentry", R_STATIC: "static", R_UNDERFLOW: "underflow",
             R_FATAL: "store-error"}
    head = names.get(code, f"r{code:#x}")
    if not got["events"]:
        return f"{head}/before-store"
    o, cur, new, tag = c["result"]
    if tag == 2:
        return f"{head}/store-error"
    shape = "noop" if new == cur else ("clean" if o == cur else "dirty")
    shape += "-zero" if o == 0 else ""
    return f"{head}/{'cold' if tag else 'warm'}/{shape}/{'ge6' if c['spec'] >= 6 else 'lt6'}"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    rows, bad, m = evaluate(image, cases=cases)
    consts, decoded = static_evidence(image)
    lines = ["case\tinput\toutcome\tstore_call\tresult\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = outcome(c, got)
        o, cur, new, tag = c["result"]
        p = c["params"]
        inp = (f"entry={c['entry']:#x},spec={c['spec']},static={c['static']},n={c['n']},gas={c['gas']:#x},host={c['host_flag']:#x},"
               f"orig={wtag(o)},cur={wtag(cur)},new={wtag(new)},tag={tag},"
               f"p98={p[0x98]:#x},pa0={p[0xa0]:#x},pa8={p[0xa8]:#x},pb0={p[0xb0]:#x},pc0={p[0xc0]:#x},"
               f"pc8={p[0xc8]:#x},pd0={p[0xd0]:#x},p138={p[0x138]:#x},p140={p[0x140]:#x},p150={p[0x150]:#x},"
               f"res={c['reserve']:#x},rsv={c['reserved']:#x},ref={c['refund']:#x}")
        ev = got.get("events", [])
        call = f"{ev[0][1]:#x}:skip={ev[0][5]}" if ev else "-"
        if "error" in got:
            res = got["error"]
        elif got["ret"][0] == "panic":
            res = "panic"
        else:
            s = got["state"]
            res = (f"ret={got['ret'][1]:#x},len={s['len']},gas={s['gas']:#x},res={s['reserve']:#x},"
                   f"rsv={s['reserved']:#x},ref={s['refund']:#x}")
        classes[oc] = classes.get(oc, 0) + 1
        lines.append(f"{i}\t{inp}\t{oc}\t{call}\t{res}\t{'yes' if ok else 'NO'}")
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
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
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = controls(image, cases)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes,
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
