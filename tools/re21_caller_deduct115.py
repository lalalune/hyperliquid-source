#!/usr/bin/env python3
"""Reconstruct and validate the node #115 caller account gates and deduction write-back.

Both transaction drivers that call the payer balance helper 0x2973440 (driver A in the
FDE at 0x29a1290, driver B in the FDE that holds 0x2963553) run the same caller-side step
around that call: an optional code gate (rejection 5), an optional nonce gate (rejections
8, 9, 10), the payer handoff, the touched flag with a journal entry of tag 2, a balance
change entry of tag 3 that keeps the old balance and the store of the new one, and for
call-kind transactions a saturating nonce bump with a journal entry of tag 6.  The tool
reads every relocation, FDE extent and code byte from the ELF file, evaluates the real
machine code of both fragments with a small concrete x86-64 evaluator (no external
programs, the binary is never executed) and compares every case with one pure-Python
reconstruction.  Negative controls show that wrong reconstructions and corrupted code
bytes are detected.
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

PAYER = 0x2973440
GROW_SLOT = 0x64e6cf0  # journal vector growth, called through this GOT slot
ENTRY = 0x58  # journal entry stride (imul $0x58)

STACK_TOP = 0x7ff0_0000_0000
RETURN_MARK = 0x7e00_dead_0000
ACCOUNT_AT = 0x7d00_0000_0000
CODE_AT = 0x7d00_0100_0000
JOURNAL_AT = 0x7d00_0200_0000
ENTRIES_AT = 0x7d00_1000_0000
TX_AT = 0x7d00_3000_0000
SENTINEL = 0xa5a5a5a5a5a5a5a5
IMPORT_BASE = 0x7c00_0000_0000
FRAME = 0x3000  # stack bytes above rsp available to the fragments

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
    p, opsize, rex, rep = 0, 32, 0, False
    while code[p] in (0x66, 0x2e, 0xf3):  # operand-size, (ignored) segment and the movss prefix
        if code[p] == 0x66:
            opsize = 16
        if code[p] == 0xf3:
            rep = True
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
    form = {"op": op, "rex": rex, "size": opsize, "rep": rep}

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
    elif op in (0xc3, 0x90, 0x0f0b):
        pass
    elif op in (0x11, 0x13, 0x88, 0x0f57, 0x01, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x29, 0x2b, 0x31, 0x33,
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
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
    elif op in (0x0c, 0x1c):
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
        self.cf, self.of = res >> size != 0, None
        res &= (1 << size) - 1
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
        self.cf, self.of = a < b, None
        res = (a - b) & ((1 << size) - 1)
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
                if not call:
                    fail(f"tail jump into stub at {va:#x}")
                kind(self)
                return None
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
                self.of = self.cf  # unsigned mul: OF == CF; only mul defines OF in this evaluator
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
        elif op == 0x0f57:
            rm = f["rm"]
            other = self.xmm[rm[1]] if rm[0] == "r" else self.load(self.ea(rm, f, va), 16)
            self.xmm[f["reg"]] ^= other
        elif op == 0x0f0b:
            fail(f"ud2 reached at {va:#x}")
        elif op == 0x0c:
            self.set_reg(0, 8, self.flags_logic((self.regs[0] | f["imm"]) & 0xff, 8), f)
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




# ---------------------------------------------------------------- the two driver fragments
# Frame offsets are the displacements the fragments use; constants.json re-reads each one
# from the instruction bytes so a wrong row here fails the static check.
DRIVERS = {
    "A": {
        "probe": 0x29a1d84,  # payer call inside the driver FDE
        "start": 0x29a1ce0,  # first instruction after the account load wrapper 0x299f4d0
        "bump_start": 0x29a1efa,  # call-kind test that opens the nonce bump block
        "segments": [(0x29a1ce0, 0x29a1fa4), (0x29a20a0, 0x29a2106), (0x29a270a, 0x29a2711),
                     (0x29a2745, 0x29a274c), (0x29a2768, 0x29a276d)],
        "exits": {0x29a1fa4: "ok", 0x29a26b2: "default_code", 0x29a2106: "payer",
                  0x29a276d: "reject", 0x29a2777: "reject"},
        "value_reg": 0,
        "frame": {"wrapper_out": 0x230, "tx_nonce": 0xcd0, "skip_nonce": 0xd71, "skip_code": 0xd73,
                  "kind": 0xcec, "address": 0x64, "payer_out": 0x230, "payer_balance": 0x1a0,
                  "payer_ctx": 0xb10},
        "regs": {"tx": 15},
    },
    "B": {
        "probe": 0x2963553,
        "start": 0x29634ef,  # first instruction after the auxiliary call 0x299f1c0
        "bump_start": 0x29636dc,
        "segments": [(0x29634ef, 0x2963796), (0x2963865, 0x29638cd), (0x2963eb1, 0x2963ebf),
                     (0x2963edb, 0x2963ee0)],
        "exits": {0x2963796: "ok", 0x2963e59: "default_code", 0x2963ee0: "reject_or_payer"},
        "value_reg": 3,
        "frame": {"tx_nonce": 0x11b0, "skip_nonce": 0x1251, "skip_code": 0x1253, "kind": 0x11cc,
                  "address": 0xd4, "payer_out": 0x210, "payer_balance": 0x760, "payer_ctx": 0xff0},
        "regs": {"account": 13, "journal": 12, "tx": 5},
    },
}
EXIT_OF = {  # model outcome -> exit address per driver
    "A": {"ok": 0x29a1fa4, "default_code": 0x29a26b2, "payer": 0x29a2106,
          5: 0x29a276d, 8: 0x29a276d, 9: 0x29a2777, 10: 0x29a2777},
    "B": {"ok": 0x2963796, "default_code": 0x2963e59, "payer": 0x2963ee0,
          5: 0x2963ee0, 8: 0x2963ee0, 9: 0x2963ee0, 10: 0x2963ee0},
}
OK_TAG = 0x21
ACC_BALANCE, ACC_NONCE, ACC_CODE, ACC_FLAGS = 0x28, 0x68, 0x70, 0x8c
CODE_LEN, CODE_DELEGATED = 0x50, 0x7c


# ---------------------------------------------------------------- reconstruction
def grow_count(len0, cap0, pushes, no_grow=False):
    n, length, cap = 0, len0, cap0
    for _ in range(pushes):
        if length == cap and not no_grow:
            n, cap = n + 1, max(4, 2 * cap)
        length += 1
    return n


def model(c, mut=frozenset()):
    """Caller gates and write-back of one driver fragment, as pure Python.

    Returns (outcome, value, payer_calls, pushes, balance, nonce, flags) where pushes is the
    list of journal entries (tag, old_balance_or_None) appended in order.
    """
    balance, nonce, flags = c["balance"], c["nonce"], c["flags"]
    skip_code, skip_nonce = c["skip_code"], c["skip_nonce"]
    if "swap_skips" in mut:
        skip_code, skip_nonce = skip_nonce, skip_code

    def code_gate():
        if skip_code:
            return None
        if c["code"] is None:
            return ("default_code", None)
        length, delegated = c["code"]
        if length != 0 and (not delegated or "ignore_delegation" in mut):
            return ("reject", 5)
        return None

    def nonce_gate():
        if skip_nonce:
            return None
        tx = c["tx_nonce"]
        if tx == nonce == M64 and "no_overflow_reject" not in mut:
            return ("reject", 8)
        if tx > nonce:
            return ("reject", 10 if "swap_9_10" in mut else 9)
        if tx < nonce:
            return ("reject", 9 if "swap_9_10" in mut else 10)
        return None

    bump_only = c.get("entry") == "bump"  # direct entry at the bump block (second touch reachable)
    if not bump_only:
        gates = (nonce_gate, code_gate) if "nonce_first" in mut else (code_gate, nonce_gate)
        for gate in gates:
            hit = gate()
            if hit:
                return hit + (0, [], balance, nonce, flags)
        tag, new = c["payer"]
        if tag != OK_TAG:
            return ("payer", tag, 1, [], balance, nonce, flags)
    pushes = []

    def touch():
        nonlocal flags
        if not flags & 4 or "touch_always" in mut:
            flags |= 4
            pushes.append((2, None))

    if not bump_only:
        touch()
        if new != balance or "balance_entry_always" in mut:
            pushes.append((3, new if "journal_new_balance" in mut else balance))
            balance = new
    if (c["kind"] != 0) if "bump_kind_nonzero" in mut else (c["kind"] == 1):
        touch()
        if nonce != M64 or "bump_wraps" in mut:
            nonce = (nonce + 1) & M64
            pushes.append((6, None))
    return ("ok", None, 0 if bump_only else 1, pushes, balance, nonce, flags)


def entry_bytes(tag, old, address):
    """Expected bytes of one appended 0x58-byte journal entry (sentinel where untouched)."""
    e = bytearray([0xa5]) * ENTRY
    e[0] = tag
    e[1:0x15] = address
    if tag == 3:
        # The 36-byte copy starts three bytes before the old balance; those three bytes are
        # the low bytes of the helper's result word (0x21, 0, 0) still in the frame.
        e[0x15:0x18] = bytes([OK_TAG, 0, 0])
        e[0x18:0x38] = old.to_bytes(32, "little")
    return bytes(e)


def old_entry(i):
    return bytes((i * 7 + j * 13 + 1) & 0xff for j in range(ENTRY))


def expected(driver, c, mut=frozenset()):
    outcome, value, calls, pushes, balance, nonce, flags = model(c, mut)
    if outcome == "reject":
        exit_va, shown = EXIT_OF[driver][value], value
    else:
        exit_va, shown = EXIT_OF[driver][outcome], value
    grows = grow_count(c["len"], c["cap"], len(pushes), "no_grow" in mut)
    entries = b"".join(entry_bytes(t, o, c["address"]) for t, o in pushes)
    return {"exit": exit_va, "value": shown, "payer_calls": calls,
            "payer_balance": c["balance"] if calls else None, "len": c["len"] + len(pushes),
            "entries": entries.hex(), "tags": "".join(str(t) for t, _ in pushes) or "-",
            "balance": balance, "nonce": nonce, "flags": flags, "grows": grows,
            "old_intact": True}


# ---------------------------------------------------------------- harness
class Fragment(TraceMachine):
    def run_to(self, start, exits, limit=5000):
        pc = start
        while pc not in exits:
            self.steps += 1
            if self.steps > limit:
                fail("step limit")
            if pc == RETURN_MARK:
                fail("fragment returned")
            pc = self.step(pc)
        return pc


def grow_target(image):
    return image.word(GROW_SLOT)


def run_case(m, driver, c):
    spec = DRIVERS[driver]
    m.reset()
    m.cf = m.zf = m.sf = False
    m.add_region(STACK_TOP - 0x20000, 0x20000 - 0x10000)  # extra frame room below the default stack
    rsp = STACK_TOP - FRAME
    m.regs[4] = rsp
    fr = spec["frame"]
    acc = m.add_region(ACCOUNT_AT, 0x100, bytes([0x5a]) * 0x100)
    acc[ACC_BALANCE:ACC_BALANCE + 32] = c["balance"].to_bytes(32, "little")
    acc[ACC_NONCE:ACC_NONCE + 8] = c["nonce"].to_bytes(8, "little")
    acc[ACC_FLAGS] = c["flags"]
    code_ptr = 0
    if c["code"] is not None:
        code = m.add_region(CODE_AT, 0x100, bytes([0x3c]) * 0x100)
        code[CODE_LEN:CODE_LEN + 8] = c["code"][0].to_bytes(8, "little")
        code[CODE_DELEGATED] = c["code"][1]
        code_ptr = CODE_AT
    acc[ACC_CODE:ACC_CODE + 8] = code_ptr.to_bytes(8, "little")
    jr = m.add_region(JOURNAL_AT, 0x18)
    cap, length = c["cap"], c["len"]
    buf_at = ENTRIES_AT
    ent = m.add_region(buf_at, max(cap, 1) * ENTRY, bytes([0xa5]) * (max(cap, 1) * ENTRY))
    for i in range(length):
        ent[i * ENTRY:(i + 1) * ENTRY] = old_entry(i)
    jr[0:24] = struct.pack("<QQQ", cap, buf_at, length)
    m.grows = 0
    m.payer_calls = []

    def grow(mc):
        if mc.regs[7] != JOURNAL_AT:
            fail("grow called with a foreign vector")
        old_cap, old_ptr, old_len = (mc.load(JOURNAL_AT + k, 8) for k in (0, 8, 16))
        if old_len != old_cap:
            fail("grow called below capacity")
        mc.grows += 1
        new_cap = max(4, 2 * old_cap)
        at = ENTRIES_AT + 0x100000 * mc.grows
        nb = mc.add_region(at, new_cap * ENTRY, bytes([0xa5]) * (new_cap * ENTRY))
        for i in range(old_len * ENTRY):
            nb[i] = mc.load(old_ptr + i, 1)
        mc.store(JOURNAL_AT, 8, new_cap)
        mc.store(JOURNAL_AT + 8, 8, at)

    def payer(mc):
        want = (rsp + fr["payer_out"], rsp + fr["payer_balance"], TX_AT, rsp + fr["payer_ctx"])
        got = (mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1])
        if got != want:
            fail("payer called with unexpected arguments")
        mc.payer_calls.append(mc.load(mc.regs[6], 32))
        tag, new = c["payer"]
        mc.store(mc.regs[7], 8, tag)
        mc.store(mc.regs[7] + 8, 32, new if tag == OK_TAG else SENTINEL)
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):  # caller-saved registers are clobbered
            mc.regs[r] = SENTINEL

    m.stubs[PAYER] = payer
    m.stubs[grow_target(m.image)] = grow
    m.store(rsp + fr["tx_nonce"], 8, c["tx_nonce"])
    m.store(rsp + fr["skip_nonce"], 1, c["skip_nonce"])
    m.store(rsp + fr["skip_code"], 1, c["skip_code"])
    m.store(rsp + fr["kind"], 1, c["kind"])
    bump = c.get("entry") == "bump"
    if bump:
        for k, b in enumerate(c["address"]):
            m.store(rsp + fr["address"] + k, 1, b)
        m.regs[12 if driver == "A" else 13] = ACCOUNT_AT
        m.regs[14 if driver == "A" else 12] = JOURNAL_AT
    elif driver == "A":
        out = rsp + fr["wrapper_out"]
        m.store(out, 8, ACCOUNT_AT)
        m.store(out + 8, 8, JOURNAL_AT)
        for k in range(0x10, 0x38):
            m.store(out + k, 1, 0x77)
        for k, b in enumerate(c["address"]):
            m.store(out + 0x24 + k, 1, b)
        m.regs[15] = TX_AT
    else:
        for k, b in enumerate(c["address"]):
            m.store(rsp + fr["address"] + k, 1, b)
        m.regs[13], m.regs[12], m.regs[5] = ACCOUNT_AT, JOURNAL_AT, TX_AT
    exit_va = m.run_to(spec["bump_start"] if bump else spec["start"], spec["exits"])
    cap1, ptr1, len1 = (m.load(JOURNAL_AT + k, 8) for k in (0, 8, 16))
    intact = all(m.load(ptr1 + i * ENTRY, ENTRY) == int.from_bytes(old_entry(i), "little")
                 for i in range(min(length, len1)))
    entries = b"".join(m.load(ptr1 + i * ENTRY, ENTRY).to_bytes(ENTRY, "little")
                       for i in range(length, len1))
    kind = spec["exits"][exit_va]
    value = m.regs[spec["value_reg"]] if kind not in ("ok", "default_code") else None
    if m.load(ACCOUNT_AT + ACC_CODE, 8) != code_ptr:
        fail("code pointer changed")
    return {"exit": exit_va, "value": value, "payer_calls": len(m.payer_calls),
            "payer_balance": m.payer_calls[0] if m.payer_calls else None, "len": len1,
            "entries": entries.hex(),
            "tags": "".join(str(entries[i * ENTRY]) for i in range(len1 - length)) or "-",
            "balance": m.load(ACCOUNT_AT + ACC_BALANCE, 32), "nonce": m.load(ACCOUNT_AT + ACC_NONCE, 8),
            "flags": m.load(ACCOUNT_AT + ACC_FLAGS, 1), "grows": m.grows, "old_intact": intact}


# ---------------------------------------------------------------- cases
NONCE_PAIRS = [(0, 0), (1, 0), (0, 1), (7, 7), (M64, M64), (M64 - 1, M64), (M64, M64 - 1),
               (M64 - 1, M64 - 1), (1 << 63, 1 << 63), (1 << 63, (1 << 63) - 1)]
CODES = [None, (0, 0), (0, 1), (33, 0), (33, 1)]
PAYERS = ["same", "diff", "zero", 6, 7, 0x12]


def word256(s):
    k = s.below(5)
    if k == 0:
        return s.below(1 << 16)
    if k == 1:
        return M256 - s.below(1 << 16)
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(24))


def make_case(s, skip_code, code, skip_nonce, pair, pay):
    balance = word256(s)
    if pay == "same":
        payer = (OK_TAG, balance)
    elif pay == "diff":
        new = word256(s)
        payer = (OK_TAG, new if new != balance else (balance ^ 1))
    elif pay == "zero":
        payer = (OK_TAG, 0)
    else:
        payer = (pay, 0)
    cap = s.pick([0, 1, 2, 3, 4, 8])
    length = cap if s.below(2) else s.below(cap + 1)
    return {"skip_code": skip_code, "code": code, "skip_nonce": skip_nonce,
            "tx_nonce": pair[0], "nonce": pair[1], "balance": balance, "payer": payer,
            "flags": s.below(256), "kind": s.pick([0, 1, 1, 2]), "address": s.take(20),
            "cap": cap, "len": length}


def cases(driver):
    s = Stream("re21-deduct-" + driver)
    out = []
    for skip_code in (0, 1):
        for code in CODES:
            for skip_nonce in (0, 1):
                for pair in NONCE_PAIRS:
                    for pay in PAYERS:
                        out.append(make_case(s, skip_code, code, skip_nonce, pair, pay))
    for i in range(96):  # direct entries at the bump block: flags bit 2 clear in half of them
        n = s.pick([0, 1, M64 - 1, M64, int.from_bytes(s.take(8), "little")])
        c = make_case(s, 1, None, 1, (n, n), "same")
        c["entry"], c["kind"] = "bump", i % 3
        c["flags"] = (c["flags"] & ~4) | (4 if i % 6 >= 3 else 0)
        out.append(c)
    for _ in range(700):  # random nonces, mostly equal so the write-back runs
        n = int.from_bytes(s.take(8), "little")
        pair = (n, n) if s.below(3) else (n, int.from_bytes(s.take(8), "little"))
        out.append(make_case(s, s.below(2), s.pick(CODES), s.below(2), pair,
                             s.pick(["same", "diff", "diff", "zero", 6])))
    return out


def describe(c):
    code = "none" if c["code"] is None else f"{c['code'][0]}/{c['code'][1]}"
    return (f"{c.get('entry', 'start')}\t{c['skip_code']}\t{code}\t{c['skip_nonce']}\t{c['tx_nonce']:#x}\t{c['nonce']:#x}\t"
            f"{c['payer'][0]:#x}\t{int(c['payer'][1] != c['balance'])}\t{c['flags']:#04x}\t"
            f"{c['kind']}\t{c['cap']}/{c['len']}")


# ---------------------------------------------------------------- static evidence
def fde_of(image, va):
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    rows = [f for f in fdes if f["start"] <= va < f["end"]]
    if len(rows) != 1:
        fail(f"expected one FDE around {va:#x}, found {len(rows)}")
    return rows[0]["start"], rows[0]["end"]


def static_evidence(image):
    out = {"binary_sha256": SHA256, "drivers": {}}
    target = grow_target(image)
    for name, spec in DRIVERS.items():
        start, end = fde_of(image, spec["probe"])
        rows = []
        for lo, hi in spec["segments"]:
            if not (start <= lo and hi <= end):
                fail(f"segment {lo:#x} outside its FDE")
            rows += sweep(image, lo, hi)
        calls, tags, disps = [], [], set()
        for va, f in rows:
            if f["op"] == 0xe8:
                calls.append([f"{va:#x}", f"{f['target']:#x}"])
            if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
                slot = (va + f["len"] + f["rm"][4]) & M64
                if slot != GROW_SLOT:
                    fail(f"indirect call at {va:#x} uses an unexpected slot")
                calls.append([f"{va:#x}", f"slot {slot:#x}"])
            if f["op"] == 0xc6 and f["rm"][0] == "m" and f["rm"][2] is not None:
                tags.append([f"{va:#x}", f["imm"]])
            if f["rm"][0] == "m" if "rm" in f else False:
                if f["rm"][1] == 4 and f["rm"][2] is None:
                    disps.add(f["rm"][4])
        for key, off in spec["frame"].items():
            if off not in disps:
                fail(f"driver {name} frame offset {key}={off:#x} not used by its code")
        if [t for _, t in tags] != [2, 3, 2, 6]:
            fail(f"driver {name} journal tag immediates changed")
        payer_calls = [c for c in calls if c[1] == f"{PAYER:#x}"]
        if len(payer_calls) != 1 or int(payer_calls[0][0], 16) != spec["probe"]:
            fail(f"driver {name} payer call edge changed")
        out["drivers"][name] = {
            "fde": [f"{start:#x}", f"{end:#x}"], "start": f"{spec['start']:#x}",
            "segments": [[f"{a:#x}", f"{b:#x}"] for a, b in spec["segments"]],
            "instructions": len(rows), "calls": calls,
            "journal_tag_stores": tags,
            "frame_offsets": {k: f"{v:#x}" for k, v in sorted(spec["frame"].items())},
            "exits": {f"{k:#x}": v for k, v in sorted(spec["exits"].items())},
        }
    rel = "GLOB_DAT" if GROW_SLOT in image.imports else "RELATIVE"
    out["grow_slot"] = {"slot": f"{GROW_SLOT:#x}", "relocation": rel,
                        "target": image.import_name(GROW_SLOT) if rel == "GLOB_DAT" else f"{target:#x}"}
    out["journal_entry_stride"] = ENTRY
    out["account_offsets"] = {"balance": ACC_BALANCE, "nonce": ACC_NONCE, "code": ACC_CODE,
                              "flags": ACC_FLAGS, "code_len": CODE_LEN, "code_delegated": CODE_DELEGATED}
    return out, rows_by_driver(image)


def rows_by_driver(image):
    return {name: [r for lo, hi in spec["segments"] for r in sweep(image, lo, hi)]
            for name, spec in DRIVERS.items()}


# ---------------------------------------------------------------- evaluation
FIELDS = ("exit", "value", "payer_calls", "payer_balance", "len", "entries", "tags", "balance",
          "nonce", "flags", "grows", "old_intact")


def evaluate(image, driver, override=None, mut=frozenset(), stop_on_first=False, machine=None):
    m = machine or Fragment(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases(driver)):
        want = expected(driver, c, mut)
        try:
            got = run_case(m, driver, c)
        except ToolError as exc:
            got = {"error": str(exc)}
        ok = all(got.get(k) == want[k] for k in FIELDS)
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            break
    return rows, bad, m


MODEL_MUTANTS = ["swap_9_10", "no_overflow_reject", "ignore_delegation", "nonce_first", "swap_skips",
                 "touch_always", "balance_entry_always", "journal_new_balance", "bump_kind_nonzero",
                 "bump_wraps", "no_grow"]
BYTE_MUTANTS = [  # (driver, address, new byte, what the byte is)
    ("A", 0x29a1e9d, 0x04, "tag 3 store immediate -> 4"),
    ("A", 0x29a1f01, 0x02, "call-kind compare immediate 1 -> 2"),
    ("A", 0x29a1de7, 0x08, "touched flag bit test 4 -> 8 (byte of or-mask kept)"),
    ("A", 0x29a20fd, 0x0b, "nonce-too-high code 9 -> 11"),
    ("B", 0x2963773, 0x07, "tag 6 store immediate -> 7"),
    ("B", 0x2963749, 0xfe, "nonce saturation compare -1 -> -2"),
    ("B", 0x2963632, 0xfe, "balance-equal mask 0xffff -> 0xfffe"),
    ("B", 0x2963edc, 0x06, "code-rejection value 5 -> 6"),
]


def controls(image):
    rows = []
    for name in MODEL_MUTANTS:
        hits = []
        for driver in DRIVERS:
            _, bad, _ = evaluate(image, driver, mut=frozenset([name]), stop_on_first=True)
            hits.append(bad)
        rows.append(("model", name, "both", int(any(hits))))
    for driver, va, byte, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, driver, override={va: byte}, stop_on_first=True)
        rows.append(("code", f"{va:#x}={byte:#04x} {what}", driver, int(bad > 0)))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    try:
        Image(bytes(corrupt))
        rows.append(("input", "one flipped .text byte", "-", 0))
    except ToolError:
        rows.append(("input", "one flipped .text byte", "-", 1))
    try:
        image.code(image.text["address"] + image.text["size"] + 0x100, 4)
        rows.append(("input", "address past .text", "-", 0))
    except ToolError:
        rows.append(("input", "address past .text", "-", 1))
    return rows


# ---------------------------------------------------------------- output
def generate(out):
    data = BINARY.read_bytes()
    image = Image(data)
    consts, rows_by = static_evidence(image)
    out.mkdir(parents=True, exist_ok=True)
    case_lines = ["driver\tcase\tentry\tskip_code\tcode_len/delegated\tskip_nonce\ttx_nonce\tstate_nonce\t"
                  "payer_tag\tnew_differs\tflags_in\tkind\tcap/len\texit\tvalue\tjournal_tags\t"
                  "nonce_out\tflags_out\tgrows\tmatch"]
    classes, totals, seen = {}, {}, {}
    for driver in DRIVERS:
        rows, bad, m = evaluate(image, driver)
        totals[driver] = {"cases": len(rows), "mismatches": bad}
        seen[driver] = m.seen
        for i, c, want, got, ok in rows:
            value = "-" if got.get("value") is None else f"{got['value']:#x}"
            case_lines.append(f"{driver}\t{i}\t{describe(c)}\t{got.get('exit', 0):#x}\t{value}\t"
                              f"{got.get('tags')}\t{got.get('nonce', 0):#x}\t{got.get('flags', 0):#04x}\t"
                              f"{got.get('grows')}\t{'yes' if ok else 'NO'}")
            key = (driver, DRIVERS[driver]["exits"].get(got.get("exit"), "?"), value, got.get("tags"))
            classes[key] = classes.get(key, 0) + 1
    (out / "cases.tsv").write_text("\n".join(case_lines) + "\n")
    lines = ["driver\texit_kind\tvalue\tjournal_tags\tcases"]
    for key in sorted(classes, key=lambda k: (k[0], k[1], str(k[2]), str(k[3]))):
        lines.append("\t".join(str(x) for x in key) + f"\t{classes[key]}")
    (out / "outcome-classes.tsv").write_text("\n".join(lines) + "\n")
    lines = ["driver\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for driver, rows in rows_by.items():
        hit = 0
        for va, f in rows:
            run = va in seen[driver]
            hit += run
            lines.append(f"{driver}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}")
        covered[driver] = [hit, len(rows)]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = controls(image)
    lines = ["kind\tcontrol\tdriver\tdetected"] + ["\t".join(str(x) for x in r) for r in ctl]
    (out / "negative-controls.tsv").write_text("\n".join(lines) + "\n")
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {
        "binary_sha256": SHA256,
        "drivers": {d: dict(totals[d], covered_instructions=covered[d]) for d in DRIVERS},
        "mismatches": sum(t["mismatches"] for t in totals.values()),
        "negative_controls": {"total": len(ctl), "detected": sum(r[3] for r in ctl)},
        "outcome_classes": len(classes),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
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
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
