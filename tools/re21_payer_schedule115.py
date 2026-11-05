#!/usr/bin/env python3
"""Reconstruct and validate the node #115 gas schedule constructor and payer balance helper.

Two functions are reconstructed: the schedule constructor 0x5be2560 (a mode byte to a
0x810-byte schedule object, every one of the 256 modes) and the payer balance helper
0x2973440 (required balance, effective price, auxiliary charge, the tag 6/7 results,
the clamped remainder and the two panic exits).  The constructed schedules are then fed
to the real cost calculation 0x5be0720 for every mode.  The tool reads every constant,
relocation and FDE extent from ELF bytes, evaluates the real machine code with a small
concrete x86-64 evaluator (no external programs, the binary is never executed), and
compares every case with an independent pure-Python reconstruction.  Negative controls
show that wrong reconstructions and corrupted code bytes are detected.
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

CTOR = 0x5be2560
PAYER = 0x2973440
COST = 0x5be0720
SLOTS = {  # GOT slots called on these paths; targets come from R_X86_64_RELATIVE addends
    "alloc": 0x64df480,
    "alloc_error": 0x64df490,
    "memset": 0x64df750,
    "panic_add_overflow": 0x64df520,
    "panic_sub_overflow": 0x64df848,
    "panic_mul_overflow": 0x64df870,
    "result_unwrap_failed": 0x64df6a0,
}
PAYER_PANIC = {"shift": 0x6443b50, "charge": 0x6441d20}  # location arguments read by the tool
SCHED_SIZE = 0x810
SCHED_HEADER = 0x188

STACK_TOP = 0x7ff0_0000_0000
RETURN_MARK = 0x7e00_dead_0000
TX_AT = 0x7d00_0000_0000
CTX_AT = 0x7d00_0100_0000
BAL_AT = 0x7d00_0200_0000
OUT_AT = 0x7d00_1000_0000
SCHED_AT = 0x7d00_2000_0000
DATA_AT = 0x7d00_3000_0000
HEAP_AT = 0x7d00_4000_0000
SENTINEL = 0xa5a5a5a5a5a5a5a5
IMPORT_BASE = 0x7c00_0000_0000
TX_SIZE = 0x120
CTX_SIZE = 0xa0

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
        if not t["address"] <= va and va + size <= t["address"] + t["size"]:
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
                0x0f1f) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
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


# ---------------------------------------------------------------- reconstruction: schedule constructor
def schedule_words(mode, mut=frozenset()):
    """Schedule constructor 0x5be2560: header words of the 0x810-byte object for a mode byte."""
    m = mode & 0xff
    zero = (0, 0)
    r15 = 0x7d00 if m != 0 or "create-base-mode0" in mut else 0
    r12 = 0x61a8 if m >= 2 else 0
    rbp, r13, r14, s8 = 0x3a98, 0x5dc0, 0, 0x7d00
    sb0 = s30 = s50 = s40 = s10 = s20 = s90 = zero
    s60, s80 = (0, 0x61a8), (0xc8, 0)
    if m < 6:
        s70, sc0, sa8 = (0x3a98, 0), (0, 0x1388), 0x11
    elif m == 6 and "mode6-as-7" not in mut:
        s70, sc0, sa8 = (0x4b00, 0x1068), (0, 0x320), 4
    else:
        sa8 = 4
        if m >= 8:
            rbp, r13 = 0x12c0, 0
        r14 = 2 if m >= 10 else 0
        sb0, sc0 = (0x7d0, 0x834), (0x64, 0x64)
        s70, s50, s60 = (0x4dbc, 0xaf0), (0x960, 0x76c), (0x9c4, 0x61a8)
        top = 13 if "mode14-as-13" not in mut else 14
        if m < 12:
            pass
        elif m <= top:
            s20, s40, s30, s80 = (1, 0), (0x30d4, 0), (0xa, 0x5208), (0xc8, 0x61a8)
        else:
            s20, s10, s90, s40 = (4, 4), (0x2cd30, 0x8976), (0x2cd30, 0x5fa), (0, 0x17e80)
            s70, s50, s30, s80, s60 = (0xaf0, 0xaf0), (0xe60, 0xf6c), (0x10, 0x5208), (0, 0x1d4c), (0x9c4, 0)
            s8, r12, r15 = 0x2328, 0, 0x2328
    w = {0x00: 1, 0x08: 1, 0x10: 0, 0x18: 0x32 if m >= (2 if "word18-from-2" in mut else 3) else 0xa,
         0x20: 3, 0x28: 3, 0x30: 8, 0x38: 0x177, 0x40: 3, 0x48: 6, 0x50: 3, 0x58: 0x200, 0x60: 2,
         0x68: s8, 0x70: 0x40, 0x78: 0x2328, 0xb0: rbp, 0xb8: r13, 0xc0: 0x8fc, 0xd8: r12, 0xf0: sa8,
         0xf8: 4, 0x120: 0x5208, 0x128: r15, 0x130: r14}
    for off, pair in ((0x80, s60), (0x90, sc0), (0xa0, s70), (0xc8, sb0), (0xe0, s80), (0x100, s30),
                      (0x110, s50), (0x138, s70), (0x148, s40), (0x158, s90), (0x168, s10), (0x178, s20)):
        w[off], w[off + 8] = pair
    if "drop-duplicate-138" in mut:
        w[0x138], w[0x140] = 0, 0
    return w


def schedule_bytes(mode, mut=frozenset()):
    body = bytearray(SCHED_SIZE)  # bytes 0x188..0x810 are cleared by the memset call
    for off, v in schedule_words(mode, mut).items():
        put(body, off, 8, v)
    return bytes(body)


# ---------------------------------------------------------------- reconstruction: cost (from RE-021-tx-admission)
class Panic(Exception):
    def __init__(self, location, kind):
        super().__init__(f"{kind}@{location:#x}")
        self.location, self.kind = location, kind


def _chk(value, location, kind):
    if value > M64:
        raise Panic(location, kind)
    return value


def cost(s, data, create, accesses, keys, auths):
    """Cost calculation 0x5be0720: [initial, refund-like word, 0, floor] or a located panic."""
    nz = s[0xf0]
    zeros = data.count(0)
    tokens = _chk(_chk((len(data) - zeros) * nz, 0x64bf370, "mul") + zeros, 0x64bf388, "add")
    extra = min(M64, s[0x158] + s[0x170])
    per_auth = min(M64, s[0xe8] + extra)
    gross = _chk(auths * per_auth, 0x64bf268, "mul")
    refund = _chk(auths * extra, 0x64bf280, "mul")
    if gross < refund:
        raise Panic(0x64bf298, "sub")
    weighted = _chk(tokens * s[0xf8], 0x64bf2b0, "mul")
    acc = _chk(_chk(accesses * s[0x110], 0x64bf2c8, "mul") + weighted, 0x64bf2b0, "add")
    initial = _chk(_chk(keys * s[0x118], 0x64bf2e0, "mul") + acc, 0x64bf2b0, "add")
    initial = _chk(initial + s[0x120], 0x64bf2b0, "add")
    initial = _chk(initial + gross - refund, 0x64bf2b0, "add")
    if create:
        initial = _chk(initial + s[0x128], 0x64bf2f8, "add")
        words = ((len(data) + 31) & M64) >> 5
        initial = _chk(min(M64, words * s[0x130]) + initial, 0x64bf310, "add")
        refund = _chk(refund + s[0x168], 0x64bf328, "add")
    a = min(M64, accesses * 20)
    k = keys << 5 if keys >> 59 == 0 else M64
    floor_list = min(M64, min(M64, a + k) * s[0x180])
    floor_tokens = _chk(len(data) * nz, 0x64bf238, "mul") if s[0x178] == nz else tokens
    floor = _chk(_chk(s[0x100] * floor_tokens, 0x64bf250, "mul") + s[0x108], 0x64bf250, "add")
    floor = _chk(floor + _chk(floor_list * s[0x100], 0x64bf340, "mul"), 0x64bf358, "add")
    return [initial, refund, 0, floor]


# ---------------------------------------------------------------- reconstruction: payer balance helper
def payer(balance, tx, ctx, mut=frozenset()):
    """Payer balance helper 0x2973440(out, &mut balance, tx, ctx)."""
    G, P, V, K = u(tx, 0xd8, 8), u(tx, 0x50, 16), u(tx, 0x60, 32), tx[0x111]
    gp = G * P
    if gp > M128:
        return {"stop": "return", "tag": 7}
    required = gp + (0 if "required-ignores-value" in mut else V)
    if required > M256:
        return {"stop": "return", "tag": 7}
    aux3 = K == 3 or ("aux-for-k-ge-3" in mut and K > 3)
    if aux3:
        N = u(tx, 0xb8, 8)
        if N >> 47:
            return {"stop": "panic", "kind": "mul", "loc": PAYER_PANIC["shift"]}
        U = N << 17
        amax = U * u(tx, 0x80, 16)
        required += amax if "aux-unsaturated" in mut else min(M128, amax)
        if required > M256:
            return {"stop": "return", "tag": 7}
    short = balance <= required if "tag6-on-equal" in mut else balance < required
    if short:
        return {"stop": "return", "tag": 6, "required": required, "balance": balance}
    eff = P
    if (K >= 2 or "effective-for-k1" in mut and K == 1) and tx[0] & 1:
        capped = min(M128, u(tx, 0x10, 16) + u(ctx, 0x98, 8))
        eff = capped if "effective-no-min" in mut else min(P, capped)
    total = G * eff + V  # G*eff <= G*P < 2**128 here, so the 128-bit check cannot fire
    if total > M256:
        return {"stop": "panic", "kind": "unwrap", "loc": PAYER_PANIC["charge"]}
    if aux3:
        actual = U * u(ctx, 0x10, 16)
        if ctx[0] & 1 or "actual-ignores-flag" in mut:
            actual = min(M128, actual)
        else:
            actual = 0
        total += actual
        if total > M256:
            return {"stop": "panic", "kind": "unwrap", "loc": PAYER_PANIC["charge"]}
    charge = total - V
    newbal = (balance - charge) & M256
    value = newbal if "clamp-missing" in mut else max(0, balance - charge)
    return {"stop": "return", "tag": 0x21, "value": value, "newbal": newbal}


# ---------------------------------------------------------------- evaluation of the real code
CALLEE_SAVED = {3: 0x3333_0000_0000_0003, 5: 0x5555_0000_0000_0005, 12: 0xcccc_0000_0000_000c,
                13: 0xdddd_0000_0000_000d, 14: 0xeeee_0000_0000_000e, 15: 0xffff_0000_0000_000f}


def _setup(m):
    m.reset()
    for r, v in CALLEE_SAVED.items():
        m.regs[r] = v


def _check_abi(m, sp):
    for r, v in CALLEE_SAVED.items():
        if m.regs[r] != v:
            fail(f"callee-saved register {r} not restored")
    if m.regs[4] != sp:
        fail("stack pointer not restored")


def _install_heap(m, fail_at=None):
    """Allocator stub: fresh 0xa5-filled regions; returns 0 on call number fail_at."""
    calls = []

    def alloc(mc):
        calls.append(mc.regs[7])
        if fail_at is not None and len(calls) == fail_at:
            mc.regs[0] = 0
            return
        base = HEAP_AT + 0x10000 * len(calls)
        mc.add_region(base, mc.regs[7], b"\xa5" * mc.regs[7])
        mc.regs[0] = base

    def memset(mc):
        dst, val, n = mc.regs[7], mc.regs[6] & 0xff, mc.regs[2]
        calls.append(("memset", dst, val, n))
        for lo, hi, buf in mc.regions:
            if lo <= dst and dst + n <= hi:
                buf[dst - lo:dst - lo + n] = bytes([val]) * n
                mc.regs[0] = dst
                return
        fail("memset outside a region")

    t = {name: m.image.relative[slot] for name, slot in SLOTS.items()}
    m.stubs[t["alloc"]] = alloc
    m.stubs[t["memset"]] = memset
    for name in ("alloc_error", "panic_add_overflow", "panic_sub_overflow", "panic_mul_overflow",
                 "result_unwrap_failed"):
        m.stubs[t[name]] = name
    return calls


def run_ctor(m, mode, fail_alloc=False):
    _setup(m)
    calls = _install_heap(m, 1 if fail_alloc else None)
    m.regs[7] = 0x5a5a_5a00 | mode  # only the low byte is an input
    sp = m.regs[4]
    try:
        steps = m.run(CTOR, limit=5000)
    except Boundary as exc:
        return {"stop": exc.kind, "args": (exc.regs[7], exc.regs[6]), "allocs": calls}, m.steps
    _check_abi(m, sp)
    ptr = m.regs[0]
    body = bytes(m.load(ptr + i, 1) for i in range(SCHED_SIZE))
    return {"stop": "return", "body": body, "allocs": calls}, steps


def run_payer(m, balance, tx, ctx, fail_at=None):
    _setup(m)
    calls = _install_heap(m, fail_at)
    m.add_region(TX_AT, TX_SIZE, tx)
    m.add_region(CTX_AT, CTX_SIZE, ctx)
    m.add_region(BAL_AT, 32, balance.to_bytes(32, "little"))
    m.add_region(OUT_AT, 0x30, struct.pack("<6Q", *([SENTINEL] * 6)))
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT_AT, BAL_AT, TX_AT, CTX_AT
    sp = m.regs[4]
    try:
        steps = m.run(PAYER, limit=5000)
    except Boundary as exc:
        r = exc.regs
        got = {"stop": exc.kind, "allocs": calls}
        if exc.kind == "panic_mul_overflow":
            got["loc"] = r[7]
        elif exc.kind == "result_unwrap_failed":
            got["loc"] = r[8]
            got["err"] = (r[7], r[6], m.load(r[2], 8), r[1])
        elif exc.kind == "alloc_error":
            got["args"] = (r[7], r[6])
        return got, m.steps
    _check_abi(m, sp)
    out = [m.load(OUT_AT + 8 * i, 8) for i in range(6)]
    got = {"stop": "return", "out": out, "bal": int.from_bytes(bytes(m.load(BAL_AT + i, 1) for i in range(32)),
                                                               "little"), "allocs": calls}
    if out[0] == 6:
        got["boxes"] = [int.from_bytes(bytes(m.load(out[k] + i, 1) for i in range(32)), "little") for k in (1, 2)]
    return got, steps


def compare_payer(got, exp, balance, consts, fail_at=None):
    if fail_at is not None:
        return got["stop"] == "alloc_error" and got["args"] == (8, 32) and len(got["allocs"]) == fail_at
    if exp["stop"] == "panic":
        if exp["kind"] == "mul":
            return got["stop"] == "panic_mul_overflow" and got["loc"] == exp["loc"]
        return (got["stop"] == "result_unwrap_failed" and got["loc"] == exp["loc"]
                and got["err"] == (consts["unwrap_message"]["va"], consts["unwrap_message"]["length"], 7,
                                   consts["unwrap_error_vtable"]))
    if got["stop"] != "return" or got["out"][0] != exp["tag"]:
        return False
    if exp["tag"] == 0x21:
        value = sum(w << (64 * i) for i, w in enumerate(got["out"][1:5]))
        return (value == exp["value"] and got["bal"] == exp["newbal"] and got["out"][5] == SENTINEL
                and not got["allocs"])
    if exp["tag"] == 6:
        return (got["boxes"] == [exp["required"], exp["balance"]] and got["bal"] == balance
                and got["allocs"] == [32, 32] and got["out"][3:] == [SENTINEL] * 3)
    return got["bal"] == balance and not got["allocs"] and got["out"][3:] == [SENTINEL] * 3


def run_cost(m, body, data, create, accesses, keys, auths):
    _setup(m)
    stubs = _install_heap(m)
    del stubs
    m.add_region(SCHED_AT, 8, struct.pack("<Q", HEAP_AT))
    m.add_region(HEAP_AT, SCHED_SIZE, body)
    m.add_region(DATA_AT, max(len(data), 8), data)
    m.add_region(OUT_AT, 0x30, struct.pack("<6Q", *([SENTINEL] * 6)))
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8], m.regs[9] = (
        OUT_AT, SCHED_AT, DATA_AT, len(data), 0x100 | create, accesses)
    m.push(auths)
    m.push(keys)
    sp = m.regs[4]
    try:
        steps = m.run(COST, limit=100000)
    except Boundary as exc:
        kind = {"panic_add_overflow": "add", "panic_sub_overflow": "sub", "panic_mul_overflow": "mul"}[exc.kind]
        return {"stop": "panic", "panic": (exc.regs[7], kind)}, m.steps
    _check_abi(m, sp)
    return {"stop": "return", "words": [m.load(OUT_AT + 8 * i, 8) for i in range(4)]}, steps


# ---------------------------------------------------------------- cases
BLAKE_INPUT = (12).to_bytes(4, "big") + bytes(208) + b"\x01"
COMPOSE_INPUTS = (
    ("blake09-call", BLAKE_INPUT, 0, 0, 0, 0),
    ("blake09-create", BLAKE_INPUT, 1, 0, 0, 0),
    ("mixed-lists", bytes(range(64)), 0, 3, 5, 2),
    ("empty-create-auth", b"", 1, 0, 0, 1),
    ("nonzero-33-create", b"\xff" * 33, 1, 1, 1, 0),
    ("auth-overflow", b"\x00\x01", 0, 0, 0, M64 // 2),
    ("keys-saturate", b"\x07" * 5, 0, 1 << 58, 1 << 59, 0),
    ("access-overflow", b"", 0, M64 // 3, 0, 0),
)


def tx_bytes(G, P, V, K, flag=0, T=0, Amax=0, N=0):
    tx = bytearray(TX_SIZE)
    put(tx, 0, 1, flag)
    put(tx, 0x10, 16, T)
    put(tx, 0x50, 16, P)
    put(tx, 0x60, 32, V)
    put(tx, 0x80, 16, Amax)
    put(tx, 0xb8, 8, N)
    put(tx, 0xd8, 8, G)
    put(tx, 0x111, 1, K)
    return bytes(tx)


def ctx_bytes(flag=0, Aact=0, S=0):
    ctx = bytearray(CTX_SIZE)
    put(ctx, 0, 1, flag)
    put(ctx, 0x10, 16, Aact)
    put(ctx, 0x98, 8, S)
    return bytes(ctx)


PROFILES = (  # (label, G, P, V, T, S, Amax, N, Aact)
    ("typical", 21000, 10 ** 9, 10 ** 18, 5 * 10 ** 8, 10 ** 8, 10, 1, 5),
    ("tip-above-price", 21000, 10 ** 9, 0, 2 * 10 ** 9, 10 ** 8, 7, 3, 9),
    ("tip-equal-price", 50000, 7 * 10 ** 8, 1, 6 * 10 ** 8, 10 ** 8, 1, 1, 1),
    ("zero-gas", 0, 10 ** 12, 10 ** 20, 1, 1, 3, 2, 3),
    ("zero-price", 1 << 20, 0, 1 << 100, 0, 0, 1, 1, 2),
    ("gp-overflow", M64, 1 << 65, 0, 1, 1, 0, 0, 0),
    ("gp-max", M64, (1 << 64) + 1, 1, 1 << 64, 5, 0, 1, 0),
    ("value-overflow", 3, 1 << 126, M256 - (3 << 126) + 1, 0, 0, 0, 0, 0),
    ("value-edge", 3, 1 << 126, M256 - (3 << 126), 0, 0, 0, 0, 0),
    ("shift-limit", 2, 5, 9, 1, 1, 1 << 20, (1 << 47) - 1, 1 << 21),
    ("shift-panic", 2, 5, 9, 1, 1, 1, 1 << 47, 1),
    ("aux-saturate", 1, 1, 0, 1, 0, 1 << 127, 1 << 46, 1 << 127),
    ("aux-actual-high", 1000, 10, 0, 1, 0, 2, 4, 1 << 90),
    ("aux-overflow-256", 1, 1, M256 - M128 + 1, 0, 0, M128, 1 << 40, M128),
    ("charge-overflow", 1, 1, M256 - (1 << 100), 0, 0, 1, 1, M128),
    ("tip-saturate", 1 << 30, M128 >> 31, 0, M128, 1, 0, 0, 0),
)


def payer_cases():
    cases = []
    for label, G, P, V, T, S, Amax, N, Aact in PROFILES:
        for K in (0, 1, 2, 3, 4, 255):
            for tflag in (0, 1):
                for cflag in (0, 1):
                    tx, ctx = tx_bytes(G, P, V, K, tflag, T, Amax, N), ctx_bytes(cflag, Aact, S)
                    for b in _balances(tx, ctx):
                        cases.append((f"{label}", b, tx, ctx, None))
    s = Stream("re21-payer")
    scales = [0, 1, 8, 32, 63, 64, 65, 100, 127, 128, 160, 200, 255, 256]

    def mag(limit_bits):
        bits = min(limit_bits, s.pick(scales))
        return 0 if bits == 0 else (1 << (bits - 1)) | s.below(1 << (bits - 1)) if bits > 1 else 1

    grid = len(cases)
    while len(cases) < grid + 1300:
        K = s.pick([0, 1, 2, 3, 3, 3, 4])
        G = mag(64)
        P = mag(128)
        V = s.pick([0, mag(256), M256 - (G * P & M256) - s.below(3)]) & M256
        tx = tx_bytes(G, P, V, K, s.below(2), mag(128), mag(128), s.pick([0, 1, mag(47), mag(48)]))
        ctx = ctx_bytes(s.below(2), mag(128), mag(64))
        cases.append(("random", s.pick(_balances(tx, ctx) + [mag(256)]), tx, ctx, None))
    for label, G, P, V, T, S, Amax, N, Aact in PROFILES[:4]:  # tag-6 paths with each allocation failing
        tx = tx_bytes(G, P, V, 3, 1, T, Amax, N)
        for fail_at in (1, 2):
            cases.append((f"alloc-fail-{fail_at}", 0, tx, ctx_bytes(1, Aact, S), fail_at))
    return cases


def _balances(tx, ctx):
    """Balances around the model's own thresholds (required and charge), plus extremes."""
    probe = payer(M256, tx, ctx)
    out = [0, M256]
    req = None
    full = payer(0, tx, ctx)
    if full.get("tag") == 6:
        req = full["required"]
        out += [req - 1, req, req + 1]
    if probe.get("tag") == 0x21:
        charge = M256 - probe["value"]
        out += [charge - 1, charge, charge + 1]
        if req is not None:
            out.append(max(req, charge - 1))
    return sorted({b for b in out if 0 <= b <= M256})


# ---------------------------------------------------------------- static evidence
def static_evidence(image, fdes):
    listing = []
    for name, start in (("ctor", CTOR), ("payer", PAYER), ("cost", COST)):
        lo, hi = fdes[start]
        listing += [(name, va, f) for va, f in sweep(image, lo, hi)]
    literals = []
    for name, va, f in listing:
        rm = f.get("rm")
        if name == "ctor" and f["op"] in (0x0f10, 0x0f28) and rm and rm[0] == "m" and rm[1] == "rip":
            at = (va + f["len"] + rm[4]) & M64
            size = 4 if f.get("rep") else 16
            raw = image.read(at, size)
            literals.append({"insn": f"{va:#x}", "va": f"{at:#x}", "size": size,
                             "words": [f"{x:#x}" for x in (struct.unpack("<I", raw) if size == 4
                                                           else struct.unpack("<2Q", raw))]})
    cmp_imms = [{"insn": f"{va:#x}", "fn": name, "imm": f"{f['imm'] & 0xff:#x}"} for name, va, f in listing
                if f["op"] == 0x80 and f["reg"] & 7 == 7 and name in ("ctor", "payer")]
    slots = {n: ({"slot": f"{s:#x}", "import": image.import_name(s)} if s in image.imports else
                 {"slot": f"{s:#x}", "target": f"{image.relative[s]:#x}"}) for n, s in sorted(SLOTS.items())}
    msg_va, msg_len = 0x6017c4, 0x49
    for name, va, f in listing:  # the expect message and its length come from the lea/mov pair at 0x2973861
        if name == "payer" and va == 0x2973861:
            msg_va = (va + f["len"] + f["rm"][4]) & M64
        if name == "payer" and va == 0x297387e:
            msg_len = f["imm"]
    text = image.read(msg_va, msg_len)
    consts = {
        "constructor_literals": literals,
        "compare_immediates": cmp_imms,
        "relocated_slots": slots,
        "unwrap_message": {"va": msg_va, "length": msg_len, "text": text.decode("ascii", "replace")},
        "unwrap_error_vtable": 0x6443e58,
        "panic_locations": {k: f"{v:#x}" for k, v in sorted(PAYER_PANIC.items())},
        "schedule_alloc": {"size": SCHED_SIZE, "header": SCHED_HEADER, "memset": SCHED_SIZE - SCHED_HEADER},
    }
    return consts, listing


# ---------------------------------------------------------------- evaluation driver
def _hexw(words):
    return ",".join(f"{off:#x}={v:#x}" for off, v in sorted(words.items()) if v)


def evaluate(image, override=None, mut=frozenset(), consts=None, stop_on_first=False):
    m = TraceMachine(image, override)
    res = {"payer": [], "modes": [], "compose": [], "bad": 0, "payer_mismatches": 0, "mode_mismatches": 0,
           "compose_mismatches": 0, "payer_outcomes": {}, "compose_outcomes": {}}

    def done():
        res["seen"] = m.seen
        return res

    for i, (label, bal, tx, ctx, fail_at) in enumerate(payer_cases()):
        exp = payer(bal, tx, ctx, mut)
        try:
            got, steps = run_payer(m, bal, tx, ctx, fail_at)
            ok = compare_payer(got, exp, bal, consts, fail_at)
        except ToolError as exc:
            got, steps, ok = {"stop": f"error:{exc}"}, m.steps, False
        key = ("alloc_error" if fail_at else f"panic-{exp['kind']}" if exp["stop"] == "panic"
               else f"tag-{exp['tag']:#x}")
        res["payer_outcomes"][key] = res["payer_outcomes"].get(key, 0) + 1
        res["payer"].append(
            f"p{i}\t{label}\t{tx[0x111]}\t{tx[0] & 1}\t{ctx[0] & 1}\t{u(tx, 0xd8, 8):#x}\t{u(tx, 0x50, 16):#x}\t"
            f"{u(tx, 0x60, 32):#x}\t{u(tx, 0x10, 16):#x}\t{u(ctx, 0x98, 8):#x}\t{u(tx, 0x80, 16):#x}\t"
            f"{u(tx, 0xb8, 8):#x}\t{u(ctx, 0x10, 16):#x}\t{bal:#x}\t{fail_at or 0}\t{key}\t"
            f"{exp.get('value', exp.get('required', 0)):#x}\t{steps}\t{'match' if ok else 'MISMATCH'}")
        if not ok:
            res["payer_mismatches"] += 1
            res["bad"] += 1
            if stop_on_first:
                return done()
    bodies = {}
    for mode in range(256):
        exp = schedule_bytes(mode, mut)
        try:
            got, steps = run_ctor(m, mode)
            ok = (got["stop"] == "return" and got["body"] == exp
                  and got["allocs"] == [SCHED_SIZE, ("memset", HEAP_AT + 0x10000 + SCHED_HEADER, 0,
                                                     SCHED_SIZE - SCHED_HEADER)])
            bodies[mode] = got.get("body", bytes(SCHED_SIZE))
        except ToolError as exc:
            steps, ok = m.steps, False
            bodies[mode] = bytes(SCHED_SIZE)
        res["modes"].append(f"{mode}\t{hashlib.sha256(exp).hexdigest()[:16]}\t{steps}\t{'match' if ok else 'MISMATCH'}")
        if not ok:
            res["mode_mismatches"] += 1
            res["bad"] += 1
            if stop_on_first:
                return done()
    got, steps = run_ctor(m, 13, fail_alloc=True)
    ok = got["stop"] == "alloc_error" and got["args"] == (8, SCHED_SIZE) and got["allocs"] == [SCHED_SIZE]
    res["modes"].append(f"13-alloc-fails\t-\t{steps}\t{'match' if ok else 'MISMATCH'}")
    if not ok:
        res["mode_mismatches"] += 1
        res["bad"] += 1
        if stop_on_first:
            return done()
    for mode in range(256):
        model_mode = 13 if "cost-uses-mode13" in mut else mode
        sched = schedule_words(model_mode, mut)
        sched.update({off: 0 for off in range(0x188, SCHED_SIZE, 8)})
        for label, data, create, accesses, keys, auths in COMPOSE_INPUTS:
            try:
                exp = {"stop": "return", "words": cost(sched, data, create, accesses, keys, auths)}
            except Panic as exc:
                exp = {"stop": "panic", "panic": (exc.location, exc.kind)}
            got, steps = run_cost(m, bodies[mode], data, create, accesses, keys, auths)
            ok = got == exp
            key = "return" if exp["stop"] == "return" else f"panic-{exp['panic'][1]}@{exp['panic'][0]:#x}"
            res["compose_outcomes"][key] = res["compose_outcomes"].get(key, 0) + 1
            shown = ",".join(str(w) for w in exp["words"]) if exp["stop"] == "return" else key
            res["compose"].append(f"m{mode}-{label}\t{mode}\t{label}\t{shown}\t{steps}\t{'match' if ok else 'MISMATCH'}")
            if not ok:
                res["compose_mismatches"] += 1
                res["bad"] += 1
                if stop_on_first:
                    return done()
    return done()


MUTANTS = ("create-base-mode0", "mode6-as-7", "mode14-as-13", "word18-from-2", "drop-duplicate-138",
           "cost-uses-mode13", "required-ignores-value", "aux-for-k-ge-3", "aux-unsaturated", "tag6-on-equal",
           "effective-for-k1", "effective-no-min", "actual-ignores-flag", "clamp-missing")
CODE_MUTANTS = (  # (va, xor) one-byte patches: compare immediates and branch opcodes
    (0x5be2584, 0x01), (0x5be25ab, 0x01), (0x5be2688, 0x01), (0x5be2880, 0x01), (0x5be2889, 0x01),
    (0x5be2833, 0x01), (0x2973526, 0x01), (0x297354a, 0x01), (0x297364c, 0x01), (0x29735bb, 0x01),
    (0x29737d2, 0x01), (0x2973604, 0x08),
)


def mutant_rows(image, consts):
    rows = []
    for name in MUTANTS:
        r = evaluate(image, mut=frozenset([name]), consts=consts, stop_on_first=True)
        rows.append(f"{name}\tmodel\t{'killed' if r['bad'] else 'SURVIVED'}")
    for va, x in CODE_MUTANTS:
        old = image.code(va, 1)[0]
        r = evaluate(image, override={va: old ^ x}, consts=consts, stop_on_first=True)
        rows.append(f"code@{va:#x}:{old:02x}->{old ^ x:02x}\tcode-bytes\t{'killed' if r['bad'] else 'SURVIVED'}")
    return rows


def class_rows():
    """Distinct schedules over all 256 modes: the mode ranges and their nonzero header words."""
    groups = []
    for mode in range(256):
        w = schedule_words(mode)
        if groups and groups[-1][2] == w:
            groups[-1][1] = mode
        else:
            groups.append([mode, mode, w])
    return [f"{lo}\t{hi}\t{_hexw(w)}" for lo, hi, w in groups]


def generate(out):
    data = BINARY.read_bytes()
    image = Image(data)
    fdes = fde_rows(image, {CTOR, PAYER, COST})
    consts, listing = static_evidence(image, fdes)
    result = evaluate(image, consts=consts)
    mutants = mutant_rows(image, consts)
    seen = result["seen"]
    names = ("ctor", "payer", "cost")
    totals = {n: sum(1 for x, _, _ in listing if x == n) for n in names}
    covered = {n: sum(1 for x, va, _ in listing if x == n and va in seen) for n in names}
    classes = class_rows()
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "binary": "artifacts/node/115/hl-node",
        "binary_sha256": SHA256,
        "functions": {name: {"fde_start": f"{fdes[v][0]:#x}", "fde_end": f"{fdes[v][1]:#x}"}
                      for name, v in (("ctor", CTOR), ("payer", PAYER), ("cost", COST))},
        "decoded_instructions": totals,
        "executed_instructions": covered,
        "schedule_modes": 256,
        "schedule_classes": len(classes),
        "schedule_mismatches": result["mode_mismatches"],
        "compose_cases": len(result["compose"]),
        "compose_mismatches": result["compose_mismatches"],
        "compose_outcomes": result["compose_outcomes"],
        "payer_cases": len(result["payer"]),
        "payer_mismatches": result["payer_mismatches"],
        "payer_outcomes": result["payer_outcomes"],
        "negative_controls": len(mutants),
        "negative_controls_killed": sum(1 for r in mutants if r.endswith("\tkilled")),
    }
    unexec = [f"{n}\t{va:#x}\t{f['bytes'].hex()}" for n, va, f in listing if va not in seen and n != "cost"]
    files = {
        "summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
        "constants.json": json.dumps(consts, indent=2, sort_keys=True) + "\n",
        "decoded-instructions.tsv": "function\tva\tlength\tbytes\topcode_key\texecuted\n" + "\n".join(
            f"{n}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{'yes' if va in seen else 'no'}"
            for n, va, f in listing if n != "cost") + "\n",
        "schedule-modes.tsv": "mode\tmodel_sha256_prefix\tsteps\tresult\n" + "\n".join(result["modes"]) + "\n",
        "schedule-classes.tsv": "mode_low\tmode_high\tnonzero_header_words\n" + "\n".join(classes) + "\n",
        "compose-cases.tsv": "id\tmode\tinput\texpected\tsteps\tresult\n" + "\n".join(result["compose"]) + "\n",
        "payer-cases.tsv": "id\tgroup\tK\ttx_flag\tctx_flag\tG\tP\tV\tT\tS\tAmax\tN\tAactual\tbalance\t"
                           "alloc_fail_at\texpected\texpected_value\tsteps\tresult\n" + "\n".join(result["payer"]) + "\n",
        "negative-controls.tsv": "control\tkind\tverdict\n" + "\n".join(mutants) + "\n",
        "unexecuted-instructions.tsv": "function\tva\tbytes\n" + "\n".join(unexec) + ("\n" if unexec else ""),
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="ascii", newline="\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    bad = summary["schedule_mismatches"] + summary["compose_mismatches"] + summary["payer_mismatches"]
    bad += summary["negative_controls"] - summary["negative_controls_killed"]
    print(json.dumps(summary, sort_keys=True))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
