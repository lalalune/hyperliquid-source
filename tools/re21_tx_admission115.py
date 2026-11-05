#!/usr/bin/env python3
"""Reconstruct and validate node #115 transaction admission before an address-09 call.

Two functions are reconstructed: the environment validation 0x2b92c10 (revision,
chain, gas cap, per-type fee and blob checks, block gas limit, initcode size and
the final sentinel) and the input cost admission 0x2b93030 (access-list sum,
the cost-callee argument contract, initial/floor gas against the gas limit and
the optional cap).  The tool reads every constant, relocation, jump table entry
and FDE extent from ELF bytes, evaluates the real machine code with a small
concrete x86-64 evaluator (no external programs, the binary is never executed),
and compares every case with an independent pure-Python reconstruction.
Negative controls show that wrong reconstructions and corrupted code bytes are
detected.
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

VALIDATE = 0x2b92c10
ADMIT = 0x2b93030
COST = 0x5be0720
JUMP_TABLE = 0x60735c
SLOTS = {  # GOT slots called on the admission path; targets come from R_X86_64_RELATIVE addends
    "cost_callee": 0x64e6198,
    "panic_add_overflow": 0x64df520,
    "panic_sub_overflow": 0x64df848,
    "panic_mul_overflow": 0x64df870,
}
SCHED_BODY = 0x7d00_2000_1000
DATA_AT = 0x7d00_3000_0000
MODE13_SCHEDULE = {  # cited from the merged RE-021-precompile-preflight-115/schedule.json (mode 13)
    0x100: 10, 0x108: 21000, 0x110: 2400, 0x118: 1900, 0x120: 21000, 0x128: 32000, 0x130: 2, 0x158: 0,
    0x168: 0, 0x170: 0, 0x178: 1, 0x180: 0, 0xe8: 25000, 0xf0: 4, 0xf8: 4}
SCHED_FIELDS = tuple(sorted(MODE13_SCHEDULE))
PANIC_ARGS = {"sum_overflow": 0x6437408, "refund_underflow": 0x644cab0, "initial_overflow": 0x644cac8}

STACK_TOP = 0x7ff0_0000_0000
RETURN_MARK = 0x7e00_dead_0000
CTX_AT = 0x7d00_0000_0000
LIST_AT = 0x7d00_0100_0000
OUT_AT = 0x7d00_1000_0000
SCHED_AT = 0x7d00_2000_0000
SENTINEL = 0xa5a5a5a5a5a5a5a5
CTX_SIZE = 0x300

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
        self.relative = {}
        for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
            where, info, addend = struct.unpack_from("<QQq", data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend & M64
        self.text = next(s for s in self.secs if s["name"] == ".text")

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
    p, opsize, rex = 0, 32, 0
    while code[p] in (0x66, 0x2e):  # operand-size and (ignored) segment prefixes, as in multi-byte nops
        if code[p] == 0x66:
            opsize = 16
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
    form = {"op": op, "rex": rex, "size": opsize}

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
    elif op in (0xc3, 0x90):
        pass
    elif op in (0x01, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x29, 0x2b, 0x31, 0x33,
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


# ---------------------------------------------------------------- reconstruction
class Mem:
    """Context bytes plus the 32-byte blob record list, read the way the model needs them."""

    def __init__(self, ctx, records=b""):
        self.ctx, self.records = bytes(ctx), bytes(records)

    def u8(self, off):
        return self.ctx[off]

    def u32(self, off):
        return int.from_bytes(self.ctx[off:off + 4], "little")

    def u64(self, off):
        return int.from_bytes(self.ctx[off:off + 8], "little")

    def u128(self, off):
        return int.from_bytes(self.ctx[off:off + 16], "little")

    def record_byte(self, ptr, at):
        if ptr != LIST_AT or not 0 <= at < len(self.records):
            raise ToolError("record outside the materialized list")
        return self.records[at]

    def record_word(self, ptr, at):
        if ptr != LIST_AT or not 0 <= at <= len(self.records) - 8:
            raise ToolError("record outside the materialized list")
        return int.from_bytes(self.records[at:at + 8], "little")


def _err(tag, fields=None):
    return {"tag": tag, "kind": "six", "fields": dict(fields or {})}


def validate(c, mut=frozenset()):
    """Environment validation 0x2b92c10: result tag and the payload words it defines."""
    rev = c.u8(0x268)
    r9 = False
    if rev > (7 if "rev9-gate-at-8" in mut else 8):
        if not c.u8(0xbc) & 1:
            return {"tag": 0x21, "kind": "tag+byte", "byte": 0}
        if rev > 10:
            if c.u64(0) | c.u64(8) == 0:
                return {"tag": 0x21, "kind": "tag+byte", "byte": 1}
            r9 = True
    ty, f264, base = c.u8(0x1f1), c.u8(0x264), c.u64(0x98)
    if c.u8(0x260):
        if c.u32(0x100) == 1:
            if c.u64(0x108) != c.u64(0x258):
                return _err(0x0c)
        elif ty < 5 and (ty & 0x1f or "chain-kind-includes-type0" in mut):
            return _err(0x0d)
    if c.u8(0x265) == 0:
        if c.u8(0x240):
            limit = c.u64(0x248)
        else:
            limit = 0x1000000 if rev >= (12 if "cap-from-rev12" in mut else 13) else M64
        gas = c.u64(0x1b8)
        if gas > limit or ("cap-equality-rejects" in mut and gas == limit):
            return _err(0x0e, {1: gas, 2: limit})
    x, y = c.u128(0x130), c.u128(0xf0)
    flag = 0 if "ignore-0x264" in mut else f264
    below_base = (1 if x >= base else 0) | flag
    if "fee-cap-le" in mut:
        lt = 1 if x <= y else 0
    else:
        lt = 1 if x < y else 0
    tip_bad = lt & c.u8(0xe0)
    fee_tag = 0 if tip_bad else (below_base * 32 + 1) & M64
    fee_ok = bool((tip_bad ^ 1) & below_base & 1)
    if ty <= 4:
        if ty in (0, 1):
            if ty == 1 and rev <= (7 if "type1-rev7" in mut else 6):
                return _err(0x1a)
            if below_base == 0:
                return _err(1)
        elif ty == 2:
            if rev <= 7:
                return _err(0x1b)
            if not fee_ok:
                return _err(fee_tag)
        elif ty == 4:
            if rev <= 11:
                return _err(0x1d)
            if not fee_ok:
                return _err(fee_tag)
            if c.u64(0x1b0) == 0:
                return _err(0x19)
        else:
            if not r9:
                return _err(0x1c)
            if not fee_ok:
                return _err(fee_tag)
            if c.u8(0) & 1 and c.u128(0x160) < c.u128(0x10):
                return _err(0x12, {2: c.u64(0x10), 3: c.u64(0x18), 4: c.u64(0x160), 5: c.u64(0x168)})
            count, ptr = c.u64(0x198), c.u64(0x190)
            if count == 0:
                return _err(0x13)
            for i in range(1 if "blob-scan-first-only" in mut else count):
                if c.record_byte(ptr, 32 * i) != 1:
                    return _err(0x16)
            over = count >= c.u64(0x228) if "blob-max-ge" in mut else count > c.u64(0x228)
            if over and c.u8(0x220) & 1:
                return _err(0x15, {1: c.u64(0x228), 2: count})
    if c.u8(0x262) == 0 and c.u64(0x1b8) > c.u64(0x90):
        return _err(2)
    if rev >= 10 and c.u8(0x1dc) == 0:
        size = c.u64(0x120)
        if c.u8(0x210):
            limit = c.u64(0x218)
        elif c.u64(0x200) == 1:
            v = c.u64(0x208)
            limit = None if v >> 63 else (v if "custom-not-doubled" in mut else 2 * v)
        else:
            limit = 0xc000 + (0x4000 if rev >= 14 and "initcode-no-rev14" not in mut else 0)
        if limit is not None and size > limit:
            return _err(0x0b, {4: limit})
    if c.u64(0x1c0) == M64 and "no-sentinel" not in mut:
        return _err(8)
    return {"tag": 0x25, "kind": "tag"}


def admit(c, rev, floor_off, cap_on, cap, cost_words, mut=frozenset()):
    """Input cost admission 0x2b93030: callee argument contract and result words."""
    count, total = 0, 0
    if c.u8(0x111) and c.u64(0xa0):
        count, ptr = c.u64(0xa0), c.u64(0x98)
        for i in range(count):
            total += c.record_word(ptr, 0x10 + (0x28 if "record-stride-0x28" in mut else 0x30) * i)
            if total > M64:
                return {"stop": "panic", "panic": "sum_overflow", "args": None}
    args = (SCHED_AT, c.u64(0x38), c.u64(0x40), 1 if (c.u8(0xfc) == 0) ^ ("create-inverted" in mut) else 0,
            count, total, c.u64(0xd0))
    w = list(cost_words)
    if floor_off:
        w[3] = 0
    if cap_on or "keep-refund" in mut:
        need = w[1]
    else:
        w[1], need = 0, 0
    if need < w[2]:
        return {"stop": "panic", "panic": "refund_underflow", "args": args}
    need = need - w[2] + w[0]
    if need > M64:
        return {"stop": "panic", "panic": "initial_overflow", "args": args}
    limit = c.u64(0xd8)
    if need > limit:
        return {"stop": "return", "args": args, "words": [3, need, limit]}
    if rev > (10 if "floor-from-rev11" in mut else 11) and w[3] > limit:
        return {"stop": "return", "args": args, "words": [4, w[3], limit]}
    top = w[3] if "cap-uses-floor-only" in mut else max(w[0], w[3])
    if limit > cap and cap_on and top > cap:
        return {"stop": "return", "args": args, "words": [4, top, cap]}
    return {"stop": "return", "args": args, "words": [0x21] + w}


class Panic(Exception):
    def __init__(self, location, kind):
        super().__init__(f"{kind}@{location:#x}")
        self.location, self.kind = location, kind


def _chk(value, location, kind):
    if value > M64:
        raise Panic(location, kind)
    return value


def cost(sched, data, create, accesses, keys, auths, mut=frozenset()):
    """Cost calculation 0x5be0720: [initial, refund-like word, 0, floor] or a located panic."""
    s = sched
    nz = s[0xf0]
    zeros = data.count(0)
    tokens = _chk(_chk((len(data) - zeros) * nz, 0x64bf370, "mul") + zeros, 0x64bf388, "add")
    extra = min(M64, s[0x158] + s[0x170])
    per_auth = min(M64, s[0xe8] + extra)
    gross = _chk(auths * per_auth, 0x64bf268, "mul")
    refund = _chk(auths * extra, 0x64bf280, "mul")
    if gross < refund:
        raise Panic(0x64bf298, "sub")
    auth_net = gross - refund
    weighted = _chk(tokens * s[0xf8], 0x64bf2b0, "mul")
    acc = _chk(_chk(accesses * s[0x110], 0x64bf2c8, "mul") + weighted, 0x64bf2b0, "add")
    initial = _chk(_chk(keys * s[0x118], 0x64bf2e0, "mul") + acc, 0x64bf2b0, "add")
    initial = _chk(initial + s[0x120], 0x64bf2b0, "add")
    initial = _chk(initial + (0 if "drop-auth-term" in mut else auth_net), 0x64bf2b0, "add")
    if create:
        initial = _chk(initial + s[0x128], 0x64bf2f8, "add")
        words = ((len(data) + 31) & M64) >> 5
        if "create-words-floor" in mut:
            words = len(data) >> 5
        word_cost = words * s[0x130]
        initial = _chk(min(M64, word_cost) + initial, 0x64bf310, "add")
        refund = _chk(refund + s[0x168], 0x64bf328, "add")
    a = min(M64, accesses * 20)
    k = keys << 5 if keys >> 59 == 0 else M64
    floor_list = min(M64, min(M64, a + k) * s[0x180])
    if s[0x178] == nz and "floor-always-tokens" not in mut:
        floor_tokens = _chk(len(data) * nz, 0x64bf238, "mul")
    else:
        floor_tokens = tokens
    floor = _chk(_chk(s[0x100] * floor_tokens, 0x64bf250, "mul") + s[0x108], 0x64bf250, "add")
    floor = _chk(floor + _chk(floor_list * s[0x100], 0x64bf340, "mul"), 0x64bf358, "add")
    return [initial, refund, 0, floor]


def path(c, data, sched, rev, floor_off, cap_on, cap, mut=frozenset()):
    """Admission 0x2b93030 composed with the real cost calculation."""
    count, total = 0, 0
    if c.u8(0x111) and c.u64(0xa0):
        count, ptr = c.u64(0xa0), c.u64(0x98)
        for i in range(count):
            total += c.record_word(ptr, 0x10 + 0x30 * i)
            if total > M64:
                return {"stop": "panic", "panic": (0x6437408, "add")}
    try:
        words = cost(sched, data, c.u8(0xfc) == 0, count, total, c.u64(0xd0), mut)
    except Panic as exc:
        return {"stop": "panic", "panic": (exc.location, exc.kind)}
    res = admit(c, rev, floor_off, cap_on, cap, words, mut)
    if res["stop"] == "panic":
        return {"stop": "panic", "panic": (PANIC_ARGS[res["panic"]], "sub" if res["panic"] == "refund_underflow"
                                            else "add")}
    return {"stop": "return", "words": res["words"]}


# ---------------------------------------------------------------- evaluation of the real code
CALLEE_SAVED = {3: 0x3333_0000_0000_0003, 5: 0x5555_0000_0000_0005, 12: 0xcccc_0000_0000_000c,
                13: 0xdddd_0000_0000_000d, 14: 0xeeee_0000_0000_000e, 15: 0xffff_0000_0000_000f}


def _machine_setup(m, ctx, records):
    m.reset()
    m.add_region(CTX_AT, CTX_SIZE, ctx)
    m.add_region(LIST_AT, max(len(records), 8), records)
    m.add_region(OUT_AT, 0x30, struct.pack("<6Q", *([SENTINEL] * 6)))
    for r, v in CALLEE_SAVED.items():
        m.regs[r] = v


def _check_abi(m, sp):
    for r, v in CALLEE_SAVED.items():
        if m.regs[r] != v:
            fail(f"callee-saved register {r} not restored")
    if m.regs[4] != sp:
        fail("stack pointer not restored")


def run_validate(m, ctx, records):
    _machine_setup(m, ctx, records)
    m.regs[7], m.regs[6] = OUT_AT, CTX_AT
    sp = m.regs[4]
    steps = m.run(VALIDATE, limit=20000)
    _check_abi(m, sp)
    if m.regs[0] != OUT_AT:
        fail("validation did not return its output pointer")
    return [m.load(OUT_AT + 8 * i, 8) for i in range(6)], steps


def run_admit(m, ctx, records, rev, floor_off, cap_on, cap, cost_words):
    _machine_setup(m, ctx, records)
    calls = []

    def cost(mc):
        calls.append((mc.regs[6], mc.regs[2], mc.regs[1], mc.regs[8], mc.regs[9],
                      mc.load(mc.regs[4], 8), mc.load(mc.regs[4] + 8, 8)))
        for i, w in enumerate(cost_words):
            mc.store(mc.regs[7] + 8 * i, 8, w)
        mc.regs[0] = mc.regs[7]

    targets = {name: m.image.relative[slot] for name, slot in SLOTS.items()}
    m.stubs[targets["cost_callee"]] = cost
    m.stubs[targets["panic_add_overflow"]] = "panic_add_overflow"
    m.stubs[targets["panic_sub_overflow"]] = "panic_sub_overflow"
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT_AT, CTX_AT, rev, SCHED_AT
    m.regs[8], m.regs[9] = floor_off, cap_on
    m.push(cap)
    sp = m.regs[4]
    try:
        steps = m.run(ADMIT, limit=20000)
    except Boundary as exc:
        which = {v: k for k, v in PANIC_ARGS.items()}.get(exc.regs[7], f"unknown:{exc.regs[7]:#x}")
        return {"stop": "panic", "panic": which, "via": exc.kind, "args": calls[0] if calls else None}, m.steps
    _check_abi(m, sp)
    if len(calls) != 1:
        fail("cost callee not called exactly once")
    return {"stop": "return", "args": calls[0], "out": [m.load(OUT_AT + 8 * i, 8) for i in range(5)]}, steps


def compare_validate(out, exp):
    if out[0] != exp["tag"]:
        return False
    if exp["kind"] == "tag":
        return out[1:] == [SENTINEL] * 5
    if exp["kind"] == "tag+byte":
        return out[1] == (SENTINEL & ~0xff) | exp["byte"] and out[2:] == [SENTINEL] * 4
    return all(out[i] == v for i, v in exp["fields"].items())


def compare_admit(got, exp):
    if got["stop"] != exp["stop"]:
        return False
    if exp["stop"] == "panic":
        return got["panic"] == exp["panic"] and (exp["args"] is None or got["args"] == exp["args"])
    if got["args"] != exp["args"]:
        return False
    words = exp["words"]
    if words[0] in (3, 4):
        return got["out"][:3] == words and got["out"][3:] == [SENTINEL, SENTINEL]
    return got["out"] == words


def run_path(m, ctx, records, data, sched, rev, floor_off, cap_on, cap):
    _machine_setup(m, ctx, records)
    m.add_region(DATA_AT, max(len(data), 8), data)
    body = bytearray(0x190)
    for off, v in sched.items():
        put(body, off, 8, v)
    m.add_region(SCHED_AT, 8, struct.pack("<Q", SCHED_BODY))
    m.add_region(SCHED_BODY, 0x190, body)
    kinds = {"panic_add_overflow": "add", "panic_sub_overflow": "sub", "panic_mul_overflow": "mul"}
    for name, kind in kinds.items():
        m.stubs[m.image.relative[SLOTS[name]]] = kind
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT_AT, CTX_AT, rev, SCHED_AT
    m.regs[8], m.regs[9] = floor_off, cap_on
    m.push(cap)
    sp = m.regs[4]
    try:
        steps = m.run(ADMIT, limit=400000)
    except Boundary as exc:
        return {"stop": "panic", "panic": (exc.regs[7], exc.kind)}, m.steps
    _check_abi(m, sp)
    return {"stop": "return", "out": [m.load(OUT_AT + 8 * i, 8) for i in range(5)]}, steps


def compare_path(got, exp):
    if got["stop"] != exp["stop"]:
        return False
    if exp["stop"] == "panic":
        return got["panic"] == exp["panic"]
    words = exp["words"]
    if words[0] in (3, 4):
        return got["out"][:3] == words and got["out"][3:] == [SENTINEL, SENTINEL]
    return got["out"] == words


def path_cases():
    s = Stream("re21-path")
    cases = []
    big = [0, 1, 2, 4, 10, 1 << 32, 1 << 59, 1 << 62, M64 // 20, M64 - 1, M64]

    def tx_for(data_len, create, accesses, keys_each, auths, limit):
        tx = bytearray(CTX_SIZE)
        put(tx, 0x111, 1, 1 if accesses else 0)
        put(tx, 0xa0, 8, accesses)
        put(tx, 0x98, 8, LIST_AT)
        put(tx, 0x38, 8, DATA_AT)
        put(tx, 0x40, 8, data_len)
        put(tx, 0xfc, 1, 0 if create else 1)
        put(tx, 0xd0, 8, auths)
        put(tx, 0xd8, 8, limit)
        recs = bytearray()
        for i in range(accesses):
            rec = bytearray(0x30)
            put(rec, 0x10, 8, keys_each[i])
            recs += rec
        return bytes(tx), bytes(recs) or bytes(8)

    # The synthetic 213-byte address-09 input from the preflight packet plus nearby limits.
    blake = (12).to_bytes(4, "big") + bytes(208) + b"\x01"
    for limit in (21875, 21876, 23189, 23190, 30000):
        for rev in (11, 12, 13):
            tx, recs = tx_for(len(blake), False, 0, [], 0, limit)
            cases.append(("blake213", tx, recs, blake, dict(MODE13_SCHEDULE), rev, 0, 0, M64))
    # Targeted panic sites: floor token multiply with all-zero data, floor sum overflow.
    for length in (0, 1, 2, 64):
        for nz in (2, 1 << 63, M64):
            sched = dict(MODE13_SCHEDULE)
            sched[0xf0] = sched[0x178] = nz
            tx, recs = tx_for(length, False, 0, [], 0, M64)
            cases.append(("floor-tokens", tx, recs, bytes(length), sched, 12, 0, 0, M64))
    for data in (b"\x01\x00", b"\x00\x01\x00", b"\x01"):  # token multiply fits, adding zero bytes overflows
        sched = dict(MODE13_SCHEDULE)
        sched[0xf0] = M64
        tx, recs = tx_for(len(data), False, 0, [], 0, M64)
        cases.append(("token-add", tx, recs, data, sched, 12, 0, 0, M64))
    for keys in ((1 << 59) - 1, 1 << 59, (1 << 60) - 1, 1 << 60):  # saturation guard keys >> 59
        for s180 in (0, 1, 2):
            sched = dict(MODE13_SCHEDULE)
            sched[0x118], sched[0x100], sched[0x108], sched[0x180] = 0, 1, 0, s180
            tx, recs = tx_for(0, False, 1, [keys], 0, M64)
            cases.append(("key-guard", tx, recs, b"", sched, 12, 0, 0, M64))
    for s108 in (M64 - 100, M64 - 21000, M64):
        for keys in ([0], [1], [3]):
            sched = dict(MODE13_SCHEDULE)
            sched[0x100], sched[0x108], sched[0x180] = 1, s108, 1
            tx, recs = tx_for(0, False, 1, keys, 0, M64)
            cases.append(("floor-sum", tx, recs, b"", sched, 12, 0, 0, M64))
    for _ in range(1500):
        n = s.pick([0, 0, 1, 2])
        length = s.pick([0, 1, 31, 32, 33, 64, 213, 300])
        data = bytes(b if s.below(3) else 0 for b in s.take(length))
        sched = dict(MODE13_SCHEDULE)
        if s.below(2):
            for off in SCHED_FIELDS:
                if s.below(3) == 0:
                    sched[off] = s.pick(big)
        if s.below(4) == 0:
            sched[0x178] = sched[0xf0]
        keys = [s.pick([0, 1, 3, 1 << 59, M64 // 2]) for _ in range(n)]
        auths = s.pick([0, 0, 1, 2, 1 << 62, M64])
        tx, recs = tx_for(length, s.below(2), n, keys, auths, s.pick([0, 21000, 53000, 1 << 40, M64]))
        cases.append(("random", tx, recs, data, sched, s.below(16), s.below(2), s.below(2),
                      s.pick([0, 21000, 60000, M64])))
    return cases


# ---------------------------------------------------------------- deterministic cases
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


def _base_ctx(rev, ty):
    ctx = bytearray(CTX_SIZE)
    for off, size, v in ((0, 8, 1), (0xbc, 1, 1), (0x10, 16, 5), (0x90, 8, 30_000_000), (0x98, 8, 1000),
                         (0xf0, 16, 1000), (0x130, 16, 1000), (0x160, 16, 10), (0x190, 8, LIST_AT),
                         (0x198, 8, 1), (0x1b0, 8, 1), (0x1b8, 8, 21000), (0x220, 1, 1), (0x228, 8, 6),
                         (0x268, 1, rev), (0x1f1, 1, ty)):
        put(ctx, off, size, v)
    return ctx


def validate_fields(boundaries):
    """Perturbation pools; thresholds come from the instruction immediates read from bytes."""
    b = boundaries
    big = [0, 1, 2, b["gas_cap"] - 1, b["gas_cap"], b["gas_cap"] + 1, 1 << 63, M64]
    return [
        (0x268, 1, list(range(0, 17)) + [0xff]),
        (0x1f1, 1, [0, 1, 2, 3, 4, 5, 6, 0x20, 0x21, 0x23, 0xff]),
        (0xbc, 1, [0, 1, 2, 3]),
        (0x0, 8, [0, 1, 2, 0x100]),
        (0x8, 8, [0, 1]),
        (0x260, 1, [0, 1, 2]),
        (0x100, 8, [0, 1, 2, (1 << 32) | 1]),
        (0x108, 8, [0, 999, 1000]),
        (0x258, 8, [999, 1000]),
        (0x265, 1, [0, 1]),
        (0x240, 1, [0, 1]),
        (0x248, 8, [0, 20999, 21000, 21001, M64]),
        (0x1b8, 8, big + [21000, 30_000_000, 30_000_001]),
        (0x90, 8, [0, 20999, 21000, 30_000_000]),
        (0x262, 1, [0, 1]),
        (0x98, 8, [0, 999, 1000, 1001, M64]),
        (0x130, 16, [0, 999, 1000, 1001, 1 << 64, (1 << 64) | 5, (1 << 128) - 1]),
        (0xf0, 16, [0, 999, 1000, 1001, 1 << 64, (1 << 128) - 1]),
        (0xe0, 1, [0, 1, 2, 3]),
        (0x264, 1, [0, 1, 2, 3]),
        (0x1b0, 8, [0, 1]),
        (0x10, 16, [0, 9, 10, 11, 1 << 64, (1 << 64) | 10]),
        (0x160, 16, [0, 9, 10, 11, 1 << 64, (1 << 64) | 9]),
        (0x198, 8, [0, 1, 2, 5, 6, 7]),
        (0x228, 8, [0, 1, 5, 6, 7]),
        (0x220, 1, [0, 1, 2]),
        (0x1dc, 1, [0, 1]),
        (0x120, 8, [0, b["initcode"] - 1, b["initcode"], b["initcode"] + 1, b["initcode_rev14"] - 1,
                    b["initcode_rev14"], b["initcode_rev14"] + 1, 999, 1000, 1001, 2000, 2001, M64]),
        (0x210, 1, [0, 1]),
        (0x218, 8, [0, 1000, M64]),
        (0x200, 8, [0, 1, 2]),
        (0x208, 8, [0, 500, 1000, (1 << 63) - 1, 1 << 63, M64]),
        (0x1c0, 8, [0, M64 - 1, M64]),
    ]


def validate_cases(boundaries):
    s = Stream("re21-validate")
    fields = validate_fields(boundaries)
    cases = []
    for rev in list(range(0, 17)):
        for ty in (0, 1, 2, 3, 4, 5, 0x20):
            cases.append(("sweep", _base_ctx(rev, ty), [1]))
    for off, size, pool in fields:
        for v in pool:
            for rev, ty in ((9, 2), (12, 3), (14, 4), (15, 0)):
                ctx = _base_ctx(rev, ty)
                put(ctx, off, size, v)
                cases.append(("single", ctx, [1] * min(int.from_bytes(ctx[0x198:0x1a0], "little"), 7)))
    for kind in (0, 1, 2, (1 << 32) | 1):
        for flag in (0, 1, 2):
            for a, b in ((0, 0), (1000, 1000), (999, 1000), (1000, 999)):
                for ty in (0, 2, 3, 5, 0x20):
                    ctx = _base_ctx(12, ty)
                    for off, size, v in ((0x260, 1, flag), (0x100, 8, kind), (0x108, 8, a), (0x258, 8, b)):
                        put(ctx, off, size, v)
                    cases.append(("grid-chain", ctx, [1]))
    for x in (999, 1000, 1001, (1 << 64) | 999):
        for y in (999, 1000, 1001, 1 << 64):
            for e0 in (0, 1, 2, 3):
                for f264 in (0, 1, 2, 3):
                    for ty, rev in ((0, 9), (1, 9), (2, 9), (3, 12), (4, 12)):
                        ctx = _base_ctx(rev, ty)
                        for off, size, v in ((0x130, 16, x), (0xf0, 16, y), (0xe0, 1, e0), (0x264, 1, f264)):
                            put(ctx, off, size, v)
                        cases.append(("grid-fee", ctx, [1]))
    for count in (0, 1, 2, 6, 7):
        for limit in (0, 1, 6, 7):
            for flag in (0, 1, 2, 3):
                for bad_at in (None, 0, count - 1):
                    for blob in (0, 1):
                        ctx = _base_ctx(12, 3)
                        for off, size, v in ((0x198, 8, count), (0x228, 8, limit), (0x220, 1, flag),
                                             (0x0, 8, 0x100 | blob), (0x160, 16, 9)):
                            put(ctx, off, size, v)
                        recs = [1] * count
                        if bad_at is not None and 0 <= bad_at < count:
                            recs[bad_at] = 0
                        cases.append(("grid-blob", ctx, recs))
    for rev in (9, 10, 13, 14, 15):
        for custom in (0, 1):
            for mode in (0, 1, 2):
                for v in (500, 1 << 63, M64):
                    for size_ in (999, 1000, 1001, 0xc000, 0xc001, 0x10000, 0x10001):
                        ctx = _base_ctx(rev, 5)
                        for off, sz, val in ((0x210, 1, custom), (0x218, 8, 1000), (0x200, 8, mode),
                                             (0x208, 8, v), (0x120, 8, size_)):
                            put(ctx, off, sz, val)
                        cases.append(("grid-initcode", ctx, [1]))
    for _ in range(1300):
        ctx = _base_ctx(s.pick(list(range(0, 17))), s.pick([0, 1, 2, 3, 3, 3, 4, 5]))
        for _ in range(1 + s.below(5)):
            off, size, pool = s.pick(fields)
            put(ctx, off, size, s.pick(pool))
        count = min(int.from_bytes(ctx[0x198:0x1a0], "little"), 7)
        recs = [s.pick([1, 1, 1, 0, 2, 0x81]) for _ in range(count)]
        cases.append(("random", ctx, recs))
    return cases


def _records(firsts):
    out = bytearray()
    for i, first in enumerate(firsts):
        out += bytes([first]) + hashlib.sha256(b"blob-record" + bytes([i])).digest()[:31]
    return bytes(out) if out else bytes(32)


def admit_cases():
    s = Stream("re21-admit")
    cases = []
    vals = [0, 1, 20999, 21000, 21001, 50000, 1 << 63, M64 - 1, M64]
    for rev in range(16):
        for floor_off in (0, 1):
            for cap_on in (0, 1):
                for initial, floor, limit, cap in ((21000, 21000, 21000, 21000), (21000, 21001, 21000, M64),
                                                   (21001, 21000, 21000, M64), (20000, 22000, 30000, 21000),
                                                   (22000, 20000, 30000, 21000), (20000, 20000, 30000, 21000),
                                                   (20000, 21000, 21000, 20999), (21000, 20000, 30000, 30000)):
                    for gain, refund in ((0, 0), (500, 500), (700, 200), (200, 700)):
                        tx = bytearray(CTX_SIZE)
                        put(tx, 0xd8, 8, limit)
                        put(tx, 0x98, 8, LIST_AT)
                        cases.append(("grid", bytes(tx), bytes(8), rev, floor_off, cap_on, cap,
                                      [initial, gain, refund, floor]))
    for _ in range(1200):
        tx = bytearray(CTX_SIZE)
        put(tx, 0x111, 1, s.pick([0, 1, 2]))
        n = s.pick([0, 0, 1, 2, 3])
        put(tx, 0xa0, 8, n)
        put(tx, 0x98, 8, LIST_AT)
        put(tx, 0x38, 8, s.pick([0, 0x7d00_3000_0000]))
        put(tx, 0x40, 8, s.pick([0, 213, 214]))
        put(tx, 0xfc, 1, s.pick([0, 1, 2]))
        put(tx, 0xd0, 8, s.pick([0, 3, 7]))
        put(tx, 0xd8, 8, s.pick(vals))
        recs = bytearray()
        for _ in range(n):
            rec = bytearray(s.take(0x30))
            put(rec, 0x10, 8, s.pick([0, 1, 2, 5, 1 << 63, M64]))
            recs += rec
        w0 = s.pick(vals)
        w1 = s.pick([0, 1, 100, 21000, M64])
        w2 = s.pick([0, 1, 100, 21000, M64])
        w3 = s.pick(vals)
        cases.append(("random", bytes(tx), bytes(recs) or bytes(8), s.below(16), s.below(2), s.below(2),
                      s.pick(vals), [w0, w1, w2, w3]))
    return cases


# ---------------------------------------------------------------- static evidence
def static_evidence(image, fdes):
    listing, cmp_imms = [], []
    for name, start in (("validate", VALIDATE), ("admit", ADMIT), ("cost", COST)):
        lo, hi = fdes[start]
        for va, form in sweep(image, lo, hi):
            listing.append((name, va, form))
            if form["op"] in (0x80, 0x83, 0x81) and form["reg"] & 7 == 7:
                cmp_imms.append({"function": name, "va": f"{va:#x}", "imm": form["imm"] & 0xff
                                 if form["op"] == 0x80 else form["imm"]})
    table = []
    for i in range(5):
        rel = struct.unpack("<i", image.read(JUMP_TABLE + 4 * i, 4))[0]
        table.append(f"{(JUMP_TABLE + rel) & M64:#x}")
    imm_at = {}
    for name, va, form in listing:
        if "imm" in form:
            imm_at[va] = form["imm"]
    consts = {
        "jump_table": {"va": f"{JUMP_TABLE:#x}", "section": image.section_of(JUMP_TABLE)[0], "targets": table},
        "relocated_slots": {k: {"slot": f"{v:#x}", "target": f"{image.relative[v]:#x}"} for k, v in SLOTS.items()},
        "panic_location_args": {k: f"{v:#x}" for k, v in PANIC_ARGS.items()},
        "compare_immediates": cmp_imms,
        "boundaries": {
            "gas_cap": 1 << 24 if imm_at.get(0x2b92d3a) == 0x1000000 else None,
            "initcode": imm_at.get(0x2b92f8d),
            "initcode_rev14": imm_at.get(0x2b92f8d, 0) + (1 << imm_at.get(0x2b92f8a, 0)),
            "floor_revision_gt": imm_at.get(0x2b93127),
        },
    }
    if None in consts["boundaries"].values():
        fail("expected immediate forms are missing")
    return consts, listing


def _fmt_ctx(ctx):
    parts = []
    for off in range(0, CTX_SIZE, 8):
        w = int.from_bytes(ctx[off:off + 8], "little")
        if w:
            parts.append(f"{off:x}={w:x}")
    return ",".join(parts)


def evaluate(image, override=None, mut=frozenset(), consts=None, stop_on_first=False):
    m = TraceMachine(image, override)
    vrows, arows, vbad, abad, tags, astops = [], [], 0, 0, {}, {}
    for i, (group, ctx, recs) in enumerate(validate_cases(consts["boundaries"])):
        records = _records(recs)
        exp = validate(Mem(ctx, records), mut)
        try:
            out, steps = run_validate(m, ctx, records)
            ok = compare_validate(out, exp)
        except ToolError:
            out, steps, ok = None, 0, False
        if not ok:
            vbad += 1
            if stop_on_first:
                return {"bad": 1}
        tags[f"{exp['tag']:#x}"] = tags.get(f"{exp['tag']:#x}", 0) + 1
        vrows.append(f"v{i}\t{group}\t{_fmt_ctx(ctx)}\t{''.join(f'{r:02x}' for r in recs)}\t{exp['tag']:#x}\t"
                     f"{exp['kind']}\t{','.join(f'{k}={v:x}' for k, v in sorted(exp.get('fields', {}).items()))}\t"
                     f"{steps}\t{'match' if ok else 'MISMATCH'}")
    prows, pbad, pstops = [], 0, {}
    for i, (group, tx, recs, rev, floor_off, cap_on, cap, words) in enumerate(admit_cases()):
        exp = admit(Mem(tx, recs), rev, floor_off, cap_on, cap, words, mut)
        try:
            got, steps = run_admit(m, tx, recs, rev, floor_off, cap_on, cap, words)
            ok = compare_admit(got, exp)
        except ToolError:
            got, steps, ok = None, 0, False
        if not ok:
            abad += 1
            if stop_on_first:
                return {"bad": 1}
        key = exp["panic"] if exp["stop"] == "panic" else f"{exp['words'][0]:#x}"
        astops[key] = astops.get(key, 0) + 1
        res = ",".join(f"{w:x}" for w in exp["words"]) if exp["stop"] == "return" else exp["panic"]
        arows.append(f"a{i}\t{group}\t{_fmt_ctx(tx)}\t{recs.hex() if len(recs) <= 0x90 else ''}\t{rev}\t{floor_off}\t"
                     f"{cap_on}\t{cap:x}\t{','.join(f'{w:x}' for w in words)}\t{res}\t{steps}\t"
                     f"{'match' if ok else 'MISMATCH'}")
    for i, (group, tx, recs, data, sched, rev, floor_off, cap_on, cap) in enumerate(path_cases()):
        exp = path(Mem(tx, recs), data, sched, rev, floor_off, cap_on, cap, mut)
        try:
            got, steps = run_path(m, tx, recs, data, sched, rev, floor_off, cap_on, cap)
            ok = compare_path(got, exp)
        except ToolError:
            steps, ok = 0, False
        if not ok:
            pbad += 1
            if stop_on_first:
                return {"bad": 1}
        if exp["stop"] == "panic":
            key = f"{exp['panic'][1]}@{exp['panic'][0]:#x}"
            res = key
        else:
            key = f"{exp['words'][0]:#x}"
            res = ",".join(f"{w:x}" for w in exp["words"])
        pstops[key] = pstops.get(key, 0) + 1
        sched_txt = ",".join(f"{off:x}={sched[off]:x}" for off in SCHED_FIELDS if sched[off] != MODE13_SCHEDULE[off])
        prows.append(f"p{i}\t{group}\t{_fmt_ctx(tx)}\t{recs.hex() if len(recs) <= 0x90 else ''}\t"
                     f"{hashlib.sha256(data).hexdigest()[:16]}:{len(data)}:{data.count(0)}\t{sched_txt or 'mode13'}\t"
                     f"{rev}\t{floor_off}\t{cap_on}\t{cap:x}\t{res}\t{steps}\t{'match' if ok else 'MISMATCH'}")
    return {"bad": vbad + abad + pbad, "validate": vrows, "admit": arows, "path": prows, "validate_mismatches": vbad,
            "admit_mismatches": abad, "path_mismatches": pbad, "tags": tags, "admit_outcomes": astops,
            "path_outcomes": pstops, "seen": set(m.seen)}


MUTANTS = ("rev9-gate-at-8", "chain-kind-includes-type0", "cap-from-rev12", "cap-equality-rejects", "ignore-0x264",
           "fee-cap-le", "type1-rev7", "blob-scan-first-only", "blob-max-ge", "custom-not-doubled",
           "initcode-no-rev14", "no-sentinel", "record-stride-0x28", "create-inverted", "keep-refund",
           "floor-from-rev11", "cap-uses-floor-only", "drop-auth-term", "create-words-floor",
           "floor-always-tokens")
CODE_MUTANTS = (  # (va, original byte, replacement): immediates and condition codes in the real code
    (0x2b92c1c, 0x08, 0x09),   # revision gate cmp $0x8
    (0x2b92d18, 0x0d, 0x0c),   # gas-cap revision cmp $0xd
    (0x2b92f8c, 0x0e, 0x0d),   # initcode shift count
    (0x2b9312a, 0x0b, 0x0a),   # floor revision cmp $0xb
    (0x2b9315a, 0x47, 0x42),   # cmova -> cmovb in the cap check
    (0x5be088a, 0x14, 0x15),   # floor bytes per access-list address (mov $0x14,%edx)
    (0x5be08a0, 0x3b, 0x3c),   # key shift guard shr $0x3b
    (0x5be0854, 0x05, 0x06),   # create word shift shr $0x5
)


def mutant_rows(image, consts):
    rows = []
    for name in MUTANTS:
        r = evaluate(image, mut=frozenset([name]), consts=consts, stop_on_first=True)
        rows.append(f"{name}\tmodel\t{'killed' if r['bad'] else 'SURVIVED'}")
    for va, old, new in CODE_MUTANTS:
        got = image.code(va, 1)[0]
        if got != old:
            fail(f"code mutant byte at {va:#x} is {got:#x}, expected {old:#x}")
        r = evaluate(image, override={va: new}, consts=consts, stop_on_first=True)
        rows.append(f"code@{va:#x}:{old:02x}->{new:02x}\tcode-bytes\t{'killed' if r['bad'] else 'SURVIVED'}")
    return rows


def generate(out):
    data = BINARY.read_bytes()
    image = Image(data)
    fdes = fde_rows(image, {VALIDATE, ADMIT, COST})
    if image.relative.get(SLOTS["cost_callee"]) != COST:
        fail("cost callee slot does not relocate to the cost calculation")
    consts, listing = static_evidence(image, fdes)
    result = evaluate(image, consts=consts)
    mutants = mutant_rows(image, consts)
    seen = result["seen"]
    totals = {n: sum(1 for x, _, _ in listing if x == n) for n in ("validate", "admit", "cost")}
    covered = {n: sum(1 for x, va, _ in listing if x == n and va in seen) for n in ("validate", "admit", "cost")}
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "binary": "artifacts/node/115/hl-node",
        "binary_sha256": SHA256,
        "functions": {name: {"fde_start": f"{fdes[v][0]:#x}", "fde_end": f"{fdes[v][1]:#x}"}
                      for name, v in (("validate", VALIDATE), ("admit", ADMIT), ("cost", COST))},
        "decoded_instructions": totals,
        "executed_instructions": covered,
        "path_cases": len(result["path"]),
        "path_mismatches": result["path_mismatches"],
        "path_outcomes": result["path_outcomes"],
        "validate_cases": len(result["validate"]),
        "validate_mismatches": result["validate_mismatches"],
        "validate_tags": result["tags"],
        "admit_cases": len(result["admit"]),
        "admit_mismatches": result["admit_mismatches"],
        "admit_outcomes": result["admit_outcomes"],
        "negative_controls": len(mutants),
        "negative_controls_killed": sum(1 for r in mutants if r.endswith("\tkilled")),
    }
    unexec = [f"{n}\t{va:#x}\t{f['bytes'].hex()}" for n, va, f in listing if va not in seen]
    files = {
        "summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
        "constants.json": json.dumps(consts, indent=2, sort_keys=True) + "\n",
        "decoded-instructions.tsv": "function\tva\tlength\tbytes\topcode_key\texecuted\n" + "\n".join(
            f"{n}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t"
            f"{'yes' if va in seen else 'no'}"
            for n, va, f in listing) + "\n",
        "validate-cases.tsv": "id\tgroup\tcontext_words\trecord_first_bytes\ttag\tkind\tfields\tsteps\tresult\n"
                              + "\n".join(result["validate"]) + "\n",
        "admit-cases.tsv": "id\tgroup\ttx_words\trecords\trevision\tfloor_off\tcap_on\tcap\tcost_words\texpected\t"
                           "steps\tresult\n" + "\n".join(result["admit"]) + "\n",
        "negative-controls.tsv": "control\tkind\tverdict\n" + "\n".join(mutants) + "\n",
        "path-cases.tsv": "id\tgroup\ttx_words\trecords\tdata_tag_len_zeros\tschedule_delta\trevision\tfloor_off\t"
                          "cap_on\tcap\texpected\tsteps\tresult\n" + "\n".join(result["path"]) + "\n",
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
    bad = summary["validate_mismatches"] + summary["admit_mismatches"] + summary["path_mismatches"]
    bad += summary["negative_controls"] - summary["negative_controls_killed"]
    print(json.dumps(summary, sort_keys=True))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
