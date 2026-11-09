#!/usr/bin/env python3
"""Reconstruct and validate the node #115 storage opcodes of the second EVM handler table: SLOAD, SSTORE, TLOAD, TSTORE.

The interpreter dispatches through function-pointer tables; the tables at 0x6485ef8 and 0x6486c60 (family B) hold SLOAD
0x4330ea0, SSTORE 0x4331150, TLOAD 0x43310d0 and TSTORE 0x4331640, and a third table at 0x649eea0 (family C) holds the
SLOAD copy 0x4f04140.  SLOAD replaces the stack top by the slot value: from spec 7 on it passes the skip flag
(gas < params +0xc8) to the fallible load behind GOT 0x64e6d98 and charges params +0xc8 for a cold slot.  SSTORE 0x4331150
is the sstore-gas handler's arithmetic (price 0x433cac0, refund 0x433c830, reserve accounting) in front of the journaled
store 0x4326080, which looks the account up (0x3ed7e80), marks it touched (journal tag 2), loads the slot, compares it
with the new word and on a change writes it and journals the old word (tag 8).  TLOAD and TSTORE need spec >= 11.
The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real machine code with a small
concrete x86-64 evaluator (no external programs, the binary is never executed) and compares every case with one
pure-Python reconstruction of the handlers and the store.  Negative controls show that wrong reconstructions and
corrupted code bytes are detected.
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
# Opcode table family B (indirect calls through two handler tables) and family C (a third monomorphised copy).
SLOAD_B, SLOAD_C = 0x4330ea0, 0x4f04140
SSTORE_B = 0x4331150
TLOAD_B, TSTORE_B = 0x43310d0, 0x4331640
STORE_B = 0x4326080  # journaled storage write reached by SSTORE_B
SSTORE_C, STORE_C = 0x4f04400, 0x4f00c30  # family C copies
COST_B, REFUND_B = 0x433cac0, 0x433c830  # price and refund bodies reached by SSTORE_B (run as real code)
LOOKUP_B, LOOKUP_C = 0x3ed7e80, 0x4ef9240  # account map lookup (stubbed: hash map with a runtime secret)
LOAD_SLOT, GROW_SLOT = 0x64e6d98, 0x64e68e8  # GOT words: fallible load 0x433bcf0, journal Vec grow
TLOAD_CALL, TSTORE_CALL = 0x43156c0, 0x4324490  # transient-storage helpers (stubbed: argument recorders)
TLOAD_C, TSTORE_C = 0x4f04370, 0x4f04dd0  # family C copies of TLOAD / TSTORE
TLOAD_CALL_C, TSTORE_CALL_C = 0x545e800, 0x5464420
TRANSIENT_AT = {TLOAD_B: 0x360, TLOAD_C: 0x270, TSTORE_B: 0x270, TSTORE_C: 0x270}  # host offset handed to the helper
PANIC_GOTS = (0x64df520, 0x64df848)
TABLE_BASES = {"B-first": 0x6485ef8, "B-second": 0x6486c60, "C": 0x649eea0}  # SLOAD (0x54) slot minus 0x54*8
OPCODES = {"SLOAD": 0x54, "SSTORE": 0x55, "TLOAD": 0x5c, "TSTORE": 0x5d}
FUNCS = (SLOAD_B, SLOAD_C, SSTORE_B, SSTORE_C, TLOAD_B, TSTORE_B, TLOAD_C, TSTORE_C, STORE_B, STORE_C, COST_B, REFUND_B, LOOKUP_B)
PRIORS = {0x2994990: "SSTORE handler of the first family (sstore-gas packet)", 0x2977910: "its store (warm/cold packet)"}

I_STACK_PTR, I_STACK_LEN, I_ADDR = 0x28, 0x30, 0x78
I_GAS, I_RESERVE, I_RESERVED, I_REFUND = 0x188, 0x190, 0x198, 0x1a0
I_STATIC, I_SPEC = 0x1a8, 0x1a9
H_JOURNAL, H_WARM, H_PARAMS, H_FLAG, H_TRANSIENT_A, H_TRANSIENT_B, H_ACCOUNTS, H_TXID, H_DB = (
    0x288, 0x2e0, 0x250, 0x265, 0x270, 0x360, 0x338, 0x390, 0x398)
PARAM_OFFS = (0x98, 0xa0, 0xa8, 0xb0, 0xc0, 0xc8, 0xd0, 0x138, 0x140, 0x150)
ENTRY = 0x58  # journal entry stride
A_FLAGS = 0x8c  # account record flag byte, bit 2 = touched

BASES = {"interp": 0x7d00_0000_0000, "host": 0x7d00_0100_0000, "params": 0x7d00_0200_0000, "stack": 0x7d00_0300_0000,
         "out": 0x7d00_0400_0000, "acct": 0x7d00_0500_0000, "rec": 0x7d00_0600_0000, "jbuf": 0x7d00_0700_0000,
         "args": 0x7d00_0800_0000}
SIZES = {"interp": 0x200, "host": 0x3c0, "params": 0x200, "out": 0x100, "acct": 0x100, "rec": 0x80, "args": 0x100}
FILLS = {"interp": 0x33, "host": 0x44, "params": 0x55, "out": 0x66, "acct": 0x77, "rec": 0x88, "jbuf": 0x99, "args": 0xaa}
STACK_FILL = 0x5c
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
SAVED_REGS = (3, 12, 13, 14, 15, 5)

R_OK, R_OOG, R_SENTRY, R_STATIC, R_UNDERFLOW, R_FATAL, R_BADOP = 0x00, 0x20, 0x25, 0x28, 0x2c, 0x36, 0x2b
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


def w32(x):
    return x.to_bytes(32, "little")


# ---------------------------------------------------------------- reconstruction
def sstore_cost(p, flag, o, cur, new, cold, mut=frozenset()):
    """0x433cac0 (same arithmetic as the first family's 0x299f910): set/reset price, cold surcharge from spec 6."""
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
    """0x433c830 (same arithmetic as 0x299f680): refund counter delta (i64)."""
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


def initial(c):
    """Initial bytes of every region for a case; the model mutates a copy, the machine mutates the real regions."""
    R = {k: bytearray(bytes([FILLS[k]]) * SIZES[k]) for k in SIZES}
    n = len(c["stack"])
    R["stack"] = bytearray(b"".join(w32(w) for w in c["stack"]) + bytes([STACK_FILL]) * 0x20)
    put(R["interp"], I_STACK_PTR, 8, BASES["stack"])
    put(R["interp"], I_STACK_LEN, 8, c["n"])
    for f, v in ((I_GAS, c["gas"]), (I_RESERVE, c["reserve"]), (I_RESERVED, c["reserved"]), (I_REFUND, c["refund"])):
        put(R["interp"], f, 8, v)
    R["interp"][I_ADDR:I_ADDR + 20] = c["addr"]
    R["interp"][I_STATIC], R["interp"][I_SPEC] = c["static"], c["spec"]
    put(R["host"], H_PARAMS, 8, BASES["params"])
    R["host"][H_FLAG] = c["host_flag"]
    put(R["host"], H_JOURNAL, 8, c["jcap"])
    put(R["host"], H_JOURNAL + 8, 8, BASES["jbuf"])
    put(R["host"], H_JOURNAL + 16, 8, c["jlen"])
    put(R["host"], H_TXID, 4, c["txid"])
    for off in PARAM_OFFS:
        put(R["params"], off, 8, c["params"][off])
    R["acct"][A_FLAGS] = c["aflags"]
    R["rec"][0:32], R["rec"][32:64] = w32(c["rec"][0]), w32(c["rec"][1])
    R["jbuf"] = bytearray(bytes([FILLS["jbuf"]]) * (ENTRY * (2 * c["jcap"] + 2)))
    for i in range(c["jlen"]):
        R["jbuf"][i * ENTRY] = 1 + i % 7
    R["args"][0:32], R["args"][32:64], R["args"][64:84] = w32(c["key"]), w32(c["value"]), c["addr"]
    return R


def push_entry(R, ev, kind, c, extra=b""):
    """Journal push of the store: grow the Vec first when len == cap, then write the entry at index len."""
    jb = R["host"]
    cap, ln = u(jb, H_JOURNAL, 8), u(jb, H_JOURNAL + 16, 8)
    if ln == cap:
        ev.append(("grow", cap))
        put(jb, H_JOURNAL, 8, cap * 2 if cap else 4)
    at = ln * ENTRY
    R["jbuf"][at] = kind
    R["jbuf"][at + 1:at + 21] = c["addr"]
    if kind == 8:
        key, old = w32(c["key"]), extra
        R["jbuf"][at + 0x15:at + 0x18] = key[:3]
        R["jbuf"][at + 0x18:at + 0x38] = key
        R["jbuf"][at + 0x38:at + 0x58] = old
    put(jb, H_JOURNAL + 16, 8, ln + 1)


def store_model(c, R, ev, mut=frozenset()):
    """0x4326080: touch the account (journal tag 2), load the slot, compare, write and journal (tag 8)."""
    ev.append(("lookup", H_ACCOUNTS, c["addr"].hex()))
    out = R["out"]
    if not c["found"]:
        out[0] = 0
        out[0x60] = 2
        return 2
    if not R["acct"][A_FLAGS] & 4:
        R["acct"][A_FLAGS] |= 4

        if "store_no_touch" not in mut:
            push_entry(R, ev, 2, c)
    cold_arg = c["cold_arg"] & 0xff
    ev.append(("load", cold_arg, w32(c["key"]).hex(), c["txid"], c["addr"].hex()))
    tag = c["tag"]
    if tag == 2:
        out[0] = 0
        out[0x60] = 2
        return 2
    rec = R["rec"]
    orig, cur, new = rec[0:32], bytes(rec[32:64]), w32(c["value"])
    out[0:64] = rec[0:64]
    out[0x40:0x60] = new
    out[0x60] = tag
    if "store_always_write" in mut or cur != new:
        rec[32:64] = new
        push_entry(R, ev, 8, c, cur if "store_journal_new" not in mut else new)
    return tag


def sstore_model(c, R, ev, mut=frozenset()):
    """0x4331150: static/underflow gates, pop key+value, sentry, static charge, store, cost, reserve, refund."""
    it = R["interp"]
    if c["static"]:
        return R_STATIC
    if c["n"] < 2:
        return R_UNDERFLOW
    put(it, I_STACK_LEN, 8, c["n"] - 2)
    key, value = c["stack"][c["n"] - 1], c["stack"][c["n"] - 2]
    if "pop_swap" in mut:
        key, value = value, key
    spec, p = c["spec"], c["params"]
    gas = c["gas"]
    if spec > (5 if "sentry_ge5" not in mut else 4) and gas <= p[0xc0]:
        return R_SENTRY
    if gas < p[0x98]:
        return R_OOG
    gas -= p[0x98]
    put(it, I_GAS, 8, gas)
    skip = int(gas < p[0xc8]) if spec > 6 else 0
    c2 = dict(c, key=key, value=value, cold_arg=skip)
    R2 = dict(R, out=bytearray(R["out"]))  # the handler's result block lives on its own stack
    tag = store_model(c2, R2, ev, mut)
    out = R2["out"]
    if tag == 2:
        if spec > 6 and not (out[0] & 1) and "err_always_fatal" not in mut:
            return R_OOG
        return R_FATAL
    o, cur, new = (int.from_bytes(out[i:i + 32], "little") for i in (0, 32, 64))
    flag = int(spec >= 6)
    try:
        cost = sstore_cost(p, flag, o, cur, new, tag, mut)
    except Panic:
        return "panic"
    if gas < cost:
        return R_OOG
    gas -= cost
    put(it, I_GAS, 8, gas)
    if c["host_flag"] and new != cur:
        res, rsv, q = c["reserve"], c["reserved"], p[0x150]
        if o == cur and o == 0:
            if res >= q:
                put(it, I_RESERVED, 8, sat_add_i64(rsv, q))
                put(it, I_RESERVE, 8, res - q)
                rsv, res = sat_add_i64(rsv, q), res - q
            else:
                need = q - res
                if "reserve_no_gas" not in mut:
                    if gas < need:
                        return R_OOG
                    gas -= need
                    put(it, I_GAS, 8, gas)
                rsv, res = sat_add_i64(q, rsv), 0
                put(it, I_RESERVED, 8, rsv)
                put(it, I_RESERVE, 8, 0)
        if o == new and o == 0 and q != 0 and "no_release" not in mut:
            put(it, I_RESERVED, 8, sat_sub_i64(rsv, q))
            put(it, I_RESERVE, 8, min(M64, res + q))
    try:
        r = sstore_refund(p, flag, o, cur, new, mut)
    except Panic:
        return "panic"
    total = s64(c["refund"]) + r
    if not I64_MIN <= total <= I64_MAX:
        return "panic"
    put(it, I_REFUND, 8, total & M64)
    return R_OK


def sload_model(c, R, ev, mut=frozenset()):
    """0x4330ea0 / 0x4f04140: replace the stack top (a key) by the slot value; spec > 6 charges the cold price."""
    it, p = R["interp"], c["params"]
    if c["n"] == 0:
        return R_UNDERFLOW
    new_path = c["spec"] > (6 if "sload_ge6" not in mut else 5)
    gas = c["gas"]
    skip = int(gas < p[0xc8]) if new_path else 0
    fail_code = R_OOG if new_path else R_FATAL
    ev.append(("lookup", H_ACCOUNTS, c["addr"].hex()))
    if not c["found"]:
        return fail_code
    key = c["stack"][c["n"] - 1]
    ev.append(("load", skip, w32(key).hex(), c["txid"], c["addr"].hex()))
    if c["tag"] == 2:
        return fail_code
    if new_path and c["tag"] & 1:
        if gas < p[0xc8]:
            return R_OOG
        if "sload_no_charge" not in mut:
            put(it, I_GAS, 8, gas - p[0xc8])
    top = (c["n"] - 1) * 32
    R["stack"][top:top + 32] = R["rec"][32:64]
    return R_OK


def tload_model(c, R, ev, mut=frozenset()):
    """0x43310d0: spec >= 11 only; the stack top is replaced by the transient value for (address, key)."""
    if c["spec"] < (11 if "tload_spec" not in mut else 10):
        return R_BADOP
    if c["n"] == 0:
        return R_UNDERFLOW
    key = c["stack"][c["n"] - 1]
    ev.append(("tload", TRANSIENT_AT[c["entry"]], c["addr"].hex(), w32(key).hex()))
    top = (c["n"] - 1) * 32
    R["stack"][top:top + 32] = w32(c["value"])
    return R_OK


def tstore_model(c, R, ev, mut=frozenset()):
    """0x4331640: spec >= 11, not static, two operands (key = top, value below) handed to 0x4324490."""
    if c["spec"] < 11:
        return R_BADOP
    if c["static"] == (1 if "tstore_static" not in mut else 2):
        return R_STATIC
    if c["n"] < 2:
        return R_UNDERFLOW
    put(R["interp"], I_STACK_LEN, 8, c["n"] - 2)
    key, value = c["stack"][c["n"] - 1], c["stack"][c["n"] - 2]
    ev.append(("tstore", TRANSIENT_AT[c["entry"]], c["addr"].hex(), w32(key).hex(), w32(value).hex()))
    return R_OK


MODELS = {"sload": sload_model, "sstore": sstore_model, "tload": tload_model, "tstore": tstore_model}


def model(c, mut=frozenset()):
    R = initial(c)
    ev = []
    if c["kind"] == "store":
        tag = store_model(c, R, ev, mut)
        ret = ("ret", tag)
        return {"ret": ret, "R": R, "events": ev}
    code = MODELS[c["kind"]](c, R, ev, mut)
    if code == "panic":
        return {"ret": ("panic", "overflow"), "R": R, "events": ev}
    return {"ret": ("ret", code), "R": R, "events": ev}


# ---------------------------------------------------------------- harness
def setup(m, c):
    image, events = m.image, []
    R = initial(c)
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    bufs = {k: m.add_region(BASES[k], len(R[k]), bytes(R[k])) for k in R}
    lookups = (LOOKUP_B, LOOKUP_C)

    def lookup(mc):
        events.append(("lookup", mc.regs[7] - BASES["host"], bytes(mc.load(mc.regs[6] + i, 1) for i in range(20)).hex()))
        mc.regs[0] = BASES["acct"] if c["found"] else 0

    def load(mc):
        ctx, key, flag = mc.regs[7], mc.regs[6], mc.regs[2]
        if mc.load(ctx, 8) != BASES["acct"] or mc.load(ctx + 8, 8) != BASES["host"] + H_JOURNAL \
                or mc.load(ctx + 16, 8) != BASES["host"] + H_WARM or mc.load(ctx + 24, 8) != BASES["host"] + H_DB:
            fail("load argument block does not name the host fields")
        k = bytes(mc.load(key + i, 1) for i in range(32))
        events.append(("load", flag & 0xffffffff, k.hex(), mc.load(ctx + 32, 4),
                       bytes(mc.load(ctx + 36 + i, 1) for i in range(20)).hex()))
        mc.regs[0] = BASES["rec"]
        mc.regs[2] = c["tag"] | 0x5a5a00

    def grow(mc):
        vec = mc.regs[7]
        cap = mc.load(vec, 8)
        events.append(("grow", cap))
        mc.store(vec, 8, cap * 2 if cap else 4)

    def tload(mc):
        out, hp, ap, kp = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        events.append(("tload", hp - BASES["host"], bytes(mc.load(ap + i, 1) for i in range(20)).hex(),
                       bytes(mc.load(kp + i, 1) for i in range(32)).hex()))
        for i, b in enumerate(w32(c["value"])):
            mc.store(out + i, 1, b)

    def tstore(mc):
        hp, ap, kp, vp = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        events.append(("tstore", hp - BASES["host"], bytes(mc.load(ap + i, 1) for i in range(20)).hex(),
                       bytes(mc.load(kp + i, 1) for i in range(32)).hex(), bytes(mc.load(vp + i, 1) for i in range(32)).hex()))

    m.stubs = {t: lookup for t in lookups}
    m.stubs[image.word(LOAD_SLOT)] = load
    m.stubs[image.word(GROW_SLOT)] = grow
    m.stubs[TLOAD_CALL] = m.stubs[TLOAD_CALL_C] = tload
    m.stubs[TSTORE_CALL] = m.stubs[TSTORE_CALL_C] = tstore
    for slot in PANIC_GOTS:
        m.stubs[image.word(slot)] = "panic"
    return events, bufs, R


def run_case(m, c):
    m.reset()
    events, bufs, R0 = setup(m, c)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    if c["kind"] == "store":
        m.regs[7], m.regs[6] = BASES["out"], BASES["host"]
        m.regs[2], m.regs[1], m.regs[8] = BASES["args"] + 64, BASES["args"], BASES["args"] + 32
        m.regs[9] = c["cold_arg"] | (0x7e7e7e00 << 8)
    else:
        m.regs[7], m.regs[6] = BASES["interp"], BASES["host"]
    got = {"events": events}
    try:
        m.run(c["entry"], limit=40000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == STACK_TOP - 0x100
    got["R"] = {k: bytes(v) for k, v in bufs.items()}
    return got


def compare(c, want, got):
    if want["ret"][0] == "panic" or got["ret"][0] == "panic":
        return want["ret"][0] == got["ret"][0] and want["events"] == got["events"]
    if c["kind"] != "store" and want["ret"] != got["ret"]:  # the store's contract is the out block, not rax
        return False
    if want["events"] != got["events"] or not got["regs_ok"]:
        return False
    return all(bytes(want["R"][k]) == got["R"][k] for k in want["R"])


# ---------------------------------------------------------------- cases
WORD_POOL = (0, 1, 2, 3, 0x100, M64, 1 << 64, M256)
KINDS = ("sload", "sload", "sstore", "sstore", "sstore", "store", "tload", "tstore")
TOTAL = 12000


def rand_word(s):
    k = s.below(10)
    if k < 6:
        return s.pick(WORD_POOL)
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


def make_case(s, kind, k):
    params = {off: s.below(30000) + 1 for off in PARAM_OFFS}
    if s.below(4) == 0:
        params[0x150] = 0
    if s.below(9) == 0:
        for off in s.pick([(0xb0,), (0xa0, 0xd0), (0xa8, 0xd0), (0x138,), (0x140,), (0x150,), (0x98,), (0xc0,), (0xc8,)]):
            params[off] = s.pick([M64, M64 - 1, 1 << 63, (1 << 63) - 1, 0])
    o = rand_word(s)
    cur = s.pick([o, o, 0, rand_word(s)])
    new = s.pick([cur, o, 0, rand_word(s), rand_word(s)])
    if k % 5 == 1:
        o, cur = 0, 0
        new = s.pick([0, rand_word(s)])
    elif k % 5 == 2:
        o, new = 0, 0
        cur = s.pick([1, M256, rand_word(s)])
    tag = s.pick([0, 1, 0, 1, 2]) if s.below(6) else 2
    n = s.pick([2, 2, 3, 5]) if s.below(12) else s.below(2)
    if kind in ("sload", "tload"):
        n = s.pick([1, 1, 2, 4]) if s.below(12) else 0
    stack = [rand_word(s) for _ in range(n)]
    spec = s.below(14)
    if s.below(3):
        spec = 6 + s.below(8)
    gas_ref = s.pick([params[0xc0], params[0x98], params[0x98] + params[0xa0], params[0x98] + params[0xd0] + params[0xa8],
                      params[0x98] + params[0xa0] + params[0x150], params[0xc8] + params[0x98], params[0xc8]])
    gas = max(0, gas_ref + s.below(9) - 4) & M64 if s.below(3) else rand_u64(s, 200000)
    jcap = s.pick([0, 1, 2, 3, 8])
    jlen = s.below(jcap + 1) if s.below(3) else jcap
    refund = s.pick([0, s.below(60000), I64_MAX - s.below(3), (1 << 63) + s.below(3), M64 - s.below(40000)])
    if k % 40 == 39 and kind == "sstore":  # o != 0, cur == 0, new == o: refund = -clears + restore price
        params[0xb0] = s.pick([M64, M64 - 1, M64 - s.below(1000)])
        params[0x140] = s.pick([I64_MAX, I64_MAX - 1, I64_MAX - s.below(1000)])
        o = new = s.pick([1, M256, rand_word(s) | 1])
        cur, n, stack, tag = 0, 2, [rand_word(s), rand_word(s)], s.pick([0, 1])
        spec, gas = 6 + s.below(7), M64 - s.below(1000)
    c = {"kind": kind, "params": params, "rec": (o, cur), "value": new, "tag": tag, "n": n, "stack": stack, "spec": spec,
         "static": int(s.below(25) == 0), "gas": gas & M64,
         "reserve": s.pick([0, params[0x150], max(0, params[0x150] - 1), s.below(60000), M64 - s.below(3)]) & M64,
         "reserved": s.pick([0, s.below(60000), I64_MAX - s.below(3), (1 << 63) + s.below(3), M64]) & M64,
         "refund": refund & M64, "host_flag": s.pick([0, 1, 1, 0x80]), "addr": s.take(20), "txid": s.below(1 << 32),
         "found": int(s.below(10) != 0), "aflags": s.pick([0, 4, 0x84, 0xfb, 0xff, 1]), "jcap": jcap, "jlen": jlen,
         "key": rand_word(s), "cold_arg": s.pick([0, 1, 1, 0, 0x7f]), "n_total": k}
    if kind == "sstore":
        c["entry"] = (SSTORE_B, SSTORE_C)[k // 8 % 2]
    elif kind == "sload":
        c["entry"] = SLOAD_B if k % 2 else SLOAD_C
    elif kind == "store":
        c["entry"] = (STORE_B, STORE_C)[k // 8 % 2]
    else:
        c["entry"] = (TLOAD_B, TLOAD_C)[k // 8 % 2] if kind == "tload" else (TSTORE_B, TSTORE_C)[k // 8 % 2]
    return c


def all_cases():
    s = Stream("re21-storage-opcodes-b-115")
    for k in range(TOTAL):
        yield make_case(s, KINDS[k % len(KINDS)], k)


# ---------------------------------------------------------------- static evidence
CHECKED = (
    (0x4330ed8, "80 bf a9 01 00 00 06", "SLOAD: spec byte +0x1a9 > 6 selects the cold-price path"),
    (0x4330eec, "48 8b a9 c8 00 00 00", "SLOAD: cold price params +0xc8"),
    (0x43310c5, "b0 2c", "SLOAD: empty stack result 0x2c"),
    (0x4330f9a, "b0 20", "SLOAD: out-of-gas result 0x20 (new path)"),
    (0x4331033, "b0 36", "SLOAD: store error result 0x36 (old path)"),
    (0x43310d0, "80 bf a9 01 00 00 0b", "TLOAD: spec byte < 11 -> invalid opcode result 0x2b"),
    (0x4331141, "b0 2b", "TLOAD: invalid opcode result 0x2b"),
    (0x4331640, "80 bf a9 01 00 00 0b", "TSTORE: spec byte < 11 -> invalid opcode result 0x2b"),
    (0x433162a, "b0 28", "SSTORE: static violation result 0x28"),
    (0x43311d5, "40 80 fd 05", "SSTORE: spec byte > 5 -> sentry check"),
    (0x43311e9, "b0 25", "SSTORE: sentry failure result 0x25"),
    (0x4331227, "40 80 fd 06", "SSTORE: spec byte > 6 -> skip flag from params +0xc8"),
    (0x43312a3, "b0 36", "SSTORE: store error result 0x36 (spec <= 6)"),
    (0x43313a8, "41 80 be 65 02 00 00", "SSTORE: host byte +0x265 enables the reserve accounting"),
)
RELIEF = ((SLOAD_B, "first table"), (SSTORE_B, "first table"), (TLOAD_B, "first table"), (TSTORE_B, "first table"))


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


def static_evidence(image):
    rows = fde_rows(image, FUNCS)
    decoded, funcs = {}, {}
    for f in FUNCS:
        lo, hi = rows[f]
        insns = sweep_padded(image, lo, hi)
        decoded[f] = insns
        calls = sorted({f"{x['target']:#x}" for va, x in insns if x and x["op"] == 0xe8})
        funcs[f"{f:#x}"] = {"bytes": hi - lo, "instructions": sum(1 for _, x in insns if x), "direct_calls": calls}
    slots = {}
    for name, base in sorted(TABLE_BASES.items()):
        for op_name, op in sorted(OPCODES.items()):
            slot = base + 8 * op
            slots[f"{name}:{op_name}:{op:#x}"] = {"slot": f"{slot:#x}", "handler": f"{image.word(slot):#x}" if slot in image.relative else None}
    checked = []
    for va, want, note in CHECKED:
        got = image.code(va, len(bytes.fromhex(want))).hex(" ")
        if got != want:
            fail(f"byte pattern at {va:#x} is {got}, expected {want}")
        checked.append({"address": f"{va:#x}", "bytes": got, "note": note})
    consts = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": slots, "checked_bytes": checked,
              "got_words": {f"{s:#x}": f"{image.word(s):#x}" for s in (LOAD_SLOT, GROW_SLOT) + PANIC_GOTS},
              "text_section": {"address": f"{image.text['address']:#x}", "offset": f"{image.text['offset']:#x}"}}
    return consts, decoded


# ---------------------------------------------------------------- evaluation
def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None, sink=None):
    """Run every case; with sink the per-case rows go to the callback instead of a list (no accumulation)."""
    m = machine or TraceMachine(image, override)
    bad = n = 0
    for i, c in enumerate(cases if cases is not None else all_cases()):
        try:
            want = model(c, mut)
            got = run_case(m, c)
            ok = compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        n += 1
        if sink:
            sink(i, c, want, got, ok)
        if stop_on_first and not ok:
            break
    return n, bad, m


MODEL_MUTANTS = ["pop_swap", "sentry_ge5", "err_always_fatal", "pre_flag_new_only", "no_cold", "noop_charges", "dirty_charges",
                 "set_reset_swap", "no_negate", "no_restore", "reserve_no_gas", "no_release", "store_always_write",
                 "sload_ge6", "tload_spec", "tstore_static", "store_no_touch", "store_journal_new", "sload_no_charge"]
BYTE_MUTANTS = [
    (0x4330ede, 0x05, "SLOAD spec threshold 6 -> 5"),
    (0x4330eef, 0xc0, "SLOAD cold price params +0xc8 -> +0xc0"),
    (0x43310c6, 0x2d, "SLOAD empty-stack result 0x2c -> 0x2d"),
    (0x4330f9b, 0x21, "SLOAD out-of-gas result 0x20 -> 0x21"),
    (0x4331034, 0x37, "SLOAD store-error result 0x36 -> 0x37"),
    (0x43310d6, 0x0a, "TLOAD spec threshold 11 -> 10"),
    (0x4331142, 0x2c, "TLOAD invalid-opcode result 0x2b -> 0x2c"),
    (0x4331646, 0x0a, "TSTORE spec threshold 11 -> 10"),
    (0x433162b, 0x29, "SSTORE static result 0x28 -> 0x29"),
    (0x43311d8, 0x04, "SSTORE sentry spec threshold 5 -> 4"),
    (0x43311ea, 0x26, "SSTORE sentry result 0x25 -> 0x26"),
    (0x433122a, 0x05, "SSTORE skip-flag spec threshold 6 -> 5"),
    (0x43312a4, 0x37, "SSTORE store-error result 0x36 -> 0x37"),
    (0x43313ab, 0x64, "SSTORE reserve flag byte +0x265 -> +0x264"),
    (0x4f04158, 0x05, "SLOAD twin spec threshold 6 -> 5"),
    (0x4f04376, 0x0a, "TLOAD copy spec threshold 11 -> 10"),
    (0x4f04ddf, 0x0a, "TSTORE copy spec threshold 11 -> 10"),
    (0x432614c, 0x04, "store: touch journal tag 2 -> 4"),
    (0x4326282, 0x09, "store: write journal tag 8 -> 9"),
    (0x4326148, 0x50, "store: journal entry stride 0x58 -> 0x50 (touch push)"),
    (0x4326114, 0x8d, "store: account flag byte +0x8c -> +0x8d"),
    (0x432611a, 0x08, "store: touched bit 0x04 -> 0x08"),
    (0x4326197, 0x03, "store: load error tag 2 -> 3"),
    (0x433cace, 0xc8, "cost: cold surcharge +0xd0 -> +0xc8"),
    (0x433caf8, 0xa0, "cost: reset price +0xa8 -> +0xa0"),
    (0x433c841, 0xa8, "refund: clear amount +0xb0 -> +0xa8"),
    (0x433ca88, 0x40, "refund: restore-to-zero +0x138 -> +0x140"),
    (0x4f04da9, 0x29, "SSTORE copy: static result 0x28 -> 0x29"),
    (0x4f04494, 0x26, "SSTORE copy: sentry result 0x25 -> 0x26"),
    (0x4f04423, 0x2d, "SSTORE copy: underflow result 0x2c -> 0x2d"),
    (0x4f04550, 0x37, "SSTORE copy: store error result 0x36 -> 0x37"),
    (0x4f04482, 0x04, "SSTORE copy: sentry spec threshold 5 -> 4"),
    (0x4f044d9, 0x05, "SSTORE copy: skip-flag spec threshold 6 -> 5"),
    (0x4f00d0a, 0x04, "store copy: touch journal tag 2 -> 4"),
    (0x4f00e53, 0x09, "store copy: write journal tag 8 -> 9"),
    (0x4f00cd3, 0x08, "store copy: touched bit 0x04 -> 0x08"),
    (0x4f00d55, 0x03, "store copy: load error tag 2 -> 3"),
]


def controls(image, cases):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases())
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, override={va: byte}, stop_on_first=True, cases=cases())
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
SAMPLE_EVERY = 4


def wtag(x):
    if x == 0:
        return "0"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(w32(x)).hexdigest()[:8]


NAMES = {R_OK: "ok", R_OOG: "out-of-gas", R_SENTRY: "sentry", R_STATIC: "static", R_UNDERFLOW: "underflow",
         R_FATAL: "store-error", R_BADOP: "bad-opcode"}


def outcome(c, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "panic":
        return f"{c['kind']}/panic"
    if c["kind"] == "store":
        o = got["R"]["out"]
        return f"store/{'missing-account' if not c['found'] else 'load-error' if c['tag'] == 2 else 'cold' if c['tag'] else 'warm'}/" \
               f"{'unchanged' if o[32:64] == o[64:96] else 'written'}"
    head = NAMES.get(code, f"r{code:#x}")
    shape = ""
    if c["kind"] == "sload":
        shape = "/new" if c["spec"] > 6 else "/old"
        if code == R_OK:
            shape += "/cold" if c["tag"] & 1 else "/warm"
    elif c["kind"] == "sstore" and got["events"]:
        o, cur = c["rec"]
        shape = f"/{'cold' if c['tag'] == 1 else 'warm'}/{'noop' if c['value'] == cur else 'clean' if o == cur else 'dirty'}"
    return f"{c['kind']}/{head}{shape}"


def case_line(i, c, got, ok):
    p = c["params"]
    inp = (f"entry={c['entry']:#x},spec={c['spec']},static={c['static']},n={c['n']},gas={c['gas']:#x},found={c['found']},"
           f"tag={c['tag']},orig={wtag(c['rec'][0])},cur={wtag(c['rec'][1])},new={wtag(c['value'])},"
           f"aflags={c['aflags']:#x},jcap={c['jcap']},jlen={c['jlen']},host={c['host_flag']:#x},cold={c['cold_arg']:#x},"
           f"p98={p[0x98]:#x},pc8={p[0xc8]:#x},pd0={p[0xd0]:#x},p150={p[0x150]:#x}")
    ev = ",".join(f"{e[0]}{':' + str(e[1]) if e[0] in ('load', 'grow') else ''}" for e in got.get("events", [])) or "-"
    if "error" in got:
        res = got["error"]
    elif got["ret"][0] == "panic":
        res = "panic"
    else:
        res = f"ret={got['ret'][1]:#x}"
        if c["kind"] != "store":
            res += f",len={u(got['R']['interp'], I_STACK_LEN, 8)},gas={u(got['R']['interp'], I_GAS, 8):#x}"
        res += f",jlen={u(got['R']['host'], H_JOURNAL + 16, 8)}"
    return f"{i}\t{c['kind']}\t{inp}\t{outcome(c, got)}\t{ev}\t{res}\t{'yes' if ok else 'NO'}"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    classes, kinds = {}, {}
    with (out / "cases.tsv").open("w") as fh:
        fh.write("case\tkind\tinput\toutcome\tcalls\tresult\tmatch\n")

        def sink(i, c, want, got, ok):
            oc = outcome(c, got) if "error" not in got else "error"
            classes[oc] = classes.get(oc, 0) + 1
            kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
            if i % SAMPLE_EVERY == 0 or not ok:
                fh.write(case_line(i, c, got, ok) + "\n")
        n, bad, m = evaluate(image, sink=sink)
    consts, decoded = static_evidence(image)
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    covered = {}
    with (out / "decoded-instructions.tsv").open("w") as fh:
        fh.write("function\taddress\tlength\tbytes\topcode\texecuted\n")
        for start, insns in sorted(decoded.items()):
            hit = total = 0
            for va, f in insns:
                if f is None:
                    fh.write(f"{start:#x}\t{va:#x}\t1\tcc\tpadding\t0\n")
                    continue
                run = va in m.seen
                hit += run
                total += 1
                fh.write(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}\n")
            covered[f"{start:#x}"] = [hit, total]
    ctl = controls(image, all_cases)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": n, "mismatches": bad, "cases_by_kind": kinds, "covered_instructions": covered,
               "outcome_classes": classes, "negative_controls": {"total": len(ctl), "detected": detected}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": n, "negative_controls": len(ctl), "negative_detected": detected, "mismatches": bad}, indent=2, sort_keys=True) + "\n")
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
