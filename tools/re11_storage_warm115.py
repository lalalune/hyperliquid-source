#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM storage warm/cold path: sstore 0x2977910 (+ twin 0x2977cd0) and sload 0x4e33680.

0x2977910 and its position twin 0x2977cd0 (same bytes except RIP displacements) look up an
account in the context account map (+0x338, items +0x350, seed +0x358, 0xa8-byte buckets),
set status bit 0x04 with a journal entry tag 2 the first time, and call the storage load
0x4e33680 through GOT 0x64e6d90 with an argument block {account, journal Vec +0x288,
access-list warm map +0x2e0, database +0x398, transaction id +0x390, address}.  The load
probes the account storage table (0x68-byte buckets: key, original, present, transaction
id, cold byte); a slot already touched in this transaction and not cold is warm; otherwise
the address and key are looked up in the access-list warm map (address hash with the map
seed, key hash 0x4e52a90/0x4e623a0 through the byte hasher 0x1770830).  A cold access with
the skip flag returns 2; otherwise a missing slot is read from the database (0x5441fe0,
or zero when status bit 0x01 is set), inserted, and a cold access pushes journal tag 9.
The store then returns {original, present, new, is_cold} and pushes journal tag 8 when the
value changes.  The tool reads every relocation, FDE extent and code byte from the ELF
file, evaluates the real machine code with a small concrete x86-64 evaluator (no external
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
                fail(f"sar is outside the supported subset at {va:#x}")
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
SSTORE_A, SSTORE_B, SLOAD = 0x2977910, 0x2977cd0, 0x4e33680
HASH_U256, HASH_WRITE, HASH_BYTES = 0x4e52a90, 0x4e623a0, 0x1770830
SLOAD_B = 0x433bcf0  # GOT 0x64e6d98: the storage load called by the twin 0x2977cd0 (different body)
DB_FN = 0x5441fe0  # direct call at 0x4e33cb4: database storage read
SEED_GOT, BYTES_GOT, RESERVE_GOT, GROW_GOT, SLOAD_GOT = 0x64dfa78, 0x64dfa80, 0x64e7028, 0x64e6cf0, 0x64e6d90
TEMPLATE = 0x64371f8  # 32-byte empty hashbrown table; word 0 is the static all-EMPTY control group
EMPTY_CTRL = None
SEED_AT = None
FS_BASE = 0x7b00_0000_2000

# context offsets read by 0x2977910 / 0x2977cd0
J_CAP, J_PTR, J_LEN = 0x288, 0x290, 0x298
WARM_AT, TXID_AT, DB_AT = 0x2e0, 0x390, 0x398
ACCT_TABLE, ACCT_ITEMS, ACCT_SEED = 0x338, 0x350, 0x358
ACCT_SIZE, SLOT_SIZE, WARM_SIZE, SET_SIZE, ENTRY = 0xa8, 0x68, 0x40, 0x20, 0x58
ACCT_STRUCT, STATUS = 0x18, 0xa4  # account struct inside a bucket; status byte = struct +0x8c
TAG_TOUCH, TAG_CHANGE, TAG_WARM = 2, 8, 9

CTX_AT = 0x7d00_0000_0000
CTX_SIZE = 0x400
OUT_AT = 0x7d00_0100_0000
ARG_AT = 0x7d00_0200_0000  # address, key and new value inputs
FRAME_AT = 0x7d00_0300_0000  # sload argument block for direct entry
TABLE_AT = 0x7d00_0400_0000
TABLE_SIZE = 0x80000
HEAP_AT = 0x7d00_1000_0000
HEAP_SIZE = 0x40000
DB_PTR = 0x7d00_0700_0000
STACK_FILL = 0x5c
JOURNAL_FILL = 0x77
OUT_FILL = 0x33
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


def fold(a, b):
    p = (a & M64) * (b & M64)
    return (p & M64) ^ (p >> 64)


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M64


def w64(data, at):
    return int.from_bytes(data[at:at + 8], "little")


# ---------------------------------------------------------------- reconstruction: hashes
def bytes_hash(data, seed, g, mut=frozenset()):
    """0x1770830: foldhash byte hasher for len(data) >= 16 (None = panic path for < 16)."""
    n = len(data)
    if n < 16:
        return None
    r8 = (g[1] + seed) & M64
    r14 = g[0]
    rdx = seed
    p = 0
    if n >= 0x81:
        r10, r9 = (g[2] + seed) & M64, (g[3] + seed) & M64
        if n > 0x100:
            rbx, r11, rcx = (g[4] + seed) & M64, (g[5] + seed) & M64, seed
            while True:
                rcx = fold(w64(data, p + 0x30) ^ r14, rcx ^ w64(data, p))
                r8 = fold(w64(data, p + 0x38) ^ r14, r8 ^ w64(data, p + 8))
                r10 = fold(w64(data, p + 0x40) ^ r14, r10 ^ w64(data, p + 0x10))
                r9 = fold(w64(data, p + 0x48) ^ r14, r9 ^ w64(data, p + 0x18))
                rbx = fold(w64(data, p + 0x50) ^ r14, rbx ^ w64(data, p + 0x20))
                r11 = fold(w64(data, p + 0x58) ^ r14, r11 ^ w64(data, p + 0x28))
                n, p = n - 0x60, p + 0x60
                if not n > 0x100:
                    break
            rdx, r8 = rcx ^ rbx, r8 ^ r11
        while True:
            rdx = fold(w64(data, p + 0x20) ^ r14, rdx ^ w64(data, p))
            r8 = fold(w64(data, p + 0x28) ^ r14, r8 ^ w64(data, p + 8))
            r10 = fold(w64(data, p + 0x30) ^ r14, r10 ^ w64(data, p + 0x10))
            r9 = fold(w64(data, p + 0x38) ^ r14, r9 ^ w64(data, p + 0x18))
            n, p = n - 0x40, p + 0x40
            if not n > 0x80:
                break
        rdx, r8 = rdx ^ r10, r8 ^ r9
    tail = (lambda k: w64(data, p + n - k))
    r9 = fold(tail(16) ^ r14, rdx ^ w64(data, p))
    r8 = fold(tail(8) ^ r14, r8 ^ w64(data, p + 8))
    limit = 0x1f if "medium_ge32" not in mut else 0x20
    if n > limit:
        r9 = fold(tail(32) ^ r14, r9 ^ w64(data, p + 0x10))
        r8 = fold(tail(24) ^ r14, r8 ^ w64(data, p + 0x18))
        if n >= 0x40:
            r9 = fold(tail(48) ^ r14, r9 ^ w64(data, p + 0x20))
            r8 = fold(tail(40) ^ r14, r8 ^ w64(data, p + 0x28))
            if n >= 0x60:
                r9 = fold(tail(64) ^ r14, r9 ^ w64(data, p + 0x30))
                r8 = fold(tail(56) ^ r14, r8 ^ w64(data, p + 0x38))
    return r8 ^ r9


def write_model(state, key, g, mut=frozenset()):
    """0x24b7080: (acc0, acc1, seed, len) after writing the length prefix 4 and 32 key bytes."""
    acc0, acc1, seed, ln = state
    if ln >= 0x41:
        rdx = fold(g[0] ^ acc1, seed ^ acc0)
        acc0, acc1, ln = 4, 0, 0x40
    else:
        v = (4 << ln) & M128 if "prefix_one" not in mut else (1 << ln) & M128
        acc0, acc1 = acc0 | (v & M64), acc1 | (v >> 64)
        ln, rdx = (ln + 0x40) & 0xff, seed
    seed = bytes_hash(key, rol(rdx, 32) if "no_rol" not in mut else rdx, g, mut)
    return acc0, acc1, seed, ln


def hash_u256(limbs32, seed, g, mut=frozenset()):
    """0x24b6e30: foldhash of a U256 (four little-endian limbs, 32 bytes) with a per-set seed."""
    acc0, acc1, seed, ln = write_model((0, 0, seed, 0), limbs32, g, mut)
    if ln == 0:
        return seed
    return fold(g[0] ^ acc1, seed ^ acc0)


def hash_addr(addr, seed, g0, mut=frozenset()):
    """0x2a318d0 hash: two folded multiplies over the 20-byte address."""
    k0, k1, k2 = w64(addr, 0), w64(addr, 8), int.from_bytes(addr[16:20], "little")
    if "addr_swap" in mut:
        k0, k1 = k1, k0
    x = fold(k1 ^ g0, k0 ^ seed) ^ k2
    return fold(x, g0)


def key_limbs(word32, mut=frozenset()):
    """Storage key bytes (big-endian B256) -> U256 limbs as stored by 0x2668d40..0x2668d69."""
    if "no_bswap" in mut:
        return bytes(word32)
    return int.from_bytes(word32, "big").to_bytes(32, "little")


# ---------------------------------------------------------------- reconstruction: tables
def full_cap(mask):
    return mask if mask < 8 else ((mask + 1) // 8) * 7


def cap_to_buckets(cap):
    if cap < 8:
        return 4 if cap < 4 else 8
    adj = cap * 8 // 7
    return 1 << (adj - 1).bit_length()


class Table:
    """hashbrown RawTable with SSE2 groups: ctrl bytes (with the 16-byte mirror) and payloads."""

    def __init__(self, size, seed, mut=frozenset()):
        self.size, self.seed, self.mut = size, seed, mut
        self.mask, self.growth_left, self.items, self.static = 0, 0, 0, True
        self.ctrl = bytearray(b"\xff" * 16)
        self.slots = {}

    def group(self, pos):
        return self.ctrl[pos:pos + 16]

    def insert_slot(self, h):
        pos, stride = h & self.mask, 0
        while True:
            g = self.group(pos)
            for bit in range(16):
                if g[bit] & 0x80:
                    i = (pos + bit) & self.mask
                    if self.ctrl[i] < 0x80 and "no_wrap_fix" not in self.mut:
                        i = next(b for b in range(16) if self.ctrl[b] & 0x80)
                    return i
            stride += 16
            pos = (pos + stride) & self.mask

    def find(self, h, key, eq):
        h2, pos, stride = h >> 57, h & self.mask, 0
        while True:
            g = self.group(pos)
            for bit in range(16):
                if g[bit] == h2:
                    i = (pos + bit) & self.mask
                    if eq(self.slots[i], key):
                        return i
            if 0xff in g:
                return None
            stride += 16
            pos = (pos + stride) & self.mask

    def set_ctrl(self, i, h2):
        self.ctrl[i] = h2
        if "no_mirror" not in self.mut:
            self.ctrl[((i - 16) & self.mask) + 16] = h2

    def put(self, i, h, payload):
        old = self.ctrl[i]
        self.set_ctrl(i, h >> 57)
        self.growth_left -= old & 1
        self.items += 1
        self.slots[i] = payload

    def resize(self, additional, hasher):
        cap = max(self.items + additional, full_cap(self.mask) + 1)
        buckets = cap_to_buckets(cap)
        old = [(i, self.slots[i]) for i in sorted(self.slots)]
        self.mask, self.static = buckets - 1, False
        self.ctrl = bytearray(b"\xff" * (buckets + 16))
        self.slots = {}
        for _, payload in old:
            h = hasher(payload)
            i = self.insert_slot(h)
            self.set_ctrl(i, h >> 57)
            self.slots[i] = payload
        self.growth_left = full_cap(self.mask) - self.items


class Entry:
    def __init__(self, addr, pad, inner):
        self.addr, self.pad, self.inner = addr, pad, inner



def hash_slot_key(key, seed, g0, mut=frozenset()):
    """0x4e336b4..0x4e336df: account-storage key hash over four U256 limbs."""
    k = [w64(key, 8 * i) for i in range(4)]
    if "key_limb_swap" in mut:
        k[2], k[3] = k[3], k[2]
    return fold(fold(k[1] ^ g0, k[0] ^ seed) ^ k[2], k[3] ^ g0)


# ---------------------------------------------------------------- reconstruction: one world
class World:
    """Model state: the touched account (status byte + storage table), access-list warm map, journal."""

    def __init__(self, c, mut=frozenset()):
        self.g, self.mut, self.txid = list(c["g"]), mut, c["txid"]
        self.accounts = {a["addr"]: a for a in c["accounts"]}
        self.status = {a["addr"]: a["status"] for a in c["accounts"]}
        self.storage = {a["addr"]: clone_table(a["storage"], mut) for a in c["accounts"]}
        self.warm = c["warm"]
        self.journal = [bytes(e) for e in c["journal"]]
        self.events = []
        self.db = c["db"]

    def push(self, entry):
        if len(self.journal) == self.cap:
            self.events.append(("journal_grow", len(self.journal)))
            self.cap = grow_cap(self.cap)
        self.journal.append(bytes(entry))

    def in_access_list(self, addr, key):
        mp = self.warm
        if mp.items == 0:
            return False
        h = hash_addr(addr, mp.seed, self.g[0], self.mut)
        i = mp.find(h, addr, lambda e, k: e.addr == k)
        if i is None:
            return False
        s = mp.slots[i].inner
        if s.items == 0 and "probe_empty_set" not in self.mut:
            return False
        hk = hash_u256(key, s.seed, self.g, self.mut)
        return s.find(hk, key, lambda a, b: a == b) is not None

    def sload(self, addr, key, skip, created):
        """0x4e33680: (dl, slot index or None).  dl 0 = warm, 1 = cold (journal tag 9), 2 = cold load skipped."""
        mut = self.mut
        st = self.storage[addr]
        h = hash_slot_key(key, st.seed, self.g[0], mut)
        i = st.find(h, key, lambda p, k: p[:32] == k)
        txid = self.txid
        pad = bytes([STACK_FILL]) * 3
        if i is not None:
            p = st.slots[i]
            same_tx = int.from_bytes(p[0x60:0x64], "little") == txid
            if same_tx and p[0x64] == 0 and "always_check" not in mut:
                return 0, i
            cold = not self.in_access_list(addr, key)
            if cold and skip and "ignore_skip" not in mut:
                return 2, ("hit", i)
            if (not same_tx or "copy_only_new_tx" not in mut) and "no_original_copy" not in mut:
                p[0x20:0x40] = p[0x40:0x60]
            p[0x60:0x64] = txid.to_bytes(4, "little")
            p[0x64] = 0
        else:
            if st.growth_left == 0:
                self.events.append(("reserve", st.items, 1))
                st.resize(1, lambda q: hash_slot_key(q[:32], st.seed, self.g[0], mut))
            cold = not self.in_access_list(addr, key)
            if cold and skip and "ignore_skip" not in mut:
                return 2, ("miss", None)
            if created and "created_reads_db" not in mut:
                value = bytes(32)
            else:
                self.events.append(("db", addr.hex(), key.hex()))
                value = db_value(self.db, addr, key)
                pad = key[:3]
            p = bytearray(SLOT_SIZE)
            p[0:32] = key
            p[32:64] = value
            p[64:96] = value if "present_zero" not in mut else bytes(32)
            p[0x60:0x64] = txid.to_bytes(4, "little")
            p[0x64] = 0
            i = st.insert_slot(h)
            st.put(i, h, p)
        if cold:
            e = bytearray([JOURNAL_FILL]) * ENTRY
            e[0] = TAG_WARM
            e[1:0x15] = addr
            e[0x15:0x18] = pad
            e[0x18:0x38] = key
            self.push(e)
            return 1, i
        return 0, i

    def sstore(self, addr, key, new, skip):
        """0x2977910 (and its position twin 0x2977cd0): bytes of the 0x61-byte result written to *out."""
        mut = self.mut
        out = {}
        if addr not in self.accounts:
            return {0: 0, 0x60: 2}
        st = self.status[addr]
        if not st & 4 or "always_touch" in mut:
            self.status[addr] = st | 4
            e = bytearray([JOURNAL_FILL]) * ENTRY
            e[0] = TAG_TOUCH
            e[1:0x15] = addr
            self.push(e)
        dl, i = self.sload(addr, key, skip, self.status[addr] & 1)
        if dl == 2:
            return {0: 0, 0x60: 2}
        p = self.storage[addr].slots[i]
        res = bytes(p[0x20:0x60]) + bytes(new)
        if p[0x40:0x60] != new or "always_journal" in mut:
            old = bytes(p[0x40:0x60])
            p[0x40:0x60] = new
            e = bytearray([JOURNAL_FILL]) * ENTRY
            e[0] = TAG_CHANGE
            e[1:0x15] = addr
            e[0x15:0x18] = key[:3]
            e[0x18:0x38] = key
            e[0x38:0x58] = old
            self.push(e)
        for k, b in enumerate(res):
            out[k] = b
        out[0x60] = dl & 1
        return out


def grow_cap(cap):
    return max(4, 2 * cap)


def db_value(db, addr, key):
    if (addr, key) in db:
        return db[(addr, key)]
    return hashlib.sha256(b"re11-db" + addr + key).digest()


def clone_table(t, mut):
    n = Table(t.size, t.seed, mut)
    n.mask, n.growth_left, n.items, n.static = t.mask, t.growth_left, t.items, t.static
    n.ctrl = bytearray(t.ctrl)
    n.slots = {i: bytearray(p) for i, p in t.slots.items()}
    return n


def canon_storage(t):
    return (t.mask, t.growth_left, t.items, t.seed, bytes(t.ctrl), t.static,
            tuple((i, bytes(t.slots[i])) for i in sorted(t.slots)))


def model(c, mut=frozenset()):
    w = World(c, mut)
    w.cap = c["jcap"]
    a = c["target"]
    if c["fn"] == "sload":
        dl, i = w.sload(a, c["key"], c["skip"], w.status[a] & 1)
        if dl == 2:
            ret = (2, "key+8" if i[0] == "miss" else ("slot", i[1]))
        else:
            ret = (dl, ("slot", i))
        out = None
    else:
        ret = None
        out = w.sstore(a, c["key"], c["new"], c["skip"])
    st = w.storage.get(a)
    return {"ret": ret, "out": out, "events": w.events, "journal": tuple(w.journal), "jcap": w.cap,
            "status": w.status.get(a), "storage": canon_storage(st) if st is not None else None}


# ---------------------------------------------------------------- harness
class Heap:
    def __init__(self, m, at, size):
        self.buf = m.add_region(at, size)
        self.at, self.next, self.end = at, at, at + size

    def alloc(self, n):
        at = self.next
        self.next += (n + 15) & ~15
        if self.next > self.end:
            fail("synthetic heap exhausted")
        return at


def write_table(m, heap, t, at, payload_bytes):
    """Place a model Table at header address `at` (ctrl, mask, growth, items, seed)."""
    if t.static:
        ctrl = EMPTY_CTRL
    else:
        buckets = t.mask + 1
        base = heap.alloc(buckets * t.size + buckets + 16)
        ctrl = base + buckets * t.size
        for k in range(buckets + 16):
            m.store(ctrl + k, 1, t.ctrl[k])
        for i, p in t.slots.items():
            raw = payload_bytes(p)
            for k in range(0, t.size, 8):
                m.store(ctrl - (i + 1) * t.size + k, 8, int.from_bytes(raw[k:k + 8], "little"))
    for k, v in enumerate((ctrl, t.mask, t.growth_left, t.items, t.seed)):
        m.store(at + 8 * k, 8, v)


def read_storage(m, at):
    ctrl, mask, gl, items, seed = (m.load(at + 8 * k, 8) for k in range(5))
    static = ctrl == EMPTY_CTRL
    if mask > 0x10000:
        fail("table mask out of range")
    cb = bytes(m.load(ctrl + k, 1) for k in range(16 if static else mask + 1 + 16))
    rows = []
    if not static:
        for i in range(mask + 1):
            if cb[i] < 0x80:
                b = ctrl - (i + 1) * SLOT_SIZE
                rows.append((i, b"".join(m.load(b + k, 8).to_bytes(8, "little") for k in range(0, SLOT_SIZE, 8))))
    return (mask, gl, items, seed, cb, static, tuple(rows))


def setup(m, c):
    image = m.image
    events = []
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    ctx = m.add_region(CTX_AT, CTX_SIZE, c["ctx"])
    m.add_region(OUT_AT, 0x80, bytes([OUT_FILL]) * 0x80)
    args = m.add_region(ARG_AT, 0x100, bytes([0x44]) * 0x100)
    args[0:20] = c["target"]
    args[0x20:0x40] = c["key"]
    if c["fn"] == "sstore":
        args[0x40:0x60] = c["new"]
    seeds = m.add_region(SEED_AT, 0x40)
    for k in range(6):
        put(seeds, 8 * k, 8, c["g"][k])
    seeds[0x30] = 2
    tables = Heap(m, TABLE_AT, TABLE_SIZE)
    heap = Heap(m, HEAP_AT, HEAP_SIZE)
    # account map: bucket = address, filler, storage table header at +0x18, status byte at +0xa4
    amap = c["amap"]

    def acct_bytes(a):
        raw = bytearray(a["filler"])
        raw[0:20] = a["addr"]
        raw[STATUS] = a["status"]
        return raw
    write_table(m, tables, amap, CTX_AT + ACCT_TABLE, lambda a: acct_bytes(a))
    acct_at = {}
    for i, a in amap.slots.items():
        b = m.load(CTX_AT + ACCT_TABLE, 8) - (i + 1) * ACCT_SIZE
        acct_at[a["addr"]] = b
        write_table(m, tables, a["storage"], b + ACCT_STRUCT, bytes)
    # warm map at +0x2e0
    warm = c["warm"]

    def warm_bytes(e):
        return bytes(e.addr) + bytes(e.pad) + bytes(0x28)
    write_table(m, tables, warm, CTX_AT + WARM_AT, warm_bytes)
    if not warm.static:
        wctrl = m.load(CTX_AT + WARM_AT, 8)
        for i, e in warm.slots.items():
            write_table(m, tables, e.inner, wctrl - (i + 1) * WARM_SIZE + 0x18, bytes)
    # journal Vec at +0x288
    jptr = heap.alloc(ENTRY * max(1, c["jcap"]))
    for k in range(ENTRY * max(1, c["jcap"])):
        m.store(jptr + k, 1, JOURNAL_FILL)
    for j, e in enumerate(c["journal"]):
        for k in range(ENTRY):
            m.store(jptr + ENTRY * j + k, 1, e[k])
    m.store(CTX_AT + J_CAP, 8, c["jcap"])
    m.store(CTX_AT + J_PTR, 8, jptr)
    m.store(CTX_AT + J_LEN, 8, len(c["journal"]))
    m.store(CTX_AT + TXID_AT, 4, c["txid"])
    m.store(CTX_AT + DB_AT, 8, DB_PTR)
    put(ctx, 0, 0, 0)

    def grow(mc):
        v = mc.regs[7]
        if v != CTX_AT + J_CAP:
            fail(f"journal grow argument {v:#x}")
        cap, ptr, ln = (mc.load(v + 8 * k, 8) for k in range(3))
        if ln != cap:
            fail("journal grow called with spare capacity")
        events.append(("journal_grow", ln))
        ncap = grow_cap(cap)
        nptr = heap.alloc(ENTRY * ncap)
        for k in range(ENTRY * ncap):
            mc.store(nptr + k, 1, mc.load(ptr + k, 1) if k < ENTRY * ln else JOURNAL_FILL)
        mc.store(v, 8, ncap)
        mc.store(v + 8, 8, nptr)

    def reserve(mc):
        t, add, hasher, fallible = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1] & 0xffffffff
        if hasher != t + 0x20 or fallible != 1:
            fail(f"reserve arguments {hasher:#x}/{fallible}")
        items, mask, seed = mc.load(t + 0x18, 8), mc.load(t + 8, 8), mc.load(t + 0x20, 8)
        events.append(("reserve", items, add))
        g0 = mc.load(SEED_AT, 8)
        cap = max(items + add, full_cap(mask) + 1)
        buckets = cap_to_buckets(cap)
        base = heap.alloc(buckets * SLOT_SIZE + buckets + 16)
        ctrl = base + buckets * SLOT_SIZE
        mt = Table(SLOT_SIZE, seed)
        mt.mask, mt.ctrl = buckets - 1, bytearray(b"\xff" * (buckets + 16))
        old = mc.load(t, 8)
        for i in range(mask + 1 if old != EMPTY_CTRL else 0):
            if mc.load(old + i, 1) < 0x80:
                b = old - (i + 1) * SLOT_SIZE
                payload = bytes(mc.load(b + k, 1) for k in range(SLOT_SIZE))
                h = hash_slot_key(payload[:32], seed, g0)
                j = mt.insert_slot(h)
                mt.set_ctrl(j, h >> 57)
                for k in range(SLOT_SIZE):
                    mc.store(ctrl - (j + 1) * SLOT_SIZE + k, 1, payload[k])
        for k in range(buckets + 16):
            mc.store(ctrl + k, 1, mt.ctrl[k])
        mc.store(t, 8, ctrl)
        mc.store(t + 8, 8, buckets - 1)
        mc.store(t + 0x10, 8, full_cap(buckets - 1) - items)

    def db(mc):
        out, dbp, ap, kp = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        if dbp != DB_PTR:
            fail(f"database argument {dbp:#x}")
        addr = bytes(mc.load(ap + k, 1) for k in range(20))
        key = bytes(mc.load(kp + k, 1) for k in range(32))
        events.append(("db", addr.hex(), key.hex()))
        v = db_value(c["db"], addr, key)
        for k in range(32):
            mc.store(out + k, 1, v[k])

    m.stubs = {image.word(GROW_GOT): grow, image.word(RESERVE_GOT): reserve, DB_FN: db}
    return ctx, events, acct_at


def run_case(m, c, entry):
    m.reset()
    ctx, events, acct_at = setup(m, c)
    before = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in (CTX_AT, ARG_AT)}
    a = c["target"]
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    if c["fn"] == "sload":
        fr = m.add_region(FRAME_AT, 0x40, bytes([0x66]) * 0x40)
        put(fr, 0, 8, acct_at[a] + ACCT_STRUCT)
        put(fr, 8, 8, CTX_AT + J_CAP)
        put(fr, 0x10, 8, CTX_AT + WARM_AT)
        put(fr, 0x18, 8, CTX_AT + DB_AT)
        put(fr, 0x20, 4, c["txid"])
        fr[0x24:0x38] = a
        m.regs[7], m.regs[6], m.regs[2] = FRAME_AT, ARG_AT + 0x20, c["skip_reg"]
        start = SLOAD
    else:
        m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, CTX_AT, ARG_AT, ARG_AT + 0x20, ARG_AT + 0x40
        m.regs[9] = c["skip_reg"]
        start = entry
    got = {"events": events}
    try:
        m.run(start, limit=400000)
    except Boundary as b:
        got["boundary"] = b.kind
        return got
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    if c["fn"] == "sload":
        dl, rax = m.regs[2] & 0xff, m.regs[0]
        if dl == 2 and rax == ARG_AT + 0x28:
            got["ret"] = (2, "key+8")
        else:
            ctrl = m.load(acct_at[a] + ACCT_STRUCT, 8)
            off = ctrl - rax + 0x20
            got["ret"] = (dl, ("slot", off // SLOT_SIZE - 1) if off % SLOT_SIZE == 0 and off > 0 else ("ptr", rax))
        got["out"] = None
    else:
        got["ret"] = None
        ob = [m.load(OUT_AT + k, 1) for k in range(0x80)]
        got["out"] = {k: ob[k] for k in range(0x61) if ob[k] != OUT_FILL or k in (0, 0x60)}
        got["out_tail_ok"] = all(b == OUT_FILL for b in ob[0x61:])
    jptr, jlen = m.load(CTX_AT + J_PTR, 8), m.load(CTX_AT + J_LEN, 8)
    got["journal"] = tuple(bytes(m.load(jptr + ENTRY * j + k, 1) for k in range(ENTRY)) for j in range(jlen))
    got["jcap"] = m.load(CTX_AT + J_CAP, 8)
    if a in acct_at:
        got["status"] = m.load(acct_at[a] + STATUS, 1)
        got["storage"] = read_storage(m, acct_at[a] + ACCT_STRUCT)
    else:
        got["status"], got["storage"] = None, None
    # every other context byte and every input byte is unchanged
    now = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in (CTX_AT, ARG_AT)}
    rest_c, was_c = bytearray(now[CTX_AT]), bytearray(before[CTX_AT])
    rest_c[J_CAP:J_LEN + 8] = was_c[J_CAP:J_LEN + 8]
    got["rest_ok"] = rest_c == was_c and now[ARG_AT] == before[ARG_AT]
    return got


def compare(c, want, got):
    if "boundary" in got:
        return False
    keys = ("ret", "events", "journal", "jcap", "status", "storage")
    if any(want[k] != got[k] for k in keys):
        return False
    if c["fn"] == "sstore":
        o = want["out"]
        full = {k: o.get(k, OUT_FILL) for k in range(0x61)}
        gfull = {k: got["out"].get(k, OUT_FILL) for k in range(0x61)}
        if full != gfull or not got["out_tail_ok"]:
            return False
    return got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
def rand_word(s):
    return int.from_bytes(s.take(8), "little")


def build_table(size, seed, items, hashf, buckets, dead, force_zero_growth):
    """Model Table holding `items` (payloads), placed by insertion, then `dead` of them tombstoned."""
    t = Table(size, seed)
    if buckets == 0:
        return t
    t.mask, t.static = buckets - 1, False
    t.ctrl = bytearray(b"\xff" * (buckets + 16))
    for p in items:
        h = hashf(p)
        i = t.insert_slot(h)
        t.set_ctrl(i, h >> 57)
        t.slots[i] = p
    t.items = len(items)
    for i in dead:
        if i in t.slots:
            t.set_ctrl(i, 0x80)
            del t.slots[i]
            t.items -= 1
    n_dead = sum(1 for k in range(buckets) if t.ctrl[k] == 0x80)
    t.growth_left = 0 if force_zero_growth else full_cap(t.mask) - t.items - n_dead
    if t.growth_left < 0:
        t.growth_left = 0
    return t


def pick_buckets(s, n):
    if n == 0:
        return s.pick([0, 0, 4, 8])
    need = cap_to_buckets(n)
    return need * s.pick([1, 1, 1, 2, 4])


def make_case(s, fn, mode):
    g = [rand_word(s) for _ in range(6)]
    txid = s.pick([0, 1, 0xffffffff, 0x80000000, int.from_bytes(s.take(4), "little")])
    n_acc = 1 + s.below(5)
    addrs = [s.take(20) for _ in range(n_acc)]
    if mode.get("addr_special"):
        addrs[0] = s.pick([bytes(20), b"\xff" * 20, bytes(19) + b"\x01"])
    target = addrs[0] if not mode.get("missing") else s.take(20)
    key_pool = [s.take(32) for _ in range(6)] + [bytes(32), b"\xff" * 32]
    accounts = []
    for a in addrs:
        status = s.below(256)
        n_slots = s.below(mode.get("max_slots", 6) + 1)
        dense_nb = s.pick([16, 32, 64]) if mode.get("dense") and a == addrs[0] else 0
        if dense_nb:  # nearly full table: probes cross groups with no EMPTY byte
            n_slots = full_cap(dense_nb - 1) - s.below(3)
        slots = []
        used = set()
        for _ in range(n_slots):
            k = s.pick(key_pool) if s.below(3) else s.take(32)
            if k in used:
                continue
            used.add(k)
            p = bytearray(SLOT_SIZE)
            p[0:32] = k
            p[32:64] = s.take(32)
            p[64:96] = p[32:64] if s.below(3) == 0 else s.take(32)
            tx = txid if s.below(2) else int.from_bytes(s.take(4), "little")
            p[0x60:0x64] = tx.to_bytes(4, "little")
            p[0x64] = s.pick([0, 0, 1, 0x80, 0xff])
            p[0x65:0x68] = s.take(3) if s.below(2) else bytes(3)
            slots.append(p)
        seed = rand_word(s)
        nb = dense_nb or pick_buckets(s, len(slots))
        if nb == 0 and slots:
            nb = cap_to_buckets(len(slots))
        dead = [s.below(max(1, nb))] if nb and s.below(4) == 0 else []
        if dense_nb:
            dead = [s.below(nb) for _ in range(s.below(3))]
        st = build_table(SLOT_SIZE, seed, slots,
                         (lambda q, seed=seed: hash_slot_key(q[:32], seed, g[0])), nb, dead,
                         nb and s.below(5) == 0)
        accounts.append({"addr": a, "status": status, "storage": st, "filler": s.take(ACCT_SIZE)})
    aseed = rand_word(s)
    amap = build_table(ACCT_SIZE, aseed, accounts, (lambda a: hash_addr(a["addr"], aseed, g[0])),
                       cap_to_buckets(len(accounts)) * s.pick([1, 1, 2]), [], False)
    if mode.get("empty_accounts"):
        amap = Table(ACCT_SIZE, aseed)
        accounts = []
    tgt = next((a for a in accounts if a["addr"] == target), None)
    # the key: an existing slot key or a fresh key
    existing = [bytes(p[:32]) for p in (tgt["storage"].slots.values() if tgt else [])]
    if existing and s.below(2):
        key = s.pick(existing)
    else:
        key = s.pick(key_pool) if s.below(2) else s.take(32)
    # access-list warm map
    wseed = rand_word(s)
    entries = []
    wa = [s.take(20) for _ in range(s.below(4) if not mode.get("dense") else s.pick([14, 28, 56]) - 1)]
    if s.below(3) and not mode.get("no_warm_target"):
        wa.append(target)
    for a in wa:
        sseed = rand_word(s)
        ks = [s.take(32) for _ in range(s.below(5) if not mode.get("dense") else s.pick([13, 27, 55]))]
        if a == target and s.below(2):
            ks.append(key)
        if s.below(6) == 0 and not mode.get("dense"):
            ks = []
        inner = build_table(SET_SIZE, sseed, [bytes(k) for k in ks],
                            (lambda q, sseed=sseed: hash_u256(q, sseed, g)),
                            cap_to_buckets(len(ks)) if ks else 0, [], False)
        inner.seed = sseed
        entries.append(Entry(a, s.take(4), inner))
    warm = build_table(WARM_SIZE, wseed, entries, (lambda e: hash_addr(e.addr, wseed, g[0])),
                       cap_to_buckets(len(entries)) if entries else s.pick([0, 4]), [], False)
    jlen = s.below(4)
    journal = [s.take(ENTRY) for _ in range(jlen)]
    jcap = jlen + s.pick([0, 0, 1, 3])
    skip_reg = s.pick([0, 1, 0x100, 0xff, 0x12345601, 0x7fffff00]) if fn == "sload" else s.pick([0, 1, 0x100, 0x2])
    c = {"fn": fn, "g": g, "txid": txid, "accounts": accounts, "amap": amap, "target": target, "key": key,
         "warm": warm, "journal": journal, "jcap": jcap, "skip_reg": skip_reg,
         "skip": (skip_reg & 0xff) != 0, "db": {}, "ctx": s.take(CTX_SIZE)}
    if fn == "sstore":
        present = None
        if tgt:
            st = tgt["storage"]
            hit = [p for p in st.slots.values() if bytes(p[:32]) == key]
            present = bytes(hit[0][64:96]) if hit else None
        c["new"] = present if present is not None and s.below(3) == 0 else s.pick([bytes(32), s.take(32)])
    return c


SLOAD_TOTAL = 1700
SSTORE_TOTAL = 1700


def all_cases():
    s = Stream("re11-storage-warm-115")
    out = []
    for fn, total in (("sload", SLOAD_TOTAL), ("sstore", SSTORE_TOTAL)):
        base = "sload" if fn == "sload" else "sstore"
        k = 0
        while k < total:
            r = s.below(10)
            mode = {}
            if r == 0:
                mode["max_slots"] = 40
            elif r == 1 and base == "sstore":
                mode[s.pick(["missing", "empty_accounts"])] = True
            elif r == 2:
                mode["addr_special"] = True
            elif r == 3:
                mode["no_warm_target"] = True
            elif r in (4, 5):
                mode["dense"] = True
            c = make_case(s, base, mode)
            c["entry"] = {"sload": SLOAD, "sstore": SSTORE_A}[fn]
            c["family"] = fn
            out.append(c)
            k += 1
    return out


# ---------------------------------------------------------------- static evidence
FUNCS = (SSTORE_A, SLOAD, HASH_U256, HASH_WRITE, HASH_BYTES)
CHECKED = (
    (0x2977924, "48 83 be 50 03 00 00 00", "account map items +0x350 == 0 -> failure"),
    (0x297794d, "48 33 96 58 03 00 00", "account map seed +0x358"),
    (0x29779c1, "4d 69 e4 a8 00 00 00", "account bucket stride 0xa8"),
    (0x2977a46, "4c 8d 86 e0 02 00 00", "access-list warm map +0x2e0 passed to sload"),
    (0x2977a85, "f6 c2 04", "touched status bit 0x04"),
    (0x2977ac3, "c6 04 10 02", "journal tag 2 (account touched)"),
    (0x2977b04, "ff 15 86 f2 b6 03", "call through GOT 0x64e6d90 (sload)"),
    (0x2977c1e, "c6 04 08 08", "journal tag 8 (storage changed)"),
    (0x2977b0f, "c6 03 00", "failure result byte 0"),
    (0x4e336e5, "49 c1 ed 39", "slot hash h2 = h >> 57"),
    (0x4e33752, "4d 6b db 68", "storage bucket stride 0x68"),
    (0x4e337e2, "41 39 6c 24 f8", "slot transaction id compare"),
    (0x4e337e9, "41 80 7c 24 fc 00", "slot cold byte compare"),
    (0x4e33af1, "48 c1 e6 05", "warm set bucket stride 32"),
    (0x4e33873, "49 c1 e2 06", "warm map bucket stride 64"),
    (0x4e33c52, "f6 44 24 07 01", "created status bit 0x01 skips the database read"),
    (0x4e33cb4, "e8 27 e3 60 00", "direct call 0x5441fe0 (database read)"),
    (0x4e33e24, "c6 04 08 09", "journal tag 9 (storage warmed)"),
    (0x4e33e97, "ff 15 8b 31 6b 01", "call through GOT 0x64e7028 (storage reserve)"),
    (0x4e623d0, "b8 04 00 00 00", "U256 length prefix 4"),
)


def static_evidence(image):
    rows = fde_rows(image, FUNCS + (SSTORE_B, SLOAD_B))
    decoded, funcs = {}, {}
    for f in FUNCS:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    a = image.code(SSTORE_A, rows[SSTORE_A][1] - SSTORE_A)
    b = image.code(SSTORE_B, rows[SSTORE_B][1] - SSTORE_B)
    if len(a) != len(b):
        fail("twin lengths differ")
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    twin = []
    for va, form in decoded[SSTORE_A]:
        if form is None:
            continue
        i = va - SSTORE_A
        if any(i <= d < i + form["len"] for d in diffs):
            rm = form.get("rm")
            if not (rm and rm[1] == "rip"):
                fail(f"twin difference outside a RIP-relative operand at {va:#x}")
            ta = (va + form["len"] + rm[4]) & M64
            fb = decode(image.code(SSTORE_B + i, 16), SSTORE_B + i)
            tb = (SSTORE_B + i + fb["len"] + fb["rm"][4]) & M64
            row = {"offset": f"{i:#x}", "a": f"{va:#x}", "b": f"{SSTORE_B + i:#x}", "rip_target_a": f"{ta:#x}",
                   "rip_target_b": f"{tb:#x}", "same_target": ta == tb}
            if ta != tb:
                row["slot_target_a"] = f"{image.word(ta):#x}"
                row["slot_target_b"] = f"{image.word(tb):#x}"
            twin.append(row)
    slots = {}
    for name, slot in (("global_seed_block", SEED_GOT), ("byte_hasher", BYTES_GOT), ("storage_reserve", RESERVE_GOT),
                       ("journal_grow", GROW_GOT), ("sload", SLOAD_GOT)):
        if slot in image.imports:
            fail(f"{name} slot is not a RELATIVE relocation")
        slots[name] = {"slot": f"{slot:#x}", "relocation": "RELATIVE", "target": f"{image.word(slot):#x}"}
    if image.word(SLOAD_GOT) != SLOAD or image.word(BYTES_GOT) != HASH_BYTES:
        fail("GOT targets changed")
    checks = {}
    for va, hx, what in CHECKED:
        want = bytes.fromhex(hx)
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "slots": slots, "checked_bytes": checks,
           "twin_rip_operands": twin, "twin_differing_bytes": len(diffs),
           "empty_table_template": {"address": f"{TEMPLATE:#x}", "ctrl": f"{image.word(TEMPLATE):#x}"},
           "context_offsets": {"journal_cap": f"{J_CAP:#x}", "journal_ptr": f"{J_PTR:#x}", "journal_len": f"{J_LEN:#x}",
                               "warm_map": f"{WARM_AT:#x}", "transaction_id": f"{TXID_AT:#x}", "database": f"{DB_AT:#x}",
                               "account_map": f"{ACCT_TABLE:#x}", "account_items": f"{ACCT_ITEMS:#x}",
                               "account_seed": f"{ACCT_SEED:#x}"},
           "bucket_sizes": {"account": ACCT_SIZE, "storage_slot": SLOT_SIZE, "warm_address": WARM_SIZE,
                            "warm_key": SET_SIZE, "journal_entry": ENTRY},
           "journal_tags": {"account_touched": TAG_TOUCH, "storage_changed": TAG_CHANGE, "storage_warmed": TAG_WARM}}
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
    global EMPTY_CTRL, SEED_AT
    EMPTY_CTRL = image.word(TEMPLATE)
    SEED_AT = image.word(SEED_GOT)
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else all_cases()):
        try:
            want = model(c, mut)
            got = run_case(m, c, c["entry"])
            ok = compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        rows.append((c["family"], i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


MODEL_MUTANTS = ["key_limb_swap", "always_check", "ignore_skip", "no_original_copy", "created_reads_db",
                 "present_zero", "always_touch", "always_journal", "addr_swap", "prefix_one", "no_rol",
                 "no_wrap_fix", "no_mirror", "medium_ge32"]
BYTE_MUTANTS = [
    (0x4e336e8, 0x38, "slot hash h2 shift 57 -> 56"),
    (0x4e33755, 0x60, "storage bucket stride 0x68 -> 0x60"),
    (0x4e337ed, 0xfd, "slot cold byte displacement -4 -> -3"),
    (0x4e3377f, 0xfe, "slot key-equality mask 0xffff -> 0xfffe"),
    (0x4e33af4, 0x06, "warm set bucket stride shift 5 -> 6"),
    (0x4e33c56, 0x02, "created status bit 0x01 -> 0x02"),
    (0x4e33e27, 0x0a, "journal tag 9 -> 10"),
    (0x4e623d1, 0x05, "U256 length prefix 4 -> 5"),
    (0x2977a87, 0x08, "touched status bit 0x04 -> 0x08"),
    (0x2977c21, 0x07, "journal tag 8 -> 7"),
    (0x29779c4, 0xa0, "account bucket stride 0xa8 -> 0xa0"),
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
def event_text(events):
    parts = []
    for e in events:
        parts.append(e[0] + ":" + ",".join((f"{x:#x}" if isinstance(x, int) else x[:8]) for x in e[1:]))
    return ";".join(parts) or "-"


def outcome(c, got):
    if "error" in got or "boundary" in got:
        return "error"
    names = sorted(set(e[0] for e in got["events"]))
    tags = "".join(str(e[0]) for e in got["journal"][len(c["journal"]):])
    if c["fn"] == "sload":
        dl = got["ret"][0]
        head = ["warm", "cold", "skipped"][dl] if dl in (0, 1, 2) else f"dl{dl}"
    else:
        r = got["out"].get(0x60, OUT_FILL)
        head = "fail" if r == 2 else ("cold" if r == 1 else "warm")
    return f"{head}/j{tags or '-'}/{'+'.join(names) or '-'}"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    rows, bad, m = evaluate(image, cases=cases)
    consts, decoded = static_evidence(image)
    lines = ["family\tcase\tinput\toutcome\tevents\tresult\tmatch"]
    classes = {}
    for fam, i, c, want, got, ok in rows:
        oc = outcome(c, got)
        tgt = next((a for a in c["accounts"] if a["addr"] == c["target"]), None)
        inp = (f"accts={len(c['accounts'])},slots={tgt['storage'].items if tgt else '-'},"
               f"status={tgt['status'] if tgt else '-':}," if tgt else f"accts={len(c['accounts'])},target=missing,")
        inp += f"warm={c['warm'].items},jlen={len(c['journal'])},jcap={c['jcap']},skip={int(c['skip'])}"
        if "error" in got or "boundary" in got:
            res = got.get("error", got.get("boundary"))
        else:
            st = got["storage"]
            res = (f"ret={got['ret']},out={hashlib.sha256(repr(sorted((got['out'] or {}).items())).encode()).hexdigest()[:12]},"
                   f"journal={len(got['journal'])}/{got['jcap']},status={got['status']},"
                   f"storage={hashlib.sha256(repr(st).encode()).hexdigest()[:12] if st else '-'}")
        ev = event_text(got.get("events", []))
        classes[f"{fam}:{oc}"] = classes.get(f"{fam}:{oc}", 0) + 1
        lines.append(f"{fam}\t{i}\t{inp}\t{oc}\t{ev}\t{res}\t{'yes' if ok else 'NO'}")
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
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
    summary = {
        "binary_sha256": SHA256, "cases": len(rows), "mismatches": bad,
        "family_cases": {f: sum(1 for r in rows if r[0] == f) for f in ("sload", "sstore")},
        "covered_instructions": covered, "outcome_classes": classes,
        "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)},
    }
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
