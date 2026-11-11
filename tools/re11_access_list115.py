#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM access-list warm-set loader 0x2668ac2..0x2668e7a.

When the context byte +0x1f1 is nonzero, 0x2668a20 builds a fresh
HashMap<Address, HashSet<U256>> from the transaction access list (items of 0x30 bytes at
context +0x178, count +0x180: address at +0x18, storage-key Vec ptr +0x8 / len +0x10) and
installs it at context +0x2e0 after dropping the previous map (0x2a03a10), then writes
0x25 to the result.  Each map and set takes a per-table foldhash seed derived from a TLS
counter (fs:-0x578) mixed with the stack address; addresses are looked up through the entry
probe 0x2a318d0 (hash with the per-map seed and global seed word 0), storage keys are
byte-swapped from 32-byte big-endian words into U256 limbs and inserted through 0x2a32b00,
whose hasher 0x24b6e30/0x24b7080 feeds a length prefix and the 32 key bytes to the foldhash
byte hasher 0x1770830 (global seed words at 0x64ffe90, lazy init 0x1770b40 when the state
byte +0x30 is not 2).  The tool reads every relocation, FDE extent and code byte from the
ELF file, evaluates the real machine code with a small concrete x86-64 evaluator (no
external programs, the binary is never executed) and compares every case with one
pure-Python reconstruction (foldhash + SSE2 hashbrown probing).  Negative controls show
that wrong reconstructions and corrupted code bytes are detected.
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
OWNER = 0x2668a20  # FDE start of the function that holds the loader
LOADER, LOADER_END = 0x2668ac2, 0x2668e7a  # loop + tail + lazy-init island, to the FDE end
PROBE, INSERT, HASH_U256, HASH_WRITE, HASH_BYTES = 0x2a318d0, 0x2a32b00, 0x24b6e30, 0x24b7080, 0x1770830
DROP_FN = 0x2a03a10  # direct call at 0x2668e09: drop of the previous map at +0x2e0
SEED_GOT, BYTES_GOT, INIT_GOT = 0x64dfa78, 0x64dfa80, 0x64e22e8
RESERVE_MAP_GOT, RESERVE_SET_GOT, PANIC_GOT = 0x64e7030, 0x64dfab8, 0x64df848
TEMPLATE = 0x64371f8  # 32-byte empty table copied into every new map and set
PSUBQ_CONST = 0x450790  # shufpd source at 0x2a32c27
C_TLS, C_SEED = 0x13198a2e03707344, 0xa4093822299f31d0
TLS_OFF = -0x578
FS_BASE = 0x7b00_0000_2000
EMPTY_CTRL = None  # read from the template at run time

# context offsets used by the loader
LIST_PTR, LIST_LEN, MAP_AT, OUT_TAG = 0x178, 0x180, 0x2e0, 0x25
ITEM = 0x30

CTX_AT = 0x7d00_0000_0000
CTX_SIZE = 0x400
OUT_AT = 0x7d00_0100_0000
LIST_AT = 0x7d00_0200_0000
KEYS_AT = 0x7d00_0300_0000
HEAP_AT = 0x7d00_1000_0000
HEAP_SIZE = 0x40000
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]  # rbx r12 r13 r14 r15 rbp


def fold(a, b):
    p = (a & M64) * (b & M64)
    return (p & M64) ^ (p >> 64)


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M64


# ---------------------------------------------------------------- reconstruction: hashes
def w64(data, at):
    return int.from_bytes(data[at:at + 8], "little")


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


def canon_table(t, inner):
    rows = []
    for i in sorted(t.slots):
        p = t.slots[i]
        rows.append((i, (p.addr, p.pad, canon_table(p.inner, False)) if inner else bytes(p)))
    return (t.mask, t.growth_left, t.items, t.seed, bytes(t.ctrl), t.static, tuple(rows))


def loader_model(c, mut=frozenset()):
    """Pure reconstruction of 0x2668ac2..0x2668e51 for one case."""
    events = []
    tls, frame = c["tls"], c["frame"]
    tls = fold(tls ^ C_TLS, frame)
    map_seed = fold(tls, C_SEED) if "map_seed_raw" not in mut else tls
    g = list(c["seeds"])
    if c["state"] != 2 and "no_init" not in mut:
        events.append(("init",))
        g = list(c["init_seeds"])
    outer = Table(64, map_seed, mut)
    pad = (frame + 0x60) & 0xffffffff
    if "pad_zero" in mut:
        pad = 0

    def map_hash(e):
        return hash_addr(e.addr, map_seed, g[0], mut)

    for addr, keys in c["items"]:
        h = hash_addr(addr, map_seed, g[0], mut)
        idx = outer.find(h, addr, lambda e, k: e.addr == k)
        if idx is None:
            if outer.growth_left == 0:
                events.append(("reserve_map", outer.items, 1))
                outer.resize(1, map_hash)
            if "seed_no_chain" not in mut:
                tls = fold(tls ^ C_TLS, frame)
            inner = Table(32, fold(tls, C_SEED), mut)
            idx = outer.insert_slot(h)
            outer.put(idx, h, Entry(addr, pad.to_bytes(4, "little"), inner))
        s = outer.slots[idx].inner
        n = len(keys)
        add = n if s.items == 0 or "add_full" in mut else (n + 1) // 2
        sh = (lambda k, s=s: hash_u256(k, s.seed, g, mut))
        if add > s.growth_left:
            events.append(("reserve_set", s.items, add))
            s.resize(add, sh)
        for word in keys:
            limbs = key_limbs(word, mut)
            hk = sh(limbs)
            if s.growth_left == 0:
                events.append(("reserve_set", s.items, 1))
                s.resize(1, sh)
            if s.find(hk, limbs, lambda a, b: a == b) is None:
                s.put(s.insert_slot(hk), hk, limbs)
    events.append(("drop", CTX_AT + MAP_AT))
    return {"map": canon_table(outer, True), "events": events, "tls": tls, "tag": OUT_TAG}


# ---------------------------------------------------------------- harness
class Heap:
    def __init__(self, m):
        self.buf = m.add_region(HEAP_AT, HEAP_SIZE)
        self.next = HEAP_AT

    def alloc(self, n):
        at = self.next
        self.next += (n + 15) & ~15
        if self.next > HEAP_AT + HEAP_SIZE:
            fail("synthetic heap exhausted")
        return at


def read_table(m, at, size, inner):
    ctrl, mask, gl, items = (m.load(at + 8 * k, 8) for k in range(4))
    seed = m.load(at + 0x20, 8)
    static = ctrl == EMPTY_CTRL
    if mask > 0x10000:
        fail("table mask out of range")
    cb = bytes(m.load(ctrl + k, 1) for k in range(16 if static else mask + 1 + 16))
    rows = []
    if not static:
        for i in range(mask + 1):
            if cb[i] < 0x80:
                b = ctrl - (i + 1) * size
                if inner:
                    addr = bytes(m.load(b + k, 1) for k in range(20))
                    pad = bytes(m.load(b + 20 + k, 1) for k in range(4))
                    rows.append((i, (addr, pad, read_table(m, b + 0x18, 32, False))))
                else:
                    rows.append((i, bytes(m.load(b + k, 1) for k in range(size))))
    return (mask, gl, items, seed, cb, static, tuple(rows))


def table_payloads(m, at, size):
    ctrl, mask = m.load(at, 8), m.load(at + 8, 8)
    if ctrl == EMPTY_CTRL:
        return []
    return [(i, ctrl - (i + 1) * size) for i in range(mask + 1) if m.load(ctrl + i, 1) < 0x80]


def make_reserve(m, heap, size, events, kind, g_at):
    def stub(mc):
        t, add, seed_at = mc.regs[7], mc.regs[6], mc.regs[2]
        if seed_at != t + 0x20:
            fail(f"{kind} hasher argument {seed_at:#x} is not table+0x20")
        items, mask = mc.load(t + 0x18, 8), mc.load(t + 8, 8)
        events.append((kind, items, add))
        seed = mc.load(seed_at, 8)
        g = [mc.load(g_at + 8 * k, 8) for k in range(6)]
        cap = max(items + add, full_cap(mask) + 1)
        buckets = cap_to_buckets(cap)
        base = heap.alloc(buckets * size + buckets + 16)
        ctrl = base + buckets * size
        model = Table(size, seed)
        model.mask, model.ctrl = buckets - 1, bytearray(b"\xff" * (buckets + 16))
        for _, b in table_payloads(mc, t, size):
            payload = bytes(mc.load(b + k, 1) for k in range(size))
            h = hash_addr(payload[:20], seed, g[0]) if size == 64 else hash_u256(payload, seed, g)
            i = model.insert_slot(h)
            model.set_ctrl(i, h >> 57)
            for k in range(size):
                mc.store(ctrl - (i + 1) * size + k, 1, payload[k])
        for k in range(buckets + 16):
            mc.store(ctrl + k, 1, model.ctrl[k])
        mc.store(t, 8, ctrl)
        mc.store(t + 8, 8, buckets - 1)
        mc.store(t + 0x10, 8, full_cap(buckets - 1) - items)
    return stub


SEED_AT = None


def setup(m, c):
    """Context, access list, seeds, TLS and stubs for one loader case."""
    image = m.image
    events = []
    ctx = m.add_region(CTX_AT, CTX_SIZE, c["ctx"])
    m.add_region(OUT_AT, 0x40, bytes([0x33]) * 0x40)
    tls = m.add_region(FS_BASE - 0x1000, 0x1000)
    put(tls, 0x1000 + TLS_OFF, 8, c["tls"])
    seeds = m.add_region(SEED_AT, 0x40)
    for k in range(6):
        put(seeds, 8 * k, 8, c["seeds"][k])
    seeds[0x30] = c["state"]
    lst = m.add_region(LIST_AT, ITEM * max(1, len(c["items"])), bytes([0x44]) * ITEM * max(1, len(c["items"])))
    keybuf = m.add_region(KEYS_AT, 0x10000)
    kp = 0
    for j, (addr, keys) in enumerate(c["items"]):
        put(lst, ITEM * j, 8, 0x5000 + len(keys))  # Vec capacity (unused by the loader)
        put(lst, ITEM * j + 8, 8, KEYS_AT + kp)
        put(lst, ITEM * j + 0x10, 8, len(keys))
        lst[ITEM * j + 0x18:ITEM * j + 0x2c] = addr
        for word in keys:
            keybuf[kp:kp + 32] = word
            kp += 32
    put(ctx, LIST_PTR, 8, LIST_AT)
    put(ctx, LIST_LEN, 8, len(c["items"]))
    heap = Heap(m)

    def init(mc):
        events.append(("init",))
        for k in range(6):
            mc.store(SEED_AT + 8 * k, 8, c["init_seeds"][k])
        mc.store(SEED_AT + 0x30, 1, 2)

    def drop(mc):
        events.append(("drop", mc.regs[7]))

    def panic(mc):
        raise Boundary("panic", mc.regs)

    m.stubs = {image.word(INIT_GOT): init, DROP_FN: drop, image.word(PANIC_GOT): panic,
               image.word(RESERVE_MAP_GOT): make_reserve(m, heap, 64, events, "reserve_map", SEED_AT),
               image.word(RESERVE_SET_GOT): make_reserve(m, heap, 32, events, "reserve_set", SEED_AT)}
    return ctx, events


def run_loader(m, c):
    m.reset()
    ctx, events = setup(m, c)
    f = c["frame"]
    m.regs[4] = f
    for k in range(0, 0xb8, 8):
        m.store(f + k, 8, 0x5a5a5a5a5a5a5a5a)
    m.store(f + 0x40, 8, CTX_AT)
    m.store(f + 0x48, 8, OUT_AT)
    for k, v in enumerate(SAVED):
        m.store(f + 0xb8 + 8 * k, 8, v)
    m.store(f + 0xb8 + 48, 8, RETURN_MARK)
    m.regs[14], m.regs[15] = OUT_AT, CTX_AT
    pc, got = LOADER, {"events": events}
    try:
        while pc != RETURN_MARK:
            m.steps += 1
            if m.steps > 3_000_000:
                fail("step limit")
            pc = m.step(pc)
    except Boundary as b:
        got["boundary"] = b.kind
    got["steps"] = m.steps
    got["map"] = read_table(m, CTX_AT + MAP_AT, 64, True)
    got["tls"] = m.load(FS_BASE + TLS_OFF, 8)
    got["tag"] = m.load(OUT_AT, 8)
    got["regs_ok"] = [m.regs[r] for r in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == f + 0xb8 + 56
    got["rax"] = m.regs[0]
    rest, want = bytearray(ctx), bytearray(c["ctx"])
    rest[MAP_AT:MAP_AT + 0x28] = want[MAP_AT:MAP_AT + 0x28]
    put(want, LIST_PTR, 8, LIST_AT)
    put(want, LIST_LEN, 8, len(c["items"]))
    got["ctx_rest_ok"] = rest == want
    return got


def compare_loader(want, got):
    return (got.get("boundary") is None and got["map"] == want["map"] and got["events"] == want["events"]
            and got["tls"] == want["tls"] and got["tag"] == want["tag"] and got["regs_ok"]
            and got["ctx_rest_ok"] and got["rax"] == OUT_AT)


def run_direct(m, c):
    """Direct entry of a hash helper with a synthetic argument block."""
    m.reset()
    data = m.add_region(LIST_AT, 0x1000, c["data"])
    seeds = m.add_region(SEED_AT, 0x40)
    for k in range(6):
        put(seeds, 8 * k, 8, c["g"][k])
    seeds[0x30] = 2
    blk = m.add_region(KEYS_AT, 0x100)

    def panic(mc):
        raise Boundary("panic", mc.regs)

    m.stubs = {m.image.word(PANIC_GOT): panic}
    if c["fn"] == "bytes":
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = LIST_AT, len(c["data"]), c["seed"], SEED_AT
        start = HASH_BYTES
    elif c["fn"] == "write":
        acc0, acc1, seed, ln = c["state"]
        put(blk, 0, 8, acc0)
        put(blk, 8, 8, acc1)
        put(blk, 0x10, 8, SEED_AT)
        put(blk, 0x18, 8, seed)
        blk[0x20] = ln
        m.regs[7], m.regs[6] = LIST_AT, KEYS_AT
        start = HASH_WRITE
    else:
        put(blk, 0, 8, c["seed"])
        m.regs[7], m.regs[6] = KEYS_AT, LIST_AT
        start = HASH_U256
    try:
        m.run(start)
    except Boundary as b:
        return {"boundary": b.kind}
    if c["fn"] == "write":
        return {"state": (u(blk, 0, 8), u(blk, 8, 8), u(blk, 0x18, 8), blk[0x20]), "gptr": u(blk, 0x10, 8)}
    return {"rax": m.regs[0]}


def direct_model(c, mut=frozenset()):
    if c["fn"] == "bytes":
        r = bytes_hash(c["data"], c["seed"], c["g"], mut)
        return {"boundary": "panic"} if r is None else {"rax": r}
    if c["fn"] == "write":
        return {"state": write_model(c["state"], c["data"][:32], c["g"], mut), "gptr": SEED_AT}
    return {"rax": hash_u256(c["data"][:32], c["seed"], c["g"], mut)}


# ---------------------------------------------------------------- cases
def rand_word(s):
    return int.from_bytes(s.take(8), "little")


def make_loader_case(s, n_items, addr_pool, key_pool, max_keys, state=2):
    items = []
    for _ in range(n_items):
        addr = s.pick(addr_pool)
        nk = s.below(max_keys + 1)
        items.append((addr, [s.pick(key_pool) for _ in range(nk)]))
    ctx = bytearray(s.take(CTX_SIZE))
    return {"ctx": bytes(ctx), "items": items, "tls": rand_word(s), "frame": STACK_TOP - 0x2000 - 16 * s.below(256),
            "seeds": [rand_word(s) for _ in range(6)], "init_seeds": [rand_word(s) for _ in range(6)],
            "state": state}


def loader_cases():
    s = Stream("re11-access-list-loader-115")
    out = []
    special = [bytes(20), b"\xff" * 20, bytes(19) + b"\x01", b"\x01" + bytes(19)]
    kspecial = [bytes(32), b"\xff" * 32, bytes(31) + b"\x01", b"\x80" + bytes(31)]
    for n in range(0, 9):  # empty list, then growing lists with fresh addresses and no keys
        out.append(make_loader_case(s, n, [s.take(20) for _ in range(64)], kspecial, 0))
    for state in (0, 1, 3, 0xff):  # lazy global-seed init
        for n in (0, 1, 5):
            out.append(make_loader_case(s, n, [s.take(20) for _ in range(4)], kspecial, 3, state))
    while len(out) < LOADER_TOTAL:
        kind = s.below(6)
        if kind == 0:  # many distinct addresses: outer growth 4 -> 8 -> 16 -> 32 -> 64
            c = make_loader_case(s, 8 + s.below(48), [s.take(20) for _ in range(256)], kspecial, 1)
        elif kind == 1:  # repeated addresses: occupied entries, (n+1)/2 reserve heuristic
            c = make_loader_case(s, 2 + s.below(10), [s.take(20) for _ in range(3)] + special[:1],
                                 [s.take(32) for _ in range(40)], 12)
        elif kind == 2:  # duplicate keys inside one list
            c = make_loader_case(s, 1 + s.below(4), [s.take(20) for _ in range(2)],
                                 [s.take(32) for _ in range(5)] + kspecial, 20)
        elif kind == 3:  # one address with many keys: set growth past 16 buckets
            c = make_loader_case(s, 1, [s.take(20)], [s.take(32) for _ in range(400)], 60)
        elif kind == 4:  # special byte patterns
            c = make_loader_case(s, 1 + s.below(6), special, kspecial, 4)
        else:
            c = make_loader_case(s, s.below(14), [s.take(20) for _ in range(1 + s.below(12))],
                                 [s.take(32) for _ in range(1 + s.below(30))], s.below(9))
        if s.below(16) == 0:
            c["state"] = s.pick([0, 1, 3])
        out.append(c)
    return out


def direct_cases():
    s = Stream("re11-access-list-hashes-115")
    out = []
    for n in list(range(0, 16)) + list(range(16, 0x181)):  # every length up to 384 bytes, panic below 16
        out.append({"fn": "bytes", "data": s.take(n), "seed": rand_word(s), "g": [rand_word(s) for _ in range(6)]})
    while len(out) < BYTES_TOTAL:
        n = s.pick([16, 31, 32, 33, 63, 64, 95, 96, 127, 128, 129, 256, 257, 352, 353, 449, 1000, 2048, 4000]
                   + [16 + s.below(4080)])
        out.append({"fn": "bytes", "data": s.take(n), "seed": rand_word(s), "g": [rand_word(s) for _ in range(6)]})
    for ln in range(256):  # every sponge length byte, twice
        for _ in range(2):
            out.append({"fn": "write", "data": s.take(32), "g": [rand_word(s) for _ in range(6)],
                        "state": (rand_word(s), rand_word(s), rand_word(s), ln)})
    for _ in range(U256_TOTAL):
        out.append({"fn": "u256", "data": s.take(32), "seed": rand_word(s), "g": [rand_word(s) for _ in range(6)]})
    return out


LOADER_TOTAL = 1700
BYTES_TOTAL = 2600
U256_TOTAL = 700


# ---------------------------------------------------------------- static evidence
FUNCS = (OWNER, PROBE, INSERT, HASH_U256, HASH_WRITE, HASH_BYTES)


def static_evidence(image):
    rows = fde_rows(image, FUNCS)
    if rows[OWNER][1] != LOADER_END:
        fail("owner FDE end changed")
    ranges = {OWNER: (LOADER, LOADER_END)}
    for f in FUNCS[1:]:
        ranges[f] = rows[f]
    decoded = {}
    for f, (lo, hi) in ranges.items():
        decoded[f] = sweep_padded(image, lo, hi)
    funcs = {}
    for f in FUNCS:
        lo, hi = rows[f]
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "reconstructed_from": f"{ranges[f][0]:#x}",
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    slots = {}
    for name, slot in (("global_seed_block", SEED_GOT), ("byte_hasher", BYTES_GOT), ("lazy_init", INIT_GOT),
                       ("reserve_map", RESERVE_MAP_GOT), ("reserve_set", RESERVE_SET_GOT), ("panic", PANIC_GOT)):
        if slot in image.imports:
            fail(f"{name} slot is not a RELATIVE relocation")
        slots[name] = {"slot": f"{slot:#x}", "relocation": "RELATIVE", "target": f"{image.word(slot):#x}"}
    if image.word(BYTES_GOT) != HASH_BYTES:
        fail("byte hasher slot target changed")
    seed_sec = [s for s in image.secs if s["address"] <= SEED_AT < s["address"] + s["size"]]
    checks = {}
    for va, want in ((0x2668ac7, b"\x48\xb9" + C_TLS.to_bytes(8, "little")),
                     (0x2668b02, b"\x48\xb9" + C_SEED.to_bytes(8, "little")),
                     (0x2668ae4, b"\x64\x48\x8b\x04\x25" + (TLS_OFF & 0xffffffff).to_bytes(4, "little")),
                     (0x2668b1d, b"\x3c\x02"), (0x2668b70, b"\x49\x83\xc4\x30"),
                     (0x2668ad1, b"\x4d\x8b\xa7" + LIST_PTR.to_bytes(4, "little")),
                     (0x2668add, b"\x49\x8b\x9f" + LIST_LEN.to_bytes(4, "little")),
                     (0x2668e02, b"\x48\x8d\xbb" + MAP_AT.to_bytes(4, "little")),
                     (0x2668e36, b"\x49\xc7\x06" + OUT_TAG.to_bytes(4, "little")),
                     (0x2668d4f, b"\x48\x0f\xce"), (0x2a3190c, b"\x48\xc1\xef\x39"),
                     (0x177083b, b"\x48\x81\xfe\x81\x00\x00\x00"), (0x24b70a5, b"\xb8\x04\x00\x00\x00"),
                     (0x24b70e3, b"\x48\xc1\xc2\x20")):
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = want.hex()
    tmpl = [image.word(TEMPLATE + 8 * k) for k in range(4)]
    const = [image.word(PSUBQ_CONST), image.word(PSUBQ_CONST + 8)]
    out = {"binary_sha256": SHA256, "functions": funcs, "slots": slots, "checked_bytes": checks,
           "global_seed_block": {"address": f"{SEED_AT:#x}", "section": seed_sec[0]["name"] if seed_sec else None,
                                 "section_type": seed_sec[0]["type"] if seed_sec else None,
                                 "state_offset": "0x30", "initialised_state": 2},
           "empty_table_template": {"address": f"{TEMPLATE:#x}", "words": [f"{w:#x}" for w in tmpl],
                                    "empty_group_bytes": image.read(tmpl[0], 16).hex()},
           "insert_counter_constant": {"address": f"{PSUBQ_CONST:#x}", "words": [f"{w:#x}" for w in const]},
           "tls_counter": {"fs_offset": f"{TLS_OFF:#x}", "mix": f"{C_TLS:#x}", "seed_multiplier": f"{C_SEED:#x}"},
           "context_offsets": {"list_ptr": f"{LIST_PTR:#x}", "list_len": f"{LIST_LEN:#x}", "item_size": ITEM,
                               "item_keys_ptr": "0x8", "item_keys_len": "0x10", "item_address": "0x18",
                               "map": f"{MAP_AT:#x}", "result_tag": OUT_TAG},
           "bucket_sizes": {"map": 64, "set": 32}}
    return out, decoded


def sweep_padded(image, lo, hi):
    """Linear decode; int3 padding is recorded as None rows, raw jump bytes as an error."""
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
def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, only=None):
    global EMPTY_CTRL, SEED_AT
    EMPTY_CTRL = image.word(TEMPLATE)
    SEED_AT = image.word(SEED_GOT)
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    fams = (("loader", loader_cases), ("direct", direct_cases))
    for kind, gen in fams:
        if only and kind not in only:
            continue
        for i, c in enumerate(gen()):
            try:
                if kind == "loader":
                    want = loader_model(c, mut)
                    got = run_loader(m, c)
                    ok = compare_loader(want, got)
                else:
                    want = direct_model(c, mut)
                    got = run_direct(m, c)
                    ok = want == got
            except ToolError as exc:
                got, ok = {"error": str(exc)}, False
            bad += not ok
            rows.append((kind, i, c, want, got, ok))
            if stop_on_first and not ok:
                return rows, bad, m
    return rows, bad, m


MODEL_MUTANTS = ["medium_ge32", "prefix_one", "no_rol", "addr_swap", "no_bswap", "no_wrap_fix", "no_mirror",
                 "map_seed_raw", "no_init", "pad_zero", "seed_no_chain", "add_full"]
BYTE_MUTANTS = [  # (address, new byte, what the byte is)
    (0x2668ac9, 0x45, "TLS mix constant low byte 0x44 -> 0x45"),
    (0x2668b1e, 0x01, "global seed state compare 2 -> 1"),
    (0x2668b73, 0x28, "access-list item stride 0x30 -> 0x28"),
    (0x2668d19, 0xe6, "reserve heuristic shr $1 -> shl $1 (ModRM reg field)"),
    (0x2a3190f, 0x38, "probe h2 shift 57 -> 56"),
    (0x2a3198d, 0xfe, "probe key-equality mask 0xffff -> 0xfffe"),
    (0x2a32b2f, 0x38, "insert h2 shift 57 -> 56"),
    (0x24b70a6, 0x05, "U256 length prefix 4 -> 5"),
    (0x24b70e6, 0x1f, "seed rotation 32 -> 31"),
    (0x24b70ec, 0x21, "byte count 32 -> 33"),
    (0x1770881, 0x20, "medium cut 0x1f -> 0x20"),
    (0x177099a, 0x7f, "long-loop bound 0x80 -> 0x7f"),
    (0x2668cf9, 0x48, "items++ base r14 -> rsi (REX.B cleared)"),
]


def controls(image):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, override={va: byte}, stop_on_first=True)
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
        parts.append(e[0] + (":" + ",".join(f"{x:#x}" for x in e[1:]) if len(e) > 1 else ""))
    return ";".join(parts) or "-"


def map_digest(mp):
    return hashlib.sha256(repr(mp).encode()).hexdigest()[:16]


def loader_outcome(c, got):
    if "error" in got:
        return "error"
    names = sorted(set(e[0] for e in got["events"]))
    mask = got["map"][0]
    sets = [row[1][2] for row in got["map"][6]]
    big = max([t[0] + 1 for t in sets if not t[5]] or [0])
    return f"map{mask + 1 if not got['map'][5] else 0}/maxset{big}/{'+'.join(names)}"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    rows, bad, m = evaluate(image)
    consts, decoded = static_evidence(image)
    lines = ["kind\tcase\tinput\toutcome\tevents\tresult\tmatch"]
    classes = {}
    for kind, i, c, want, got, ok in rows:
        if kind == "loader":
            oc = loader_outcome(c, got)
            n_keys = sum(len(k) for _, k in c["items"])
            inp = (f"items={len(c['items'])},addrs={len(set(a for a, _ in c['items']))},keys={n_keys},"
                   f"state={c['state']},frame={c['frame']:#x}")
            res = (f"map={map_digest(got['map'])},items={got['map'][2]},tls={got['tls']:#x}"
                   if "map" in got else got.get("error", "-"))
            ev = event_text(got.get("events", []))
        else:
            fn = c["fn"]
            if fn == "write":
                inp = f"write,len={c['state'][3]:#x}"
                res = ",".join(f"{x:#x}" for x in got["state"]) if "state" in got else got.get("error", got.get("boundary"))
            else:
                inp = f"{fn},n={len(c['data'])}" if fn == "bytes" else "u256"
                res = f"{got['rax']:#x}" if "rax" in got else got.get("boundary", got.get("error"))
            oc = f"{fn}/" + ("panic" if got.get("boundary") == "panic" else
                             "long" if fn == "bytes" and len(c["data"]) > 0x100 else
                             "mid_long" if fn == "bytes" and len(c["data"]) > 0x80 else
                             "medium" if fn == "bytes" else
                             "flush" if fn == "write" and c["state"][3] >= 0x41 else "ok")
            ev = "-"
        classes[f"{kind}:{oc}"] = classes.get(f"{kind}:{oc}", 0) + 1
        lines.append(f"{kind}\t{i}\t{inp}\t{oc}\t{ev}\t{res}\t{'yes' if ok else 'NO'}")
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
    ctl = controls(image)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {
        "binary_sha256": SHA256, "cases": len(rows),
        "loader_cases": sum(1 for r in rows if r[0] == "loader"),
        "direct_cases": sum(1 for r in rows if r[0] == "direct"), "mismatches": bad,
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
