#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM account value transfer 0x4322860 with its account lookup 0x3ed7e80.

The transfer takes (state, from, to, value): 20-byte addresses and a 256-bit amount in four little-endian limbs.
The state holds the account hashbrown map at +0xc8 (0xa8-byte buckets: address, then the account with its four
balance limbs at bucket +0x40 and a flag byte at +0xa4 whose bit 2 means touched) and the journal Vec of 0x58-byte
entries at +0x18/+0x20/+0x28.  When from equals to (all 20 bytes) nothing changes and the result is 3 if the
balance covers the value, else 0; the map is probed by an inlined copy of the lookup.  A zero value only touches
the receiver.  Otherwise the sender is touched (journal entry tag 2, once), a balance below the value returns 0
with nothing debited, the debit is stored before the receiver is looked up, the receiver is touched, a credit
that would exceed 2^256-1 returns 1 (the debit stays), and success stores the credit, pushes a tag 4 entry
(addresses at +1 and +0x15, value limbs 0..2 at +0x30, limb 3 at +0x48; bytes +0x29..+0x30 are uninitialised
stack) and calls the trace hook 0x4323270 (stubbed here, arguments recorded) before returning 3.  A missing
account is an unwrap panic with a distinct message per site.  The tool reads every relocation, FDE extent and code
byte from the ELF file, evaluates the real machine code with a small concrete x86-64 evaluator (no external
programs, the binary is never executed) and compares every case with one pure-Python reconstruction, including
the map hash and the probe.  Negative controls show that wrong reconstructions and corrupted code bytes are
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

    if 0x50 <= op <= 0x5f or 0x0fc8 <= op <= 0x0fcf:
        form["r"] = (op & 7) | ((rex & 1) << 3)
    elif op in (0xc3, 0x90, 0x0f0b, 0xcc):
        pass
    elif op in (0x11, 0x13, 0x38, 0x88, 0x0f57, 0x01, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x29, 0x2b, 0x31, 0x33,
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5, 0x0feb, 0x0f50) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
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
        elif op == 0x0feb:  # por
            rm = f["rm"]
            if rm[0] == "r":
                other = self.xmm[rm[1]]
            else:
                other = self.load(self.ea(rm, f, va), 16)
            self.xmm[f["reg"]] |= other
        elif op == 0x0f50:  # movmskps
            if f["rm"][0] != "r":
                fail("movmskps with a memory operand")
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
        elif 0x0fc8 <= op <= 0x0fcf:  # bswap
            n = 8 if size == 64 else 4
            self.regs[f["r"]] = int.from_bytes((self.regs[f["r"]] & ((1 << (8 * n)) - 1)).to_bytes(n, "little"), "big")
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
TRANSFER = 0x4322860  # value transfer between two accounts (journal touch + transfer entries)
LOOKUP = 0x3ed7e80  # account map lookup (20-byte address -> account pointer or null)
TRACE = 0x4323270  # transfer trace hook called after a successful transfer (stubbed: arguments recorded)
GROW = 0x43bc980  # RELATIVE target of GOT slot 0x64e68e8: journal Vec grow (stubbed)
PANIC = 0x1680c10  # RELATIVE target of GOT slot 0x64df830: unwrap on None (stubbed: Boundary)
SEED_GOT = 0x64dfa78  # RELATIVE slot -> per-process hash seed word (NOBITS, so the tool supplies it)
GROW_SLOT, PANIC_SLOT = 0x64e68e8, 0x64df830

# state object offsets (rdi of the transfer)
S_JCAP, S_JPTR, S_JLEN = 0x18, 0x20, 0x28  # journal Vec<[u8; 0x58]>: capacity, pointer, length
S_ACC = 0xc8  # account map header: ctrl +0, mask +8, growth +0x10, items +0x18, secret +0x20
M_CTRL, M_MASK, M_GROWTH, M_ITEMS, M_SECRET = 0x00, 0x08, 0x10, 0x18, 0x20
BKT = 0xa8  # account bucket: 20-byte address, then the account at +0x18
B_BAL, B_FLAG = 0x40, 0xa4  # balance (4 limbs) and flag byte (bit 2 = touched) inside the bucket
E_SIZE = 0x58  # journal entry size
TAG_TOUCH, TAG_TRANSFER = 2, 4
E_VALUE, E_LIMB3 = 0x30, 0x48  # transfer entry: value limbs 0..2 at +0x30, limb 3 at +0x48

R_INSUFFICIENT, R_OVERFLOW, R_OK = 0, 1, 3
MSG_FROM, MSG_TO, MSG_TO_ZERO, MSG_SELF = 0x6485c98, 0x6485cb0, 0x6485cc8, 0x6485ce0

STATE_AT, STATE_SIZE = 0x7d00_0000_0000, 0x200
TABLE_AT = 0x7d00_0400_0000
JOLD_AT, JBIG_AT = 0x7d00_0600_0000, 0x7d00_0700_0000
FROM_AT, TO_AT, VAL_AT = 0x7d00_0800_0000, 0x7d00_0800_1000, 0x7d00_0800_2000
BIGCAP = 48
STATE_FILL, TABLE_FILL, JBIG_FILL, ARG_FILL = 0x44, 0x66, 0x77, 0x88
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


# ---------------------------------------------------------------- reconstruction
def addr_hash(addr, secret, seed, mut=frozenset()):
    """Account map hash of a 20-byte address: folded multiply with the map secret and the process seed."""
    a0, a1, a2 = (int.from_bytes(addr[0:8], "little"), int.from_bytes(addr[8:16], "little"),
                  int.from_bytes(addr[16:20], "little"))
    p = (a0 ^ (secret if "hash_no_secret" not in mut else 0)) * (a1 ^ seed)
    z = (p & M64) ^ (a2 if "hash_no_a2" not in mut else 0) ^ (p >> 64)
    p = z * seed
    return (p & M64) ^ (p >> 64)


def limbs(x):
    return [(x >> (64 * i)) & M64 for i in range(4)]


def entry_bytes(tag, frm, to=None, value=None, garbage=0, mut=frozenset()):
    """Bytes the transfer writes into one journal entry as (offset, bytes) runs."""
    runs = [(0, bytes([tag])), (1, frm)]
    if tag == TAG_TRANSFER:
        runs.append((0x15, to))
        vb = value.to_bytes(32, "little")
        if "value_limb0_first" in mut:
            vb = vb[8:] + vb[:8]
        runs.append((0x29, bytes([garbage]) * 7))  # 7 bytes of uninitialised stack copied by the misaligned move
        runs.append((E_VALUE, vb[:24]))
        runs.append((E_LIMB3, vb[24:]))
    return runs


def model(c, mut=frozenset()):
    """0x4322860 reconstructed: result byte (or panic), final accounts, journal and trace events."""
    accts = {a: dict(v) for a, v in c["accts"].items()}
    jold, jbig = bytearray(c["jold"]), bytearray(c["jbig"])
    st = {"cap": c["jcap"], "len": c["jlen"], "big": False}
    events = []

    def lookup(a):
        if c["items"] == 0 and "ignore_items" not in mut:
            return None
        return accts.get(a)

    def push(runs):
        if st["len"] == st["cap"]:
            jbig[:st["cap"] * E_SIZE] = jold[:st["cap"] * E_SIZE]
            st["cap"], st["big"] = BIGCAP, True
        buf = jbig if st["big"] else jold
        for off, data in runs:
            buf[st["len"] * E_SIZE + off:st["len"] * E_SIZE + off + len(data)] = data
        st["len"] += 1

    def touch(a, acct):
        if not acct["flag"] & 4 or "touch_always" in mut:
            push(entry_bytes(TAG_TOUCH, a))
            acct["flag"] |= 4

    def out(kind, val):
        return {"ret": (kind, val), "accts": {a: (v["bal"], v["flag"]) for a, v in accts.items()},
                "head": (st["cap"], st["len"], st["big"]), "jold": bytes(jold), "jbig": bytes(jbig), "events": events}

    frm, to, value = c["from"], c["to"], c["value"]
    if frm == to:
        a = lookup(frm)
        if a is None:
            return out("panic", MSG_SELF)
        ok = a["bal"] > value if "self_strict" in mut else a["bal"] >= value
        return out("ret", R_OK if ok else R_INSUFFICIENT)
    if value == 0 and "zero_not_special" not in mut:
        b = lookup(to)
        if b is None:
            return out("panic", MSG_TO_ZERO)
        if "zero_no_touch" not in mut:
            touch(to, b)
        return out("ret", R_OK)
    a = lookup(frm)
    if a is None:
        return out("panic", MSG_FROM)
    touch(frm, a)
    if a["bal"] < value:
        return out("ret", R_INSUFFICIENT if "borrow_is_one" not in mut else R_OVERFLOW)
    a["bal"] -= value
    b = lookup(to)
    if b is None:
        return out("panic", MSG_TO)
    touch(to, b)
    total = b["bal"] + value
    if total > M256:
        if "overflow_wraps" in mut:
            b["bal"] = total & M256
            return out("ret", R_OK)
        return out("ret", R_OVERFLOW)
    b["bal"] = total
    if "no_transfer_entry" not in mut:
        push(entry_bytes(TAG_TRANSFER if "tag_swap" not in mut else 3, frm, to, value, c["fill"], mut))
    events.append(("trace", to.hex() if "trace_swap" in mut else frm.hex(), frm.hex() if "trace_swap" in mut else to.hex(),
                   value.to_bytes(32, "little").hex()))
    return out("ret", R_OK)


# ---------------------------------------------------------------- fixture: account hashbrown table
def layout(nb, entries, tombs, decoys):
    """entries [(address, hash, {offset: bytes})], tombs [slot], decoys [(slot, h2, address)] -> (memory, ctrl, slots).

    Inserts take the first free byte of the first probe group that has one (triangular probing)."""
    mask = nb - 1
    mem = bytearray([TABLE_FILL]) * (nb * BKT + nb + 16)
    ctrl_off = nb * BKT
    ctrl = [0xff] * nb
    for i in tombs:
        ctrl[i] = 0x80
    taken = set()
    for i, h2, key in decoys:
        ctrl[i] = h2
        taken.add(i)
        at = ctrl_off - (i + 1) * BKT
        mem[at:at + len(key)] = key
    slots = {}
    for key, h, fields in entries:
        pos, stride = h & mask, 0
        while True:
            free = [(pos + k) & mask for k in range(16) if ((pos + k) & mask) not in taken]
            if free:
                slot = free[0]
                break
            stride += 16
            pos = (pos + stride) & mask
        taken.add(slot)
        slots[key] = slot
        ctrl[slot] = h >> 57
        at = ctrl_off - (slot + 1) * BKT
        mem[at:at + len(key)] = key
        for off, data in fields.items():
            mem[at + off:at + off + len(data)] = data
    if 0xff not in ctrl:
        fail("table has no EMPTY slot")
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb]
    return mem, ctrl_off, slots


def build_table(c, mut=frozenset()):
    entries = []
    for a in c["order"]:
        v = c["accts"][a]
        entries.append((a, addr_hash(a, c["secret"], c["seed"], mut),
                        {B_BAL: v["bal"].to_bytes(32, "little"), B_FLAG: bytes([v["flag"]])}))
    return layout(c["buckets"], entries, c["tombs"], c["decoys"])


# ---------------------------------------------------------------- harness
def region(m, base):
    return next(buf for lo, hi, buf in m.regions if lo == base)


def setup(m, c):
    events = []
    m.regions[0][2][:] = bytes([c["fill"]]) * len(m.regions[0][2])
    st = m.add_region(STATE_AT, STATE_SIZE, bytes([STATE_FILL]) * STATE_SIZE)
    mem, coff, slots = build_table(c, c.get("fixture_mut", frozenset()))
    m.add_region(TABLE_AT, len(mem), bytes(mem))
    put(st, S_JCAP, 8, c["jcap"])
    put(st, S_JPTR, 8, JOLD_AT)
    put(st, S_JLEN, 8, c["jlen"])
    put(st, S_ACC + M_CTRL, 8, TABLE_AT + coff)
    put(st, S_ACC + M_MASK, 8, c["buckets"] - 1)
    put(st, S_ACC + M_GROWTH, 8, 0x4321)
    put(st, S_ACC + M_ITEMS, 8, c["items"])
    put(st, S_ACC + M_SECRET, 8, c["secret"])
    m.add_region(JOLD_AT, len(c["jold"]), bytes(c["jold"]))
    m.add_region(JBIG_AT, len(c["jbig"]), bytes(c["jbig"]))
    m.add_region(FROM_AT, 0x20, c["from"] + bytes([ARG_FILL]) * 12)
    m.add_region(TO_AT, 0x20, c["to"] + bytes([ARG_FILL]) * 12)
    m.add_region(VAL_AT, 0x20, c["value"].to_bytes(32, "little"))
    m.add_region(m.image.word(SEED_GOT), 8, c["seed"].to_bytes(8, "little"))

    def grow(mc):
        vec = mc.regs[7]
        cap, ptr = mc.load(vec, 8), mc.load(vec + 8, 8)
        for i in range(0, cap * E_SIZE, 8):
            mc.store(JBIG_AT + i, 8, mc.load(ptr + i, 8))
        mc.store(vec, 8, BIGCAP)
        mc.store(vec + 8, 8, JBIG_AT)
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    def trace(mc):
        rd = lambda p, n: bytes(mc.load(p + i, 1) for i in range(n))  # noqa: E731
        events.append(("trace", rd(mc.regs[6], 20).hex(), rd(mc.regs[2], 20).hex(), rd(mc.regs[1], 32).hex()))
        mc.regs[6] = mc.regs[2] = mc.regs[1] = 0xd2d2_d2d2_d2d2_d2d2
        for r in (0, 7, 8, 9, 10, 11):
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1
    m.stubs = {GROW: grow, TRACE: trace, PANIC: "panic"}
    return events, slots


def run_case(m, c):
    m.reset()
    events, slots = setup(m, c)
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = STATE_AT, FROM_AT, TO_AT, VAL_AT
    if c["same_ptr"]:
        m.regs[2] = FROM_AT
    tab_before = bytes(region(m, TABLE_AT))
    st_before = bytes(region(m, STATE_AT))
    args_before = [bytes(region(m, b)) for b in (FROM_AT, TO_AT, VAL_AT)]
    got = {"events": events}
    try:
        m.run(TRANSFER, limit=20000)
        got["ret"] = ("ret", m.regs[0] & 0xff)
        got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    except Boundary as b:
        got["ret"] = ("panic", b.regs[7])
        got["regs_ok"] = True
    tab, st = region(m, TABLE_AT), region(m, STATE_AT)
    accts, mask = {}, bytearray(tab)
    ctrl_off = c["buckets"] * BKT
    for a, slot in slots.items():
        at = ctrl_off - (slot + 1) * BKT
        accts[a] = (u(tab, at + B_BAL, 32), tab[at + B_FLAG])
        mask[at + B_BAL:at + B_BAL + 32] = bytes(32)
        mask[at + B_FLAG] = 0
    ref = bytearray(tab_before)
    for a, slot in slots.items():
        at = ctrl_off - (slot + 1) * BKT
        ref[at + B_BAL:at + B_BAL + 32] = bytes(32)
        ref[at + B_FLAG] = 0
    got["accts"] = accts
    got["head"] = (u(st, S_JCAP, 8), u(st, S_JLEN, 8), u(st, S_JPTR, 8) == JBIG_AT)
    got["jold"], got["jbig"] = bytes(region(m, JOLD_AT)), bytes(region(m, JBIG_AT))
    srest, sbef = bytearray(st), bytearray(st_before)
    for off in (S_JCAP, S_JPTR, S_JLEN):
        srest[off:off + 8] = sbef[off:off + 8]
    got["rest_ok"] = (bytes(mask) == bytes(ref) and bytes(srest) == bytes(sbef) and
                      [bytes(region(m, b)) for b in (FROM_AT, TO_AT, VAL_AT)] == args_before)
    return got


def compare(c, want, got):
    if "error" in got:
        return False
    if want["ret"] != got["ret"] or want["events"] != got["events"]:
        return False
    if want["accts"] != {a: v for a, v in got["accts"].items()} or want["head"] != got["head"]:
        return False
    if want["jold"] != got["jold"] or want["jbig"] != got["jbig"]:
        return False
    return got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
TOTAL = 12000
LIMB_POOL = (0, 1, M64, M64 - 1, 1 << 63, (1 << 63) - 1)
MODES = ["ok-plain", "ok-exact", "short", "borrow-chain", "credit-exact", "overflow", "zero-value", "self-ok",
         "self-short", "missing-from", "missing-to", "table-stress", "near-addr", "empty-items", "carry-chain",
         "same-ptr", "zero-missing", "self-missing", "self-empty", "self-stress"]


def rand_word(s):
    k = s.below(8)
    if k == 0:
        return 0
    if k == 1:
        return 1
    if k == 2:
        return M256
    if k == 3:
        return sum(s.pick(LIMB_POOL) << (64 * i) for i in range(4))
    if k == 4:
        return int.from_bytes(s.take(32), "little")
    if k == 5:
        return int.from_bytes(s.take(32), "little") >> (8 * (1 + s.below(31)))
    if k == 6:
        return 1 << (64 * s.below(4))
    return (1 << (64 * (1 + s.below(4)))) - 1


def rand_addr(s):
    k = s.below(8)
    if k == 0:
        return bytes(20)
    if k == 1:
        return bytes([0xff]) * 20
    return s.take(20)


def flip_bit(s, addr):
    b = bytearray(addr)
    b[s.pick([0, 7, 8, 15, 16, 17, 19])] ^= 1 << s.below(8)
    return bytes(b)


def balances(s, mode, value):
    """(from balance, to balance) for the mode, aimed at the carry/borrow boundaries of 0x4322860."""
    small = s.pick([0, 1, 2, 1 << 64, 5 << 128])
    to_bal = rand_word(s)
    if mode == "ok-exact":
        frm = value
    elif mode in ("short", "self-short"):
        frm = value - 1 - s.below(3) if value > 3 else 0
        if value == 0:
            frm = 0
    elif mode == "borrow-chain":
        # high limbs of the balance exceed the value but the low limbs are smaller: borrows ripple upward
        lv = limbs(value)
        j = 1 + s.below(3)
        lb = [min(M64, lv[i] + (1 if i >= j else 0)) if i >= j else max(0, lv[i] - 1 - s.below(2)) for i in range(4)]
        frm = sum(x << (64 * i) for i, x in enumerate(lb))
        if frm < value:
            frm = value
    elif mode == "credit-exact":
        frm = value + small
        to_bal = M256 - value
    elif mode == "overflow":
        frm = value + small
        to_bal = M256 - value + 1 + s.below(3) if value else 5
        to_bal = min(to_bal, M256)
    elif mode == "carry-chain":
        frm = value + small
        lv = limbs(value)
        j = s.below(4)
        to_bal = sum(((M64 - lv[i]) if i < j else (M64 - lv[i] if s.below(2) else lv[i])) << (64 * i) for i in range(4))
        to_bal += s.below(2)
    else:
        frm = value + small
    return min(frm, M256), min(to_bal, M256)


def make_case(s, mode):
    nb = 64 if mode == "self-stress" else s.pick([16, 16, 32, 64])
    secret = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little") | 1
    frm = rand_addr(s)
    to = rand_addr(s)
    while to == frm:
        to = s.take(20)
    if mode in ("self-ok", "self-short", "same-ptr", "self-missing", "self-empty", "self-stress"):
        to = frm
    if mode == "near-addr":
        to = flip_bit(s, frm)
    value = rand_word(s)
    if mode in ("zero-value", "zero-missing"):
        value = 0
    elif value == 0 and mode not in ("self-ok", "self-short", "self-missing", "self-empty", "self-stress"):
        value = 1 + s.below(1000)
    if mode in ("carry-chain", "overflow", "credit-exact") and value == 0:
        value = M64
    fb, tb = balances(s, mode, value)
    accts = {}
    accts[frm] = {"bal": fb, "flag": s.pick([0, 0, 4, 4, 0x40, 0x44, 0xfb, 0xff])}
    if to != frm:
        accts[to] = {"bal": tb, "flag": s.pick([0, 0, 4, 0x80, 0xfb, 0xff, 0x44])}
    if mode in ("missing-from", "self-missing"):
        del accts[frm]
    if mode in ("missing-to", "zero-missing") and to in accts:
        del accts[to]
    for _ in range(s.below(4) if mode not in ("table-stress", "self-stress") else s.below(nb // 3)):
        a = s.take(20)
        if a not in accts and a != frm and a != to:
            accts[a] = {"bal": rand_word(s), "flag": s.pick([0, 4])}
    if mode in ("ok-plain", "ok-exact") and s.below(5) == 0:
        accts = {a: v for a, v in accts.items() if a in (frm, to)}
    order = list(accts)
    for i in range(len(order) - 1, 0, -1):
        j = s.below(i + 1)
        order[i], order[j] = order[j], order[i]
    tombs = sorted({s.below(nb) for _ in range(s.below(4))})
    decoys = []
    probe_for = [frm, to] if mode not in ("missing-to", "zero-missing") else [to]
    if mode in ("near-addr", "table-stress", "missing-to", "missing-from", "zero-missing", "self-missing", "self-stress") or s.below(4) == 0:
        for tgt in probe_for:
            h = addr_hash(tgt, secret, seed)
            for _ in range(1 + s.below(3)):
                i = ((h & (nb - 1)) + s.below(16)) & (nb - 1)
                if i not in tombs and all(i != j for j, _, _ in decoys) and len(decoys) + len(order) + len(tombs) + 3 < nb:
                    decoys.append((i, h >> 57, flip_bit(s, tgt)))
    if mode in ("table-stress", "self-stress"):
        base = addr_hash(frm, secret, seed) & (nb - 1)
        for k in range(16):
            i = (base + k) & (nb - 1)
            if len(decoys) + len(order) + len(tombs) + 3 >= nb:
                break
            if i not in tombs and all(i != j for j, _, _ in decoys) and (mode == "self-stress" or s.below(3)):
                decoys.append((i, s.below(0x80), s.take(20)))
    items = len(order) + len(decoys)
    if mode in ("empty-items", "self-empty"):
        items = 0
    jcap = 1 + s.below(6)
    jlen = jcap - s.below(min(jcap, 3) + 1) if s.below(3) else s.below(jcap + 1)
    jold = bytearray(s.take((jcap + 1) * E_SIZE))
    jbig = bytearray([JBIG_FILL]) * (BIGCAP * E_SIZE)
    return {"mode": mode, "buckets": nb, "secret": secret, "seed": seed, "from": frm, "to": to, "value": value,
            "accts": accts, "order": order, "tombs": tombs, "decoys": decoys, "items": items, "jcap": jcap,
            "jlen": jlen, "jold": bytes(jold), "jbig": bytes(jbig), "fill": 0x10 + s.below(0xe0),
            "same_ptr": mode == "same-ptr" or (mode.startswith("self") and s.below(4) == 0)}


def all_cases():
    s = Stream("re21-transfer-balance-115")
    for k in range(TOTAL):
        yield make_case(s, MODES[k % len(MODES)])



# ---------------------------------------------------------------- trace hook 0x4323270
T_VEC = 0x00  # sink Vec<[u8; 0x50]> of log records: capacity, pointer (+8), length (+0x10)
T_FLAG, T_LEVEL = 0x124, 0x126  # no record when the flag byte is nonzero or the level byte is below 0x0e
LEVEL_MIN = 0x0e
REC = 0x50  # log record size
TOPICS_TAG, DATA_LEN = 3, 0x20
TOPIC_SIG, TOPIC_PLUS, REC_TAIL = 0x4581e0, 0x4581f0, 0x7ca51f  # rodata: the topic-0 hash and a record constant
GOT_ODD, GOT_EVEN = 0x64df8c8, 0x64df8c0  # RELATIVE words chosen by the parity of the data pointer
ALLOC_SLOT, ALLOC_FAIL60, ALLOC_FAIL20, VGROW_SLOT = 0x64df480, 0x64df490, 0x64df498, 0x64dfa48
SINK_AT, SINK_SIZE = 0x7d00_0a00_0000, 0x200
VOLD_AT, VBIG_AT = 0x7d00_0a10_0000, 0x7d00_0a20_0000
P1_AT, P2_AT = 0x7d00_0b00_0000, 0x7d00_0c00_0000
VBIGCAP = 24
HEAP_FILL, SINK_FILL = 0x99, 0x55


def rodata(image, va, n):
    return image.read(va, n)


def rec_bytes(image, p1, p2, fill, mut=frozenset()):
    """The 0x50-byte log record the hook pushes (the last 4 bytes are uninitialised stack)."""
    odd = p2 & 1
    if "even_tag_always" in mut:
        odd = 1
    rcx = p2 if odd else p2 | 1
    rdx = image.word(GOT_ODD) if odd else image.word(GOT_EVEN)
    q = struct.pack("<7Q", TOPICS_TAG if "topics_two" not in mut else 2, p1, TOPICS_TAG, rdx, p2, DATA_LEN, rcx)
    return q + rodata(image, REC_TAIL, 16) + struct.pack("<I", 0xfeffffff) + bytes([fill]) * 4


def topic_obj(image, frm, to, mut=frozenset()):
    """The 0x60-byte topic block: signature, then both addresses left-padded to 32 bytes."""
    if "topics_swapped" in mut:
        frm, to = to, frm
    return rodata(image, TOPIC_SIG, 16) + rodata(image, TOPIC_PLUS, 16) + bytes(12) + frm + bytes(12) + to


def trace_model(image, c, mut=frozenset()):
    """0x4323270 reconstructed: the sink and heap after the call, or the allocation failure it ends in."""
    sink_vec = {"cap": c["vcap"], "len": c["vlen"], "big": False}
    p1m, p2m = bytearray(c["p1mem"]), bytearray(c["p2mem"])
    vold, vbig = bytearray(c["vold"]), bytearray(c["vbig"])
    res = {"ret": ("ret", None)}

    def done():
        res.update(vec=(sink_vec["cap"], sink_vec["len"], sink_vec["big"]), p1=bytes(p1m), p2=bytes(p2m),
                   vold=bytes(vold), vbig=bytes(vbig))
        return res
    gate_level = c["level"] > LEVEL_MIN if "level_gt" in mut else c["level"] >= LEVEL_MIN
    if not gate_level or (c["flag"] != 0 and "flag_ignored" not in mut):
        return done()
    if c["value"] == 0 and "zero_logged" not in mut:
        return done()
    if c["p1"] is None:
        res["ret"] = ("alloc-error", 0x60)
        return done()
    p1off = c["p1"] - P1_AT
    p1m[p1off:p1off + 0x60] = topic_obj(image, c["from"], c["to"], mut)
    if c["p2"] is None:
        res["ret"] = ("alloc-error", 0x20)
        return done()
    order = "little" if "value_little_endian" in mut else "big"
    p2off = c["p2"] - P2_AT
    p2m[p2off:p2off + 32] = c["value"].to_bytes(32, order)
    if sink_vec["len"] == sink_vec["cap"]:
        vbig[:sink_vec["cap"] * REC] = vold[:sink_vec["cap"] * REC]
        sink_vec["cap"], sink_vec["big"] = VBIGCAP, True
    buf = vbig if sink_vec["big"] else vold
    buf[sink_vec["len"] * REC:(sink_vec["len"] + 1) * REC] = rec_bytes(image, c["p1"], c["p2"], c["fill"], mut)
    sink_vec["len"] += 1
    return done()


def trace_run(m, c):
    m.reset()
    m.regions[0][2][:] = bytes([c["fill"]]) * len(m.regions[0][2])
    sink = m.add_region(SINK_AT, SINK_SIZE, bytes([SINK_FILL]) * SINK_SIZE)
    put(sink, T_VEC, 8, c["vcap"])
    put(sink, T_VEC + 8, 8, VOLD_AT)
    put(sink, T_VEC + 0x10, 8, c["vlen"])
    sink[T_FLAG] = c["flag"]
    sink[T_LEVEL] = c["level"]
    m.add_region(VOLD_AT, len(c["vold"]), bytes(c["vold"]))
    m.add_region(VBIG_AT, len(c["vbig"]), bytes(c["vbig"]))
    m.add_region(P1_AT, len(c["p1mem"]), bytes(c["p1mem"]))
    m.add_region(P2_AT, len(c["p2mem"]), bytes(c["p2mem"]))
    m.add_region(FROM_AT, 0x20, c["from"] + bytes([ARG_FILL]) * 12)
    m.add_region(TO_AT, 0x20, c["to"] + bytes([ARG_FILL]) * 12)
    m.add_region(VAL_AT, 0x20, c["value"].to_bytes(32, "little"))
    sink_before = bytes(sink)
    args_before = [bytes(region(m, b)) for b in (FROM_AT, TO_AT, VAL_AT)]
    served = []

    def alloc(mc):
        size = mc.regs[7]
        want = 0x60 if not served else 0x20
        if size != want:
            fail(f"allocation of {size:#x} bytes, expected {want:#x}")
        got = c["p1"] if not served else c["p2"]
        served.append(size)
        mc.regs[0] = got if got is not None else 0
        for r in (1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    def vgrow(mc):
        vec = mc.regs[7]
        cap, ptr = mc.load(vec, 8), mc.load(vec + 8, 8)
        for i in range(0, cap * REC, 8):
            mc.store(VBIG_AT + i, 8, mc.load(ptr + i, 8))
        mc.store(vec, 8, VBIGCAP)
        mc.store(vec + 8, 8, VBIG_AT)
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1
    m.stubs = {m.image.word(ALLOC_SLOT): alloc, m.image.word(ALLOC_FAIL60): "alloc-fail-60",
               m.image.word(ALLOC_FAIL20): "alloc-fail-20", m.image.word(VGROW_SLOT): vgrow}
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = SINK_AT, FROM_AT, TO_AT, VAL_AT
    got = {}
    try:
        m.run(TRACE, limit=5000)
        got["ret"] = ("ret", None)
        got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    except Boundary as b:
        got["ret"] = ("alloc-error", b.regs[6]) if b.kind.startswith("alloc-fail") else ("panic", b.kind)
        got["regs_ok"] = (b.kind == "alloc-fail-60") == (b.regs[6] == 0x60) and b.regs[7] == 1
    sink = region(m, SINK_AT)
    got["vec"] = (u(sink, T_VEC, 8), u(sink, T_VEC + 0x10, 8), u(sink, T_VEC + 8, 8) == VBIG_AT)
    got["vold"], got["vbig"] = bytes(region(m, VOLD_AT)), bytes(region(m, VBIG_AT))
    got["p1"], got["p2"] = bytes(region(m, P1_AT)), bytes(region(m, P2_AT))
    rest = bytearray(sink)
    for off in range(0, 0x18):
        rest[off] = sink_before[off]
    got["rest_ok"] = bytes(rest) == sink_before and \
        [bytes(region(m, b)) for b in (FROM_AT, TO_AT, VAL_AT)] == args_before
    return got


def trace_compare(want, got):
    if "error" in got:
        return False
    keys = ("ret", "vec", "p1", "p2", "vold", "vbig")
    return all(want[k] == got[k] for k in keys) and got["regs_ok"] and got["rest_ok"]


TRACE_TOTAL = 6000
TRACE_MODES = ["logged", "logged-odd", "logged-grow", "level-low", "level-edge", "flag-set", "zero-value", "alloc-fail-60",
               "alloc-fail-20", "logged-max"]


def make_trace_case(s, mode):
    frm, to = rand_addr(s), rand_addr(s)
    value = rand_word(s) or 1
    level = s.pick([0x0e, 0x0e, 0x0f, 0x10, 0x40, 0xff, 0x20])
    flag = 0
    if mode == "level-low":
        level = s.pick([0, 1, 0x0d, 0x0c, 0x08])
    elif mode == "level-edge":
        level = s.pick([0x0d, 0x0e, 0x0f])
    elif mode == "flag-set":
        flag = s.pick([1, 2, 0x80, 0xff])
    elif mode == "zero-value":
        value = 0
    elif mode == "logged-max":
        value = M256 if s.below(2) else (1 << 255)
    vcap = 1 + s.below(4)
    vlen = vcap if mode == "logged-grow" else s.below(vcap + 1)
    p2off = 0x10 + (s.below(8) | (1 if mode == "logged-odd" else 0))
    p1 = None if mode == "alloc-fail-60" else P1_AT + 0x10 * (1 + s.below(3))
    p2 = None if mode == "alloc-fail-20" else P2_AT + p2off
    if mode not in ("logged-odd", "logged-grow", "alloc-fail-20") and s.below(2):
        p2 = (p2 | 1) if p2 else p2
    return {"mode": mode, "from": frm, "to": to, "value": value, "level": level, "flag": flag, "vcap": vcap, "vlen": vlen,
            "vold": s.take((vcap + 1) * REC), "vbig": bytes([HEAP_FILL]) * (VBIGCAP * REC),
            "p1": p1, "p2": p2, "p1mem": bytes([HEAP_FILL]) * 0x100, "p2mem": bytes([HEAP_FILL]) * 0x100,
            "fill": 0x10 + s.below(0xe0)}


def trace_cases():
    s = Stream("re21-transfer-trace-115")
    for k in range(TRACE_TOTAL):
        yield make_trace_case(s, TRACE_MODES[k % len(TRACE_MODES)])


def trace_outcome(c, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "alloc-error":
        return f"alloc-error/{code:#x}"
    if kind != "ret":
        return "panic"
    if c["level"] < LEVEL_MIN:
        return "skipped/level"
    if c["flag"]:
        return "skipped/flag"
    if c["value"] == 0:
        return "skipped/zero-value"
    return "logged/" + ("odd-pointer" if c["p2"] & 1 else "even-pointer") + ("/grow" if got["vec"][2] else "")


TRACE_MODEL_MUTANTS = ["level_gt", "flag_ignored", "zero_logged", "value_little_endian", "topics_swapped",
                       "even_tag_always", "topics_two"]
TRACE_BYTE_MUTANTS = [
    (0x4323284, 0x0f, "level threshold 0x0e -> 0x0f"),
    (0x4323294, 0x01, "flag byte compared with 1 instead of 0"),
    (0x43232c6, 0x58, "topic block size 0x60 -> 0x58"),
    (0x4323393, 0x18, "data block size 0x20 -> 0x18"),
    (0x43233a8, 0xce, "bswap of limb 0 uses the wrong register"),
    (0x43233c7, 0x03, "odd-pointer tag or 1 -> or 3"),
    (0x43233c9, 0x02, "pointer parity test bit 0 -> bit 1"),
    (0x43233f6, 0x02, "record topic count 3 -> 2"),
    (0x4323417, 0x10, "record data length 0x20 -> 0x10"),
    (0x43233ed, 0xfe, "record constant 0xfeffffff -> 0xfeffffFE"),
    (0x432343d, 0x05, "record stride shl 4 -> shl 5"),
]
# ---------------------------------------------------------------- static evidence
FUNCS = (TRANSFER, LOOKUP, TRACE)
CHECKED = (
    (0x4322899, "3d ff ff 00 00", "transfer: from == to when both 20-byte lanes match (16 + 4 bytes)"),
    (0x43228be, "83 f0 0f", "transfer: value == 0 test (OR of the four limbs)"),
    (0x43228ca, "49 8d bf c8 00 00 00", "transfer: account map header at state +0xc8"),
    (0x43228df, "f6 80 8c 00 00 00 04", "transfer: touched flag = bit 2 of account byte +0x8c"),
    (0x43228fa, "49 6b d5 58", "transfer: journal entry size 0x58"),
    (0x43228fe, "c6 04 11 02", "transfer: touch entry tag 2"),
    (0x4322923, "48 8b 50 28", "transfer: balance limb 0 at account +0x28"),
    (0x432297e, "0f 82 d6 02 00 00", "transfer: debit borrow out of limb 3 -> result 0"),
    (0x4322a2a, "40 b5 01", "transfer: credit overflow result 1"),
    (0x4322a77, "c6 04 08 04", "transfer: transfer entry tag 4"),
    (0x4322ad0, "e8 9b 07 00 00", "transfer: direct call of the trace hook 0x4323270"),
    (0x4322ad5, "40 b5 03", "transfer: success result 3"),
    (0x4322add, "49 83 bf e0 00 00 00 00", "transfer: self path item count (state +0xe0) == 0 -> unwrap panic"),
    (0x4322afb, "49 33 8f e8 00 00 00", "transfer: self path map secret (state +0xe8)"),
    (0x4322b1b, "48 c1 ee 39", "transfer: self path h2 = hash >> 57"),
    (0x4322b6b, "4d 69 c0 a8 00 00 00", "transfer: self path bucket size 0xa8"),
    (0x4322bfe, "8d 2c 40", "transfer: self path result 3 * (balance >= value)"),
    (0x4322c1b, "40 b5 03", "transfer: zero-value result 3"),
    (0x432327e, "80 bf 26 01 00 00 0e", "trace: level byte (sink +0x126) below 0x0e -> no record"),
    (0x432328e, "80 bf 24 01 00 00 00", "trace: flag byte (sink +0x124) nonzero -> no record"),
    (0x43232c5, "bf 60 00 00 00", "trace: topic block of 0x60 bytes through the allocator slot 0x64df480"),
    (0x4323392, "bf 20 00 00 00", "trace: data block of 0x20 bytes"),
    (0x43233a6, "49 0f cf", "trace: byte-swapped value limbs (bswap) stored in reverse limb order"),
    (0x3ed7e80, "48 83 7f 18 00", "lookup: item count (+0x18) == 0 -> null"),
    (0x3ed7e9c, "48 33 4f 20", "lookup: map secret (+0x20) xored into address bytes 0..8"),
    (0x3ed7eb9, "49 c1 e8 39", "lookup: h2 = hash >> 57"),
    (0x3ed7f05, "4d 69 c9 a8 00 00 00", "lookup: bucket size 0xa8"),
    (0x3ed7f71, "48 8d 81 70 ff ff ff", "lookup: account = bucket end - 0x90 (bucket +0x18)"),
)
INDIRECT = {0x64e68e8: GROW, 0x64df830: PANIC, 0x64df480: 0x6355830, 0x64df490: 0x141e251, 0x64df498: 0x141e264,
            0x64dfa48: 0x1437200, 0x64df4c0: 0x1680cab, 0x64df4a0: 0x635de30}


def static_evidence(image):
    rows = fde_rows(image, FUNCS)
    decoded, funcs = {}, {}
    for f in FUNCS:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    calls, ind = {}, {}
    for f in FUNCS:
        calls[f"{f:#x}"], ind[f"{f:#x}"] = {}, {}
        for va, fm in decoded[f]:
            if fm is None:
                continue
            if fm["bytes"][:2] == b"\xff\x15":
                slot = va + fm["len"] + int.from_bytes(fm["bytes"][2:6], "little", signed=True)
                ind[f"{f:#x}"][f"{va:#x}"] = f"{slot:#x}->{image.word(slot):#x}"
            elif fm["op"] == 0xe8:
                calls[f"{f:#x}"][f"{va:#x}"] = f"{fm['target']:#x}"
    want_calls = {f"{TRANSFER:#x}": {"0x43228d1": f"{LOOKUP:#x}", "0x43229b2": f"{LOOKUP:#x}", "0x4322ad0": f"{TRACE:#x}",
                                     "0x4322c0d": f"{LOOKUP:#x}"}, f"{LOOKUP:#x}": {},
                 f"{TRACE:#x}": {"0x43234b1": "0x4355f10", "0x43234d4": "0x63f0a50"}}
    if calls != want_calls:
        fail(f"call graph changed: {calls}")
    slots_seen = {int(v.split("->")[0], 16): int(v.split("->")[1], 16) for d in ind.values() for v in d.values()}
    if slots_seen != INDIRECT:
        fail(f"indirect calls changed: {slots_seen}")
    seed = {"slot": f"{SEED_GOT:#x}", "relocation": "RELATIVE", "target": f"{image.word(SEED_GOT):#x}",
            "target_section_has_file_bytes": image.section_of(image.word(SEED_GOT))[0] is not None}
    checks = {}
    for va, hx, what in CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "direct_calls": calls, "indirect_calls": ind,
           "hash_seed": seed, "checked_bytes": checks,
           "state_offsets": {"journal_cap": f"{S_JCAP:#x}", "journal_ptr": f"{S_JPTR:#x}", "journal_len": f"{S_JLEN:#x}",
                             "account_map": f"{S_ACC:#x}"},
           "bucket": {"size": BKT, "balance": f"{B_BAL:#x}", "flag": f"{B_FLAG:#x}"},
           "journal_entry": {"size": E_SIZE, "touch_tag": TAG_TOUCH, "transfer_tag": TAG_TRANSFER,
                             "value_limbs_0_2": f"{E_VALUE:#x}", "value_limb_3": f"{E_LIMB3:#x}"},
           "results": {"insufficient": R_INSUFFICIENT, "overflow": R_OVERFLOW, "ok": R_OK},
           "panic_messages": {"from_missing": f"{MSG_FROM:#x}", "to_missing": f"{MSG_TO:#x}",
                              "to_missing_zero_value": f"{MSG_TO_ZERO:#x}", "self_missing": f"{MSG_SELF:#x}"}}
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
def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None, keep=True):
    """Run transfer cases; rows are kept only when asked, so big runs stay small in memory."""
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    fixture = frozenset(x for x in mut if x.startswith("hash_"))
    for i, c in enumerate(cases if cases is not None else all_cases()):
        try:
            want = model(c, mut)
            if fixture:
                c = dict(c, fixture_mut=fixture)
            got = run_case(m, c)
            ok = compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        if keep:
            rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


def evaluate_trace(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None, keep=True):
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else trace_cases()):
        try:
            want = trace_model(image, c, mut)
            got = trace_run(m, c)
            ok = trace_compare(want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        if keep:
            rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


MODEL_MUTANTS = ["touch_always", "self_strict", "zero_not_special", "zero_no_touch", "borrow_is_one", "overflow_wraps",
                 "no_transfer_entry", "tag_swap", "trace_swap", "value_limb0_first", "ignore_items", "hash_no_secret",
                 "hash_no_a2"]
BYTE_MUTANTS = [
    (0x432289a, 0xfe, "self compare mask 0xffff -> 0xfeff"),
    (0x43228c0, 0x07, "zero-value test xor 0xf -> 0x7"),
    (0x43228cd, 0xd0, "account map at state +0xc8 -> +0xd0"),
    (0x43228e5, 0x08, "touched flag bit 2 -> bit 3"),
    (0x43228fd, 0x50, "journal entry size 0x58 -> 0x50"),
    (0x4322901, 0x03, "touch tag 2 -> 3"),
    (0x4322926, 0x30, "balance limb 0 at +0x28 -> +0x30"),
    (0x432297f, 0x83, "debit borrow jb -> jae"),
    (0x4322a2c, 0x02, "overflow result 1 -> 2"),
    (0x4322a7a, 0x05, "transfer tag 4 -> 5"),
    (0x4322ad7, 0x02, "success result 3 -> 2"),
    (0x4322ae4, 0x01, "self path item count compared with 1"),
    (0x4322afe, 0xf0, "self path secret +0xe8 -> +0xf0"),
    (0x4322b1e, 0x38, "self path h2 shift 57 -> 56"),
    (0x4322b6e, 0xb0, "self path bucket size 0xa8 -> 0xb0"),
    (0x4322c00, 0x80, "self path result scale 3 -> 5"),
    (0x4322c1d, 0x02, "zero-value result 3 -> 2"),
    (0x3ed7e84, 0x01, "lookup item count compared with 1"),
    (0x3ed7e9f, 0x28, "lookup secret +0x20 -> +0x28"),
    (0x3ed7ebc, 0x38, "lookup h2 shift 57 -> 56"),
    (0x3ed7f08, 0xb0, "lookup bucket size 0xa8 -> 0xb0"),
    (0x3ed7f74, 0x78, "lookup account offset -0x90 -> -0x88"),
]


def controls(image):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True, keep=False)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, override={va: byte}, stop_on_first=True, keep=False)
        rows.append(("code", f"{va:#x}={byte:#04x} {what}", int(bad > 0)))
    for name in TRACE_MODEL_MUTANTS:
        _, bad, _ = evaluate_trace(image, mut=frozenset([name]), stop_on_first=True, keep=False)
        rows.append(("trace-model", name, int(bad > 0)))
    for va, byte, what in TRACE_BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate_trace(image, override={va: byte}, stop_on_first=True, keep=False)
        rows.append(("trace-code", f"{va:#x}={byte:#04x} {what}", int(bad > 0)))
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
        fde_rows(image, (TRANSFER + 1,))
        rows.append(("input", "start inside a function has no FDE", 0))
    except ToolError:
        rows.append(("input", "start inside a function has no FDE", 1))
    return rows


# ---------------------------------------------------------------- output
SAMPLE_EVERY = 12  # the case tables keep every 12th case; the digest in summary.json covers all of them


def wtag(x):
    if x is None:
        return "-"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def outcome(c, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "panic":
        return {MSG_FROM: "panic/from-missing", MSG_TO: "panic/to-missing", MSG_TO_ZERO: "panic/to-missing-zero",
                MSG_SELF: "panic/self-missing"}.get(code, "panic/other")
    if c["from"] == c["to"]:
        return "self/" + ("sufficient" if code == R_OK else "insufficient")
    if c["value"] == 0:
        return "zero-value/ok"
    name = {R_INSUFFICIENT: "insufficient", R_OVERFLOW: "overflow", R_OK: "transferred"}.get(code, f"r{code}")
    return "transfer/" + name


def run_stream(fh, runner, digest, classes, sample_header):
    """Run one case stream, write sampled rows, fold every row into the digest; returns (cases, mismatches)."""
    fh.write(sample_header)
    n = bad = 0
    for i, c, line, ok, oc in runner():
        bad += not ok
        n += 1
        classes[oc] = classes.get(oc, 0) + 1
        digest.update(f"{i}\t{line}\t{ok}\n".encode())
        if i % SAMPLE_EVERY == 0 or not ok:
            fh.write(f"{i}\t{c['mode']}\t{oc}\t{line}\t{'yes' if ok else 'NO'}\n")
    return n, bad


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    consts, decoded = static_evidence(image)
    m = TraceMachine(image)
    digest = hashlib.sha256()

    def transfer_rows():
        for i, c in enumerate(all_cases()):
            try:
                want = model(c)
                got = run_case(m, c)
                ok = compare(c, want, got)
            except ToolError as exc:
                got, ok = {"error": str(exc)}, False
            inp = (f"from={c['from'].hex()[:8]},to={c['to'].hex()[:8]},value={wtag(c['value'])},"
                   f"fbal={wtag(c['accts'].get(c['from'], {}).get('bal'))},"
                   f"tbal={wtag(c['accts'].get(c['to'], {}).get('bal'))},j={c['jlen']}/{c['jcap']},"
                   f"items={c['items']}/{c['buckets']}")
            if "error" in got:
                res = got["error"]
            else:
                cap, ln, big = got["head"]
                res = f"{got['ret'][0]}={got['ret'][1]:#x},j={ln}/{cap}{'+' if big else ''},trace={len(got['events'])}"
            yield i, c, f"{inp}\t{res}", ok, outcome(c, got)

    def trace_rows():
        for i, c in enumerate(trace_cases()):
            try:
                want = trace_model(image, c)
                got = trace_run(m, c)
                ok = trace_compare(want, got)
            except ToolError as exc:
                got, ok = {"error": str(exc)}, False
            inp = (f"from={c['from'].hex()[:8]},to={c['to'].hex()[:8]},value={wtag(c['value'])},level={c['level']:#x},"
                   f"flag={c['flag']:#x},vec={c['vlen']}/{c['vcap']},p2={'-' if c['p2'] is None else hex(c['p2'] - P2_AT)}")
            if "error" in got:
                res = got["error"]
            else:
                res = f"{got['ret'][0]}:{got['ret'][1] if got['ret'][1] is not None else '-'},vec={got['vec'][1]}/{got['vec'][0]}"
            yield i, c, f"{inp}\t{res}", ok, trace_outcome(c, got)
    classes, tclasses = {}, {}
    head = "case\tmode\toutcome\tinput\tresult\tmatch\n"
    with open(out / "cases.tsv", "w") as fh:
        n1, bad1 = run_stream(fh, transfer_rows, digest, classes, head)
    transfer_digest = digest.hexdigest()
    digest = hashlib.sha256()
    with open(out / "trace-cases.tsv", "w") as fh:
        n2, bad2 = run_stream(fh, trace_rows, digest, tclasses, head)
    trace_digest = digest.hexdigest()
    (out / "outcome-classes.tsv").write_text(
        "stream\toutcome\tcases\n" + "".join(f"transfer\t{k}\t{classes[k]}\n" for k in sorted(classes)) +
        "".join(f"trace\t{k}\t{tclasses[k]}\n" for k in sorted(tclasses)))
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
    det = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": n1 + n2, "transfer_cases": n1, "trace_cases": n2,
               "mismatches": bad1 + bad2, "covered_instructions": covered, "transfer_outcomes": classes,
               "trace_outcomes": tclasses, "transfer_digest": transfer_digest, "trace_digest": trace_digest,
               "negative_controls": {"total": len(ctl), "detected": det}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": n1 + n2, "negative_controls": len(ctl),
                                                  "negative_detected": det, "mismatches": bad1 + bad2},
                                                 indent=2, sort_keys=True) + "\n")
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
    print(json.dumps({k: summary[k] for k in ("cases", "mismatches", "negative_controls")}, sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
