#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM TLOAD 0x2994410 and TSTORE 0x2994e90 handlers with the transient lookup 0x295f490.

TLOAD and TSTORE are opcode table slots 0x5c/0x5d of the RELATIVE tables 0x64414b0/0x64421a0
(slot 0x54 = the SLOAD handler).  Both return 0x2b while the spec byte (+0x1a9) is below 0x0b.
TLOAD returns 0x2c on an empty stack; otherwise it replaces the stack top with the value the
lookup 0x295f490 finds for (executing address +0x78, top) in the host transient map at +0x360,
or zero.  The lookup is a two-level hashbrown map: the outer table (ctrl +0, mask +8, items
+0x18, secret +0x20, 0x40-byte buckets) is keyed by the 20-byte address with the folded
two-multiply hash and the process seed behind GOT slot 0x64dfa78; each outer bucket carries an
inner table header (ctrl -0x28, mask -0x20, items -0x10, secret -0x08) keyed by the 32-byte slot
whose hash mixes all four limbs (limb 3 into the second multiplier).  An item count of zero at
either level yields zero without a probe.  TSTORE returns 0x28 when the static byte +0x1a8 is
exactly 1 and 0x2c with fewer than two words; otherwise it pops key and value and hands
(host +0x270, address, key, value) to the writer 0x2972390 (stubbed here, arguments recorded).
The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real
machine code with a small concrete x86-64 evaluator (no external programs, the binary is never
executed) and compares every case with one pure-Python reconstruction, including both hashes
and both probes.  Negative controls show that wrong reconstructions and corrupted code bytes are
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
TLOAD = 0x2994410  # opcode table slot 0x5c (RELATIVE tables 0x64414b0 / 0x64421a0)
TSTORE = 0x2994e90  # opcode table slot 0x5d
GET = 0x295f490  # two-level transient map lookup called by TLOAD (evaluated, not stubbed)
INSERT = 0x2972390  # transient write called by TSTORE (stubbed: arguments recorded)
OP_TABLES = (0x64414b0, 0x64421a0)
TLOAD_OP, TSTORE_OP = 0x5c, 0x5d
SEED_GOT = 0x64dfa78  # RELATIVE slot -> per-process hash seed word (NOBITS, so the tool supplies it)

# interpreter offsets
I_STACK_PTR, I_STACK_LEN, I_ADDR, I_STATIC, I_SPEC = 0x28, 0x30, 0x78, 0x1a8, 0x1a9
# host offsets
H_TMAP, H_JOURNAL = 0x360, 0x270  # TLOAD reads the map at +0x360, TSTORE hands +0x270 to the writer
# outer map header at H_TMAP
M_CTRL, M_MASK, M_GROWTH, M_ITEMS, M_SECRET = 0x00, 0x08, 0x10, 0x18, 0x20
BUCKET = 0x40  # both levels: outer = 20-byte address + inner header; inner = 32-byte key + 32-byte value
O_INNER = 0x18  # inner header (ctrl, mask, growth, items, secret) inside the outer bucket
CANCUN = 0x0b  # first spec byte that has TLOAD/TSTORE

INTERP_AT = 0x7d00_0000_0000
INTERP_SIZE = 0x200
HOST_AT = 0x7d00_0100_0000
HOST_SIZE = 0x400
STK_AT = 0x7d00_0300_0000
TABLE_AT = 0x7d00_0400_0000
INNER_AT = 0x7d00_0500_0000
INNER_STRIDE = 0x1_0000
INTERP_FILL, HOST_FILL, STACK_FILL, TABLE_FILL = 0x33, 0x44, 0x5c, 0x66
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

R_OK, R_STATIC, R_NOT_ACTIVATED, R_UNDERFLOW = 0x00, 0x28, 0x2b, 0x2c


# ---------------------------------------------------------------- reconstruction
def addr_hash(addr, secret, seed, mut=frozenset()):
    """Outer key hash of a 20-byte address (same folded multiply as the SLOAD account map)."""
    a0, a1, a2 = (int.from_bytes(addr[0:8], "little"), int.from_bytes(addr[8:16], "little"),
                  int.from_bytes(addr[16:20], "little"))
    p = (a0 ^ (secret if "hash_no_secret" not in mut else 0)) * (a1 ^ seed)
    z = (p & M64) ^ a2 ^ (p >> 64)
    p = z * seed
    return (p & M64) ^ (p >> 64)


def key_hash(key, secret, seed, mut=frozenset()):
    """Inner key hash of a 256-bit slot (four little-endian limbs) with the per-address secret."""
    k = [(key >> (64 * i)) & M64 for i in range(4)]
    p = (k[0] ^ secret) * (k[1] ^ seed)
    z = (p & M64) ^ (p >> 64) ^ k[2]
    p = z * (seed ^ (k[3] if "hash_no_k3" not in mut else 0))
    return (p & M64) ^ (p >> 64)


def tload_value(c, mut=frozenset()):
    """0x295f490 reconstructed: value of (address, key) in the transient map, zero when absent."""
    if c["outer_items"] == 0 and "ignore_outer_items" not in mut:
        return 0
    inner = c["maps"].get(c["addr"])
    if inner is None:
        return 0
    if inner["items"] == 0 and "ignore_inner_items" not in mut:
        return 0
    return inner["values"].get(c["stack"][-1], 0 if "absent_ones" not in mut else M256)


def model(c, mut=frozenset()):
    """TLOAD 0x2994410 / TSTORE 0x2994e90 reconstructed: result byte, stack and the write handed on."""
    st = {"n": c["n"], "top": c["stack"][-1] if c["stack"] else None}
    ev = []

    def done(code):
        return {"ret": ("ret", code), "state": st, "events": ev}
    if c["spec"] < (CANCUN if "fork_ge10" not in mut else 10):
        return done(R_NOT_ACTIVATED)
    if c["op"] == TLOAD_OP:
        if c["n"] == 0:
            return done(R_UNDERFLOW)
        if "keep_top" not in mut:
            st["top"] = tload_value(c, mut)
        return done(R_OK)
    static = c["static"] == 1 if "static_nonzero" not in mut else c["static"] != 0
    if static:
        return done(R_STATIC)
    if c["n"] < (2 if "underflow_lt3" not in mut else 3):
        return done(R_UNDERFLOW)
    key, value = c["stack"][-1], c["stack"][-2]
    if "swap_key_value" in mut:
        key, value = value, key
    ev.append(("insert", f"host+{H_JOURNAL:#x}", c["addr"].hex(), key.to_bytes(32, "little").hex(),
               value.to_bytes(32, "little").hex()))
    st["n"] = c["n"] - 2
    st["top"] = c["stack"][-3] if c["n"] >= 3 else None
    return done(R_OK)


# ---------------------------------------------------------------- fixture: hashbrown tables
def layout(nb, entries, tombs, decoys):
    """hashbrown layout: entries [(key bytes, hash, payload)], tombs [slot], decoys [(slot, h2, key bytes)].

    Returns (memory, ctrl offset, {key bytes: slot}).  Inserts take the first EMPTY/DELETED byte of the
    first probe group that has one (triangular probing), like hashbrown's insert path."""
    mask = nb - 1
    mem = bytearray([TABLE_FILL]) * (nb * BUCKET + nb + 16)
    ctrl_off = nb * BUCKET
    ctrl = [0xff] * nb
    for i in tombs:
        ctrl[i] = 0x80
    taken = set()
    for i, h2, key in decoys:
        ctrl[i] = h2
        taken.add(i)
        mem[ctrl_off - (i + 1) * BUCKET:ctrl_off - (i + 1) * BUCKET + len(key)] = key
    slots = {}
    for key, h, payload in entries:
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
        at = ctrl_off - (slot + 1) * BUCKET
        mem[at:at + len(key)] = key
        mem[at + len(key):at + len(key) + len(payload)] = payload
    if 0xff not in ctrl:
        fail("table has no EMPTY slot")
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb]
    return mem, ctrl_off, slots


def build_maps(c, mut=frozenset()):
    """Regions for the outer table and every inner table, hashed with the (possibly mutated) hashes."""
    regions = []
    outer_entries = []
    for j, addr in enumerate(c["order"]):
        inner = c["maps"][addr]
        entries = [(v.to_bytes(32, "little"), key_hash(v, inner["secret"], c["seed"], mut), val.to_bytes(32, "little"))
                   for v, val in inner["order"]]
        mem, coff, _ = layout(inner["buckets"], entries, inner["tombs"], inner["decoys"])
        base = INNER_AT + j * INNER_STRIDE
        regions.append((base, mem))
        head = bytearray(4) + struct.pack("<QQQQQ", base + coff, inner["buckets"] - 1, 0x1234, inner["items"],
                                          inner["secret"])
        outer_entries.append((addr, addr_hash(addr, c["secret"], c["seed"], mut), bytes(head)))
    mem, coff, _ = layout(c["buckets"], outer_entries, c["tombs"], c["decoys"])
    regions.append((TABLE_AT, mem))
    return regions, TABLE_AT + coff


# ---------------------------------------------------------------- harness
def setup(m, c):
    events = []
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(INTERP_AT, INTERP_SIZE, bytes([INTERP_FILL]) * INTERP_SIZE)
    put(it, I_STACK_PTR, 8, STK_AT)
    put(it, I_STACK_LEN, 8, c["n"])
    it[I_SPEC] = c["spec"]
    it[I_STATIC] = c["static"]
    it[I_ADDR:I_ADDR + 20] = c["addr"]
    host = m.add_region(HOST_AT, HOST_SIZE, bytes([HOST_FILL]) * HOST_SIZE)
    regions, ctrl = build_maps(c, c.get("fixture_mut", frozenset()))
    put(host, H_TMAP + M_CTRL, 8, ctrl)
    put(host, H_TMAP + M_MASK, 8, c["buckets"] - 1)
    put(host, H_TMAP + M_GROWTH, 8, 0x4321)
    put(host, H_TMAP + M_ITEMS, 8, c["outer_items"])
    put(host, H_TMAP + M_SECRET, 8, c["secret"])
    m.add_region(STK_AT, 0x20 * max(1, len(c["stack"])), b"".join(w.to_bytes(32, "little") for w in c["stack"]))
    for base, mem in regions:
        m.add_region(base, len(mem), bytes(mem))
    m.add_region(m.image.word(SEED_GOT), 8, c["seed"].to_bytes(8, "little"))

    def insert(mc):
        dst, addr_p, key_p, val_p = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        where = f"host+{dst - HOST_AT:#x}" if HOST_AT <= dst < HOST_AT + HOST_SIZE else f"{dst:#x}"
        addr = bytes(mc.load(addr_p + i, 1) for i in range(20))
        key = bytes(mc.load(key_p + i, 1) for i in range(32))
        val = bytes(mc.load(val_p + i, 1) for i in range(32))
        events.append(("insert", where, addr.hex(), key.hex(), val.hex()))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):  # the writer may clobber every caller-saved register
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1
    m.stubs = {INSERT: insert}
    return events


def run_case(m, c):
    m.reset()
    events = setup(m, c)
    keep = {lo: bytes(buf) for lo, hi, buf in m.regions if lo not in (INTERP_AT, STK_AT, STACK_TOP - 0x10000)}
    before = bytes(next(buf for lo, hi, buf in m.regions if lo == INTERP_AT))
    stk_before = bytes(next(buf for lo, hi, buf in m.regions if lo == STK_AT))
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = INTERP_AT, HOST_AT
    got = {"events": events}
    it = next(buf for lo, hi, buf in m.regions if lo == INTERP_AT)
    stk = next(buf for lo, hi, buf in m.regions if lo == STK_AT)
    entry = TLOAD if c["op"] == TLOAD_OP else TSTORE
    try:
        m.run(entry, limit=20000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    n = u(it, I_STACK_LEN, 8)
    got["state"] = {"n": n, "top": u(stk, 0x20 * (n - 1), 32) if 0 < n <= c["n"] else None}
    now = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in keep}
    rest = bytearray(it)
    rest[I_STACK_LEN:I_STACK_LEN + 8] = before[I_STACK_LEN:I_STACK_LEN + 8]
    srest = bytearray(stk)
    if c["op"] == TLOAD_OP and c["n"]:
        srest[0x20 * (c["n"] - 1):0x20 * c["n"]] = stk_before[0x20 * (c["n"] - 1):0x20 * c["n"]]
    got["rest_ok"] = now == keep and bytes(rest) == before and bytes(srest) == stk_before
    return got


def compare(c, want, got):
    if want["ret"] != got["ret"] or want["events"] != got["events"] or want["state"] != got["state"]:
        return False
    return got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
TOTAL = 4800
WORD_POOL = (0, 1, 2, 0x100, M64, 1 << 64, 1 << 128, 1 << 192, M256)
MODES = ["hit", "decoy", "cluster", "inner-miss", "near-key", "outer-miss", "near-addr", "empty-outer",
         "empty-inner", "hit"]


def rand_word(s):
    if s.below(10) < 4:
        return s.pick(WORD_POOL)
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def rand_addr(s):
    k = s.below(6)
    if k == 0:
        return bytes(20)
    if k == 1:
        return bytes([0xff]) * 20
    return s.take(20)


def flip_key(s, key):
    """Same key except one bit in one limb (each limb takes a separate lane of the compare)."""
    return key ^ (1 << (64 * s.below(4) + s.below(64)))


def decoys_for(s, h, nb, tombs, mk, n):
    out = []
    for _ in range(n):
        i = ((h & (nb - 1)) + s.below(16)) & (nb - 1)
        if i not in tombs and all(i != j for j, _, _ in out):
            out.append((i, h >> 57, mk()))
    return out


def inner_map(s, seed, want_key, mode, target):
    nb = s.pick([16, 16, 32, 64])
    secret = int.from_bytes(s.take(8), "little")
    keys = []
    for _ in range(s.below(5) if mode != "cluster" or not target else s.below(nb // 2)):
        k = rand_word(s)
        if k != want_key and k not in keys:
            keys.append(k)
    if target and mode == "near-key":
        near = flip_key(s, want_key)
        if near not in keys:
            keys.append(near)
    if target and mode not in ("inner-miss", "near-key"):
        keys.insert(s.below(len(keys) + 1), want_key)
    tombs = sorted({s.below(nb) for _ in range(s.below(4))})
    h = key_hash(want_key, secret, seed)
    decoys = []
    if target and (mode in ("decoy", "cluster") or s.below(4) == 0):
        decoys = decoys_for(s, h, nb, tombs, lambda: flip_key(s, want_key).to_bytes(32, "little"), 1 + s.below(3))
    if target and mode == "cluster":
        base = h & (nb - 1)
        for k in range(16):
            i = (base + k) & (nb - 1)
            if len(decoys) + len(keys) + len(tombs) + 2 >= nb:
                break
            if i not in tombs and all(i != j for j, _, _ in decoys) and s.below(5):
                decoys.append((i, s.below(0x80), s.take(32)))
    values = {k: rand_word(s) for k in keys}
    items = len(keys) + len(decoys)
    if mode == "empty-inner" and target:
        items = 0
    return {"buckets": nb, "secret": secret, "order": [(k, values[k]) for k in keys], "values": values,
            "tombs": tombs, "decoys": decoys, "items": items}


def make_case(s, mode, op):
    nb = s.pick([16, 16, 32, 64])
    secret = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little") | 1
    target = rand_addr(s)
    n = s.pick([1, 1, 2, 3, 5]) if s.below(12) else s.pick([0, 1])
    stack = [rand_word(s) for _ in range(n)]
    want_key = stack[-1] if stack else rand_word(s)
    others = []
    while len(others) < s.below(5):
        a = s.take(20)
        if a != target and a not in others:
            others.append(a)
    if mode == "near-addr":
        fake = bytearray(target)
        fake[s.pick([0, 7, 8, 15, 16, 17, 19])] ^= 1 << s.below(8)
        others.append(bytes(fake))
    order = list(others)
    present = mode not in ("outer-miss", "near-addr")
    if present:
        order.insert(s.below(len(order) + 1), target)
    maps = {a: inner_map(s, seed, want_key, mode, a == target) for a in order}
    tombs = sorted({s.below(nb) for _ in range(s.below(4))})
    h = addr_hash(target, secret, seed)
    decoys = []
    if mode in ("decoy", "outer-miss") or s.below(4) == 0:
        def fake_addr():
            f = bytearray(target)
            f[s.pick([0, 7, 8, 15, 16, 19])] ^= 1 << s.below(8)
            return bytes(f)
        decoys = decoys_for(s, h, nb, tombs, fake_addr, 1 + s.below(3))
    if mode == "cluster":
        base = h & (nb - 1)
        for k in range(16):
            i = (base + k) & (nb - 1)
            if len(decoys) + len(order) + len(tombs) + 2 >= nb:
                break
            if i not in tombs and all(i != j for j, _, _ in decoys) and s.below(5):
                decoys.append((i, s.below(0x80), s.take(20)))
    outer_items = len(order) + len(decoys)
    if mode == "empty-outer":
        outer_items = 0
    spec = s.pick([CANCUN, CANCUN, CANCUN, CANCUN, CANCUN + 1, CANCUN + 2, s.below(16), 10])
    static = s.pick([0, 0, 0, 0, 0, 1, 2, 0xff]) if op == TSTORE_OP else s.pick([0, 1])
    return {"op": op, "mode": mode, "buckets": nb, "secret": secret, "seed": seed, "addr": target, "order": order,
            "maps": maps, "tombs": tombs, "decoys": decoys, "outer_items": outer_items, "n": n, "stack": stack,
            "spec": spec, "static": static}


def all_cases():
    s = Stream("re11-transient-storage-115")
    out = []
    for k in range(TOTAL):
        op = TSTORE_OP if (k // 10) % 4 == 3 else TLOAD_OP
        out.append(make_case(s, MODES[k % 10], op))
    return out


# ---------------------------------------------------------------- static evidence
FUNCS = (TLOAD, TSTORE, GET)
CHECKED = (
    (0x2994410, "80 bf a9 01 00 00 0b", "TLOAD: spec byte +0x1a9 < 0x0b -> result 0x2b"),
    (0x2994423, "48 8b 5f 30", "TLOAD: stack length +0x30 (0 -> result 0x2c)"),
    (0x299444d, "48 81 c6 60 03 00 00", "TLOAD: transient map at host +0x360"),
    (0x299445c, "e8 2f b0 fc ff", "TLOAD: direct call of the lookup 0x295f490"),
    (0x299446b, "41 0f 11 4c 1e f0", "TLOAD: looked-up value replaces the stack top"),
    (0x2994481, "b0 2b", "result 0x2b (opcode not activated)"),
    (0x2994484, "b0 2c", "result 0x2c (stack underflow)"),
    (0x2994e90, "80 bf a9 01 00 00 0b", "TSTORE: spec byte +0x1a9 < 0x0b -> result 0x2b"),
    (0x2994e99, "80 bf a8 01 00 00 01", "TSTORE: static byte +0x1a8 == 1 -> result 0x28"),
    (0x2994ea8, "48 83 f9 02", "TSTORE: needs two stack words"),
    (0x2994ef4, "48 81 c6 70 02 00 00", "TSTORE: writer gets host +0x270"),
    (0x2994f0c, "e8 7f d4 fd ff", "TSTORE: direct call of the writer 0x2972390"),
    (0x2994f1b, "b0 28", "result 0x28 (state change in a static call)"),
    (0x295f494, "48 83 7e 18 00", "lookup: outer item count +0x18 == 0 -> zero"),
    (0x295f4a5, "48 8b 05 cc 05 b8 03", "lookup: hash seed through GOT slot 0x64dfa78"),
    (0x295f4b3, "48 33 56 20", "lookup: outer secret +0x20 xored into address bytes 0..8"),
    (0x295f4d0, "49 c1 ea 39", "lookup: h2 = hash >> 57"),
    (0x295f518, "49 c1 e6 06", "lookup: outer bucket size 0x40"),
    (0x295f537, "66 41 0f 6e 6b d0", "lookup: address bytes 16..20 compared as one u32 lane"),
    (0x295f582, "49 83 7b f0 00", "lookup: inner item count (bucket -0x10) == 0 -> zero"),
    (0x295f590, "49 33 53 f8", "lookup: inner secret (bucket -0x08) xored into key limb 0"),
    (0x295f5a5, "4c 33 49 18", "lookup: key limb 3 xored into the seed for the second multiply"),
    (0x295f5b6, "49 8b 43 d8", "lookup: inner ctrl (bucket -0x28)"),
    (0x295f5ba, "49 8b 73 e0", "lookup: inner mask (bucket -0x20)"),
    (0x295f5fd, "49 c1 e3 06", "lookup: inner bucket size 0x40"),
    (0x295f673, "41 0f 10 42 e0", "lookup: value = inner bucket -0x20..0"),
    (0x2972409, "48 8b 87 f0 00 00 00", "writer: map ctrl at arg +0xf0 (host +0x270 +0xf0 = host +0x360)"),
    (0x2972410, "4c 8b 8f f8 00 00 00", "writer: map mask at arg +0xf8"),
    (0x29724d0, "48 83 bf 08 01 00 00", "writer: map item count at arg +0x108"),
    (0x29724ef, "48 33 8f 10 01 00 00", "writer: map secret at arg +0x110"),
)


def opcode_slots(image):
    rows = {}
    for table in OP_TABLES:
        for op, want in ((TLOAD_OP, TLOAD), (TSTORE_OP, TSTORE)):
            slot = table + 8 * (op - 0x54)
            got = image.relative.get(slot)
            if got != want:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * (op - 0x54):#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}"}
        sload = image.relative.get(table)
        rows[f"{table:#x}+0x0"] = {"opcode": "0x54", "target": f"{sload:#x}"}
    return rows


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
    for f in FUNCS:
        calls[f"{f:#x}"] = {}
        for va, fm in decoded[f]:
            if fm is None:
                continue
            if fm["bytes"][:2] == b"\xff\x15":
                fail(f"unexpected indirect call at {va:#x}")
            if fm["op"] == 0xe8:
                calls[f"{f:#x}"][f"{va:#x}"] = f"{fm['target']:#x}"
    if calls != {f"{TLOAD:#x}": {"0x299445c": f"{GET:#x}"}, f"{TSTORE:#x}": {"0x2994f0c": f"{INSERT:#x}"},
                 f"{GET:#x}": {}}:
        fail(f"call graph changed: {calls}")
    seed = {"slot": f"{SEED_GOT:#x}", "relocation": "RELATIVE", "target": f"{image.word(SEED_GOT):#x}",
            "target_section_has_file_bytes": image.section_of(image.word(SEED_GOT))[0] is not None}
    checks = {}
    for va, hx, what in CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "direct_calls": calls, "opcode_table_slots": opcode_slots(image),
           "hash_seed": seed, "checked_bytes": checks,
           "interpreter_offsets": {"stack_ptr": f"{I_STACK_PTR:#x}", "stack_len": f"{I_STACK_LEN:#x}",
                                   "address": f"{I_ADDR:#x}", "static_flag": f"{I_STATIC:#x}", "spec": f"{I_SPEC:#x}"},
           "host_offsets": {"transient_map": f"{H_TMAP:#x}", "tstore_writer_arg": f"{H_JOURNAL:#x}"},
           "map_header": {"ctrl": f"{M_CTRL:#x}", "mask": f"{M_MASK:#x}", "items": f"{M_ITEMS:#x}",
                          "secret": f"{M_SECRET:#x}"},
           "bucket_bytes": BUCKET, "inner_header_in_outer_bucket": f"{O_INNER:#x}", "first_spec": CANCUN,
           "results": {"ok": R_OK, "static_call": R_STATIC, "not_activated": R_NOT_ACTIVATED, "underflow": R_UNDERFLOW}}
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
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


MODEL_MUTANTS = ["fork_ge10", "static_nonzero", "underflow_lt3", "swap_key_value", "keep_top", "ignore_outer_items",
                 "ignore_inner_items", "absent_ones", "hash_no_secret", "hash_no_k3"]
BYTE_MUTANTS = [
    (0x2994416, 0x0a, "TLOAD fork threshold 0x0b -> 0x0a"),
    (0x2994450, 0x68, "TLOAD map host +0x360 -> +0x368"),
    (0x2994482, 0x2a, "TLOAD not-activated result 0x2b -> 0x2a"),
    (0x2994485, 0x2d, "TLOAD underflow result 0x2c -> 0x2d"),
    (0x2994e9f, 0x00, "TSTORE static test == 1 -> == 0"),
    (0x2994eab, 0x01, "TSTORE needs 2 words -> 1"),
    (0x2994ef7, 0x78, "TSTORE writer arg host +0x270 -> +0x278"),
    (0x2994f1c, 0x29, "TSTORE static result 0x28 -> 0x29"),
    (0x295f497, 0x10, "outer item count +0x18 -> +0x10"),
    (0x295f4b6, 0x28, "outer secret +0x20 -> +0x28"),
    (0x295f4d3, 0x38, "outer h2 shift 57 -> 56"),
    (0x295f586, 0x01, "inner item count compared with 1"),
    (0x295f5a8, 0x10, "key limb 3 -> limb 2 in the second multiply"),
    (0x295f5b5, 0x38, "inner h2 shift 57 -> 56"),
    (0x295f677, 0xd0, "value read at bucket -0x30 instead of -0x20"),
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
    if x is None:
        return "-"
    if x == 0:
        return "0"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def outcome(c, want, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "panic":
        return "panic"
    names = {R_OK: "ok", R_STATIC: "static-call", R_NOT_ACTIVATED: "not-activated", R_UNDERFLOW: "underflow"}
    head = ("tload/" if c["op"] == TLOAD_OP else "tstore/") + names.get(code, f"r{code:#x}")
    if code != R_OK:
        return head
    if c["op"] == TSTORE_OP:
        return head + "/write-handed-on"
    hit = c["outer_items"] and c["addr"] in c["maps"] and c["maps"][c["addr"]]["items"] and \
        c["stack"][-1] in c["maps"][c["addr"]]["values"]
    return f"{head}/{'value' if hit else 'zero'}/{c['mode']}"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    rows, bad, m = evaluate(image, cases=cases)
    consts, decoded = static_evidence(image)
    lines = ["case\tinput\toutcome\twrite\tresult\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = outcome(c, want, got)
        inner = c["maps"].get(c["addr"])
        inp = (f"op={c['op']:#x},spec={c['spec']},static={c['static']:#x},n={c['n']},buckets={c['buckets']},"
               f"items={c['outer_items']},addrs={len(c['order'])},present={int(inner is not None)},"
               f"inner_items={inner['items'] if inner else '-'},inner_buckets={inner['buckets'] if inner else '-'},"
               f"decoys={len(c['decoys'])}/{len(inner['decoys']) if inner else '-'},tombs={len(c['tombs'])},"
               f"addr={c['addr'].hex()},top={wtag(c['stack'][-1] if c['stack'] else None)}")
        ev = got.get("events", [])
        write = "-"
        if ev:
            key, value = (int.from_bytes(bytes.fromhex(x), "little") for x in ev[0][3:5])
            write = f"{ev[0][1]}:key={wtag(key)}:value={wtag(value)}"
        if "error" in got:
            res = got["error"]
        elif got["ret"][0] == "panic":
            res = "panic"
        else:
            s = got["state"]
            res = f"ret={got['ret'][1]:#x},n={s['n']},top={wtag(s['top'])}"
        classes[oc] = classes.get(oc, 0) + 1
        lines.append(f"{i}\t{inp}\t{oc}\t{write}\t{res}\t{'yes' if ok else 'NO'}")
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
