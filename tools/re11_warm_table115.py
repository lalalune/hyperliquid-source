#!/usr/bin/env python3
"""Reconstruct and validate node #115 EVM warm-set table growth (reserve_rehash 0x3eda870, 0x143d5f0) and drop 0x2a03a10.

The EIP-2929/2930 warm set is a HashMap<Address, HashSet<U256>> (64-byte map buckets, 32-byte
set buckets, SSE2 hashbrown groups, per-table foldhash seed at table +0x20).  When an insert
finds no growth left, the loader calls reserve_rehash through GOT slots 0x64e7030 (map body
0x3eda870 with its allocation helper 0x3ed8040) and 0x64dfab8 (set body 0x143d5f0, whose
hasher callees 0x143dd40/0x143dcc0 run as real code).  Each body either rehashes in place
(items + additional <= capacity/2: FULL->DELETED, DELETED->EMPTY, mirror copy, re-seat with
swap/move) or allocates a new table (capacity_to_buckets, layout overflow checks, malloc,
memset 0xff, move every full bucket, free the old allocation with sdallocx flags), and on
overflow or allocation failure returns an error or panics depending on the fallibility
byte.  The drop 0x2a03a10 frees every inner set allocation and then the map allocation.
The tool reads relocations, FDE extents and code bytes from the ELF file, evaluates the
real machine code with a small concrete x86-64 evaluator (no external programs, the binary
is never executed) and compares every case with one pure-Python reconstruction.  Negative
controls show that wrong reconstructions and corrupted code bytes are detected.
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
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5, 0x3a, 0x0f64, 0x0feb, 0x0fbd) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
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
    elif op in (0x3d, 0x35):
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
        res = (a - b) & ((1 << size) - 1)
        self.cf, self.of = a < b, bool((((a ^ b) & (a ^ res)) >> (size - 1)) & 1)
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
        elif op == 0x3a:  # cmp r8, r/m8 (defines OF for jno)
            self.flags_sub(self.reg(f["reg"], 8, f), self.get(f["rm"], 8, f, va), 8)
        elif op == 0x35:  # xor eax/rax, imm32
            mask = (1 << size) - 1
            self.set_reg(0, size, self.flags_logic((self.regs[0] ^ f["imm"]) & mask, size), f)
        elif op in (0x0f64, 0x0feb):  # pcmpgtb, por
            if not f["p66"]:
                fail(f"unsupported MMX form {op:#x} at {va:#x}")
            rm = f["rm"]
            if rm[0] == "r":
                b = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                b = self.load(at, 16)
            a = self.xmm[f["reg"]]
            if op == 0x0feb:
                res = a | b
            else:
                res = 0
                for i in range(16):
                    x, y = (a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff
                    if (x - 256 if x & 0x80 else x) > (y - 256 if y & 0x80 else y):
                        res |= 0xff << (8 * i)
            self.xmm[f["reg"]] = res
        elif op == 0x0fbd:  # bsr (lzcnt would carry f3)
            if f["rep"]:
                fail("lzcnt is outside the supported subset")
            a = self.get(f["rm"], size, f, va)
            if a == 0:
                fail(f"bsr of zero at {va:#x}")
            self.zf = False
            self.put(("r", f["reg"]), size, a.bit_length() - 1, f, va)
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
MAP_RESERVE, MAP_RESERVE_END = 0x3eda870, 0x3edae06  # RawTable<(Address, HashSet<U256>)>::reserve_rehash
LAYOUT_HELPER = 0x3ed8040  # direct call at 0x3eda8db: new table allocation for 64-byte buckets
SET_RESERVE, SET_RESERVE_END = 0x143d5f0, 0x143dcba  # RawTable<U256>::reserve_rehash
SET_HASH, SET_REHASH_HASH = 0x143dd40, 0x143dcc0  # hasher callees of the set path (run as real code)
DROP_FN, DROP_END = 0x2a03a10, 0x2a03b0f  # drop of HashMap<Address, HashSet<U256>>
CALLERS = {  # GOT slot -> function reached through it (read from RELATIVE relocations)
    "map_reserve_got": 0x64e7030, "set_reserve_got": 0x64dfab8}
SEED_GOT = 0x64dfa78
MALLOC_GOT, MALLOCX_GOT, MEMSET_GOT, MEMMOVE_GOT = 0x64df480, 0x64df590, 0x64df750, 0x64df568
FREE_GOT, CAP_PANIC_GOT, ALLOC_ERR_GOT, PANIC_GOT = 0x64df4a0, 0x64df6b8, 0x64df490, 0x64df848
SPECIAL_CONST = 0x454f80  # por source: 16 x 0x80
TEMPLATE = 0x64371f8  # 32-byte empty table copied into every new map and set (ctrl = static empty group)
OK = 0x8000000000000001
EMPTY, DELETED = 0xff, 0x80
ISIZE_LIMIT = 0x7ffffffffffffff0
FS_BASE = 0x7b00_0000_2000

TBL_AT = 0x7d00_0000_0000
OLD_AT = 0x7d00_0100_0000  # existing table allocation
OLD_SIZE = 0x40000
HEAP_AT = 0x7d00_1000_0000
HEAP_SIZE = 0x80000
SEED_AT = None
EMPTY_CTRL = None


def fold(a, b):
    p = (a & M64) * (b & M64)
    return (p & M64) ^ (p >> 64)


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M64


def w64(data, at):
    return int.from_bytes(data[at:at + 8], "little")


# ---------------------------------------------------------------- reconstruction: hashes
def bytes_hash(data, seed, g):
    """foldhash byte hasher for 16 <= len <= 0x20 (the only lengths a U256 key produces)."""
    n = len(data)
    r8, r14, rdx, p = (g[1] + seed) & M64, g[0], seed, 0
    tail = (lambda k: w64(data, p + n - k))
    r9 = fold(tail(16) ^ r14, rdx ^ w64(data, p))
    r8 = fold(tail(8) ^ r14, r8 ^ w64(data, p + 8))
    if n > 0x1f:
        r9 = fold(tail(32) ^ r14, r9 ^ w64(data, p + 0x10))
        r8 = fold(tail(24) ^ r14, r8 ^ w64(data, p + 0x18))
    return r8 ^ r9


def hash_u256(key32, seed, g, mut=frozenset()):
    """Set hasher: length prefix 4 into the accumulator, then the 32 key bytes, then finish."""
    acc0 = 4 if "prefix_one" not in mut else 1
    h = bytes_hash(key32, rol(seed, 32), g)
    return fold(g[0] ^ 0, h ^ acc0)


def hash_addr(addr, seed, g0, mut=frozenset()):
    """Map hasher (inlined at 0x3eda978..0x3eda998 and 0x3edab50..0x3edab74)."""
    k0, k1, k2 = w64(addr, 0), w64(addr, 8), int.from_bytes(addr[16:20], "little")
    if "addr_swap" in mut:
        k0, k1 = k1, k0
    x = fold(k1 ^ g0, k0 ^ seed) ^ k2
    return fold(x, g0)


# ---------------------------------------------------------------- reconstruction: hashbrown table
def full_cap(mask):
    return mask if mask < 8 else ((mask + 1) >> 3) * 7


def buckets_for(cap, kind, mut=frozenset()):
    """capacity_to_buckets; None = capacity overflow."""
    if cap < 15:
        if "small_rule" in mut:
            return (cap & 8) + 8
        return 4 if cap < 4 else (cap & 8) + 8
    if cap >> 61 and "no_cap_check" not in mut:
        return None
    adj = ((cap << 3) & M64) // 7
    b = 1 << (adj - 1).bit_length()
    if "pow2_up" in mut:
        b <<= 1
    if kind == "set" and b - 1 > 0x7fffffffffffffe:
        return None
    return b


def layout(buckets, size):
    """(ctrl offset, total) or None on overflow."""
    off = buckets * size
    if off > M64 or off > (1 << 64) - 16:
        return None
    off = (off + 15) & ~15
    total = off + buckets + 16
    if total > M64 or total > ISIZE_LIMIT:
        return None
    return off, total


class Model:
    """State of one table: ctrl pointer, ctrl bytes (with mirror) and full payloads by index."""

    def __init__(self, ctrl_at, mask, growth, items, ctrl, slots):
        self.ctrl_at, self.mask, self.growth, self.items = ctrl_at, mask, growth, items
        self.ctrl, self.slots = bytearray(ctrl), dict(slots)

    def set_ctrl(self, i, h2, mut):
        self.ctrl[i] = h2
        if "no_mirror" not in mut:
            self.ctrl[((i - 16) & self.mask) + 16] = h2

    def insert_slot(self, h, mut):
        pos, stride = h & self.mask, 0
        while True:
            g = self.ctrl[pos:pos + 16]
            for bit in range(16):
                if g[bit] & 0x80:
                    i = (pos + bit) & self.mask
                    if self.ctrl[i] < 0x80 and "no_wrap_fix" not in mut:
                        i = next(b for b in range(16) if self.ctrl[b] & 0x80)
                    return i
            stride += 16
            pos = (pos + stride) & self.mask


def reserve_model(c, mut=frozenset()):
    """Pure reconstruction of 0x3eda870 (kind map) and 0x143d5f0 (kind set) for one case."""
    kind, size = c["kind"], 64 if c["kind"] == "map" else 32
    t = Model(c["ctrl_at"], c["mask"], c["growth"], c["items"], c["ctrl"], c["slots"])
    events, heap = [], HEAP_AT
    g = c["g"]
    shift = 57 if "h2_shift56" not in mut else 56

    def hasher(payload):
        if kind == "map":
            return hash_addr(payload[:20], c["seed"], g[0], mut)
        return hash_u256(payload, c["seed"], g, mut)

    def overflow():
        if c["infallible"]:
            return {"boundary": "capacity_overflow", "events": events}
        return {"rax": 0, "events": events}

    new_items = t.items + c["additional"]
    if new_items > M64:
        if "add_wraps" not in mut:
            return overflow()
        new_items &= M64
    full = full_cap(t.mask)
    limit = full // 2 if "inplace_full" not in mut else full
    if new_items <= limit:
        # rehash in place: FULL -> DELETED, DELETED/EMPTY -> EMPTY, then mirror, then re-seat
        n = t.mask + 1
        for i in range(0, 16 * ((n + 15) // 16)):
            t.ctrl[i] = EMPTY if t.ctrl[i] & 0x80 else DELETED
        if n < 16:
            events.append(("memmove", t.ctrl_at + 16, t.ctrl_at, n))
            t.ctrl[16:16 + n] = t.ctrl[0:n]
        else:
            events.append(("memmove", t.ctrl_at + n, t.ctrl_at, 16))
            t.ctrl[n:n + 16] = t.ctrl[0:16]
        for i in range(n):
            if t.ctrl[i] != DELETED:
                continue
            while True:
                h = hasher(t.slots[i])
                new = t.insert_slot(h, mut)
                start = h & t.mask
                if ((i - start) ^ (new - start)) & t.mask < 16 and "no_same_group" not in mut:
                    t.set_ctrl(i, h >> shift, mut)
                    break
                prev = t.ctrl[new]
                t.set_ctrl(new, h >> shift, mut)
                if prev == EMPTY or "move_not_swap" in mut:
                    t.set_ctrl(i, EMPTY, mut)
                    t.slots[new] = t.slots.pop(i)
                    break
                t.slots[i], t.slots[new] = t.slots[new], t.slots[i]
        t.growth = full_cap(t.mask) - t.items
        return {"rax": OK, "events": events, "table": t}
    cap = max(new_items, full + 1)
    buckets = buckets_for(cap, kind, mut)
    lay = None if buckets is None else layout(buckets, size)
    if lay is None:
        return overflow()
    off, total = lay
    if kind == "map" and total <= 15:
        events.append(("mallocx", total, 4))
    else:
        events.append(("malloc", total))
    if c["alloc_fail"] or total > HEAP_SIZE:
        if c["infallible"]:
            return {"boundary": "alloc_error", "align": 16, "size": total, "events": events}
        return {"rax": 16, "rdx": total, "events": events}
    base = heap
    ctrl_at = base + off
    events.append(("memset", ctrl_at, EMPTY, buckets + 16))
    nt = Model(ctrl_at, buckets - 1, 0, t.items, b"\xff" * (buckets + 16), {})
    for i in sorted(t.slots):
        h = hasher(t.slots[i])
        j = nt.insert_slot(h, mut)
        nt.set_ctrl(j, h >> shift, mut)
        nt.slots[j] = t.slots[i]
    nt.growth = full_cap(nt.mask) - nt.items if "growth_full" not in mut else full_cap(nt.mask)
    if t.mask:
        osize = (t.mask + 1) * size + t.mask + 1 + 16
        flags = 4 if osize < 16 or "free_flag" in mut else 0
        events.append(("free", t.ctrl_at - (t.mask + 1) * size, osize, flags))
    return {"rax": OK, "events": events, "table": nt}


def drop_model(c, mut=frozenset()):
    """Pure reconstruction of 0x2a03a10: free every inner set allocation, then the map allocation."""
    events = []
    mask = c["mask"]
    if mask == 0:
        return {"events": events}
    for i in sorted(c["slots"]):
        if "drop_skip_inner" in mut:
            break
        p = c["slots"][i]
        ictrl, imask = w64(p, 0x18), w64(p, 0x20)
        if imask == 0:
            continue
        isize = (imask + 1) * 32 + imask + 1 + 16
        events.append(("free", (ictrl - (imask + 1) * 32) & M64, isize & M64, 4 if isize < 16 else 0))
    osize = (mask + 1) * 64 + mask + 1 + 16
    events.append(("free", c["ctrl_at"] - (mask + 1) * 64, osize, 4 if osize < 16 or "free_flag" in mut else 0))
    return {"events": events}


# ---------------------------------------------------------------- harness
def setup_common(m, c, events):
    seeds = m.add_region(SEED_AT, 0x40)
    for k in range(6):
        put(seeds, 8 * k, 8, c["g"][k])
    seeds[0x30] = 2
    heap = {"next": HEAP_AT}
    m.add_region(HEAP_AT, HEAP_SIZE)
    image = m.image

    def malloc(mc, flags=None):
        n = mc.regs[7]
        events.append(("malloc", n) if flags is None else ("mallocx", n, mc.regs[6]))
        if c["alloc_fail"] or n > HEAP_SIZE:
            mc.regs[0] = 0
            return
        mc.regs[0] = heap["next"]
        heap["next"] += (n + 15) & ~15

    def memset(mc):
        d, v, n = mc.regs[7], mc.regs[6] & 0xff, mc.regs[2]
        events.append(("memset", d, v, n))
        for k in range(n):
            mc.store(d + k, 1, v)
        mc.regs[0] = d

    def memmove(mc):
        d, s, n = mc.regs[7], mc.regs[6], mc.regs[2]
        events.append(("memmove", d, s, n))
        data = [mc.load(s + k, 1) for k in range(n)]
        for k in range(n):
            mc.store(d + k, 1, data[k])
        mc.regs[0] = d

    def free(mc):
        events.append(("free", mc.regs[7], mc.regs[6], mc.regs[2] & 0xffffffff))

    def cap_panic(mc):
        if mc.regs[6] != 0x39:
            fail("capacity-overflow panic with an unexpected message length")
        raise Boundary("capacity_overflow", mc.regs)

    def alloc_err(mc):
        raise Boundary("alloc_error", mc.regs)

    def panic(mc):
        raise Boundary("panic", mc.regs)

    m.stubs = {image.word(MALLOC_GOT): malloc, image.word(MALLOCX_GOT): (lambda mc: malloc(mc, 1)),
               image.word(MEMSET_GOT): memset, image.word(MEMMOVE_GOT): memmove,
               image.word(FREE_GOT): free, image.word(CAP_PANIC_GOT): cap_panic,
               image.word(ALLOC_ERR_GOT): alloc_err, image.word(PANIC_GOT): panic}


def build_table(m, c):
    """Write the existing table (struct at TBL_AT, allocation at OLD_AT) into machine memory."""
    size = 64 if c["kind"] in ("map", "drop") else 32
    tbl = m.add_region(TBL_AT, 0x40)
    put(tbl, 0, 8, c["ctrl_at"])
    put(tbl, 8, 8, c["mask"])
    put(tbl, 0x10, 8, c["growth"])
    put(tbl, 0x18, 8, c["items"])
    put(tbl, 0x20, 8, c.get("seed", 0))
    if c["mask"]:
        old = m.add_region(OLD_AT, OLD_SIZE, bytes([0x5a]) * OLD_SIZE)
        off = c["ctrl_at"] - OLD_AT
        old[off:off + len(c["ctrl"])] = c["ctrl"]
        for i, p in c["slots"].items():
            b = off - (i + 1) * size
            old[b:b + size] = p


def read_back(m, size):
    ctrl_at, mask, growth, items = (m.load(TBL_AT + 8 * k, 8) for k in range(4))
    if ctrl_at == EMPTY_CTRL:
        return (ctrl_at, mask, growth, items, b"", ())
    if mask > 0x10000:
        fail("table mask out of range")
    cb = bytes(m.load(ctrl_at + k, 1) for k in range(mask + 1 + 16))
    rows = tuple((i, bytes(m.load(ctrl_at - (i + 1) * size + k, 1) for k in range(size)))
                 for i in range(mask + 1) if cb[i] < 0x80)
    return (ctrl_at, mask, growth, items, cb, rows)


def canon(t):
    if t.ctrl_at == EMPTY_CTRL:
        return (t.ctrl_at, t.mask, t.growth, t.items, b"", ())
    return (t.ctrl_at, t.mask, t.growth, t.items, bytes(t.ctrl), tuple(sorted(t.slots.items())))


def run_case(m, c):
    m.reset()
    events = []
    setup_common(m, c, events)
    build_table(m, c)
    if c["kind"] == "drop":
        m.regs[7] = TBL_AT
        try:
            m.run(DROP_FN)
        except Boundary as b:
            return {"boundary": b.kind, "events": events}
        return {"events": events}
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = TBL_AT, c["additional"], TBL_AT + 0x20, c["infallible"]
    start = MAP_RESERVE if c["kind"] == "map" else SET_RESERVE
    try:
        m.run(start, limit=3_000_000)
    except Boundary as b:
        out = {"boundary": b.kind, "events": events}
        if b.kind == "alloc_error":
            out["align"], out["size"] = b.regs[7], b.regs[6]
        return out
    out = {"rax": m.regs[0], "events": events}
    if m.regs[0] == 16:
        out["rdx"] = m.regs[2]
    if m.regs[0] == OK:
        out["table"] = read_back(m, 64 if c["kind"] == "map" else 32)
    return out


def model_case(c, mut=frozenset()):
    if c["kind"] == "drop":
        return drop_model(c, mut)
    r = reserve_model(c, mut)
    if "table" in r:
        r["table"] = canon(r["table"])
    return r


# ---------------------------------------------------------------- cases
def rand_word(s):
    return int.from_bytes(s.take(8), "little")


def make_table(s, kind, buckets, n_live, n_dead, seed, g, window=None):
    """A table built by real insertions (model probing) followed by tombstoning n_dead entries."""
    size = 64 if kind in ("map", "drop") else 32
    if buckets == 0:
        return {"ctrl_at": EMPTY_CTRL, "mask": 0, "growth": 0, "items": 0, "ctrl": b"", "slots": {}}
    off = buckets * size
    ctrl_at = OLD_AT + off
    t = Model(ctrl_at, buckets - 1, 0, 0, b"\xff" * (buckets + 16), {})
    keys = []
    while len(keys) < n_live + n_dead:
        if kind == "set":
            p = s.take(32)
        elif kind == "map":
            p = s.take(64)
        else:  # drop: payload with an inner table header at +0x18
            p = bytearray(s.take(64))
            imask = s.pick([0, 0, 3, 7, 15, 31, 63, 255, 4095])
            put(p, 0x18, 8, 0x7d00_4000_0000 + 0x10000 * s.below(256) + 32 * (imask + 1))
            put(p, 0x20, 8, imask)
            p = bytes(p)
        h = hash_addr(p[:20], seed, g[0]) if kind != "set" else hash_u256(p, seed, g)
        if window is not None and (h & (buckets - 1)) not in window:
            continue
        i = t.insert_slot(h, frozenset())
        t.set_ctrl(i, h >> 57, frozenset())
        t.slots[i] = p
        keys.append(i)
    dead = set()
    while len(dead) < n_dead:
        dead.add(s.pick(keys))
    for i in sorted(dead):
        t.set_ctrl(i, DELETED, frozenset())
        del t.slots[i]
    return {"ctrl_at": ctrl_at, "mask": buckets - 1, "growth": full_cap(buckets - 1) - n_live - n_dead,
            "items": n_live, "ctrl": bytes(t.ctrl), "slots": dict(t.slots)}


HUGE = [1 << 59, (1 << 61) - 1, 1 << 61, 1 << 62, (1 << 57) + 3, 1 << 58, 1 << 56, 1 << 55, 1 << 50, M64]


def reserve_cases(kind, total):
    s = Stream(f"re11-warm-table-{kind}")
    out = []
    shapes = ["grow", "cluster", "dense", "inplace", "inplace", "cluster", "static", "huge", "allocfail", "dense"]
    for n in range(total):
        shape = shapes[n % len(shapes)] if n >= 60 else ["grow", "inplace", "static", "huge", "allocfail", "dense"][n % 6]
        g = [rand_word(s) for _ in range(6)]
        seed = rand_word(s)
        buckets = s.pick([4, 4, 8, 8, 16, 16, 32, 32, 64, 128]) if n % 97 else 256
        full = full_cap(buckets - 1)
        if shape == "static":
            buckets = 0
            live = dead = 0
        elif shape == "dense":  # the new table ends at exactly 7/8 load: full groups and the small-table wrap
            buckets = s.pick([4, 4, 8, 8, 16, 32, 64, 128])
            full = full_cap(buckets - 1)
            live = full - s.below(2)
            dead = full - live
        elif shape == "inplace":
            live = s.below(full // 2 + 1)
            dead = full - live - s.below(2)  # growth_left 0 or 1
            dead = max(dead, 0)
        else:
            live = s.below(full + 1)
            dead = s.below(full - live + 1)
        window = None
        if shape == "cluster":  # probe starts packed into one window: full groups while re-seating in place
            buckets = s.pick([8, 8, 16, 32, 64, 128, 256])
            full = full_cap(buckets - 1)
            live = min(full // 2 - 1, 2 + s.below(40)) if buckets > 8 else 2
            dead = full - live - s.below(2)
            w0 = s.below(buckets)
            window = {(w0 + k) & (buckets - 1) for k in range(1 if buckets == 8 else 1 + s.below(6))}
        c = make_table(s, kind, buckets, live, dead, seed, g, window)
        growth = c["growth"]
        if shape in ("inplace", "cluster"):
            lo, hi = growth + 1, full // 2 - live
            add = lo + s.below(hi - lo + 1) if hi >= lo else growth + 1
        elif shape == "huge":
            add = (s.pick(HUGE) - s.below(3)) & M64
            if s.below(4) == 0:
                add = (M64 - live + 1 + s.below(4)) & M64  # items + additional wraps
            add = max(add, growth + 1)
        elif shape == "dense":
            add = full_cap(2 * buckets - 1) - live
        else:
            add = growth + 1 + s.below(2 * full + 6)
        c.update({"kind": kind, "seed": seed, "g": g, "additional": add,
                  "infallible": 1 if (shape in ("huge", "allocfail") and s.below(2)) or shape == "grow" and s.below(8) == 0 else 0,
                  "alloc_fail": shape == "allocfail", "shape": shape})
        out.append(c)
    return out


def drop_cases(total):
    s = Stream("re11-warm-table-drop")
    out = []
    for n in range(total):
        g = [rand_word(s) for _ in range(6)]
        seed = rand_word(s)
        buckets = 0 if n % 11 == 0 else s.pick([4, 8, 16, 32, 64, 128])
        full = full_cap(buckets - 1) if buckets else 0
        live = s.below(full + 1) if n % 13 else 0
        dead = s.below(full - live + 1) if buckets else 0
        c = make_table(s, "drop", buckets, live, dead, seed, g)
        c.update({"kind": "drop", "seed": seed, "g": g, "alloc_fail": False, "shape": "drop"})
        out.append(c)
    return out


MAP_TOTAL, SET_TOTAL, DROP_TOTAL = 2300, 2100, 900


def all_cases():
    return reserve_cases("map", MAP_TOTAL) + reserve_cases("set", SET_TOTAL) + drop_cases(DROP_TOTAL)


def outcome(c, r):
    if "boundary" in r:
        return r["boundary"]
    if c["kind"] == "drop":
        return "drop_none" if not r["events"] else ("drop_outer_only" if len(r["events"]) == 1 else "drop_inner_and_outer")
    if r["rax"] == 0:
        return "capacity_overflow_err"
    if r["rax"] == 16:
        return "alloc_err"
    if any(e[0] == "malloc" or e[0] == "mallocx" for e in r["events"]):
        return "resize_free_old" if any(e[0] == "free" for e in r["events"]) else "resize_from_static"
    return "rehash_in_place"


def digest(obj):
    return hashlib.sha256(repr(obj).encode()).hexdigest()[:16]


# ---------------------------------------------------------------- static evidence
FUNCS = ((MAP_RESERVE, "map reserve_rehash"), (LAYOUT_HELPER, "64-byte table allocation helper"),
         (SET_RESERVE, "set reserve_rehash"), (DROP_FN, "map drop"))


def static_evidence(image):
    rows = fde_rows(image, {f for f, _ in FUNCS})
    fns = []
    for start, label in FUNCS:
        s, e = rows[start]
        fns.append({"start": f"{s:#x}", "end": f"{e:#x}", "bytes": e - s, "role": label,
                    "sha256": hashlib.sha256(image.code(s, e - s)).hexdigest()})
    got = {}
    for name, slot in (("map_reserve_got", 0x64e7030), ("set_reserve_got", 0x64dfab8), ("malloc", MALLOC_GOT),
                       ("mallocx", MALLOCX_GOT), ("memset", MEMSET_GOT), ("memmove", MEMMOVE_GOT),
                       ("sdallocx", FREE_GOT), ("capacity_overflow_panic", CAP_PANIC_GOT),
                       ("handle_alloc_error", ALLOC_ERR_GOT), ("global_seed", SEED_GOT)):
        entry = {"slot": f"{slot:#x}"}
        if slot in image.imports:
            entry["import"] = image.import_name(slot)
        else:
            entry["target"] = f"{image.word(slot):#x}"
        got[name] = entry
    if image.word(0x64e7030) != MAP_RESERVE or image.word(0x64dfab8) != SET_RESERVE:
        fail("reserve GOT slots do not resolve to the reconstructed bodies")
    special = image.read(SPECIAL_CONST, 16)
    if special != b"\x80" * 16:
        fail("special-byte constant changed")
    return {"functions": fns, "got": got, "special_const": {"address": f"{SPECIAL_CONST:#x}", "hex": special.hex()},
            "empty_ctrl": f"{EMPTY_CTRL:#x}", "empty_group_hex": image.read(EMPTY_CTRL, 16).hex(),
            "global_seed_block": f"{SEED_AT:#x}"}


def init_globals(image):
    global EMPTY_CTRL, SEED_AT
    EMPTY_CTRL = image.word(TEMPLATE)
    SEED_AT = image.word(SEED_GOT)


def compare(want, got):
    return want == got


def evaluate(image, cases, override=None, mut=frozenset(), stop_on_first=False, machine=None):
    m = machine or Machine(image, override)
    results = []
    for c in cases:
        want = model_case(c, mut)
        try:
            got = run_case(m, c)
        except ToolError as e:
            got = {"error": str(e)}
        ok = compare(want, got)
        results.append((c, want, got, ok))
        if stop_on_first and not ok:
            break
    return results


MODEL_MUTANTS = ["no_mirror", "no_wrap_fix", "inplace_full", "move_not_swap", "no_same_group", "growth_full",
                 "free_flag", "drop_skip_inner", "pow2_up", "small_rule", "h2_shift56", "addr_swap", "prefix_one",
                 "add_wraps", "no_cap_check"]


def byte_mutants(image):
    """(address of an immediate byte, new byte, what the byte is); every address is checked to hold the imm."""
    picks = [
        (0x3eda8d3, 0x20, "map bucket size 0x40 passed to the layout helper"),
        (0x3eda9cc, 0x38, "map resize: h2 = hash >> 57"),
        (0x3edab10, 0x08, "map in-place: group-width compare for the mirror copy"),
        (0x3edadaa, 0x0f, "map free: ctrl-offset rounding +0x4f"),
        (0x3edadb5, 0x10, "map free: +17 (mirror + 1) in the old allocation size"),
        (0x3ed8059, 0x04, "helper: small-capacity bucket rule and 8"),
        (0x3ed8060, 0x08, "helper: capacity < 4 -> 4 buckets"),
        (0x3ed8073, 0x3e, "helper: capacity >> 61 overflow test"),
        (0x3ed816c, 0x04, "helper: buckets < 9 growth rule"),
        (0x143d715, 0x04, "set bucket size shift 5"),
        (0x143d8e2, 0x38, "set resize: h2 = hash >> 57"),
        (0x143d9da, 0x08, "set in-place: group-width compare for the mirror copy"),
        (0x143da75, 0x08, "set in-place: same-group distance < 16"),
        (0x143dc14, 0x0f, "set free: ctrl-offset rounding +0x2f"),
        (0x2a03a9e, 0x30, "drop: inner allocation size +0x31"),
        (0x2a03acd, 0x50, "drop: outer allocation size +0x51"),
        (0x2a03a82, 0x05, "drop: 64-byte bucket shift"),
    ]
    out = []
    for at, new, what in picks:
        form = decode(image.code(at, 16), at)
        if "imm" not in form:
            fail(f"mutant site {at:#x} has no immediate")
        width = 1
        if form["op"] in (0x81, 0xc7, 0x69, 0x3d, 0x35) or 0xb8 <= form["op"] <= 0xbf:
            width = 8 if 0xb8 <= form["op"] <= 0xbf and form["rex"] & 8 else 4
        imm_at = at + form["len"] - width  # low byte of the immediate
        old = image.code(imm_at, 1)[0]
        if old == new:
            fail(f"mutant at {at:#x} is a no-op")
        out.append((at, imm_at, old, new, what))
    return out


def controls(image, cases, results):
    rows = []
    for mut in MODEL_MUTANTS:
        caught = 0
        for c, _, got, _ in results:
            if model_case(c, frozenset([mut])) != got:
                caught = 1
                break
        rows.append(("model", mut, "-", "detected" if caught else "MISSED"))
    for at, imm_at, old, new, what in byte_mutants(image):
        rel = [c for c in cases if c["kind"] == ("drop" if at < 0x3000000 and at > 0x2000000 else
                                                ("set" if at < 0x2000000 else "map"))]
        res = evaluate(image, rel, override={imm_at: new}, stop_on_first=True)
        caught = sum(1 for r in res if not r[3])
        rows.append(("code-byte", f"{imm_at:#x}:{old:02x}->{new:02x}", what, "detected" if caught else "MISSED"))
    for label, field in (("model seed differs from the table seed", "seed"), ("global seed word 0 differs", "g")):
        caught = 0
        for c, _, got, _ in results[:400]:
            if c["kind"] == "drop":
                continue
            bad = dict(c)
            bad[field] = c[field] ^ 1 if field == "seed" else [c["g"][0] ^ 1] + list(c["g"][1:])
            if model_case(bad) != got:
                caught = 1
                break
        rows.append(("input", label, "-", "detected" if caught else "MISSED"))
    return rows


def ev_text(events):
    return ";".join(",".join(str(x) if not isinstance(x, int) else f"{x:#x}" for x in e) for e in events) or "-"


def generate(out):
    data = BINARY.read_bytes()
    image = Image(data)
    init_globals(image)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    static = static_evidence(image)
    cases = all_cases()
    m = TraceMachine(image)
    results = evaluate(image, cases, machine=m)
    mism = [r for r in results if not r[3]]
    lines = ["#\tkind\tshape\tbuckets_before\titems\tgrowth_before\tadditional\tinfallible\toutcome\trax\tbuckets_after\tgrowth_after\tevents\tstate_digest\tmatch"]
    classes = {}
    for n, (c, want, got, ok) in enumerate(results):
        oc = outcome(c, got) if "error" not in got else "error"
        classes[(c["kind"], oc)] = classes.get((c["kind"], oc), 0) + 1
        tb = got.get("table")
        lines.append("\t".join([
            str(n), c["kind"], c["shape"], str(c["mask"] + 1 if c["mask"] else 0), str(c["items"]), str(c["growth"]),
            f"{c.get('additional', 0):#x}", str(c.get("infallible", 0)), oc,
            f"{got['rax']:#x}" if "rax" in got else "-", str(tb[1] + 1 if tb and tb[1] else 0) if tb else "-",
            str(tb[2]) if tb else "-", ev_text(got.get("events", [])), digest(got), "yes" if ok else "NO"]))
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text("kind\toutcome\tcases\n" + "".join(
        f"{k}\t{o}\t{v}\n" for (k, o), v in sorted(classes.items())))
    insn_rows = ["function\taddress\tlength\tbytes\texecuted"]
    covered = {}
    ends = {MAP_RESERVE: MAP_RESERVE_END, SET_RESERVE: SET_RESERVE_END, DROP_FN: DROP_END}
    frows = fde_rows(image, {LAYOUT_HELPER})
    ends[LAYOUT_HELPER] = frows[LAYOUT_HELPER][1]
    for start, label in FUNCS:
        rows = sweep_padded(image, start, ends[start])
        hit = 0
        for va, form in rows:
            ex = va in m.seen
            hit += ex
            insn_rows.append(f"{start:#x}\t{va:#x}\t{form['len']}\t{form['bytes'].hex()}\t{'yes' if ex else 'no'}")
        covered[f"{start:#x}"] = {"instructions": len(rows), "executed": hit}
    (out / "decoded-instructions.tsv").write_text("\n".join(insn_rows) + "\n")
    ctl = controls(image, cases, results)
    (out / "negative-controls.tsv").write_text("class\tmutation\twhat\tresult\n" + "".join("\t".join(r) + "\n" for r in ctl))
    summary = {"binary_sha256": SHA256, "cases": len(results), "mismatches": len(mism),
               "cases_by_kind": {k: sum(1 for c in cases if c["kind"] == k) for k in ("map", "set", "drop")},
               "coverage": covered, "negative_controls": len(ctl),
               "negative_controls_detected": sum(1 for r in ctl if r[3] == "detected")}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "constants.json").write_text(json.dumps(static, indent=1, sort_keys=True) + "\n")
    return summary


def sweep_padded(image, lo, hi):
    """Linear decode of an FDE extent; trailing int3 padding is decoded as single bytes."""
    rows, va = [], lo
    while va < hi:
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        s = generate(a.out)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(s, sort_keys=True))
    return 0 if s["mismatches"] == 0 and s["negative_controls"] == s["negative_controls_detected"] else 1


if __name__ == "__main__":
    sys.exit(main())
