#!/usr/bin/env python3
"""Reconstruct and validate node #115 EVM storage and account state access: SLOAD, BALANCE/EXTCODE*, EXTCODECOPY, TSTORE writer.

One concrete x86-64 evaluator (shared core below) runs the real machine code of four families of
functions read byte-for-byte from the ELF file, and each family has one pure-Python reconstruction
that every case is compared against.  The binary is never executed and no external program is called.

sl_  SLOAD handler 0x2993ff0 and its position twin 0x2993bd0: empty stack -> 0x2c; executing address
     looked up in the host account map (hashbrown, ctrl +0x338, mask +0x340, items +0x350, 0xa8-byte
     buckets, two-multiply folded hash keyed by host secret +0x358 and the process seed behind GOT
     0x64dfa78); a miss / load error returns 0x20 from spec 7 and 0x36 before; a hit calls the storage
     load (0x4e33680 / 0x433bcf0, stubbed) and from spec 7 charges the cold surcharge params +0xc8.
ar_  BALANCE / EXTCODESIZE / EXTCODEHASH / SELFBALANCE, both copies named by the RELATIVE opcode tables
     0x6441210 / 0x6441f00, and the two account loaders 0x2990fe0 / 0x2991160: address = low 160 bits
     of the popped word, cold-account price params +0x80, skip of a cold load when gas is short, the
     spec-dependent "empty" rule and the Keccak-256 empty-code hash halves pinned in .rodata.
ec_  EXTCODECOPY 0x298fca0 / 0x29901a0 (slot 0x3c of the same two opcode tables, calling the account
     loaders 0x2990fe0 / 0x2991160 with load_code = 1): four pops before the width checks, per-word copy
     price params +0x20 saturated to 2^64-1, memory growth through .got 0x64e6de0, Bytes clone and
     truncation to the original length, code-offset saturation, memcpy of the in-range part and memset
     zero-fill (only the zero-only path is bound-checked), borrow flag at memory +0x10, Bytes and
     shared-pointer release; seven panic locations.
tw_  transient-storage writer 0x2972390 called by TSTORE 0x2994e90: two-level hashbrown map at
     argument +0xf0, zero value = remove (EMPTY/DELETED neighbour rule), non-zero = overwrite or insert
     (inner reserve through .got 0x64e6c90 when growth_left is 0), 0x58-byte journal record tag 0x0a
     (vector grow through .got 0x64e6cf0); a new address takes the thread-local RandomState boundary.

Negative controls (wrong reconstructions, corrupted code bytes, corrupted binary, out-of-range fetch)
must all be detected.  `--out DIR` regenerates every evidence file; case listings are sampled (every
10th row) and the full listings are pinned by SHA-256 in summary.json (`--full` writes them whole).
"""
import argparse
import concurrent.futures
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
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64, 0xf0):  # operand size, segments, rep/repne, lock
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
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x87, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f1e, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5, 0x0fad, 0x0fbd, 0x0fa3, 0x0feb, 0x0f50, 0x0f54, 0x0f56) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
    elif op in (0x0f70, 0x0fc6, 0x0fa4, 0x0fac):
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
        n = 8 if rex & 8 else 2 if opsize == 16 else 4
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
        if code in (12, 13, 14, 15):
            if getattr(self, "of", None) is None:
                fail(f"signed condition without a defined overflow flag at {va:#x}")
            less = self.sf != self.of
            if code == 12:
                return less
            if code == 13:
                return not less
            if code == 14:
                return less or self.zf
            return not (less or self.zf)
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
        elif op == 0x90 or op == 0x0f1f or (op == 0x0f1e and f["rep"]):
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
        elif op == 0x87:  # xchg r/m, r
            a, b = self.get(f["rm"], size, f, va), self.reg(f["reg"], size, f)
            self.put(f["rm"], size, b, f, va)
            self.set_reg(f["reg"], size, a, f)
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
            self.set_reg(f["r"], 64 if f["rex"] & 8 else f["size"] if f["size"] == 16 else 32, f["imm"], f)
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
            elif kind == 6:  # unsigned div of rdx:rax (or edx:eax) by r/m
                if a == 0:
                    fail(f"divide by zero at {va:#x}")
                mask = (1 << size) - 1
                num = (self.regs[2] & mask) << size | (self.regs[0] & mask)
                q, r = divmod(num, a)
                if q > mask:
                    fail(f"divide overflow at {va:#x}")
                self.set_reg(0, size, q, f)
                self.set_reg(2, size, r, f)
                self.cf = self.of = None
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
        elif op == 0x0fa3:  # bt r/m, r (register forms only)
            if f["rm"][0] != "r":
                fail(f"unsupported bt memory form at {va:#x}")
            self.cf = bool(self.get(f["rm"], size, f, va) >> (self.reg(f["reg"], size, f) % size) & 1)
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
            elif kind == 7:
                res = (a - (1 << size) if a >> (size - 1) else a) >> count & mask
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
        elif op in (0x0fa4, 0x0fac, 0x0fad):  # shld imm / shrd imm / shrd cl
            if size != 64:
                fail("shld/shrd width")
            count = (f["imm"] if op != 0x0fad else self.regs[1]) & 63
            a, b = self.get(f["rm"], 64, f, va), self.reg(f["reg"], 64, f)
            if op == 0x0fa4:
                res = ((a << count) | (b >> (64 - count))) & M64 if count else a
            else:
                res = ((a >> count) | (b << (64 - count))) & M64 if count else a
            if count:
                self.flags_logic(res, 64)
            self.put(f["rm"], 64, res, f, va)
        elif op == 0x0fbd:  # bsr: a zero source sets ZF and leaves the destination unchanged
            if f["rep"]:
                fail("lzcnt is outside the supported subset")
            a = self.get(f["rm"], size, f, va)
            self.zf = a == 0
            self.cf = self.of = None
            if a:
                self.set_reg(f["reg"], size, a.bit_length() - 1, f)
        elif op == 0x0feb:  # por
            if not f["p66"]:
                fail(f"unsupported 0feb form at {va:#x}")
            rm = f["rm"]
            if rm[0] == "r":
                b = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                b = self.load(at, 16)
            self.xmm[f["reg"]] |= b
        elif op in (0x0f54, 0x0f56):  # andps / orps
            if f["p66"]:
                fail(f"unsupported {op:#x} form at {va:#x}")
            rm = f["rm"]
            if rm[0] == "r":
                b = self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                b = self.load(at, 16)
            self.xmm[f["reg"]] = self.xmm[f["reg"]] & b if op == 0x0f54 else self.xmm[f["reg"]] | b
        elif op == 0x0f50:  # movmskps
            if f["p66"] or f["rm"][0] != "r":
                fail(f"unsupported 0f50 form at {va:#x}")
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
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


# ====================================================================================================
# family sl: re11_sload_handler115 (names prefixed sl_ / SL_)
# ====================================================================================================
SL_HANDLER = 0x2993ff0  # SLOAD opcode handler (interpreter, host) -> instruction result byte
SL_TWIN = 0x2993bd0  # position twin of the handler: same bytes except rel32/RIP operands, calls the fallible load
SL_LOAD_SLOT, SL_TWIN_LOAD_SLOT = 0x64e6d90, 0x64e6d98  # RELATIVE GOT slots called by the two handlers
SL_LOAD, SL_TWIN_LOAD = 0x4e33680, 0x433bcf0  # storage loads (reconstructed in the open warm/cold and cache-load packets; stubbed)
SL_LOAD_OF = {SL_HANDLER: SL_LOAD, SL_TWIN: SL_TWIN_LOAD}
SL_SEED_GOT = 0x64dfa78  # RELATIVE slot -> per-process hash seed word (NOBITS, so the tool supplies it)
SL_PANIC_GOTS = (0x64df520, 0x64df848)  # arithmetic-overflow panic entries (GLOB_DAT/RELATIVE slots)

# interpreter offsets read by 0x2993ff0
SL_I_STACK_PTR, SL_I_STACK_LEN, SL_I_ADDR, SL_I_GAS, SL_I_SPEC = 0x28, 0x30, 0x78, 0x188, 0x1a9
# host offsets
SL_H_PARAMS, SL_H_CTX_A, SL_H_WARM, SL_H_CTRL, SL_H_MASK, SL_H_ITEMS, SL_H_SECRET, SL_H_WORD, SL_H_CTX_B = (
    0x250, 0x288, 0x2e0, 0x338, 0x340, 0x350, 0x358, 0x390, 0x398)
SL_P_COLD = 0xc8  # gas parameter: cold SLOAD surcharge
SL_BUCKET = 0xa8  # account-map bucket size; key = 20-byte address at bucket +0, value pointer passed = bucket +0x18

SL_INTERP_AT = 0x7d00_0000_0000
SL_INTERP_SIZE = 0x200
SL_HOST_AT = 0x7d00_0100_0000
SL_HOST_SIZE = 0x400
SL_PARAMS_AT = 0x7d00_0200_0000
SL_PARAMS_SIZE = 0x100
SL_STK_AT = 0x7d00_0300_0000
SL_TABLE_AT = 0x7d00_0400_0000
SL_RESULT_AT = 0x7d00_0500_0000
SL_SEED_AT = None  # read from the GOT slot at run time
SL_INTERP_FILL, SL_HOST_FILL, SL_PARAMS_FILL, SL_STACK_FILL, SL_TABLE_FILL, SL_RESULT_FILL = 0x33, 0x44, 0x55, 0x5c, 0x66, 0x77
SL_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

SL_R_OK, SL_R_OOG, SL_R_UNDERFLOW, SL_R_FATAL = 0x00, 0x20, 0x2c, 0x36


# ---------------------------------------------------------------- reconstruction
def sl_addr_hash(addr, secret, seed, mut=frozenset()):
    """Hash of a 20-byte address: two folded 64x64->128 multiplies (foldhash style)."""
    a0 = int.from_bytes(addr[0:8], "little")
    a1 = int.from_bytes(addr[8:16], "little")
    a2 = int.from_bytes(addr[16:20], "little")
    x = a0 ^ (secret if "hash_no_secret" not in mut else 0)
    y = a1 ^ seed
    p = x * y
    hi, lo = p >> 64, p & M64
    z = lo ^ a2 ^ hi
    if "hash_one_fold" in mut:
        return z
    p = z * seed
    return (p & M64) ^ (p >> 64)


def sl_model(c, mut=frozenset()):
    """0x2993ff0 reconstructed: result byte, gas, stack top and the load call it makes."""
    st = {"gas": c["gas"], "top": c["stack"][-1] if c["stack"] else None}
    ev = []

    def done(code):
        return {"ret": ("ret", code), "state": st, "events": ev}
    if c["n"] == 0:
        return done(SL_R_UNDERFLOW)
    berlin = c["spec"] > (6 if "spec_ge6" not in mut else 5)
    miss = SL_R_OOG if berlin else SL_R_FATAL
    if "miss_swap" in mut:
        miss = SL_R_FATAL if berlin else SL_R_OOG
    entry = c["entries"].get(c["addr"]) if c["items"] else None
    if entry is None:
        return done(miss if "miss_ok" not in mut else SL_R_OK)
    cold = c["params"][SL_P_COLD]
    skip = int(c["gas"] < cold if "skip_le" not in mut else c["gas"] <= cold) if berlin else 0
    ev.append(("load", SL_LOAD_OF[c["entry"]], entry, c["word390"], c["addr"].hex(),
               c["stack"][-1].to_bytes(32, "little").hex(), skip))
    tag = c["tag"]
    if tag == 2:
        return done(SL_R_OOG if berlin else SL_R_FATAL)
    if berlin and tag & 1 and "no_cold_charge" not in mut:
        if c["gas"] < cold:
            return done(SL_R_OOG)
        st["gas"] = c["gas"] - cold
    elif not berlin and tag & 1 and "cold_pre_berlin" in mut:
        st["gas"] = (c["gas"] - cold) & M64
    if "keep_top" not in mut:
        st["top"] = c["value"]
    return done(SL_R_OK)


# ---------------------------------------------------------------- fixture: hashbrown account map
def sl_build_table(c, mut=frozenset()):
    """Lay out ctrl bytes and buckets for c['entries'] using the reconstructed hash; returns (memory, ctrl va)."""
    nb = c["buckets"]
    mask = nb - 1
    mem = bytearray([SL_TABLE_FILL]) * (nb * SL_BUCKET + nb + 16)
    ctrl_off = nb * SL_BUCKET
    ctrl = [0xff] * nb

    def setc(i, b):
        ctrl[i] = b

    for i in c["tombs"]:
        setc(i, 0x80)
    for i, key in c["decoys"]:  # FULL bytes carrying a chosen h2 with a different address
        setc(i, key[0])
        mem[ctrl_off - (i + 1) * SL_BUCKET:ctrl_off - (i + 1) * SL_BUCKET + 20] = key[1]
    for addr, slot in sorted(c["placed"].items()):
        h = sl_addr_hash(addr, c["secret"], c["seed"], mut)
        setc(slot, h >> 57)
        mem[ctrl_off - (slot + 1) * SL_BUCKET:ctrl_off - (slot + 1) * SL_BUCKET + 20] = addr
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb] if nb < 16 else ctrl[i]
    return mem, SL_TABLE_AT + ctrl_off


def sl_place(c, s):
    """Insert the entries the way hashbrown does (first EMPTY/DELETED on the triangular probe)."""
    nb = c["buckets"]
    mask = nb - 1
    used = set(c["tombs"]) | {i for i, _ in c["decoys"]}
    taken = {i for i, _ in c["decoys"]}
    placed = {}
    for addr in c["order"]:
        h = sl_addr_hash(addr, c["secret"], c["seed"])
        pos, stride = h & mask, 0
        while True:
            free = [(pos + k) & mask for k in range(16) if ((pos + k) & mask) not in taken]
            if free:
                slot = free[0]
                break
            stride += 16
            pos = (pos + stride) & mask
        taken.add(slot)
        placed[addr] = slot
    return placed


# ---------------------------------------------------------------- harness
def sl_setup(m, c):
    image = m.image
    events = []
    m.regions[0][2][:] = bytes([SL_STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(SL_INTERP_AT, SL_INTERP_SIZE, bytes([SL_INTERP_FILL]) * SL_INTERP_SIZE)
    put(it, SL_I_STACK_PTR, 8, SL_STK_AT)
    put(it, SL_I_STACK_LEN, 8, c["n"])
    put(it, SL_I_GAS, 8, c["gas"])
    it[SL_I_SPEC] = c["spec"]
    it[SL_I_ADDR:SL_I_ADDR + 20] = c["addr"]
    host = m.add_region(SL_HOST_AT, SL_HOST_SIZE, bytes([SL_HOST_FILL]) * SL_HOST_SIZE)
    put(host, SL_H_PARAMS, 8, SL_PARAMS_AT)
    tmem, ctrl = sl_build_table(c, c.get("fixture_mut", frozenset()))
    put(host, SL_H_CTRL, 8, ctrl)
    put(host, SL_H_MASK, 8, c["buckets"] - 1)
    put(host, SL_H_ITEMS, 8, c["items"])
    put(host, SL_H_SECRET, 8, c["secret"])
    put(host, SL_H_WORD, 4, c["word390"])
    pr = m.add_region(SL_PARAMS_AT, SL_PARAMS_SIZE, bytes([SL_PARAMS_FILL]) * SL_PARAMS_SIZE)
    put(pr, SL_P_COLD, 8, c["params"][SL_P_COLD])
    m.add_region(SL_STK_AT, 0x20 * max(1, len(c["stack"])), b"".join(w.to_bytes(32, "little") for w in c["stack"]))
    m.add_region(SL_TABLE_AT, len(tmem), bytes(tmem))
    m.add_region(image.word(SL_SEED_GOT), 8, c["seed"].to_bytes(8, "little"))
    m.add_region(SL_RESULT_AT, 0x40, bytes([SL_RESULT_FILL]) * 0x20 + c["value"].to_bytes(32, "little"))

    def load(mc, target):
        ctx, kp, fl = mc.regs[7], mc.regs[6], mc.regs[2]
        acct = mc.load(ctx, 8)
        ptrs = (mc.load(ctx + 0x8, 8), mc.load(ctx + 0x10, 8), mc.load(ctx + 0x18, 8))
        if ptrs != (SL_HOST_AT + SL_H_CTX_A, SL_HOST_AT + SL_H_WARM, SL_HOST_AT + SL_H_CTX_B):
            fail(f"load context pointers {[hex(x) for x in ptrs]}")
        word = mc.load(ctx + 0x20, 4)
        addr = bytes(mc.load(ctx + 0x24 + i, 1) for i in range(20))
        k = bytes(mc.load(kp + i, 1) for i in range(32))
        slot = (ctrl - SL_BUCKET - acct + 0x18) // SL_BUCKET
        if ctrl - (slot + 1) * SL_BUCKET + 0x18 != acct:
            fail(f"account pointer {acct:#x} is not a bucket +0x18")
        events.append(("load", target, slot, word, addr.hex(), k.hex(), fl))
        mc.regs[0] = SL_RESULT_AT
        mc.regs[2] = c["tag"] | c["rdx_high"] << 8

    m.stubs = {SL_LOAD: lambda mc: load(mc, SL_LOAD), SL_TWIN_LOAD: lambda mc: load(mc, SL_TWIN_LOAD)}
    for slot in SL_PANIC_GOTS:
        m.stubs[image.word(slot)] = "panic"
    return events


def sl_run_case(m, c):
    m.reset()
    events = sl_setup(m, c)
    keep = {lo: bytes(buf) for lo, hi, buf in m.regions if lo not in (SL_INTERP_AT, SL_STK_AT, STACK_TOP - 0x10000)}
    before = bytes(next(buf for lo, hi, buf in m.regions if lo == SL_INTERP_AT))
    stk_before = bytes(next(buf for lo, hi, buf in m.regions if lo == SL_STK_AT))
    for k, v in zip((3, 12, 13, 14, 15, 5), SL_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = SL_INTERP_AT, SL_HOST_AT
    got = {"events": events}
    it = next(buf for lo, hi, buf in m.regions if lo == SL_INTERP_AT)
    stk = next(buf for lo, hi, buf in m.regions if lo == SL_STK_AT)
    try:
        m.run(c["entry"], limit=20000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SL_SAVED and m.regs[4] == STACK_TOP - 0x100
    n = c["n"]
    got["state"] = {"gas": u(it, SL_I_GAS, 8), "top": u(stk, 0x20 * (n - 1), 32) if n else None}
    now = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in keep}
    rest = bytearray(it)
    rest[SL_I_GAS:SL_I_GAS + 8] = before[SL_I_GAS:SL_I_GAS + 8]
    srest = bytearray(stk)
    if n:
        srest[0x20 * (n - 1):0x20 * n] = stk_before[0x20 * (n - 1):0x20 * n]
    got["rest_ok"] = now == keep and bytes(rest) == before and bytes(srest) == stk_before
    return got


def sl_compare(c, want, got):
    if want["ret"] != got["ret"] or want["events"] != got["events"] or want["state"] != got["state"]:
        return False
    return got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
SL_TOTAL = 4400
SL_WORD_POOL = (0, 1, 2, 0x100, M64, 1 << 64, M256)


def sl_rand_word(s):
    if s.below(10) < 5:
        return s.pick(SL_WORD_POOL)
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def sl_rand_addr(s):
    k = s.below(6)
    if k == 0:
        return bytes(20)
    if k == 1:
        return bytes([0xff]) * 20
    return s.take(20)


def sl_make_case(s, mode):
    nb = s.pick([16, 16, 32, 64])
    secret = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little") | 1
    target = sl_rand_addr(s)
    others = []
    want = s.below(6) if mode != "cluster" else s.below(nb // 2)
    while len(others) < want:
        a = s.take(20)
        if a != target and a not in others:
            others.append(a)
    tombs = sorted({s.below(nb) for _ in range(s.below(4))})
    decoys = []
    present = mode != "absent" and (mode == "cluster" or s.below(6) != 0)
    h = sl_addr_hash(target, secret, seed)
    if mode in ("decoy", "cluster") or s.below(4) == 0:
        # FULL ctrl bytes with the target's h2 in the target's first group, different address
        for _ in range(1 + s.below(3)):
            i = ((h & (nb - 1)) + s.below(16)) & (nb - 1)
            if i not in tombs and all(i != j for j, _ in decoys):
                fake = bytearray(target)
                fake[s.pick([0, 7, 8, 15, 16, 19])] ^= 1 << s.below(8)
                decoys.append((i, (h >> 57, bytes(fake))))
    if mode == "near":  # same first 16 bytes, last 4 differ (the u32 compare lane)
        fake = bytearray(target)
        fake[16 + s.below(4)] ^= 0x80
        others.append(bytes(fake))
    order = list(others)
    if present:
        order.insert(s.below(len(order) + 1), target)
    if mode == "cluster":
        # crowd the target's first group so the probe walks to a later group
        base = h & (nb - 1)
        for k in range(16):
            i = (base + k) & (nb - 1)
            if len(decoys) + len(order) + 2 >= nb:
                break
            if i not in tombs and all(i != j for j, _ in decoys) and s.below(5):
                decoys.append((i, (s.below(0x80), s.take(20))))
    c = {"buckets": nb, "secret": secret, "seed": seed, "addr": target, "tombs": tombs, "decoys": decoys,
         "order": order}
    c["placed"] = sl_place(c, s)
    c["entries"] = {a: slot for a, slot in c["placed"].items()}
    c["items"] = len(order) + len(decoys) if s.below(10) else 0
    if mode == "empty":
        c["items"] = 0
    params = {SL_P_COLD: s.pick([2100, 2000, s.below(30000) + 1, 0, M64, M64 - 1])}
    gas_ref = params[SL_P_COLD]
    gas = (gas_ref + s.below(5) - 2) & M64 if s.below(2) else s.pick([0, 1, s.below(200000), M64])
    n = s.pick([1, 1, 2, 5]) if s.below(14) else 0
    c.update({"mode": mode, "params": params, "gas": gas, "n": n, "stack": [sl_rand_word(s) for _ in range(n)],
              "spec": s.below(13), "tag": s.pick([0, 1, 0, 1, 2]), "rdx_high": s.pick([0, 0, 1, 0xff, 0x80, 0xabcdef]),
              "value": sl_rand_word(s), "word390": int.from_bytes(s.take(4), "little")})
    return c


def sl_all_cases():
    s = Stream("re11-sload-handler-115")
    out = []
    for k in range(SL_TOTAL):
        mode = ["any", "decoy", "cluster", "any", "near", "absent", "any", "decoy", "empty", "any"][k % 10]
        c = sl_make_case(s, mode)
        c["entry"] = SL_TWIN if (k // 10) % 2 else SL_HANDLER
        out.append(c)
    return out


# ---------------------------------------------------------------- static evidence
SL_FUNCS = (SL_HANDLER, SL_TWIN)
SL_CHECKED = (
    (0x2993ff0, "48 8b 47 30", "stack length +0x30 (0 -> result 0x2c without a frame)"),
    (0x2994025, "80 bf a9 01 00 00 06", "spec byte +0x1a9 > 6 -> cold-charging arm"),
    (0x2994039, "4c 8b ba c8 00 00 00", "cold surcharge params +0xc8"),
    (0x299406a, "48 83 be 50 03 00 00 00", "account map item count host +0x350 == 0 -> miss"),
    (0x2994078, "4c 8d 86 98 03 00 00", "host +0x398 passed to the load"),
    (0x2994092, "48 33 96 58 03 00 00", "hash secret host +0x358 xored into address bytes 0..8"),
    (0x29940b3, "49 c1 ea 39", "h2 = hash >> 57"),
    (0x2994107, "4d 69 ec a8 00 00 00", "bucket size 0xa8"),
    (0x29942b5, "48 8d be 88 02 00 00", "host +0x288 passed to the load"),
    (0x29942bc, "44 8b 8e 90 03 00 00", "host u32 +0x390 passed to the load"),
    (0x29942c3, "48 81 c6 e0 02 00 00", "host +0x2e0 (warm set) passed to the load"),
    (0x29942fe, "ff 15 8c 2a b5 03", "call through GOT slot 0x64e6d90"),
    (0x2994309, "b0 20", "out of gas / Berlin miss result 0x20"),
    (0x299436f, "b0 36", "pre-Berlin miss / load error result 0x36"),
    (0x299438e, "4d 29 fe", "gas -= cold surcharge (borrow -> 0x20)"),
    (0x2994397, "4d 89 b4 24 88 01 00", "gas written back to interpreter +0x188"),
    (0x29943ff, "b0 2c", "stack underflow result 0x2c"),
)


def sl_static_evidence(image):
    rows = fde_rows(image, SL_FUNCS)
    decoded, funcs = {}, {}
    for f in SL_FUNCS:
        lo, hi = rows[f]
        decoded[f] = sl_sweep_padded(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    if rows[SL_TWIN][1] - SL_TWIN != rows[SL_HANDLER][1] - SL_HANDLER:
        fail("twin FDE lengths differ")
    calls = {}
    for f in SL_FUNCS:
        calls[f"{f:#x}"] = {}
        for va, fm in decoded[f]:
            if fm is not None and fm["bytes"][:2] == b"\xff\x15":
                slot = (va + 6 + struct.unpack("<i", fm["bytes"][2:6])[0]) & M64
                calls[f"{f:#x}"][f"{va:#x}"] = {"slot": f"{slot:#x}", "target": f"{image.word(slot):#x}"}
            if fm is not None and fm["bytes"][:1] in (b"\xe8",):
                fail(f"unexpected direct call at {va:#x}")
    want = {SL_HANDLER: (SL_LOAD_SLOT, SL_LOAD), SL_TWIN: (SL_TWIN_LOAD_SLOT, SL_TWIN_LOAD)}
    for f, (slot, target) in want.items():
        got = sorted(calls[f"{f:#x}"].values(), key=lambda x: x["slot"])
        if got != [{"slot": f"{slot:#x}", "target": f"{target:#x}"}] * 2:
            fail(f"load calls changed: {calls}")
    twin = []
    for (va, fa), (vb, fb) in zip(decoded[SL_HANDLER], decoded[SL_TWIN]):
        if vb - SL_TWIN != va - SL_HANDLER or (fa is None) != (fb is None):
            fail(f"twin instruction boundaries differ at {vb:#x}")
        if fa is None or fa["bytes"] == fb["bytes"]:
            continue
        n = fa["len"]
        if fb["len"] != n or n < 5 or fa["bytes"][:n - 4] != fb["bytes"][:n - 4]:
            fail(f"twin difference outside a trailing rel32/disp32 at {vb:#x}")
        ta = (va + n + struct.unpack("<i", fa["bytes"][n - 4:n])[0]) & M64
        tb = (vb + n + struct.unpack("<i", fb["bytes"][n - 4:n])[0]) & M64
        if ta != tb and not (ta == SL_LOAD_SLOT and tb == SL_TWIN_LOAD_SLOT):
            fail(f"twin operand at {vb:#x} names {tb:#x}, handler names {ta:#x}")
        twin.append({"handler": f"{va:#x}", "twin": f"{vb:#x}", "target_handler": f"{ta:#x}", "target_twin": f"{tb:#x}"})
    seed = {"slot": f"{SL_SEED_GOT:#x}", "relocation": "RELATIVE", "target": f"{image.word(SL_SEED_GOT):#x}",
            "target_section_has_file_bytes": image.section_of(image.word(SL_SEED_GOT))[0] is not None}
    checks = {}
    for va, hx, what in SL_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "load_calls": calls, "twin_operands": twin,
           "hash_seed": seed, "checked_bytes": checks,
           "interpreter_offsets": {"stack_ptr": f"{SL_I_STACK_PTR:#x}", "stack_len": f"{SL_I_STACK_LEN:#x}",
                                   "address": f"{SL_I_ADDR:#x}", "gas_remaining": f"{SL_I_GAS:#x}", "spec": f"{SL_I_SPEC:#x}"},
           "host_offsets": {"gas_params": f"{SL_H_PARAMS:#x}", "load_ctx_a": f"{SL_H_CTX_A:#x}", "warm_set": f"{SL_H_WARM:#x}",
                            "map_ctrl": f"{SL_H_CTRL:#x}", "map_mask": f"{SL_H_MASK:#x}", "map_items": f"{SL_H_ITEMS:#x}",
                            "hash_secret": f"{SL_H_SECRET:#x}", "load_word_u32": f"{SL_H_WORD:#x}",
                            "load_ctx_b": f"{SL_H_CTX_B:#x}"},
           "gas_params": {"cold_surcharge": f"{SL_P_COLD:#x}"}, "bucket_bytes": SL_BUCKET,
           "results": {"ok": SL_R_OK, "out_of_gas": SL_R_OOG, "underflow": SL_R_UNDERFLOW, "miss_or_load_error": SL_R_FATAL}}
    return out, decoded


def sl_sweep_padded(image, lo, hi):
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
def sl_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    fixture = frozenset(x for x in mut if x.startswith("hash_"))
    for i, c in enumerate(cases if cases is not None else sl_all_cases()):
        try:
            want = sl_model(c, mut)
            if fixture:
                c = dict(c, fixture_mut=fixture)
            got = sl_run_case(m, c)
            ok = sl_compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


SL_MODEL_MUTANTS = ["spec_ge6", "miss_swap", "miss_ok", "skip_le", "no_cold_charge", "cold_pre_berlin", "keep_top",
                 "hash_no_secret", "hash_one_fold"]
SL_BYTE_MUTANTS = [
    (0x299402b, 0x05, "cold arm spec threshold 6 -> 5"),
    (0x299403c, 0xc0, "cold surcharge params +0xc8 -> +0xc0"),
    (0x299406d, 0x48, "item count host +0x350 -> +0x348"),
    (0x2994095, 0x50, "hash secret host +0x358 -> +0x350"),
    (0x29940b6, 0x38, "h2 shift 57 -> 56"),
    (0x299410a, 0xa0, "bucket size 0xa8 -> 0xa0"),
    (0x29942be, 0x88, "load word host +0x390 -> +0x388"),
    (0x299430a, 0x21, "out-of-gas result 0x20 -> 0x21"),
    (0x2994370, 0x37, "miss/error result 0x36 -> 0x37"),
    (0x2994400, 0x2d, "underflow result 0x2c -> 0x2d"),
    (0x2993eea, 0x21, "twin out-of-gas result 0x20 -> 0x21"),
    (0x2993f50, 0x37, "twin miss/error result 0x36 -> 0x37"),
]


def sl_controls(image, cases):
    rows = []
    for name in SL_MODEL_MUTANTS:
        _, bad, _ = sl_evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in SL_BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = sl_evaluate(image, override={va: byte}, stop_on_first=True, cases=cases)
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
def sl_wtag(x):
    if x is None:
        return "-"
    if x == 0:
        return "0"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def sl_outcome(c, got):
    if "error" in got:
        return "error"
    kind, code = got["ret"]
    if kind == "panic":
        return "panic"
    names = {SL_R_OK: "ok", SL_R_OOG: "out-of-gas", SL_R_UNDERFLOW: "underflow", SL_R_FATAL: "miss-or-error"}
    head = names.get(code, f"r{code:#x}")
    fork = "berlin" if c["spec"] > 6 else "pre-berlin"
    if not got["events"]:
        if c["n"] == 0:
            return head
        return f"{head}/{fork}/{'empty-map' if not c['items'] else 'absent'}"
    tag = {0: "warm", 1: "cold", 2: "load-error"}[c["tag"]]
    probe = "crowded-group" if c["mode"] == "cluster" else ("decoy" if c["decoys"] else "direct")
    return f"{head}/{fork}/{tag}/{probe}"


def sl_generate(out):
    image = load_image()
    out.mkdir(parents=True, exist_ok=True)
    cases = sl_all_cases()
    rows, bad, m = sl_evaluate(image, cases=cases)
    consts, decoded = sl_static_evidence(image)
    lines = ["case\tinput\toutcome\tload_call\tresult\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = sl_outcome(c, got)
        inp = (f"entry={c['entry']:#x},spec={c['spec']},n={c['n']},gas={c['gas']:#x},cold={c['params'][SL_P_COLD]:#x},"
               f"buckets={c['buckets']},items={c['items']},present={int(c['addr'] in c['entries'])},"
               f"decoys={len(c['decoys'])},tombs={len(c['tombs'])},addr={c['addr'].hex()},tag={c['tag']},"
               f"rdx_high={c['rdx_high']:#x},key={sl_wtag(c['stack'][-1] if c['stack'] else None)},value={sl_wtag(c['value'])}")
        ev = got.get("events", [])
        call = f"{ev[0][1]:#x}:slot={ev[0][2]}:skip={ev[0][6]}" if ev else "-"
        if "error" in got:
            res = got["error"]
        elif got["ret"][0] == "panic":
            res = "panic"
        else:
            s = got["state"]
            res = f"ret={got['ret'][1]:#x},gas={s['gas']:#x},top={sl_wtag(s['top'])}"
        classes[oc] = classes.get(oc, 0) + 1
        lines.append(f"{i}\t{inp}\t{oc}\t{call}\t{res}\t{'yes' if ok else 'NO'}")
    (out / "sl-cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "sl-outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
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
    (out / "sl-decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = sl_controls(image, cases)
    (out / "sl-negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "sl-constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes,
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "sl-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ====================================================================================================
# family ar: re11_account_read115 (names prefixed ar_ / AR_)
# ====================================================================================================
AR_OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); each names its own copy here
AR_SLOAD_OP = 0x54
AR_SLOAD_BODIES = (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 of each table holds an SLOAD handler copy
AR_BALANCE, AR_EXTCODESIZE, AR_EXTCODEHASH, AR_SELFBALANCE = 0x31, 0x3b, 0x3f, 0x47
AR_OPS = (AR_BALANCE, AR_EXTCODESIZE, AR_EXTCODEHASH, AR_SELFBALANCE)
AR_NAMES = {AR_BALANCE: "BALANCE", AR_EXTCODESIZE: "EXTCODESIZE", AR_EXTCODEHASH: "EXTCODEHASH", AR_SELFBALANCE: "SELFBALANCE"}
# (opcode, copy) -> body; copy 0 = table 0x6441210, copy 1 = table 0x6441f00
AR_BODIES = {
    (AR_BALANCE, 0): 0x2994f20, (AR_BALANCE, 1): 0x2995080,
    (AR_EXTCODESIZE, 0): 0x2990b00, (AR_EXTCODESIZE, 1): 0x2990ca0,
    (AR_EXTCODEHASH, 0): 0x29906a0, (AR_EXTCODEHASH, 1): 0x29908d0,
    (AR_SELFBALANCE, 0): 0x2990f10, (AR_SELFBALANCE, 1): 0x2990e40,
}
AR_LOADERS = {0: 0x2990fe0, 1: 0x2991160}       # account loaders called by the copy-0 / copy-1 handlers
AR_LOADER_OP = 0x100                             # pseudo opcode for direct loader cases
AR_STATE_GOT = {0: 0x64e6ce8, 1: 0x64e6d58}      # state loaders behind GOT slots (copy 0 uses both through 0x2990fe0)
AR_STATE_DIRECT = 0x2971760                      # state loader called directly by loader copy 1
AR_CODE_LOAD = 0x299f1c0                         # code loader called by loader copy 0 when load_code is set
AR_ARC_DROP_GOT = 0x64e4fa8
AR_PANIC_GOT = 0x64df830
AR_PANIC_LOCATION = 0x6443808
AR_EMPTY_LO, AR_EMPTY_HI = 0x4537f0, 0x452020        # rodata halves compared with the code hash
AR_SAVED_REGS = (3, 5, 12, 13, 14, 15)
AR_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

AR_INTERP_AT, AR_INTERP_SIZE = 0x7d00_0100_0000, 0x200
AR_HOST_AT, AR_HOST_SIZE = 0x7d00_0200_0000, 0x400
AR_PARAM_AT, AR_PARAM_SIZE = 0x7d00_0300_0000, 0x100
AR_ACCT_AT, AR_ACCT_SIZE = 0x7d00_0400_0000, 0x100
AR_CREC_AT, AR_CREC_SIZE = 0x7d00_0500_0000, 0x80
AR_STK_AT, AR_STK_WORDS = 0x7d00_0600_0000, 0x400
AR_OUT_AT, AR_OUT_SIZE = 0x7d00_0700_0000, 0x80
AR_ADDR_AT, AR_ADDR_SIZE = 0x7d00_0800_0000, 0x20
AR_CODEARG = 0x0c0d_e000_0000_00a5             # value the state-loader stub leaves at out+0x18

AR_I_STACK_PTR, AR_I_STACK_LEN, AR_I_ADDR, AR_I_GASREC, AR_I_SPEC = 0x28, 0x30, 0x78, 0x170, 0x1a9
AR_G_REMAINING = 0x18                          # remaining gas inside the gas record (interp+0x188)
AR_H_PARAMS, AR_H_JOURNAL, AR_H_SPEC, AR_H_DB = 0x250, 0x270, 0x396, 0x398
AR_P_COLD = 0x80
AR_A_BAL, AR_A_HASH, AR_A_NONCE, AR_A_CODE, AR_A_FLAGS = 0x28, 0x48, 0x68, 0x70, 0x8c
AR_C_LEN = 0x50
AR_S_ACCOUNT, AR_S_CODEARG, AR_S_TAG = 0x00, 0x18, 0x38   # state-loader output record
AR_O_TAG, AR_O_PTR, AR_O_COLD, AR_O_EMPTY = 0x00, 0x08, 0x60, 0x61   # account-loader output record
AR_STACK_LIMIT = 0x400
AR_HASH_GATE, AR_SELF_GATE, AR_LEGACY_SPEC_MAX = 5, 6, 2
AR_F_TOUCHED, AR_F_NOT_EXISTING = 0x4, 0x8
AR_R_OK, AR_R_OOG, AR_R_NOT_ACTIVE, AR_R_UNDERFLOW, AR_R_OVERFLOW, AR_R_FATAL = 0x00, 0x20, 0x2b, 0x2c, 0x2d, 0x36
AR_WORDS_PER_FILL = 4


def ar_name(op):
    return AR_NAMES.get(op, "LOADER")


def ar_keccak_f(st):
    rc, r, x, y = [], 1, 1, 0
    for _ in range(24):
        c = 0
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                c |= 1 << ((1 << j) - 1)
        rc.append(c)
    rot = [[0] * 5 for _ in range(5)]
    for t in range(24):
        rot[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    rol = lambda v, n: ((v << n) | (v >> (64 - n))) & M64 if n else v
    for rnd in range(24):
        c = [st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20] for i in range(5)]
        d = [c[(i - 1) % 5] ^ rol(c[(i + 1) % 5], 1) for i in range(5)]
        st = [st[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for i in range(5):
            for j in range(5):
                b[j + 5 * ((2 * i + 3 * j) % 5)] = rol(st[i + 5 * j], rot[i][j])
        st = [b[i + 5 * j] ^ (~b[(i + 1) % 5 + 5 * j] & b[(i + 2) % 5 + 5 * j]) for j in range(5) for i in range(5)]
        st = [st[i + 5 * j] for j in range(5) for i in range(5)]
        st[0] ^= rc[rnd]
    return st


def ar_keccak256(data, rate=0x88):
    st = [0] * 25
    padded = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    padded[-1] |= 0x80
    for k in range(0, len(padded), rate):
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(padded[k + 8 * i:k + 8 * i + 8], "little")
        st = ar_keccak_f(st)
    return b"".join(v.to_bytes(8, "little") for v in st[:4])


AR_EMPTY_HASH = ar_keccak256(b"")


class AR_Panic(Exception):
    pass


# ---------------------------------------------------------------- reconstruction
def ar_address_bytes(word, mut):
    a = word & ((1 << 160) - 1)
    if "address_little_endian" in mut:
        return a.to_bytes(20, "little")
    return a.to_bytes(20, "big")


def ar_is_empty(c, mut):
    """Loader 'empty' flag: account-content rule above spec byte 2, status-flag rule at or below it."""
    modern = (c["hash"] in (AR_EMPTY_HASH, bytes(32)) and c["balance"] == 0 and c["nonce"] == 0)
    if "empty_ignores_spec" in mut or c["hspec"] > AR_LEGACY_SPEC_MAX:
        return modern
    if "legacy_ignores_touched" in mut:
        return bool(c["flags"] & AR_F_NOT_EXISTING)
    return bool(c["flags"] & AR_F_NOT_EXISTING) and not c["flags"] & AR_F_TOUCHED


def ar_load_account(c, s, copy, addr, load_code, mut):
    """Account loader 0x2990fe0 / 0x2991160.  Returns (ok, cold, empty) and updates s['gas']."""
    cost, rem = c["cold"], s["gas"]
    skip = rem <= cost if "skip_when_equal" in mut else rem < cost
    if copy == 0:
        s["calls"].append(("state", AR_STATE_GOT[0], addr.hex(), int(skip), 0))
    else:
        s["calls"].append(("state-direct", AR_STATE_DIRECT, addr.hex(), int(skip), load_code))
    if c["db"] == "err":
        return None
    cold = c["db"] == "cold"
    if copy == 0 and load_code and not ("no_code_load_on_cold_oog" in mut and cold and rem < cost):
        s["calls"].append(("code", AR_CODE_LOAD, AR_ACCT_AT, AR_CODEARG))
    if "charge_warm_too" in mut or (cold and "no_cold_charge" not in mut):
        if rem < cost:
            if "underflow_wraps" in mut:
                s["gas"] = (rem - cost) & M64
                return False, cold, ar_is_empty(c, mut)
            return None
        s["gas"] = rem - cost
    return True, cold, ar_is_empty(c, mut)


def ar_model(c, mut=frozenset()):
    s = {"gas": c["gas"], "len": c["len"], "stack": dict(c["stack"]), "calls": [], "panic": None,
         "ret": None, "out": None}
    op, copy, n = c["op"], c["copy"], c["len"]
    if op == AR_LOADER_OP:
        r = ar_load_account(c, s, copy, c["addr"], c["load_code"], mut)
        out = bytearray(c["out_fill"])
        if r is None:
            put(out, AR_O_TAG, 8, 2)
            out[AR_O_PTR] = 0
        else:
            put(out, AR_O_TAG, 8, 0)
            put(out, AR_O_PTR, 8, AR_ACCT_AT + AR_A_BAL)
            out[AR_O_COLD], out[AR_O_EMPTY] = int(r[1]), int(r[2])
        s["out"] = bytes(out)
        return s
    gate = {AR_EXTCODEHASH: AR_HASH_GATE - ("hash_gate_minus_one" in mut), AR_SELFBALANCE: AR_SELF_GATE}.get(op)
    if gate is not None and c["spec"] < gate:
        s["ret"] = AR_R_NOT_ACTIVE
        return s
    if op == AR_SELFBALANCE:
        if "selfbalance_overflow_first" in mut and n == AR_STACK_LIMIT:
            s["ret"] = AR_R_OVERFLOW
            return s
        s["calls"].append(("state", AR_STATE_GOT[copy], c["self_addr"].hex(), 0, 0))
        if c["db"] == "err":
            s["ret"] = AR_R_OOG if "selfbalance_err_oog" in mut else AR_R_FATAL
            return s
        if n == AR_STACK_LIMIT:
            s["ret"] = AR_R_OVERFLOW
            return s
        s["stack"][n] = c["balance"]
        s["len"], s["ret"] = n + 1, AR_R_OK
        return s
    if n == 0:
        s["ret"] = AR_R_UNDERFLOW
        return s
    addr = ar_address_bytes(c["stack"][n - 1], mut)
    r = ar_load_account(c, s, copy, addr, 1 if op == AR_EXTCODESIZE else 0, mut)
    if r is None:
        s["ret"] = AR_R_OOG
        return s
    if op == AR_BALANCE:
        s["stack"][n - 1] = c["balance"]
    elif op == AR_EXTCODESIZE:
        if c["code_len"] is None:
            if "codesize_none_is_zero" in mut:
                s["stack"][n - 1] = 0
            else:
                s["panic"] = "extcodesize-code-none"
                return s
        else:
            s["stack"][n - 1] = c["code_len"]
    else:
        if "extcodehash_uses_loader_empty" in mut:
            empty = r[2]
        else:
            empty = c["hash"] in (AR_EMPTY_HASH, bytes(32)) and c["balance"] == 0 and c["nonce"] == 0
        s["stack"][n - 1] = 0 if empty else int.from_bytes(c["hash"], "big")
    s["ret"] = AR_R_OK
    return s


# ---------------------------------------------------------------- case images
def ar_interp_bytes(c, s):
    b = bytearray(c["interp_fill"])
    put(b, AR_I_STACK_PTR, 8, AR_STK_AT)
    put(b, AR_I_STACK_LEN, 8, s["len"])
    b[AR_I_ADDR:AR_I_ADDR + 20] = c["self_addr"]
    put(b, AR_I_GASREC + AR_G_REMAINING, 8, s["gas"])
    b[AR_I_SPEC] = c["spec"]
    return bytes(b)


def ar_host_bytes(c):
    b = bytearray(c["host_fill"])
    put(b, AR_H_PARAMS, 8, AR_PARAM_AT)
    b[AR_H_SPEC] = c["hspec"]
    return bytes(b)


def ar_param_bytes(c):
    b = bytearray(c["param_fill"])
    put(b, AR_P_COLD, 8, c["cold"])
    return bytes(b)


def ar_acct_bytes(c):
    b = bytearray(c["acct_fill"])
    put(b, AR_A_BAL, 32, c["balance"])
    b[AR_A_HASH:AR_A_HASH + 32] = c["hash"]
    put(b, AR_A_NONCE, 8, c["nonce"])
    put(b, AR_A_CODE, 8, 0 if c["code_len"] is None else AR_CREC_AT)
    b[AR_A_FLAGS] = c["flags"]
    return bytes(b)


def ar_crec_bytes(c):
    b = bytearray(c["crec_fill"])
    put(b, AR_C_LEN, 8, c["code_len"] or 0)
    return bytes(b)


def ar_stack_image(words):
    b = bytearray(32 * AR_STK_WORDS)
    for i, w in words.items():
        put(b, 32 * i, 32, w)
    return bytes(b)


# ---------------------------------------------------------------- contract stubs
class AR_CaseMachine(TraceMachine):
    def transfer(self, target, call, va):
        if target in self.panics:
            self.panic_site = va
            self.panic_arg = self.regs[7]
            raise Boundary("panic", self.regs)
        return super().transfer(target, call, va)


def ar_read_addr(m, at):
    return bytes(m.load(at + i, 1) for i in range(20))


def ar_state_stub(slot):
    def run(m):
        c = m.case
        out, skip = m.regs[7], m.regs[8]
        if m.regs[6] != AR_HOST_AT + AR_H_JOURNAL or m.regs[2] != AR_HOST_AT + AR_H_DB or skip not in (0, 1):
            fail(f"state loader {slot:#x} called outside its contract")
        m.calls.append(("state", slot, ar_read_addr(m, m.regs[1]).hex(), skip, 0))
        m.store(out + AR_S_ACCOUNT, 8, AR_ACCT_AT)
        m.store(out + AR_S_CODEARG, 8, AR_CODEARG)
        m.store(out + AR_S_TAG, 1, {"warm": 0, "cold": 1, "err": 2}[c["db"]])
    return run


def ar_state_direct_stub(m):
    c = m.case
    if m.regs[7] != AR_HOST_AT + AR_H_JOURNAL or m.regs[6] != AR_HOST_AT + AR_H_DB or m.regs[8] not in (0, 1)\
            or m.regs[1] not in (0, 1):
        fail("direct state loader called outside its contract")
    m.calls.append(("state-direct", AR_STATE_DIRECT, ar_read_addr(m, m.regs[2]).hex(), m.regs[8], m.regs[1]))
    m.regs[0] = AR_ACCT_AT
    m.regs[2] = 0x5a5a_5a5a_5a5a_5a00 | {"warm": 0, "cold": 1, "err": 2}[c["db"]]


def ar_code_stub(m):
    if m.regs[7] != AR_ACCT_AT:
        fail("code loader called outside its contract")
    m.calls.append(("code", AR_CODE_LOAD, m.regs[7], m.regs[6]))


def ar_arc_stub(m):
    fail("shared-pointer drop reached")


def ar_install(m, image):
    m.panics = {image.word(AR_PANIC_GOT)}
    m.panic_site = m.panic_arg = None
    m.calls = []
    for slot in AR_STATE_GOT.values():
        m.stubs[image.word(slot)] = ar_state_stub(slot)
    m.stubs[AR_STATE_DIRECT] = ar_state_direct_stub
    m.stubs[AR_CODE_LOAD] = ar_code_stub
    m.stubs[image.word(AR_ARC_DROP_GOT)] = ar_arc_stub


def ar_panic_sites(image):
    """Return addresses of the GOT panic calls inside the EXTCODESIZE copies (pattern lea rdi; call [rip])."""
    sites = {}
    for copy in (0, 1):
        start = AR_BODIES[(AR_EXTCODESIZE, copy)]
        va = start
        while va < start + 0x200:
            f = decode(image.code(va, 16), va)
            if f["op"] == 0xff and f["rm"][1] == "rip" and va + f["len"] + f["rm"][4] == AR_PANIC_GOT:
                sites[copy] = va + f["len"]
                break
            va += f["len"]
        else:
            fail(f"no panic call in EXTCODESIZE copy {copy}")
    return sites


def ar_run_case(m, c):
    m.reset()
    m.case = c
    ar_install(m, m.image)
    it = m.add_region(AR_INTERP_AT, AR_INTERP_SIZE, ar_interp_bytes(c, c))
    host = m.add_region(AR_HOST_AT, AR_HOST_SIZE, ar_host_bytes(c))
    par = m.add_region(AR_PARAM_AT, AR_PARAM_SIZE, ar_param_bytes(c))
    acct = m.add_region(AR_ACCT_AT, AR_ACCT_SIZE, ar_acct_bytes(c))
    crec = m.add_region(AR_CREC_AT, AR_CREC_SIZE, ar_crec_bytes(c))
    stk = m.add_region(AR_STK_AT, 32 * AR_STK_WORDS, ar_stack_image(c["stack"]))
    out = m.add_region(AR_OUT_AT, AR_OUT_SIZE, c["out_fill"])
    ab = m.add_region(AR_ADDR_AT, AR_ADDR_SIZE, c["addr"] + bytes(AR_ADDR_SIZE - 20))
    fixed = [bytes(r) for r in (host, par, acct, crec, ab)]
    for k, v in zip(AR_SAVED_REGS, AR_SAVED):
        m.regs[k] = v
    if c["op"] == AR_LOADER_OP:
        m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = (AR_OUT_AT, AR_INTERP_AT + AR_I_GASREC, AR_HOST_AT, AR_ADDR_AT,
                                                                   c["load_code"])
        start = AR_LOADERS[c["copy"]]
    else:
        m.regs[7], m.regs[6] = AR_INTERP_AT, AR_HOST_AT
        start = AR_BODIES[(c["op"], c["copy"])]
    try:
        m.run(start, limit=20000)
        ret, panic = m.regs[0] & 0xff, None
    except Boundary:
        ret, panic = None, (m.panic_site, m.panic_arg)
    return {"ret": ret, "panic": panic, "interp": bytes(it), "stack": bytes(stk), "out": bytes(out),
            "fixed_ok": [bytes(r) for r in (host, par, acct, crec, ab)] == fixed,
            "regs_ok": panic is not None or ([m.regs[k] for k in AR_SAVED_REGS] == AR_SAVED
                                             and m.regs[4] == STACK_TOP - 0x100),
            "calls": list(m.calls)}


def ar_compare(c, want, got, sites):
    if want["panic"] is not None or got["panic"] is not None:
        return (want["panic"] is not None and got["panic"] == (sites[c["copy"]], AR_PANIC_LOCATION)
                and got["fixed_ok"] and got["calls"] == want["calls"])
    if c["op"] == AR_LOADER_OP:
        return (got["regs_ok"] and got["fixed_ok"] and got["out"] == want["out"] and got["calls"] == want["calls"]
                and got["interp"] == ar_interp_bytes(c, want) and got["stack"] == ar_stack_image(c["stack"]))
    return (want["ret"] == got["ret"] and got["regs_ok"] and got["fixed_ok"] and got["calls"] == want["calls"]
            and got["interp"] == ar_interp_bytes(c, want) and got["stack"] == ar_stack_image(want["stack"])
            and got["out"] == c["out_fill"])


# ---------------------------------------------------------------- cases
AR_PER_BODY = 600
AR_PER_LOADER = 600
AR_SPECS = tuple(range(0x10)) + (0x7f, 0xff)
AR_HSPECS = (0, 1, 2, 3, 4, 5, 0x11, 0xff)
AR_LENS = (0, 1, 1, 2, 3, 9, 0x3fe, 0x3ff, 0x400)


def ar_rand_word(st):
    return int.from_bytes(st.take(32), "little")


def ar_pick_hash(st):
    kind = st.pick(("empty", "empty", "zero", "zero", "rand", "empty-lo-flip", "empty-hi-flip", "zero-one-bit"))
    if kind == "empty":
        return kind, AR_EMPTY_HASH
    if kind == "zero":
        return kind, bytes(32)
    if kind == "rand":
        return kind, st.take(32)
    b = bytearray(AR_EMPTY_HASH if kind.startswith("empty") else bytes(32))
    pos = st.below(16) + (16 if kind == "empty-hi-flip" else 0) if kind.startswith("empty") else st.below(32)
    b[pos] ^= 1 << st.below(8)
    return kind, bytes(b)


def ar_make_case(st, op, copy, k):
    c = {"id": f"{ar_name(op).lower()}-{copy}-{k:04d}", "op": op, "copy": copy}
    c["spec"] = st.pick(AR_SPECS)
    c["hspec"] = st.pick(AR_HSPECS)
    c["cold"] = st.pick((0, 1, 100, 2600, 2600, 1 << 63, M64, int.from_bytes(st.take(8), "little")))
    gk = st.pick(("below", "equal", "above", "zero", "max", "rand"))
    c["gas"] = {"below": (c["cold"] - 1) & M64 if c["cold"] else 0, "equal": c["cold"],
                "above": (c["cold"] + 1) & M64, "zero": 0, "max": M64,
                "rand": int.from_bytes(st.take(8), "little")}[gk]
    c["db"] = st.pick(("warm", "cold", "cold", "err"))
    c["balance"] = st.pick((0, 0, 1, 1 << 255, ar_rand_word(st)))
    c["hash_kind"], c["hash"] = ar_pick_hash(st)
    c["nonce"] = st.pick((0, 0, 1, int.from_bytes(st.take(8), "little")))
    c["flags"] = st.pick((0, AR_F_TOUCHED, AR_F_NOT_EXISTING, AR_F_TOUCHED | AR_F_NOT_EXISTING, st.take(1)[0]))
    c["code_len"] = st.pick((None, 0, 1, 0x6000, int.from_bytes(st.take(8), "little")))
    c["self_addr"] = st.take(20)
    c["interp_fill"] = st.take(AR_INTERP_SIZE)
    c["host_fill"] = st.take(AR_HOST_SIZE)
    c["param_fill"] = st.take(AR_PARAM_SIZE)
    c["acct_fill"] = st.take(AR_ACCT_SIZE)
    c["crec_fill"] = st.take(AR_CREC_SIZE)
    c["out_fill"] = st.take(AR_OUT_SIZE)
    if op == AR_LOADER_OP:
        c["len"], c["stack"] = 0, {}
        c["addr"] = st.take(20)
        c["load_code"] = k % 2
        c["spec"] = st.pick(AR_SPECS)
        return c
    n = st.pick(AR_LENS)
    c["len"] = n
    c["stack"] = {}
    for i in range(max(0, n - AR_WORDS_PER_FILL), n):
        c["stack"][i] = st.pick((ar_rand_word(st), ar_rand_word(st) & ((1 << 160) - 1), st.below(0x100)))
    c["addr"] = bytes(20)
    c["load_code"] = 0
    return c


def ar_all_cases():
    out = []
    for op in AR_OPS:
        for copy in (0, 1):
            st = Stream(f"re11-account-read-115/{ar_name(op)}/{copy}")
            out += [ar_make_case(st, op, copy, k) for k in range(AR_PER_BODY)]
    for copy in (0, 1):
        st = Stream(f"re11-account-read-115/loader/{copy}")
        out += [ar_make_case(st, AR_LOADER_OP, copy, k) for k in range(AR_PER_LOADER)]
    return out


# ---------------------------------------------------------------- static evidence
AR_CHECKED = (
    (0x2994f2a, "48 8b 5f 30", "handlers: stack length at interp+0x30"),
    (0x2994f5d, "48 c1 e9 20", "BALANCE: high address dword = bswap(limb 2) >> 32 (low 160 bits, big-endian)"),
    (0x2994f6f, "48 81 c6 70 01 00 00", "handlers: gas record interp+0x170 passed to the account loader"),
    (0x2994f83, "45 31 c0", "BALANCE: load_code = 0"),
    (0x2994f9b, "48 83 f8 02", "handlers: loader tag 2 = error"),
    (0x2994fa4, "b9 36 00 00 00", "handlers: error byte 1 would give 0x36 (loaders only write 0, giving 0x20)"),
    (0x2995066, "b0 2c", "handlers: empty stack gives 0x2c"),
    (0x29906a0, "80 bf a9 01 00 00 05", "EXTCODEHASH copy 0: spec byte interp+0x1a9 < 5 gives 0x2b"),
    (0x29908d0, "80 bf a9 01 00 00 05", "EXTCODEHASH copy 1: same gate"),
    (0x29908c0, "b0 2b", "EXTCODEHASH: not-activated result 0x2b"),
    (0x29907c9, "66 0f 74 0d 4f 18 ac fd", "EXTCODEHASH: code hash high half compared with rodata 0x452020"),
    (0x29907d1, "66 0f 74 05 17 30 ac fd", "EXTCODEHASH: code hash low half compared with rodata 0x4537f0"),
    (0x2990832, "48 83 3f 00", "EXTCODEHASH: nonce == 0 test"),
    (0x2990b63, "41 b8 01 00 00 00", "EXTCODESIZE copy 0: load_code = 1"),
    (0x2990c1e, "48 8b 49 50", "EXTCODESIZE: bytecode length at +0x50"),
    (0x2990c69, "48 8d 3d 98 2b ab 03", "EXTCODESIZE: panic location record 0x6443808 (code None)"),
    (0x2990d03, "41 b8 01 00 00 00", "EXTCODESIZE copy 1: load_code = 1"),
    (0x2990f10, "80 bf a9 01 00 00 06", "SELFBALANCE copy 0: spec byte < 6 gives 0x2b"),
    (0x2990e40, "80 bf a9 01 00 00 06", "SELFBALANCE copy 1: same gate"),
    (0x2990f2b, "8b 87 88 00 00 00", "SELFBALANCE: address bytes 16..19 at interp+0x88"),
    (0x2990f35, "0f 10 47 78", "SELFBALANCE: address bytes 0..15 at interp+0x78"),
    (0x2990f63, "b0 36", "SELFBALANCE: state-load error gives 0x36"),
    (0x2990f8d, "48 3d 00 04 00 00", "SELFBALANCE: stack limit 0x400 checked after the load"),
    (0x2990fcc, "b0 2d", "SELFBALANCE: overflow result 0x2d"),
    (0x2990ff7, "48 8b 82 50 02 00 00", "loader 0: host+0x250 parameter block"),
    (0x2990ffe, "48 8b 80 80 00 00 00", "loader 0: cold account price at params+0x80"),
    (0x2991005, "4c 8b 66 18", "loader 0: remaining gas at record+0x18"),
    (0x2991014, "41 0f 92 c0", "loader 0: skip_cold_load = remaining < price"),
    (0x299101f, "44 0f b6 aa 96 03 00 00", "loader 0: spec byte host+0x396"),
    (0x2991027, "48 81 c2 98 03 00 00", "loader 0: database at host+0x398"),
    (0x299103f, "41 80 fe 02", "loader 0: state-load tag 2 = error"),
    (0x2991049, "48 c7 03 02 00 00 00", "loader 0: writes tag 2"),
    (0x2991075, "41 80 fd 02", "loader 0: spec > 2 selects the content rule"),
    (0x2991087, "66 0f 74 0d 91 0f ac fd", "loader 0: code hash high half vs 0x452020"),
    (0x299108f, "66 0f 74 05 59 27 ac fd", "loader 0: code hash low half vs 0x4537f0"),
    (0x29910e4, "49 83 7f 68 00", "loader 0: nonce at account+0x68"),
    (0x29910f9, "41 0f b6 8f 8c 00 00 00", "loader 0: status flags at account+0x8c"),
    (0x2991101, "f6 c1 08", "loader 0: flag 0x08 (loaded as not existing)"),
    (0x2991115, "f6 c1 04", "loader 0: flag 0x04 (touched)"),
    (0x2991126, "4c 2b 64 24 10", "loader 0: cold charge remaining - price"),
    (0x2991131, "4c 89 62 18", "loader 0: remaining gas stored only on success"),
    (0x2991135, "48 c7 03 00 00 00 00", "loader 0: writes tag 0"),
    (0x2991171, "48 8b b2 50 02 00 00", "loader 1: host+0x250 parameter block"),
    (0x2991178, "4c 8b a6 80 00 00 00", "loader 1: cold account price at params+0x80"),
    (0x2991194, "0f b6 aa 96 03 00 00", "loader 1: spec byte host+0x396"),
    (0x29911ac, "80 fa 02", "loader 1: direct state-load returns tag in dl"),
    (0x29911b5, "48 c7 03 02 00 00 00", "loader 1: writes tag 2"),
    (0x29911c8, "40 80 fd 02", "loader 1: spec > 2 selects the content rule"),
    (0x2991242, "0f b6 80 8c 00 00 00", "loader 1: status flags at account+0x8c"),
    (0x2991249, "a8 08", "loader 1: flag 0x08"),
    (0x2991256, "a8 04", "loader 1: flag 0x04"),
    (0x2991260, "4d 29 e7", "loader 1: cold charge"),
    (0x299126d, "48 c7 03 00 00 00 00", "loader 1: writes tag 0"),
)


def ar_hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def ar_static_evidence(image):
    starts = set(AR_BODIES.values()) | set(AR_LOADERS.values())
    fdes = fde_rows(image, starts)
    for table, copy in zip(AR_OP_TABLES, (0, 1)):
        if image.relative.get(table + 8 * AR_SLOAD_OP) not in AR_SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op in AR_OPS:
            if image.relative.get(table + 8 * op) != AR_BODIES[(op, copy)]:
                fail(f"opcode table {table:#x} slot {op:#x} does not name the {ar_name(op)} copy {copy}")
    for va, want, _ in AR_CHECKED:
        got = ar_hexs(image.code(va, len(bytes.fromhex(want.replace(" ", "")))))
        if got != want:
            fail(f"pinned bytes differ at {va:#x}: {got}")
    if image.read(AR_EMPTY_LO, 16) + image.read(AR_EMPTY_HI, 16) != AR_EMPTY_HASH:
        fail("rodata halves are not Keccak-256 of the empty string")
    insns = {}
    for key in sorted(AR_BODIES) + [(AR_LOADER_OP, 0), (AR_LOADER_OP, 1)]:
        start = AR_BODIES[key] if key[0] != AR_LOADER_OP else AR_LOADERS[key[1]]
        insns[key] = ar_sweep_padded(image, *fdes[start])
    if ar_loader_tags(insns) != {0: [0, 2], 1: [0, 2]}:
        fail("account loaders write an unexpected tag")
    return fdes, insns


def ar_loader_tags(insns):
    """Every 'mov qword [rbx], imm32' in a loader body: the output tags it can produce."""
    tags = {}
    for copy in (0, 1):
        tags[copy] = sorted({f["imm"] for _, f in insns[(AR_LOADER_OP, copy)]
                             if f["op"] == 0xc7 and f["size"] == 64 and f["rm"] == ("m", 3, None, 1, 0)})
    return tags


def ar_reach(key, va, seen, sites):
    if va in seen:
        return "yes"
    if key[0] == AR_EXTCODESIZE and va >= sites[key[1]]:
        return "no:after-noreturn-panic-or-landing-pad"
    return "no:tag-1-arm (loaders write tags 0 and 2 only)"


def ar_sweep_padded(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


# ---------------------------------------------------------------- evaluation and controls
def ar_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, cases=None, machine=None):
    m = machine or AR_CaseMachine(image, override)
    sites = ar_panic_sites(image)
    rows = []
    for c in cases:
        want = ar_model(c, mut)
        got = ar_run_case(m, c)
        ok = ar_compare(c, want, got, sites)
        rows.append((c, want, got, ok))
        if stop_on_first and not ok:
            break
    return rows, m


AR_MODEL_MUTANTS = ["hash_gate_minus_one", "no_cold_charge", "charge_warm_too", "skip_when_equal", "empty_ignores_spec",
                 "legacy_ignores_touched", "extcodehash_uses_loader_empty", "selfbalance_overflow_first",
                 "selfbalance_err_oog", "address_little_endian", "codesize_none_is_zero", "underflow_wraps",
                 "no_code_load_on_cold_oog"]
AR_BYTE_MUTANTS = [
    (0x29906a6, 0x06, "EXTCODEHASH copy 0 gate 5 -> 6"),
    (0x29908d6, 0x04, "EXTCODEHASH copy 1 gate 5 -> 4"),
    (0x2990f16, 0x07, "SELFBALANCE copy 0 gate 6 -> 7"),
    (0x2990f93, 0x75, "SELFBALANCE copy 0 je -> jne on the stack limit"),
    (0x2990f64, 0x37, "SELFBALANCE copy 0 error result 0x36 -> 0x37"),
    (0x2991001, 0x88, "loader 0 cold price params+0x80 -> +0x88"),
    (0x2991078, 0x03, "loader 0 content-rule spec bound 2 -> 3"),
    (0x2991103, 0x10, "loader 0 not-existing flag 0x08 -> 0x10"),
    (0x2991117, 0x08, "loader 0 touched flag 0x04 -> 0x08"),
    (0x299108b, 0x81, "loader 0 empty-hash high-half displacement"),
    (0x2991134, 0x10, "loader 0 gas store record+0x18 -> +0x10"),
    (0x29911cb, 0x01, "loader 1 content-rule spec bound 2 -> 1"),
    (0x2991257, 0x0c, "loader 1 touched flag 0x04 -> 0x0c"),
    (0x2991261, 0x01, "loader 1 sub -> add on the cold charge"),
    (0x2990c21, 0x48, "EXTCODESIZE copy 0 code length +0x50 -> +0x48"),
    (0x29907cd, 0x3f, "EXTCODEHASH copy 0 empty-hash high-half displacement"),
    (0x2994f60, 0x18, "BALANCE copy 0 address shift 0x20 -> 0x18"),
    (0x29950c0, 0x18, "BALANCE copy 1 address shift 0x20 -> 0x18"),
]


def ar_controls(image, cases):
    rows = []
    for mt in AR_MODEL_MUTANTS:
        r, _ = ar_evaluate(image, mut=frozenset([mt]), stop_on_first=True, cases=cases)
        bad = next((x[0]["id"] for x in r if not x[3]), "")
        rows.append(("model", mt, "detected" if bad else "MISSED", bad))
    for va, value, label in AR_BYTE_MUTANTS:
        if image.code(va, 1)[0] == value:
            fail(f"byte mutant at {va:#x} does not change the byte")
        try:
            r, _ = ar_evaluate(image, override={va: value}, stop_on_first=True, cases=cases)
            bad = next((x[0]["id"] for x in r if not x[3]), "")
        except ToolError as exc:
            bad = "tool-error:" + str(exc).split(" at ")[0]
        rows.append(("code", f"{va:#x}={value:#04x} {label}", "detected" if bad else "MISSED", bad))
    bad = bytearray(image.data)
    bad[0x1000] ^= 1
    try:
        Image(bytes(bad))
        rows.append(("input", "binary with one flipped byte", "MISSED", ""))
    except ToolError:
        rows.append(("input", "binary with one flipped byte", "detected", "sha256"))
    try:
        Machine(image).fetch(image.text["address"] + image.text["size"] + 0x10)
        rows.append(("input", "code fetch outside .text", "MISSED", ""))
    except ToolError:
        rows.append(("input", "code fetch outside .text", "detected", "range"))
    return rows


def ar_outcome(c, want):
    if want["panic"] is not None:
        return "panic:" + want["panic"]
    if c["op"] == AR_LOADER_OP:
        if want["out"][AR_O_TAG] == 2:
            return "error"
        return f"ok cold={want['out'][AR_O_COLD]} empty={want['out'][AR_O_EMPTY]}"
    r = {AR_R_OK: "ok", AR_R_OOG: "out-of-gas", AR_R_NOT_ACTIVE: "not-activated", AR_R_UNDERFLOW: "underflow",
         AR_R_OVERFLOW: "overflow", AR_R_FATAL: "fatal"}[want["ret"]]
    if want["ret"] == AR_R_OK and want["gas"] != c["gas"]:
        r += "+cold-charge"
    return r


def ar_generate(out):
    image = load_image()
    fdes, insns = ar_static_evidence(image)
    cases = ar_all_cases()
    rows, m = ar_evaluate(image, cases=cases, machine=AR_CaseMachine(image))
    mism = [r[0]["id"] for r in rows if not r[3]]
    if mism:
        fail(f"{len(mism)} mismatches, first {mism[:5]}")
    ctl = ar_controls(image, cases)
    if any(r[2] != "detected" for r in ctl):
        fail(f"negative control missed: {[r for r in ctl if r[2] != 'detected']}")
    sites = ar_panic_sites(image)
    seen = m.seen
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    lines = ["case\tbody\tspec\thost_spec\tstack_len\ttop\tgas\tcold_price\tstate\tbalance\thash\tnonce\tflags\t"
             "code_len\tload_code\tret_or_panic\tstack_len_after\tgas_after\tresult_word\tout_record\tcalls\tmatch"]
    classes = {}
    for c, want, got, ok in rows:
        n = c["len"]
        body = AR_LOADERS[c["copy"]] if c["op"] == AR_LOADER_OP else AR_BODIES[(c["op"], c["copy"])]
        oc = ar_outcome(c, want)
        key = (ar_name(c["op"]), c["copy"], oc)
        classes[key] = classes.get(key, 0) + 1
        res = "-"
        if want["ret"] == AR_R_OK and c["op"] != AR_LOADER_OP:
            res = f"{want['stack'][want['len'] - 1]:064x}"
        lines.append("\t".join([
            c["id"], f"{body:#x}", f"{c['spec']:#x}", f"{c['hspec']:#x}", str(n),
            f"{c['stack'][n - 1]:064x}" if n else "-", f"{c['gas']:#x}", f"{c['cold']:#x}", c["db"],
            f"{c['balance']:#x}", c["hash_kind"], f"{c['nonce']:#x}", f"{c['flags']:#04x}",
            "none" if c["code_len"] is None else f"{c['code_len']:#x}", str(c["load_code"]),
            f"panic@{sites[c['copy']]:#x}" if want["panic"] else ("-" if want["ret"] is None else f"{want['ret']:#04x}"),
            str(want["len"]), f"{want['gas']:#x}", res,
            "-" if want["out"] is None else want["out"][:0x10].hex() + ":" + want["out"][AR_O_COLD:AR_O_EMPTY + 1].hex(),
            ";".join(f"{k[0]}@{k[1]:#x}({','.join(str(x) for x in k[2:])})" if k[0] != "code"
                     else f"code@{k[1]:#x}({k[2]:#x},{k[3]:#x})" for k in want["calls"]) or "-",
            "yes" if ok else "no"]))
    (out / "ar-cases.tsv").write_text("\n".join(lines) + "\n")
    oc_lines = ["body\tcopy\toutcome\tcases"] + [f"{a}\t{b}\t{o}\t{n}" for (a, b, o), n in sorted(classes.items())]
    (out / "ar-outcome-classes.tsv").write_text("\n".join(oc_lines) + "\n")
    ins_lines = ["body\tcopy\tva\tbytes\texecuted"]
    total = hit = 0
    unreached = {}
    for key in sorted(insns):
        for va, f in insns[key]:
            total += 1
            hit += va in seen
            r = ar_reach(key, va, seen, sites)
            unreached[r] = unreached.get(r, 0) + 1
            ins_lines.append(f"{ar_name(key[0])}\t{key[1]}\t{va:#x}\t{ar_hexs(f['bytes'])}\t{r}")
    (out / "ar-decoded-instructions.tsv").write_text("\n".join(ins_lines) + "\n")
    fn = ["role\tname\tcopy\tstart\tend\tsize\tsha256"]
    for key in sorted(insns):
        start = AR_BODIES[key] if key[0] != AR_LOADER_OP else AR_LOADERS[key[1]]
        s, e = fdes[start]
        role = "account loader" if key[0] == AR_LOADER_OP else "handler"
        fn.append(f"{role}\t{ar_name(key[0])}\t{key[1]}\t{s:#x}\t{e:#x}\t{e - s}\t{hashlib.sha256(image.code(s, e - s)).hexdigest()}")
    (out / "ar-functions.tsv").write_text("\n".join(fn) + "\n")
    const = {
        "binary_sha256": SHA256,
        "opcode_tables": {f"{t:#x}": {ar_name(op): f"{image.relative[t + 8 * op]:#x}" for op in AR_OPS} for t in AR_OP_TABLES},
        "account_loaders": {str(k): f"{v:#x}" for k, v in AR_LOADERS.items()},
        "pinned_bytes": [{"va": f"{va:#x}", "bytes": b, "meaning": t} for va, b, t in AR_CHECKED],
        "got_slots": {"state_loader_copy0": f"{AR_STATE_GOT[0]:#x}->{image.word(AR_STATE_GOT[0]):#x}",
                      "state_loader_copy1": f"{AR_STATE_GOT[1]:#x}->{image.word(AR_STATE_GOT[1]):#x}",
                      "shared_pointer_drop": f"{AR_ARC_DROP_GOT:#x}->{image.word(AR_ARC_DROP_GOT):#x}",
                      "panic": f"{AR_PANIC_GOT:#x}->{image.word(AR_PANIC_GOT):#x}"},
        "direct_callees": {"state_loader_direct": f"{AR_STATE_DIRECT:#x}", "code_loader": f"{AR_CODE_LOAD:#x}"},
        "panic_sites": {str(k): f"{v:#x}" for k, v in sorted(sites.items())},
        "panic_location_record": f"{AR_PANIC_LOCATION:#x}",
        "empty_code_hash": {"rodata_lo": f"{AR_EMPTY_LO:#x}", "rodata_hi": f"{AR_EMPTY_HI:#x}",
                            "bytes": (image.read(AR_EMPTY_LO, 16) + image.read(AR_EMPTY_HI, 16)).hex(),
                            "keccak256_empty_recomputed": AR_EMPTY_HASH.hex()},
        "fields": {"interp": {"stack_ptr": AR_I_STACK_PTR, "stack_len": AR_I_STACK_LEN, "self_address": AR_I_ADDR,
                              "gas_record": AR_I_GASREC, "gas_remaining": AR_I_GASREC + AR_G_REMAINING, "spec": AR_I_SPEC},
                   "host": {"params": AR_H_PARAMS, "journal": AR_H_JOURNAL, "spec": AR_H_SPEC, "database": AR_H_DB},
                   "params": {"cold_account_price": AR_P_COLD},
                   "account": {"balance": AR_A_BAL, "code_hash": AR_A_HASH, "nonce": AR_A_NONCE, "code": AR_A_CODE,
                               "status_flags": AR_A_FLAGS},
                   "bytecode": {"len": AR_C_LEN},
                   "state_load_record": {"account": AR_S_ACCOUNT, "code_arg": AR_S_CODEARG, "tag": AR_S_TAG},
                   "account_load_record": {"tag": AR_O_TAG, "balance_ptr": AR_O_PTR, "cold": AR_O_COLD, "empty": AR_O_EMPTY}},
        "results": {"ok": AR_R_OK, "out_of_gas": AR_R_OOG, "not_activated": AR_R_NOT_ACTIVE, "underflow": AR_R_UNDERFLOW,
                    "overflow": AR_R_OVERFLOW, "fatal": AR_R_FATAL},
        "spec_gates": {"EXTCODEHASH": AR_HASH_GATE, "SELFBALANCE": AR_SELF_GATE, "empty_rule_legacy_max": AR_LEGACY_SPEC_MAX},
        "status_flags": {"touched": AR_F_TOUCHED, "loaded_as_not_existing": AR_F_NOT_EXISTING},
        "stack_limit": AR_STACK_LIMIT,
        "loader_tags_written": {str(k): v for k, v in ar_loader_tags(insns).items()},
    }
    (out / "ar-constants.json").write_text(json.dumps(const, indent=2, sort_keys=True) + "\n")
    ctl_lines = ["kind\tcontrol\tresult\tfirst_detecting_case"] + ["\t".join(r) for r in ctl]
    (out / "ar-negative-controls.tsv").write_text("\n".join(ctl_lines) + "\n")
    summary = {
        "binary_sha256": SHA256,
        "cases": len(rows), "matches": sum(1 for r in rows if r[3]),
        "cases_per_body": {f"{ar_name(k[0])}/{k[1]}": sum(1 for r in rows if (r[0]["op"], r[0]["copy"]) == k)
                           for k in sorted(insns)},
        "instructions": total, "instructions_executed": hit,
        "instruction_reach": dict(sorted(unreached.items())),
        "negative_controls": len(ctl), "negative_controls_detected": sum(1 for r in ctl if r[2] == "detected"),
        "outcome_classes": len(classes),
    }
    (out / "ar-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ====================================================================================================
# family tw: re11_transient_writer115 (names prefixed tw_ / TW_)
# ====================================================================================================
TW_WRITER = 0x2972390  # transient write called by TSTORE 0x2994e90 (direct call 0x2994f0c)
TW_TSTORE = 0x2994e90
TW_RESERVE_GOT = 0x64e6c90  # inner-table reserve (called with additional = 1 when growth_left == 0)
TW_GROW_GOT = 0x64e6cf0  # journal vector grow-one
TW_SEED_GOT = 0x64dfa78  # RELATIVE slot -> per-process hash seed word (NOBITS, so the tool supplies it)

# writer argument offsets (argument = host +0x270)
TW_J_CAP, TW_J_PTR, TW_J_LEN = 0x18, 0x20, 0x28
TW_M_CTRL, TW_M_MASK, TW_M_GROWTH, TW_M_ITEMS, TW_M_SECRET = 0xf0, 0xf8, 0x100, 0x108, 0x110
# inner header inside an outer bucket, relative to the bucket end
TW_I_CTRL, TW_I_MASK, TW_I_GROWTH, TW_I_ITEMS, TW_I_SECRET = -0x28, -0x20, -0x18, -0x10, -0x08
TW_BUCKET = 0x40
TW_REC = 0x58  # journal record: tag 0x0a, address, 3 padding bytes, key, old value
TW_REC_TAG = 0x0a
TW_REC_PAD = range(0x15, 0x18)
TW_EMPTY, TW_DELETED = 0xff, 0x80
TW_RESERVED_GROWTH = 5  # what the reserve stub leaves in growth_left
TW_GROW_BY = 4  # what the journal grow stub adds to the capacity

TW_ARG_AT = 0x7d00_0100_0000
TW_ARG_SIZE = 0x200
TW_ARGS_AT = 0x7d00_0200_0000  # address / key / value buffers
TW_JOURNAL_AT = 0x7d00_0300_0000
TW_TABLE_AT = 0x7d00_0400_0000
TW_INNER_AT = 0x7d00_0500_0000
TW_INNER_STRIDE = 0x1_0000
TW_ARG_FILL, TW_JOURNAL_FILL, TW_TABLE_FILL = 0x44, 0x77, 0x66
TW_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


# ---------------------------------------------------------------- reconstruction
def tw_addr_hash(addr, secret, seed, mut=frozenset()):
    """Outer key hash of a 20-byte address (folded two-multiply hash with the map secret)."""
    a0, a1, a2 = (int.from_bytes(addr[0:8], "little"), int.from_bytes(addr[8:16], "little"),
                  int.from_bytes(addr[16:20], "little"))
    p = (a0 ^ (secret if "hash_no_secret" not in mut else 0)) * (a1 ^ seed)
    z = (p & M64) ^ a2 ^ (p >> 64)
    p = z * seed
    return (p & M64) ^ (p >> 64)


def tw_key_hash(key, secret, seed, mut=frozenset()):
    """Inner key hash of a 256-bit slot (four little-endian limbs) with the per-address secret."""
    k = [(key >> (64 * i)) & M64 for i in range(4)]
    p = (k[0] ^ secret) * (k[1] ^ seed)
    z = (p & M64) ^ (p >> 64) ^ k[2]
    p = z * (seed ^ (k[3] if "hash_no_k3" not in mut else 0))
    return (p & M64) ^ (p >> 64)


class TW_Table:
    """A hashbrown table as the model sees it: control bytes and full-slot contents."""

    def __init__(self, nb, ctrl, slots):
        self.nb, self.mask, self.ctrl, self.slots = nb, nb - 1, list(ctrl), dict(slots)

    def group(self, pos):
        return [self.ctrl[(pos + k) & self.mask] for k in range(16)]

    def set_ctrl(self, i, byte, edits):
        self.ctrl[i] = byte
        edits.append(("ctrl", i, byte))
        edits.append(("ctrl", ((i - 16) & self.mask) + 16, byte))

    def find(self, key, h, mut=frozenset()):
        """Probe for key; returns (slot or None, first special slot seen before the stopping group)."""
        h2 = h >> (57 if "h2_shift56" not in mut else 56)
        pos, stride, ins = h & self.mask, 0, None
        while True:
            g = self.group(pos)
            for k in range(16):
                if g[k] == h2:
                    i = (pos + k) & self.mask
                    if self.slots.get(i, (None,))[0] == key:
                        return i, ins
            if ins is None:
                sp = [k for k in range(16) if g[k] & 0x80]
                if sp:
                    ins = (pos + sp[0]) & self.mask
            if TW_EMPTY in g:
                return None, ins
            stride += 16
            pos = (pos + stride) & self.mask


def tw_remove_byte(t, i, mut=frozenset()):
    """hashbrown erase: DELETED when the non-EMPTY run through i spans a whole group, else EMPTY.

    lz = non-EMPTY bytes at the end of the group before i, tz = non-EMPTY bytes from i on."""
    before = t.group((i - 16) & t.mask)
    after = t.group(i)
    lz = 0
    for b in reversed(before):
        if b == TW_EMPTY:
            break
        lz += 1
    tz = 0
    for b in after:
        if b == TW_EMPTY:
            break
        tz += 1
    limit = 16 if "erase_limit15" not in mut else 15
    return TW_DELETED if lz + tz >= limit else TW_EMPTY


def tw_model(c, mut=frozenset()):
    """0x2972390 reconstructed: edits to the transient map and the journal, calls made, or the boundary."""
    edits, calls = [], []
    out = {"edits": edits, "calls": calls, "ret": ("ret",)}
    addr, key, value = c["addr"], c["key"], c["value"]
    outer = TW_Table(c["buckets"], c["ctrl"], {i: (a,) for a, i in c["slot_of"].items()})
    if value == 0 or "remove_any" in mut:
        if c["outer_items"] == 0 and "ignore_outer_items" not in mut:
            return out
    oslot, _ = outer.find(addr, tw_addr_hash(addr, c["secret"], c["seed"], mut), mut)
    if oslot is None:
        if value == 0:
            return out
        out["ret"] = ("boundary", "tls")
        return out
    inner = c["maps"][addr]
    it = TW_Table(inner["buckets"], inner["ctrl"], {i: kv for i, kv in inner["slots"].items()})
    growth, items = inner["growth"], inner["items"]
    h = tw_key_hash(key, inner["secret"], c["seed"], mut)
    if value == 0 or "remove_any" in mut:
        slot, _ = it.find(key, h, mut)
        if slot is None:
            return out
        old = it.slots[slot][1]
        byte = tw_remove_byte(it, slot, mut)
        if byte == TW_EMPTY:
            growth += 1
            edits.append(("inner", "growth", growth))
        it.set_ctrl(slot, byte, edits)
        edits.append(("inner", "items", items - 1))
    else:
        if growth == 0 and "no_reserve" not in mut:
            calls.append(("reserve", addr.hex()))
            growth = TW_RESERVED_GROWTH
            edits.append(("inner", "growth", growth))
        slot, ins = it.find(key, h, mut)
        if slot is not None:
            old = it.slots[slot][1]
            edits.append(("value", slot, value))
            if old == value and "journal_always" not in mut:
                return out
        else:
            old = 0
            prev = it.ctrl[ins]
            it.set_ctrl(ins, h >> 57, edits)
            if prev == TW_EMPTY and "growth_on_deleted" not in mut:
                edits.append(("inner", "growth", growth - 1))
            elif prev != TW_EMPTY and "growth_on_deleted" in mut:
                edits.append(("inner", "growth", growth - 1))
            edits.append(("inner", "items", items + 1))
            edits.append(("key", ins, key))
            edits.append(("value", ins, value))
    cap, n = c["jcap"], c["jlen"]
    if n == cap and "no_grow" not in mut:
        calls.append(("grow",))
        edits.append(("journal", "cap", cap + TW_GROW_BY))
    rec = bytearray(TW_REC)
    rec[0] = TW_REC_TAG if "tag_0b" not in mut else 0x0b
    rec[1:0x15] = addr
    rec[0x18:0x38] = key.to_bytes(32, "little")
    rec[0x38:0x58] = (old if "journal_new" not in mut else value).to_bytes(32, "little")
    edits.append(("record", n, bytes(rec)))
    edits.append(("journal", "len", n + 1))
    return out


# ---------------------------------------------------------------- fixture: hashbrown tables
def tw_layout(nb, entries, tombs, decoys, key_len):
    """hashbrown layout: entries [(key bytes, hash, payload)], tombs [slot], decoys [(slot, h2, key bytes)].

    Returns (memory, ctrl offset, ctrl list, {key bytes: slot}).  Inserts take the first EMPTY/DELETED
    byte of the first probe group that has one (triangular probing), like hashbrown's insert path."""
    mask = nb - 1
    mem = bytearray([TW_TABLE_FILL]) * (nb * TW_BUCKET + nb + 16)
    ctrl_off = nb * TW_BUCKET
    ctrl = [TW_EMPTY] * nb
    for i in tombs:
        ctrl[i] = TW_DELETED
    taken = set()
    for i, h2, key in decoys:
        ctrl[i] = h2
        taken.add(i)
        mem[ctrl_off - (i + 1) * TW_BUCKET:ctrl_off - (i + 1) * TW_BUCKET + len(key)] = key
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
        at = ctrl_off - (slot + 1) * TW_BUCKET
        mem[at:at + len(key)] = key
        mem[at + key_len:at + key_len + len(payload)] = payload
    if TW_EMPTY not in ctrl:
        fail("table has no EMPTY slot")
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb]
    return mem, ctrl_off, ctrl, slots


def tw_build(c):
    """Regions for the outer table and every inner table; fills the model's view of both levels."""
    regions = []
    outer_entries = []
    for j, addr in enumerate(c["order"]):
        inner = c["maps"][addr]
        entries = [(k.to_bytes(32, "little"), tw_key_hash(k, inner["secret"], c["seed"]), v.to_bytes(32, "little"))
                   for k, v in inner["order"]]
        mem, coff, ctrl, slots = tw_layout(inner["buckets"], entries, inner["tombs"], inner["decoys"], 32)
        base = TW_INNER_AT + j * TW_INNER_STRIDE
        regions.append((base, mem))
        inner["base"], inner["ctrl"], inner["coff"] = base, ctrl, coff
        inner["slots"] = {slots[k.to_bytes(32, "little")]: (k, v) for k, v in inner["order"]}
        for i, _, kb in inner["decoys"]:
            inner["slots"][i] = (int.from_bytes(kb, "little"), None)
        head = bytearray(4) + struct.pack("<QQQQQ", base + coff, inner["buckets"] - 1, inner["growth"], inner["items"],
                                          inner["secret"])
        outer_entries.append((addr, tw_addr_hash(addr, c["secret"], c["seed"]), bytes(head)))
    mem, coff, ctrl, slots = tw_layout(c["buckets"], outer_entries, c["tombs"], c["decoys"], 20)
    regions.append((TW_TABLE_AT, mem))
    c["ctrl"], c["slot_of"] = ctrl, slots
    for i, _, ab in c["decoys"]:
        c["slot_of"].setdefault(ab, i)
    return regions, TW_TABLE_AT + coff


def tw_apply(c, regions, arg, journal, edits):
    """Expected final bytes: the fixture regions with the model's edits applied."""
    mem = {base: bytearray(m) for base, m in regions}
    arg = bytearray(arg)
    journal = bytearray(journal)
    inner = c["maps"].get(c["addr"])
    if inner is not None:
        im, coff = mem[inner["base"]], inner["coff"]
        oslot = c["slot_of"][c["addr"]]
        om = mem[TW_TABLE_AT]
        oend = c["buckets"] * TW_BUCKET - oslot * TW_BUCKET
    for e in edits:
        if e[0] == "ctrl":
            im[coff + e[1]] = e[2]
        elif e[0] == "inner":
            off = {"growth": TW_I_GROWTH, "items": TW_I_ITEMS}[e[1]]
            put(om, oend + off, 8, e[2])
        elif e[0] == "key":
            at = coff - (e[1] + 1) * TW_BUCKET
            im[at:at + 32] = e[2].to_bytes(32, "little")
        elif e[0] == "value":
            at = coff - (e[1] + 1) * TW_BUCKET + 32
            im[at:at + 32] = e[2].to_bytes(32, "little")
        elif e[0] == "journal":
            put(arg, {"cap": TW_J_CAP, "len": TW_J_LEN}[e[1]], 8, e[2])
        elif e[0] == "record":
            journal[e[1] * TW_REC:(e[1] + 1) * TW_REC] = e[2]
    return mem, bytes(arg), bytes(journal)


# ---------------------------------------------------------------- harness
def tw_setup(m, c):
    calls = []
    regions, ctrl = tw_build(c)
    arg = bytearray([TW_ARG_FILL]) * TW_ARG_SIZE
    put(arg, TW_J_CAP, 8, c["jcap"])
    put(arg, TW_J_PTR, 8, TW_JOURNAL_AT)
    put(arg, TW_J_LEN, 8, c["jlen"])
    put(arg, TW_M_CTRL, 8, ctrl)
    put(arg, TW_M_MASK, 8, c["buckets"] - 1)
    put(arg, TW_M_GROWTH, 8, c["outer_growth"])
    put(arg, TW_M_ITEMS, 8, c["outer_items"])
    put(arg, TW_M_SECRET, 8, c["secret"])
    journal = bytes([TW_JOURNAL_FILL]) * (TW_REC * (c["jcap"] + TW_GROW_BY))
    args = c["addr"] + bytes(12) + c["key"].to_bytes(32, "little") + c["value"].to_bytes(32, "little")
    m.add_region(TW_ARG_AT, TW_ARG_SIZE, bytes(arg))
    m.add_region(TW_JOURNAL_AT, len(journal), journal)
    m.add_region(TW_ARGS_AT, len(args), args)
    for base, mem in regions:
        m.add_region(base, len(mem), bytes(mem))
    m.add_region(m.image.word(TW_SEED_GOT), 8, c["seed"].to_bytes(8, "little"))

    def clobber(mc):
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1
        for r in range(16):
            mc.xmm[r] = 0xc2c2_c2c2_c2c2_c2c2_c2c2_c2c2_c2c2_c2c2

    def reserve(mc):
        tbl, add, hasher, fallible = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        if add != 1 or fallible != 1 or hasher != tbl + 0x20:
            fail(f"reserve arguments {add:#x} {fallible:#x} {hasher - tbl:#x}")
        a = bytes(mc.load(tbl - 0x18 + i, 1) for i in range(20))
        calls.append(("reserve", a.hex()))
        mc.store(tbl + 0x10, 8, TW_RESERVED_GROWTH)
        clobber(mc)

    def grow(mc):
        vec = mc.regs[7]
        if vec != TW_ARG_AT + TW_J_CAP:
            fail(f"grow argument {vec:#x}")
        calls.append(("grow",))
        mc.store(vec, 8, mc.load(vec, 8) + TW_GROW_BY)
        clobber(mc)
    m.stubs = {m.image.word(TW_RESERVE_GOT): reserve, m.image.word(TW_GROW_GOT): grow}
    return calls, regions, bytes(arg), journal


def tw_snapshot(m, base):
    return bytes(next(buf for lo, hi, buf in m.regions if lo == base))


def tw_run_case(m, c):
    m.reset()
    calls, regions, arg, journal = tw_setup(m, c)
    for k, v in zip((3, 12, 13, 14, 15, 5), TW_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = TW_ARG_AT, TW_ARGS_AT, TW_ARGS_AT + 32, TW_ARGS_AT + 64
    got = {"calls": calls}
    try:
        m.run(TW_WRITER, limit=20000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got, regions, arg, journal
    except ToolError as exc:
        if not str(exc).startswith("fs-relative operand at 0x29725f7"):
            raise
        got["ret"] = ("boundary", "tls")
        return got, regions, arg, journal
    got["ret"] = ("ret",)
    got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == TW_SAVED and m.regs[4] == STACK_TOP - 0x100
    got["mem"] = {base: tw_snapshot(m, base) for base, _ in regions}
    got["arg"] = tw_snapshot(m, TW_ARG_AT)
    j = bytearray(tw_snapshot(m, TW_JOURNAL_AT))
    got["pad"] = []
    for n in range(len(j) // TW_REC):
        if j[n * TW_REC] == TW_REC_TAG and n >= c["jlen"]:
            got["pad"].append(bytes(j[n * TW_REC + 0x15:n * TW_REC + 0x18]))
            j[n * TW_REC + 0x15:n * TW_REC + 0x18] = bytes([TW_JOURNAL_FILL]) * 3
    got["journal"] = bytes(j)
    got["args_ok"] = tw_snapshot(m, TW_ARGS_AT) == c["addr"] + bytes(12) + c["key"].to_bytes(32, "little") +\
        c["value"].to_bytes(32, "little")
    return got, regions, arg, journal


def tw_compare(c, want, got, regions, arg, journal):
    if want["ret"] != got["ret"] or want["calls"] != got["calls"]:
        return False
    if want["ret"] != ("ret",):
        return True
    mem, warg, wj = tw_apply(c, regions, arg, journal, want["edits"])
    wj = bytearray(wj)
    for e in want["edits"]:
        if e[0] == "record":
            wj[e[1] * TW_REC + 0x15:e[1] * TW_REC + 0x18] = bytes([TW_JOURNAL_FILL]) * 3
    return (got["regs_ok"] and got["args_ok"] and got["arg"] == warg and got["journal"] == bytes(wj)
            and all(got["mem"][b] == bytes(mem[b]) for b in mem))


# ---------------------------------------------------------------- cases
TW_TOTAL = 6000
TW_WORD_POOL = (1, 2, 0x100, M64, 1 << 64, 1 << 128, 1 << 192, M256)
TW_MODES = ["remove-hit", "remove-key-miss", "remove-addr-miss", "remove-empty-outer", "update-same", "update-new",
         "insert", "insert-tomb", "reserve", "journal-full", "cluster", "new-addr"]


def tw_rand_word(s):
    if s.below(10) < 4:
        return s.pick(TW_WORD_POOL)
    return (int.from_bytes(s.take(32), "little") >> (8 * s.below(32))) or 1


def tw_flip_key(s, key):
    return key ^ (1 << (64 * s.below(4) + s.below(64)))


def tw_decoys_for(s, h, nb, tombs, mk, n):
    out = []
    for _ in range(n):
        i = ((h & (nb - 1)) + s.below(16)) & (nb - 1)
        if i not in tombs and all(i != j for j, _, _ in out):
            out.append((i, h >> 57, mk()))
    return out


def tw_inner_map(s, seed, key, mode, target):
    nb = s.pick([16, 16, 32, 64])
    secret = int.from_bytes(s.take(8), "little")
    keys = []
    for _ in range(s.below(6) if mode != "cluster" or not target else 4 + s.below(nb // 2)):
        k = tw_rand_word(s)
        if k != key and k not in keys:
            keys.append(k)
    present = target and mode in ("remove-hit", "update-same", "update-new", "cluster", "journal-full") or\
        (target and mode == "reserve" and s.below(2))
    if present:
        keys.insert(s.below(len(keys) + 1), key)
    h = tw_key_hash(key, secret, seed)
    tombs = sorted({s.below(nb) for _ in range(s.below(4))})
    if target and mode == "insert-tomb":
        tombs = sorted(set(tombs) | {((h & (nb - 1)) + s.below(4)) & (nb - 1)})
    if target and mode == "remove-hit" and s.below(3) == 0:
        # crowd the neighbourhood so that erase has to leave a DELETED byte
        tombs = sorted(set(tombs) | {((h & (nb - 1)) + k) & (nb - 1) for k in range(-15, 17) if s.below(24)})
    decoys = []
    if target and (mode in ("cluster", "remove-key-miss") or s.below(4) == 0):
        decoys = tw_decoys_for(s, h, nb, tombs, lambda: tw_flip_key(s, key).to_bytes(32, "little"), 1 + s.below(3))
    if target and mode == "cluster":
        base = h & (nb - 1)
        for k in range(20):
            i = (base + k) & (nb - 1)
            if len(decoys) + len(keys) + len(tombs) + 2 >= nb:
                break
            if i not in tombs and all(i != j for j, _, _ in decoys) and s.below(5):
                decoys.append((i, s.below(0x80), s.take(32)))
    values = {k: tw_rand_word(s) for k in keys}
    full = len(keys) + len(decoys) + len(tombs)
    if full + 1 >= nb:
        keep = max(0, nb - 2 - len(keys) - len(decoys))
        tombs = tombs[:keep]
    growth = s.pick([1, 2, 7, 0x1234]) if not (target and mode == "reserve") else 0
    return {"buckets": nb, "secret": secret, "order": [(k, values[k]) for k in keys], "values": values,
            "tombs": tombs, "decoys": decoys, "items": len(keys) + len(decoys), "growth": growth}


def tw_make_case(s, mode):
    nb = s.pick([16, 16, 32, 64])
    secret = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little") | 1
    k = s.below(6)
    target = bytes(20) if k == 0 else bytes([0xff]) * 20 if k == 1 else s.take(20)
    key = tw_rand_word(s) if s.below(8) else s.pick([0, 1, M256])
    value = tw_rand_word(s)
    if mode.startswith("remove"):
        value = 0
    others = []
    while len(others) < s.below(5):
        a = s.take(20)
        if a != target and a not in others:
            others.append(a)
    order = list(others)
    present = mode not in ("remove-addr-miss", "new-addr")
    if present:
        order.insert(s.below(len(order) + 1), target)
    maps = {a: tw_inner_map(s, seed, key, mode, a == target) for a in order}
    if mode == "update-same":
        maps[target]["values"][key] = value
        maps[target]["order"] = [(kk, value if kk == key else vv) for kk, vv in maps[target]["order"]]
    tombs = sorted({s.below(nb) for _ in range(s.below(4))})
    h = tw_addr_hash(target, secret, seed)
    decoys = []
    if mode in ("remove-addr-miss", "new-addr", "cluster") or s.below(4) == 0:
        def fake_addr():
            f = bytearray(target)
            f[s.pick([0, 7, 8, 15, 16, 19])] ^= 1 << s.below(8)
            return bytes(f)
        decoys = tw_decoys_for(s, h, nb, tombs, fake_addr, 1 + s.below(3))
    outer_items = len(order) + len(decoys)
    if mode == "remove-empty-outer" or (mode == "remove-hit" and s.below(10) == 0):
        outer_items = 0
    jcap = s.pick([0, 1, 4, 8])
    jlen = jcap if mode == "journal-full" or s.below(3) == 0 else s.below(jcap + 1)
    return {"mode": mode, "buckets": nb, "secret": secret, "seed": seed, "addr": target, "key": key, "value": value,
            "order": order, "maps": maps, "tombs": tombs, "decoys": decoys, "outer_items": outer_items,
            "outer_growth": s.pick([1, 3, 0x4321]), "jcap": jcap, "jlen": jlen}


def tw_all_cases():
    s = Stream("re11-transient-writer-115")
    return [tw_make_case(s, TW_MODES[k % len(TW_MODES)]) for k in range(TW_TOTAL)]


# ---------------------------------------------------------------- static evidence
TW_FUNCS = (TW_WRITER,)
TW_CHECKED = (
    (0x29723a4, "f3 0f 6f 01", "value word loaded from the 4th argument"),
    (0x29723bc, "83 f0 0f", "value == 0 test (movmskps of the or-ed halves)"),
    (0x29723da, "48 8b 97 10 01 00 00", "outer secret at arg +0x110"),
    (0x2972405, "49 c1 ed 39", "outer h2 = hash >> 57"),
    (0x2972409, "48 8b 87 f0 00 00 00", "outer ctrl at arg +0xf0"),
    (0x29724d0, "48 83 bf 08 01 00 00 00", "remove: outer item count +0x108 == 0 -> return"),
    (0x29725c8, "48 83 bf 00 01 00 00 00", "new address: outer growth_left +0x100"),
    (0x29725f7, "64 48 33 04 25 88 fa ff ff", "new address: thread-local RandomState word (packet boundary)"),
    (0x297272d, "49 83 7c 24 e8 00", "insert: inner growth_left (bucket -0x18) == 0 -> reserve"),
    (0x29727b7, "66 0f d7 eb", "insert: key compared as two 16-byte lanes"),
    (0x2972812, "41 0f 10 45 e0", "update: old value = inner bucket -0x20..0"),
    (0x2972843, "0f 89 c0 03 00 00", "insert: small-table fix-up when the slot byte is FULL"),
    (0x2972875, "46 88 04 10", "insert: h2 into the control byte"),
    (0x2972879, "46 88 44 18 10", "insert: h2 into the mirror byte (index - 16) & mask + 16"),
    (0x2972895, "66 0f fb c1", "insert: growth_left -= EMPTY bit, items += 1 (one psubq)"),
    (0x2972906, "0f 84 a8 00 00 00", "old value == new value -> no journal record"),
    (0x297293d, "48 3b 5f 18", "journal: len +0x28 == cap +0x18 -> grow"),
    (0x2972960, "48 6b cb 58", "journal: record size 0x58"),
    (0x2972964, "c6 04 08 0a", "journal: record tag 0x0a"),
    (0x2972ac7, "66 bd 1f 00", "erase: bsr default 31 -> 16 leading EMPTY bytes"),
    (0x2972ae5, "66 41 83 f9 0f", "erase: EMPTY run of 16 or more -> DELETED"),
    (0x2972aec, "48 ff 41 e8", "erase: growth_left + 1 on EMPTY"),
    (0x2972afc, "48 ff 49 f0", "erase: items - 1"),
)


def tw_static_evidence(image):
    rows = fde_rows(image, TW_FUNCS)
    decoded, funcs = {}, {}
    for f in TW_FUNCS:
        lo, hi = rows[f]
        decoded[f] = tw_sweep_padded(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    calls = {}
    for va, fm in decoded[TW_WRITER]:
        if fm is None:
            continue
        if fm["bytes"][:2] == b"\xff\x15":
            slot = va + fm["len"] + struct.unpack_from("<i", fm["bytes"], 2)[0]
            calls[f"{va:#x}"] = {"got": f"{slot:#x}"}
        elif fm["op"] == 0xe8:
            calls[f"{va:#x}"] = {"direct": f"{fm['target']:#x}"}
    for slot in (TW_RESERVE_GOT, TW_GROW_GOT):
        if not any(v.get("got") == f"{slot:#x}" for v in calls.values()):
            fail(f"no call through {slot:#x}")
    seed = {"slot": f"{TW_SEED_GOT:#x}", "target": f"{image.word(TW_SEED_GOT):#x}",
            "target_section_has_file_bytes": image.section_of(image.word(TW_SEED_GOT))[0] is not None}
    checks = {}
    for va, hx, what in TW_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    tstore_call = image.code(0x2994f0c, 5)
    if tstore_call[0] != 0xe8 or 0x2994f11 + struct.unpack_from("<i", tstore_call, 1)[0] != TW_WRITER:
        fail("TSTORE no longer calls the writer")
    out = {"binary_sha256": SHA256, "functions": funcs, "calls": calls, "hash_seed": seed, "checked_bytes": checks,
           "tstore_call": {"site": "0x2994f0c", "target": f"{TW_WRITER:#x}"},
           "writer_arg_offsets": {"journal_cap": f"{TW_J_CAP:#x}", "journal_ptr": f"{TW_J_PTR:#x}", "journal_len": f"{TW_J_LEN:#x}",
                                  "ctrl": f"{TW_M_CTRL:#x}", "mask": f"{TW_M_MASK:#x}", "growth_left": f"{TW_M_GROWTH:#x}",
                                  "items": f"{TW_M_ITEMS:#x}", "secret": f"{TW_M_SECRET:#x}"},
           "inner_header_from_bucket_end": {"ctrl": "-0x28", "mask": "-0x20", "growth_left": "-0x18", "items": "-0x10",
                                            "secret": "-0x8"},
           "journal_record": {"bytes": TW_REC, "tag": TW_REC_TAG, "address": "0x1..0x15", "padding": "0x15..0x18",
                              "key": "0x18..0x38", "old_value": "0x38..0x58"},
           "stubs": {"reserve_got": f"{TW_RESERVE_GOT:#x}", "reserve_target": f"{image.word(TW_RESERVE_GOT):#x}",
                     "grow_got": f"{TW_GROW_GOT:#x}", "grow_target": f"{image.word(TW_GROW_GOT):#x}"}}
    return out, decoded


def tw_sweep_padded(image, lo, hi):
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
def tw_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or TraceMachine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else tw_all_cases()):
        try:
            got, regions, arg, journal = tw_run_case(m, c)
            want = tw_model(c, mut)
            ok = tw_compare(c, want, got, regions, arg, journal)
        except (ToolError, Boundary) as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


TW_MODEL_MUTANTS = ["hash_no_secret", "hash_no_k3", "h2_shift56", "erase_limit15", "remove_any", "ignore_outer_items",
                 "no_reserve", "journal_always", "growth_on_deleted", "no_grow", "tag_0b", "journal_new"]
TW_BYTE_MUTANTS = [
    (0x29723dd, 0x18, "outer secret +0x110 -> +0x118"),
    (0x2972408, 0x38, "outer h2 shift 57 -> 56"),
    (0x29724d7, 0x01, "remove: outer item count compared with 1"),
    (0x2972732, 0x01, "insert: growth_left compared with 1"),
    (0x2972907, 0x85, "journal only when old == new"),
    (0x2972940, 0x20, "journal compares len with ptr"),
    (0x2972967, 0x0b, "record tag 0x0a -> 0x0b"),
    (0x297287d, 0x00, "insert mirror byte (index - 16) & mask + 16 -> + 0"),
    (0x2972ae9, 0x0e, "erase limit 15 -> 14"),
    (0x2972aef, 0xe0, "erase growth_left -> mask"),
    (0x2972aff, 0xe8, "erase items -> growth_left"),
]


def tw_controls(image, cases):
    rows = []
    for name in TW_MODEL_MUTANTS:
        _, bad, _ = tw_evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in TW_BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = tw_evaluate(image, override={va: byte}, stop_on_first=True, cases=cases)
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
def tw_wtag(x):
    if x is None:
        return "-"
    if x == 0:
        return "0"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def tw_outcome(c, want, got):
    if "error" in got:
        return "error"
    if got["ret"] != ("ret",):
        return "-".join(got["ret"])
    kinds = [e[0] for e in want["edits"]]
    head = "remove" if c["value"] == 0 else "write"
    if not kinds:
        return f"{head}/no-change"
    tags = []
    if "key" in kinds:
        tags.append("insert")
    elif head == "write":
        tags.append("overwrite")
    else:
        b = [e[2] for e in want["edits"] if e[0] == "ctrl"][0]
        tags.append("erase-empty" if b == TW_EMPTY else "erase-deleted")
    tags += [x[0] for x in want["calls"]]
    tags.append("journal" if "record" in kinds else "no-journal")
    return head + "/" + "+".join(tags)


def tw_generate(out):
    image = load_image()
    out.mkdir(parents=True, exist_ok=True)
    cases = tw_all_cases()
    rows, bad, m = tw_evaluate(image, cases=cases)
    consts, decoded = tw_static_evidence(image)
    lines = ["case\tmode\tinput\toutcome\tcalls\tmatch"]
    classes = {}
    for i, c, want, got, ok in rows:
        oc = tw_outcome(c, want, got) if want is not None else "error"
        inner = c["maps"].get(c["addr"])
        inp = (f"buckets={c['buckets']},outer_items={c['outer_items']},addrs={len(c['order'])},"
               f"present={int(inner is not None)},inner_buckets={inner['buckets'] if inner else '-'},"
               f"inner_items={inner['items'] if inner else '-'},inner_growth={inner['growth'] if inner else '-'},"
               f"tombs={len(c['tombs'])}/{len(inner['tombs']) if inner else '-'},jcap={c['jcap']},jlen={c['jlen']},"
               f"addr={c['addr'].hex()},key={tw_wtag(c['key'])},value={tw_wtag(c['value'])}")
        calls = ",".join(x[0] for x in got.get("calls", [])) or "-"
        classes[oc] = classes.get(oc, 0) + 1
        lines.append(f"{i}\t{c['mode']}\t{inp}\t{oc}\t{calls}\t{'yes' if ok else 'NO'}")
    (out / "tw-cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "tw-outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\tfirst\tlast\tinstructions\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = total = 0
        run_lo = run_state = None
        prev = None
        segs = []
        for va, f in insns:
            if f is None:
                continue
            r = int(va in m.seen)
            hit += r
            total += 1
            if run_state is None or r != run_state:
                if run_state is not None:
                    segs.append((run_lo, prev, run_n, run_state))
                run_lo, run_state, run_n = va, r, 0
            run_n += 1
            prev = va
        segs.append((run_lo, prev, run_n, run_state))
        for lo, hi, n, r in segs:
            lines.append(f"{start:#x}\t{lo:#x}\t{hi:#x}\t{n}\t{r}")
        covered[f"{start:#x}"] = [hit, total]
    (out / "tw-coverage-runs.tsv").write_text("\n".join(lines) + "\n")
    ctl = tw_controls(image, cases)
    (out / "tw-negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "tw-constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(rows), "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes,
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "tw-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ====================================================================================================
# ec_: EXTCODECOPY handler, both opcode-table copies
# ====================================================================================================
# ---------------------------------------------------------------- ec target constants
EC_OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); each names its own copy here
EC_SLOAD_OP = 0x54
EC_SLOAD_BODIES = (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 of each table holds an SLOAD handler copy
EC_EXTCODECOPY = 0x3c
EC_BODIES = {0: 0x298fca0, 1: 0x29901a0}  # copy 0 = table 0x6441210, copy 1 = table 0x6441f00
EC_LOADERS = {0: 0x2990fe0, 1: 0x2991160}  # account loaders called directly by each copy (load_code = 1)
EC_GROW_GOT = 0x64e6de0                    # memory growth routine (called with the needed word count)
EC_MEMCPY_GOT, EC_MEMSET_GOT = 0x64df508, 0x64df750
EC_ARC_DROP_GOT = 0x64e4fa8
EC_PANIC_GOTS = (0x64df830, 0x64df6b8, 0x64df520)
EC_PANIC_FMT_GOT = 0x64df6b8                # panic_fmt-style helper: location in rdx
EC_STATIC_VTABLE = 0x6451328               # empty Bytes vtable (drop at +0x20)
EC_SAVED_REGS = (3, 5, 12, 13, 14, 15)
EC_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]

EC_INTERP_AT, EC_INTERP_SIZE = 0x7d00_0100_0000, 0x200
EC_HOST_AT, EC_HOST_SIZE = 0x7d00_0200_0000, 0x400
EC_PARAM_AT, EC_PARAM_SIZE = 0x7d00_0300_0000, 0x100
EC_ACCT_AT, EC_ACCT_SIZE = 0x7d00_0400_0000, 0x100
EC_BC_AT, EC_BC_SIZE = 0x7d00_0500_0000, 0x80
EC_STK_AT, EC_STK_WORDS = 0x7d00_0600_0000, 0x400
EC_VT_AT, EC_VT_SIZE = 0x7d00_0700_0000, 0x40
EC_CODE_AT, EC_CLONE_AT, EC_CODE_SIZE = 0x7d00_0800_0000, 0x7d00_0900_0000, 0x140
EC_MEMOBJ_AT, EC_MEMOBJ_SIZE = 0x7d00_0a00_0000, 0x40
EC_MEM_AT, EC_MEM_SIZE = 0x7d00_0b00_0000, 0x1000
EC_CLONE_STUB, EC_DROP_STUB = 0x7b00_0000_0010, 0x7b00_0000_0020
EC_REC_SIZE = 0x70                         # loader output record copied by the handler (+0x00..+0x6f)
EC_DATA_TOKEN = 0x0da7_a000_0000_0011       # data word the clone stub stores in the cloned Bytes

EC_I_MEMOBJ, EC_I_CTX, EC_I_STACK_PTR, EC_I_STACK_LEN, EC_I_WORDS, EC_I_GAS = 0x10, 0x18, 0x28, 0x30, 0x170, 0x188
EC_H_PARAMS = 0x250
EC_P_COPY = 0x20                           # per-word copy price
EC_A_CODE = 0x48                           # bytecode pointer inside the account (loader tag 0)
EC_R_TAG, EC_R_ACCT, EC_R_ERR, EC_R_CODE = 0x00, 0x08, 0x08, 0x50
EC_B_COUNT, EC_B_VT, EC_B_PTR, EC_B_PADLEN, EC_B_DATA, EC_B_LEN = 0x00, 0x30, 0x38, 0x40, 0x48, 0x50
EC_M_FLAG, EC_M_PTR, EC_M_LEN = 0x10, 0x20, 0x28
EC_R_OK, EC_R_OOG, EC_R_INVALID_OPERAND, EC_R_UNDERFLOW, EC_R_FATAL = 0x00, 0x20, 0x24, 0x2c, 0x36

EC_PANIC_UNWRAP, EC_PANIC_RANGE = 0x64437f0, 0x6451d20
EC_P_CODE_END, EC_P_DST_ADD, EC_P_DST_END, EC_P_ZERO_END, EC_P_ZERO_BOUND = 0x64bfd40, 0x64bfd58, 0x64bfd70, 0x64bfd88, 0x64bfda0


class EC_Panic(Exception):
    pass


def ec_ceil_words(n):
    return (n >> 5) + (1 if n & 0x1f else 0)


# ---------------------------------------------------------------- reconstruction
def ec_address_bytes(word, mut):
    a = word & ((1 << 160) - 1)
    return a.to_bytes(20, "little" if "address_little_endian" in mut else "big")


def ec_model(c, mut=frozenset()):
    """Pure reconstruction of EXTCODECOPY: returns the expected observable state."""
    s = {"ret": None, "panic": None, "len": c["len"], "gas": c["gas"], "words": c["words"], "calls": [],
         "flag": c["flag"], "mem": bytearray(c["mem"]), "count": c["count"]}
    n = c["len"]
    if n < 4:
        s["ret"] = EC_R_UNDERFLOW
        return s
    addr, moff, coff, size = (c["stack"][n - 1 - i] for i in range(4))
    s["len"] = n - 4                     # popped before any operand check
    if size >> 64:
        s["ret"] = EC_R_INVALID_OPERAND
        return s
    words = ec_ceil_words(size)
    if "copy_words_floor" in mut:
        words = size >> 5
    cost = words * c["cpw"]
    if cost > M64:
        cost = M64 if "no_cost_saturation" not in mut else cost & M64
    if c["gas"] < cost or ("gas_check_inclusive" in mut and c["gas"] == cost and cost):
        s["ret"] = EC_R_OOG
        return s
    s["gas"] = c["gas"] - cost
    if size == 0 and "zero_size_checks_offset" not in mut:
        mo = 0
    else:
        if moff >> 64:
            s["ret"] = EC_R_INVALID_OPERAND
            return s
        mo = moff
        end = min(mo + size, M64)
        need = ec_ceil_words(end)
        if need > c["words"] or ("grow_when_equal" in mut and need == c["words"]):
            s["calls"].append(("grow", need))
            if c["grow_ret"]:
                s["ret"] = c["grow_ret"]
                return s
            s["words"] = need
    if "load_before_charge" in mut:
        s["gas"] = c["gas"]
    s["calls"].append(("load", ec_address_bytes(addr, mut).hex(), 1))
    if c["tag"] == 2:
        s["ret"] = EC_R_FATAL if c["err"] & 1 else EC_R_OOG
        if "err_always_oog" in mut:
            s["ret"] = EC_R_OOG
        return s
    bc = c["bc"] and not (c["tag"] == 1 and "tag1_uses_account" in mut)
    if not bc:
        s["panic"] = EC_PANIC_UNWRAP
        return s
    olen, plen = c["olen"], c["plen"]
    if olen > plen and "no_range_check" not in mut:
        s["panic"] = EC_PANIC_RANGE
        return s
    if olen == 0 and "always_clone" not in mut:
        drop = ("drop", "static", c["ptr0"], 0)
        code = b""
    else:
        s["calls"].append(("clone", plen))
        drop = ("drop", "clone", EC_CLONE_AT, olen)
        code = c["code"][:olen]
    if coff >> 64 and "wide_offset_zero" not in mut:
        co = olen
    else:
        co = min(coff & M64 if "wide_offset_zero" in mut else coff, olen)
    s["flag"] = M64
    base = c["ctx"]
    if size == 0:
        s["flag"] = 0
    else:
        if co < olen:
            if co + size > M64:
                s["panic"] = EC_P_CODE_END
                return s
            k = min(co + size, olen) - co
            if "copy_full_size" in mut:
                k = min(size, olen)
            if mo + k > M64:
                s["panic"] = EC_P_DST_ADD
                return s
            s["calls"].append(("memcpy", base + mo, k))
            s["mem"][base + mo:base + mo + k] = code[co:co + k]
            if mo + size > M64:
                s["panic"] = EC_P_DST_END
                return s
            rem, z = size - k, mo + k
        else:
            if mo + size > M64:
                s["panic"] = EC_P_ZERO_END
                return s
            bound = (c["mlen"] - c["ctx"]) & M64
            if mo + size > bound and "no_zero_bound" not in mut:
                s["panic"] = EC_P_ZERO_BOUND
                return s
            rem, z = size, mo
        s["calls"].append(("memset", base + z, rem))
        if "no_zero_fill" not in mut:
            s["mem"][base + z:base + z + rem] = bytes(rem)
        s["flag"] = 0
    s["calls"].append(drop)
    if c["tag"] != 0 and "no_arc_release" not in mut:
        s["count"] = (c["count"] - 1) & M64
        if s["count"] == 0:
            s["calls"].append(("arc-drop-slow",))
    s["ret"] = EC_R_OK
    return s


# ---------------------------------------------------------------- case images
def ec_interp_bytes(c, s):
    b = bytearray(c["interp_fill"])
    put(b, EC_I_MEMOBJ, 8, EC_MEMOBJ_AT)
    put(b, EC_I_CTX, 8, c["ctx"])
    put(b, EC_I_STACK_PTR, 8, EC_STK_AT)
    put(b, EC_I_STACK_LEN, 8, s["len"])
    put(b, EC_I_WORDS, 8, s["words"])
    put(b, EC_I_GAS, 8, s["gas"])
    return bytes(b)


def ec_host_bytes(c):
    b = bytearray(c["host_fill"])
    put(b, EC_H_PARAMS, 8, EC_PARAM_AT)
    return bytes(b)


def ec_param_bytes(c):
    b = bytearray(c["param_fill"])
    put(b, EC_P_COPY, 8, c["cpw"])
    return bytes(b)


def ec_acct_bytes(c):
    b = bytearray(c["acct_fill"])
    put(b, EC_A_CODE, 8, EC_BC_AT if (c["bc"] and c["tag"] == 0) else 0)
    return bytes(b)


def ec_bc_bytes(c, count):
    b = bytearray(c["bc_fill"])
    put(b, EC_B_COUNT, 8, count)
    put(b, EC_B_VT, 8, EC_VT_AT)
    put(b, EC_B_PTR, 8, c["ptr0"])
    put(b, EC_B_PADLEN, 8, c["plen"])
    put(b, EC_B_DATA, 8, EC_DATA_TOKEN ^ 0xff)
    put(b, EC_B_LEN, 8, c["olen"])
    return bytes(b)


def ec_memobj_bytes(c, flag):
    b = bytearray(c["memobj_fill"])
    put(b, EC_M_FLAG, 8, flag)
    put(b, EC_M_PTR, 8, EC_MEM_AT)
    put(b, EC_M_LEN, 8, c["mlen"])
    return bytes(b)


def ec_vt_bytes():
    b = bytearray(EC_VT_SIZE)
    put(b, 0x00, 8, EC_CLONE_STUB)
    put(b, 0x20, 8, EC_DROP_STUB)
    return bytes(b)


def ec_stack_image(words):
    b = bytearray(32 * EC_STK_WORDS)
    for i, w in words.items():
        put(b, 32 * i, 32, w)
    return bytes(b)


# ---------------------------------------------------------------- contract stubs
class EC_CaseMachine(TraceMachine):
    def transfer(self, target, call, va):
        if target in self.panics:
            self.panic_site = va
            # panic_fmt takes (arguments, location); the other panic helpers take the location first
            self.panic_arg = self.regs[2] if target == self.fmt_panic else self.regs[7]
            raise Boundary("panic", self.regs)
        return super().transfer(target, call, va)


def ec_in_stack(m, at):
    return STACK_TOP - 0x10000 <= at < STACK_TOP


def ec_grow_stub(m):
    c = m.case
    if m.regs[7] != EC_INTERP_AT + EC_I_WORDS or m.regs[6] != EC_INTERP_AT or m.regs[2] != EC_HOST_AT + EC_H_PARAMS:
        fail("growth routine called outside its contract")
    m.calls.append(("grow", m.regs[1]))
    if not c["grow_ret"]:
        m.store(EC_INTERP_AT + EC_I_WORDS, 8, m.regs[1])
    m.regs[0] = c["grow_ret"]


def ec_loader_stub(m):
    c = m.case
    out = m.regs[7]
    if not ec_in_stack(m, out) or m.regs[6] != EC_INTERP_AT + EC_I_WORDS or m.regs[2] != EC_HOST_AT or m.regs[8] != 1:
        fail("account loader called outside its contract")
    m.calls.append(("load", bytes(m.load(m.regs[1] + i, 1) for i in range(20)).hex(), m.regs[8]))
    for i, x in enumerate(c["rec_fill"]):
        m.store(out + i, 1, x)
    m.store(out + EC_R_TAG, 8, c["tag"])
    if c["tag"] == 2:
        m.store(out + EC_R_ERR, 1, c["err"])
    elif c["tag"] == 0:
        m.store(out + EC_R_ACCT, 8, EC_ACCT_AT)
    else:
        m.store(out + EC_R_CODE, 8, EC_BC_AT if c["bc"] else 0)


def ec_clone_stub(m):
    c = m.case
    if m.regs[6] != EC_BC_AT + EC_B_DATA or m.regs[2] != c["ptr0"] or not ec_in_stack(m, m.regs[7]):
        fail("bytes clone called outside its contract")
    m.calls.append(("clone", m.regs[1]))
    out = m.regs[7]
    m.store(out, 8, EC_VT_AT)
    m.store(out + 8, 8, EC_CLONE_AT)
    m.store(out + 16, 8, m.regs[1])
    m.store(out + 24, 8, EC_DATA_TOKEN)


def ec_drop_stub(kind):
    def run(m):
        if not ec_in_stack(m, m.regs[7]):
            fail("bytes drop called outside its contract")
        want = EC_DATA_TOKEN if kind == "clone" else None
        if want is not None and m.load(m.regs[7], 8) != want:
            fail("bytes drop got the wrong data word")
        m.calls.append(("drop", kind, m.regs[6], m.regs[2]))
    return run


def ec_memcpy_stub(m):
    dst, src, n = m.regs[7], m.regs[6], m.regs[2]
    if n > EC_MEM_SIZE:
        fail("memcpy length outside the fixture")
    data = [m.load(src + i, 1) for i in range(n)]
    for i, x in enumerate(data):
        m.store(dst + i, 1, x)
    m.calls.append(("memcpy", dst - EC_MEM_AT, n))
    m.regs[0] = dst


def ec_memset_stub(m):
    dst, val, n = m.regs[7], m.regs[6], m.regs[2]
    if n > EC_MEM_SIZE or val != 0:
        fail("memset outside the fixture contract")
    for i in range(n):
        m.store(dst + i, 1, 0)
    m.calls.append(("memset", dst - EC_MEM_AT, n))
    m.regs[0] = dst


def ec_arc_stub(m):
    if m.regs[7] < STACK_TOP - 0x10000:
        fail("shared-pointer drop called outside its contract")
    m.calls.append(("arc-drop-slow",))


def ec_install(m, image):
    m.panics = {image.word(g) for g in EC_PANIC_GOTS}
    m.fmt_panic = image.word(EC_PANIC_FMT_GOT)
    m.panic_site = m.panic_arg = None
    m.calls = []
    m.stubs[image.word(EC_GROW_GOT)] = ec_grow_stub
    for copy in (0, 1):
        m.stubs[EC_LOADERS[copy]] = ec_loader_stub
    m.stubs[EC_CLONE_STUB] = ec_clone_stub
    m.stubs[EC_DROP_STUB] = ec_drop_stub("clone")
    m.stubs[image.word(EC_STATIC_VTABLE + 0x20)] = ec_drop_stub("static")
    m.stubs[image.word(EC_MEMCPY_GOT)] = ec_memcpy_stub
    m.stubs[image.word(EC_MEMSET_GOT)] = ec_memset_stub
    m.stubs[image.word(EC_ARC_DROP_GOT)] = ec_arc_stub


def ec_run_case(m, c):
    m.reset()
    m.case = c
    ec_install(m, m.image)
    it = m.add_region(EC_INTERP_AT, EC_INTERP_SIZE, ec_interp_bytes(c, c))
    host = m.add_region(EC_HOST_AT, EC_HOST_SIZE, ec_host_bytes(c))
    par = m.add_region(EC_PARAM_AT, EC_PARAM_SIZE, ec_param_bytes(c))
    acct = m.add_region(EC_ACCT_AT, EC_ACCT_SIZE, ec_acct_bytes(c))
    bc = m.add_region(EC_BC_AT, EC_BC_SIZE, ec_bc_bytes(c, c["count"]))
    stk = m.add_region(EC_STK_AT, 32 * EC_STK_WORDS, ec_stack_image(c["stack"]))
    vt = m.add_region(EC_VT_AT, EC_VT_SIZE, ec_vt_bytes())
    code0 = m.add_region(EC_CODE_AT, EC_CODE_SIZE, c["code0"])
    clone = m.add_region(EC_CLONE_AT, EC_CODE_SIZE, c["code"])
    mo = m.add_region(EC_MEMOBJ_AT, EC_MEMOBJ_SIZE, ec_memobj_bytes(c, c["flag"]))
    mem = m.add_region(EC_MEM_AT, EC_MEM_SIZE, c["mem"])
    fixed = [bytes(r) for r in (host, par, acct, stk, vt, code0, clone)]
    for k, v in zip(EC_SAVED_REGS, EC_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = EC_INTERP_AT, EC_HOST_AT
    try:
        m.run(EC_BODIES[c["copy"]], limit=20000)
        ret, panic = m.regs[0] & 0xff, None
    except Boundary:
        ret, panic = None, (m.panic_site, m.panic_arg)
    return {"ret": ret, "panic": panic, "interp": bytes(it), "bc": bytes(bc), "memobj": bytes(mo), "mem": bytes(mem),
            "fixed_ok": [bytes(r) for r in (host, par, acct, stk, vt, code0, clone)] == fixed,
            "regs_ok": panic is not None or ([m.regs[k] for k in EC_SAVED_REGS] == EC_SAVED
                                             and m.regs[4] == STACK_TOP - 0x100),
            "calls": list(m.calls)}


def ec_expected_calls(c, want):
    out = []
    for k in want["calls"]:
        if k[0] in ("memcpy", "memset"):
            out.append((k[0], k[1], k[2]))
        else:
            out.append(k)
    return out


def ec_compare(c, want, got):
    if (want["panic"] is None) != (got["panic"] is None):
        return False
    if want["panic"] is not None:
        return (got["panic"][1] == want["panic"] and got["fixed_ok"] and got["calls"] == ec_expected_calls(c, want)
                and got["interp"] == ec_interp_bytes(c, want) and got["mem"] == bytes(want["mem"])
                and got["memobj"] == ec_memobj_bytes(c, want["flag"]))
    return (want["ret"] == got["ret"] and got["regs_ok"] and got["fixed_ok"]
            and got["calls"] == ec_expected_calls(c, want) and got["interp"] == ec_interp_bytes(c, want)
            and got["mem"] == bytes(want["mem"]) and got["memobj"] == ec_memobj_bytes(c, want["flag"])
            and got["bc"] == ec_bc_bytes(c, want["count"]))


# ---------------------------------------------------------------- cases
EC_PER_COPY = 5000
EC_LENS = (0, 1, 2, 3, 4, 4, 4, 5, 9, 0x400)
EC_MODES = ("small", "small", "small", "small", "wide-offsets", "zero-size", "gas", "grow", "huge-size", "huge-mem",
         "bound", "tag")


def ec_rand_word(st):
    return int.from_bytes(st.take(32), "little")


def ec_high(st):
    return st.pick((1, 1 << 63, 1 << 191, ec_rand_word(st))) << 64 & M256


def ec_make_case(st, copy, k):
    c = {"id": f"extcodecopy-{copy}-{k:05d}", "copy": copy}
    mode = c["mode"] = EC_MODES[(k // 2) % len(EC_MODES)] if k % 2 == 0 else st.pick(EC_MODES)
    c["ctx"] = st.pick((0, 0x20, 0x40, 0x100, 0x1e0))
    c["olen"] = st.pick((0, 1, 2, 31, 32, 33, 0x40, 0x7f, 0x100, st.below(0x101)))
    c["plen"] = st.pick((c["olen"], c["olen"], c["olen"] + 33, c["olen"] + st.below(8)))
    if st.below(24) == 0 and c["olen"]:
        c["plen"] = c["olen"] - 1 - st.below(c["olen"])
    c["plen"] = min(c["plen"], EC_CODE_SIZE)
    c["code"] = st.take(EC_CODE_SIZE)
    c["code0"] = st.take(EC_CODE_SIZE)
    c["ptr0"] = EC_CODE_AT
    c["tag"] = st.pick((0, 0, 0, 0, 0, 2, 1)) if mode != "tag" else st.pick((0, 1, 2))
    c["err"] = st.take(1)[0]
    c["bc"] = st.below(40) != 0
    c["count"] = st.pick((1, 1, 2, 7, M64))
    c["flag"] = st.pick((0, 0, 1, M64))
    c["cpw"] = st.pick((0, 1, 3, 3, 3, 7, 1 << 32, M64))
    c["gas"] = st.pick((M64, M64, 1 << 40, 0, 3, 100, int.from_bytes(st.take(8), "little")))
    co = st.pick((0, 0, 1, 2, 31, 32, 0x40, 0x7f, 0x80, 0x100, 0x101, st.below(0x120)))
    mo = st.pick((0, 0, 1, 31, 32, 0x41, 0x100, 0x3e1, st.below(0x400)))
    size = st.pick((0, 1, 2, 31, 32, 33, 0x40, 0x7f, 0x100, 0x1ff, 0x200, st.below(0x201)))
    words = st.pick((0, 1, ec_ceil_words(mo + size), ec_ceil_words(mo + size) - 1, 0x40, 0x80))
    c["grow_ret"] = 0
    mlen = st.pick((EC_MEM_SIZE, EC_MEM_SIZE, 0x800, c["ctx"] + mo + size, c["ctx"] + mo + size - 1, 0))
    if mode == "wide-offsets":
        co |= ec_high(st) if st.below(2) else 0
        mo |= ec_high(st) if st.below(2) else 0
        size |= ec_high(st) if st.below(3) == 0 else 0
    elif mode == "zero-size":
        size = 0
        mo |= ec_high(st) if st.below(2) else 0
    elif mode == "gas":
        c["cpw"] = st.pick((1, 3, 1 << 61, 1 << 62, M64))
        cost = ec_ceil_words(size) * c["cpw"]
        c["gas"] = st.pick((cost - 1, cost, cost + 1, M64, 0)) & M64 if cost <= M64 else st.pick((M64, M64 - 1))
    elif mode == "grow":
        words = st.pick((0, ec_ceil_words(mo + size) - 1, ec_ceil_words(mo + size)))
        c["grow_ret"] = st.pick((0, 0, 0x21, 0x50, 0x01))
    elif mode in ("huge-size", "huge-mem"):
        # Paths that the real growth routine rejects; the stub reports success so the handler's own overflow
        # panics after growth are reached (contract-only, labelled "forced-growth" in the outcome classes).
        c["cpw"], c["gas"], c["grow_ret"] = st.pick((0, 1)), M64, 0
        if mode == "huge-size":
            co = st.pick((0, 1, c["olen"], co))
            lim = max(co if co < c["olen"] else 0, mo)
            if lim == 0:
                mo = lim = 1
            size = M64 - st.below(lim)
        else:
            size = st.pick((1, 2, 0x20, st.below(0x40) + 1))
            co = st.pick((0, c["olen"], 0x100))
            k = min(size, c["olen"]) if co < c["olen"] else 0
            mo = M64 - (st.below(k) if k else st.pick((0, 1, size - 1, size, st.below(0x20))))
        words, mlen = 0, st.pick((EC_MEM_SIZE, 0x800))
    elif mode == "bound":
        co = st.pick((c["olen"], c["olen"] + 1, 0x7fff))
        mlen = st.pick((c["ctx"] + mo + size, c["ctx"] + mo + size - 1, c["ctx"] + mo + size + 1, 0,
                        c["ctx"] - 1 if c["ctx"] else 0))
        size = size or 1
    c["words"] = max(words, 0)
    c["mlen"] = max(mlen, 0) & M64
    c["mem"] = st.take(EC_MEM_SIZE)
    c["interp_fill"] = st.take(EC_INTERP_SIZE)
    c["host_fill"] = st.take(EC_HOST_SIZE)
    c["param_fill"] = st.take(EC_PARAM_SIZE)
    c["acct_fill"] = st.take(EC_ACCT_SIZE)
    c["bc_fill"] = st.take(EC_BC_SIZE)
    c["memobj_fill"] = st.take(EC_MEMOBJ_SIZE)
    c["rec_fill"] = st.take(EC_REC_SIZE)
    n = st.pick(EC_LENS)
    c["len"] = n
    c["stack"] = {}
    vals = (st.pick((ec_rand_word(st), ec_rand_word(st) & ((1 << 160) - 1))), mo, co, size)
    for i in range(min(n, 4)):
        c["stack"][n - 1 - i] = vals[i]
    if n > 4:
        c["stack"][n - 5] = ec_rand_word(st)
    return c


def ec_all_cases(per_copy=EC_PER_COPY):
    out = []
    for copy in (0, 1):
        st = Stream(f"re11-extcodecopy-115/{copy}")
        out += [ec_make_case(st, copy, k) for k in range(per_copy)]
    return out


# ---------------------------------------------------------------- static evidence
# (va, bytes, meaning, also_in_copy_1_at_va_plus_0x500)
EC_CHECKED = (
    (0x298fcb1, "48 8b 47 30", "stack length at interp+0x30", True),
    (0x298fcb5, "b1 2c", "fewer than 4 words gives 0x2c", True),
    (0x298fcb7, "48 83 f8 04", "four operands needed", True),
    (0x298fd16, "48 0f ce", "address limb 2 byte-swapped", True),
    (0x298fd19, "48 c1 ee 20", "high address dword = bswap(limb 2) >> 32 (low 160 bits, big-endian)", True),
    (0x298fd35, "48 89 47 30", "stack length stored (4 popped) before the operand checks", True),
    (0x298fd56, "b1 24", "size or memory offset wider than 64 bits gives 0x24", True),
    (0x298fd5e, "49 8b 97 50 02 00 00", "host+0x250 parameter block", True),
    (0x298fd6e, "83 e6 1f", "size & 31 (word rounding)", True),
    (0x298fd71, "48 83 fe 01", "words = size/32 + (size%32 != 0)", True),
    (0x298fd79, "48 f7 62 20", "cost = words * params[+0x20]", True),
    (0x298fd7d, "0f 80 2b 03 00 00", "multiply overflow saturates the cost (copy 0)", False),
    (0x298fd83, "48 8b 97 88 01 00 00", "remaining gas at interp+0x188", True),
    (0x298fd8d, "0f 82 32 03 00 00", "cost > remaining gives 0x20 (copy 0)", False),
    (0x298fd93, "48 8d b7 70 01 00 00", "memory word count / gas record at interp+0x170", True),
    (0x298fd9a, "48 89 97 88 01 00 00", "remaining gas stored before the memory check", True),
    (0x298fdd7, "48 3b 0e", "needed words compared with interp+0x170", True),
    (0x298fe29, "41 b8 01 00 00 00", "account loader load_code = 1", True),
    (0x298fe2f, "e8 ac 11 00 00", "copy 0 calls account loader 0x2990fe0", False),
    (0x298fe3e, "48 83 f8 02", "loader tag 2 = error", True),
    (0x298fe47, "b8 36 00 00 00", "error byte bit 0 set gives 0x36", True),
    (0x298fe4c, "b9 20 00 00 00", "otherwise 0x20", True),
    (0x298fecc, "48 83 c1 48", "tag 0: bytecode pointer at account+0x48", True),
    (0x298fec4, "48 8d 94 24 20 01 00 00", "tag 1: bytecode pointer at record+0x50", True),
    (0x298fedc, "0f 84 e7 01 00 00", "no bytecode panics (copy 0)", False),
    (0x298fee2, "4c 8b 7e 50", "bytecode original length at +0x50", True),
    (0x298fee6, "48 8b 4e 40", "bytecode padded length at +0x40", True),
    (0x298fefd, "0f 87 d5 01 00 00", "original > padded length panics (copy 0)", False),
    (0x298ff40, "48 8b 76 38", "empty code: pointer kept, length 0", True),
    (0x298ff4c, "4c 8d 05 d5 13 ac 03", "empty code: static Bytes vtable 0x6451328 (copy 0)", False),
    (0x298ff7a, "4d 0f 42 e5", "code offset = min(offset, code length)", True),
    (0x298ff86, "4d 0f 45 e5", "wide code offset saturates to the code length", True),
    (0x298ff8f, "4c 8b 78 10", "shared memory object at interp+0x10", True),
    (0x298ff93, "48 8b 40 18", "call-frame memory offset at interp+0x18", True),
    (0x298ff97, "49 8b 4f 28", "memory length at memory+0x28", True),
    (0x298ff9b, "49 8b 6f 20", "memory buffer at memory+0x20", True),
    (0x298ffa2, "49 c7 47 10 ff ff ff ff", "borrow flag memory+0x10 set to -1 without a check", True),
    (0x299002e, "48 29 c1", "zero-fill bound = memory length - frame offset", True),
    (0x2990031, "48 39 ca", "zero-fill end compared with the bound", True),
    (0x299004b, "49 8b 47 10", "borrow flag reloaded", True),
    (0x299004f, "48 ff c0", "borrow flag + 1", True),
    (0x2990068, "41 ff 50 20", "Bytes drop through vtable +0x20", True),
    (0x299006c, "48 83 bc 24 d0 00 00 00 00", "nonzero tag releases the record's shared pointer", True),
    (0x29900ae, "48 c7 c0 ff ff ff ff", "saturated cost = 2^64-1", True),
    (0x29900c5, "b1 20", "out of gas 0x20", True),
)
EC_FOLLOWER_DELTA = 0x500                 # copy 1 = copy 0 + 0x500 for every non-relative pinned instruction
EC_AFTER_NORETURN_FROM = 0x4b5            # body offset of the ud2 / landing pads


def ec_hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def ec_sweep_padded(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


def ec_rip_target(f, va):
    rm = f.get("rm")
    if rm and rm[0] == "m" and rm[1] == "rip":
        return va + f["len"] + rm[4]
    return None


def ec_static_evidence(image):
    starts = set(EC_BODIES.values())
    fdes = fde_rows(image, starts)
    for table, copy in zip(EC_OP_TABLES, (0, 1)):
        if image.relative.get(table + 8 * EC_SLOAD_OP) not in EC_SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        if image.relative.get(table + 8 * EC_EXTCODECOPY) != EC_BODIES[copy]:
            fail(f"opcode table {table:#x} slot {EC_EXTCODECOPY:#x} does not name EXTCODECOPY copy {copy}")
    for va, want, _, both in EC_CHECKED:
        n = len(bytes.fromhex(want.replace(" ", "")))
        for at in (va, va + EC_FOLLOWER_DELTA) if both else (va,):
            got = ec_hexs(image.code(at, n))
            if got != want:
                fail(f"pinned bytes differ at {at:#x}: {got}")
    s0, e0 = fdes[EC_BODIES[0]]
    s1, e1 = fdes[EC_BODIES[1]]
    if e0 - s0 != e1 - s1 or s1 - s0 != EC_FOLLOWER_DELTA:
        fail("EXTCODECOPY copies differ in extent")
    insns = {copy: ec_sweep_padded(image, *fdes[EC_BODIES[copy]]) for copy in (0, 1)}
    # Both copies decode to the same instruction lengths; only relative targets and the loader call differ.
    if [f["len"] for _, f in insns[0]] != [f["len"] for _, f in insns[1]]:
        fail("EXTCODECOPY copies decode differently")
    refs = {}
    for copy in (0, 1):
        got = []
        for va, f in insns[copy]:
            t = ec_rip_target(f, va)
            if t is not None:
                got.append(t)
            if f["op"] == 0xe8:
                got.append(("direct", (va + f["len"] + f["rel"]) & M64))
        refs[copy] = got
    want_got = [EC_GROW_GOT, EC_MEMCPY_GOT, EC_MEMSET_GOT, EC_ARC_DROP_GOT]
    for copy in (0, 1):
        if ("direct", EC_LOADERS[copy]) not in refs[copy]:
            fail(f"copy {copy} does not call loader {EC_LOADERS[copy]:#x}")
        for g in want_got + list(EC_PANIC_GOTS) + [EC_STATIC_VTABLE, EC_PANIC_UNWRAP, EC_PANIC_RANGE, EC_P_CODE_END, EC_P_DST_ADD,
                                                EC_P_DST_END, EC_P_ZERO_END, EC_P_ZERO_BOUND]:
            if g not in refs[copy]:
                fail(f"copy {copy} has no reference to {g:#x}")
    for slot, name in ((EC_MEMCPY_GOT, "memcpy"), (EC_MEMSET_GOT, "memset")):
        if slot not in image.imports or image.import_name(slot) != name:
            fail(f"GOT {slot:#x} is not the {name} import")
    return fdes, insns, refs


def ec_reach(copy, va, seen, after_noreturn):
    if va in seen:
        return "yes"
    if va - EC_BODIES[copy] >= EC_AFTER_NORETURN_FROM or va in after_noreturn:
        return "no:after-noreturn-or-landing-pad"
    return "no:unreached"


def ec_noreturn_followers(image, insns):
    panic_targets = set(EC_PANIC_GOTS)
    out = set()
    for copy in (0, 1):
        rows = insns[copy]
        for (va, f), (nva, _) in zip(rows, rows[1:]):
            if f["op"] == 0xff and ec_rip_target(f, va) in panic_targets:
                out.add(nva)
    return out


# ---------------------------------------------------------------- evaluation and controls
def ec_evaluate(image, override=None, mut=frozenset(), stop_on_first=False, cases=None, machine=None):
    m = machine or EC_CaseMachine(image, override)
    rows = []
    for c in cases:
        want = ec_model(c, mut)
        try:
            got = ec_run_case(m, c)
            ok = ec_compare(c, want, got)
        except ToolError:
            if machine is not None or not (override or mut):
                raise
            got, ok = None, False
        rows.append((c, want, got, ok))
        if stop_on_first and not ok:
            break
    return rows, m


EC_MODEL_MUTANTS = ["address_little_endian", "copy_words_floor", "no_cost_saturation", "gas_check_inclusive",
                 "zero_size_checks_offset", "grow_when_equal", "load_before_charge", "err_always_oog",
                 "tag1_uses_account", "no_range_check", "always_clone", "wide_offset_zero", "copy_full_size",
                 "no_zero_bound", "no_zero_fill", "no_arc_release"]
EC_BYTE_MUTANTS = [
    (0x298fcba, 0x03, "copy 0 operand count 4 -> 3"),
    (0x298fcb6, 0x2d, "copy 0 underflow result 0x2c -> 0x2d"),
    (0x298fd57, 0x25, "copy 0 wide-operand result 0x24 -> 0x25"),
    (0x298fd70, 0x0f, "copy 0 word rounding mask 0x1f -> 0x0f"),
    (0x298fd7c, 0x28, "copy 0 copy price params+0x20 -> +0x28"),
    (0x298fd96, 0x78, "copy 0 memory record interp+0x170 -> +0x178"),
    (0x298fe2b, 0x00, "copy 0 load_code 1 -> 0"),
    (0x298fe41, 0x03, "copy 0 loader error tag 2 -> 3"),
    (0x298fe48, 0x37, "copy 0 error result 0x36 -> 0x37"),
    (0x298fe4d, 0x21, "copy 0 loader out-of-gas result 0x20 -> 0x21"),
    (0x298fecf, 0x40, "copy 0 account bytecode offset +0x48 -> +0x40"),
    (0x298fee5, 0x40, "copy 0 original length +0x50 -> padded +0x40"),
    (0x298ff7b, 0x43, "copy 0 cmovb -> cmovae on the code offset"),
    (0x298ff87, 0x44, "copy 0 cmovne -> cmove on the wide code offset"),
    (0x299002f, 0x01, "copy 0 zero-fill bound sub -> add"),
    (0x2990035, 0x83, "copy 0 zero-fill bound ja -> jae"),
    (0x2990051, 0xc8, "copy 0 borrow flag inc -> dec"),
    (0x2990074, 0x01, "copy 0 tag test 0 -> 1 before the shared-pointer release"),
    (0x29900b1, 0x00, "copy 0 saturated cost -1 -> -256"),
    (0x29901ba, 0x05, "copy 1 operand count 4 -> 5"),
    (0x2990348, 0x38, "copy 1 error result 0x36 -> 0x38"),
    (0x2990487, 0x44, "copy 1 cmovne -> cmove on the wide code offset"),
]


def ec_controls(image, cases):
    rows = []
    for mt in EC_MODEL_MUTANTS:
        r, _ = ec_evaluate(image, mut=frozenset([mt]), stop_on_first=True, cases=cases)
        bad = next((x[0]["id"] for x in r if not x[3]), "")
        rows.append(("model", mt, "detected" if bad else "MISSED", bad))
    for va, value, label in EC_BYTE_MUTANTS:
        if image.code(va, 1)[0] == value:
            fail(f"byte mutant at {va:#x} does not change the byte")
        try:
            r, _ = ec_evaluate(image, override={va: value}, stop_on_first=True, cases=cases)
            bad = next((x[0]["id"] for x in r if not x[3]), "")
        except ToolError as exc:
            bad = "tool-error:" + str(exc).split(" at ")[0]
        rows.append(("code", f"{va:#x}={value:#04x} {label}", "detected" if bad else "MISSED", bad))
    bad = bytearray(image.data)
    bad[0x1000] ^= 1
    try:
        Image(bytes(bad))
        rows.append(("input", "binary with one flipped byte", "MISSED", ""))
    except ToolError:
        rows.append(("input", "binary with one flipped byte", "detected", "sha256"))
    try:
        Machine(image).fetch(image.text["address"] + image.text["size"] + 0x10)
        rows.append(("input", "code fetch outside .text", "MISSED", ""))
    except ToolError:
        rows.append(("input", "code fetch outside .text", "detected", "range"))
    return rows


EC_PANIC_NAMES = {EC_PANIC_UNWRAP: "no-bytecode", EC_PANIC_RANGE: "length-range", EC_P_CODE_END: "code-offset+size",
               EC_P_DST_ADD: "mem-offset+copied", EC_P_DST_END: "mem-offset+size(copy)",
               EC_P_ZERO_END: "mem-offset+size(zero)", EC_P_ZERO_BOUND: "zero-fill-bound"}


def ec_outcome(c, want):
    tag = f" tag{c['tag']}"
    forced = " forced-growth" if c["mode"] in ("huge-size", "huge-mem") else ""
    if want["panic"] is not None:
        return "panic:" + EC_PANIC_NAMES[want["panic"]] + tag + forced
    r = {EC_R_OK: "ok", EC_R_OOG: "out-of-gas", EC_R_INVALID_OPERAND: "invalid-operand", EC_R_UNDERFLOW: "underflow",
         EC_R_FATAL: "fatal"}.get(want["ret"], f"growth-error-{want['ret']:#04x}")
    if want["ret"] == EC_R_OK:
        kinds = [k[0] for k in want["calls"]]
        r += "+copy" if "memcpy" in kinds else ""
        r += "+zero" if "memset" in kinds else ""
        r += "+grow" if "grow" in kinds else ""
        r += "+empty-code" if not c["olen"] else ""
        r += tag
    return r + forced


def ec_fmt_call(k):
    return k[0] + "(" + ",".join(f"{x:#x}" if isinstance(x, int) else str(x) for x in k[1:]) + ")"


def ec_generate(out, per_copy=EC_PER_COPY):
    image = load_image()
    fdes, insns, refs = ec_static_evidence(image)
    cases = ec_all_cases(per_copy)
    rows, m = ec_evaluate(image, cases=cases, machine=EC_CaseMachine(image))
    mism = [r[0]["id"] for r in rows if not r[3]]
    if mism:
        fail(f"{len(mism)} mismatches, first {mism[:5]}")
    ctl = ec_controls(image, cases)
    if any(r[2] != "detected" for r in ctl):
        fail(f"negative control missed: {[r for r in ctl if r[2] != 'detected']}")
    seen = m.seen
    after = ec_noreturn_followers(image, insns)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    lines = ["case\tbody\tmode\tstack_len\tmem_offset\tcode_offset\tsize\tgas\tcopy_price\tmem_words\tgrow_ret\t"
             "frame_offset\tmem_len\ttag\tcode_len\tpadded_len\tret_or_panic\tstack_len_after\tgas_after\t"
             "mem_words_after\tmem_sha256\tcalls\tmatch"]
    classes = {}
    for c, want, got, ok in rows:
        n = c["len"]
        oc = ec_outcome(c, want)
        key = (c["copy"], oc)
        classes[key] = classes.get(key, 0) + 1
        ops = [f"{c['stack'][n - 1 - i]:#x}" if n > i else "-" for i in (1, 2, 3)]
        lines.append("\t".join([
            c["id"], f"{EC_BODIES[c['copy']]:#x}", c["mode"], str(n), *ops, f"{c['gas']:#x}", f"{c['cpw']:#x}",
            f"{c['words']:#x}", f"{c['grow_ret']:#x}", f"{c['ctx']:#x}", f"{c['mlen']:#x}",
            str(c["tag"]) + ("" if c["bc"] else "/none"), f"{c['olen']:#x}", f"{c['plen']:#x}",
            f"panic:{want['panic']:#x}" if want["panic"] else f"{want['ret']:#04x}",
            str(want["len"]), f"{want['gas']:#x}", f"{want['words']:#x}",
            hashlib.sha256(bytes(want["mem"])).hexdigest()[:16],
            ";".join(ec_fmt_call(k) for k in want["calls"]) or "-",
            "yes" if ok else "no"]))
    # Every row is hashed; one row in CASE_SAMPLE is committed (the tool regenerates all of them).
    all_rows = "\n".join(lines) + "\n"
    (out / "ec-cases.tsv").write_text(all_rows)
    oc_lines = ["copy\toutcome\tcases"] + [f"{a}\t{o}\t{k}" for (a, o), k in sorted(classes.items())]
    (out / "ec-outcome-classes.tsv").write_text("\n".join(oc_lines) + "\n")
    ins_lines = ["copy\tva\tbytes\texecuted"]
    total = hit = 0
    unreached = {}
    for copy in (0, 1):
        for va, f in insns[copy]:
            total += 1
            hit += va in seen
            r = ec_reach(copy, va, seen, after)
            unreached[r] = unreached.get(r, 0) + 1
            ins_lines.append(f"{copy}\t{va:#x}\t{ec_hexs(f['bytes'])}\t{r}")
    if unreached.get("no:unreached"):
        fail(f"{unreached['no:unreached']} reachable instructions were not executed")
    (out / "ec-decoded-instructions.tsv").write_text("\n".join(ins_lines) + "\n")
    fn = ["role\tcopy\tstart\tend\tsize\tsha256"]
    for copy in (0, 1):
        s, e = fdes[EC_BODIES[copy]]
        digest = hashlib.sha256(image.code(s, e - s)).hexdigest()
        fn.append(f"EXTCODECOPY handler\t{copy}\t{s:#x}\t{e:#x}\t{e - s}\t{digest}")
    (out / "ec-functions.tsv").write_text("\n".join(fn) + "\n")
    const = {
        "binary_sha256": SHA256,
        "opcode_tables": {f"{t:#x}": f"{image.relative[t + 8 * EC_EXTCODECOPY]:#x}" for t in EC_OP_TABLES},
        "account_loaders": {str(k): f"{v:#x}" for k, v in EC_LOADERS.items()},
        "pinned_bytes": [{"va": f"{va:#x}", "bytes": b, "meaning": t, "also_copy_1": both}
                         for va, b, t, both in EC_CHECKED],
        "got_slots": {"memory_growth": f"{EC_GROW_GOT:#x}->{image.word(EC_GROW_GOT):#x}",
                      "memcpy": f"{EC_MEMCPY_GOT:#x}->{image.import_name(EC_MEMCPY_GOT)}",
                      "memset": f"{EC_MEMSET_GOT:#x}->{image.import_name(EC_MEMSET_GOT)}",
                      "shared_pointer_drop": f"{EC_ARC_DROP_GOT:#x}->{image.word(EC_ARC_DROP_GOT):#x}",
                      "panics": [f"{g:#x}->{image.word(g):#x}" for g in EC_PANIC_GOTS]},
        "static_bytes_vtable": {"va": f"{EC_STATIC_VTABLE:#x}", "drop": f"{image.word(EC_STATIC_VTABLE + 0x20):#x}"},
        "panic_locations": {v: f"{k:#x}" for k, v in sorted(EC_PANIC_NAMES.items())},
        "fields": {"interp": {"memory": EC_I_MEMOBJ, "frame_memory_offset": EC_I_CTX, "stack_ptr": EC_I_STACK_PTR,
                              "stack_len": EC_I_STACK_LEN, "memory_words": EC_I_WORDS, "gas_remaining": EC_I_GAS},
                   "host": {"params": EC_H_PARAMS}, "params": {"copy_price_per_word": EC_P_COPY},
                   "account": {"bytecode": EC_A_CODE},
                   "loader_record": {"tag": EC_R_TAG, "account": EC_R_ACCT, "error_byte": EC_R_ERR, "bytecode": EC_R_CODE},
                   "bytecode": {"strong_count": EC_B_COUNT, "bytes_vtable": EC_B_VT, "bytes_ptr": EC_B_PTR,
                                "padded_len": EC_B_PADLEN, "bytes_data": EC_B_DATA, "original_len": EC_B_LEN},
                   "memory": {"borrow_flag": EC_M_FLAG, "buffer": EC_M_PTR, "len": EC_M_LEN}},
        "results": {"ok": EC_R_OK, "out_of_gas": EC_R_OOG, "invalid_operand": EC_R_INVALID_OPERAND,
                    "underflow": EC_R_UNDERFLOW, "fatal": EC_R_FATAL},
        "rip_references": {str(k): sorted(f"{x:#x}" for x in v if isinstance(x, int)) for k, v in refs.items()},
    }
    (out / "ec-constants.json").write_text(json.dumps(const, indent=2, sort_keys=True) + "\n")
    ctl_lines = ["kind\tcontrol\tresult\tfirst_detecting_case"] + ["\t".join(r) for r in ctl]
    (out / "ec-negative-controls.tsv").write_text("\n".join(ctl_lines) + "\n")
    summary = {
        "binary_sha256": SHA256,
        "cases": len(rows), "matches": sum(1 for r in rows if r[3]),
        "cases_per_copy": {str(k): sum(1 for r in rows if r[0]["copy"] == k) for k in (0, 1)},
        "instructions": total, "instructions_executed": hit,
        "instruction_reach": dict(sorted(unreached.items())),
        "negative_controls": len(ctl), "negative_controls_detected": sum(1 for r in ctl if r[2] == "detected"),
        "outcome_classes": len(classes),
    }
    (out / "ec-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary




# ====================================================================================================
# merged driver: one image, the four families in parallel processes, sampled case listings
# ====================================================================================================
_IMAGE = None


def load_image():
    """The digest-checked image, read once per process and shared by every family."""
    global _IMAGE
    if _IMAGE is None:
        _IMAGE = Image(BINARY.read_bytes())
    return _IMAGE


FAMILIES = (("sl", "SLOAD handler + twin"), ("ar", "BALANCE/EXTCODE*/SELFBALANCE + account loaders"),
            ("tw", "TSTORE transient writer"), ("ec", "EXTCODECOPY handler, both copies"))
SAMPLE_EVERY = 10


def family_generate(key, out):
    gen = {"sl": sl_generate, "ar": ar_generate, "tw": tw_generate, "ec": ec_generate}[key]
    return gen(pathlib.Path(out))


def control_counts(path):
    rows = path.read_text().splitlines()[1:]
    detected = sum(1 for r in rows if r.split("\t")[2] in ("detected", "1", "True"))
    return len(rows), detected


def generate(out, full=False, parallel=True):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    keys = [k for k, _ in FAMILIES]
    if parallel:
        with concurrent.futures.ProcessPoolExecutor(len(keys)) as ex:
            list(ex.map(family_generate, keys, [str(out)] * len(keys)))
    else:
        for k in keys:
            family_generate(k, out)
    fams = {}
    for k, label in FAMILIES:
        part = json.loads((out / f"{k}-summary.json").read_text())
        (out / f"{k}-summary.json").unlink()
        cases = out / f"{k}-cases.tsv"
        text = cases.read_bytes()
        lines = text.decode().splitlines()
        rows = lines[1:]
        if any(r.rsplit("\t", 1)[-1] != "yes" for r in rows):
            fail(f"family {k}: a case row is not a match")
        if not full:
            cases.write_text("\n".join([lines[0]] + rows[::SAMPLE_EVERY]) + "\n")
        total, detected = control_counts(out / f"{k}-negative-controls.tsv")
        if detected != total:
            fail(f"family {k}: {total - detected} negative controls missed")
        fams[k] = {"label": label, "cases": len(rows), "matches": len(rows),
                   "full_cases_tsv_sha256": hashlib.sha256(text).hexdigest(),
                   "sampled_rows_committed": len(rows[::SAMPLE_EVERY]),
                   "negative_controls": total, "negative_controls_detected": detected, "detail": part}
    summary = {
        "binary_sha256": SHA256,
        "families": fams,
        "cases": sum(f["cases"] for f in fams.values()),
        "mismatches": 0,
        "negative_controls": sum(f["negative_controls"] for f in fams.values()),
        "negative_controls_detected": sum(f["negative_controls_detected"] for f in fams.values()),
        "case_listing": "full" if full else f"every {SAMPLE_EVERY}th row; full listing pinned by sha256",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--full", action="store_true", help="write the whole case listings instead of every 10th row")
    a = ap.parse_args(argv)
    try:
        s = generate(a.out, full=a.full)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: s[k] for k in ("cases", "mismatches", "negative_controls", "negative_controls_detected")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
