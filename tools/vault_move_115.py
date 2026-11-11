"""Reconstruct and verify node #115's vault move core (0x44ae810) and the four helpers it runs.

The body takes (result record, vault object, source address, signed amount, aux bytes, flag, three context words) and
returns either one of five reject codes (0x16 and 0x17 for a non-leader caller, 0x09 for a negative vault value outside
address set A, 0x02 for a failed leader-share check, 0x2d for insufficient availability), an unwrap/format panic, or the
success record 0x8000000000000004 after it debited the source, credited the vault, rewritten the source address's
per-address record (u64 total, i64 net, 12 aux bytes) and left the balance word of the context saturating-updated.

  * gates     mode qword == 1 and source != leader -> 0x16; policy byte == 0 and source != leader -> 0x17.
  * value     value(vault address) plus, for a parent vault (mode low dword 2), value(child) over a B-tree set in key
              order, signed saturating; every overflow calls the reporter with its panic-location constant.
  * negative  a negative value needs the vault address to be one of the eight constants of 0x421a3c0, else 0x09.
  * share     with flag byte 0, mode low dword != 1, source != leader and the address not in 0x421a520's eight constants:
              look the leader up in the record table (B-tree map or ring), lead = sat_i64(value * weight) / 1e6 must be
              >= 1e-7 and 0x14ca350's checked quotient lead / (u64(max(value, 0) + amount) / 1e6) must be >= 0.05.
  * settle    available(ctx, source) >= amount (a negative amount panics); debit, balance -= amount, credit, balance +=
              amount, the settle callee; the source's record gets u64 += amount, i64 += amount (saturating, reporter on
              overflow) and the 12 aux bytes; the result carries amount / 1e6 and the vault address.

`model` is the reconstruction. A concrete x86-64 evaluator runs the real bytes of the body and of 0x421a3c0, 0x421a520,
0x14ca350 and 0x45578e0; the other callees are recording contract stubs. The binary is never executed.
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
M32 = (1 << 32) - 1
M64 = (1 << 64) - 1
M128 = (1 << 128) - 1
M256 = (1 << 256) - 1

STACK_TOP = 0x7ff0_0000_0000
RETURN_MARK = 0x7e00_dead_0000
SENTINEL = 0xa5a5a5a5a5a5a5a5
IMPORT_BASE = 0x7c00_0000_0000
SSE_OPS = frozenset((0x0f2a, 0x0f2c, 0x0f2e, 0x0f58, 0x0f59, 0x0f5c, 0x0f5d, 0x0f5e, 0x0f5f, 0x0f62, 0x0f15,
                     0x0f7e, 0x0fd6))


def sext(v, bits):
    return v - (1 << bits) if v >> (bits - 1) else v


def dbits(x):
    return int.from_bytes(struct.pack("<d", x), "little")


def bdouble(v):
    return struct.unpack("<d", (v & M64).to_bytes(8, "little"))[0]


def fdiv(a, b):
    if b == 0:
        if a == 0 or a != a:
            return float("nan")
        neg = (a < 0) != (str(b)[0] == "-")
        return float("-inf") if neg else float("inf")
    return a / b




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
    elif op in (0xc3, 0x90, 0x0f0b, 0xcc, 0x98):
        pass
    elif op in (0x11, 0x13, 0x38, 0x88, 0x0f57, 0x01, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x29, 0x2b, 0x31, 0x33,
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x87, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f1e, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
                0x0f6e, 0x0f60, 0x0f76, 0x0ffb, 0x0fa5, 0x0fad, 0x0fbd, 0x0fa3, 0x0feb, 0x0f50, 0x0f54, 0x0f56,
                0x0f2a, 0x0f2c, 0x0f2e, 0x0f58, 0x0f59, 0x0f5c, 0x0f5d, 0x0f5e, 0x0f5f, 0x0f62, 0x0f15, 0x0f7e, 0x0fd6) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
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
    elif op in (0x3d, 0x05, 0xa9):
        form["imm"] = struct.unpack_from("<i", code, p)[0]
        p += 4
    elif op in (0x0c, 0x1c, 0x3c, 0x24, 0x34):
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
    elif op in (0x83, 0xc1, 0x80, 0xc0):
        p = modrm(p)
        form["imm"] = struct.unpack_from("<b", code, p)[0] if op not in (0xc1, 0xc0) else code[p]
        p += 1
    elif op in (0x81, 0xc7):
        p = modrm(p)
        if opsize == 16:
            form["imm"] = struct.unpack_from("<h", code, p)[0]
            p += 2
        else:
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
        self.zf = self.sf = self.cf = self.pf = False
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
        self.zf, self.sf, self.cf, self.of = res == 0, bool(res >> (size - 1)), False, False
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
        if code == 10:
            return self.pf
        if code == 11:
            return not self.pf
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
        if op == 0x98 or op in SSE_OPS or (op in (0x0f10, 0x0f11) and f["f2"]) or (op == 0x0f6e and f["rex"] & 8):
            return self.step_sse(f, va, nxt)
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
        elif op == 0xa9:
            self.flags_logic(self.regs[0] & f["imm"] & ((1 << size) - 1), size)
        elif 0xb8 <= op <= 0xbf:
            self.set_reg(f["r"], 64 if f["rex"] & 8 else 32, f["imm"], f)
        elif op == 0xc7:
            if f["reg"] & 7:
                fail("unsupported c7 form")
            self.put(f["rm"], size, f["imm"] & ((1 << size) - 1), f, va)
        elif op in (0xc1, 0xd1, 0xc0):
            if op == 0xc0:
                size = 8
            count = (f["imm"] if op != 0xd1 else 1) & (63 if size == 64 else 31)
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
        elif 0x70 <= op <= 0x7f or 0x0f80 <= op <= 0x0f8f:
            if not self.cond(op & 15, va):
                return nxt
            if f["target"] in self.stubs:  # conditional tail call (`jne callee`)
                return self.transfer(f["target"], False, nxt)
            return f["target"]
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
        elif op == 0x34:
            self.set_reg(0, 8, self.flags_logic((self.regs[0] ^ f["imm"]) & 0xff, 8), f)
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

    def sse_src(self, f, va, width, aligned=False):
        rm = f["rm"]
        if rm[0] == "r":
            return self.xmm[rm[1]] & ((1 << (8 * width)) - 1)
        at = self.ea(rm, f, va)
        if aligned and at % 16:
            fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
        return self.load(at, width)

    def step_sse(self, f, va, nxt):
        """Scalar/packed double-precision forms, movq/movsd, cdqe: only the forms this body uses."""
        op, size, rm, dst = f["op"], f["size"], f.get("rm"), f.get("reg")
        if op == 0x98:
            if size == 64:
                self.regs[0] = sext(self.regs[0] & M32, 32) & M64
            elif size == 32:
                self.regs[0] = sext(self.regs[0] & 0xffff, 16) & M32
            else:
                fail(f"unsupported cwde form at {va:#x}")
        elif op == 0x0f10 and f["f2"]:  # movsd xmm, xmm/m64
            if rm[0] == "r":
                self.xmm[dst] = (self.xmm[dst] & ~M64 & M128) | (self.xmm[rm[1]] & M64)
            else:
                self.xmm[dst] = self.load(self.ea(rm, f, va), 8)
        elif op == 0x0f11 and f["f2"]:  # movsd xmm/m64, xmm
            if rm[0] == "r":
                self.xmm[rm[1]] = (self.xmm[rm[1]] & ~M64 & M128) | (self.xmm[dst] & M64)
            else:
                self.store(self.ea(rm, f, va), 8, self.xmm[dst] & M64)
        elif op == 0x0f6e:  # movq xmm, r/m64 (REX.W); movd is handled by the base evaluator
            self.xmm[dst] = self.get(rm, 64, f, va)
        elif op == 0x0f7e and f["rep"]:  # movq xmm, xmm/m64
            self.xmm[dst] = self.sse_src(f, va, 8)
        elif op == 0x0f7e:  # movd/movq r/m, xmm
            self.put(rm, 64 if f["rex"] & 8 else 32, self.xmm[dst], f, va)
        elif op == 0x0fd6:  # movq xmm/m64, xmm
            if rm[0] == "r":
                self.xmm[rm[1]] = self.xmm[dst] & M64
            else:
                self.store(self.ea(rm, f, va), 8, self.xmm[dst] & M64)
        elif op == 0x0f2a and f["f2"]:  # cvtsi2sd xmm, r/m32/64
            v = sext(self.get(rm, size, f, va), size)
            self.xmm[dst] = (self.xmm[dst] & ~M64 & M128) | dbits(float(v))
        elif op == 0x0f2c and f["f2"]:  # cvttsd2si r, xmm/m64
            d = bdouble(self.sse_src(f, va, 8))
            lim = 1 << (size - 1)
            if d != d or not (-lim <= d < lim):
                v = lim
            else:
                v = int(d)
            self.set_reg(dst, size, v, f)
        elif op in (0x0f58, 0x0f59, 0x0f5c, 0x0f5d, 0x0f5e, 0x0f5f) and f["f2"]:
            a, b = bdouble(self.xmm[dst] & M64), bdouble(self.sse_src(f, va, 8))
            if op == 0x0f58:
                r = a + b
            elif op == 0x0f59:
                r = a * b
            elif op == 0x0f5c:
                r = a - b
            elif op == 0x0f5e:
                r = fdiv(a, b)
            elif op == 0x0f5d:
                r = a if a < b else b
            else:
                r = a if a > b else b
            self.xmm[dst] = (self.xmm[dst] & ~M64 & M128) | dbits(r)
        elif op == 0x0f5c and f["p66"]:  # subpd
            b = self.sse_src(f, va, 16, True)
            a = self.xmm[dst]
            self.xmm[dst] = dbits(bdouble(a & M64) - bdouble(b & M64)) | dbits(bdouble(a >> 64) - bdouble(b >> 64)) << 64
        elif op == 0x0f2e and f["p66"]:  # ucomisd
            a, b = bdouble(self.xmm[dst] & M64), bdouble(self.sse_src(f, va, 8))
            self.of = False
            self.sf = False
            if a != a or b != b:
                self.zf = self.pf = self.cf = True
            else:
                self.pf = False
                self.zf, self.cf = a == b, a < b
        elif op == 0x0f62 and f["p66"]:  # punpckldq
            b = self.sse_src(f, va, 16, True)
            a = self.xmm[dst]
            d = lambda v, i: (v >> (32 * i)) & 0xffffffff
            self.xmm[dst] = d(a, 0) | d(b, 0) << 32 | d(a, 1) << 64 | d(b, 1) << 96
        elif op == 0x0f15 and f["p66"]:  # unpckhpd
            b = self.sse_src(f, va, 16, True)
            self.xmm[dst] = (self.xmm[dst] >> 64) | (b >> 64) << 64
        else:
            fail(f"unsupported SSE form {op:#x} at {va:#x}")
        return nxt


class TraceMachine(Machine):
    """Machine that also records every executed instruction address across runs."""

    def __init__(self, image, code_override=None):
        self.hits = {}
        self.cur = set()
        super().__init__(image, code_override)

    @property
    def seen(self):
        return self.hits.keys()

    def step(self, va):
        self.hits[va] = self.hits.get(va, 0) + 1
        self.cur.add(va)
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


# ---------------------------------------------------------------- target layout (all read from the bytes below)
OWNER = 0x44ae810            # vault move core, FDE [0x44ae810, 0x44af2e1)
CALLEES = {                  # direct callees that stay outside this reconstruction (recording contract stubs)
    "value": 0x44a9430,      # (ctx words, address) -> signed value of one address
    "settle": 0x44ad9e0,     # (vault, key copy, amount, vault value, aux, scratch) weighting / share bookkeeping
    "credit": 0x4472ea0,     # (ctx, address copy, amount)
    "log": 0x44e0810,        # (record) drop of a 0x34-tagged diagnostic
    "ring_find": 0x45578e0,  # (ring, key) -> al = 1 when absent, rdx = logical index   (real bytes)
}
SLOTS = {                    # relocation slots called indirectly: slot -> role
    0x64e5078: "avail",      # (ctx, key copy) -> unsigned available amount (0x446bdd0)
    0x64e7170: "debit",      # (ctx, key copy, amount) (0x447db40)
    0x64e6a80: "cond_a",     # (address) -> al   (0x421a3c0, real bytes)
    0x64e5ae8: "cond_b",     # (address) -> al   (0x421a520, real bytes)
    0x64dfb50: "memcmp",     # imported memcmp
    0x64e4ea8: "ovf",        # overflow report (0, location)
    0x64df830: "panic",      # Option::unwrap on None style panic (location)
    0x64df6a0: "panic_fmt",  # formatted panic
    0x64e0058: "ratio",      # (f64 num, f64 den) -> (ok, f64)   (0x14ca350, real bytes)
}
EXT_END = 0x44af2e1
# fixed addresses of the fixture objects
OUT_AT, VAULT_AT, CTX_AT, KEY_AT, AUX_AT, CLO_AT = (0x1000_0000_0000 + i * 0x10000 for i in range(6))
SET_AT, MAP_AT, RING_AT = 0x1000_0100_0000, 0x1000_0200_0000, 0x1000_0300_0000
SET_NODE, MAP_NODE = 0x148, 0x358
VAULT_SIZE, CTX_SIZE, OUT_SIZE = 0x100, 0x600, 0x30
RING_ELEM = 0x48
FILL = 0xa5
HEAD = 0x8000000000000019   # failure head word
OK_HEAD = HEAD - 0x15       # 0x8000000000000004
NICHE = 0x8000000000000000  # vault+0x50 word: B-tree map variant (otherwise a ring buffer)
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x1111111111111111 * (i + 1) for i in range(6))

# panic / overflow-report call sites: location operand = the rip-relative `lea` that precedes the call
PANIC_SITES = {0x44af1f7: "set-descend-unwrap", 0x44af2a0: "set-empty-unwrap", 0x44af2ad: "entry-missing-unwrap",
               0x44af2ba: "negative-amount"}
OVF_SITES = {0x44aeb7a: "vault-sum", 0x44af152: "balance-sub", 0x44af181: "balance-add", 0x44af19c: "entry-u64",
             0x44af1d7: "entry-i64", 0x44af206: "leader-total"}
CONSTS = {"lo": 0x459808, "hi": 0x459360, "cap": 0x458e50, "scale": 0x4599a0, "floor": 0x459920, "share": 0x459038}


def rip_target(image, va):
    """Target of the rip-relative operand of the lea at `va`."""
    f = decode(image.code(va, 16), va)
    return (va + f["len"] + f["rm"][4]) & M64


def protected(image, fn):
    """The 20-byte addresses an `is one of` predicate accepts: per block, pcmpeqb xmm1 against a 16-byte pool entry
    for the 4-byte tail (a match needs that entry's other 12 bytes to be zero) and pcmpeqb xmm0 against the head."""
    end = next(f["end"] for f in fde_extents.eh_frame_records(image.data, image.secs)[1] if f["start"] == fn)
    tails, heads, out = None, None, []
    for va, f in sweep(image, fn, end):
        if f["op"] == 0x0f74 and f["rm"][0] == "m" and f["rm"][1] == "rip":
            pool = image.read((va + f["len"] + f["rm"][4]) & M64, 16)
            if f["reg"] == 1:
                tails = pool
            else:
                heads = pool
                out.append(heads + tails[:4] if tails[4:] == bytes(12) else None)
    return out


class Layout:
    """Every number the model needs from the binary: constants and the call-site operands."""

    def __init__(self, image):
        self.k = {n: struct.unpack("<d", image.read(a, 8))[0] for n, a in CONSTS.items()}
        self.panic = {name: self.site_arg(image, va) for va, name in PANIC_SITES.items()}
        self.ovf = {name: self.site_arg(image, va) for va, name in OVF_SITES.items()}
        self.targets = {role: image.word(slot) for slot, role in SLOTS.items()}
        self.ratio_const = self.site_arg(image, 0x44af272)
        fmt = decode(image.code(0x44af2d4, 16), 0x44af2d4)["imm"]
        self.fmt = (fmt, self.site_arg(image, 0x44af2c1), self.site_arg(image, 0x44af2c8))
        self.prot_a = protected(image, self.targets["cond_a"])
        self.prot_b = protected(image, self.targets["cond_b"])
        self.k["tiny_neg"] = struct.unpack("<d", image.read(0x458fa0, 8))[0]
        self.k["min_den"] = struct.unpack("<d", image.read(0x459ba0, 8))[0]

    @staticmethod
    def site_arg(image, va):
        # the lea at the site (panic: lea rdi; overflow report: lea rsi after xor edi; some are `lea` + 7 or so)
        for back in range(0, 16):
            try:
                f = decode(image.code(va + back, 16), va + back) if back else decode(image.code(va, 16), va)
            except ToolError:
                continue
            if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
                return (va + back + f["len"] + f["rm"][4]) & M64
        fail(f"no rip-relative operand at {va:#x}")


# ---------------------------------------------------------------- deterministic generator
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

    def bytes(self, k):
        return self.take(k)

    def chance(self, num, den):
        return self.below(den) < num


# ---------------------------------------------------------------- B-tree fixtures
SET_CAP = 11
MAXN = {0: 11}
MINN = {0: 1}
for _h in range(1, 4):
    MAXN[_h] = MAXN[_h - 1] * 12 + 11
    MINN[_h] = MINN[_h - 1] * 2 + 1


def plan_tree(st, n, h):
    """Nested plan for n keys at height h: leaf -> n; internal -> list of (child plans) with n - len(children) + 1
    separators. Every child holds between MINN[h-1] and MAXN[h-1] keys; the root holds at least one key."""
    if h == 0:
        return n
    lo, hi = MINN[h - 1], MAXN[h - 1]
    ok = [c for c in range(2, 13) if lo * c + (c - 1) <= n <= hi * c + (c - 1)]
    c = st.pick(ok)
    sizes = [lo] * c
    extra = n - (c - 1) - lo * c
    while extra:
        i = st.below(c)
        if sizes[i] < hi:
            sizes[i] += 1
            extra -= 1
    return [plan_tree(st, s, h - 1) for s in sizes]


def feasible_heights(n):
    return [h for h in range(0, 4) if MINN[h] <= n <= MAXN[h]]


class Arena:
    """A bump region of fixed-size nodes."""

    def __init__(self, base, node, fill=FILL):
        self.base, self.node, self.fill, self.nodes = base, node, fill, []

    def alloc(self):
        self.nodes.append(bytearray([self.fill]) * self.node)
        return self.base + (len(self.nodes) - 1) * self.node

    def buf(self, ptr):
        return self.nodes[(ptr - self.base) // self.node]

    def bytes(self):
        return b"".join(bytes(n) for n in self.nodes)


def build_set(arena, st, keys, h):
    """BTreeSet<[u8;20]> nodes: parent@0, keys@8, parent_idx@0xe4, len@0xe6, edges@0xe8. Returns (root, height)."""
    plan = plan_tree(st, len(keys), h)
    pos = [0]

    def make(p, parent, pidx):
        ptr = arena.alloc()
        nd = arena.buf(ptr)
        put(nd, 0, 8, parent)
        put(nd, 0xe4, 2, pidx)
        if isinstance(p, int):
            put(nd, 0xe6, 2, p)
            for i in range(p):
                nd[8 + 20 * i:28 + 20 * i] = keys[pos[0]]
                pos[0] += 1
            return ptr
        put(nd, 0xe6, 2, len(p) - 1)
        for i, child in enumerate(p):
            put(nd, 0xe8 + 8 * i, 8, make(child, ptr, i))
            if i < len(p) - 1:
                nd[8 + 20 * i:28 + 20 * i] = keys[pos[0]]
                pos[0] += 1
        return ptr

    return make(plan, 0, 0), h


def build_map(arena, st, items, h):
    """BTreeMap<[u8;20], [u8;0x30]> nodes: vals@0, parent@0x210, keys@0x218, parent_idx@0x2f4, len@0x2f6,
    edges@0x2f8. items = sorted [(key, val)]. Returns (root, height, {key: value address})."""
    plan = plan_tree(st, len(items), h)
    pos = [0]
    where = {}

    def put_kv(nd, ptr, i):
        key, val = items[pos[0]]
        nd[0x218 + 20 * i:0x22c + 20 * i] = key
        nd[0x30 * i:0x30 * i + 0x30] = val
        where[key] = ptr + 0x30 * i
        pos[0] += 1

    def make(p, parent, pidx):
        ptr = arena.alloc()
        nd = arena.buf(ptr)
        put(nd, 0x210, 8, parent)
        put(nd, 0x2f4, 2, pidx)
        if isinstance(p, int):
            put(nd, 0x2f6, 2, p)
            for i in range(p):
                put_kv(nd, ptr, i)
            return ptr
        put(nd, 0x2f6, 2, len(p) - 1)
        for i, child in enumerate(p):
            put(nd, 0x2f8 + 8 * i, 8, make(child, ptr, i))
            if i < len(p) - 1:
                put_kv(nd, ptr, i)
        return ptr

    return make(plan, 0, 0), h, where


def build_ring(items, cap, head):
    """VecDeque of 0x48-byte elements (key@0 padded to 0x18, value@0x18) with `head` as the physical start."""
    buf = bytearray([FILL]) * (cap * RING_ELEM)
    where = {}
    for i, (key, val) in enumerate(items):
        phys = (head + i) % cap
        base = phys * RING_ELEM
        buf[base:base + 0x18] = key + b"\0" * 4
        buf[base + 0x18:base + 0x48] = val
        where[key] = RING_AT + base + 0x18
    return buf, where


def record(weight, u, i, tail):
    r = bytearray([FILL]) * 0x30
    put(r, 0, 8, dbits(weight))
    put(r, 8, 8, u)
    put(r, 0x10, 8, i)
    r[0x24:0x30] = tail
    return bytes(r)


# ---------------------------------------------------------------- recording stubs
def addr_at(m, at):
    return bytes(m.load(at + i, 1) for i in range(20))


def tag_ptr(c, v):
    return {CTX_AT: "ctx", VAULT_AT: "vault", VAULT_AT + 0x8c: "vault.addr", VAULT_AT + 0x50: "vault.map",
            AUX_AT: "aux"}.get(v, v)


def value_of(c, addr):
    """The `value` callee: a deterministic signed value per address (the case draws scale and seed)."""
    h = hashlib.sha256(c["vseed"] + addr).digest()
    base = int.from_bytes(h[:8], "little") % 2000001 - 1000000
    v = (abs(base) if c["vpos"] else base) * c["vscale"]
    return max(-(1 << 63), min((1 << 63) - 1, v))


def install_stubs(m, lay, c, calls):
    def clobber():
        for r in (1, 6, 7, 8, 9, 10, 11):
            m.regs[r] = 0xdeadbeefdeadbeef

    def reg(n):
        return m.regs[n]

    def s_value(m):
        w = tuple(m.load(reg(7) + 8 * i, 8) for i in range(3))
        a = addr_at(m, reg(6))
        calls.append(("value", a, tag_ptr(c, w[0]), w[1], w[2]))
        m.regs[0] = value_of(c, a) & M64
        clobber()

    def s_settle(m):
        key = addr_at(m, reg(6))
        sc = tuple(m.load(reg(9) + 8 * i, 8) for i in range(3))
        calls.append(("settle", tag_ptr(c, reg(7)), key, reg(2), reg(1), tag_ptr(c, reg(8)),
                      (tag_ptr(c, sc[0]), sc[1], sc[2])))
        clobber()

    def s_credit(m):
        calls.append(("credit", tag_ptr(c, reg(7)), addr_at(m, reg(6)), reg(2)))
        clobber()

    def s_log(m):
        calls.append(("log", m.load(reg(7), 2)))
        clobber()

    def s_avail(m):
        calls.append(("avail", tag_ptr(c, reg(7)), addr_at(m, reg(6))))
        m.regs[0] = c["avail"]
        clobber()

    def s_debit(m):
        calls.append(("debit", tag_ptr(c, reg(7)), addr_at(m, reg(6)), reg(2)))
        clobber()

    def s_memcmp(m):
        a, b = addr_at(m, reg(7)), addr_at(m, reg(6))
        n = reg(2)
        if n != 20:
            fail("memcmp length")
        d = next((x - y for x, y in zip(a, b) if x != y), 0)
        m.regs[0] = (0x7a7a7a7a00000000 | (d & M32))
        clobber()

    def s_ovf(m):
        calls.append(("ovf", reg(6)))
        clobber()

    def boom(kind):
        def s(m):
            raise Boundary(f"{kind}:{reg(7):#x}", m.regs)
        return s

    def boom_fmt(m):
        raise Boundary(f"panic:{reg(7):#x}:{reg(6):#x}:{reg(1):#x}:{reg(8):#x}", m.regs)

    t = lay.targets
    for role, fn in (("avail", s_avail), ("debit", s_debit), ("memcmp", s_memcmp), ("ovf", s_ovf),
                     ("panic", boom("panic")), ("panic_fmt", boom_fmt)):
        m.stubs[t[role]] = fn
    for role, fn in (("value", s_value), ("settle", s_settle), ("credit", s_credit), ("log", s_log)):
        m.stubs[CALLEES[role]] = fn


# ---------------------------------------------------------------- fixture memory for one case
def fixture(c):
    """Initial memory of every object the body can touch, plus the address of each map record."""
    st = Stream("shape/" + c["label"])
    vault = bytearray([FILL]) * VAULT_SIZE
    put(vault, 0x00, 8, c["mode"])
    children = c["children"]
    sets = Arena(SET_AT, SET_NODE)
    root, height = 0, 0
    if children:
        root, height = build_set(sets, st, children, c["set_h"])
    put(vault, 0x08, 8, 0 if c["set_root0"] else root)
    put(vault, 0x10, 8, height)
    put(vault, 0x18, 8, c["set_count"])
    items = sorted(c["entries"].items())
    maps, ring, where = Arena(MAP_AT, MAP_NODE), bytearray(), {}
    if c["kind"] == "tree":
        mroot, mh = 0, 0
        if items:
            mroot, mh, where = build_map(maps, st, items, c["map_h"])
        put(vault, 0x50, 8, NICHE)
        put(vault, 0x58, 8, mroot)
        put(vault, 0x60, 8, mh)
        put(vault, 0x68, 8, len(items))
    else:
        ring, where = build_ring(items, c["ring_cap"], c["ring_head"])
        put(vault, 0x50, 8, c["ring_cap"])
        put(vault, 0x58, 8, RING_AT)
        put(vault, 0x60, 8, c["ring_head"])
        put(vault, 0x68, 8, len(items))
    vault[0x8c:0xa0] = c["addr"]
    vault[0xa0:0xb4] = c["leader"]
    vault[0xb5] = c["pol"]
    ctx = bytearray([FILL]) * CTX_SIZE
    put(ctx, 0x4a8, 8, c["bal"])
    key = bytearray([FILL]) * 0x18
    key[0:20] = c["key"]
    aux = bytearray([FILL]) * 0x10
    aux[0:12] = c["aux"]
    clo = bytearray(24)
    put(clo, 0, 8, CTX_AT)
    put(clo, 8, 8, c["w1"])
    put(clo, 16, 8, c["w2"])
    regions = {"out": (OUT_AT, bytearray([FILL]) * OUT_SIZE), "vault": (VAULT_AT, vault), "ctx": (CTX_AT, ctx),
               "key": (KEY_AT, key), "aux": (AUX_AT, aux), "clo": (CLO_AT, clo)}
    if sets.nodes:
        regions["set"] = (SET_AT, bytearray(sets.bytes()))
    if maps.nodes:
        regions["map"] = (MAP_AT, bytearray(maps.bytes()))
    if ring:
        regions["ring"] = (RING_AT, bytearray(ring))
    return regions, where


# ---------------------------------------------------------------- reconstruction of the body
def sat64(v):
    return max(-(1 << 63), min((1 << 63) - 1, v))


def i64(v):
    return sext(v & M64, 64)


def leader_share(lay, r12, weight, mut):
    """Leader-position value in USDC units: saturating cast of (vault value * weight) divided by 1e6."""
    k = lay.k
    x = float(r12) * weight
    if dbits(x) & 0x7fffffffffffffff > 0x7fefffffffffffff:
        x1 = 0.0                                   # NaN or +-inf: pxor leaves 0
    elif k["lo"] > x or x > k["hi"]:
        t = k["lo"] if k["lo"] > x else x           # maxsd lo, x
        x1 = k["hi"] if k["hi"] < t else t          # minsd hi, t
    else:
        x1 = x
    if "no-clamp" in mut:
        x1 = x if x == x and abs(x) != float("inf") else 0.0
    if x1 > k["cap"]:
        q = (1 << 63) - 1
    elif x1 != x1:
        q = 0
    elif not (-(1 << 63) <= x1 < (1 << 63)):
        q = -(1 << 63)
    else:
        q = int(x1)
    if "cast-round" in mut:
        q = int(round(x1)) if abs(x1) < 2.0 ** 62 else q
    return float(q) / k["scale"]


def ratio_model(lay, num, den, mut=frozenset()):
    """0x14ca350: checked division. Returns (ok, quotient); any NaN/inf operand, a numerator below zero (beyond the
    tiny negative that is clamped to zero), or a denominator below the minimum fails."""
    k = lay.k
    fin = lambda x: dbits(x) & 0x7fffffffffffffff <= 0x7fefffffffffffff
    if not (fin(num) and fin(den)):
        return False, num
    if num < 0 and num > k["tiny_neg"] and "ratio-no-clamp" not in mut:
        num = 0.0
        if (k["min_den"] > den if "ratio-min-den-ge" not in mut else k["min_den"] >= den):
            return False, num
    else:
        if 0 > num or (k["min_den"] > den if "ratio-min-den-ge" not in mut else k["min_den"] >= den):
            return False, num
    q = fdiv(num, den)
    return dbits(q) & 0x7fffffffffffffff < 0x7ff0000000000000, q


def model(c, lay, mut=frozenset()):
    """Ordered calls, output record, balance and map-record updates of one run of the body at 0x44ae810."""
    calls, out = [], bytearray([FILL]) * OUT_SIZE
    state = {"bal": c["bal"], "recs": {}, "panic": None}
    key, leader, addr, mode, amount = c["key"], c["leader"], c["addr"], c["mode"], c["amount"]
    ne = key != leader

    def done(panic=None):
        state["panic"] = panic
        return {"panic": panic, "out": bytes(out), "bal": state["bal"], "recs": state["recs"], "calls": calls}

    def reject(code):
        put(out, 0, 8, HEAD)
        put(out, 0x10, 2, code)
        return done()

    def value(a):
        calls.append(("value", a, "ctx", c["w1"], c["w2"]))
        return value_of(c, a)

    def ovf(site):
        calls.append(("ovf", lay.ovf[site]))

    def find(k):
        """Map lookup by 20-byte key; the ring variant goes through the ring_find callee first."""
        return c["entries"].get(k)

    gate_mode = (mode == 1 if "mode-low32-gate" not in mut else (mode & M32) == 1) and ne
    gate_pol = (c["pol"] == 0 if "pol-eq-one" not in mut else c["pol"] != 1) and ne
    if "gate-order" in mut:
        if gate_pol:
            return reject(0x17)
        if gate_mode:
            return reject(0x16)
    else:
        if gate_mode:
            return reject(0x16)
        if gate_pol:
            return reject(0x17)
    r12 = value(addr)
    count_ok = c["set_count"] != 0 or "count-gate-off" in mut
    if (mode & M32) == 2 and count_ok and not c["set_root0"] and c["children"]:
        for a in sorted(c["children"], reverse="set-unsorted" in mut):
            v = value(a)
            s = r12 + v
            if not -(1 << 63) <= s < (1 << 63):
                if "sum-no-report" not in mut:
                    ovf("vault-sum")
                if "wrap-sum" not in mut:
                    s = sat64(s)
                else:
                    s = i64(s)
            r12 = s
    if r12 < 0:
        if addr not in lay.prot_a:
            return reject(9 if "nine-as-two" not in mut else 2)
    normal = (c["r9"] & 0xff != 0) if "r9-whole" not in mut else c["r9"] != 0
    if not normal:
        if (mode & M32) == 1 or not ne:
            normal = True
        else:
            normal = addr in (lay.prot_b if "prot-a-as-b" not in mut else lay.prot_a) or "cond-b-skip" in mut
    if not normal:
        rec = find(leader if "leader-by-source" not in mut else key)
        if rec is None:
            return reject(2)
        lead = leader_share(lay, r12, bdouble(u(rec, 0, 8)), mut)
        total = r12 if r12 > 0 or "total-no-clamp" in mut else 0
        s = total + (amount & M64)
        if s >> 64:
            ovf("leader-total")
            if "total-no-sat" not in mut:
                s = M64
        if lay.k["floor"] > lead:
            return reject(2)
        ok, ratio = ratio_model(lay, lead, float(s) / lay.k["scale"], mut)
        if not ok or lay.k["share"] > ratio:
            return reject(2)
    calls.append(("avail", "ctx", key))
    if amount < 0 and "neg-no-panic" not in mut:
        return done("panic:" + ":".join(hex(x) for x in (lay.panic["negative-amount"], lay.fmt[0], lay.fmt[1],
                                                         lay.fmt[2])))
    if (c["avail"] < amount) if "avail-le" not in mut else (c["avail"] <= amount):
        if "log-skip" not in mut:
            calls.append(("log", 0x34))
        put(out, 0, 8, HEAD)
        put(out, 0x10, 2, 0x2d)
        return done()
    if "credit-first" in mut:
        calls.append(("credit", "ctx", addr, amount))
    calls.append(("debit", "ctx", key, amount))
    b = state["bal"] - amount
    if not -(1 << 63) <= b < (1 << 63):
        ovf("balance-sub")
        b = sat64(b) if "sub-wrap" not in mut else i64(b)
    if "credit-first" not in mut:
        calls.append(("credit", "ctx", addr, amount))
    b2 = b + amount
    if not -(1 << 63) <= b2 < (1 << 63):
        ovf("balance-add")
        b2 = sat64(b2)
    state["bal"] = b2
    calls.append(("settle", "vault", key, amount, r12 & M64 if "settle-signed" not in mut else r12, "aux",
                  ("ctx", c["w1"], c["w2"])))
    rec = find(key if "entry-by-leader" not in mut else leader)
    if rec is None:
        return done("panic:" + hex(lay.panic["entry-missing-unwrap"]))
    new = bytearray(rec)
    uu = u(rec, 8, 8) + amount
    if uu >> 64:
        ovf("entry-u64")
        uu = M64 if "u64-wrap" not in mut else uu & M64
    ii = i64(u(rec, 0x10, 8)) + amount
    if not -(1 << 63) <= ii < (1 << 63):
        ovf("entry-i64")
        ii = sat64(ii) if "i64-wrap" not in mut else i64(ii)
    put(new, 8, 8, uu)
    put(new, 0x10, 8, ii)
    if "aux-skip" not in mut:
        new[0x24:0x30] = c["aux"]
    state["recs"][key] = bytes(new)
    put(out, 0, 8, OK_HEAD)
    put(out, 8, 8, dbits(float(amount) / (lay.k["scale"] if "scale-1e9" not in mut else 1e9)))
    out[0x10:0x24] = addr if "addr-16" not in mut else addr[:16] + bytes([FILL]) * 4
    return done()


def expected_regions(c, lay, want, regions, where):
    """Initial regions with the model's balance and record updates patched in."""
    exp = {n: (b, bytearray(buf)) for n, (b, buf) in regions.items()}
    exp["out"][1][:] = want["out"]
    put(exp["ctx"][1], 0x4a8, 8, want["bal"])
    name = "map" if c["kind"] == "tree" else "ring"
    for k, rec in want["recs"].items():
        at = where[k] - exp[name][0]
        exp[name][1][at:at + 0x30] = rec
    return exp


# ---------------------------------------------------------------- one run on the real bytes
def run_case(m, lay, c):
    m.reset()
    regions, where = fixture(c)
    bufs = {n: m.add_region(base, len(buf), bytes(buf)) for n, (base, buf) in regions.items()}
    calls = []
    install_stubs(m, lay, c, calls)
    for r, v in zip(SAVED_REGS, SAVED):
        m.regs[r] = v
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, VAULT_AT, KEY_AT
    m.regs[1], m.regs[8], m.regs[9] = c["amount"] & M64, AUX_AT, 0x5555555500000000 | (c["r9"] & M32)
    m.store(m.regs[4], 8, CLO_AT)  # first stack argument: pointer to the three closure words
    sp = m.regs[4]
    panic = None
    try:
        m.run(OWNER, limit=400000)
    except Boundary as b:
        if not b.kind.startswith("panic:"):
            raise
        panic = b.kind
    ok = panic is not None or ([m.regs[r] for r in SAVED_REGS] == list(SAVED) and m.regs[4] == sp
                               and m.regs[0] == OUT_AT)
    return {"calls": calls, "panic": panic, "regions": {n: bytes(b) for n, b in bufs.items()}, "regs_ok": ok,
            "steps": m.steps}, regions, where


def first_diff(a, b):
    return next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))


def compare(c, lay, want, got, regions, where):
    if want["panic"] != got["panic"]:
        return f"panic {want['panic']} != {got['panic']}"
    if want["calls"] != got["calls"]:
        i = next((i for i, (x, y) in enumerate(zip(want["calls"], got["calls"])) if x != y),
                 min(len(want["calls"]), len(got["calls"])))
        return f"call {i}: want {want['calls'][i:i + 1]} got {got['calls'][i:i + 1]}"
    exp = expected_regions(c, lay, want, regions, where)
    for n, (base, buf) in exp.items():
        if bytes(buf) != got["regions"][n]:
            return f"region {n} differs at +{first_diff(bytes(buf), got['regions'][n]):#x}"
    if not got["regs_ok"]:
        return "callee-saved registers, stack pointer or return value"
    return None


# ---------------------------------------------------------------- deterministic cases
def rand_key(st, base=None):
    if base is None:
        return st.bytes(20)
    pos = st.pick((0, 3, 15, 16, 17, 19))
    b = bytearray(base)
    b[pos] ^= 1 + st.below(255)
    return bytes(b)


def rand_record(st):
    w = st.pick((0.5, 1.0, 0.05, 0.001, 1e-9, 0.0, float("nan"), float("inf"), -0.5, 1e19, -1e19, 0.3, 0.9999,
                 0.25, 0.5, 0.7, 1e300, 1e305, -1e305, 1e307))
    if st.chance(1, 5):
        w = (st.below(10 ** 6) + 1) / 10 ** 6
    uu = st.pick((0, 5, 1 << 63, M64 - 5, M64, 12345, int.from_bytes(st.bytes(8), "little")))
    ii = st.pick((0, 5, -5, (1 << 63) - 4, -(1 << 63) + 3, 777, i64(int.from_bytes(st.bytes(8), "little"))))
    return record(w, uu, ii & M64, st.bytes(12))


def gen_case(k, lay):
    st = Stream(f"vault-move-115/{k}")
    c = {"k": k, "label": str(k)}
    c["mode"] = st.pick((2, 2, 2, 2, 2, 1, 0, 3, 0x100000002, 0x100000001, (1 << 63) | 2, 2, 1))
    leader = st.bytes(20)
    rel = st.pick(("same", "same", "same", "tail", "last", "first", "random", "random"))
    c["leader"] = leader
    c["key"] = leader if rel == "same" else rand_key(st) if rel == "random" else rand_key(st, leader)
    if rel == "tail":
        b = bytearray(leader)
        b[16 + st.below(4)] ^= 0x40
        c["key"] = bytes(b)
    c["pol"] = st.pick((0, 1, 0xff, 2, 1))
    c["r9"] = st.pick((0, 0, 0, 1, 0x100, 0xffffff01, 0x5a, 0))
    c["addr"] = st.bytes(20)
    n = st.pick((0, 1, 2, 3, 7, 11, 12, 13, 20, 35, 60, 5, 8))
    if st.chance(1, 40):
        n = 150
    keys = set()
    while len(keys) < n:
        keys.add(st.bytes(20) if st.chance(3, 4) or not keys else rand_key(st, min(keys)))
    c["children"] = sorted(keys)
    c["set_h"] = st.pick(feasible_heights(n)) if n else 0
    c["set_root0"] = n > 0 and st.chance(1, 14)
    c["set_count"] = 0 if n and st.chance(1, 14) else n
    c["vseed"] = st.bytes(8)
    c["vpos"] = st.chance(3, 4)
    c["vscale"] = st.pick((1, 1, 1000, 10 ** 6, 10 ** 6, 10 ** 12, 10 ** 15, 1 << 56, 1 << 60))
    c["amount"] = st.pick((0, 1, 7, 10 ** 6, 5 * 10 ** 6, 10 ** 9, 1 << 40, 1 << 62, (1 << 63) - 1, -1, -5,
                           -(1 << 63), 3 * 10 ** 6, 10 ** 7))
    a = c["amount"]
    c["avail"] = st.pick((a, a + 1, a - 1, 0, 1 << 63, M64, int.from_bytes(st.bytes(8), "little"), a, a + 1000)) & M64
    c["bal"] = st.pick((0, 100, -100, 1 << 40, -(1 << 63) + 2, (1 << 63) - 3, -(1 << 63) + a if a > 0 else 5,
                        (1 << 63) - 1 - a if a > 0 else 9, 5 * 10 ** 6))
    if st.chance(1, 3):
        pool = [a for a in lay.prot_a + lay.prot_b if a]
        c["addr"] = st.pick(pool)
        if st.chance(1, 5):
            b = bytearray(c["addr"])
            b[st.below(20)] ^= 1 << st.below(8)
            c["addr"] = bytes(b)
    c["aux"] = st.bytes(12)
    c["w1"], c["w2"] = int.from_bytes(st.bytes(8), "little"), int.from_bytes(st.bytes(8), "little")
    c["kind"] = st.pick(("tree", "tree", "ring"))
    entries = {}
    if st.chance(17, 20):
        entries[c["leader"]] = rand_record(st)
    if st.chance(17, 20):
        entries[c["key"]] = rand_record(st)
    for _ in range(st.pick((0, 0, 1, 3, 8, 15, 30))):
        entries[st.bytes(20)] = rand_record(st)
    if entries and st.chance(1, 12) and len(entries) > 1:
        entries.pop(c["key"], None)
    if k % 200 == 7:  # leader-share boundary: the vault value is i64::MAX and a negative amount carries the u64 total
        c.update(mode=2, r9=0, pol=1, amount=-1 - st.below(2), vscale=1 << 60, vpos=True, key=rand_key(st),
                 addr=st.bytes(20))
        entries = {c["leader"]: record(0.12, 5, 5, bytes(12)), c["key"]: rand_record(st)}
    c["entries"] = entries
    ne = len(entries)
    c["map_h"] = st.pick(feasible_heights(ne)) if ne else 0
    c["ring_cap"] = max(ne, 1) + st.pick((0, 1, 3, 10))
    c["ring_head"] = st.below(c["ring_cap"])
    return c


LAYOUT = None


def all_cases(lay, scale=1.0):
    for k in range(int(CASES * scale)):
        yield gen_case(k, lay)


CASES = 10400


def machine(image, override=None):
    return TraceMachine(image, override)


def evaluate(image, lay, cases, mut=frozenset(), override=None, stop_on_first=False, machine_=None):
    m = machine_ or machine(image, override)
    n = bad = 0
    first = None
    digest = hashlib.sha256()
    for c in cases:
        try:
            got, regions, where = run_case(m, lay, c)
        except (ToolError, Boundary, KeyError, ValueError, IndexError, OverflowError, struct.error) as e:
            if override is None and not mut:
                raise
            got = None
        n += 1
        if got is None:
            why = "evaluator fault"
        else:
            why = compare(c, lay, model(c, lay, mut), got, regions, where)
        if why:
            bad += 1
            first = first or (c["k"], why)
            if stop_on_first:
                break
        elif got is not None:
            digest.update(f"{c['k']}/{got['panic']}/{got['regions']['out'].hex()}/{len(got['calls'])}\n".encode())
    return {"n": n, "bad": bad, "first": first, "digest": digest.hexdigest(), "machine": m}


# ---------------------------------------------------------------- the four helpers that run as real bytes
HELPERS = {"cond_a": 0x421a3c0, "cond_b": 0x421a520, "ratio": 0x14ca350, "ring_find": 0x45578e0}
HELPER_LEN = {"cond_a": 347, "cond_b": 347, "ratio": 148, "ring_find": 492}
FUNCS = {"owner": (OWNER, EXT_END)}
FUNCS.update({n: (a, a + HELPER_LEN[n]) for n, a in HELPERS.items()})
HIT_CAP = 150
H_ADDR, H_RING, H_KEY = 0x1000_0400_0000, 0x1000_0500_0000, 0x1000_0600_0000

F_POOL = (0.0, -0.0, 1.0, 0.5, 0.05, 1e-7, 1e-9, 3.5, 100.0, 1e6, 1e12, 1e300, -1e300, 5e-324, -5e-324,
          float("nan"), float("inf"), float("-inf"), 123456.789, 0.049999999999999996, 0.05, 0.0500000001, 2.5e-5,
          1e305, 1e307, -1e305)


def helper_cases(lay):
    """Direct calls of the four helpers (the owner reaches only part of their input space)."""
    cases = []
    members = [a for a in lay.prot_a + lay.prot_b if a]
    for name in ("cond_a", "cond_b"):
        own = [a for a in (lay.prot_a if name == "cond_a" else lay.prot_b)]
        st = Stream("helper/" + name)
        for i in range(1200):
            if i < 8:
                addr = own[i] or st.bytes(20)
            elif i % 3 == 0:
                addr = st.pick(own) or st.bytes(20)
                b = bytearray(addr)
                b[st.below(20)] ^= 1 << st.below(8)
                addr = bytes(b)
            elif i % 3 == 1:
                addr = st.pick(members)
            else:
                addr = st.bytes(20)
            cases.append({"helper": name, "addr": addr, "id": len(cases)})
    st = Stream("helper/ratio")
    k = lay.k
    near = (k["tiny_neg"], k["min_den"], k["tiny_neg"] / 2, k["tiny_neg"] * 2, k["min_den"] / 2, k["min_den"] * 2,
            -k["tiny_neg"])
    for i in range(3400):
        pool = F_POOL + near
        num = st.pick(pool) if st.chance(3, 4) else (st.below(2 * 10 ** 6) - 10 ** 6) / 10 ** (st.below(9))
        den = st.pick(pool) if st.chance(3, 4) else st.below(10 ** 7) / 10 ** (st.below(8))
        cases.append({"helper": "ratio", "num": num, "den": den, "id": len(cases)})
    for i in range(2200):
        n = st.below(40) if i % 7 else st.pick((0, 1, 2, 3))
        cap = max(n, 1) + st.pick((0, 0, 1, 2, 7))
        head = st.below(cap)
        keys = set()
        while len(keys) < n:
            keys.add(st.bytes(20) if st.chance(2, 3) or not keys else rand_key(st, min(keys)))
        keys = sorted(keys)
        r = st.below(5)
        probe = (st.pick(keys) if keys and r < 2 else st.bytes(20) if r == 2 else
                 rand_key(st, st.pick(keys)) if keys else st.bytes(20))
        cases.append({"helper": "ring_find", "keys": keys, "cap": cap, "head": head, "probe": probe, "id": len(cases)})
    return cases


def run_helper(m, lay, c):
    m.reset()
    h = c["helper"]
    m.stubs[lay.targets["memcmp"]] = memcmp_stub(m)
    for r, v in zip(SAVED_REGS, SAVED):
        m.regs[r] = v
    sp = m.regs[4]
    if h in ("cond_a", "cond_b"):
        buf = bytearray([FILL]) * 0x18
        buf[0:20] = c["addr"]
        m.add_region(H_ADDR, 0x18, bytes(buf))
        m.regs[7] = H_ADDR
        m.run(HELPERS[h])
        return {"rax": m.regs[0] & 0xff}
    if h == "ratio":
        m.xmm[0], m.xmm[1] = dbits(c["num"]), dbits(c["den"])
        m.regs[7] = 0x6666
        m.run(HELPERS[h])
        return {"rax": m.regs[0], "x0": m.xmm[0] & M64, "x1": m.xmm[1] & M64}
    ring, where = build_ring([(k, bytes(0x30)) for k in c["keys"]], c["cap"], c["head"])
    ring = bytearray(ring)
    m.add_region(RING_AT, max(len(ring), 16), bytes(ring))
    hdr = bytearray(0x20)
    put(hdr, 0, 8, c["cap"])
    put(hdr, 8, 8, RING_AT)
    put(hdr, 0x10, 8, c["head"])
    put(hdr, 0x18, 8, len(c["keys"]))
    m.add_region(H_RING, 0x20, bytes(hdr))
    kb = bytearray([FILL]) * 0x18
    kb[0:20] = c["probe"]
    m.add_region(H_KEY, 0x18, bytes(kb))
    m.regs[7], m.regs[6] = H_RING, H_KEY
    m.run(HELPERS[h])
    ok = [m.regs[r] for r in SAVED_REGS] == list(SAVED) and m.regs[4] == sp
    return {"rax": m.regs[0], "rdx": m.regs[2], "regs_ok": ok}


def helper_model(lay, c, mut=frozenset()):
    h = c["helper"]
    if h in ("cond_a", "cond_b"):
        own = lay.prot_a if h == "cond_a" else lay.prot_b
        if "prot-drop-last" in mut:
            own = own[:-1]
        if "prot-head-only" in mut:
            return {"rax": int(any(a and a[:16] == c["addr"][:16] for a in own))}
        return {"rax": int(c["addr"] in own)}
    if h == "ratio":
        ok, q = ratio_model(lay, c["num"], c["den"], mut)
        return {"rax": int(ok), "x0": dbits(q), "x1": dbits(c["den"])}
    keys = c["keys"]
    lo, hi = 0, len(keys)
    while lo < hi:
        mid = (lo + hi) // 2
        if (keys[mid] < c["probe"]) if "ring-le" not in mut else (keys[mid] <= c["probe"]):
            lo = mid + 1
        else:
            hi = mid
    found = lo < len(keys) and keys[lo] == c["probe"]
    return {"rax": 0 if found else 1, "rdx": lo, "regs_ok": True}


def memcmp_stub(m):
    def s(m):
        a, b = addr_at(m, m.regs[7]), addr_at(m, m.regs[6])
        if m.regs[2] != 20:
            fail("memcmp length")
        d = next((x - y for x, y in zip(a, b) if x != y), 0)
        m.regs[0] = 0x7a7a7a7a00000000 | (d & M32)
        for r in (1, 6, 7, 8, 9, 10, 11):
            m.regs[r] = 0xdeadbeefdeadbeef
    return s


def eval_helpers(image, lay, cases, override=None, stop_on_first=False, machine_=None, mut=frozenset(), hit_log=None):
    m = machine_ or machine(image, override)
    bad, first, n = 0, None, 0
    for c in cases:
        try:
            got = run_helper(m, lay, c)
        except (ToolError, Boundary, KeyError, ValueError, IndexError, AssertionError):
            if override is None:
                raise
            got = None
        n += 1
        if hit_log is not None:
            for va in m.cur:
                lst = hit_log.setdefault(va, [])
                if len(lst) < HIT_CAP:
                    lst.append(c["id"])
            m.cur = set()
        want = helper_model(lay, c, mut)
        if got is None or any(got[k] != v for k, v in want.items()):
            bad += 1
            first = first or (c["helper"], n)
            if stop_on_first:
                break
    return {"n": n, "bad": bad, "first": first, "machine": m}
import itertools


# ---------------------------------------------------------------- negative controls
OWNER_MUTANTS = (
    "mode-low32-gate", "wrap-sum", "no-clamp", "cast-round", "pol-eq-one", "gate-order", "sum-no-report",
    "count-gate-off", "set-unsorted", "nine-as-two", "r9-whole", "prot-a-as-b", "cond-b-skip", "leader-by-source",
    "total-no-clamp", "total-no-sat", "neg-no-panic", "avail-le", "log-skip", "credit-first", "sub-wrap",
    "settle-signed", "entry-by-leader", "u64-wrap", "i64-wrap", "aux-skip", "scale-1e9", "addr-16",
    "ratio-no-clamp", "ratio-min-den-ge",
)
HELPER_MUTANTS = ("prot-drop-last", "prot-head-only", "ratio-no-clamp", "ratio-min-den-ge", "ring-le")

# Mutants that cannot change any observable (name -> why); everything else must be detected.
EQUIV = {
    "model:no-clamp": "the maxsd/minsd clamp to [-2^63, 2^63] is redundant: cvttsd2si plus the compare against 2^63-1024 "
                      "already yield i64::MAX above the range and i64::MIN below it",
    "byte:owner:0x44af0ad:0x44af0ad:jcc:77^01": "same redundant clamp: both successors reach the same cvttsd2si saturation",
    "byte:owner:0x44af0b7:0x44af0b7:jcc:77^01": "same redundant clamp: both successors reach the same cvttsd2si saturation",
    "byte:owner:0x44ae9b5:0x44ae9b8:imm8:08^01": "tree-height threshold of an 8-way unrolled descent; heights are below 8 "
                                                 "for every key count a 64-bit length can hold with 11-key nodes",
    "byte:owner:0x44aea98:0x44aea9b:imm8:08^01": "same threshold in the second descent loop; the unrolled body is unreachable",
    "byte:owner:0x44af222:0x44af225:imm32:ff^01": "u64::MAX-1 and u64::MAX both round to 2^64 as f64 before the share division",
    "byte:ring_find:0x455794b:0x455794e:imm8:01^01": "a one-element tail compares element 0 either way (special case vs. loop of zero steps)",
    "byte:ring_find:0x4557994:0x4557997:imm8:01^01": "a one-element range takes one extra no-op halving step, then the same final compare",
    "byte:ring_find:0x4557a31:0x4557a32:imm32:01^01": "eax=1 is only returned when the second slice is empty, which cannot happen "
                                                      "for head < capacity; otherwise eax is rewritten before return",
    "byte:ring_find:0x4557aaf:0x4557ab0:imm32:00^01": "bit 0 of eax is overwritten by the following setne al",
}


def flip(c, **kw):
    d = dict(c)
    d.update(kw)
    return d


def flip_byte(b, i):
    x = bytearray(b)
    x[i] ^= 1
    return bytes(x)


WORLD = (
    ("leader-last-byte", lambda c: flip(c, leader=flip_byte(c["leader"], 19))),
    ("leader-first-byte", lambda c: flip(c, leader=flip_byte(c["leader"], 0))),
    ("policy-byte", lambda c: flip(c, pol=c["pol"] ^ 1)),
    ("amount-plus-one", lambda c: flip(c, amount=c["amount"] + 1)),
    ("balance-plus-one", lambda c: flip(c, bal=c["bal"] + 1)),
    ("aux-byte", lambda c: flip(c, aux=flip_byte(c["aux"], 3))),
    ("addr-last-byte", lambda c: flip(c, addr=flip_byte(c["addr"], 19))),
    ("mode-high-word", lambda c: flip(c, mode=c["mode"] ^ (1 << 32))),
    ("r9-low-bit", lambda c: flip(c, r9=c["r9"] ^ 1)),
    ("value-seed", lambda c: flip(c, vseed=flip_byte(c["vseed"], 0))),
    ("avail-minus-one", lambda c: flip(c, avail=(c["avail"] - 1) & M64)),
    ("entry-weight", lambda c: flip(c, entries={k: (flip_byte(v, 6) if i == 0 else v)
                                                for i, (k, v) in enumerate(sorted(c["entries"].items()))})),
    ("child-key", lambda c: flip(c, children=[flip_byte(k, 7) if i == 0 else k for i, k in enumerate(c["children"])])),
)


def sites(image, reached):
    """Byte positions whose change must be visible: immediate operands, condition codes of jcc/setcc/cmovcc and the
    pool displacement of the two address predicates, restricted to instructions the cases executed."""
    rows = []
    for name, (a, e) in FUNCS.items():
        for va, f in sweep(image, a, e):
            if va not in reached:
                continue
            op, n = f["op"], f["len"]
            raw = image.read(va, n)
            if 0x70 <= op <= 0x7f:
                rows.append((name, va, va, 1, "jcc"))
            elif 0x0f80 <= op <= 0x0f8f or 0x0f90 <= op <= 0x0f9f or 0x0f40 <= op <= 0x0f4f:
                rows.append((name, va, va + raw.index(0x0f) + 1, 1, "cc"))
            if f.get("imm") is not None and op not in (0xe8, 0xe9) and not 0x70 <= op <= 0x7f:
                if f["op"] in (0x83, 0x81) and f["rm"][0] == "r" and f["rm"][1] == 4:
                    continue
                if op in (0x80, 0x83, 0xc6, 0xc0, 0xc1, 0xa8, 0x0c, 0x1c, 0x24, 0x34, 0x3c, 0x6b) or 0xb0 <= op <= 0xb7:
                    rows.append((name, va, va + n - 1, 1, "imm8"))
                elif 0xb8 <= op <= 0xbf and n == 10:
                    rows.append((name, va, va + n - 1, 1, "imm64-top"))
                elif op in (0x81, 0xc7) and f["size"] == 16:
                    rows.append((name, va, va + n - 2, 1, "imm16"))
                elif op in (0x81, 0xc7, 0x69, 0x3d, 0x05, 0xa9) or 0xb8 <= op <= 0xbf:
                    rows.append((name, va, va + n - 4, 1, "imm32"))
            if name in ("cond_a", "cond_b", "ratio") and f.get("rm") and f["rm"][0] == "m" and f["rm"][1] == "rip":
                rows.append((name, va, va + n - 4, 0x10, "pool"))
    return rows


def site_name(row, raw_byte):
    func, va, at, x, kind = row
    return f"byte:{func}:{va:#x}:{at:#x}:{kind}:{raw_byte:02x}^{x:02x}"


def run_controls(image, lay, reached, owner_hits, helper_hits):
    rows = []
    shared = machine(image)

    def add(name, detected, witness):
        rows.append({"control": name, "detected": detected, "witness": witness})

    for mut in OWNER_MUTANTS:
        if mut in ("ratio-no-clamp", "ratio-min-den-ge"):
            r = eval_helpers(image, lay, [c for c in HELPER_CASES if c["helper"] == "ratio"], mut=frozenset([mut]),
                             stop_on_first=True, machine_=shared)
            add(f"model:{mut}", r["bad"] > 0, f"helper/{r['first'][0]}/{r['first'][1]}" if r["bad"] else "-")
            continue
        limit = 3000 if f"model:{mut}" in EQUIV else CASES
        r = evaluate(image, lay, itertools.islice(all_cases(lay), limit), mut=frozenset([mut]), stop_on_first=True,
                     machine_=shared)
        add(f"model:{mut}", r["bad"] > 0, f"case/{r['first'][0]}" if r["bad"] else f"none of {r['n']}")
    for mut in HELPER_MUTANTS:
        if mut in ("ratio-no-clamp", "ratio-min-den-ge"):
            continue
        r = eval_helpers(image, lay, HELPER_CASES, mut=frozenset([mut]), stop_on_first=True, machine_=shared)
        add(f"model:helper-{mut}", r["bad"] > 0, f"helper/{r['first'][0]}/{r['first'][1]}" if r["bad"] else "-")
    for name, fn in WORLD:
        found = None
        for c in all_cases(lay):
            try:
                c2 = fn(c)
            except (IndexError, ValueError):
                continue
            try:
                got, regions, where = run_case(shared, lay, c2)
            except (ToolError, Boundary):
                found = c["k"]
                break
            if compare(c, lay, model(c, lay), got, regions, where):
                found = c["k"]
                break
        add(f"world:{name}", found is not None, f"case/{found}" if found is not None else "-")
    bad = bytearray(image.data[:4096])
    bad[100] ^= 1
    try:
        Image(bytes(bad) + image.data[4096:])
        add("binary:digest", False, "-")
    except ToolError:
        add("binary:digest", True, "sha256 mismatch")
    try:
        image.read(0x10, 4)
        add("binary:read-outside-sections", False, "-")
    except ToolError:
        add("binary:read-outside-sections", True, "outside file-backed sections")
    try:
        decode(bytes([0x0f, 0x0b ^ 0x0f]) + bytes(14), 0)
        add("binary:unsupported-opcode", False, "-")
    except ToolError:
        add("binary:unsupported-opcode", True, "unsupported opcode")
    for row in sites(image, reached):
        func, va, at, x, kind = row
        old = image.read(at, 1)[0]
        override = {at: old ^ x}
        if func == "owner":
            ids = owner_hits.get(va, [])
            r = evaluate(image, lay, (gen_case(k, lay) for k in ids), override=override, stop_on_first=True)
        else:
            ids = helper_hits.get(va, [])
            r = eval_helpers(image, lay, [HELPER_CASES[i] for i in ids], override=override, stop_on_first=True)
        w = f"none of {len(ids)} executing cases"
        if r["bad"]:
            w = f"case/{r['first'][0]}" if func == "owner" else f"helper/{r['first'][0]}/{r['first'][1]}"
        add(site_name(row, old), r["bad"] > 0, w)
    return rows


# ---------------------------------------------------------------- evidence
HELPER_CASES = []
ROLE = {"owner": "vault move core", "cond_a": "address in set A", "cond_b": "address in set B",
        "ratio": "checked division num/den", "ring_find": "sorted ring binary search"}
STUB_ROLE = {0x44a9430: "value of one address", 0x44ad9e0: "settle / share bookkeeping", 0x4472ea0: "credit helper",
             0x44e0810: "diagnostic drop", 0x446bdd0: "available amount", 0x447db40: "debit helper",
             0x4524e40: "overflow report", 0x1680c10: "unwrap-none panic", 0x1680c30: "formatted panic"}


def call_text(rec):
    parts = [str(rec[0])]
    for a in rec[1:]:
        if isinstance(a, bytes):
            parts.append(a.hex())
        elif isinstance(a, tuple):
            parts.append("(" + ",".join(f"{x:#x}" if isinstance(x, int) else str(x) for x in a) + ")")
        elif isinstance(a, int):
            parts.append(f"{a:#x}" if a >= 0 else str(a))
        else:
            parts.append(str(a))
    return " ".join(parts)


def outcome(want):
    if want["panic"]:
        return want["panic"]
    o = want["out"]
    if u(o, 0, 8) == OK_HEAD:
        return "ok"
    return f"reject-{u(o, 0x10, 2):#x}"


def callee_rows(image, lay):
    rows = []
    for va, f in sweep(image, OWNER, EXT_END):
        if f["op"] == 0xe8:
            t = f["target"]
            role = next((n for n, a in CALLEES.items() if a == t), None)
            rows.append((va, "call", t, role or "?", ("real" if role in HELPERS else "stub") if role else "?"))
        elif f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
            slot = (va + f["len"] + f["rm"][4]) & M64
            t = image.word(slot)
            role = SLOTS.get(slot, "?")
            how = "real" if role in HELPERS else "stub"
            rows.append((va, f"slot {slot:#x}", t, role, how))
        elif f["op"] == 0xff and f["reg"] & 7 == 2:
            rows.append((va, "indirect register (memcmp pointer in rbp)", lay.targets["memcmp"], "memcmp", "stub"))
        elif ("target" in f and f["op"] != 0xe8) and not OWNER <= f["target"] < EXT_END:
            rows.append((va, "jump outside", f["target"], "?", "?"))
    if any(r[3] == "?" for r in rows):
        fail(f"unclassified call: {[r for r in rows if r[3] == '?']}")
    return rows


def generate(out, scale=1.0):
    global HELPER_CASES
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail("node #115 digest mismatch")
    image = Image(data)
    lay = Layout(image)
    HELPER_CASES = helper_cases(lay)
    # -- whole-body comparison of the owner on every case
    m = machine(image)
    counts, sample, digest = {}, [], hashlib.sha256()
    owner_hits = {}
    n_owner, bad = 0, 0
    for c in all_cases(lay, scale):
        got, regions, where = run_case(m, lay, c)
        want = model(c, lay)
        why = compare(c, lay, want, got, regions, where)
        if why:
            fail(f"owner case {c['k']}: {why}")
        n_owner += 1
        for va in m.cur:
            lst = owner_hits.setdefault(va, [])
            if len(lst) < HIT_CAP:
                lst.append(c["k"])
        m.cur = set()
        oc = outcome(want)
        counts[oc] = counts.get(oc, 0) + 1
        digest.update(f"{c['k']}/{oc}/{want['bal']}/{want['out'].hex()}\n".encode())
        if c["k"] % 6 == 0:
            sample.append((c, want, got["steps"], oc))
    # -- direct helper cases
    helper_hits = {}
    hres = eval_helpers(image, lay, HELPER_CASES, machine_=m, hit_log=helper_hits)
    if hres["bad"]:
        fail(f"helper mismatch {hres['first']}")
    reached = set(m.hits)
    ctl = run_controls(image, lay, reached, owner_hits, helper_hits)
    equiv = [r for r in ctl if not r["detected"] and r["control"] in EQUIV]
    missed = [r["control"] for r in ctl if not r["detected"] and r["control"] not in EQUIV]
    if missed:
        fail(f"undetected controls: {missed}")
    out.mkdir(parents=True, exist_ok=True)
    w = lambda name, lines: (out / name).write_text("\n".join(lines) + "\n")

    rows = ["function\trole\tstart\tend\tbytes\tinstructions\texecuted\truns_as"]
    ins = ["function\taddress\tlength\tbytes\truns"]
    unr = ["function\taddress\tlength\tbytes"]
    for name, (a, e) in FUNCS.items():
        insns = sweep(image, a, e)
        ex = sum(1 for v, _ in insns if v in reached)
        rows.append(f"{name}\t{ROLE[name]}\t{a:#x}\t{e:#x}\t{e - a}\t{len(insns)}\t{ex}\t"
                    f"{'case-driven real bytes' if name == 'owner' else 'real bytes, also called by the owner'}")
        for v, f in insns:
            ins.append(f"{name}\t{v:#x}\t{f['len']}\t{image.read(v, f['len']).hex()}\t{m.hits.get(v, 0)}")
            if v not in reached:
                unr.append(f"{name}\t{v:#x}\t{f['len']}\t{image.read(v, f['len']).hex()}")
    w("bodies.tsv", rows)
    w("instructions.tsv", ins)
    w("unreached.tsv", unr)

    crow = ["site\tkind\ttarget\trole\truns_as"]
    for va, kind, t, role, how in callee_rows(image, lay):
        crow.append(f"{va:#x}\t{kind}\t{t:#x}\t{role}\t{how}")
    w("callees.tsv", crow)

    k = ["name\taddress\tvalue"]
    for n, a in CONSTS.items():
        k.append(f"{n}\t{a:#x}\t{lay.k[n]!r}")
    k.append(f"tiny_neg\t0x458fa0\t{lay.k['tiny_neg']!r}")
    k.append(f"min_den\t0x459ba0\t{lay.k['min_den']!r}")
    for i, a in enumerate(lay.prot_a):
        k.append(f"set_a[{i}]\t0x421a3c0\t{a.hex() if a else 'unmatchable'}")
    for i, a in enumerate(lay.prot_b):
        k.append(f"set_b[{i}]\t0x421a520\t{a.hex() if a else 'unmatchable'}")
    for n, v in lay.panic.items():
        k.append(f"panic:{n}\t-\t{v:#x}")
    for n, v in lay.ovf.items():
        k.append(f"overflow-site:{n}\t-\t{v:#x}")
    w("constants.tsv", k)

    srows = ["case\tmode\tr9\tkey_is_leader\tamount\tmap\tentries\tchildren\toutcome\tbalance_after\tupdated\tsteps\tcalls"]
    for c, want, steps, oc in sample:
        srows.append(f"{c['k']}\t{c['mode']:#x}\t{c['r9']:#x}\t{int(c['key'] == c['leader'])}\t{c['amount']}\t{c['kind']}\t"
                     f"{len(c['entries'])}\t{len(c['children'])}\t{oc}\t{want['bal']}\t{len(want['recs'])}\t{steps}\t"
                     + " | ".join(call_text(r) for r in want["calls"]))
    w("cases-sample.tsv", srows)
    hrows = ["case\thelper\tinput\tresult"]
    for i, c in enumerate(HELPER_CASES):
        if i % 20:
            continue
        want = helper_model(lay, c)
        if c["helper"] in ("cond_a", "cond_b"):
            inp = c["addr"].hex()
        elif c["helper"] == "ratio":
            inp = f"{c['num']!r} / {c['den']!r}"
        else:
            inp = f"{len(c['keys'])} keys cap {c['cap']} head {c['head']} probe {c['probe'].hex()[:8]}"
        res = " ".join(f"{k_}={v:#x}" if isinstance(v, int) and not isinstance(v, bool) else f"{k_}={v}"
                       for k_, v in want.items())
        hrows.append(f"{i}\t{c['helper']}\t{inp}\t{res}")
    w("helper-cases-sample.tsv", hrows)
    w("controls.tsv", ["control\tdetected\twitness"] + [f"{r['control']}\t{'yes' if r['detected'] else 'no'}\t{r['witness']}"
                                                         for r in ctl])
    w("equivalent-mutants.tsv", ["mutant\tchecked\twhy"] + [f"{r['control']}\t{r['witness']}\t{EQUIV[r['control']]}"
                                                           for r in equiv])
    total = n_owner + len(HELPER_CASES)
    detected = sum(1 for r in ctl if r["detected"])
    summary = {
        "binary_sha256": SHA256, "owner": f"{OWNER:#x}", "owner_cases": n_owner, "helper_cases": len(HELPER_CASES),
        "outcomes": dict(sorted(counts.items())), "mismatches": 0, "owner_digest": digest.hexdigest(),
        "controls": len(ctl), "controls_detected": detected, "equivalent": len(equiv),
        "owner_instructions": len(sweep(image, OWNER, EXT_END)),
        "owner_instructions_executed": sum(1 for v, _ in sweep(image, OWNER, EXT_END) if v in reached),
    }
    w("summary.json", json.dumps(summary, indent=1, sort_keys=True).split("\n"))
    meas = {"cases": total, "negative_controls": len(ctl), "negative_detected": detected, "equivalent": len(equiv),
            "owner_cases": n_owner, "helper_cases": len(HELPER_CASES)}
    w("measure.json", json.dumps(meas, indent=1, sort_keys=True).split("\n"))
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    a = ap.parse_args(argv)
    try:
        s = generate(a.out)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{s['owner_cases']}+{s['helper_cases']} cases, {s['mismatches']} mismatches, "
          f"{s['controls_detected']}+{s['equivalent']}/{s['controls']} controls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
