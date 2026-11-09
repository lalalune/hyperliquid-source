"""Reconstruct and verify the Vec<(Option<String>, Option<String>)> rmp-serde path of node #115.

The body 0x2274a90 is a `serialize_newtype_struct(out, ser, name, name_len, &Vec<T>)` monomorph whose elements are
0x30-byte pairs of `Option<String>`. It rejects the reserved name `_ExtStruct`, then either writes the array header
first and serializes every element on the outer serializer (element body 0x2274810), or, when the length does not
fit in u32, allocates a 0x80-byte buffer, serializes each element into a counted compound (element body 0x226ca20)
and lets Compound::end 0x227e2e0 write the counted header and copy the buffer. A pair is a two-element array: the
header 0x92, then per field the nil byte 0xc0 or a MessagePack str (header, length bytes, payload).

The reconstruction is `model`. A concrete x86-64 evaluator runs the real bytes of all three bodies and of the
array-header writer 0x25e7940, both str writers 0x25e8750/0x25e8bf0, both tuple ends 0x22997f0/0x22999e0,
Compound::end 0x227e2e0 and the RawVec reserve 0x231e050 on generated cases; only finish_grow, memcpy, malloc and
sdallocx are contract stubs. It compares the written bytes, the Vec<u8> capacity, the result record and the ordered
event list (hdr/str/element calls with compound state, growth steps, buffer allocation and release). The binary is
never executed.
"""
import itertools
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
EXT_NAME = b"_ExtStruct"          # rmp-serde's reserved newtype name for MessagePack ext values
EXT_TEXT = b"expected tuple"      # static error text every body returns for that name
ERR_TAG = 0x8000000000000000      # result word 0 for "error carried in words 1..2"
EXT_TAG = ERR_TAG | 2             # result word 0 for a static-str error
OK_TRIPLE = ERR_TAG | 4           # result word 0 for Ok(())
DIRECT_MARK = ERR_TAG             # compound word 0 when the array header was written up front (no buffer)
RESERVE = 0x231e050               # RawVec reserve(vec, len, additional, 1, 1): contract stub
GROW = 0x231dc90                  # finish_grow: cases leave enough room, so reaching it is a tool error
UNWIND = 0x63f0a50                # _Unwind_Resume (landing pads only)
MALLOC_GOT = 0x64df480
FREE_GOT = 0x64df4a0              # sdallocx(ptr, size, flags)
ALLOC_ERROR_GOT = 0x64df498       # handle_alloc_error(align, size), never returns
COUNT_PANIC_GOT = 0x64df520       # panic(Location) on a u32 element-count overflow, never returns
MEMCPY_GOT = 0x64df508
BUF_CAP = 0x80                    # initial capacity of the buffered-compound Vec<u8>
CFG_MASK = 0xff0101               # bits of the serializer config kept in the compound
SER_AT = 0x7100_0000_0000
VEC_AT = 0x7180_0000_0000
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x30000
OUT_AT = 0x7500_0000_0000
ARG_AT = 0x7580_0000_0000         # the Vec<T> argument record {cap, ptr, len}
NAME_AT = 0x75c0_0000_0000
ELEM_AT = 0x7600_0000_0000        # element base pointer (never dereferenced by the bodies)
HEAP_AT = 0x7800_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
FAULT = (0x0bad_0000_0000_0007, 0x0bad_0000_0000_0011)

# ---------------------------------------------------------------- target constants
VEC_BODY = 0x2274a90                # newtype(Vec<(Option<String>, Option<String>)>) serializer, 0x30-byte elements
PAIR_B = 0x2274810                  # element serializer for the outer serializer (layout b)
PAIR_A = 0x226ca20                  # element serializer for the buffered compound (layout a)
HDR_B = 0x25e7940                   # write_array_len for layout b
STR_B = 0x25e8750                   # write_str for layout b
STR_A = 0x25e8bf0                   # write_str for layout a
TEND_B = 0x22997f0                  # tuple/array Compound::end of the pair (layout b)
TEND_A = 0x22999e0                  # same for layout a
END_B = 0x227e2e0                   # buffered Compound::end for layout b
STRIDE = 0x30
ELEM_NAME_AT = 0x5f178d              # static name every element call passes (length 0x16)
ELEM_NAME_LEN = 0x16
NONE_BYTE = 0xc0
TUPLE_HDR = 0x92
ALLOC_ERR_REC = 0x2600000003        # word 2 of the push-grow failure record
GROW_AT = 0x7300_0000_0000
GROW_SLOT = 0x4_0000
GROW_SLOTS = 12
STR_AT = 0x7700_0000_0000
STR_SIZE = 0x80000
HEAP_SIZE = 0x80
BUF_SIZE = 0x20000
FALLIBLE = {HDR_B: "hdr", STR_B: "str", STR_A: "str", PAIR_B: "pair", PAIR_A: "pair"}
ROLES = {VEC_BODY: "vec", PAIR_B: "pair-b", PAIR_A: "pair-a"}
FNS = (VEC_BODY, PAIR_B, PAIR_A)
REAL_CALLEES = (HDR_B, STR_B, STR_A, TEND_B, TEND_A, END_B, RESERVE)


def extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in list(ROLES) + list(REAL_CALLEES):
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext


# ---------------------------------------------------------------- reconstruction
def mp_str_head(n):
    if n < 32:
        return bytes([0xa0 | n])
    if n < 0x100:
        return bytes([0xd9, n])
    if n < 0x10000:
        return b"\xda" + n.to_bytes(2, "big")
    return b"\xdb" + (n & 0xffffffff).to_bytes(4, "big")


def mp_array(n, mut=frozenset()):
    n &= 0xffffffff
    if n < (17 if "arr-fix17" in mut else 16):
        return bytes([0x90 | (n & 0xf)])
    if n < 0x10000:
        return b"\xdc" + n.to_bytes(2, "big")
    return b"\xdd" + n.to_bytes(4, "big")


def config_word(cfg, mut=frozenset()):
    lo = int.from_bytes(cfg[0:2], "little")
    mid = int.from_bytes(cfg[2:4], "little") | cfg[4] << 16
    return lo | (mid & (0xffffff if "cfg-nomask" in mut else CFG_MASK)) << 16


def buffered(n, mut=frozenset()):
    return (n >> 31 if "split-31" in mut else n >> 32) != 0


def iterations(n):
    """Elements a fault-free walk serializes: the loop counts the byte span n * 0x30 (mod 2^64) down by 0x30."""
    total = (n * STRIDE) & M64
    return None if total % STRIDE else total // STRIDE


class Vec:
    """A Vec<u8> with the amortized growth the push and reserve paths use: new cap = max(8, 2 * cap, len + need)."""

    def __init__(self, cap, data, events, mut):
        self.cap, self.data, self.ev, self.mut = cap, bytearray(data), events, mut

    def push(self, bs):
        need = len(bs)
        if self.cap - len(self.data) < need:
            new = max(8, 2 * self.cap, len(self.data) + need)
            if "grow-linear" in self.mut:
                new = max(8, len(self.data) + need)
            self.ev.append(("grow", self.cap, new))
            self.cap = new
        self.data += bs


class Ctx:
    def __init__(self, fault, errw, mut, msg):
        self.fault, self.errw, self.mut, self.msg, self.k, self.ev = fault, errw, mut, msg, 0, []

    def fallible(self):
        hit = self.fault == self.k
        self.k += 1
        return hit


def fail_rec(w0=ERR_TAG):
    return (w0, FAULT[0], FAULT[1])


def m_str(ctx, V, s):
    """write_str: marker byte, length bytes, payload."""
    ctx.ev.append(("str", len(s)))
    if ctx.fallible():
        return fail_rec()
    head = mp_str_head(len(s))
    V.push(head[:1])
    if len(head) > 1:
        V.push(head[1:])
    if s:
        V.push(s)
    return None


def m_pair(ctx, V, layout, fields, name, grow_fails=False):
    """(Option<String>, Option<String>) as a two-element MessagePack array. Returns None for Ok or the failing
    record. Layout b opens the array with write_array_len(2) (a recorded, fallible call); layout a pushes 0x92."""
    mut = ctx.mut
    if (name[:10] if "ext-prefix" in mut else name) == EXT_NAME:
        return (EXT_TAG, ctx.msg[0], ctx.msg[1] + (1 if "msg-len" in mut else 0))
    if layout == "b":
        ctx.ev.append(("hdr", 2))
        if ctx.fallible():
            return fail_rec()
        V.push(bytes([TUPLE_HDR]))
    else:
        V.push(bytes([TUPLE_HDR]))
    for f in fields:
        if f is None:
            V.push(bytes([NONE_BYTE if "none-byte" not in mut else 0xc1]))
        else:
            r = m_str(ctx, V, f)
            if r is not None:
                return r
    return None


def m_vec(c, ctx, outer):
    """The Vec body: direct array when the length fits in u32, otherwise a counted compound with a 0x80 buffer."""
    mut = ctx.mut
    name, n = c["name"], c["n"]
    if (name[:10] if "ext-prefix" in mut else name) == EXT_NAME:
        return (EXT_TAG if "ext-tag" not in mut else ERR_TAG, c["vmsg"][0], c["vmsg"][1])
    elems = c["elems"]
    count = iterations(n)
    if not buffered(n, mut):
        ctx.ev.append(("hdr", n & 0xffffffff))
        if ctx.fallible():
            return fail_rec()
        outer.push(mp_array(n, mut))
        for i in range(count):
            ctx.ev.append(("pair-b", i * STRIDE))
            if ctx.fallible():
                return (c["errw"], FAULT[0], FAULT[1])
            r = m_pair(ctx, outer, "b", elems[i], c["ename"])
            if r is not None:
                return r
        return None
    ctx.ev.append(("malloc", HEAP_SIZE))
    if c["oom"]:
        return "alloc-error"
    comp = Vec(HEAP_SIZE, b"", ctx.ev, mut)
    cfg = config_word(c["cfg"], mut)
    done = 0
    for i in range(count):
        ctx.ev.append(("pair-a", i * STRIDE, done, len(comp.data), cfg))
        if ctx.fallible():
            ctx.ev.append(("free", comp.cap))
            return (c["errw"], FAULT[0], FAULT[1])
        r = m_pair(ctx, comp, "a", elems[i], c["ename"])
        if r is not None:
            ctx.ev.append(("free", comp.cap))
            return r
        done += 1
    ctx.ev.append(("hdr", done + (1 if "count-plus1" in mut else 0)))
    if ctx.fallible():
        ctx.ev.append(("free", comp.cap))
        return fail_rec()
    outer.push(mp_array(done + (1 if "count-plus1" in mut else 0), mut))
    if "end-no-copy" not in mut:
        outer.push(bytes(comp.data))
    ctx.ev.append(("free", comp.cap))
    return None


def model(c, mut=frozenset()):
    """Predicted (appended bytes, final cap, result words or None for Ok, event list, boundary)."""
    ctx = Ctx(c["fault"], c["errw"], mut, c["msg"])
    V = Vec(c["room"] + len(c["prefix"]), c["prefix"], ctx.ev, mut)
    boundary = None
    if c["role"] == "vec":
        r = m_vec(c, ctx, V)
    else:
        r = m_pair(ctx, V, "b" if c["role"] == "pair-b" else "a", c["fields"], c["name"])
    if r == "alloc-error":
        boundary, r = ("alloc-error", 1, HEAP_SIZE), None
    return {"out": bytes(V.data), "cap": V.cap, "result": r, "events": ctx.ev, "boundary": boundary}


# ---------------------------------------------------------------- evaluation
class CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.boundary = (self.noreturn[target], self.regs[7], self.regs[6])
            raise Boundary("noreturn", self.regs)
        if call and target in FALLIBLE:
            kind = FALLIBLE[target]
            rdi = self.regs[7]
            if target == PAIR_B:
                self.events.append(("pair-b", (self.regs[8] - ELEM_AT) & M64))
            elif target == PAIR_A:
                ser = self.regs[6]
                self.events.append(("pair-a", (self.regs[8] - ELEM_AT) & M64, self.load(ser + 0x20, 4),
                                    self.load(ser + 0x10, 8), self.load(ser + 0x18, 8)))
            elif kind == "hdr":
                self.events.append(("hdr", self.regs[2] & 0xffffffff))
            else:
                self.events.append(("str", self.regs[2]))
            hit = self.case["fault"] == self.k
            self.k += 1
            if hit:
                if kind == "str":
                    self.regs[0], self.regs[2] = FAULT
                else:
                    w0 = self.case["errw"] if kind == "pair" else FAULT[0]
                    w1, w2 = (FAULT[0], FAULT[1]) if kind == "pair" else (FAULT[1], 0)
                    if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                        fail("callee output slot is not on the stack")
                    self.store(rdi, 8, w0)
                    self.store(rdi + 8, 8, w1)
                    if kind == "pair":
                        self.store(rdi + 16, 8, w2)
                for r in (1, 2, 6, 7, 8, 9, 10, 11) if kind == "str" else (0, 1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = 0x0dead
                if kind == "str":
                    self.regs[2] = FAULT[1]
                    self.regs[0] = FAULT[0]
                return None
        return super().transfer(target, call, va)


def region_of(m, addr):
    for lo, hi, buf in m.regions:
        if lo <= addr < hi:
            return lo, buf
    fail(f"no region at {addr:#x}")


def install(m, image, c):
    m.events, m.k, m.boundary, m.grows, m.heap = [], 0, None, 0, []

    def grow(m):
        out, old, optr, new = m.regs[7], m.regs[6], m.regs[2], m.regs[1]
        if m.regs[8] != 1 or m.regs[9] != 1:
            fail("finish_grow called with an unexpected layout argument")
        if new > GROW_SLOT or m.grows >= GROW_SLOTS:
            fail("grow request exceeds the stub arena")
        lo, buf = region_of(m, optr)
        nptr = GROW_AT + m.grows * GROW_SLOT
        _, nbuf = region_of(m, nptr)
        nbuf[:old] = buf[optr - lo:optr - lo + old]
        m.grows += 1
        m.events.append(("grow", old, new))
        m.store(out, 8, 0)
        m.store(out + 8, 8, nptr)
        m.regs[0] = 0

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        dlo, dbuf = region_of(m, dst)
        slo, sbuf = region_of(m, src)
        dbuf[dst - dlo:dst - dlo + n] = sbuf[src - slo:src - slo + n]
        m.regs[0] = dst

    def malloc(m):
        m.events.append(("malloc", m.regs[7]))
        m.regs[0] = 0 if c["oom"] else HEAP_AT

    def free(m):
        if m.regs[2] & 0xffffffff:
            fail("free with flags")
        region_of(m, m.regs[7])
        m.events.append(("free", m.regs[6]))

    m.stubs[GROW] = grow
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.stubs[image.word(MALLOC_GOT)] = malloc
    m.stubs[image.word(FREE_GOT)] = free
    m.noreturn = {image.word(ALLOC_ERROR_GOT): "alloc-error"}


def pack_fields(fields, at):
    """Option<String> pair -> 0x30 bytes plus string bytes appended to the string pool."""
    rec, pool = bytearray(0x30), bytearray()
    for i, f in enumerate(fields):
        if f is None:
            put(rec, 0x18 * i, 8, ERR_TAG)
            put(rec, 0x18 * i + 8, 8, 0x1111_0000 + i)
        else:
            put(rec, 0x18 * i, 8, len(f) + (i + 1) * 5)
            put(rec, 0x18 * i + 8, 8, at + len(pool))
            pool += f
        put(rec, 0x18 * i + 0x10, 8, len(f) if f is not None else 0x2222)
    return bytes(rec), bytes(pool)


def run_case(m, c):
    m.reset()
    m.case = c
    install(m, m.image, c)
    role = c["role"]
    va = {"vec": VEC_BODY, "pair-b": PAIR_B, "pair-a": PAIR_A}[role]
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    if role == "pair-a":
        sreg = m.add_region(SER_AT, 0x40, bytes(vec) + c["cfg"] + c["ser_tail"][:3])
        vbase = SER_AT
    else:
        sreg = m.add_region(SER_AT, 0x10, VEC_AT.to_bytes(8, "little") + c["cfg"] + c["ser_tail"][:3])
        m.add_region(VEC_AT, 0x18, bytes(vec))
        vbase = VEC_AT
    m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    m.add_region(HEAP_AT, HEAP_SIZE)
    for k in range(GROW_SLOTS):
        m.add_region(GROW_AT + k * GROW_SLOT, GROW_SLOT)
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    recs, pool = [], bytearray()
    elems = c["elems"] if role == "vec" else [c["fields"]]
    for f in elems:
        rec, p = pack_fields(f, STR_AT + len(pool))
        recs.append(rec)
        pool += p
    ereg = m.add_region(ELEM_AT, max(0x30, 0x30 * len(recs)), b"".join(recs))
    sp = m.add_region(STR_AT, STR_SIZE, bytes(pool))
    nm = c["name"]
    name = m.add_region(NAME_AT, 0x40, nm + bytes(0x40 - len(nm)))
    if role == "vec":
        arg = bytearray(0x18)
        put(arg, 0, 8, c["vcap"])
        put(arg, 8, 8, ELEM_AT)
        put(arg, 0x10, 8, c["n"])
        areg = m.add_region(ARG_AT, 0x18, bytes(arg))
        elem_reg = ARG_AT
    else:
        elem_reg, areg, arg = ELEM_AT, None, None
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, SER_AT, NAME_AT, len(nm), elem_reg
    snap = (bytes(ereg), bytes(sp), bytes(name))
    try:
        m.run(va, limit=c.get("limit", 600000))
    except Boundary:
        pass
    ln = m.load(vbase + 0x10, 8)
    ptr = m.load(vbase + 8, 8)
    lo, rb = region_of(m, ptr)
    return {"boundary": m.boundary, "out": bytes(rb[ptr - lo:ptr - lo + ln]) if ln <= GROW_SLOT else None,
            "cap": m.load(vbase, 8), "ser_rest": bytes(sreg[0x18:] if role == "pair-a" else sreg[8:]),
            "result": bytes(out), "events": list(m.events),
            "inputs_same": snap == (bytes(ereg), bytes(sp), bytes(name)) and (areg is None or bytes(areg) == bytes(arg)),
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100}


def compare(c, want, got):
    if want["boundary"] is not None or got["boundary"] is not None:
        return None if got["boundary"] == want["boundary"] and got["events"] == want["events"] else "boundary"
    if not got["regs_ok"] or not got["inputs_same"] or got["out"] is None:
        return "machine"
    tail = c["cfg"] + c["ser_tail"][:3]
    if got["ser_rest"] != (tail if c["role"] != "pair-a" else tail + c["ser_tail"][3:3] + bytes(0x40 - 0x18 - len(tail))):
        return "serializer"
    if got["events"] != want["events"]:
        return "events"
    if got["out"] != want["out"]:
        return "bytes"
    if got["cap"] != want["cap"]:
        return "capacity"
    res = want["result"]
    expect = (OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10) if res is None else \
        b"".join(x.to_bytes(8, "little") for x in res)
    return None if got["result"] == expect else "result"


# ---------------------------------------------------------------- cases
STR_LENS = (0, 1, 2, 5, 17, 31, 32, 33, 64, 100, 255, 256, 257, 300)
ERRWS = (ERR_TAG, 0, 1, ERR_TAG | 3, ERR_TAG | 5, M64)
CFGS = (b"\x00\x00\x00\x00\x00", b"\x01\x01\x01\x01\x01", b"\xff\xff\xff\xff\xff", b"\x00\x01\x00\x01\x02",
        b"\x02\x00\x02\x00\x00", b"\x5a\xa5\x5a\xa5\x5a")
PER_ROLE = {"vec": 6000, "pair-b": 2500, "pair-a": 2500}


def names(stream, k):
    sel = k % 8
    if sel == 0:
        return EXT_NAME
    if sel == 1:
        b = bytearray(EXT_NAME)
        b[(k // 8) % 10] ^= 1 << ((k // 80) % 8)
        return bytes(b)
    if sel == 2:
        return EXT_NAME[:9] if (k // 8) % 2 else EXT_NAME + stream.take(1)
    return stream.take(stream.below(24))


def gen_field(stream):
    if stream.below(5) == 0:
        return None
    ln = STR_LENS[stream.below(len(STR_LENS))]
    return stream.take(ln) if ln <= 64 else bytes([97 + stream.below(26)]) * ln


def wrap_len(m, j):
    """n >= 2^32 whose byte span n * 0x30 wraps to exactly m elements: n = m + j * 2^60."""
    return m + (1 + j % 15) * (1 << 60)


def make_case(stream, role, k):
    c = {"role": role, "k": k, "prefix": stream.take(stream.below(6)), "ser_tail": stream.take(8),
         "cfg": CFGS[(k // 3) % len(CFGS)] if k % 5 else stream.take(5), "fault": None, "oom": False,
         "name": names(stream, k), "errw": ERRWS[(k // 11) % len(ERRWS)], "vcap": int.from_bytes(stream.take(8), "little"),
         "ename": b"", "msg": (0, 0), "vmsg": (0, 0)}
    c["ser_tail"] = c["ser_tail"][:3] + b""
    if role == "vec":
        sel = (k // 8) % 10
        if sel < 5:
            c["n"] = (0, 1, 2, 3, 4, 5, 7, 9, 12, 16)[(k // 2) % 10]
        elif sel < 7:
            c["n"] = wrap_len(1 + stream.below(6), k)
        elif sel == 7:  # a length of 2^32 or 2^32+1 elements: only an early element failure ends the walk
            c["n"] = (0x1_0000_0000, 0x1_0000_0001, 0x8000_0000, 0x8000_0001)[(k // 2) % 4]
            c["trunc"] = True
        elif sel == 8:
            c["n"] = wrap_len(1 + stream.below(3), k)
            c["oom"] = (k // 80) % 2 == 0
        else:
            c["n"] = stream.below(14)
        cnt = iterations(c["n"])
        if cnt is None:
            c["n"] = wrap_len(1 + stream.below(3), k)
            cnt = iterations(c["n"])
        c["elems"] = [(gen_field(stream), gen_field(stream)) for _ in range(cnt if cnt < 1000 else 4)]
        total = 12 + sum(len(f or b"") + 6 for e in c["elems"] for f in e) + 6 * (cnt if cnt < 1000 else 4) + 8
    else:
        c["fields"] = (gen_field(stream), gen_field(stream))
        total = 12 + sum(len(f or b"") + 6 for f in c["fields"])
    c["room"] = (8, 9, 16, 40, 0x100, 0x1000)[(k // 7) % 6]
    if c["room"] < total and (k // 5) % 3 != 1:  # keep some tight cases that force the Vec<u8> to grow
        c["room"] = total + c["room"]
    return c


def attach(c, facts):
    c["ename"] = facts["elem_name"]
    c["msg"] = facts["pair_msg"]
    c["vmsg"] = facts["vec_msg"]
    if c["role"] == "pair-a":
        c["msg"] = facts["pair_a_msg"]
    return c


def count_fallible(c):
    return sum(1 for e in model(c)["events"] if e[0] in ("hdr", "str", "pair-b", "pair-a"))


def all_cases(facts, per_role=None):
    per = per_role or PER_ROLE
    for role in ("vec", "pair-b", "pair-a"):
        stream = Stream(f"rmp-pair-vec/{role}")
        for k in range(per[role]):
            c = attach(make_case(stream, role, k), facts)
            if c.get("trunc"):
                c["fault"] = stream.below(3)
            elif (k // 4) % 3 == 1:
                n = count_fallible(c)
                if n:
                    c["fault"] = stream.below(n)
            yield c


# ---------------------------------------------------------------- static facts
def facts_of(image, ext):
    """Constants and call pattern read from the bytes of the three bodies."""
    out = {}
    for va, key in ((PAIR_B, "pair_msg"), (PAIR_A, "pair_a_msg"), (VEC_BODY, "vec_msg")):
        insns = sweep(image, va, ext[va])
        msg = None
        for i, (v, f) in enumerate(insns):
            if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
                nxt = [g for _, g in insns[i + 1:i + 4] if g["op"] == 0xc7 and g["rm"][0] == "m"]
                if nxt and nxt[0]["imm"] in (len(EXT_TEXT), 0x15):
                    msg = ((v + f["len"] + f["rm"][4]) & M64, nxt[0]["imm"])
        if msg is None:
            fail(f"{va:#x}: no static message record")
        if va == VEC_BODY and image.read(msg[0], msg[1]) != EXT_TEXT:
            fail("vec body ext-arm message is not the expected text")
        out[key] = msg
        calls = [f["target"] for _, f in insns if f["op"] == 0xe8 and f["target"] != UNWIND]
        out[key + "_calls"] = calls
    if out["pair_msg_calls"] != [HDR_B, STR_B, STR_B, TEND_B] and out["pair_msg_calls"][:1] != [HDR_B]:
        fail("pair-b call pattern changed")
    if out["vec_msg_calls"] != [HDR_B, PAIR_B, PAIR_B, END_B, PAIR_B, PAIR_A] and \
            out["vec_msg_calls"][:3] != [HDR_B, PAIR_B, PAIR_B]:
        fail("vec body call pattern changed")
    leas = {(v + f["len"] + f["rm"][4]) & M64 for v, f in sweep(image, VEC_BODY, ext[VEC_BODY])
            if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip"}
    if ELEM_NAME_AT not in leas:
        fail("vec body does not pass the element name record")
    out["elem_name"] = image.read(ELEM_NAME_AT, ELEM_NAME_LEN)
    if out["elem_name"] == EXT_NAME:
        fail("element name is the reserved name")
    out["pair_b_calls"], out["pair_a_calls"], out["vec_calls"] = out["pair_msg_calls"], out["pair_a_msg_calls"], \
        out["vec_msg_calls"]
    return out


def machine(image, ext):
    m = CaseMachine(image)
    m.extents = ext
    return m


def evaluate(image, ext, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = CaseMachine(image, override)
    m.extents = ext
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except (ToolError, Boundary, KeyError):
            if override is None:
                raise
            got = None
        why = compare(c, model(c, mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad


# ---------------------------------------------------------------- controls
MODEL_MUTANTS = ("arr-fix17", "ext-prefix", "ext-tag", "msg-len", "cfg-nomask", "split-31", "count-plus1",
                 "end-no-copy", "grow-linear", "none-byte")


def imm_sites(image, ext, va, limit=16):
    """Immediates of 8/32-bit forms inside one body; one low bit of each is flipped."""
    sites = []
    for v, f in sweep(image, va, ext[va]):
        imm = f.get("imm")
        if imm is None:
            continue
        if f["op"] in (0x83, 0x80, 0xc6, 0xc1):
            sites.append((va, f"imm8@{v:#x}", v + f["len"] - 1, 0x01))
        elif f["op"] in (0xc7, 0x81) and f.get("size") != 64 or f["op"] in range(0xb8, 0xc0) and f.get("size") != 64:
            sites.append((va, f"imm32@{v:#x}", v + f["len"] - 4, 0x01))
    return sites[:limit]


def controls(image, ext, results, facts):
    out = []
    pairs = [(c, got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(pairs):
            if compare(c, model(c, frozenset(mut)), got):
                return i
        return None

    for name in MODEL_MUTANTS:
        out.append(("model", name, first_hit({name})))
    equivalent = 0
    for va in FNS:
        role = ROLES[va]
        sample = [c for c, _, _ in results if c["role"] == role][:300]
        for fva, label, at, bit in imm_sites(image, ext, va):
            _, bad = evaluate(image, ext, sample, override={at: image.code(at, 1)[0] ^ bit}, stop_on_first=True)
            if bad:
                out.append(("bytes", f"{role}-{label}", sample.index(bad[0][0])))
            else:
                equivalent += 1
    for label, fn in (("binary-digest", lambda: Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))),
                      ("body-not-fde-start", lambda: extents_check(image, VEC_BODY + 1)),
                      ("wrong-element-name", lambda: facts_with_name(image, ext, ELEM_NAME_AT + 1)),
                      ("out-of-range-read", lambda: image.read(0x10, 4))):
        try:
            fn()
            out.append(("range", label, None))
        except ToolError:
            out.append(("range", label, 0))
    return out, equivalent


def extents_check(image, va):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    if va not in {f["start"] for f in ordered}:
        fail(f"no FDE starts at {va:#x}")


def facts_with_name(image, ext, at):
    global ELEM_NAME_AT
    saved = ELEM_NAME_AT
    ELEM_NAME_AT = at
    try:
        facts_of(image, ext)
    finally:
        ELEM_NAME_AT = saved


def generate(out, per=None):
    image = Image(BINARY.read_bytes())
    ext = extents(image)
    facts = facts_of(image, ext)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    m = CaseMachine(image)
    m.extents = ext
    results, kinds, digest = [], {}, hashlib.sha256()
    rows = ["role\tcase\tname_hex\tlength\tfault_event\toom\troom\tfields\tout_len\tout_sha256\tresult\tevents"]
    sample_keep, ncases = [], 0
    for c in all_cases(facts, per):
        got = run_case(m, c)
        want = model(c)
        why = compare(c, want, got)
        if why:
            fail(f"mismatch role {c['role']} case {c['k']} ({why})")
        digest.update(got["out"] + got["result"])
        kind = "alloc_error" if want["boundary"] else ("ok" if want["result"] is None else "error")
        kinds[(c["role"], kind)] = kinds.get((c["role"], kind), 0) + 1
        ncases += 1
        if c["k"] < 300:
            sample_keep.append((c, got))
        if c["k"] % 2 == 0:
            ev = got["events"]
            short = ",".join(e[0][0] + e[0][-1] for e in ev[:10]) + ("+" + str(len(ev) - 10) if len(ev) > 10 else "")
            nf = sum(1 for f in (c.get("fields") or ()) for _ in [0]) if c["role"] != "vec" else len(c["elems"])
            rows.append("\t".join([c["role"], str(c["k"]), hexs(c["name"]), f"{c['n']:#x}" if c["role"] == "vec" else "-",
                                   "-" if c["fault"] is None else str(c["fault"]), "1" if c["oom"] else "0",
                                   str(c["room"]), str(nf), str(len(got["out"])),
                                   hashlib.sha256(got["out"]).hexdigest()[:16], got["result"].hex()[:16], short or "-"]))
    (out / "cases-sample.tsv").write_text("\n".join(rows) + "\n")
    # controls re-run a bounded prefix of every role against the stored results
    ctl_results = [(c, got, None) for c, got in sample_keep if c["k"] < 300]
    ctrl, equivalent = controls(image, ext, ctl_results, facts)
    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "controls.tsv").write_text("\n".join(lines) + "\n")
    detected = sum(1 for _, _, h in ctrl if h is not None)
    summary = {"binary_sha256": SHA256, "cases": ncases, "mismatches": 0, "outputs_sha256": digest.hexdigest(),
               "case_kinds": {f"{r}/{k}": v for (r, k), v in sorted(kinds.items())},
               "controls": len(ctrl), "controls_detected": detected, "equivalent_byte_flips_skipped": equivalent,
               "real_functions": [f"{v:#x}" for v in list(ROLES) + list(REAL_CALLEES)],
               "contract_stubs": ["finish_grow 0x231dc90", "memcpy", "malloc", "sdallocx"]}
    if detected != len(ctrl):
        fail(f"negative controls not detected: {[n for _, n, h in ctrl if h is None]}")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": ncases, "negative_controls": len(ctrl),
                                                  "negative_detected": detected}, indent=2, sort_keys=True) + "\n")
    return summary


def hexs(b):
    return b.hex() if b else "-"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
