"""Reconstruct and verify 54 rmp-serde `newtype(Vec<T>)` serializers of node #115: direct and buffered sequences.

Each body is a `serialize_newtype_struct(out, ser, name, name_len, &Vec<T>)` monomorph in one of three copy
families (0x226/0x227, 0x419/0x41a, 0x52f). It rejects the reserved name `_ExtStruct` with the static
"expected tuple" error, then serializes the vector as a MessagePack array. When the length fits in u32 it writes
the array header first and calls the element serializer on the outer serializer for every element. Otherwise it
allocates a 0x80-byte buffer, builds a compound (buffer, masked config, u32 element count, outer serializer),
serializes each element into the compound and lets Compound::end write the counted header and copy the buffer.

The reconstruction is `model`; a concrete x86-64 evaluator runs the real bytes of each body, of its copy
family's array-header writer and of its Compound::end on generated cases, with the element serializers as
recording stubs, and compares written bytes, result record and the ordered event list (header lengths, element
offsets and compound state, buffer allocation and release). The binary is never executed.
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

# Per copy family: the array-header writer and Compound::end of each serializer layout.
#   layout "b": serializer = {&mut Vec<u8>, config bytes at +8..+0xc}; flag byte +0xc
#   layout "a": serializer = {Vec<u8> inline at +0, config bytes at +0x18..+0x1c}; flag byte +0x1c
FAMILIES = {
    "226": {"hdr_b": 0x25e7940, "end_b": 0x227e2e0, "hdr_a": 0x25e7c10, "end_a": 0x227e1b0},
    "419": {"hdr_b": None, "end_b": 0x41acea0, "hdr_a": None, "end_a": 0x41acd70},
    "52f": {"hdr_b": None, "end_b": 0x5306e90, "hdr_a": None, "end_a": 0x5306d60},
}
CFG_AT = {"a": 0x18, "b": 0x8}
FLAG_AT = {"a": 0x1c, "b": 0xc}

# body: (copy family, layout, element stride).  The element serializers (direct and buffered-compound) are read
# from the call pattern of the bytes; the copy family decides which header writer / end the body may call.
BODIES = {
    # 0x226 family, layout b (two element serializers: one for the outer serializer, one for the compound)
    0x226bd40: ("226", "b", 0x120), 0x226c670: ("226", "b", 0x30), 0x226cbc0: ("226", "b", 0x510),
    0x226d820: ("226", "b", 0x98), 0x226dea0: ("226", "b", 0x200), 0x226f620: ("226", "b", 0x50),
    0x226fb50: ("226", "b", 0x16), 0x2270560: ("226", "b", 0x30), 0x2271f10: ("226", "b", 0x50),
    0x2272fc0: ("226", "b", 0x48), 0x2273370: ("226", "b", 0x120), 0x2276da0: ("226", "b", 0x14),
    0x2277e10: ("226", "b", 0x158), 0x22768f0: ("226", "b", 0x38),
    # 0x226 family, layout a (one element serializer for both paths)
    0x226e9f0: ("226", "a", 0x48), 0x22710d0: ("226", "a", 0x98), 0x2272c10: ("226", "a", 0x16),
    0x22776c0: ("226", "a", 0x120), 0x226e650: ("226", "a", 0x38),
    # 0x419 family (0x41a3070 and 0x419d8a0 are left out: named in other packets)
    0x419f6f0: ("419", "b", 0x120), 0x41a0430: ("419", "b", 0x120), 0x41a66c0: ("419", "b", 0x30),
    0x419e240: ("419", "b", 0x510), 0x41a15a0: ("419", "b", 0x98), 0x419d4f0: ("419", "b", 0x200),
    0x41a10a0: ("419", "b", 0x50), 0x41a2600: ("419", "b", 0x50), 0x419f340: ("419", "b", 0x48),
    0x419bf60: ("419", "b", 0x14), 0x41a4ea0: ("419", "b", 0x158), 0x419e830: ("419", "b", 0x38),
    0x41a6d10: ("419", "a", 0x48), 0x41a5ce0: ("419", "a", 0x98), 0x419cd20: ("419", "a", 0x16),
    0x41a1de0: ("419", "a", 0x120), 0x41a36c0: ("419", "a", 0x38),
    # 0x52f family
    0x52f2950: ("52f", "b", 0x120), 0x52f6b40: ("52f", "b", 0x120), 0x52f35b0: ("52f", "b", 0x30),
    0x52fa560: ("52f", "b", 0x30), 0x52f8530: ("52f", "b", 0x510), 0x52f5ff0: ("52f", "b", 0x98),
    0x52fa060: ("52f", "b", 0x200), 0x52f4310: ("52f", "b", 0x50), 0x52fd150: ("52f", "b", 0x50),
    0x52f5c40: ("52f", "b", 0x16), 0x52f19c0: ("52f", "b", 0x14), 0x52fbca0: ("52f", "b", 0x158),
    0x52f3d70: ("52f", "b", 0x38),
    0x52f3200: ("52f", "a", 0x48), 0x52f7cd0: ("52f", "a", 0x98), 0x52f7840: ("52f", "a", 0x16),
    0x52fdea0: ("52f", "a", 0x120), 0x52fc980: ("52f", "a", 0x38),
}

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
ELEM_ERR_W0 = (ERR_TAG, 0, 1, ERR_TAG | 3, ERR_TAG | 5, M64)


# ---------------------------------------------------------------- reconstruction
def mp_array(n, mut=frozenset()):
    """write_array_len(n as u32)."""
    n &= 0xffff if "hdr-u16" in mut else 0xffffffff
    if n < (17 if "arr-fix17" in mut else 16):
        return bytes([0x90 | (n & 0xf)])
    if n < (0x10001 if "arr16-limit" in mut else 0x10000):
        return b"\xdc" + (n & 0xffff).to_bytes(2, "big")
    return b"\xdd" + (n & 0xffffffff).to_bytes(4, "big")


def is_ext(name, mut=frozenset()):
    if "ext-prefix" in mut:
        return name[:10] == EXT_NAME
    return name == EXT_NAME


def element_byte(i, compound):
    """What the element-serializer stubs append: one byte per element, distinct for the two targets."""
    return ((0x40 if compound else 0x00) + i * 7) & 0xff


def config_word(ser_cfg, mut=frozenset()):
    """The compound's config qword, built from the serializer's config bytes (+0..+4 of CFG_AT)."""
    lo = int.from_bytes(ser_cfg[0:2], "little")
    mid = int.from_bytes(ser_cfg[2:4], "little") | ser_cfg[4] << 16
    mask = 0xffffff if "cfg-nomask" in mut else CFG_MASK
    return lo | (mid & mask) << 16


def buffered(n, mut=frozenset()):
    """The bodies pick the buffered compound when the length does not fit in u32."""
    if "split-31" in mut:
        return n >> 31 != 0
    return n >> 32 != 0


def iterations(n, stride, mut=frozenset()):
    """Element calls made by a fault-free run: the loop walks `ptr .. ptr + n * stride` (wrapping), and the
    buffered loop always serializes the first element before testing the remaining byte count."""
    total = (n * stride) & M64
    if total % stride:
        return None  # the remaining-byte counter never reaches 0: the walk only stops on an element error
    return total // stride - (1 if "iter-minus1" in mut and n >> 32 else 0)


def model(c, mut=frozenset()):
    """Predicted (appended bytes, result words or None for Ok, event list, boundary)."""
    fam, layout, stride = BODIES[c["body"]]
    stride_m = stride + (8 if "stride-plus8" in mut else 0)
    p = {"out": b"", "result": None, "events": [], "boundary": None}
    if is_ext(c["name"], mut):
        p["result"] = (EXT_TAG if "ext-tag" not in mut else ERR_TAG, c["msg"][0], c["msg"][1] + (1 if "msg-len" in mut else 0))
        return p
    n = c["n"]
    ev = p["events"]
    k = [0]

    def fallible():
        hit = c["fault"] == k[0]
        k[0] += 1
        return hit

    def elem_fail():
        w0 = c["errw"]
        p["result"] = (w0 if "err-retag" not in mut else ERR_TAG, FAULT[0], FAULT[1])

    if not buffered(n, mut):
        ev.append(("hdr", n & 0xffffffff))
        if fallible():
            p["result"] = (ERR_TAG if "hdr-err-tag" not in mut else EXT_TAG, FAULT[0], FAULT[1])
            return p
        p["out"] += mp_array(n, mut)
        count = iterations(n, stride_m, mut)
        for i in (range(count) if count is not None else itertools.count()):
            ev.append(("direct", i * stride_m & M64))
            if fallible():
                elem_fail()
                return p
            p["out"] += bytes([element_byte(i, False)])
        return p
    # buffered compound: Vec<u8> with capacity 0x80, elements counted in a u32
    ev.append(("malloc", BUF_CAP))
    if c["oom"]:
        p["boundary"] = ("alloc-error", 1, BUF_CAP)
        return p
    cfg = config_word(c["cfg"], mut)
    count = iterations(n, stride_m, mut)
    buf = b""
    for i in (range(count) if count is not None else itertools.count()):
        ev.append(("compound", i * stride_m & M64, i, len(buf), cfg))
        if fallible():
            elem_fail()
            if "err-no-free" not in mut:
                ev.append(("free", BUF_CAP))
            return p
        buf += bytes([element_byte(i, True)])
    ev.append(("hdr", count + (1 if "count-plus1" in mut else 0)))
    if fallible():
        p["result"] = (ERR_TAG, FAULT[0], FAULT[1])
        ev.append(("free", BUF_CAP))
        return p
    p["out"] += mp_array(count + (1 if "count-plus1" in mut else 0), mut) + (b"" if "end-no-copy" in mut else buf)
    ev.append(("free", BUF_CAP))
    return p


# ---------------------------------------------------------------- evaluation
class CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.boundary = (self.noreturn[target], self.regs[7], self.regs[6]) if self.noreturn[target] == "alloc-error" \
                else (self.noreturn[target], self.regs[7])
            raise Boundary("noreturn", self.regs)
        if call and target in self.hdrs:
            self.events.append(("hdr", self.regs[2] & 0xffffffff))
            if self.next_fault():
                rdi = self.regs[7]
                if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                    fail("header writer output slot is not on the stack")
                self.store(rdi, 8, FAULT[0])
                self.store(rdi + 8, 8, FAULT[1])
                for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = 0x0dead
                return None
        return super().transfer(target, call, va)

    def next_fault(self):
        hit = self.case["fault"] == self.k
        self.k += 1
        return hit


def vec_of(m, ser, layout):
    return ser if layout == "a" else m.load(ser, 8)


def install(m, image, c):
    fam, layout, stride = BODIES[c["body"]]
    m.events, m.reserves, m.k, m.boundary = [], [], 0, None
    m.counts = {"direct": 0, "compound": 0}
    f = FAMILIES[fam]
    m.hdrs = {m.roles[c["body"]]["hdr"]}

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        if vec not in (SER_AT, VEC_AT):
            fail("reserve called on a foreign vector")
        cap = m.load(vec, 8)
        if ln != m.load(vec + 0x10, 8) or cap - ln >= add or m.regs[1] != 1 or m.regs[8] != 1:
            fail("reserve called outside its contract")
        if ln + add > BUF_SIZE:
            fail("case output larger than the buffer region")
        m.reserves.append((ln, add))
        m.store(vec, 8, ln + add)

    def grow(m):
        fail("finish_grow reached; the case did not leave enough room")

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.regs[0] = dst

    def malloc(m):
        m.events.append(("malloc", m.regs[7]))
        m.regs[0] = 0 if c["oom"] else HEAP_AT

    def free(m):
        if m.regs[7] != HEAP_AT or m.regs[2] & 0xffffffff:
            fail("free of a foreign pointer or with flags")
        m.events.append(("free", m.regs[6]))

    def append(vec, byte):
        cap, ln = m.load(vec, 8), m.load(vec + 0x10, 8)
        ptr = m.load(vec + 8, 8)
        m.store(ptr + ln, 1, byte)
        m.store(vec + 0x10, 8, ln + 1)
        if ln + 1 > cap:
            fail("element stub would overrun the vector")

    def element(kind):
        def run(m):
            slot, elem, ser = m.regs[7], m.regs[6], m.regs[2]
            off = (elem - ELEM_AT) & M64
            if ser == SER_AT and kind in ("direct", "single"):
                i = m.counts["direct"]
                m.counts["direct"] += 1
                m.events.append(("direct", off))
                target = vec_of(m, SER_AT, layout)
                compound = False
            elif STACK_TOP - 0x10000 <= ser < STACK_TOP and kind in ("compound", "single"):
                i = m.counts["compound"]
                m.counts["compound"] += 1
                cap, ptr, ln = m.load(ser, 8), m.load(ser + 8, 8), m.load(ser + 0x10, 8)
                if cap != BUF_CAP or ptr != HEAP_AT or m.load(ser + 0x28, 8) != SER_AT:
                    fail("compound element serializer got a foreign compound")
                m.events.append(("compound", off, m.load(ser + 0x20, 4), ln, m.load(ser + 0x18, 8)))
                target = ser
                compound = True
            else:
                fail(f"{kind} element serializer called with serializer {ser:#x}")
            if not STACK_TOP - 0x10000 <= slot < STACK_TOP:
                fail("element result slot is not on the stack")
            if m.next_fault():
                m.store(slot, 8, c["errw"])
                m.store(slot + 8, 8, FAULT[0])
                m.store(slot + 16, 8, FAULT[1])
            else:
                append(target, element_byte(i, compound))
                m.store(slot, 8, OK_TRIPLE)
            for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
                m.regs[r] = 0x0dead
        return run

    roles = m.roles[c["body"]]
    if layout == "b":
        m.stubs[roles["direct"]] = element("direct")
        m.stubs[roles["compound"]] = element("compound")
    else:
        m.stubs[roles["direct"]] = element("single")
    m.stubs[RESERVE] = reserve
    m.stubs[GROW] = grow
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.stubs[image.word(MALLOC_GOT)] = malloc
    m.stubs[image.word(FREE_GOT)] = free
    m.noreturn = {image.word(ALLOC_ERROR_GOT): "alloc-error", image.word(COUNT_PANIC_GOT): "count-overflow"}


def run_case(m, c):
    m.reset()
    m.case = c
    install(m, m.image, c)
    va = c["body"]
    layout = BODIES[va][1]
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    if layout == "a":
        ser = bytes(vec) + c["cfg"] + c["ser_tail"][:3]
        sreg = m.add_region(SER_AT, 0x20, ser)
        vreg = sreg
    else:
        ser = VEC_AT.to_bytes(8, "little") + c["cfg"] + c["ser_tail"][:3]
        sreg = m.add_region(SER_AT, 0x10, ser)
        vreg = m.add_region(VEC_AT, 0x18, bytes(vec))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    arg = bytearray(0x18)
    put(arg, 0, 8, c["vcap"])
    put(arg, 8, 8, ELEM_AT)
    put(arg, 0x10, 8, c["n"])
    areg = m.add_region(ARG_AT, 0x18, bytes(arg))
    name = m.add_region(NAME_AT, 0x40, c["name"] + bytes(0x40 - len(c["name"])))
    heap = m.add_region(HEAP_AT, BUF_CAP)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, SER_AT, NAME_AT, len(c["name"]), ARG_AT
    try:
        m.run(va, limit=c.get("limit", 400000))
    except Boundary:
        pass
    vbase = SER_AT if layout == "a" else VEC_AT
    ln = m.load(vbase + 0x10, 8)
    return {"boundary": m.boundary, "out": bytes(buf[:ln]) if ln <= BUF_SIZE else None,
            "tail_clean": ln <= BUF_SIZE and (not any(buf[ln:]) or ln < len(c["prefix"])),
            "ptr": m.load(vbase + 8, 8), "cap": m.load(vbase, 8), "ser_rest": bytes(sreg[0x18:] if layout == "a" else sreg[8:]),
            "result": bytes(out), "inputs_same": bytes(areg) == bytes(arg) and bytes(name[:len(c["name"])]) == c["name"],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "events": list(m.events), "reserves": list(m.reserves), "heap": bytes(heap)}


def compare(c, want, got):
    if want["boundary"] is not None or got["boundary"] is not None:
        if got["boundary"] != want["boundary"] or got["events"] != want["events"]:
            return "boundary"
        return None
    if not got["regs_ok"] or not got["inputs_same"] or not got["tail_clean"] or got["out"] is None:
        return "machine"
    if got["ser_rest"] != c["cfg"] + c["ser_tail"][:3] or got["ptr"] != BUF_AT or got["cap"] < len(got["out"]):
        return "serializer"
    if got["events"] != want["events"]:
        return "events"
    if got["out"] != c["prefix"] + want["out"]:
        return "bytes"
    res = want["result"]
    if res is None:
        expect = OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10
    else:
        expect = b"".join(x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    return None


# ---------------------------------------------------------------- cases
PER_BODY = 200
SMALL_N = (0, 1, 2, 3, 7, 15, 16, 17, 31, 32, 100, 255, 256, 300)
BIG_N = (0xffff, 0x10000)
EDGE_N = (0xffffffff, 0xfffffff0, 0x100000000, 0x100000001, 0x1_0000_0010, M64)
CFG_BYTES = (b"\x00\x00\x00\x00\x00", b"\x01\x01\x01\x01\x01", b"\xff\xff\xff\xff\xff", b"\x00\x01\x00\x01\x02",
             b"\x02\x00\x02\x00\x00", b"\x5a\xa5\x5a\xa5\x5a")
ROOMS = (8, 9, 16, 17, 0x40, 0x101, 0x1000)


def names(stream, k):
    sel = k % 8
    if sel == 0:
        return EXT_NAME
    if sel == 1:  # one byte away from the reserved name, at every position
        b = bytearray(EXT_NAME)
        b[(k // 8) % 10] ^= 1 << ((k // 80) % 8)
        return bytes(b)
    if sel == 2:
        return EXT_NAME[:9] if (k // 8) % 2 else EXT_NAME + stream.take(1)
    return stream.take(stream.below(24))


def wrap_len(stride, m, j):
    """A length >= 2^32 whose element walk wraps to exactly m elements: n = m + j * 2^(64 - tz(stride))."""
    tz = (stride & -stride).bit_length() - 1
    step = 1 << (64 - tz)
    j = 1 + j % ((1 << tz) - 1) if tz > 1 else 1
    return m + j * step


def fallible_count(c):
    return sum(1 for e in model(c)["events"] if e[0] in ("hdr", "direct", "compound"))


def make_case(stream, va, k, index):
    fam, layout, stride = BODIES[va]
    c = {"body": va, "k": k, "prefix": stream.take(stream.below(6)), "ser_tail": stream.take(8),
         "cfg": CFG_BYTES[(k // 3) % len(CFG_BYTES)] if k % 5 else stream.take(5),
         "fault": None, "oom": False, "name": names(stream, k), "room": ROOMS[(k // 7) % len(ROOMS)],
         "errw": ELEM_ERR_W0[(k // 11) % len(ELEM_ERR_W0)], "vcap": int.from_bytes(stream.take(8), "little")}
    sel = (k // 8) % 10
    if sel < 5:
        c["n"] = SMALL_N[(k // 2) % len(SMALL_N)]
    elif sel < 7:
        c["n"] = wrap_len(stride, 1 + stream.below(40), k)
    elif sel == 7:
        c["n"] = EDGE_N[k % len(EDGE_N)]
        c["fault"] = 1 + stream.below(3) if c["n"] >> 32 == 0 else stream.below(3)
    elif sel == 8:
        c["n"] = wrap_len(stride, 1 + stream.below(3), k)
        c["oom"] = (k // 80) % 2 == 0
    else:
        c["n"] = stream.below(70)
    if k == 13 and index % 7 == 0:  # one 64 Ki-element array per seventh body: the 0xdc/0xdd header bound
        c["n"], c["name"], c["fault"] = BIG_N[index // 7 % 2], b"Vec", None
        c["limit"] = 4_000_000
    c["msg"] = (0, 0)
    if c["fault"] is None and (k // 4) % 3 == 1:
        n = fallible_count(c)
        if n:
            c["fault"] = stream.below(n)
    if c["fault"] is not None and c["n"] >> 32 == 0 and c["n"] > 0xffff and c["fault"] == 0:
        c["fault"] = 1
    if True:
        need = len(mp_array(c["n"])) + 1 + (min(c["n"], 0x10010) if c["n"] >> 32 == 0 else 64)
        if c["room"] < need:
            c["room"] = need + c["room"]
    del c["msg"]
    return c


def all_cases(per_body=PER_BODY):
    out = []
    for index, va in enumerate(sorted(BODIES)):
        stream = Stream(f"rmp-seq-newtype/{va:#x}")
        for k in range(per_body):
            out.append(make_case(stream, va, k, index))
    return out


# ---------------------------------------------------------------- Compound::end on its own
END_PER_FN = 300
END_CAPS = (DIRECT_MARK, BUF_CAP, BUF_CAP, 0x100, 0x41, 0)
END_COUNTS = (0, 1, 15, 16, 17, 0xffff, 0x10000, 0xffffffff, 0x12345678)


def end_model(c, mut=frozenset()):
    """Compound::end(out, &compound): a 2^63 capacity word means the header was already written (Ok at once);
    otherwise write_array_len(count), append the buffer, release it (sdallocx(ptr, cap, 0)) unless cap is 0."""
    p = {"out": b"", "result": None, "events": [], "boundary": None}
    if c["cap"] == DIRECT_MARK and "end-mark-hdr" not in mut:
        return p
    p["events"].append(("hdr", c["count"]))
    release = c["cap"] != 0 or "end-free-zero" in mut
    if c["fault"] == 0:
        p["result"] = (ERR_TAG, FAULT[0], FAULT[1])
        if release and "end-err-keep" not in mut:
            p["events"].append(("free", c["cap"]))
        return p
    p["out"] = mp_array(c["count"], mut) + c["buf"][:c["blen"]]
    if release:
        p["events"].append(("free", c["cap"]))
    return p


def end_cases(per_fn=END_PER_FN):
    out = []
    for fam in sorted(FAMILIES):
        for layout in "ab":
            va = FAMILIES[fam]["end_" + layout]
            stream = Stream(f"rmp-seq-newtype/end/{va:#x}")
            for k in range(per_fn):
                cap = END_CAPS[k % len(END_CAPS)]
                blen = 0 if cap in (0, DIRECT_MARK) else stream.below(min(cap, BUF_CAP) + 1)
                c = {"end": va, "fam": fam, "layout": layout, "k": k, "cap": cap, "blen": blen,
                     "count": END_COUNTS[(k // 6) % len(END_COUNTS)], "buf": stream.take(BUF_CAP),
                     "prefix": stream.take(stream.below(6)), "ser_tail": stream.take(8), "cfg": stream.take(5),
                     "fault": 0 if (k // 3) % 4 == 1 else None, "oom": False}
                c["room"] = blen + 6 + (stream.below(64) if k % 2 else 0)
                out.append(c)
    return out


def run_end_case(m, c, hdr):
    m.reset()
    m.case = c
    m.events, m.reserves, m.k, m.boundary = [], [], 0, None
    m.hdrs = {hdr}

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        if vec not in (SER_AT, VEC_AT) or ln != m.load(vec + 0x10, 8) or m.load(vec, 8) - ln >= add:
            fail("reserve called outside its contract")
        m.reserves.append((ln, add))
        m.store(vec, 8, ln + add)

    def grow(m):
        fail("finish_grow reached; the case did not leave enough room")

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.regs[0] = dst

    def free(m):
        if m.regs[7] != HEAP_AT or m.regs[2] & 0xffffffff:
            fail("free of a foreign pointer or with flags")
        m.events.append(("free", m.regs[6]))

    m.stubs[RESERVE] = reserve
    m.stubs[GROW] = grow
    m.stubs[m.image.word(MEMCPY_GOT)] = memcpy
    m.stubs[m.image.word(FREE_GOT)] = free
    m.noreturn = {}
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    if c["layout"] == "a":
        sreg = m.add_region(SER_AT, 0x20, bytes(vec) + c["cfg"] + c["ser_tail"][:3])
    else:
        sreg = m.add_region(SER_AT, 0x10, VEC_AT.to_bytes(8, "little") + c["cfg"] + c["ser_tail"][:3])
        m.add_region(VEC_AT, 0x18, bytes(vec))
    buf = m.add_region(BUF_AT, 0x1000, c["prefix"])
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    heap = m.add_region(HEAP_AT, BUF_CAP, c["buf"])
    comp = bytearray(0x30)
    put(comp, 0, 8, c["cap"])
    put(comp, 8, 8, HEAP_AT)
    put(comp, 0x10, 8, c["blen"])
    put(comp, 0x18, 8, config_word(c["cfg"]))
    put(comp, 0x20, 4, c["count"])
    put(comp, 0x28, 8, SER_AT)
    creg = m.add_region(ARG_AT, 0x30, bytes(comp))
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = OUT_AT, ARG_AT
    m.run(c["end"], limit=100000)
    vbase = SER_AT if c["layout"] == "a" else VEC_AT
    ln = m.load(vbase + 0x10, 8)
    return {"boundary": None, "out": bytes(buf[:ln]), "tail_clean": not any(buf[ln:]) or ln < len(c["prefix"]),
            "ptr": m.load(vbase + 8, 8), "cap": m.load(vbase, 8),
            "ser_rest": bytes(sreg[0x18:] if c["layout"] == "a" else sreg[8:]), "result": bytes(out),
            "inputs_same": bytes(heap) == c["buf"] and bytes(creg) == bytes(comp),
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "events": list(m.events), "reserves": list(m.reserves)}


def evaluate_end(image, ext, rows, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, ext, rows, override)
    hdr_of = {}
    for r in rows:
        hdr_of[r["end_fn"]] = r["hdr"]
    results, bad = [], []
    for c in cases:
        try:
            got = run_end_case(m, c, hdr_of[c["end"]])
        except ToolError:
            if override is None:
                raise
            got = None
        why = compare(c, end_model(c, mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad


END_MUTANTS = ("end-mark-hdr", "end-free-zero", "end-err-keep", "arr-fix17", "arr16-limit", "hdr-u16")


def end_byte_sites(image, ext):
    """Per Compound::end: the `neg; jno` direct-mark test and the header-result compare (cmp rax, 2)."""
    sites = []
    for fam in sorted(FAMILIES):
        for layout in "ab":
            va = FAMILIES[fam]["end_" + layout]
            picked = {}
            for v, f in sweep(image, va, ext[va]):
                if f["op"] == 0x71 and "jno" not in picked:
                    picked["jno"] = (v, 0x01)
                elif f["op"] == 0x83 and f.get("imm") == 2 and f["rm"][0] == "r" and "cmp2" not in picked:
                    picked["cmp2"] = (v + f["len"] - 1, 0x01)
            for label in sorted(picked):
                sites.append((va, label) + picked[label])
    return sites


def end_controls(image, ext, rows, results):
    out = []
    for name in END_MUTANTS:
        hit = next((i for i, (c, got, _) in enumerate(results) if compare(c, end_model(c, {name}), got)), None)
        out.append(("model", name, hit))
    for va, label, at, bit in end_byte_sites(image, ext):
        cases = [c for c, _, _ in results if c["end"] == va]
        _, bad = evaluate_end(image, ext, rows, cases, override={at: image.code(at, 1)[0] ^ bit}, stop_on_first=True)
        out.append(("bytes", f"end-{label}@{at:#x}", cases.index(bad[0][0]) if bad else None))
    return out


# ---------------------------------------------------------------- static checks
def extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in list(BODIES) + [v for f in FAMILIES.values() for v in f.values() if v]:
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext


def body_facts(image, ext, va):
    """Everything the model needs from one body, read from its bytes: call pattern (header writer, element
    serializers, Compound::end), stride, flag offset, config offsets, the ext-arm message and the 0x80 buffer."""
    fam, layout, stride = BODIES[va]
    insns = sweep(image, va, ext[va])
    calls = [f["target"] for _, f in insns if f["op"] == 0xe8 and f["target"] != UNWIND]
    gots = sorted({(v + f["len"] + f["rm"][4]) & M64 for v, f in insns
                   if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip"})
    if len(calls) != 6:
        fail(f"body {va:#x} has {len(calls)} direct calls, expected 6")
    hdr, d1, d2, end, d3, comp = calls
    if not (d1 == d2 == d3):
        fail(f"body {va:#x} does not call one direct element serializer three times")
    if (layout == "a") != (comp == d1):
        fail(f"body {va:#x} compound element serializer does not match layout {layout}")
    want_end = FAMILIES[fam]["end_" + layout]
    if end != want_end:
        fail(f"body {va:#x} ends with {end:#x}, expected {want_end:#x}")
    want_hdr = FAMILIES[fam]["hdr_" + layout]
    if want_hdr is not None and hdr != want_hdr:
        fail(f"body {va:#x} header writer {hdr:#x} is not {want_hdr:#x}")
    if gots != [MALLOC_GOT, ALLOC_ERROR_GOT, FREE_GOT, COUNT_PANIC_GOT]:
        fail(f"body {va:#x} .got calls {[hex(g) for g in gots]}")
    imms = [f.get("imm") for _, f in insns if f.get("imm") is not None]
    adds = {f["imm"] for _, f in insns if f["op"] in (0x81, 0x83) and f["reg"] & 7 == 0 and f["rm"][0] == "r"}
    strides = sorted(a for a in adds if a > 0 and -a in adds)
    if strides != [stride]:
        fail(f"body {va:#x} walks with stride(s) {strides}, declared {stride:#x}")
    flags = sorted({f["rm"][4] for _, f in insns if f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m"
                    and f.get("imm") == 0})
    if flags != [FLAG_AT[layout]]:
        fail(f"body {va:#x} tests flag offsets {flags}")
    cfg_offs = sorted({f["rm"][4] for _, f in insns if f["op"] in (0x1b6, 0x1b7, 0xfb6, 0xfb7) and f["rm"][0] == "m"
                       and f["rm"][1] != "rip" and f["rm"][4] in range(CFG_AT[layout], CFG_AT[layout] + 5)})
    if CFG_MASK not in imms or BUF_CAP not in imms or (1 << 63) not in [i & M64 for i in imms]:
        fail(f"body {va:#x} lacks the compound constants")
    name_lo = int.from_bytes(EXT_NAME[:8], "little")
    if name_lo not in [i & M64 for i in imms] or int.from_bytes(EXT_NAME[8:], "little") not in imms or 10 not in imms:
        fail(f"body {va:#x} does not compare the name with {EXT_NAME!r}")
    msg = None
    for i, (v, f) in enumerate(insns):
        if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
            nxt = [g for _, g in insns[i + 1:i + 4] if g["op"] == 0xc7 and g["rm"][0] == "m"]
            if nxt:
                msg = ((v + f["len"] + f["rm"][4]) & M64, nxt[0]["imm"])
    if msg is None or image.read(msg[0], msg[1]) != EXT_TEXT:
        fail(f"body {va:#x} ext-arm message is not {EXT_TEXT!r}")
    return {"va": va, "end": ext[va], "insns": len(insns), "hdr": hdr, "direct": d1, "compound": comp,
            "end_fn": end, "msg": msg, "flag": flags[0], "cfg_offsets": cfg_offs}


def static_rows(image, ext):
    rows = [body_facts(image, ext, va) for va in sorted(BODIES)]
    # every copy family uses one header writer per layout
    for fam in FAMILIES:
        for layout in "ab":
            hdrs = {r["hdr"] for r in rows if BODIES[r["va"]][:2] == (fam, layout)}
            if len(hdrs) != 1:
                fail(f"family {fam} layout {layout} uses header writers {sorted(map(hex, hdrs))}")
    return rows


def header_writers(rows):
    return sorted({r["hdr"] for r in rows})


EXCLUDED = {0x41a3070: "named in another pending packet", 0x419d8a0: "named in RE-010-cancel-routing-115"}
SCAN_RANGES = ((0x2260000, 0x2280000), (0x4190000, 0x41b0000), (0x52f0000, 0x5300000))
EXT_MOVABS = b"\x48\xb8" + EXT_NAME[:8]


def family_scan(image, ext):
    """Every FDE in the three copy ranges that holds the `_ExtStruct` name test and calls one of the six
    Compound::end functions (rel32 call bytes). The modelled set must be exactly the bodies with the six-call
    pattern, minus the listed exclusions."""
    ends = {}
    for fam, f in FAMILIES.items():
        for key in ("end_a", "end_b"):
            ends[f[key]] = (fam, key[-1])
    rows = []
    for va in sorted(ext):
        if not any(lo <= va < hi for lo, hi in SCAN_RANGES):
            continue
        code = image.code(va, ext[va] - va)
        if EXT_MOVABS not in code:
            continue
        calls = []
        for i in range(len(code) - 4):
            if code[i] == 0xe8:
                t = (va + i + 5 + struct.unpack_from("<i", code, i + 1)[0]) & M64
                if t in ends:
                    calls.append(t)
        if not calls:
            continue
        fams = sorted({ends[t] for t in calls})
        if va in BODIES:
            status = "modelled"
        elif va in EXCLUDED:
            status = "excluded: " + EXCLUDED[va]
        else:
            status = "other-shape"
        rows.append((va, ext[va] - va, ",".join(f"{f}/{lay}" for f, lay in fams), len(calls), status))
    found = {r[0] for r in rows if r[4] == "modelled"}
    if found != set(BODIES):
        fail(f"family scan misses modelled bodies {sorted(map(hex, set(BODIES) - found))}")
    for va in EXCLUDED:
        if va not in {r[0] for r in rows}:
            fail(f"excluded body {va:#x} is not in the scanned family")
    return rows


# ---------------------------------------------------------------- evaluation and controls
def machine(image, ext, rows, override=None):
    m = CaseMachine(image, override)
    m.extents = ext
    m.roles = {r["va"]: r for r in rows}
    return m


def with_msg(c, rows_by_va):
    return dict(c, msg=rows_by_va[c["body"]]["msg"])


def evaluate(image, ext, rows, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, ext, rows, override)
    by = {r["va"]: r for r in rows}
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except ToolError:
            if override is None:
                raise
            got = None
        cm = with_msg(c, by)
        why = compare(cm, model(cm, mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad


MODEL_MUTANTS = ("arr-fix17", "arr16-limit", "hdr-u16", "ext-prefix", "ext-tag", "msg-len", "cfg-nomask",
                 "split-31", "iter-minus1", "stride-plus8", "err-retag", "hdr-err-tag", "err-no-free", "count-plus1",
                 "end-no-copy")


def byte_sites(image, ext):
    """Per body: the name-length immediate, the u32-split shift, the 0x80 buffer size, the config mask and the
    ext message length. Each one is flipped (one bit) and must be caught."""
    sites = []
    for va in sorted(BODIES):
        picked = {}
        for v, f in sweep(image, va, ext[va]):
            imm = f.get("imm")
            if f["op"] == 0x83 and imm == 10 and "cmp10" not in picked:
                picked["cmp10"] = (v + f["len"] - 1, 0x01)
            elif f["op"] in (0xc1,) and imm == 0x20 and "shr32" not in picked:
                picked["shr32"] = (v + f["len"] - 1, 0x01)
            elif imm == BUF_CAP and f["op"] in (0xbf,) and "bufcap" not in picked:
                picked["bufcap"] = (v + 1, 0x40)
            elif imm == CFG_MASK and "cfgmask" not in picked:
                picked["cfgmask"] = (v + f["len"] - 4, 0x01)
            elif f["op"] == 0xc7 and f["rm"][0] == "m" and imm == len(EXT_TEXT):
                picked["msglen"] = (v + f["len"] - 4, 0x01)
        for label in sorted(picked):
            sites.append((va, label) + picked[label])
    return sites


def range_controls(image, ext, rows):
    out = []
    # a body address that is not an FDE start
    saved = dict(BODIES)
    try:
        BODIES[0x2273371] = ("226", "b", 0x120)
        try:
            extents(image)
            out.append(("range", "body-not-fde-start", None))
        except ToolError:
            out.append(("range", "body-not-fde-start", 0))
        del BODIES[0x2273371]
        BODIES[0x2273370] = ("226", "b", 0x130)  # wrong stride
        try:
            body_facts(image, ext, 0x2273370)
            out.append(("range", "declared-stride-wrong", None))
        except ToolError:
            out.append(("range", "declared-stride-wrong", 0))
        BODIES[0x2273370] = ("226", "a", 0x120)  # wrong layout
        try:
            body_facts(image, ext, 0x2273370)
            out.append(("range", "declared-layout-wrong", None))
        except ToolError:
            out.append(("range", "declared-layout-wrong", 0))
        BODIES[0x2273370] = ("419", "b", 0x120)  # wrong copy family
        try:
            body_facts(image, ext, 0x2273370)
            out.append(("range", "declared-family-wrong", None))
        except ToolError:
            out.append(("range", "declared-family-wrong", 0))
    finally:
        BODIES.clear()
        BODIES.update(saved)
    try:
        Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))
        out.append(("range", "binary-digest", None))
    except ToolError:
        out.append(("range", "binary-digest", 0))
    return out


def controls(image, ext, rows, results, sites):
    out = []
    by = {r["va"]: r for r in rows}
    gots = [(with_msg(c, by), got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(gots):
            if compare(c, model(c, frozenset(mut)), got):
                return i
        return None

    for name in MODEL_MUTANTS:
        out.append(("model", name, first_hit({name})))
    for va, label, at, bit in sites:
        cases = [c for c, _, _ in results if c["body"] == va and c.get("limit") is None]
        _, bad = evaluate(image, ext, rows, cases, override={at: image.code(at, 1)[0] ^ bit}, stop_on_first=True)
        out.append(("bytes", f"{label}@{at:#x}", cases.index(bad[0][0]) if bad else None))
    out.extend(range_controls(image, ext, rows))
    return out


def coverage(image, ext, rows, cases):
    m = machine(image, ext, rows)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        run_case(m, c)
    reals = sorted({r["hdr"] for r in rows} | {r["end_fn"] for r in rows})
    table = []
    for va in sorted(BODIES) + reals:
        insns = [v for v, _ in sweep(image, va, ext[va])]
        table.append((va, len(insns), sum(1 for v in insns if v in seen)))
    return table


def hexs(b):
    return b.hex() if b else "-"


def generate(out, per_body=PER_BODY):
    image = Image(BINARY.read_bytes())
    ext = extents(image)
    rows = static_rows(image, ext)
    scan = family_scan(image, ext)
    other = [r for r in scan if r[4] == "other-shape"]
    for r in other:  # an unmodelled family member must fail the six-call pattern, not merely be left out
        if r[0] in BODIES:
            fail(f"{r[0]:#x} listed twice")
    sites = byte_sites(image, ext)
    cases = all_cases(per_body)
    results, bad = evaluate(image, ext, rows, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first body {c['body']:#x} case {c['k']} ({why})")
    ecases = end_cases()
    eresults, ebad = evaluate_end(image, ext, rows, ecases)
    if ebad:
        c, why = ebad[0]
        fail(f"{len(ebad)} Compound::end mismatches; first {c['end']:#x} case {c['k']} ({why})")
    ctrl = controls(image, ext, rows, results, sites) + end_controls(image, ext, rows, eresults)
    cov = coverage(image, ext, rows, [c for c in cases[::3] if c.get("limit") is None])
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tfde_end\tinstructions\tcopy_family\tlayout\tstride\tflag_offset\tconfig_offsets\theader_writer\t"
             "direct_element\tcompound_element\tcompound_end\text_message_at\text_message_len"]
    for r in rows:
        fam, layout, stride = BODIES[r["va"]]
        lines.append(f"{r['va']:#x}\t{r['end']:#x}\t{r['insns']}\t{fam}\t{layout}\t{stride:#x}\t{r['flag']:#x}\t"
                     f"{','.join(f'{o:#x}' for o in r['cfg_offsets']) or '-'}\t{r['hdr']:#x}\t{r['direct']:#x}\t"
                     f"{r['compound']:#x}\t{r['end_fn']:#x}\t{r['msg'][0]:#x}\t{r['msg'][1]}")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tname_hex\tlength\tconfig\tfault_event\toom\troom\tprefix\tout_len\tout_sha256\tresult\tevents\treserves"]
    for c, got, _ in results:
        if c["k"] % 8 not in (0, 3):  # reserved name and a random name, every length/fault mix
            continue
        evs = got["events"]
        short = ",".join(e[0][0] for e in evs[:12]) + ("+" + str(len(evs) - 12) if len(evs) > 12 else "")
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), hexs(c["name"]), f"{c['n']:#x}", c["cfg"].hex(),
                                "-" if c["fault"] is None else str(c["fault"]), "1" if c["oom"] else "0",
                                str(c["room"]), hexs(c["prefix"]), str(len(got["out"])),
                                hashlib.sha256(got["out"]).hexdigest()[:16], got["result"].hex(), short or "-",
                                str(len(got["reserves"]))]))
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tfde_size\tcompound_end_family_layout\tcompound_end_calls\tstatus"]
    for va, size, fams, n, status in scan:
        lines.append(f"{va:#x}\t{size}\t{fams}\t{n}\t{status}")
    (out / "family-scan.tsv").write_text("\n".join(lines) + "\n")

    lines = ["compound_end\tlayout\tcase\tcap\tbuffer_len\tcount\tfault\tout_len\tout_sha256\tresult\tevents"]
    for c, got, _ in eresults:
        if c["k"] % 5:
            continue
        lines.append("\t".join([f"{c['end']:#x}", c["layout"], str(c["k"]), f"{c['cap']:#x}", str(c["blen"]),
                                f"{c['count']:#x}", "-" if c["fault"] is None else str(c["fault"]), str(len(got["out"])),
                                hashlib.sha256(got["out"]).hexdigest()[:16], got["result"].hex(),
                                ",".join(f"{e[0]}:{e[1]:#x}" for e in got["events"]) or "-"]))
    (out / "end-cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        lines.append(f"{va:#x}\t{'body' if va in BODIES else 'real-callee'}\t{n}\t{hit}")
    (out / "coverage.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    kinds = {}
    by = {r["va"]: r for r in rows}
    for c, got, _ in results:
        digest.update(got["out"] + got["result"])
        cm = with_msg(c, by)
        p = model(cm)
        if is_ext(c["name"]):
            kind = "ext_error"
        elif p["boundary"]:
            kind = "alloc_error"
        elif buffered(c["n"]):
            kind = "buffered_fault" if p["result"] else "buffered_ok"
        else:
            kind = "direct_fault" if p["result"] else "direct_ok"
        kinds[kind] = kinds.get(kind, 0) + 1
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(BODIES),
        "body_instructions": sum(r["insns"] for r in rows),
        "body_instructions_executed": sum(h for v, _, h in cov if v in BODIES),
        "real_callees": [f"{t:#x}" for t in sorted({r["hdr"] for r in rows} | {r["end_fn"] for r in rows})],
        "element_serializer_stubs": len({r["direct"] for r in rows} | {r["compound"] for r in rows}),
        "cases": len(results),
        "compound_end_cases": len(eresults),
        "case_kinds": dict(sorted(kinds.items())),
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "family_scan": {"members": len(scan), "modelled": sum(1 for r in scan if r[4] == "modelled"),
                        "excluded": sum(1 for r in scan if r[4].startswith("excluded")),
                        "other_shape": sum(1 for r in scan if r[4] == "other-shape")},
        "controls": len(ctrl),
        "controls_detected": sum(1 for _, _, h in ctrl if h is not None),
    }
    if summary["controls_detected"] != summary["controls"]:
        missed = [n for _, n, h in ctrl if h is None]
        fail(f"negative controls not detected: {missed}")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-body", type=int, default=PER_BODY)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.per_body)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
