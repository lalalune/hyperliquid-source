"""Reconstruct and verify 24 forwarding rmp-serde newtype serializers of node #115 (collections and field tuples).

Each body is a `serialize_newtype_struct(out, ser, name, name_len, value)` monomorph of the 0x226xxxx/0x227xxxx
copy family that hands its value to an inner serializer. All of them first reject the reserved newtype name
`_ExtStruct` with a static error. Family "seq" (10 bodies) turns a two-representation collection (a B-tree map
selected by the niche word 0x8000000000000000, otherwise a ring buffer) into one 72-byte iterator record and
forwards it to collect_seq; family "tuple" (14 bodies) writes an n-element array header and calls the inner field
serializer on each 0x20-byte field, stopping at the first error, then runs Compound::end.

The reconstruction is `model` (with `ring_record`/`tree_record`); a concrete x86-64 evaluator runs the real bytes of
each body and of the real leaf writers (array header and Compound::end of both serializer layouts) on generated
cases, with the inner serializers as argument-checking contract stubs, and compares the written bytes, the result
record, the ordered fallible-call list and every inner argument. The binary is never executed.
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
ERR_TAG = 0x8000000000000000      # word 0 of the 24-byte result for "error carried in words 1..2"; also the BTreeMap niche
EXT_TAG = ERR_TAG | 2             # result word 0 for the static-str error
OK_TRIPLE = ERR_TAG | 4           # result word 0 for Ok(())
EXT_MESSAGES = (b"expected tuple", b"expected i8 and bytes")
RESERVE = 0x231e050               # RawVec reserve(vec, len, additional, 1, 1)
GROW = 0x231dc90                  # finish_grow; layout-a cases leave enough room to never reach it
MEMCPY_GOT = 0x64df508
PANIC_GOTS = (0x64df570, 0x64df730, 0x64df620)

# Leaf writers that run for real.  Layout "a": the serializer holds the Vec<u8> inline (cap, ptr, len at +0/+8/+0x10)
# and its struct-map flag at +0x1c.  Layout "b": the serializer holds a pointer to the Vec<u8> at +0, flag at +0xc.
# Each copy family (0x226xxxx, 0x419xxxx, 0x52fxxxx) has its own copies of the header writer, Compound::end and
# the RawVec reserve.
HDR_A, END_A = 0x25e7c10, 0x22999e0
HDR_B, END_B = 0x25e7940, 0x22997f0
LEAF_SETS = {
    ("226", "a"): {"hdr": HDR_A, "end": END_A, "reserve": RESERVE},
    ("226", "b"): {"hdr": HDR_B, "end": END_B},
    ("419", "a"): {"hdr": 0x3d50540, "end": 0x41d4150, "reserve": 0x43bd910},
    ("419", "b"): {"hdr": 0x3d50270, "end": 0x41d3f60},
    ("52f", "a"): {"hdr": 0x57cee80, "end": 0x5325140, "reserve": 0x5963a10},
}
SLOT_WRITERS = tuple(sorted({s["hdr"] for s in LEAF_SETS.values()}))   # error comes back in an out slot (rdi)
ENDS = tuple(sorted({s["end"] for s in LEAF_SETS.values()}))           # Compound::end, writes the caller's result
RESERVES = tuple(sorted({s["reserve"] for s in LEAF_SETS.values() if "reserve" in s}))
REAL = SLOT_WRITERS + ENDS
FLAG_AT = {"a": 0x1c, "b": 0xc}


def copy_family(va):
    return "226" if va < 0x3000000 else "419" if va < 0x5000000 else "52f"


def leaves(va):
    return LEAF_SETS[(copy_family(va), BODIES[va][1])]

# Family "seq": serialize_newtype_struct over a two-representation collection.  Word 0 of the value is the niche:
# 0x8000000000000000 selects the B-tree arm (root +8, height +0x10, length +0x18), any other word 0 is the
# capacity of a ring buffer (pointer +8, head +0x10, length +0x18).  The body builds one 72-byte iterator record
# (tag 0/1 = B-tree range with or without a root, tag 2 = the ring buffer's two slices) and tail-forwards
# (out, ser, &record) to the inner collect_seq.  elem = element stride in bytes.
# Family "tuple": serialize_newtype_struct over an n-field tuple of 0x20-byte fields; array header n, then the inner
# field serializer on value + 0x20*i for each field, then Compound::end.
STRIDE = 0x20
BODIES = {
    0x226b570: ("seq", "b", 0x30, 0x22402e0),
    0x2270cf0: ("seq", "b", 0x30, 0x2223290),
    0x22742e0: ("seq", "b", 0x30, 0x22141d0),
    0x2278390: ("seq", "b", 0x30, 0x2214860),
    0x2271df0: ("seq", "b", 0x20, 0x222a7a0),
    0x22724c0: ("seq", "b", 0x20, 0x22099e0),
    0x2275050: ("seq", "b", 0x20, 0x223c180),
    0x2276370: ("seq", "b", 0x20, 0x225afb0),
    0x226dc40: ("seq", "b", 0x68, 0x2269e30),
    0x226dd70: ("seq", "b", 0x68, 0x221b120),
    0x419a200: ("seq", "b", 0x30, 0x4148490),
    0x419c490: ("seq", "b", 0x68, 0x4179f80),
    0x419ddc0: ("seq", "b", 0x20, 0x418e390),
    0x419e700: ("seq", "b", 0x68, 0x4153060),
    0x419eef0: ("seq", "b", 0x20, 0x4137610),
    0x41a1950: ("seq", "b", 0x30, 0x4162e10),
    0x41a3fd0: ("seq", "b", 0x30, 0x415be90),
    0x41a58e0: ("seq", "b", 0x20, 0x4155980),
    0x41a6a70: ("seq", "b", 0x20, 0x41665f0),
    0x52f0ef0: ("seq", "b", 0x20, 0x52dff80),
    0x52f1d70: ("seq", "b", 0x68, 0x52e47f0),
    0x52f1ea0: ("seq", "b", 0x20, 0x528e670),
    0x52f2810: ("seq", "b", 0x30, 0x52b3650),
    0x52f3060: ("seq", "b", 0x68, 0x52aa6d0),
    0x52f55e0: ("seq", "b", 0x30, 0x52cd190),
    0x52f5720: ("seq", "b", 0x30, 0x527e150),
    0x52f9560: ("seq", "b", 0x20, 0x52a13a0),
    0x52fc330: ("seq", "b", 0x30, 0x52dbda0),
    0x52fc470: ("seq", "b", 0x20, 0x5275f60),
    0x226d0b0: ("tuple", "b", 2, 0x23f8c10),
    0x22722c0: ("tuple", "b", 2, 0x2bbf710),
    0x2273720: ("tuple", "b", 2, 0x23f8dd0),
    0x2273dc0: ("tuple", "b", 2, 0x221bdb0),
    0x2275a30: ("tuple", "b", 2, 0x2bb4720),
    0x2275ba0: ("tuple", "b", 2, 0x2bb23f0),
    0x226e4c0: ("tuple", "b", 3, 0x2d17de0),
    0x419aaa0: ("tuple", "b", 2, 0x3692e10),
    0x419dc50: ("tuple", "b", 2, 0x38ce820),
    0x41a2f00: ("tuple", "b", 2, 0x3c057a0),
    0x41a5770: ("tuple", "b", 2, 0x369ee90),
    0x419ed60: ("tuple", "b", 3, 0x38b8470),
    0x419c310: ("tuple", "a", 2, 0x3c055a0),
    0x419d0d0: ("tuple", "a", 2, 0x369f070),
    0x41a3c90: ("tuple", "a", 2, 0x3692960),
    0x41a6b90: ("tuple", "a", 2, 0x38ce5f0),
    0x419cb90: ("tuple", "a", 3, 0x38b81c0),
    0x52f4cc0: ("tuple", "a", 2, 0x548e970),
    0x52f9730: ("tuple", "a", 2, 0x4d7b1c0),
    0x52fb880: ("tuple", "a", 2, 0x5a0ad40),
    0x52fc790: ("tuple", "a", 2, 0x5915100),
    0x52fda50: ("tuple", "a", 2, 0x59154f0),
    0x52f9ed0: ("tuple", "a", 3, 0x517f420),
    0x226b990: ("tuple", "a", 2, 0x2bb21f0),
    0x226eda0: ("tuple", "a", 2, 0x2bb4540),
    0x226f9d0: ("tuple", "a", 2, 0x23f89e0),
    0x22703e0: ("tuple", "a", 2, 0x2249f00),
    0x2273c40: ("tuple", "a", 2, 0x23f8f90),
    0x22761f0: ("tuple", "a", 2, 0x2bbf3b0),
    0x22725e0: ("tuple", "a", 3, 0x2d17810),
}
INNER = {spec[3] for spec in BODIES.values()}
# Tuple bodies: argument order of the inner field serializer and the field stride in bytes.
FIELD_ABI = {va: ("value,ser", STRIDE) for va, spec in BODIES.items() if spec[0] == "tuple"}
FIELD_ABI.update({0x22703e0: ("ser,value", 0x18), 0x2273dc0: ("ser,value", 0x18), 0x2275a30: ("value,ser", 0x10),
                  0x226eda0: ("value,ser", 0x10), 0x419aaa0: ("value,ser", 0x10), 0x41a3c90: ("value,ser", 0x10),
                  0x52f4cc0: ("value,ser", 0x10)})
SEQ_WORDS = 9                     # the iterator record is 72 bytes
RING_WORDS = 5                    # tag 2 defines words 0..4 (two slices); words 5..8 are enum padding

SER_AT = 0x7100_0000_0000
VEC_AT = 0x7180_0000_0000
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x4000
OUT_AT = 0x7500_0000_0000
VAL_AT = 0x7580_0000_0000
NAME_AT = 0x75c0_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
FAULT = (0x0bad_0000_0000_0007, 0x0bad_0000_0000_0011, 0x0bad_0000_0000_0022)
JUNK = 0x0dead_0000_0000_0001


# ---------------------------------------------------------------- reconstruction
def is_ext(name, mut=frozenset()):
    if "ext-prefix" in mut:
        return name[:10] == EXT_NAME
    if "ext-case" in mut:
        return name.lower() == EXT_NAME.lower()
    if "ext-len9" in mut:
        return name[:9] == EXT_NAME[:9] and len(name) in (9, 10)
    return name == EXT_NAME


def ring_record(cap, ptr, head, length, elem, mut=frozenset()):
    """The ring-buffer arm: VecDeque::iter() as (first slice begin, end, second slice begin, end)."""
    if length == 0 and "empty-general" not in mut:
        return [2, ptr, ptr, ptr, ptr]
    if "no-wrap-sub" in mut:
        phys = head
    elif "wrap-gt" in mut:
        phys = (head - cap) & M64 if head > cap else head
    else:
        phys = (head - cap) & M64 if head >= cap else head
    room = (cap - (head if "room-from-head" in mut else phys)) & M64
    split = length > room
    e = elem + 8 if "elem-size" in mut else elem
    at = lambda i: (ptr + (i * e)) & M64  # noqa: E731
    if split:
        tail = (length - room) & M64
        first_end = at(cap) if "first-end-len" not in mut else at(phys + length)
        return [2 if "tag-1" not in mut else 1, at(phys), first_end, ptr, at(tail)]
    end = (phys + length) & M64
    return [2 if "tag-1" not in mut else 1, at(phys), at(end), ptr, ptr if "second-from-head" not in mut else at(phys)]


def tree_record(root, height, length, mut=frozenset()):
    """The B-tree arm: a full range (front and back handles on the same root) plus the remaining length."""
    flag = 1 if root else 0
    if "tree-flag-inverted" in mut:
        flag ^= 1
    n = length if (root or "tree-len-always" in mut) else 0
    if "tree-height-zero" in mut:
        height = 0
    return [flag, 0, root, height, flag, 0, root, height, n]


def seq_record(value, elem, mut=frozenset()):
    w0, w1, w2, w3 = value
    if w0 == ERR_TAG and "niche-ignored" not in mut:
        return tree_record(w1, w2, w3, mut)
    return ring_record(w0, w1, w2, w3, elem, mut)


def model(c, msg, mut=frozenset()):
    """Predicted (appended bytes, result triple or None for Ok, ordered fallible-call list, inner-call records)."""
    family, layout, arg, inner = BODIES[c["body"]]
    if is_ext(c["name"], mut):
        at, n = msg
        return b"", (EXT_TAG if "ext-tag" not in mut else ERR_TAG, at, n - (1 if "msg-len" in mut else 0)), [], []
    if family == "seq":
        rec = seq_record(c["value"], arg, mut)
        k = 0
        res = FAULT if c["fault"] == k else c["inner_res"][0]
        if "seq-ok-forced" in mut:
            res = (OK_TRIPLE,) + tuple(res[1:])
        return b"", tuple(res), [inner], [("seq", rec)]
    leaf = leaves(c["body"])
    n = arg + (1 if "hdr-count" in mut else 0)
    out, calls, inners, err = b"", [], [], None

    def fallible(target, data, kind):
        nonlocal out, err
        if err is not None:
            return
        k = len(calls)
        calls.append(target)
        if kind == "inner":
            order, stride = FIELD_ABI[c["body"]]
            if "stride" in mut:
                stride += 8
            if "order-swapped" in mut:
                order = "ser,value" if order == "value,ser" else "value,ser"
            inners.append(("field", order, len(inners) * stride))
            res = FAULT if c["fault"] == k else c["inner_res"][len(inners) - 1]
            failed = (res[0] & 0xff != 4) if "ok-any-tag" in mut else (res[0] != OK_TRIPLE)
            if failed:
                if not ("err-continue" in mut):
                    err = tuple(res)
            return
        if c["fault"] == k:
            a, b, x = FAULT
            err = (a, b, x) if kind == "end" else (ERR_TAG | (4 if "err-tag" in mut else 0), a, b)
        else:
            out += data

    use_call = (c["flag"] == 2) if "flag-inverted" not in mut else (c["flag"] != 2)
    if layout == "b" or use_call:
        fallible(leaf["hdr"], bytes([0x90 | n]), "hdr")
    else:
        out += bytes([0x90 | n])
    for _ in range(arg):
        fallible(inner, b"", "inner")
    if "end-skipped" not in mut:
        fallible(leaf["end"], b"", "end")
    if "err-keeps" in mut and err is not None:
        out += b"\x00"
    return out, err, calls, inners


# ---------------------------------------------------------------- evaluation
class CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.calls_seen.append(("panic", target))
            raise Boundary("noreturn", self.regs)
        in_body = call and self.body_lo <= va - 5 < self.body_hi
        if in_body and target in INNER:
            k = self.direct
            self.direct += 1
            self.result_calls.append(target)
            self.inner_call(target, k)
            return None
        if in_body and target in REAL:
            k = self.direct
            self.direct += 1
            self.result_calls.append(target)
            if self.case["fault"] == k:
                return self.fault(target)
        if not call and target in INNER and self.body_lo <= va - 5 < self.body_hi:
            fail("unexpected tail jump into an inner serializer")
        if target in INNER:
            fail(f"inner serializer {target:#x} reached outside the body")
        return super().transfer(target, call, va)

    def inner_call(self, target, k):
        """Contract stub of the inner value serializer: check the arguments, record them, write a result."""
        c = self.case
        family = BODIES[c["body"]][0]
        rdi, rsi, rdx = self.regs[7], self.regs[6], self.regs[2]
        if target != BODIES[c["body"]][3]:
            fail(f"body called inner {target:#x}, not its own")
        if family == "seq":
            if rdi != OUT_AT or rsi != SER_AT:
                fail("collect_seq did not receive (out, ser)")
            if not STACK_TOP - 0x10000 <= rdx < STACK_TOP:
                fail("iterator record is not on the stack")
            rec = [self.load(rdx + 8 * i, 8) for i in range(SEQ_WORDS)]
            self.inner_records.append(("seq", rec))
            res = FAULT if c["fault"] == k else c["inner_res"][0]
        else:
            if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                fail("field serializer did not receive a stack result slot")
            if rdx == SER_AT and rsi != SER_AT:
                self.inner_records.append(("field", "value,ser", (rsi - VAL_AT) & M64))
            elif rsi == SER_AT and rdx != SER_AT:
                self.inner_records.append(("field", "ser,value", (rdx - VAL_AT) & M64))
            else:
                fail("field serializer did not receive the serializer")
            idx = len(self.inner_records) - 1
            res = FAULT if c["fault"] == k else c["inner_res"][idx]
        for i, w in enumerate(res):
            self.store(rdi + 8 * i, 8, w)
        self.regs[0] = rdi
        for r in (1, 2, 6, 7, 8, 9, 10, 11):
            self.regs[r] = JUNK + r
        for i in range(16):
            self.xmm[i] = (JUNK << 64) | i

    def fault(self, target):
        a, b, x = FAULT
        rdi = self.regs[7]
        if target in SLOT_WRITERS:
            if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                fail("writer output slot is not on the stack")
            self.store(rdi, 8, a)
            self.store(rdi + 8, 8, b)
        elif target in ENDS:
            if rdi != OUT_AT:
                fail("Compound::end did not receive the caller's result record")
            for i, w in enumerate(FAULT):
                self.store(OUT_AT + 8 * i, 8, w)
        self.regs[0], self.regs[2] = (OUT_AT, 0) if target in ENDS else (a, b)
        for r in (1, 6, 7, 8, 9, 10, 11):
            self.regs[r] = JUNK + r
        return None


def install(m, image):
    m.calls_seen, m.result_calls, m.reserves, m.inner_records = [], [], [], []
    m.direct = 0

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        if vec not in (SER_AT, VEC_AT):
            fail("reserve called on a foreign vector")
        cap = m.load(vec + 0, 8)
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

    for target in RESERVES:
        m.stubs[target] = reserve
    m.stubs[GROW] = grow
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.noreturn = {image.word(g) for g in PANIC_GOTS}


def run_case(m, c):
    m.reset()
    m.case = c
    install(m, m.image)
    va = c["body"]
    layout = BODIES[va][1]
    m.body_lo, m.body_hi = va, m.extents[va]
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    if layout == "a":
        ser = bytes(vec) + c["ser_tail"]
        ser = ser[:FLAG_AT["a"]] + bytes([c["flag"]]) + ser[FLAG_AT["a"] + 1:]
        sreg = m.add_region(SER_AT, 0x20, ser)
    else:
        ser = VEC_AT.to_bytes(8, "little") + c["ser_tail"]
        ser = ser[:FLAG_AT["b"]] + bytes([c["flag"]]) + ser[FLAG_AT["b"] + 1:]
        sreg = m.add_region(SER_AT, 0x10, ser)
        m.add_region(VEC_AT, 0x18, bytes(vec))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    val = m.add_region(VAL_AT, 0x80, c["val_bytes"])
    name = m.add_region(NAME_AT, 0x40, c["name"] + bytes(0x40 - len(c["name"])))
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[9], m.regs[10], m.regs[11] = c["r9"], JUNK + 10, JUNK + 11
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, SER_AT, NAME_AT, len(c["name"]), VAL_AT
    try:
        m.run(va, limit=400000)
        panic = None
    except Boundary:
        panic = m.calls_seen[-1] if m.calls_seen else ("boundary",)
    ln = m.load((SER_AT if layout == "a" else VEC_AT) + 0x10, 8)
    ptr = m.load((SER_AT if layout == "a" else VEC_AT) + 8, 8)
    ser_now = bytes(sreg)
    return {"panic": panic, "out": bytes(buf[:ln]) if ln <= BUF_SIZE else None,
            "tail_clean": ln <= BUF_SIZE and (not any(buf[ln:]) or ln < len(c["prefix"])),
            "ptr": ptr, "ser_rest": ser_now[0x18:] if layout == "a" else ser_now,
            "result": bytes(out), "rax": m.regs[0],
            "inputs_same": bytes(val) == c["val_bytes"] and bytes(name[:len(c["name"])]) == c["name"],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "calls": list(m.result_calls), "reserves": list(m.reserves), "inners": list(m.inner_records)}


def expected_ser_rest(c):
    layout = BODIES[c["body"]][1]
    if layout == "a":
        tail = bytearray(c["ser_tail"])
        tail[FLAG_AT["a"] - 0x18] = c["flag"]
        return bytes(tail)
    ser = bytearray(VEC_AT.to_bytes(8, "little") + c["ser_tail"])
    ser[FLAG_AT["b"]] = c["flag"]
    return bytes(ser)


def inner_matches(want, got):
    """Field calls must match exactly; a seq record is compared on its defined words only."""
    if len(want) != len(got):
        return False
    for w, g in zip(want, got):
        if w[0] != g[0]:
            return False
        if w[0] == "field":
            if tuple(w) != tuple(g):
                return False
            continue
        wv, gv = w[1], g[1]
        if wv[0] in (0, 1) and len(wv) == SEQ_WORDS:
            if list(wv) != list(gv):
                return False
        elif list(wv) != list(gv[:len(wv)]) or len(wv) != RING_WORDS:
            return False
    return True


def compare(c, want, got):
    data, res, calls, inners = want
    if got["panic"] is not None or not got["regs_ok"] or not got["inputs_same"] or not got["tail_clean"]:
        return "machine"
    if got["rax"] != OUT_AT:
        return "return-register"
    if got["ser_rest"] != expected_ser_rest(c) or got["ptr"] != BUF_AT:
        return "serializer"
    if got["out"] != c["prefix"] + data:
        return "bytes"
    if got["calls"] != calls:
        return "calls"
    if not inner_matches(inners, got["inners"]):
        return "inner-arguments"
    if res is None:
        expect = OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10
    else:
        expect = b"".join(x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    for ln, add in got["reserves"]:
        if ln + add > len(c["prefix"]) + len(data) and res is None:
            return "reserve"
    return None


# ---------------------------------------------------------------- cases
PER_BODY = 200
FLAGS = (0, 1, 2, 2, 3, 0xff)
ROOMS = (0, 0, 1, 2, 3, 5, 8, 17, 0x40)
SPECIAL_W = (0, 1, 2, 3, 7, 8, 0x10, 0xff, 0x100, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
             (1 << 63) - 1, 1 << 63, M64, M64 - 1, M64 - 7)
OK_LIKE = (OK_TRIPLE, ERR_TAG, ERR_TAG | 1, ERR_TAG | 2, ERR_TAG | 3, ERR_TAG | 5, ERR_TAG | 0x104, 4, 2, 0, M64)


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
    if sel == 3:
        return EXT_NAME.lower() if (k // 8) % 2 else EXT_NAME.upper()
    return stream.take(stream.below(24))


def word(stream):
    sel = stream.below(4)
    w = int.from_bytes(stream.take(8), "little")
    if sel == 0:
        return SPECIAL_W[stream.below(len(SPECIAL_W))]
    if sel == 1:
        return stream.below(40)
    if sel == 2:
        return w >> (8 * stream.below(8))
    return w


def ring_value(stream, k):
    """(cap, ptr, head, len) shaped to reach every arm of the slice split, including wrapped heads."""
    ptr = int.from_bytes(stream.take(8), "little") & ~7
    mode = (k // 8) % 9
    cap = SPECIAL_W[stream.below(len(SPECIAL_W))] if mode == 8 else stream.below(64) + (0 if mode else 1)
    if cap == ERR_TAG:
        cap += 1
    if mode == 0:      # empty
        head, length = stream.below(cap + 1), 0
    elif mode == 1:    # contiguous: head + len <= cap
        head = stream.below(cap + 1) if cap else 0
        length = stream.below(cap - head + 1) if cap >= head else 0
    elif mode == 2:    # wrapped: head + len > cap
        head = stream.below(cap) if cap else 0
        length = cap - head + 1 + stream.below(head + 1) if cap else 1
    elif mode == 3:    # exactly at the split point
        head = stream.below(cap + 1)
        length = cap - head
    elif mode == 4:    # one past the split point
        head = stream.below(cap + 1)
        length = cap - head + 1
    elif mode == 5:    # head already at or past capacity (unnormalized physical index)
        head = cap + stream.below(cap + 2)
        length = stream.below(cap + 2)
    elif mode == 6:    # full
        head = stream.below(cap) if cap else 0
        length = cap
    elif mode == 7:    # zero capacity
        cap, head, length = 0, word(stream), word(stream)
    else:              # arbitrary words
        head, length = word(stream), word(stream)
    return [cap, ptr, head & M64, length & M64]


def tree_value(stream, k):
    root = 0 if (k // 8) % 3 == 0 else int.from_bytes(stream.take(8), "little") | 8
    return [ERR_TAG, root, word(stream), word(stream)]


def inner_result(stream, k, i):
    sel = stream.below(5)
    if sel < 3 or (k // 16) % 4 == 0:
        return (OK_TRIPLE, int.from_bytes(stream.take(8), "little"), int.from_bytes(stream.take(8), "little"))
    w0 = OK_LIKE[stream.below(len(OK_LIKE))] if sel == 3 else int.from_bytes(stream.take(8), "little")
    if w0 == OK_TRIPLE:
        w0 = ERR_TAG | 1
    return (w0, int.from_bytes(stream.take(8), "little"), int.from_bytes(stream.take(8), "little"))


def fallible_count(c):
    return len(model(c, (0, 0))[2])


def make_case(stream, va, k):
    family, layout, arg, inner = BODIES[va]
    c = {"body": va, "k": k, "flag": FLAGS[k % len(FLAGS)], "prefix": stream.take(stream.below(6)),
         "ser_tail": stream.take(8), "fault": None, "name": names(stream, k),
         "r9": int.from_bytes(stream.take(8), "little")}
    val = bytearray(stream.take(0x80))
    if family == "seq":
        value = tree_value(stream, k) if (k // 4) % 2 else ring_value(stream, k)
        for i, w in enumerate(value):
            put(val, 8 * i, 8, w)
        c["value"] = tuple(value)
        c["inner_res"] = [inner_result(stream, k, 0)]
    else:
        c["value"] = None
        c["inner_res"] = [inner_result(stream, k, i) for i in range(arg)]
    c["val_bytes"] = bytes(val)
    room = ROOMS[(k // 7) % len(ROOMS)]
    if layout == "b":
        room = max(room, 0x100)  # finish_grow is outside this packet; layout b never grows
    c["room"] = room
    n = fallible_count(c)
    if family == "tuple" and (k // 3) % 3 == 1 and n:
        c["fault"] = stream.below(n)
    return c


def all_cases(per_body=PER_BODY):
    out = []
    for va in sorted(BODIES):
        stream = Stream(f"rmp-newtype-forward/{va:#x}")
        for k in range(per_body):
            out.append(make_case(stream, va, k))
    return out


# ---------------------------------------------------------------- static checks
def extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in list(BODIES) + list(REAL) + sorted(INNER):
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext


def direct_calls(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] in (0xe8, 0xe9):
            out.append(("call" if f["op"] == 0xe8 else "jmp", f["target"], v))
        elif f["op"] == 0xff and f["reg"] & 7 in (2, 4) and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append(("got", v + f["len"] + f["rm"][4], v))
    return out


def elem_from_bytes(insns):
    """Element stride of a seq body: `shl $k` (times 3 after `lea (r,r,2)`) or the immediate of `imul $e`."""
    shifts = {f["imm"] for _, f in insns if f["op"] == 0xc1 and f["reg"] & 7 == 4}
    muls = {f["imm"] for _, f in insns if f["op"] in (0x69, 0x6b)}
    triples = any(f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == f["rm"][2] and f["rm"][3] == 2
                  and f["rm"][4] == 0 for _, f in insns)  # lea (r,r,2): index * 3
    if shifts and not muls and len(shifts) == 1:
        return (3 if triples else 1) << shifts.pop()
    if muls and not shifts and len(muls) == 1:
        return muls.pop()
    return None


def field_stride_from_bytes(insns):
    """Field stride of a tuple body: the smallest `add $imm, reg` / `lea imm(reg)` step in {0x10, 0x18, 0x20}
    on a register other than rsp and rip (the pointer walk between field calls)."""
    steps = set()
    for _, f in insns:
        if f["op"] == 0x83 and f["reg"] & 7 == 0 and f["rm"][0] == "r" and f["rm"][1] != 4:
            steps.add(f["imm"])
        elif f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] not in (4, "rip") and f["rm"][2] is None:
            steps.add(f["rm"][4])
    hits = sorted(steps & {0x10, 0x18, 0x20})
    return hits[0] if hits else None


def static_rows(image, ext):
    """Per body: callees, ext-name immediates, ext-arm message, header count, flag offset and element stride,
    all read from the bytes and checked against BODIES."""
    rows = []
    name_lo = int.from_bytes(EXT_NAME[:8], "little")
    name_hi = int.from_bytes(EXT_NAME[8:], "little")
    for va in sorted(BODIES):
        family, layout, arg, inner = BODIES[va]
        insns = sweep(image, va, ext[va])
        calls = direct_calls(image, va, ext[va])
        targets = [t for kind, t, _ in calls if kind == "call" or (kind == "jmp" and not va <= t < ext[va])]
        if any(kind == "got" for kind, _, _ in calls):
            fail(f"body {va:#x} has .got calls")
        inner_calls = [t for t in targets if t not in REAL + RESERVES]
        if set(inner_calls) != {inner}:
            fail(f"body {va:#x} inner callees {sorted(map(hex, set(inner_calls)))} != {inner:#x}")
        if family == "seq":
            if targets != [inner]:
                fail(f"seq body {va:#x} calls {targets}")
            elem = elem_from_bytes(insns)
            if elem != arg:
                fail(f"seq body {va:#x} element stride {elem} != {arg}")
        else:
            leaf = leaves(va)
            want = [leaf["hdr"]] * (2 if layout == "b" else 1) + [inner] * arg + [leaf["end"]]
            if layout == "a":
                want.append(leaf["reserve"])
            if targets != want:
                fail(f"tuple body {va:#x} call sequence {[hex(t) for t in targets]}")
            stride = field_stride_from_bytes(insns)
            if stride != FIELD_ABI[va][1]:
                fail(f"tuple body {va:#x} field stride {stride} != {FIELD_ABI[va][1]}")
            counts = sorted({f["imm"] for _, f in insns if f["op"] == 0xba} - ({1} if layout == "a" else set()))
            if counts != [arg]:
                fail(f"tuple body {va:#x} header counts {counts}")
            flags = sorted({f["rm"][4] for _, f in insns if f["op"] == 0x80 and f["reg"] & 7 == 7
                            and f["rm"][0] == "m" and f.get("imm") == 2})
            if flags != [FLAG_AT[layout]]:
                fail(f"tuple body {va:#x} flag offsets {flags}")
            if layout == "a":
                inline = [f["imm"] & 0xff for _, f in insns if f["op"] == 0xc6 and f["rm"][0] == "m"]
                if inline != [0x90 | arg]:
                    fail(f"tuple body {va:#x} inline header bytes {inline}")
        imms = [f.get("imm") for _, f in insns]
        if name_lo not in [i & M64 for i in imms if i is not None] or name_hi not in imms or 10 not in imms:
            fail(f"body {va:#x} does not compare the name with {EXT_NAME!r}")
        msg = None
        for i, (v, f) in enumerate(insns):
            if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
                at = (v + f["len"] + f["rm"][4]) & M64
                nxt = [g for _, g in insns[i + 1:i + 4] if g["op"] == 0xc7 and g["rm"][0] == "m"]
                if nxt:
                    msg = (at, nxt[0]["imm"])
        if msg is None:
            fail(f"body {va:#x} has no ext-arm message")
        text = image.read(msg[0], msg[1])
        if text not in EXT_MESSAGES:
            fail(f"body {va:#x} ext message is {text!r}")
        rows.append({"va": va, "end": ext[va], "insns": len(insns), "targets": targets, "msg": msg,
                     "text": text.decode(), "inner_end": ext[inner]})
    return rows


# ---------------------------------------------------------------- evaluation and controls
def machine(image, ext, override=None):
    m = CaseMachine(image, override)
    m.extents = ext
    return m


def evaluate(image, ext, msgs, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except ToolError:
            if override is None:
                raise
            got = None
        why = compare(c, model(c, msgs[c["body"]], mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad


MODEL_MUTANTS = ("ext-prefix", "ext-case", "ext-len9", "ext-tag", "msg-len", "empty-general", "no-wrap-sub", "wrap-gt",
                 "room-from-head", "elem-size", "first-end-len", "second-from-head", "tag-1", "tree-flag-inverted",
                 "tree-len-always", "tree-height-zero", "niche-ignored", "seq-ok-forced", "hdr-count", "stride", "order-swapped",
                 "ok-any-tag", "err-continue", "err-tag", "flag-inverted", "end-skipped", "err-keeps")


def byte_sites(image, ext):
    """Per body, bytes whose flip must be caught: the name length immediate, one byte of the reserved name, the
    ext message length, the element stride (seq), the header count, the field step and the flag offset (tuple)."""
    sites = []
    for va in sorted(BODIES):
        family = BODIES[va][0]
        insns = sweep(image, va, ext[va])
        picked = {}
        for v, f in insns:
            raw = image.code(v, f["len"])
            if f["op"] == 0x83 and f["reg"] & 7 == 7 and f.get("imm") == 10 and "cmp10" not in picked:
                picked["cmp10"] = v + f["len"] - 1
            elif 0xb8 <= f["op"] <= 0xbf and f["len"] == 10 and raw[-8:] == EXT_NAME[:8] and "name" not in picked:
                picked["name"] = v + f["len"] - 8 + 4
            elif f["op"] == 0xc7 and f["rm"][0] == "m" and f.get("imm") in (0xe, 0x15):
                picked["msglen"] = v + f["len"] - 4
            elif family == "seq" and f["op"] == 0xc1 and f["reg"] & 7 == 4 and "elem" not in picked:
                picked["elem"] = v + f["len"] - 1
            elif family == "seq" and f["op"] in (0x69, 0x6b) and "elem" not in picked:
                picked["elem"] = v + f["len"] - (4 if f["op"] == 0x69 else 1)
            elif family == "seq" and f["op"] == 0x0f43 and "wrap" not in picked:
                picked["wrap"] = v + 1 + (1 if raw[0] & 0xf0 == 0x40 else 0) + 1
            elif family == "tuple" and f["op"] == 0xba and "count" not in picked:
                picked["count"] = v + 1
            elif (BODIES[va][1] == "a" and f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m"
                  and "flag" not in picked):  # layout b calls the header writer in both arms: its flag is inert
                picked["flag"] = v + f["len"] - 2
            elif family == "tuple" and f["op"] == 0x83 and f["reg"] & 7 == 0 and f["rm"][0] == "r" and "step" not in picked:
                picked["step"] = v + f["len"] - 1
            elif family == "tuple" and f["op"] == 0xc6 and f["rm"][0] == "m" and "inline" not in picked:
                picked["inline"] = v + f["len"] - 1
        for i, (kind, t, at) in enumerate(direct_calls(image, va, ext[va])):
            if kind == "call" and t in INNER and "inner-call" not in picked:
                picked["inner-call"] = at + 1
        for label in sorted(picked):
            sites.append((va, label, picked[label]))
    return sites


def controls(image, ext, msgs, results, sites):
    rows = []
    gots = [(c, got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(gots):
            if compare(c, model(c, msgs[c["body"]], frozenset(mut)), got):
                return i
        return None

    for name in MODEL_MUTANTS:
        rows.append(("model", name, first_hit({name})))
    for va, label, at in sites:
        cases = [c for c, _ in gots if c["body"] == va]
        _, bad = evaluate(image, ext, msgs, cases, override={at: image.code(at, 1)[0] ^ 0x01}, stop_on_first=True)
        rows.append(("bytes", f"{label}@{at:#x}", cases.index(bad[0][0]) if bad else None))
    return rows


def coverage(image, ext, msgs, cases):
    m = machine(image, ext)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        run_case(m, c)
    rows = []
    for va in sorted(BODIES) + sorted(REAL):
        insns = [v for v, _ in sweep(image, va, ext[va])]
        rows.append((va, len(insns), sum(1 for v in insns if v in seen)))
    return rows


def hexs(b):
    return b.hex() if b else "-"


def arm_of(c):
    family = BODIES[c["body"]][0]
    if is_ext(c["name"]):
        return "ext"
    if family == "seq":
        w0, _, head, length = c["value"]
        if w0 == ERR_TAG:
            return "tree-root" if c["value"][1] else "tree-empty"
        if length == 0:
            return "ring-empty"
        phys = (head - w0) & M64 if head >= w0 else head
        return "ring-wrapped" if length > ((w0 - phys) & M64) else "ring-contiguous"
    if c["fault"] is not None:
        return "fault"
    bad = [r for r in c["inner_res"] if r[0] != OK_TRIPLE]
    return "inner-error" if bad else "ok"


def generate(out, per_body=PER_BODY):
    image = Image(BINARY.read_bytes())
    ext = extents(image)
    static = static_rows(image, ext)
    msgs = {r["va"]: r["msg"] for r in static}
    sites = byte_sites(image, ext)
    cases = all_cases(per_body)
    results, bad = evaluate(image, ext, msgs, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first body {c['body']:#x} case {c['k']} ({why})")
    ctrl = controls(image, ext, msgs, results, sites)
    cov = coverage(image, ext, msgs, cases)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tfde_end\tinstructions\tcopy_family\tfamily\tlayout\telement_or_fields\tfield_abi\tinner\t"
             "inner_fde_end\text_message_at\text_message_len\text_message\tdirect_callees"]
    for r in static:
        family, layout, arg, inner = BODIES[r["va"]]
        abi = "%s/%#x" % FIELD_ABI[r["va"]] if family == "tuple" else "-"
        lines.append(f"{r['va']:#x}\t{r['end']:#x}\t{r['insns']}\t{copy_family(r['va'])}\t{family}\t{layout}\t"
                     f"{arg:#x}\t{abi}\t{inner:#x}\t"
                     f"{r['inner_end']:#x}\t{r['msg'][0]:#x}\t{r['msg'][1]}\t{r['text']}\t"
                     f"{','.join(f'{t:#x}' for t in r['targets'])}")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tarm\tname_hex\tflag\tfault_call\tvalue_words\tinner_args\tinner_results\tout_len\t"
             "out_sha256\tresult"]
    for c, got, _ in results:
        if c["k"] % 16 not in (2, 4, 9, 13):
            continue
        if got["inners"] and got["inners"][0][0] == "seq":
            rec = got["inners"][0][1]
            args = ",".join(f"{w:x}" for w in (rec[:RING_WORDS] if rec[0] == 2 else rec))
        else:
            args = ",".join(f"{order}@{off:#x}" for _, order, off in got["inners"]) or "-"
        vals = ",".join(f"{w:x}" for w in c["value"]) if c["value"] else "-"
        ires = ",".join(f"{r[0]:x}" for r in c["inner_res"])
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), arm_of(c), hexs(c["name"]), f"{c['flag']:#x}",
                                "-" if c["fault"] is None else str(c["fault"]), vals, args, ires,
                                str(len(got["out"])), hashlib.sha256(got["out"]).hexdigest()[:16],
                                got["result"].hex()]))
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        lines.append(f"{va:#x}\t{'body' if va in BODIES else 'real-callee'}\t{n}\t{hit}")
    (out / "coverage.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    arms = {}
    for c, got, _ in results:
        digest.update(got["out"] + got["result"] + repr(got["inners"]).encode())
        a = arm_of(c)
        arms[a] = arms.get(a, 0) + 1
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(BODIES),
        "bodies_by_family": {f: sum(1 for s in BODIES.values() if s[0] == f) for f in ("seq", "tuple")},
        "bodies_by_copy_family": {k: sum(1 for va in BODIES if copy_family(va) == k) for k in ("226", "419", "52f")},
        "body_instructions": sum(r["insns"] for r in static),
        "body_instructions_executed": sum(h for v, _, h in cov if v in BODIES),
        "real_callees": [f"{t:#x}" for t in sorted(REAL)],
        "contract_stubs": [f"{t:#x}" for t in sorted(INNER)] + [f"{t:#x}" for t in RESERVES] + ["memcpy"],
        "cases": len(results),
        "case_arms": dict(sorted(arms.items())),
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
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
