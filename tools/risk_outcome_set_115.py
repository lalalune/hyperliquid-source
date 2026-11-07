"""Reconstruct and verify three rmp-serde `newtype(BTreeSet<OutcomeRecord>)` serializers of node #115, the five-field
record writer they stream, and the B-tree `Iter::next` that feeds it.

Each body is a `serialize_newtype_struct(out, ser, name, name_len, &BTreeSet<Record>)` monomorph (copy families
226/419/52f, the serializer-first layout). It rejects the reserved name `_ExtStruct` with the static "expected tuple"
error, builds a lazy B-tree iterator over the set record {root, height, length}, writes the length as a MessagePack
array header and streams every 0x98-byte record through the record writer. A length that does not fit in u32 takes the
buffered arm instead (0x80-byte buffer, per-record counter, the walk then ends in the "unwrap on None" panic).
The record writer emits outcome (u64), settleFraction, details, nameAndDescription (a two-string array) and sideNames
(a two-string newtype closed by a tuple end), with the field names only when the serializer's struct-map flag is 1.

The reconstruction is `body_model`, `record_model` and `next_model`. A concrete x86-64 evaluator runs the real bytes of
each body, its record writer, header/uint/string writers, the two record-field helpers, the tuple end, Compound::end and
the family's `Iter::next` on generated trees, then compares written bytes, the result record, the iterator record, the
ordered writer-call list (which is also the fault-injection order) and the panic locations. The binary is never executed.
"""

import itertools
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import time

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




EXT_NAME = b"_ExtStruct"          # rmp-serde's reserved newtype name for MessagePack ext values
EXT_TEXT = b"expected tuple"      # static error text every body returns for that name
ERR_TAG = 0x8000000000000000      # result word 0 for "error carried in words 1..2" / direct-compound mark
EXT_TAG = ERR_TAG | 2
OK_TRIPLE = ERR_TAG | 4           # result word 0 for Ok(()) of the element-level writers
DIRECT_MARK = ERR_TAG
UNWIND = 0x63f0a50
MALLOC_GOT = 0x64df480
FREE_GOT = 0x64df4a0
ALLOC_ERROR_GOT = 0x64df498
COUNT_PANIC_GOT = 0x64df520
MEMCPY_GOT = 0x64df508
PANIC_GOT = 0x64df830
BUF_CAP = 0x80
CFG_MASK = 0xff0101

# copy families: reserve/grow (RawVec contract stubs), header writer, uint writer, str writer, the two record-field
# helpers, the tuple end, the B-tree Iter::next
FAMS = {
    "226": dict(res=0x231e050, grow=0x231dc90, hdr=0x25e7c10, wu=0x25e9f10, ws=0x25e8bf0, nd=0x22e6f10, nt=0x22771c0,
                tend=0x22999e0, nxt=0x238a340, rec=0x28ff740),
    "419": dict(res=0x43bd910, grow=0x43bd550, hdr=0x3d50540, wu=0x3d51450, ws=0x41c6610, nd=0x3675c30, nt=0x419f010,
                tend=0x41d4150, nxt=0x37cc740, rec=0x44b83e0),
    "52f": dict(res=0x5963a10, grow=0x5963650, hdr=0x57cee80, wu=0x57cfd20, ws=0x57cf5d0, nd=None, nt=0x52f13c0,
                tend=0x5325140, nxt=0x5133fb0, rec=0x50c01d0),
}
BODIES = {
    0x226c320: dict(fam="226", end=0x227e1b0),
    0x41a70c0: dict(fam="419", end=0x41acd70),
    0x52f0c10: dict(fam="52f", end=0x5306d60),
}
# immediates of the five `cmp byte [ser+0x1b], imm` key tests in code order: outcome, settleFraction, details,
# nameAndDescription, sideNames (the 52f copy tests the fourth against 0: that key is written for any non-zero flag)
FLAG_CMPS = {"226": (1, 1, 1, 1, 1), "419": (1, 1, 1, 1, 1), "52f": (1, 1, 1, 0, 1)}
HOOK_ROLES =("hdr", "wu", "ws", "nd", "nt", "tend", "rec")
CONV2 = ("hdr", "wu")             # result in memory, Ok = 2
CONV4 = ("nd", "nt", "tend", "rec")   # result in memory, Ok = ERR_TAG | 4, error = {ERR_TAG, w1, w2}
# ws returns in registers: rax == 2 is Ok, otherwise (rax, rdx) is the error pair

KEY_BYTES = 0x98                  # one record: 6 Strings + the u64 outcome
KEY_AT = 8
PIDX_AT = 0x690
LEN_AT = 0x692
EDGE_AT = 0x698
NODE_STRIDE = 0x800
ITER_BYTES = 0x48
F_OUTCOME = 0x90
F_SETTLE, F_DETAILS, F_NAME, F_DESC, F_S1, F_S2 = 0x00, 0x18, 0x30, 0x48, 0x60, 0x78   # String {cap, ptr, len}
KEY_NAMES = (b"outcome", b"settleFraction", b"details")
NAME_DESC = b"nameAndDescription"
SIDE_NAMES = b"sideNames"
SIDE_TYPE = b"SideMap"

TREE_AT = 0x7600_0000_0000
STR_AT = 0x7640_0000_0000
ITER_AT = 0x7680_0000_0000
COMP_AT = 0x76c0_0000_0000
SER_AT = 0x7100_0000_0000
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x4000
OUT_AT = 0x7500_0000_0000
REC_AT = 0x7580_0000_0000
NAME_AT = 0x75c0_0000_0000
ONE_AT = 0x7700_0000_0000          # one record for the direct record cases
HEAP_AT = 0x7800_0000_0000
HEAP_SIZE = 0x4000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
FAULT = (0x0bad_0000_0000_0007, 0x0bad_0000_0000_0011)
GARBAGE = 0xa5


def addr(i):
    return 0 if i is None else TREE_AT + i * NODE_STRIDE


def mp_array(n, mut=frozenset()):
    """write_array_len(n as u32)."""
    n &= 0xffff if "hdr-u16" in mut else 0xffffffff
    if n < (17 if "arr-fix17" in mut else 16):
        return bytes([0x90 | (n & 0xf)])
    if n < 0x10000:
        return b"\xdc" + (n & 0xffff).to_bytes(2, "big")
    return b"\xdd" + (n & 0xffffffff).to_bytes(4, "big")


def is_ext(name, mut=frozenset()):
    if "ext-prefix" in mut:
        return name[:10] == EXT_NAME
    return name == EXT_NAME


def config_word(cfg, mut=frozenset()):
    lo = int.from_bytes(cfg[0:2], "little")
    mid = int.from_bytes(cfg[2:4], "little") | cfg[4] << 16
    mask = 0xffffff if "cfg-nomask" in mut else CFG_MASK
    return lo | (mid & mask) << 16


class VecSim:
    """Vec<u8> with the amortisation replaced by the contract stub: reserve(len, add) makes capacity len + add."""
    def __init__(self, cap, ln, events):
        self.cap, self.ln, self.out, self.events = cap, ln, bytearray(), events

    def ensure(self, add):
        if self.cap - self.ln < add:
            self.events.append(("res", self.ln, add))
            self.cap = self.ln + add

    def push(self, bs):
        self.ln += len(bs)
        self.out += bs


def write_uint(vec, v, mut=frozenset()):
    """rmp::encode::write_uint: smallest MessagePack unsigned form; tag byte first, payload second."""
    lim8 = 0x81 if "uint-80" in mut else 0x80
    lim16 = 0x101 if "uint-100" in mut else 0x100
    lim32 = 0x10001 if "uint-10000" in mut else 0x10000
    lim64 = 0x100000001 if "uint-2e32" in mut else 1 << 32
    if v < lim8:
        vec.ensure(1)
        vec.push(bytes([v & 0xff]))
    elif v < lim16:
        vec.ensure(1)
        vec.push(b"\xcc")
        vec.ensure(1)
        vec.push(bytes([v & 0xff]))
    elif v < lim32:
        vec.ensure(1)
        vec.push(b"\xcd")
        vec.ensure(2)
        vec.push((v & 0xffff).to_bytes(2, "big"))
    elif v < lim64:
        vec.ensure(1)
        vec.push(b"\xce")
        vec.ensure(4)
        vec.push((v & 0xffffffff).to_bytes(4, "big"))
    else:
        vec.ensure(1)
        vec.push(b"\xcf")
        vec.ensure(8)
        vec.push(v.to_bytes(8, "big"))


def write_str(vec, b, mut=frozenset()):
    """rmp::encode::write_str: fixstr / str8 / str16 / str32 marker, length bytes, then the payload."""
    n = len(b)
    if n < (33 if "str-fix33" in mut else 32):
        vec.ensure(1)
        vec.push(bytes([0xa0 | (n & 0x1f)]))
    elif n < 256:
        vec.ensure(1)
        vec.push(b"\xd9")
        vec.ensure(1)
        vec.push(bytes([n]))
    elif n < 0x10000:
        vec.ensure(1)
        vec.push(b"\xda")
        vec.ensure(2)
        vec.push(n.to_bytes(2, "big"))
    else:
        vec.ensure(1)
        vec.push(b"\xdb")
        vec.ensure(4)
        vec.push(n.to_bytes(4, "big"))
    vec.ensure(n)
    vec.push(bytes(b))


# ---------------------------------------------------------------- reconstruction: B-tree view and Iter::next
class Tree:
    """nodes[i] = {keys: [record dicts], edges (None for a leaf), parent, pidx}; root index or None."""

    def __init__(self, nodes, root, height):
        self.nodes, self.root, self.height = nodes, root, height
        self.by = {addr(i): n for i, n in enumerate(nodes)}

    def count(self):
        return sum(len(n["keys"]) for n in self.nodes)

    def image(self):
        """(node bytes, string-pool bytes): every record string is placed in the pool and pointed at."""
        buf = bytearray([GARBAGE]) * (len(self.nodes) * NODE_STRIDE + NODE_STRIDE)
        pool = bytearray()
        for i, n in enumerate(self.nodes):
            base = i * NODE_STRIDE
            put(buf, base, 8, addr(n["parent"]))
            for j, rec in enumerate(n["keys"]):
                record_image(buf, base + KEY_AT + KEY_BYTES * j, rec, pool)
            put(buf, base + PIDX_AT, 2, n["pidx"])
            put(buf, base + LEN_AT, 2, len(n["keys"]))
            if n["edges"] is not None:
                for j, e in enumerate(n["edges"]):
                    put(buf, base + EDGE_AT + 8 * j, 8, addr(e))
        return bytes(buf), bytes(pool)


def record_image(buf, at, rec, pool):
    for off, key in ((F_SETTLE, "settle"), (F_DETAILS, "details"), (F_NAME, "name"), (F_DESC, "desc"), (F_S1, "s1"), (F_S2, "s2")):
        s = rec[key]
        put(buf, at + off, 8, len(s) + 3)
        put(buf, at + off + 8, 8, STR_AT + len(pool))
        put(buf, at + off + 0x10, 8, len(s))
        pool += s + b"\x00"
    put(buf, at + F_OUTCOME, 8, rec["outcome"])


class Wild(Exception):
    """The case would make Iter::next dereference memory outside the generated tree."""


def first_edge(tree, a):
    n = tree.by.get(a)
    if n is None or n["edges"] is None:
        raise Wild
    return addr(n["edges"][0])


def iter_words(tree, rem):
    root = addr(tree.root)
    return [1 if root else 0, 0, root, tree.height, 0, 0, 0, 0, rem]


class Panic(Exception):
    def __init__(self, loc):
        super().__init__(loc)
        self.loc = loc


def next_model(w, tree, mut=frozenset(), locs=(0, 0)):
    """Iter::next on the 9-word record w (only the front half is used). Returns (node address, index) or None;
    raises Panic for the two unwrap failures. The record is updated in place."""
    if w[8] == 0:
        return None
    w[8] = (w[8] - 1) & M64
    if (w[0] & 0xffffffff) != 1 and "tag-any" not in mut:
        raise Panic(locs[1])
    node = w[1]
    if node == 0:
        a = w[2]
        for _ in range(w[3] - (1 if "lazy-short" in mut else 0)):
            a = first_edge(tree, a)
        w[0], w[1], w[2], w[3] = 1, a, 0, 0
        node, height, idx = a, 0, 0
    else:
        node, height, idx = w[1], w[2], w[3]
    view = tree.by.get(node)
    if view is None:
        raise Wild
    while idx >= len(view["keys"]) + (1 if "len-off1" in mut else 0):
        parent = tree.by[node]["parent"]
        if parent is None:
            raise Panic(locs[0])
        idx = tree.by[node]["pidx"] + (1 if "pidx-plus1" in mut else 0)
        node = addr(parent)
        height += 1
        view = tree.by[node]
    key = (node, idx)
    if height == 0:
        w[1], w[2], w[3] = node, 0, idx + 1
    else:
        n = tree.by[node]
        if n["edges"] is None:
            raise Wild
        child = addr(n["edges"][idx + (0 if "edge-idx" in mut else 1)])
        for _ in range(height - 1 - (1 if "desc-short" in mut else 0)):
            child = first_edge(tree, child)
        w[1], w[2], w[3] = child, 0, 0
    return key


EMPTY_REC = dict(outcome=0xa5a5a5a5a5a5a5a5, settle=b"", details=b"", name=b"", desc=b"", s1=b"", s2=b"")


def key_record(tree, key):
    node, idx = key
    keys = tree.by[node]["keys"]
    return keys[idx] if idx < len(keys) else EMPTY_REC


# ---------------------------------------------------------------- reconstruction: the record writer and the set body
class Run:
    """Model-side recorder of the call sequence the real code makes: every writer call is an event and a fault point."""
    def __init__(self, fault, events):
        self.fault, self.ev, self.k = fault, events, 0

    def hook(self, *event):
        self.ev.append(event)
        hit = self.fault == self.k
        self.k += 1
        return hit


def m_hdr(run, vec, n, mut):
    if run.hook("hdr", n & 0xffffffff):
        return False
    b = mp_array(n, mut)
    vec.ensure(1)
    vec.push(b[:1])
    if len(b) > 1:
        vec.ensure(len(b) - 1)
        vec.push(b[1:])
    return True


def m_uint(run, vec, v, mut):
    if run.hook("wu", v):
        return False
    write_uint(vec, v, mut)
    return True


def m_str(run, vec, b, mut):
    if run.hook("ws", bytes(b)):
        return False
    write_str(vec, b, mut)
    return True


def m_key(vec, name, marker, mut):
    """Inline field-name write: marker byte (reserve 1), then the name bytes (reserve len)."""
    vec.ensure(1)
    vec.push(bytes([marker]))
    vec.ensure(len(name))
    vec.push(name)


def record_model(run, vec, rec, cfg, fam, mut=frozenset()):
    """The five-field record writer (outcome, settleFraction, details, nameAndDescription, sideNames) on the
    serializer whose config bytes are cfg (flag1b = cfg[3], flag1c = cfg[4]); False when a writer call failed."""
    f1b, f1c = cfg[3], cfg[4]
    named = f1b == 1
    head = (((f1b ^ (0 if "hdr-flag" in mut else 1)) << 4) & 0xff) | 0x85
    vec.ensure(1)
    vec.push(bytes([head]))
    if named:
        m_key(vec, KEY_NAMES[0], 0xa7, mut)
    if not m_uint(run, vec, rec["outcome"], mut):
        return False
    if named:
        m_key(vec, KEY_NAMES[1], 0xae, mut)
    if not m_str(run, vec, rec["settle"], mut):
        return False
    if named:
        m_key(vec, KEY_NAMES[2], 0xa7, mut)
    if not m_str(run, vec, rec["details"], mut):
        return False
    if (f1b != 0 if FLAG_CMPS[fam][3] == 0 and "nd-eq1" not in mut else named) and not m_str(run, vec, NAME_DESC, mut):
        return False
    if FAMS[fam]["nd"] is not None:
        if run.hook("nd"):
            return False
        vec.ensure(1)
        vec.push(b"\x92")
    elif not m_hdr(run, vec, 2, mut):
        return False
    if not m_str(run, vec, rec["name"], mut) or not m_str(run, vec, rec["desc"], mut):
        return False
    if named and not m_str(run, vec, SIDE_NAMES, mut):
        return False
    if run.hook("nt"):
        return False
    if f1c == (3 if "nt-flag" in mut else 2):
        if not m_hdr(run, vec, 2, mut):
            return False
    else:
        vec.ensure(1)
        vec.push(b"\x92")
    if not m_str(run, vec, rec["s1"], mut) or not m_str(run, vec, rec["s2"], mut):
        return False
    # the tuple end sees the direct-mark capacity (neg overflows) and returns Ok without writing
    return not run.hook("tend", 2)


def body_model(c, mut=frozenset()):
    p = {"out": b"", "result": None, "events": [], "boundary": None}
    if is_ext(c["name"], mut):
        p["result"] = (EXT_TAG if "ext-tag" not in mut else ERR_TAG, c["msg"][0], c["msg"][1] + (1 if "msg-len" in mut else 0))
        return p
    ev, tree = p["events"], c["tree"]
    fam = BODIES[c["body"]]["fam"]
    rem = 0 if tree.root is None else c["len"]
    buffered = (rem != 0) if "split-any" in mut else (rem >> 32) != 0
    run = Run(c["fault"], ev)
    if not buffered:
        vec = VecSim(len(c["prefix"]) + c["room"], len(c["prefix"]), ev)
        if not m_hdr(run, vec, rem, mut):
            p["result"] = (ERR_TAG if "hdr-err-tag" not in mut else EXT_TAG, FAULT[0], FAULT[1])
            return p
        w = iter_words(tree, rem)
        try:
            while True:
                key = next_model(w, tree, mut, c["locs"])
                if key is None:
                    break
                if run.hook("rec", "ser", key[0], key[1], 0, 0):
                    p["result"] = (ERR_TAG, FAULT[0], FAULT[1])
                    break
                if not record_model(run, vec, key_record(tree, key), c["cfg"], fam, mut):
                    p["result"] = (ERR_TAG, FAULT[0], FAULT[1])
                    break
        except Panic as pn:
            p["boundary"] = ("unwrap-none", pn.loc)
            p["out_valid"] = True
        p["out"] = bytes(vec.out)
        return p
    ev.append(("malloc", BUF_CAP))
    if c["oom"]:
        p["boundary"] = ("alloc-error", 1, BUF_CAP)
        return p
    comp = VecSim(BUF_CAP, 0, ev)
    ccfg = config_word(c["cfg"], mut)
    cbytes = ccfg.to_bytes(8, "little")
    cfgc = bytes([cbytes[0], cbytes[1], cbytes[2], cbytes[3], cbytes[4]])
    counter = 0
    w = iter_words(tree, rem)
    try:
        while True:
            key = next_model(w, tree, mut, c["locs"])
            if key is None:
                break
            if run.hook("rec", "cmp", key[0], key[1], counter, ccfg):
                p["result"] = (ERR_TAG, FAULT[0], FAULT[1])
                if "err-no-free" not in mut:
                    ev.append(("free", comp.cap))
                return p
            ok = record_model(run, comp, key_record(tree, key), cfgc, fam, mut)
            if not ok:
                p["result"] = (ERR_TAG, FAULT[0], FAULT[1])
                if "err-no-free" not in mut:
                    ev.append(("free", comp.cap))
                p["heap"] = bytes(comp.out)
                return p
            counter = (counter + 1) & 0xffffffff
    except Panic as pn:
        p["boundary"] = ("unwrap-none", pn.loc)
        p["heap"] = bytes(comp.out)
        return p
    # unreachable with a real tree (the walk would need 2^32 records); kept so the model reads like the body and so
    # that model mutants which reach it still produce a comparable answer
    vec = VecSim(len(c["prefix"]) + c["room"], len(c["prefix"]), ev)
    m_hdr(Run(None, ev), vec, counter, mut)
    vec.push(bytes(comp.out))
    ev.append(("free", comp.cap))
    p["out"] = bytes(vec.out)
    return p


def rec_case_model(c, mut=frozenset()):
    """Direct call of the record writer on one record."""
    ev = []
    run = Run(c["fault"], ev)
    vec = VecSim(len(c["prefix"]) + c["room"], len(c["prefix"]), ev)
    ok = record_model(run, vec, c["rec"], c["cfg"], c["fam"], mut)
    return {"out": bytes(vec.out), "events": ev, "result": None if ok else (ERR_TAG, FAULT[0], FAULT[1]), "boundary": None}


def next_expect(c, mut=frozenset()):
    """Direct Iter::next case: returns (ret, words_after, boundary)."""
    w = list(c["words"])
    try:
        key = next_model(w, c["tree"], mut, c["locs"])
    except Panic as pn:
        return None, w, ("unwrap-none", pn.loc)
    ret = 0 if key is None else key[0] + KEY_AT + KEY_BYTES * key[1]
    return ret, w, None


def reference_bytes(records, flag1b, flag1c, fam):
    """Independent oracle for valid cases: MessagePack of the record list (fixmap/fixarray of five fields) built from
    the field values, without any of the Vec bookkeeping."""
    def s(b):
        n = len(b)
        return (bytes([0xa0 | n]) if n < 32 else (b"\xd9" + bytes([n]) if n < 256 else b"\xda" + n.to_bytes(2, "big"))) + bytes(b)

    def u(v):
        if v < 0x80:
            return bytes([v])
        for lim, tag, size in ((1 << 8, 0xcc, 1), (1 << 16, 0xcd, 2), (1 << 32, 0xce, 4), (1 << 64, 0xcf, 8)):
            if v < lim:
                return bytes([tag]) + v.to_bytes(size, "big")
    n = len(records)
    out = bytearray(bytes([0x90 | n]) if n < 16 else b"\xdc" + n.to_bytes(2, "big"))
    for r in records:
        out.append((((flag1b ^ 1) << 4) & 0xff) | 0x85)
        k = flag1b == 1
        out += (bytes([0xa7]) + KEY_NAMES[0] if k else b"") + u(r["outcome"])
        out += (bytes([0xae]) + KEY_NAMES[1] if k else b"") + s(r["settle"])
        out += (bytes([0xa7]) + KEY_NAMES[2] if k else b"") + s(r["details"])
        out += (s(NAME_DESC) if (flag1b != 0 if fam == "52f" else k) else b"") + b"\x92" + s(r["name"]) + s(r["desc"])
        out += (s(SIDE_NAMES) if k else b"") + (b"\x92" if flag1c != 2 else b"\x92") + s(r["s1"]) + s(r["s2"])
    return bytes(out)


# ---------------------------------------------------------------- evaluation
class CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            kind = self.noreturn[target]
            self.boundary = (kind, self.regs[7], self.regs[6]) if kind == "alloc-error" else (kind, self.regs[7])
            raise Boundary("noreturn", self.regs)
        if call:
            role = self.hooks.get(target)
            if role is not None:
                self.events.append(self.event_of(role))
                if self.next_fault():
                    self.fail_result(role)
                    return None
        return super().transfer(target, call, va)

    def event_of(self, role):
        r = self.regs
        if role == "hdr":
            return ("hdr", r[2] & 0xffffffff)
        if role == "wu":
            return ("wu", r[2])
        if role == "ws":
            n = r[2]
            if n > 0x400:
                fail("string length out of range")
            return ("ws", bytes(self.load(r[6] + i, 1) for i in range(n)))
        if role == "tend":
            return ("tend", self.load(r[6] + 0x20, 4))
        if role in ("nd", "nt"):
            return (role,)
        comp = r[2]
        kind = "ser" if comp == SER_AT else "cmp"
        counter = self.load(comp + 0x20, 4) if kind == "cmp" else 0
        cfgw = self.load(comp + 0x18, 8) if kind == "cmp" else 0
        rel = r[6] - TREE_AT
        return ("rec", kind, TREE_AT + (rel // NODE_STRIDE) * NODE_STRIDE, (rel % NODE_STRIDE - KEY_AT) // KEY_BYTES, counter, cfgw)

    def fail_result(self, role):
        rdi = self.regs[7]
        if role == "ws":
            for r in (1, 2, 6, 7, 8, 9, 10, 11):
                self.regs[r] = 0x0dead
            self.regs[0], self.regs[2] = FAULT
            return
        if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
            fail("fault result slot is not on the stack")
        if role in CONV4 or role == "rec":
            self.store(rdi, 8, ERR_TAG)
            self.store(rdi + 8, 8, FAULT[0])
            self.store(rdi + 16, 8, FAULT[1])
        else:
            self.store(rdi, 8, FAULT[0])
            self.store(rdi + 8, 8, FAULT[1])
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.regs[r] = 0x0dead

    def next_fault(self):
        hit = self.case["fault"] == self.k
        self.k += 1
        return hit



def install(m, image, c, fam):
    F = FAMS[fam]
    m.events, m.k, m.boundary = [], 0, None
    m.hooks = {F[r]: r for r in HOOK_ROLES if F[r] is not None}

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        ok = vec == SER_AT or STACK_TOP - 0x10000 <= vec < STACK_TOP
        if not ok:
            fail("reserve called on a foreign vector")
        cap = m.load(vec, 8)
        if ln != m.load(vec + 0x10, 8) or cap - ln >= add or m.regs[1] != 1 or m.regs[8] != 1:
            fail("reserve called outside its contract")
        if ln + add > (HEAP_SIZE if m.load(vec + 8, 8) == HEAP_AT else BUF_SIZE):
            fail("case output larger than its region")
        m.events.append(("res", ln, add))
        m.store(vec, 8, ln + add)

    def grow_(m):
        fail("finish_grow reached; the case did not leave enough room")

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.regs[0] = dst

    def malloc(m):
        m.events.append(("malloc", m.regs[7]))
        m.regs[0] = 0 if c.get("oom") else HEAP_AT

    def free(m):
        if m.regs[7] != HEAP_AT or m.regs[2] & 0xffffffff:
            fail("free of a foreign pointer or with flags")
        m.events.append(("free", m.regs[6]))

    m.stubs[F["res"]] = reserve
    m.stubs[F["grow"]] = grow_
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.stubs[image.word(MALLOC_GOT)] = malloc
    m.stubs[image.word(FREE_GOT)] = free
    m.noreturn = {image.word(ALLOC_ERROR_GOT): "alloc-error", image.word(PANIC_GOT): "unwrap-none",
                  image.word(COUNT_PANIC_GOT): "count-overflow"}


def ser_region(m, c):
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    sreg = m.add_region(SER_AT, 0x20, bytes(vec) + c["cfg"] + c["ser_tail"][:3])
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    return sreg, buf


def run_case(m, c):
    m.reset()
    m.case = c
    if c["kind"] == "rec":
        install(m, m.image, c, c["fam"])
        img = bytearray(KEY_BYTES)
        pool = bytearray()
        record_image(img, 0, c["rec"], pool)
        oreg = m.add_region(ONE_AT, KEY_BYTES, bytes(img))
        m.add_region(STR_AT, len(pool) + 16, bytes(pool))
        sreg, buf = ser_region(m, c)
        out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
        for kk, v in zip(SAVED_REGS, SAVED):
            m.regs[kk] = v
        m.add_region(HEAP_AT, HEAP_SIZE, b"")
        m.regs[7], m.regs[6], m.regs[2] = OUT_AT, ONE_AT, SER_AT
        try:
            m.run(FAMS[c["fam"]]["rec"], limit=c.get("limit", 2_000_000))
        except Boundary:
            pass
        ln = m.load(SER_AT + 0x10, 8)
        return {"boundary": m.boundary, "out": bytes(buf[:ln]) if ln <= len(buf) else None,
                "tail_clean": ln <= len(buf) and (not any(buf[ln:]) or ln < len(c["prefix"])),
                "ptr": m.load(SER_AT + 8, 8), "cap": m.load(SER_AT, 8), "ser_rest": bytes(sreg[0x18:]),
                "result": bytes(out), "tree_same": bytes(oreg) == bytes(img), "name_same": True,
                "regs_ok": [m.regs[kk] for kk in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
                "events": list(m.events)}
    tree = c["tree"]
    timg, pool = tree.image()
    if c["kind"] == "next":
        install(m, m.image, c, NEXTS[c["fn"]])
        treg = m.add_region(TREE_AT, len(timg), timg)
        w = bytearray(ITER_BYTES)
        for i, x in enumerate(c["words"]):
            put(w, 8 * i, 8, x)
        ireg = m.add_region(ITER_AT, ITER_BYTES, bytes(w))
        m.regs[7] = ITER_AT
        for kk, v in zip(SAVED_REGS, SAVED):
            m.regs[kk] = v
        try:
            m.run(c["fn"], limit=100000)
        except Boundary:
            pass
        return {"boundary": m.boundary, "ret": m.regs[0], "words": [u(ireg, 8 * i, 8) for i in range(9)],
                "tree_same": bytes(treg) == timg,
                "regs_ok": [m.regs[kk] for kk in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
                "events": list(m.events)}
    fam = BODIES[c["body"]]["fam"]
    install(m, m.image, c, fam)
    treg = m.add_region(TREE_AT, len(timg), timg)
    m.add_region(STR_AT, len(pool) + 16, pool)
    sreg, buf = ser_region(m, c)
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    for kk, v in zip(SAVED_REGS, SAVED):
        m.regs[kk] = v
    heap = m.add_region(HEAP_AT, HEAP_SIZE, b"")
    rec = bytearray(0x18)
    put(rec, 0, 8, addr(tree.root))
    put(rec, 8, 8, c["height"])
    put(rec, 0x10, 8, c["len"])
    rreg = m.add_region(REC_AT, 0x18, bytes(rec))
    name = m.add_region(NAME_AT, 0x40, c["name"] + bytes(0x40 - len(c["name"])))
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, SER_AT, NAME_AT, len(c["name"]), REC_AT
    try:
        m.run(c["body"], limit=c.get("limit", 3_000_000))
    except Boundary:
        pass
    ln = m.load(SER_AT + 0x10, 8)
    return {"boundary": m.boundary, "out": bytes(buf[:ln]) if ln <= len(buf) else None,
            "tail_clean": ln <= len(buf) and (not any(buf[ln:]) or ln < len(c["prefix"])),
            "ptr": m.load(SER_AT + 8, 8), "cap": m.load(SER_AT, 8), "ser_rest": bytes(sreg[0x18:]),
            "result": bytes(out), "tree_same": bytes(treg) == timg and bytes(rreg) == bytes(rec),
            "name_same": bytes(name[:len(c["name"])]) == c["name"], "heap": bytes(heap),
            "regs_ok": [m.regs[kk] for kk in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "events": list(m.events)}


def oracle_applies(c):
    return (c["kind"] == "body" and c["tree"].root is not None and c["len"] == c["tree"].count()
            and not is_ext(c["name"]) and c["fault"] is None and c["len"] < 16)


def compare(c, want, got):
    if c["kind"] == "next":
        ret, words, bnd = want
        if got["boundary"] != bnd:
            return "boundary"
        if bnd is None and (got["ret"] != ret or not got["regs_ok"]):
            return "return"
        if got["words"] != words or not got["tree_same"]:
            return "iterator"
        return None
    if want["boundary"] is not None or got["boundary"] is not None:
        if got["boundary"] != want["boundary"] or got["events"] != want["events"]:
            return "boundary"
        if want.get("out_valid") and (got["out"] is None or got["out"] != c["prefix"] + want["out"]):
            return "bytes"
        if "heap" in want and (got["heap"][:len(want["heap"])] != want["heap"] or any(got["heap"][len(want["heap"]):])):
            return "heap"
        return None
    if not got["regs_ok"] or not got["tree_same"] or not got["name_same"] or not got["tail_clean"] or got["out"] is None:
        return "machine"
    if got["ser_rest"] != c["cfg"] + c["ser_tail"][:3] or got["ptr"] != BUF_AT or got["cap"] < len(got["out"]):
        return "serializer"
    if got["events"] != want["events"]:
        return "events"
    if got["out"] != c["prefix"] + want["out"]:
        return "bytes"
    if "heap" in want and (got["heap"][:len(want["heap"])] != want["heap"] or any(got["heap"][len(want["heap"]):])):
        return "heap"
    if oracle_applies(c) and want["out"] != reference_bytes([key_record(c["tree"], k) for k in inorder_keys(c["tree"])],
                                                           c["cfg"][3], c["cfg"][4], BODIES[c["body"]]["fam"]):
        return "oracle"
    res = want["result"]
    expect = OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10 if res is None else b"".join(x.to_bytes(8, "little") for x in res)
    return None if got["result"] == expect else "result"


# ---------------------------------------------------------------- cases
PER_BODY = 1500
PER_REC = 3000
PER_NEXT = 1300
OUTCOMES = (0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000, 1 << 63, M64, 0x1234567890)
CFG_BYTES = (b"\x00\x00\x00\x00\x00", b"\x01\x01\x01\x01\x01", b"\xff\xff\xff\xff\xff", b"\x00\x01\x00\x01\x02",
             b"\x02\x00\x02\x00\x00", b"\x5a\xa5\x5a\xa5\x5a", b"\x00\x00\x00\x01\x00", b"\x00\x00\x00\x00\x02",
             b"\x00\x00\x00\x02\x02", b"\x00\x00\x00\x03\x01")
STR_LENS = (0, 0, 1, 2, 3, 5, 8, 12, 17, 30, 31, 32, 33, 40, 100, 255, 256, 300)


def rand_str(stream, big=False):
    n = stream.pick(STR_LENS) if big or stream.below(6) == 0 else stream.below(14)
    return stream.take(n) if n else b""


def rand_rec(stream, big=False):
    o = stream.pick(OUTCOMES) if stream.below(3) else int.from_bytes(stream.take(8), "little") >> stream.below(64)
    return dict(outcome=o, settle=rand_str(stream, big), details=rand_str(stream, big), name=rand_str(stream, big),
                desc=rand_str(stream, big), s1=rand_str(stream, big), s2=rand_str(stream, big))


def make_tree(stream, shape, big=False):
    """Random B-tree of the given height (-1: no root); leaves hold 1..11 records (usually few), internal nodes
    1..3; sizes are capped at 24 nodes."""
    if shape < 0:
        return Tree([], None, stream.below(4))
    nodes = []

    def build(h, parent, pidx, top):
        i = len(nodes)
        nodes.append({"keys": [], "edges": None, "parent": parent, "pidx": pidx})
        if h == 0:
            cnt = stream.pick((0, 1, 1, 2, 2, 3, 4, 11)) if top else stream.pick((1, 1, 2, 3, 11))
            if top and cnt == 11 and stream.below(2):
                cnt = 5
        else:
            cnt = stream.pick((1, 1, 2, 3)) if h > 1 else stream.pick((1, 1, 2, 3, 5))
        nodes[i]["keys"] = [rand_rec(stream, big and stream.below(4) == 0) for _ in range(cnt)]
        if h > 0:
            nodes[i]["edges"] = [build(h - 1, i, e, False) for e in range(cnt + 1)]
        return i

    for _ in range(30):
        nodes.clear()
        root = build(shape, None, 0, True)
        if len(nodes) <= 24:
            return Tree(list(nodes), root, shape)
    nodes.clear()
    root = build(0, None, 0, True)
    return Tree(list(nodes), root, 0)


def inorder_keys(tree):
    out = []

    def visit(i):
        n = tree.nodes[i]
        for j in range(len(n["keys"])):
            if n["edges"] is not None:
                visit(n["edges"][j])
            out.append((addr(i), j))
        if n["edges"] is not None:
            visit(n["edges"][-1])
    if tree.root is not None:
        visit(tree.root)
    return out


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


def length_for(stream, tree, k):
    n = tree.count()
    sel = (k // 7) % 14
    if sel < 6:
        return n, 0
    if sel == 6:
        return n + stream.below(2), 0
    if sel == 7:
        return n + 1 + stream.below(3), 0
    if sel == 8:
        return stream.below(n + 1), 0
    if sel == 9:
        return ((1 + stream.below(3)) << 32) + stream.below(n + 1), 1
    if sel == 10:
        return 0, 0
    if sel == 11:
        return (1 << 32) + stream.below(2), 1
    if sel == 12:
        return (1 << 63) + stream.below(5), 1
    return stream.pick((0xf, 0x10, 0x11, 0xffff, 0x10000, 0x10001, 0xffffffff, 0x7fffffff)), 0


def pick_cfg(stream, k):
    return CFG_BYTES[(k // 3) % len(CFG_BYTES)] if k % 5 else stream.take(5)


def make_body_case(stream, va, k):
    c = {"kind": "body", "body": va, "k": k, "prefix": stream.take(stream.below(6)), "ser_tail": stream.take(8),
         "cfg": pick_cfg(stream, k), "fault": None, "oom": False, "name": names(stream, k), "msg": (0, 0)}
    shape = {0: -1, 1: 0, 2: 0, 3: 0, 4: 1, 5: 1, 6: 1, 7: 2, 8: 0, 9: 1}[(k // 3) % 10]
    c["tree"] = make_tree(stream, shape, big=k % 11 == 0)
    c["len"], big = length_for(stream, c["tree"], k)
    big = big and c["tree"].root is not None
    c["height"] = c["tree"].height if c["tree"].root is not None else stream.below(5)
    n = c["tree"].count()
    need = 5 + 8 * 720 * 0 + 0
    c["room"] = stream.below(2200) if stream.below(3) else 2400
    if big and stream.below(5) == 0:
        c["oom"] = True
    elif stream.below(3 if big else 5) == 0:
        c["fault"] = stream.below(10 * n + 6)
    return c


def make_rec_case(stream, fam, k):
    c = {"kind": "rec", "fam": fam, "k": k, "prefix": stream.take(stream.below(6)), "ser_tail": stream.take(8),
         "cfg": pick_cfg(stream, k), "fault": None, "rec": rand_rec(stream, big=k % 4 == 0)}
    c["room"] = stream.below(900) if stream.below(3) else 1800
    if stream.below(2):
        c["fault"] = stream.below(26)
    return c


def next_states(stream, tree):
    w = iter_words(tree, tree.count() + 2 if tree.root is not None else 0)
    out = [list(w)]
    try:
        for _ in range(tree.count() + 1):
            if next_model(w, tree) is None:
                break
            out.append(list(w))
    except Panic:
        pass
    return out


def make_next_cases(stream, fn, count):
    cases, k = [], 0
    while len(cases) < count:
        tree = make_tree(stream, stream.pick((0, 0, 1, 1, 2, 2)))
        for w in next_states(stream, tree):
            if len(cases) >= count:
                break
            sel = k % 11
            w = list(w)
            if sel == 5:
                w[8] = 0
            elif sel == 6:
                w[0] = stream.pick((0, 2, 0x100000001, 0xffffffff))
            elif sel == 7:
                w[8] = (1 << 63) + stream.below(5)
            elif sel == 8:
                w[4:8] = [stream.below(1 << 63) for _ in range(4)]
            cases.append({"kind": "next", "fn": fn, "k": k, "tree": tree, "words": w, "locs": NEXT_LOCS[fn]})
            k += 1
    return cases


def output_bytes_ok(c):
    try:
        p = body_model(dict(c, msg=(0, 0), locs=NEXT_LOCS[FAMS[BODIES[c["body"]]["fam"]]["nxt"]]))
    except Wild:
        return False
    return len(p["out"]) + len(c["prefix"]) < BUF_SIZE - 64 and len(p.get("heap", b"")) < HEAP_SIZE - 64


def all_cases(per_body=PER_BODY, per_rec=PER_REC, per_next=PER_NEXT):
    cases = []
    for va in sorted(BODIES):
        stream = Stream(f"outcome-set/{va:#x}")
        k = 0
        while k < per_body:
            c = make_body_case(stream, va, k)
            if not output_bytes_ok(c):
                continue
            cases.append(c)
            k += 1
    for fam in sorted(FAMS):
        stream = Stream(f"outcome-record/{fam}")
        cases.extend(make_rec_case(stream, fam, k) for k in range(per_rec))
    for fn in sorted(NEXT_LOCS):
        stream = Stream(f"outcome-next/{fn:#x}")
        cases.extend(make_next_cases(stream, fn, per_next))
    return cases


# ---------------------------------------------------------------- static checks
NEXT_LOCS = {}
NEXTS = {FAMS[f]["nxt"]: f for f in FAMS}
SHARED_ROLES = ("hdr", "wu", "ws", "nd", "nt", "tend")


def all_functions():
    fns = {}
    for va, b in BODIES.items():
        fns[va] = "body"
        fns[b["end"]] = "real-callee"
    for f, F in FAMS.items():
        fns[F["rec"]] = "record"
        fns[F["nxt"]] = "iter-next"
        for r in SHARED_ROLES:
            if F[r] is not None:
                fns[F[r]] = "real-callee"
    return fns


def extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in all_functions():
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext


def rip_target(v, f):
    return (v + f["len"] + f["rm"][4]) & M64


def lea_targets(insns):
    return [rip_target(v, f) for v, f in insns if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip"]


def facts(image, ext, va):
    b = BODIES[va]
    F = FAMS[b["fam"]]
    insns = sweep(image, va, ext[va])
    calls = [f["target"] for _, f in insns if f["op"] == 0xe8 and f["target"] != UNWIND]
    want = [F["hdr"], F["rec"], F["nxt"], F["rec"], b["end"]]
    if calls != want:
        fail(f"body {va:#x} direct calls {[hex(x) for x in calls]}, expected {[hex(x) for x in want]}")
    gots = sorted({rip_target(v, f) for v, f in insns if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip"})
    if gots != [MALLOC_GOT, ALLOC_ERROR_GOT, FREE_GOT, COUNT_PANIC_GOT]:
        fail(f"body {va:#x} .got calls {[hex(g) for g in gots]}")
    imms = [f.get("imm") for _, f in insns if f.get("imm") is not None]
    if CFG_MASK not in imms or BUF_CAP not in imms or (1 << 63) not in [i & M64 for i in imms]:
        fail(f"body {va:#x} lacks the compound constants")
    if int.from_bytes(EXT_NAME[:8], "little") not in [i & M64 for i in imms] or int.from_bytes(EXT_NAME[8:], "little") not in imms or 10 not in imms:
        fail(f"body {va:#x} does not compare the name with {EXT_NAME!r}")
    msg = None
    for i, (v, f) in enumerate(insns):
        if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
            nxt = [g for _, g in insns[i + 1:i + 4] if g["op"] == 0xc7 and g["rm"][0] == "m"]
            if nxt:
                msg = (rip_target(v, f), nxt[0]["imm"])
    if msg is None or image.read(msg[0], msg[1]) != EXT_TEXT:
        fail(f"body {va:#x} ext-arm message is not {EXT_TEXT!r}")
    if sum(1 for _, f in insns if f["op"] == 0xc1 and f["imm"] == 0x20) != 1:
        fail(f"body {va:#x}: the shr-by-32 u32 test is not unique")
    return {"va": va, "end": ext[va], "insns": len(insns), "msg": msg}


def rec_facts(image, ext, fam):
    F = FAMS[fam]
    va = F["rec"]
    insns = sweep(image, va, ext[va])
    calls = [f["target"] for _, f in insns if f["op"] == 0xe8 and f["target"] not in (F["res"],)]
    if F["nd"] is not None:
        want = [F["wu"], F["ws"], F["ws"], F["ws"], F["nd"], F["ws"], F["nt"]]
    else:
        want = [F["wu"], F["ws"], F["ws"], F["ws"], F["hdr"], F["ws"], F["ws"], F["ws"], F["nt"]]
    if calls != want:
        fail(f"record writer {va:#x} calls {[hex(x) for x in calls]}, expected {[hex(x) for x in want]}")
    imms = {f.get("imm") & M64 for _, f in insns if f.get("imm") is not None}
    for name in KEY_NAMES:
        for pos in (0, len(name) - (8 if len(name) > 8 else 4)):
            width = 8 if len(name) > 8 else 4
            if int.from_bytes(name[pos:pos + width], "little") not in imms:
                fail(f"record writer {va:#x} lacks the inline name bytes of {name!r}")
    pool = {image.read(t, 18) for t in lea_targets(insns)}
    if NAME_DESC not in pool or SIDE_NAMES not in {image.read(t, 9) for t in lea_targets(insns)}:
        fail(f"record writer {va:#x} does not reference {NAME_DESC!r} and {SIDE_NAMES!r}")
    if SIDE_TYPE not in {image.read(t, 7) for t in lea_targets(insns)}:
        fail(f"record writer {va:#x} does not name the newtype {SIDE_TYPE!r}")
    disps = sorted({f["rm"][4] for _, f in insns if f.get("rm") and f["rm"][0] == "m" and f["rm"][1] not in ("rip", 4)})
    for need in (F_OUTCOME, 0x8, 0x10, 0x20, 0x28, 0x1b):
        if need not in disps:
            fail(f"record writer {va:#x} lacks displacement {need:#x}")
    if 0x60 not in imms:
        fail(f"record writer {va:#x} does not offset the sideNames field by 0x60")
    cmps = tuple(f["imm"] for _, f in insns if f["op"] == 0x80 and f.get("rm") and f["rm"][0] == "m" and f["rm"][1] == 15 and f["rm"][4] == 0x1b)
    if cmps != FLAG_CMPS[fam]:
        fail(f"record writer {va:#x} key tests {cmps}, expected {FLAG_CMPS[fam]}")
    return {"va": va, "end": ext[va], "insns": len(insns), "calls": len(calls), "disps": disps, "cmps": cmps}


def next_facts(image, ext, va):
    insns = sweep(image, va, ext[va])
    gots = sorted({rip_target(v, f) for v, f in insns if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip"})
    if gots != [PANIC_GOT]:
        fail(f"next {va:#x} .got calls {[hex(g) for g in gots]}")
    locs = lea_targets(insns)
    if len(locs) != 2:
        fail(f"next {va:#x} panic locations {[hex(x) for x in locs]}")
    disps = sorted({f["rm"][4] for _, f in insns if f.get("rm") and f["rm"][0] == "m" and f["rm"][1] not in ("rip", 4)})
    if not {EDGE_AT, PIDX_AT, LEN_AT, 0x40} <= set(disps):
        fail(f"next {va:#x} node displacements {disps}")
    # the key address is node + 8 + 0x98 * index
    if not any(f["op"] == 0x69 and f.get("imm") == KEY_BYTES for _, f in insns):
        fail(f"next {va:#x} does not scale the index by {KEY_BYTES:#x}")
    return {"va": va, "end": ext[va], "insns": len(insns), "locs": locs, "disps": disps}


def static_rows(image, ext):
    rows = {va: facts(image, ext, va) for va in sorted(BODIES)}
    recs = {f: rec_facts(image, ext, f) for f in sorted(FAMS)}
    nrows = {va: next_facts(image, ext, va) for va in sorted(NEXTS)}
    NEXT_LOCS.clear()
    for va, r in nrows.items():
        NEXT_LOCS[va] = tuple(r["locs"])
    return rows, recs, nrows


def machine(image, ext, override=None):
    m = CaseMachine(image, override)
    m.extents = ext
    return m


def with_msg(c, rows):
    if c["kind"] == "body":
        return dict(c, msg=rows[c["body"]]["msg"], locs=NEXT_LOCS[FAMS[BODIES[c["body"]]["fam"]]["nxt"]])
    return c


def expected(c, rows, mut):
    if c["kind"] == "body":
        return body_model(with_msg(c, rows), mut)
    if c["kind"] == "rec":
        return rec_case_model(c, mut)
    return next_expect(c, mut)


def evaluate(image, ext, rows, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except ToolError:
            if override is None:
                raise
            got = None
        why = compare(c, expected(c, rows, mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad



# ---------------------------------------------------------------- controls
MODEL_MUTANTS = ("arr-fix17", "hdr-u16", "ext-prefix", "ext-tag", "msg-len", "cfg-nomask", "split-any", "hdr-err-tag",
                 "err-no-free", "uint-80", "uint-100", "uint-10000", "uint-2e32", "str-fix33", "hdr-flag", "nt-flag",
                 "nd-eq1", "tag-any", "lazy-short", "desc-short", "edge-idx", "pidx-plus1", "len-off1")


def fam_of_fn():
    out = {}
    for va, b in BODIES.items():
        out[va], out[b["end"]] = b["fam"], b["fam"]
    for f, F in FAMS.items():
        for r in HOOK_ROLES + ("nxt",):
            if F[r] is not None:
                out[F[r]] = f
    return out


def case_fam(c):
    return BODIES[c["body"]]["fam"] if c["kind"] == "body" else (c["fam"] if c["kind"] == "rec" else NEXTS[c["fn"]])


def cases_using(results, va):
    fam = fam_of_fn()[va]
    out = []
    for c, _, _ in results:
        if case_fam(c) != fam:
            continue
        if c["kind"] == "next":
            if c["fn"] == va:
                out.append(c)
        elif va in BODIES:
            if c["kind"] == "body" and c["body"] == va:
                out.append(c)
        elif va == FAMS[fam]["nxt"]:
            continue
        else:
            out.append(c)
    return out


def byte_sites(image, ext, seen, per_body=5, per_rec=8, per_next=5, per_callee=2):
    """Byte corruptions of executed instructions: conditional jumps, 8/32/64-bit immediates and 8-bit displacements."""
    kinds = all_functions()
    targets = []
    for va in sorted(kinds):
        quota = {"body": per_body, "record": per_rec, "iter-next": per_next}.get(kinds[va], per_callee)
        targets.append((va, quota))
    sites = []
    for va, quota in targets:
        cand = []
        for v, f in sweep(image, va, ext[va]):
            if v not in seen:
                continue
            op, b = f["op"], f["bytes"]
            if 0x70 <= op <= 0x7f:
                cand.append(("jcc", v, 0x01))
            elif 0x0f80 <= op <= 0x0f8f:
                cand.append(("jcc", v + b.index(0x0f) + 1, 0x01))
            elif op in (0x83, 0xc1, 0x80, 0xc0) and "imm" in f:
                cand.append(("imm8", v + f["len"] - 1, 0x01))
            elif op in (0x81, 0x3d, 0x05, 0x69, 0xc7) and "imm" in f:
                cand.append(("imm32", v + f["len"] - 4, 0x01))
            elif 0xb8 <= op <= 0xbf:
                cand.append(("imm64" if f["rex"] & 8 else "imm32", v + f["len"] - (8 if f["rex"] & 8 else 4), 0x01))
            elif f.get("rm") and f["rm"][0] == "m" and f["rm"][1] not in ("rip", None) and f["rm"][4] and -128 <= f["rm"][4] < 128 \
                    and op not in (0x8d,):
                pos = next((i for i in range(len(b) - 1, 0, -1) if b[i] == f["rm"][4] & 0xff), None)
                if pos is not None and ("imm" not in f or pos < f["len"] - 1):
                    cand.append(("disp8", v + pos, 0x02))
        step = max(1, len(cand) // quota)
        for label, at, bit in cand[::step][:quota]:
            sites.append((va, label, at, bit))
    return sites


def range_controls(image, ext):
    out = []
    saved = {va: dict(r) for va, r in BODIES.items()}
    saved_fams = {f: dict(F) for f, F in FAMS.items()}
    try:
        BODIES[0x226c321] = dict(saved[0x226c320])
        try:
            extents(image)
            out.append(("range", "body-not-fde-start", None))
        except ToolError:
            out.append(("range", "body-not-fde-start", 0))
        del BODIES[0x226c321]
        FAMS["226"]["nxt"] = FAMS["419"]["nxt"]
        try:
            facts(image, ext, 0x226c320)
            out.append(("range", "declared-next-wrong", None))
        except ToolError:
            out.append(("range", "declared-next-wrong", 0))
        FAMS["226"]["nxt"] = saved_fams["226"]["nxt"]
        BODIES[0x226c320]["end"] = saved[0x41a70c0]["end"]
        try:
            facts(image, ext, 0x226c320)
            out.append(("range", "declared-end-wrong", None))
        except ToolError:
            out.append(("range", "declared-end-wrong", 0))
        BODIES[0x226c320]["end"] = saved[0x226c320]["end"]
        FLAG_CMPS["52f"], keep = (1, 1, 1, 1, 1), FLAG_CMPS["52f"]
        try:
            rec_facts(image, ext, "52f")
            out.append(("range", "declared-key-test-wrong", None))
        except ToolError:
            out.append(("range", "declared-key-test-wrong", 0))
        FLAG_CMPS["52f"] = keep
        FAMS["419"]["wu"] = FAMS["226"]["wu"]
        try:
            rec_facts(image, ext, "419")
            out.append(("range", "declared-uint-writer-wrong", None))
        except ToolError:
            out.append(("range", "declared-uint-writer-wrong", 0))
    finally:
        BODIES.clear()
        BODIES.update(saved)
        for f in FAMS:
            FAMS[f].clear()
            FAMS[f].update(saved_fams[f])
    try:
        next_facts(image, ext, 0x238a341)
        out.append(("range", "next-not-fde-start", None))
    except (ToolError, KeyError):
        out.append(("range", "next-not-fde-start", 0))
    try:
        Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))
        out.append(("range", "binary-digest", None))
    except ToolError:
        out.append(("range", "binary-digest", 0))
    return out


def sample_step(n, target=60):
    want = max(1, n // target)
    return max([p for p in (1, 11, 13, 17, 19, 23, 29, 31, 37) if p <= want])


def controls(image, ext, rows, results, sites):
    out, equivalent = [], []
    gots = [(c, got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(gots):
            if compare(c, expected(c, rows, frozenset(mut)), got):
                return i
        return None

    for name in MODEL_MUTANTS:
        out.append(("model", name, first_hit({name})))
    for va, label, at, bit in sites:
        every = cases_using(results, va)
        flipped = {at: image.code(at, 1)[0] ^ bit}
        cases = every[::sample_step(len(every))]
        for pick in (lambda c: c["kind"] == "body" and c["oom"],
                     lambda c: c["kind"] == "body" and c["fault"] is not None and c["len"] >> 32 and c["tree"].root is not None,
                     lambda c: c["kind"] == "body" and is_ext(c["name"]),
                     lambda c: c["kind"] == "rec" and c["fault"] is not None,
                     lambda c: c["kind"] == "rec" and c["cfg"][3] == 1 and c["fault"] is None,
                     lambda c: c["kind"] == "rec" and c["cfg"][3] not in (0, 1) and c["fault"] is None,
                     lambda c: c["kind"] == "body" and c["len"] >= 0xf and c["len"] < (1 << 32) and c["len"] > c["tree"].count()):
            cases += [c for c in [x for x in every if pick(x)][:6] if c not in cases]
        _, bad = evaluate(image, ext, rows, cases, override=flipped, stop_on_first=True)
        if bad:
            out.append(("bytes", f"{va:#x}:{label}@{at:#x}", cases.index(bad[0][0])))
        else:
            equivalent.append((va, label, at))
    out.extend(range_controls(image, ext))
    return out, equivalent


def coverage(image, ext, rows, cases):
    m = machine(image, ext)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        run_case(m, c)
    table = []
    for va in sorted(all_functions()):
        insns = [v for v, _ in sweep(image, va, ext[va])]
        table.append((va, len(insns), sum(1 for v in insns if v in seen)))
    return table, seen


def hexs(b):
    return b.hex() if b else "-"


def case_kind(c, rows):
    if c["kind"] == "next":
        w = c["words"]
        if w[8] == 0:
            return "next_empty"
        if w[0] & 0xffffffff != 1:
            return "next_bad_tag"
        return "next_lazy" if w[1] == 0 else "next_mid"
    if c["kind"] == "rec":
        if c["fault"] is not None:
            return "record_fault"
        return "record_named" if c["cfg"][3] == 1 else ("record_flag_other" if c["cfg"][3] else "record_array")
    p = body_model(with_msg(c, rows))
    if is_ext(c["name"]):
        return "ext_error"
    if p["boundary"]:
        return "alloc_error" if p["boundary"][0] == "alloc-error" else ("buffered_panic" if c["len"] >> 32 and c["tree"].root is not None else "direct_panic")
    if c["tree"].root is None or c["len"] == 0:
        return "empty_set" if p["result"] is None else "direct_fault"
    if p["result"]:
        return "buffered_fault" if c["len"] >> 32 else "direct_fault"
    return "direct_ok" + ("_oracle" if oracle_applies(c) else "")


SAMPLE_BODY = 5
SAMPLE_REC = 6
SAMPLE_NEXT = 5


def generate(out, per_body=PER_BODY, per_rec=PER_REC, per_next=PER_NEXT):
    image = Image(BINARY.read_bytes())
    ext = extents(image)
    rows, recs, nrows = static_rows(image, ext)
    t0 = time.time()
    cases = all_cases(per_body, per_rec, per_next)
    results, bad = evaluate(image, ext, rows, cases)
    print(f"evaluated {len(cases)} cases in {time.time() - t0:.0f}s", file=sys.stderr)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first {c['kind']} {c.get('body') or c.get('fam') or c.get('fn')} case {c['k']} ({why})")
    cov, seen = coverage(image, ext, rows, cases[::5])
    sites = byte_sites(image, ext, seen)
    print(f"{len(sites)} byte sites; coverage done at {time.time() - t0:.0f}s", file=sys.stderr)
    ctrl, equivalent = controls(image, ext, rows, results, sites)
    print(f"controls done at {time.time() - t0:.0f}s, {len(equivalent)} flips without witness", file=sys.stderr)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tfde_end\tinstructions\tcopy_family\theader_writer\trecord_writer\titer_next\tcompound_end\text_message_at\text_message_len"]
    for va, r in sorted(rows.items()):
        b = BODIES[va]
        F = FAMS[b["fam"]]
        lines.append(f"{va:#x}\t{r['end']:#x}\t{r['insns']}\t{b['fam']}\t{F['hdr']:#x}\t{F['rec']:#x}\t{F['nxt']:#x}\t{b['end']:#x}\t{r['msg'][0]:#x}\t{r['msg'][1]}")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["copy_family\trecord_writer\tfde_end\tinstructions\twriter_calls\tkey_test_immediates\tuint\tstr\tnameAndDescription_helper\tnewtype_helper\ttuple_end"]
    for fam, r in sorted(recs.items()):
        F = FAMS[fam]
        lines.append(f"{fam}\t{r['va']:#x}\t{r['end']:#x}\t{r['insns']}\t{r['calls']}\t{','.join(str(x) for x in r['cmps'])}\t{F['wu']:#x}\t{F['ws']:#x}\t"
                     f"{'inline' if F['nd'] is None else format(F['nd'], '#x')}\t{F['nt']:#x}\t{F['tend']:#x}")
    (out / "records.tsv").write_text("\n".join(lines) + "\n")

    lines = ["iter_next\tfde_end\tinstructions\tcopy_family\tascend_panic_location\ttag_panic_location\tnode_displacements"]
    for va, r in sorted(nrows.items()):
        lines.append(f"{va:#x}\t{r['end']:#x}\t{r['insns']}\t{NEXTS[va]}\t{r['locs'][0]:#x}\t{r['locs'][1]:#x}\t{','.join(hex(d) for d in r['disps'])}")
    (out / "iter-next.tsv").write_text("\n".join(lines) + "\n")

    lines = ["unit\tcase\tkind\tname_hex\tnodes\trecords\trecord_len\tconfig\tfault_event\toom\troom\tprefix\tout_len\tout_sha256\tresult\tevents"]
    nlines = ["iter_next\tcase\tkind\tnodes\trecords\twords_before\tret_node_offset\twords_after\tboundary"]
    digest = hashlib.sha256()
    kinds = {}
    for c, got, _ in results:
        kind = case_kind(c, rows)
        kinds[kind] = kinds.get(kind, 0) + 1
        if c["kind"] in ("body", "rec"):
            digest.update(got["out"] or b"")
            digest.update(got["result"])
            digest.update(repr(got["events"]).encode())
            short = ",".join(e_[0] for e_ in got["events"][:10]) + ("+" + str(len(got["events"]) - 10) if len(got["events"]) > 10 else "")
            step = SAMPLE_BODY if c["kind"] == "body" else SAMPLE_REC
            if c["k"] % step == 0:
                unit = f"{c['body']:#x}" if c["kind"] == "body" else f"rec-{c['fam']}"
                t = c.get("tree")
                lines.append("\t".join([unit, str(c["k"]), kind, hexs(c.get("name", b"")), "-" if t is None else str(len(t.nodes)),
                                        "1" if t is None else str(t.count()), f"{c['len']:#x}" if t is not None else "-", c["cfg"].hex(),
                                        "-" if c["fault"] is None else str(c["fault"]), "1" if c.get("oom") else "0", str(c["room"]), hexs(c["prefix"]),
                                        str(len(got["out"] or b"")), hashlib.sha256(got["out"] or b"").hexdigest()[:16], got["result"].hex(), short or "-"]))
        else:
            digest.update(repr((got["ret"], got["words"], got["boundary"])).encode())
            if c["k"] % SAMPLE_NEXT == 0:
                t = c["tree"]
                rel = "-" if not got["ret"] else f"{(got['ret'] - TREE_AT) // NODE_STRIDE}+{(got['ret'] - TREE_AT) % NODE_STRIDE:#x}"
                nlines.append("\t".join([f"{c['fn']:#x}", str(c["k"]), kind, str(len(t.nodes)), str(t.count()),
                                         ",".join(f"{x:#x}" for x in c["words"][:4] + c["words"][8:]), rel,
                                         ",".join(f"{x:#x}" for x in got["words"][:4] + got["words"][8:]),
                                         "-" if got["boundary"] is None else f"{got['boundary'][0]}:{got['boundary'][1]:#x}"]))
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")
    (out / "next-cases-sample.tsv").write_text("\n".join(nlines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\tinstruction_va_of_corruption\tkind\tnote"]
    for va, label, at in equivalent:
        lines.append(f"{va:#x}\t{at:#x}\t{label}\tno generated case distinguishes this byte flip")
    (out / "undetected-flips.tsv").write_text("\n".join(lines) + "\n")

    fns = all_functions()
    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        lines.append(f"{va:#x}\t{fns[va]}\t{n}\t{hit}")
    (out / "coverage.tsv").write_text("\n".join(lines) + "\n")

    detected = sum(1 for _, _, h in ctrl if h is not None)
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(BODIES),
        "record_writers": len(FAMS),
        "iter_next_copies": len(NEXTS),
        "body_instructions": sum(r["insns"] for r in rows.values()),
        "record_instructions": sum(r["insns"] for r in recs.values()),
        "next_instructions": sum(r["insns"] for r in nrows.values()),
        "cases": len(results),
        "case_kinds": dict(sorted(kinds.items())),
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": detected,
        "byte_flips_without_witness": len(equivalent),
    }
    if detected != len(ctrl):
        missed = [n for _, n, h in ctrl if h is None]
        fail(f"negative controls not detected: {missed}")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": len(results), "negative_controls": len(ctrl),
                                                  "negative_detected": detected}, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-body", type=int, default=PER_BODY)
    ap.add_argument("--per-rec", type=int, default=PER_REC)
    ap.add_argument("--per-next", type=int, default=PER_NEXT)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.per_body, args.per_rec, args.per_next)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
