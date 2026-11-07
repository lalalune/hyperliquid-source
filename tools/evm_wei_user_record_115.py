"""Reconstruct and verify node #115's msgpack encoders of the (wei, user) record.

The record holds a U256 `wei` at +0x00 and a 20-byte address `user` at +0x20. It is serialized as two fields in the
order wei, user by two bodies per copy family:

  wei_user_vec (0x22eae20 / 0x38c1980)  serializer = the output Vec (cap, ptr, len; struct-as-map byte +0x1b).
              Header byte ((flag ^ 1) << 4 | 0x82) & 0xff - fixmap 2 for flag 1, fixarray 2 for flag 0, any other
              flag gives whatever the shifted bits make (2 -> 0xb2, a fixstr marker; 0x11 -> fixmap 2). Names only
              when the byte is exactly 1, both pushed inline: fixstr marker 0xa3 / 0xa4 (reserve 1 only when the Vec
              is full), then the name bytes (reserve 3 / 4 when the spare capacity is <= 2 / 3).
              Values: wei -> U256 inline-Vec serializer, user (record + 0x20) -> address inline-Vec serializer.
  wei_user_ser (0x22eacf0 / 0x38c1e50)  serializer = rmp Serializer (word 0 = &Vec, struct-as-map byte +0x0b).
              Map header when the byte != 0, array header when 0 (length 2), names only when the byte == 1,
              through the rmp str writer.

Every failure is propagated without touching the output again: a header or str-writer failure (word 0 / rax != 2)
becomes (0x8000000000000000, w0, w1); a value serializer failure (word 0 != 0x8000000000000004) is copied through as
its three words; success writes only word 0 = 0x8000000000000004.

The reconstruction is `model` (class `Flow`). A concrete x86-64 evaluator runs the real bytes of all four bodies,
with RawVec::reserve, the rmp header / str writers and the value serializers replaced by recording contract stubs,
and compares the ordered calls, every byte appended to the Vec, the final capacity and length, the serializer
bytes, the 24-byte result record and the callee-saved registers. The binary is never executed.
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
ERR_TAG = 0x8000000000000000      # result word 0 for "rmp encode error carried in words 1..2"
OK_TAG = ERR_TAG | 4              # result word 0 for Ok(()) of a nested serializer
WRITER_OK = 2                     # low-level rmp writers report success as word 0 == 2
VFLAG_AT = 0x1b                   # inline-Vec serializer: struct-as-map byte
SFLAG_AT = 0x0b                   # rmp Serializer: struct-as-map byte
RECORD = 0x40                     # one case record slot (U256 wei at +0x00, 20-byte user at +0x20, then padding)
NFIELDS = 2

# Two copy families of the same two bodies (monomorphized twice; every callee is a family-local copy too).
#   vec  - record -> inline-Vec rmp (header byte and both names pushed inline: fixstr marker + immediates)
#   ser  - record -> rmp Serializer (map/array header writers, str writer)
#   json - record -> serde_json pretty Serializer (only family a has a JSON body)
FAMILY_BODIES = {
    "a": {"vec": 0x22eae20, "ser": 0x22eacf0, "json": 0x22eab20},
    "b": {"vec": 0x38c1980, "ser": 0x38c1e50},
}
# serde_json PrettyFormatter helpers that the JSON body calls; they run REAL (they are part of the JSON output):
#   key    - SerializeMap::serialize_key: "\n" (first) or ",\n", indent x current_indent, '"' escaped key '"'
#   escape - format_escaped_str_contents: copies runs of bytes whose ESCAPE table entry is 0, escapes the rest
#   end    - PrettyFormatter::end_object: current_indent - 1, "\n" + indent when has_value, then '}'
HELPERS = {"key": 0x26077c0, "escape": 0x25bf330, "end": 0x232b070}
MEMCPY_GOT = 0x64df508            # memcpy import slot used by the indent loops and the escape flush
ESCAPE_GOT = 0x64e13d8            # relocated pointer to serde_json's 256-byte ESCAPE table
JSON_PANICS = {0x64df520: "add_overflow_panic", 0x64df730: "unreachable_panic", 0x64df848: "sub_overflow_panic"}
JSON_PANIC_LOC = 0x642dc18        # Location of the current_indent + 1 overflow check in the JSON body
KIND_OF = {va: k for fam in FAMILY_BODIES.values() for k, va in fam.items()}
FAMILY_OF = {va: f for f, fam in FAMILY_BODIES.items() for va in fam.values()}
BODIES = tuple(FAMILY_BODIES["a"].values()) + tuple(FAMILY_BODIES["b"].values())
CODE = BODIES + tuple(HELPERS.values())
KIND_NAME = {"vec": "wei_user_vec", "ser": "wei_user_ser", "json": "wei_user_json"}
BODY_NAME = {va: f"{KIND_NAME[KIND_OF[va]]}/{FAMILY_OF[va]}" for va in BODIES}

# Callees that stay outside the reconstruction. Each becomes a recording contract stub.
#   reserve     - RawVec::reserve(vec, len, additional, 1, 1): grows capacity, never returns an error
#   slot_writer - (slot, ser, len): rmp map / array header writer, Ok when slot word 0 == 2
#   rax_writer  - (ser, ptr, len) -> rax/rdx: rmp str writer, Ok when rax == 2
#   nested      - (slot, &value, vec|ser): value serializer, Ok when slot word 0 == 0x8000000000000004
#   json_value  - (&value, json ser) -> rax: serde_json value serializer, Ok when rax == 0 (else a boxed error)
#   (role, kind, family a, family b)
STUBS = (
    ("vec_reserve", "reserve", 0x231e050, 0x43bd910),
    ("b160_vec", "nested", 0x298c770, 0x3d3f4f0),
    ("u256_vec", "nested", 0x29fe7f0, 0x43c40a0),
    ("map_hdr", "slot_writer", 0x25e7670, 0x3d4f6d0),
    ("arr_hdr", "slot_writer", 0x25e7940, 0x3d50270),
    ("ser_str", "rax_writer", 0x25e8750, 0x41c6110),
    ("b160_ser", "nested", 0x298ac30, 0x3d40000),
    ("u256_ser", "nested", 0x29fe6a0, 0x43c43a0),
    ("u256_json", "json_value", 0x29fed00, None),
    ("b160_json", "json_value", 0x298b150, None),
)
ROLE_KIND = {r: k for r, k, _, _ in STUBS}
ROLE_VA = {"a": {r: va for r, _, va, _ in STUBS}, "b": {r: vb for r, _, _, vb in STUBS if vb is not None}}

# The record, in serialization order. (key, value kind, record offset)
#   b160 - 20-byte address by pointer; u256 - 32-byte word by pointer
FIELDS = (
    ("wei", "u256", 0x00),
    ("user", "b160", 0x20),
)

# Regions of the evaluation
VEC_AT = 0x7180_0000_0000          # inline-Vec serializer (cap, ptr, len, .., +0x1b flag)
SVEC_AT = 0x7190_0000_0000         # the Vec behind the rmp Serializer
SER_AT = 0x71a0_0000_0000          # rmp Serializer (word 0 = &Vec, +0x0b flag) / serde_json pretty Serializer
#                                    (&Vec, indent ptr, indent len, current_indent, has_value byte +0x20)
INDENT_AT = 0x71c0_0000_0000       # the indent bytes
JSER_SIZE = 0x28
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x1000
ST_AT = 0x7300_0000_0000
NREC = 4
ST_SIZE = NREC * RECORD
OUT_AT = 0x7500_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
STACK_LO = STACK_TOP - 0x10000


# ---------------------------------------------------------------- reconstruction
def vec_marker(flag, mut=frozenset()):
    """Inline-Vec record header byte: ((flag ^ 1) << 4 | 0x82) & 0xff. flag 1 -> fixmap 2, flag 0 -> fixarray 2,
    any other flag -> whatever the shifted bits make (2 -> 0xb2, a fixstr marker; 0x11 -> 0x82, fixmap 2)."""
    if "marker-map-array-only" in mut:
        return 0x82 if flag == 1 else 0x92
    if "marker-no-mask" in mut:
        return ((flag ^ 1) << 4 | 0x82) & 0xff if flag < 16 else 0x92
    if "marker-count-six" in mut:
        return ((flag ^ 1) << 4 | 0x86) & 0xff
    return ((flag ^ 1) << 4 | 0x82) & 0xff


class Flow:
    """Python reconstruction of one run: the Vec bytes, its capacity, the ordered calls and the result record.
    Every call that a stub answers draws its words from the case plan."""

    def __init__(self, c, mut):
        self.c, self.mut = c, mut
        self.cap, self.ln = c["cap"], len(c["prefix"])
        self.out = bytearray()
        self.calls = []

    def reserve(self, add):
        self.calls.append(("vec_reserve", self.ln, add))
        self.cap = self.ln + add + self.c["extra"]

    def push(self, data):
        self.out.extend(data)
        self.ln += len(data)

    def answer(self, role, args):
        k = len(self.calls)
        self.calls.append((role,) + tuple(args))
        c = self.c
        if k < len(c["plan"]):
            return c["plan"][k] if c["fault"] == k else c["okplan"][k]
        return (0x0dead, 0x0dead, 0x0dead)

    def inline_name(self, name):
        """fixstr marker (reserve 1 only when the Vec is full), then the name bytes (reserve len(name) when the
        spare capacity after the marker is <= len(name) - 1)."""
        n = len(name)
        if self.cap == self.ln and "no-marker-reserve" not in self.mut:
            self.reserve(1)
        self.push(bytes([0xa0 | n]))
        limit = n if "reserve-lt" in self.mut else n - 1
        if self.cap - self.ln <= limit:
            self.reserve(n)
        self.push(name.encode())

    def names_on(self, flag):
        if "names-when-nonzero" in self.mut:
            return flag != 0
        if "names-when-odd" in self.mut:
            return flag & 1 == 1
        return flag == 1

    def value(self, kind, base, off, via):
        role = f"{kind}_{via}"
        if "kinds-swapped" in self.mut:
            role = ("b160_" if kind == "u256" else "u256_") + via
        at = off if "field-offset-unbased" in self.mut else base + off
        if "user-offset-0x14" in self.mut and off == 0x20:
            at = base + 0x14
        w = self.answer(role, ("stk", ("S", at), via))
        if w[0] != OK_TAG:
            if "nested-error-tag-only" in self.mut:
                return (w[0],)
            return tuple(w)
        return None

    def str_key(self, role, who, name):
        w = self.answer(role, (who, name.encode()))
        if w[0] == WRITER_OK:
            return None
        if "str-error-raw" in self.mut:
            return (w[0], w[1], w[2])
        if "str-error-low32" in self.mut:
            return (ERR_TAG, w[0] & 0xffffffff, w[1])
        return (ERR_TAG, w[0], w[1])

    def fields(self):
        rows = list(FIELDS)
        if "swap-fields" in self.mut:
            rows.reverse()
        return rows

    def record_vec(self, base):
        """0x22eae20: inline-Vec serializer of one record at S+base."""
        flag = self.c["flag"]
        if self.cap == self.ln and "no-header-reserve" not in self.mut:
            self.reserve(1)
        self.push(bytes([vec_marker(flag, self.mut)]))
        for name, kind, off in self.fields():
            if self.names_on(flag):
                self.inline_name(name)
            err = self.value(kind, base, off, "vec")
            if err:
                return err
        return (OK_TAG,)

    def record_ser(self, base):
        """0x22eacf0: rmp Serializer of one record at S+base."""
        flag = self.c["flag"]
        as_map = (flag == 1) if "map-when-one" in self.mut else flag != 0
        n = 6 if "count-six" in self.mut else NFIELDS
        w = self.answer("map_hdr" if as_map else "arr_hdr", ("stk", "ser", n))
        if (w[0] != WRITER_OK) if "header-ok-any" not in self.mut else (w[0] & 0xff) not in (WRITER_OK,):
            if "header-error-raw" in self.mut:
                return tuple(w)
            return (ERR_TAG, w[0], w[1])
        for name, kind, off in self.fields():
            if self.names_on(flag):
                err = self.str_key("ser_str", "ser", name)
                if err:
                    return err
            err = self.value(kind, base, off, "ser")
            if err:
                return err
        return (OK_TAG,)


class JsonFlow(Flow):
    """0x22eab20 and the three real PrettyFormatter helpers it calls."""

    def byte(self, b):
        if self.cap == self.ln and "json-no-byte-reserve" not in self.mut:
            self.reserve(1)
        self.push(bytes([b]))

    def two(self, data):
        if self.cap - self.ln <= (0 if "json-two-reserve-lt" in self.mut else 1):
            self.reserve(2)
        self.push(data)

    def indent(self, n):
        text = self.c["indent"]
        if n == 0 or not text:
            return
        for _ in range(n + 1 if "indent-one-more" in self.mut else n):
            if len(text) > self.cap - self.ln:
                self.reserve(len(text))
            self.push(text)

    def escape(self, raw):
        # format_escaped_str_contents: the keys hold no byte with a non-zero ESCAPE entry, so the whole key is one
        # run, flushed by reserve-if-short + memcpy.
        if len(raw) > self.cap - self.ln or "escape-always-reserve" in self.mut:
            self.reserve(len(raw))
        self.push(raw)

    def record_json(self, base):
        cur = self.c["cur"]
        if cur == M64 and "indent-wraps" not in self.mut:
            return ("panic",)
        cur = (cur + 1) & M64
        self.cur, self.has = cur, 0
        self.byte(0x7b)
        first = True
        for name, kind, off in self.fields():
            if first or "always-newline" in self.mut:
                self.byte(0x0a)
            else:
                self.two(b",\n")
            first = False
            self.indent(cur - 1 if "indent-before-inc" in self.mut else cur)
            self.byte(0x22)
            self.escape(name.encode())
            self.byte(0x22)
            self.two(b": ")
            role = f"{kind}_json"
            if "kinds-swapped" in self.mut:
                role = ("b160_" if kind == "u256" else "u256_") + "json"
            at = base + off
            if "user-offset-0x14" in self.mut and off == 0x20:
                at = base + 0x14
            w = self.answer(role, (("S", at), "ser"))
            if w[0] != 0:
                return ("err", w[0])
            if "has-value-unset" not in self.mut:
                self.has = 1
        cur -= 1
        if "end-keeps-indent" not in self.mut:
            self.cur = cur
        if self.has and "end-no-newline" not in self.mut:
            self.byte(0x0a)
            self.indent(cur)
        self.byte(0x7d)
        return ("ok",)


def model(c, mut=frozenset()):
    """Predict calls, appended Vec bytes, final capacity/length and the result record (rmp bodies) or
    (result, current_indent, has_value) (JSON body)."""
    if KIND_OF[c["body"]] == "json":
        f = JsonFlow(c, mut)
        f.cur, f.has = c["cur"], c["has_in"]
        res = f.record_json(c["base"])
        return f.calls, bytes(f.out), f.cap, f.ln, (res, f.cur, f.has)
    f = Flow(c, mut)
    if KIND_OF[c["body"]] == "vec":
        res = f.record_vec(c["base"])
    else:
        res = f.record_ser(c["base"])
    return f.calls, bytes(f.out), f.cap, f.ln, res


# ---------------------------------------------------------------- evaluation
def uses_ser(c):
    return KIND_OF[c["body"]] in ("ser", "json")


def arg_ptr(m, v):
    if ST_AT <= v < ST_AT + ST_SIZE:
        return ("S", v - ST_AT)
    if STACK_LO <= v < STACK_TOP:
        return ("stack", bytes(m.load(v + i, 1) for i in range(16)))
    return ("ptr", v)


def who(v):
    return {VEC_AT: "vec", SVEC_AT: "vec", SER_AT: "ser"}.get(v, ("ptr", v))


def text_at(m, ptr, n):
    if n > 64:
        return ("long", ptr, n)
    try:
        return bytes(m.load(ptr + i, 1) for i in range(n))
    except ToolError:
        return ("bad", ptr, n)


def slot_of(v):
    if STACK_LO <= v < STACK_TOP:
        return "stk"
    if v == OUT_AT:
        return "out"
    return ("ptr", v)


def plan_for(c, k):
    if k < len(c["plan"]):
        return c["plan"][k] if c["fault"] == k else c["okplan"][k]
    return (0x0dead, 0x0dead, 0x0dead)


def install(m, c, vec_at):
    m.calls = []

    def reserve(m):
        r = m.regs
        if r[7] != vec_at or r[1] != 1 or r[8] != 1 or r[6] != m.load(vec_at + 0x10, 8):
            fail("reserve called outside its contract")
        ln, add = r[6], r[2]
        if ln + add + c["extra"] > BUF_SIZE:
            fail("case output larger than the buffer region")
        m.calls.append(("vec_reserve", ln, add))
        m.store(vec_at, 8, ln + add + c["extra"])
        for x in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            r[x] = 0x0dead_0000 | x

    def make(role):
        kind = ROLE_KIND[role]

        def stub(m):
            r = m.regs
            k = len(m.calls)
            if kind == "json_value":
                rec = (role, arg_ptr(m, r[7]), who(r[6]))
            elif kind == "rax_writer":
                rec = (role, who(r[7]), text_at(m, r[6], r[2]))
            elif kind == "slot_writer":
                rec = (role, slot_of(r[7]), who(r[6]), r[2])
            else:
                rec = (role, slot_of(r[7]), arg_ptr(m, r[6]), who(r[2]))
            m.calls.append(rec)
            w = plan_for(c, k)
            if kind == "json_value":
                r[0] = w[0]
            elif kind == "rax_writer":
                r[0], r[2] = w[0], w[1]
            else:
                if slot_of(r[7]) not in ("stk", "out"):
                    fail("result slot is neither the stack nor the case output")
                for i in range(3):
                    m.store(r[7] + 8 * i, 8, w[i])
                r[0] = r[7]
            for x in (1, 6, 7, 8, 9, 10, 11):
                r[x] = 0x0dead_0000 | x
        return stub

    def memcpy(m):
        r = m.regs
        if r[2] > BUF_SIZE:
            fail("memcpy length outside the case buffers")
        for i in range(r[2]):
            m.store(r[7] + i, 1, m.load(r[6] + i, 1))
        r[0] = r[7]
        for x in (1, 2, 6, 7, 8, 9, 10, 11):
            r[x] = 0x0dead_0000 | x

    for role, va in ROLE_VA[FAMILY_OF[c["body"]]].items():
        m.stubs[va] = reserve if role == "vec_reserve" else make(role)
    if KIND_OF[c["body"]] == "json":
        m.stubs[m.image.word(MEMCPY_GOT)] = memcpy
        for got, name in JSON_PANICS.items():
            m.stubs[m.image.word(got)] = name


def run_json_case(m, c):
    """0x22eab20(record, serializer): the serializer is a serde_json pretty Serializer whose Vec is SVEC_AT."""
    m.reset()
    install(m, c, SVEC_AT)
    svec = bytearray(c["svec"])
    put(svec, 0, 8, c["cap"])
    put(svec, 8, 8, BUF_AT)
    put(svec, 0x10, 8, len(c["prefix"]))
    ser = bytearray(c["jser"])
    put(ser, 0, 8, SVEC_AT)
    put(ser, 8, 8, INDENT_AT)
    put(ser, 0x10, 8, len(c["indent"]))
    put(ser, 0x18, 8, c["cur"])
    ser[0x20] = c["has_in"]
    inputs = (bytes(ser), bytes(ser))
    sreg = m.add_region(SVEC_AT, 0x18, bytes(svec[:0x18]))
    serreg = m.add_region(SER_AT, JSER_SIZE, bytes(ser))
    ireg = m.add_region(INDENT_AT, 0x40, c["indent"])
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"])
    st = m.add_region(ST_AT, ST_SIZE, bytes(c["st"]))
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = ST_AT + c["base"], SER_AT
    panic = None
    try:
        m.run(c["body"], limit=200000)
    except Boundary as b:
        if b.kind not in JSON_PANICS.values():
            raise
        panic = (b.kind, b.regs[7])
    ln = m.load(SVEC_AT + 0x10, 8)
    return {"calls": list(m.calls), "result": m.regs[0].to_bytes(8, "little"), "vec": bytes(sreg),
            "st": bytes(st), "rax": m.regs[0], "buf": bytes(buf[:min(ln, BUF_SIZE)]),
            "tail": bytes(buf[min(ln, BUF_SIZE):]), "len": ln, "comp": b"", "ser": bytes(serreg), "inputs": inputs,
            "indent": bytes(ireg), "panic": panic,
            "regs_ok": panic is not None or ([m.regs[k] for k in SAVED_REGS] == list(SAVED)
                                             and m.regs[4] == STACK_TOP - 0x100)}


def run_case(m, c):
    if KIND_OF[c["body"]] == "json":
        return run_json_case(m, c)
    m.reset()
    ser_side = uses_ser(c)
    vec_at = SVEC_AT if ser_side else VEC_AT
    install(m, c, vec_at)
    comp = bytearray(c["comp"])
    svec = bytearray(c["svec"])
    target = svec if ser_side else comp
    put(target, 0, 8, c["cap"])
    put(target, 8, 8, BUF_AT)
    put(target, 0x10, 8, len(c["prefix"]))
    ser = bytearray(c["ser"])
    put(ser, 0, 8, SVEC_AT)
    if ser_side:
        ser[SFLAG_AT] = c["flag"]
    else:
        comp[VFLAG_AT] = c["flag"]
    inputs = (bytes(comp), bytes(ser))
    creg = m.add_region(VEC_AT, 0x30, bytes(comp))
    sreg = m.add_region(SVEC_AT, 0x18, bytes(svec[:0x18]))
    serreg = m.add_region(SER_AT, 0x10, bytes(ser))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"])
    st = m.add_region(ST_AT, ST_SIZE, bytes(c["st"]))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, ST_AT + c["base"], VEC_AT if not ser_side else SER_AT
    m.run(c["body"], limit=200000)
    vreg = sreg if ser_side else creg
    ln = m.load(vec_at + 0x10, 8)
    return {"calls": list(m.calls), "result": bytes(out), "vec": bytes(vreg), "st": bytes(st), "rax": m.regs[0],
            "buf": bytes(buf[:min(ln, BUF_SIZE)]), "tail": bytes(buf[min(ln, BUF_SIZE):]), "len": ln,
            "comp": bytes(creg), "ser": bytes(serreg), "inputs": inputs,
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100}


def match_call(want, got):
    if len(want) != len(got) or want[0] != got[0]:
        return False
    return all(w == g for w, g in zip(want[1:], got[1:]))


def result_bytes(res):
    if len(res) == 1:
        return res[0].to_bytes(8, "little") + b"\x5a" * 0x10
    return b"".join((x & M64).to_bytes(8, "little") for x in res)


def compare_json(c, want, got):
    calls, data, cap, ln, (res, cur, has) = want
    if not got["regs_ok"]:
        return "machine"
    if got["st"] != bytes(c["st"]) or got["indent"][:len(c["indent"])] != c["indent"]:
        return "inputs"
    if res == ("panic",):
        if got["panic"] != ("add_overflow_panic", JSON_PANIC_LOC):
            return "panic"
        return None if not got["calls"] and got["len"] == len(c["prefix"]) and got["ser"] == got["inputs"][0] \
            else "panic"
    if got["panic"] is not None:
        return "panic"
    if len(calls) != len(got["calls"]) or not all(match_call(w, g) for w, g in zip(calls, got["calls"])):
        return "calls"
    if got["len"] != ln or got["buf"] != c["prefix"] + data or any(got["tail"]):
        return "bytes"
    if u(got["vec"], 0, 8) != cap or u(got["vec"], 8, 8) != BUF_AT:
        return "capacity"
    ser0 = got["inputs"][0]
    if u(got["ser"], 0x18, 8) != cur or got["ser"][0x20] != has:
        return "serializer"
    if got["ser"][:0x18] != ser0[:0x18] or got["ser"][0x21:] != ser0[0x21:]:
        return "serializer"
    if got["rax"] != (0 if res == ("ok",) else res[1]):
        return "result"
    return None


def compare(c, want, got):
    """First difference between the model and the machine, or None."""
    if got is None:
        return "tool-error"
    if KIND_OF[c["body"]] == "json":
        return compare_json(c, want, got)
    calls, data, cap, ln, res = want
    if not got["regs_ok"]:
        return "machine"
    if got["st"] != bytes(c["st"]):
        return "inputs"
    if len(calls) != len(got["calls"]) or not all(match_call(w, g) for w, g in zip(calls, got["calls"])):
        return "calls"
    if got["len"] != ln or got["buf"] != c["prefix"] + data or any(got["tail"]):
        return "bytes"
    if u(got["vec"], 0, 8) != cap or u(got["vec"], 8, 8) != BUF_AT:
        return "capacity"
    comp0, ser0 = got["inputs"]
    if uses_ser(c):
        if got["ser"] != ser0 or got["comp"] != comp0:
            return "serializer"
    elif got["comp"][0x18:] != comp0[0x18:]:
        return "serializer"
    if got["rax"] != OUT_AT:
        return "machine"
    if got["result"] != result_bytes(res):
        return "result"
    return None


# ---------------------------------------------------------------- cases
CASES = {"vec": 4000, "ser": 4000, "json": 6000}   # per body
INDENTS = (b"  ", b"  ", b"\t", b"", b"    ", b" ", b"\t\t", b"--", b" " * 9)
CURS = (0, 0, 1, 2, 3, 1, 5, M64, M64 - 1)
FLAGS = (0, 1, 1, 1, 0, 2, 0x80, 0xff, 1, 0, 1, 3, 0x10, 0x11, 0x21, 0xfe)
SLACK = tuple(range(0, 16)) + (40, 120, 400)


def plan_words(stream, kind):
    """(ok words, failing words) for one stubbed call."""
    junk = (int.from_bytes(stream.take(8), "little"), int.from_bytes(stream.take(8), "little"))
    if kind == "json_value":
        return (0,) + junk, (stream.pick((1, ERR_TAG, 0x7f00_0000_0010, int.from_bytes(stream.take(8), "little")
                                          | 1 << 63)),) + junk
    if kind in ("rax_writer", "slot_writer", "reserve"):
        okw = WRITER_OK
        bad = stream.pick((0, 1, 3, 0x102, OK_TAG, ERR_TAG, int.from_bytes(stream.take(8), "little") | 1 << 40))
    else:
        okw = OK_TAG
        bad = stream.pick((WRITER_OK, ERR_TAG, ERR_TAG | 3, ERR_TAG | 5, 0, OK_TAG | 1 << 32,
                           int.from_bytes(stream.take(8), "little") | 1 << 40))
    return (okw,) + junk, (bad,) + junk


def fill_plan(stream, c):
    """Grow the per-call word plan along the fault-free path until the call list is stable, then pick the failing
    call: k % (n + 2), so every call position fails in turn and two of every n + 2 cases run fault-free."""
    for _ in range(64):
        calls = model(c)[0]
        if len(calls) <= len(c["plan"]):
            break
        for rec in calls[len(c["plan"]):]:
            ok, bad = plan_words(stream, ROLE_KIND[rec[0]])
            c["okplan"].append(ok)
            c["plan"].append(bad)
    else:
        fail("case plan does not converge")
    n, k = len(calls), c["k"]
    c["fault"] = k % (n + 2) if k % (n + 2) < n else -1
    if c["fault"] >= 0 and calls[c["fault"]][0] == "vec_reserve":
        c["fault"] = -1  # reserve cannot fail (it aborts instead of returning an error)
    return c


def body_case(stream, body, k):
    st = bytearray(stream.take(ST_SIZE))
    flag = FLAGS[k % len(FLAGS)] if k % 17 else stream.below(256)
    if k % 23 == 5:
        prefix = stream.take(stream.below(3000))  # long Vec: lengths with high bits set in the spare-capacity test
    else:
        prefix = stream.take(stream.below(24))
    ln = len(prefix)
    cap = ln + stream.pick(SLACK)
    if k % 3 == 0:
        cap = ln + stream.below(9)  # tight: every inline push meets the reserve tests at its edges
    c = {"body": body, "k": k, "st": st, "base": RECORD * stream.below(NREC), "comp": bytearray(stream.take(0x30)),
         "svec": bytearray(stream.take(0x18)), "ser": bytearray(stream.take(0x10)), "flag": flag, "prefix": prefix,
         "cap": cap, "extra": stream.pick((0, 0, 1, 3, 17)), "fault": -1, "plan": [], "okplan": []}
    if KIND_OF[body] == "json":
        c["jser"] = bytearray(stream.take(JSER_SIZE))
        c["indent"] = stream.pick(INDENTS) if k % 11 else stream.take(1 + stream.below(12))
        c["cur"] = stream.pick(CURS)
        if c["cur"] == M64 - 1:
            c["indent"] = b""  # a non-empty indent would repeat 2^64 - 1 times
        c["has_in"] = stream.pick((0, 1, 0x5a))
    return fill_plan(stream, c)


def all_cases(scale=1.0):
    out = []
    for body in BODIES:
        s = Stream(f"evm-wei-user-record-115/{body:#x}")
        for k in range(int(CASES[KIND_OF[body]] * scale)):
            out.append(body_case(s, body, k))
    return out


# ---------------------------------------------------------------- static rows
def extents(image):
    rows = fde_rows(image, set(CODE))
    return {va: rows[va][1] for va in CODE}


def direct_calls(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] in (0xe8, 0xe9) and not (va <= f["target"] < end):
            out.append((v, "call" if f["op"] == 0xe8 else "tail", f["target"]))
        elif (0x70 <= f["op"] <= 0x7f or 0x0f80 <= f["op"] <= 0x0f8f) and not (va <= f["target"] < end):
            out.append((v, "jcc", f["target"]))
        elif f["op"] == 0xff and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append((v, "got", image.word((v + f["len"] + f["rm"][4]) & M64)))
    return out


def rip_texts(image, insns):
    """lea reg, [rip+d] targets that hold one of the record's names (read as bytes from the file)."""
    names = {n.encode() for n, _, _ in FIELDS}
    out = []
    for v, f in insns:
        if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
            at = (v + f["len"] + f["rm"][4]) & M64
            for n in sorted(names):
                try:
                    if image.read(at, len(n)) == n:
                        out.append((v, at, n.decode()))
                except ToolError:
                    pass
    return out


def inline_names(image, insns):
    """Name bytes stored by `mov` immediates (fixstr name bodies pushed inline): imm32 stores and imm16 stores."""
    out = []
    for v, f in insns:
        if f["op"] in (0xc6, 0xc7, *range(0xb8, 0xc0)) and f.get("imm") is not None and f["imm"] > 0x5f:
            n = f["len"] - (f["len"] - 1 if f["op"] == 0xc6 else 0)
            raw = f["imm"].to_bytes(8, "little").rstrip(b"\0")
            if raw.isascii() and all(0x61 <= b <= 0x7a for b in raw):
                out.append((v, raw.decode()))
    return out


def flag_tests(insns):
    out = []
    for v, f in insns:
        if f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m" and f["rm"][4] in (VFLAG_AT, SFLAG_AT):
            out.append((v, f["rm"][4], f["imm"]))
    return out


def header_ops(insns):
    """The inline-Vec header arithmetic: (xor imm, shl imm, or imm) on the flag byte register."""
    xs = [f["imm"] for _, f in insns if f["op"] in (0x80, 0x83) and f["reg"] & 7 == 6 and f["rm"][0] == "r"]
    ss = [f["imm"] for _, f in insns if f["op"] == 0xc0 and f["reg"] & 7 == 4]
    os_ = [f["imm"] for _, f in insns if f["op"] in (0x80, 0x83) and f["reg"] & 7 == 1 and f["rm"][0] == "r"]
    return [x & 0xff for x in xs], [x & 0xff for x in ss], [x & 0xff for x in os_]


def body_row(image, ext, va):
    insns = sweep(image, va, ext[va])
    calls = direct_calls(image, va, ext[va])
    role_of = {v: r for r, v in ROLE_VA[FAMILY_OF.get(va, "a")].items()}
    role_of.update({v: "helper_" + n for n, v in HELPERS.items()})
    role_of.update({image.word(g): n for g, n in JSON_PANICS.items()})
    role_of[image.word(MEMCPY_GOT)] = "memcpy"
    names = rip_texts(image, insns)
    leas = [(v + f["len"] + f["rm"][4]) & M64 for v, f in insns
            if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip"]
    return {"end": ext[va], "size": ext[va] - va, "insns": len(insns), "leas": leas,
            "calls": [(v, how, t, role_of.get(t, "?")) for v, how, t in calls],
            "names": names, "inline": inline_names(image, insns), "flags": flag_tests(insns),
            "header": header_ops(insns)}


def check_static(rows):
    """The facts the model takes from the bytes, re-derived and asserted for both families."""
    for name, fam in FAMILY_BODIES.items():
        check_family(name, {k: rows[va] for k, va in fam.items()})
    check_json(rows)


def check_json(rows):
    r = rows[FAMILY_BODIES["a"]["json"]]
    seq = [(x[1], x[2]) for x in r["calls"] if x[1] in ("call", "tail", "got")]
    want = [("call", HELPERS["key"]), ("call", 0x29fed00), ("call", HELPERS["key"]), ("call", 0x298b150),
            ("call", HELPERS["end"])]
    if [x for x in seq if x[0] == "call" and x[1] != 0x231e050] != want:
        fail(f"wei_user_json call order changed: {seq}")
    if [n for _, _, n in r["names"]] != ["wei", "user"]:
        fail(f"wei_user_json key texts changed: {r['names']}")
    if JSON_PANIC_LOC not in r["leas"]:
        fail("wei_user_json panic Location lea changed")
    if r["inline"]:
        fail("wei_user_json stores name immediates")
    for name, va in HELPERS.items():
        hr = rows[va]
        tails = [x[2] for x in hr["calls"] if x[1] == "call"]
        if name == "key" and sorted(tails) != sorted([HELPERS["escape"]] + [0x231e050] * 5):
            fail(f"key writer callees changed: {[hex(x) for x in tails]}")
        if name in ("escape", "end") and set(tails) != {0x231e050}:
            fail(f"{name} helper callees changed: {[hex(x) for x in tails]}")


def check_family(name, rows):
    r = rows["vec"]
    roles = [x[3] for x in r["calls"] if x[1] in ("call", "tail")]
    if [x for x in roles if x != "vec_reserve"] != ["u256_vec", "b160_vec"]:
        fail(f"family {name}: wei_user_vec call order changed: {roles}")
    if roles.count("vec_reserve") != 5:
        fail(f"family {name}: wei_user_vec reserve sites changed: {roles}")
    # "wei" is stored as `mov byte [+2], 'i'` then `mov word [+0], "we"`; "user" as one dword immediate.
    if [n for _, n in r["inline"]] != ["i", "we", "user"]:
        fail(f"family {name}: wei_user_vec inline names changed: {r['inline']}")
    if [(o, i) for _, o, i in r["flags"]] != [(VFLAG_AT, 1)] * 2:
        fail(f"family {name}: wei_user_vec flag tests changed: {r['flags']}")
    if tuple([x & 0xff for x in part] for part in r["header"]) != ([1], [4], [0x82]):
        fail(f"family {name}: wei_user_vec header arithmetic changed: {r['header']}")
    r = rows["ser"]
    roles = [x[3] for x in r["calls"] if x[1] in ("call", "tail")]
    if roles != ["map_hdr", "arr_hdr", "ser_str", "u256_ser", "ser_str", "b160_ser"]:
        fail(f"family {name}: wei_user_ser call order changed: {roles}")
    if [n for _, _, n in r["names"]] != ["wei", "user"]:
        fail(f"family {name}: wei_user_ser key texts changed: {r['names']}")
    if [(o, i) for _, o, i in r["flags"]] != [(SFLAG_AT, 0), (SFLAG_AT, 1), (SFLAG_AT, 1)]:
        fail(f"family {name}: wei_user_ser flag tests changed: {r['flags']}")


# ---------------------------------------------------------------- controls
def machine(image, override=None):
    return TraceMachine(image, override)


def evaluate(image, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, override)
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except (ToolError, Boundary):
            if override is None and not mut:
                raise
            got = None
        why = compare(c, model(c, mut), got)
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad, m


MODEL_MUTANTS = (
    "marker-map-array-only", "marker-no-mask", "marker-count-six", "no-header-reserve", "no-marker-reserve",
    "reserve-lt", "names-when-nonzero", "names-when-odd", "kinds-swapped", "field-offset-unbased",
    "user-offset-0x14", "nested-error-tag-only", "str-error-raw", "str-error-low32", "swap-fields", "map-when-one",
    "count-six", "header-ok-any", "header-error-raw",
    "json-no-byte-reserve", "json-two-reserve-lt", "indent-one-more", "escape-always-reserve", "indent-wraps",
    "always-newline", "indent-before-inc", "has-value-unset", "end-keeps-indent", "end-no-newline",
)

IMM8_OPS = (0x80, 0x83, 0xc6, 0xc0, 0xc1)

# Flip patterns other than bit 0 where bit 0 gives the same machine for every reachable state:
#   0x22eac31 `cmpb $0, state` -> $1 still calls end_object for state 2 (Rest); $2 skips it.
#   0x26078c6 `movb $2, state` (Rest) -> 3 still reads as "not First"; 1 makes the next key write "\n" again.
SITE_XOR = {0x22eac31: 0x02, 0x26078c6: 0x03}
# Immediates of the escape scan loop that only decide whether the scan stops at or one byte past the key end. With
# the escape-free keys wei/user the flush writes the same bytes either way, so these two flips are equivalent
# mutants by construction and are excluded (listed here, counted in summary.json, asserted by the tests).
EQUIVALENT_SITES = {
    0x25bf34f: "escape scan start index (1 -> 0): the key is flushed from its start pointer with its full length",
    0x25bf364: "escape scan end test (1 -> 0): the last scanned byte is never escapable for wei/user",
}


def byte_sites(image, ext, reached):
    """Bytes whose change must be visible: one byte of every immediate operand of the four bodies that the cases
    reach (flag tests, header xor/shift/or, fixstr markers, name bytes, spare-capacity tests, reserve sizes, field
    lengths, record offset), except stack-frame arithmetic and the constant ERR/OK tag words, which are flipped in
    their top byte (the low byte of 0x8000000000000004 is the Ok tag and must be seen too)."""
    sites = []
    for va in CODE:
        owner = va if va in BODIES else FAMILY_BODIES["a"]["json"]
        for v, f in sweep(image, va, ext[va]):
            if f.get("imm") is None or f["op"] in (0xe8, 0xe9) or 0x70 <= f["op"] <= 0x7f or v not in reached:
                continue
            if f["op"] in (0x0f80,) or f["op"] & 0xfff0 == 0x0f80:
                continue
            raw = image.read(v, f["len"])
            if f["op"] in (0x83, 0x81) and f["rm"][0] == "r" and f["rm"][1] == 4:
                continue  # rsp adjust
            if f["op"] in IMM8_OPS:
                at = v + f["len"] - 1
            elif f["op"] in (0x81, 0xc7) or 0xb8 <= f["op"] <= 0xbf and f["len"] in (5, 6):
                at = v + f["len"] - 4
            elif 0xb8 <= f["op"] <= 0xbf and f["len"] == 10:
                at = v + f["len"] - 8
                sites.append({"body": owner, "insn": v, "at": v + f["len"] - 1, "old": raw[-1], "xor": 0x01})
            elif f["op"] == 0x66c7 or (f["op"] == 0xc7 and f["len"] >= 6):
                at = v + f["len"] - 2
            else:
                continue
            if v in EQUIVALENT_SITES:
                continue
            sites.append({"body": owner, "insn": v, "at": at, "old": raw[at - v], "xor": SITE_XOR.get(v, 0x01)})
    return sites


def controls(image, cases, sites):
    rows = []
    by_body = {}
    for c in cases:
        by_body.setdefault(c["body"], []).append(c)
    for mut in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, cases, frozenset([mut]), stop_on_first=True)
        rows.append({"control": f"model:{mut}", "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    for s in sites:
        override = {s["at"]: s["old"] ^ s["xor"]}
        _, bad, _ = evaluate(image, by_body[s["body"]], override=override, stop_on_first=True)
        rows.append({"control": f"byte:{s['body']:#x}:{s['insn']:#x}:{s['at']:#x}:{s['old']:02x}^{s['xor']:02x}",
                     "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    return rows


# ---------------------------------------------------------------- output
SAMPLE_STEP = 7   # every 7th case of each body; all 22,000 are hashed into summary.json


def hexs(b):
    return b.hex() if b else "-"


def call_text(rec):
    parts = [rec[0]]
    for a in rec[1:]:
        if isinstance(a, bytes):
            parts.append(a.decode("ascii", "replace"))
        elif isinstance(a, tuple) and a[0] == "S":
            parts.append(f"S+{a[1]:#x}")
        elif isinstance(a, tuple) and a[0] == "stack":
            parts.append("stack:" + a[1][:8].hex())
        elif isinstance(a, int):
            parts.append(f"{a:#x}")
        else:
            parts.append(str(a))
    return " ".join(parts)


def generate(out, scale=1.0):
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail("node #115 digest mismatch")
    image = Image(data)
    ext = extents(image)
    rows = {va: body_row(image, ext, va) for va in CODE}
    check_static(rows)
    cases = all_cases(scale)
    results, bad, m = evaluate(image, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first {c['body']:#x}/{c['k']}: {why}")
    reached = m.seen
    sites = byte_sites(image, ext, reached)
    ctl = controls(image, cases, sites)
    missed = [r["control"] for r in ctl if not r["detected"]]
    if missed:
        fail(f"undetected controls: {missed}")
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\trole\tend\tbytes\tinstructions\treached\tflag_tests\tkey_texts\theader_xor_shl_or"]
    cov = ["body\tinstruction\tlength\treason"]
    for va in CODE:
        insns = sweep(image, va, ext[va])
        hit = sum(1 for v, _ in insns if v in reached)
        r = rows[va]
        flags = ",".join(f"+{o:#x}=={i}" for _, o, i in r["flags"]) or "-"
        texts = ",".join([n for _, _, n in r["names"]] + [f"imm:{n}" for _, n in r["inline"]]) or "-"
        hdr = "/".join(",".join(f"{x:#x}" for x in part) or "-" for part in r["header"])
        lines.append(f"{va:#x}\t{BODY_NAME.get(va) or HELPER_NAME[va]}\t{r['end']:#x}\t{r['size']}\t{r['insns']}\t{hit}\t{flags}\t{texts}"
                     f"\t{hdr}")
        for v, f in insns:
            if v not in reached:
                cov.append(f"{va:#x}\t{v:#x}\t{f['len']}\t{unreached_why(va, v)}")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")
    (out / "unreached.tsv").write_text("\n".join(cov) + "\n")

    crow = ["body\tsite\tkind\ttarget\trole"]
    for va in CODE:
        for v, how, t, role in rows[va]["calls"]:
            crow.append(f"{va:#x}\t{v:#x}\t{how}\t{t:#x}\t{role}")
    (out / "callees.tsv").write_text("\n".join(crow) + "\n")

    frow = ["index\tkey\tvalue_kind\trecord_offset\tvec_key_how\tvec_role\tser_role"]
    for i, (name, kind, off) in enumerate(FIELDS):
        frow.append(f"{i}\t{name}\t{kind}\t{off:#x}\tinline\t{kind}_vec\t{kind}_ser")
    (out / "fields.tsv").write_text("\n".join(frow) + "\n")

    srow = ["role\tkind\tfamily_a\tfamily_b"]
    for role, kind, va, vb in STUBS:
        srow.append(f"{role}\t{kind}\t{va:#x}\t{vb:#x}" if vb is not None else f"{role}\t{kind}\t{va:#x}\t-")
    (out / "stubs.tsv").write_text("\n".join(srow) + "\n")

    rows_out = ["body\tcase\tflag\tfault\trecord\tprefix_len\tcap\textra\tfinal_len\tfinal_cap\tresult\tappended"
                "\tcall_list"]
    for c, got, _ in results:
        if c["k"] % SAMPLE_STEP:
            continue
        rows_out.append(f"{c['body']:#x}\t{c['k']}\t{c['flag']:#x}\t{c['fault']}\t{c['base'] // RECORD}\t"
                        f"{len(c['prefix'])}\t{c['cap']}\t{c['extra']}\t{got['len']}\t{u(got['vec'], 0, 8)}\t"
                        f"{got['result'].hex()}\t{hexs(got['buf'][len(c['prefix']):])}\t"
                        + " | ".join(call_text(r) for r in got["calls"]))
    (out / "cases-sample.tsv").write_text("\n".join(rows_out) + "\n")

    crows = ["control\tdetected\twitness"]
    for r in ctl:
        crows.append(f"{r['control']}\t{'yes' if r['detected'] else 'no'}\t{r['witness']}")
    (out / "controls.tsv").write_text("\n".join(crows) + "\n")

    by = {}
    for c, got, _ in results:
        d = by.setdefault(f"{c['body']:#x}", {"cases": 0, "ok": 0, "error": 0, "panic": 0, "reserve_calls": 0,
                                              "flag_one": 0, "flag_zero": 0, "flag_other": 0})
        d["cases"] += 1
        if KIND_OF[c["body"]] == "json":
            d["ok" if got["panic"] is None and got["rax"] == 0 else "panic" if got["panic"] else "error"] += 1
        else:
            d["ok" if got["result"][:8] == OK_TAG.to_bytes(8, "little") else "error"] += 1
        d["reserve_calls"] += sum(1 for r in got["calls"] if r[0] == "vec_reserve")
        d["flag_one" if c["flag"] == 1 else "flag_zero" if c["flag"] == 0 else "flag_other"] += 1
    digest = hashlib.sha256()
    for c, got, _ in results:
        digest.update(f"{c['body']:#x}/{c['k']}/{got['result'].hex()}/{got['buf'].hex()}/{got['vec'].hex()}/"
                      f"{'|'.join(call_text(r) for r in got['calls'])}\n".encode())
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(BODIES),
        "body_instructions": sum(len(sweep(image, va, ext[va])) for va in BODIES),
        "body_instructions_reached": sum(1 for va in BODIES for v, _ in sweep(image, va, ext[va]) if v in reached),
        "cases": len(results),
        "mismatches": 0,
        "controls": len(ctl),
        "controls_detected": sum(1 for r in ctl if r["detected"]),
        "model_mutants": len(MODEL_MUTANTS),
        "byte_flips": len(sites),
        "equivalent_sites_excluded": len(EQUIVALENT_SITES),
        "all_cases_sha256": digest.hexdigest(),
        "per_body": dict(sorted(by.items())),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


HELPER_NAME = {va: f"json_{n}_helper" for n, va in HELPERS.items()}


def unreached_why(va, v):
    """Why an instruction of the evaluated code is never reached by the cases (checked by the unit tests)."""
    if va == HELPERS["escape"]:
        return "escape arm: the keys wei/user hold no byte with a non-zero ESCAPE table entry"
    if va == HELPERS["key"]:
        return "unreachable arm: the JSON body always builds the compound as Map (state byte 0 == 0)"
    if va == HELPERS["end"]:
        return "current_indent == 0 panic: the JSON body incremented it before the call"
    if va == FAMILY_BODIES["a"]["json"]:
        return "unreachable arm: key writer state byte 0 is never 1 / end skipped only for an empty map"
    return "unexplained"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--scale", type=float, default=1.0, help="case count multiplier (default 1.0 = 20,000 cases)")
    a = ap.parse_args(argv)
    try:
        s = generate(a.out, a.scale)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{s['cases']} cases, {s['mismatches']} mismatches, {s['controls_detected']}/{s['controls']} controls, "
          f"{s['body_instructions_reached']}/{s['body_instructions']} body instructions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
