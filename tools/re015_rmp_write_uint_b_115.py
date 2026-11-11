"""Reconstruct and verify the layout-b rmp `write_uint` copies of node #115 with their width helpers and RawVec growth.

Three copy families (0x25e9c70, 0x3d517e0, 0x57d00b0) each hold a `write_uint(out, &ser, v)` whose serializer
holds a pointer to a `Vec<u8>` writer {cap, ptr, len}. It writes the smallest MessagePack unsigned form: a positive
fixint inline, otherwise a width helper (u8 inline or helper, u16, u32, u64) that stores the tag byte first, grows
the buffer when fewer than the payload bytes are free, then stores the big-endian payload. Growth runs the real
`reserve` and `finish_grow` bytes; only the allocator imports are stubbed. The result record is (2, marker) on
success and (0 or 1, 0x2600000003) when the first or the second growth site fails.

The reconstruction is `write_uint_b`, `helper`, `reserve_model` and `finish_grow`. A concrete x86-64 evaluator runs
the real bytes on generated vector states and compares the result record, the final {cap, ptr, len}, the whole
buffer and the ordered allocator calls. The binary is never executed.
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
# Layout-b `rmp::encode::write_uint` copies (the serializer is a pointer to the Vec<u8> writer), their
# MessagePack width helpers, and the RawVec growth pair (reserve + finish_grow) they call. Nothing here is
# stubbed except the allocator imports.
TAGS = {"u8": 0xcc, "u16": 0xcd, "u32": 0xce, "u64": 0xcf}
WIDTH = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}
FAMILIES = {
    "226": {"wu": 0x25e9c70, "u8": None, "u16": 0x25ea4b0, "u32": 0x25ea780, "u64": 0x25ea910,
            "reserve": 0x231e050, "grow": 0x231dc90},
    "419": {"wu": 0x3d517e0, "u8": None, "u16": 0x3d51d10, "u32": 0x3d51f40, "u64": 0x3d520d0,
            "reserve": 0x43bd910, "grow": 0x43bd550},
    "52f": {"wu": 0x57d00b0, "u8": 0x57d0250, "u16": 0x57d0510, "u32": 0x57d0750, "u64": 0x57d08e0,
            "reserve": 0x5963a10, "grow": 0x5963650},
}
ALLOC_GOTS = {"malloc": 0x64df480, "aligned_realloc": 0x64df580, "realloc": 0x64df588, "aligned_alloc": 0x64df590}
ALLOC_ERROR_GOT = 0x64df498
ERR_WORD = 0x2600000003         # result word 1 of every Err(..) record
ALLOC_LIMIT = 0x10000           # the stub allocator refuses anything larger (returns NULL)
SER_AT = 0x7100_0000_0000
VEC_AT = 0x7180_0000_0000
BUF_AT = 0x7200_0000_0000
ALLOC_AT = 0x7300_0000_0000     # n-th successful allocation lives at ALLOC_AT + n * ALLOC_STRIDE
ALLOC_STRIDE = 0x20000
OUT_AT = 0x7500_0000_0000
WRAP_AT = 0x7600_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
PREFILL = 0x5a
PREFILL_WORD = 0x5a5a5a5a5a5a5a5a
BYTE_TAG_FAMILIES = ("419",)    # these write the marker with a one-byte store, the others with a full qword


def fn_list():
    out = []
    for fam in sorted(FAMILIES):
        for role in ("wu", "u8", "u16", "u32", "u64", "reserve", "grow"):
            if FAMILIES[fam][role] is not None:
                out.append((fam, role, FAMILIES[fam][role]))
    return out


def extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for fam, role, va in fn_list():
        if va not in ext:
            fail(f"no FDE starts at {va:#x} ({fam} {role})")
    return ext


def call_targets(image, ext, va):
    return [f["target"] for _, f in sweep(image, va, ext[va]) if f["op"] == 0xe8]


def got_slots(image, ext, va):
    return sorted({(v + f["len"] + f["rm"][4]) & M64 for v, f in sweep(image, va, ext[va])
                   if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip"})


def tag_immediates(image, ext, va):
    """movb $imm8, mem stores whose immediate is one of the four MessagePack unsigned tags."""
    found = []
    for v, f in sweep(image, va, ext[va]):
        if f["op"] == 0xc6 and f["rm"][0] == "m" and (f["imm"] & 0xff) in TAGS.values():
            found.append(f["imm"] & 0xff)
    return found


def facts(image, ext):
    """Every claim the model relies on that can be read from the bytes alone."""
    rows = []
    for fam, info in sorted(FAMILIES.items()):
        wu_calls = call_targets(image, ext, info["wu"])
        helpers = {r: info[r] for r in ("u8", "u16", "u32", "u64") if info[r] is not None}
        want = set(helpers.values()) | {info["grow"], info["reserve"]}
        if set(wu_calls) != want:
            fail(f"{fam} write_uint calls {sorted(hex(x) for x in set(wu_calls))}, expected {sorted(hex(x) for x in want)}")
        for role, va in helpers.items():
            if set(call_targets(image, ext, va)) != {info["grow"], info["reserve"]}:
                fail(f"{fam} helper {role} {va:#x} does not call exactly grow and reserve")
            if TAGS[role] not in tag_immediates(image, ext, va):
                fail(f"{fam} helper {role} {va:#x} never stores tag {TAGS[role]:#x}")
        if call_targets(image, ext, info["reserve"]) != [info["grow"]]:
            fail(f"{fam} reserve {info['reserve']:#x} does not call finish_grow {info['grow']:#x}")
        if call_targets(image, ext, info["grow"]):
            fail(f"{fam} finish_grow {info['grow']:#x} has direct calls")
        if got_slots(image, ext, info["grow"]) != sorted(ALLOC_GOTS.values()):
            fail(f"{fam} finish_grow GOT slots {[hex(g) for g in got_slots(image, ext, info['grow'])]}")
        if got_slots(image, ext, info["reserve"]) != [ALLOC_ERROR_GOT]:
            fail(f"{fam} reserve GOT slots differ")
        inline = tag_immediates(image, ext, info["wu"])
        if info["u8"] is None and inline.count(0xcc) < 1:
            fail(f"{fam} write_uint has no inline 0xcc store")
        if info["u8"] is not None and 0xcc in inline:
            fail(f"{fam} write_uint stores 0xcc inline although it has a u8 helper")
        rows.append((fam, info, helpers))
    return rows


# ---------------------------------------------------------------- the reconstruction
def max8(x):
    """RawVec minimum non-zero capacity for one-byte elements: cmp $9 / cmovae into a register preset to 8."""
    return x if x >= 9 else 8


def tzcnt(x):
    if x == 0:
        return 64
    return (x & -x).bit_length() - 1


class VecModel:
    """Vec<u8> {cap, ptr, len} plus its heap: buffers are keyed by allocation number, bytes by offset."""

    def __init__(self, cap, ln, buf, fail_at, mut=frozenset()):
        self.cap, self.len, self.cur = cap, ln, 0
        self.bufs = {0: dict(buf)}
        self.sizes = {0: cap}
        self.n_calls = self.n_ok = 0
        self.fail_at, self.events, self.mut = fail_at, [], mut
        self.family_byte_tag = False

    def store(self, off, b):
        self.bufs[self.cur][off & M64] = b

    def ptr_value(self, p0):
        return p0 if self.cur == 0 else ALLOC_AT + (self.cur - 1) * ALLOC_STRIDE

    def alloc(self, kind, size, old, extra=()):
        """The stub allocator: call k fails when k == fail_at or the request exceeds ALLOC_LIMIT."""
        k = self.n_calls
        self.n_calls += 1
        self.events.append((kind, size) + ((old,) if old is not None else ()) + tuple(extra))
        limit = ALLOC_LIMIT + 1 if "alloc-limit" in self.mut else ALLOC_LIMIT
        if k == self.fail_at or size > limit:
            return False
        self.n_ok += 1
        keep = {o: b for o, b in self.bufs[self.cur].items() if o < min(old or 0, size)} if old is not None else {}
        if "realloc-no-copy" in self.mut:
            keep = {}
        self.bufs[self.n_ok] = keep
        self.sizes[self.n_ok] = size
        self.cur = self.n_ok
        return True


def finish_grow(st, oldcap, newcap, align=1, elem=1):
    """finish_grow(out, oldcap, ptr, newcap, align, elem) -> (ok, out triple). Mutates st on success."""
    size = newcap * elem
    ovf = size >> 64
    size &= M64
    limit = (1 << 63) - align
    if "size-limit" in st.mut:
        limit = (1 << 63) - align - 1
    if ovf or size > limit & M64 or (limit < 0):
        return False, (1, 0, None)
    plain = align < 0x11 and align <= size
    if "plain-cond" in st.mut:
        plain = align < 0x10 and align <= size
    tz = tzcnt(align)
    if oldcap != 0:
        if plain or tz == 0:
            ok = st.alloc("realloc", size, oldcap)
        else:
            ok = st.alloc("arealloc", size, oldcap, (tz,))
    elif size == 0:
        return True, (0, align, 0)
    else:
        if plain or tz == 0:
            ok = st.alloc("malloc", size, None)
        else:
            ok = st.alloc("amalloc", size, None, (tz,))
    if not ok:
        return False, (1, align, size)
    return True, (0, None, size)


def grow_inline(st, newcap):
    """Caller side of finish_grow with align = elem = 1: on success cap becomes newcap."""
    ok, _ = finish_grow(st, st.cap, newcap)
    if ok:
        st.cap = newcap & M64
    return ok


def push_fix(st, v):
    """Positive fixint: one byte, grow on a full buffer; Err(0) when the growth fails."""
    if st.cap == st.len:
        newcap = max8((2 * st.len) & M64) if "grow-no-double" not in st.mut else max8(st.len + 1)
        if "min-cap-4" in st.mut:
            newcap = (2 * st.len) & M64 if (2 * st.len) & M64 >= 5 else 4
        if not grow_inline(st, newcap):
            return 0
    st.store(st.len, v)
    st.len = (st.len + 1) & M64
    return 2


def helper(st, role, v):
    """The width helper: tag byte first, then the big-endian payload; returns 2, or 0 / 1 for the two growth sites."""
    n = WIDTH[role]
    tag = TAGS[role]
    if "tag-swap" in st.mut and role == "u16":
        tag = 0xce
    if st.cap == st.len:
        if not grow_inline(st, max8((2 * st.len) & M64)):
            return 0
    st.store(st.len, tag)
    old = st.len
    st.len = (st.len + 1) & M64
    room = (st.cap - st.len) & M64
    need = n - 1 if "room-off-by-one" in st.mut else n
    if room < need:
        required = (old + 1 + n) & M64
        if required < st.len and "wrap-check-off" not in st.mut:
            return 1
        newcap = max8(max((2 * st.cap) & M64, required))
        if not grow_inline(st, newcap):
            return 1 if "err-code-swap" not in st.mut else 0
    payload = (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little" if "be-to-le" in st.mut else "big")
    for i, b in enumerate(payload):
        st.store(st.len + i, b)
    st.len = (st.len + n) & M64
    return 2


def write_uint_b(st, v):
    """Layout-b write_uint(out, &ser, v): the Result record words (2, marker) or (code, ERR_WORD)."""
    lim8 = 0x81 if "uint-80" in st.mut else 0x80
    lim16 = 0x101 if "uint-100" in st.mut else 0x100
    lim32 = 0x10001 if "uint-10000" in st.mut else 0x10000
    lim64 = 0x100000001 if "uint-2e32" in st.mut else 1 << 32
    if v < lim8:
        code = push_fix(st, v)
        marker = ("fix", v)
    elif v < lim16:
        code, marker = helper(st, "u8", v), ("tag", 0xcc)
    elif v < lim32:
        code, marker = helper(st, "u16", v), ("tag", 0xcd)
    elif v < lim64:
        code, marker = helper(st, "u32", v), ("tag", 0xce)
    else:
        code, marker = helper(st, "u64", v), ("tag", 0xcf)
    if code != 2:
        return (code, ERR_WORD)
    if marker[0] == "fix":
        return (2, int.from_bytes(bytes([0, marker[1] & 0xff]) + bytes([PREFILL]) * 6, "little"))
    if st.family_byte_tag:
        return (2, marker[1] | (PREFILL_WORD & ~0xff))
    return (2, marker[1])


def reserve_model(st, ln, add, elem):
    """reserve(vec, len, add, align, elem) -> None, or the handle_alloc_error arguments."""
    if elem == 0:
        return (0, ln)
    need = ln + add
    if need >> 64:
        return (0, ln)
    cap = st.cap
    if elem == 1:
        mincap = 8
    elif elem <= 0x400:
        mincap = 4
    else:
        mincap = 1
    if "min-cap-elem" in st.mut:
        mincap = 8
    newcap = max((2 * cap) & M64, need & M64)
    newcap = max(newcap, mincap)
    ok, out = finish_grow(st, cap, newcap, 1, elem)
    if not ok:
        return (out[1], out[2])
    st.cap = newcap
    return None


# ---------------------------------------------------------------- cases
VALS = (0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000, M64, 0x7fffffffffffffff)


def make_buf(stream, cap, ln):
    return hashlib.shake_256(stream.take(16)).digest(ln) if ln else b""


def state_case(stream, fam, role, k, cap, ln, v, fail_at, wrap=False):
    return {"kind": "call", "fam": fam, "role": role, "k": k, "cap": cap, "len": ln, "v": v, "fail_at": fail_at,
            "wrap": wrap, "buf": make_buf(stream, cap, ln) if not wrap else b""}


def random_value(stream):
    bits = stream.below(65)
    return stream.below(1 << bits) if bits else 0


def exhaustive_cases(fam, k0=0):
    """Every (cap, len <= cap) up to 12, 12 values, no failure / first / second allocation failing."""
    stream = Stream(f"exh-{fam}")
    out, k = [], k0
    for cap in range(13):
        for ln in range(cap + 1):
            for v in VALS:
                for fail_at in (None, 0, 1):
                    out.append(dict(state_case(stream, fam, "wu", k, cap, ln, v, fail_at), exhaustive=True))
                    k += 1
    return out


def random_cases(fam, n, k0=0):
    stream = Stream(f"rnd-{fam}")
    out = []
    for i in range(n):
        shape = i % 6
        if shape == 0:
            cap = stream.below(40)
            ln = stream.below(cap + 1)
        elif shape == 1:
            ln = stream.below(300)
            cap = ln
        elif shape == 2:
            cap = stream.below(3000)
            ln = max(0, cap - stream.below(10))
        elif shape == 3:
            cap = 0x8000 + stream.below(0x8001)
            ln = cap - stream.below(3)
        elif shape == 4:
            cap = stream.below(2000)
            ln = stream.below(cap + 1)
        else:
            cap = stream.below(9)
            ln = cap
        v = stream.pick(VALS) if i % 3 == 0 else random_value(stream)
        fail_at = stream.pick((None, None, None, 0, 1, 2))
        out.append(state_case(stream, fam, "wu", k0 + i, cap, ln, v, fail_at))
    return out


def helper_cases(fam, n, k0=0):
    """Direct entries to each width helper with values inside that helper's range."""
    stream = Stream(f"hlp-{fam}")
    out = []
    roles = [r for r in ("u8", "u16", "u32", "u64") if FAMILIES[fam][r] is not None]
    for i in range(n):
        role = roles[i % len(roles)]
        width = WIDTH[role]
        cap = stream.below(24)
        ln = stream.below(cap + 1)
        v = stream.below(1 << (8 * width)) if i % 5 else stream.pick((0, 1, (1 << (8 * width)) - 1, 1 << (8 * width - 1)))
        out.append(state_case(stream, fam, role, k0 + i, cap, ln, v, stream.pick((None, None, 0, 1))))
    return out


def huge_cases(fam, k0=0):
    """Capacities at the doubling and size-limit boundaries (the buffer is never touched on the refusal arms)."""
    stream = Stream(f"big-{fam}")
    out, k = [], k0
    for cap in (1 << 62, (1 << 62) - 1, (1 << 62) + 1, 0x8001, 0x10000, 0x7fff, 0x4000, 0x4001, 0x2001):
        for v in (0x7f, 0x80, 0x100, 0x10000, 0x100000000):
            for fail_at in (None, 0):
                if cap >= 1 << 40:
                    c = state_case(stream, fam, "wu", k, cap, cap, v, fail_at, wrap=True)
                else:
                    c = state_case(stream, fam, "wu", k, cap, cap, v, fail_at)
                out.append(dict(c, big=True))
                k += 1
    return out


def wrap_cases(fam, k0=0):
    """len near 2^64: the pointer is chosen so ptr + len lands inside a small region, reaching the wrap checks."""
    out, k = [], k0
    for ln in ((1 << 64) - 3, (1 << 64) - 4, (1 << 64) - 5, (1 << 64) - 9, (1 << 64) - 10, (1 << 64) - 11):
        for cap_extra in (1, 2, 3, 5, 9):
            for v in (0x80, 0x100, 0x10000, 0x100000000):
                out.append({"kind": "call", "fam": fam, "role": "wu", "k": k, "cap": (ln + cap_extra) & M64, "len": ln,
                            "v": v, "fail_at": None, "wrap": True, "buf": b"", "wrapcase": True})
                k += 1
    return out


GROW_ALIGNS = (1, 2, 4, 8, 16, 32, 64, 3, 0)
GROW_ELEMS = (1, 2, 3, 4, 8, 24, 0x100, 0x401)


def grow_cases(fam, n, k0=0):
    stream = Stream(f"grow-{fam}")
    out = []
    for i in range(n):
        oldcap = stream.pick((0, 0, 1, 7, 8, 100, 4096))
        newcap = stream.pick((0, 1, 8, 9, 100, 1000, 4096, 0x7fff, 0x10000, 1 << 62, 1 << 63, M64, stream.below(70000)))
        align = stream.pick(GROW_ALIGNS)
        elem = stream.pick(GROW_ELEMS)
        out.append({"kind": "grow", "fam": fam, "role": "grow", "k": k0 + i, "cap": oldcap, "newcap": newcap,
                    "align": align, "elem": elem, "fail_at": stream.pick((None, None, None, 0))})
    return out


def reserve_cases(fam, n, k0=0):
    stream = Stream(f"res-{fam}")
    out = []
    for i in range(n):
        cap = stream.pick((0, 1, 7, 8, 9, 100, 4096))
        ln = stream.below(cap + 1) if cap < 100 else stream.pick((0, cap, cap - 1))
        add = stream.pick((1, 2, 3, 8, 9, 100, 5000, 0x10000, 1 << 63, M64 - ln if ln else M64))
        elem = stream.pick((0, 1, 1, 1, 2, 4, 0x400, 0x401))
        out.append({"kind": "reserve", "fam": fam, "role": "reserve", "k": k0 + i, "cap": cap, "len": ln, "add": add,
                    "elem": elem, "fail_at": stream.pick((None, None, None, 0)), "buf": b""})
    return out


PER_FAMILY_RANDOM = 2200
PER_FAMILY_HELPER = 1400
PER_FAMILY_GROW = 700
PER_FAMILY_RESERVE = 500


def all_cases():
    out = []
    for fam in sorted(FAMILIES):
        k = 0
        for group in (exhaustive_cases(fam), random_cases(fam, PER_FAMILY_RANDOM), helper_cases(fam, PER_FAMILY_HELPER),
                      huge_cases(fam), wrap_cases(fam), grow_cases(fam, PER_FAMILY_GROW),
                      reserve_cases(fam, PER_FAMILY_RESERVE)):
            for c in group:
                out.append(dict(c, k=k))
                k += 1
    return out


# ---------------------------------------------------------------- machine and one case
class CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.boundary = (self.noreturn[target], self.regs[7], self.regs[6])
            raise Boundary("noreturn", self.regs)
        return super().transfer(target, call, va)


def machine(image, override=None):
    return CaseMachine(image, override)


def install(m, image, c):
    sizes = {}
    m.events, m.n_calls, m.n_ok, m.boundary = [], 0, 0, None
    m.live = sizes
    m.sizes = sizes

    def take(m, size):
        k = m.n_calls
        m.n_calls += 1
        if k == c["fail_at"] or size > ALLOC_LIMIT:
            return 0
        at = ALLOC_AT + m.n_ok * ALLOC_STRIDE
        m.n_ok += 1
        m.add_region(at, max(size, 1))
        sizes[at] = size
        return at

    def malloc(m):
        size = m.regs[7]
        m.events.append(("malloc", size))
        m.regs[0] = take(m, size)

    def realloc(m):
        ptr, size = m.regs[7], m.regs[6]
        old = sizes.get(ptr)
        if old is None:
            fail(f"realloc of a foreign pointer {ptr:#x}")
        m.events.append(("realloc", size, old))
        new = take(m, size)
        if new:
            for i in range(min(old, size)):
                m.store(new + i, 1, m.load(ptr + i, 1))
        m.regs[0] = new

    def amalloc(m):
        size, tz = m.regs[7], m.regs[6]
        m.events.append(("amalloc", size, tz))
        m.regs[0] = take(m, size)

    def arealloc(m):
        ptr, size, tz = m.regs[7], m.regs[6], m.regs[2]
        old = sizes.get(ptr)
        if old is None:
            fail(f"aligned realloc of a foreign pointer {ptr:#x}")
        m.events.append(("arealloc", size, old, tz))
        new = take(m, size)
        if new:
            for i in range(min(old, size)):
                m.store(new + i, 1, m.load(ptr + i, 1))
        m.regs[0] = new

    m.stubs[image.word(ALLOC_GOTS["malloc"])] = malloc
    m.stubs[image.word(ALLOC_GOTS["realloc"])] = realloc
    m.stubs[image.word(ALLOC_GOTS["aligned_alloc"])] = amalloc
    m.stubs[image.word(ALLOC_GOTS["aligned_realloc"])] = arealloc
    m.noreturn = {image.word(ALLOC_ERROR_GOT): "alloc-error"}


def initial_pointer(c):
    """Where the case's buffer starts: a dangling 1 for cap 0, a wrapped pointer for the 2^64 cases."""
    if c.get("wrap"):
        return (WRAP_AT - c["len"]) & M64
    return BUF_AT if c["cap"] else 1


def region_bytes(m, ptr, size):
    for lo, hi, buf in m.regions:
        if lo <= ptr and ptr + size <= hi:
            return bytes(buf[ptr - lo:ptr - lo + size])
    fail(f"heap read outside regions at {ptr:#x}")


def run_case(m, c):
    m.reset()
    install(m, m.image, c)
    for kk, val in zip(SAVED_REGS, SAVED):
        m.regs[kk] = val
    fam = FAMILIES[c["fam"]]
    va = fam[c["role"]]
    p0 = initial_pointer(c)
    out = m.add_region(OUT_AT, 0x18, bytes([PREFILL]) * 0x18)
    if c["kind"] == "grow":
        if c["cap"]:
            m.add_region(BUF_AT, c["cap"] if c["cap"] <= 0x2000 else 0x2000)
            m.sizes[BUF_AT] = c["cap"]
        m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8], m.regs[9] = (
            OUT_AT, c["cap"], BUF_AT if c["cap"] else 1, c["newcap"], c["align"], c["elem"])
        m.sizes_note = c["cap"]
    else:
        vec = bytearray(0x18)
        put(vec, 0, 8, c["cap"])
        put(vec, 8, 8, p0)
        put(vec, 0x10, 8, c["len"])
        vreg = m.add_region(VEC_AT, 0x18, bytes(vec))
        if c.get("wrap"):
            m.add_region(WRAP_AT, 0x40)
            m.sizes[p0] = c["cap"]
        elif c["cap"]:
            bsz = c["cap"]
            m.add_region(BUF_AT, bsz, c["buf"])
            m.sizes[BUF_AT] = bsz
        if c["kind"] == "reserve":
            m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = VEC_AT, c["len"], c["add"], 1, c["elem"]
        elif c["role"] == "wu":
            m.add_region(SER_AT, 0x10, VEC_AT.to_bytes(8, "little"))
            m.regs[7], m.regs[6], m.regs[2] = OUT_AT, SER_AT, c["v"]
        else:
            if c["fam"] == "52f":       # the 52f helpers take the serializer and load the vector pointer themselves
                m.add_region(SER_AT, 0x10, VEC_AT.to_bytes(8, "little"))
                m.regs[7], m.regs[6] = SER_AT, c["v"]
            else:
                m.regs[7], m.regs[6] = VEC_AT, c["v"]
    try:
        m.run(va, limit=c.get("limit", 200_000))
    except Boundary:
        pass
    got = {"boundary": m.boundary, "events": list(m.events), "rax": m.regs[0], "n_ok": m.n_ok,
           "regs_ok": [m.regs[kk] for kk in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
           "result": bytes(out)}
    if c["kind"] != "grow":
        got["cap"], got["ptr"], got["len"] = (m.load(VEC_AT, 8), m.load(VEC_AT + 8, 8), m.load(VEC_AT + 0x10, 8))
        if c.get("wrap"):
            got["wrap_bytes"] = bytes(m.load(WRAP_AT + i, 1) for i in range(0x40))
        else:
            ptr, ln = got["ptr"], got["len"]
            size = m.sizes.get(ptr)
            got["heap"] = region_bytes(m, ptr, size) if size is not None and ptr else b""
            got["heap_size"] = size
    return got


# ---------------------------------------------------------------- expectation and comparison
def expect(c, mut=frozenset()):
    buf = {i: b for i, b in enumerate(c["buf"])} if c["kind"] != "grow" else {}
    if c.get("wrap"):
        buf = {}
    st = VecModel(c["cap"], c.get("len", 0), buf, c["fail_at"], mut)
    st.family_byte_tag = c["fam"] in BYTE_TAG_FAMILIES
    st.events = []
    p0 = initial_pointer(c)
    want = {"boundary": None, "result": None, "rax": None}
    if c["kind"] == "grow":
        ok, (flag, w1, w2) = finish_grow(st, c["cap"], c["newcap"], c["align"], c["elem"])
        res = bytearray(bytes([PREFILL]) * 0x18)
        ptr = ALLOC_AT + (st.cur - 1) * ALLOC_STRIDE if ok and st.cur else (1 if False else None)
        put(res, 0, 8, flag)
        if flag == 0:
            word1 = ptr if ptr is not None else w1
            put(res, 8, 8, word1)
            put(res, 0x10, 8, w2)
        else:
            put(res, 8, 8, w1)
            if w2 is not None:
                put(res, 0x10, 8, w2)
        want["result"] = bytes(res)
        want["events"] = st.events
        want["n_ok"] = st.n_ok
        return want
    if c["kind"] == "reserve":
        b = reserve_model(st, c["len"], c["add"], c["elem"])
        want["events"] = st.events
        want["n_ok"] = st.n_ok
        if b is not None:
            want["boundary"] = ("alloc-error", b[0], b[1])
            want["cap"], want["ptr"], want["len"] = c["cap"], p0, c["len"]
            return want
        want["cap"], want["len"], want["ptr"] = st.cap, c["len"], st.ptr_value(p0)
        want["heap"] = None
        return want
    if c["role"] == "wu":
        r = write_uint_b(st, c["v"])
        res = bytearray(bytes([PREFILL]) * 0x18)
        put(res, 0, 8, r[0])
        put(res, 8, 8, r[1])
        want["result"] = bytes(res)
        want["rax"] = OUT_AT
    else:
        want["rax"] = helper(st, c["role"], c["v"])
    want["events"] = st.events
    want["n_ok"] = st.n_ok
    want["cap"], want["len"], want["ptr"] = st.cap, st.len, st.ptr_value(p0)
    if c.get("wrap"):
        wb = bytearray(0x40)
        for off, b in st.bufs[st.cur].items():
            real = (p0 + off) & M64
            if WRAP_AT <= real < WRAP_AT + 0x40:
                wb[real - WRAP_AT] = b
        want["wrap_bytes"] = bytes(wb)
    else:
        size = st.cap if st.cur else c["cap"]
        # a failed growth leaves the old buffer; a successful one holds exactly the modelled bytes
        size = st.sizes[st.cur]
        img = bytearray(size)
        for off, b in st.bufs[st.cur].items():
            if off < size:
                img[off] = b
        want["heap"] = bytes(img) if (p0 != 1 or st.cur) else b""
        want["heap_size"] = size if (p0 != 1 or st.cur) else None
    return want


def compare(c, want, got):
    if not got["regs_ok"] and got["boundary"] is None:
        return "machine"
    if (got["boundary"] is None) != (want["boundary"] is None) or (
            got["boundary"] is not None and any(w is not None and g != w for g, w in zip(got["boundary"], want["boundary"]))):
        return "boundary"
    if got["events"] != want["events"]:
        return "events"
    if got["n_ok"] != want["n_ok"]:
        return "allocs"
    if want["boundary"] is not None and c["kind"] == "reserve" and want["boundary"][2] is None:
        return None
    if c["kind"] == "grow":
        # the stack garbage word of the overflow error is not part of the contract
        a, b = got["result"], want["result"]
        if a[:0x10] != b[:0x10]:
            return "result"
        flag = int.from_bytes(a[:8], "little")
        if flag == 0 and a[0x10:0x18] != b[0x10:0x18]:
            return "result"
        return None
    if got["cap"] != want["cap"] or got["len"] != want["len"] or (want["boundary"] is None and got["ptr"] != want["ptr"]):
        return "vector"
    if want["boundary"] is not None:
        return None
    if c["kind"] == "reserve":
        return None
    if want["rax"] is not None and got["rax"] != want["rax"]:
        return "rax"
    if want["result"] is not None and got["result"] != want["result"]:
        return "result"
    if c.get("wrap"):
        return None if got["wrap_bytes"] == want["wrap_bytes"] else "bytes"
    if got.get("heap") != want["heap"] or got.get("heap_size") != want["heap_size"]:
        return "bytes"
    return None


def evaluate(image, cases, mut=frozenset(), override=None, stop_on_first=False, trace=None):
    m = machine(image, override)
    if trace is not None:
        orig = m.step

        def step(va):
            trace.add(va)
            return orig(va)
        m.step = step
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except ToolError:
            if override is None:
                raise
            got = None
        why = compare(c, expect(c, mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad


# ---------------------------------------------------------------- negative controls
MODEL_MUTANTS = ("uint-80", "uint-100", "uint-10000", "uint-2e32", "grow-no-double", "min-cap-4", "tag-swap",
                 "room-off-by-one", "wrap-check-off", "be-to-le", "err-code-swap", "alloc-limit", "realloc-no-copy",
                 "size-limit", "plain-cond", "min-cap-elem")


def candidate_sites(image, ext, executed):
    """Flip sites chosen from decoded forms of instructions the clean run executed: tag stores, width
    limits, shift, minimum capacity, growth room tests and the carry/wrap tests."""
    sites = []
    for fam, role, va in fn_list():
        seen = set()
        for v, f in sweep(image, va, ext[va]):
            if v not in executed:
                continue
            imm = f.get("imm")
            op = f["op"]
            label = None
            if op == 0xc6 and f["rm"][0] == "m" and imm is not None and (imm & 0xff) in TAGS.values():
                label, at, bit = "tag", v + f["len"] - 1, 0x01
            elif op == 0x81 and imm in (0x100, 0x10000):
                label, at, bit = f"limit-{imm:#x}", v + f["len"] - 4 + (1 if imm == 0x100 else 2), 0x01
            elif op == 0xc1 and imm == 0x20:
                label, at, bit = "shr32", v + f["len"] - 1, 0x20
            elif op == 0x83 and f["rm"][0] == "r" and imm in (1, 3, 7, 9, 2):
                label, at, bit = f"cmp-{imm}", v + f["len"] - 1, 0x01
            elif op == 0x83 and imm == 1 and f["rm"][0] == "r":
                label, at, bit = "cmp-1", v + f["len"] - 1, 0x01
            elif 0xb8 <= op <= 0xbf and imm == 8:
                label, at, bit = "mincap8", v + f["len"] - 4, 0x04
            elif op in (0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79):
                label, at, bit = f"jcc-{op:#x}", v, 0x01
            elif op in (0x0f82, 0x0f83, 0x0f84, 0x0f85, 0x0f86, 0x0f87):
                label, at, bit = f"jcc-{op:#x}", v + 1, 0x01
            elif op == 0x0f47 or op == 0x0f43 or op == 0x0f42 or op == 0x0f45:
                label, at, bit = f"cmov-{op:#x}", v + 1, 0x01
            if label is not None:
                key = (label, at)
                if key not in seen:
                    seen.add(key)
                    sites.append((fam, role, va, label, at, bit))
    return sites


def flip_controls(image, ext, cases, executed, per_site_cases=600):
    """Flip one bit at every chosen site; the first bit that changes a result counts. Sites where no tried bit
    changes any result are reported separately as equivalent (not counted as controls)."""
    controls, equivalent = [], []
    by_fam = {}
    for c in cases:
        if True:
            by_fam.setdefault(c["fam"], []).append(c)
    for fam, role, va, label, at, bit in candidate_sites(image, ext, executed):
        direct = [c for c in by_fam[fam] if c["role"] == role and role != "wu"]
        direct = direct[::max(1, len(direct) // 250)]
        wu = [c for c in by_fam[fam] if c["role"] == "wu" and not c.get("big")]
        pool = direct + wu[::max(1, len(wu) // (per_site_cases - len(direct)))]
        hit = None
        for b in (bit, 0x02, 0x04, 0x10, 0x08, 0x40):
            _, bad = evaluate(image, pool, override={at: image.code(at, 1)[0] ^ b}, stop_on_first=True)
            if bad:
                hit = (b, pool.index(bad[0][0]))
                break
        if hit:
            controls.append(("bytes", f"{fam}:{role}:{label}@{at:#x}^{hit[0]:#x}", hit[1]))
        else:
            equivalent.append(f"{fam}:{role}:{label}@{at:#x}")
    return controls, equivalent


def range_controls(image, ext):
    out = []
    try:
        Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))
        out.append(("range", "binary-digest", None))
    except ToolError:
        out.append(("range", "binary-digest", 0))
    saved = FAMILIES["226"]["u16"]
    for name, val in (("helper-not-fde-start", saved + 1), ("helper-swapped-with-u32", FAMILIES["226"]["u32"])):
        FAMILIES["226"]["u16"] = val
        try:
            facts(image, ext if val in ext else dict(ext))
            out.append(("range", name, None))
        except (ToolError, KeyError):
            out.append(("range", name, 0))
        finally:
            FAMILIES["226"]["u16"] = saved
    saved_tag = TAGS["u16"]
    TAGS["u16"] = 0xcb
    try:
        facts(image, ext)
        out.append(("range", "tag-constant-wrong", None))
    except ToolError:
        out.append(("range", "tag-constant-wrong", 0))
    finally:
        TAGS["u16"] = saved_tag
    saved_got = ALLOC_GOTS["realloc"]
    ALLOC_GOTS["realloc"] = saved_got + 8
    try:
        facts(image, ext)
        out.append(("range", "alloc-slot-wrong", None))
    except ToolError:
        out.append(("range", "alloc-slot-wrong", 0))
    finally:
        ALLOC_GOTS["realloc"] = saved_got
    return out


def model_controls(cases, results):
    out = []
    gots = [(c, got) for c, got, _ in results]
    for name in MODEL_MUTANTS:
        hit = None
        for i, (c, got) in enumerate(gots):
            if compare(c, expect(c, frozenset({name})), got):
                hit = i
                break
        out.append(("model", name, hit))
    return out


def coverage(image, ext, executed):
    table = []
    for fam, role, va in fn_list():
        insns = [v for v, _ in sweep(image, va, ext[va])]
        table.append((fam, role, va, ext[va] - va, len(insns), sum(1 for v in insns if v in executed)))
    return table


# ---------------------------------------------------------------- generation
def hexs(b):
    return b.hex() if b else "-"


def case_line(c, want, got):
    ev = ",".join(e[0][0] + str(e[1]) for e in got["events"][:6]) or "-"
    v = c.get("v", c.get("newcap", c.get("add", 0)))
    return "\t".join([f"{FAMILIES[c['fam']][c['role']]:#x}", str(c["k"]), c["kind"], c["role"], f"{c['cap']:#x}",
                      f"{c.get('len', 0):#x}", f"{v:#x}", "-" if c["fail_at"] is None else str(c["fail_at"]),
                      "wrap" if c.get("wrap") else "-", got["result"][:16].hex() if c["kind"] != "reserve" else "-",
                      f"{got.get('len', 0):#x}", f"{got.get('cap', 0):#x}", ev])


def generate(out):
    image = Image(BINARY.read_bytes())
    ext = extents(image)
    rows = facts(image, ext)
    cases = all_cases()
    executed = set()
    results, bad = evaluate(image, cases, trace=executed)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first {c['fam']} {c['role']} {c['kind']} case {c['k']} ({why})")
    ctrl = model_controls(cases, results)
    fc, equivalent = flip_controls(image, ext, cases, executed)
    ctrl += fc
    ctrl += range_controls(image, ext)
    cov = coverage(image, ext, executed)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["family\trole\tfunction\tfde_bytes\tinstructions\tcalls\tgot_slots\ttag_stores"]
    for fam, role, va in fn_list():
        calls = ",".join(f"{t:#x}" for t in sorted(set(call_targets(image, ext, va))))
        gots = ",".join(f"{g:#x}" for g in got_slots(image, ext, va))
        tags = ",".join(f"{t:#x}" for t in tag_immediates(image, ext, va))
        lines.append(f"{fam}\t{role}\t{va:#x}\t{ext[va] - va}\t{len(sweep(image, va, ext[va]))}\t{calls or '-'}\t{gots or '-'}\t{tags or '-'}")
    (out / "functions.tsv").write_text("\n".join(lines) + "\n")

    lines = ["got_slot\tallocator_role\timport_symbol"]
    for role, slot in sorted(ALLOC_GOTS.items(), key=lambda kv: kv[1]):
        lines.append(f"{slot:#x}\t{role}\t{image.import_name(slot) if slot in image.imports else '-'}")
    lines.append(f"{ALLOC_ERROR_GOT:#x}\thandle_alloc_error\t{image.import_name(ALLOC_ERROR_GOT) if ALLOC_ERROR_GOT in image.imports else '-'}")
    (out / "allocator-slots.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    kinds = {}
    lines = ["function\tcase\tkind\trole\tcap\tlen\tvalue\tfail_alloc\tshape\tresult16\tfinal_len\tfinal_cap\tallocs"]
    for c, got, _ in results:
        digest.update(got["result"])
        digest.update(got.get("heap", b""))
        digest.update(repr(got["events"]).encode())
        shape = c["kind"] + ("-wrap" if c.get("wrap") else "") + ("-fail" if got["boundary"] is None and c["fail_at"] is not None and got["events"] else "")
        kinds[shape] = kinds.get(shape, 0) + 1
        if c["k"] % 7 == 0:
            lines.append(case_line(c, None, got))
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\trole\tfunction\tfde_bytes\tinstructions\texecuted"]
    for fam, role, va, size, n, hit in cov:
        lines.append(f"{fam}\t{role}\t{va:#x}\t{size}\t{n}\t{hit}")
    (out / "coverage.tsv").write_text("\n".join(lines) + "\n")

    (out / "equivalent-flips.txt").write_text("\n".join(equivalent) + "\n" if equivalent else "none\n")

    detected = sum(1 for _, _, h in ctrl if h is not None)
    summary = {
        "binary_sha256": SHA256,
        "families": len(FAMILIES),
        "functions": len(fn_list()),
        "function_instructions": sum(r[4] for r in cov),
        "instructions_executed": sum(r[5] for r in cov),
        "cases": len(results),
        "case_shapes": dict(sorted(kinds.items())),
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": detected,
        "equivalent_flip_sites": len(equivalent),
    }
    if detected != len(ctrl):
        fail(f"negative controls not detected: {[n for _, n, h in ctrl if h is None]}")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": len(results), "negative_controls": len(ctrl),
                                                  "negative_detected": detected}, indent=2, sort_keys=True) + "\n")
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
