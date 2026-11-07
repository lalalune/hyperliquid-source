"""Reconstruct and verify the rmp-serde "map as a sequence of [key, value] pairs" collect path of node #115.

Two byte-identical copies (0x222a7a0 in the 0x226 family, 0x4155980 in the 0x419 family) serialize a collection of
(20-byte address, u64) entries that is either a BTreeMap (walked with the real Iter::next 0x23863d0 / 0x37c4430) or
a pair of slices of 0x20-byte elements.  With a length below 2^32 they write an array header of that length, then
every entry as a 2-element array [ "0x" + 40 lowercase hex digits, u64 ] through the per-element key and value
serializers (0x2297f40/0x2293c30, 0x41cf6c0/0x41ce7d0), stopping at the first error, and finally hand the
compound state to the buffer-end routine.  A length of 2^32 or more takes the deferred-length path: a 0x80-byte
buffer is allocated and each entry goes to the deferred entry routine with a running count.

The reconstruction is `model` (with `tree_iter`, `slice_iter` and the rmp encoders); a concrete x86-64 evaluator
runs the real bytes of the collect bodies, the B-tree iterators, the key/value serializers, the hex encoder and the
rmp leaf writers on generated cases, with faults injected at any leaf call, and compares written bytes, result
record, the ordered leaf/stub call list, the deferred-state records and frees.  The binary is never executed.
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
        self.zf, self.sf, self.cf, self.of = res == 0, bool(res >> (size - 1)), False, False  # and/or/xor/test clear OF
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
ERR_TAG = 0x8000000000000000      # word 0 of a 24-byte result carrying an error in words 1..2; also the "no pending" niche
OK_TRIPLE = ERR_TAG | 4           # word 0 of Ok(())
HEX_GOT = 0x64e4d08               # "0x" + lowercase hex encoder (out, cap, src, n, skip_leading_zero)
MALLOC_GOT, FREE_GOT, MEMCPY_GOT = 0x64df480, 0x64df4a0, 0x64df508
PANIC_GOTS = {0x64df830: "unwrap-none", 0x64df520: "add-overflow", 0x64df498: "alloc-error",
              0x64df570: "slice-end", 0x64df730: "assert", 0x64df620: "index"}
RESERVES = (0x231e050, 0x43bd910, 0x231dc90, 0x43bd550)   # RawVec reserve and finish_grow of both families
BUFFER_BYTES = 0x80               # initial capacity of the deferred-length buffer
PAIR = 2                          # each map entry is written as a 2-element array [key, value]
KEY_BYTES = 20                    # the B-tree key is a 20-byte address, written as a 42-character "0x..." string
HEX_CHARS = 2 + 2 * KEY_BYTES

# Two byte-identical copy families.  Roles: collect = the seq-of-pairs collect body, next = BTreeMap Iter::next,
# key/value = per-element serializers of the pair, hdr/uint/str/end = rmp leaf writers of serializer layout "b"
# (Vec<u8> behind a pointer at +0, flag byte +0xc).  Deferred-length path: entry = per-entry writer into the
# state buffer, ekey/evalue = its key/value serializers, *_a = layout "a" leaf writers (Vec<u8> inline at +0/+8/+0x10,
# flag byte +0x1c), which is exactly the deferred state record; bufend = buffer end (contract stub).
COPIES = {
    "226": {"collect": 0x222a7a0, "next": 0x23863d0, "key": 0x2297f40, "value": 0x2293c30, "entry": 0x228b8d0,
            "bufend": 0x227e2e0, "hdr": 0x25e7940, "uint": 0x25e9c70, "str": 0x25e8750, "end": 0x22997f0,
            "ekey": 0x22962a0, "evalue": 0x2296160, "hdr_a": 0x25e7c10, "uint_a": 0x25e9f10, "str_a": 0x25e8bf0,
            "end_a": 0x22999e0, "reserve": 0x231e050},
    "419": {"collect": 0x4155980, "next": 0x37c4430, "key": 0x41cf6c0, "value": 0x41ce7d0, "entry": 0x41bff50,
            "bufend": 0x41acea0, "hdr": 0x3d50270, "uint": 0x3d517e0, "str": 0x41c6110, "end": 0x41d3f60,
            "ekey": 0x41ce910, "evalue": 0x41cfc10, "hdr_a": 0x3d50540, "uint_a": 0x3d51450, "str_a": 0x41c6610,
            "end_a": 0x41d4150, "reserve": 0x43bd910},
}
BODY_ROLES = ("collect", "next", "key", "value", "entry", "ekey", "evalue")
LEAF_ROLES = ("hdr", "uint", "str", "end", "hdr_a", "uint_a", "str_a", "end_a")
STUB_ROLES = ("bufend",)
DEFERRED_ENTRIES = 2              # two entries (at most 54 bytes each) fit the 0x80 buffer without growth
# Call templates read from the bytes (direct e8/e9 targets and rip-relative GOT calls, in address order).
TEMPLATES = {
    "collect": ("c:hdr", "got:malloc", "j:", "j:", "j:", "c:next", "c:entry", "j:", "c:hdr", "c:key", "c:value",
                "c:end", "j:", "got:free", "j:", "c:bufend", "got:free", "got:add-overflow", "got:alloc-error",
                "c:unwind", "got:free", "got:free", "c:unwind"),
    "next": ("j:", "j:", "got:unwrap-none", "got:unwrap-none"),
    "key": ("j:", "c:hdr", "c:uint", "got:free", "got:hex", "c:str"),
    "value": ("j:", "c:hdr", "c:uint", "got:free", "c:uint"),
    "entry": ("c:ekey", "c:evalue", "c:end_a", "got:free", "c:reserve", "j:", "got:free", "c:unwind"),
    "ekey": ("j:", "c:hdr_a", "c:uint_a", "got:free", "got:hex", "c:str_a"),
    "evalue": ("j:", "c:hdr_a", "c:uint_a", "got:free", "c:uint_a"),
}
UNWIND = 0x63f0a50

# B-tree node layout (LeafNode<[u8; 20], u64>, InternalNode adds the edges).
NODE_PARENT, NODE_VALS, NODE_KEYS, NODE_PIDX, NODE_LEN, NODE_EDGES = 0, 0x8, 0x60, 0x13c, 0x13e, 0x140
CAPACITY = 11
NODE_SPAN = 0x200
ELEM = 0x20                       # slice element: key bytes at +0, value u64 at +0x18
ELEM_VALUE = 0x18

SER_AT = 0x7100_0000_0000
VEC_AT = 0x7180_0000_0000
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x8000
OUT_AT = 0x7500_0000_0000
IT_AT = 0x7580_0000_0000
NODE_AT = 0x7600_0000_0000
ELEM_AT = 0x7700_0000_0000
HEAP_AT = 0x7800_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
FAULT = (0x0bad_0000_0000_0007, 0x0bad_0000_0000_0011, 0x0bad_0000_0000_0022)
JUNK = 0x0dead_0000_0000_0001


# ---------------------------------------------------------------- reconstruction
def array_header(n, mut=frozenset()):
    """rmp write_array_len: fixarray below 16, array16 below 2^16, else array32."""
    limit = 15 if "fixarray-15" in mut else 17 if "fixarray-17" in mut else 16
    if n < limit:
        return bytes([0x90 | n])
    if n < (0x10000 if "array16-limit" not in mut else 0x8000):
        return b"\xdc" + n.to_bytes(2, "big")
    return b"\xdd" + (n & 0xffffffff).to_bytes(4, "big")


def write_uint(v, mut=frozenset()):
    """rmp write_uint: the smallest of positive fixint, uint8, uint16, uint32, uint64."""
    if v < (0x80 if "fixint-128" not in mut else 0x81):
        return bytes([v])
    if v < 0x100:
        return b"\xcc" + bytes([v])
    if v < (0x10000 if "uint16-limit" not in mut else 0x8000):
        return b"\xcd" + v.to_bytes(2, "big")
    if v < (1 << 32) and "no-uint32" not in mut:
        return b"\xce" + v.to_bytes(4, "big")
    return b"\xcf" + v.to_bytes(8, "big")


def write_str(s, mut=frozenset()):
    n = len(s)
    if n < 32 and "str8-always" not in mut:
        return bytes([0xa0 | n]) + s
    if n < (0x100 if "str8-limit-40" not in mut else 40) or "fixstr-wide" in mut:
        return (b"\xd9" + bytes([n]) if "fixstr-wide" not in mut else bytes([0xa0 | (n & 0x1f)])) + s
    if n < 0x10000:
        return b"\xda" + n.to_bytes(2, "big") + s
    return b"\xdb" + n.to_bytes(4, "big") + s


def address_text(key, mut=frozenset()):
    """The key text: "0x" then two lowercase hex digits per byte, leading zeros kept."""
    digits = key.hex()
    if "hex-upper" in mut:
        digits = digits.upper()
    if "hex-strip-zero" in mut and digits.startswith("0"):
        digits = digits[1:]
    if "key-19" in mut:
        digits = digits[:-2]
    return (b"" if "no-0x" in mut else b"0x") + digits.encode()


class IterPanic(Exception):
    pass


def tree_iter(rec, nodes, mut=frozenset()):
    """BTreeMap Iter::next over a lazily-descended front handle; yields (key_at, value_at) in key order.

    rec words: 0 = handle tag (1 = Some), 1 = leaf node (0 = not yet descended), 2/3 = root and height when not
    descended, else height (always 0 for a leaf edge) and edge index; word 8 = remaining length.
    """
    tag, node, a, b = rec[0], rec[1], rec[2], rec[3]
    remaining = rec[8]
    while True:
        if remaining == 0 and "remaining-ignored" not in mut:
            return
        remaining = (remaining - 1) & M64
        if tag & 0xffffffff != 1 and "none-ok" not in mut:   # cmpl: only the low 32 bits of the tag
            raise IterPanic("unwrap-none")
        if node == 0:
            node, height = a, b
            for _ in range(height):
                node = nodes[node]["edges"][0]
            idx, height = 0, 0
        else:
            height, idx = a, b
        while idx >= len(nodes[node]["keys"]):
            parent = nodes[node]["parent"]
            if parent == 0:
                if "remaining-ignored" in mut or "root-stops" in mut:
                    return
                raise IterPanic("unwrap-none")
            idx = nodes[node]["pidx"]
            node = parent
            height += 1
        kv_node, kv_idx = node, idx
        if height == 0:
            nxt, nidx = node, idx + 1
        else:
            nxt = nodes[node]["edges"][idx + 1]
            for _ in range(height - 1):
                nxt = nodes[nxt]["edges"][0]
            nidx = 0
        if "preorder" in mut and height:
            nxt, nidx = node, idx + 1
        tag, node, a, b = 1, nxt, 0, nidx
        yield (kv_node + NODE_KEYS + KEY_BYTES * kv_idx, kv_node + NODE_VALS + 8 * kv_idx)


def slice_iter(rec, mut=frozenset()):
    """The slice-pair arm (tag 2): first [w1, w2), then [w3, w4), 0x20-byte elements."""
    first, second = (rec[1], rec[2]), (rec[3], rec[4])
    parts = (second, first) if "slices-swapped" in mut else (first, second)
    if "second-skipped" in mut:
        parts = parts[:1]
    for lo, hi in parts:
        at = lo
        while at != hi:
            yield (at, at + (ELEM_VALUE if "value-at-0x10" not in mut else 0x10))
            at = (at + ELEM) & M64


def length_of(rec, mut=frozenset()):
    if rec[0] == 2:
        return ((((rec[2] - rec[1]) & M64) >> 5) + (((rec[4] - rec[3]) & M64) >> 5)) & M64
    return rec[8]


def state_config(ser):
    """The deferred-length buffer copies the serializer's config: u16 +8, then (u16 +0xa | u8 +0xc << 16) & 0xff0101."""
    hi = (ser[0xa] | ser[0xb] << 8 | ser[0xc] << 16) & 0xff0101
    return (hi << 16) | ser[8] | ser[9] << 8


def model(c, mem, mut=frozenset()):
    """Predict bytes, result triple, ordered leaf/stub calls, stub records, frees and the panic (or None).

    mem(at, n) reads the case's input bytes (keys, values) by address.
    """
    rec, flag = c["rec"], c["ser"][0xc]
    calls, out, buf, frees, entries, bufend = [], b"", b"", [], [], None
    state = None
    # The length test reads the whole tag word (cmpq), the per-entry arm test only its low 32 bits (cmpl).
    it = slice_iter(rec, mut) if rec[0] & 0xffffffff == 2 else tree_iter(rec, c["nodes"], mut)
    n = length_of(rec, mut)
    fault = c["fault"]

    def call(role):
        calls.append(role)
        return len(calls) - 1 == fault

    def finish(result, panic=None):
        return {"out": out, "buffer": buf, "result": result, "calls": calls, "entries": entries, "bufend": bufend,
                "frees": frees, "panic": panic}

    def pair(kat, vat, suffix, header_call):
        """One [key, value] element: header (inline byte or a call), key text, value, Compound::end.

        Returns (bytes written, error triple or None).  With flag byte 2 the 2-element header is deferred to the
        key serializer, which writes it through the header leaf ("hdr.key"); otherwise the caller writes it.
        """
        key, value = mem(kat, KEY_BYTES), int.from_bytes(mem(vat, 8), "little")
        lazy = (flag == 2) if "flag-ignored" not in mut else False
        head = array_header(PAIR, mut) if "no-pair-header" not in mut else b""
        steps = []
        if lazy:
            steps.append(("hdr" + suffix + ".key", head))
        elif header_call:
            steps.append(("hdr" + suffix, head))
        else:
            steps.append((None, head))
        items = [("str" + suffix, write_str(address_text(key, mut), mut)), ("uint" + suffix, write_uint(value, mut))]
        steps += items[::-1] if "value-first" in mut else items
        data = b""
        for role, chunk in steps:
            if role is not None and call(role):
                return data, (ERR_TAG, FAULT[0], FAULT[1])
            data += chunk
        if call("end" + suffix):
            return data, FAULT if "end-err-tag" not in mut else (ERR_TAG, FAULT[0], FAULT[1])
        return data, None

    deferred = (n >> 32) != 0 if "deferred-ge" not in mut else n >= 0xffffffff
    try:
        if deferred:
            calls.append("malloc")
            if c["malloc_fail"]:
                return finish(None, "alloc-error")
            cfg = state_config(c["ser"]) if "cfg-unmasked" not in mut else \
                (c["ser"][0xa] | c["ser"][0xb] << 8 | c["ser"][0xc] << 16) << 16 | c["ser"][8] | c["ser"][9] << 8
            state = [BUFFER_BYTES if "buffer-0x100" not in mut else 0x100, HEAP_AT, 0, cfg, 0, SER_AT]
            if "deferred-header" in mut:
                buf += array_header(0, mut)
            for kat, vat in it:
                entries.append((kat, vat, state[4], state[0], state[1], len(buf), state[3]))
                if len(entries) > DEFERRED_ENTRIES:
                    fail("deferred case would grow the buffer")
                data, err = pair(kat, vat, "_a", False)
                buf += data
                if err is not None:
                    if "no-free-on-error" not in mut:
                        frees.append((HEAP_AT, state[0]))
                    return finish(err)
                if "count-frozen" not in mut:
                    state[4] += 1
        else:
            if call("hdr"):
                return finish((ERR_TAG, FAULT[0], FAULT[1]))
            out += array_header(n, mut)
            state = [ERR_TAG, 2 if "state-ptr-zero" not in mut else 0, 0, 0, 0, SER_AT]
            for kat, vat in it:
                data, err = pair(kat, vat, "", True)
                out += data
                if err is not None and "err-continue" not in mut:
                    return finish(err)
        if "bufend-skipped" in mut and not deferred:
            return finish(None)
        call("bufend")
        bufend = list(state)
        return finish(c["bufend_res"])
    except IterPanic as p:
        return finish(None, str(p))




# ---------------------------------------------------------------- evaluation
class CaseMachine(TraceMachine):
    def transfer(self, target, call, va):
        role = self.role_of.get(target)
        if role == "entry" and call:
            rsi, rdx, rcx = self.regs[6], self.regs[2], self.regs[1]
            if not STACK_TOP - 0x10000 <= self.regs[7] < STACK_TOP or not STACK_TOP - 0x10000 <= rcx < STACK_TOP:
                fail("deferred entry did not receive a stack slot and state")
            if self.load(rcx + 0x28, 8) != SER_AT:
                fail("deferred state does not hold the serializer")
            self.entries.append((rsi, rdx, self.load(rcx + 0x20, 4), self.load(rcx, 8), self.load(rcx + 8, 8),
                                 self.load(rcx + 0x10, 8), self.load(rcx + 0x18, 8)))
        elif role in LEAF_ROLES:
            if any(lo <= va - 5 < hi for lo, hi in self.lazy_ranges) and role.startswith("hdr"):
                role += ".key"
            k = len(self.calls)
            self.calls.append(role)
            if self.case["fault"] == k:
                return self.fault(role, call)
        elif role in STUB_ROLES:
            k = len(self.calls)
            self.calls.append(role)
            self.stub(role, k)
            return self.pop() if not call else None
        return super().transfer(target, call, va)

    def clobber(self):
        for r in (1, 6, 8, 9, 10, 11):
            self.regs[r] = JUNK + r
        for i in range(16):
            self.xmm[i] = (JUNK << 64) | i

    def fault(self, role, call):
        a, b, x = FAULT
        rdi = self.regs[7]
        role = role.split(".")[0].split("_")[0]     # both layouts share the result conventions
        if role in ("hdr", "uint"):
            if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                fail("writer output slot is not on the stack")
            self.store(rdi, 8, a)
            self.store(rdi + 8, 8, b)
            self.regs[0], self.regs[2] = rdi, JUNK
        elif role == "str":
            self.regs[0], self.regs[2] = a, b
        else:
            if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                fail("Compound::end did not receive a stack result slot")
            for i, w in enumerate(FAULT):
                self.store(rdi + 8 * i, 8, w)
            self.regs[0], self.regs[2] = rdi, JUNK
        self.clobber()
        return None if call else self.pop()

    def stub(self, role, k):
        """Contract stub of the buffer end: record the 0x30-byte state it receives, write the case's result."""
        rdi, rsi = self.regs[7], self.regs[6]
        if rdi != OUT_AT:
            fail("buffer end did not receive the caller's result record")
        words = [self.load(rsi + 8 * i, 8) for i in range(6)]
        words[4] &= 0xffffffff           # the count is a u32; the upper half of that word is never written
        self.bufend_rec = words
        for i, w in enumerate(self.case["bufend_res"]):
            self.store(OUT_AT + 8 * i, 8, w)
        self.regs[0] = rdi
        self.clobber()
        self.regs[2] = JUNK


def install(m, image, copy):
    m.calls, m.entries, m.frees, m.reserves, m.bufend_rec = [], [], [], [], None
    m.heap = None
    roles = COPIES[copy]
    m.role_of = {roles[r]: r for r in LEAF_ROLES + STUB_ROLES + ("entry",)}
    if getattr(m, "extents", None) is None:
        m.extents = extents(image)
    ext = m.extents
    m.lazy_ranges = [(roles[r], ext[roles[r]]) for r in ("key", "ekey")]

    def malloc(m):
        if m.regs[7] != BUFFER_BYTES:
            fail("deferred buffer allocated with an unexpected size")
        m.calls.append("malloc")
        if m.case["malloc_fail"]:
            m.regs[0] = 0
        else:
            m.heap = m.add_region(HEAP_AT, BUFFER_BYTES)
            m.regs[0] = HEAP_AT
        m.clobber()

    def free(m):
        m.frees.append((m.regs[7], m.regs[6]))
        m.clobber()

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.regs[0] = dst

    def reserve(m):
        fail("vector growth reached; cases leave enough capacity")

    m.stubs[image.word(MALLOC_GOT)] = malloc
    m.stubs[image.word(FREE_GOT)] = free
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    for r in RESERVES:
        m.stubs[r] = reserve
    for got, kind in PANIC_GOTS.items():
        m.stubs[image.word(got)] = kind
    m.stubs[UNWIND] = "unwind"


def lay_nodes(nodes):
    """Byte image of each node at its address (parent, values, keys, parent index, length, edges)."""
    out = {}
    for at, nd in nodes.items():
        b = bytearray(NODE_SPAN)
        put(b, NODE_PARENT, 8, nd["parent"])
        for i, (k, v) in enumerate(zip(nd["keys"], nd["vals"])):
            put(b, NODE_VALS + 8 * i, 8, v)
            b[NODE_KEYS + KEY_BYTES * i:NODE_KEYS + KEY_BYTES * (i + 1)] = k
        put(b, NODE_PIDX, 2, nd["pidx"])
        put(b, NODE_LEN, 2, len(nd["keys"]))
        for i, e in enumerate(nd["edges"]):
            put(b, NODE_EDGES + 8 * i, 8, e)
        out[at] = bytes(b)
    return out


def case_memory(c):
    regions = {}
    if c["nodes"]:
        regions.update(lay_nodes(c["nodes"]))
    if c["elems"]:
        regions[ELEM_AT] = c["elems"]
    return regions


def reader(regions):
    def mem(at, n):
        for base, b in regions.items():
            if base <= at and at + n <= base + len(b):
                return b[at - base:at - base + n]
        fail(f"model read outside the case memory at {at:#x}")
    return mem


def run_case(m, c):
    m.reset()
    m.case = c
    install(m, m.image, c["copy"])
    m.add_region(SER_AT, 0x10, VEC_AT.to_bytes(8, "little") + bytes(c["ser"][8:16]))
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    m.add_region(VEC_AT, 0x18, bytes(vec))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"])
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    rec = b"".join(w.to_bytes(8, "little") for w in c["rec"])
    it = m.add_region(IT_AT, 0x48, rec)
    regions = case_memory(c)
    keep = {}
    for base, b in regions.items():
        keep[base] = (m.add_region(base, len(b), b), b)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, SER_AT, IT_AT
    m.regs[1], m.regs[8], m.regs[9] = JUNK + 1, JUNK + 8, JUNK + 9
    try:
        m.run(COPIES[c["copy"]]["collect"], limit=600000)
        panic = None
    except Boundary as b:
        panic = b.kind
    ln = m.load(VEC_AT + 0x10, 8)
    return {"panic": panic, "out": bytes(buf[len(c["prefix"]):ln]) if ln <= BUF_SIZE else None,
            "prefix_same": bytes(buf[:len(c["prefix"])]) == c["prefix"], "ptr": m.load(VEC_AT + 8, 8),
            "result": bytes(out), "rax": m.regs[0], "calls": list(m.calls), "entries": list(m.entries),
            "bufend": m.bufend_rec, "frees": list(m.frees),
            "heap": bytes(m.heap) if m.heap is not None else None,
            "inputs_same": bytes(it) == rec and all(bytes(r) == b for r, b in keep.values()),
            "regs_ok": panic is not None or ([m.regs[k] for k in SAVED_REGS] == list(SAVED)
                                             and m.regs[4] == STACK_TOP - 0x100)}


def heap_matches(want, got):
    """The deferred buffer holds exactly the predicted bytes, the rest of the 0x80 bytes untouched."""
    if got["heap"] is None:
        return want["buffer"] == b"" and "malloc" not in want["calls"] or want["calls"] == ["malloc"]
    n = len(want["buffer"])
    return got["heap"][:n] == want["buffer"] and not any(got["heap"][n:])


def compare(c, want, got):
    if not got["regs_ok"] or not got["inputs_same"] or not got["prefix_same"] or got["ptr"] != BUF_AT:
        return "machine"
    if got["panic"] != want["panic"]:
        return "panic"
    if got["calls"] != want["calls"]:
        return "calls"
    if got["out"] != want["out"]:
        return "bytes"
    if not heap_matches(want, got):
        return "deferred-buffer"
    if [tuple(e) for e in got["entries"]] != [tuple(e) for e in want["entries"]]:
        return "entries"
    if want["panic"] is not None:
        return None
    if got["rax"] != OUT_AT:
        return "return-register"
    if got["bufend"] != want["bufend"]:
        return "buffer-state"
    if got["frees"] != want["frees"]:
        return "frees"
    expect = b"".join(x.to_bytes(8, "little") for x in want["result"]) if want["result"] is not None else None
    if got["result"] != expect:
        return "result"
    return None


# ---------------------------------------------------------------- cases
CASES = 10000
FLAGS = (0, 1, 2, 2, 3, 0xff)
ROOMS = (0x1800, 0x2000, 0x3000, 0x4000)    # always enough: growth (reserve/finish_grow) is out of scope
SPECIAL_V = (0, 1, 0x7f, 0x80, 0x81, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0xffffffff,
             0x100000000, (1 << 63) - 1, 1 << 63, M64)
RESULTS = ((OK_TRIPLE, 0, 0), (ERR_TAG, 3, 4), (ERR_TAG | 2, 0x55, 9), (1, 2, 3))
MODES = ("tree", "tree", "tree", "tree", "slices", "slices", "resume", "lengths", "deferred", "faults")


def value(stream):
    if stream.below(3):
        return stream.pick(SPECIAL_V)
    return int.from_bytes(stream.take(8), "little") >> (8 * stream.below(8))


def key(stream):
    k = bytearray(stream.take(KEY_BYTES))
    for i in range(stream.below(4) * stream.below(3)):
        k[i] = 0
    return bytes(k)


def tree(stream, height):
    """A B-tree with consistent parent links; internal nodes may be empty, leaves hold 0..11 keys."""
    nodes, order = {}, []

    def build(level, parent, pidx):
        at = NODE_AT + NODE_SPAN * len(order)
        order.append(at)
        if level == 0:
            n = stream.pick((0, 1, 1, 2, 3, 5, 11)) if len(order) < 40 else 0
        else:
            n = stream.pick((0, 1, 1, 2)) if len(order) < 24 else 0
        nd = {"parent": parent, "pidx": pidx, "keys": [key(stream) for _ in range(n)],
              "vals": [value(stream) for _ in range(n)], "edges": []}
        nodes[at] = nd
        if level:
            nd["edges"] = [build(level - 1, at, i) for i in range(n + 1)]
        return at

    root = build(height, 0, stream.below(0x10000))
    return nodes, root


def walk_count(nodes, root, height):
    rec = [1, 0, root, height, 1, 0, root, height, M64]
    return sum(1 for _ in tree_iter(rec, nodes, {"root-stops"}))


def make_case(stream, k):
    mode = MODES[k % len(MODES)]
    c = {"k": k, "mode": mode, "copy": "226" if (k // len(MODES)) % 2 == 0 else "419", "fault": -1,
         "malloc_fail": False, "nodes": {}, "elems": b""}
    ser = bytearray(stream.take(16))
    ser[0xc] = stream.pick(FLAGS)
    c["ser"] = bytes(ser)
    c["prefix"] = stream.take(stream.below(5))
    c["room"] = stream.pick(ROOMS)
    c["bufend_res"] = stream.pick(RESULTS)
    junk = [int.from_bytes(stream.take(8), "little") for _ in range(9)]
    if mode == "slices":
        n = stream.below(9)
        c["elems"] = b"".join(key(stream) + stream.take(4) + value(stream).to_bytes(8, "little") for _ in range(n))
        at = lambda i: ELEM_AT + ELEM * i  # noqa: E731
        i0 = stream.below(n + 1)
        i1 = i0 + stream.below(n - i0 + 1)
        j0 = stream.below(n + 1)
        j1 = j0 + stream.below(n - j0 + 1)
        if stream.below(4) == 0:
            i0 = i1
        c["rec"] = [2, at(i0), at(i1), at(j0), at(j1)] + junk[5:]
    else:
        height = stream.pick((0, 0, 1, 1, 2, 3, 9) if mode != "deferred" else (0, 1, 2))
        nodes, root = tree(stream, height)
        while mode == "deferred" and walk_count(nodes, root, height) > DEFERRED_ENTRIES:
            nodes, root = tree(stream, height)
        c["nodes"] = nodes
        count = walk_count(nodes, root, height)
        rec = [1, 0, root, height] + junk[4:8] + [count]
        if mode == "resume":
            leaves = [a for a, nd in nodes.items() if not nd["edges"]]
            leaf = stream.pick(leaves)
            rec[1], rec[2], rec[3] = leaf, 0, stream.below(len(nodes[leaf]["keys"]) + 2)
            rec[8] = stream.below(count + 3)
        elif mode == "lengths":
            pick = stream.below(4)
            if pick == 0:
                rec[8] = count + 1 + stream.below(3)
            elif pick == 1:
                rec[8] = stream.below(count + 1)
            elif pick == 2:
                rec[8] = 0xffffffff          # the largest length that still takes the direct path (array32 header)
            else:
                rec[0] = stream.pick((0, 3, 0x100000001))
                rec[8] = stream.below(2) * (1 + stream.below(3))
        elif mode == "deferred":
            rec[8] = (1 << 32) + stream.below(1 << 30) if stream.below(3) else stream.pick((1 << 32, M64, 1 << 63))
            c["malloc_fail"] = stream.below(8) == 0
        c["rec"] = rec
    probe = model(c, reader(case_memory(c)))
    calls = len(probe["calls"])
    if mode in ("faults", "deferred") or stream.below(6) == 0:
        c["fault"] = stream.below(calls + 1) if mode != "deferred" else (
            [i for i, r in enumerate(probe["calls"]) if r == "entry"] or [-1])[0] + stream.below(3)
    return c


def all_cases(n=CASES):
    stream = Stream("serialization-rmp-map-pairs-115")
    return [make_case(stream, k) for k in range(n)]


# ---------------------------------------------------------------- static rows
def extents(image):
    starts = {COPIES[cp][r] for cp in COPIES for r in BODY_ROLES}
    return {s: e for s, (_, e) in fde_rows(image, starts).items()}


def call_rows(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] in (0xe8, 0xe9):
            out.append(("c" if f["op"] == 0xe8 else "j", f["target"], v))
        elif f["op"] == 0xff and f["reg"] & 7 in (2, 4) and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append(("got", v + f["len"] + f["rm"][4], v))
    return out


def symbolic(image, copy, rows, lo, hi):
    names = {a: r for r, a in COPIES[copy].items()}
    gots = {MALLOC_GOT: "malloc", FREE_GOT: "free", HEX_GOT: "hex"}
    gots.update(PANIC_GOTS)
    out = []
    for kind, target, _ in rows:
        if kind == "got":
            out.append("got:" + gots.get(target, f"{target:#x}"))
        elif kind == "j" and lo <= target < hi:
            out.append("j:")
        elif target == UNWIND:
            out.append("c:unwind")
        else:
            out.append(f"{kind}:" + names.get(target, f"{target:#x}"))
    return tuple(out)


def static_rows(image):
    ext = extents(image)
    rows = []
    shapes = {}
    for copy in sorted(COPIES):
        for role in BODY_ROLES:
            va = COPIES[copy][role]
            end = ext[va]
            insns = sweep(image, va, end)
            sym = symbolic(image, copy, call_rows(image, va, end), va, end)
            if sym != TEMPLATES[role]:
                fail(f"{copy} {role} {va:#x}: call template differs: {sym}")
            shape = tuple(f["op"] for _, f in insns)
            if shapes.setdefault(role, shape) != shape:
                fail(f"{role}: copy {copy} does not have the same opcode sequence as the other copy")
            rows.append({"copy": copy, "role": role, "start": va, "end": end, "insns": len(insns),
                         "sha256": hashlib.sha256(image.code(va, end - va)).hexdigest(), "calls": " ".join(sym)})
    if image.word(HEX_GOT) != 0x2eabb50:
        fail("hex encoder slot does not point at 0x2eabb50")
    return rows, ext


# ---------------------------------------------------------------- evaluation driver
def evaluate(image, cases, override=None, stop_on_first=False, trace=None):
    m = CaseMachine(image, override)
    m.extents = extents(image)
    if trace is not None:
        m.seen = trace
    results, misses = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except ToolError as e:
            if override is None:
                raise
            got = {"error": str(e)}
        want = model(c, reader(case_memory(c)))
        why = "machine-error" if "error" in got else compare(c, want, got)
        results.append(got)
        if why:
            misses.append((c["k"], why))
            if stop_on_first:
                break
    return results, misses


MODEL_MUTANTS = ("fixarray-15", "fixarray-17", "fixint-128", "uint16-limit", "no-uint32", "str8-limit-40",
                 "fixstr-wide", "hex-upper", "hex-strip-zero", "key-19", "no-0x", "remaining-ignored", "none-ok",
                 "root-stops", "preorder", "slices-swapped", "second-skipped", "value-at-0x10", "deferred-ge",
                 "buffer-0x100", "cfg-unmasked", "deferred-header", "no-free-on-error", "count-frozen",
                 "state-ptr-zero", "no-pair-header", "value-first", "end-err-tag", "err-continue", "bufend-skipped",
                 "flag-ignored")


def model_controls(cases, results):
    rows = []
    for mut in MODEL_MUTANTS:
        hit = None
        for c, got in zip(cases, results):
            try:
                want = model(c, reader(case_memory(c)), frozenset([mut]))
            except (KeyError, ToolError):
                hit = (c["k"], "model-error")
                break
            why = compare(c, want, got)
            if why:
                hit = (c["k"], why)
                break
        rows.append(("model", mut, hit))
    return rows


def byte_sites(image, ext):
    """Every conditional jump of the four 0x226 bodies, inverted (opcode low bit flipped)."""
    sites = []
    for role in BODY_ROLES:
        va = COPIES["226"][role]
        for v, f in sweep(image, va, ext[va]):
            b = f["bytes"]
            if 0x70 <= b[0] <= 0x7f:
                sites.append((role, v, v, b[0] ^ 1))
            elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
                sites.append((role, v, v + 1, b[1] ^ 1))
    return sites


BYTE_SUBSET = 240


def byte_controls(image, cases, sites, seen):
    rows = []
    subset = [c for c in cases if c["copy"] == "226"][:BYTE_SUBSET]
    for role, insn, at, new in sites:
        if insn not in seen:
            rows.append(("byte", f"{role}:{insn:#x}", "unreached"))
            continue
        _, misses = evaluate(image, subset, {at: new}, stop_on_first=True)
        rows.append(("byte", f"{role}:{insn:#x}", misses[0] if misses else None))
    return rows


def coverage(image, ext, seen):
    rows = []
    for copy in sorted(COPIES):
        for role in BODY_ROLES:
            va = COPIES[copy][role]
            insns = [v for v, _ in sweep(image, va, ext[va])]
            missing = [v for v in insns if v not in seen]
            runs, start, prev = [], None, None
            idx = {v: i for i, v in enumerate(insns)}
            for v in missing:
                if start is None or idx[v] != idx[prev] + 1:
                    if start is not None:
                        runs.append((start, prev))
                    start = v
                prev = v
            if start is not None:
                runs.append((start, prev))
            rows.append((copy, role, va, len(insns), len(insns) - len(missing), runs))
    return rows


def hexs(b):
    return b.hex() if b else "-"


def case_row(c, got):
    rec = " ".join(f"{w:x}" for w in c["rec"][:5]) + " .. " + f"{c['rec'][8]:x}"
    return "\t".join([str(c["k"]), c["copy"], c["mode"], f"{c['ser'][0xc]:#x}", str(c["fault"]),
                      str(len(c["nodes"])), str(len(c["elems"]) // ELEM), rec, got["panic"] or "-",
                      ",".join(got["calls"]) or "-", hexs(got["out"])[:160], got["result"].hex()])


SAMPLE_EVERY = 2


def generate(out, n=CASES, controls=True):
    image = Image(BINARY.read_bytes())
    rows, ext = static_rows(image)
    cases = all_cases(n)
    seen = set()
    results, misses = evaluate(image, cases, trace=seen)
    if misses:
        fail(f"{len(misses)} cases differ from the reconstruction, first {misses[0]}")
    cov = coverage(image, ext, seen)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "bodies.tsv", "w", newline="\n") as f:
        f.write("copy\trole\tstart\tend\tinstructions\tsha256\tcall_template\n")
        for r in rows:
            f.write(f"{r['copy']}\t{r['role']}\t{r['start']:#x}\t{r['end']:#x}\t{r['insns']}\t{r['sha256']}\t{r['calls']}\n")
    with open(out / "coverage.tsv", "w", newline="\n") as f:
        f.write("copy\trole\tstart\tinstructions\treached\tunreached_runs\n")
        for copy, role, va, total, hit, runs in cov:
            text = " ".join(f"{a:#x}-{b:#x}" for a, b in runs) or "-"
            f.write(f"{copy}\t{role}\t{va:#x}\t{total}\t{hit}\t{text}\n")
    lines = ["k\tcopy\tmode\tflag\tfault\tnodes\telems\trecord\tpanic\tcalls\tbytes\tresult"]
    digest = hashlib.sha256()
    for c, got in zip(cases, results):
        row = case_row(c, got)
        digest.update(row.encode() + b"\n")
        if c["k"] % SAMPLE_EVERY == 0:
            lines.append(row)
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")
    summary = {"binary_sha256": SHA256, "cases": len(cases), "mismatches": 0, "all_case_rows_sha256": digest.hexdigest(),
               "sample_every": SAMPLE_EVERY, "modes": {m: sum(1 for c in cases if c["mode"] == m) for m in sorted(set(MODES))},
               "panics": {}, "faults_injected": sum(1 for c in cases if c["fault"] >= 0),
               "coverage": {f"{cp}:{role}": [hit, total] for cp, role, _, total, hit, _ in cov}}
    for got in results:
        if got["panic"]:
            summary["panics"][got["panic"]] = summary["panics"].get(got["panic"], 0) + 1
    summary["panics"] = dict(sorted(summary["panics"].items()))
    if controls:
        crow = model_controls(cases, results)
        sites = byte_sites(image, ext)
        crow += byte_controls(image, cases, sites, seen)
        with open(out / "controls.tsv", "w", newline="\n") as f:
            f.write("kind\tmutation\tfirst_detecting_case\treason\n")
            for kind, mut, hit in crow:
                if hit is None:
                    f.write(f"{kind}\t{mut}\t-\tundetected\n")
                elif hit == "unreached":
                    f.write(f"{kind}\t{mut}\t-\tunreached\n")
                else:
                    f.write(f"{kind}\t{mut}\t{hit[0]}\t{hit[1]}\n")
        summary["controls"] = {
            "model": [sum(1 for k, _, h in crow if k == "model" and h not in (None, "unreached")), len(MODEL_MUTANTS)],
            "byte_reached": [sum(1 for k, _, h in crow if k == "byte" and h not in (None, "unreached")),
                             sum(1 for k, _, h in crow if k == "byte" and h != "unreached")],
            "byte_unreached": sum(1 for k, _, h in crow if k == "byte" and h == "unreached")}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--cases", type=int, default=CASES)
    args = ap.parse_args(argv)
    try:
        s = generate(args.out, args.cases)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps({k: s[k] for k in ("cases", "mismatches", "controls")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
