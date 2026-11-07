"""Reconstruct and verify the node #115 user-signed action MessagePack encoders as one flow.

Three layers of the rmp-serde path that turns an EIP-712 user-signed action into MessagePack are rebuilt as
pure Python models and checked against the real machine code by a concrete x86-64 evaluator (the binary is
never executed; its bytes are interpreted):

  signed-action  (sa_*)  17 action bodies of the 0x24xxxxx family that call the chain serializer 0x2674b80:
                         map/array header, signatureChainId, hyperliquidChain and every per-action field.
  field-helpers  (fh_*)  the six keyed field helpers those bodies call (amount, gasLimit, destinationChainId,
                         addressEncoding, abstraction, data/Unvalidated) plus their 0x44fxxxx copies.
  newtype-tuples (nt_*)  17 serialize_newtype_struct monomorphs of the 0x226xxxx/0x227xxxx family with the
                         `_ExtStruct` reserved-name gate and their string / integer / address / 2-tuple payloads.

The evaluator, the ELF image reader (through tools/fde_extents.py and tools/elf_index.py), the MessagePack
length rules and the case/stub memory layout are shared; each layer keeps its own model, cases, controls and
evidence files (prefixed with the layer name). `--out DIR` regenerates every evidence file byte for byte.
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


# ---------------------------------------------------------------- shared MessagePack rules and case layout
def mp_uint(v, mut=frozenset()):
    if v < (0x81 if "uint-fixint" in mut else 0x80):
        return bytes([v])
    if v < 0x100:
        return b"\xcc" + bytes([v])
    if v < 0x10000:
        return (b"\xce" + v.to_bytes(4, "big")) if "uint-u16" in mut else (b"\xcd" + v.to_bytes(2, "big"))
    if v < 0x100000000:
        return b"\xce" + v.to_bytes(4, "big")
    return b"\xcf" + v.to_bytes(8, "big")

def mp_str(b, mut=frozenset()):
    n = len(b)
    if n < (33 if "str-fix32" in mut else 32):
        return bytes([0xa0 | (n & 0x1f)]) + b
    if n < (257 if "str8-limit" in mut else 256):
        return b"\xd9" + bytes([n & 0xff]) + b
    if n < 0x10000:
        return b"\xda" + n.to_bytes(2, "big") + b
    return b"\xdb" + n.to_bytes(4, "big") + b

MEMCPY_GOT = 0x64df508

PANIC_GOTS = (0x64df570, 0x64df730, 0x64df620)

SER_AT = 0x7100_0000_0000

BUF_AT = 0x7200_0000_0000

BUF_SIZE = 0x4000

OUT_AT = 0x7500_0000_0000

STR_AT = 0x7600_0000_0000

STR_SIZE = 0x2000

SAVED_REGS = (3, 5, 12, 13, 14, 15)

SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)

FAULT = (0x0bad_0000_0000_0007, 0x0bad_0000_0000_0011, 0x0bad_0000_0000_0022)

SPECIAL_U64 = (0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000, M64)

def hexs(b):
    return b.hex() if b else "-"

ROOMS = (0, 0, 1, 2, 3, 5, 8, 17, 18, 0x40, 0x1000)


# ================================================================ signed-action layer: 17 action bodies under the chain serializer
sa_WS = 0x25e8bf0      # rmp write_str(ser, ptr, len) -> rax 2 = Ok, else (rax, rdx) error

sa_U64 = 0x25e9f10     # rmp write_uint(out, ser, value) -> [out] 2 = Ok, else ([out], [out+8])

sa_UINT = 0x2631340    # impl-serde uint: big-endian bytes -> "0x" + hex without leading zeros

sa_CHAIN = 0x2674b80   # Local / Sandbox / Testnet / Mainnet fixstr serializer (RE-015-chain-codec-115)

sa_BOOLF = 0x226a340   # bool value writer (0xc2 / 0xc3) through 0x25eab50

sa_BOOLB = 0x25eab50   # rmp Marker::to_u8 (infallible); the body stores the byte inline

sa_HSTR = 0x24586c0    # serialize_field(key, &String): key only in map mode, then the string

sa_HU64 = 0x2459630    # serialize_field(key, u64): key only in map mode, then the uint

sa_ADDRH = 0x24a5850   # H160 value writer: to_hex then write_str

sa_NIL = 0x226a3b0     # serialize_none: nil marker 0xc0

sa_TOHEX = 0x2eabb50   # to_hex(buf, cap, bytes, len, skip_leading_zero) reached through GOT 0x64e4d08

sa_TOHEX_GOT = 0x64e4d08

sa_RESERVE = 0x231e050  # RawVec reserve(vec, len, additional, 1, 1)

sa_REAL = (sa_WS, sa_U64, sa_UINT, sa_CHAIN, sa_BOOLF, sa_BOOLB, sa_HSTR, sa_HU64, sa_ADDRH, sa_TOHEX, sa_NIL)

sa_NONE_CAP = 0x8000000000000000  # Option<String> niche: None

sa_OK_TRIPLE = 0x8000000000000004

sa_ERR_TAG = 0x8000000000000000

sa_STUBS = {
    0x24599a0: (("rdx", "u64", 0x68), ("rcx", "u64", 0x70)),
    0x245a590: (("rdx", "u8", 0x59),),
    0x24596c0: (("rdx", "const", 0x5ed60f), ("rcx", "const", 11), ("r8", "u32", 0x3c)),
    0x2458f40: (("rdx", "u32", 0xb4),),
    0x24585c0: (("rdx", "u32", 0xb0),),
    0x2459290: (("rdx", "u64", 0xa0),),
    0x245b4b0: (("rdx", "ptr", 0x60),),
}

sa_REGNO = {"rdx": 2, "rcx": 1, "r8": 8}

sa_CHAIN_NAMES = (b"Local", b"Sandbox", b"Testnet", b"Mainnet")

sa_CHOICE_NAMES = (b"yes", b"no", b"abstain")

sa_KIND_CALLS = {
    "u256": (sa_UINT,), "chain": (sa_CHAIN,), "u64": (sa_U64,), "str": (sa_WS,), "addr": (sa_TOHEX, sa_WS),
    "h256": (sa_TOHEX, sa_WS), "bool": (sa_BOOLF,), "boolb": (), "choice": (sa_WS,), "addrh": (sa_ADDRH,),
    "hstr": (sa_HSTR,), "hu64": (sa_HU64,), "ostr": (sa_WS,),
}

sa_SIG = ("signatureChainId", "i", "u256")

sa_HLC = ("hyperliquidChain", "i", "chain")

sa_BODIES = {
    0x2406120: ("CDeposit/CWithdraw", 0x00, 0x30, (("wei", "i", "u64", 0x20), ("nonce", "w", "u64", 0x28))),
    0x2407270: ("SendAsset", 0x90, 0xb8, (("destination", "i", "str", 0x00), ("sourceDex", "w", "str", 0x18),
                                         ("destinationDex", "w", "str", 0x30), ("token", "h", "hstr", 0x48),
                                         ("amount", "h", "stub", 0x24599a0), ("fromSubAccount", "h", "hstr", 0x78),
                                         ("nonce", "h", "hu64", 0xb0))),
    0x2407d40: ("title/description", 0x30, 0x58, (("title", "i", "str", 0x00), ("description", "w", "str", 0x18),
                                                 ("?", "h", "stub", 0x245a590), ("nonce", "h", "hu64", 0x50))),
    0x2408af0: ("TokenDelegate", 0x00, 0x44, (("validator", "i", "addr", 0x30), ("wei", "w", "u64", 0x20),
                                             ("isUndelegate", "w", "bool", 0x45), ("nonce", "h", "hu64", 0x28))),
    0x240ad50: ("UsdClassTransfer", 0x18, 0x41, (("amount", "i", "str", 0x00), ("toPerp", "w", "bool", 0x40),
                                                ("nonce", "w", "u64", 0x38))),
    0x240ba90: ("ApproveBuilderFee", 0x18, 0x54, (("maxFeeRate", "i", "str", 0x00), ("builder", "w", "addrh", 0x40),
                                                 ("nonce", "w", "u64", 0x38))),
    0x240d140: ("user/enabled", 0x00, 0x3c, (("user", "i", "addr", 0x28), ("enabled", "w", "bool", 0x3d),
                                            ("nonce", "w", "u64", 0x20))),
    0x240dec0: ("UserSetAbstraction", 0x00, 0x3d, (("user", "i", "addr", 0x28), ("abstraction", "h", "stub", 0x24596c0),
                                                  ("nonce", "w", "u64", 0x20))),
    0x240f270: ("token/destinationRecipient", 0x80, 0xb5, (("token", "i", "str", 0x00), ("amount", "w", "str", 0x18),
                                                          ("sourceDex", "w", "str", 0x30), ("destinationRecipient", "h", "hstr", 0x48),
                                                          ("?", "h", "stub", 0x2458f40), ("?", "h", "stub", 0x24585c0),
                                                          ("?", "h", "stub", 0x2459290), ("?", "h", "stub", 0x245b4b0),
                                                          ("nonce", "h", "hu64", 0xa8))),
    0x2410010: ("ConvertToMultiSigUser", 0x18, 0x40, (("signers", "i", "str", 0x00), ("nonce", "w", "u64", 0x38))),
    0x24119f0: ("vote", 0x00, 0x48, (("id", "i", "h256", 0x20), ("choice", "w", "choice", 0x49), ("nonce", "w", "u64", 0x40))),
    0x2412830: ("UsdSend", 0x30, 0x58, (("destination", "i", "str", 0x00), ("amount", "w", "str", 0x18), ("time", "w", "u64", 0x50))),
    0x2413110: ("SpotSend", 0x48, 0x70, (("destination", "i", "str", 0x00), ("token", "w", "str", 0x18),
                                        ("amount", "w", "str", 0x30), ("time", "h", "hu64", 0x68))),
    0x2d3c1b0: ("extendLongTermStaking", 0x00, 0x28, (("extendLongTermStaking", "i", "boolb", 0x29), ("nonce", "w", "u64", 0x20))),
    0x2d3df10: ("ApproveAgent", 0x18, 0x54, (("agentAddress", "i", "addr", 0x40), ("agentName", "w", "ostr", 0x00),
                                            ("nonce", "w", "u64", 0x38))),
    0x2d3ea40: ("user/isFinalize", 0x00, 0x3c, (("user", "i", "addr", 0x28), ("isFinalize", "w", "bool", 0x3d),
                                               ("nonce", "w", "u64", 0x20))),
    0x2d400f0: ("tradingUser", 0x00, 0x3c, (("tradingUser", "i", "addr", 0x28), ("nonce", "w", "u64", 0x20))),
}

sa_CHAIN_CALLERS = {0x2674b80: tuple(sorted(sa_BODIES))}

sa_CTX_AT = 0x7300_0000_0000

sa_ST_AT = 0x7400_0000_0000

sa_ST_SIZE = 0x100

def sa_hex_uint(v):
    """impl-serde serialize_uint: lowercase hex without leading zeros, "0x0" for zero."""
    return b"0x" + (b"%x" % v)

def sa_field_value(kind, off, st, strs, mut):
    """Bytes the value callee(s) of one field write, or None for a stub (it writes nothing here)."""
    if kind == "u256":
        v = int.from_bytes(st[off:off + 32], "little")
        if "uint-pad" in mut:
            return mp_str(b"0x" + (b"%064x" % v))
        return mp_str(b"0x0" if v == 0 and "uint-zero" not in mut else sa_hex_uint(v) if v else b"0x")
    if kind == "chain":
        names = sa_CHAIN_NAMES[::-1] if "chain-order" in mut else sa_CHAIN_NAMES
        return mp_str(names[st[off]])
    if kind in ("u64", "hu64"):
        v = int.from_bytes(st[off:off + 8], "little")
        if "uint-fixint" in mut and v == 0x80:
            return bytes([v])
        if "uint-u16" in mut and 0x100 <= v < 0x10000:
            return b"\xce" + v.to_bytes(4, "big")
        return mp_uint(v)
    if kind == "ostr" and int.from_bytes(st[off:off + 8], "little") == sa_NONE_CAP:
        return b"\xa0" if "none-as-empty" in mut else b"\xc0"
    if kind in ("str", "hstr", "ostr"):
        n = int.from_bytes(st[off + 0x10:off + 0x18], "little")
        p = int.from_bytes(st[off + 8:off + 16], "little") - STR_AT
        b = bytes(strs[p:p + n])
        if "str-fix32" in mut and n == 32:
            return bytes([0xa0 | 31]) + b
        if "str8-limit" in mut and n == 0x100:
            return b"\xd9\x00" + b
        return mp_str(b)
    if kind in ("addr", "addrh"):
        h = st[off:off + 20].hex().encode()
        return mp_str(b"0x" + (h.upper() if "hex-upper" in mut else h))
    if kind == "h256":
        h = st[off:off + 32].hex().encode()
        if "h256-short" in mut:
            h = h.lstrip(b"0") or b"0"
        return mp_str(b"0x" + h)
    if kind in ("bool", "boolb"):
        return b"\xc3" if (st[off] == 1) != ("bool-flip" in mut) else b"\xc2"
    if kind == "choice":
        names = (b"yes", b"abstain", b"no") if "choice-order" in mut else sa_CHOICE_NAMES
        return mp_str(names[st[off]])
    if kind == "stub":
        return None
    fail(f"unknown field kind {kind}")

def sa_field_list(va, mut):
    name, sig, chain, fields = sa_BODIES[va]
    rows = [sa_SIG + (sig,), sa_HLC + (chain,)] + list(fields)
    if "swap" in mut and mut["swap"] == va:
        rows[2], rows[3] = rows[3], rows[2]
    return rows

def sa_stub_args(target, st):
    out = []
    for reg, kind, x in sa_STUBS[target]:
        if kind == "u64":
            out.append(int.from_bytes(st[x:x + 8], "little"))
        elif kind == "u32":
            out.append(int.from_bytes(st[x:x + 4], "little"))
        elif kind == "u8":
            out.append(st[x])
        elif kind == "ptr":
            out.append(sa_ST_AT + x)
        else:
            out.append(x)
    return tuple(out)

def sa_segments(c, mut=frozenset()):
    """Ordered output of one body: ("bytes", b) written inline and ("call", target, b, extra) per callee."""
    va, st, strs = c["body"], c["st"], c["strs"]
    mapping = c["map"] != ("map-flip" in mut)
    rows = sa_field_list(va, mut)
    count = len(rows) + 1 - (1 if "count-off" in mut else 0)
    segs = [("bytes", bytes([(0x80 if mapping else 0x90) | count]))]
    if mapping:
        segs.append(("call", sa_WS, mp_str(c["tag"]), None))
    segs.append(("call", sa_WS, mp_str(c["variant"]), None))
    for key, mode, kind, off in rows:
        k = key.encode()
        if mode == "h":
            target = off if kind == "stub" else sa_KIND_CALLS[kind][0]
            if kind == "stub" and off in c.get("real", ()):
                segs.append(("call", target, fl_helper_bytes(c, off, mapping, mut), None))
            elif kind == "stub":
                segs.append(("call", target, b"", sa_stub_args(target, st)))
            else:
                segs.append(("call", target, (mp_str(k) if mapping else b"") + sa_field_value(kind, off, st, strs, mut), None))
            continue
        if mapping:
            segs.append(("bytes", mp_str(k)) if mode == "i" else ("call", sa_WS, mp_str(k), None))
        value = sa_field_value(kind, off, st, strs, mut)
        calls = sa_KIND_CALLS[kind]
        if kind == "ostr" and int.from_bytes(st[off:off + 8], "little") == sa_NONE_CAP:
            calls = (sa_NIL,)
        calls = [t for t in calls if t != sa_TOHEX]
        if not calls:
            segs.append(("bytes", value))
        for t in calls:
            segs.append(("call", t, value, None))
    return segs

def sa_fault_result(target, mut):
    """Result record a body stores when the callee at `target` reports an error."""
    a, b, cc = FAULT
    if target == sa_WS:
        return (sa_ERR_TAG, a, b) if "fault-ws-as-out" not in mut else (sa_ERR_TAG, a, cc)
    if target == sa_U64:
        return (sa_ERR_TAG, a, b) if "fault-u64-tag" not in mut else (a, b, cc)
    return (a, b, cc)

def sa_model(c, mut=frozenset()):
    """Predicted (output bytes, result triple or None for Ok, stub calls, result-call list)."""
    out = bytearray(c["prefix"])
    stubs, calls = [], []
    k = 0
    for seg in sa_segments(c, mut):
        if seg[0] == "bytes":
            out += seg[1]
            continue
        _, target, b, extra = seg
        calls.append(target)
        if c["fault"] == k:
            return bytes(out), sa_fault_result(target, mut), stubs, calls
        k += 1
        if target in sa_STUBS and target not in c.get("real", ()):
            stubs.append((target, len(out)) + extra)
        out += b
    return bytes(out), None, stubs, calls

class sa_CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.calls_seen.append(("panic", target))
            raise Boundary("noreturn", self.regs)
        if call and self.body_lo <= va - 5 < self.body_hi and target not in (self.tohex, sa_RESERVE, sa_BOOLB):
            k = self.direct
            self.direct += 1
            self.result_calls.append(target)
            if self.case["fault"] == k:
                return self.fault(target)
        if target in sa_STUBS and target not in self.case.get("real", ()):
            regs = tuple(self.regs[sa_REGNO[r]] & (M64 if kind not in ("u32", "u8") else 0xffffffff)
                         for r, kind, _ in sa_STUBS[target])
            self.stub_calls.append((target, self.load(SER_AT + 0x10, 8)) + regs)
            self.store(self.regs[7], 8, sa_OK_TRIPLE)
            return None
        return super().transfer(target, call, va)

    def fault(self, target):
        a, b, c = FAULT
        rdi = self.regs[7]
        if STACK_TOP - 0x10000 <= rdi < STACK_TOP:
            if target == sa_U64:
                self.store(rdi, 8, a)
                self.store(rdi + 8, 8, b)
            else:
                self.store(rdi, 8, a)
                self.store(rdi + 8, 8, b)
                self.store(rdi + 16, 8, c)
        self.regs[0], self.regs[2] = a, b
        self.regs[1] = self.regs[6] = self.regs[7] = self.regs[8] = self.regs[9] = self.regs[10] = self.regs[11] = 0x0dead
        return None

def sa_install(m, image):
    m.calls_seen, m.stub_calls, m.result_calls, m.reserves = [], [], [], []
    m.direct = 0
    m.tohex = image.word(sa_TOHEX_GOT)

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        cap = m.load(vec + 0, 8)
        if vec != SER_AT or ln != m.load(SER_AT + 0x10, 8) or cap - ln >= add or m.regs[1] != 1 or m.regs[8] != 1:
            fail("reserve called outside its contract")
        if ln + add > BUF_SIZE:
            fail("case output larger than the buffer region")
        m.reserves.append((ln, add))
        m.store(vec, 8, ln + add)

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.regs[0] = dst

    m.stubs[sa_RESERVE] = reserve
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.noreturn = {image.word(g) for g in PANIC_GOTS}

def sa_run_case(m, c, start=None):
    m.reset()
    m.case = c
    sa_install(m, m.image)
    va = c["body"]
    m.body_lo, m.body_hi = va, m.extents[va]
    ser = bytearray(0x20)
    put(ser, 0, 8, len(c["prefix"]) + c["room"])
    put(ser, 8, 8, BUF_AT)
    put(ser, 0x10, 8, len(c["prefix"]))
    ser[0x18:0x20] = c["ser_tail"]
    ser[0x1b] = 1 if c["map"] else 0
    m.add_region(SER_AT, 0x20, bytes(ser))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    ctx = bytearray(0x48)
    put(ctx, 0x20, 8, STR_AT + c["tag_at"])
    put(ctx, 0x28, 8, len(c["tag"]))
    put(ctx, 0x30, 8, STR_AT + c["variant_at"])
    put(ctx, 0x38, 8, len(c["variant"]))
    put(ctx, 0x40, 8, SER_AT)
    m.add_region(sa_CTX_AT, 0x48, bytes(ctx))
    st = m.add_region(sa_ST_AT, sa_ST_SIZE, c["st"])
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    strs = m.add_region(STR_AT, STR_SIZE, c["strs"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, sa_ST_AT, sa_CTX_AT
    try:
        m.run(start or va, limit=200000)
        panic = None
    except Boundary:
        panic = m.calls_seen[-1]
    ln = m.load(SER_AT + 0x10, 8)
    return {"panic": panic, "out": bytes(buf[:ln]), "tail_clean": not any(buf[ln:]) or ln < len(c["prefix"]),
            "cap": m.load(SER_AT, 8), "ptr": m.load(SER_AT + 8, 8), "ret": m.regs[0], "result": bytes(out),
            "st_same": bytes(st) == c["st"] and bytes(strs) == c["strs"],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "stubs": list(m.stub_calls), "calls": list(m.result_calls), "reserves": list(m.reserves)}

def sa_compare(c, want, got):
    out, res, stubs, calls = want
    if got["panic"] is not None or not got["regs_ok"] or not got["st_same"] or not got["tail_clean"]:
        return "machine"
    if got["out"] != out:
        return "bytes"
    if got["ptr"] != BUF_AT or got["ret"] != OUT_AT:
        return "vec"
    if got["calls"] != calls:
        return "calls"
    if got["stubs"] != stubs:
        return "stubs"
    if res is None:
        expect = sa_OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10
    else:
        expect = b"".join(x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    for ln, add in got["reserves"]:
        if ln + add > len(out) and res is None:
            return "reserve"
    return None

sa_PER_BODY = 600

sa_SPECIAL_LENS = (0, 1, 31, 32, 255, 256, 300)

def sa_ascii_bytes(st, n):
    return bytes(0x20 + b % 0x5f for b in st.take(n))

def sa_make_case(stream, va, k):
    name, sig, chain, fields = sa_BODIES[va]
    st = bytearray(stream.take(sa_ST_SIZE))
    strs = bytearray(STR_SIZE)
    at = [0]

    def place(b):
        p = at[0]
        strs[p:p + len(b)] = b
        at[0] += len(b) + 1
        return p

    tag = sa_ascii_bytes(stream, 1 + stream.below(12))
    variant = sa_ascii_bytes(stream, 1 + stream.below(40))
    tag_at, variant_at = place(tag), place(variant)
    style = k % 4
    rows = [sa_SIG + (sig,), sa_HLC + (chain,)] + list(fields)
    for key, mode, kind, off in rows:
        if kind == "u256":
            nz = stream.below(33) if style else (k // 4) % 33
            v = int.from_bytes(stream.take(32), "little") >> (8 * (32 - nz)) if nz else 0
            if nz and stream.below(4) == 0:
                v = 1 << (8 * nz - 1 - stream.below(8))
            st[off:off + 32] = v.to_bytes(32, "little")
        elif kind == "chain":
            st[off] = stream.below(4)
        elif kind in ("u64", "hu64"):
            v = SPECIAL_U64[stream.below(len(SPECIAL_U64))] if stream.below(2) else int.from_bytes(stream.take(8), "little") >> (8 * stream.below(8))
            put(st, off, 8, v)
        elif kind == "ostr" and stream.below(4) == 0:
            put(st, off, 8, sa_NONE_CAP)
        elif kind in ("str", "hstr", "ostr"):
            n = sa_SPECIAL_LENS[stream.below(len(sa_SPECIAL_LENS))] if stream.below(3) == 0 else stream.below(48)
            b = stream.take(n)
            put(st, off, 8, n + stream.below(64))
            put(st, off + 8, 8, STR_AT + place(b))
            put(st, off + 0x10, 8, n)
        elif kind in ("bool", "boolb"):
            st[off] = stream.below(2)
        elif kind == "choice":
            st[off] = stream.below(3)
    prefix = stream.take(stream.below(6))
    room = (0, 1, 3, 8, 0x40, 0x1000)[stream.below(6)] if style != 3 else 0
    n_calls = len(sa_model({"body": va, "st": bytes(st), "strs": bytes(strs), "tag": tag, "variant": variant,
                         "map": k % 2 == 0, "prefix": prefix, "fault": None}, {})[3])
    fault = None if style < 2 else (k // 4) % (n_calls + 1)
    if fault == n_calls:
        fault = None
    return {"body": va, "k": k, "st": bytes(st), "strs": bytes(strs), "tag": tag, "variant": variant,
            "tag_at": tag_at, "variant_at": variant_at, "map": k % 2 == 0, "prefix": prefix, "room": room,
            "ser_tail": stream.take(8), "fault": fault}

def sa_all_cases(per_body=sa_PER_BODY):
    out = []
    for va in sorted(sa_BODIES):
        stream = Stream(f"re015-signed-action-{va:x}")
        out.extend(sa_make_case(stream, va, k) for k in range(per_body))
    return out

def sa_extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in list(sa_BODIES) + list(sa_REAL) + list(sa_STUBS):
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext

def sa_count_imm_sites(image, ext):
    """Byte site of the `or r8, 0x80|n` map/array header immediate in each body (pattern 41 80 cc..cf imm)."""
    sites = {}
    for va in sorted(sa_BODIES):
        rows = sweep(image, va, ext[va])
        want = 0x80 | (len(sa_field_list(va, {})) + 1)
        hits = [v + f["len"] - 1 for v, f in rows if f["op"] == 0x80 and f["rm"][0] == "r" and f["reg"] & 7 == 1
                and f["imm"] & 0xff == want]
        if len(hits) != 1:
            fail(f"body {va:#x}: {len(hits)} header immediates")
        sites[va] = hits[0]
    return sites

def sa_direct_calls(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] == 0xe8:
            out.append(f["target"])
        elif f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append(image.word(v + f["len"] + f["rm"][4]))
    return out

def sa_static_rows(image, ext):
    rows = []
    for va in sorted(sa_BODIES):
        targets = set(sa_direct_calls(image, va, ext[va]))
        allowed = set(sa_REAL) | set(sa_STUBS) | {sa_RESERVE} | {image.word(g) for g in PANIC_GOTS}
        if not targets <= allowed:
            fail(f"body {va:#x} calls outside the declared set: {sorted(map(hex, targets - allowed))}")
        if sa_CHAIN not in targets:
            fail(f"body {va:#x} does not call the chain serializer")
        for t in targets:
            if t in sa_STUBS and not any(f[2] == "stub" and f[3] == t for f in sa_BODIES[va][3]):
                fail(f"body {va:#x} calls stub {t:#x} without a declared field")
        rows.append((va, ext[va] - va, len(sweep(image, va, ext[va])), sorted(targets)))
    if image.word(sa_TOHEX_GOT) != sa_TOHEX:
        fail("to_hex GOT slot no longer names 0x2eabb50")
    return rows

def sa_machine(image, ext, override=None):
    m = sa_CaseMachine(image, override)
    m.extents = ext
    return m

def sa_evaluate(image, ext, cases, mut=None, override=None, stop_on_first=False, seen=None):
    m = sa_machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        if seen is not None:
            m.seen_hook = seen
        got = sa_run_case(m, c)
        why = sa_compare(c, sa_model(c, mut or {}), got)
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad

sa_MODEL_MUTANTS = ("uint-pad", "uint-zero", "chain-order", "uint-fixint", "uint-u16", "str-fix32", "str8-limit",
                 "hex-upper", "h256-short", "bool-flip", "choice-order", "map-flip", "count-off",
                 "fault-ws-as-out", "fault-u64-tag", "none-as-empty")

def sa_controls(image, ext, results, sites):
    rows = []
    gots = [(c, got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(gots):
            if sa_compare(c, sa_model(c, mut), got):
                return i
        return None

    for name in sa_MODEL_MUTANTS:
        rows.append(("model", name, first_hit({name: True})))
    for va in sorted(sa_BODIES):
        rows.append(("model", f"swap-fields-3-4@{va:#x}", first_hit({"swap": va})))
    for va in sorted(sa_BODIES):
        at = sites[va]
        byte = image.code(at, 1)[0]
        cases = [c for c, _ in gots if c["body"] == va]
        _, bad = sa_evaluate(image, ext, cases, override={at: byte ^ 0x01}, stop_on_first=True)
        rows.append(("bytes", f"header-imm@{at:#x}", cases.index(bad[0][0]) if bad else None))
    return rows

def sa_coverage(image, ext, cases):
    m = sa_machine(image, ext)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        sa_run_case(m, c)
    rows = []
    for va in sorted(sa_BODIES) + sorted(sa_REAL):
        insns = [v for v, _ in sweep(image, va, ext[va])]
        hit = sum(1 for v in insns if v in seen)
        rows.append((va, len(insns), hit))
    return rows

def sa_generate(out):
    data = BINARY.read_bytes()
    image = Image(data)
    ext = sa_extents(image)
    static = sa_static_rows(image, ext)
    sites = sa_count_imm_sites(image, ext)
    cases = sa_all_cases()
    results, bad = sa_evaluate(image, ext, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first body {c['body']:#x} case {c['k']} ({why})")
    ctrl = sa_controls(image, ext, results, sites)
    cov = sa_coverage(image, ext, cases[::3])
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tfde_end\tbytes\tinstructions\taction_inferred\tdirect_callees"]
    for va, size, n, targets in static:
        lines.append(f"{va:#x}\t{ext[va]:#x}\t{size}\t{n}\t{sa_BODIES[va][0]}\t{','.join(f'{t:#x}' for t in targets)}")
    (out / "signed-action-bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tposition\tkey\tkey_mode\tkind\tstruct_offset_or_stub\tvalue_callees"]
    for va in sorted(sa_BODIES):
        for i, (key, mode, kind, off) in enumerate(sa_field_list(va, {})):
            calls = (off,) if kind == "stub" else sa_KIND_CALLS[kind]
            lines.append(f"{va:#x}\t{i + 1}\t{key}\t{mode}\t{kind}\t{off:#x}\t{','.join(f'{t:#x}' for t in calls) or 'inline'}")
    (out / "signed-action-fields.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tmode\tfault_call\troom\tprefix\tout_len\tout_sha256\tresult\tresult_calls\treserves\tstub_calls"]
    for c, got, _ in results:
        if c["k"] % 25:
            continue
        res = got["result"].hex()
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), "map" if c["map"] else "array",
                                "-" if c["fault"] is None else str(c["fault"]), str(c["room"]), hexs(c["prefix"]),
                                str(len(got["out"])), hashlib.sha256(got["out"]).hexdigest(), res,
                                str(len(got["calls"])), str(len(got["reserves"])),
                                ";".join(",".join(f"{x:#x}" for x in s) for s in got["stubs"]) or "-"]))
    (out / "signed-action-cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "signed-action-controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        role = "body" if va in sa_BODIES else "real-callee"
        lines.append(f"{va:#x}\t{role}\t{n}\t{hit}")
    (out / "signed-action-coverage.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    kinds = {"map": 0, "array": 0, "fault": 0, "ok": 0}
    for c, got, _ in results:
        digest.update(got["out"] + got["result"])
        kinds["map" if c["map"] else "array"] += 1
        kinds["ok" if c["fault"] is None else "fault"] += 1
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(sa_BODIES),
        "body_bytes": sum(s for _, s, _, _ in static),
        "body_instructions": sum(n for _, _, n, _ in static),
        "real_callees": [f"{t:#x}" for t in sorted(sa_REAL)],
        "stubbed_field_helpers": [f"{t:#x}" for t in sorted(sa_STUBS)],
        "cases": len(results),
        "case_kinds": kinds,
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": sum(1 for _, _, h in ctrl if h is not None),
        "body_instructions_executed": sum(h for v, _, h in cov if v in sa_BODIES),
    }
    if summary["controls_detected"] != summary["controls"]:
        fail("a negative control was not detected")
    (out / "signed-action-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ field-helpers layer: the keyed helpers the action bodies call
fh_WS = 0x25e8bf0       # rmp write_str(ser, ptr, len) -> rax 2 = Ok, else (rax, rdx) error

fh_U64 = 0x25e9f10      # rmp write_uint(out, ser, value) -> [out] = 2 Ok, else [out], [out+8] error

fh_RESERVE = 0x231e050  # RawVec reserve(vec, len, additional, 1, 1)

fh_NEWTYPE = 0x22781c0  # serialize_newtype_struct(out, ser, name, name_len, value), reached by a tail jump

fh_WS_B = 0x41c6610     # the same writers in the 0x44fxxxx copy family

fh_U64_B = 0x3d51450

fh_RESERVE_B = 0x43bd910

fh_LEAVES = {"a": (fh_WS, fh_U64, fh_RESERVE), "b": (fh_WS_B, fh_U64_B, fh_RESERVE_B)}

fh_RESERVES = (fh_RESERVE, fh_RESERVE_B)

fh_REAL = (fh_WS, fh_U64, fh_WS_B, fh_U64_B)

fh_OK_TRIPLE = 0x8000000000000004

fh_ERR_TAG = 0x8000000000000000

fh_ABSTRACTION_TABLE = 0x5ed130      # rel32 jump table of 0x24596c0, indexed by the low byte of r8

fh_DEST_KEY_AT = 0x5ed63d            # first 16 bytes of the destinationChainId key (movups source)

fh_NEWTYPE_NAME_AT = 0x5f174d        # 11-byte newtype name passed to 0x22781c0

fh_HELPERS = {
    0x24599a0: ("amount", b"amount", "nz", "str"),
    0x2459290: ("gasLimit", b"gasLimit", "nz", "u64"),
    0x24585c0: ("destinationChainId", b"destinationChainId", "nz", "u32"),
    0x2458f40: ("addressEncoding", b"addressEncoding", "nz", "encoding"),
    0x24596c0: ("abstraction", None, "ws", "abstraction"),
    0x245b4b0: ("data", b"data", "eq1", "newtype"),
}

fh_COPIES = {0x44f67b0: 0x24599a0, 0x44fb0c0: 0x2458f40, 0x44fb870: 0x24585c0}

fh_FAMILY = {va: "a" for va in fh_HELPERS}

for _copy, _base in fh_COPIES.items():
    fh_HELPERS[_copy] = fh_HELPERS[_base]
    fh_FAMILY[_copy] = "b"

fh_ENCODING_NAMES = (b"hex", b"base58")              # dl == 1 -> base58, any other byte -> hex

fh_ABSTRACTION_NAMES = (b"e", b"i", b"z", b"u", b"p")  # low byte of r8 indexes the 5-entry jump table

fh_NEWTYPE_NAME = b"Unvalidated"

def fh_key_written(test, flag, mut):
    if "key-always" in mut:
        return True
    if test == "eq1":
        return flag != 0 if "eq1-as-nz" in mut else flag == 1
    return flag == 1 if "nz-as-eq1" in mut else flag != 0

def fh_fixkey(key, mut):
    if "key-marker" in mut:
        return bytes([0xa0 | (len(key) + 1)]) + key
    if "key-case" in mut:
        return bytes([0xa0 | len(key)]) + key.lower()
    return bytes([0xa0 | len(key)]) + key

def fh_model(c, mut=frozenset()):
    """Predicted (appended bytes, result triple or None for Ok, fallible-call list, newtype stub call or None)."""
    label, key, test, kind = fh_HELPERS[c["helper"]]
    ws, u64 = fh_LEAVES[fh_FAMILY[c["helper"]]][:2]
    flag, args, fault = c["flag"], c["args"], c["fault"]
    out, calls = b"", []
    err = None

    def fallible(target, data):
        nonlocal out, err
        if err is not None:
            return
        k = len(calls)
        calls.append(target)
        if fault == k:
            a, b, _ = FAULT
            err = (fh_ERR_TAG | (4 if "err-tag" in mut else 0), a, b)
        else:
            out += data

    if test == "ws":
        if fh_key_written(test, flag, mut):
            fallible(ws, mp_str(c["key"], mut))
    elif fh_key_written(test, flag, mut):
        out += fh_fixkey(key, mut)
    newtype = None
    if kind == "str":
        fallible(ws, mp_str(c["value"], mut))
    elif kind == "u64":
        fallible(u64, mp_uint(args[0] & M64, mut))
    elif kind == "u32":
        v = args[0] & (M64 if "u32-full" in mut else 0xffffffff)
        fallible(u64, mp_uint(v, mut))
    elif kind == "encoding":
        dl = args[0] & 0xff
        one = dl != 0 if "enc-nonzero" in mut else dl == 1
        if err is None:
            out += mp_str(fh_ENCODING_NAMES[1 if one else 0], mut)
    elif kind == "abstraction":
        d = args[2] & 0xff
        if d >= len(fh_ABSTRACTION_NAMES):
            fail(f"abstraction discriminant {d} is outside the 5-entry jump table")
        names = fh_ABSTRACTION_NAMES
        if "abs-order" in mut:
            names = (names[1], names[0]) + names[2:]
        if err is None:
            out += mp_str(names[d], mut)
    elif kind == "newtype":
        if err is None:
            newtype = (len(c["prefix"]) + len(out), STR_AT + c["name_at"] if "name-ptr" in mut else fh_NEWTYPE_NAME_AT,
                       len(fh_NEWTYPE_NAME) - (1 if "name-len" in mut else 0), args[0] & M64)
            if fault == 0:
                err = FAULT
    if "err-keeps" in mut and err is not None:
        out += b"\x00"
    return out, err, calls, newtype

class fh_CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.calls_seen.append(("panic", target))
            raise Boundary("noreturn", self.regs)
        if call and self.body_lo <= va - 5 < self.body_hi and target not in fh_RESERVES:
            k = self.direct
            self.direct += 1
            self.result_calls.append(target)
            if self.case["fault"] == k:
                return self.fault(target)
        return super().transfer(target, call, va)

    def fault(self, target):
        a, b, _ = FAULT
        rdi = self.regs[7]
        if target in (fh_U64, fh_U64_B):
            if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                fail("write_uint output slot is not on the stack")
            self.store(rdi, 8, a)
            self.store(rdi + 8, 8, b)
        self.regs[0], self.regs[2] = a, b
        for r in (1, 6, 7, 8, 9, 10, 11):
            self.regs[r] = 0x0dead
        return None

def fh_install(m, image):
    m.calls_seen, m.result_calls, m.reserves, m.newtype = [], [], [], []
    m.direct = 0

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        cap = m.load(vec + 0, 8)
        if vec != SER_AT or ln != m.load(SER_AT + 0x10, 8) or cap - ln >= add or m.regs[1] != 1 or m.regs[8] != 1:
            fail("reserve called outside its contract")
        if ln + add > BUF_SIZE:
            fail("case output larger than the buffer region")
        m.reserves.append((ln, add))
        m.store(vec, 8, ln + add)

    def memcpy(m):
        dst, src, n = m.regs[7], m.regs[6], m.regs[2]
        for i in range(n):
            m.store(dst + i, 1, m.load(src + i, 1))
        m.regs[0] = dst

    def newtype(m):
        if m.regs[7] != OUT_AT or m.regs[6] != SER_AT:
            fail("newtype serializer reached with foreign out/ser")
        m.newtype.append((m.load(SER_AT + 0x10, 8), m.regs[2], m.regs[1], m.regs[8]))
        trip = FAULT if m.case["fault"] == 0 else (fh_OK_TRIPLE, 0x5a5a5a5a5a5a5a5a, 0x5a5a5a5a5a5a5a5a)
        for i, x in enumerate(trip):
            m.store(OUT_AT + 8 * i, 8, x)
        m.regs[0] = OUT_AT

    for r in fh_RESERVES:
        m.stubs[r] = reserve
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.stubs[fh_NEWTYPE] = newtype
    m.noreturn = {image.word(g) for g in PANIC_GOTS}

def fh_run_case(m, c):
    m.reset()
    m.case = c
    fh_install(m, m.image)
    va = c["helper"]
    m.body_lo, m.body_hi = va, m.extents[va]
    ser = bytearray(0x20)
    put(ser, 0, 8, len(c["prefix"]) + c["room"])
    put(ser, 8, 8, BUF_AT)
    put(ser, 0x10, 8, len(c["prefix"]))
    ser[0x18:0x20] = c["ser_tail"]
    ser[0x1b] = c["flag"]
    sreg = m.add_region(SER_AT, 0x20, bytes(ser))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    strs = m.add_region(STR_AT, STR_SIZE, c["strs"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = OUT_AT, SER_AT
    m.regs[2], m.regs[1], m.regs[8] = c["args"]
    try:
        m.run(va, limit=200000)
        panic = None
    except Boundary:
        panic = m.calls_seen[-1] if m.calls_seen else ("boundary",)
    ln = m.load(SER_AT + 0x10, 8)
    return {"panic": panic, "out": bytes(buf[:ln]), "tail_clean": not any(buf[ln:]) or ln < len(c["prefix"]),
            "ptr": m.load(SER_AT + 8, 8), "ser_tail": bytes(sreg[0x18:0x20]), "result": bytes(out),
            "strs_same": bytes(strs) == c["strs"],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "calls": list(m.result_calls), "reserves": list(m.reserves), "newtype": list(m.newtype)}

def fh_compare(c, want, got):
    data, res, calls, newtype = want
    expect_tail = bytearray(c["ser_tail"])
    expect_tail[3] = c["flag"]
    if got["panic"] is not None or not got["regs_ok"] or not got["strs_same"] or not got["tail_clean"]:
        return "machine"
    if got["ser_tail"] != bytes(expect_tail) or got["ptr"] != BUF_AT:
        return "serializer"
    if got["out"] != c["prefix"] + data:
        return "bytes"
    if got["calls"] != calls:
        return "calls"
    if got["newtype"] != ([newtype] if newtype else []):
        return "newtype"
    if res is None:
        expect = fh_OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10
    else:
        expect = b"".join(x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    for ln, add in got["reserves"]:
        if ln + add > len(c["prefix"]) + len(data) and res is None and not newtype:
            return "reserve"
    return None

fh_PER_HELPER = 2000

fh_SPECIAL_LENS = (0, 1, 2, 31, 32, 33, 255, 256, 257, 300, 0x7ff)

fh_FLAGS = (0, 1, 1, 0, 2, 0x80, 0xff)

def fh_fallible_count(helper, flag):
    _, _, test, kind = fh_HELPERS[helper]
    n = 1 if (test == "ws" and flag != 0) else 0
    n += 1 if kind in ("str", "u64", "u32") else 0
    n += 1 if kind == "newtype" else 0
    return n

def fh_make_case(stream, va, k):
    _, _, test, kind = fh_HELPERS[va]
    flag = fh_FLAGS[k % len(fh_FLAGS)]
    room = ROOMS[(k // 7) % len(ROOMS)]
    prefix = stream.take(stream.below(6))
    strs = bytearray(stream.take(STR_SIZE))
    c = {"helper": va, "k": k, "flag": flag, "room": room, "prefix": prefix, "ser_tail": stream.take(8),
         "fault": None, "name_at": 0}
    r = [int.from_bytes(stream.take(8), "little") for _ in range(3)]
    if kind == "str":
        n = fh_SPECIAL_LENS[k % len(fh_SPECIAL_LENS)] if k % 3 else stream.below(400)
        at = stream.below(STR_SIZE - n)
        c["value"] = bytes(strs[at:at + n])
        r[0], r[1] = STR_AT + at, n
    elif kind in ("u64", "u32"):
        sel = k % 4
        if sel == 0:
            r[0] = SPECIAL_U64[(k // 4) % len(SPECIAL_U64)]
        elif sel == 1:
            r[0] = (r[0] & ~0xffffffff) | SPECIAL_U64[(k // 4) % 9]
        elif sel == 2:
            r[0] = r[0] >> (8 * stream.below(8))
    elif kind == "encoding":
        r[0] = (r[0] & ~0xff) | ((0, 1, 2, 0xff, 0x80, 1, 0)[k % 7] if k % 3 else stream.below(256))
    elif kind == "abstraction":
        r[2] = (r[2] & ~0xff) | (k % 5)
        n = (11, 0, 1, 31, 32, 255, 256)[(k // 5) % 7]
        at = stream.below(STR_SIZE - n)
        c["key"] = bytes(strs[at:at + n])
        r[0], r[1] = STR_AT + at, n
    c["args"] = tuple(r)
    c["strs"] = bytes(strs)
    n = fh_fallible_count(va, flag)
    if (k // 3) % 2 and n:
        c["fault"] = stream.below(n)
    return c

def fh_all_cases(per_helper=fh_PER_HELPER):
    out = []
    for va in sorted(fh_HELPERS):
        stream = Stream(f"re015-field-helpers/{va:#x}")
        for k in range(per_helper):
            out.append(fh_make_case(stream, va, k))
    return out

def fh_extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in list(fh_HELPERS) + list(fh_REAL) + [fh_NEWTYPE]:
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext

def fh_direct_calls(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] in (0xe8, 0xe9):
            out.append(("call" if f["op"] == 0xe8 else "jmp", f["target"]))
        elif f["op"] == 0xff and f["reg"] & 7 in (2, 4) and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append(("got", image.word(v + f["len"] + f["rm"][4])))
    return out

def fh_static_rows(image, ext):
    rows = []
    for va in sorted(fh_HELPERS):
        allowed = set(fh_LEAVES[fh_FAMILY[va]]) | {fh_NEWTYPE}
        targets = {t for kind, t in fh_direct_calls(image, va, ext[va]) if not (kind == "jmp" and va <= t < ext[va])}
        if not targets <= allowed:
            fail(f"helper {va:#x} calls outside the declared set: {sorted(map(hex, targets - allowed))}")
        rows.append((va, ext[va] - va, len(sweep(image, va, ext[va])), sorted(targets)))
    return rows

def fh_table_rows(image, ext):
    """The abstraction jump table (5 rel32 entries inside 0x24596c0) and the byte each arm stores."""
    lo, hi = 0x24596c0, ext[0x24596c0]
    rows = []
    insns = sweep(image, lo, hi)
    for i in range(8):
        tgt = (fh_ABSTRACTION_TABLE + struct.unpack("<i", image.read(fh_ABSTRACTION_TABLE + 4 * i, 4))[0]) & M64
        if not lo <= tgt < hi:
            break
        stores = [f["imm"] & 0xff for v, f in insns
                  if tgt <= v < tgt + 0x30 and f["op"] == 0xc6 and f["rm"][0] == "m" and f["imm"] & 0xff != 0xa1][:1]
        rows.append((i, tgt, stores[0] if stores else None))
    if [bytes([s]) for _, _, s in rows] != list(fh_ABSTRACTION_NAMES):
        fail("abstraction jump table arms do not store the declared names")
    if image.read(fh_DEST_KEY_AT, 16) + b"Id" != fh_HELPERS[0x24585c0][1]:
        fail("destinationChainId key bytes differ")
    if image.read(fh_NEWTYPE_NAME_AT, len(fh_NEWTYPE_NAME)) != fh_NEWTYPE_NAME:
        fail("newtype name bytes differ")
    return rows

def fh_marker_sites(image, ext):
    """Every inline `mov byte [..], imm8` (key/value marker and one-letter names) in each helper."""
    sites = []
    for va in sorted(fh_HELPERS):
        for v, f in sweep(image, va, ext[va]):
            if f["op"] == 0xc6 and f["rm"][0] == "m":
                sites.append((va, v + f["len"] - 1, f["imm"] & 0xff))
    return sites

def fh_machine(image, ext, override=None):
    m = fh_CaseMachine(image, override)
    m.extents = ext
    return m

def fh_evaluate(image, ext, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = fh_machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        got = fh_run_case(m, c)
        why = fh_compare(c, fh_model(c, mut), got)
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad

fh_MODEL_MUTANTS = ("str-fix32", "str8-limit", "uint-fixint", "uint-u16", "key-always", "eq1-as-nz", "nz-as-eq1",
                 "key-marker", "key-case", "err-tag", "u32-full", "enc-nonzero", "abs-order", "name-ptr",
                 "name-len", "err-keeps")

def fh_controls(image, ext, results, sites):
    rows = []
    gots = [(c, got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(gots):
            if fh_compare(c, fh_model(c, frozenset(mut)), got):
                return i
        return None

    for name in fh_MODEL_MUTANTS:
        rows.append(("model", name, first_hit({name})))
    for va, at, imm in sites:
        cases = [c for c, _ in gots if c["helper"] == va]
        _, bad = fh_evaluate(image, ext, cases, override={at: image.code(at, 1)[0] ^ 0x01}, stop_on_first=True)
        rows.append(("bytes", f"imm8-{imm:#04x}@{at:#x}", cases.index(bad[0][0]) if bad else None))
    return rows

def fh_coverage(image, ext, cases):
    m = fh_machine(image, ext)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        fh_run_case(m, c)
    rows = []
    for va in sorted(fh_HELPERS) + sorted(fh_REAL):
        insns = [v for v, _ in sweep(image, va, ext[va])]
        rows.append((va, len(insns), sum(1 for v in insns if v in seen)))
    return rows

def fh_generate(out, per_helper=fh_PER_HELPER):
    image = Image(BINARY.read_bytes())
    ext = fh_extents(image)
    static = fh_static_rows(image, ext)
    table = fh_table_rows(image, ext)
    sites = fh_marker_sites(image, ext)
    cases = fh_all_cases(per_helper)
    results, bad = fh_evaluate(image, ext, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first helper {c['helper']:#x} case {c['k']} ({why})")
    ctrl = fh_controls(image, ext, results, sites)
    cov = fh_coverage(image, ext, cases[::3])
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["helper\tfamily\tsame_rules_as\tfde_end\tbytes\tinstructions\tfield\tkey\tkey_test\tvalue_kind\tcallees"]
    for va, size, n, targets in static:
        label, key, test, kind = fh_HELPERS[va]
        lines.append(f"{va:#x}\t{fh_FAMILY[va]}\t{fh_COPIES.get(va, va):#x}\t{ext[va]:#x}\t{size}\t{n}\t{label}\t{(key or b'(caller)').decode()}\t{test}\t{kind}\t"
                     f"{','.join(f'{t:#x}' for t in targets)}")
    (out / "field-helpers-helpers.tsv").write_text("\n".join(lines) + "\n")

    lines = ["discriminant\tarm\tstored_byte\tname"]
    for i, tgt, s in table:
        lines.append(f"{i}\t{tgt:#x}\t{s:#04x}\t{chr(s)}")
    (out / "field-helpers-abstraction-table.tsv").write_text("\n".join(lines) + "\n")

    lines = ["helper\tcase\tflag\tfault_call\troom\tprefix\targ_rdx\targ_rcx\targ_r8\tout_len\tout_sha256\tresult\t"
             "calls\treserves\tnewtype"]
    for c, got, _ in results:
        if c["k"] % 20:
            continue
        lines.append("\t".join([f"{c['helper']:#x}", str(c["k"]), f"{c['flag']:#x}",
                                "-" if c["fault"] is None else str(c["fault"]), str(c["room"]), hexs(c["prefix"]),
                                *(f"{a:#x}" for a in c["args"]), str(len(got["out"])),
                                hashlib.sha256(got["out"]).hexdigest(), got["result"].hex(),
                                ",".join(f"{t:#x}" for t in got["calls"]) or "-", str(len(got["reserves"])),
                                ";".join(",".join(f"{x:#x}" for x in s) for s in got["newtype"]) or "-"]))
    (out / "field-helpers-cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "field-helpers-controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        lines.append(f"{va:#x}\t{'helper' if va in fh_HELPERS else 'real-callee'}\t{n}\t{hit}")
    (out / "field-helpers-coverage.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    kinds = {"map_key": 0, "no_key": 0, "fault": 0, "ok": 0}
    for c, got, _ in results:
        digest.update(got["out"] + got["result"])
        _, _, test, _ = fh_HELPERS[c["helper"]]
        kinds["map_key" if fh_key_written(test, c["flag"], frozenset()) else "no_key"] += 1
        kinds["ok" if c["fault"] is None else "fault"] += 1
    summary = {
        "binary_sha256": SHA256,
        "helpers": len(fh_HELPERS),
        "helper_bytes": sum(s for _, s, _, _ in static),
        "helper_instructions": sum(n for _, _, n, _ in static),
        "helper_instructions_executed": sum(h for v, _, h in cov if v in fh_HELPERS),
        "real_callees": [f"{t:#x}" for t in sorted(fh_REAL)],
        "contract_stubs": [f"{t:#x}" for t in fh_RESERVES + (fh_NEWTYPE,)],
        "cases": len(results),
        "case_kinds": kinds,
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": sum(1 for _, _, h in ctrl if h is not None),
    }
    if summary["controls_detected"] != summary["controls"]:
        missed = [n for _, n, h in ctrl if h is None]
        fail(f"negative controls not detected: {missed}")
    (out / "field-helpers-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ newtype-tuples layer: serialize_newtype_struct bodies and the _ExtStruct gate
nt_EXT_NAME = b"_ExtStruct"          # rmp-serde's reserved newtype name for MessagePack ext values

nt_ERR_TAG = 0x8000000000000000      # result word 0 for "error carried in words 1..2"

nt_EXT_MESSAGES = (b"expected tuple", b"expected i8 and bytes")  # the two static rmp-serde ext errors

nt_EXT_TAG = nt_ERR_TAG | 2             # result word 0 for the "expected tuple" error (static str in words 1..2)

nt_OK_TRIPLE = nt_ERR_TAG | 4           # result word 0 for Ok(())

nt_RESERVE = 0x231e050               # RawVec reserve(vec, len, additional, 1, 1)

nt_GROW = 0x231dc90                  # finish_grow; cases give the B-layout vectors enough room to never reach it

nt_HEX_GOT = 0x64e4d08               # .got slot of the 20-byte "0x" hex formatter (runs real)

nt_WS_A, nt_UINT_A, nt_HDR_A, nt_END_A = 0x25e8bf0, 0x25e9f10, 0x25e7c10, 0x22999e0

nt_WS_B, nt_UINT_B, nt_HDR_B, nt_END_B = 0x25e8750, 0x25e9c70, 0x25e7940, 0x22997f0

nt_RAX_WRITERS = (nt_WS_A, nt_WS_B)                       # error comes back in rax:rdx

nt_SLOT_WRITERS = (nt_UINT_A, nt_HDR_A, nt_UINT_B, nt_HDR_B)    # error comes back in an out slot (rdi)

nt_ENDS = (nt_END_A, nt_END_B)                            # Compound::end, writes the caller's result record

nt_FALLIBLE = nt_RAX_WRITERS + nt_SLOT_WRITERS + nt_ENDS

nt_REAL = (nt_WS_A, nt_UINT_A, nt_HDR_A, nt_END_A, nt_WS_B, nt_UINT_B, nt_HDR_B, nt_END_B, 0x2eabb50)

nt_BODIES = {
    0x226f0a0: ("a", "str", None),
    0x226f1e0: ("a", "u32", None),
    0x2275170: ("a", "u8", None),
    0x226e3e0: ("a", "h160", None),
    0x226ca20: ("a", "optstr2", "inline"),
    0x226e250: ("a", "str2", "inline"),     # tests +0x1c == 2 but both arms store 0x92 inline
    0x22771c0: ("a", "str2", "flag"),
    0x22767a0: ("a", "u64x2", "flag"),
    0x2277cc0: ("a", "u64x2", "flag"),
    0x2274fc0: ("b", "str", None),
    0x226d020: ("b", "u32", None),
    0x2272430: ("b", "u8", None),
    0x2277b70: ("b", "h160", None),
    0x2274e80: ("b", "str2", "call"),
    0x2276c90: ("b", "str2", "call"),
    0x2275d10: ("b", "u64x2", "call"),
    0x2277a70: ("b", "u64x2", "call"),
}

nt_FLAG_AT = {"a": 0x1c, "b": 0xc}

nt_LEAVES = {"a": {"str": nt_WS_A, "uint": nt_UINT_A, "hdr": nt_HDR_A, "end": nt_END_A},
          "b": {"str": nt_WS_B, "uint": nt_UINT_B, "hdr": nt_HDR_B, "end": nt_END_B}}

nt_VEC_AT = 0x7180_0000_0000

nt_VAL_AT = 0x7580_0000_0000

nt_NAME_AT = 0x75c0_0000_0000

def nt_is_ext(name, mut=frozenset()):
    if "ext-prefix" in mut:
        return name[:10] == nt_EXT_NAME
    if "ext-case" in mut:
        return name.lower() == nt_EXT_NAME.lower()
    return name == nt_EXT_NAME

def nt_model(c, msg, mut=frozenset()):
    """Predicted (appended bytes, result triple or None for Ok, fallible-call list)."""
    layout, kind, header = nt_BODIES[c["body"]]
    leaf = nt_LEAVES[layout]
    v = c["value"]
    if nt_is_ext(c["name"], mut):
        at, n = msg
        return b"", (nt_EXT_TAG if "ext-tag" not in mut else nt_ERR_TAG, at, n - (1 if "msg-len" in mut else 0)), []
    out, calls, err = b"", [], None

    def fallible(target, data, slot_end=False):
        nonlocal out, err
        if err is not None:
            return
        k = len(calls)
        calls.append(target)
        if c["fault"] == k:
            a, b, x = FAULT
            err = (a, b, x) if slot_end else (nt_ERR_TAG | (4 if "err-tag" in mut else 0), a, b)
        else:
            out += data

    def inline(data):
        nonlocal out
        if err is None:
            out += data

    if header == "inline":
        inline(b"\x92")
    elif header == "flag":
        use_call = (c["flag"] != 2) if "flag-inverted" in mut else (c["flag"] == 2)
        if use_call:
            fallible(leaf["hdr"], b"\x92")
        else:
            inline(b"\x92")
    elif header == "call":
        fallible(leaf["hdr"], b"\x92" if "hdr-fix3" not in mut else b"\x93")

    if kind == "str":
        fallible(leaf["str"], mp_str(v["s0"], mut))
    elif kind == "u32":
        fallible(leaf["uint"], mp_uint(v["w0"] & (M64 if "u32-full" in mut else 0xffffffff), mut))
    elif kind == "u8":
        fallible(leaf["uint"], mp_uint(v["w0"] & (0xffff if "u8-wide" in mut else 0xff), mut))
    elif kind == "u64x2":
        fallible(leaf["uint"], mp_uint(v["w0"] & M64, mut))
        fallible(leaf["uint"], mp_uint(v["w1"] & M64, mut))
    elif kind == "h160":
        text = v["h"].hex().encode()
        fallible(leaf["str"], mp_str((b"" if "hex-no-0x" in mut else b"0x") + (text.upper() if "hex-upper" in mut else text), mut))
    elif kind in ("str2", "optstr2"):
        for s in (v["s0"], v["s1"]):
            if s is None and "none-as-empty" not in mut:
                inline(b"\xc0")
            else:
                fallible(leaf["str"], mp_str(s or b"", mut))
    if header is not None:
        fallible(leaf["end"], b"", slot_end=True)
    if "err-keeps" in mut and err is not None:
        out += b"\x00"
    return out, err, calls

class nt_CaseMachine(Machine):
    def transfer(self, target, call, va):
        if target in self.noreturn:
            self.calls_seen.append(("panic", target))
            raise Boundary("noreturn", self.regs)
        if call and self.body_lo <= va - 5 < self.body_hi and target in nt_FALLIBLE:
            k = self.direct
            self.direct += 1
            self.result_calls.append(target)
            if self.case["fault"] == k:
                return self.fault(target)
        return super().transfer(target, call, va)

    def fault(self, target):
        a, b, x = FAULT
        rdi = self.regs[7]
        if target in nt_SLOT_WRITERS:
            if not STACK_TOP - 0x10000 <= rdi < STACK_TOP:
                fail("writer output slot is not on the stack")
            self.store(rdi, 8, a)
            self.store(rdi + 8, 8, b)
        elif target in nt_ENDS:
            if rdi != OUT_AT:
                fail("Compound::end did not receive the caller's result record")
            for i, w in enumerate(FAULT):
                self.store(OUT_AT + 8 * i, 8, w)
        self.regs[0], self.regs[2] = (OUT_AT, 0) if target in nt_ENDS else (a, b)
        for r in (1, 6, 7, 8, 9, 10, 11):
            self.regs[r] = 0x0dead
        return None

def nt_install(m, image):
    m.calls_seen, m.result_calls, m.reserves = [], [], []
    m.direct = 0

    def reserve(m):
        vec, ln, add = m.regs[7], m.regs[6], m.regs[2]
        if vec not in (SER_AT, nt_VEC_AT):
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

    m.stubs[nt_RESERVE] = reserve
    m.stubs[nt_GROW] = grow
    m.stubs[image.word(MEMCPY_GOT)] = memcpy
    m.noreturn = {image.word(g) for g in PANIC_GOTS}

def nt_run_case(m, c):
    m.reset()
    m.case = c
    nt_install(m, m.image)
    va = c["body"]
    layout = nt_BODIES[va][0]
    m.body_lo, m.body_hi = va, m.extents[va]
    vec = bytearray(0x18)
    put(vec, 0, 8, len(c["prefix"]) + c["room"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    if layout == "a":
        ser = bytes(vec) + c["ser_tail"]
        ser = ser[:nt_FLAG_AT["a"]] + bytes([c["flag"]]) + ser[nt_FLAG_AT["a"] + 1:]
        sreg = m.add_region(SER_AT, 0x20, ser)
        vreg = sreg
    else:
        ser = nt_VEC_AT.to_bytes(8, "little") + c["ser_tail"]
        ser = ser[:nt_FLAG_AT["b"]] + bytes([c["flag"]]) + ser[nt_FLAG_AT["b"] + 1:]
        sreg = m.add_region(SER_AT, 0x10, ser)
        vreg = m.add_region(nt_VEC_AT, 0x18, bytes(vec))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"] + bytes(BUF_SIZE - len(c["prefix"])))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    val = m.add_region(nt_VAL_AT, 0x40, c["val_bytes"])
    name = m.add_region(nt_NAME_AT, 0x40, c["name"] + bytes(0x40 - len(c["name"])))
    strs = m.add_region(STR_AT, STR_SIZE, c["strs"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, SER_AT, nt_NAME_AT, len(c["name"]), nt_VAL_AT
    try:
        m.run(va, limit=400000)
        panic = None
    except Boundary:
        panic = m.calls_seen[-1] if m.calls_seen else ("boundary",)
    vbase = 0 if layout == "a" else None
    ln = m.load((SER_AT if layout == "a" else nt_VEC_AT) + 0x10, 8)
    ptr = m.load((SER_AT if layout == "a" else nt_VEC_AT) + 8, 8)
    del vbase
    ser_now = bytes(sreg)
    return {"panic": panic, "out": bytes(buf[:ln]) if ln <= BUF_SIZE else None,
            "tail_clean": ln <= BUF_SIZE and (not any(buf[ln:]) or ln < len(c["prefix"])),
            "ptr": ptr, "ser_rest": ser_now[0x18:] if layout == "a" else ser_now,
            "result": bytes(out), "inputs_same": bytes(strs) == c["strs"] and bytes(val) == c["val_bytes"]
            and bytes(name[:len(c["name"])]) == c["name"],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100,
            "calls": list(m.result_calls), "reserves": list(m.reserves), "vec_ok": vreg is not None}

def nt_expected_ser_rest(c):
    layout = nt_BODIES[c["body"]][0]
    if layout == "a":
        tail = bytearray(c["ser_tail"])
        tail[nt_FLAG_AT["a"] - 0x18] = c["flag"]
        return bytes(tail)
    ser = bytearray(nt_VEC_AT.to_bytes(8, "little") + c["ser_tail"])
    ser[nt_FLAG_AT["b"]] = c["flag"]
    return bytes(ser)

def nt_compare(c, want, got):
    data, res, calls = want
    if got["panic"] is not None or not got["regs_ok"] or not got["inputs_same"] or not got["tail_clean"]:
        return "machine"
    if got["ser_rest"] != nt_expected_ser_rest(c) or got["ptr"] != BUF_AT:
        return "serializer"
    if got["out"] != c["prefix"] + data:
        return "bytes"
    if got["calls"] != calls:
        return "calls"
    if res is None:
        expect = nt_OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10
    else:
        expect = b"".join(x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    for ln, add in got["reserves"]:
        if ln + add > len(c["prefix"]) + len(data) and res is None:
            return "reserve"
    return None

nt_PER_BODY = 640

nt_SPECIAL_LENS = (0, 1, 2, 31, 32, 33, 255, 256, 257, 300, 0x7ff)

nt_SPECIAL_W = (0, 1, 0x1f, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000,
             0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, M64, M64 - 0x1f, M64 - 0x20, M64 - 0x7f, M64 - 0x80,
             M64 - 0x7fff, M64 - 0x8000, M64 - 0x7fffffff, M64 - 0x80000000)

nt_FLAGS = (0, 1, 2, 2, 3, 0xff)

def nt_names(stream, k):
    sel = k % 8
    if sel in (0, 1):
        return nt_EXT_NAME
    if sel == 2:  # one byte away from the reserved name, at every position
        b = bytearray(nt_EXT_NAME)
        b[(k // 8) % 10] ^= 1 << ((k // 80) % 8)
        return bytes(b)
    if sel == 3:
        return nt_EXT_NAME[:9] if (k // 8) % 2 else nt_EXT_NAME + stream.take(1)
    if sel == 4:
        return nt_EXT_NAME.lower() if (k // 8) % 2 else nt_EXT_NAME.upper()
    return stream.take(stream.below(24))

def nt_fallible_count(c):
    _, _, calls = nt_model(c, (0, 0))
    return len(calls)

def nt_make_case(stream, va, k):
    layout, kind, header = nt_BODIES[va]
    c = {"body": va, "k": k, "flag": nt_FLAGS[k % len(nt_FLAGS)], "prefix": stream.take(stream.below(6)),
         "ser_tail": stream.take(8), "fault": None, "name": nt_names(stream, k)}
    room = ROOMS[(k // 7) % len(ROOMS)]
    strs = bytearray(stream.take(STR_SIZE))
    val = bytearray(stream.take(0x40))
    v = {}

    def text(slot, allow_none):
        if allow_none and stream.below(4) == 0:
            put(val, slot, 8, nt_ERR_TAG)
            return None
        n = nt_SPECIAL_LENS[stream.below(len(nt_SPECIAL_LENS))] if stream.below(3) else stream.below(400)
        at = stream.below(STR_SIZE - n)
        cap = n + stream.below(50)
        if allow_none and cap == nt_ERR_TAG:
            cap += 1
        put(val, slot, 8, cap)
        put(val, slot + 8, 8, STR_AT + at)
        put(val, slot + 16, 8, n)
        return bytes(strs[at:at + n])

    def word(slot):
        sel = stream.below(4)
        w = int.from_bytes(stream.take(8), "little")
        if sel == 0:
            w = nt_SPECIAL_W[stream.below(len(nt_SPECIAL_W))]
        elif sel == 1:
            w = (w & ~0xffffffff) | nt_SPECIAL_W[stream.below(15)]
        elif sel == 2:
            w >>= 8 * stream.below(8)
        put(val, slot, 8, w)
        return w

    if kind == "str":
        v["s0"] = text(0, False)
    elif kind in ("str2", "optstr2"):
        v["s0"] = text(0, kind == "optstr2")
        v["s1"] = text(0x18, kind == "optstr2")
    elif kind == "h160":
        v["h"] = bytes(val[:20])
    else:
        v["w0"] = word(0)
        v["w1"] = word(8)
    c["value"], c["val_bytes"], c["strs"] = v, bytes(val), bytes(strs)
    if layout == "b":
        room = max(room, 0x1800)  # finish_grow is outside this packet; layout b never grows
    c["room"] = room
    n = nt_fallible_count(c)
    if (k // 3) % 2 and n:
        c["fault"] = stream.below(n)
    return c

def nt_all_cases(per_body=nt_PER_BODY):
    out = []
    for va in sorted(nt_BODIES):
        stream = Stream(f"rmp-newtype-tuples/{va:#x}")
        for k in range(per_body):
            out.append(nt_make_case(stream, va, k))
    return out

def nt_extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in list(nt_BODIES) + list(nt_REAL):
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext

def nt_direct_calls(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] in (0xe8, 0xe9):
            out.append(("call" if f["op"] == 0xe8 else "jmp", f["target"]))
        elif f["op"] == 0xff and f["reg"] & 7 in (2, 4) and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append(("got", v + f["len"] + f["rm"][4]))
    return out

def nt_static_rows(image, ext):
    """Per body: callees, ext-name immediates, ext-arm message and flag offset, all from the bytes."""
    rows = []
    name_lo = int.from_bytes(nt_EXT_NAME[:8], "little")
    name_hi = int.from_bytes(nt_EXT_NAME[8:], "little")
    for va in sorted(nt_BODIES):
        layout, kind, header = nt_BODIES[va]
        insns = sweep(image, va, ext[va])
        allowed = set(nt_LEAVES[layout].values()) | {nt_RESERVE}
        targets = set()
        gots = set()
        for k, t in nt_direct_calls(image, va, ext[va]):
            if k == "got":
                gots.add(t)
            elif not (k == "jmp" and va <= t < ext[va]):
                targets.add(t)
        if not targets <= allowed:
            fail(f"body {va:#x} calls outside its layout: {sorted(map(hex, targets - allowed))}")
        if gots - {nt_HEX_GOT} or (kind == "h160") != (nt_HEX_GOT in gots):
            fail(f"body {va:#x} has unexpected .got calls")
        imms = [f.get("imm") for _, f in insns]
        if name_lo not in [i & M64 for i in imms if i is not None] or name_hi not in imms or 10 not in imms:
            fail(f"body {va:#x} does not compare the name with {nt_EXT_NAME!r}")
        msg = None
        for i, (v, f) in enumerate(insns):
            if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip":
                at = (v + f["len"] + f["rm"][4]) & M64
                nxt = [g for _, g in insns[i + 1:i + 4] if g["op"] == 0xc7 and g["rm"][0] == "m"]
                if nxt:
                    msg = (at, nxt[0]["imm"])
        if msg is None:
            fail(f"body {va:#x} has no ext-arm message")
        flag_offsets = sorted({f["rm"][4] for _, f in insns if f["op"] == 0x80 and f["reg"] & 7 == 7
                               and f["rm"][0] == "m" and f.get("imm") == 2})
        if (header == "flag" or (layout == "b" and header == "call" and flag_offsets)) and flag_offsets != [nt_FLAG_AT[layout]]:
            fail(f"body {va:#x} tests flag offsets {flag_offsets}")
        text = image.read(msg[0], msg[1])
        if text not in nt_EXT_MESSAGES:
            fail(f"body {va:#x} ext message is {text!r}")
        rows.append({"va": va, "end": ext[va], "insns": len(insns), "targets": sorted(targets),
                     "hex_got": nt_HEX_GOT in gots, "msg": msg, "text": text.decode(), "flag_offsets": flag_offsets})
    return rows

def nt_machine(image, ext, override=None):
    m = nt_CaseMachine(image, override)
    m.extents = ext
    return m

def nt_evaluate(image, ext, msgs, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = nt_machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        try:
            got = nt_run_case(m, c)
        except ToolError:
            if override is None:
                raise
            got = None
        why = nt_compare(c, nt_model(c, msgs[c["body"]], mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad

nt_MODEL_MUTANTS = ("str-fix32", "str8-limit", "uint-fixint", "u32-full", "u8-wide", "ext-prefix", "ext-case", "ext-tag", "msg-len", "err-tag", "flag-inverted",
                 "hdr-fix3", "hex-no-0x", "hex-upper", "none-as-empty", "err-keeps")

def nt_byte_sites(image, ext):
    """Per body: the length immediate of the name test, one byte of the reserved name, the ext message length
    and (layout a) the inline 0x92 header byte. Each one is flipped and must be caught."""
    sites = []
    for va in sorted(nt_BODIES):
        insns = sweep(image, va, ext[va])
        picked = {}
        for v, f in insns:
            raw = image.code(v, f["len"])
            if f["op"] == 0x83 and f.get("imm") == 10 and "cmp10" not in picked:
                picked["cmp10"] = v + f["len"] - 1
            elif f["op"] == 0xb8 + 0 or (0xb8 <= f["op"] <= 0xbf and f["len"] == 10):
                if raw[-8:] == nt_EXT_NAME[:8] and "name" not in picked:
                    picked["name"] = v + f["len"] - 8 + 4
            elif f["op"] == 0xc7 and f["rm"][0] == "m" and f.get("imm") in (0xe, 0x15):
                picked["msglen"] = v + f["len"] - 4
            elif f["op"] == 0xc6 and f.get("imm", 0) & 0xff == 0x92 and "hdr" not in picked:
                picked["hdr"] = v + f["len"] - 1
            elif f["op"] == 0xc6 and f.get("imm", 0) & 0xff == 0xc0 and "nil" not in picked:
                picked["nil"] = v + f["len"] - 1
        for label in sorted(picked):
            sites.append((va, label, picked[label]))
    return sites

def nt_controls(image, ext, msgs, results, sites):
    rows = []
    gots = [(c, got) for c, got, _ in results]

    def first_hit(mut):
        for i, (c, got) in enumerate(gots):
            if nt_compare(c, nt_model(c, msgs[c["body"]], frozenset(mut)), got):
                return i
        return None

    for name in nt_MODEL_MUTANTS:
        rows.append(("model", name, first_hit({name})))
    for va, label, at in sites:
        cases = [c for c, _ in gots if c["body"] == va]
        _, bad = nt_evaluate(image, ext, msgs, cases, override={at: image.code(at, 1)[0] ^ 0x01}, stop_on_first=True)
        rows.append(("bytes", f"{label}@{at:#x}", cases.index(bad[0][0]) if bad else None))
    return rows

def nt_coverage(image, ext, msgs, cases):
    m = nt_machine(image, ext)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        nt_run_case(m, c)
    rows = []
    for va in sorted(nt_BODIES) + sorted(nt_REAL):
        insns = [v for v, _ in sweep(image, va, ext[va])]
        rows.append((va, len(insns), sum(1 for v in insns if v in seen)))
    return rows

def nt_generate(out, per_body=nt_PER_BODY):
    image = Image(BINARY.read_bytes())
    ext = nt_extents(image)
    static = nt_static_rows(image, ext)
    msgs = {r["va"]: r["msg"] for r in static}
    sites = nt_byte_sites(image, ext)
    cases = nt_all_cases(per_body)
    results, bad = nt_evaluate(image, ext, msgs, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first body {c['body']:#x} case {c['k']} ({why})")
    ctrl = nt_controls(image, ext, msgs, results, sites)
    cov = nt_coverage(image, ext, msgs, cases[::2])
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tfde_end\tinstructions\tlayout\tvalue_kind\tarray_header\tflag_offsets\text_message_at\t"
             "ext_message_len\text_message\tcallees"]
    for r in static:
        layout, kind, header = nt_BODIES[r["va"]]
        callees = [f"{t:#x}" for t in r["targets"]] + ([f"got:{nt_HEX_GOT:#x}"] if r["hex_got"] else [])
        lines.append(f"{r['va']:#x}\t{r['end']:#x}\t{r['insns']}\t{layout}\t{kind}\t{header or '-'}\t"
                     f"{','.join(f'{o:#x}' for o in r['flag_offsets']) or '-'}\t{r['msg'][0]:#x}\t{r['msg'][1]}\t"
                     f"{r['text']}\t{','.join(callees)}")
    (out / "newtype-tuples-bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tname_hex\tflag\tfault_call\troom\tprefix\tout_len\tout_sha256\tresult\tcalls\treserves"]
    for c, got, _ in results:
        if c["k"] % 32 not in (0, 6, 10, 13):  # reserved name, random name, near miss with fault, random name
            continue
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), hexs(c["name"]), f"{c['flag']:#x}",
                                "-" if c["fault"] is None else str(c["fault"]), str(c["room"]), hexs(c["prefix"]),
                                str(len(got["out"])), hashlib.sha256(got["out"]).hexdigest(), got["result"].hex(),
                                ",".join(f"{t:#x}" for t in got["calls"]) or "-", str(len(got["reserves"]))]))
    (out / "newtype-tuples-cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "newtype-tuples-controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        lines.append(f"{va:#x}\t{'body' if va in nt_BODIES else 'real-callee'}\t{n}\t{hit}")
    (out / "newtype-tuples-coverage.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    kinds = {"ext_error": 0, "fault": 0, "ok": 0}
    for c, got, _ in results:
        digest.update(got["out"] + got["result"])
        if nt_is_ext(c["name"]):
            kinds["ext_error"] += 1
        else:
            kinds["ok" if c["fault"] is None else "fault"] += 1
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(nt_BODIES),
        "body_instructions": sum(r["insns"] for r in static),
        "body_instructions_executed": sum(h for v, _, h in cov if v in nt_BODIES),
        "real_callees": [f"{t:#x}" for t in sorted(nt_REAL)],
        "contract_stubs": [f"{nt_RESERVE:#x}", "memcpy"],
        "cases": len(results),
        "case_kinds": kinds,
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": sum(1 for _, _, h in ctrl if h is not None),
    }
    if summary["controls_detected"] != summary["controls"]:
        missed = [n for _, n, h in ctrl if h is None]
        fail(f"negative controls not detected: {missed}")
    (out / "newtype-tuples-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ================================================================ flow layer: action bodies with their field helpers run real
# The signed-action layer stubs the keyed field helpers; the field-helpers layer runs them from a synthetic
# serializer. Here the three action bodies that call five of those helpers run with the helpers' real bytes, so
# one case goes body -> helper -> leaf writer, and the prediction is the signed-action model with each helper
# segment filled in by the field-helpers model. `0x245b4b0` (tail-jumps to the newtype serializer) and
# `0x245a590` (owned by action-wire-gov-vote-codec-115) stay contract stubs.
FL_HELPERS = frozenset({0x24599a0, 0x2459290, 0x24585c0, 0x2458f40, 0x24596c0})
FL_BODIES = tuple(sorted(va for va in sa_BODIES
                         if any(kind == "stub" and off in FL_HELPERS for _, _, kind, off in sa_BODIES[va][3])))
FL_PER_BODY = 2000
FL_STR_AT = 0x1800                 # amount string slot inside the case string pool (after the body's own strings)
FL_KEY_AT = 0x5ed60f               # .rodata key the UserSetAbstraction body passes to 0x24596c0 in rdx/rcx
FL_KEY = b"abstraction"
# `nz-as-eq1` and `u32-full` are not flow controls: the bodies only ever hand the helpers a mode byte of 0 or 1 and
# a 32-bit destinationChainId, so those two wrong helper rules are indistinguishable on this path.
FL_MUTANTS = ("flow-stub", "str-fix32", "str8-limit", "uint-fixint", "uint-u16", "key-always", "key-marker",
              "key-case", "enc-nonzero", "abs-order")


def fl_helper_bytes(c, target, mapping, mut):
    """Bytes the real helper at `target` appends, from the field-helpers model fed with the body's arguments."""
    if "flow-stub" in mut:
        return b""
    args = sa_stub_args(target, c["st"])
    fc = {"helper": target, "flag": 1 if mapping else 0, "fault": None, "prefix": b"",
          "args": args + (0,) * (3 - len(args)), "value": b"", "key": c.get("key", FL_KEY)}
    kind = fh_HELPERS[target][3]
    if kind == "str":
        ptr, n = args
        fc["value"] = c["strs"][ptr - STR_AT:ptr - STR_AT + n]
    out, err, _, _ = fh_model(fc, mut)
    if err is not None:
        fail("helper model reported an error without a fault")
    return out


def fl_make_case(stream, va, k):
    c = sa_make_case(stream, va, k)
    st, strs = bytearray(c["st"]), bytearray(c["strs"])
    stubs = {off for _, _, kind, off in sa_BODIES[va][3] if kind == "stub"}
    if 0x24599a0 in stubs:
        n = fh_SPECIAL_LENS[stream.below(len(fh_SPECIAL_LENS))] if stream.below(3) == 0 else stream.below(48)
        if strs[FL_STR_AT - 1] or any(strs[FL_STR_AT:]):
            fail("flow case string pool overlaps the amount slot")
        strs[FL_STR_AT:FL_STR_AT + n] = sa_ascii_bytes(stream, n)
        put(st, 0x68, 8, STR_AT + FL_STR_AT)
        put(st, 0x70, 8, n)
    if 0x24596c0 in stubs:
        st[0x3c] = stream.below(len(fh_ABSTRACTION_NAMES))
    if 0x2458f40 in stubs and stream.below(3) == 0:
        st[0xb4] = (0, 1, 2, 0x80, 0xff)[stream.below(5)]
    if 0x24585c0 in stubs and stream.below(3) == 0:
        put(st, 0xb0, 4, (0, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff)[stream.below(8)])
    return dict(c, st=bytes(st), strs=bytes(strs), real=FL_HELPERS, key=FL_KEY)


def fl_all_cases(per_body=FL_PER_BODY):
    out = []
    for va in FL_BODIES:
        stream = Stream(f"re015-signed-action-flow-{va:x}")
        out.extend(fl_make_case(stream, va, k) for k in range(per_body))
    return out


def fl_static(image, ext):
    if image.read(FL_KEY_AT, len(FL_KEY)) != FL_KEY:
        fail("the abstraction key bytes moved")
    rows = []
    for va in FL_BODIES:
        called = set(sa_direct_calls(image, va, ext[va]))
        real = sorted(called & FL_HELPERS)
        if not real:
            fail(f"flow body {va:#x} calls no reconstructed helper")
        rows.append((va, real, sorted((called & set(sa_STUBS)) - FL_HELPERS)))
    return rows


def fl_controls(image, ext, results):
    rows = []
    gots = [(c, got) for c, got, _ in results]
    for name in FL_MUTANTS:
        hit = next((i for i, (c, got) in enumerate(gots) if sa_compare(c, sa_model(c, {name: True}), got)), None)
        rows.append(("model", name, hit))
    for va, at, _ in fh_marker_sites(image, ext):
        if va not in FL_HELPERS:
            continue
        cases = [c for c, _ in gots]
        _, bad = fl_evaluate(image, ext, cases, override={at: image.code(at, 1)[0] ^ 0x01}, stop_on_first=True)
        rows.append(("bytes", f"helper-marker@{at:#x}", cases.index(bad[0][0]) if bad else None))
    return rows


def fl_evaluate(image, ext, cases, mut=None, override=None, stop_on_first=False):
    return sa_evaluate(image, ext, cases, mut=mut, override=override, stop_on_first=stop_on_first)


def fl_coverage(image, ext, cases):
    m = sa_machine(image, ext)
    seen = set()
    orig = m.step

    def step(va):
        seen.add(va)
        return orig(va)

    m.step = step
    for c in cases:
        sa_run_case(m, c)
    rows = []
    for va in list(FL_BODIES) + sorted(FL_HELPERS):
        insns = [v for v, _ in sweep(image, va, ext[va])]
        rows.append((va, len(insns), sum(1 for v in insns if v in seen)))
    return rows


def fl_generate(out):
    image = Image(BINARY.read_bytes())
    ext = sa_extents(image)
    static = fl_static(image, ext)
    cases = fl_all_cases()
    results, bad = fl_evaluate(image, ext, cases)
    if bad:
        c, why = bad[0]
        fail(f"flow: {len(bad)} mismatches; first body {c['body']:#x} case {c['k']} ({why})")
    ctrl = fl_controls(image, ext, results)
    cov = fl_coverage(image, ext, cases[::4])
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\taction_inferred\thelpers_run_real\thelpers_still_stubbed"]
    for va, real, stubbed in static:
        lines.append(f"{va:#x}\t{sa_BODIES[va][0]}\t{','.join(f'{t:#x}' for t in real)}\t"
                     f"{','.join(f'{t:#x}' for t in stubbed) or '-'}")
    (out / "flow-bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tmode\tfault_call\troom\tout_len\tout_sha256\tresult\tresult_calls\tstub_calls"]
    for c, got, _ in results:
        if c["k"] % 50:
            continue
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), "map" if c["map"] else "array",
                                "-" if c["fault"] is None else str(c["fault"]), str(c["room"]),
                                str(len(got["out"])), hashlib.sha256(got["out"]).hexdigest(), got["result"].hex(),
                                str(len(got["calls"])),
                                ";".join(",".join(f"{x:#x}" for x in s) for s in got["stubs"]) or "-"]))
    (out / "flow-cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "flow-controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov:
        lines.append(f"{va:#x}\t{'body' if va in FL_BODIES else 'helper-run-real'}\t{n}\t{hit}")
    (out / "flow-coverage.tsv").write_text("\n".join(lines) + "\n")

    digest = hashlib.sha256()
    kinds = {"map": 0, "array": 0, "fault": 0, "ok": 0}
    for c, got, _ in results:
        digest.update(got["out"] + got["result"])
        kinds["map" if c["map"] else "array"] += 1
        kinds["ok" if c["fault"] is None else "fault"] += 1
    summary = {
        "binary_sha256": SHA256,
        "bodies": [f"{va:#x}" for va in FL_BODIES],
        "helpers_run_real": [f"{t:#x}" for t in sorted(FL_HELPERS)],
        "cases": len(results),
        "case_kinds": kinds,
        "mismatches": 0,
        "outputs_sha256": digest.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": sum(1 for _, _, h in ctrl if h is not None),
        "helper_instructions": sum(n for v, n, _ in cov if v in FL_HELPERS),
        "helper_instructions_executed": sum(h for v, _, h in cov if v in FL_HELPERS),
    }
    if summary["controls_detected"] != summary["controls"]:
        fail("flow: a negative control was not detected")
    (out / "flow-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary

# ---------------------------------------------------------------- the merged packet
LAYERS = (("signed-action", sa_generate), ("field-helpers", fh_generate), ("newtype-tuples", nt_generate),
          ("flow", fl_generate))


def generate(out, layers=None):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    per = {}
    for label, gen in LAYERS:
        if layers is None or label in layers:
            per[label] = gen(out)
    if layers is not None:
        return per
    summary = {
        "binary_sha256": SHA256,
        "layers": {label: {k: per[label][k] for k in ("cases", "mismatches", "controls", "controls_detected",
                                                       "outputs_sha256")} for label in per},
        "cases": sum(s["cases"] for s in per.values()),
        "mismatches": sum(s["mismatches"] for s in per.values()),
        "controls": sum(s["controls"] for s in per.values()),
        "controls_detected": sum(s["controls_detected"] for s in per.values()),
    }
    if summary["controls_detected"] != summary["controls"] or summary["mismatches"]:
        fail("merged packet is not clean")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--layer", action="append", choices=[label for label, _ in LAYERS],
                    help="regenerate only these layers (no merged summary.json)")
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.layer)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
